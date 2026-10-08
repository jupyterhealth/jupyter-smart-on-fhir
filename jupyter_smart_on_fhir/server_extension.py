import json
import os
from dataclasses import dataclass
from functools import wraps
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

import jwt
import tornado
from jupyter_core.paths import jupyter_runtime_dir
from jupyter_server.auth.decorator import allow_unauthenticated
from jupyter_server.auth.identity import IdentityProvider, User
from jupyter_server.base.handlers import JupyterHandler
from jupyter_server.extension.application import ExtensionApp
from jupyter_server.utils import url_path_join
from tornado import web
from tornado.httpclient import AsyncHTTPClient, HTTPClientError
from tornado.httputil import url_concat
from traitlets import Callable, List, Unicode

from jupyter_smart_on_fhir.auth import SMARTConfig, generate_state

smart_path = "smart-on-fhir"
launch_path = f"{smart_path}/launch"
login_path = f"{smart_path}/login"
callback_path = f"{smart_path}/callback"


def _jupyter_server_extension_points():
    return [
        {"module": "jupyter_smart_on_fhir.server_extension", "app": SMARTExtensionApp}
    ]


def authenticated_unless_smart_auth(method):
    """Protect an endpoint unless smart auth is enabled

    If using SMART for auth, allow unauthenticated access,
    otherwise protect it via regular auth.

    Applied to the requests leading up to SMART launch,
    after which regular auth is applied.
    """

    @wraps(method)
    def wrapped(self, *args, **kwargs):
        identity_provider = self.settings["identity_provider"]
        if isinstance(identity_provider, SMARTIdentityProvider):
            wrap = allow_unauthenticated
        else:
            wrap = web.authenticated
        return wrap(method)(self, *args, **kwargs)

    return wrapped


@dataclass
class SMARTTokenUser(User):
    smart_token: str = (
        ""  # required, but needs a default due to dataclass init nonsense
    )


def _username_from_token(token: str, log) -> str | None:
    try:
        id_token = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        log.exception("Failed to decode id token")
        return None
    for key in ["fhirUser", "profile", "sub"]:
        if key in id_token:
            return id_token[key]
    # fallback on sha of token itself
    return f"sha-{sha256(token.encode()).hexdigest()[:7]}"


class SMARTIdentityProvider(IdentityProvider):
    """
    IdentityProvider that users SMART launch itself for auth.

    Upon completion of auth, the launch token is stored,
    associated with the browser.

    Subsequent requests compare the token stored in the cookie with the current stateful $SMART_TOKEN,
    and only accept requests from the browser that set that token.
    """

    def persist_user_model(self, handler: web.RequestHandler) -> None:
        """Persist the user model to a cookie."""
        self.set_login_cookie(handler, handler.current_user)

    async def get_user_token(self, handler: web.RequestHandler):
        token = self.get_token(handler)
        if token:
            return self.user_from_token(token)
        else:
            return None

    def user_from_token(self, token: str) -> SMARTTokenUser | None:
        if not token or token != os.getenv("SMART_TOKEN"):
            # app has only one active smart token at a time,
            # reject previously authorized clients
            self.log.warning("Not accepting mismatched SMART token")
            return None

        username = _username_from_token(token, log=self.log)
        if username is None:
            return None
        return SMARTTokenUser(username=username, smart_token=token)

    def user_to_cookie(self, user: SMARTTokenUser):
        return user.smart_token

    def user_from_cookie(self, cookie):
        return self.user_from_token(cookie)


class SMARTExtensionApp(ExtensionApp):
    """Jupyter server extension for SMART on FHIR"""

    name = "smart-on-fhir"
    scopes = List(
        Unicode(),
        help="""Scopes to request authorization for at the FHIR endpoint""",
        default_value=["openid", "profile", "fhirUser", "launch", "patient/*.*"],
    ).tag(config=True)

    client_id = Unicode(
        help="""Client ID for the SMART application""",
    ).tag(config=True)

    redirect_uri = Unicode(
        help="""Redirect URI for the SMART application

        If unspecified, will deduce from the current request
        """,
    ).tag(config=True)

    default_issuer = Unicode(
        help="""default issuer for launch page, if none specified
        """,
    ).tag(config=True)

    token_file = Unicode(
        os.path.join(jupyter_runtime_dir(), "smart_token.json"),
        help="""JSON file in which to store tokens""",
    ).tag(config=True)

    smart_launch_hook = Callable(
        None,
        allow_none=True,
        help="""
        Callback for smart launch
        
        Called during the initial launch handler
        Can take action on the provider-specific launch parameter
        
        Hook takes::
        
            smart_launch_hook(launch, url, smart_config, handler)
        
        where
        - launch: the opaque launch parameter in the URL query
        - url: the full URL
        - smart_config: SMARTConfig dataclass
        - handler: the current RequestHandler
        """,
    ).tag(config=True)

    smart_callback_hook = Callable(
        None,
        allow_none=True,
        help="""
        Callback for smart oauthc allback
        
        Called during the initial launch handler
        Can take action on the provider-specific launch parameter
        
        Hook takes::
        
            smart_launch_hook(token, launch, smart_config, handler)
        
        where
        - launch: the opaque launch parameter in the URL query
        - url: the full URL
        - smart_config: SMARTConfig dataclass
        - handler: the current RequestHandler
        """,
    ).tag(config=True)

    def initialize_settings(self):
        os.environ["SMART_TOKEN_FILE"] = self.token_file
        self.settings["smart_auth"] = self
        self.settings["smart_client_id"] = self.client_id
        self.settings["smart_redirect_uri"] = self.redirect_uri
        self.settings["smart_default_issuer"] = self.default_issuer
        self.settings["smart_oauth_state"] = None

    def initialize_handlers(self):
        self.handlers.extend(
            [
                (launch_path, SMARTLaunchHandler),
                (login_path, SMARTLoginHandler),
                (callback_path, SMARTCallbackHandler),
            ]
        )


def get_next_url(handler):
    """Get next url and validate it"""
    next_url = handler.get_argument("next", None)
    if next_url and ":" in next_url:
        handler.log.warning(f"Not allowing absolute next URL: {next_url}")
        next_url = None
    if next_url:
        # ensure single leading '/', avoid backslash shenanigans
        next_url = "/" + next_url.replace("\\", "%5C").lstrip("/")
        parsed_next_url = urlparse(next_url)
        # make it an absolute path, strip host info
        next_url = "/" + parsed_next_url.path.lstrip("/")
        # and relative to self.base_url
        if not (next_url + "/").startswith(handler.base_url):
            next_url = url_path_join(handler.base_url, next_url)
        # restore query, fragment
        if parsed_next_url.query:
            next_url = next_url + "?" + parsed_next_url.query
        if parsed_next_url.fragment:
            next_url = next_url + "#" + parsed_next_url.fragment
    else:
        next_url = handler.base_url
    return next_url


class SMARTLaunchHandler(JupyterHandler):
    """Handler for SMART on FHIR authentication"""

    @authenticated_unless_smart_auth
    async def get(self):
        smart_auth = self.settings["smart_auth"]
        fhir_url = self.get_argument("iss", self.settings["smart_default_issuer"])
        if not fhir_url:
            raise web.HTTPError(400, "issuer (?iss=...) required")
        smart_config = SMARTConfig.from_url(fhir_url, self.request.full_url())
        self.settings["smart_config"] = smart_config
        self.log.info("Starting smart launch for %s", self.request.query_arguments)
        launch = self.get_argument("launch", "")
        login_params = {
            "launch": launch,
            "scope": " ".join(smart_auth.scopes),
        }
        if self.get_argument("next", None):
            login_params["next"] = get_next_url(self)

        hook = smart_auth.smart_launch_hook
        if hook:
            hook_out = await hook(
                launch=launch,
                url=self.request.full_url(),
                smart_config=smart_config,
                handler=self,
            )
            if hook_out:
                if "scope" in hook_out:
                    login_params["scope"] = hook_out["scope"]
                if "next" in hook_out:
                    login_params["next"] = hook_out["next"]

        # TODO: persist next_url differently
        self.redirect(
            url_concat(url_path_join(self.base_url, login_path), login_params)
        )


class SMARTLoginHandler(JupyterHandler):
    """Login handler for SMART on FHIR"""

    @authenticated_unless_smart_auth
    def get(self):
        state = generate_state(get_next_url(self))
        # only allow a single oauth state to be valid at a time
        if self.settings.get("smart_oauth_state"):
            self.log.warning("Overwriting stale smart oauth state")
        self.settings["smart_oauth_state"] = state
        if state["next_url"]:
            self.log.info("Will redirect to %s after SMART login", state["next_url"])

        smart_config = self.settings["smart_config"]
        auth_url = smart_config.auth_url
        oauth_params = {
            "aud": smart_config.fhir_url,
            "state": state["state_id"],
            "launch": self.get_argument("launch"),
            "redirect_uri": self.settings["smart_redirect_uri"]
            or urljoin(
                self.request.full_url(), url_path_join(self.base_url, callback_path)
            ),
            "client_id": self.settings["smart_client_id"],
            "code_challenge": state["code_challenge"],
            "code_challenge_method": "S256",
            "response_type": "code",
            "scope": self.get_argument("scope"),
        }
        self.redirect(url_concat(auth_url, oauth_params))


class SMARTCallbackHandler(JupyterHandler):
    """Callback handler for SMART on FHIR"""

    async def token_for_code(self, code: str, code_verifier: str) -> dict:
        data = dict(
            client_id=self.settings["smart_client_id"],
            grant_type="authorization_code",
            code=code,
            code_verifier=code_verifier,
            redirect_uri=self.settings["smart_redirect_uri"]
            or urljoin(
                self.request.full_url(), url_path_join(self.base_url, callback_path)
            ),
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            token_reply = await AsyncHTTPClient().fetch(
                self.settings["smart_config"].token_url,
                body=urlencode(data),
                headers=headers,
                method="POST",
            )
        except HTTPClientError as e:
            self.log.error(
                "Error fetching token: %s", e.response.body.decode("utf8", "replace")
            )
            raise
        return json.loads(token_reply.body.decode("utf8", "replace"))

    @authenticated_unless_smart_auth
    async def get(self):
        if "error" in self.request.arguments:
            raise tornado.web.HTTPError(400, self.get_argument("error"))
        code = self.get_argument("code")
        if not code:
            raise tornado.web.HTTPError(
                400, "Error: no code in response from FHIR server"
            )
        state = self.settings.get("smart_oauth_state")
        if not state:
            raise tornado.web.HTTPError(400, "Error: missing persisted oauth state")
        state_id = state["state_id"]
        arg_state = self.get_argument("state")
        if not arg_state:
            raise tornado.web.HTTPError(400, "Error: missing state query argument")
        if arg_state != state_id:
            raise tornado.web.HTTPError(
                400, "Error: state received from FHIR server does not match"
            )
        self.settings["smart_oauth_state"] = None

        token_response = await self.token_for_code(
            code, code_verifier=state["code_verifier"]
        )
        smart_auth = self.settings["smart_auth"]
        self.log.info(
            "Persisting token info to %s and $SMART_TOKEN", smart_auth.token_file
        )
        with Path(smart_auth.token_file).open("w") as f:
            json.dump(
                {
                    "token": token_response,
                    "fhir_url": self.settings["smart_config"].fhir_url,
                    # the full output of the .well-known/smart-configuration endpoint
                    "smart_config": self.settings["smart_config"].smart_config,
                },
                f,
                sort_keys=True,
                indent=1,
            )
        # if using SMART for Auth, persist token
        # for subsequent cookie-authenticated requests
        identity_provider = self.settings["identity_provider"]
        if isinstance(identity_provider, SMARTIdentityProvider):
            smart_token = token_response["access_token"]
            username = _username_from_token(smart_token, log=identity_provider.log)
            if not username:
                raise RuntimeError("Failed to get username!")
            user = SMARTTokenUser(username=username, smart_token=smart_token)
            identity_provider.set_login_cookie(self, user)

        os.environ["SMART_TOKEN"] = token_response["access_token"]

        redirected = False
        hook = self.settings["smart_auth"].smart_callback_hook
        if hook:
            # hook is responsible for redirect (?)
            redirected = await hook(
                token_response=token_response,
                smart_config=self.settings["smart_config"],
                handler=self,
            )
        if not redirected:
            self.redirect(state["next_url"] or self.base_url)


if __name__ == "__main__":
    SMARTExtensionApp.launch_instance()
