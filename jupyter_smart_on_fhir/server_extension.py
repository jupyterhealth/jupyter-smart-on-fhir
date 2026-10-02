import json
import os
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

from jupyter_core.paths import jupyter_runtime_dir
from jupyter_server.auth.decorator import allow_unauthenticated
from jupyter_server.auth.identity import IdentityProvider
from jupyter_server.base.handlers import JupyterHandler
from jupyter_server.extension.application import ExtensionApp
from jupyter_server.utils import url_path_join
from tornado import web
from tornado.httpclient import AsyncHTTPClient, HTTPClientError
from tornado.httputil import url_concat
from traitlets import Bool, Callable, Int, List, Unicode, default

from jupyter_smart_on_fhir.auth import SMARTConfig, generate_state
from jupyter_smart_on_fhir.session import (
    SESSION_COOKIE_NAME,
    TOKEN_DIR_ENV,
    SMARTSession,
    SMARTSessionStore,
    parse_cookie_header,
)

smart_path = "smart-on-fhir"
launch_path = f"{smart_path}/launch"
login_path = f"{smart_path}/login"
callback_path = f"{smart_path}/callback"


def _jupyter_server_extension_points():
    return [
        {"module": "jupyter_smart_on_fhir.server_extension", "app": SMARTExtensionApp}
    ]


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
        help="""Legacy single token file, used only with persist_global_token (Hub mode)."""
    ).tag(config=True)

    @default("token_file")
    def _token_file_default(self):
        return os.path.join(jupyter_runtime_dir(), "smart_token.json")

    allowed_issuers = List(
        Unicode(),
        help="""FHIR base URLs (the launch `iss`) this server accepts; exact match after
        normalization. REQUIRED in standalone mode (SMARTIdentityProvider): a launch from
        any other issuer is refused before any outbound request. Under JupyterHub the Hub
        login already gates the handlers, so an empty list only logs a startup warning
        (enforced when set).""",
    ).tag(config=True)

    discovery_timeout = Int(
        10, help="Seconds allowed for the .well-known/smart-configuration fetch."
    ).tag(config=True)

    discovery_cache_ttl = Int(
        3600,
        help="Seconds to reuse a discovered SMART configuration per issuer (anonymous "
        "launches must not turn into a stream of requests to the EHR).",
    ).tag(config=True)

    token_dir = Unicode(
        help="""Directory for per-session token files (one 0600 JSON file per session).
        Wiped at startup. Exported to kernels as $SMART_TOKEN_DIR.""",
    ).tag(config=True)

    @default("token_dir")
    def _token_dir_default(self):
        return os.path.join(jupyter_runtime_dir(), "smart-sessions")

    session_lifetime = Int(
        3600,
        help="""Max seconds a session lives after login; shortened to the token's
        expires_in when that is smaller.""",
    ).tag(config=True)

    pending_lifetime = Int(
        600, help="Seconds a launch may sit un-completed before it is discarded."
    ).tag(config=True)

    max_pending_sessions = Int(
        500,
        help="Launches that may be awaiting their callback at once; the oldest is "
        "evicted beyond this (never refused).",
    ).tag(config=True)

    cookie_name = Unicode(SESSION_COOKIE_NAME, help="Session cookie name").tag(
        config=True
    )

    cookie_secure = Bool(
        None,
        allow_none=True,
        help="""Set the Secure flag on the session cookie. None (default): only when the
        request is https (honours ServerApp.trust_xheaders behind a proxy).""",
    ).tag(config=True)

    cookie_partitioned = Bool(
        True,
        help="""Add the Partitioned (CHIPS) attribute when the cookie is Secure so it
        survives inside an EHR iframe where third-party cookies are blocked.""",
    ).tag(config=True)

    persist_global_token = Bool(
        False,
        help="""JupyterHub mode: also write the latest token to `token_file` and
        $SMART_TOKEN (one server per user makes that per-user). Ignored, with a warning,
        when the identity provider is SMARTIdentityProvider (standalone), where a shared
        file would be readable by every session's kernel.""",
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
        allowed = {normalize_issuer(u) for u in self.allowed_issuers if u.strip()}
        check_standalone_config(allowed, self.serverapp.identity_provider_class)
        store = SMARTSessionStore(
            self.token_dir,
            pending_lifetime=self.pending_lifetime,
            session_lifetime=self.session_lifetime,
            max_pending=self.max_pending_sessions,
        )
        store.wipe()  # no session survives a restart
        os.environ[TOKEN_DIR_ENV] = self.token_dir
        self.settings["smart_auth"] = self
        self.settings["smart_session_store"] = store
        self.settings["smart_session_cookie_name"] = self.cookie_name
        self.settings["smart_allowed_issuers"] = allowed
        self.settings["smart_discovery_cache"] = {}
        if not allowed:
            self.log.warning(
                "SMARTExtensionApp.allowed_issuers is empty: any logged-in Jupyter user "
                "may launch from any FHIR server (Hub login is the only gate)"
            )
        self.settings["smart_client_id"] = self.client_id
        self.settings["smart_redirect_uri"] = self.redirect_uri
        self.settings["smart_default_issuer"] = self.default_issuer
        if self.persist_global_token:
            if issubclass(
                self.serverapp.identity_provider_class, SMARTIdentityProvider
            ):
                self.log.warning(
                    "persist_global_token is ignored in standalone mode (SMARTIdentityProvider)"
                )
            else:
                os.environ["SMART_TOKEN_FILE"] = self.token_file

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


class SMARTIdentityProvider(IdentityProvider):
    """Completed in a later task; declared here so config checks can reference it."""


def normalize_issuer(url: str) -> str:
    """Canonical form for allowlist matching: lower-case scheme+host, no trailing slash,
    https required except for localhost development."""
    url = (url or "").strip().rstrip("/")
    parts = urlparse(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"issuer must be an absolute URL: {url!r}")
    scheme, netloc = parts.scheme.lower(), parts.netloc.lower()
    host = netloc.rsplit("@", 1)[-1].split(":", 1)[0]
    if scheme != "https" and host not in ("localhost", "127.0.0.1"):
        raise ValueError(f"issuer must be https: {url!r}")
    return parts._replace(scheme=scheme, netloc=netloc).geturl()


def check_standalone_config(allowed_issuers: set, identity_provider_class) -> None:
    """Standalone mode has no other gate, so an empty allowlist would mean 'trust any EHR'."""
    if (
        isinstance(identity_provider_class, type)
        and issubclass(identity_provider_class, SMARTIdentityProvider)
        and not allowed_issuers
    ):
        raise ValueError(
            "SMARTExtensionApp.allowed_issuers must list at least one EHR issuer "
            "when ServerApp.identity_provider_class is SMARTIdentityProvider"
        )


async def discover(iss: str, base_url: str, timeout: float) -> SMARTConfig:
    """Async SMART discovery (the launch handler runs on the event loop; never block it).
    `iss` is kept as the EHR sent it: SMART requires `aud` to equal that value."""
    reply = await AsyncHTTPClient().fetch(
        f"{iss.rstrip('/')}/{SMARTConfig.broadcast_path}",
        headers={"Accept": "application/json"},
        request_timeout=timeout,
        follow_redirects=False,
    )
    cfg = json.loads(reply.body.decode("utf8", "replace"))
    return SMARTConfig(
        base_url=base_url,
        fhir_url=iss,
        token_url=cfg["token_endpoint"],
        auth_url=cfg["authorization_endpoint"],
        smart_config=cfg,
    )


async def cached_discover(handler, fhir_url: str, normalized: str) -> SMARTConfig:
    """Discovery result per normalized issuer, reused for discovery_cache_ttl seconds."""
    smart_auth = handler.settings["smart_auth"]
    cache = handler.settings["smart_discovery_cache"]
    store = handler.settings["smart_session_store"]
    now = store.clock()
    hit = cache.get(normalized)
    if hit and hit[0] > now:
        return hit[1]
    config = await discover(
        fhir_url, handler.request.full_url(), smart_auth.discovery_timeout
    )
    cache[normalized] = (now + smart_auth.discovery_cache_ttl, config)
    return config


COOKIES_BLOCKED_MESSAGE = (
    "No SMART session cookie was sent with this request. If this app is embedded inside "
    "your EHR, your browser may be blocking third-party cookies. Ask your EHR administrator "
    "to configure the app to open in a new window, or allow cookies for this site."
)
LAUNCH_EXPIRED_MESSAGE = (
    "Your launch expired or the app restarted. Relaunch from the EHR patient chart."
)
NOT_ALLOWED_ISSUER_MESSAGE = (
    "That FHIR server is not an allowed EHR issuer for this app."
)


def set_session_cookie(handler, session_id: str) -> None:
    """Signed, HttpOnly session cookie; Secure+SameSite=None(+Partitioned) on https."""
    smart_auth = handler.settings["smart_auth"]
    name = smart_auth.cookie_name
    secure = smart_auth.cookie_secure
    if secure is None:
        secure = handler.request.protocol == "https"
    # Build through SimpleCookie so quoting matches what browsers/tornado expect, then emit
    # the header ourselves: Python's Morsel has no 'Partitioned' attribute.
    jar = SimpleCookie()
    jar[name] = handler.create_signed_value(name, session_id).decode("utf8")
    morsel = jar[name]
    morsel["path"] = handler.base_url
    morsel["max-age"] = smart_auth.session_lifetime
    morsel["httponly"] = True
    if secure:
        morsel["secure"] = True
        morsel["samesite"] = "None"
    else:
        morsel["samesite"] = "Lax"
        handler.log.warning(
            "SMART session cookie set without Secure (request is not https); "
            "EHR iframe embedding will not work"
        )
    header = morsel.OutputString()
    if secure and smart_auth.cookie_partitioned:
        header += "; Partitioned"
    handler.add_header("Set-Cookie", header)


def resolve_session(handler) -> tuple[SMARTSession | None, str]:
    """(session, reason), reason in {"ok", "no-cookie", "duplicate-cookie", "bad-signature",
    "unknown-or-expired"}."""
    store = handler.settings.get("smart_session_store")
    name = handler.settings.get("smart_session_cookie_name")
    if store is None or not name:
        return None, "no-cookie"
    jar = parse_cookie_header(handler.request.headers.get("Cookie"))
    if jar is None:
        # tornado would verify the LAST value while a kernel might read the FIRST; refuse.
        return None, "duplicate-cookie"
    if name not in jar:
        return None, "no-cookie"
    raw = handler.get_signed_cookie(name)
    if not raw:
        return None, "bad-signature"
    session = store.get(raw.decode("utf8", "replace"))
    if session is None:
        return None, "unknown-or-expired"
    return session, "ok"


def require_session(handler) -> SMARTSession:
    session, reason = resolve_session(handler)
    if session is not None:
        return session
    handler.log.warning("SMART session missing on %s: %s", handler.request.path, reason)
    # Only a truly absent cookie means "blocked by the browser". A cookie that is present
    # but unverifiable is the restart case (ephemeral cookie secret) or an expired launch.
    if reason == "no-cookie":
        raise web.HTTPError(400, COOKIES_BLOCKED_MESSAGE)
    raise web.HTTPError(400, LAUNCH_EXPIRED_MESSAGE)


def is_smart_idp(handler) -> bool:
    return isinstance(handler.identity_provider, SMARTIdentityProvider)


def require_jupyter_user_unless_smart_idp(handler) -> None:
    """Hub/default-provider mode: behave exactly like @tornado.web.authenticated did in
    0.1.x. Standalone mode (SMARTIdentityProvider) has no prior login, so it is open."""
    if is_smart_idp(handler) or handler.current_user:
        return
    if handler.request.method in ("GET", "HEAD"):
        url = handler.get_login_url()
        if "?" not in url:
            url = url_concat(url, {"next": handler.request.uri})
        handler.redirect(url)
        raise web.Finish()
    raise web.HTTPError(403)


class SMARTLaunchHandler(JupyterHandler):
    """Entry point the EHR redirects to. Checks the issuer allowlist before anything
    else, mints a fresh session for this browser, and hands off to the login handler."""

    @allow_unauthenticated
    async def get(self):
        require_jupyter_user_unless_smart_idp(self)
        smart_auth = self.settings["smart_auth"]
        store = self.settings["smart_session_store"]
        fhir_url = self.get_argument(
            "iss", self.settings["smart_default_issuer"]
        ).strip()
        if not fhir_url:
            raise web.HTTPError(400, "issuer (?iss=...) required")
        # Normalize ONLY to match the allowlist; keep `iss` as sent for discovery and `aud`
        # (SMART: aud == launch iss; Medplum sends a trailing slash).
        try:
            normalized = normalize_issuer(fhir_url)
        except ValueError:
            raise web.HTTPError(400, NOT_ALLOWED_ISSUER_MESSAGE)
        allowed = self.settings["smart_allowed_issuers"]
        # Standalone: always enforced (startup refuses an empty list). Hub: enforced when set.
        if (allowed or is_smart_idp(self)) and normalized not in allowed:
            self.log.warning(
                "Refusing SMART launch from issuer not on allowlist: %s", fhir_url
            )
            raise web.HTTPError(400, NOT_ALLOWED_ISSUER_MESSAGE)
        try:
            smart_config = await cached_discover(self, fhir_url, normalized)
        except (HTTPClientError, OSError, KeyError, ValueError) as e:
            self.log.error("SMART discovery failed for %s: %s", fhir_url, e)
            raise web.HTTPError(502, "Could not read the EHR's SMART configuration")
        # A launch always starts a new session (defeats session fixation); drop any old one.
        old, _ = resolve_session(self)
        if old is not None:
            store.delete(old.session_id)
        session = store.create(
            fhir_url, smart_config
        )  # evicts the oldest pending at capacity
        set_session_cookie(self, session.session_id)
        self.log.info(
            "Starting smart launch %s for %s", session.session_id[:8], fhir_url
        )
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

        self.redirect(
            url_concat(url_path_join(self.base_url, login_path), login_params)
        )


class SMARTLoginHandler(JupyterHandler):
    """Login handler for SMART on FHIR"""

    @allow_unauthenticated
    def get(self):
        require_jupyter_user_unless_smart_idp(self)
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

    @allow_unauthenticated
    async def get(self):
        require_jupyter_user_unless_smart_idp(self)
        if "error" in self.request.arguments:
            raise web.HTTPError(400, self.get_argument("error"))
        code = self.get_argument("code")
        if not code:
            raise web.HTTPError(400, "Error: no code in response from FHIR server")
        state = self.settings.get("smart_oauth_state")
        if not state:
            raise web.HTTPError(400, "Error: missing persisted oauth state")
        state_id = state["state_id"]
        arg_state = self.get_argument("state")
        if not arg_state:
            raise web.HTTPError(400, "Error: missing state query argument")
        if arg_state != state_id:
            raise web.HTTPError(
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
