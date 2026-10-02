import json
import os
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

from jupyter_core.paths import jupyter_runtime_dir
from jupyter_server.auth.authorizer import Authorizer
from jupyter_server.auth.decorator import allow_unauthenticated
from jupyter_server.auth.identity import IdentityProvider, User
from jupyter_server.base.handlers import JupyterHandler
from jupyter_server.extension.application import ExtensionApp
from jupyter_server.utils import url_path_join
from tornado import web
from tornado.httpclient import AsyncHTTPClient, HTTPClientError
from tornado.httputil import url_concat
from traitlets import Bool, Callable, Int, List, Unicode, default

from jupyter_smart_on_fhir.auth import SMARTConfig, generate_state
from jupyter_smart_on_fhir.session import (
    COOKIE_NAME_ENV,
    SESSION_COOKIE_NAME,
    TOKEN_DIR_ENV,
    SMARTSession,
    SMARTSessionError,
    SMARTSessionStore,
    parse_cookie_header,
    session_id_from_cookie_header,
)

smart_path = "smart-on-fhir"
launch_path = f"{smart_path}/launch"
login_path = f"{smart_path}/login"
callback_path = f"{smart_path}/callback"
session_path = f"{smart_path}/session"


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
        check_standalone_config(
            allowed,
            self.serverapp.identity_provider_class,
            self.serverapp.authorizer_class,
            getattr(self.serverapp.kernel_manager, "allowed_message_types", None),
            self.log,
        )
        store = SMARTSessionStore(
            self.token_dir,
            pending_lifetime=self.pending_lifetime,
            session_lifetime=self.session_lifetime,
            max_pending=self.max_pending_sessions,
        )
        store.wipe()  # no session survives a restart
        os.environ[TOKEN_DIR_ENV] = self.token_dir
        os.environ[COOKIE_NAME_ENV] = self.cookie_name
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
                (session_path, SMARTSessionInfoHandler),
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


def normalize_issuer(url: str) -> str:
    """Canonical form for allowlist matching: lower-case scheme+host, no trailing slash,
    https required except for localhost development."""
    # urlparse silently drops tabs/newlines, so reject them before parsing.
    if any(c in (url or "") for c in "\t\r\n"):
        raise ValueError(f"issuer contains control characters: {url!r}")
    url = (url or "").strip().rstrip("/")
    parts = urlparse(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"issuer must be an absolute URL: {url!r}")
    # Non-ASCII hosts can case-fold onto ASCII ones (Kelvin sign -> "k").
    if not parts.netloc.isascii():
        raise ValueError(f"issuer host must be ASCII: {url!r}")
    scheme, netloc = parts.scheme.lower(), parts.netloc.lower()
    host = netloc.rsplit("@", 1)[-1].split(":", 1)[0]
    if scheme != "https" and host not in ("localhost", "127.0.0.1"):
        raise ValueError(f"issuer must be https: {url!r}")
    return parts._replace(scheme=scheme, netloc=netloc).geturl()


def check_standalone_config(
    allowed_issuers: set,
    identity_provider_class,
    authorizer_class=None,
    allowed_message_types=None,
    log=None,
) -> None:
    """Standalone mode has no other gate: refuse an empty allowlist ('trust any EHR') or
    a non-SMART authorizer, and warn when sessions may execute code in their kernel."""
    if not (
        isinstance(identity_provider_class, type)
        and issubclass(identity_provider_class, SMARTIdentityProvider)
    ):
        return
    if not allowed_issuers:
        raise ValueError(
            "SMARTExtensionApp.allowed_issuers must list at least one EHR issuer "
            "when ServerApp.identity_provider_class is SMARTIdentityProvider"
        )
    if authorizer_class is not None and not (
        isinstance(authorizer_class, type)
        and issubclass(authorizer_class, SMARTAuthorizer)
    ):
        raise ValueError(
            "standalone mode requires ServerApp.authorizer_class = SMARTAuthorizer: "
            "a session could otherwise start kernels and run code"
        )
    if (
        log is not None
        and allowed_message_types is not None
        and not allowed_message_types
    ):
        log.warning(
            "MappingKernelManager.allowed_message_types is empty: sessions can send "
            "execute_request; set the comm-only list"
        )


async def fetch_discovery_document(iss: str, timeout: float) -> dict:
    """Async fetch of the issuer's .well-known/smart-configuration (never block the loop)."""
    reply = await AsyncHTTPClient().fetch(
        f"{iss.rstrip('/')}/{SMARTConfig.broadcast_path}",
        headers={"Accept": "application/json"},
        request_timeout=timeout,
        follow_redirects=False,
    )
    return json.loads(reply.body.decode("utf8", "replace"))


def config_from_document(cfg: dict, iss: str, base_url: str) -> SMARTConfig:
    """`iss` is kept as this launch sent it: SMART requires `aud` to equal that value."""
    return SMARTConfig(
        base_url=base_url,
        fhir_url=iss,
        token_url=cfg["token_endpoint"],
        auth_url=cfg["authorization_endpoint"],
        smart_config=cfg,
    )


async def cached_discover(handler, fhir_url: str, normalized: str) -> SMARTConfig:
    """SMARTConfig for this launch; the discovery document is reused per normalized
    issuer for discovery_cache_ttl seconds."""
    smart_auth = handler.settings["smart_auth"]
    cache = handler.settings["smart_discovery_cache"]
    store = handler.settings["smart_session_store"]
    now = store.clock()
    hit = cache.get(normalized)
    fresh = hit is not None and hit[0] > now
    if fresh:
        cfg = hit[1]
    else:
        cfg = await fetch_discovery_document(fhir_url, smart_auth.discovery_timeout)
    # Cache only the (usable) document: aud must be each launch's own iss, not the first's.
    config = config_from_document(cfg, fhir_url, handler.request.full_url())
    if not fresh:
        cache[normalized] = (now + smart_auth.discovery_cache_ttl, cfg)
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
    jar = parse_cookie_header(handler.request.headers.get("Cookie"), unique_name=name)
    if jar is None:
        # Session cookie sent twice: tornado verifies the LAST, a kernel might read the FIRST.
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
        except (HTTPClientError, OSError, KeyError, TypeError, ValueError) as e:
            self.log.error("SMART discovery failed for %s: %s", fhir_url, e)
            raise web.HTTPError(502, "Could not read the EHR's SMART configuration")
        # A launch always starts a new session (defeats session fixation); drop any old one.
        old, _ = resolve_session(self)
        if old is not None:
            store.delete(old.session_id)
        # evicts the oldest pending at capacity
        session = store.create(fhir_url, smart_config)
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
    """Builds the EHR authorize URL with state/PKCE stored on this browser's session."""

    @allow_unauthenticated
    def get(self):
        require_jupyter_user_unless_smart_idp(self)
        store = self.settings["smart_session_store"]
        session = require_session(self)
        state = generate_state(get_next_url(self))
        store.set_oauth_state(session.session_id, state)
        if state["next_url"]:
            self.log.info("Will redirect to %s after SMART login", state["next_url"])

        smart_config = session.smart_config
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
        self.redirect(url_concat(smart_config.auth_url, oauth_params))


class SMARTCallbackHandler(JupyterHandler):
    """OAuth redirect target: validates state against this browser's session only."""

    async def token_for_code(
        self, code: str, code_verifier: str, token_url: str
    ) -> dict:
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
                token_url, body=urlencode(data), headers=headers, method="POST"
            )
        except HTTPClientError as e:
            # e.response is None on timeouts/connection errors; never dereference blindly
            body = (
                e.response.body.decode("utf8", "replace")
                if e.response is not None
                else ""
            )
            self.log.error("Error fetching token (%s): %s", e.code, body[:500])
            raise
        try:
            token_response = json.loads(token_reply.body.decode("utf8", "replace"))
        except ValueError:
            token_response = None
        if not isinstance(token_response, dict):
            raise SMARTSessionError("Token response is not a JSON object")
        return token_response

    @allow_unauthenticated
    async def get(self):
        require_jupyter_user_unless_smart_idp(self)
        store = self.settings["smart_session_store"]
        session = require_session(self)
        # SMART: validate state on EVERY request to the redirect URL, error responses included.
        arg_state = self.get_argument("state", "")
        if not arg_state:
            raise web.HTTPError(400, "Error: missing state query argument")
        if not session.state_id or arg_state != session.state_id:
            raise web.HTTPError(
                400,
                "Error: state received from FHIR server does not match this session",
            )
        if "error" in self.request.arguments:
            detail = self.get_argument("error_description", "") or self.get_argument(
                "error"
            )
            raise web.HTTPError(400, f"The EHR refused the launch: {detail}")
        code = self.get_argument("code", "")
        if not code:
            raise web.HTTPError(400, "Error: no code in response from FHIR server")

        # Consume state before awaiting: a concurrent replay must not reach the EHR too.
        code_verifier = session.code_verifier
        session.state_id = None
        session.code_verifier = None
        try:
            token_response = await self.token_for_code(
                code, code_verifier, session.smart_config.token_url
            )
            session = store.complete(session.session_id, token_response)
        except (HTTPClientError, OSError, SMARTSessionError) as e:
            self.log.error(
                "SMART token exchange failed for session %s: %s",
                session.session_id[:8],
                e,
            )
            raise web.HTTPError(
                502, "Could not obtain a token from the EHR. Relaunch from the EHR."
            )
        self.log.info("SMART session %s authenticated", session.session_id[:8])

        smart_auth = self.settings["smart_auth"]
        if smart_auth.persist_global_token and not is_smart_idp(self):
            # Hub mode only: one server per user makes the shared file per-user.
            with Path(smart_auth.token_file).open("w") as f:
                json.dump(
                    {
                        "token": token_response,
                        "fhir_url": session.fhir_url,
                        "smart_config": session.smart_config.smart_config,
                    },
                    f,
                    sort_keys=True,
                    indent=1,
                )
            os.environ["SMART_TOKEN"] = token_response["access_token"]

        redirected = False
        hook = smart_auth.smart_callback_hook
        if hook:
            redirected = await hook(
                token_response=token_response,
                smart_config=session.smart_config,
                handler=self,
            )
        if not redirected:
            # naming the session makes a frame now holding a different cookie fail closed
            dest = url_concat(
                session.next_url or self.base_url, {"smart_session": session.session_id}
            )
            self.redirect(dest)


NOT_LAUNCHED_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>Not launched</title></head><body style="font-family:sans-serif;margin:3rem">
<h1>This app must be opened from your EHR.</h1>
<p>Open the patient chart in your EHR and launch the app from there. There is no
separate login.</p></body></html>"""


class SMARTNotLaunchedHandler(JupyterHandler):
    """Stands in for /login: the only way in is an EHR launch, so this is a 403 page."""

    @allow_unauthenticated
    def get(self):
        self.set_status(403)
        self.set_header("Content-Type", "text/html; charset=utf-8")
        self.finish(NOT_LAUNCHED_HTML)


class SMARTSessionInfoHandler(JupyterHandler):
    """Cheap authenticated probe: lets a page confirm its cookie works and tests
    confirm identity without going through the authorizer-guarded API."""

    @web.authenticated
    def get(self):
        session, _ = resolve_session(self)
        if session is None:
            # Hub/default provider: a logged-in user need not hold a SMART session.
            raise web.HTTPError(403)
        self.set_header("Content-Type", "application/json")
        self.finish(
            json.dumps(
                {"session": session.session_id[:12], "expires_at": session.expires_at}
            )
        )


class SMARTIdentityProvider(IdentityProvider):
    """Standalone-server identity: a user exists only for a browser whose session was
    minted by an EHR launch on this server and has completed the OAuth callback.

    Configure with
    `c.ServerApp.identity_provider_class = "jupyter_smart_on_fhir.server_extension.SMARTIdentityProvider"`
    together with SMARTAuthorizer and a non-empty allowed_issuers. Do not use under
    JupyterHub (Hub's provider stays in charge there).
    """

    @default("login_handler_class")
    def _login_handler_class_default(self):
        return SMARTNotLaunchedHandler

    def get_user(self, handler):
        store = handler.settings.get("smart_session_store")
        session, reason = resolve_session(handler)
        if reason != "ok" or store is None or not store.is_authenticated(session):
            return None
        # A render URL names its session; a frame whose cookie now belongs to another
        # launch must fail closed rather than show that other patient.
        wanted = handler.get_arguments("smart_session")
        # A crafted next_url may carry its own smart_session, so every value must match.
        if len(wanted) > 1 or (wanted and wanted[0] != session.session_id):
            handler.log.warning(
                "smart_session query arg does not match the cookie's session"
            )
            return None
        return User(username=f"smart-{session.session_id[:12]}")

    def clear_login_cookie(self, handler):
        session, _ = resolve_session(handler)
        if session is not None:
            handler.settings["smart_session_store"].delete(session.session_id)
        clear_session_cookie(handler)


def clear_session_cookie(handler) -> None:
    """Deletion must carry the same attributes as the set (Secure/SameSite/Partitioned),
    or the browser keeps the partitioned cookie."""
    smart_auth = handler.settings["smart_auth"]
    secure = smart_auth.cookie_secure
    if secure is None:
        secure = handler.request.protocol == "https"
    header = f"{smart_auth.cookie_name}=; Path={handler.base_url}; Max-Age=0; HttpOnly"
    header += "; Secure; SameSite=None" if secure else "; SameSite=Lax"
    if secure and smart_auth.cookie_partitioned:
        header += "; Partitioned"
    handler.add_header("Set-Cookie", header)


def kernel_session_id(handler, kernel_id: str) -> str | None:
    """Session that started this kernel, read from the Cookie header Voilà put in its env."""
    try:
        km = handler.kernel_manager.get_kernel(kernel_id)
    except Exception:
        return None
    env = (getattr(km, "_launch_args", None) or {}).get("env") or {}
    return session_id_from_cookie_header(
        env.get("HTTP_COOKIE"),
        handler.settings.get("smart_session_cookie_name", SESSION_COOKIE_NAME),
    )


class SMARTAuthorizer(Authorizer):
    """A SMART session may only talk to the kernel Voilà started for it. Everything
    else in the Jupyter API (contents, terminals, sessions, kernel listing/creation,
    kernelspecs, config, ...) is denied. Voilà's render and shutdown routes are not
    authorizer-guarded, so rendering is unaffected."""

    def is_authorized(self, handler, user, action, resource):
        if resource != "kernels" or action not in ("execute", "read"):
            return False
        kernel_id = (
            handler.path_kwargs.get("kernel_id") if handler.path_kwargs else None
        )
        if not kernel_id and handler.path_args:
            kernel_id = handler.path_args[0]
        if not kernel_id:
            return False  # kernel listing
        session, _ = resolve_session(handler)
        if session is None:
            return False
        return kernel_session_id(handler, kernel_id) == session.session_id


if __name__ == "__main__":
    SMARTExtensionApp.launch_instance()
