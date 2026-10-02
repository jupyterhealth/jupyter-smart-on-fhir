"""Per-browser SMART sessions.

OAuth state, the PKCE verifier and the token are keyed by a session id that lives in a
signed cookie. This module has no tornado/requests imports so notebook kernels can use
the read-side helpers at the bottom of the file.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SESSION_COOKIE_NAME = "smart-session"
TOKEN_DIR_ENV = "SMART_TOKEN_DIR"
COOKIE_NAME_ENV = "SMART_COOKIE_NAME"
COOKIE_HEADER_ENV = "HTTP_COOKIE"
SAFE_SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class SMARTSessionError(Exception):
    """Raised when a session is unknown or expired, or unresolvable in a kernel."""


@dataclass
class SMARTSession:
    session_id: str
    fhir_url: str
    smart_config: Any  # SMARTConfig; typed Any to keep this module free of auth.py's requests import
    created: float
    expires_at: float
    state_id: str | None = None
    code_verifier: str | None = None
    next_url: str | None = None
    token: dict[str, Any] | None = None


class SMARTSessionStore:
    """In-memory sessions plus one 0600 token file per session for kernels to read."""

    def __init__(
        self,
        token_dir: str | os.PathLike,
        pending_lifetime: int = 600,
        session_lifetime: int = 3600,
        max_pending: int = 500,
        clock: Callable[[], float] = time.time,
    ):
        self.token_dir = Path(token_dir)
        self.token_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.token_dir, 0o700)
        self.pending_lifetime = pending_lifetime
        self.session_lifetime = session_lifetime
        self.max_pending = max_pending
        self.clock = clock
        self._sessions: dict[str, SMARTSession] = {}

    def create(self, fhir_url: str, smart_config: Any) -> SMARTSession:
        self.purge_expired()
        # Anonymous launches must never lock clinicians out: at capacity, evict the
        # oldest launch that has not completed its callback instead of refusing.
        pending = sorted(
            (sess for sess in self._sessions.values() if sess.token is None),
            key=lambda sess: sess.created,
        )
        while pending and len(pending) >= max(self.max_pending, 1):
            self.delete(pending.pop(0).session_id)
        now = self.clock()
        sess = SMARTSession(
            session_id=secrets.token_urlsafe(32),
            fhir_url=fhir_url,
            smart_config=smart_config,
            created=now,
            expires_at=now + self.pending_lifetime,
        )
        self._sessions[sess.session_id] = sess
        return sess

    def get(self, session_id: str | None) -> SMARTSession | None:
        self.purge_expired()
        if not session_id:
            return None
        return self._sessions.get(session_id)

    def is_authenticated(self, sess: SMARTSession | None) -> bool:
        return (
            sess is not None
            and sess.token is not None
            and self.clock() < sess.expires_at
        )

    def set_oauth_state(self, session_id: str, state: dict[str, Any]) -> SMARTSession:
        sess = self._require(session_id)
        sess.state_id = state["state_id"]
        sess.code_verifier = state["code_verifier"]
        sess.next_url = state.get("next_url")
        return sess

    def complete(self, session_id: str, token_response: dict[str, Any]) -> SMARTSession:
        sess = self._require(session_id)
        # A 2xx body is not a token: SMART requires a bearer access_token.
        if not token_response.get("access_token"):
            raise SMARTSessionError("Token response has no access_token")
        if str(token_response.get("token_type", "")).lower() != "bearer":
            raise SMARTSessionError("Token response token_type is not bearer")
        lifetime = self.session_lifetime
        expires_in = token_response.get("expires_in")
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            lifetime = min(lifetime, int(expires_in))
        expires_at = self.clock() + lifetime
        smart_config = getattr(sess.smart_config, "smart_config", sess.smart_config)
        payload = {
            "token": token_response,
            "fhir_url": sess.fhir_url,
            "smart_config": smart_config,
            "expires_at": expires_at,
        }
        # File first: a failed write must leave the session pending, not half-authenticated.
        self._write_token_file(session_id, payload)
        sess.token = token_response
        sess.expires_at = expires_at
        # state is single-use: a replayed callback must not re-mint a token
        sess.state_id = None
        sess.code_verifier = None
        return sess

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        try:
            self.token_file(session_id).unlink()
        except (FileNotFoundError, SMARTSessionError):
            pass

    def purge_expired(self) -> int:
        now = self.clock()
        expired = [
            sid for sid, sess in self._sessions.items() if now >= sess.expires_at
        ]
        for sid in expired:
            self.delete(sid)
        return len(expired)

    def wipe(self) -> None:
        """Remove every token file on disk (server startup: no session survives a restart)."""
        self._sessions.clear()
        for path in self.token_dir.iterdir():
            # Only our own files: <id>.json, or .<id>.<hex>.tmp from a write cut short by a crash.
            if not path.is_file() or path.is_symlink():
                continue
            if _is_token_file_name(path.name):
                path.unlink(missing_ok=True)

    def token_file(self, session_id: str) -> Path:
        if not SAFE_SESSION_ID.match(session_id or ""):
            raise SMARTSessionError("Invalid SMART session id")
        return self.token_dir / f"{session_id}.json"

    def _require(self, session_id: str) -> SMARTSession:
        sess = self.get(session_id)
        if sess is None:
            raise SMARTSessionError("Unknown or expired SMART session")
        return sess

    def _write_token_file(self, session_id: str, payload: dict[str, Any]) -> None:
        path = self.token_file(session_id)
        # Temp name is not *.json so readers never see a partial token file.
        tmp = self.token_dir / f".{session_id}.{secrets.token_hex(8)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, sort_keys=True, indent=1)
            os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise


_TMP_FILE_NAME = re.compile(r"^\.([A-Za-z0-9_-]{16,128})\.[0-9a-f]+\.tmp$")


def _is_token_file_name(name: str) -> bool:
    if name.endswith(".json"):
        return bool(SAFE_SESSION_ID.match(name[: -len(".json")]))
    return bool(_TMP_FILE_NAME.match(name))


# --- kernel-side helpers (no server objects available here) -------------------------


def parse_cookie_header(
    header: str | None, unique_name: str | None = None
) -> dict[str, str] | None:
    """Lenient Cookie-header parse matching tornado.httputil.parse_cookie: a malformed
    sibling cookie must not hide the session cookie (http.cookies.SimpleCookie would).

    Returns None if `unique_name` appears more than once: tornado keeps the last value
    and a naive reader the first, and for the session cookie that disagreement is
    exploitable, so refuse outright. Any other repeated name keeps its FIRST value here
    (tornado keeps the last); only the session cookie's uniqueness matters."""
    jar: dict[str, str] = {}
    if not header:
        return jar
    for chunk in header.split(";"):
        if "=" not in chunk:
            continue
        key, _, val = chunk.partition("=")
        key, val = key.strip(), val.strip()
        if not key:
            continue
        if key in jar:
            if key == unique_name:
                return None
            continue
        if len(val) >= 2 and val[0] == val[-1] == '"':
            val = val[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        jar[key] = val
    return jar


def session_id_from_signed_value(value: str | None, cookie_name: str) -> str | None:
    """Session id from a tornado v2 signed cookie value, without verifying the signature.

    A kernel only exists because the server already verified this exact cookie, so the
    kernel just needs the id back out. Only the signed form is accepted, and the name
    embedded in it must be the session cookie's, so a stray bare value cannot steer a
    kernel to another session's file.
    """
    if not value or "|" not in value:
        return None
    parts = value.split("|")
    # v2 layout: 2|<key_version>|<len>:<timestamp>|<len>:<name>|<len>:<b64 value>|<signature>
    if len(parts) != 6 or parts[0] != "2":
        return None
    try:
        _, name = parts[3].split(":", 1)
        _, b64 = parts[4].split(":", 1)
        sid = base64.b64decode(b64).decode("utf8")
    except Exception:
        return None
    if name != cookie_name or not SAFE_SESSION_ID.match(sid):
        return None
    return sid


def session_id_from_cookie_header(
    header: str | None, cookie_name: str = SESSION_COOKIE_NAME
) -> str | None:
    jar = parse_cookie_header(header, unique_name=cookie_name)
    if not jar:
        return None
    return session_id_from_signed_value(jar.get(cookie_name), cookie_name)


def current_token_file(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    token_dir = env.get(TOKEN_DIR_ENV)
    if not token_dir:
        raise SMARTSessionError(
            f"{TOKEN_DIR_ENV} is not set; is the jupyter_smart_on_fhir server extension loaded?"
        )
    sid = session_id_from_cookie_header(
        env.get(COOKIE_HEADER_ENV), env.get(COOKIE_NAME_ENV, SESSION_COOKIE_NAME)
    )
    if not sid:
        raise SMARTSessionError(
            "No SMART session cookie reached this kernel. Set "
            "c.VoilaConfiguration.http_header_envs = ['Cookie'] and open the app from the EHR. "
            "(load_token() works only in kernels started by Voilà.)"
        )
    return Path(token_dir) / f"{sid}.json"


def load_token(
    env: Mapping[str, str] | None = None, now: Callable[[], float] = time.time
) -> dict[str, Any]:
    path = current_token_file(env)
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as e:
        raise SMARTSessionError(
            f"No token for this SMART session (expired or not launched): {path.name}"
        ) from e
    expires_at = data.get("expires_at")
    if isinstance(expires_at, (int, float)) and now() >= expires_at:
        raise SMARTSessionError("This SMART session has expired; relaunch from the EHR")
    return data
