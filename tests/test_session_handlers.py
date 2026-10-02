"""Launch/login/callback with per-browser sessions, configured as the template deploys
them (SMARTIdentityProvider, allow_unauthenticated_access=False). Discovery and the
token exchange are faked; no SMART sandbox."""

# NOTE: this header has only what Tasks 4 uses; Task 5 adds `parse_qsl`, Task 6 adds
# `json` and `callback_path` (ruff --fix strips unused imports at each commit).
import os
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import pytest
from traitlets.config import Config

from jupyter_smart_on_fhir import server_extension as ext
from jupyter_smart_on_fhir import session as s
from jupyter_smart_on_fhir.auth import SMARTConfig
from jupyter_smart_on_fhir.server_extension import (
    SMARTCallbackHandler,
    SMARTIdentityProvider,
    launch_path,
    login_path,
)

ISS = "https://ehr.example/fhir"
COOKIE = "smart-session"


@pytest.fixture
def jp_server_config(tmp_path):
    c = Config()
    c.ServerApp.jpserver_extensions = {"jupyter_smart_on_fhir.server_extension": True}
    c.ServerApp.identity_provider_class = SMARTIdentityProvider
    c.ServerApp.allow_unauthenticated_access = False
    c.ServerApp.disable_check_xsrf = True
    c.SMARTExtensionApp.client_id = "client-123"
    c.SMARTExtensionApp.allowed_issuers = [ISS]
    c.SMARTExtensionApp.token_dir = str(tmp_path / "sessions")
    c.SMARTExtensionApp.token_file = str(tmp_path / "legacy.json")
    return c


@pytest.fixture(autouse=True)
def fake_discovery(monkeypatch):
    calls = []

    async def discover(iss, base_url, timeout):
        calls.append(iss)
        return SMARTConfig(
            base_url=base_url,
            fhir_url=iss,
            token_url="https://ehr.example/token",
            auth_url="https://ehr.example/authorize",
            smart_config={"token_endpoint": "https://ehr.example/token"},
        )

    monkeypatch.setattr(ext, "discover", discover)
    return calls


@pytest.fixture
def fake_token_exchange(monkeypatch):
    calls = []

    async def token_for_code(self, code, code_verifier, token_url):
        calls.append({"code": code, "code_verifier": code_verifier, "token_url": token_url})
        return {"access_token": f"AT-{code}", "token_type": "Bearer", "id_token": "IDT", "patient": "P1", "expires_in": 900}

    monkeypatch.setattr(SMARTCallbackHandler, "token_for_code", token_for_code)
    return calls


@pytest.fixture(autouse=True)
def _clean_smart_token_env():
    yield
    os.environ.pop("SMART_TOKEN", None)


def session_set_cookie(response) -> str:
    """The raw Set-Cookie header for the session cookie (Jupyter may set others)."""
    hits = [h for h in response.headers.get_list("Set-Cookie") if h.startswith(f"{COOKIE}=")]
    assert len(hits) == 1, response.headers.get_list("Set-Cookie")
    return hits[0]


def cookie_header(response) -> str:
    jar = SimpleCookie()
    jar.load(session_set_cookie(response))
    return f"{COOKIE}={jar[COOKIE].coded_value}"


def store_of(jp_serverapp):
    return jp_serverapp.web_app.settings["smart_session_store"]


async def launch(jp_fetch, iss=ISS, **extra):
    return await jp_fetch(
        launch_path, params={"iss": iss, "launch": "L1", **extra},
        follow_redirects=False, raise_error=False,
    )


# ---- launch -----------------------------------------------------------------------


async def test_launch_creates_session_and_sets_httponly_cookie(jp_fetch, jp_serverapp):
    r = await launch(jp_fetch)
    assert r.code == 302, r.body
    raw = session_set_cookie(r)
    assert "HttpOnly" in raw
    assert f"Path={jp_serverapp.base_url}" in raw
    assert "SameSite=Lax" in raw  # test server is plain http
    assert "Secure" not in raw and "Partitioned" not in raw
    sid = s.session_id_from_cookie_header(cookie_header(r))
    sess = store_of(jp_serverapp).get(sid)
    assert sess is not None and sess.fhir_url == ISS and sess.token is None
    assert urlparse(r.headers["Location"]).path.endswith(login_path)


async def test_launch_rejects_issuer_not_on_allowlist(jp_fetch, fake_discovery):
    r = await launch(jp_fetch, iss="https://attacker.example/fhir")
    assert r.code == 400
    assert "not an allowed EHR issuer" in r.body.decode()
    assert fake_discovery == []  # no outbound request was made
    assert not any(h.startswith(f"{COOKIE}=") for h in r.headers.get_list("Set-Cookie"))


async def test_launch_matches_normalized_issuer_but_keeps_iss_as_sent(jp_fetch, jp_serverapp, fake_discovery):
    # SMART: aud must equal the launch iss *as sent* (Medplum sends a trailing slash);
    # normalization is only for allowlist matching.
    raw = "https://EHR.example/fhir/"
    r = await launch(jp_fetch, iss=raw)
    assert r.code == 302, r.body
    assert fake_discovery == [raw]
    sess = store_of(jp_serverapp).get(s.session_id_from_cookie_header(cookie_header(r)))
    assert sess.fhir_url == raw and sess.smart_config.fhir_url == raw


async def test_launch_discovery_timeout_is_502(jp_fetch, monkeypatch):
    from tornado.httpclient import HTTPClientError

    async def discover(iss, base_url, timeout):
        raise HTTPClientError(599, "Timeout")

    monkeypatch.setattr(ext, "discover", discover)
    r = await launch(jp_fetch)
    assert r.code == 502


async def test_relaunch_replaces_existing_session(jp_fetch, jp_serverapp):
    first = await launch(jp_fetch)
    first_sid = s.session_id_from_cookie_header(cookie_header(first))
    second = await jp_fetch(
        launch_path, params={"iss": ISS, "launch": "L2"},
        headers={"Cookie": cookie_header(first)}, follow_redirects=False, raise_error=False,
    )
    second_sid = s.session_id_from_cookie_header(cookie_header(second))
    assert second_sid != first_sid
    assert store_of(jp_serverapp).get(first_sid) is None  # fixation: old id is dead
    assert store_of(jp_serverapp).get(second_sid) is not None


async def test_launch_at_capacity_evicts_oldest_and_still_works(jp_fetch, jp_serverapp):
    store_of(jp_serverapp).max_pending = 1
    first = await launch(jp_fetch)
    second = await launch(jp_fetch)
    assert first.code == 302 and second.code == 302  # anonymous floods never lock clinicians out
    assert store_of(jp_serverapp).get(s.session_id_from_cookie_header(cookie_header(first))) is None
    assert store_of(jp_serverapp).get(s.session_id_from_cookie_header(cookie_header(second))) is not None


async def test_launch_discovery_is_cached_per_issuer(jp_fetch, fake_discovery):
    assert (await launch(jp_fetch)).code == 302
    assert (await launch(jp_fetch, iss=ISS + "/")).code == 302  # same issuer after normalization
    assert fake_discovery == [ISS]  # one outbound discovery for both launches


async def test_settings_exported_for_kernels_and_startup_wipes_token_dir(jp_serverapp, tmp_path):
    smart_auth = jp_serverapp.web_app.settings["smart_auth"]
    assert os.environ[s.TOKEN_DIR_ENV] == smart_auth.token_dir
    assert jp_serverapp.web_app.settings["smart_session_cookie_name"] == COOKIE
    assert jp_serverapp.web_app.settings["smart_allowed_issuers"] == {ISS}
    assert jp_serverapp.web_app.settings["smart_discovery_cache"] == {}
    assert list(os.scandir(smart_auth.token_dir)) == []
