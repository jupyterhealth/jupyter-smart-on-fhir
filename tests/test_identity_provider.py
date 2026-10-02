"""With SMARTIdentityProvider, only a browser holding an authenticated session is a user:
page handlers redirect to /login (a 403 page), API handlers 403 directly."""

import asyncio
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlparse

import pytest
from tornado.httpclient import HTTPRequest
from tornado.simple_httpclient import SimpleAsyncHTTPClient
from tornado.web import create_signed_value
from traitlets.config import Config

from jupyter_smart_on_fhir import server_extension as ext
from jupyter_smart_on_fhir import session as s
from jupyter_smart_on_fhir.server_extension import (
    SMARTAuthorizer,
    SMARTCallbackHandler,
    SMARTIdentityProvider,
    callback_path,
    launch_path,
    login_path,
    session_path,
)

ISS = "https://ehr.example/fhir"
COOKIE = "smart-session"


@pytest.fixture
def jp_server_config(tmp_path):
    c = Config()
    c.ServerApp.jpserver_extensions = {"jupyter_smart_on_fhir.server_extension": True}
    c.ServerApp.identity_provider_class = SMARTIdentityProvider
    c.ServerApp.authorizer_class = SMARTAuthorizer
    c.ServerApp.allow_unauthenticated_access = False
    c.ServerApp.disable_check_xsrf = True
    c.SMARTExtensionApp.client_id = "client-123"
    c.SMARTExtensionApp.allowed_issuers = [ISS]
    c.SMARTExtensionApp.token_dir = str(tmp_path / "sessions")
    c.SMARTExtensionApp.token_file = str(tmp_path / "legacy.json")
    return c


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    async def fetch_discovery_document(iss, timeout):
        return {
            "token_endpoint": "https://ehr.example/token",
            "authorization_endpoint": "https://ehr.example/authorize",
        }

    async def token_for_code(self, code, code_verifier, token_url):
        return {
            "access_token": "AT",
            "token_type": "Bearer",
            "id_token": "IDT",
            "patient": "P1",
            "expires_in": 900,
        }

    monkeypatch.setattr(ext, "fetch_discovery_document", fetch_discovery_document)
    monkeypatch.setattr(SMARTCallbackHandler, "token_for_code", token_for_code)


@pytest.fixture(autouse=True)
def follow_redirects(http_server_client, monkeypatch):
    # pytest_jupyter's client re-wraps the HTTPRequest tornado passes when following a
    # redirect into a URL, so the fetch never resolves; pass HTTPRequest straight through.
    wrapped = http_server_client.fetch

    def fetch(path, **kwargs):
        if isinstance(path, HTTPRequest):
            return SimpleAsyncHTTPClient.fetch(http_server_client, path, **kwargs)
        return wrapped(path, **kwargs)

    monkeypatch.setattr(http_server_client, "fetch", fetch)


def cookie_header(response) -> str:
    hits = [
        h for h in response.headers.get_list("Set-Cookie") if h.startswith(f"{COOKIE}=")
    ]
    assert len(hits) == 1
    jar = SimpleCookie()
    jar.load(hits[0])
    return f"{COOKIE}={jar[COOKIE].coded_value}"


async def complete_launch(jp_fetch) -> str:
    """Run launch→login→callback; return the authenticated browser's Cookie header."""
    l = await jp_fetch(
        launch_path,
        params={"iss": ISS, "launch": "L1"},
        follow_redirects=False,
        raise_error=False,
    )
    assert l.code == 302, l.body
    cookie = cookie_header(l)
    q = dict(parse_qsl(urlparse(l.headers["Location"]).query))
    lg = await jp_fetch(
        login_path,
        params=q,
        headers={"Cookie": cookie},
        follow_redirects=False,
        raise_error=False,
    )
    assert lg.code == 302, lg.body
    state = dict(parse_qsl(urlparse(lg.headers["Location"]).query))["state"]
    cb = await jp_fetch(
        callback_path,
        params={"code": "C1", "state": state},
        headers={"Cookie": cookie},
        follow_redirects=False,
        raise_error=False,
    )
    assert cb.code == 302, cb.body
    return cookie


async def test_session_info_without_session_is_403(jp_fetch):
    r = await jp_fetch(session_path, raise_error=False)
    assert r.code == 403


async def test_page_without_session_redirects_to_login_which_is_403(jp_fetch):
    r = await jp_fetch("tree", follow_redirects=False, raise_error=False)
    assert r.code == 302 and "/login" in r.headers["Location"]
    r = await jp_fetch("login", raise_error=False)
    assert r.code == 403
    assert "must be opened from your EHR" in r.body.decode()


async def test_session_info_with_authenticated_session_is_200(jp_fetch, jp_serverapp):
    cookie = await complete_launch(jp_fetch)
    r = await jp_fetch(session_path, headers={"Cookie": cookie}, raise_error=False)
    assert r.code == 200
    body = r.body.decode()
    sid = s.session_id_from_cookie_header(cookie)
    assert sid[:12] in body and "expires_at" in body


async def test_pending_session_is_not_a_user(jp_fetch):
    l = await jp_fetch(
        launch_path,
        params={"iss": ISS, "launch": "L1"},
        follow_redirects=False,
        raise_error=False,
    )
    r = await jp_fetch(
        session_path, headers={"Cookie": cookie_header(l)}, raise_error=False
    )
    assert r.code == 403


async def test_unsigned_cookie_is_refused(jp_fetch, jp_serverapp):
    cookie = await complete_launch(jp_fetch)
    sid = s.session_id_from_cookie_header(cookie)
    assert jp_serverapp.web_app.settings["smart_session_store"].get(sid) is not None
    r = await jp_fetch(
        session_path, headers={"Cookie": f"{COOKIE}={sid}"}, raise_error=False
    )
    assert r.code == 403


async def test_duplicate_session_cookie_is_refused(jp_fetch):
    cookie = await complete_launch(jp_fetch)
    r = await jp_fetch(
        session_path,
        headers={"Cookie": f"{COOKIE}={'z' * 32}; {cookie}"},
        raise_error=False,
    )
    assert r.code == 403


async def test_logout_clears_cookie_with_matching_attributes(jp_fetch):
    cookie = await complete_launch(jp_fetch)
    r = await jp_fetch("logout", headers={"Cookie": cookie}, raise_error=False)
    deletions = [
        h for h in r.headers.get_list("Set-Cookie") if h.startswith(f"{COOKIE}=;")
    ]
    assert (
        len(deletions) == 1
        and "Max-Age=0" in deletions[0]
        and "SameSite=Lax" in deletions[0]
    )
    assert "HttpOnly" in deletions[0] and "Path=/" in deletions[0]


async def test_session_query_arg_mismatch_is_refused(jp_fetch):
    cookie = await complete_launch(jp_fetch)
    sid = s.session_id_from_cookie_header(cookie)
    ok = await jp_fetch(
        session_path,
        params={"smart_session": sid},
        headers={"Cookie": cookie},
        raise_error=False,
    )
    assert ok.code == 200
    other = await jp_fetch(
        session_path,
        params={"smart_session": "q" * 32},
        headers={"Cookie": cookie},
        raise_error=False,
    )
    assert other.code == 403  # a frame for another session fails closed


async def test_duplicate_session_query_arg_is_refused(jp_fetch):
    cookie = await complete_launch(jp_fetch)
    sid = s.session_id_from_cookie_header(cookie)
    params = [("smart_session", "q" * 32), ("smart_session", sid)]
    r = await jp_fetch(
        session_path, params=params, headers={"Cookie": cookie}, raise_error=False
    )
    assert (
        r.code == 403
    )  # a crafted next_url value must not be bypassed by ours appended after it


async def test_expired_session_is_refused_and_file_removed(jp_fetch, jp_serverapp):
    cookie = await complete_launch(jp_fetch)
    store = jp_serverapp.web_app.settings["smart_session_store"]
    sid = s.session_id_from_cookie_header(cookie)
    path = store.token_file(sid)
    assert path.exists()
    assert (
        await jp_fetch(session_path, headers={"Cookie": cookie}, raise_error=False)
    ).code == 200
    exp = store._sessions[sid].expires_at  # capture BEFORE swapping the clock
    store.clock = lambda: exp + 1
    r = await jp_fetch(session_path, headers={"Cookie": cookie}, raise_error=False)
    assert r.code == 403
    assert not path.exists()


async def test_logout_ends_session(jp_fetch, jp_serverapp):
    cookie = await complete_launch(jp_fetch)
    sid = s.session_id_from_cookie_header(cookie)
    r = await jp_fetch("logout", headers={"Cookie": cookie}, raise_error=False)
    assert r.code == 200
    assert jp_serverapp.web_app.settings["smart_session_store"].get(sid) is None


async def test_authorizer_denies_api_surfaces_even_with_session(jp_fetch):
    cookie = await complete_launch(jp_fetch)
    for path in (
        ("api", "kernels"),
        ("api", "contents"),
        ("api", "sessions"),
        ("api", "kernelspecs"),
    ):
        r = await jp_fetch(*path, headers={"Cookie": cookie}, raise_error=False)
        assert r.code == 403, path
    r = await jp_fetch(
        "api",
        "kernels",
        method="POST",
        body="{}",
        headers={"Cookie": cookie},
        raise_error=False,
    )
    assert r.code == 403
    r = await jp_fetch(
        "api", "terminals", headers={"Cookie": cookie}, raise_error=False
    )
    assert r.code in (403, 404)  # 404 when the terminals extension is not installed


async def test_cookie_signed_with_another_secret_is_refused(jp_fetch):
    cookie = await complete_launch(jp_fetch)
    sid = s.session_id_from_cookie_header(cookie)
    jar = SimpleCookie()
    jar[COOKIE] = create_signed_value("other-secret", COOKIE, sid).decode()
    r = await jp_fetch(
        session_path,
        headers={"Cookie": f"{COOKIE}={jar[COOKIE].coded_value}"},
        raise_error=False,
    )
    assert r.code == 403


async def test_relaunch_shuts_down_kernels_of_the_ended_session(
    jp_fetch, jp_serverapp, monkeypatch
):
    first = await complete_launch(jp_fetch)
    other = await complete_launch(jp_fetch)

    class FakeKernel:
        def __init__(self, cookie):
            self._launch_args = {"env": {"HTTP_COOKIE": cookie}}

    class FakeKernelManager:
        kernels = {"k-first": FakeKernel(first), "k-other": FakeKernel(other)}
        shut_down = []

        def list_kernel_ids(self):
            return list(self.kernels)

        def get_kernel(self, kid):
            return self.kernels[kid]

        async def shutdown_kernel(self, kid, now=False):
            self.shut_down.append((kid, now))

    fake = FakeKernelManager()
    monkeypatch.setattr(jp_serverapp, "kernel_manager", fake)
    r = await jp_fetch(
        launch_path,
        params={"iss": ISS, "launch": "L2"},
        headers={"Cookie": first},
        follow_redirects=False,
        raise_error=False,
    )
    assert r.code == 302
    await asyncio.sleep(0)  # let the scheduled shutdown task run
    assert fake.shut_down == [("k-first", True)]
