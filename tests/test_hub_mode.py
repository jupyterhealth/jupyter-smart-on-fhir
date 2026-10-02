"""With a non-SMART identity provider (JupyterHub, or the default token provider), the
launch handlers must still require a logged-in Jupyter user, exactly as 0.1.x did."""

import json
import os
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlparse

import pytest
from jupyter_server.utils import url_path_join
from traitlets.config import Config

from jupyter_smart_on_fhir import server_extension as ext
from jupyter_smart_on_fhir.auth import SMARTConfig
from jupyter_smart_on_fhir.server_extension import SMARTCallbackHandler, callback_path, launch_path, login_path

ISS = "https://ehr.example/fhir"


@pytest.fixture
def jp_server_config(tmp_path):
    c = Config()
    c.ServerApp.jpserver_extensions = {"jupyter_smart_on_fhir.server_extension": True}
    c.ServerApp.disable_check_xsrf = True
    c.SMARTExtensionApp.client_id = "client-123"
    c.SMARTExtensionApp.allowed_issuers = [ISS]
    c.SMARTExtensionApp.token_dir = str(tmp_path / "sessions")
    c.SMARTExtensionApp.token_file = str(tmp_path / "legacy.json")
    c.SMARTExtensionApp.persist_global_token = True
    return c


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    async def discover(iss, base_url, timeout):
        return SMARTConfig(base_url=base_url, fhir_url=iss, token_url="https://ehr.example/token",
                           auth_url="https://ehr.example/authorize", smart_config={})

    async def token_for_code(self, code, code_verifier, token_url):
        return {"access_token": "AT-HUB", "token_type": "Bearer", "id_token": "IDT", "patient": "P1", "expires_in": 900}

    monkeypatch.setattr(ext, "discover", discover)
    monkeypatch.setattr(SMARTCallbackHandler, "token_for_code", token_for_code)
    yield
    os.environ.pop("SMART_TOKEN", None)


async def test_launch_requires_jupyter_user_under_default_idp(jp_serverapp, http_server_client, jp_base_url):
    # Bound test client, but NO Authorization token and no cookie: an anonymous visitor
    # hitting /user/<owner>/smart-on-fhir/launch directly on a Hub user server.
    path = url_path_join(jp_base_url, launch_path) + f"?iss={ISS}&launch=L1"
    r = await http_server_client.fetch(path, follow_redirects=False, raise_error=False)
    assert r.code == 302
    assert urlparse(r.headers["Location"]).path == url_path_join(jp_base_url, "login")


async def test_hub_mode_enforces_allowlist_when_set(jp_fetch):
    r = await jp_fetch(launch_path, params={"iss": "https://attacker.example/fhir", "launch": "L1"},
                       follow_redirects=False, raise_error=False)
    assert r.code == 400 and "not an allowed EHR issuer" in r.body.decode()


async def test_launch_proceeds_for_logged_in_jupyter_user(jp_fetch):
    r = await jp_fetch(launch_path, params={"iss": ISS, "launch": "L1"}, follow_redirects=False, raise_error=False)
    assert r.code == 302
    assert urlparse(r.headers["Location"]).path.endswith(login_path)


async def test_hub_mode_persists_global_token_for_logged_in_user(jp_fetch, jp_serverapp, tmp_path):
    l = await jp_fetch(launch_path, params={"iss": ISS, "launch": "L1"}, follow_redirects=False, raise_error=False)
    jar = SimpleCookie()
    for h in l.headers.get_list("Set-Cookie"):
        jar.load(h)
    cookie = "; ".join(f"{m.key}={m.coded_value}" for m in jar.values())
    q = dict(parse_qsl(urlparse(l.headers["Location"]).query))
    lg = await jp_fetch(login_path, params=q, headers={"Cookie": cookie}, follow_redirects=False, raise_error=False)
    assert lg.code == 302, lg.body
    state = dict(parse_qsl(urlparse(lg.headers["Location"]).query))["state"]
    cb = await jp_fetch(callback_path, params={"code": "C1", "state": state}, headers={"Cookie": cookie},
                        follow_redirects=False, raise_error=False)
    assert cb.code == 302, cb.body
    assert json.loads((tmp_path / "legacy.json").read_text())["token"]["access_token"] == "AT-HUB"
    assert os.environ["SMART_TOKEN"] == "AT-HUB"
    assert os.environ["SMART_TOKEN_FILE"] == str(tmp_path / "legacy.json")
