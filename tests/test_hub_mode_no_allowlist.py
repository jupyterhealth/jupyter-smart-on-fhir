"""Hub mode with NO allowlist configured: the upgrade path for existing Hub deployments.
The Hub login still gates the handlers, so launches proceed and the server only warns.
(Whether this should become mandatory under Hub is Min's call in the PR.)"""

from urllib.parse import urlparse

import pytest
from traitlets.config import Config

from jupyter_smart_on_fhir import server_extension as ext
from jupyter_smart_on_fhir.server_extension import launch_path, login_path

ISS = "https://ehr.example/fhir"


@pytest.fixture
def jp_server_config(tmp_path):
    c = Config()
    c.ServerApp.jpserver_extensions = {"jupyter_smart_on_fhir.server_extension": True}
    c.ServerApp.disable_check_xsrf = True
    c.SMARTExtensionApp.client_id = "client-123"
    c.SMARTExtensionApp.token_dir = str(tmp_path / "sessions")
    c.SMARTExtensionApp.token_file = str(tmp_path / "legacy.json")
    return c


@pytest.fixture(autouse=True)
def fake_discovery(monkeypatch):
    async def fetch_discovery_document(iss, timeout):
        return {
            "token_endpoint": "https://ehr.example/token",
            "authorization_endpoint": "https://ehr.example/authorize",
        }

    monkeypatch.setattr(ext, "fetch_discovery_document", fetch_discovery_document)


async def test_hub_without_allowlist_still_launches_for_logged_in_user(
    jp_fetch, jp_serverapp
):
    assert jp_serverapp.web_app.settings["smart_allowed_issuers"] == set()
    r = await jp_fetch(
        launch_path,
        params={"iss": ISS, "launch": "L1"},
        follow_redirects=False,
        raise_error=False,
    )
    assert r.code == 302 and urlparse(r.headers["Location"]).path.endswith(login_path)
