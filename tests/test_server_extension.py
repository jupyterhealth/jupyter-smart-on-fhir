import json
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlparse, urlunparse

import pytest
from conftest import SandboxConfig
from jupyter_server.utils import url_path_join
from tornado.httpclient import AsyncHTTPClient, HTTPClientError
from traitlets.config import Config

from jupyter_smart_on_fhir.server_extension import (
    callback_path,
    launch_path,
    login_path,
)


@pytest.fixture
def client_id():
    return "client_id"


@pytest.fixture
def jp_server_config(client_id):
    c = Config()
    c.ServerApp.jpserver_extensions = {"jupyter_smart_on_fhir.server_extension": True}
    c.SMARTExtensionApp.client_id = client_id
    c.SMARTExtensionApp.allowed_issuers = ["http://localhost:5555/v/r4/fhir"]
    c.ServerApp.disable_check_xsrf = True

    return c


async def test_uninformed_endpoint(jp_fetch):
    with pytest.raises(HTTPClientError) as e:
        await jp_fetch(launch_path)
    assert e.value.code == 400


@pytest.fixture
def public_client(client_id):
    return SandboxConfig(
        client_id=client_id,
        client_type=0,
        pkce_validation=2,
        # setting IDs so we omit login screen in sandbox; unsure I would test that flow
        patient_ids=["6bb97c2b-8762-4763-ad16-2d88db590b74"],
        provider_ids=["63003abb-3924-46df-a75a-0a1f42733189"],
    )


async def test_login_handler(
    http_server_client, jp_base_url, jp_fetch, jp_serverapp, sandbox, public_client
):
    """I think this test can be split in three with some engineering. Perhaps useful, not sure"""
    # Try endpoint and get redirected to login
    next_path = url_path_join("/test-next?a=b&c=d")
    query = {
        "iss": f"{sandbox}/v/r4/fhir",
        "launch": public_client.get_launch_code(),
        "next": next_path,
    }
    with pytest.raises(HTTPClientError) as exc_info:
        response = await jp_fetch(
            launch_path,
            params=query,
            follow_redirects=False,
        )
    response = exc_info.value.response
    assert response.code == 302
    cookie = SimpleCookie()
    for c in response.headers.get_list("Set-Cookie"):
        cookie.load(c)
    cookie_header = "; ".join(
        f"{morsel.key}={morsel.coded_value}" for morsel in cookie.values()
    )
    redirect_url = response.headers["Location"]
    redirect = urlparse(redirect_url)
    assert redirect.path == url_path_join(jp_base_url, login_path)
    login_query = dict(parse_qsl(redirect.query))

    assert login_query["launch"] == query["launch"]
    assert "scope" in login_query

    # Login with headers and get redirected to auth url
    with pytest.raises(HTTPClientError) as exc_info:
        response = await jp_fetch(
            login_path,
            params=login_query,
            headers={"Cookie": cookie_header},
            follow_redirects=False,
        )
    response = exc_info.value.response
    assert response.code == 302
    auth_url = response.headers["Location"]
    assert auth_url.startswith(sandbox)

    # Internally, get redirected to provider-auth
    with pytest.raises(HTTPClientError) as exc_info:
        http_client = AsyncHTTPClient()
        response = await http_client.fetch(auth_url, follow_redirects=False)
    response = exc_info.value.response
    assert response.code == 302
    callback_url = response.headers["Location"]
    callback_url_parsed = urlparse(callback_url)
    # strip proto://host for jp_fetch
    server_callback_url = urlunparse(callback_url_parsed._replace(netloc="", scheme=""))
    params = dict(parse_qsl(callback_url_parsed.query))
    # SMART does different URL escaping
    # SMART dev server appears to do some weird unescaping with callback URL
    server_callback_url = server_callback_url.replace("@", "%40")
    assert server_callback_url.startswith(url_path_join(jp_base_url, callback_path))
    assert "code" in params

    with pytest.raises(HTTPClientError) as exc_info:
        await jp_fetch(
            callback_path,
            params=params,
            headers={"Cookie": cookie_header},
            follow_redirects=False,
        )
    response = exc_info.value.response
    assert response.code == 302
    dest_url = response.headers["Location"]

    dest = urlparse(dest_url)
    assert dest.path == urlparse(url_path_join(jp_base_url, next_path)).path
    dest_query = {k: v for k, v in parse_qsl(dest.query) if k != "smart_session"}
    assert dest_query == dict(parse_qsl(urlparse(next_path).query))
    assert "smart_session" in dict(parse_qsl(dest.query))

    from jupyter_smart_on_fhir import session as s

    store = jp_serverapp.web_app.settings["smart_session_store"]
    sess = store.get(s.session_id_from_cookie_header(cookie_header))
    assert sess is not None and store.is_authenticated(sess)
    token = sess.token["access_token"]
    smart_config = sess.smart_config
    url = url_path_join(smart_config.fhir_url, "Condition")
    resp = await http_client.fetch(url, headers={"Authorization": f"Bearer {token}"})
    data = json.loads(resp.body.decode("utf8"))
    assert data
    assert isinstance(data, dict)
    assert "resourceType" in data
    assert data["resourceType"] == "Bundle"
