import json
import os
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlparse, urlunparse

import pytest
from jupyter_server.utils import url_path_join
from tornado.httpclient import AsyncHTTPClient, HTTPClientError
from traitlets.config import Config

from jupyter_smart_on_fhir.server_extension import (
    SMARTIdentityProvider,
    callback_path,
    launch_path,
    login_path,
)


@pytest.fixture
def jp_server_config(client_id):
    c = Config()
    c.ServerApp.identity_provider_class = (
        "jupyter_smart_on_fhir.server_extension.SMARTIdentityProvider"
    )
    c.ServerApp.jpserver_extensions = {"jupyter_smart_on_fhir.server_extension": True}
    c.SMARTExtensionApp.client_id = client_id

    return c


async def test_smart_launch(
    http_server_client, jp_base_url, fetch_noauth, jp_serverapp, sandbox, public_client
):
    # Try endpoint and get redirected to login
    assert type(jp_serverapp.identity_provider) is SMARTIdentityProvider
    next_path = url_path_join("/test-next?a=b&c=d")
    query = {
        "iss": f"{sandbox}/v/r4/fhir",
        "launch": public_client.get_launch_code(),
        "next": next_path,
    }
    with pytest.raises(HTTPClientError) as exc_info:
        response = await fetch_noauth(
            launch_path,
            params=query,
            follow_redirects=False,
        )
    response = exc_info.value.response
    assert response.code == 302
    redirect_url = response.headers["Location"]
    redirect = urlparse(redirect_url)
    assert redirect.path == url_path_join(jp_base_url, login_path)
    login_query = dict(parse_qsl(redirect.query))

    assert login_query["launch"] == query["launch"]
    assert "scope" in login_query

    # Login with headers and get redirected to auth url
    with pytest.raises(HTTPClientError) as exc_info:
        response = await fetch_noauth(
            login_path, params=login_query, follow_redirects=False
        )
    response = exc_info.value.response
    assert response.code == 302
    auth_url = response.headers["Location"]
    assert auth_url.startswith(sandbox)
    cookie = SimpleCookie()
    for c in response.headers.get_list("Set-Cookie"):
        cookie.load(c)

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

    cookie_header = "; ".join(
        f"{morsel.key}={morsel.coded_value}" for morsel in cookie.values()
    )
    with pytest.raises(HTTPClientError) as exc_info:
        await fetch_noauth(
            callback_path,
            params=params,
            headers={"Cookie": cookie_header},
            follow_redirects=False,
        )
    response = exc_info.value.response
    assert response.code == 302
    dest_url = response.headers["Location"]

    assert dest_url == url_path_join(jp_base_url, next_path)
    assert "SMART_TOKEN" in os.environ
    token = os.environ["SMART_TOKEN"]

    # load login cookie
    cookie = SimpleCookie()
    for c in response.headers.get_list("Set-Cookie"):
        cookie.load(c)
    cookie_header = "; ".join(
        f"{morsel.key}={morsel.coded_value}" for morsel in cookie.values()
    )

    resp = await fetch_noauth(
        "api/me",
        headers={"Cookie": cookie_header},
    )
    me = json.loads(resp.body.decode("utf8"))
    practitioner_id = public_client.provider_ids[0]
    username = f"Practitioner/{practitioner_id}"
    assert me["identity"]["username"] == username

    resp = await fetch_noauth("api/me", headers={"Authorization": f"Bearer {token}"})
    me = json.loads(resp.body.decode("utf8"))
    assert me["identity"]["username"] == username

    # auth should no longer be valid after new token is issued
    os.environ["SMART_TOKEN"] = "new_token"

    with pytest.raises(HTTPClientError) as exc_info:
        resp = await fetch_noauth(
            "api/me",
            headers={"Cookie": cookie_header},
        )
    response = exc_info.value.response
    assert response.code == 403

    with pytest.raises(HTTPClientError) as exc_info:
        resp = await fetch_noauth(
            "api/me", headers={"Authorization": f"Bearer {token}"}
        )
    response = exc_info.value.response
    assert response.code == 403
