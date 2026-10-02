"""set_session_cookie attribute matrix and standalone config check, without a server."""

import logging

import pytest

from jupyter_smart_on_fhir import server_extension as ext


class FakeAuth:
    cookie_name = "smart-session"
    cookie_secure = None
    cookie_partitioned = True
    session_lifetime = 3600


class FakeRequest:
    def __init__(self, protocol):
        self.protocol = protocol


class FakeHandler:
    base_url = "/app/"
    log = logging.getLogger("test")

    def __init__(self, protocol="https", auth=None):
        self.request = FakeRequest(protocol)
        self.settings = {"smart_auth": auth or FakeAuth()}
        self.headers = []

    def create_signed_value(self, name, value):
        return f"2|1:0|10:1700000000|{len(name)}:{name}|8:c2lnbmVk|sig".encode()

    def add_header(self, name, value):
        self.headers.append((name, value))


def test_https_cookie_is_secure_none_partitioned_httponly():
    h = FakeHandler("https")
    ext.set_session_cookie(h, "x" * 32)
    ((_, header),) = h.headers
    assert header.startswith("smart-session=")
    assert "HttpOnly" in header and "Secure" in header and "SameSite=None" in header
    assert header.endswith("; Partitioned")
    assert "Path=/app/" in header and "Max-Age=3600" in header


def test_http_cookie_is_lax_without_secure_or_partitioned():
    h = FakeHandler("http")
    ext.set_session_cookie(h, "x" * 32)
    ((_, header),) = h.headers
    assert (
        "SameSite=Lax" in header
        and "Secure" not in header
        and "Partitioned" not in header
    )


def test_forced_secure_and_partitioned_off():
    auth = FakeAuth()
    auth.cookie_secure = True
    auth.cookie_partitioned = False
    h = FakeHandler("http", auth)
    ext.set_session_cookie(h, "x" * 32)
    ((_, header),) = h.headers
    assert (
        "Secure" in header and "SameSite=None" in header and "Partitioned" not in header
    )


def test_normalize_issuer():
    assert (
        ext.normalize_issuer(" HTTPS://EHR.Example/fhir/R4/ ")
        == "https://ehr.example/fhir/R4"
    )
    assert (
        ext.normalize_issuer("http://localhost:8103/fhir/R4")
        == "http://localhost:8103/fhir/R4"
    )
    with pytest.raises(ValueError):
        ext.normalize_issuer("http://ehr.example/fhir")  # plain http only for localhost
    with pytest.raises(ValueError):
        ext.normalize_issuer("ehr.example/fhir")
    with pytest.raises(ValueError):
        ext.normalize_issuer(
            "https://ehr.exa\tmple/fhir"
        )  # urlparse would drop the tab
    with pytest.raises(ValueError):
        ext.normalize_issuer(
            "https://\u212aehr.example/fhir"
        )  # Kelvin sign folds to "k"


def test_check_standalone_config_requires_allowlist():
    ext.check_standalone_config({"https://ehr.example/fhir"}, ext.SMARTIdentityProvider)
    ext.check_standalone_config(set(), object)  # not standalone: fine
    with pytest.raises(ValueError, match="allowed_issuers"):
        ext.check_standalone_config(set(), ext.SMARTIdentityProvider)
