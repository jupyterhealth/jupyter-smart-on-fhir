"""SMARTAuthorizer unit tests with fake handlers: a session may touch only the kernel
Voilà started for it."""

import logging

from jupyter_smart_on_fhir import server_extension as ext
from jupyter_smart_on_fhir.session import SMARTSession


class FakeKM:
    def __init__(self, cookie):
        self._launch_args = {"env": {"HTTP_COOKIE": cookie}} if cookie is not None else {}


class FakeKernelManager:
    def __init__(self, kernels):
        self.kernels = kernels

    def get_kernel(self, kid):
        return self.kernels[kid]  # KeyError for unknown, like MappingKernelManager


class FakeStore:
    """Returns real SMARTSession objects, as the production store does."""

    def __init__(self, ids):
        self.sessions = {
            sid: SMARTSession(session_id=sid, fhir_url="https://ehr.example/fhir", smart_config=None,
                              created=0.0, expires_at=9e12, token={"access_token": "AT"})
            for sid in ids
        }

    def get(self, sid):
        return self.sessions.get(sid)


def signed(name, sid):
    import base64

    b = base64.b64encode(sid.encode()).decode()
    return f"2|1:0|10:1700000000|{len(name)}:{name}|{len(b)}:{b}|sig"


class FakeHandler:
    log = logging.getLogger("test")

    def __init__(self, sid, kernels, kernel_id=None):
        self.sid = sid
        cookie = f"smart-session={signed('smart-session', sid)}" if sid else ""
        self.request = type("R", (), {"path": "/x", "headers": {"Cookie": cookie}})()
        self.settings = {
            "smart_session_store": FakeStore([s for s in [sid] if s]),
            "smart_session_cookie_name": "smart-session",
        }
        self.kernel_manager = FakeKernelManager(kernels)
        self.path_kwargs = {"kernel_id": kernel_id} if kernel_id else {}
        self.path_args = ()

    def get_signed_cookie(self, name):
        return self.sid.encode() if self.sid else None


A, B = "a" * 32, "b" * 32
KERNELS = {"k-a": FakeKM(f"smart-session={signed('smart-session', A)}"),
           "k-b": FakeKM(f"smart-session={signed('smart-session', B)}"),
           "k-none": FakeKM(None)}
auth = ext.SMARTAuthorizer()


def test_own_kernel_execute_and_read_allowed():
    h = FakeHandler(A, KERNELS, "k-a")
    assert auth.is_authorized(h, object(), "execute", "kernels") is True
    assert auth.is_authorized(h, object(), "read", "kernels") is True


def test_other_sessions_kernel_denied():
    h = FakeHandler(A, KERNELS, "k-b")
    assert auth.is_authorized(h, object(), "execute", "kernels") is False


def test_kernel_without_session_env_or_unknown_denied():
    assert auth.is_authorized(FakeHandler(A, KERNELS, "k-none"), object(), "execute", "kernels") is False
    assert auth.is_authorized(FakeHandler(A, KERNELS, "nope"), object(), "execute", "kernels") is False


def test_kernel_write_and_list_denied():
    assert auth.is_authorized(FakeHandler(A, KERNELS, "k-a"), object(), "write", "kernels") is False
    assert auth.is_authorized(FakeHandler(A, KERNELS), object(), "read", "kernels") is False  # list, no id


def test_everything_else_denied():
    h = FakeHandler(A, KERNELS)
    for resource in ("contents", "terminals", "sessions", "kernelspecs", "api", "config", "nbconvert"):
        for action in ("read", "write", "execute"):
            assert auth.is_authorized(h, object(), action, resource) is False, (action, resource)
