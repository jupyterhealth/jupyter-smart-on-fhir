import json
import os
import stat

import pytest

from jupyter_smart_on_fhir import session as s


class FakeSmartConfig:
    def __init__(self):
        self.fhir_url = "https://ehr.example/fhir"
        self.smart_config = {"authorization_endpoint": "https://ehr.example/authorize"}


@pytest.fixture
def clock():
    class Clock:
        now = 1_000_000.0

        def __call__(self):
            return self.now

    return Clock()


@pytest.fixture
def store(tmp_path, clock):
    return s.SMARTSessionStore(tmp_path / "sessions", clock=clock)


def test_create_returns_pending_session_with_safe_id(store):
    sess = store.create("https://ehr.example/fhir", FakeSmartConfig())
    assert s.SAFE_SESSION_ID.match(sess.session_id)
    assert sess.token is None
    assert store.is_authenticated(sess) is False
    assert store.get(sess.session_id) is sess


def test_token_dir_is_private(tmp_path, clock):
    store = s.SMARTSessionStore(tmp_path / "sessions", clock=clock)
    assert stat.S_IMODE(os.stat(store.token_dir).st_mode) == 0o700


def test_pending_session_expires_after_pending_lifetime(store, clock):
    sess = store.create("https://ehr.example/fhir", FakeSmartConfig())
    clock.now += store.pending_lifetime + 1
    assert store.get(sess.session_id) is None


def test_create_evicts_oldest_pending_at_cap(tmp_path, clock):
    store = s.SMARTSessionStore(tmp_path / "sessions", max_pending=2, clock=clock)
    a = store.create("https://ehr.example/fhir", FakeSmartConfig())
    clock.now += 1
    b = store.create("https://ehr.example/fhir", FakeSmartConfig())
    clock.now += 1
    c = store.create("https://ehr.example/fhir", FakeSmartConfig())  # never refuses
    assert store.get(a.session_id) is None  # oldest pending evicted
    assert store.get(b.session_id) is b and store.get(c.session_id) is c


def test_eviction_never_touches_authenticated_sessions(tmp_path, clock):
    store = s.SMARTSessionStore(tmp_path / "sessions", max_pending=1, clock=clock)
    done = store.create("https://ehr.example/fhir", FakeSmartConfig())
    store.complete(done.session_id, {"access_token": "AT", "token_type": "Bearer"})
    p1 = store.create("https://ehr.example/fhir", FakeSmartConfig())
    clock.now += 1
    p2 = store.create("https://ehr.example/fhir", FakeSmartConfig())
    assert store.get(done.session_id) is done
    assert store.get(p1.session_id) is None and store.get(p2.session_id) is p2


def test_complete_rejects_non_bearer_or_missing_token(store):
    sess = store.create("https://ehr.example/fhir", FakeSmartConfig())
    with pytest.raises(s.SMARTSessionError, match="access_token"):
        store.complete(sess.session_id, {"token_type": "Bearer"})
    with pytest.raises(s.SMARTSessionError, match="token_type"):
        store.complete(sess.session_id, {"access_token": "AT", "token_type": "mac"})
    assert sess.token is None and not store.token_file(sess.session_id).exists()


def test_set_oauth_state_records_state_and_verifier(store):
    sess = store.create("https://ehr.example/fhir", FakeSmartConfig())
    store.set_oauth_state(
        sess.session_id, {"state_id": "S1", "code_verifier": "V1", "next_url": "/next"}
    )
    assert (sess.state_id, sess.code_verifier, sess.next_url) == ("S1", "V1", "/next")


def test_complete_writes_private_token_file_and_clears_state(store, clock):
    sess = store.create("https://ehr.example/fhir", FakeSmartConfig())
    store.set_oauth_state(sess.session_id, {"state_id": "S1", "code_verifier": "V1"})
    store.complete(
        sess.session_id,
        {"access_token": "AT", "token_type": "bearer", "expires_in": 600},
    )
    assert store.is_authenticated(sess) is True
    assert sess.state_id is None and sess.code_verifier is None
    assert sess.expires_at == clock.now + 600
    path = store.token_file(sess.session_id)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    data = json.loads(path.read_text())
    assert data["token"]["access_token"] == "AT"
    assert data["fhir_url"] == "https://ehr.example/fhir"
    assert data["smart_config"] == {
        "authorization_endpoint": "https://ehr.example/authorize"
    }
    assert data["expires_at"] == sess.expires_at


def test_complete_caps_lifetime_at_session_lifetime(store, clock):
    sess = store.create("https://ehr.example/fhir", FakeSmartConfig())
    store.complete(
        sess.session_id,
        {"access_token": "AT", "token_type": "bearer", "expires_in": 99_999},
    )
    assert sess.expires_at == clock.now + store.session_lifetime


def test_get_purges_every_expired_session(store, clock):
    a = store.create("https://ehr.example/fhir", FakeSmartConfig())
    b = store.create("https://ehr.example/fhir", FakeSmartConfig())
    store.complete(
        a.session_id, {"access_token": "AT", "token_type": "bearer", "expires_in": 60}
    )
    store.complete(
        b.session_id, {"access_token": "AT", "token_type": "bearer", "expires_in": 60}
    )
    pa, pb = store.token_file(a.session_id), store.token_file(b.session_id)
    clock.now += 61
    assert store.get(a.session_id) is None  # looking up A also purges B
    assert not pa.exists() and not pb.exists()
    assert store.purge_expired() == 0


def test_delete_removes_session_and_file(store):
    sess = store.create("https://ehr.example/fhir", FakeSmartConfig())
    store.complete(sess.session_id, {"access_token": "AT", "token_type": "bearer"})
    store.delete(sess.session_id)
    assert store.get(sess.session_id) is None
    assert not store.token_file(sess.session_id).exists()


def test_wipe_removes_stale_files_from_disk(tmp_path, clock):
    d = tmp_path / "sessions"
    d.mkdir()
    (d / ("x" * 32 + ".json")).write_text("{}")
    store = s.SMARTSessionStore(d, clock=clock)
    store.wipe()
    assert list(d.iterdir()) == []


def test_unknown_session_raises_on_mutation(store):
    with pytest.raises(s.SMARTSessionError):
        store.set_oauth_state("nope", {"state_id": "S", "code_verifier": "V"})
    with pytest.raises(s.SMARTSessionError):
        store.complete("nope", {"access_token": "AT", "token_type": "bearer"})


def test_token_file_rejects_unsafe_ids(store):
    with pytest.raises(s.SMARTSessionError):
        store.token_file("../etc/passwd")
