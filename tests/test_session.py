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


def test_create_with_zero_max_pending_still_creates(tmp_path, clock):
    store = s.SMARTSessionStore(tmp_path / "sessions", max_pending=0, clock=clock)
    a = store.create("https://ehr.example/fhir", FakeSmartConfig())
    b = store.create("https://ehr.example/fhir", FakeSmartConfig())
    assert store.get(a.session_id) is None and store.get(b.session_id) is b


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


def test_complete_leaves_session_pending_when_token_file_write_fails(
    store, monkeypatch
):
    sess = store.create("https://ehr.example/fhir", FakeSmartConfig())
    store.set_oauth_state(sess.session_id, {"state_id": "S1", "code_verifier": "V1"})

    def fail(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(s.os, "replace", fail)
    with pytest.raises(OSError):
        store.complete(sess.session_id, {"access_token": "AT", "token_type": "bearer"})
    assert sess.token is None
    assert sess.state_id == "S1" and sess.code_verifier == "V1"
    assert not store.token_file(sess.session_id).exists()
    assert list(store.token_dir.iterdir()) == []  # temp file cleaned up


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


@pytest.mark.parametrize("expires_in", [float("inf"), float("nan"), True])
def test_complete_ignores_non_finite_or_bool_expires_in(store, clock, expires_in):
    sess = store.create("https://ehr.example/fhir", FakeSmartConfig())
    store.complete(
        sess.session_id,
        {"access_token": "AT", "token_type": "bearer", "expires_in": expires_in},
    )
    assert sess.expires_at == clock.now + store.session_lifetime


def test_on_delete_hook_called_on_delete_and_purge(tmp_path, clock):
    ended = []
    store = s.SMARTSessionStore(
        tmp_path / "sessions", clock=clock, on_delete=ended.append
    )
    a = store.create("https://ehr.example/fhir", FakeSmartConfig())
    b = store.create("https://ehr.example/fhir", FakeSmartConfig())
    store.delete(a.session_id)
    assert ended == [a.session_id]
    clock.now += store.pending_lifetime + 1
    assert store.purge_expired() == 1
    assert ended == [a.session_id, b.session_id]
    store.delete(a.session_id)  # already gone: no second notification
    assert ended == [a.session_id, b.session_id]


def test_raising_on_delete_hook_does_not_break_deletion(tmp_path, clock):
    def boom(session_id):
        raise RuntimeError("kernel manager gone")

    store = s.SMARTSessionStore(tmp_path / "sessions", clock=clock, on_delete=boom)
    sess = store.create("https://ehr.example/fhir", FakeSmartConfig())
    store.complete(sess.session_id, {"access_token": "AT", "token_type": "bearer"})
    store.delete(sess.session_id)
    assert store.get(sess.session_id) is None
    assert not store.token_file(sess.session_id).exists()


def test_wipe_removes_stale_files_from_disk(tmp_path, clock):
    d = tmp_path / "sessions"
    d.mkdir()
    (d / ("x" * 32 + ".json")).write_text("{}")
    (d / (".x" + "x" * 31 + ".abc.tmp")).write_text("{}")
    store = s.SMARTSessionStore(d, clock=clock)
    store.wipe()
    assert list(d.iterdir()) == []


def test_wipe_removes_only_session_files(tmp_path, clock):
    d = tmp_path / "sessions"
    d.mkdir()
    sid = "s" * 32
    (d / "dir.json").mkdir()
    (d / "other.json").write_text("{}")
    (d / f"{sid}.json").write_text("{}")
    (d / f".{sid}.abcd.tmp").write_text("{}")
    store = s.SMARTSessionStore(d, clock=clock)
    store.wipe()
    assert sorted(p.name for p in d.iterdir()) == ["dir.json", "other.json"]


def test_unknown_session_raises_on_mutation(store):
    with pytest.raises(s.SMARTSessionError):
        store.set_oauth_state("nope", {"state_id": "S", "code_verifier": "V"})
    with pytest.raises(s.SMARTSessionError):
        store.complete("nope", {"access_token": "AT", "token_type": "bearer"})


def test_token_file_rejects_unsafe_ids(store):
    with pytest.raises(s.SMARTSessionError):
        store.token_file("../etc/passwd")


import base64 as _b64

NAME = "smart-session"


def _signed(value, name=NAME):
    # tornado v2 signed-value layout; the signature field is irrelevant to the parser
    b = _b64.b64encode(value.encode()).decode()
    return f"2|1:0|10:1700000000|{len(name)}:{name}|{len(b)}:{b}|deadbeef"


def test_parse_cookie_header_is_lenient_like_tornado():
    header = 'ga={"a":1}; weird value=x y; smart-session="quoted=value"; last=1'
    jar = s.parse_cookie_header(header)
    assert jar["smart-session"] == "quoted=value"
    assert jar["last"] == "1"
    assert s.parse_cookie_header(None) == {} and s.parse_cookie_header("") == {}


def test_parse_cookie_header_refuses_duplicate_names():
    # tornado keeps the LAST value, a naive parser the FIRST: a crafted header could steer
    # a kernel to another session, so a repeated session cookie means no cookies at all.
    header = "smart-session=a; x=1; smart-session=b"
    assert s.parse_cookie_header(header, unique_name="smart-session") is None
    assert s.parse_cookie_header(header)["smart-session"] == "a"
    assert s.session_id_from_cookie_header("smart-session=a; smart-session=b") is None


def test_duplicate_unrelated_cookie_does_not_hide_the_session():
    sid = "a" * 32
    header = f"_ga=1; _ga=2; smart-session={_signed(sid)}"
    assert s.parse_cookie_header(header, unique_name="smart-session")["_ga"] == "1"
    assert s.session_id_from_cookie_header(header) == sid


def test_session_id_from_signed_value_requires_v2_and_matching_name():
    sid = "b" * 32
    assert s.session_id_from_signed_value(_signed(sid), NAME) == sid
    assert s.session_id_from_signed_value(_signed(sid, name="other"), NAME) is None
    assert (
        s.session_id_from_signed_value(sid, NAME) is None
    )  # bare ids are not accepted
    assert s.session_id_from_signed_value("2|1:0|bad", NAME) is None
    assert s.session_id_from_signed_value(_signed("../x"), NAME) is None


def test_session_id_from_cookie_header_picks_named_cookie_after_malformed_sibling():
    sid = "c" * 32
    header = f'ga={{"a":1}}; _xsrf=123; smart-session="{_signed(sid)}"; other=1'
    assert s.session_id_from_cookie_header(header) == sid
    assert s.session_id_from_cookie_header(header, cookie_name="nope") is None
    assert s.session_id_from_cookie_header(None) is None


def test_load_token_reads_this_sessions_file(tmp_path):
    sid = "d" * 32
    (tmp_path / f"{sid}.json").write_text(
        json.dumps({"token": {"access_token": "AT"}, "expires_at": 2_000_000})
    )
    env = {
        s.TOKEN_DIR_ENV: str(tmp_path),
        s.COOKIE_HEADER_ENV: f"smart-session={_signed(sid)}",
    }
    assert s.load_token(env, now=lambda: 1_000_000)["token"]["access_token"] == "AT"


def test_load_token_uses_exported_cookie_name(tmp_path):
    sid = "g" * 32
    (tmp_path / f"{sid}.json").write_text(
        json.dumps({"token": {"access_token": "AT"}, "expires_at": 2_000_000})
    )
    env = {
        s.TOKEN_DIR_ENV: str(tmp_path),
        s.COOKIE_NAME_ENV: "custom",
        s.COOKIE_HEADER_ENV: f"custom={_signed(sid, name='custom')}",
    }
    assert s.load_token(env, now=lambda: 1_000_000)["token"]["access_token"] == "AT"


def test_load_token_rejects_expired_file(tmp_path):
    sid = "f" * 32
    (tmp_path / f"{sid}.json").write_text(
        json.dumps({"token": {"access_token": "AT"}, "expires_at": 1_000})
    )
    env = {
        s.TOKEN_DIR_ENV: str(tmp_path),
        s.COOKIE_HEADER_ENV: f"smart-session={_signed(sid)}",
    }
    with pytest.raises(s.SMARTSessionError, match="expired"):
        s.load_token(env, now=lambda: 2_000)


def test_load_token_errors_are_actionable(tmp_path):
    with pytest.raises(s.SMARTSessionError, match="SMART_TOKEN_DIR"):
        s.load_token({})
    with pytest.raises(s.SMARTSessionError, match="http_header_envs"):
        s.load_token({s.TOKEN_DIR_ENV: str(tmp_path)})
    sid = "e" * 32
    with pytest.raises(s.SMARTSessionError, match="expired or not launched"):
        s.load_token(
            {
                s.TOKEN_DIR_ENV: str(tmp_path),
                s.COOKIE_HEADER_ENV: f"smart-session={_signed(sid)}",
            }
        )
