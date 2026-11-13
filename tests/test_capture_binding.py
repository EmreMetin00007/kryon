"""Durable captured requests use synthetic vaults and never send traffic."""
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from conftest import load_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers/mcp-memory-server"))

from workflow_compiler import ingest_captured_requests  # noqa: E402
from cco_surface_core import session_store  # noqa: E402
from cco_surface_core.store import query_surface  # noqa: E402

BASE = "https://api.test/"


@pytest.fixture
def capture(tmp_path, monkeypatch):
    scope, policy = tmp_path / "scope.json", tmp_path / "policy.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": BASE}], "allow_osint": False,
                                 "allow_public_labs": False, "allow_loopback": False}))
    policy.write_text('{}')
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy))
    session_store.put_session(BASE, "alice", cookies={"sid": "alice-private"},
                              headers={"X-Tenant": "tenant-alpha"}, check_url=BASE + "me", marker="alice")
    session_store.refresh_status(BASE, "alice", lambda *_: (200, "alice"))
    headers = {"Cookie": "sid=alice-private", "X-Tenant": "tenant-alpha"}
    binding = {"target": BASE, "identity": "alice"}
    return tmp_path, headers, binding, scope, policy


def save(capture, request):
    home, headers, binding, *_ = capture
    ingest_captured_requests([{**request, "req_headers": {**headers, **request.get("headers", {})}}],
                             cco_home=str(home), session_binding=binding)
    return next(r for r in query_surface("api.test", db_path=str(home / "agent_memory.db"))
                if urlsplit(r["url"]).path == urlsplit(request["url"]).path and r["method"] == request["method"])


@pytest.mark.parametrize("kind", ["GET", "JSON", "FORM", "GRAPHQL"])
def test_capture_roundtrip_keeps_full_request_encrypted_and_bound(capture, kind):
    from cco_surface_core.request_store import load_capture

    home, headers, *_ = capture
    private = "private-long-" + "x" * 150
    request = {"url": BASE + "search?q=" + private, "method": "GET"}
    if kind == "JSON":
        request = {"url": BASE + "search", "method": "POST", "content_type": "application/json",
                   "req_body": {"q": private, "nested": {"password": "body-private"}}}
    elif kind == "FORM":
        request = {"url": BASE + "search", "method": "POST",
                   "content_type": "application/x-www-form-urlencoded", "req_body": "q=" + private}
    elif kind == "GRAPHQL":
        request = {"url": BASE + "graphql", "method": "POST", "content_type": "application/json",
                   "req_body": {"query": 'query A($id:ID!){a(id:$id,key:"inline-private"){id}}',
                                "operationName": "A", "variables": {"id": private}}}
    record = save(capture, request)
    assert record["capture_ref"].startswith("cap-")
    packet = load_capture(record["capture_ref"], operation_id=record["operation_id"],
                          observation_id=record["observation_id"], headers=headers, home=str(home))
    assert packet["request"]["method"] == request["method"]
    assert private in json.dumps(packet["request"])
    assert packet["binding"] == record["capture_binding"]
    assert "scope_revision" in packet["binding"] and "session_version" in packet["binding"]
    public = json.dumps(record)
    for secret in (private, "body-private", "inline-private", "alice-private"):
        assert secret not in public
        assert secret.encode() not in (home / "agent_memory.db").read_bytes()


@pytest.mark.parametrize("change", ["operation", "observation", "cookie", "tenant", "scope", "policy", "session", "new_capture"])
def test_stale_or_swapped_capture_never_reaches_validator(capture, monkeypatch, change):
    home, headers, binding, scope, policy = capture
    record = save(capture, {"url": BASE + "search?q=alpha", "method": "GET"})
    hunter = load_server("hunter")
    from cco_hunter_core.request_context import request_binding, store_context
    item = {"url": record["url"], "method": "GET", "vuln_class": "sql_injection", "param": "q",
            "location": "query", "operation_id": record["operation_id"], "observation_id": record["observation_id"]}
    item["request_ref"] = store_context({**item, "capture_ref": record["capture_ref"],
                                         "binding": request_binding(headers), "baseline_headers": headers})
    if change == "operation":
        item["operation_id"] = "op-other"
    elif change == "observation":
        item["observation_id"] += 1
    elif change == "cookie":
        headers = {**headers, "Cookie": "sid=bob-private"}
    elif change == "tenant":
        headers = {**headers, "X-Tenant": "tenant-beta"}
    elif change == "scope":
        scope.write_text(json.dumps({"in_scope": []}))
    elif change == "policy":
        policy.write_text(json.dumps({"required_request_headers": {"X-Research": "changed"}}))
    elif change == "session":
        session_store.put_session(BASE, "alice", cookies={"sid": "rotated"}, home=str(home))
    elif change == "new_capture":
        ingest_captured_requests([{"url": BASE + "search?q=beta", "method": "GET"}], cco_home=str(home))
    monkeypatch.setattr(hunter, "_validator_call", lambda *_a, **_k: pytest.fail("stale capture reached validator"))
    result = hunter._loop_validate(item, headers=json.dumps(headers))
    assert result["verdict"] == "INCONCLUSIVE"


def test_bound_capture_hydrates_from_vault_and_survives_transient_context_loss(capture):
    from cco_hunter_core.request_context import materialize_record, _CONTEXTS

    _, headers, *_ = capture
    private = "query-private-" + "x" * 150
    record = save(capture, {"url": BASE + "search?q=" + private, "method": "GET"})
    _CONTEXTS.clear()
    hydrated, missing = materialize_record(record, headers=headers)
    assert not missing
    assert hydrated["params"][0]["sample"] == private
    assert hydrated["capture_ref"] == record["capture_ref"]
    _, denied = materialize_record(record, headers={"Cookie": "sid=bob-private"})
    assert denied


def test_capture_binding_requires_a_fresh_matching_account(capture):
    home, _, binding, *_ = capture
    with pytest.raises(ValueError):
        ingest_captured_requests([{"url": BASE + "search?q=alpha", "method": "GET",
                                   "req_headers": {"Cookie": "sid=bob-private"}}],
                                 cco_home=str(home), session_binding=binding)


def test_capture_guard_rechecks_each_wire_hop_and_keeps_parent_policy(capture):
    from cco_hunter_core.request_context import bind_policy_gate, captured_request, current_policy_gate

    _, headers, _, scope, _ = capture
    record = save(capture, {"url": BASE + "search?q=alpha", "method": "GET"})
    parent_calls = []

    def parent(method, url, wire_headers):
        parent_calls.append(method)
        return method == "GET", "parent policy"

    def sender(method, url, **kwargs):
        gate = current_policy_gate()
        assert gate(method, url, kwargs["headers"])[0]
        assert not gate("POST", url, kwargs["headers"])[0]
        scope.write_text(json.dumps({"in_scope": []}))
        assert not gate(method, url, kwargs["headers"])[0]
        return {"ok": True, "status": 200}

    with bind_policy_gate(parent):
        assert captured_request(record, sender, "GET", record["url"], headers=headers)["ok"]
    assert parent_calls == ["GET", "POST"]  # Stale hop never reaches parent or transport.


def test_capture_secret_swap_and_expiry_are_rejected(capture, monkeypatch):
    import sqlite3
    from cco_surface_core.request_store import load_capture

    home, headers, *_ = capture
    first = save(capture, {"url": BASE + "first?q=alpha", "method": "GET"})
    second = save(capture, {"url": BASE + "second?q=beta", "method": "GET"})
    with sqlite3.connect(home / "agent_memory.db") as conn:
        other = conn.execute("SELECT secret_ref FROM surface_request_bindings WHERE capture_ref=?",
                             (second["capture_ref"],)).fetchone()[0]
        conn.execute("UPDATE surface_request_bindings SET secret_ref=? WHERE capture_ref=?",
                     (other, first["capture_ref"]))
    with pytest.raises(ValueError):
        load_capture(first["capture_ref"], operation_id=first["operation_id"],
                      observation_id=first["observation_id"], headers=headers, home=str(home))
    now = session_store.time.time()
    monkeypatch.setattr(session_store.time, "time", lambda: now + 301)
    with pytest.raises(ValueError):
        load_capture(second["capture_ref"], operation_id=second["operation_id"],
                      observation_id=second["observation_id"], headers=headers, home=str(home))


def test_failed_batch_rolls_back_new_links_and_own_vault_secrets(capture, monkeypatch):
    import sqlite3
    from cco_surface_core import request_store

    home, headers, binding, _, policy = capture
    original = request_store.save_capture
    created = []

    def save_and_change_policy(*args, **kwargs):
        result = original(*args, **kwargs)
        created.append(result[1])
        policy.write_text(json.dumps({"changed": True}))
        return result

    monkeypatch.setattr(request_store, "save_capture", save_and_change_policy)
    with pytest.raises(ValueError):
        ingest_captured_requests([
            {"url": BASE + "first?q=alpha", "method": "GET", "req_headers": headers},
            {"url": BASE + "second?q=beta", "method": "GET", "req_headers": headers},
        ], cco_home=str(home), session_binding=binding)
    with sqlite3.connect(home / "agent_memory.db") as conn:
        assert conn.execute("SELECT COUNT(*) FROM attack_surface").fetchone()[0] == 0
    assert len(created) == 1 and created[0]
    with pytest.raises(KeyError):
        request_store._vault(home).get_secret(created[0])


def test_repeated_bound_capture_restores_operation_head_without_copying_b(capture):
    from cco_surface_core.request_store import load_capture

    home, headers, *_ = capture
    first = save(capture, {"url": BASE + "search?q=alpha", "method": "GET"})
    other = save(capture, {"url": BASE + "search?q=beta", "method": "GET"})
    current = save(capture, {"url": BASE + "search?q=alpha", "method": "GET"})
    assert current["observation_id"] == first["observation_id"]
    assert current["capture_ref"] == first["capture_ref"]
    assert current["observation_count"] == 2
    assert load_capture(first["capture_ref"], operation_id=first["operation_id"],
                        observation_id=first["observation_id"], headers=headers, home=str(home))
    with pytest.raises(ValueError):
        load_capture(other["capture_ref"], operation_id=other["operation_id"],
                      observation_id=other["observation_id"], headers=headers, home=str(home))


def test_transient_request_reference_cannot_use_a_previous_observation(capture, monkeypatch):
    home, headers, *_ = capture
    from cco_surface_core.parsers import parse_xhr
    from cco_surface_core.store import ingest_records

    ingest_records(parse_xhr([{"url": BASE + "search?q=alpha", "method": "GET"}]),
                   db_path=str(home / "agent_memory.db"))
    record = query_surface("api.test", db_path=str(home / "agent_memory.db"))[0]
    hunter = load_server("hunter")
    from cco_hunter_core.request_context import request_binding, store_context
    item = {"url": record["url"], "method": "GET", "vuln_class": "sql_injection", "param": "q",
            "location": "query", "operation_id": record["operation_id"], "observation_id": record["observation_id"]}
    item["request_ref"] = store_context({**item, "binding": request_binding(headers)})
    ingest_records(parse_xhr([{"url": BASE + "search?q=beta", "method": "GET"}]),
                   db_path=str(home / "agent_memory.db"))
    monkeypatch.setattr(hunter, "_validator_call", lambda *_a, **_k: pytest.fail("stale observation reached validator"))
    assert hunter._loop_validate(item, headers=json.dumps(headers))["verdict"] == "INCONCLUSIVE"


def test_stale_surface_variant_does_not_block_current_independent_probes(capture, monkeypatch):
    from cco_surface_core.parsers import parse_xhr
    from cco_surface_core.store import ingest_records, next_work

    home, headers, *_ = capture
    db = str(home / "agent_memory.db")
    for query in ("q=alpha", "q=beta&sort=new"):
        ingest_records(parse_xhr([{"url": BASE + "search?" + query, "method": "GET"}]), db_path=db)
    queued = next_work(BASE, db_path=db)["queue"]
    assert len(queued) == 2 and queued[0]["operation_id"] == queued[1]["operation_id"]
    stale_id = queued[0]["observation_id"]
    hunter = load_server("hunter")
    calls = []

    def send(method, url, **_kwargs):
        assert "alpha" not in url
        calls.append((method, url))
        return {"ok": True, "status": 200, "text": "synthetic result", "headers": {}}

    monkeypatch.setattr(hunter, "_live_request", send)
    monkeypatch.setattr(hunter, "_light_oracle", lambda *_: ("INCONCLUSIVE", "no signal"))
    monkeypatch.setattr(hunter, "write_artifact", lambda *_a, **_kw: "")
    result = json.loads(hunter.fuzz_attack_surface(BASE, live=True, headers=json.dumps(headers),
                                                  max_requests=2, sleep_s=0))
    stale = [row for row in result["fanout"] if row.get("observation_id") == stale_id]
    assert stale and all(row["coverage_status"] == "not_tested" and not row["live"] for row in stale)
    assert len(calls) == result["requests_sent"] == 2
    assert calls[0][1] == BASE + "search?q=beta&sort=new"
    assert not result["stopped"] and not result["marked_tested"]
