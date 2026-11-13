"""crAPI adapter contracts: scope, auth carriage, decoding and proof binding."""
import io
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from discovery_crapi_runner import CrApiExecutor, NoRedirect, proof_is_bound, response_kind  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402


class Reply(io.BytesIO):
    def __init__(self, value, status=200, headers=None):
        super().__init__(value if isinstance(value, bytes) else json.dumps(value).encode())
        self.code = status
        self.headers = headers or {"Content-Type": "application/json"}


class Opener:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return next(self.replies)


@pytest.fixture
def executor(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    policy = tmp_path / "policy.json"
    scope.write_text(json.dumps({"scope_policy": "explicit_only", "allow_loopback": False,
                                 "in_scope": [{"asset": "http://127.0.0.1:18901"}]}))
    policy.write_text(json.dumps({"allow_loopback": False, "allow_osint": False, "allow_public_labs": False}))
    ex = CrApiExecutor("http://127.0.0.1:18901", SharedBudget(http=10, tokens=100000, seconds=600),
                       [{"alias": "test-a", "work_email": "a@example.test", "password": "synthetic-only"}],
                       tmp_path / "trial", scope, policy)
    monkeypatch.setattr("discovery_crapi_runner.time.sleep", lambda _: None)
    monkeypatch.setattr("discovery_crapi_runner.event", lambda *a, **kw: None)
    return ex


def test_bearer_csrf_and_put_body_are_carried_without_persisting_tokens(executor):
    executor.opener = Opener([
        Reply({"access_token": "test-secret-token", "csrf_token": "csrf-one"}),
        Reply({"id": "own-fixture", "service_tier": "basic"}, headers={"X-CSRF-Token-Next": "csrf-two"}),
        Reply({"service_tier": "premium"}),
    ])
    executor.fetch("POST", "/api/v1/equipment", body={"name": "own fixture"}, actor_alias="test-a")
    executor.fetch("PUT", "/api/v1/equipment/own-fixture", body={"service_tier": "premium"}, actor_alias="test-a")
    sent = executor.opener.requests
    assert sent[1].get_header("Authorization") == "Bearer test-secret-token"
    assert sent[2].get_header("X-csrf-token") == "csrf-two"
    assert json.loads(sent[2].data) == {"service_tier": "premium"}
    archives = "".join(p.read_text() for p in executor.out.rglob("*.json"))
    assert "test-secret-token" not in archives and "csrf-one" not in archives
    assert executor.budget.snapshot()["used"]["http"] == 3


@pytest.mark.parametrize("method,path", [("DELETE", "/api/v1/equipment/1"), ("GET", "//other.test/path")])
def test_prohibited_requests_do_not_even_bootstrap_auth(executor, method, path):
    executor.opener = Opener([])
    reply = executor.fetch(method, path, actor_alias="test-a")
    assert reply["status"] == 0
    assert not executor.opener.requests
    assert executor.budget.snapshot()["used"]["http"] == 0


def test_scope_is_rechecked_after_an_operator_scope_change(executor):
    executor.scope_file.write_text(json.dumps({"in_scope": []}))
    executor.opener = Opener([])
    assert executor.fetch("GET", "/")["status"] == 0
    assert not executor.opener.requests


def test_bad_gzip_is_a_decode_failure_with_raw_archive(executor):
    executor.opener = Opener([Reply(b"plain bytes", headers={"Content-Encoding": "gzip"})])
    reply = executor.fetch("GET", "/api/v1/equipment/catalog/export")
    assert reply["classification"] == "invalid_gzip"
    assert next(executor.out.rglob("*.wire.bin")).read_bytes() == b"plain bytes"


def test_large_response_can_be_inspected_without_more_http(executor):
    executor.opener = Opener([Reply({"padding": "x" * 20000, "private_note": "observed-canary"})])
    reply = executor.fetch("GET", "/api/v1/equipment/catalog/export")
    assert reply["body"]["truncated"]
    excerpt = executor.fetch("GET", "/", artifact_ref=reply["evidence_ref"], search="private_note")
    assert "observed-canary" in excerpt["body"]["excerpt"]
    assert excerpt["no_http_request"] and len(executor.opener.requests) == 1


def test_proof_requires_exact_response_and_actor_binding():
    record = {"evidence_ref": "response-1", "method": "GET", "path": "/objects/2",
              "actor_alias": "test-a", "status": 200, "body": {"note": "canary-abc"}}
    claim = {"evidence_ref": "response-1", "method": "GET", "path": "/objects/2",
             "actor_alias": "test-a", "observed_status": 200, "evidence_value": "canary-abc"}
    assert proof_is_bound(claim, [record])
    for key, bad in [("actor_alias", "test-b"), ("path", "/objects/3"), ("evidence_value", "HTTP 200")]:
        assert not proof_is_bound({**claim, key: bad}, [record])


def test_fault_types_do_not_conflate_challenge_with_authorization():
    assert response_kind(403, {"x-challenge": "required"}, {}) == "challenge"
    assert response_kind(403, {}, {}) == "authorization_or_csrf"
    assert response_kind(502, {"x-lab-injected": "502"}, {}) == "injected_server_fault"
    assert NoRedirect().redirect_request(None, None, 302, "", {}, "http://other.test") is None
