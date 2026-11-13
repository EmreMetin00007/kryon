"""Offline boundaries for the functional lab runner and temporary SSH worker."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parents[1] / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(SCRIPTS))
host = load("lab_functional_probe")
remote = load("lab_functional_worker")


class Response(io.BytesIO):
    def __init__(self, body, status=200, headers=None):
        super().__init__(body)
        self.code = status
        self.headers = headers or {}


class Opener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return next(self.responses)


@pytest.fixture
def worker(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "ROOT", tmp_path)
    monkeypatch.setattr(remote.time, "sleep", lambda seconds: None)
    result = remote.Worker("functional-20261110T191630Z")
    result.run.mkdir(parents=True)
    result.account = {"work_email": "synthetic@example.test", "password": "synthetic-password"}
    result.secrets.update(result.account.values())
    return result


def test_login_and_csrf_rotate_without_persisting_secrets(worker):
    responses = [Response(json.dumps({"access_token": "synthetic-token-1", "csrf_token": "synthetic-csrf-1",
                 "alias": "tech-north-a"}).encode()),
                 Response(json.dumps({"csrf_token": "synthetic-csrf-2", "refreshed": True}).encode())]
    worker.opener = Opener(responses)
    login = worker.request("login")
    refresh = worker.request("refresh")
    assert login["own_account"] and refresh["csrf_rotated"]
    assert worker.csrf == "synthetic-csrf-2"
    archive = (worker.run / "functional-exchanges.jsonl").read_text()
    for secret in worker.secrets:
        assert secret not in archive
    assert all(request.full_url.startswith(remote.ORIGIN + "/") for request in worker.opener.requests)


@pytest.mark.parametrize("kind,error,headers,body", [
    ("gzip", "gzip.BadGzipFile", {"Content-Encoding": "gzip"}, b'{"filler":"example"}'),
    ("utf8", "UnicodeDecodeError", {}, b'{"filler":"example"}\xff'),
])
def test_real_decode_path_rejects_bad_encoding(worker, kind, error, headers, body):
    worker.opener = Opener([Response(body, headers=headers)])
    record = worker.request(kind)
    assert record["decode_error"] == error
    assert record["normalized"]["json_parsed"] is False


def test_cutoff_detects_missing_events_even_if_http_body_completes(worker):
    worker.opener = Opener([Response(b'{"seq":0}\n{"seq":1}\n',
                           headers={"X-Lab-Stream-Cut": "after-2048"})])
    record = worker.request("cutoff")
    assert record["normalized"]["read_complete"] is True
    assert record["normalized"]["stream_incomplete"] is True
    assert record["normalized"]["completed_events"] == 2


def test_unlabelled_502_stops_as_unexpected_degradation(worker):
    worker.opener = Opener([Response(b'{"error":"unavailable"}', status=502)])
    with pytest.raises(RuntimeError, match="Unexpected upstream"):
        worker.request("session")
    evidence = json.loads((worker.run / "functional-exchanges.jsonl").read_text())
    assert evidence["status"] == 502 and "stop_reason" in evidence


def test_labelled_502_is_preserved_as_intended_fixture(worker):
    worker.opener = Opener([Response(b'{"error":"unavailable"}', status=502,
                           headers={"X-Lab-Injected": "502"})])
    assert worker.request("session")["normalized"]["status"] == 502


def test_remote_request_budget_prevents_extra_network(worker):
    worker.calls = remote.MAX_CALLS
    worker.opener = Opener([])
    with pytest.raises(RuntimeError, match="budget"):
        worker.request("session")
    assert not worker.opener.requests


def test_smaller_continuation_budget_is_enforced(worker):
    worker.max_calls = 2
    worker.calls = 2
    worker.opener = Opener([])
    with pytest.raises(RuntimeError, match="budget"):
        worker.request("session")
    assert not worker.opener.requests


def test_original_gateway_action_mismatch_is_still_a_failed_contract():
    item = {"id": "gateway", "category": "upstream_error", "action": "wait_retry",
            "delay_seconds": 1, "payload_usable": False}
    assert host.valid_decision(item, "gateway") is False
    item["action"] = "backoff_retry"
    assert host.valid_decision(item, "gateway") is True


def test_redirect_does_not_follow_other_target(worker):
    worker.opener = Opener([Response(b"", status=302)])
    with pytest.raises(RuntimeError, match="redirect refused"):
        worker.request("session")
    assert len(worker.opener.requests) == 1
    assert remote.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example") is None


def test_provider_observation_excludes_identity_body_and_unknown_headers():
    record = {"body_redacted": "private host data", "normalized": {
        "status": 401, "json_parsed": True, "body": {"token": "private-token", "error": "other"},
        "context": "private credentials", "identity": "private user", "url": "http://private-host",
        "headers": {"authorization": "Bearer private-token", "retry-after": "3"}}}
    result = host.provider_observation(record, "expiry")
    assert result == {"id": "expiry", "status": 401, "json_parsed": True,
                      "headers": {"Retry-After": "3"}}


@pytest.mark.parametrize("delay,action,passed", [(3, "wait_retry", True), (2, "wait_retry", False),
    (True, "wait_retry", False), (61, "wait_retry", False), (3, "shell_exec", False)])
def test_provider_decision_cannot_skip_wait_or_choose_other_actions(delay, action, passed):
    item = {"id": "throttle", "category": "rate_limited", "action": action,
            "delay_seconds": delay, "payload_usable": False}
    assert host.valid_decision(item, "throttle", 3) is passed


def test_worker_cannot_dispatch_generic_commands(worker):
    with pytest.raises(ValueError, match="Unknown fixed"):
        worker.dispatch({"action": "exec", "command": "anything"})
    with pytest.raises(KeyError):
        worker.request("discovery")


def test_unsafe_restore_does_not_call_compose(worker, monkeypatch):
    worker.prepared = True
    monkeypatch.setattr(remote.subprocess, "run", lambda *args, **kwargs: pytest.fail("unsafe mutation"))
    with pytest.raises(RuntimeError, match="restore refused"):
        worker.restore()


def test_inspection_never_reads_secret_files_or_ground_truth():
    assert ".env" not in host.INSPECT and "ground-truth" not in host.INSPECT
    assert "discovery_crapi_runner" not in (SCRIPTS / "lab_functional_probe.py").read_text()
    assert "run_suite" not in (SCRIPTS / "lab_functional_probe.py").read_text()


def test_trace_preserves_raw_framing_without_losing_valid_events(worker):
    raw = '{"seq":1}\\n{"seq":2}\nnon-json-note\n{"seq":3}\n'
    (worker.run / "proxy.log").write_text(raw)
    result = worker.dispatch({"action": "trace"})
    assert result["raw_log"] == raw
    assert [event["seq"] for event in result["events"]] == [1, 2, 3]
    assert result["parse_errors"] == 1


def test_trace_parses_actual_proxy_text_format(worker):
    raw = '[2026-11-10 20:00:00.001] [SEQ=0017] actor=hash GET    /api/v1/access/session -> 500 ( 300.1ms) FORWARDED=False evidence_ref=injected-500\n'
    (worker.run / "proxy.log").write_text(raw)
    result = worker.dispatch({"action": "trace"})
    assert result["raw_log"] == raw and result["parse_errors"] == 0
    assert result["events"][0]["seq"] == 17 and result["events"][0]["status"] == 500
