"""Recovery policy contracts, checked offline before any live measurement."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("p0_completion", SCRIPTS / "p0_functional_completion.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def rate(header="5", error="rate_limited"):
    return {"status": 429, "headers": {"retry-after": header},
            "body_redacted": json.dumps({"error": error})}


class Worker:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.now = 0.0
        self.waits = []
        self.requests = 0

    def wait(self, seconds):
        self.waits.append(seconds)
        self.now += seconds
        return {"waited_seconds": seconds}

    def call(self, action, **options):
        assert action == "request" and options == {"case": "session"}
        self.requests += 1
        return next(self.responses)


def test_repeated_429_recovers_with_bounded_exponential_waits():
    worker = Worker([rate(), rate(), rate(), {"status": 200, "own_account": True}])
    result = module.recover(worker, rate(), 5, now=lambda: worker.now)
    assert worker.waits == [5.25, 10.25, 20.25, 30.25]
    assert result["total_wait_seconds"] == 66
    assert result["recovered"]["status"] == 200 and worker.requests == 4


def test_budget_429_is_terminal_without_any_retry():
    worker = Worker([])
    with pytest.raises(module.meta.ProbeStopped, match="not transient"):
        module.recover(worker, rate(error="budget_exhausted"), 5, now=lambda: worker.now)
    assert not worker.waits and not worker.requests


@pytest.mark.parametrize("header", [None, "0", "61", "-1", "garbage", "1000000"])
def test_bad_or_excessive_retry_after_stops_before_wait(header):
    worker = Worker([])
    with pytest.raises(module.meta.ProbeStopped, match="Retry-After"):
        module.recover(worker, rate(header), 5, now=lambda: worker.now)
    assert not worker.requests and not worker.waits


def test_four_attempt_limit_does_not_make_fifth_request():
    worker = Worker([rate()] * 4)
    with pytest.raises(module.meta.ProbeStopped, match="Four retry"):
        module.recover(worker, rate(), 5, now=lambda: worker.now)
    assert worker.requests == 4


def test_large_server_wait_honored_then_cumulative_budget_stops():
    worker = Worker([rate("60")])
    with pytest.raises(module.meta.ProbeStopped, match="time budget"):
        module.recover(worker, rate("60"), 60, now=lambda: worker.now)
    assert worker.waits == [60.25] and worker.requests == 1


def test_insufficient_actual_wait_cannot_send_retry():
    worker = Worker([])
    worker.wait = lambda seconds: {"waited_seconds": seconds - 1}
    with pytest.raises(module.meta.ProbeStopped, match="Observed wait"):
        module.recover(worker, rate(), 5, now=lambda: worker.now)
    assert not worker.requests


def test_unexpected_503_during_recovery_stops():
    worker = Worker([{"status": 503, "headers": {}}])
    with pytest.raises(module.meta.ProbeStopped, match="Unexpected response"):
        module.recover(worker, rate(), 5, now=lambda: worker.now)
    assert worker.requests == 1


def test_p0_large_metadata_omits_private_body_and_identities():
    record = {"headers": {}, "normalized": {"status": 200, "json_parsed": True,
              "bytes_received": 2097152, "nesting_depth": 23, "tail_marker_present": True,
              "account": "private", "api_key": "private", "body": {"token": "private"}}}
    result = module.observation(record, "large_json")
    assert "private" not in json.dumps(result)
    assert result["nesting_depth"] == 23 and result["tail_marker_present"] is True


def test_125_call_scope_requires_explicit_override(tmp_path):
    scope = {"status": "READY", "in_scope": [{"asset": value} for value in [
        "ssh://31.58.250.147:22", "http://31.58.250.147:18901", "http://127.0.0.1:18901"]],
        "rules": {"max_rps": 2, "max_concurrency": 1, "http_request_budget": 125,
                  "no_dos": True, "no_destructive": True, "stop_on_unexpected_degradation": True}}
    (tmp_path / ".codex").mkdir()
    path = tmp_path / ".codex/scope.json"
    path.write_text(json.dumps(scope))
    admin = module.lab.LabSSH.__new__(module.lab.LabSSH)
    admin.directory = tmp_path
    with pytest.raises(RuntimeError, match="limits"):
        admin.scope()
    scope["rules"]["explicit_125_http_authorization"] = True
    path.write_text(json.dumps(scope))
    admin.scope()
