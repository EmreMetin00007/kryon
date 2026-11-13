"""Offline evidence and request-boundary regression tests for the Meta probe."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import urllib.error
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "meta_functional_probe", Path(__file__).parents[1] / "scripts/meta_functional_probe.py")
probe_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe_module)


class Response(io.BytesIO):
    status = 200
    headers = {"Content-Type": "application/json"}


class Opener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return result


def message(text):
    return {"status": "completed", "model": probe_module.MODEL,
            "output": [{"type": "message", "content": [
                {"type": "output_text", "text": text}]}], "usage": {"total_tokens": 7}}


def tool_response(arguments='{"values":[12,8,4]}', name="sum_values"):
    return {"status": "completed", "output": [{"type": "function_call", "name": name,
            "arguments": arguments, "call_id": "synthetic-call-1"}],
            "usage": {"total_tokens": 5}}


def json_response(value):
    return Response(json.dumps(value).encode())


def stream_response(done=True):
    events = [{"type": "response.output_text.delta", "delta": "STREAM_"},
              {"type": "response.output_text.delta", "delta": "OK"},
              {"type": "response.completed", "response": message("STREAM_OK")}]
    wire = "".join("data: " + json.dumps(event) + "\n\n" for event in events)
    return Response((wire + ("data: [DONE]\n\n" if done else "")).encode())


@pytest.fixture
def previous(tmp_path, monkeypatch):
    monkeypatch.setattr(probe_module, "DATA_ROOT", tmp_path)
    monkeypatch.setattr(probe_module, "audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(probe_module.time, "sleep", lambda duration: None)
    directory = tmp_path / "prior"
    directory.mkdir()
    checks = [{"check": name, "passed": True} for name in sorted(
        probe_module.INITIAL_CHECKS | {"http_" + name for name in probe_module.EXPECTED})]
    summary = {"endpoint": probe_module.ENDPOINT, "model_requested": probe_module.MODEL,
               "vds_calls": 0, "checks_passed": 10, "checks_executed": 10,
               "planned_checks": 13, "checks": checks, "measured_tokens": 972,
               "provider_calls": 3}
    (directory / "summary.json").write_text(json.dumps(summary))
    manifest = {"summary.json": hashlib.sha256((directory / "summary.json").read_bytes()).hexdigest()}
    (directory / "EVIDENCE-MANIFEST.json").write_text(json.dumps(manifest))
    return directory


@pytest.fixture
def probe(tmp_path, previous):
    directory = tmp_path / "new"
    (directory / ".codex").mkdir(parents=True)
    scope = {"status": "READY", "in_scope": [{"asset": probe_module.ENDPOINT,
             "methods": ["POST"]}], "rules": {"max_requests": 3, "max_rps": 1,
             "max_concurrency": 1, "max_output_tokens_per_request": 1536,
             "synthetic_input_only": True, "stop_on_provider_error": True}}
    (directory / ".codex/scope.json").write_text(json.dumps(scope))
    return probe_module.Probe(directory, "synthetic-secret-never-real", "remaining",
                              probe_module.resume_evidence(directory, previous))


@pytest.mark.parametrize("done", [True, False])
def test_remaining_sequence_and_verified_aggregate(probe, previous, done):
    original = {path.name: path.read_bytes() for path in previous.iterdir()}
    probe.opener = Opener([json_response(tool_response()), json_response(message("24")),
                           stream_response(done)])
    probe.run()
    summary = probe.finish(None)
    requests = probe.opener.requests
    assert len(requests) == 3
    assert all(request.full_url == probe_module.ENDPOINT and request.method == "POST"
               for request in requests)
    first, followup, streamed = [json.loads(request.data) for request in requests]
    assert first["tool_choice"] == "auto"
    assert first["tools"][0]["name"] == "sum_values"
    assert "tools" not in followup and "tool_choice" not in followup
    assert followup["input"][-1]["output"] == '{"total": 24}'
    assert streamed["stream"] is True
    assert summary["provider_calls"] == summary["planned_provider_calls"] == 3
    assert summary["measured_tokens"] == 19
    assert summary["suite"] == {"checks_passed": 13, "checks_executed": 13,
                                "planned_checks": 13, "complete": True,
                                "measured_tokens": 991}
    assert original == {path.name: path.read_bytes() for path in previous.iterdir()}
    manifest = json.loads((probe.directory / "EVIDENCE-MANIFEST.json").read_text())
    assert ".codex/scope.json" in manifest
    assert all(hashlib.sha256((probe.directory / name).read_bytes()).hexdigest() == digest
               for name, digest in manifest.items())
    with pytest.raises(probe_module.ProbeStopped, match="budget"):
        probe.request("fourth", probe_module.body("extra"))
    assert len(requests) == 3


@pytest.mark.parametrize("arguments,name", [
    ("not-json", "sum_values"), ('{"values":[12,8,4]}', "shell_exec"),
    ('{"values":[12.0,8,4]}', "sum_values"), ('{"values":[12,8,4],"extra":1}', "sum_values"),
])
def test_unexpected_tool_fails_without_continuation(probe, arguments, name):
    probe.opener = Opener([json_response(tool_response(arguments, name))])
    with pytest.raises(probe_module.ProbeStopped, match="Unexpected local tool"):
        probe.run()
    assert probe.checks[0]["passed"] is False
    assert len(probe.opener.requests) == 1
    assert probe.finish("Unexpected tool")["suite"]["complete"] is False


def test_http_error_keeps_body_without_retry(probe):
    error = {"error": {"type": "invalid_request_error", "param": "tool_choice",
                      "message": "synthetic provider error"}}
    probe.opener = Opener([urllib.error.HTTPError(
        probe_module.ENDPOINT, 400, "Bad Request", {}, io.BytesIO(json.dumps(error).encode()))])
    with pytest.raises(probe_module.ProbeStopped, match="HTTP 400; no retry"):
        probe.run()
    evidence = json.loads((probe.directory / "01-tool-selection.json").read_text())
    assert evidence["response"] == error
    assert len(probe.opener.requests) == 1
    assert probe.finish("HTTP 400")["suite"]["checks_passed"] == 10


def test_truncated_stream_keeps_partial_evidence(probe):
    wire = b'data: {"type":"response.output_text.delta","delta":"STREAM_"}\n\n'
    probe.opener = Opener([json_response(tool_response()), json_response(message("24")),
                           Response(wire)])
    with pytest.raises(probe_module.ProbeStopped, match="did not complete"):
        probe.run()
    evidence = json.loads((probe.directory / "03-streaming.json").read_text())
    assert evidence["events"][0]["delta"] == "STREAM_"
    assert evidence["stream_wire"] == wire.decode()
    assert probe.finish("Incomplete stream")["suite"]["complete"] is False


def test_failed_check_does_not_mark_complete(probe):
    probe.opener = Opener([json_response(tool_response()), json_response(message("25")),
                           stream_response()])
    probe.run()
    summary = probe.finish(None)
    assert summary["checks_passed"] == 2
    assert summary["complete"] is summary["suite"]["complete"] is False


@pytest.mark.parametrize("field,value", [
    ("max_requests", 0), ("max_rps", 2), ("max_concurrency", 2),
    ("synthetic_input_only", False), ("stop_on_provider_error", False),
    ("max_output_tokens_per_request", 64),
])
def test_scope_limits_block_before_network(probe, field, value):
    scope_path = probe.directory / ".codex/scope.json"
    scope = json.loads(scope_path.read_text())
    scope["rules"][field] = value
    scope_path.write_text(json.dumps(scope))
    probe.opener = Opener([])
    with pytest.raises(probe_module.ProbeStopped):
        probe.request("blocked", probe_module.body("synthetic"))
    assert not probe.opener.requests


def test_scope_does_not_accept_other_endpoint(probe):
    path = probe.directory / ".codex/scope.json"
    scope = json.loads(path.read_text())
    scope["in_scope"][0]["asset"] = "https://api.meta.ai/v1/other"
    path.write_text(json.dumps(scope))
    with pytest.raises(probe_module.ProbeStopped, match="Exact POST endpoint"):
        probe.validate_scope(probe_module.body("synthetic"))


def test_prior_evidence_tampering_rejected(tmp_path, previous):
    (previous / "summary.json").write_text("{}")
    with pytest.raises(probe_module.ProbeStopped, match="preserved manifest"):
        probe_module.resume_evidence(tmp_path / "new", previous)


def test_manifest_path_escape_rejected(tmp_path, previous):
    path = previous / "EVIDENCE-MANIFEST.json"
    manifest = json.loads(path.read_text())
    manifest["../outside"] = "invalid"
    path.write_text(json.dumps(manifest))
    with pytest.raises(probe_module.ProbeStopped, match="unsafe path"):
        probe_module.resume_evidence(tmp_path / "new", previous)


def test_save_redacts_and_refuses_overwrite(probe):
    probe.save("synthetic.json", {"text": probe.key})
    assert probe.key not in (probe.directory / "synthetic.json").read_text()
    with pytest.raises(FileExistsError):
        probe.save("synthetic.json", {"text": "replacement"})


def test_redirect_is_refused():
    assert probe_module.NoRedirect().redirect_request(None, None, 302, "redirect", {},
                                                      "https://other.example") is None


def test_nonterminal_key_input_rejected(monkeypatch):
    monkeypatch.setattr(probe_module.sys, "stdin", io.StringIO("synthetic-secret"))
    with pytest.raises(RuntimeError, match="interactive terminal"):
        probe_module.read_key()
