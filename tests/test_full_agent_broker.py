"""Offline provider diagnostics and conservative token accounting regressions."""
from __future__ import annotations

import json
from http.client import IncompleteRead

import pytest
import requests
from urllib3.exceptions import ProtocolError

from full_agent_budget import BudgetError, provider_accounting_usage, usage_tokens
from test_full_agent_preflight import broker as broker, mock_provider


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send",
                        lambda *_a, **_kw: pytest.fail("offline provider test opened a connection"))


def request_body():
    return {"model": "model", "messages": [{"role": "user", "content": "owned task"}], "max_tokens": 128}


def assert_retained_failure(broker, reason, caught):
    assert caught.value.code == reason and broker.stop_reason == reason
    event = broker.budget.snapshot()["events"][-1]
    assert event["provider_failure_reason"] == reason
    assert event["charged"] == event["reserved"] > 0 and not event["measurement_valid"]
    assert broker.budget.used["tokens"] == event["reserved"]
    assert not broker.budget.pending and broker.budget.blocked
    assert event["cost_usd"] is None
    diagnostic = json.loads((broker.private / "provider-response-diagnostics.json").read_text())[-1]
    assert diagnostic["failure_reason"] == reason
    assert "synthetic-private" not in json.dumps(event) + json.dumps(diagnostic) + str(caught.value)
    # An indeterminate request must never be replayed, including when its
    # caller retries after the first error. The charged reservation stays.
    with pytest.raises(BudgetError):
        broker.completion(request_body())
    assert broker.calls == 1 and broker.budget.used["tokens"] == event["reserved"]


@pytest.mark.parametrize("usage,reason", [
    (None, "usage_missing"),
    ("synthetic-private-usage", "usage_shape_invalid"),
    ({"prompt_tokens": "synthetic-private-count", "completion_tokens": 2}, "usage_counts_invalid"),
    ({"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}, "usage_zero_on_nonempty_completion"),
    ({"prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5}, "usage_zero_on_nonempty_completion"),
])
@pytest.mark.parametrize("message", [{"content": "synthetic-private-completion"}, {"tool_calls": [{"function": {
    "name": "example", "arguments": "{}"}}]}])
def test_unmeasured_nonempty_completion_retains_full_reservation(broker, monkeypatch, usage, reason, message):
    response = {"choices": [{"message": message}]}
    if usage is not None:
        response["usage"] = usage
    mock_provider(monkeypatch, broker, response)
    with pytest.raises(BudgetError) as caught:
        broker.completion(request_body())
    assert_retained_failure(broker, reason, caught)
    assert broker.budget.events[-1]["usage"] is None


def test_empty_completion_with_valid_prompt_usage_is_measured(broker, monkeypatch):
    mock_provider(monkeypatch, broker, {"choices": [{"message": {"content": ""}}], "usage": {
        "prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5}})
    broker.completion(request_body())
    assert broker.budget.used["tokens"] == 5 and not broker.budget.blocked
    assert broker.budget.events[-1]["measurement_valid"]


def test_common_usage_parser_rejects_zero_output_for_nonempty_completion():
    usage = {"prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5}
    assert usage_tokens(usage) == 5
    with pytest.raises(BudgetError) as caught:
        provider_accounting_usage(usage, provider="https://provider.invalid/v1", model="model",
                                  nonempty_completion=True)
    assert caught.value.code == "usage_zero_on_nonempty_completion"


@pytest.mark.parametrize("failure", [requests.ConnectionError("synthetic-private-url"),
    requests.ReadTimeout("synthetic-private-header"), requests.exceptions.SSLError("synthetic-private-certificate")])
def test_transport_failure_has_distinct_diagnosis_without_replay(broker, monkeypatch, failure):
    mock_provider(monkeypatch, broker, {}, failure=failure)
    with pytest.raises(BudgetError) as caught:
        broker.completion(request_body())
    assert_retained_failure(broker, "provider_transport_error", caught)
    assert broker.budget.events[-1]["upstream_http_status"] is None
    assert broker.budget.events[-1]["provider_error"] == type(failure).__name__


@pytest.mark.parametrize("failure", [ProtocolError("synthetic-private-stream"),
    IncompleteRead(b"synthetic-private-partial-body"), OSError("synthetic-private-stream")])
def test_body_transport_failure_after_http_200_remains_transport_error(broker, monkeypatch, failure):
    mock_provider(monkeypatch, broker, {})
    post = requests.Session.post

    def broken_post(session, *args, **kwargs):
        response = post(session, *args, **kwargs)
        def read(*_a, **_kw):
            raise failure
        response.raw.read = read
        return response

    monkeypatch.setattr(requests.Session, "post", broken_post)
    with pytest.raises(BudgetError) as caught:
        broker.completion(request_body())
    assert_retained_failure(broker, "provider_transport_error", caught)
    assert broker.budget.events[-1]["upstream_http_status"] == 200


@pytest.mark.parametrize("status", [401, 429, 503])
def test_provider_http_error_has_distinct_diagnosis_without_replay(broker, monkeypatch, status):
    mock_provider(monkeypatch, broker, {"error": {"message": "synthetic-private-body"}}, status=status)
    with pytest.raises(BudgetError, match=f"provider HTTP {status}") as caught:
        broker.completion(request_body())
    assert_retained_failure(broker, "provider_http_error", caught)
    assert broker.budget.events[-1]["upstream_http_status"] == status


@pytest.mark.parametrize("response,reason", [
    (["synthetic-private-response"], "response_object_invalid"),
    ({"error": {"message": "synthetic-private-error"}}, "provider_response_error"),
])
def test_invalid_response_and_provider_error_envelope_are_not_network_errors(broker, monkeypatch, response, reason):
    mock_provider(monkeypatch, broker, response)
    with pytest.raises(BudgetError) as caught:
        broker.completion(request_body())
    assert_retained_failure(broker, reason, caught)


def test_unparseable_provider_response_is_not_a_transport_or_usage_error(broker, monkeypatch):
    mock_provider(monkeypatch, broker, {})
    post = requests.Session.post

    def malformed_post(session, *args, **kwargs):
        response = post(session, *args, **kwargs)
        response.raw.read = lambda *_a, **_kw: b"synthetic-private-invalid-json"
        return response

    monkeypatch.setattr(requests.Session, "post", malformed_post)
    with pytest.raises(BudgetError) as caught:
        broker.completion(request_body())
    assert_retained_failure(broker, "response_json_invalid", caught)


def test_shared_provider_transport_and_tool_executor_work_via_narrow_interfaces(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from full_agent_budget import SharedBudget
    from full_agent_executor import HostBroker, HostToolExecutor
    from full_agent_provider import MeteredProviderTransport

    private, work = tmp_path / "private", tmp_path / "work"
    private.mkdir()
    work.mkdir()

    class Executor:
        timeout_seconds = 900
        def __init__(self):
            self.calls = []
            self.terminated = 0
        def __call__(self, task):
            self.calls.append(task)
            return {"actual_request_cost": 1, "result": {"output": '{"ok": true}'}}
        def terminate(self):
            self.terminated += 1

    engine = SimpleNamespace(
        _is_known_tool=lambda _name: True,
        tool_capability=lambda name: {"network": name == "kali-tools_curl_request"},
        validate_tool_invocation=lambda *_a, **_kw: {"allowed": True, "reason": "allowed"},
    )
    host = HostBroker(
        budget=SharedBudget(http=3, tokens=30000),
        engine=engine,
        executor=Executor(),
        workdir=work,
        private=private,
        provider="https://provider.invalid/v1",
        models={"model"},
        api_key="host-only-sentinel",
    )
    assert isinstance(host.provider_transport, MeteredProviderTransport)
    assert isinstance(host.tool_executor, HostToolExecutor)
    assert not hasattr(host, "gate")
    assert not hasattr(host, "dispatch")
    assert not hasattr(host, "record_task_completion")

    mock_provider(monkeypatch, host, {
        "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 4, "total_tokens": 15},
    })
    response = host.provider_transport.complete(request_body())
    assert response["choices"][0]["message"]["content"] == "ok"
    assert host.budget.used["tokens"] == 15
    assert host.calls == 1

    emitted = host.call_tool("kali-tools", "curl_request", {"url": "http://127.0.0.1:8765/"})
    assert emitted["isError"] is False
    assert host.budget.used["http"] == 1
    host.close()
    assert host.executor.terminated >= 1


def test_native_compat_broker_reuses_shared_provider_and_executor_without_duplicating_engines(broker):
    from full_agent_executor import HostBroker
    from full_agent_native_compat import LOCAL_TOOLS, NativeBrokerCompat, make_server, runtime_request
    import full_agent_broker as compat_facade

    assert isinstance(broker, HostBroker)
    assert isinstance(broker, NativeBrokerCompat)
    assert compat_facade.Broker is NativeBrokerCompat
    assert compat_facade.LOCAL_TOOLS is LOCAL_TOOLS
    assert callable(make_server)
    assert callable(runtime_request)
