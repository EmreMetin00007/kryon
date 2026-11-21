"""Reusable metered OpenAI-compatible provider transport and diagnostics.

Shared host primitive with no native client, bridge, or local-tool dependencies.
Only this host layer touches provider credentials and token accounting.
"""
from __future__ import annotations

from http.client import HTTPException
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from typing import Any

from full_agent_budget import (
    BudgetError,
    completion_request,
    provider_accounting_usage,
    provider_json,
    usage_tokens,
)

MAX_BODY = 16 * 1024 * 1024
TOOL_DESCRIPTION_LIMIT = 20
PYTHON_ALLOWANCE_INSTRUCTION = (
    " Submit submit_phase_summary from existing evidence; preserve NOT TESTED work."
)


def dump(path, value):
    """Atomically write JSON without NaN/Infinity."""
    path = Path(path)
    content = json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".host-", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(content)
            handle.flush()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def runtime_allowance_request(body, info, *, instruction):
    """Append the exact allowance metadata and host instruction for admission."""
    return {
        **body,
        "messages": [
            *body["messages"],
            {"role": "user", "content": "Host runtime allowance: " + provider_json(info).decode() + instruction},
        ],
    }


def provider_usage_diagnostics(response):
    """Retain bounded accounting shape, never model text or arbitrary values."""
    def count(value):
        result: dict[str, Any] = {
            "type": type(value).__name__
            if type(value) in {int, float, bool, str, list, dict, type(None)}
            else "other"
        }
        if type(value) is int and abs(value) <= 1_000_000_000_000:
            result["value"] = value
        return result

    if not isinstance(response, dict):
        return {"response_object": False}
    usage = response.get("usage")
    result = {
        "response_object": True,
        "usage_present": "usage" in response,
        "usage_type": count(usage)["type"],
        "error_present": "error" in response,
        "choices_count": min(len(response["choices"]), 1000)
        if isinstance(response.get("choices"), list)
        else None,
    }
    if isinstance(usage, dict):
        result["counts"] = {
            key: count(usage[key])
            for key in ("prompt_tokens", "completion_tokens", "total_tokens")
            if key in usage
        }
        result["details"] = {}
        for field, subset in (
            ("prompt_tokens_details", "cached_tokens"),
            ("completion_tokens_details", "reasoning_tokens"),
        ):
            if field in usage:
                detail = usage[field]
                result["details"][field] = {"type": count(detail)["type"]}
                if isinstance(detail, dict) and subset in detail:
                    result["details"][field][subset] = count(detail[subset])
    return result


def provider_failure_reason(exc, status):
    """Classify known host errors without persisting exception text."""
    if status is not None and status != 200:
        return "provider_http_error"
    if isinstance(exc, BudgetError):
        if exc.code is not None:
            return exc.code
        return {
            "provider omitted usage": "usage_missing",
            "invalid provider token usage": "usage_counts_invalid",
            "inconsistent provider token usage": "usage_total_inconsistent",
            "invalid provider usage details": "usage_details_invalid",
            "invalid provider usage subset": "usage_subset_invalid",
            "provider usage exceeded admitted prompt or output bound": "usage_bound_exceeded",
            "provider response omitted choices": "choices_missing",
            "provider response too large": "response_too_large",
            "session is closed": "session_closed",
            "native session is closed": "session_closed",
        }.get(str(exc), "provider_budget_error")
    if isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError)):
        return "response_json_invalid"
    # raw.read() can raise urllib3/http.client errors directly, outside
    # requests' exception wrapper, even after receiving HTTP 200 headers.
    from requests.exceptions import RequestException
    from urllib3.exceptions import HTTPError

    if isinstance(exc, (RequestException, HTTPError, HTTPException, OSError)):
        return "provider_transport_error"
    return "provider_response_invalid"


def provider_failure(reason, status, *, reservation_retained):
    """Surface a stable diagnosis without upstream exception/body text."""
    message = (
        f"provider HTTP {status}; response body withheld"
        if reason == "provider_http_error"
        else reason.replace("_", " ")
    )
    if reservation_retained:
        message += "; token reservation retained"
    return BudgetError(message, code=reason)


class SessionGate:
    """Shared fail-closed lifecycle gate for provider and executor calls."""

    def __init__(self):
        self.closed = threading.Event()
        self.stop_reason = ""

    def require_open(self):
        if self.closed.is_set():
            raise BudgetError("session is closed", code="session_closed")
        if self.stop_reason:
            raise BudgetError(self.stop_reason)


class MeteredProviderTransport:
    """Bounded, usage-settled OpenAI-compatible chat completions transport."""

    def __init__(
        self,
        *,
        budget,
        private,
        provider,
        models,
        api_key,
        api_key_header="Authorization",
        session_gate=None,
        provider_options=None,
    ):
        if api_key_header not in {"Authorization", "X-API-Key"}:
            raise ValueError("unsupported provider API key header")
        self.budget = budget
        self.private = Path(private)
        self.provider = provider
        self.models = set(models)
        self.api_key = api_key
        self.api_key_header = api_key_header
        self.session_gate = session_gate or SessionGate()
        self.provider_options = dict(provider_options) if isinstance(provider_options, dict) and provider_options else None
        self.provider_lock = threading.Lock()
        self.transport_lock = threading.Lock()
        self.upstream = None
        self._active_upstreams: set[Any] = set()
        self.calls = 0
        self.provider_requests = []
        self.provider_responses = []

    def close_upstream(self):
        with self.transport_lock:
            targets = list(self._active_upstreams)
            if self.upstream is not None and self.upstream not in targets:
                targets.append(self.upstream)
            self._active_upstreams.clear()
            self.upstream = None
        if targets:
            # Closing a response while another thread reads it can block on
            # the IO lock. It must never delay terminating host children.
            import time as _time

            threads = []
            for target in targets:
                def close_response(obj=target):
                    try:
                        obj.close()
                    except Exception:
                        pass

                closer = threading.Thread(target=close_response, daemon=True)
                closer.start()
                threads.append(closer)
            deadline = _time.monotonic() + 0.2
            for closer in threads:
                rem = max(0.0, deadline - _time.monotonic())
                closer.join(timeout=rem)

    def complete(
        self,
        body,
        *,
        prepare_request=None,
        runtime_policy=None,
        task_spec_id=None,
        context_projection=None,
        minimum_output_tokens=1,
        max_body=MAX_BODY,
    ):
        """Admit, reserve, execute, verify usage, and settle one completion."""
        with self.provider_lock:
            self.session_gate.require_open()
            remaining = self.budget.available("tokens")
            metrics = {
                "remaining_tokens": remaining,
                "messages_bytes": len(provider_json(body.get("messages"))) if isinstance(body, dict) else 0,
                "tools_bytes": len(provider_json(body.get("tools"))) if isinstance(body, dict) else 0,
                "admitted": False,
                "task_spec_id": task_spec_id,
            }
            if context_projection is not None:
                metrics["context_projection"] = context_projection
            self.provider_requests.append(metrics)
            runtime_info = None
            try:
                if prepare_request is not None:
                    body, runtime_info, remaining = prepare_request(body, metrics)
                    if runtime_info is not None:
                        metrics["runtime_allowance"] = runtime_info
                    if isinstance(body, dict):
                        metrics.update(
                            messages_bytes=len(provider_json(body.get("messages"))),
                            tools_bytes=len(provider_json(body.get("tools"))),
                        )
                if self.provider_options and isinstance(body, dict) and "providerOptions" not in body:
                    body = {**body, "providerOptions": self.provider_options}
                request, reserve = completion_request(
                    body,
                    models=self.models,
                    remaining=remaining,
                    diagnostics=metrics,
                    minimum_output_tokens=minimum_output_tokens,
                )
                ticket = self.budget.reserve("tokens", reserve)
                if runtime_info is not None and runtime_policy is not None:
                    runtime_policy.admitted(runtime_info)
                metrics.update(admitted=True, reservation=reserve)
            except BudgetError as exc:
                metrics["rejection"] = (
                    "bounded_prompt_does_not_fit"
                    if exc.args == ("insufficient tokens for bounded prompt and completion",)
                    else "budget_unavailable"
                )
                if runtime_policy is not None:
                    if str(exc) in {"context_limit_exhausted", "phase_call_budget_exhausted"}:
                        metrics["rejection"] = str(exc)
                    self.session_gate.stop_reason = (
                        "phase_token_budget_exhausted"
                        if metrics["rejection"] == "bounded_prompt_does_not_fit"
                        and remaining < self.budget.available("tokens")
                        else str(exc)
                        if str(exc) in {"context_limit_exhausted", "phase_call_budget_exhausted"}
                        else "token_admission_exhausted"
                    )
                elif metrics["rejection"] == "bounded_prompt_does_not_fit":
                    # No retries/extra completions after an admission failure.
                    self.session_gate.stop_reason = "token_admission_exhausted"
                raise
            finally:
                dump(self.private / "provider-requests.json", self.provider_requests)
                if runtime_policy is not None:
                    dump(self.private / "runtime-policy.json", runtime_policy.snapshot())
            dump(self.private / "budget.json", self.budget.snapshot())
            self.calls += 1
            call_index = self.calls
            if self.budget.checkpoint is not None:
                self.budget.checkpoint()

        response, measured, safe_usage = None, None, None
        status, error, encoding = None, None, None
        failure_reason, accounting_shape, response_bytes = None, None, None
        accounting_basis = None
        local_upstream = None
        try:
            import requests

            with requests.Session() as session:
                session.trust_env = False
                with session.post(
                    self.provider.rstrip("/") + "/chat/completions",
                    data=provider_json(request),
                    headers={
                        self.api_key_header: (
                            "Bearer " + self.api_key
                            if self.api_key_header == "Authorization"
                            else self.api_key
                        ),
                        "Content-Type": "application/json",
                    },
                    allow_redirects=False,
                    timeout=min(360, self.budget.remaining_seconds()),
                    stream=True,
                ) as upstream:
                    local_upstream = upstream
                    with self.transport_lock:
                        self._active_upstreams.add(upstream)
                        self.upstream = upstream
                    self.session_gate.require_open()
                    status = upstream.status_code
                    header = upstream.headers.get("Content-Encoding", "identity").strip().lower()
                    encoding = header if header in {"identity", "gzip", "deflate", "br", "zstd"} else "other"
                    if upstream.status_code != 200:
                        raise BudgetError(f"provider HTTP {status}; response body withheld")
                    # requests' raw stream otherwise returns compressed wire
                    # bytes. Bound the decoded JSON body, including gzip/br.
                    raw = upstream.raw.read(max_body + 1, decode_content=True)
                    response_bytes = len(raw)
                    if len(raw) > max_body:
                        raise BudgetError("provider response too large")
                    response = json.loads(raw)
                    accounting_shape = provider_usage_diagnostics(response)
            if not isinstance(response, dict):
                raise BudgetError("provider response is not an object", code="response_object_invalid")
            if response.get("error") is not None:
                raise BudgetError("provider returned an error", code="provider_response_error")
            choices = response.get("choices")
            nonempty_completion = isinstance(choices, list) and any(
                isinstance(row, dict)
                and isinstance(row.get("message"), dict)
                and any(
                    row["message"].get(field)
                    for field in (
                        "content",
                        "tool_calls",
                        "function_call",
                        "refusal",
                        "reasoning",
                        "reasoning_content",
                    )
                )
                for row in choices
            )
            usage, accounting_basis = provider_accounting_usage(
                response.get("usage"),
                provider=self.provider,
                model=request["model"],
                nonempty_completion=nonempty_completion,
            )
            measured = usage_tokens(usage)
            safe_usage = {
                key: usage[key]
                for key in ("prompt_tokens", "completion_tokens", "total_tokens")
                if key in usage
            }
            for key, subset in (
                ("prompt_tokens_details", "cached_tokens"),
                ("completion_tokens_details", "reasoning_tokens"),
            ):
                if isinstance(usage.get(key), dict):
                    detail = usage[key]
                    safe_usage[key] = {subset: detail[subset]} if detail.get(subset) is not None else {}
            if (
                usage["prompt_tokens"] > metrics["prompt_upper_bound"]
                or usage["completion_tokens"] > metrics["admitted_output_tokens"]
            ):
                measured = None
                raise BudgetError("provider usage exceeded admitted prompt or output bound")
            if not isinstance(response.get("choices"), list) or not response["choices"]:
                raise BudgetError("provider response omitted choices")
            return response
        except Exception as exc:
            # Never retain exception text: requests exceptions can contain
            # URLs, headers or private response data. Status is sufficient.
            error = type(exc).__name__
            failure_reason = provider_failure_reason(exc, status)
            self.session_gate.stop_reason = failure_reason
            raise provider_failure(failure_reason, status, reservation_retained=measured is None) from None
        finally:
            with self.transport_lock:
                if local_upstream is not None:
                    self._active_upstreams.discard(local_upstream)
                    if self.upstream is local_upstream:
                        self.upstream = next(iter(self._active_upstreams), None)
            with self.provider_lock:
                try:
                    self.budget.settle(
                        ticket,
                        measured,
                        model=request["model"],
                        runtime_phase=runtime_info["phase"] if runtime_info else None,
                        task_spec_id=metrics["task_spec_id"],
                        usage=safe_usage,
                        upstream_http_status=status,
                        provider_error=error,
                        provider_failure_reason=failure_reason,
                        usage_diagnostics=accounting_shape,
                        accounting_basis=accounting_basis,
                        provider_content_encoding=encoding,
                        prompt_upper_bound=metrics["prompt_upper_bound"],
                        reserved_output_tokens=metrics["admitted_output_tokens"],
                        bound_profile=metrics["bound_profile"],
                        cost_usd=None,
                    )
                except BudgetError:
                    if failure_reason is not None:
                        # Settlement retains the reservation, but must not
                        # replace a transport/HTTP diagnosis with missing usage.
                        raise provider_failure(failure_reason, status, reservation_retained=True) from None
                    raise
                finally:
                    dump(self.private / "budget.json", self.budget.snapshot())
                    self.provider_responses.append(
                        {
                            "call": call_index,
                            "model": request["model"],
                            "upstream_http_status": status,
                            "content_encoding": encoding,
                            "decoded_response_bytes": response_bytes,
                            "failure_reason": failure_reason,
                            "usage_diagnostics": accounting_shape,
                            "accounting_basis": accounting_basis,
                            "accounted_usage": safe_usage,
                        }
                    )
                    dump(self.private / "provider-response-diagnostics.json", self.provider_responses)
