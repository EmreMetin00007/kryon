"""Host-owned, atomic reservations for the native planner and every worker.

No reservation is refunded without a valid measurement. Cached prompt and
reasoning tokens are subsets in the OpenAI usage schema, never extra tokens.
"""
from __future__ import annotations

import json
import copy
import base64
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import time
from typing import Any
import uuid


class BudgetError(RuntimeError):
    def __init__(self, message, *, code=None):
        super().__init__(message)
        self.code = code


class SharedBudget:
    def __init__(self, *, http=300, tokens=1_000_000, seconds=1800, clock=time.monotonic):
        if any(type(n) is not int or n <= 0 for n in (http, tokens, seconds)):
            raise ValueError("budgets must be positive integers")
        self.limits = {"http": http, "tokens": tokens}
        self.used = {"http": 0, "tokens": 0}
        self.pending = {}
        self.events = []
        self.blocked = ""
        self.clock, self.deadline = clock, clock() + seconds
        self.seconds_limit = seconds
        self.lock = threading.RLock()
        self.checkpoint = None

    def remaining_seconds(self):
        return max(0, self.deadline - self.clock())

    def _available(self, kind):
        return self.limits[kind] - self.used[kind] - sum(
            row[1] for row in self.pending.values() if row[0] == kind)

    def available(self, kind):
        with self.lock:
            return self._available(kind)

    def reserve(self, kind, amount):
        with self.lock:
            if self.blocked or not self.remaining_seconds():
                raise BudgetError(self.blocked or "wall clock budget exhausted")
            if kind not in self.limits or type(amount) is not int or amount < 0:
                raise ValueError("invalid reservation")
            if amount > self._available(kind):
                raise BudgetError(kind + " budget exhausted or reserved")
            ticket = uuid.uuid4().hex
            self.pending[ticket] = (kind, amount)
            if self.checkpoint is not None:
                self.checkpoint()
            return ticket

    def settle(self, ticket, actual, **metadata):
        with self.lock:
            if ticket not in self.pending:
                raise BudgetError("unknown or already settled reservation")
            kind, amount = self.pending.pop(ticket)
            valid = type(actual) is int and 0 <= actual <= amount
            charged = actual if valid else amount
            self.used[kind] += charged
            self.events.append({"kind": kind, "reserved": amount, "charged": charged,
                                "measurement_valid": valid, **metadata})
            if not valid:
                self.blocked = "missing or invalid " + kind + " usage"
            if self.checkpoint is not None:
                self.checkpoint()
            if not valid:
                raise BudgetError(self.blocked)

    def snapshot(self):
        with self.lock:
            return {"limits": dict(self.limits), "used": dict(self.used),
                    "reserved": {k: self.limits[k] - self.used[k] - self._available(k) for k in self.limits},
                    "blocked": self.blocked, "remaining_seconds": self.remaining_seconds(),
                    "events": list(self.events)}


def usage_tokens(usage, *, nonempty_completion=False):
    if usage is None:
        raise BudgetError("provider omitted usage", code="usage_missing")
    if not isinstance(usage, dict):
        raise BudgetError("invalid provider usage shape", code="usage_shape_invalid")
    prompt, completion = usage.get("prompt_tokens"), usage.get("completion_tokens")
    if any(type(n) is not int or n < 0 for n in (prompt, completion)):
        raise BudgetError("invalid provider token usage", code="usage_counts_invalid")
    assert isinstance(prompt, int) and isinstance(completion, int)
    if nonempty_completion and completion == 0:
        raise BudgetError("provider reported zero usage for nonempty completion",
                          code="usage_zero_on_nonempty_completion")
    total = prompt + completion
    if total <= 0 or ("total_tokens" in usage and
                      (type(usage["total_tokens"]) is not int or usage["total_tokens"] != total)):
        raise BudgetError("inconsistent provider token usage", code="usage_total_inconsistent")
    for field, child, bound in (("prompt_tokens_details", "cached_tokens", prompt),
                                ("completion_tokens_details", "reasoning_tokens", completion)):
        detail = usage.get(field)
        if detail is not None:
            if not isinstance(detail, dict):
                raise BudgetError("invalid provider usage details", code="usage_details_invalid")
            count = detail.get(child, 0)
            # Optional subset metadata can be unknown. Aggregate prompt and
            # completion counts remain mandatory and cover these subsets once.
            if count is None:
                continue
            if type(count) is not int:
                raise BudgetError("invalid provider usage subset", code="usage_subset_invalid")
            assert isinstance(count, int)
            if not 0 <= count <= bound:
                raise BudgetError("invalid provider usage subset", code="usage_subset_invalid")
    return total


def provider_accounting_usage(usage, *, provider, model, nonempty_completion=False):
    """Validate usage; conservatively adapt one observed reasoning mismatch.

    Crouton sometimes reports reasoning above completion while total equals
    prompt + completion. Its semantics are uncertain, so charge both output
    counts when that mismatch occurs. Preserve the raw response for diagnostics.
    """
    try:
        usage_tokens(usage, nonempty_completion=nonempty_completion)
        return usage, 'reported_aggregate'
    except BudgetError as exc:
        if (str(exc) != 'invalid provider usage subset'
                or provider != 'https://openrouter.ai/api/v1'
                or model != 'stealth/crouton-alpha'):
            raise
        detail = usage.get('completion_tokens_details')
        reasoning = detail.get('reasoning_tokens') if isinstance(detail, dict) else None
        completion = usage.get('completion_tokens')
        if type(reasoning) is not int or reasoning <= completion:
            raise
        # Validate every other field, including the reported total and cache
        # bounds, before adapting only this nonnegative reasoning mismatch.
        checked = {**usage, 'completion_tokens_details': {**detail, 'reasoning_tokens': 0}}
        usage_tokens(checked)
        canonical = {**usage, 'completion_tokens_details': dict(detail),
                     'completion_tokens': completion + reasoning,
                     'total_tokens': usage['prompt_tokens'] + completion + reasoning}
        usage_tokens(canonical)
        return canonical, 'conservative_completion_plus_reasoning'


def provider_json(value):
    """The exact compact UTF-8 representation used for provider transport."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def compact_json_text(value):
    """Remove JSON framing whitespace, preserving strings and number spelling."""
    try:
        json.loads(value)
    except (ValueError, TypeError):
        return value
    result, quoted, escaped = [], False, False
    for char in value:
        if quoted:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            result.append(char)
        elif char not in " \t\r\n":
            result.append(char)
    return "".join(result)


TOKENIZER_URL = 'https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken'
TOKENIZER_HASH = '223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7'
FRAMING_TOKENS = 2048


@lru_cache(maxsize=4)
def local_encoder(cache_dir):
    """Load the pinned vocabulary locally. Never fetch a missing cache asset."""
    if not cache_dir:
        return None
    try:
        from tiktoken import Encoding
        path = Path(cache_dir) / hashlib.sha1(TOKENIZER_URL.encode()).hexdigest()
        with path.open('rb') as handle:
            raw = handle.read(2_000_001)
        if len(raw) > 2_000_000 or hashlib.sha256(raw).hexdigest() != TOKENIZER_HASH:
            return None
        ranks = {base64.b64decode(token): int(rank) for token, rank in
                 (line.split() for line in raw.splitlines())}
        return Encoding(name='cl100k_base', mergeable_ranks=ranks,
            pat_str=r"'(?i:[sdmt]|ll|ve|re)|[^\r\n\p{L}\p{N}]?+\p{L}++|\p{N}{1,3}+| ?[^\s\p{L}\p{N}]++[\r\n]*+|\s++$|\s*[\r\n]|\s+(?!\S)|\s",
            special_tokens={'<|endoftext|>': 100257, '<|fim_prefix|>': 100258,
                            '<|fim_middle|>': 100259, '<|fim_suffix|>': 100260,
                            '<|endofprompt|>': 100276})
    except (ImportError, OSError, ValueError):
        return None


def prompt_bound(raw):
    """Provider-independent engineering estimate with an offline byte fallback.

    Count serialized text with a pinned local tokenizer, allow 50% tokenizer
    variance and 2048 framing tokens. The output-limit field is covered by
    framing. This is not a universal upper bound for compatible providers;
    measured prompt/output overruns fail closed in the broker.
    """
    cache = os.environ.get('TIKTOKEN_CACHE_DIR', os.environ.get('DATA_GYM_CACHE_DIR',
                           str(Path(tempfile.gettempdir()) / 'data-gym-cache')))
    encoder = local_encoder(cache)
    count = len(encoder.encode_ordinary(raw.decode('utf-8'))) if encoder is not None else None
    upper = min(len(raw), (3 * count + 1) // 2) if count is not None else len(raw)
    return upper + FRAMING_TOKENS, {
        'bound_profile': 'cl100k_base_1.5x' if count is not None else 'utf8_bytes_1x',
        'serialized_tokens': count, 'tokenizer_sha256': TOKENIZER_HASH if count is not None else None,
        'framing_tokens': FRAMING_TOKENS, 'tokens_per_byte': 1 if count is None else None,
    }


def completion_request(body, *, models, remaining, output_limit=8192, diagnostics=None,
                       minimum_output_tokens=1):
    """Reserve a calibrated text prompt bound and a bounded completion."""
    allowed = {"model", "messages", "tools", "tool_choice", "parallel_tool_calls", "temperature",
               "top_p", "stop", "max_tokens", "max_completion_tokens", "stream", "stream_options",
               "presence_penalty", "frequency_penalty", "seed", "user", "reasoning_effort",
               "providerOptions"}
    if not isinstance(body, dict) or set(body) - allowed or body.get("model") not in models:
        raise ValueError("unsupported provider request or model")
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages required")
    for msg in messages:
        if not isinstance(msg, dict):
            raise ValueError("invalid message")
        content = msg.get("content")
        if content is not None and not isinstance(content, str):
            if not isinstance(content, list) or any(not isinstance(p, dict) or
                    p.get("type") != "text" or not isinstance(p.get("text"), str) for p in content):
                raise ValueError("only text content has a supported token bound")
    request = {k: v for k, v in body.items() if k not in {"stream_options", "max_tokens", "max_completion_tokens"}}
    request["stream"] = False  # Buffer upstream; release the reservation only after usage arrives.
    raw = provider_json(request)
    request_bytes = len(raw)
    upper, profile = prompt_bound(raw)
    requested = body.get("max_completion_tokens", body.get("max_tokens", output_limit))
    if type(requested) is not int or requested <= 0:
        raise ValueError("invalid output token limit")
    cap = min(requested, output_limit, remaining - upper)
    if diagnostics is not None:
        diagnostics.update(profile, request_bytes=request_bytes,
                           prompt_upper_bound=upper, requested_output_tokens=requested,
                           output_limit=output_limit, available_after_prompt=remaining - upper,
                           admitted_output_tokens=max(0, cap))
    if type(minimum_output_tokens) is not int or minimum_output_tokens <= 0:
        raise ValueError("minimum output tokens must be a positive integer")
    if cap < minimum_output_tokens:
        raise BudgetError("insufficient tokens for bounded prompt and completion")
    request["max_tokens"] = cap
    if diagnostics is not None:
        diagnostics['wire_request_bytes'] = len(provider_json(request))
    return request, upper + cap


def compact_tools(tools, *, description_limit=320, strip_annotations=False):
    """Shorten narrative metadata; preserve all argument/validation semantics."""
    if type(description_limit) is not int or not 1 <= description_limit <= 320:
        raise ValueError("description_limit must be an integer from 1 to 320")
    if type(strip_annotations) is not bool:
        raise ValueError("strip_annotations must be boolean")

    def schema(value):
        if not isinstance(value, dict):
            return copy.deepcopy(value)
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key in {"title", "description"} and isinstance(item, str):
                continue
            if key in {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"} and isinstance(item, dict):
                result[key] = {name: schema(child) for name, child in item.items()}
            elif key in {"items", "additionalItems", "additionalProperties", "unevaluatedProperties",
                         "unevaluatedItems", "contains", "propertyNames", "not", "if", "then", "else"}:
                result[key] = [schema(child) for child in item] if isinstance(item, list) else schema(item)
            elif key in {"allOf", "anyOf", "oneOf", "prefixItems"} and isinstance(item, list):
                result[key] = [schema(child) for child in item]
            else:
                # Literals (including default/enum/const/examples), constraints,
                # references and unknown extensions are never interpreted.
                result[key] = copy.deepcopy(item)
        return result

    def compact(value):
        if isinstance(value, list):
            return [compact(item) for item in value]
        if not isinstance(value, dict):
            return value
        return {key: (copy.deepcopy(item) if key in {"default", "enum", "const", "examples"}
                      else schema(item) if strip_annotations and key in {"parameters", "inputSchema"}
                      else " ".join(item.split())[:description_limit] if key == "description" and isinstance(item, str)
                      else compact(item)) for key, item in value.items()
                if not (strip_annotations and key == "description" and isinstance(item, str))}
    return compact(tools)
