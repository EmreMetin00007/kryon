"""Lazy deterministic budget-aware scheduler with endpoint/profile fairness."""
from __future__ import annotations

from collections import deque
from typing import Any, Callable, Iterable, Iterator, Sequence
from urllib.parse import urlsplit

MAX_SCHEDULER_QUEUE = 64
ACCESS_CALL_CAP = 14
ACCESS_TOKEN_CAP = 37_500


def _endpoint_sort_key(item: Any) -> tuple[str, str, str]:
    if isinstance(item, dict):
        url = str(item.get("url") or item.get("route") or item.get("target") or "")
        param = str(item.get("param") or "")
        parsed = urlsplit(url)
        return (parsed.path or "/", url, param)
    text = str(item or "")
    return (urlsplit(text).path or "/", text, "")


class LazyBudgetScheduler:
    """Lazily materialize bounded eligible (endpoint, profile) work with round-robin fairness."""

    def __init__(
        self,
        endpoints: Iterable[Any],
        profiles: Sequence[str],
        *,
        eligibility_fn: Callable[[Any, str], bool | dict[str, Any]] | None = None,
        max_queue_size: int = MAX_SCHEDULER_QUEUE,
        call_budget: int = ACCESS_CALL_CAP,
        token_budget: int = ACCESS_TOKEN_CAP,
    ) -> None:
        if type(max_queue_size) is not int or max_queue_size < 1:
            raise ValueError("max_queue_size must be a positive integer")
        if type(call_budget) is not int or call_budget < 0:
            raise ValueError("call_budget must be a non-negative integer")
        if type(token_budget) is not int or token_budget < 0:
            raise ValueError("token_budget must be a non-negative integer")
        self._endpoints = sorted(endpoints, key=_endpoint_sort_key)
        self._profiles = sorted(dict.fromkeys(str(p) for p in profiles if p))
        self._eligibility_fn = eligibility_fn
        self.max_queue_size = max_queue_size
        self.call_budget = call_budget
        self.token_budget = token_budget

        self._queue: deque[dict[str, Any]] = deque()
        self._iters: list[tuple[str, Iterator[Any]]] = [
            (profile, iter(self._endpoints)) for profile in self._profiles
        ]
        self._cursor = 0
        self._exhausted = not self._iters
        self.peak_queue_size = 0
        self.materialized_count = 0
        self.ineligible_count = 0
        self.dispatched_count = 0
        self.deferred_count = 0
        self.calls_used = 0
        self.tokens_used = 0

    @property
    def queue_size(self) -> int:
        return len(self._queue)

    def _is_eligible(self, endpoint: Any, profile: str) -> tuple[bool, str]:
        if self._eligibility_fn is None:
            return True, ""
        decision = self._eligibility_fn(endpoint, profile)
        if isinstance(decision, dict):
            return bool(decision.get("eligible")), str(decision.get("reason_code") or "")
        return bool(decision), ""

    def _pull_next_eligible(self) -> dict[str, Any] | None:
        while self._iters:
            if self._cursor >= len(self._iters):
                self._cursor = 0
            profile, it = self._iters[self._cursor]
            try:
                endpoint = next(it)
            except StopIteration:
                self._iters.pop(self._cursor)
                continue
            self._cursor = (self._cursor + 1) % len(self._iters) if self._iters else 0
            eligible, reason = self._is_eligible(endpoint, profile)
            if not eligible:
                self.ineligible_count += 1
                continue
            self.materialized_count += 1
            return {
                "endpoint": endpoint,
                "profile": profile,
                "reason_code": reason,
            }
        self._exhausted = True
        return None

    def refill(self) -> int:
        """Pull eligible items lazily until the bounded active queue is full or inputs end."""
        while len(self._queue) < self.max_queue_size and not self._exhausted:
            item = self._pull_next_eligible()
            if item is None:
                break
            self._queue.append(item)
            if len(self._queue) > self.peak_queue_size:
                self.peak_queue_size = len(self._queue)
        return len(self._queue)

    def pop_next(self, *, estimated_tokens: int = 0) -> dict[str, Any] | None:
        """Pop the next fair eligible item if call and token budgets permit; otherwise defer."""
        self.refill()
        if not self._queue:
            return None
        if self.calls_used + 1 > self.call_budget or self.tokens_used + max(0, int(estimated_tokens)) > self.token_budget:
            self.defer_remaining()
            return None
        item = self._queue.popleft()
        self.dispatched_count += 1
        self.refill()
        return item

    def record_usage(self, *, calls: int = 1, tokens: int = 0) -> None:
        self.calls_used += max(0, int(calls))
        self.tokens_used += max(0, int(tokens))

    def defer_remaining(self) -> int:
        """Drain queued items and remaining lazy stream as budget-deferred without materializing payloads."""
        deferred = len(self._queue)
        self._queue.clear()
        while self._iters:
            item = self._pull_next_eligible()
            if item is None:
                break
            deferred += 1
        self.deferred_count += deferred
        return deferred


def interleave_fair_work(
    rows: Sequence[dict[str, Any]],
    *,
    max_queue_size: int = MAX_SCHEDULER_QUEUE,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministically interleave work slices across profiles & endpoints under a bounded queue."""
    if not rows:
        return [], []
    by_bucket: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        key = str(
            row.get("validation_profile")
            or (row.get("arguments") or {}).get("validation_profile")
            or row.get("vector")
            or ""
        )
        by_bucket.setdefault(key, []).append(row)

    def _slice_sort_key(row: dict[str, Any]) -> tuple[str, str, str]:
        args = row.get("arguments") if isinstance(row.get("arguments"), dict) else {}
        target = str(args.get("target") or args.get("target_url") or row.get("route") or "")
        param = str(row.get("param") or args.get("param") or "")
        return (urlsplit(target).path or "/", target, param)

    ordered_buckets = [
        sorted(by_bucket[key], key=_slice_sort_key)
        for key in sorted(by_bucket)
    ]
    selected: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    idx = 0
    while True:
        progressed = False
        for bucket in ordered_buckets:
            if idx < len(bucket):
                progressed = True
                if len(selected) < max_queue_size:
                    selected.append(bucket[idx])
                else:
                    deferred.append(bucket[idx])
        if not progressed:
            break
        idx += 1
    return selected, deferred
