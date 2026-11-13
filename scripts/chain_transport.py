"""The final policy and budget boundary for every chain HTTP transmission."""
from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit

from action_manifest import DEFAULT_ROUTE_CAP


class ChainAbort(Exception):
    pass


class ChainTransport:
    """Authorize and reserve each wire attempt, including login and retries.

    Reservations are serialized; I/O runs outside the lock so an approved
    burst stays concurrent. Failed sends still consume their reservation.
    """

    def __init__(self, sender, gate):
        self._sender = sender
        self._gate = gate
        self._lock = threading.Lock()
        self._state: dict | None = None

    def begin(self, budget: dict) -> None:
        with self._lock:
            if self._state is not None:
                raise ChainAbort("aynı executor eşzamanlı iki zincir çalıştıramaz")
            self._state = {
                "max_requests": budget["max_requests"], "sent": 0,
                "deadline": time.monotonic() + budget["max_duration_seconds"],
                "route_cap": int(budget.get("route_cap", DEFAULT_ROUTE_CAP) or 0),
                "route_counts": {}, "tool": "", "step_sent": 0,
                "step_max": None, "step_deadline": None,
                "step_counts": {}, "step_deadlines": {},
            }

    def begin_step(self, step: dict) -> None:
        with self._lock:
            state = self._state
            if state is None:
                raise ChainAbort("ağ gönderimi için aktif zincir bağlamı yok")
            step_id = step.get("id", step["tool"])
            step_deadline = None
            if step.get("max_duration_seconds"):
                step_deadline = state["step_deadlines"].setdefault(
                    step_id, time.monotonic() + step["max_duration_seconds"])
            state.update(tool=step["tool"], step_id=step_id,
                         step_sent=state["step_counts"].get(step_id, 0),
                         step_max=step.get("max_requests"),
                         step_deadline=step_deadline)

    def snapshot(self) -> dict:
        with self._lock:
            state = self._state or {}
            return {"sent": state.get("sent", 0),
                    "route_counts": dict(state.get("route_counts", {}))}

    def finish(self) -> dict:
        with self._lock:
            state = self._state or {}
            result = {"sent": state.get("sent", 0),
                      "route_counts": dict(state.get("route_counts", {}))}
            self._state = None
        return result

    def request(self, method: str, url: str, headers: dict, body, timeout: float) -> dict:
        method, url, headers = str(method).upper(), str(url), dict(headers or {})
        with self._lock:
            state = self._state
            if state is None or not state["tool"]:
                raise ChainAbort("ağ gönderimi için aktif zincir/adım bağlamı yok")
            deadline = min(state["deadline"], state["step_deadline"] or state["deadline"])
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChainAbort("süre bütçesi aşıldı")
            if state["sent"] >= state["max_requests"]:
                raise ChainAbort("istek bütçesi aşıldı")
            if state["step_max"] is not None and state["step_sent"] >= state["step_max"]:
                raise ChainAbort("adım istek bütçesi aşıldı")
            try:
                route = (urlsplit(url).path or "/").rstrip("/") or "/"
            except ValueError as exc:
                raise ChainAbort("geçersiz istek URL'si") from exc
            spent = state["route_counts"].get(route, 0)
            if state["tool"] != "race_burst" and state["route_cap"] and spent >= state["route_cap"]:
                raise ChainAbort(f"rota bütçesi tükendi: {route} (cap {state['route_cap']}) — park et")
            allowed, reason = self._gate(state["tool"], url, method, headers)
            if not allowed:
                raise ChainAbort(reason)
            # The gate may itself take time; never send after the deadline.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChainAbort("süre bütçesi aşıldı")
            state["sent"] += 1
            state["step_sent"] += 1
            state["step_counts"][state["step_id"]] = state["step_sent"]
            state["route_counts"][route] = spent + 1
        return self._sender(method, url, headers, body, min(float(timeout), remaining))
