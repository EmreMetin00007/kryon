"""Shared lab executor for both experiment flows.

Both the host baseline and the LLM loop send every request through this
executor: scope guard (local paths only), one shared budget accounting
implementation (SharedBudget), session/body carriage. This is the
slice-level equalizer; wiring into the production broker/policy path
remains a separate step and is not claimed here.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from full_agent_budget import SharedBudget  # noqa: F401  (re-exported for callers)


class LabExecutor:
    def __init__(self, base: str, budget: SharedBudget):
        self.base = base.rstrip("/")
        self.budget = budget

    def fetch(self, method: str, path: str, body: dict | None = None,
              session: str | None = None) -> dict:
        if not path.startswith("/") or path.startswith("//"):
            return {"path": path, "method": method, "status": 0,
                    "body": {"error": "scope: local paths only"}}
        method = method.upper()
        ticket = self.budget.reserve("http", 1)
        headers: dict[str, str] = {}
        if session:
            headers["X-Session"] = session
        data = None
        if method == "POST":
            data = json.dumps(body or {}).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, headers=headers, method=method, data=data)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                status, raw = resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read().decode()
        except Exception as exc:  # transport failure is evidence, not a crash
            status, raw = 0, json.dumps({"error": f"transport: {type(exc).__name__}"})
        self.budget.settle(ticket, 1)
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw
        return {"path": path, "method": method, "status": status, "body": parsed}
