"""Host-owned phase allowances and bounded opportunities to finish a task."""
from __future__ import annotations

import json

from full_agent_budget import BudgetError

PHASE_WEIGHTS = {"recon": 20, "enum": 30, "access": 25, "report": 15, "planner": 10}
PROVIDER_CALL_LIMITS = {"recon": 10, "enum": 16, "access": 24, "report": 16, "planner": 8}
MAX_CONTEXT_BYTES = 24_000
MAX_PROMPT_TOKENS = 12_000
MIN_OUTPUT_TOKENS = 1024
FINALIZATION_TURNS = 3
PHASE_FINALIZATION_TURNS = {"recon": 3, "enum": 6, "access": 4, "report": 8, "planner": 0}
FINALIZATION_TOOL_RESERVE = {"recon": 2, "enum": 6, "access": 4, "report": 8, "planner": 0}


class RuntimePolicy:
    def __init__(self, budget):
        self.budget = budget
        total = budget.limits["tokens"]
        # Small offline runs still need prompt framing plus a usable planner
        # completion. The floor is taken from worker shares, never extra funds.
        planner = min(total // 3, max(8192, total * PHASE_WEIGHTS['planner'] // 100))
        self.limits = {phase: (total - planner) * weight // 90
                       for phase, weight in PHASE_WEIGHTS.items() if phase != 'planner'}
        self.limits['planner'] = planner
        self.limits["planner"] += total - sum(self.limits.values())
        self.calls = {}
        self.tool_calls = {}
        self.finalizing = set()
        self.finalization_calls = {}
        self.tool_failures = {}

    def allowance(self, spec):
        phase, ident = (spec.phase, spec.id) if spec is not None else ("planner", "planner")
        # Sum by phase, not only by task ID: repeated delegations cannot reset
        # an allowance. Unknown usage is already conservatively charged.
        spent = sum(row["charged"] for row in self.budget.snapshot()["events"]
                    if row["kind"] == "tokens" and row.get("runtime_phase") == phase)
        return min(self.budget.available("tokens"), max(0, self.limits[phase] - spent)), phase, ident

    def prepare(self, spec, prompt_tokens):
        remaining, phase, ident = self.allowance(spec)
        count = self.calls.get(ident, 0)
        finish_turns = PHASE_FINALIZATION_TURNS[phase]
        finish_reserve = min(self.limits[phase] // 3, 2 * (prompt_tokens + MIN_OUTPUT_TOKENS))
        if spec is not None and (count >= PROVIDER_CALL_LIMITS[phase] - finish_turns
                                 or remaining < prompt_tokens + MIN_OUTPUT_TOKENS + finish_reserve
                                 or self.tool_calls.get(ident, 0) >= spec.max_calls - FINALIZATION_TOOL_RESERVE[phase]):
            self.finalizing.add(ident)
        finishing = ident in self.finalizing
        if (count >= PROVIDER_CALL_LIMITS[phase]
                or finishing and self.finalization_calls.get(ident, 0) >= finish_turns):
            raise BudgetError("phase_call_budget_exhausted")
        return {"phase": phase, "spec_id": ident, "phase_token_limit": self.limits[phase],
                "remaining_phase_tokens": remaining, "provider_calls_used": count,
                "request_token_allowance": (remaining if finishing or spec is None
                                            else max(0, remaining - finish_reserve)),
                "provider_call_limit": PROVIDER_CALL_LIMITS[phase],
                "finalization_calls_used": self.finalization_calls.get(ident, 0),
                "finalization_call_limit": finish_turns,
                "tool_calls_used": self.tool_calls.get(ident, 0), "finalizing": finishing,
                "remaining_tool_calls": max(0, spec.max_calls - self.tool_calls.get(ident, 0))
                    if spec is not None else None,
                "disabled_tools": sorted(tool for (task, tool), count in self.tool_failures.items()
                                         if task == ident and count >= 2),
                "finish_reserve_tokens": finish_reserve, "minimum_output_tokens": MIN_OUTPUT_TOKENS}

    def admitted(self, info):
        ident = info["spec_id"]
        self.calls[ident] = self.calls.get(ident, 0) + 1
        if info["finalizing"]:
            self.finalization_calls[ident] = self.finalization_calls.get(ident, 0) + 1

    def allowed_tools(self, spec):
        allowed = set(spec.tools) | {"read", "write", "edit", "bash"}
        allowed -= {tool for (task, tool), count in self.tool_failures.items() if task == spec.id and count >= 2}
        if spec.id in self.finalizing:
            closing = {"read", "write", "edit", "validator_session_vault_check",
                       "kali-tools_ledger_prepare_handoff", "kali-tools_ledger_attempt_add_batch",
                       "kali-tools_ledger_coverage", "hunter_coverage_report", "kali-tools_ledger_checkpoint"}
            if spec.phase == "report":
                closing.add("bash")
            allowed &= closing
        return allowed

    def check_tool(self, spec, tool):
        ident = spec.id
        count = self.tool_calls.get(ident, 0)
        # A single provider response may contain several native tool calls.
        # Preserve closure slots at each execution, not just next completion.
        if count >= spec.max_calls - FINALIZATION_TOOL_RESERVE[spec.phase]:
            self.finalizing.add(ident)
        if tool not in self.allowed_tools(spec):
            raise ValueError("tool unavailable in current phase or finalization")
        if count >= spec.max_calls:
            raise BudgetError("phase_tool_budget_exhausted")
        self.tool_calls[ident] = count + 1

    def record_result(self, spec, tool, execution, error=None):
        failed = bool(error) or bool(execution and execution.get('execution_failed'))
        try:
            output = execution['result']['output']
            parsed = json.loads(output) if isinstance(output, str) else output
            if isinstance(parsed, dict):
                # A clean negative security result is not a broken tool.
                # Brake execution/schema errors, never ordinary test verdicts.
                failed |= bool(parsed.get('error'))
                rows = parsed.get('results')
                failed |= isinstance(rows, list) and bool(rows) and all(
                    isinstance(row, dict) and row.get('ok') is False and bool(row.get('error')) for row in rows)
        except (KeyError, TypeError, ValueError):
            pass
        key = (spec.id, tool)
        self.tool_failures[key] = self.tool_failures.get(key, 0) + 1 if failed else 0

    def snapshot(self):
        return {"schema": "native-runtime-policy/1", "phase_token_limits": dict(self.limits),
                "provider_call_limits": PROVIDER_CALL_LIMITS, "max_context_bytes": MAX_CONTEXT_BYTES,
                "max_prompt_tokens": MAX_PROMPT_TOKENS,
                "minimum_output_tokens": MIN_OUTPUT_TOKENS, "finalization_turns": FINALIZATION_TURNS,
                "phase_finalization_turns": PHASE_FINALIZATION_TURNS,
                "finalization_tool_reserve": FINALIZATION_TOOL_RESERVE,
                "provider_calls": dict(self.calls), "tool_calls": dict(self.tool_calls),
                "finalization_calls": dict(self.finalization_calls),
                "disabled_tools": {spec: sorted(tool for (task, tool), count in self.tool_failures.items()
                                               if task == spec and count >= 2)
                                   for spec, _ in self.tool_failures},
                "finalizing_tasks": sorted(self.finalizing)}
