"""Clean ReAct tool-calling investigator loop over MeteredProviderTransport."""
from __future__ import annotations

import concurrent.futures
import copy
import json
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable
from urllib.parse import urlsplit

from agentic_bsag import (
    NODE_ARTIFACT,
    NODE_AUTH_CONTEXT,
    NODE_ENDPOINT,
    STATUS_IN_PROGRESS,
    STATUS_SUSPECT_DECOY,
    STATUS_VERIFIED,
    BeliefStateAttackGraph,
)
from agentic_context import (
    CHARS_PER_TOKEN as CHARS_PER_TOKEN,
    _ANGLE_QUOTE_TRANS as _ANGLE_QUOTE_TRANS,
    _BANNER_MARKERS as _BANNER_MARKERS,
    _EPOCH_HARD_CHAR_LIMIT as _EPOCH_HARD_CHAR_LIMIT,
    _EVENT_SCHEME_RE as _EVENT_SCHEME_RE,
    _FRAMING_RESERVE_TOKENS as _FRAMING_RESERVE_TOKENS,
    _HTML_TAG_RE as _HTML_TAG_RE,
    _LOCAL_READ_TOOLS as _LOCAL_READ_TOOLS,
    _MAX_HTTP400_RECOVERIES as _MAX_HTTP400_RECOVERIES,
    _PROMPT_HARD_CHAR_LIMIT as _PROMPT_HARD_CHAR_LIMIT,
    _PROMPT_SOFT_CHAR_LIMIT as _PROMPT_SOFT_CHAR_LIMIT,
    _RECEIPT_ID_RE as _RECEIPT_ID_RE,
    _SCRIPT_STYLE_RE as _SCRIPT_STYLE_RE,
    _SQL_FRAGMENT_RE as _SQL_FRAGMENT_RE,
    _TRANSIENT_FAILURE_REASONS as _TRANSIENT_FAILURE_REASONS,
    _TRANSIENT_HTTP_STATUSES as _TRANSIENT_HTTP_STATUSES,
    _UNTRUSTED_BLOCK_RE as _UNTRUSTED_BLOCK_RE,
    _UNTRUSTED_END as _UNTRUSTED_END,
    _UNTRUSTED_START as _UNTRUSTED_START,
    _accumulate_usage as _accumulate_usage,
    _atomic_write_json as _atomic_write_json,
    _build_rolled_history_summary as _build_rolled_history_summary,
    _collapse_tool_content as _collapse_tool_content,
    _group_turns as _group_turns,
    _new_usage_dict as _new_usage_dict,
    _sanitize_messages_for_http400 as _sanitize_messages_for_http400,
    _sanitize_text_for_http400 as _sanitize_text_for_http400,
    _sanitize_untrusted_blocks as _sanitize_untrusted_blocks,
    _sanitize_url_for_http400 as _sanitize_url_for_http400,
    _strip_state_banner as _strip_state_banner,
    _strip_untrusted_markers as _strip_untrusted_markers,
    _summarize_receipt_obj_for_http400 as _summarize_receipt_obj_for_http400,
    _summarize_untrusted_payload_for_http400 as _summarize_untrusted_payload_for_http400,
    _truncate_recent_tool_content as _truncate_recent_tool_content,
    _turn_cutoff_index as _turn_cutoff_index,
    account_completion_tokens as account_completion_tokens,
    build_synthesis_prompt as build_synthesis_prompt,
    build_system_prompt as build_system_prompt,
    build_worker_system_prompt as build_worker_system_prompt,
    compact_messages_for_context as compact_messages_for_context,
    effective_tokens_from_usage as effective_tokens_from_usage,
    estimate_tokens as estimate_tokens,
)
from agentic_http import AgenticHTTPClient, ServiceDegradationError
from agentic_oob import LoopbackCallbackServer
from agentic_oracle import DifferentialOracle
from agentic_receipts import ReceiptStore
from agentic_seed import apply_seed_surface
from agentic_scheduler import (
    AntiBiasUCBScheduler,
    ArmSelection,
    LazyInterventionMonitor,
)
from agentic_sharding import (
    SubsystemCluster,
    build_cross_shard_synthesis_prompts,
    build_shard_prompts,
    cluster_discovered_surface,
    collect_cross_shard_synthesis_context,
)
from agentic_surface import SurfaceFrontierTracker
from agentic_telemetry import TelemetryLogger, write_process_metrics
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher, canonicalize_and_deduplicate_findings
from full_agent_budget import BudgetError, SharedBudget, compact_tools
from full_agent_provider import MeteredProviderTransport, SessionGate


def _build_assistant_history_entry(msg: dict[str, Any]) -> dict[str, Any]:
    """Build an assistant message dict, preserving non-empty reasoning_content across tool-call turns."""
    content = msg.get("content")
    tool_calls = msg.get("tool_calls") or []
    entry: dict[str, Any] = {
        "role": "assistant",
        "content": content if content is not None else "",
    }
    if tool_calls:
        entry["tool_calls"] = tool_calls
        reasoning_content = msg.get("reasoning_content")
        if isinstance(reasoning_content, str) and reasoning_content:
            entry["reasoning_content"] = reasoning_content
    return entry


class AgenticInvestigator:
    """ReAct tool-calling security investigator backed by MeteredProviderTransport."""

    def __init__(
        self,
        *,
        http_client: AgenticHTTPClient,
        receipt_store: ReceiptStore,
        transport: MeteredProviderTransport,
        budget: SharedBudget,
        model: str,
        root_dir: str | Path,
        discovery_hints: list[str] | None = None,
        max_turns: int = 55,
        reasoning_effort: str = "low",
        max_provider_retries: int = 4,
        sleep_fn: Callable[[float], None] = time.sleep,
        use_bsag: bool = False,
        scheduler_mode: str = "ucb",
        verification_gate: str = "differential",
        intervention_mode: str = "lazy",
        execution_mode: str = "monolithic",
        micro_budget: int = 14,
        synthesis_interval: int = 3,
        enable_telemetry: bool | None = None,
        scout_model: str | None = None,
        scout_max_turns: int = 22,
        scout_token_share: float = 0.40,
        max_shards: int = 3,
        bootstrap_turns: int = 12,
        shard_turns: int = 25,
        shard_token_quota: int = 0,
        bootstrap_model: str | None = None,
        epoch_char_limit: int = _EPOCH_HARD_CHAR_LIMIT,
        cache_token_weight: float = 0.10,
        seed_surface: dict[str, Any] | None = None,
        oob_server: LoopbackCallbackServer | None = None,
        enable_cross_shard_synthesis: bool = True,
    ):
        self.http = http_client
        self.receipts = receipt_store
        self.transport = transport
        self.budget = budget
        self.model = model
        self.scout_model = str(scout_model or "").strip()
        self.scout_max_turns = max(1, int(scout_max_turns))
        self.scout_token_share = min(0.85, max(0.10, float(scout_token_share)))
        self.max_shards = max(1, int(max_shards))
        self.bootstrap_turns = max(1, int(bootstrap_turns))
        self.shard_turns = max(1, int(shard_turns))
        self.shard_token_quota = max(0, int(shard_token_quota))
        self.bootstrap_model = str(bootstrap_model or "").strip()
        raw_epoch_limit = int(_EPOCH_HARD_CHAR_LIMIT if epoch_char_limit is None else epoch_char_limit)
        self.epoch_char_limit = max(
            _PROMPT_HARD_CHAR_LIMIT,
            _EPOCH_HARD_CHAR_LIMIT if raw_epoch_limit <= 0 else raw_epoch_limit,
        )
        if isinstance(cache_token_weight, bool):
            raise ValueError("cache_token_weight must be between 0.0 and 1.0")
        eff_weight = float(cache_token_weight)
        if not (0.0 <= eff_weight <= 1.0):
            raise ValueError(f"cache_token_weight must be between 0.0 and 1.0, got {cache_token_weight!r}")
        self.cache_token_weight = eff_weight
        self._active_model = self.model
        self._handoff_phase = "single"
        self._handoff_summary: dict[str, Any] | None = None
        self._sharding_summary: dict[str, Any] | None = None
        self._stats_lock = threading.Lock()
        self.root_dir = Path(root_dir).expanduser().resolve()
        self.checkpoint_path = self.root_dir / "checkpoint.json"
        self.discovery_hints = [str(h) for h in (discovery_hints or ["/"]) if str(h).strip()] or ["/"]
        self.max_turns = max(1, int(max_turns))
        self.reasoning_effort = reasoning_effort
        self.max_provider_retries = max(0, int(max_provider_retries))
        self.sleep_fn = sleep_fn
        self._min_call_interval_seconds = 0.0
        self._last_provider_call_at: float | None = None
        self.execution_mode = str(execution_mode or "monolithic").strip().lower()
        if self.execution_mode not in {"ephemeral", "monolithic", "sharded"}:
            raise ValueError(f"invalid execution_mode: {execution_mode!r}")
        self.use_bsag = bool(use_bsag)
        self.scheduler_mode = str(scheduler_mode or "ucb").strip().lower()
        self.verification_gate = str(verification_gate or "differential").strip().lower()
        self.intervention_mode = str(intervention_mode or "lazy").strip().lower()
        self.micro_budget = max(2, int(micro_budget))
        self.synthesis_interval = max(1, int(synthesis_interval))
        self.enable_cross_shard_synthesis = bool(enable_cross_shard_synthesis)

        use_telem = bool(enable_telemetry) if enable_telemetry is not None else (
            self.execution_mode == "ephemeral" or self.use_bsag
        )
        self.telemetry: TelemetryLogger | None = TelemetryLogger(self.root_dir) if use_telem else None
        self.bsag: BeliefStateAttackGraph | None = (
            BeliefStateAttackGraph(
                base_url=http_client.base_url,
                root_dir=self.root_dir,
                allowed_methods=sorted(http_client.allowed_methods),
                actor_summaries=http_client.actors.summaries(),
            )
            if self.use_bsag
            else None
        )
        self._oob_server: LoopbackCallbackServer | None = oob_server
        self.oracle: DifferentialOracle = DifferentialOracle(
            http_client=http_client,
            receipt_store=receipt_store,
            mode=self.verification_gate,
            oob_server=self._oob_server,
        )
        self.scheduler = AntiBiasUCBScheduler(mode=self.scheduler_mode)
        self.intervention_monitor = LazyInterventionMonitor(
            mode=self.intervention_mode,
            micro_budget=self.micro_budget,
        )
        self.dispatcher = ToolDispatcher(
            http_client=http_client,
            receipt_store=receipt_store,
            root_dir=self.root_dir,
            bsag=self.bsag,
            oracle=self.oracle,
            telemetry=self.telemetry,
            oob_server=self._oob_server,
        )
        self.seeded_surface_count: int = (
            apply_seed_surface(self.dispatcher.surface_tracker, seed_surface)
            if isinstance(seed_surface, dict)
            else 0
        )
        self.token_usage: dict[str, int] = _new_usage_dict()
        self._last_metrics_paths: tuple[Path, Path] | None = None
        self._epoch_turn_start: int = 0
        self._epoch_summary_text: str = ""
        self._epoch_advancements: int = 0

    @staticmethod
    def _close_dispatcher(dispatcher: Any) -> None:
        close_fn = getattr(dispatcher, "close", None)
        if callable(close_fn):
            close_fn()

    @staticmethod
    def _classify_budget_error(exc: BudgetError, *, is_shard: bool = False) -> str:
        if is_shard:
            msg = str(exc).lower()
            if (
                "budget exhausted" in msg
                or "insufficient tokens" in msg
                or "token_admission_exhausted" in msg
                or (exc.code == "provider_budget_error" and "token" in msg)
            ):
                return "budget_exhausted"
        return exc.code or "budget_exhausted"

    def _wrapup_reasons(
        self,
        turn: int,
        *,
        dispatcher: ToolDispatcher | None = None,
        max_turns_override: int | None = None,
        shard_token_quota: int | None = None,
        shard_tokens_used: int | None = None,
    ) -> list[str]:
        eff_disp = dispatcher if dispatcher is not None else self.dispatcher
        eff_max_turns = max_turns_override if max_turns_override is not None else self.max_turns
        http_rem = self.http.budget.limit - self.http.budget.used
        http_reserve_floor = int(getattr(eff_disp, "http_reserve_floor", 0) or 0)
        usable_http_rem = max(0, http_rem - http_reserve_floor)
        tok_rem = self.budget.available("tokens")
        tok_lim = self.budget.limits["tokens"]
        wrapup_reasons: list[str] = []
        if tok_lim > 0:
            tok_threshold = max(30_000, int(tok_lim * 0.15)) if tok_lim >= 60_000 else int(tok_lim * 0.15)
            if tok_rem <= tok_threshold:
                wrapup_reasons.append(f"tokens={tok_rem}/{tok_lim}")
        if (
            shard_token_quota is not None
            and shard_token_quota > 0
            and shard_tokens_used is not None
            and shard_tokens_used >= int(shard_token_quota * 0.80)
        ):
            wrapup_reasons.append(f"shard_tokens={shard_tokens_used}/{shard_token_quota}")
        if eff_max_turns > 5 and (eff_max_turns - turn) <= 4:
            wrapup_reasons.append(f"turns_left={max(0, eff_max_turns - turn)}")
        elif shard_token_quota is not None and eff_max_turns > 3 and (eff_max_turns - turn) <= 3:
            wrapup_reasons.append(f"turns_left={max(0, eff_max_turns - turn)}")
        if self.http.budget.limit > 15 and usable_http_rem <= 10:
            wrapup_reasons.append(f"http_left={usable_http_rem}/{self.http.budget.limit}")
        sec_lim = float(getattr(self.budget, "seconds_limit", 0) or self.budget.limits.get("seconds") or 0)
        sec_rem = float(self.budget.remaining_seconds())
        if sec_lim > 0:
            sec_threshold = min(90.0, max(15.0, sec_lim * 0.15)) if sec_lim >= 90.0 else sec_lim * 0.15
            if sec_rem <= sec_threshold:
                wrapup_reasons.append(f"seconds_left={int(max(0.0, sec_rem))}/{int(sec_lim)}s")
        return wrapup_reasons

    def _sync_coverage_gate(
        self,
        turn: int,
        *,
        dispatcher: ToolDispatcher | None = None,
        max_turns_override: int | None = None,
        allow_coverage_gate: bool = True,
        allow_discovery_gate: bool = False,
        disable_gate_last_n_turns: int = 0,
        shard_token_quota: int | None = None,
        shard_tokens_used: int | None = None,
    ) -> bool:
        """Align `coverage_gate_enabled` and `discovery_finish_gate` with `[BUDGET-WRAPUP]` so `finish` is never rejected during wrapup."""
        eff_disp = dispatcher if dispatcher is not None else self.dispatcher
        eff_max_turns = max_turns_override if max_turns_override is not None else self.max_turns
        wrapup_reasons = self._wrapup_reasons(
            turn,
            dispatcher=eff_disp,
            max_turns_override=eff_max_turns,
            shard_token_quota=shard_token_quota,
            shard_tokens_used=shard_tokens_used,
        )
        eff_enabled = (
            allow_coverage_gate
            and eff_max_turns > 5
            and not wrapup_reasons
        )
        eff_disp.coverage_gate_enabled = eff_enabled
        eff_disp.discovery_finish_gate = bool(
            allow_discovery_gate
            and not eff_enabled
            and not wrapup_reasons
            and not (disable_gate_last_n_turns > 0 and turn > eff_max_turns - disable_gate_last_n_turns)
        )
        return eff_enabled

    def _state_banner(
        self,
        turn: int,
        *,
        dispatcher: ToolDispatcher | None = None,
        max_turns_override: int | None = None,
        shard_cluster: SubsystemCluster | None = None,
        allow_coverage_gate: bool = True,
        shard_token_quota: int | None = None,
        shard_tokens_used: int | None = None,
    ) -> str:
        eff_disp = dispatcher if dispatcher is not None else self.dispatcher
        eff_max_turns = max_turns_override if max_turns_override is not None else self.max_turns
        http_rem = self.http.budget.limit - self.http.budget.used
        tok_rem = self.budget.available("tokens")
        tok_lim = self.budget.limits["tokens"]
        actor_list = [a["alias"] for a in self.http.actors.summaries()]
        nb = eff_disp.notebook_state
        nb_parts = []
        if nb.get("surface_notes"):
            nb_parts.append(f"surface={nb['surface_notes'][:300]}")
        if nb.get("hypotheses"):
            hyps = [f"{h.get('id')}:{h.get('vuln_class')}:{h.get('status')}" for h in nb["hypotheses"][-8:]]
            nb_parts.append("hyps=" + ",".join(hyps))
        nb_line = f"\n[NOTEBOOK] {' | '.join(nb_parts)}" if nb_parts else ""
        frontier_line = eff_disp.surface_tracker.format_frontier_banner(max_chars=950)
        write_nudge = ""
        write_allowed = self.http.allowed_methods & {"POST", "PUT", "PATCH"}
        tracker = eff_disp.surface_tracker
        declared_allowed = {op for op in tracker.declared_write_ops if op[0] in write_allowed}
        untested_declared = declared_allowed - tracker.tested_write_ops
        needs_write_phase = bool(untested_declared) if declared_allowed else (not tracker.tested_write_ops)
        if (
            write_allowed
            and needs_write_phase
            and turn >= max(10, eff_max_turns // 4)
        ):
            pending_writes = tracker.untested_write_ops()
            if pending_writes:
                top_writes = ", ".join(pending_writes[:4])
                write_nudge = (
                    f"\n[WRITE-PHASE] Mutating HTTP methods ({','.join(sorted(write_allowed))}) are in scope and "
                    f"declared endpoints remain untested ({top_writes}). Verify field-level validation and "
                    f"authorization on these write endpoints before continuing read-only checks: for PUT/PATCH "
                    f"updates, fetch the current JSON representation with GET first, send a schema-preserving "
                    f"update using `base_receipt_id` + `json_merge` to check whether read-only/restricted fields "
                    f"are properly rejected, confirm state persistence with a follow-up GET, and call "
                    f"`record_finding` immediately if a restriction is not enforced."
                )
        wrapup_reasons = self._wrapup_reasons(
            turn,
            dispatcher=eff_disp,
            max_turns_override=eff_max_turns,
            shard_token_quota=shard_token_quota,
            shard_tokens_used=shard_tokens_used,
        )
        if wrapup_reasons or not allow_coverage_gate:
            eff_disp.coverage_gate_enabled = False
        wrapup_line = (
            f"\n[BUDGET-WRAPUP] Low remaining budget ({', '.join(wrapup_reasons)}): "
            "stop broad new discovery, immediately call `record_finding` for every verified vulnerability "
            "already supported by receipts in memory (with exact proof and control receipt IDs), "
            "and then call `finish` listing any untested areas."
            if wrapup_reasons
            else ""
        )
        shard_tok_part = (
            f" | shard_tokens={shard_tokens_used}/{shard_token_quota}"
            if shard_token_quota is not None and shard_token_quota > 0 and shard_tokens_used is not None
            else ""
        )
        shard_line = (
            f"\n[SHARD SCOPE] shard_id={shard_cluster.shard_id} | families={shard_cluster.families}{shard_tok_part}"
            if shard_cluster is not None
            else ""
        )
        sec_rem = int(max(0.0, float(self.budget.remaining_seconds())))
        return (
            f"\n[STATE] http_budget: {http_rem}/{self.http.budget.limit} left | "
            f"llm_tokens: {tok_rem}/{tok_lim} left | time_left: {sec_rem}s | turn: {turn}/{eff_max_turns} | "
            f"actors: {actor_list} | findings: {len(eff_disp.findings)} | "
            f"receipts: {self.receipts.count()}"
            f"{shard_line}"
            f"{nb_line}"
            f"{frontier_line}"
            f"{write_nudge}"
            f"{wrapup_line}"
        )

    def _last_provider_status(self) -> int | None:
        responses = getattr(self.transport, "provider_responses", None)
        if not responses:
            return None
        lock = getattr(self.transport, "provider_lock", None)
        if lock is not None:
            with lock:
                status = responses[-1].get("upstream_http_status") if responses else None
        else:
            status = responses[-1].get("upstream_http_status")
        return status if isinstance(status, int) else None

    def _is_transient_provider_error(self, exc: Exception) -> bool:
        if not isinstance(exc, BudgetError):
            return False
        reason = exc.code or ""
        if reason in _TRANSIENT_FAILURE_REASONS:
            return True
        if reason == "provider_http_error":
            return self._last_provider_status() in _TRANSIENT_HTTP_STATUSES
        return False

    def _is_http400_provider_error(self, exc: Exception) -> bool:
        return (
            isinstance(exc, BudgetError)
            and (exc.code or "") == "provider_http_error"
            and self._last_provider_status() == 400
        )

    def _clear_transient_gates(self) -> None:
        gate = getattr(self.transport, "session_gate", None)
        if gate is not None:
            gate.stop_reason = ""
        # SharedBudget.settle retains the conservative reservation on failure and
        # sets blocked="missing or invalid tokens usage"; clear only that transient
        # block before retrying so the retained reservation still bounds total spend.
        lock = getattr(self.budget, "lock", None)
        if lock is not None:
            with lock:
                if getattr(self.budget, "blocked", "") == "missing or invalid tokens usage":
                    self.budget.blocked = ""
        elif getattr(self.budget, "blocked", "") == "missing or invalid tokens usage":
            self.budget.blocked = ""

    def _project_epoch_messages(
        self,
        messages: list[dict[str, Any]],
        *,
        max_tool_chars: int = 5200,
        epoch_turn_start: int | None = None,
        epoch_summary_text: str | None = None,
        epoch_state: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Project an append-only, prompt-cache-stable view of the current epoch."""
        if len(messages) <= 1:
            return copy.deepcopy(messages)

        turn_groups = _group_turns(messages)
        default_start = int(epoch_state.get("turn_start", 0)) if epoch_state is not None else self._epoch_turn_start
        default_summary = str(epoch_state.get("summary_text", "")) if epoch_state is not None else self._epoch_summary_text
        raw_start = default_start if epoch_turn_start is None else epoch_turn_start
        raw_summary = default_summary if epoch_summary_text is None else epoch_summary_text
        if raw_start > 0 and raw_start >= len(turn_groups):
            eff_start = 0
            eff_summary = ""
        else:
            eff_start = raw_start
            eff_summary = raw_summary

        sys_msg = copy.deepcopy(messages[0])
        init_user_msg = copy.deepcopy(messages[1])
        if eff_summary:
            init_user_msg["content"] = str(init_user_msg.get("content") or "") + eff_summary

        projected: list[dict[str, Any]] = [sys_msg, init_user_msg]
        for group in turn_groups[eff_start:]:
            for msg in group:
                item = copy.deepcopy(msg)
                if (
                    item.get("role") == "tool"
                    and isinstance(item.get("content"), str)
                    and len(item["content"]) > max_tool_chars
                ):
                    item["content"] = _truncate_recent_tool_content(
                        item["content"],
                        max_tool_chars,
                        preserve_banner=True,
                    )
                projected.append(item)
        return projected

    def _prepare_bounded_body(
        self,
        messages: list[dict[str, Any]],
        *,
        omit_reasoning_effort: bool = False,
        keep_recent_turns_override: int | None = None,
        epoch_state: dict[str, Any] | None = None,
        model_override: str | None = None,
        excluded_tools: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        avail = self.budget.available("tokens")
        schemas = (
            [
                s for s in TOOL_SCHEMAS
                if str(((s.get("function") or {}).get("name")) or "") not in excluded_tools
            ]
            if excluded_tools
            else TOOL_SCHEMAS
        )
        wire_tools_default = compact_tools(schemas, description_limit=140, strip_annotations=False)
        wire_tools_tight = compact_tools(schemas, description_limit=96, strip_annotations=True)

        def _serialized_len(msgs: list[dict[str, Any]], tools_payload: list[dict[str, Any]]) -> int:
            return len(
                json.dumps(
                    {"messages": msgs, "tools": tools_payload},
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )

        def _fits_epoch_budget(byte_len: int) -> bool:
            return (
                byte_len <= self.epoch_char_limit
                and byte_len + _FRAMING_RESERVE_TOKENS + 256 <= avail
            )

        chosen_msgs: list[dict[str, Any]] | None = None
        chosen_tools: list[dict[str, Any]] = wire_tools_default
        serialized_bytes = 0

        turn_groups = _group_turns(messages)
        cur_epoch_start = int(epoch_state.get("turn_start", 0)) if epoch_state is not None else self._epoch_turn_start
        epoch_applicable = (
            keep_recent_turns_override is None
            and self.execution_mode in {"monolithic", "sharded"}
            and not (cur_epoch_start > 0 and cur_epoch_start >= len(turn_groups))
        )
        if epoch_applicable:
            epoch_msgs = self._project_epoch_messages(
                messages,
                max_tool_chars=5200,
                epoch_state=epoch_state,
            )
            epoch_bytes = _serialized_len(epoch_msgs, wire_tools_default)
            if _fits_epoch_budget(epoch_bytes):
                chosen_msgs = epoch_msgs
                chosen_tools = wire_tools_default
                serialized_bytes = epoch_bytes
            elif len(turn_groups) - cur_epoch_start > 1:
                cand_start = max(cur_epoch_start + 1, len(turn_groups) - 1)
                cand_summary = _build_rolled_history_summary(
                    turn_groups[:cand_start],
                    max_chars=1800,
                )
                cand_msgs = self._project_epoch_messages(
                    messages,
                    max_tool_chars=5200,
                    epoch_turn_start=cand_start,
                    epoch_summary_text=cand_summary,
                    epoch_state=epoch_state,
                )
                cand_bytes = _serialized_len(cand_msgs, wire_tools_default)
                if _fits_epoch_budget(cand_bytes):
                    if epoch_state is not None:
                        epoch_state["turn_start"] = cand_start
                        epoch_state["summary_text"] = cand_summary
                        epoch_state["advancements"] = int(epoch_state.get("advancements", 0)) + 1
                    else:
                        self._epoch_turn_start = cand_start
                        self._epoch_summary_text = cand_summary
                    with self._stats_lock:
                        self._epoch_advancements += 1
                    chosen_msgs = cand_msgs
                    chosen_tools = wire_tools_default
                    serialized_bytes = cand_bytes

        if chosen_msgs is None:
            schedules: tuple[tuple[int, int, int, bool], ...] = (
                (3, 5200, 1800, False),
                (2, 4600, 1400, False),
                (2, 3200, 1100, True),
                (1, 2400, 800, True),
                (1, 1400, 500, True),
            )
            init_turns = 3
            init_max_chars = 5200
            init_hist_chars = 1800
            if keep_recent_turns_override is not None:
                capped_turns = max(1, int(keep_recent_turns_override))
                schedules = tuple(
                    (min(turns, capped_turns), max_chars, hist_chars, use_tight)
                    for turns, max_chars, hist_chars, use_tight in schedules
                )
                if capped_turns == 1:
                    schedules = (
                        (1, 2400, 800, True),
                        (1, 1400, 500, True),
                    )
                init_turns, init_max_chars, init_hist_chars, _ = schedules[0]
            chosen_msgs = compact_messages_for_context(
                messages,
                keep_recent_turns=init_turns,
                max_recent_tool_chars=init_max_chars,
                max_history_summary_chars=init_hist_chars,
            )
            chosen_tools = wire_tools_default
            for turns, max_chars, hist_chars, use_tight_tools in schedules:
                candidate = compact_messages_for_context(
                    messages,
                    keep_recent_turns=turns,
                    max_recent_tool_chars=max_chars,
                    max_history_summary_chars=hist_chars,
                )
                tools_payload = wire_tools_tight if use_tight_tools else wire_tools_default
                chosen_msgs = candidate
                chosen_tools = tools_payload
                serialized_bytes = _serialized_len(candidate, tools_payload)
                if (
                    serialized_bytes <= _PROMPT_HARD_CHAR_LIMIT
                    and serialized_bytes + _FRAMING_RESERVE_TOKENS + 256 <= avail
                ):
                    break

        headroom = avail - (serialized_bytes + _FRAMING_RESERVE_TOKENS)
        max_out = min(8192, max(256, headroom)) if headroom > 0 else 2048
        body: dict[str, Any] = {
            "model": model_override or self._active_model,
            "messages": chosen_msgs,
            "tools": chosen_tools,
            "tool_choice": "auto",
            "max_tokens": max_out,
        }
        if self.reasoning_effort and not omit_reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        return body

    def _complete_with_retry(
        self,
        messages: list[dict[str, Any]],
        *,
        epoch_state: dict[str, Any] | None = None,
        model_override: str | None = None,
        usage_sink: dict[str, int] | None = None,
        calls_sink: list[int] | None = None,
        excluded_tools: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        attempt = 0
        http400_attempts = 0
        wire_messages = messages
        omit_reasoning_effort = False
        keep_recent_turns_override: int | None = None
        while True:
            with self._stats_lock:
                min_interval = self._min_call_interval_seconds
                last_call_at = self._last_provider_call_at
            if min_interval > 0.0 and last_call_at is not None:
                clock_fn = getattr(self.budget, "clock", time.monotonic)
                elapsed = max(0.0, float(clock_fn()) - last_call_at)
                wait_for = min_interval - elapsed
                if wait_for > 0.0:
                    rem = float(self.budget.remaining_seconds())
                    bounded_wait = min(wait_for, max(0.0, rem - 1.0)) if rem > 1.0 else 0.0
                    if bounded_wait > 0.0:
                        self.sleep_fn(bounded_wait)
            body = self._prepare_bounded_body(
                wire_messages,
                omit_reasoning_effort=omit_reasoning_effort,
                keep_recent_turns_override=keep_recent_turns_override,
                epoch_state=epoch_state,
                model_override=model_override,
                excluded_tools=excluded_tools,
            )
            clock_fn = getattr(self.budget, "clock", time.monotonic)
            with self._stats_lock:
                self._last_provider_call_at = float(clock_fn())
            try:
                if calls_sink is not None:
                    calls_sink[0] += 1
                resp = self.transport.complete(body, minimum_output_tokens=16)
                turn_usage = account_completion_tokens(resp, body)
                with self._stats_lock:
                    _accumulate_usage(self.token_usage, turn_usage, count_call=True)
                if usage_sink is not None:
                    _accumulate_usage(usage_sink, turn_usage, count_call=True)
                return resp
            except Exception as exc:
                if (
                    self.max_provider_retries > 0
                    and http400_attempts < _MAX_HTTP400_RECOVERIES
                    and self._is_http400_provider_error(exc)
                ):
                    http400_attempts += 1
                    self._clear_transient_gates()
                    wire_messages = _sanitize_messages_for_http400(messages)
                    if http400_attempts >= 2:
                        keep_recent_turns_override = 1
                        omit_reasoning_effort = True
                    continue
                if attempt < self.max_provider_retries and self._is_transient_provider_error(exc):
                    attempt += 1
                    status = self._last_provider_status()
                    if status == 429:
                        delay = min(45.0, float(5 * (2 ** (attempt - 1))))
                        with self._stats_lock:
                            self._min_call_interval_seconds = min(10.0, max(4.0, self._min_call_interval_seconds + 2.0))
                    else:
                        delay = min(30.0, float(2 ** attempt))
                    self._clear_transient_gates()
                    rem = float(self.budget.remaining_seconds())
                    bounded_delay = min(delay, rem) if rem > 0.0 else 0.0
                    if bounded_delay > 0.0:
                        self.sleep_fn(bounded_delay)
                    continue
                raise

    def _save_checkpoint(self, *, turn: int, status: str, messages: list[dict[str, Any]]) -> None:
        if self.bsag is not None:
            self.bsag.save()
        _atomic_write_json(
            self.checkpoint_path,
            {
                "schema": "agentic-checkpoint/1",
                "turn": turn,
                "status": status,
                "execution_mode": self.execution_mode,
                "messages": messages,
                "notebook": self.dispatcher.notebook_state,
                "findings": self.dispatcher.findings,
                "surface_frontier": self.dispatcher.surface_tracker.to_dict(),
                "bsag": self.bsag.to_dict() if self.bsag is not None else None,
                "scheduler": self.scheduler.to_dict() if self.execution_mode == "ephemeral" else None,
                "finish_rejections": self.dispatcher.finish_rejections,
                "http_used": self.http.budget.used,
                "http_limit": self.http.budget.limit,
                "receipt_count": self.receipts.count(),
                "llm_calls": self.transport.calls,
                "token_usage": dict(self.token_usage),
                "finished": self.dispatcher.finished,
                "finish_summary": self.dispatcher.finish_summary,
                "untested_areas": self.dispatcher.untested_areas,
                "epoch_turn_start": self._epoch_turn_start,
                "epoch_summary_text": self._epoch_summary_text,
                "epoch_advancements": self._epoch_advancements,
            },
        )

    def _load_checkpoint(self) -> tuple[int, list[dict[str, Any]]] | None:
        if not self.checkpoint_path.is_file():
            return None
        try:
            data = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or not isinstance(data.get("messages"), list):
            return None
        if isinstance(data.get("notebook"), dict):
            self.dispatcher.notebook_state = data["notebook"]
            self.dispatcher._save_notebook()
        if isinstance(data.get("findings"), list):
            self.dispatcher.findings = data["findings"]
            self.dispatcher._save_findings()
        if isinstance(data.get("surface_frontier"), dict):
            self.dispatcher.surface_tracker.load_dict(data["surface_frontier"])
        if self.bsag is not None:
            if isinstance(data.get("bsag"), dict):
                self.bsag.load_dict(data["bsag"])
            else:
                self.bsag.load_sqlite()
        if isinstance(data.get("scheduler"), dict):
            self.scheduler.load_dict(data["scheduler"])
        if type(data.get("finish_rejections")) is int:
            self.dispatcher.finish_rejections = data["finish_rejections"]
        if isinstance(data.get("token_usage"), dict):
            for k in self.token_usage:
                if type(data["token_usage"].get(k)) is int:
                    self.token_usage[k] = data["token_usage"][k]
        self.dispatcher.finished = bool(data.get("finished", False))
        self.dispatcher.finish_summary = str(data.get("finish_summary") or "")
        self.dispatcher.untested_areas = list(data.get("untested_areas") or [])
        raw_epoch_start = data.get("epoch_turn_start", 0)
        if isinstance(raw_epoch_start, int) and not isinstance(raw_epoch_start, bool):
            self._epoch_turn_start = max(0, raw_epoch_start)
        else:
            self._epoch_turn_start = 0
        raw_epoch_summary = data.get("epoch_summary_text", "")
        self._epoch_summary_text = raw_epoch_summary if isinstance(raw_epoch_summary, str) else ""
        raw_epoch_adv = data.get("epoch_advancements", 0)
        if isinstance(raw_epoch_adv, int) and not isinstance(raw_epoch_adv, bool):
            self._epoch_advancements = max(0, raw_epoch_adv)
        else:
            self._epoch_advancements = 0
        return int(data.get("turn", 0)), data["messages"]

    def _ablation_config(self) -> dict[str, Any]:
        return {
            "execution_mode": self.execution_mode,
            "use_bsag": self.use_bsag,
            "scheduler": self.scheduler_mode,
            "verification_gate": self.verification_gate,
            "intervention": self.intervention_mode,
            "micro_budget": self.micro_budget,
            "synthesis_interval": self.synthesis_interval,
        }

    def write_metrics(self) -> tuple[Path, Path, dict[str, Any]]:
        events = self.telemetry.events() if self.telemetry is not None else []
        json_p, md_p, metrics = write_process_metrics(
            self.root_dir,
            events=events,
            bsag=self.bsag,
            surface_tracker=self.dispatcher.surface_tracker,
            findings=self.dispatcher.findings,
            token_usage=self.token_usage,
            ablation_config=self._ablation_config(),
        )
        self._last_metrics_paths = (json_p, md_p)
        return json_p, md_p, metrics

    def _seed_bsag_initial(self) -> None:
        if self.bsag is None:
            return
        for row in self.http.actors.summaries():
            self.bsag.register_auth_context(
                alias=row["alias"],
                role=row.get("role") or "member",
                tenant=row.get("tenant") or "",
                authenticated=True,
            )
        has_endpoints = any(n.node_type == NODE_ENDPOINT for n in self.bsag.nodes.values())
        if not has_endpoints:
            for hint in self.discovery_hints:
                self.bsag.ensure_endpoint(hint, method="GET", step=0)

    def _select_next_arm_fallback(self, step_idx: int) -> ArmSelection:
        """Select a fallback arm from SurfaceFrontierTracker when use_bsag=False."""
        frontier = self.dispatcher.surface_tracker.high_value_frontier()
        if frontier["unvisited_routes"]:
            raw = frontier["unvisited_routes"][0]
            path = raw.split(" ", 1)[1].split("?", 1)[0]
            return ArmSelection(node_id=f"ep:{path}", category="surface_discovery", score=1.0, reason="frontier_unvisited", route_template=path)
        if frontier["untested_cross_actor_objects"]:
            raw = frontier["untested_cross_actor_objects"][0]
            path = raw.split(" ", 2)[1]
            return ArmSelection(node_id=f"ep:{path}", category="object_isolation", score=1.0, reason="frontier_cross_actor", route_template=path)
        if frontier["untested_write_ops"]:
            raw = frontier["untested_write_ops"][0]
            path = raw.split(" ", 1)[1]
            return ArmSelection(node_id=f"ep:{path}", category="state_mutation", score=1.0, reason="frontier_write", route_template=path)
        hint = self.discovery_hints[step_idx % len(self.discovery_hints)]
        return ArmSelection(node_id=f"ep:{hint}", category="surface_discovery", score=0.5, reason="hint_fallback", route_template=hint)

    def _run_synthesis_pass(self, worker_idx: int) -> int:
        """Run a lightweight 1-step synthesis pass over compact BSAG summary to add multi-hop hypotheses."""
        if self.bsag is None or self.budget.available("tokens") < 3000 or self.budget.remaining_seconds() <= 5:
            return 0
        summary = self.bsag.compact_summary(max_chars=3200)
        synth_msgs = build_synthesis_prompt(graph_summary=summary)
        body: dict[str, Any] = {
            "model": self.model,
            "messages": synth_msgs,
            "max_tokens": 512,
        }
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        try:
            resp = self.transport.complete(body, minimum_output_tokens=16)
        except Exception:
            return 0
        usage = account_completion_tokens(resp, body)
        with self._stats_lock:
            _accumulate_usage(self.token_usage, usage, count_call=False)
        if self.telemetry is not None:
            self.telemetry.emit(
                "token_usage",
                worker_id=f"synth-{worker_idx:03d}",
                prompt_tokens=usage["prompt_tokens"],
                completion_tokens=usage["completion_tokens"],
                total_tokens=usage["total_tokens"],
                source=usage["source"],
            )
        choice = (resp.get("choices") or [{}])[0]
        raw_text = str(((choice.get("message") or {}).get("content")) or "").strip()
        if not raw_text:
            return 0
        # Parse JSON array robustly even if wrapped in code fences
        match = re.search(r"\[.*\]", raw_text, re.DOTALL)
        if not match:
            return 0
        try:
            items = json.loads(match.group(0))
        except ValueError:
            return 0
        if not isinstance(items, list):
            return 0
        added = 0
        for item in items[:3]:
            if not isinstance(item, dict):
                continue
            ep = str(item.get("endpoint") or "").strip()
            if not ep:
                continue
            ep_nid = self.bsag.endpoint_node_id(ep)
            existing_ep = self.bsag.nodes.get(ep_nid)
            if existing_ep is not None and existing_ep.status in {STATUS_VERIFIED, STATUS_SUSPECT_DECOY}:
                continue
            if existing_ep is None:
                self.bsag.ensure_endpoint(ep, method="GET")
            cat = str(item.get("category") or "multi_step_workflow").strip()
            if cat not in {
                "surface_discovery",
                "auth_session",
                "access_control",
                "object_isolation",
                "input_validation",
                "state_mutation",
                "multi_step_workflow",
            }:
                cat = "multi_step_workflow"
            _, dv, _ = self.bsag.register_hypothesis(
                endpoint_node_id=ep_nid,
                category=cat,
                vuln_class=str(item.get("vuln_class") or cat),
                summary=str(item.get("summary") or "cross-endpoint synthesis hypothesis"),
                status=STATUS_IN_PROGRESS,
                multi_hop=True,
            )
            if dv:
                added += 1
        if self.telemetry is not None:
            self.telemetry.emit("synthesis", worker_idx=worker_idx, hypotheses_added=added)
        return added

    def run(self, *, resume: bool = False) -> dict[str, Any]:
        """Run (or resume) the investigator loop in `monolithic`, `ephemeral`, or `sharded` mode."""
        if self.execution_mode == "ephemeral":
            return self._run_ephemeral(resume=resume)
        if self.execution_mode == "sharded":
            return self._run_sharded(resume=resume)
        return self._run_monolithic(resume=resume)

    def _run_ephemeral(self, *, resume: bool = False) -> dict[str, Any]:
        """Run the 5-layer Thin-Control, Thick-State ephemeral worker orchestrator."""
        total_turns = 0
        if resume:
            loaded = self._load_checkpoint()
            if loaded is not None:
                total_turns, _ = loaded
        self._seed_bsag_initial()

        status = "running"
        worker_idx = 0
        last_synth_worker = 0
        last_auth_count = (
            sum(1 for n in self.bsag.nodes.values() if n.node_type == NODE_AUTH_CONTEXT)
            if self.bsag is not None
            else len(self.http.actors.actors)
        )
        last_art_count = (
            sum(1 for n in self.bsag.nodes.values() if n.node_type == NODE_ARTIFACT)
            if self.bsag is not None
            else 0
        )

        try:
            while total_turns < self.max_turns:
                if self.budget.remaining_seconds() <= 5 or self.budget.available("tokens") < 2500:
                    status = "budget_exhausted"
                    break
                http_rem = self.http.budget.limit - self.http.budget.used
                if http_rem <= 1:
                    status = "http_budget_exhausted"
                    break

                # Periodic synthesis pass on interval or newly discovered AUTH_CONTEXT / ARTIFACT
                if self.bsag is not None and worker_idx > 0:
                    cur_auth = sum(1 for n in self.bsag.nodes.values() if n.node_type == NODE_AUTH_CONTEXT)
                    cur_art = sum(1 for n in self.bsag.nodes.values() if n.node_type == NODE_ARTIFACT)
                    if (
                        (worker_idx - last_synth_worker) >= self.synthesis_interval
                        or cur_auth > last_auth_count
                        or cur_art > last_art_count + 2
                    ):
                        self._run_synthesis_pass(worker_idx)
                        total_turns += 1
                        last_synth_worker = worker_idx
                        last_auth_count = cur_auth
                        last_art_count = cur_art
                        if total_turns >= self.max_turns:
                            status = "max_turns_reached"
                            break

                arm: ArmSelection | None = (
                    self.scheduler.select_arm(self.bsag)
                    if self.bsag is not None
                    else self._select_next_arm_fallback(worker_idx)
                )
                if arm is None:
                    status = "finished"
                    break

                worker_idx += 1
                worker_id = f"w-{worker_idx:03d}"
                self.scheduler.record_selection(arm.node_id, arm.category)
                self.intervention_monitor.reset_worker_window()
                self.dispatcher.set_active_context(
                    worker_id=worker_id,
                    node_id=arm.node_id,
                    category=arm.category,
                )
                self.dispatcher.coverage_gate_enabled = False
                self.dispatcher.discovery_finish_gate = False
                self.dispatcher.finished = False
                self.dispatcher.consume_step_deltas()

                if self.telemetry is not None:
                    self.telemetry.emit(
                        "worker_start",
                        worker_id=worker_id,
                        node_id=arm.node_id,
                        category=arm.category,
                        score=arm.score,
                        reason=arm.reason,
                        route_template=arm.route_template,
                    )

                slice_text = (
                    self.bsag.slice_for_arm(arm.node_id, arm.category, max_chars=2400)
                    if self.bsag is not None
                    else f"Target slice: {arm.route_template} | category={arm.category}{self.dispatcher.surface_tracker.format_frontier_banner(max_chars=1200)}"
                )
                sys_prompt = build_worker_system_prompt(
                    base_url=self.http.base_url,
                    allowed_methods=sorted(self.http.allowed_methods),
                    http_budget_remaining=self.http.budget.limit - self.http.budget.used,
                    micro_budget=self.micro_budget,
                )
                user_prompt = (
                    f"Assigned verification slice ({arm.category}) for {arm.route_template or arm.node_id}.\n"
                    f"Graph slice:\n{slice_text}\n\n"
                    f"Initial discovery hints: {json.dumps(self.discovery_hints, ensure_ascii=False)}\n"
                    "Execute focused HTTP checks for this slice using the tools, record any verified finding "
                    "immediately with proof + comparative control receipts, and call `finish` when done."
                )
                worker_messages: list[dict[str, Any]] = [
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_prompt},
                ]

                worker_steps = 0
                worker_dv = 0
                worker_de = 0
                findings_before = len(self.dispatcher.findings)
                stop_reason = "completed"

                while worker_steps < self.micro_budget and total_turns < self.max_turns:
                    if self.budget.remaining_seconds() <= 5 or self.budget.available("tokens") < 2500:
                        stop_reason = "budget_exhausted"
                        status = "budget_exhausted"
                        break
                    if (self.http.budget.limit - self.http.budget.used) <= 0:
                        stop_reason = "http_budget_exhausted"
                        status = "http_budget_exhausted"
                        break

                    resp = self._complete_with_retry(worker_messages)
                    total_turns += 1
                    worker_steps += 1
                    if self.telemetry is not None:
                        self.telemetry.emit(
                            "token_usage",
                            worker_id=worker_id,
                            total_tokens=self.token_usage["total_tokens"],
                        )

                    choice = (resp.get("choices") or [{}])[0]
                    msg = choice.get("message") or {}
                    tool_calls = msg.get("tool_calls") or []
                    worker_messages.append(_build_assistant_history_entry(msg))

                    if not tool_calls:
                        stop_reason = "no_signal"
                        break

                    for idx, tc in enumerate(tool_calls):
                        fn = tc.get("function") or {}
                        name = str(fn.get("name") or "")
                        raw_args = fn.get("arguments") or "{}"
                        try:
                            parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                        except ValueError:
                            parsed_args = {}
                        result_text = self.dispatcher.dispatch(name, parsed_args)
                        worker_messages.append({
                            "role": "tool",
                            "tool_call_id": str(tc.get("id") or f"call_{total_turns}_{idx}"),
                            "content": result_text,
                        })

                    step_dv, step_de, claim_submitted = self.dispatcher.consume_step_deltas()
                    worker_dv += step_dv
                    worker_de += step_de
                    if self.telemetry is not None and self.bsag is not None:
                        snap = self.bsag.metrics_snapshot()
                        self.telemetry.emit(
                            "bsag_delta",
                            worker_id=worker_id,
                            node_id=arm.node_id,
                            category=arm.category,
                            delta_v=step_dv,
                            delta_e=step_de,
                            total_nodes=snap["total_nodes"],
                            total_edges=snap["total_edges"],
                        )

                    http_rem_ratio = (self.http.budget.limit - self.http.budget.used) / max(1, self.http.budget.limit)
                    decision = self.intervention_monitor.evaluate_step(
                        delta_v=step_dv,
                        delta_e=step_de,
                        worker_steps=worker_steps,
                        scheduler=self.scheduler,
                        claim_submitted=claim_submitted,
                        finish_requested=self.dispatcher.finished,
                        bsag=self.bsag,
                        http_remaining_ratio=http_rem_ratio,
                    )
                    if decision.intervene and decision.action not in {"block_early_finish", "route_to_oracle"}:
                        if self.telemetry is not None:
                            self.telemetry.emit(
                                "intervention",
                                worker_id=worker_id,
                                node_id=arm.node_id,
                                category=arm.category,
                                trigger=decision.trigger,
                                action=decision.action,
                                reason=decision.reason,
                            )
                        if decision.action == "switch_arm":
                            if self.bsag is not None:
                                self.bsag.mark_stagnant(arm.node_id)
                            stop_reason = "stagnation"
                            break
                        if decision.action == "cooldown_category":
                            stop_reason = "low_entropy"
                            break
                        if decision.action == "rotate_worker":
                            stop_reason = "micro_budget"
                            break

                    if self.dispatcher.finished:
                        stop_reason = "worker_finished"
                        break

                finding_gain = max(0, len(self.dispatcher.findings) - findings_before)
                reward = min(2.0, 0.25 * worker_dv + 0.3 * worker_de + 1.0 * finding_gain)
                self.scheduler.record_outcome(arm.node_id, arm.category, reward)
                if self.bsag is not None and arm.node_id in self.bsag.nodes:
                    ep_node = self.bsag.nodes[arm.node_id]
                    if ep_node.visit_count == 0:
                        ep_node.visit_count += 1
                    tested_cats = ep_node.attributes.setdefault("categories_tested", {})
                    tested_cats[arm.category] = int(tested_cats.get(arm.category) or 0) + 1
                    if stop_reason == "worker_finished" and finding_gain == 0 and ep_node.status == STATUS_IN_PROGRESS:
                        ep_node.information_gain_ema = 0.7 * ep_node.information_gain_ema + 0.3 * min(1.0, reward)
                if self.telemetry is not None:
                    self.telemetry.emit(
                        "worker_end",
                        worker_id=worker_id,
                        node_id=arm.node_id,
                        category=arm.category,
                        stop_reason=stop_reason,
                        steps_used=worker_steps,
                        delta_v_total=worker_dv,
                        delta_e_total=worker_de,
                        findings_added=finding_gain,
                    )
                self.dispatcher.finished = False
                self._save_checkpoint(turn=total_turns, status="in_progress", messages=worker_messages[-4:])

                if status in {"budget_exhausted", "http_budget_exhausted"}:
                    break
                # Stop campaign cleanly when all priority arms are covered or budget exhausted
                if (
                    self.bsag is not None
                    and worker_idx >= 4
                    and not self.scheduler.has_unexplored_priority_arms(self.bsag)
                ):
                    http_rem_ratio = (self.http.budget.limit - self.http.budget.used) / max(1, self.http.budget.limit)
                    if http_rem_ratio <= 0.25:
                        status = "finished"
                        break
            else:
                if status == "running":
                    status = "max_turns_reached"

            if status == "running":
                status = "finished"
            self.dispatcher.finished = status == "finished"
            self._save_checkpoint(turn=total_turns, status=status, messages=[])
        except BudgetError as exc:
            status = exc.code or "budget_exhausted"
            self._save_checkpoint(turn=total_turns, status=status, messages=[])
        except Exception as exc:
            status = f"error:{type(exc).__name__}"
            self._save_checkpoint(turn=total_turns, status=status, messages=[])
            raise
        finally:
            self._close_dispatcher(self.dispatcher)
            if self.telemetry is not None or self.bsag is not None:
                self.write_metrics()

        return self._result_summary(status)

    def _build_handoff_packet(self, *, reason: str, next_turn: int) -> tuple[str, str]:
        """Construct a compact, target-agnostic Phase 2 deep-verification prompt from Phase 1 state."""
        sys_prompt = (
            build_system_prompt(
                base_url=self.http.base_url,
                allowed_methods=sorted(self.http.allowed_methods),
                actor_summaries=self.http.actors.summaries(),
                discovery_hints=self.discovery_hints,
                http_budget=self.http.budget.limit,
            )
            + "\n\nPHASE 2 DEEP VERIFICATION HANDOFF:\n"
            "- A fast Phase 1 scout already mapped initial routes, established sessions (including dynamically registered actors), "
            "and recorded verified findings listed below.\n"
            "- Do NOT re-discover already-visited routes or re-record already-verified findings.\n"
            "- Focus immediately on high-value untested gaps: allowed mutating endpoints (PUT/PATCH/POST mass assignment & authorization), "
            "untested concrete object IDs across peer and cross-tenant actors (including UI<->API sibling parity), unprobed query/form "
            "parameters (SQLi, XSS, open redirect), and deeper multi-step or business-logic workflows.\n"
            "- Reuse existing receipt_ids with `replay_as` or `read_receipt` where helpful, and call `record_finding` immediately upon verification."
        )

        lines: list[str] = [
            f"[HANDOFF SUMMARY] reason={reason} | scout_model={self.scout_model} | deep_model={self.model} | "
            f"findings_so_far={len(self.dispatcher.findings)} | receipts_so_far={self.receipts.count()}"
        ]
        if self.dispatcher.findings:
            f_rows = []
            for f in self.dispatcher.findings[:20]:
                ev = str(f.get("evidence_value") or "")[:70]
                f_rows.append(
                    f"  - {f.get('finding_id')} [{f.get('class_type')}] {f.get('method')} {f.get('path') or f.get('url')} "
                    f"actor={f.get('actor_alias') or f.get('actor')} ev={ev!r}"
                )
            lines.append("[VERIFIED FINDINGS (DO NOT DUPLICATE)]\n" + "\n".join(f_rows))
        else:
            lines.append("[VERIFIED FINDINGS] none yet")

        tracker = self.dispatcher.surface_tracker
        frontier = tracker.high_value_frontier()
        frontier_compact = json.dumps(frontier, ensure_ascii=False, separators=(",", ":"))
        if len(frontier_compact) > 1400:
            frontier_compact = frontier_compact[:1397] + "..."
        lines.append(f"[REMAINING FRONTIER]\n{frontier_compact}")

        declared_writes = sorted(f"{m} {p}" for m, p in tracker.declared_write_ops)
        tested_writes = sorted(f"{m} {p}" for m, p in tracker.tested_write_ops)
        if declared_writes:
            lines.append(
                f"[WRITE OPS] declared={declared_writes[:12]} | tested={tested_writes[:12]}"
            )
        if tracker.discovered_params:
            param_items = [
                f"{tmpl}:{sorted(ps)[:4]}"
                for tmpl, ps in sorted(tracker.discovered_params.items())[:12]
            ]
            lines.append("[DISCOVERED PARAMS] " + ", ".join(param_items))

        # Compact receipt index (prefer distinct (actor, method, path) up to 45 entries)
        seen_sig: set[tuple[str, str, str, int]] = set()
        rec_lines: list[str] = []
        for rid in self.receipts.list_ids():
            try:
                rec = self.receipts.get(rid)
            except Exception:
                continue
            actor = str(rec.get("actor") or "anon")
            method = str(rec.get("method") or "GET")
            url = str(rec.get("url") or "")
            parsed = urlsplit(url)
            short_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            if len(short_path) > 72:
                short_path = short_path[:69] + "..."
            status = int(rec.get("status") or 0)
            sig = (actor, method, short_path, status)
            if sig in seen_sig:
                continue
            seen_sig.add(sig)
            rlen = int(rec.get("response_length") or len(str(rec.get("body") or "")))
            rec_lines.append(f"  {rid} {actor} {method} {short_path} -> {status} ({rlen}B)")
            if len(rec_lines) >= 45:
                break
        if rec_lines:
            lines.append("[NOTABLE RECEIPTS]\n" + "\n".join(rec_lines))

        nb = self.dispatcher.notebook_state
        scout_notes_parts: list[str] = []
        if nb.get("surface_notes"):
            scout_notes_parts.append(str(nb["surface_notes"])[:350])
        if nb.get("notes"):
            scout_notes_parts.extend(str(n)[:160] for n in nb["notes"][-4:])
        if self.dispatcher.finish_summary:
            scout_notes_parts.append("scout_summary: " + self.dispatcher.finish_summary[:300])
        if scout_notes_parts:
            lines.append("[SCOUT NOTES]\n" + " | ".join(scout_notes_parts)[:800])

        user_prompt = (
            "Phase 2 deep verification begins now. Review the Phase 1 handoff packet below and immediately test "
            "remaining high-value targets (write endpoints, untested concrete object IDs across actors, unprobed parameters, "
            "and multi-step workflows) without repeating verified findings.\n\n"
            + "\n".join(lines)
            + self._state_banner(next_turn)
        )
        return sys_prompt, user_prompt

    @staticmethod
    def _merge_surface_trackers(dst: SurfaceFrontierTracker, src: SurfaceFrontierTracker) -> None:
        """Merge visited routes, objects, params, write ops, and actor coverage from a shard tracker."""
        dst.exercised_actors.update(src.exercised_actors)
        dst.visited_method_paths.update(src.visited_method_paths)
        dst.visited_method_templates.update(src.visited_method_templates)
        dst.html_or_form_templates.update(src.html_or_form_templates)
        dst.declared_write_ops.update(src.declared_write_ops)
        dst.tested_write_ops.update(src.tested_write_ops)
        dst.discovered_write_ops.update(src.discovered_write_ops)
        dst.discovered_routes.update(src.discovered_routes)
        dst._pruned_404_objects.update(src._pruned_404_objects)

        for alias, meta in src.actors.items():
            if alias not in dst.actors:
                dst.actors[alias] = dict(meta)

        for dict_attr in (
            "tested_params_by_template",
            "actors_by_template",
            "actors_by_path",
            "route_2xx_actors",
            "discovered_params",
            "collection_listed_objects",
            "api_prefix_routes",
        ):
            dst_map = getattr(dst, dict_attr)
            src_map = getattr(src, dict_attr)
            for key, vals in src_map.items():
                dst_map.setdefault(key, set()).update(vals)

        for tmpl, pmap in src.param_probes_by_template.items():
            dst_pmap = dst.param_probes_by_template.setdefault(tmpl, {})
            for pname, rec in pmap.items():
                dst_rec = dst_pmap.setdefault(pname, {"values": set(), "has_special": False})
                dst_rec["values"].update(rec.get("values") or ())
                dst_rec["has_special"] = bool(dst_rec.get("has_special") or rec.get("has_special"))

        for obj_path, entry in src.discovered_objects.items():
            existing = dst.discovered_objects.get(obj_path)
            if existing is None:
                dst.discovered_objects[obj_path] = {
                    "path": entry["path"],
                    "template": entry["template"],
                    "owner_actor": entry.get("owner_actor", ""),
                    "seen_by": set(entry.get("seen_by") or ()),
                    "listed_by": set(entry.get("listed_by") or ()),
                    "tested_by": set(entry.get("tested_by") or ()),
                    "verified_2xx": bool(entry.get("verified_2xx")),
                }
            else:
                if not existing.get("owner_actor") and entry.get("owner_actor"):
                    existing["owner_actor"] = entry["owner_actor"]
                existing["seen_by"].update(entry.get("seen_by") or ())
                existing.setdefault("listed_by", set()).update(entry.get("listed_by") or ())
                existing["tested_by"].update(entry.get("tested_by") or ())
                existing["verified_2xx"] = bool(existing.get("verified_2xx") or entry.get("verified_2xx"))

    def _execute_monolithic_loop(
        self,
        *,
        dispatcher: ToolDispatcher,
        messages: list[dict[str, Any]],
        start_turn: int,
        max_turns: int,
        epoch_state: dict[str, Any] | None = None,
        model_name: str | None = None,
        allow_coverage_gate: bool = True,
        allow_discovery_gate: bool = False,
        disable_gate_last_n_turns: int = 0,
        checkpoint_fn: Callable[[int, str, list[dict[str, Any]]], None] | None = None,
        handoff_scout_cfg: dict[str, Any] | None = None,
        shard_cluster: SubsystemCluster | None = None,
        usage_sink: dict[str, int] | None = None,
        calls_sink: list[int] | None = None,
        shard_token_quota: int | None = None,
        excluded_tools: frozenset[str] | None = None,
    ) -> tuple[str, int, list[dict[str, Any]]]:
        """Run a bounded ReAct monolithic loop over a caller-supplied dispatcher and message list."""
        status = "running"
        empty_nudges = 0
        reserve_floor_turns = 0
        last_completed_turn = start_turn - 1
        recent_local_reads: list[tuple[int, str, str, str]] = []
        eff_model = model_name or self.model
        is_shard = shard_cluster is not None or shard_token_quota is not None

        def _shard_tokens_used() -> int:
            if usage_sink is None:
                return 0
            return effective_tokens_from_usage(usage_sink, self.cache_token_weight)

        def _enter_deep_phase(reason: str, completed_turn: int) -> None:
            nonlocal messages, empty_nudges, recent_local_reads, eff_model
            assert handoff_scout_cfg is not None
            self._handoff_summary = {
                "scout_model": self.scout_model,
                "deep_model": self.model,
                "handoff_reason": reason,
                "handoff_after_turn": completed_turn,
                "scout_calls": self.transport.calls - handoff_scout_cfg["start_calls"],
                "scout_tokens": self.token_usage["total_tokens"] - handoff_scout_cfg["start_tokens"],
                "scout_http": self.http.budget.used - handoff_scout_cfg["start_http"],
                "scout_findings": len(dispatcher.findings),
            }
            self._handoff_phase = "deep"
            self._active_model = self.model
            eff_model = self.model
            self._epoch_turn_start = 0
            self._epoch_summary_text = ""
            if epoch_state is not None:
                epoch_state["turn_start"] = 0
                epoch_state["summary_text"] = ""
            dispatcher.finished = False
            dispatcher.finish_rejections = 0
            p2_sys, p2_usr = self._build_handoff_packet(reason=reason, next_turn=completed_turn + 1)
            dispatcher.finish_summary = ""
            messages = [
                {"role": "system", "content": p2_sys},
                {"role": "user", "content": p2_usr},
            ]
            empty_nudges = 0
            recent_local_reads = []

        try:
            for turn in range(start_turn, max_turns + 1):
                if handoff_scout_cfg is not None and self._handoff_phase == "scout":
                    scout_tokens_used = self.token_usage["total_tokens"] - handoff_scout_cfg["start_tokens"]
                    if turn > handoff_scout_cfg["turn_limit"] or scout_tokens_used >= handoff_scout_cfg["token_cap"]:
                        _enter_deep_phase(
                            "scout_turn_limit" if turn > handoff_scout_cfg["turn_limit"] else "scout_token_cap",
                            turn - 1,
                        )

                if dispatcher.finished:
                    status = "finished"
                    break
                cur_shard_tokens = _shard_tokens_used()
                min_global_tokens = 3500 if is_shard else 2500
                if (
                    self.budget.remaining_seconds() <= 5
                    or self.budget.available("tokens") < min_global_tokens
                    or (
                        shard_token_quota is not None
                        and shard_token_quota > 0
                        and cur_shard_tokens >= shard_token_quota
                    )
                ):
                    status = "budget_exhausted"
                    if checkpoint_fn is not None:
                        checkpoint_fn(last_completed_turn, status, messages)
                    break

                http_reserve_floor = int(getattr(dispatcher, "http_reserve_floor", 0) or 0)
                if (
                    http_reserve_floor > 0
                    and (self.http.budget.limit - self.http.budget.used) <= http_reserve_floor
                ):
                    if reserve_floor_turns >= 1:
                        status = "finished" if dispatcher.findings else "budget_exhausted"
                        if checkpoint_fn is not None:
                            checkpoint_fn(last_completed_turn, status, messages)
                        break
                    reserve_floor_turns += 1

                self._sync_coverage_gate(
                    turn,
                    dispatcher=dispatcher,
                    max_turns_override=max_turns,
                    allow_coverage_gate=allow_coverage_gate,
                    allow_discovery_gate=allow_discovery_gate,
                    disable_gate_last_n_turns=disable_gate_last_n_turns,
                    shard_token_quota=shard_token_quota,
                    shard_tokens_used=cur_shard_tokens,
                )
                if handoff_scout_cfg is not None and self._handoff_phase == "scout" and turn >= handoff_scout_cfg["turn_limit"] - 1:
                    dispatcher.coverage_gate_enabled = False
                if disable_gate_last_n_turns > 0 and turn > max_turns - disable_gate_last_n_turns:
                    dispatcher.coverage_gate_enabled = False
                    dispatcher.discovery_finish_gate = False

                resp = self._complete_with_retry(
                    messages,
                    epoch_state=epoch_state,
                    model_override=eff_model,
                    usage_sink=usage_sink,
                    calls_sink=calls_sink,
                    excluded_tools=excluded_tools,
                )
                choice = (resp.get("choices") or [{}])[0]
                msg = choice.get("message") or {}
                tool_calls = msg.get("tool_calls") or []
                messages.append(_build_assistant_history_entry(msg))

                if tool_calls:
                    cur_shard_tokens = _shard_tokens_used()
                    self._sync_coverage_gate(
                        turn,
                        dispatcher=dispatcher,
                        max_turns_override=max_turns,
                        allow_coverage_gate=allow_coverage_gate,
                        allow_discovery_gate=allow_discovery_gate,
                        disable_gate_last_n_turns=disable_gate_last_n_turns,
                        shard_token_quota=shard_token_quota,
                        shard_tokens_used=cur_shard_tokens,
                    )
                    if handoff_scout_cfg is not None and self._handoff_phase == "scout" and turn >= handoff_scout_cfg["turn_limit"] - 1:
                        dispatcher.coverage_gate_enabled = False
                    if disable_gate_last_n_turns > 0 and turn > max_turns - disable_gate_last_n_turns:
                        dispatcher.coverage_gate_enabled = False
                        dispatcher.discovery_finish_gate = False
                    empty_nudges = 0
                    recent_local_reads = [entry for entry in recent_local_reads if turn - entry[0] <= 8]
                    for idx, tc in enumerate(tool_calls):
                        fn = tc.get("function") or {}
                        name = str(fn.get("name") or "")
                        raw_args = fn.get("arguments") or "{}"
                        try:
                            parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                        except ValueError:
                            parsed_args = {}
                        if excluded_tools and name in excluded_tools:
                            result_text = json.dumps(
                                {
                                    "error": "tool_disabled_in_bootstrap_discovery",
                                    "hint": "Focus on surface/auth discovery; Stage 2 shards handle record_finding.",
                                },
                                ensure_ascii=False,
                            )
                        else:
                            result_text = dispatcher.dispatch(name, parsed_args)
                        if name in _LOCAL_READ_TOOLS and not (
                            name == "notebook" and str(parsed_args.get("action") or "read").lower() != "read"
                        ):
                            canon_args = json.dumps(parsed_args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                            rid = str(parsed_args.get("receipt_id") or "")
                            exact_hits = sum(
                                1
                                for t_prev, n_prev, a_prev, _ in recent_local_reads
                                if n_prev == name and a_prev == canon_args and (turn - t_prev) <= 6
                            )
                            same_rid_hits = (
                                sum(
                                    1
                                    for _, n_prev, _, r_prev in recent_local_reads
                                    if n_prev in {"read_receipt", "extract_surface"} and r_prev == rid
                                )
                                if rid
                                else 0
                            )
                            recent_local_reads.append((turn, name, canon_args, rid))
                            if exact_hits >= 1 or same_rid_hits >= 2:
                                target_ref = rid or name
                                result_text += (
                                    f"\n[LOOP GUARD] Repeated local inspection of `{target_ref}` detected. "
                                    "Do NOT re-read it again; act directly on untested routes, cross-actor replays, "
                                    "or allowed write operations in [SURFACE FRONTIER], or call `record_finding` for verified issues."
                                )
                        if idx == len(tool_calls) - 1:
                            cur_shard_tokens = _shard_tokens_used()
                            result_text = result_text + self._state_banner(
                                turn + 1,
                                dispatcher=dispatcher,
                                max_turns_override=max_turns,
                                shard_cluster=shard_cluster,
                                allow_coverage_gate=allow_coverage_gate,
                                shard_token_quota=shard_token_quota,
                                shard_tokens_used=cur_shard_tokens,
                            )
                            shard_wrapup_urgent = (
                                shard_token_quota is not None
                                and shard_token_quota > 0
                                and cur_shard_tokens >= int(shard_token_quota * 0.80)
                            )
                            http_rem_after = self.http.budget.limit - self.http.budget.used
                            eff_floor = int(getattr(dispatcher, "http_reserve_floor", 0) or 0)
                            usable_http_rem = max(0, http_rem_after - eff_floor)
                            if (
                                turn >= max_turns - 2
                                or usable_http_rem <= 8
                                or shard_wrapup_urgent
                            ):
                                if excluded_tools and "record_finding" in excluded_tools:
                                    result_text += (
                                        "\n[URGENT] Bootstrap discovery turns or budget nearly exhausted: "
                                        "call `finish` now so Stage 2 shards can begin."
                                    )
                                else:
                                    result_text += "\n[URGENT] Budget or turns nearly exhausted: call `record_finding` for verified issues and `finish`."
                        messages.append({
                            "role": "tool",
                            "tool_call_id": str(tc.get("id") or f"call_{turn}_{idx}"),
                            "content": result_text,
                        })
                else:
                    empty_nudges += 1
                    if empty_nudges >= 3:
                        if (
                            handoff_scout_cfg is not None
                            and self._handoff_phase == "scout"
                            and turn < max_turns - 1
                            and self.budget.available("tokens") >= 15_000
                        ):
                            last_completed_turn = turn
                            _enter_deep_phase("scout_stopped_no_tool_calls", turn)
                            if checkpoint_fn is not None:
                                checkpoint_fn(turn, "in_progress", messages)
                            continue
                        status = "stopped_no_tool_calls"
                        last_completed_turn = turn
                        if checkpoint_fn is not None:
                            checkpoint_fn(turn, status, messages)
                        break
                    messages.append({
                        "role": "user",
                        "content": (
                            "Continue investigating using the provided tools, or call `finish` when done."
                            + self._state_banner(
                                turn + 1,
                                dispatcher=dispatcher,
                                max_turns_override=max_turns,
                                shard_cluster=shard_cluster,
                                allow_coverage_gate=allow_coverage_gate,
                                shard_token_quota=shard_token_quota,
                                shard_tokens_used=_shard_tokens_used(),
                            )
                        ),
                    })

                last_completed_turn = turn
                if dispatcher.finished:
                    if (
                        handoff_scout_cfg is not None
                        and self._handoff_phase == "scout"
                        and turn < max_turns - 1
                        and self.budget.available("tokens") >= 15_000
                    ):
                        _enter_deep_phase("scout_finished", turn)
                        if checkpoint_fn is not None:
                            checkpoint_fn(turn, "in_progress", messages)
                        continue
                    status = "finished"
                    if checkpoint_fn is not None:
                        checkpoint_fn(turn, status, messages)
                    break
                if checkpoint_fn is not None:
                    checkpoint_fn(turn, "in_progress", messages)
            else:
                status = "max_turns_reached"
        except BudgetError as exc:
            status = self._classify_budget_error(exc, is_shard=is_shard)
            if checkpoint_fn is not None:
                checkpoint_fn(last_completed_turn, status, messages)
        except ServiceDegradationError:
            status = "service_degraded"
            if checkpoint_fn is not None:
                checkpoint_fn(last_completed_turn, status, messages)
        except Exception as exc:
            status = f"error:{type(exc).__name__}"
            if checkpoint_fn is not None:
                checkpoint_fn(last_completed_turn, status, messages)
            raise
        return status, last_completed_turn, messages

    def _run_monolithic(self, *, resume: bool = False) -> dict[str, Any]:
        """Run (or resume) the ReAct investigator loop until finish or budget/turn exhaustion."""
        start_turn = 1
        messages: list[dict[str, Any]] | None = None
        if resume:
            loaded = self._load_checkpoint()
            if loaded is not None:
                last_turn, loaded_msgs = loaded
                if self.dispatcher.finished:
                    self._close_dispatcher(self.dispatcher)
                    return self._result_summary("finished")
                start_turn = last_turn + 1
                messages = loaded_msgs

        handoff_enabled = bool(self.scout_model and self.scout_model != self.model and not resume)
        scout_start_tokens = self.token_usage["total_tokens"]
        scout_start_calls = self.transport.calls
        scout_start_http = self.http.budget.used
        scout_token_cap = max(20_000, int(self.budget.limits["tokens"] * self.scout_token_share))
        scout_turn_limit = min(self.scout_max_turns, max(1, self.max_turns - 4))
        if handoff_enabled:
            self._handoff_phase = "scout"
            self._active_model = self.scout_model
        else:
            self._handoff_phase = "single"
            self._active_model = self.model

        if messages is None:
            self._epoch_turn_start = 0
            self._epoch_summary_text = ""
            self._epoch_advancements = 0
            sys_prompt = build_system_prompt(
                base_url=self.http.base_url,
                allowed_methods=sorted(self.http.allowed_methods),
                actor_summaries=self.http.actors.summaries(),
                discovery_hints=self.discovery_hints,
                http_budget=self.http.budget.limit,
            )
            init_prompt = (
                "Begin the security investigation of the authorized target. "
                "Start by discovering the surface using the initial discovery entry points, "
                "inspecting extracted routes/forms/JS/OpenAPI schemas, and systematically testing "
                "authentication, authorization, tenant isolation, and input validation. "
                + self._state_banner(1)
            )
            messages = [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": init_prompt},
            ]

        handoff_cfg = (
            {
                "start_tokens": scout_start_tokens,
                "start_calls": scout_start_calls,
                "start_http": scout_start_http,
                "token_cap": scout_token_cap,
                "turn_limit": scout_turn_limit,
            }
            if handoff_enabled
            else None
        )
        try:
            status, _, _ = self._execute_monolithic_loop(
                dispatcher=self.dispatcher,
                messages=messages,
                start_turn=start_turn,
                max_turns=self.max_turns,
                epoch_state=None,
                model_name=self._active_model,
                allow_coverage_gate=True,
                checkpoint_fn=lambda t, st, msgs: self._save_checkpoint(turn=t, status=st, messages=msgs),
                handoff_scout_cfg=handoff_cfg,
            )
        finally:
            self._close_dispatcher(self.dispatcher)
            if self._handoff_summary is not None:
                self._handoff_summary.update(
                    deep_calls=max(0, self.transport.calls - scout_start_calls - self._handoff_summary["scout_calls"]),
                    deep_tokens=max(
                        0,
                        self.token_usage["total_tokens"] - scout_start_tokens - self._handoff_summary["scout_tokens"],
                    ),
                    deep_http=max(0, self.http.budget.used - scout_start_http - self._handoff_summary["scout_http"]),
                    deep_findings=max(0, len(self.dispatcher.findings) - self._handoff_summary["scout_findings"]),
                    total_findings=len(self.dispatcher.findings),
                )
            if self.telemetry is not None or self.bsag is not None:
                self.write_metrics()

        return self._result_summary(status)

    def _run_sharded(self, *, resume: bool = False) -> dict[str, Any]:
        """Run 2-stage subsystem-clustered parallel monolithic execution."""
        if resume:
            loaded = self._load_checkpoint()
            if loaded is not None and self.dispatcher.finished:
                self._close_dispatcher(self.dispatcher)
                return self._result_summary("finished")

        boot_model = self.bootstrap_model or self.model
        bootstrap_discovery_only = bool(self.bootstrap_model and self.bootstrap_model != self.model)
        self._active_model = boot_model
        self._handoff_phase = "single"
        self._epoch_advancements = 0
        boot_max_turns = min(self.max_turns, self.bootstrap_turns, max(4, self.max_turns // 3))
        boot_epoch_state: dict[str, Any] = {"turn_start": 0, "summary_text": "", "advancements": 0}
        boot_usage: dict[str, int] = _new_usage_dict()
        boot_calls = [0]

        def _build_sharding_summary(
            *,
            boot_turns: int,
            boot_findings_count: int,
            fallback_to_monolithic: bool,
            fallback_reason: str | None = None,
            shards: list[dict[str, Any]] | None = None,
            stage3_synthesis: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            summary: dict[str, Any] = {
                "bootstrap_model": boot_model,
                "shard_model": self.model,
                "cache_token_weight": round(self.cache_token_weight, 4),
                "bootstrap_discovery_only": bootstrap_discovery_only,
                "bootstrap_turns": boot_turns,
                "bootstrap_calls": boot_calls[0],
                "bootstrap_tokens": boot_usage["total_tokens"],
                "bootstrap_effective_tokens": effective_tokens_from_usage(boot_usage, self.cache_token_weight),
                "bootstrap_cached_tokens": boot_usage["cached_prompt_tokens"],
                "bootstrap_uncached_tokens": boot_usage["uncached_prompt_tokens"],
                "bootstrap_reasoning_tokens": boot_usage["reasoning_tokens"],
                "bootstrap_epoch_advancements": int(boot_epoch_state.get("advancements", 0)),
                "bootstrap_findings": boot_findings_count,
                "fallback_to_monolithic": fallback_to_monolithic,
                "shards": shards or [],
            }
            if fallback_reason is not None:
                summary["fallback_reason"] = fallback_reason
            if stage3_synthesis is not None:
                summary["stage3_synthesis"] = stage3_synthesis
            return summary

        base_sys_prompt = build_system_prompt(
            base_url=self.http.base_url,
            allowed_methods=sorted(self.http.allowed_methods),
            actor_summaries=self.http.actors.summaries(),
            discovery_hints=self.discovery_hints,
            http_budget=self.http.budget.limit,
        )
        if bootstrap_discovery_only:
            init_prompt = (
                "Stage 1 Surface & Session Discovery (discovery-only bootstrap). "
                "Maximize surface coverage across the authorized target: crawl all initial discovery entry points, "
                "inspect HTML/JS/OpenAPI responses with `extract_surface`, execute any sign-up/login flows to "
                "populate live multi-actor sessions, and discover concrete object IDs, query/form parameters, and "
                "write endpoints. Do NOT attempt vulnerability claims or call `record_finding`; "
                "call `finish` once surface discovery is solid so Stage 2 shards can perform deep verification."
                + self._state_banner(
                    1,
                    max_turns_override=boot_max_turns,
                    allow_coverage_gate=False,
                )
            )
            boot_excluded_tools: frozenset[str] | None = frozenset({"record_finding"})
            boot_allow_coverage_gate = False
            boot_allow_discovery_gate = True
        else:
            init_prompt = (
                "Begin the security investigation of the authorized target. "
                "Start by discovering the surface using the initial discovery entry points, "
                "inspecting extracted routes/forms/JS/OpenAPI schemas, executing any sign-up/login flows, "
                "and systematically testing authentication, authorization, tenant isolation, and input validation. "
                + self._state_banner(1, max_turns_override=boot_max_turns)
            )
            boot_excluded_tools = None
            boot_allow_coverage_gate = True
            boot_allow_discovery_gate = False

        boot_messages: list[dict[str, Any]] = [
            {"role": "system", "content": base_sys_prompt},
            {"role": "user", "content": init_prompt},
        ]

        try:
            self.dispatcher.bootstrap_stage1_virgin_guard = True
            try:
                boot_status, boot_last_turn, boot_messages = self._execute_monolithic_loop(
                    dispatcher=self.dispatcher,
                    messages=boot_messages,
                    start_turn=1,
                    max_turns=boot_max_turns,
                    epoch_state=boot_epoch_state,
                    model_name=boot_model,
                    allow_coverage_gate=boot_allow_coverage_gate,
                    allow_discovery_gate=boot_allow_discovery_gate,
                    disable_gate_last_n_turns=2 if (boot_allow_coverage_gate or boot_allow_discovery_gate) else 0,
                    checkpoint_fn=lambda t, st, msgs: self._save_checkpoint(turn=t, status=st, messages=msgs),
                    usage_sink=boot_usage,
                    calls_sink=boot_calls,
                    excluded_tools=boot_excluded_tools,
                )
            finally:
                self.dispatcher.bootstrap_stage1_virgin_guard = False
            self.dispatcher.discovery_finish_gate = False
            boot_findings_snap = copy.deepcopy(self.dispatcher.findings)

            if (
                boot_status in {"budget_exhausted", "service_degraded"}
                or self.budget.remaining_seconds() <= 5
                or self.budget.available("tokens") < 2500
                or (self.http.budget.limit - self.http.budget.used) <= 0
            ):
                self._sharding_summary = _build_sharding_summary(
                    boot_turns=boot_last_turn,
                    boot_findings_count=len(boot_findings_snap),
                    fallback_to_monolithic=False,
                    shards=[],
                )
                final_status = boot_status if boot_status != "running" else "budget_exhausted"
                return self._result_summary(final_status)

            clusters = cluster_discovered_surface(
                self.dispatcher.surface_tracker,
                max_shards=self.max_shards,
            )
            if len(clusters) <= 1 or self.budget.available("tokens") < 40_000:
                fallback_reason = "single_cluster" if len(clusters) <= 1 else "low_remaining_tokens"
                can_continue = boot_last_turn < self.max_turns and (
                    boot_status in {"max_turns_reached", "finished", "stopped_no_tool_calls"}
                    if bootstrap_discovery_only
                    else boot_status == "max_turns_reached"
                )
                if can_continue:
                    self.dispatcher.finished = False
                    self.dispatcher.finish_rejections = 0
                    self.dispatcher.finish_summary = ""
                    self._active_model = self.model
                    if bootstrap_discovery_only:
                        cont_epoch_state: dict[str, Any] = {
                            "turn_start": 0,
                            "summary_text": "",
                            "advancements": 0,
                        }
                        cont_sys_prompt = build_system_prompt(
                            base_url=self.http.base_url,
                            allowed_methods=sorted(self.http.allowed_methods),
                            actor_summaries=self.http.actors.summaries(),
                            discovery_hints=self.discovery_hints,
                            http_budget=self.http.budget.limit,
                        )
                        frontier_banner = self.dispatcher.surface_tracker.format_frontier_banner(max_chars=2400)
                        cont_user_prompt = (
                            "Stage 1 discovery is complete. Continue the security investigation using the "
                            "discovered surface frontier and live actor sessions below. Systematically verify "
                            "authentication, authorization, tenant isolation, write endpoints, and input validation, "
                            "and call `record_finding` for every confirmed issue.\n\n"
                            f"[LIVE ACTORS]\n{json.dumps(self.http.actors.summaries(), ensure_ascii=False)}\n"
                            f"{frontier_banner}"
                            + self._state_banner(
                                boot_last_turn + 1,
                                dispatcher=self.dispatcher,
                                max_turns_override=self.max_turns,
                                allow_coverage_gate=True,
                            )
                        )
                        cont_messages: list[dict[str, Any]] = [
                            {"role": "system", "content": cont_sys_prompt},
                            {"role": "user", "content": cont_user_prompt},
                        ]
                    else:
                        cont_epoch_state = boot_epoch_state
                        cont_messages = boot_messages

                    cont_status, _, _ = self._execute_monolithic_loop(
                        dispatcher=self.dispatcher,
                        messages=cont_messages,
                        start_turn=boot_last_turn + 1,
                        max_turns=self.max_turns,
                        epoch_state=cont_epoch_state,
                        model_name=self.model,
                        allow_coverage_gate=True,
                        checkpoint_fn=lambda t, st, msgs: self._save_checkpoint(turn=t, status=st, messages=msgs),
                        excluded_tools=None,
                    )
                    self._sharding_summary = _build_sharding_summary(
                        boot_turns=boot_last_turn,
                        boot_findings_count=len(boot_findings_snap),
                        fallback_to_monolithic=True,
                        fallback_reason=fallback_reason,
                        shards=[],
                    )
                    return self._result_summary(cont_status)

                self._sharding_summary = _build_sharding_summary(
                    boot_turns=boot_last_turn,
                    boot_findings_count=len(boot_findings_snap),
                    fallback_to_monolithic=True,
                    fallback_reason=fallback_reason,
                    shards=[],
                )
                return self._result_summary(boot_status)

            # Stage 2: Parallel monolithic subsystem shards
            self._active_model = self.model
            rem_http_after_boot = self.http.budget.limit - self.http.budget.used
            rem_tok_after_boot = self.budget.available("tokens")
            rem_tokens = rem_tok_after_boot
            num_shards = len(clusters)
            reserve_for_stage3 = bool(
                self.enable_cross_shard_synthesis
                and len(clusters) >= 2
                and rem_http_after_boot >= 40
                and rem_tok_after_boot >= 45_000
            )
            stage3_http_reserve = (
                min(30, max(12, int(rem_http_after_boot * 0.15)))
                if reserve_for_stage3
                else 0
            )
            if self.shard_token_quota > 0:
                eff_shard_token_quota = self.shard_token_quota
            else:
                token_share = 0.85 if stage3_http_reserve > 0 else 0.90
                eff_shard_token_quota = max(25_000, int((rem_tokens * token_share) / num_shards))
            bootstrap_surface_snap = copy.deepcopy(self.dispatcher.surface_tracker.to_dict())
            shard_base_sys_prompt = build_system_prompt(
                base_url=self.http.base_url,
                allowed_methods=sorted(self.http.allowed_methods),
                actor_summaries=self.http.actors.summaries(),
                discovery_hints=self.discovery_hints,
                http_budget=self.http.budget.limit,
            )

            def _run_shard_worker(cluster: SubsystemCluster) -> dict[str, Any]:
                shard_dir = self.root_dir / "shards" / cluster.shard_id
                shard_dir.mkdir(parents=True, exist_ok=True)
                shared_oob = (
                    self._oob_server
                    if self._oob_server is not None
                    else getattr(self.dispatcher, "_oob_server", None)
                )
                shard_dispatcher = ToolDispatcher(
                    http_client=self.http,
                    receipt_store=self.receipts,
                    root_dir=shard_dir,
                    bsag=None,
                    oracle=self.oracle,
                    telemetry=self.telemetry,
                    oob_server=shared_oob,
                    http_reserve_floor=stage3_http_reserve,
                )
                try:
                    shard_dispatcher.surface_tracker.load_dict(copy.deepcopy(bootstrap_surface_snap))
                    shard_dispatcher.coverage_gate_enabled = False
                    shard_dispatcher.discovery_finish_gate = False
                    shard_dispatcher.set_active_context(worker_id=cluster.shard_id, category=cluster.name)

                    shard_epoch_state: dict[str, Any] = {"turn_start": 0, "summary_text": "", "advancements": 0}
                    shard_usage: dict[str, int] = _new_usage_dict()
                    shard_calls = [0]
                    init_banner = self._state_banner(
                        1,
                        dispatcher=shard_dispatcher,
                        max_turns_override=self.shard_turns,
                        shard_cluster=cluster,
                        allow_coverage_gate=False,
                        shard_token_quota=eff_shard_token_quota,
                        shard_tokens_used=0,
                    )
                    s_sys, s_usr = build_shard_prompts(
                        cluster,
                        base_system_prompt=shard_base_sys_prompt,
                        bootstrap_findings=boot_findings_snap,
                        receipts=self.receipts,
                        state_banner=init_banner,
                    )
                    shard_messages: list[dict[str, Any]] = [
                        {"role": "system", "content": s_sys},
                        {"role": "user", "content": s_usr},
                    ]

                    def _shard_ckpt(t: int, st: str, _msgs: list[dict[str, Any]]) -> None:
                        _atomic_write_json(
                            shard_dir / "checkpoint.json",
                            {
                                "schema": "agentic-shard-checkpoint/1",
                                "shard_id": cluster.shard_id,
                                "families": cluster.families,
                                "turn": t,
                                "status": st,
                                "findings": shard_dispatcher.findings,
                            },
                        )

                    try:
                        s_status, _, _ = self._execute_monolithic_loop(
                            dispatcher=shard_dispatcher,
                            messages=shard_messages,
                            start_turn=1,
                            max_turns=self.shard_turns,
                            epoch_state=shard_epoch_state,
                            model_name=self.model,
                            allow_coverage_gate=False,
                            allow_discovery_gate=False,
                            checkpoint_fn=_shard_ckpt,
                            shard_cluster=cluster,
                            usage_sink=shard_usage,
                            calls_sink=shard_calls,
                            shard_token_quota=eff_shard_token_quota,
                            excluded_tools=None,
                        )
                    except BudgetError as exc:
                        s_status = self._classify_budget_error(exc, is_shard=True)
                    except Exception as exc:
                        s_status = f"error:{type(exc).__name__}"

                    return {
                        "shard_id": cluster.shard_id,
                        "name": cluster.name,
                        "families": list(cluster.families),
                        "calls": shard_calls[0],
                        "tokens": shard_usage["total_tokens"],
                        "effective_tokens": effective_tokens_from_usage(shard_usage, self.cache_token_weight),
                        "cached_tokens": shard_usage["cached_prompt_tokens"],
                        "uncached_tokens": shard_usage["uncached_prompt_tokens"],
                        "reasoning_tokens": shard_usage["reasoning_tokens"],
                        "epoch_advancements": int(shard_epoch_state.get("advancements", 0)),
                        "shard_token_quota": eff_shard_token_quota,
                        "findings": list(shard_dispatcher.findings),
                        "status": s_status,
                        "surface_tracker": shard_dispatcher.surface_tracker,
                        "finish_summary": shard_dispatcher.finish_summary,
                        "untested_areas": list(shard_dispatcher.untested_areas),
                    }
                finally:
                    self._close_dispatcher(shard_dispatcher)

            shard_results: list[dict[str, Any]] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(clusters)) as pool:
                futures = [pool.submit(_run_shard_worker, cluster) for cluster in clusters]
                for fut in futures:
                    shard_results.append(fut.result())

            # Merge surface trackers and findings from bootstrap + all shards.
            merged_findings: list[dict[str, Any]] = list(boot_findings_snap)
            shard_summaries_text: list[str] = []
            merged_untested: list[str] = list(self.dispatcher.untested_areas)
            for sres in shard_results:
                self._merge_surface_trackers(self.dispatcher.surface_tracker, sres["surface_tracker"])
                merged_findings.extend(sres["findings"])
                if sres["finish_summary"]:
                    shard_summaries_text.append(f"[{sres['shard_id']}] {sres['finish_summary']}")
                for area in sres["untested_areas"]:
                    if area not in merged_untested:
                        merged_untested.append(area)

            for row in self.http.actors.summaries():
                self.dispatcher.surface_tracker.actors[row["alias"]] = {
                    "alias": row["alias"],
                    "role": str(row.get("role") or "").strip().lower(),
                    "tenant": str(row.get("tenant") or "").strip().lower(),
                }

            actor_meta_map = {
                row["alias"]: {
                    "alias": row["alias"],
                    "role": str(row.get("role") or "").lower(),
                    "tenant": str(row.get("tenant") or "").lower(),
                }
                for row in self.http.actors.summaries()
            }
            self.dispatcher.findings = canonicalize_and_deduplicate_findings(
                merged_findings,
                actor_meta_map=actor_meta_map,
                receipt_store=self.receipts,
            )
            self.dispatcher._save_findings()

            if shard_summaries_text:
                prefix = (self.dispatcher.finish_summary + " | ") if self.dispatcher.finish_summary else ""
                self.dispatcher.finish_summary = prefix + " | ".join(shard_summaries_text)
            self.dispatcher.untested_areas = merged_untested

            shard_statuses = [r["status"] for r in shard_results]
            if all(st == "finished" for st in shard_statuses):
                overall_status = "finished"
            elif any(st == "finished" for st in shard_statuses):
                overall_status = "finished"
            elif all(st == "budget_exhausted" for st in shard_statuses):
                overall_status = "budget_exhausted"
            else:
                overall_status = shard_statuses[0] if shard_statuses else "finished"

            synth_ctx = collect_cross_shard_synthesis_context(
                shard_results=shard_results,
                findings=self.dispatcher.findings,
                receipts=self.receipts,
                surface_tracker=self.dispatcher.surface_tracker,
                actor_summaries=self.http.actors.summaries(),
            )
            stage3_summary: dict[str, Any] | None = None
            if (
                self.enable_cross_shard_synthesis
                and synth_ctx.get("should_trigger")
                and (self.http.budget.limit - self.http.budget.used) >= 6
                and self.budget.available("tokens") >= 18_000
                and self.budget.remaining_seconds() > 15
            ):
                stage3_dir = self.root_dir / "shards" / "stage3-synthesis"
                stage3_dir.mkdir(parents=True, exist_ok=True)
                shared_oob = (
                    self._oob_server
                    if self._oob_server is not None
                    else getattr(self.dispatcher, "_oob_server", None)
                )
                stage3_dispatcher = ToolDispatcher(
                    http_client=self.http,
                    receipt_store=self.receipts,
                    root_dir=stage3_dir,
                    bsag=None,
                    oracle=self.oracle,
                    telemetry=self.telemetry,
                    oob_server=shared_oob,
                    bootstrap_stage1_virgin_guard=False,
                    http_reserve_floor=0,
                )
                try:
                    stage3_dispatcher.surface_tracker.load_dict(
                        copy.deepcopy(self.dispatcher.surface_tracker.to_dict())
                    )
                    stage3_dispatcher.coverage_gate_enabled = False
                    stage3_dispatcher.discovery_finish_gate = False
                    stage3_dispatcher.bootstrap_stage1_virgin_guard = False
                    stage3_dispatcher.http_reserve_floor = 0
                    stage3_dispatcher.set_active_context(
                        worker_id="stage3-synthesis",
                        category="cross_shard",
                    )

                    s3_max_turns = min(12, max(6, self.max_turns // 3))
                    s3_epoch_state: dict[str, Any] = {
                        "turn_start": 0,
                        "summary_text": "",
                        "advancements": 0,
                    }
                    s3_usage: dict[str, int] = _new_usage_dict()
                    s3_calls = [0]
                    s3_http_rem = max(0, self.http.budget.limit - self.http.budget.used)
                    s3_banner = self._state_banner(
                        1,
                        dispatcher=stage3_dispatcher,
                        max_turns_override=s3_max_turns,
                        allow_coverage_gate=False,
                    )
                    s3_sys, s3_usr = build_cross_shard_synthesis_prompts(
                        base_system_prompt=shard_base_sys_prompt,
                        synthesis_context=synth_ctx,
                        actor_summaries=self.http.actors.summaries(),
                        http_budget_remaining=s3_http_rem,
                        state_banner=s3_banner,
                    )
                    s3_messages: list[dict[str, Any]] = [
                        {"role": "system", "content": s3_sys},
                        {"role": "user", "content": s3_usr},
                    ]

                    def _stage3_ckpt(t: int, st: str, _msgs: list[dict[str, Any]]) -> None:
                        _atomic_write_json(
                            stage3_dir / "checkpoint.json",
                            {
                                "schema": "agentic-shard-checkpoint/1",
                                "shard_id": "stage3-synthesis",
                                "families": ["cross_shard"],
                                "turn": t,
                                "status": st,
                                "findings": stage3_dispatcher.findings,
                            },
                        )

                    try:
                        s3_status, _, _ = self._execute_monolithic_loop(
                            dispatcher=stage3_dispatcher,
                            messages=s3_messages,
                            start_turn=1,
                            max_turns=s3_max_turns,
                            epoch_state=s3_epoch_state,
                            model_name=self.model,
                            allow_coverage_gate=False,
                            allow_discovery_gate=False,
                            checkpoint_fn=_stage3_ckpt,
                            usage_sink=s3_usage,
                            calls_sink=s3_calls,
                            excluded_tools=None,
                        )
                    except BudgetError as exc:
                        s3_status = self._classify_budget_error(exc, is_shard=True)
                    except Exception as exc:
                        s3_status = f"error:{type(exc).__name__}"

                    self._merge_surface_trackers(
                        self.dispatcher.surface_tracker,
                        stage3_dispatcher.surface_tracker,
                    )
                    for row in self.http.actors.summaries():
                        self.dispatcher.surface_tracker.actors[row["alias"]] = {
                            "alias": row["alias"],
                            "role": str(row.get("role") or "").strip().lower(),
                            "tenant": str(row.get("tenant") or "").strip().lower(),
                        }
                    s3_actor_meta = {
                        row["alias"]: {
                            "alias": row["alias"],
                            "role": str(row.get("role") or "").lower(),
                            "tenant": str(row.get("tenant") or "").lower(),
                        }
                        for row in self.http.actors.summaries()
                    }
                    s3_findings_count = len(stage3_dispatcher.findings)
                    if stage3_dispatcher.findings:
                        merged_after_s3 = list(self.dispatcher.findings) + list(stage3_dispatcher.findings)
                        self.dispatcher.findings = canonicalize_and_deduplicate_findings(
                            merged_after_s3,
                            actor_meta_map=s3_actor_meta,
                            receipt_store=self.receipts,
                        )
                        self.dispatcher._save_findings()
                    if stage3_dispatcher.finish_summary:
                        prefix = (
                            (self.dispatcher.finish_summary + " | ")
                            if self.dispatcher.finish_summary
                            else ""
                        )
                        self.dispatcher.finish_summary = (
                            prefix + f"[stage3-synthesis] {stage3_dispatcher.finish_summary}"
                        )
                    for area in stage3_dispatcher.untested_areas:
                        if area not in self.dispatcher.untested_areas:
                            self.dispatcher.untested_areas.append(area)
                    if overall_status != "finished" and s3_status == "finished":
                        overall_status = "finished"
                    stage3_summary = {
                        "triggered": True,
                        "status": s3_status,
                        "calls": s3_calls[0],
                        "tokens": s3_usage["total_tokens"],
                        "effective_tokens": effective_tokens_from_usage(s3_usage, self.cache_token_weight),
                        "cached_tokens": s3_usage["cached_prompt_tokens"],
                        "uncached_tokens": s3_usage["uncached_prompt_tokens"],
                        "reasoning_tokens": s3_usage["reasoning_tokens"],
                        "findings": s3_findings_count,
                    }
                finally:
                    self._close_dispatcher(stage3_dispatcher)

            self.dispatcher.finished = overall_status == "finished"

            self._sharding_summary = _build_sharding_summary(
                boot_turns=boot_last_turn,
                boot_findings_count=len(boot_findings_snap),
                fallback_to_monolithic=False,
                shards=[
                    {
                        "shard_id": r["shard_id"],
                        "name": r["name"],
                        "families": r["families"],
                        "calls": r["calls"],
                        "tokens": r["tokens"],
                        "effective_tokens": r["effective_tokens"],
                        "cached_tokens": r["cached_tokens"],
                        "uncached_tokens": r["uncached_tokens"],
                        "reasoning_tokens": r["reasoning_tokens"],
                        "epoch_advancements": r["epoch_advancements"],
                        "shard_token_quota": r["shard_token_quota"],
                        "findings": len(r["findings"]),
                        "status": r["status"],
                    }
                    for r in shard_results
                ],
                stage3_synthesis=stage3_summary,
            )
            self._save_checkpoint(turn=boot_last_turn, status=overall_status, messages=[])
            return self._result_summary(overall_status)
        finally:
            self._close_dispatcher(self.dispatcher)
            if self.telemetry is not None or self.bsag is not None:
                self.write_metrics()

    def _result_summary(self, status: str) -> dict[str, Any]:
        with self._stats_lock:
            usage_out: dict[str, Any] = dict(self.token_usage)
            eff_tokens = effective_tokens_from_usage(self.token_usage, self.cache_token_weight)
            epoch_advancements = self._epoch_advancements
        prompt_tok = int(usage_out.get("prompt_tokens", 0))
        cached_tok = int(usage_out.get("cached_prompt_tokens", 0))
        usage_out["cache_hit_rate"] = round(cached_tok / prompt_tok, 4) if prompt_tok > 0 else 0.0
        usage_out["effective_tokens"] = eff_tokens
        usage_out["cache_token_weight"] = round(self.cache_token_weight, 4)
        out: dict[str, Any] = {
            "status": status,
            "execution_mode": self.execution_mode,
            "ablation": self._ablation_config(),
            "finished": self.dispatcher.finished,
            "finish_summary": self.dispatcher.finish_summary,
            "untested_areas": self.dispatcher.untested_areas,
            "findings_count": len(self.dispatcher.findings),
            "findings_path": str(self.dispatcher.findings_path),
            "receipts_count": self.receipts.count(),
            "http_requests_used": self.http.budget.used,
            "http_requests_limit": self.http.budget.limit,
            "llm_calls": self.transport.calls,
            "token_usage": usage_out,
            "epoch_advancements": epoch_advancements,
            "checkpoint_path": str(self.checkpoint_path),
        }
        if self._handoff_summary is not None:
            out["handoff_summary"] = dict(self._handoff_summary)
        if self._sharding_summary is not None:
            out["sharding_summary"] = copy.deepcopy(self._sharding_summary)
        if self.bsag is not None:
            out["bsag_summary"] = self.bsag.metrics_snapshot()
        if self._last_metrics_paths is not None:
            out["process_metrics_json"] = str(self._last_metrics_paths[0])
            out["process_metrics_md"] = str(self._last_metrics_paths[1])
        return out
