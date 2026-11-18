"""Reusable host MCP tool executor, workspace confinement, and HostBroker.

Composes MeteredProviderTransport and HostToolExecutor with narrow interfaces,
without native client configuration, local client tools, or bridge sockets.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import threading

from full_agent_budget import BudgetError, compact_json_text, compact_tools, provider_json
from full_agent_provider import (
    MeteredProviderTransport,
    SessionGate,
    TOOL_DESCRIPTION_LIMIT,
    dump,
)

# Reviewed entry points only. No arbitrary shell, raw database, credentials,
# external scanners or MCP-internal paid model calls cross this boundary.
CATALOG = {
    "hunter": {"run_web_loop", "fuzz_attack_surface", "coverage_report", "predict_vulnerabilities"},
    "validator": {
        "validate_sqli",
        "validate_ssti",
        "validate_path_traversal",
        "validate_xss_reflection",
        "validate_open_redirect",
        "validate_business_logic",
        "validate_auth_bypass",
        "validate_idor",
        "session_vault_check",
    },
    "browser": {
        "browser_extract_links",
        "browser_capture_requests",
        "browser_runtime_observe",
        "browser_dom_xss_probe",
    },
    "kali-tools": {
        "curl_request",
        "crawl_web_surface",
        "compose_js_routes",
        "ledger_attempt_add",
        "ledger_attempt_add_batch",
        "ledger_coverage",
        "ledger_prepare_handoff",
        "ledger_checkpoint",
    },
    "reasoning": {"recall_lessons", "record_lesson"},
}


class HostToolExecutor:
    """Bounded, policy-gated and HTTP-budgeted MCP tool execution."""

    def __init__(
        self,
        *,
        budget,
        engine,
        executor,
        workdir,
        private,
        session_gate=None,
        tasks_provider=None,
        runtime_policy_provider=None,
    ):
        self.budget = budget
        self.engine = engine
        self.executor = executor
        self.workdir = Path(workdir).resolve()
        self.private = Path(private)
        self.session_gate = session_gate or SessionGate()
        self._tasks_provider = tasks_provider or (lambda: None)
        self._runtime_policy_provider = runtime_policy_provider or (lambda: None)
        self.lock = threading.RLock()
        self.catalog = {}
        self.tools = []
        self.loops = []
        self.checkpoints = []
        self.handoffs = {}

    def terminate(self):
        self.executor.terminate()
        # A call may have been admitted just before stop. Wait for its short
        # cleanup, then terminate again to cover a concurrent spawn.
        if self.lock.acquire(timeout=5):
            try:
                self.executor.terminate()
            finally:
                self.lock.release()

    def load_catalog(self, home):
        from campaign_worker import _load_server_module

        for group, allowed in CATALOG.items():
            mod = _load_server_module("mcp-" + group, home)
            rows = asyncio.run(mod.mcp.list_tools())
            # Host tools emit text content, not FastMCP structuredContent.
            self.catalog[group] = compact_tools(
                [
                    row.model_dump(mode="json", exclude_none=True, exclude={"outputSchema"})
                    for row in rows
                    if row.name in allowed
                ],
                description_limit=TOOL_DESCRIPTION_LIMIT,
            )
            found = {row["name"] for row in self.catalog[group]}
            if found != allowed:
                raise ValueError("MCP catalog mismatch: " + group + " " + str(sorted(allowed - found)))

    def handoff_file_hash(self, path):
        raw = Path(path)
        resolved = raw.resolve(strict=True)
        if (
            raw.is_symlink()
            or resolved.parent != self.workdir
            or not resolved.is_file()
            or resolved.stat().st_size > 1024 * 1024
        ):
            raise ValueError("handoff file must be a bounded regular workdir file")
        return hashlib.sha256(resolved.read_bytes()).hexdigest()

    def remember_handoff(self, args, result, artifact, summary_hash):
        """Record only output from a successful host MCP execution, not prose."""
        tasks = self._tasks_provider()
        if tasks is None or not isinstance(result, dict) or result.get("ok") is not True:
            return
        source = tasks.active_spec
        if source is None or source.phase not in {"enum", "seed"} or args.get("target") != source.target:
            raise ValueError("handoff producer does not match the active discovery task")
        summary = tasks.summary_path(source)
        supplied = self.workdir / args.get("summary_file", "summaries/enum-2.json")
        if supplied.resolve() != summary:
            raise ValueError("handoff must consume the active discovery summary")
        if hashlib.sha256(summary.read_bytes()).hexdigest() != summary_hash:
            raise ValueError("discovery summary changed during handoff preparation")
        pool = self.workdir / "object-pool.json"
        pending = {}
        for label, name in result.get("handoffs", {}).items():
            path = self.workdir / ("handoff-" + label + ".json")
            if str(path) != name or path.parent != self.workdir:
                raise ValueError("unexpected host handoff path")
            pending[label] = {
                "producer_spec_id": source.id,
                "target": source.target,
                "summary": str(summary),
                "summary_sha256": summary_hash,
                "producer_artifact": str(artifact),
                "producer_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "files": {
                    str(pool): self.handoff_file_hash(pool),
                    str(path): self.handoff_file_hash(path),
                },
            }
        self.handoffs.update(pending)
        dump(self.private / "handoff-receipts.json", self.handoffs)

    def confine(self, args):
        # Ledger calls read solver-authored files on the host. Require their
        # standard confinement checks, and disallow links out of the mount.
        for name in ("workdir", "artifact", "summary_file", "spec_file"):
            value = args.get(name)
            if value:
                if not isinstance(value, str):
                    raise ValueError("invalid artifact path")
                path = (self.workdir / value).resolve()
                if path != self.workdir and self.workdir not in path.parents:
                    raise ValueError("artifact path escapes solver workspace")

    def call_tool(self, group, name, args, *, origin="solver"):
        if name not in CATALOG.get(group, set()) or not isinstance(args, dict):
            raise ValueError("tool outside benchmark catalog")
        full = group + "_" + name
        with self.lock:  # One active MCP call; nested browser requests share its allowance.
            self.session_gate.require_open()
            tasks = self._tasks_provider()
            runtime_policy = self._runtime_policy_provider()
            if (
                origin == "solver"
                and tasks is not None
                and tasks.active_spec is not None
                and full not in tasks.active_spec.tools
            ):
                raise ValueError("tool outside active TaskSpec")
            if origin == "solver" and runtime_policy is not None and tasks is not None and tasks.active_spec is not None:
                try:
                    runtime_policy.check_tool(tasks.active_spec, full)
                except BudgetError as exc:
                    self.session_gate.stop_reason = str(exc)
                    raise
            self.confine(args)
            summary_hash = None
            if full == "kali-tools_ledger_prepare_handoff" and tasks is not None:
                summary_path = self.workdir / args.get("summary_file", "summaries/enum-2.json")
                tasks.normalize_summary_file(summary_path)
                summary_hash = hashlib.sha256(summary_path.read_bytes()).hexdigest()
                dump(self.private / "summary-normalizations.json", tasks.normalizations)
            from wire_budget import network_required, require_accounted_tool

            require_accounted_tool(full, args, self.engine)
            network = network_required(full, args, self.engine)
            # Every supported network adapter rechecks the actual request at
            # egress. This outer shape/scope/grant check must not consume its
            # stuck/rate counters before that same request is sent.
            decision = (
                self.engine.validate_tool_invocation(full, args, _policy_preflight=True)
                if network
                else self.engine.validate_tool_invocation(full, args)
            )
            if not decision["allowed"]:
                raise ValueError("policy denied: " + decision.get("reason", ""))
            reservation = self.budget.available("http") if network else 0
            if network and reservation == 0:
                raise BudgetError("http budget exhausted")
            ticket = self.budget.reserve("http", reservation)
            dump(self.private / "budget.json", self.budget.snapshot())
            self.executor.timeout_seconds = min(900, self.budget.remaining_seconds())
            result, error = None, None
            artifact = self.private / f"tool-{len(self.tools):04d}.json"
            spec_id = tasks.active_spec.id if origin == "solver" and tasks is not None and tasks.active_spec else None
            try:
                self.session_gate.require_open()
                result = self.executor(
                    {
                        "tool_name": full,
                        "args_json": json.dumps(args),
                        "request_cost": reservation,
                        "reserved_request_cost": reservation,
                    }
                )
            except BaseException as exc:
                error = type(exc).__name__
                raise
            finally:
                if runtime_policy is not None and spec_id is not None and tasks is not None:
                    runtime_policy.record_result(tasks.active_spec, full, result, error)
                # LocalMCPExecutor validates the random invocation ID and wire
                # reservation. An interrupted child is charged its full allowance.
                try:
                    self.budget.settle(
                        ticket,
                        result.get("actual_request_cost") if isinstance(result, dict) else None,
                        tool=full,
                        origin=origin,
                    )
                finally:
                    dump(self.private / "budget.json", self.budget.snapshot())
                    dump(
                        artifact,
                        {
                            "tool": full,
                            "arguments": args,
                            "execution": result,
                            "origin": origin,
                            "error": error,
                            "task_spec_id": spec_id,
                            "input_summary_sha256": summary_hash,
                        },
                    )
                    self.tools.append(
                        {"tool": full, "artifact": str(artifact), "origin": origin, "task_spec_id": spec_id}
                    )
            raw = result["result"].get("output")
            try:
                parsed = json.loads(raw) if isinstance(raw, str) else raw
            except ValueError:
                parsed = None
            if full == "hunter_run_web_loop" and isinstance(parsed, dict) and parsed.get("run_id"):
                self.loops.append(parsed)
            if full == "kali-tools_ledger_prepare_handoff" and not result.get("execution_failed"):
                self.remember_handoff(args, parsed, artifact, summary_hash)
            if full == "kali-tools_ledger_checkpoint":
                self.checkpoints.append({"args": args, "output": parsed})
            return {
                "content": [
                    {
                        "type": "text",
                        "text": compact_json_text(raw) if isinstance(raw, str) else provider_json(raw).decode("utf-8"),
                    }
                ],
                "isError": bool(result.get("execution_failed")),
            }


class HostBroker:
    """Shared host runtime composing MeteredProviderTransport and HostToolExecutor."""

    def __init__(
        self,
        *,
        budget,
        engine,
        executor,
        workdir,
        private,
        provider,
        models,
        api_key,
        api_key_header="Authorization",
        tasks=None,
    ):
        self._budget = budget
        self._engine = engine
        self._workdir = Path(workdir).resolve()
        self._private = Path(private)
        self.tasks = tasks
        self.runtime_policy = None
        self.task_finalization = None
        self.session_gate = SessionGate()
        self.provider_transport = MeteredProviderTransport(
            budget=budget,
            private=self._private,
            provider=provider,
            models=models,
            api_key=api_key,
            api_key_header=api_key_header,
            session_gate=self.session_gate,
        )
        self.tool_executor = HostToolExecutor(
            budget=budget,
            engine=engine,
            executor=executor,
            workdir=self._workdir,
            private=self._private,
            session_gate=self.session_gate,
            tasks_provider=lambda: self.tasks,
            runtime_policy_provider=lambda: self.runtime_policy,
        )

    # Narrow state delegation so callers/tests can configure or inspect fields
    # directly on the broker without duplicating transport or executor logic.
    @property
    def budget(self):
        return self._budget

    @budget.setter
    def budget(self, value):
        self._budget = value
        self.provider_transport.budget = value
        self.tool_executor.budget = value

    @property
    def engine(self):
        return self._engine

    @engine.setter
    def engine(self, value):
        self._engine = value
        self.tool_executor.engine = value

    @property
    def workdir(self):
        return self._workdir

    @workdir.setter
    def workdir(self, value):
        resolved = Path(value).resolve()
        self._workdir = resolved
        self.tool_executor.workdir = resolved

    @property
    def private(self):
        return self._private

    @private.setter
    def private(self, value):
        resolved = Path(value)
        self._private = resolved
        self.provider_transport.private = resolved
        self.tool_executor.private = resolved
    @property
    def closed(self):
        return self.session_gate.closed

    @property
    def stop_reason(self):
        return self.session_gate.stop_reason

    @stop_reason.setter
    def stop_reason(self, value):
        self.session_gate.stop_reason = value

    @property
    def provider(self):
        return self.provider_transport.provider

    @provider.setter
    def provider(self, value):
        self.provider_transport.provider = value

    @property
    def models(self):
        return self.provider_transport.models

    @models.setter
    def models(self, value):
        self.provider_transport.models = set(value)

    @property
    def api_key(self):
        return self.provider_transport.api_key

    @api_key.setter
    def api_key(self, value):
        self.provider_transport.api_key = value

    @property
    def api_key_header(self):
        return self.provider_transport.api_key_header

    @api_key_header.setter
    def api_key_header(self, value):
        self.provider_transport.api_key_header = value

    @property
    def provider_lock(self):
        return self.provider_transport.provider_lock

    @property
    def transport_lock(self):
        return self.provider_transport.transport_lock

    @property
    def upstream(self):
        return self.provider_transport.upstream

    @upstream.setter
    def upstream(self, value):
        self.provider_transport.upstream = value

    @property
    def calls(self):
        return self.provider_transport.calls

    @calls.setter
    def calls(self, value):
        self.provider_transport.calls = value

    @property
    def provider_requests(self):
        return self.provider_transport.provider_requests

    @property
    def provider_responses(self):
        return self.provider_transport.provider_responses

    @property
    def lock(self):
        return self.tool_executor.lock

    @property
    def executor(self):
        return self.tool_executor.executor

    @executor.setter
    def executor(self, value):
        self.tool_executor.executor = value

    @property
    def catalog(self):
        return self.tool_executor.catalog

    @catalog.setter
    def catalog(self, value):
        self.tool_executor.catalog = value

    @property
    def tools(self):
        return self.tool_executor.tools

    @tools.setter
    def tools(self, value):
        self.tool_executor.tools = value

    @property
    def loops(self):
        return self.tool_executor.loops

    @loops.setter
    def loops(self, value):
        self.tool_executor.loops = value

    @property
    def checkpoints(self):
        return self.tool_executor.checkpoints

    @checkpoints.setter
    def checkpoints(self, value):
        self.tool_executor.checkpoints = value

    @property
    def handoffs(self):
        return self.tool_executor.handoffs

    @handoffs.setter
    def handoffs(self, value):
        self.tool_executor.handoffs = value

    def close(self):
        """Stop admission before terminating host tool children and provider IO."""
        self.session_gate.closed.set()
        self.tool_executor.terminate()
        self.provider_transport.close_upstream()

    def _require_open(self):
        self.session_gate.require_open()

    def load_catalog(self, home):
        return self.tool_executor.load_catalog(home)

    def _handoff_file_hash(self, path):
        return self.tool_executor.handoff_file_hash(path)

    def _remember_handoff(self, args, result, artifact, summary_hash):
        return self.tool_executor.remember_handoff(args, result, artifact, summary_hash)

    def _confine(self, args):
        return self.tool_executor.confine(args)

    def call_tool(self, group, name, args, *, origin="solver"):
        return self.tool_executor.call_tool(group, name, args, origin=origin)

    def _check_handoff(self, spec):
        """Enforce host-sealed enum->access handoff integrity and freshness."""
        if spec.phase not in {"access", "authz"}:
            return
        label = spec.vector or spec.phase
        record = self.handoffs.get(label)
        if not record or record["target"] != spec.target:
            raise ValueError("host handoff missing for " + spec.id)
        source = next(s for s in self.tasks.specs if s.id == record["producer_spec_id"])
        summary = self.tasks.summary_path(source)
        if hashlib.sha256(summary.read_bytes()).hexdigest() != record["summary_sha256"]:
            raise ValueError("host handoff stale: discovery summary changed")
        if any(self._handoff_file_hash(path) != digest for path, digest in record["files"].items()):
            raise ValueError("host handoff stale: packet or pool changed")
        from brain import _handoff_gate_error

        error = _handoff_gate_error(spec)
        if error:
            raise ValueError(error)

    def finalize_task(self, reason):
        """Preserve draft bytes and tool receipts after execution stops; no model call."""
        with self.lock:
            if self.task_finalization is not None or self.tasks is None or self.tasks.active_spec is None:
                return self.task_finalization
            spec = self.tasks.active_spec
            try:
                evidence = []
                for row in self.tools:
                    if row.get("task_spec_id") != spec.id or row["origin"] != "solver":
                        continue
                    path = Path(row["artifact"])
                    evidence.append(
                        {
                            "tool": row["tool"],
                            "artifact": str(path),
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        }
                    )
                self.task_finalization = self.tasks.finalize_active(reason, evidence, self.private)
            except (ValueError, OSError) as exc:
                self.task_finalization = {
                    "spec_id": spec.id,
                    "reason": reason,
                    "action": "summary_preserved",
                    "error": type(exc).__name__,
                }
            dump(self.private / "task-finalization.json", self.task_finalization)
            return self.task_finalization

    def project_runtime_context(self, body, spec, info):
        return body, info, None
