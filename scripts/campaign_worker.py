#!/usr/bin/env python3
"""Safe campaign worker runner.

The default CLI runner is dry-run only. Real execution is intentionally an
injectable callback so policy, permit, heartbeat, settlement, and redaction stay
centralized while MCP/tool orchestration can evolve separately.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from fnmatch import fnmatch
import hashlib
import importlib.util
import inspect
import json
import math
import os
import re
import secrets
import signal
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from campaign_runtime import CampaignRuntime
from wire_budget import (campaign_wire_budget, current_budget, network_required, require_accounted_tool,
                         UnsupportedWireAccounting, validate_usage)
from executor_isolation import (
    ExecutorContract,
    ResourceLimits,
    apply_process_resource_limits,
    attach_cgroup,
)


SECRET_KEY_RE = re.compile(r"(?i)(authorization|headers?|cookie|token|secret|password|api[_-]?key|bearer)")
SECRET_VALUE_RE = re.compile(r"(?i)(bearer\s+)[a-z0-9._~+/=-]{8,}")
from runtime_paths import runtime_root
REPO_ROOT = runtime_root()
TOOL_SERVER_PREFIXES = {
    "kali-tools_": "mcp-kali-tools",
    "validator_": "mcp-validator",
    "hunter_": "mcp-hunter",
    "memory-server_": "mcp-memory-server",
    "rag-engine_": "mcp-rag-engine",
    "reasoning_": "mcp-reasoning",
    "telemetry_": "mcp-telemetry",
    "web-advanced_": "mcp-web-advanced",
    "llm-security_": "mcp-llm-security",
    "browser_": "mcp-browser",
    "agent-browse_": "mcp-agent-browse",
    "otp_": "mcp-otp",
    "osint-tools_": "mcp-osint-tools",
    "ad-tools_": "mcp-ad-tools",
    "container-tools_": "mcp-container-tools",
    "ctf-platform_": "mcp-ctf-platform",
}
_SERVER_CACHE: dict[tuple[str, str], Any] = {}
CHILD_RESULT_PREFIX = "__CCO_WORKER_RESULT__:"


class ChildExecutionError(RuntimeError):
    def __init__(self, response):
        self.response = response
        detail = str(response.get("error") or "")[:300]
        super().__init__(f"executor subprocess failed: {response.get('error_type', 'UnknownError')}: {detail}")


class AccountedExecutionError(RuntimeError):
    """A trusted runner failed after measuring its transport attempts."""
    def __init__(self, message, actual_request_cost, result=None):
        super().__init__(message)
        if isinstance(actual_request_cost, bool) or not isinstance(actual_request_cost, int) or actual_request_cost < 0:
            raise ValueError("invalid measured request count")
        self.actual_request_cost = actual_request_cost
        self.result = result or {}
CUSTOM_TASK_FIELDS = {
    "id", "campaign_id", "parent_id", "kind", "tool_name", "args_json",
    "attempts", "max_attempts", "request_cost", "usd_cost_micros", "idempotency_key",
}


def redact(value: Any):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)):
                redacted[key] = "<redacted>"
            else:
                redacted[key] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return SECRET_VALUE_RE.sub(r"\1<redacted>", value)
    return value


def mark_empty_result(result: Any) -> Any:
    if isinstance(result, dict) and not result:
        return {"no_progress": True, "reason": "empty_result"}
    return result


def _hunter_incomplete_result(task: dict, output: dict) -> dict | None:
    """Distinguish a partial LIVE web loop from successful task completion."""
    if task.get("tool_name") != "hunter_run_web_loop":
        return None
    try:
        args = json.loads(task.get("args_json") or "{}")
    except (TypeError, ValueError):
        args = {}
    result = output.get("result") if isinstance(output, dict) else None
    if not isinstance(result, dict) or result.get("mode") != "local_mcp" or not args.get("live"):
        return None
    raw = result.get("output")
    try:
        report = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        report = None
    replan = report.get("replan") if isinstance(report, dict) else None
    if (not isinstance(report, dict) or report.get("mode") != "LIVE" or
            not isinstance(replan, dict) or replan.get("status") not in {
                "blocked", "incomplete", "review_coverage"}):
        return {"reason": "invalid web loop result", "replan": {"status": "invalid", "actions": []}}
    if args.get("gap_ref"):
        gap = report.get("coverage_gap")
        if (not isinstance(gap, dict) or gap.get("fingerprint") != args["gap_ref"]
                or gap.get("status") not in {"confirmed", "tested_clean"}
                or gap.get("coverage_recorded") is not True):
            return {"reason": "coverage dimension remains untested", "replan": replan,
                    "run_id": str(report.get("run_id") or ""),
                    "coverage_gap": {key: gap.get(key) for key in ("fingerprint", "status")} if isinstance(gap, dict) else {}}
    if replan["status"] == "review_coverage" and report.get("ok") is True:
        return None
    return {"reason": "web loop requires replanning", "replan": replan,
            "run_id": str(report.get("run_id") or ""), "artifact": str(report.get("artifact") or "")}


def _is_live_hunter_task(task: dict) -> bool:
    if task.get("tool_name") != "hunter_run_web_loop":
        return False
    try:
        args = json.loads(task.get("args_json") or "{}")
    except (TypeError, ValueError):
        return False
    return isinstance(args, dict) and bool(args.get("live"))


def dry_run_executor(task: dict) -> dict:
    return {
        "result": {
            "executed": False,
            "mode": "dry_run",
            "task_id": task.get("id"),
            "tool_name": task.get("tool_name"),
            "args": redact(json.loads(task.get("args_json") or "{}")),
        },
        "checkpoint": {"phase": "dry_run_complete"},
        "actual_request_cost": 0,
        "actual_usd_cost": 0.0,
    }


def _tool_allowed(tool_name: str) -> bool:
    raw = os.environ.get("CCO_WORKER_ALLOWED_TOOLS", "").strip()
    if not raw:
        return True
    patterns = [part.strip() for part in raw.split(",") if part.strip()]
    return any(fnmatch(tool_name, pattern) for pattern in patterns)


def _resolve_tool(tool_name: str) -> tuple[str, str]:
    for prefix, server_dir in TOOL_SERVER_PREFIXES.items():
        if tool_name.startswith(prefix):
            return server_dir, tool_name[len(prefix):]
    raise ValueError(f"unsupported worker tool: {tool_name}")


def _load_server_module(server_dir: str, cco_home: str | Path | None = None):
    cache_home = str(Path(cco_home).expanduser().resolve()) if cco_home else ""
    if cco_home:
        os.environ["CCO_HOME"] = str(cco_home)
    cache_key = (server_dir, cache_home)
    if cache_key in _SERVER_CACHE:
        return _SERVER_CACHE[cache_key]
    if server_dir == "mcp-memory-server":
        # Kuzu mmaps ~8TB VA at import; under worker RLIMIT_AS this crashes.
        # Default worker children to networkx (SQLite stays system-of-record).
        backend = os.environ.get("CCO_WORKER_GRAPH_BACKEND") or "networkx"
        os.environ["CCO_GRAPH_BACKEND"] = os.environ.get("CCO_GRAPH_BACKEND") or backend
    candidates = (
        REPO_ROOT / "mcp-servers" / server_dir / "server.py",
        Path(sys.prefix) / "share" / "hackagent" / "mcp-servers" / server_dir / "server.py",
    )
    path = next((candidate for candidate in candidates if candidate.exists()), None)
    if path is None:
        raise ValueError(f"MCP server module missing: {server_dir}")
    module_name = "cco_worker_" + re.sub(r"[^a-zA-Z0-9_]", "_", server_dir)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"MCP server module cannot load: {server_dir}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    _SERVER_CACHE[cache_key] = module
    return module


def _invoke_local_mcp_tool(tool_name: str, args: dict, cco_home: str | Path | None = None):
    if not tool_name:
        raise ValueError("task tool_name missing")
    if not _tool_allowed(tool_name):
        raise ValueError(f"worker tool not allowed: {tool_name}")
    if current_budget() is not None:
        from policy_engine import PolicyEngine
        require_accounted_tool(tool_name, args, PolicyEngine(cco_home=str(cco_home) if cco_home else None))
    server_dir, function_name = _resolve_tool(tool_name)
    module = _load_server_module(server_dir, cco_home)
    func = getattr(module, function_name, None)
    if not callable(func):
        server_short = server_dir.removeprefix("mcp-").replace("-", "_")
        for candidate in (
            f"{server_short}_{function_name}",
            function_name.removeprefix(f"{server_short}_"),
        ):
            func = getattr(module, candidate, None)
            if callable(func):
                break
    if not callable(func):
        raise ValueError(f"tool function not found: {tool_name}")
    def invoke():
        raw = func(**args)
        return asyncio.run(raw) if inspect.isawaitable(raw) else raw

    if current_budget() is not None and tool_name.startswith("validator_"):
        from policy_engine import PolicyEngine
        from cco_validator_core.egress import scoped_wire_gate
        engine = PolicyEngine(cco_home=str(cco_home) if cco_home else None)
        def gate(method, url, headers):
            decision = engine.validate_wire_invocation(tool_name, {
                "target": url, "url": url, "method": method, "headers": headers})
            return decision["allowed"], decision["reason"]
        with scoped_wire_gate(gate):
            return invoke()
    if current_budget() is not None and tool_name == "kali-tools_discover_web_surface":
        from policy_engine import PolicyEngine
        mem_dir = str(REPO_ROOT / "mcp-servers" / "mcp-memory-server")
        if mem_dir not in sys.path:
            sys.path.insert(0, mem_dir)
        from cco_surface_core.wire import scoped_surface_requests
        engine = PolicyEngine(cco_home=str(cco_home) if cco_home else None)
        def gate(method, url, headers):
            decision = engine.validate_wire_invocation(tool_name, {
                "target": url, "url": url, "method": method, "headers": headers})
            return decision["allowed"], decision["reason"]
        target = args.get("target") or ""
        with scoped_surface_requests(gate, target):
            return invoke()
    raw = invoke()
    return raw


def _limits_from_payload(data: dict | None) -> ResourceLimits | None:
    if not data:
        return None
    backend = "container" if data.get("cgroup_mode") == "container" else "process"
    return ResourceLimits.from_mapping(data, backend=backend)


def _emit_child_result(response: dict, max_bytes: int = 16 * 1024 * 1024) -> None:
    try:
        serialized = json.dumps(response, ensure_ascii=False, allow_nan=False, default=str).encode("utf-8")
    except Exception:
        serialized = json.dumps({
            "ok": False,
            "error_type": "ResultSerializationError",
            "executor_pid": os.getpid(),
        }, separators=(",", ":")).encode("utf-8")
    if len(serialized) > max_bytes:
        serialized = json.dumps({
            "ok": False,
            "error_type": "OutputLimitExceeded",
            "executor_pid": os.getpid(),
        }, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(serialized).decode("ascii")
    print(f"{CHILD_RESULT_PREFIX}{encoded}", flush=True)


def _read_child_payload(max_bytes: int) -> dict:
    raw = sys.stdin.buffer.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("executor input exceeds contract limit")
    payload = json.loads(raw.decode("utf-8") or "{}")
    if not isinstance(payload, dict):
        raise ValueError("executor input must be an object")
    return payload


def _execute_tool_child() -> int:
    budget = None
    try:
        payload = _read_child_payload(16 * 1024 * 1024)
        args = payload.get("args") or {}
        if not isinstance(args, dict):
            raise ValueError("task args_json must be an object")
        limits = _limits_from_payload(payload.get("resource_limits"))
        rlimits = apply_process_resource_limits(limits) if limits else {}
        descriptor = payload.get("wire_budget")
        if descriptor is not None:
            with campaign_wire_budget(descriptor["limit"], descriptor["invocation_id"]) as budget:
                raw = _invoke_local_mcp_tool(payload.get("tool_name", ""), args, payload.get("cco_home") or None)
        else:
            raw = _invoke_local_mcp_tool(payload.get("tool_name", ""), args, payload.get("cco_home") or None)
        response = {"ok": True, "output": raw, "executor_pid": os.getpid(), "rlimits": rlimits}
        exit_code = 0
    except BaseException as exc:
        response = {"ok": False, "error_type": type(exc).__name__,
                    "error": str(exc)[:300], "executor_pid": os.getpid()}
        exit_code = 1
    if budget is not None:
        response["wire_usage"] = budget.snapshot()
    _emit_child_result(response)
    return exit_code


class _SubprocessExecutor:
    """Shared process-group, timeout, cgroup, and container lifecycle."""

    def __init__(self, timeout_seconds: float = 900, cgroup_root: str | Path | None = None):
        self.timeout_seconds = max(0.1, float(timeout_seconds))
        self.cgroup_root = cgroup_root
        self._process = None
        self._cgroup = None
        self._container_cleanup: tuple[str, str] | None = None
        self._process_lock = threading.Lock()

    @staticmethod
    def _kill_process_group(process, grace_seconds: float = 0.2) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            if process.poll() is None:
                try:
                    process.terminate()
                except OSError:
                    pass
            return
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            try:
                os.killpg(process.pid, 0)
            except (OSError, ProcessLookupError):
                return
            time.sleep(0.02)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass

    @staticmethod
    def _remove_container(container_cleanup: tuple[str, str] | None) -> None:
        if not container_cleanup:
            return
        try:
            subprocess.run(
                [container_cleanup[0], "rm", "-f", container_cleanup[1]],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def terminate(self) -> None:
        with self._process_lock:
            process = self._process
            cgroup = self._cgroup
            container_cleanup = self._container_cleanup
        if cgroup:
            cgroup.kill()
        if process is None:
            self._remove_container(container_cleanup)
            return
        try:
            self._kill_process_group(process)
            if process.poll() is None:
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
        finally:
            self._remove_container(container_cleanup)

    def _run_subprocess(
        self,
        command: list[str],
        payload: dict,
        *,
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
        limits: ResourceLimits | None = None,
        max_input_bytes: int = 16 * 1024 * 1024,
        container_cleanup: tuple[str, str] | None = None,
    ) -> tuple[dict, dict]:
        serialized = json.dumps(payload, ensure_ascii=False, allow_nan=False)
        if len(serialized.encode("utf-8")) > max_input_bytes:
            raise ValueError("executor input exceeds contract limit")
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            cwd=str(cwd) if cwd else None,
            start_new_session=True,
        )
        with self._process_lock:
            self._process = process
            self._container_cleanup = container_cleanup
        cgroup = None
        cgroup_report = {"applied": False, "mode": "disabled"}
        try:
            if limits:
                try:
                    cgroup, cgroup_report = attach_cgroup(process.pid, limits, self.cgroup_root)
                    with self._process_lock:
                        if self._process is process:
                            self._cgroup = cgroup
                except Exception:
                    self.terminate()
                    raise
            try:
                stdout, _stderr = process.communicate(serialized, timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                self.terminate()
                process.communicate()
                raise TimeoutError(f"executor subprocess timed out after {self.timeout_seconds:g}s") from exc
        finally:
            self._kill_process_group(process)
            if cgroup:
                cgroup.kill()
                cgroup.cleanup()
            self._remove_container(container_cleanup)
            with self._process_lock:
                if self._process is process:
                    self._process = None
                    self._cgroup = None
                    self._container_cleanup = None
        framed = [line[len(CHILD_RESULT_PREFIX):] for line in stdout.splitlines() if line.startswith(CHILD_RESULT_PREFIX)]
        if not framed:
            raise RuntimeError(f"executor subprocess exited without a framed result (exit={process.returncode})")
        try:
            response = json.loads(base64.urlsafe_b64decode(framed[-1].encode("ascii")).decode("utf-8"))
        except Exception as exc:
            raise RuntimeError("executor subprocess returned an invalid framed result") from exc
        if not response.get("ok"):
            raise ChildExecutionError(response)
        return response, cgroup_report


class LocalMCPExecutor(_SubprocessExecutor):
    """Timeout-bound subprocess executor for local MCP server functions."""

    def __init__(self, cco_home: str | Path | None = None, timeout_seconds: float = 900,
                 limits: ResourceLimits | None = None, cgroup_root: str | Path | None = None):
        super().__init__(timeout_seconds, cgroup_root)
        self.cco_home = cco_home
        self.limits = limits

    def _command(self) -> list[str]:
        command = [sys.executable, str(Path(__file__).resolve()), "_execute-tool"]
        if self.limits and self.limits.network == "deny":
            unshare = shutil.which("unshare")
            if not unshare:
                raise RuntimeError("network-denied process isolation requires unshare")
            return [unshare, "--net", "--", *command]
        return command

    def __call__(self, task: dict) -> dict:
        tool_name = str(task.get("tool_name") or "")
        args = json.loads(task.get("args_json") or "{}")
        if not isinstance(args, dict):
            raise ValueError("task args_json must be an object")
        payload = {
            "tool_name": tool_name,
            "args": args,
            "cco_home": str(self.cco_home or ""),
            "resource_limits": self.limits.child_payload() if self.limits else None,
        }
        child_env = os.environ.copy()
        descriptor = None
        if "request_cost" in task:
            reserved = task.get("reserved_request_cost", task["request_cost"])
            if isinstance(reserved, bool) or not isinstance(reserved, int) or reserved < 0:
                raise ValueError("invalid reserved campaign request budget")
            child_env["CCO_CAMPAIGN_WIRE_BUDGET"] = str(reserved)
            descriptor = {"limit": reserved, "invocation_id": secrets.token_hex(16)}
            payload["wire_budget"] = descriptor
        else:
            child_env.pop("CCO_CAMPAIGN_WIRE_BUDGET", None)
        execution_failed = False
        try:
            response, cgroup_report = self._run_subprocess(
                self._command(), payload, env=child_env, limits=self.limits
            )
        except ChildExecutionError as exc:
            if descriptor is None:
                raise
            response, cgroup_report = exc.response, {}
            execution_failed = True
        out = {
            "result": {
                "executed": True,
                "mode": "local_mcp",
                "tool_name": tool_name,
                "executor_pid": response.get("executor_pid"),
                "output": response.get("output"),
                "isolation": {
                    "network": self.limits.network if self.limits else "inherit",
                    "rlimits": response.get("rlimits") or {},
                    "cgroup": cgroup_report,
                },
            },
            "checkpoint": {"phase": "local_mcp_complete", "tool_name": tool_name},
        }
        if descriptor is not None:
            usage = response.get("wire_usage")
            out["actual_request_cost"] = validate_usage(usage, **descriptor)
            out["wire_usage"] = usage
            if execution_failed:
                out["execution_failed"] = True
                out["result"]["error_type"] = response.get("error_type") or "UnknownError"
            return out
        if tool_name == "hunter_run_web_loop":
            try:
                report = json.loads(response.get("output") or "{}")
                count = report.get("requests_authorized") if isinstance(report, dict) else None
                if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
                    if "request_cost" in task and count > int(task.get("reserved_request_cost", task["request_cost"])):
                        raise RuntimeError("reported web request count exceeds its campaign reservation")
                    out["actual_request_cost"] = count
            except (TypeError, ValueError):
                pass
        return out


class CustomSubprocessExecutor(_SubprocessExecutor):
    """Contract-bound custom code executor; custom code is never imported by the worker."""

    def __init__(self, contract_path: str | Path, timeout_seconds: float = 900,
                 cgroup_root: str | Path | None = None):
        if os.environ.get("CCO_ENABLE_CUSTOM_WORKER_EXECUTOR") != "1":
            raise ValueError("custom worker executor disabled; set CCO_ENABLE_CUSTOM_WORKER_EXECUTOR=1")
        self.contract = ExecutorContract.load(contract_path)
        super().__init__(min(float(timeout_seconds), float(self.contract.limits.cpu_seconds)), cgroup_root)

    def __call__(self, task: dict) -> dict:
        from policy_engine import PolicyEngine
        if ("request_cost" in task and self.contract.limits.network != "deny"
                and network_required(task.get("tool_name", ""), json.loads(task.get("args_json") or "{}"), PolicyEngine())):
            raise UnsupportedWireAccounting("custom network executor has no enforced campaign wire allowance")
        safe_task = {key: task.get(key) for key in CUSTOM_TASK_FIELDS if key in task}
        payload = {
            "contract_sha256": self.contract.digest,
            "executor_code_sha256": self.contract.code_sha256,
            "task": safe_task,
        }
        cleanup = None
        if self.contract.backend == "container":
            command, container_name, runtime = self.contract.container_command(
                SCRIPT_DIR / "custom_executor_child.py",
                SCRIPT_DIR / "executor_isolation.py",
            )
            cleanup = (runtime, container_name)
            environment = self.contract.environment(SCRIPT_DIR)
            cwd = self.contract.path.parent
        else:
            base = [
                sys.executable, str(SCRIPT_DIR / "custom_executor_child.py"),
                "--contract", str(self.contract.path),
            ]
            command = self.contract.process_command(base)
            environment = self.contract.environment(SCRIPT_DIR)
            cwd = self.contract.path.parent
        response, cgroup_report = self._run_subprocess(
            command,
            payload,
            env=environment,
            cwd=cwd,
            limits=self.contract.limits,
            max_input_bytes=self.contract.max_input_bytes,
            container_cleanup=cleanup,
        )
        output = response.get("output")
        if not isinstance(output, dict):
            raise RuntimeError("custom executor returned an invalid output object")
        result = output.get("result") or {}
        checkpoint = output.get("checkpoint") or {"phase": "custom_complete"}
        if not isinstance(result, dict) or not isinstance(checkpoint, dict):
            raise RuntimeError("custom executor result and checkpoint must be objects")
        result.update({
            "executed": True,
            "mode": "custom_subprocess",
            "executor_pid": response.get("executor_pid"),
            "contract_sha256": self.contract.digest,
            "executor_code_sha256": self.contract.code_sha256,
            "isolation": {
                "backend": self.contract.backend,
                "network": self.contract.limits.network,
                "rlimits": response.get("rlimits") or {},
                "cgroup": cgroup_report,
            },
        })
        output["result"] = result
        output["checkpoint"] = checkpoint
        return output


CHAIN_TOOL_NAME = "chain_runner_execute"


class ChainTaskExecutor:
    """`chain_runner_execute` görevlerini ChainExecutor ile koşar (Faz 3).

    args: {manifest | manifest_json, identities?, login_recipe?, target_bases?}
    Zincir terminali succeed değilse istisna: worker görevi retry'lı fail eder.
    """

    def __init__(self, runtime: CampaignRuntime, sender=None, policy_engine=None,
                 evidence_graph=None, evidence_context=None):
        self.evidence_graph = evidence_graph
        self.evidence_context = evidence_context
        self.runtime = runtime
        self.sender = sender
        self.policy_engine = policy_engine

    def __call__(self, task: dict) -> dict:
        from chain_executor import ChainExecutor

        try:
            args = json.loads(task.get("args_json") or "{}")
        except Exception as exc:
            raise ValueError(f"chain task args_json bozuk: {exc}") from exc
        if not isinstance(args, dict):
            raise ValueError("chain task args object olmalı")
        manifest = args.get("manifest")
        if manifest is None and args.get("manifest_json"):
            manifest = json.loads(str(args["manifest_json"]))
        if not isinstance(manifest, dict):
            raise ValueError("chain task manifest (dict) gerektirir")
        if "request_cost" in task:
            reserved = task.get("reserved_request_cost", task["request_cost"])
            if isinstance(reserved, bool) or not isinstance(reserved, int) or reserved < 0:
                raise ValueError("invalid reserved campaign request budget")
            # ChainTransport already accounts every request. Bind that cap to
            # the campaign reservation instead of trusting a larger manifest.
            manifest = json.loads(json.dumps(manifest))
            budget = manifest.get("budget") or {}
            if isinstance(budget, dict) and isinstance(budget.get("max_requests"), int):
                budget["max_requests"] = min(budget["max_requests"], reserved)
                manifest["budget"] = budget
        engine = self.policy_engine
        if engine is None:
            engine = self.runtime._policy_engine(task.get("scope_file") or None)
        graph = self.evidence_graph
        owns_graph = False
        if manifest.get('evidence_chain') and graph is None:
            from evidence_chaining import EvidenceGraph
            graph = EvidenceGraph(self.runtime.cco_home / 'agent_memory.db')
            owns_graph = True
        runner = ChainExecutor(
            evidence_graph=graph, evidence_context=self.evidence_context,
            policy_engine=engine,
            sender=self.sender,
            identities=args.get("identities") or {},
            target_bases=args.get("target_bases") or {},
            login_recipe=args.get("login_recipe"),
        )
        try:
            out = runner.execute(manifest)
        finally:
            if owns_graph:
                graph.close()
        def _ev_preview(step: dict) -> str:
            raw = (str((step.get("result") or {}).get("excerpt") or "")
                   or str((step.get("result") or {}).get("value_preview") or ""))
            return " ".join(raw.split())[:200]
        summary = {
            "manifest_hash": out.get("manifest_hash", ""),
            "terminal": out.get("terminal", ""),
            "success": bool(out.get("success")),
            "requests_sent": out.get("requests_sent", 0),
            "verdict": out.get("verdict", "INCONCLUSIVE"),
            "replay_evidence_hash": out.get("replay_evidence_hash", ""),
            "steps": [
                {"id": s.get("id"), "tool": s.get("tool"),
                 "oracle_passed": bool(s.get("oracle_passed")),
                 "evidence": _ev_preview(s),
                 "evidence_sha256": hashlib.sha256(
                     json.dumps(s.get("result") or {},
                                ensure_ascii=False, sort_keys=True,
                                default=str).encode("utf-8")).hexdigest()[:16]}
                for s in out.get("steps_executed", [])
            ],
        }
        if not out.get("success") and not (out.get("status") == "completed" and out.get("verdict") == "NOT_CONFIRMED"):
            # Başarısız koşunun adım kanıtı kaybolmasın: dosyaya yaz + hataya özetle.
            import os as _os
            evpath = ""
            try:
                evdir = _os.path.join(
                    _os.path.expanduser(_os.environ.get("CCO_WORKDIR", "~/.cco")),
                    "chain-evidence")
                _os.makedirs(evdir, exist_ok=True)
                evpath = _os.path.join(evdir, f"task_{task.get('id')}_steps.json")
                with open(evpath, "w", encoding="utf-8") as fh:
                    json.dump(out.get("steps_executed", []), fh,
                              ensure_ascii=False, indent=1, default=str)
            except Exception:
                evpath = ""
            detail = "; ".join(
                f"{s.get('id')}:{s.get('tool')}:oracle={s.get('oracle_passed')}"
                for s in out.get("steps_executed", []))
            msg = (f"chain terminal={out.get('terminal')}: "
                   f"{out.get('terminal_error') or 'oracle fail'} | steps: {detail}")
            if evpath:
                msg += f" | evidence: {evpath}"
            summary["evidence_path"] = evpath
            summary["terminal_error"] = out.get("terminal_error", "")
            raise AccountedExecutionError(msg, int(out.get("requests_sent", 0) or 0), result=summary)
        return {
            "result": summary,
            "checkpoint": {"phase": "chain_completed", "terminal": summary["terminal"],
                           "manifest_hash": summary["manifest_hash"]},
            "actual_request_cost": int(out.get("requests_sent", 0) or 0),
        }


class CampaignWorker:
    def __init__(self, runtime: CampaignRuntime, worker_id: str,
                 executor: Callable[[dict], dict] | None = None,
                 claim_timeout_seconds: float = 300,
                 heartbeat_interval_seconds: float | None = None,
                 chain_executor: Callable[[dict], dict] | None = None):
        self.runtime = runtime
        self.worker_id = worker_id
        self.executor = executor or dry_run_executor
        self.chain_executor = chain_executor
        self.claim_timeout_seconds = max(0.2, float(claim_timeout_seconds))
        default_interval = min(30.0, self.claim_timeout_seconds / 3)
        requested_interval = default_interval if heartbeat_interval_seconds is None else float(heartbeat_interval_seconds)
        self.heartbeat_interval_seconds = max(0.05, min(requested_interval, self.claim_timeout_seconds / 2))

    def _executor_for(self, task: dict) -> Callable[[dict], dict]:
        if task.get("tool_name") == CHAIN_TOOL_NAME:
            return self.chain_executor or ChainTaskExecutor(self.runtime)
        return self.executor

    def _terminate_executor(self) -> None:
        terminate = getattr(self.executor, "terminate", None)
        if callable(terminate):
            terminate()

    def _execute_with_heartbeats(self, task: dict, permit_holder: dict[str, str],
                                 executor: Callable[[dict], dict] | None = None) -> dict:
        run_executor = executor or self.executor
        stop = threading.Event()
        executor_done = threading.Event()
        lock = threading.Lock()
        heartbeat_error: list[Exception] = []

        def heartbeat_loop():
            heartbeat_count = 0
            while not stop.is_set():
                if stop.wait(self.heartbeat_interval_seconds):
                    break
                with lock:
                    current_permit = permit_holder["value"]
                try:
                    refreshed = self.runtime.heartbeat_task_with_permit(
                        current_permit,
                        {
                            "phase": "executing",
                            "worker_id": self.worker_id,
                            "heartbeat": heartbeat_count + 1,
                        },
                        claim_timeout_seconds=self.claim_timeout_seconds,
                        allow_expired_lease=True,
                    )
                except Exception as exc:
                    heartbeat_error.append(exc)
                    stop.set()
                    while not executor_done.is_set():
                        self._terminate_executor()
                        if executor_done.wait(0.02):
                            break
                    return
                with lock:
                    permit_holder["value"] = refreshed
                heartbeat_count += 1

        thread = threading.Thread(target=heartbeat_loop, name=f"cco-heartbeat-{task['id']}", daemon=True)
        thread.start()
        execution_error = None
        output = None
        try:
            output = run_executor(task) or {}
        except Exception as exc:
            execution_error = exc
        finally:
            executor_done.set()
            stop.set()
            thread.join()
        if heartbeat_error:
            raise heartbeat_error[0]
        if execution_error:
            raise execution_error
        return output or {}

    def run_once(self, campaign_id: int | None = None,
                 kinds: list[str] | None = None) -> dict:
        task = self.runtime.claim_next_task(
            self.worker_id,
            campaign_id=campaign_id,
            claim_timeout_seconds=self.claim_timeout_seconds,
            kinds=kinds,
        )
        if not task:
            return {"claimed": False}
        permit = task["execution_permit"]
        permit_holder = {"value": permit}
        try:
            permit_holder["value"] = self.runtime.heartbeat_task_with_permit(
                permit,
                {"phase": "pre_execute", "worker_id": self.worker_id},
                claim_timeout_seconds=self.claim_timeout_seconds,
                allow_expired_lease=True,
            )
            output = self._execute_with_heartbeats(
                task, permit_holder, executor=self._executor_for(task))
            incomplete = _hunter_incomplete_result(task, output)
            if incomplete is None and isinstance(output.get("wire_usage"), dict):
                usage = output["wire_usage"]
                if output.get("execution_failed") or usage.get("blocked_reason"):
                    incomplete = {"reason": usage.get("blocked_reason") or "native tool execution failed",
                                  "wire_usage": usage,
                                  "error_type": (output.get("result") or {}).get("error_type", "")}
            if incomplete is not None:
                safe_result = redact({"executed": True, "mode": "local_mcp",
                                      "tool_name": task.get("tool_name"), **incomplete})
                checkpoint = {"phase": "replan_required", "reason": incomplete["reason"]}
                self.runtime.block_task_with_permit(
                    permit_holder["value"], incomplete["reason"], result=safe_result, checkpoint=checkpoint,
                    actual_request_cost=output.get("actual_request_cost"),
                    actual_usd_cost=output.get("actual_usd_cost"))
                return {"claimed": True, "task_id": task["id"], "status": "blocked", "result": safe_result}
            # Kapanıştan önce son bir heartbeat: icra sonrası settlement
            # gecikmesi permit'i düşürmesin (fencing hâlâ bizdeyse yeniler)
            permit_holder["value"] = self.runtime.heartbeat_task_with_permit(
                permit_holder["value"],
                {"phase": "settling", "worker_id": self.worker_id},
                claim_timeout_seconds=self.claim_timeout_seconds,
                allow_expired_lease=True,
            )
            result = mark_empty_result(redact(output.get("result") or {}))
            checkpoint = redact(output.get("checkpoint") or {"phase": "completed"})
            self.runtime.complete_task_with_permit(
                permit_holder["value"],
                result=result,
                checkpoint=checkpoint,
                actual_request_cost=output.get("actual_request_cost"),
                actual_usd_cost=output.get("actual_usd_cost"),
            )
            return {
                "claimed": True,
                "task_id": task["id"],
                "status": "done",
                "result": result,
            }
        except Exception as exc:
            try:
                try:
                    permit_holder["value"] = self.runtime.heartbeat_task_with_permit(
                        permit_holder["value"],
                        {"phase": "settling_failed", "worker_id": self.worker_id},
                        claim_timeout_seconds=self.claim_timeout_seconds,
                        allow_expired_lease=True,
                    )
                except Exception:
                    pass
                if isinstance(exc, UnsupportedWireAccounting):
                    self.runtime.block_task_with_permit(
                        permit_holder["value"], str(exc), result={"executed": False, "error_type": type(exc).__name__},
                        checkpoint={"phase": "wire_accounting_unavailable"}, actual_request_cost=0)
                    return {"claimed": True, "task_id": task["id"], "status": "blocked", "error": type(exc).__name__}
                if isinstance(exc, AccountedExecutionError):
                    self.runtime.block_task_with_permit(
                        permit_holder["value"], "network execution requires replanning",
                        result=redact({"executed": True, "error_type": type(exc).__name__, **exc.result}),
                        checkpoint={"phase": "replan_required"}, actual_request_cost=exc.actual_request_cost)
                    return {"claimed": True, "task_id": task["id"], "status": "blocked", "error": type(exc).__name__}
                if self.runtime.is_network_task(task):
                    # The child may have sent requests before failing. Without
                    # a trustworthy count, charge the reservation and require
                    # explicit replanning instead of silently retrying.
                    reason = "network execution failed; request count unavailable"
                    self.runtime.block_task_with_permit(
                        permit_holder["value"], reason,
                        result={"executed": True, "error_type": type(exc).__name__},
                        checkpoint={"phase": "replan_required", "reason": reason})
                    return {"claimed": True, "task_id": task["id"], "status": "blocked",
                            "error": type(exc).__name__}
                self.runtime.fail_task_with_permit(
                    permit_holder["value"],
                    str(redact(str(exc))),
                    retry_in=60,
                    checkpoint={"phase": "failed", "error": type(exc).__name__},
                )
            except Exception:
                pass
            return {
                "claimed": True,
                "task_id": task["id"],
                "status": "failed",
                "error": type(exc).__name__,
            }


def main(argv: list[str] | None = None) -> int:
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    if effective_argv and effective_argv[0] == "_execute-tool":
        return _execute_tool_child()
    parser = argparse.ArgumentParser(description="CCO safe campaign worker")
    parser.add_argument("command", choices=["run-once", "drain"], nargs="?", default="run-once")
    parser.add_argument("--worker-id", default="cco-worker")
    parser.add_argument("--campaign-id", type=int)
    parser.add_argument("--kinds", default="",
                        help="Virgülle ayrılmış task kind filtresi (boş = tümü)")
    parser.add_argument("--max-tasks", type=int, default=10)
    parser.add_argument("--claim-timeout", type=float, default=300)
    parser.add_argument("--heartbeat-interval", type=float)
    parser.add_argument("--execution-timeout", type=float, default=900)
    parser.add_argument("--mode", choices=["dry-run", "local-mcp", "custom"], default="dry-run")
    parser.add_argument("--executor-contract", default="")
    parser.add_argument("--cpu-limit-seconds", type=int)
    parser.add_argument("--cpu-limit-cores", type=float, default=1.0)
    parser.add_argument("--memory-limit-mb", type=int, default=1024)
    parser.add_argument("--pids-limit", type=int, default=128)
    parser.add_argument("--network-policy", choices=["inherit", "deny"], default="inherit")
    parser.add_argument("--cgroup-mode", choices=["best_effort", "required"], default="best_effort")
    parser.add_argument("--cgroup-root", default="")
    args = parser.parse_args(effective_argv)
    runtime = CampaignRuntime()
    if args.mode == "custom":
        if not args.executor_contract:
            parser.error("--executor-contract is required with --mode custom")
        executor = CustomSubprocessExecutor(
            args.executor_contract,
            timeout_seconds=args.execution_timeout,
            cgroup_root=args.cgroup_root or None,
        )
    elif args.mode == "local-mcp":
        limit_mapping = {
            "cpu_seconds": args.cpu_limit_seconds or max(1, int(math.ceil(args.execution_timeout))),
            "cpu_cores": args.cpu_limit_cores,
            "memory_mb": args.memory_limit_mb,
            "pids": args.pids_limit,
            "network": args.network_policy,
            "cgroup_mode": args.cgroup_mode,
        }
        limits = ResourceLimits.from_mapping(limit_mapping, backend="process")
        executor = LocalMCPExecutor(
            runtime.cco_home,
            timeout_seconds=args.execution_timeout,
            limits=limits,
            cgroup_root=args.cgroup_root or None,
        )
    else:
        executor = dry_run_executor
    worker = CampaignWorker(
        runtime,
        args.worker_id,
        executor,
        args.claim_timeout,
        heartbeat_interval_seconds=args.heartbeat_interval,
    )
    kinds = [k.strip() for k in (args.kinds or "").split(",") if k.strip()] or None
    if args.command == "drain":
        results = []
        for _ in range(max(1, args.max_tasks)):
            step = worker.run_once(args.campaign_id, kinds=kinds)
            results.append(step)
            if not step.get("claimed"):
                break
        print(json.dumps({"drained": results,
                          "claimed_total": sum(1 for r in results if r.get("claimed"))},
                         indent=2, ensure_ascii=False))
        return 0 if all(r.get("status") != "failed" for r in results) else 2
    result = worker.run_once(args.campaign_id, kinds=kinds)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("status") != "failed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
