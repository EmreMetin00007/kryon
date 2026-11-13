#!/usr/bin/env python3
"""Offline multi-worker soak and stress validation for the campaign runtime."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from campaign_runtime import CampaignRuntime
from campaign_worker import CampaignWorker, LocalMCPExecutor
from executor_isolation import ResourceLimits


REPORT_SCHEMA = "cco-worker-soak/1"
OFFLINE_TOOL = "kali-tools_cvss_calculate"
OFFLINE_ARGS = {
    "av": "N", "ac": "L", "pr": "N", "ui": "N",
    "s": "U", "c": "H", "i": "H", "a": "N",
}


@dataclass(frozen=True)
class SoakConfig:
    tasks_per_round: int = 100
    workers: int = 4
    stale_claims: int = 5
    stale_lease_seconds: float = 0.1
    duration_seconds: float = 0.0
    max_tasks: int = 10000
    executor: str = "local-mcp"
    timeout_seconds: float = 300.0
    execution_timeout_seconds: float = 30.0
    claim_timeout_seconds: float = 5.0
    heartbeat_interval_seconds: float = 0.5
    synthetic_delay_ms: float = 1.0
    cpu_limit_seconds: int = 30
    cpu_limit_cores: float = 1.0
    memory_limit_mb: int = 512
    pids_limit: int = 64
    cgroup_mode: str = "best_effort"

    def validate(self) -> None:
        if self.tasks_per_round < 1:
            raise ValueError("tasks_per_round must be positive")
        if self.workers < 1:
            raise ValueError("workers must be positive")
        if not 0 <= self.stale_claims <= self.tasks_per_round:
            raise ValueError("stale_claims must be between zero and tasks_per_round")
        if self.stale_lease_seconds <= 0:
            raise ValueError("stale_lease_seconds must be positive")
        if self.duration_seconds < 0 or self.timeout_seconds <= 0:
            raise ValueError("duration must be non-negative and timeout must be positive")
        if self.max_tasks < self.tasks_per_round:
            raise ValueError("max_tasks must be at least tasks_per_round")
        if self.executor not in {"synthetic", "local-mcp"}:
            raise ValueError("executor must be synthetic or local-mcp")


class SyntheticExecutor:
    def __init__(self, delay_ms: float = 0.0):
        self.delay_seconds = max(0.0, float(delay_ms)) / 1000.0

    def __call__(self, task: dict) -> dict:
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        return {
            "result": {
                "executed": True,
                "mode": "synthetic_soak",
                "task_id": int(task["id"]),
            },
            "checkpoint": {"phase": "synthetic_complete"},
            "actual_request_cost": 1,
            "actual_usd_cost": 0.0,
        }


def _resource_limits(config: SoakConfig) -> ResourceLimits:
    return ResourceLimits.from_mapping({
        "cpu_seconds": config.cpu_limit_seconds,
        "cpu_cores": config.cpu_limit_cores,
        "memory_mb": config.memory_limit_mb,
        "pids": config.pids_limit,
        "network": "inherit",
        "cgroup_mode": config.cgroup_mode,
    }, backend="process")


def _executor_for(config: SoakConfig, cco_home: Path):
    if config.executor == "synthetic":
        return SyntheticExecutor(config.synthetic_delay_ms)
    return LocalMCPExecutor(
        cco_home,
        timeout_seconds=config.execution_timeout_seconds,
        limits=_resource_limits(config),
    )


def _enqueue_batch(runtime: CampaignRuntime, campaign_id: int, start: int, count: int) -> None:
    for sequence in range(start, start + count):
        runtime.enqueue_task(
            campaign_id,
            "offline-score",
            OFFLINE_TOOL,
            OFFLINE_ARGS,
            request_cost=1,
            usd_cost=0.0,
            idempotency_key=f"soak-{sequence}",
        )


def _create_stale_claims(runtime: CampaignRuntime, campaign_id: int, count: int, lease_seconds: float) -> int:
    claimed = 0
    for index in range(count):
        task = runtime.claim_next_task(
            f"simulated-crash-{index}",
            campaign_id=campaign_id,
            claim_timeout_seconds=lease_seconds,
        )
        if task:
            claimed += 1
    if claimed:
        time.sleep(lease_seconds + min(0.25, max(0.05, lease_seconds / 2)))
    return claimed


def _drain_campaign(config: SoakConfig, cco_home: Path, campaign_id: int) -> tuple[list[dict], list[str]]:
    outcomes: list[dict] = []
    errors: list[str] = []
    outcome_lock = threading.Lock()
    stop = threading.Event()
    executors = []
    executor_lock = threading.Lock()
    deadline = time.monotonic() + config.timeout_seconds

    def worker_loop(index: int) -> None:
        runtime = CampaignRuntime(str(cco_home))
        executor = _executor_for(config, cco_home)
        with executor_lock:
            executors.append(executor)
        worker = CampaignWorker(
            runtime,
            f"soak-worker-{index}",
            executor,
            claim_timeout_seconds=config.claim_timeout_seconds,
            heartbeat_interval_seconds=config.heartbeat_interval_seconds,
        )
        while not stop.is_set() and time.monotonic() < deadline:
            result = worker.run_once(campaign_id)
            if result.get("claimed"):
                with outcome_lock:
                    outcomes.append(result)
                    if result.get("status") != "done":
                        errors.append(f"task {result.get('task_id')} returned {result.get('status')}")
                        stop.set()
                        return
                continue
            outstanding = runtime.list_tasks(campaign_id)
            unexpected = sorted({
                task["status"] for task in outstanding
                if task["status"] in {"blocked", "dead_letter", "rate_limited", "waiting_approval"}
            })
            if unexpected:
                with outcome_lock:
                    errors.append(f"unexpected task states: {', '.join(unexpected)}")
                    stop.set()
                return
            if not any(task["status"] in {"pending", "running", "rate_limited", "waiting_approval"}
                       for task in outstanding):
                return
            time.sleep(0.01)
        with outcome_lock:
            if not stop.is_set():
                errors.append(f"worker {index} exceeded drain timeout")
                stop.set()

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=config.workers)
    futures = [pool.submit(worker_loop, index) for index in range(config.workers)]
    done, pending = concurrent.futures.wait(futures, timeout=config.timeout_seconds)
    if pending:
        stop.set()
        with outcome_lock:
            errors.append("campaign drain exceeded timeout")
        with executor_lock:
            active_executors = list(executors)
        for executor in active_executors:
            terminate = getattr(executor, "terminate", None)
            if callable(terminate):
                terminate()
        newly_done, pending = concurrent.futures.wait(pending, timeout=5)
        done |= newly_done
    for future in done:
        try:
            future.result()
        except Exception as exc:
            errors.append(f"worker future failed: {type(exc).__name__}")
    if pending:
        errors.append(f"{len(pending)} worker futures did not terminate")
    pool.shutdown(wait=not pending, cancel_futures=True)
    return outcomes, errors


def _verify(runtime: CampaignRuntime, campaign_id: int, produced: int,
            stale_claims: int, outcomes: list[dict], errors: list[str], expected_requests: int | None = None) -> dict:
    conn = sqlite3.connect(runtime.db_path)
    conn.row_factory = sqlite3.Row
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    status_counts = {
        row["status"]: int(row["count"])
        for row in conn.execute(
            "SELECT status, COUNT(*) AS count FROM tasks WHERE campaign_id=? GROUP BY status",
            (campaign_id,),
        ).fetchall()
    }
    task_stats = conn.execute(
        """
        SELECT COUNT(*) AS total,
               COUNT(DISTINCT idempotency_key) AS unique_keys,
               MAX(attempts) AS max_attempts,
               SUM(CASE WHEN lease_token != '' OR execution_permit_id != '' OR worker_fencing_token != '' THEN 1 ELSE 0 END) AS live_secrets,
               SUM(reserved_request_cost) AS task_request_reservations,
               SUM(reserved_usd_micros) AS task_usd_reservations
        FROM tasks WHERE campaign_id=?
        """,
        (campaign_id,),
    ).fetchone()
    events = {
        row["event_type"]: int(row["count"])
        for row in conn.execute(
            """
            SELECT event_type, COUNT(*) AS count FROM task_events
            WHERE task_id IN (SELECT id FROM tasks WHERE campaign_id=?)
            GROUP BY event_type
            """,
            (campaign_id,),
        ).fetchall()
    }
    duplicate_completions = conn.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT task_id FROM task_events
            WHERE event_type='completed'
              AND task_id IN (SELECT id FROM tasks WHERE campaign_id=?)
            GROUP BY task_id HAVING COUNT(*) != 1
        )
        """,
        (campaign_id,),
    ).fetchone()[0]
    campaign = conn.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
    conn.close()

    completed_outcomes = [outcome for outcome in outcomes if outcome.get("status") == "done"]
    outcome_ids = [int(outcome["task_id"]) for outcome in completed_outcomes]
    invariants = {
        "sqlite_integrity": integrity == "ok",
        "wal_enabled": str(journal_mode).lower() == "wal",
        "all_tasks_present": int(task_stats["total"] or 0) == produced,
        "all_tasks_done": status_counts == {"done": produced},
        "idempotency_unique": int(task_stats["unique_keys"] or 0) == produced,
        "exactly_once_completion": events.get("completed", 0) == produced and duplicate_completions == 0,
        "worker_outcomes_unique": len(completed_outcomes) == produced and len(set(outcome_ids)) == produced,
        "stale_claims_recovered": events.get("recovered_stale", 0) == stale_claims,
        "leases_and_permits_cleared": int(task_stats["live_secrets"] or 0) == 0,
        "task_reservations_cleared": int(task_stats["task_request_reservations"] or 0) == 0
                                     and int(task_stats["task_usd_reservations"] or 0) == 0,
        "campaign_reservations_cleared": int(campaign["requests_reserved"] or 0) == 0
                                         and int(campaign["usd_reserved_micros"] or 0) == 0,
        "budget_settled": int(campaign["requests_used"] or 0) == (produced if expected_requests is None else expected_requests),
        "no_worker_errors": not errors,
    }
    return {
        "success": all(invariants.values()),
        "invariants": invariants,
        "status_counts": status_counts,
        "events": events,
        "max_attempts": int(task_stats["max_attempts"] or 0),
        "requests_used": int(campaign["requests_used"] or 0),
        "errors": errors,
    }


def _run_soak_at(config: SoakConfig, cco_home: Path) -> dict:
    config.validate()
    cco_home.mkdir(parents=True, exist_ok=True)
    policy_path = cco_home / "worker-soak-policy.json"
    max_policy_calls = max(1000, config.max_tasks * 100)
    policy_path.write_text(json.dumps({
        "profile": "offline-soak",
        "rate_limit_profile": "soak",
        "rate_limits": {
            "default": {"window_seconds": 3600, "max_calls": max_policy_calls},
            "soak": {"window_seconds": 3600, "max_calls": max_policy_calls},
            "overrides": {OFFLINE_TOOL: {"window_seconds": 3600, "max_calls": max_policy_calls}},
        },
    }), encoding="utf-8")
    previous_policy = os.environ.get("CCO_PROGRAM_POLICY_FILE")
    previous_tools = os.environ.get("CCO_WORKER_ALLOWED_TOOLS")
    os.environ["CCO_PROGRAM_POLICY_FILE"] = str(policy_path)
    os.environ["CCO_WORKER_ALLOWED_TOOLS"] = OFFLINE_TOOL
    try:
        runtime = CampaignRuntime(str(cco_home))
        campaign_id = runtime.create_campaign(
            "offline-worker-soak",
            budget_requests=config.max_tasks,
            budget_usd=0.0,
            notes="offline deterministic worker soak",
        )
        started = time.monotonic()
        run_until = started + config.duration_seconds
        produced = 0
        stale_claims = 0
        all_outcomes: list[dict] = []
        all_errors: list[str] = []
        rounds = 0

        while produced < config.max_tasks:
            batch_size = min(config.tasks_per_round, config.max_tasks - produced)
            _enqueue_batch(runtime, campaign_id, produced, batch_size)
            produced += batch_size
            rounds += 1
            if rounds == 1 and config.stale_claims:
                stale_claims = _create_stale_claims(
                    runtime, campaign_id, config.stale_claims, config.stale_lease_seconds
                )
            outcomes, errors = _drain_campaign(config, cco_home, campaign_id)
            all_outcomes.extend(outcomes)
            all_errors.extend(errors)
            if errors or config.duration_seconds <= 0 or time.monotonic() >= run_until:
                break

        verification = _verify(
            runtime, campaign_id, produced, stale_claims, all_outcomes, all_errors,
            expected_requests=produced if config.executor == "synthetic" else 0,
        )
        elapsed = time.monotonic() - started
        return {
            "schema": REPORT_SCHEMA,
            "success": verification["success"],
            "workload": {
                "executor": config.executor,
                "workers": config.workers,
                "tasks": produced,
                "rounds": rounds,
                "simulated_stale_claims": stale_claims,
            },
            "metrics": {
                "elapsed_seconds": round(elapsed, 4),
                "tasks_per_second": round(produced / elapsed, 4) if elapsed else 0.0,
            },
            **verification,
        }
    finally:
        if previous_policy is None:
            os.environ.pop("CCO_PROGRAM_POLICY_FILE", None)
        else:
            os.environ["CCO_PROGRAM_POLICY_FILE"] = previous_policy
        if previous_tools is None:
            os.environ.pop("CCO_WORKER_ALLOWED_TOOLS", None)
        else:
            os.environ["CCO_WORKER_ALLOWED_TOOLS"] = previous_tools


def run_soak(config: SoakConfig, cco_home: str | Path | None = None) -> dict:
    if cco_home is not None:
        return _run_soak_at(config, Path(cco_home).expanduser().resolve())
    with tempfile.TemporaryDirectory(prefix="cco-worker-soak-") as temp_dir:
        return _run_soak_at(config, Path(temp_dir) / ".cco")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an offline campaign worker soak/stress test")
    parser.add_argument("--tasks", type=int, default=100, help="tasks per workload round")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--stale-claims", type=int, default=5)
    parser.add_argument("--stale-lease-seconds", type=float, default=0.1)
    parser.add_argument("--duration-seconds", type=float, default=0.0)
    parser.add_argument("--max-tasks", type=int, default=10000)
    parser.add_argument("--executor", choices=["synthetic", "local-mcp"], default="local-mcp")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--execution-timeout", type=float, default=30.0)
    parser.add_argument("--claim-timeout", type=float, default=5.0)
    parser.add_argument("--heartbeat-interval", type=float, default=0.5)
    parser.add_argument("--synthetic-delay-ms", type=float, default=1.0)
    parser.add_argument("--cpu-limit-seconds", type=int, default=30)
    parser.add_argument("--cpu-limit-cores", type=float, default=1.0)
    parser.add_argument("--memory-limit-mb", type=int, default=512)
    parser.add_argument("--pids-limit", type=int, default=64)
    parser.add_argument("--cgroup-mode", choices=["best_effort", "required"], default="best_effort")
    parser.add_argument("--cco-home", default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    config = SoakConfig(
        tasks_per_round=args.tasks,
        workers=args.workers,
        stale_claims=args.stale_claims,
        stale_lease_seconds=args.stale_lease_seconds,
        duration_seconds=args.duration_seconds,
        max_tasks=args.max_tasks,
        executor=args.executor,
        timeout_seconds=args.timeout,
        execution_timeout_seconds=args.execution_timeout,
        claim_timeout_seconds=args.claim_timeout,
        heartbeat_interval_seconds=args.heartbeat_interval,
        synthetic_delay_ms=args.synthetic_delay_ms,
        cpu_limit_seconds=args.cpu_limit_seconds,
        cpu_limit_cores=args.cpu_limit_cores,
        memory_limit_mb=args.memory_limit_mb,
        pids_limit=args.pids_limit,
        cgroup_mode=args.cgroup_mode,
    )
    try:
        report = run_soak(config, args.cco_home or None)
    except ValueError as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
    if args.json:
        print(rendered)
    else:
        status = "PASS" if report["success"] else "FAIL"
        workload = report["workload"]
        metrics = report["metrics"]
        print(
            f"worker soak {status}: {workload['tasks']} tasks, {workload['workers']} workers, "
            f"{metrics['elapsed_seconds']}s, {metrics['tasks_per_second']} tasks/s"
        )
        for name, passed in report["invariants"].items():
            print(f"  {'ok' if passed else 'FAIL'} {name}")
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
