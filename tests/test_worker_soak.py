import importlib.util
import os
import sys
import threading
import time


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_soak():
    path = os.path.join(REPO_ROOT, "scripts", "worker_soak.py")
    spec = importlib.util.spec_from_file_location("worker_soak_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_synthetic_soak_validates_concurrency_and_stale_recovery(tmp_path):
    mod = _load_soak()
    config = mod.SoakConfig(
        tasks_per_round=24,
        workers=4,
        stale_claims=3,
        executor="synthetic",
        max_tasks=24,
        timeout_seconds=20,
        synthetic_delay_ms=2,
    )

    report = mod.run_soak(config, tmp_path / ".cco")

    assert report["success"] is True
    assert report["workload"]["tasks"] == 24
    assert report["workload"]["simulated_stale_claims"] == 3
    assert report["events"]["recovered_stale"] == 3
    assert report["events"]["completed"] == 24
    assert all(report["invariants"].values())
    assert report["max_attempts"] == 2
    assert report["requests_used"] == 24


def test_local_mcp_soak_exercises_offline_subprocess_executor(tmp_path):
    mod = _load_soak()
    config = mod.SoakConfig(
        tasks_per_round=4,
        workers=2,
        stale_claims=0,
        executor="local-mcp",
        max_tasks=4,
        timeout_seconds=30,
        execution_timeout_seconds=10,
    )

    report = mod.run_soak(config, tmp_path / ".cco")

    assert report["success"] is True
    assert report["workload"]["executor"] == "local-mcp"
    assert report["status_counts"] == {"done": 4}
    assert report["invariants"]["sqlite_integrity"] is True
    assert report["requests_used"] == 0 and report["invariants"]["budget_settled"]


def test_duration_soak_runs_multiple_bounded_rounds(tmp_path):
    mod = _load_soak()
    config = mod.SoakConfig(
        tasks_per_round=4,
        workers=2,
        stale_claims=0,
        duration_seconds=0.05,
        max_tasks=20,
        executor="synthetic",
        timeout_seconds=20,
        synthetic_delay_ms=1,
    )

    report = mod.run_soak(config, tmp_path / ".cco")

    assert report["success"] is True
    assert 4 <= report["workload"]["tasks"] <= 20
    assert report["workload"]["rounds"] >= 1


def test_soak_timeout_terminates_active_executor(tmp_path, monkeypatch):
    mod = _load_soak()

    class HangingExecutor:
        def __init__(self):
            self.stopped = threading.Event()

        def __call__(self, _task):
            self.stopped.wait(30)
            raise TimeoutError("terminated")

        def terminate(self):
            self.stopped.set()

    executors = []

    def factory(_config, _home):
        executor = HangingExecutor()
        executors.append(executor)
        return executor

    monkeypatch.setattr(mod, "_executor_for", factory)
    config = mod.SoakConfig(
        tasks_per_round=1,
        workers=1,
        stale_claims=0,
        executor="synthetic",
        max_tasks=1,
        timeout_seconds=0.2,
    )

    started = time.monotonic()
    report = mod.run_soak(config, tmp_path / ".cco")

    assert time.monotonic() - started < 3
    assert report["success"] is False
    assert executors and executors[0].stopped.is_set()
    assert any("timeout" in error for error in report["errors"])
