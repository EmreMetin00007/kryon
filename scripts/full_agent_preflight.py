#!/usr/bin/env python3
"""Freeze a Python workflow contract and test local prerequisites.

This command never calls an LLM or starts the benchmark. Readiness is not
acceptance. The private evaluator and the solver must not share a host root,
host /tmp, prior sessions, or the lab source tree.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

from http_chromium_acceptance import assess_results, preflight as browser_preflight
import llm_config

from runtime_paths import runtime_root

ROOT = runtime_root()
SCHEMA = "full-agent-preflight/1"
MAX_REQUESTS = 300
MAX_SECONDS = 1800
MAX_LLM_TOKENS = 1_000_000
SERVERS = ("hunter", "validator", "browser", "kali-tools", "memory-server", "reasoning", "telemetry")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def baseline_reference(directory):
    """Require the measured comparison, not a caller's summary or a mock run."""
    directory = Path(directory).resolve(strict=True)
    path = directory / "acceptance.json"
    record = json.loads(path.read_text())
    verified = assess_results(directory / "junit.xml", directory / "tests")
    if (record.get("status") != "passed" or record.get("pytest_exit_code") != 0
            or any(record.get(key) != verified[key] for key in ("tests", "runs"))):
        raise ValueError("baseline manifest does not match its saved measurements")
    if any(row.get("lab_version") != "blind-lab/3" or row["score"]["proven"] != 8
           for row in verified["runs"]):
        raise ValueError("the comparison requires the measured blind-lab/3 baseline")
    return {"manifest": str(path), "sha256": sha256(path),
            "junit_sha256": sha256(directory / "junit.xml"),
            "solver": "deterministic_http_chromium_campaign",
            "lab_version": "blind-lab/3", "seeds": [row["seed"] for row in verified["runs"]],
            "requests_per_seed": [row["requests"] for row in verified["runs"]],
            "positives_per_seed": 8, "negatives_per_seed": 8}


def model_selection(config, model="", worker_model=""):
    """Inspect names only; provider credentials never enter the manifest."""
    data = json.loads(Path(config).read_text())
    if data.get("schema") == llm_config.SCHEMA:
        return llm_config.model_selection(config, model, worker_model)
    from full_agent_native_compat import native_model_selection
    return native_model_selection(data, model, worker_model)


def runtime_file(path):
    """Allow runtime code without evaluator, test, history or state inputs."""
    parts = path.parts
    if any(part in {"tests", "test", "lab", "docs", ".git", "__pycache__", "archive", "node_modules"}
           for part in parts):
        return False
    if path.name.startswith(("test_", "seed_", "blind", "http_chromium", "full_agent", "negative-control", "lab-validate", "worker_soak")):
        return False
    if parts[0] == "scripts":
        return path.suffix in {".py", ".sh"}
    if parts[0] == "mcp-servers":
        return len(parts) > 2 and parts[1] in {"mcp-" + name for name in SERVERS} and path.suffix in {".py", ".json", ".txt"}
    if parts[0] in {"config", "rules"}:
        return path.suffix in {".json", ".md"} and "program-profiles" not in parts
    if parts[:2] == (".claude", "skills"):
        return path.suffix in {".md", ".py", ".json"}
    return path.as_posix() in {"pyproject.toml", "AGENTS.md", "CLAUDE.md",
                              ".opencode/agents/kalibounty.md", ".opencode/agents/worker.md",
                              ".opencode/plugins/security-gate.js"}


def prepare_runtime(directory, models, provider_config=None):
    """Stage a read-only runtime snapshot, never a copy of the whole checkout.

    Scope starts empty. The snapshot is not a runnable benchmark until the
    operator launcher supplies scoped sessions and metered host interfaces.
    """
    from full_agent_native_compat import prepare_native_runtime
    return prepare_native_runtime(
        directory,
        models,
        provider_config,
        root=ROOT,
        runtime_file=runtime_file,
        sha256=sha256,
    )


def prepare_python_runtime(directory, models, provider_config):
    """Freeze Python/MCP code and a secret-free provider route, without a client.

    Neither agent prompts, client plugins nor client configuration are copied.
    The model receives tool schemas and bounded evidence, never this bundle.
    """
    provider = llm_config.snapshot(provider_config, models)
    runtime = Path(directory) / "runtime"
    runtime.mkdir()
    files = []
    for folder in ("scripts", "mcp-servers", "config"):
        for path in sorted((ROOT / folder).rglob("*")):
            relative = path.relative_to(ROOT)
            if (not path.is_file() or path.is_symlink() or not runtime_file(relative)
                    or path.name in {"llm.json", "llm.example.json"}
                    or "opencode" in path.name):
                continue
            if any(parent.is_symlink() for parent in path.parents if parent != ROOT and ROOT in parent.parents):
                raise ValueError("runtime source contains a symlinked parent")
            target = runtime / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
            files.append({"path": relative.as_posix(), "source_sha256": sha256(path), "sha256": sha256(target)})
    generated = {
        "config/llm.json": provider,
        ".codex/scope.json": {"in_scope": [], "allow_loopback": False, "allow_osint": False, "allow_public_labs": False},
        ".codex/program-policy.json": {"denied_tools": ["*"]},
    }
    for name, data in generated.items():
        target = runtime / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, indent=2) + "\n")
        files.append({"path": name, "sha256": sha256(target), "generated": True})
    index = Path(directory) / "runtime-index.json"
    index.write_text(json.dumps({"schema": "full-agent-runtime-snapshot/1", "runnable": False,
                                "models": models, "files": sorted(files, key=lambda row: row["path"])}, indent=2) + "\n")
    for path in [*runtime.rglob("*"), runtime]:
        path.chmod(0o555 if path.is_dir() else 0o444)
    return {"path": str(runtime), "index": str(index), "index_sha256": sha256(index),
            "files": len(files), "runnable": False}


def isolation_command(workdir, command, *, bwrap, opencode=None, workspace="/workspace"):
    """Construct an allowlisted root, with no host root, /root or /tmp bind.

    This is the prerequisite probe, not the native-agent launch command.
    A later launcher must additionally mount only a sanitized runtime bundle
    and host-custodied MCP interfaces; this probe cannot attest that launcher.
    """
    workdir = Path(workdir).resolve(strict=True)
    if not workdir.is_dir() or workdir == ROOT or ROOT in workdir.parents:
        raise ValueError("solver workdir must be outside the code repository")
    if not command:
        raise ValueError("an explicit isolated command is required")
    if workspace != "/workspace" and workspace != str(workdir):
        raise ValueError("workspace mount must preserve the workdir or use /workspace")
    args = [str(bwrap), "--die-with-parent", "--new-session", "--cap-drop", "ALL",
            "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--clearenv"]
    # Executables and libraries, without /usr/share or /usr/local/share copies
    # of the project, benchmarks or documentation.
    for path in ("/usr/bin", "/usr/lib", "/usr/lib64", "/usr/local/bin", "/usr/local/lib"):
        if Path(path).is_dir():
            args += ["--ro-bind", path, path]
    for name in ("bin", "sbin", "lib", "lib64"):
        entry = Path("/" + name)
        if entry.is_symlink():
            args += ["--symlink", os.readlink(entry), str(entry)]
        elif entry.is_dir():
            args += ["--ro-bind", str(entry), str(entry)]
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
             "--dir", "/home/solver", "--bind", str(workdir), workspace,
             "--chdir", workspace, "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
             "--setenv", "PYTHONNOUSERSITE", "1"]
    if opencode:
        args += ["--ro-bind", str(Path(opencode).resolve(strict=True)), "/opt/opencode"]
    return [*args, "--", *command]


def check_isolation(directory, bwrap, opencode):
    """Probe real read denial and a fresh process namespace, without an LLM."""
    directory = Path(directory)
    work = directory / "solver-probe"
    work.mkdir()
    nonce = secrets.token_hex(16)
    (work / "allowed.txt").write_text(nonce)
    private = directory / "evaluator-probe.txt"
    private.write_text("synthetic evaluator sentinel")
    probe = (
        "import json,os,pathlib; "
        "p=pathlib.Path; "
        f"hidden=[{str(private)!r},{str(ROOT)!r},{str(directory)!r}]; "
        "assert all(not p(x).exists() for x in hidden); "
        "assert not p('/proc/1/root'+hidden[0]).exists(); "
        "assert not p('/root/.codex').exists(); "
        "assert 'CCO_PREFLIGHT_HOST_SENTINEL' not in os.environ; "
        f"assert p('/workspace/allowed.txt').read_text()=={nonce!r}; "
        "p('/workspace/writable.txt').write_text('ok'); "
        f"print(json.dumps({{'nonce':{nonce!r},'host_paths_hidden':True,'workspace_writable':True}}))"
    )
    env = dict(os.environ, CCO_PREFLIGHT_HOST_SENTINEL="must-not-cross")
    command = isolation_command(work, ["python3", "-I", "-c", probe], bwrap=bwrap, opencode=opencode)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, env=env)
        proof = json.loads(result.stdout) if result.returncode == 0 else {}
        ok = (result.returncode == 0 and proof == {"nonce": nonce, "host_paths_hidden": True,
                                                  "workspace_writable": True}
              and (work / "writable.txt").read_text() == "ok")
        return {"name": "isolated_solver_namespace", "ok": ok,
                "exit_code": result.returncode, "error": result.stderr.strip()[:300] if not ok else "",
                "proof": {key: value for key, value in proof.items() if key != "nonce"}}
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return {"name": "isolated_solver_namespace", "ok": False, "error": type(exc).__name__}


def native_contract(baseline, models, token_budget=MAX_LLM_TOKENS, *, solver_mode="native", seconds_budget=None,
                    http_budget=MAX_REQUESTS):
    """Private operator contract. It must never be supplied as a solver prompt."""
    if token_budget is not None and (type(token_budget) is not int or token_budget <= 0):
        raise ValueError("token budget must be a positive integer")
    if solver_mode not in {"native", "python_loop"}:
        raise ValueError("unsupported solver mode")
    seconds = seconds_budget if seconds_budget is not None else (900 if solver_mode == "python_loop" else MAX_SECONDS)
    if type(seconds) is not int or not 0 < seconds <= MAX_SECONDS:
        raise ValueError("seconds budget must be positive and within the supported ceiling")
    if type(http_budget) is not int or not 0 < http_budget <= MAX_REQUESTS:
        raise ValueError("HTTP request budget must be positive and within the supported ceiling")
    if solver_mode == "native" and (seconds != MAX_SECONDS or http_budget != MAX_REQUESTS):
        raise ValueError("native preflight uses its existing fixed deadline")
    contract = {
        "schema": "full-agent-contract/1", "visibility": "operator_only",
        "solver": "native_opencode_planner_worker", "baseline": baseline, "models": models,
        "limits": {"http_requests_per_seed": http_budget, "seconds_per_seed": seconds,
                   "llm_tokens_per_seed": token_budget,
                   "llm_tokens_total": token_budget * len(baseline.get("seeds", [])) if token_budget else None,
                   "token_accounting": "prompt_tokens + completion_tokens; cached/reasoning subsets counted once",
                   "prompt_admission": {
                       "profile": "min(UTF8 bytes, ceil(1.5 * local cl100k_base tokens)) + 2048",
                       "offline_fallback": "UTF8 bytes + 2048; no tokenizer download",
                       "scope": "text-only serialized JSON; engineering estimate, not provider tokenizer oracle",
                       "measured_overrun": "prompt or completion overrun retains full reservation and stops run"},
                   "budget_basis": "initial engineering ceiling, not measured optimal consumption"},
        "initial_solver_inputs": ["exact_start_url", "scope_and_readonly_policy",
                                  "synthetic_session_references", "budgets"],
        "excluded_solver_inputs": ["truth", "lab_source", "tests", "docs", "graphify-out", ".git",
                                   "prior_sessions", "prior_results", "seed", "expected_case_count"],
        "required_evidence": ["fresh_native_session_id", "planner_and_worker_model_ids",
                              "native_task_delegation_events", "tool_execution_artifacts",
                              "signed_current_validation_and_coverage", "signed_gate_closure",
                              "server_request_accounting", "llm_usage_and_cost",
                              "contract_repair_count", "wall_clock_duration", "runtime_bundle_hash"],
        "acceptance": {"positives_per_seed": 8, "clean_negatives_per_seed": 8,
                       "false_positives": 0, "closure_verified": True,
                       "unknown_cost_is_zero": False, "model_prose_is_evidence": False},
        "holdout": {"status": "not_evaluated", "minimum_families": 3,
                    "minimum_positives": 24, "minimum_negatives": 24,
                    "overall_recall": 0.70, "per_family_recall": 0.50, "negative_coverage": 0.90,
                    "seed_variation_is_independent_family": False},
    }
    if solver_mode == "python_loop":
        contract.update(solver="python-workflow-v1", solver_mode=solver_mode)
        contract["required_evidence"] = [name for name in contract["required_evidence"]
                                         if name not in {"fresh_native_session_id", "native_task_delegation_events"}]
        contract["required_evidence"].extend(["python_phase_transitions", "signed_attempt_ledger", "host_handoff"])
    return contract


def holdout_policy_contract(family: str) -> dict:
    """Shared private-policy provisioning contract for holdout families."""
    from full_agent_holdout import private_policy_contract
    return private_policy_contract(family)


def provision_holdout_policy(**kwargs) -> dict:
    """Delegate private holdout policy provisioning to the single shared contract."""
    from full_agent_holdout import provision_private_policy
    return provision_private_policy(**kwargs)


def python_host_inventory():
    """Freeze host code too: the Python model never receives these bytes."""
    paths = list((ROOT / "scripts").glob("*.py"))
    paths.extend((ROOT / "mcp-servers").rglob("*.py"))
    paths.extend(ROOT / "config" / name for name in ("tool-capabilities.json", "mcp-core-tools.json"))
    return {path.relative_to(ROOT).as_posix(): sha256(path) for path in sorted(paths)
            if path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--model", default="")
    parser.add_argument("--worker-model", default="")
    parser.add_argument("--provider-config", type=Path, default=llm_config.default_config(),
                        help="operator-owned provider configuration; credentials are not copied")
    parser.add_argument("--token-budget", type=int, default=None)
    parser.add_argument("--solver-mode", choices=("native", "python_loop"), default="python_loop")
    parser.add_argument("--seconds-budget", type=int, default=None)
    parser.add_argument("--http-budget", type=int, default=MAX_REQUESTS)
    parser.add_argument("--holdout-family", default="", help="registered host-only independent family")
    parser.add_argument("--holdout-seed", type=int, default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/cco-work/full-agent-preflight"))
    args = parser.parse_args(argv)
    output, baseline = args.output_dir.expanduser().resolve(), args.baseline.expanduser().resolve()
    if (output == ROOT or ROOT in output.parents or output == baseline or baseline in output.parents
            or output in baseline.parents):
        parser.error("output must be outside the repository and separate from baseline evidence")
    try:
        reference = baseline_reference(baseline)
        select = llm_config.model_selection if args.solver_mode == "python_loop" else model_selection
        models = select(args.provider_config, args.model, args.worker_model)
        contract = native_contract(reference, models, args.token_budget,
                                   solver_mode=args.solver_mode, seconds_budget=args.seconds_budget,
                                   http_budget=args.http_budget)
        if args.holdout_family or args.holdout_seed is not None:
            from full_agent_holdout import selection
            contract["holdout_run"] = selection(args.holdout_family, args.holdout_seed)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="preflight-", dir=output))
    contract_path = directory / "contract.json"
    contract_path.write_text(json.dumps(contract, indent=2) + "\n")
    prepare = prepare_python_runtime if args.solver_mode == "python_loop" else prepare_runtime
    snapshot = prepare(directory, models, args.provider_config)
    checks = []
    opencode = bwrap = None
    if args.solver_mode == "native":
        opencode, bwrap = shutil.which("opencode"), shutil.which("bwrap")
        for name, binary in (("opencode_binary", opencode), ("bubblewrap_binary", bwrap)):
            checks.append({"name": name, "ok": bool(binary)})
    else:
        checks.append({"name": "python_runtime", "ok": bool(sys.executable)})
    checks += browser_preflight()
    if args.solver_mode == "native" and bwrap and opencode:
        checks.append(check_isolation(directory, bwrap, opencode))
    prerequisites = all(check["ok"] for check in checks)
    status = ("environment_unavailable" if not prerequisites else "configuration_required"
              if args.token_budget is None else "prerequisites_ready")
    manifest = {"schema": SCHEMA, "mode": "preflight_only", "status": status,
                "created_at": datetime.now(timezone.utc).isoformat(), "checks": checks,
                "contract": str(contract_path), "contract_sha256": sha256(contract_path),
                "runtime_snapshot": snapshot,
                "llm_calls": 0, "target_requests": 0, "acceptance_passed": False,
                "launcher": "scripts/full_agent_launcher.py",
                "remaining": ["native launcher isolation and metering validation in a socket/namespace-capable environment",
                              "native run and signed closure audit",
                              "independent holdout families"]}
    if args.holdout_family:
        manifest["policy_provisioning"] = holdout_policy_contract(args.holdout_family)
    if args.token_budget is None:
        manifest["remaining"].insert(0, "operator LLM token budget")
    if args.solver_mode == "python_loop":
        manifest.update(solver_mode=args.solver_mode, host_runtime=python_host_inventory())
        manifest["remaining"] = ["Python workflow run and signed closure audit", "independent holdout families"]
    path = directory / "preflight.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": status, "artifact": str(path), "llm_calls": 0, "acceptance_passed": False}))
    return 2 if not prerequisites else 3 if args.token_budget is None else 0


if __name__ == "__main__":
    raise SystemExit(main())
