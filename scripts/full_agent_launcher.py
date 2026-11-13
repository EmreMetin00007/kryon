#!/usr/bin/env python3
"""Launch one bounded Python workflow from a verified preflight snapshot.

The default is offline inspection. --execute explicitly starts an owned lab
and paid model calls. This launcher collects evidence; it never grants full
agent acceptance or substitutes a deterministic campaign for the planner.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

import full_agent_preflight as preflight
import llm_config
from full_agent_budget import SharedBudget
from full_agent_executor import CATALOG
from full_agent_provider import dump

from runtime_paths import runtime_root

ROOT = runtime_root()
SCHEMA = "full-agent-launch/1"


def __getattr__(name):
    if name in {"BRIDGE_URL", "LOCAL_TOOLS", "NATIVE_PLANNER", "NATIVE_POLICY", "NATIVE_WORKER"}:
        from full_agent_native_compat import (BRIDGE_URL, LOCAL_TOOLS, NATIVE_PLANNER,
                                              NATIVE_POLICY, NATIVE_WORKER)
        return {
            "BRIDGE_URL": BRIDGE_URL,
            "LOCAL_TOOLS": LOCAL_TOOLS,
            "NATIVE_PLANNER": NATIVE_PLANNER,
            "NATIVE_POLICY": NATIVE_POLICY,
            "NATIVE_WORKER": NATIVE_WORKER,
        }[name]
    if name == "Broker":
        from full_agent_native_compat import NativeBrokerCompat
        return NativeBrokerCompat
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def prepared_run(path):
    """Replay the baseline and every frozen byte before enabling transports."""
    path = Path(path).expanduser().resolve(strict=True)
    if path.is_dir():
        path = path / "preflight.json"
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != preflight.SCHEMA or manifest.get("mode") != "preflight_only":
        raise ValueError("a native preflight manifest is required")

    def artifact(name, digest):
        raw = Path(name)
        resolved = raw.resolve(strict=True)
        if raw.is_symlink() or path.parent not in resolved.parents or preflight.sha256(resolved) != digest:
            raise ValueError("preflight artifact is outside its directory or has changed")
        return resolved

    contract_path = artifact(manifest["contract"], manifest["contract_sha256"])
    contract = json.loads(contract_path.read_text())
    solver_mode = contract.get("solver_mode", "native")
    supported = {"native": "native_opencode_planner_worker", "python_loop": "python-workflow-v1"}
    if contract.get("schema") != "full-agent-contract/1" or contract.get("solver") != supported.get(solver_mode):
        raise ValueError("unsupported native contract")
    reference = preflight.baseline_reference(Path(contract["baseline"]["manifest"]).parent)
    if reference != contract["baseline"]:
        raise ValueError("baseline evidence changed since preflight")
    tokens = contract["limits"]["llm_tokens_per_seed"]
    options = ({"solver_mode": solver_mode, "seconds_budget": contract["limits"]["seconds_per_seed"],
                "http_budget": contract["limits"]["http_requests_per_seed"]}
               if solver_mode == "python_loop" else {})
    expected = preflight.native_contract(reference, contract["models"], tokens, **options)
    if solver_mode == "python_loop" and manifest.get("host_runtime") != preflight.python_host_inventory():
        raise ValueError("Python host runtime changed since preflight")
    if "holdout_run" in contract:
        from full_agent_holdout import replay, selection
        selected = contract["holdout_run"]
        replay(selected)
        expected["holdout_run"] = selection(selected["family"], selected["seed"])
    if contract != expected:
        raise ValueError("native contract does not match the supported limits and evidence requirements")
    snapshot = manifest["runtime_snapshot"]
    index_path = artifact(snapshot["index"], snapshot["index_sha256"])
    index = json.loads(index_path.read_text())
    runtime = Path(snapshot["path"]).resolve(strict=True)
    if (runtime != path.parent / "runtime" or Path(snapshot["path"]).is_symlink()
            or index.get("schema") != "full-agent-runtime-snapshot/1"
            or index.get("runnable") is not False or index.get("models") != contract["models"]):
        raise ValueError("invalid closed runtime snapshot")
    allowed_generated = {".codex/scope.json", ".codex/program-policy.json"}
    if solver_mode != "python_loop":
        allowed_generated.add("opencode.json")
    listed = set()
    for row in index["files"]:
        relative = Path(row["path"])
        if (not relative.parts or relative.is_absolute() or ".." in relative.parts or row["path"] in listed
                or not (preflight.runtime_file(relative) or relative.as_posix() in allowed_generated)):
            raise ValueError("invalid runtime inventory")
        target = runtime / relative
        if target.is_symlink() or any(parent.is_symlink() for parent in target.parents if parent != runtime and runtime in parent.parents):
            raise ValueError("runtime snapshot contains a symlink")
        if not target.is_file() or preflight.sha256(target) != row["sha256"]:
            raise ValueError("runtime file changed since preflight")
        listed.add(row["path"])
    actual = set()
    for target in runtime.rglob("*"):
        if target.is_symlink():
            raise ValueError("runtime snapshot contains a symlink")
        if target.is_file():
            actual.add(target.relative_to(runtime).as_posix())
    if actual != listed or len(listed) != snapshot["files"]:
        raise ValueError("runtime inventory is incomplete")
    return {"manifest": manifest, "manifest_path": path, "contract": contract,
            "runtime": runtime, "index": index}


def provider_settings(config, models):
    """Only one configured OpenAI-compatible provider crosses the broker."""
    data = json.loads(Path(config).read_text())
    if data.get("schema") == llm_config.SCHEMA:
        return llm_config.provider_settings(config, models)
    from full_agent_native_compat import native_provider_settings
    return native_provider_settings(data, models)


def lab_policy(base):
    url = urlsplit(base)
    if (url.scheme != "http" or url.hostname != "127.0.0.1" or not url.port
            or url.path != "/" or url.username or url.password or url.query or url.fragment):
        raise ValueError("launcher scope must be the exact owned loopback origin")
    scope = {"in_scope": [{"asset": base}], "scope_policy": "explicit_only", "blind_mode": True,
             "allow_loopback": False, "allow_osint": False, "allow_public_labs": False}
    policy = {"blind_mode": True, "blocked_http_methods": ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"],
              "background_network_jobs": "deny", "fuzz_max_requests_per_call": preflight.MAX_REQUESTS,
              "time_budget_max_seconds": preflight.MAX_SECONDS,
              "blind_discovery": {"synthetic_accounts_only": True, "owned_objects_private": True},
              "xss_execution": {"enabled": True, "max_browser_requests": 8, "wait_ms": 0}}
    return scope, policy


def verify_lab_scope(runtime, base):
    """Check the staged exact origin and read-only policy before any traffic."""
    expected = lab_policy(base)
    paths = [Path(runtime) / ".codex" / name
             for name in ("scope.json", "program-policy.json")]
    for path, value in zip(paths, expected):
        if path.is_symlink() or json.loads(path.read_text()) != value:
            raise ValueError("staged owned-lab scope/policy mismatch")
    return {"target": base, "exact_origin_verified": True, "before_traffic": True,
            "files": {str(path): preflight.sha256(path) for path in paths}}


def stage_runtime(prepared, directory, base):
    """Copy the frozen bundle, then replace only launcher-owned configuration."""
    if prepared["contract"].get("solver_mode") == "python_loop":
        return stage_python_runtime(prepared, directory, base)
    from full_agent_native_compat import stage_native_runtime
    return stage_native_runtime(
        prepared,
        directory,
        base,
        root=ROOT,
        lab_policy=lab_policy,
        sha256=preflight.sha256,
        max_seconds=preflight.MAX_SECONDS,
    )


def stage_python_runtime(prepared, directory, base):
    """Prepare only the host-owned Python runtime and exact loopback policy."""
    runtime = Path(directory) / "runtime"
    shutil.copytree(prepared["runtime"], runtime)
    for path in [runtime, *runtime.rglob("*")]:
        path.chmod(0o700 if path.is_dir() else 0o600)
    scope, policy = lab_policy(base)
    dump(runtime / ".codex/scope.json", scope)
    dump(runtime / ".codex/program-policy.json", policy)
    index = Path(directory) / "runtime-index.json"
    dump(index, {"schema": "full-agent-runtime-snapshot/1", "runnable": True,
                 "models": prepared["contract"]["models"],
                 "source_index_sha256": prepared["manifest"]["runtime_snapshot"]["index_sha256"],
                 "files": [{"path": path.relative_to(runtime).as_posix(), "sha256": preflight.sha256(path)}
                           for path in sorted(runtime.rglob("*")) if path.is_file()]})
    for path in [*runtime.rglob("*"), runtime]:
        path.chmod(0o555 if path.is_dir() else 0o444)
    return runtime, index


def bootstrap_plan(base, workdir, *, solver_mode="native"):
    from brain import build_plan
    specs = build_plan(base, str(workdir), tool_profile="broker")
    for spec in specs:
        spec.scope_ref = str(Path(workdir).parent / "runtime/.codex/scope.json")
        if spec.phase == 'recon':
            spec.max_calls = 10
    for spec in specs:
        if spec.phase == 'access' and 'validator_session_vault_check' not in spec.tools:
            spec.tools.append('validator_session_vault_check')
            spec.commands.insert(0, 'Refresh supplied session references with validator_session_vault_check before LIVE.')
    if solver_mode == "python_loop":
        from full_agent_python_broker import PHASE_CALL_LIMITS, REPORT_CARRYOVER_STEP
        from orchestration_spec import Step
        goals = {"recon": [("fetch-entry", "Fetch the scoped entry point and retain its HTTP response", False)],
                 "enum": [("discover-surface", "Inventory observed routes and parameters; fetch any listed documentation", False)],
                 "access": [("minimal-validation", "Validate a candidate with the supplied deterministic tools", False),
                            ("broader-coverage", "Record remaining untested vectors explicitly", True)],
                 "report": [("review-evidence", "Review the verified phase summaries and signed evidence", False),
                            (REPORT_CARRYOVER_STEP, "Host preserves unfinished work from verified prior summaries", True)]}
        for spec in specs:
            spec.max_calls = PHASE_CALL_LIMITS[spec.phase]
            spec.steps = [Step(id=ident, command=command, optional=optional)
                          for ident, command, optional in goals[spec.phase]]
    return specs


def make_server(path, broker):
    from full_agent_native_compat import make_server as native_make_server
    return native_make_server(path, broker)


def solver_prompt(base, workdir, bindings, limits):
    from full_agent_native_compat import solver_prompt as native_solver_prompt
    return native_solver_prompt(base, workdir, bindings, limits, bootstrap_plan=bootstrap_plan)


def launch_command(*, workdir, runtime, socket_path, public_trust, validations, nonce, prompt, bwrap, opencode):
    from full_agent_native_compat import launch_command as native_launch_command
    return native_launch_command(
        workdir=workdir,
        runtime=runtime,
        socket_path=socket_path,
        public_trust=public_trust,
        validations=validations,
        nonce=nonce,
        prompt=prompt,
        bwrap=bwrap,
        opencode=opencode,
        root=ROOT,
        host_policy_file=host_policy_file,
        isolation_command=preflight.isolation_command,
        sha256=preflight.sha256,
    )


def host_policy_file(home, runtime):
    private_policy = Path(home) / "holdout-program-policy.json"
    return private_policy if private_policy.exists() else Path(runtime) / ".codex/program-policy.json"


@contextmanager
def host_environment(home, workdir, runtime):
    """MCP children get fresh private state, never inherited provider credentials."""
    previous = dict(os.environ)
    kept = {key: value for key, value in previous.items()
            if key in {"PATH", "LANG", "LC_ALL", "PLAYWRIGHT_BROWSERS_PATH"}}
    os.environ.clear()
    os.environ.update(kept)
    os.environ.update({"CCO_HOME": str(home), "CCO_WORKDIR": str(workdir), "CCO_USE_KEYRING": "0",
                       "CCO_SCOPE_FILE": str(runtime / ".codex/scope.json"),
                       "CCO_PROGRAM_POLICY_FILE": str(host_policy_file(home, runtime)),
                       "CCO_GRAPH_BACKEND": "networkx", "CCO_HUNTER_ENABLE_LLM": "0",
                       "CCO_BLIND_MODE": "1", "CCO_HEADED": "0", "CCO_SURFACE_AUTO_INGEST": "1",
                       "NO_PROXY": "127.0.0.1,localhost"})
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def setup_sessions(broker, accounts, base, home):
    if not accounts:
        return {}
    from cco_surface_core import session_store
    bindings = {}
    for label, account in accounts.items():
        session_store.put_session(base, label, headers={"Authorization": "Bearer " + account["token"]},
                                  check_url=base, marker=label, home=str(home))
        session_store.bind_resources(base, label, {"role": account["role"]},
                                     permits=lambda url: url == base, home=str(home))
        result = broker.call_tool("validator", "session_vault_check", {"target": base, "identity": label}, origin="setup")
        checked = json.loads(result["content"][0]["text"])
        if result.get("isError") or checked.get("status") != "fresh":
            raise ValueError("synthetic session check failed")
        bindings[label] = {"target": base, "role": account["role"], "test_data_only": True,
                           "owned_objects_private": True}
    return bindings


def supervise(command, broker, private, *, startup_seconds=15):
    """Bound the native process tree and retain raw events even on interruption."""
    from full_agent_native_compat import supervise as native_supervise
    return native_supervise(command, broker, private, popen=subprocess.Popen, startup_seconds=startup_seconds)


def launch_seed(prepared, *, seed, output, provider, api_key, bwrap=None, opencode=None, timeout_seconds=None,
                observed_db=None, observation_context=None):
    from campaign_worker import LocalMCPExecutor
    from evidence_trust import prepare as prepare_trust
    from lab.blind_lab import serve
    from policy_engine import PolicyEngine

    check_seed(prepared["contract"], seed)
    solver_mode = prepared["contract"].get("solver_mode", "native")
    if solver_mode == "python_loop":
        frozen = llm_config.provider_settings(prepared["runtime"] / "config/llm.json", prepared["contract"]["models"])
        if any(provider.get(key) != frozen[key] for key in ("name", "url", "models", "api_key_header")):
            raise ValueError("provider routing changed since preflight")
    started = time.monotonic()
    limits = dict(prepared["contract"]["limits"])
    if timeout_seconds is not None:
        if type(timeout_seconds) is not int or not 0 < timeout_seconds <= limits["seconds_per_seed"]:
            raise ValueError("timeout must be positive and cannot exceed the frozen contract")
        limits["seconds_per_seed"] = timeout_seconds
    budget = SharedBudget(http=limits["http_requests_per_seed"], tokens=limits["llm_tokens_per_seed"],
                          seconds=limits["seconds_per_seed"])
    if solver_mode == "python_loop":
        from full_agent_python_broker import PythonBroker, PythonRuntimePolicy
        runtime_policy = PythonRuntimePolicy(budget)
        broker_type = PythonBroker
    else:
        from full_agent_native_compat import NativeBrokerCompat
        from full_agent_runtime_policy import RuntimePolicy
        runtime_policy = RuntimePolicy(budget)
        broker_type = NativeBrokerCompat
    limits['runtime_policy'] = runtime_policy.snapshot()
    directory = Path(tempfile.mkdtemp(prefix="python-" if solver_mode == "python_loop" else "native-", dir=output))
    private, workdir = directory / "private", directory / "solver"
    private.mkdir(mode=0o700)
    workdir.mkdir(mode=0o700)
    home = private / "state"
    home.mkdir(mode=0o700)
    # Redacted, signed artifacts are public to the solver. Keys and vaults
    # remain siblings of this directory and never enter the mount table.
    validations = home / "validations"
    validations.mkdir(mode=0o700)
    manifest = {"schema": SCHEMA, "status": "starting", "seed": seed, "acceptance_passed": False,
                "preflight": str(prepared["manifest_path"]), "models": prepared["contract"]["models"],
                "llm_cost_usd": None, "contract_repair_count": None, "holdout": "not_evaluated",
                "target_requests": 0,
                "effective_limits": limits,
                "token_reservation_basis": "2 tokens per UTF-8 JSON byte + 4096 framing + bounded output; engineering bound, not a tokenizer oracle"}
    manifest_path = directory / "launch.json"
    if solver_mode == "python_loop":
        manifest.update(solver_mode=solver_mode, solver="python-workflow-v1",
                        provider_kind="loopback" if urlsplit(provider["url"]).hostname in
                        {"127.0.0.1", "localhost", "::1"} else "remote")
    dump(manifest_path, manifest)
    lab = lab_thread = broker = None
    try:
        if "holdout_run" in prepared["contract"]:
            from full_agent_holdout import start
            selected = prepared["contract"]["holdout_run"]
            lab = start(selected, private)
            manifest["independent_family"] = selected["family"]
            manifest["lab_version"] = selected["lab_version"]
        else:
            lab = serve(seed, version=prepared["contract"]["baseline"]["lab_version"])
        base = f"http://127.0.0.1:{lab.server_port}/"
        runtime, index = stage_runtime(prepared, directory, base)
        dump(private / "scope-verification.json", verify_lab_scope(runtime, base))
        if lab.blind_state.get("lab_version") == "readonly-traversal/1":
            from lab.readonly_traversal_holdout import declaration
            sys.path.insert(0, str(ROOT / "mcp-servers/mcp-validator"))
            from cco_validator_core.traversal import application_files
            policy = lab_policy(base)[1]
            policy["path_traversal"] = declaration(lab.blind_state, base)
            # Only fixture declarations extend the unchanged public policy.
            # The solver mount retains the generic policy and no endpoint list.
            for case in lab.blind_state["truth"]:
                application_files(policy["path_traversal"], base.rstrip("/") + case["path"],
                                  case["param"], "query", lambda url: url.startswith(base))
            dump(home / "holdout-program-policy.json", policy)
            dump(private / "fixture-policy-verification.json", {
                "before_traffic": True, "declarations_validated": len(policy["path_traversal"]["files"]),
                "sha256": preflight.sha256(home / "holdout-program-policy.json"),
                "public_policy_unchanged": True, "host_only": True})
        from orchestration_spec import dump_specs
        specs = (bootstrap_plan(base, workdir, solver_mode=solver_mode)
                 if solver_mode == "python_loop" else bootstrap_plan(base, workdir))
        (workdir / "specs.json").write_text(dump_specs(specs))
        manifest.update(target=base, runtime_index=str(index), runtime_index_sha256=preflight.sha256(index))
        with host_environment(home, workdir, runtime):
            try:
                engine = PolicyEngine(cco_home=str(home), repo_root=str(runtime),
                                      scope_file=str(runtime / ".codex/scope.json"),
                                      program_policy_file=str(host_policy_file(home, runtime)))
                mcp_permissions = {group + "_" + tool: "allow" for group, names in CATALOG.items() for tool in names}
                if solver_mode != "python_loop":
                    from full_agent_native_compat import LOCAL_TOOLS as NATIVE_LOCAL_TOOLS
                    mcp_permissions = {**{tool: "allow" for tool in NATIVE_LOCAL_TOOLS}, **mcp_permissions}
                dump(home / "permissions.json", {"default": "deny", "tools": mcp_permissions})
                for group, names in CATALOG.items():
                    for tool in names:
                        engine.grant_approval(group + "_" + tool, "127.0.0.1", ttl_seconds=limits["seconds_per_seed"],
                                              reason="explicitly executed native benchmark; owned loopback only")
                trust = prepare_trust()
                broker = broker_type(budget=budget, engine=engine, executor=LocalMCPExecutor(home), workdir=workdir,
                                private=private, provider=provider["url"], models=provider["models"], api_key=api_key,
                                api_key_header=provider.get("api_key_header", "Authorization"))
                with (private / "setup.log").open("w") as log, redirect_stdout(log), redirect_stderr(log):
                    broker.load_catalog(home)
                    lab_thread = threading.Thread(target=lab.serve_forever, daemon=True)
                    lab_thread.start()
                    bindings = setup_sessions(broker, lab.blind_state["accounts"], base, home)
                if solver_mode == "python_loop":
                    from full_agent_tasks import TaskRegistry
                    broker.tasks = TaskRegistry(specs, workdir, bindings, setup_checks_passed=True)
                else:
                    from full_agent_tasks import NativeTasks
                    broker.tasks = NativeTasks(specs, workdir, bindings, setup_checks_passed=True)
                broker.runtime_policy = runtime_policy
                dump(private / "runtime-policy.json", broker.runtime_policy.snapshot())
                dump(private / "task-specs.json", [spec.to_dict() for spec in broker.tasks.specs])
                if solver_mode == "python_loop":
                    from full_agent_python_solver import PythonSolver
                    solver = PythonSolver(broker, model=prepared["contract"]["models"]["worker"].split("/", 1)[1],
                                          observed_db=observed_db, observation_context=observation_context)
                    manifest.update(solver.run())
                    manifest["schema"] = SCHEMA
                else:
                    manifest.update(run_native_session(broker, workdir, runtime, trust, validations,
                                                       base, bindings, limits, private, bwrap, opencode))
            finally:
                if broker is not None:
                    broker.close()
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
    except Exception as exc:
        manifest.update(status="launch_failed", error=type(exc).__name__)
    finally:
        if lab_thread is not None:
            lab.shutdown()
            lab_thread.join(timeout=5)
        if lab is not None:
            lab.server_close()
            manifest["target_requests"] = lab.blind_state["requests"]
            if "holdout_run" in prepared["contract"]:
                dump(private / "evaluator/wire.json", lab.blind_state["wire"])
            if lab.blind_state.get("db") is not None:
                lab.blind_state["db"].close()
            if lab.blind_state.get("fixtures") is not None:
                lab.blind_state["fixtures"].cleanup()
        manifest.update(budget=budget.snapshot(), llm_calls=broker.calls if broker else 0,
                        wall_clock_seconds=time.monotonic() - started)
        if broker is not None:
            dump(private / "tool-index.json", broker.tools)
            dump(private / "checkpoint-candidates.json", broker.checkpoints)
            if solver_mode != "python_loop":
                dump(private / "native-gates.json", broker.gates)
                manifest["native_session_ids"] = sorted({row["session_id"] for row in broker.gates if row.get("session_id")})
                manifest["native_delegations"] = sum(row["tool"] == "task" and row["allowed"] for row in broker.gates)
        dump(private / "budget.json", budget.snapshot())
        dump(manifest_path, manifest)
        if solver_mode == "python_loop":
            dump(directory / "manifest.json", manifest)
    return manifest_path, manifest


def resume_python_run(prepared, *, directory, seed, provider, api_key, timeout_seconds=None):
    """Resume the original workspace and grants, without recreating a target.

    A stopped ephemeral lab cannot be silently replaced with another instance.
    Missing/expired sessions and policy grants remain blocked by normal gates.
    """
    from campaign_worker import LocalMCPExecutor
    from full_agent_python_broker import PythonBroker
    from full_agent_python_solver import PythonSolver
    from full_agent_tasks import TaskRegistry
    from orchestration_spec import TaskSpec
    from policy_engine import PolicyEngine
    from workflow_checkpoint import WorkflowCheckpoint

    if prepared['contract'].get('solver_mode') != 'python_loop':
        raise ValueError('resume requires the Python engine')
    directory = Path(directory).expanduser().resolve(strict=True)
    if directory.name == 'checkpoint.json':
        directory = directory.parent.parent
    elif directory.name == 'solver':
        directory = directory.parent
    private, workdir, runtime = directory / 'private', directory / 'solver', directory / 'runtime'
    manifest_path = directory / 'launch.json'
    manifest = json.loads(manifest_path.read_bytes())
    if (manifest['seed'] != seed or manifest['preflight'] != str(prepared['manifest_path'])
            or manifest.get('solver_mode') != 'python_loop'):
        raise ValueError('resume run does not match preflight or seed')
    index_path = directory / 'runtime-index.json'
    if preflight.sha256(index_path) != manifest['runtime_index_sha256']:
        raise ValueError('resume runtime index changed')
    index = json.loads(index_path.read_bytes())
    for ref in index['files']:
        path = runtime / ref['path']
        if runtime not in path.resolve().parents or path.is_symlink() or preflight.sha256(path) != ref['sha256']:
            raise ValueError('resume runtime changed')
    frozen = llm_config.provider_settings(runtime / 'config/llm.json', prepared['contract']['models'])
    if any(provider.get(key) != frozen[key] for key in ('name', 'url', 'models', 'api_key_header')):
        raise ValueError('provider routing changed since preflight')
    limits = manifest['effective_limits']
    seconds = timeout_seconds or limits['seconds_per_seed']
    budget = SharedBudget(http=limits['http_requests_per_seed'], tokens=limits['llm_tokens_per_seed'], seconds=seconds)
    home = private / 'state'
    with host_environment(home, workdir, runtime):
        payload = WorkflowCheckpoint(workdir).read()
        context = payload['context']
        engine = PolicyEngine(cco_home=str(home), repo_root=str(runtime),
                              scope_file=str(runtime / '.codex/scope.json'),
                              program_policy_file=str(host_policy_file(home, runtime)))
        broker = PythonBroker(budget=budget, engine=engine, executor=LocalMCPExecutor(home), workdir=workdir,
                              private=private, provider=provider['url'], models=provider['models'], api_key=api_key,
                              api_key_header=provider.get('api_key_header', 'Authorization'))
        try:
            broker.tasks = TaskRegistry([TaskSpec.from_dict(row) for row in context['base_specs']],
                                      workdir, context['bindings'])
            with (private / 'resume-setup.log').open('a') as log, redirect_stdout(log), redirect_stderr(log):
                broker.load_catalog(home)
            solver = PythonSolver(broker, model=prepared['contract']['models']['worker'].split('/', 1)[1],
                                  observed_db=context['observed_db'], observation_context=context['observation_context'],
                                  resume=True)
            manifest.update(solver.run())
        finally:
            broker.close()
    manifest['schema'] = SCHEMA
    manifest['resumed'] = True
    dump(manifest_path, manifest)
    dump(directory / 'manifest.json', manifest)
    return manifest_path, manifest


def run_native_session(broker, workdir, runtime, trust, validations, base, bindings, limits, private, bwrap, opencode):
    from full_agent_native_compat import run_native_session as compat_run_native_session
    return compat_run_native_session(
        broker,
        workdir,
        runtime,
        trust,
        validations,
        base,
        bindings,
        limits,
        private,
        bwrap,
        opencode,
        make_server_fn=make_server,
        launch_command_fn=launch_command,
        solver_prompt_fn=solver_prompt,
        supervise_fn=supervise,
    )


def check_seed(contract, seed):
    """An independent selection never admits a comparison seed by accident."""
    if "holdout_run" in contract:
        from full_agent_holdout import replay
        replay(contract["holdout_run"], seed)
    elif seed not in contract["baseline"]["seeds"]:
        raise ValueError("seed is not part of the frozen comparison")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/cco-work/full-agent-runs"))
    parser.add_argument("--api-key-env", default=None)
    parser.add_argument("--provider-config", type=Path, default=llm_config.default_config(),
                        help="operator-owned provider configuration; models must match the frozen contract")
    parser.add_argument("--timeout-seconds", type=int,
                        help="shorten the frozen per-seed deadline (cannot increase it)")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument('--resume', nargs='?', const='latest', metavar='RUN_DIRECTORY',
                        help='resume an existing signed Python checkpoint; defaults to latest run in output-dir')
    parser.add_argument('--observed-db', type=Path, help='consume P5 observation plans within existing task permissions')
    parser.add_argument('--observation-context', help='select P5 observations from this exact policy context')
    parser.add_argument("--solver-mode", choices=("native", "python_loop"), default=None)
    args = parser.parse_args(argv)
    try:
        prepared = prepared_run(args.preflight)
        solver_mode = prepared["contract"].get("solver_mode", "native")
        if args.solver_mode is not None and args.solver_mode != solver_mode:
            raise ValueError("solver mode must match the frozen preflight contract")
        if args.resume and solver_mode != 'python_loop':
            raise ValueError('resume requires the Python engine')
        if args.resume and (args.observed_db or args.observation_context):
            raise ValueError('resume preserves the original observation context')
        check_seed(prepared["contract"], args.seed)
        if args.timeout_seconds is not None and not 0 < args.timeout_seconds <= prepared["contract"]["limits"]["seconds_per_seed"]:
            raise ValueError("timeout must be positive and cannot exceed the frozen contract")
        output = args.output_dir.expanduser().resolve()
        baseline = Path(prepared["contract"]["baseline"]["manifest"]).parent
        for protected in (ROOT, prepared["manifest_path"].parent, baseline):
            if output == protected or protected in output.parents or output in protected.parents:
                raise ValueError("output must be separate from repository, preflight and baseline evidence")
        if not args.execute:
            print(json.dumps({"status": "plan_only", "preflight_status": prepared["manifest"]["status"],
                              "llm_calls": 0, "target_requests": 0, "acceptance_passed": False}))
            return 0
        if prepared["contract"]["limits"]["llm_tokens_per_seed"] is None:
            raise ValueError("an explicit preflight token budget is required")
        if prepared["manifest"]["status"] != "prerequisites_ready":
            raise ValueError("rerun preflight in a socket/namespace-capable environment before execution")
        provider = provider_settings(args.provider_config, prepared["contract"]["models"])
        api_key = os.environ.get(args.api_key_env or provider.get("api_key_env", "CCO_BENCHMARK_API_KEY"), "")
        if not api_key:
            raise ValueError("provider credential is required in the selected environment variable")
        bwrap = opencode = None
        if solver_mode == "native":
            bwrap, opencode = shutil.which("bwrap"), shutil.which("opencode")
        if solver_mode == "native" and (not bwrap or not opencode):
            raise ValueError("bubblewrap and OpenCode are required")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    output.mkdir(parents=True, exist_ok=True)
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        options = {"timeout_seconds": args.timeout_seconds} if args.timeout_seconds is not None else {}
        if args.resume:
            directory = args.resume
            if directory == 'latest':
                candidates = list(output.glob('*/solver/checkpoint.json'))
                if not candidates:
                    parser.error('no checkpoint in output directory')
                directory = max(candidates, key=lambda path: path.stat().st_mtime_ns)
            path, manifest = resume_python_run(prepared, directory=directory, seed=args.seed,
                                                provider=provider, api_key=api_key, **options)
        else:
            if args.observed_db:
                options.update(observed_db=args.observed_db.expanduser().resolve(),
                               observation_context=args.observation_context)
            path, manifest = launch_seed(prepared, seed=args.seed, output=output, provider=provider, api_key=api_key,
                                         bwrap=bwrap, opencode=opencode, **options)
    finally:
        signal.signal(signal.SIGTERM, previous)
    summary = {"status": manifest["status"], "artifact": str(path), "llm_calls": manifest["llm_calls"],
               "acceptance_passed": False}
    if solver_mode == "python_loop" and manifest["status"] != "python_finished_verified":
        summary.update(stop_reason=manifest.get("stop_reason"), failure_phase=manifest.get("failure_phase"))
    print(json.dumps(summary))
    return 0 if manifest["status"] in {"native_finished_unverified", "python_finished_verified"} else 130 if manifest["status"] == "interrupted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
