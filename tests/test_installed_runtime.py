"""Build and smoke-test the wheel outside the source checkout without network."""
import json
import os
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from release_artifacts import _stage_release_source  # noqa: E402


def _run(args, *, cwd, env, timeout=90):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, (result.stdout + result.stderr)[-3000:]
    return result.stdout


def test_installed_wheel_exposes_all_servers_and_cli(tmp_path):
    pytest.importorskip("build")
    stage, dist = tmp_path / "source", tmp_path / "dist"
    _stage_release_source(stage)
    env = dict(os.environ, CCO_HOME=str(tmp_path / "home"), CCO_GRAPH_BACKEND="networkx",
               PIP_DISABLE_PIP_VERSION_CHECK="1")
    env.pop("PYTHONPATH", None)
    env.pop("CCO_VAULT_KEY", None)
    env["CCO_USE_KEYRING"] = "0"
    _run([sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(dist)],
         cwd=stage, env=env)
    wheels = list(dist.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        packaged = set(archive.namelist())
    for profile in (ROOT / "config" / "program-profiles").glob("*.json"):
        assert any(name.endswith("/config/program-profiles/" + profile.name) for name in packaged), profile.name
    for mod_name in ("full_agent_provider.py", "full_agent_executor.py", "full_agent_native_compat.py"):
        assert any(name.endswith("scripts/" + mod_name) for name in packaged), mod_name
    venv = tmp_path / "venv"
    _run([sys.executable, "-m", "venv", "--system-site-packages", str(venv)], cwd=tmp_path, env=env)
    py, bindir = venv / "bin" / "python", venv / "bin"
    _run([str(py), "-m", "pip", "install", "--no-deps", str(wheels[0])], cwd=tmp_path, env=env)
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test"}]}))
    env["CCO_SCOPE_FILE"] = str(scope)
    for cli in ("cco-agent", "cco-operator", "cco-campaign", "cco-worker", "cco-worker-soak", "cco-governance",
                "cco-policy", "cco-release-check", "cco-release-artifacts", "cco-rag-bootstrap",
                "cco-finding-migration", "cco-engagement"):
        _run([str(bindir / cli), "--help"], cwd=tmp_path, env=env)
    assert "--max-attempts" in _run([str(bindir / "cco-campaign"), "schedule-gaps", "--help"], cwd=tmp_path, env=env)
    assert "--run-id" in _run([str(bindir / "cco-campaign"), "resume-gaps", "--help"], cwd=tmp_path, env=env)
    assert "pytest" in _run([str(bindir / "cco-release-check"), "--list"], cwd=tmp_path, env=env)
    isolation = _run([str(bindir / "cco-engagement"), "--id", "synthetic", "--scope", str(scope),
                      "--home-root", str(tmp_path / "states"), "--work-root", str(tmp_path / "works")],
                     cwd=tmp_path, env=env)
    assert json.loads(isolation)["created"] is False
    (tmp_path / "config").mkdir()
    (tmp_path / "config/mcp-servers.json").write_text(json.dumps({"mcp": {"browser": {
        "type": "local", "command": ["python3", "server.py"], "enabled": True,
        "environment": {"CCO_HOME": ".cco"}}}}))
    inspect_env = ("import json,os; cfg=json.loads(os.environ['CCO_MCP_CONFIG_CONTENT']); "
                   "print(json.dumps({'home':os.environ['CCO_HOME'], "
                   "'server_home':cfg['mcp']['browser']['environment']['CCO_HOME']}))")
    launched = _run([str(bindir / "cco-engagement"), "--id", "synthetic", "--scope", str(scope),
                     "--home-root", str(tmp_path / "states"), "--work-root", str(tmp_path / "works"),
                     "--", str(py), "-c", inspect_env], cwd=tmp_path, env=env)
    assert json.loads(launched)["home"] == json.loads(launched)["server_home"]
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    with sqlite3.connect(home / "agent_memory.db") as conn:
        conn.execute("CREATE TABLE findings (id INTEGER PRIMARY KEY, target TEXT, type TEXT, "
                     "description TEXT, payload TEXT)")
        conn.executemany("INSERT INTO findings VALUES (?, ?, ?, ?, ?)", [
            (1, "https://owned.test:443/api/a", "xss", "same", "synthetic-marker"),
            (2, "https://owned.test/api/a", "xss", "same", "synthetic-marker"),
        ])
    preview = _run([str(bindir / "cco-finding-migration"), "--cco-home", str(home),
                    "--scope-file", str(scope), "--workdir", str(tmp_path / "run"),
                    "--engagement-id", "synthetic", "--ids", "1,2"], cwd=tmp_path, env=env)
    assert json.loads(preview)["groups"][0]["selected_ids"] == [1, 2]
    assert "synthetic-marker" not in preview
    script = tmp_path / "smoke_installed.py"
    script.write_text('''
import asyncio, base64, importlib.util, json, os, sys, time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
root = Path(sys.prefix) / "share" / "hackagent" / "mcp-servers"
results = {}
for path in sorted(root.glob("mcp-*/server.py")):
    name = path.parent.name
    spec = importlib.util.spec_from_file_location("installed_" + name.replace("-", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    results[name] = {"tools": len(asyncio.run(mod.mcp.list_tools()))}
    for flag in ("HAS_SURFACE", "HAS_FALLBACK", "HAS_SESSION", "HAS_RUNTIME_HOOKS",
                 "HAS_JS_CORE", "HAS_POSTEX"):
        if hasattr(mod, flag): results[name][flag] = bool(getattr(mod, flag))
    if name == "mcp-validator":
        store = mod._session_store()
        from cco_validator_core.oob_collector import verify_collector_event
        result = verify_collector_event({}, "{}", "{}", str(Path(os.environ["CCO_HOME"]) / "unused.db"),
                                        scope_revision="scope", policy_hash="policy")
        results[name]["oob_collector"] = result["authenticated"] is False
        target = "https://owned.test"
        store.put_session(target, "alice", cookies={"session": "installed-synthetic-secret"},
                          check_url=target + "/me", marker="installed-marker")
        status = store.refresh_status(target, "alice", lambda *_: (200, "installed-marker"))
        index = (Path(os.environ["CCO_HOME"]) / "session_vault.json").read_text()
        results[name]["encrypted_session"] = (status["status"] == "fresh"
            and bool(store.verified_session(target, "alice"))
            and "installed-synthetic-secret" not in index and "installed-marker" not in index)
        token = "ccossrf" + "a" * 24
        oob_target = target + "/fetch?url=installed-private-value"
        now = int(time.time())
        mod._store_oob_challenge(token, token + ".callback.test", oob_target, "SSRF", "url", "run-installed",
                                 now, "a" * 64, "b" * 64, "scope", "policy")
        oob_index = Path(mod._oob_challenge_path(token)).read_text()
        challenge = mod._load_oob_challenge(token)
        results[name]["encrypted_oob_challenge"] = ("installed-private-value" not in oob_index
            and challenge["target_url"] == oob_target)
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        encode = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
        event = {"schema": "cco-oob-collector-event/1", "collector_id": "installed-collector",
                 "event_id": "installed-event", "nonce": token, "host": token + ".callback.test",
                 "target_binding": "a" * 64, "probe_binding": "b" * 64, "param": "url",
                 "run_id": "run-installed", "scope_revision": "scope", "policy_hash": "policy",
                 "protocol": "dns", "observed_at": now}
        message = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        event["signature"] = encode(private.sign(message))
        verified = verify_collector_event(challenge, json.dumps(event),
                     json.dumps({"installed-collector": encode(public)}),
                     str(Path(os.environ["CCO_HOME"]) / "oob-replay.db"),
                     scope_revision="scope", policy_hash="policy")
        results[name]["oob_collector_verified"] = (verified["authenticated"]
            and Path(verified["event_path"]).is_file())
    if name == "mcp-hunter":
        import inspect
        from cco_hunter_core.campaign_gaps import load_request, versions
        from cco_hunter_core.gap_queue import gap_plan, plan_gaps
        target = "https://owned.test"
        item = {"url": target + "/search?q=installed-value", "method": "GET", "param": "q",
                "location": "query", "vuln_class": "sql_injection", "identity": "anonymous",
                "resource_owner": "unspecified", "run_id": "installed-run"}
        assert mod._record_coverage_plan(target, item)
        gap = {"endpoint": mod._coverage_url(item["url"]), "vuln_class": "sql_injection",
               **{key: mod._coverage_context(item)[key] for key in
                  ("method", "param", "carrier", "identity", "resource_owner", "run_id")}}
        reference = gap_plan(target, gap, versions()[0])[0]
        restored = load_request(mod.MEM_DB, mod.CCO_HOME, target, reference)
        results[name]["coverage_campaign_bridge"] = (restored["item"]["url"] == item["url"]
            and inspect.signature(mod.run_web_loop).parameters["gap_ref"].default == ""
            and inspect.signature(mod.coverage_report).parameters["campaign_id"].default == 0
            and inspect.signature(mod.coverage_report).parameters["max_attempts"].default == 3)
        from scripts.campaign_runtime import CampaignRuntime
        from cco_surface_core import session_store
        from policy_engine import ScopeResolver
        session_store.put_session(target, "alice", cookies={"sid": "installed-synthetic-secret"},
                                  check_url=target + "/me", marker="installed-account")
        check = lambda *_: (200, "installed-account")
        session_store.refresh_status(target, "alice", check)
        item = {**item, "identity": "alice", "run_id": "installed-session-run"}
        assert mod._record_coverage_plan(target, item)
        gap = {**gap, "identity": "alice", "run_id": "installed-session-run"}
        reference = plan_gaps(mod.MEM_DB, target, [gap], ScopeResolver(), versions()[0])[0][0]["fingerprint"]
        runtime = CampaignRuntime(os.environ["CCO_HOME"])
        runtime._policy_engine().grant_approval("hunter_run_web_loop", "owned.test", ttl_seconds=600, reason="installed synthetic")
        campaign = runtime.create_campaign("installed", scope_file=os.environ["CCO_SCOPE_FILE"], budget_requests=4)
        bindings = json.dumps({"alice": {"target": target, "test_data_only": True}})
        scheduled = runtime.schedule_coverage_gaps(campaign, target, session_bindings=bindings, request_cost=4,
                                                   run_id="installed-session-run")
        task = runtime.claim_next_task("installed-worker", campaign)
        runtime.block_task_with_permit(task["execution_permit"], "session unavailable", actual_request_cost=1,
            result={"coverage_gap": {"fingerprint": reference, "status": "inconclusive"},
                    "replan": {"status": "blocked", "automatic_retry": False, "actions": [{"category": "session"}]}})
        assert not runtime.resume_coverage_gaps(campaign, target)["resumed"]
        session_store.refresh_status(target, "alice", check)
        resumed = runtime.claim_next_task("installed-worker-2", campaign)
        results[name]["coverage_session_resume"] = (len(scheduled["scheduled"]) == 1
            and resumed["id"] == task["id"] and resumed["attempts"] == 2
            and resumed["reserved_request_cost"] == 3 and runtime.show_campaign(campaign)["requests_used"] == 1)
        from wire_budget import campaign_wire_budget
        from cco_validator_core.egress import egress_request
        from cco_browser_core.policy import install_readonly_request_gate
        class Response:
            status_code, text, content, headers = 200, "synthetic", b"synthetic", {}
        class Engine:
            def validate_wire_invocation(self, *args): return {"allowed": True}
        class CDPSession:
            def __init__(self): self.handlers = {}
            def send(self, method, params=None):
                info = {"targetId": "installed-owned", "browserContextId": "installed-context", "type": "page"}
                if method == "Target.getTargetInfo": return {"targetInfo": info}
                if method == "Target.getTargets": return {"targetInfos": [info]}
                if method == "Target.attachToTarget": return {"sessionId": "installed-session"}
                if method == "Target.sendMessageToTarget":
                    message = json.loads(params["message"])
                    self.handlers["Target.receivedMessageFromTarget"]({"sessionId": params["sessionId"],
                        "message": json.dumps({"id": message["id"], "result": {}})})
                return {}
            def on(self, event, handler): self.handlers[event] = handler
            def detach(self): pass
        class Context:
            pages = []
            def new_page(self): raise AssertionError("unused installed test page")
            def close(self): pass
            @property
            def browser(self): return self
            def new_browser_cdp_session(self): return CDPSession()
            def new_cdp_session(self, frame): return CDPSession()
            def on(self, *args): pass
            def route_web_socket(self, *args): pass
            def route(self, pattern, handler): self.handler = handler
        class Request:
            frame = type("Frame", (), {"page": None})()
            method, url = "GET", target
            def all_headers(self): return {}
        class Route:
            request = Request()
            def abort(self, *args): self.allowed = False
            def continue_(self, **kwargs): self.allowed = True
        context, route = Context(), Route()
        install_readonly_request_gate(context, Engine(), "browser_browser_extract_links")
        with campaign_wire_budget(2, "a" * 32) as counter:
            assert egress_request("GET", target, transport=lambda *a, **kw: Response())["ok"]
            context.handler(route)
            assert route.allowed
            blocked = egress_request("GET", target, transport=lambda *a, **kw: Response())
            results[name]["shared_wire_budget"] = (blocked["blocked"] == "budget"
                and counter.snapshot()["authorized_requests"] == 2)
        from scripts.campaign_worker import LocalMCPExecutor
        local = LocalMCPExecutor(os.environ["CCO_HOME"])
        score = local({"tool_name": "kali-tools_cvss_calculate", "args_json": "{}", "request_cost": 1})
        results[name]["native_wire_count"] = (score["actual_request_cost"] == 0
            and score["wire_usage"]["limit"] == 1)
print(json.dumps(results))
''')
    data = json.loads(_run([str(py), str(script)], cwd=tmp_path, env=env, timeout=90))
    assert len(data) == 16
    assert data["mcp-memory-server"]["tools"] == 15
    assert data["mcp-validator"]["encrypted_session"]
    assert data["mcp-validator"]["oob_collector"]
    assert data["mcp-validator"]["encrypted_oob_challenge"]
    assert data["mcp-validator"]["oob_collector_verified"]
    assert data["mcp-hunter"]["coverage_campaign_bridge"]
    assert data["mcp-hunter"]["coverage_session_resume"]
    assert data["mcp-hunter"]["shared_wire_budget"]
    assert data["mcp-hunter"]["native_wire_count"]
    assert all(data["mcp-kali-tools"][flag] for flag in ("HAS_SURFACE", "HAS_JS_CORE", "HAS_POSTEX"))
    assert all(data["mcp-browser"][flag] for flag in ("HAS_FALLBACK", "HAS_SESSION", "HAS_RUNTIME_HOOKS"))
    llm_cfg = tmp_path / "llm.json"
    llm_cfg.write_text(json.dumps({
        "schema": "cco-llm/1",
        "model": "owned/model",
        "providers": {"owned": {"base_url": "https://provider.invalid/v1", "models": ["model"], "api_key_env": "LOCAL_TEST_KEY"}},
    }))
    plan_work = tmp_path / "plan-work"
    plan_work.mkdir()
    checked = json.loads(_run([str(bindir / "cco-agent"), "check-config", "--provider-config", str(llm_cfg)], cwd=tmp_path, env=env))
    assert checked["status"] == "valid" and checked["model"] == "owned/model"
    planned = json.loads(_run([str(bindir / "cco-agent"), "plan", "--target", "https://owned.test", "--workdir", str(plan_work)], cwd=tmp_path, env=env))
    assert [row["id"] for row in planned] == ["recon-1", "enum-2", "access-3", "report-4"]
    isolated_py = tmp_path / "check_python_isolation.py"
    isolated_py.write_text(
        f"""
from pathlib import Path
import sys
import scripts
sys.path.insert(0, str(Path(scripts.__file__).resolve().parent))
for blocked in ('full_agent_native_compat', 'scripts.full_agent_native_compat', 'full_agent_broker', 'scripts.full_agent_broker'):
    sys.modules[blocked] = None
import agent_cli
import full_agent_provider
import full_agent_executor
import full_agent_python_broker
import full_agent_python_solver
import full_agent_preflight
import full_agent_launcher
import orchestration_spec
assert agent_cli.main(['check-config', '--provider-config', {str(llm_cfg)!r}]) == 0
assert agent_cli.main(['plan', '--target', 'https://owned.test', '--workdir', {str(plan_work)!r}]) == 0
for forbidden in ('full_agent_native_compat', 'scripts.full_agent_native_compat', 'full_agent_broker', 'scripts.full_agent_broker'):
    assert sys.modules.get(forbidden) is None, forbidden
"""
    )
    _run([str(py), str(isolated_py)], cwd=tmp_path, env=env)
