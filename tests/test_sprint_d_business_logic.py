"""Sprint D Slice 2 tests: stateful business-logic primitives, policy gating, and signed completions."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

import pytest

_VALIDATOR_DIR = Path(__file__).resolve().parents[1] / "mcp-servers/mcp-validator"
if str(_VALIDATOR_DIR) not in sys.path:
    sys.path.append(str(_VALIDATOR_DIR))

from conftest import load_server  # noqa: E402
import brain  # noqa: E402
import python_candidate_runtime as cand  # noqa: E402
import signed_completion  # noqa: E402
from cco_validator_core.evidence import artifact_is_current, current_scope_revision  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_python_broker import PythonBroker, PythonRuntimePolicy  # noqa: E402
from full_agent_python_solver import PythonSolver  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from test_full_agent_python_solver import terminal  # noqa: E402


def _make_biz_loopback_server():
    """Real loopback HTTP server exposing vulnerable, safe, broken-control, and decoy biz routes."""
    lock = threading.Lock()
    state: dict[str, dict] = {
        "objects": {
            "coupon-vuln": {"id": "coupon-vuln", "kind": "idempotency_replay", "uses": 0, "total": 100},
            "coupon-vuln-ctrl": {"id": "coupon-vuln-ctrl", "kind": "idempotency_replay", "uses": 0, "total": 100},
            "coupon-safe": {"id": "coupon-safe", "kind": "idempotency_replay", "uses": 0, "total": 100},
            "coupon-safe-ctrl": {"id": "coupon-safe-ctrl", "kind": "idempotency_replay", "uses": 0, "total": 100},
            "seq-vuln": {"id": "seq-vuln", "kind": "sequence_step_skip", "prepared": False, "status": "draft"},
            "seq-vuln-ctrl": {"id": "seq-vuln-ctrl", "kind": "sequence_step_skip", "prepared": False, "status": "draft"},
            "seq-safe": {"id": "seq-safe", "kind": "sequence_step_skip", "prepared": False, "status": "draft"},
            "seq-safe-ctrl": {"id": "seq-safe-ctrl", "kind": "sequence_step_skip", "prepared": False, "status": "draft"},
            "tag-vuln": {"id": "tag-vuln", "kind": "schema_symmetry", "title": "initial", "server_tag": "initial"},
            "tag-vuln-ctrl": {"id": "tag-vuln-ctrl", "kind": "schema_symmetry", "title": "initial", "server_tag": "initial"},
            "tag-safe": {"id": "tag-safe", "kind": "schema_symmetry", "title": "initial", "server_tag": "initial"},
            "tag-safe-ctrl": {"id": "tag-safe-ctrl", "kind": "schema_symmetry", "title": "initial", "server_tag": "initial"},
            "broken-ctrl": {"id": "broken-ctrl", "kind": "idempotency_replay", "uses": 0, "total": 100},
            "broken-ctrl-ctrl": {"id": "broken-ctrl-ctrl", "kind": "idempotency_replay", "uses": 0, "total": 100},
        },
        "decoy_hits": 0,
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, code: int, payload: dict):
            raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _resolve_obj_key(self, parsed) -> tuple[str, bool]:
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) != 3 or parts[0] != "biz":
                return "", False
            oid = parts[2]
            qs = dict(parse_qsl(parsed.query))
            is_ctrl = qs.get("role") == "control"
            key = f"{oid}-ctrl" if is_ctrl else oid
            return key, is_ctrl

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/":
                return self._send(200, {"ok": True})
            key, _ = self._resolve_obj_key(parsed)
            with lock:
                obj = copy.deepcopy(state["objects"].get(key))
            if obj is None:
                return self._send(404, {"error": "not found"})
            return self._send(200, obj)

        def _mutate(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/biz/decoy/unauthorized":
                with lock:
                    state["decoy_hits"] += 1
                return self._send(200, {"purged": True})
            key, is_ctrl = self._resolve_obj_key(parsed)
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                data = json.loads(raw_body or "{}")
            except ValueError:
                return self._send(400, {"error": "invalid json"})
            with lock:
                obj = state["objects"].get(key)
                if obj is None:
                    return self._send(404, {"error": "not found"})
                op = data.get("op")
                oid = key[:-5] if is_ctrl else key
                vulnerable = oid.endswith("-vuln")
                if oid == "broken-ctrl":
                    return self._send(500, {"error": "control broken"})
                if op == "redeem":
                    if obj["uses"] >= 1 and not vulnerable:
                        return self._send(409, {"error": "single use"})
                    obj["uses"] += 1
                    obj["total"] -= 10
                    return self._send(200, {"applied": True, "uses": obj["uses"]})
                if op == "prepare":
                    obj["prepared"] = True
                    return self._send(200, {"applied": True, "prepared": True})
                if op == "complete":
                    if not obj["prepared"] and not vulnerable:
                        return self._send(409, {"error": "prepare required"})
                    obj["status"] = "complete"
                    return self._send(200, {"applied": True, "status": "complete"})
                if op == "title":
                    obj["title"] = str(data.get("title") or "")
                    return self._send(200, {"applied": True, "title": obj["title"]})
                if op == "server_tag":
                    if vulnerable:
                        obj["server_tag"] = str(data.get("server_tag") or "")
                    return self._send(200, {"applied": True, "server_tag": obj["server_tag"]})
                return self._send(400, {"error": "unknown op"})

        do_POST = _mutate
        do_PUT = _mutate

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    return srv, state


def _setup_policy_env(tmp_path: Path, base: str, biz_ops: list[dict], monkeypatch):
    home = tmp_path / "cco_home"
    home.mkdir(exist_ok=True)
    (home / "validations").mkdir(exist_ok=True)
    scope_file = tmp_path / "scope.json"
    policy_file = tmp_path / "program-policy.json"
    scope_file.write_text(json.dumps({
        "in_scope": [{"asset": base}],
        "scope_policy": "explicit_only",
        "blind_mode": True,
        "allow_loopback": False,
        "allow_osint": False,
        "allow_public_labs": False,
    }), encoding="utf-8")
    policy_file.write_text(json.dumps({
        "blind_mode": True,
        "blocked_http_methods": ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"],
        "background_network_jobs": "deny",
        "business_logic_operations": biz_ops,
        "rate_limits": {
            "default": {"window_seconds": 60, "max_calls": 600},
            "conservative": {"window_seconds": 60, "max_calls": 600},
        },
    }), encoding="utf-8")
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope_file))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy_file))
    monkeypatch.setenv("CCO_GRAPH_BACKEND", "networkx")
    return home, scope_file, policy_file


def test_policy_engine_business_logic_operations_validation_and_isolation(tmp_path, monkeypatch):
    base = "http://127.0.0.1:42000/"
    biz_url = f"{base}biz/coupon/coupon-1"
    decoy_url = f"{base}biz/decoy/unauthorized"
    home, scope_file, policy_file = _setup_policy_env(
        tmp_path,
        base,
        [{
            "method": "POST",
            "url": biz_url,
            "operation_id": "op-biz-1",
            "kind": "idempotency_replay",
            "carriers": ["json"],
            "allow_state_mutation": True,
            "test_data_only": True,
        }],
        monkeypatch,
    )
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope_file), program_policy_file=str(policy_file))

    # Authorized validator_validate_business_logic passes preflight and wire checks.
    assert engine.validate_tool_invocation("validator_validate_business_logic", {
        "target_url": biz_url,
        "method": "POST",
        "carrier": "json",
        "kind": "idempotency_replay",
        "operation_id": "op-biz-1",
    }, _policy_preflight=True)["allowed"] is True
    assert engine.validate_wire_invocation("validator_validate_business_logic", {
        "target_url": biz_url,
        "url": biz_url,
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
    })["allowed"] is True
    assert engine.validate_wire_invocation("validator_validate_business_logic", {
        "target_url": f"{biz_url}?role=control",
        "url": f"{biz_url}?role=control",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
    })["allowed"] is True

    # Unauthorized tools (curl_request, bash, hunter) remain blocked on POST even for biz_url.
    assert engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": biz_url, "method": "POST", "data": '{"op":"redeem"}',
    })["reason"] == "blocked_http_method"
    assert engine.validate_wire_invocation("kali-tools_curl_request", {
        "url": biz_url, "method": "POST", "headers": {"Content-Type": "application/json"},
    })["reason"] == "blocked_http_method"

    # Undeclared URLs and wrong methods/carriers remain blocked.
    assert engine.validate_tool_invocation("validator_validate_business_logic", {
        "target_url": decoy_url,
        "method": "POST",
        "carrier": "json",
        "kind": "idempotency_replay",
    }, _policy_preflight=True)["reason"] == "blocked_http_method"
    assert engine.validate_tool_invocation("validator_validate_business_logic", {
        "target_url": biz_url,
        "method": "PUT",
        "carrier": "json",
        "kind": "idempotency_replay",
    }, _policy_preflight=True)["reason"] == "blocked_http_method"
    assert engine.validate_tool_invocation("validator_validate_business_logic", {
        "target_url": biz_url,
        "method": "POST",
        "carrier": "form",
        "kind": "idempotency_replay",
    }, _policy_preflight=True)["reason"] == "blocked_http_method"

    # Malformed declarations (e.g., allow_state_mutation != True) fail closed on load.
    bad_policy = tmp_path / "bad-policy.json"
    bad_policy.write_text(json.dumps({
        "blind_mode": True,
        "business_logic_operations": [{
            "method": "POST",
            "url": biz_url,
            "operation_id": "op-bad",
            "kind": "idempotency_replay",
            "allow_state_mutation": False,
            "test_data_only": True,
        }],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="business_logic_operations"):
        PolicyEngine(cco_home=str(home), scope_file=str(scope_file), program_policy_file=str(bad_policy))


def test_validator_business_logic_loopback_confirmed_unconfirmed_signed_completion_and_inconclusive(tmp_path, monkeypatch):
    srv, _state = _make_biz_loopback_server()
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}/"
        biz_ops = [
            {"method": "POST", "url": f"{base}biz/coupon/coupon-vuln", "operation_id": "op-cv", "kind": "idempotency_replay", "carriers": ["json"], "allow_state_mutation": True, "test_data_only": True},
            {"method": "POST", "url": f"{base}biz/coupon/coupon-safe", "operation_id": "op-cs", "kind": "idempotency_replay", "carriers": ["json"], "allow_state_mutation": True, "test_data_only": True},
            {"method": "POST", "url": f"{base}biz/workflow/seq-vuln", "operation_id": "op-sv", "kind": "sequence_step_skip", "carriers": ["json"], "allow_state_mutation": True, "test_data_only": True},
            {"method": "POST", "url": f"{base}biz/workflow/seq-safe", "operation_id": "op-ss", "kind": "sequence_step_skip", "carriers": ["json"], "allow_state_mutation": True, "test_data_only": True},
            {"method": "PUT", "url": f"{base}biz/tag/tag-vuln", "operation_id": "op-tv", "kind": "schema_symmetry", "carriers": ["json"], "allow_state_mutation": True, "test_data_only": True},
            {"method": "PUT", "url": f"{base}biz/tag/tag-safe", "operation_id": "op-ts", "kind": "schema_symmetry", "carriers": ["json"], "allow_state_mutation": True, "test_data_only": True},
            {"method": "POST", "url": f"{base}biz/coupon/broken-ctrl", "operation_id": "op-bc", "kind": "idempotency_replay", "carriers": ["json"], "allow_state_mutation": True, "test_data_only": True},
        ]
        home, _, _ = _setup_policy_env(tmp_path, base, biz_ops, monkeypatch)
        validator = load_server("validator")

        for kind, slug, meth in (
            ("idempotency_replay", "coupon/coupon", "POST"),
            ("sequence_step_skip", "workflow/seq", "POST"),
            ("schema_symmetry", "tag/tag", "PUT"),
        ):
            pos = json.loads(validator.validate_business_logic(
                f"{base}biz/{slug}-vuln", kind=kind, method=meth, carrier="json", param="op",
            ))
            assert pos["verdict"] == "CONFIRMED", pos
            assert pos["oracle"] == "business_logic"
            assert pos["evidence"]["normal_control_passed"] is True
            assert pos["evidence"]["violation_effect_observed"] is True
            assert "signed_completion" not in pos
            assert artifact_is_current(pos, trusted_root=str(home / "validations"), expected_target=f"{base}biz/{slug}-vuln")

            neg = json.loads(validator.validate_business_logic(
                f"{base}biz/{slug}-safe", kind=kind, method=meth, carrier="json", param="op",
            ))
            assert neg["verdict"] == "UNCONFIRMED", neg
            assert neg["oracle"] == "business_logic"
            assert neg["evidence"]["normal_control_passed"] is True
            assert neg["evidence"]["violation_effect_observed"] is False
            env = neg.get("signed_completion")
            assert isinstance(env, dict)
            ok, payload, err = signed_completion.verify_signed_completion(
                env,
                expected_target=f"{base}biz/{slug}-safe",
                expected_profile="stateful_business_logic",
                expected_scope=current_scope_revision(),
            )
            assert ok, err
            assert payload["completion_status"] == "completed_clean"
            assert payload["findings_count"] == 0

        # Broken normal control returns INCONCLUSIVE (never UNCONFIRMED clean).
        inc = json.loads(validator.validate_business_logic(
            f"{base}biz/coupon/broken-ctrl", kind="idempotency_replay", method="POST", carrier="json", param="op",
        ))
        assert inc["verdict"] == "INCONCLUSIVE"
        assert "signed_completion" not in inc
    finally:
        srv.shutdown()
        thread.join(timeout=5)
        srv.server_close()


def test_sprint_d_candidate_broker_and_solver_end_to_end_business_logic(tmp_path, monkeypatch):
    srv, state = _make_biz_loopback_server()
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}/"
        biz_ops = [
            {"method": "POST", "url": f"{base}biz/coupon/coupon-vuln", "operation_id": "op-cv", "kind": "idempotency_replay", "carriers": ["json"], "allow_state_mutation": True, "test_data_only": True},
            {"method": "PUT", "url": f"{base}biz/tag/tag-safe", "operation_id": "op-ts", "kind": "schema_symmetry", "carriers": ["json"], "allow_state_mutation": True, "test_data_only": True},
        ]
        home, scope_file, policy_file = _setup_policy_env(tmp_path, base, biz_ops, monkeypatch)
        workdir = tmp_path / "solver"
        private = tmp_path / "private"
        workdir.mkdir()
        private.mkdir()
        (private / "state").mkdir(exist_ok=True)

        # Verify Brain template alignment.
        tpl = brain.broker_vector_template("race-business")
        assert "validator_validate_business_logic" in tpl["tools"]

        specs = brain.build_plan(base, str(workdir), tool_profile="broker")
        for spec in specs:
            spec.scope_ref = str(scope_file)
        (home / "permissions.json").write_text(json.dumps({
            "default": "deny",
            "tools": {t: "allow" for t in brain.broker_tools()},
        }), encoding="utf-8")
        engine = PolicyEngine(cco_home=str(home), scope_file=str(scope_file), program_policy_file=str(policy_file))
        for tool in brain.broker_tools():
            engine.grant_approval(tool, "127.0.0.1", ttl_seconds=600, reason="sprint-d-test")
        budget = SharedBudget(http=100, tokens=100000, seconds=60)
        from campaign_worker import LocalMCPExecutor
        broker = PythonBroker(
            budget=budget, engine=engine, executor=LocalMCPExecutor(home),
            workdir=workdir, private=private, provider="http://127.0.0.1:1/v1",
            models={"m"}, api_key="k",
        )
        from full_agent_tasks import TaskRegistry
        broker.tasks = TaskRegistry(specs, workdir, {}, setup_checks_passed=False)
        broker.runtime_policy = PythonRuntimePolicy(budget)
        broker.load_catalog(home)
        solver = PythonSolver(broker, model="m")
        recon, enum_spec, access_spec = specs[:3]

        # Seed enum discovery receipt containing vulnerable POST coupon, safe PUT tag, and unauthorized decoy.
        disc_payload = {
            "status_code": 200,
            "text": json.dumps({
                "actions": [
                    {"url": f"{base}biz/coupon/coupon-vuln", "method": "POST", "operation_id": "op-cv", "json_body": {"op": "redeem", "coupon": "BIZ-ONE"}},
                    {"url": f"{base}biz/tag/tag-safe", "method": "PUT", "operation_id": "op-ts", "json_body": {"op": "server_tag", "server_tag": "x"}},
                    {"url": f"{base}biz/decoy/unauthorized", "method": "POST", "json_body": {"op": "purge"}},
                ]
            }),
        }
        ref = broker.archive(disc_payload, "enum-biz")
        broker.results.append({"spec_id": enum_spec.id, "tool": "kali-tools_curl_request", "arguments": {"url": base}, "content_ref": ref})
        for prev_spec, nxt in ((recon, "enum"), (enum_spec, "access")):
            s_obj = {"status": "done", "next": nxt, "steps": [{"id": s.id, "status": "done"} for s in prev_spec.steps]}
            solver.summaries[prev_spec.id] = s_obj
            p = broker.tasks.summary_path(prev_spec)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(s_obj), encoding="utf-8")
            solver.task_states[prev_spec.id] = "completed"
        monkeypatch.setenv("CCO_WORKDIR", str(workdir))
        monkeypatch.setattr(broker, "_check_handoff", lambda _spec: None)
        broker.tasks.active_spec = access_spec

        candidates = solver.plan_candidates(access_spec)
        biz_by_route = {
            urlsplit(c["route"]).path: c
            for c in candidates
            if c.get("validation_profile") == "stateful_business_logic" or not c["eligible"]
        }
        decoy = next(c for c in candidates if urlsplit(c["route"]).path == "/biz/decoy/unauthorized")
        assert decoy["eligible"] is False
        assert decoy["reason_code"] == "unsupported_readonly_method"
        coupon_cand = next(
            c for c in candidates
            if urlsplit(c["route"]).path == "/biz/coupon/coupon-vuln"
            and c.get("validation_profile") == "stateful_business_logic"
        )
        tag_cand = next(
            c for c in candidates
            if urlsplit(c["route"]).path == "/biz/tag/tag-safe"
            and c.get("validation_profile") == "stateful_business_logic"
        )
        assert coupon_cand["eligible"] is True
        assert coupon_cand["tool"] == "validator_validate_business_logic"
        assert tag_cand["eligible"] is True
        assert tag_cand["tool"] == "validator_validate_business_logic"
        assert biz_by_route["/biz/decoy/unauthorized"]["eligible"] is False

        # Execute host access validation dispatch on both eligible candidates.
        dispatched = solver.dispatch_access_validation(access_spec)
        assert dispatched is True
        solver.refresh_candidate_evidence(access_spec)
        vuln_row = next(
            c for c in solver.candidates_by_task[access_spec.id].values()
            if c["route"].endswith("coupon-vuln") and c.get("validation_profile") == "stateful_business_logic"
        )
        safe_row = next(
            c for c in solver.candidates_by_task[access_spec.id].values()
            if c["route"].endswith("tag-safe") and c.get("validation_profile") == "stateful_business_logic"
        )
        assert vuln_row["evidence_accepted"] is True and vuln_row["accepted_verdict"] == "CONFIRMED"
        assert vuln_row["outcome"] == "positive"
        assert safe_row["evidence_accepted"] is True and safe_row["accepted_verdict"] == "UNCONFIRMED"
        assert safe_row["outcome"] == "completed_negative"
        assert safe_row["completion_status"] == "negative_verified"
        assert state["decoy_hits"] == 0
        broker.close()
    finally:
        srv.shutdown()
        thread.join(timeout=5)
        srv.server_close()
