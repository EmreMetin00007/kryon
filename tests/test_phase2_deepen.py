"""Faz 2: zincir onkosul dogrulama + deepen grant kapisi."""
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from conftest import load_server, make_signed_validation  # noqa: E402


def _load(alias, filename):
    spec = importlib.util.spec_from_file_location(alias, REPO_ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


chain = _load("chain_executor_phase2", "chain_executor.py")


class _AllowGate:
    def validate_tool_invocation(self, tool_name, args=None, **kwargs):
        return {"allowed": True}


def _sender(method, url, headers, body, timeout):
    return {"ok": True, "status": 200, "len": 2, "text": "{}", "headers": {},
            "location": "", "error": None}


def _manifest(steps):
    return {"schema_version": "action-manifest/1.0", "objective": "t",
            "target_ref": "scope-asset-1", "risk": "active_read_only",
            "budget": {"max_requests": 10, "max_duration_seconds": 30},
            "identity_refs": [], "steps": steps}


def _http_step(sid, nxt, requires=None):
    step = {"id": sid, "tool": "http_get", "args": {"path": "/x"},
            "expect": {"oracle": "status_code", "status": 200},
            "on_success": nxt, "on_failure": "fail"}
    if requires:
        step["requires"] = requires
    return step


def test_requires_blocks_unmet_precondition():
    ex = chain.ChainExecutor(policy_engine=_AllowGate(), sender=_sender,
                             target_bases={"scope-asset-1": "http://lab.test"})
    out = ex.execute(_manifest([
        _http_step("consume", "succeed", requires=["produce"]),
        _http_step("produce", "succeed"),
    ]))
    assert out["success"] is False
    assert "önkoşul" in (out.get("terminal_error") or "")


def test_requires_passes_after_oracle():
    ex = chain.ChainExecutor(policy_engine=_AllowGate(), sender=_sender,
                             target_bases={"scope-asset-1": "http://lab.test"})
    out = ex.execute(_manifest([
        _http_step("produce", "consume"),
        _http_step("consume", "succeed", requires=["produce"]),
    ]))
    assert out["success"] is True


def test_deepen_requires_real_grant(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_SCOPE_REVISION", "scope-v1")
    monkeypatch.setenv("CCO_POLICY_HASH", "policy-v1")
    kali = load_server("kali-tools")
    record = make_signed_validation("http://t.local/item?id=1", "SQL Injection")
    monkeypatch.setattr(kali, "_load_validation", lambda vid: record)
    monkeypatch.setattr(kali, "_deepen_engine_factory", None)

    blocked = kali._sqlmap_confirmed_gate("v1", allow_deepen=True, action="dump",
                                          target="http://t.local/item?id=1")
    assert blocked["ok"] is False and blocked.get("requires_approval") is True

    policy_mod = _load("policy_engine_phase2", "policy_engine.py")
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"scope_policy": "explicit_only",
                                 "in_scope": [{"asset": "t.local", "type": "web"}]}))
    empty = tmp_path / "program-policy.json"
    empty.write_text("{}")
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(empty))

    def factory():
        engine = policy_mod.PolicyEngine(cco_home=str(tmp_path / ".cco"),
                                         scope_file=str(scope))
        engine.grant_approval("kali-tools_sqlmap_test", "t.local",
                              ttl_seconds=600, reason="test")
        return engine

    monkeypatch.setattr(kali, "_deepen_engine_factory", factory)
    allowed = kali._sqlmap_confirmed_gate("v1", allow_deepen=True, action="dump",
                                          target="http://t.local/item?id=1")
    assert allowed["ok"] is True and allowed["destructive"] is True
    wrong_target = kali._sqlmap_confirmed_gate("v1", allow_deepen=True, action="dump",
                                               target="http://t.local/other?id=1")
    assert wrong_target["ok"] is False
    monkeypatch.setenv("CCO_SCOPE_REVISION", "scope-v2")
    stale = kali._sqlmap_confirmed_gate("v1", allow_deepen=True, action="dump",
                                        target="http://t.local/item?id=1")
    assert stale["ok"] is False
