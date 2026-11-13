"""Worker tasks must carry the actual scope and all mandatory evidence tools."""
import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from brain import build_plan  # noqa: E402
from orchestration_spec import TaskSpec, render_task_prompt, validate_spec  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402


def test_planned_tasks_include_scope_and_protocol_tools(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "https://owned.test"}]}))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    engine = PolicyEngine(cco_home=str(tmp_path / "home"), repo_root=str(ROOT))
    required = {"kali-tools_ledger_attempt_add_batch", "memory-server_store_finding",
                "memory-server_update_finding_validation"}
    for spec in build_plan("https://owned.test", str(tmp_path / "run")):
        assert required <= set(spec.tools)
        prompt = render_task_prompt(spec)
        assert f"Scope: {scope}" in prompt
        assert engine._task_spec_violation("task", {"subagent_type": "worker", "prompt": prompt}) is None


def test_nonexistent_tool_is_rejected_even_with_opt_in_justification(tmp_path):
    spec = TaskSpec(id="enum-1", phase="enum", target="https://owned.test",
                    tools=["kali-tools_nonexistent_review_tool"], commands=["inspect"],
                    evidence_dir=str(tmp_path), tool_justification="needed for test")
    assert any("not registered" in error for error in validate_spec(spec))


def test_gate_rejects_phantom_tool_bare_bash_and_missing_scope(tmp_path):
    engine = PolicyEngine(cco_home=str(tmp_path / "home"), repo_root=str(ROOT))
    base = ("Target: https://owned.test\nScope: .codex/scope.json\n"
            "Evidence dir: /tmp/run\nCommands:\n- inspect\n"
            "Return exactly one JSON summary\n")
    for tools in ("kali-tools_nonexistent_review_tool", "bash"):
        assert engine._task_spec_violation("task", {
            "subagent_type": "worker", "prompt": f"Tools: {tools}\n" + base})
    prompt = render_task_prompt(build_plan("https://owned.test", "/tmp/run")[0])
    prompt = "\n".join(line for line in prompt.splitlines() if not line.startswith("Scope:"))
    assert engine._task_spec_violation("task", {"subagent_type": "worker", "prompt": prompt})


def test_task_preserves_scoped_url_and_requires_actual_command(tmp_path):
    target = "https://owned.test/tenant-a/app?view=main"
    spec = build_plan(target, str(tmp_path))[0]
    assert spec.target == target
    assert any(target in command for command in spec.commands)
    engine = PolicyEngine(cco_home=str(tmp_path / "home"), repo_root=str(ROOT))
    prompt = render_task_prompt(spec)
    assert engine._task_spec_violation("task", {"subagent_type": "worker", "prompt": prompt}) is None
    prompt = prompt.replace("Commands:\n", "Commands:\nNo commands here\n", 1)
    assert engine._task_spec_violation("task", {"subagent_type": "worker", "prompt": prompt})


def test_web_plan_uses_hunter_and_finishes_with_evidence_gated_report(tmp_path):
    specs = build_plan("https://owned.test/app", str(tmp_path))
    assert [spec.phase for spec in specs] == ["recon", "enum", "access", "report"]
    access = next(spec for spec in specs if spec.phase == "access")
    assert "hunter_run_web_loop" in access.tools and access.tool_justification
    assert any("live=false" in command for command in access.commands)
    assert "validator_generate_validation_report" in specs[-1].tools
    assert all(not validate_spec(spec) for spec in specs)
