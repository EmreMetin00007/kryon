"""Hardening regressions: unknown-tool deny and secret-path deny."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _load_policy_engine():
    path = REPO_ROOT / "scripts" / "policy_engine.py"
    spec = importlib.util.spec_from_file_location("policy_engine_hardening", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _engine(tmp_path):
    module = _load_policy_engine()
    return module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))


# --- 1. Unknown tool default-deny -------------------------------------------


def test_unknown_tool_is_denied(tmp_path):
    engine = _engine(tmp_path)
    result = engine.validate_tool_invocation(
        "unknown_new_tool", {"url": "https://evil.example.com/x"}
    )
    assert result["allowed"] is False
    assert result["reason"] == "blocked_unknown_tool"


def test_unknown_tool_with_harmless_args_is_still_denied(tmp_path):
    engine = _engine(tmp_path)
    result = engine.validate_tool_invocation("totally_made_up", {"q": "hello"})
    assert result["allowed"] is False
    assert result["reason"] == "blocked_unknown_tool"


def test_registered_and_native_tools_are_not_unknown(tmp_path):
    engine = _engine(tmp_path)
    assert engine.validate_tool_invocation(
        "kali-tools_cvss_calculate", {"av": "N"}
    )["allowed"] is True
    assert engine.validate_tool_invocation(
        "read", {"filePath": str(tmp_path / "README.md")}
    )["allowed"] is True


# --- 2. Secret-path deny -----------------------------------------------------


@pytest.mark.parametrize(
    "secret_path",
    [
        "/srv/app/.env",
        "/srv/app/.env.local",
        "/srv/app/.env.production",
        str(Path.home() / ".ssh" / "id_rsa"),
        str(Path.home() / ".aws" / "credentials"),
        str(Path.home() / ".gnupg" / "private.key"),
        "/srv/app/.cco/credential_vault.db",
        "/srv/app/credential_vault.db",
        "/srv/app/certs/server.pem",
        "/srv/app/certs/server.key",
        "/home/u/.config/opencode/auth.json",
    ],
)
def test_read_of_secret_path_is_denied(tmp_path, secret_path):
    engine = _engine(tmp_path)
    result = engine.validate_tool_invocation("read", {"filePath": secret_path})
    assert result["allowed"] is False
    assert result["reason"] == "blocked_secret_path"


@pytest.mark.parametrize(
    "safe_path",
    [
        "/srv/app/README.md",
        "/srv/app/.env.example",
        "/srv/app/.env.sample",
        "/srv/app/src/token_utils.py",
        "/srv/app/docs/credentials-rotation.md",
    ],
)
def test_read_of_normal_path_is_allowed(tmp_path, safe_path):
    engine = _engine(tmp_path)
    result = engine.validate_tool_invocation("read", {"filePath": safe_path})
    assert result["allowed"] is True


def test_grep_and_glob_secret_paths_are_denied(tmp_path):
    engine = _engine(tmp_path)
    grep = engine.validate_tool_invocation(
        "grep", {"pattern": "x", "path": str(Path.home() / ".ssh")}
    )
    assert grep["allowed"] is False
    assert grep["reason"] == "blocked_secret_path"
    glob = engine.validate_tool_invocation("glob", {"pattern": "**/.env"})
    assert glob["allowed"] is False
    assert glob["reason"] == "blocked_secret_path"


def test_bash_local_files_are_not_network_targets(tmp_path):
    engine = _engine(tmp_path)
    for command in (
        "cat notes.txt && echo 127.0.0.1",
        "echo wrote > out.txt; echo 127.0.0.1",
        "echo wrote >> out.txt && echo 127.0.0.1",
        "python3 script.py 127.0.0.1",
        "cat data.json; echo 127.0.0.1",
    ):
        data = engine.extract_invocation_data("bash", {"command": command})
        assert data["targets"] == ["127.0.0.1"], command
        result = engine.validate_tool_invocation("bash", {"command": command})
        assert result["allowed"] is True, command
    # Real hosts must still be extracted.
    data = engine.extract_invocation_data(
        "bash", {"command": "curl -s https://example.com/health"}
    )
    assert data["targets"] == ["example.com"]


def test_bash_variable_and_path_tokens_are_not_invalid_targets(tmp_path):
    engine = _engine(tmp_path)
    data = engine.extract_invocation_data("bash", {"command": (
        "H=10.112.140.17; D=/root/cco-work/target-$H; "
        "nmap -p- -T4 $H -oA $D/recon/nmap_full"
    )})
    assert data["targets"] == ["10.112.140.17"]
    assert data["invalid_targets"] == []
    data = engine.extract_invocation_data("bash", {"command": (
        "cat /root/cco-work/target-10.112.140.17/recon/diag.py; echo 127.0.0.1"
    )})
    assert data["targets"] == ["127.0.0.1"]
    assert data["invalid_targets"] == []
    # A malformed single-slash network expression stays invalid.
    data = engine.extract_invocation_data("bash", {"command": "nmap 10.0.0.5/33"})
    assert data["invalid_targets"] == ["10.0.0.5/33"]


def _engine_with_policy(tmp_path, policy):
    module = _load_policy_engine()
    codex = tmp_path / ".codex"
    codex.mkdir(exist_ok=True)
    (codex / "program-policy.json").write_text(json.dumps(policy))
    return module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))


def test_bash_budget_blocks_after_limit(tmp_path):
    engine = _engine_with_policy(tmp_path, {"bash_budget_max_calls": 3})
    for _ in range(3):
        assert engine.validate_tool_invocation(
            "bash", {"command": "echo 127.0.0.1"}
        )["allowed"] is True
    result = engine.validate_tool_invocation("bash", {"command": "echo 127.0.0.1"})
    assert result["allowed"] is False
    assert result["reason"] == "blocked_bash_budget"
    assert "MCP" in result["guidance"]


def test_bash_budget_zero_disables(tmp_path):
    engine = _engine_with_policy(tmp_path, {"bash_budget_max_calls": 0})
    for _ in range(5):
        assert engine.validate_tool_invocation(
            "bash", {"command": "echo 127.0.0.1"}
        )["allowed"] is True


def test_repeat_brake_on_third_identical_agent_error(tmp_path):
    engine = _engine(tmp_path)
    reasons = [
        engine.validate_tool_invocation("read", {"filePath": "/srv/app/.env"})["reason"]
        for _ in range(3)
    ]
    assert reasons[0] == "blocked_secret_path"
    assert reasons[1] == "blocked_secret_path"
    assert reasons[2].startswith("blocked_repeat_brake")
    # The brake persists instead of oscillating back to the raw reason.
    fourth = engine.validate_tool_invocation("read", {"filePath": "/srv/app/.env"})
    assert fourth["reason"].startswith("blocked_repeat_brake")


def test_worker_task_without_tools_line_is_blocked(tmp_path):
    engine = _engine(tmp_path)
    result = engine.validate_tool_invocation("task", {
        "subagent_type": "worker",
        "description": "web enum",
        "prompt": "Enumerate http://10.112.140.17 and report.",
    })
    assert result["allowed"] is False
    assert result["reason"] == "blocked_task_spec"


def test_worker_task_with_named_mcp_tools_is_allowed(tmp_path):
    from orchestration_spec import TaskSpec, render_task_prompt

    engine = _engine(tmp_path)
    prompt = render_task_prompt(TaskSpec(
        id="enum-1", phase="enum", target="local", evidence_dir=str(tmp_path / "evidence"),
        tools=["kali-tools_compose_js_routes", "kali-tools_curl_request"], commands=["Extract routes"]))
    result = engine.validate_tool_invocation("task", {
        "subagent_type": "worker",
        "description": "JS routes",
        "prompt": prompt,
    })
    assert result["allowed"] is True


def test_worker_task_with_bash_exception_is_allowed(tmp_path):
    from orchestration_spec import TaskSpec, render_task_prompt

    engine = _engine(tmp_path)
    prompt = render_task_prompt(TaskSpec(
        id="local-1", phase="recon", target="local", evidence_dir=str(tmp_path / "evidence"),
        tools=["bash"], bash_justification="local file sort", commands=["Sort files"]))
    result = engine.validate_tool_invocation("task", {
        "subagent_type": "worker",
        "prompt": prompt,
    })
    assert result["allowed"] is True


def test_non_worker_task_is_not_spec_checked(tmp_path):
    engine = _engine(tmp_path)
    result = engine.validate_tool_invocation("task", {
        "subagent_type": "brain_sol",
        "prompt": "Reality-check the plan.",
    })
    assert result["allowed"] is True


def test_python_phase_gate_requires_declared_mcp_tools():
    # Archived agent prose is not a runtime guard. The Python host must reject
    # undeclared tools and aliases even without a client or Markdown prompt.
    from types import SimpleNamespace
    from full_agent_budget import SharedBudget
    from full_agent_python_broker import PythonRuntimePolicy

    policy = PythonRuntimePolicy(SharedBudget(tokens=150000, http=20, seconds=60))
    spec = SimpleNamespace(id="access-test", phase="access", max_calls=3,
                           tools=["hunter_run_web_loop"])
    assert policy.allowed_tools(spec) == {
        "hunter_run_web_loop", "read_artifact", "submit_phase_summary"}
    for tool in ("bash", "task", "run_web_loop", "validator_validate_sqli"):
        with pytest.raises(ValueError, match="tool unavailable"):
            policy.check_tool(spec, tool)
    assert policy.tool_calls.get(spec.id, 0) == 0
    policy.check_tool(spec, "hunter_run_web_loop")
    assert policy.tool_calls[spec.id] == 1
    policy.repairing.add(spec.id)
    assert policy.allowed_tools(spec) == {"submit_phase_summary"}
    with pytest.raises(ValueError, match="tool unavailable"):
        policy.check_tool(spec, "hunter_run_web_loop")


def test_repeat_brake_does_not_apply_to_scope_blocks(tmp_path):
    engine = _engine(tmp_path)
    reasons = [
        engine.validate_tool_invocation(
            "kali-tools_curl_request", {"url": "https://outside.example.org/"}
        )["reason"]
        for _ in range(3)
    ]
    assert reasons == ["blocked_scope"] * 3


def test_reload_cache_picks_up_scope_edits(tmp_path):
    module = _load_policy_engine()
    codex = tmp_path / ".codex"
    codex.mkdir()
    scope_file = codex / "scope.json"
    scope_file.write_text(json.dumps(
        {"in_scope": [{"asset": "example.com", "type": "web"}]}
    ))
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "*", ttl_seconds=600, reason="test")
    assert engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://example.com/a"}
    )["allowed"] is True
    # Editing the scope file (same engine) must be honoured on the next call.
    scope_file.write_text(json.dumps(
        {"in_scope": [{"asset": "other.example.org", "type": "web"}]}
    ))
    result = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://example.com/a"}
    )
    assert result["allowed"] is False
    assert result["reason"] == "blocked_scope"
    assert engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://other.example.org/a"}
    )["allowed"] is True


def test_bash_slash_secret_path_is_denied(tmp_path):
    engine = _engine(tmp_path)
    result = engine.validate_tool_invocation(
        "bash", {"command": "cat /srv/app/.env"}
    )
    assert result["allowed"] is False
    assert result["reason"] == "blocked_secret_path"
