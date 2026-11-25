"""Tests for the interactive zero-flag `cco-agent start` launcher."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_presets  # noqa: E402
import agentic_wizard  # noqa: E402


def _make_inputs(answers: list[str]) -> Any:
    it = iter(answers)
    return lambda _prompt: next(it)


def test_wizard_loopback_plan_only_when_user_declines_live_run(tmp_path: Path) -> None:
    logs: list[str] = []
    out_dir = tmp_path / "loopback-out"
    called_runner: list[list[str]] = []

    rc = agentic_wizard.run_wizard(
        provider_config=REPO_ROOT / "config" / "llm.example.json",
        input_fn=_make_inputs([
            "http://127.0.0.1:18080/",  # 1) target
            "",                          # 2) optional scope
            "3",                         # 3) bounty-safe
            "",                          # 4) default methods GET,HEAD
            "Pentest: SecretHeaderVal99",  # 5) header 1
            "X-API-Key: topsecret123",     # 5) sensitive header 2
            "",                          # 5) done headers
            "",                          # 6) anon
            str(out_dir),                # 7) output_dir
            "h",                         # decline execute
        ]),
        output_fn=logs.append,
        runner_main=lambda argv: (called_runner.append(argv), 0)[1],
        workdir=tmp_path,
        cwd=tmp_path,
        environ={},
    )
    assert rc == 0
    assert called_runner == []
    assert (out_dir / "agentic-plan.json").is_file()
    assert (out_dir / "run.json").is_file()

    # Reusable run.json must be valid cco-run/1 and MUST NOT contain sensitive header value
    cfg = agentic_presets.load_run_config(out_dir / "run.json")
    assert cfg["preset"] == "bounty-safe"
    assert cfg["custom_headers"] == ["Pentest: SecretHeaderVal99"]
    assert "topsecret123" not in (out_dir / "run.json").read_text(encoding="utf-8")

    # Output logs must NEVER print header values
    joined_logs = "\n".join(logs)
    assert "SecretHeaderVal99" not in joined_logs
    assert "topsecret123" not in joined_logs
    assert "Pentest" in joined_logs


def test_wizard_non_loopback_confirmed_launches_runner_with_all_safety_flags(tmp_path: Path) -> None:
    scope_file = tmp_path / ".codex" / "scope.json"
    scope_file.parent.mkdir(parents=True, exist_ok=True)
    scope_file.write_text(json.dumps({"in_scope": ["https://target.example.invalid"]}), encoding="utf-8")

    storage_file = tmp_path / "storage.json"
    storage_file.write_text(json.dumps({"cookies": [], "origins": []}), encoding="utf-8")

    remote_provider = tmp_path / "remote-llm.json"
    remote_provider.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "vercel/deepseek/deepseek-v4.1-flash",
            "providers": {
                "vercel": {
                    "base_url": "https://ai-gateway.vercel.sh/v1",
                    "models": ["deepseek/deepseek-v4.1-flash"],
                    "api_key_env": "AI_GATEWAY_API_KEY",
                    "api_key_header": "Authorization",
                }
            },
        }),
        encoding="utf-8",
    )

    out_dir = tmp_path / "remote-out"
    called_runner: list[list[str]] = []
    logs: list[str] = []

    rc = agentic_wizard.run_wizard(
        provider_config=remote_provider,
        input_fn=_make_inputs([
            "https://target.example.invalid",  # 1) non-loopback target
            "",                                # 2) accept auto-detected .codex/scope.json
            "standard",                        # 3) preset by name
            "GET,HEAD,POST",                   # 4) explicit methods
            "Pentest: Cyberbounty",            # 5) header
            "",                                # 5) done
            str(storage_file),                 # 6) auto-detected Playwright storage_state
            str(out_dir),                      # 7) output_dir
            "e",                               # confirm live run
        ]),
        output_fn=logs.append,
        runner_main=lambda argv: (called_runner.append(argv), 0)[1],
        workdir=tmp_path,
        cwd=tmp_path,
        environ={"AI_GATEWAY_API_KEY": "present-for-test"},
    )
    assert rc == 0
    assert len(called_runner) == 1
    argv = called_runner[0]
    assert "--execute" in argv
    assert "--tui" in argv
    assert "--allow-non-loopback" in argv
    assert "--authorize-live-provider" in argv
    assert "--scope-file" in argv
    assert "--storage-state" in argv
    assert f"member={storage_file}" in argv
    assert "Pentest: Cyberbounty" in argv


def test_wizard_warns_and_stops_cleanly_when_remote_api_key_env_missing(tmp_path: Path) -> None:
    remote_provider = tmp_path / "remote-llm.json"
    remote_provider.write_text(
        json.dumps({
            "schema": "cco-llm/1",
            "model": "vercel/deepseek/deepseek-v4.1-flash",
            "providers": {
                "vercel": {
                    "base_url": "https://ai-gateway.vercel.sh/v1",
                    "models": ["deepseek/deepseek-v4.1-flash"],
                    "api_key_env": "AI_GATEWAY_API_KEY",
                    "api_key_header": "Authorization",
                }
            },
        }),
        encoding="utf-8",
    )
    called_runner: list[list[str]] = []
    logs: list[str] = []

    rc = agentic_wizard.run_wizard(
        provider_config=remote_provider,
        input_fn=_make_inputs([
            "http://127.0.0.1:18080/",
            "",
            "1",
            "",
            "",
            "",
            str(tmp_path / "no-key-out"),
        ]),
        output_fn=logs.append,
        runner_main=lambda argv: (called_runner.append(argv), 0)[1],
        workdir=tmp_path,
        cwd=tmp_path,
        environ={},
    )
    assert rc == 0
    assert called_runner == []
    assert any("AI_GATEWAY_API_KEY" in line for line in logs)
