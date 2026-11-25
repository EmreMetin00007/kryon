"""Tests for engagement presets, cco-run/1 config loader, and LLM-friendly cco-agent subcommands."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agent_cli  # noqa: E402
import agentic_presets  # noqa: E402
import agentic_runner  # noqa: E402


def test_presets_catalog_and_cli_output(capsys: pytest.CaptureFixture[str]) -> None:
    rc = agent_cli.main(["presets"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema"] == "cco-run/1"
    assert set(doc["presets"].keys()) == {"quick", "standard", "bounty-safe", "deep"}
    assert "execute" in doc["cli_only_safety_flags"]
    assert "allow_non_loopback" in doc["cli_only_safety_flags"]
    assert doc["presets"]["bounty-safe"]["options"]["max_rps"] == 2.0
    assert doc["presets"]["bounty-safe"]["options"]["allowed_methods"] == ["GET", "HEAD"]

    rc_text = agent_cli.main(["presets", "--format", "text"])
    assert rc_text == 0
    text_out = capsys.readouterr().out
    assert "bounty-safe:" in text_out
    assert "standard:" in text_out


def test_run_example_config_is_valid() -> None:
    loaded = agentic_presets.load_run_config(REPO_ROOT / "config" / "run.example.json")
    assert loaded["preset"] == "bounty-safe"
    assert loaded["target"] == "http://127.0.0.1:8000/"
    assert loaded["allowed_methods"] == ["GET", "HEAD"]
    assert loaded["custom_headers"] == ["X-Program-Tag: authorized-test"]


@pytest.mark.parametrize(
    "forbidden_key,forbidden_val",
    [
        ("execute", True),
        ("allow_non_loopback", True),
        ("authorize_live_provider", True),
        ("live_authorization_reason", "sneaky"),
    ],
)
def test_run_config_rejects_forbidden_authorization_keys(
    tmp_path: Path,
    forbidden_key: str,
    forbidden_val: object,
) -> None:
    cfg = tmp_path / "bad.json"
    cfg.write_text(
        json.dumps({
            "schema": "cco-run/1",
            "target": "http://127.0.0.1:18080/",
            "output_dir": str(tmp_path / "out"),
            forbidden_key: forbidden_val,
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="CLI"):
        agentic_presets.load_run_config(cfg)


def test_run_config_rejects_unknown_keys_and_symlinks(tmp_path: Path) -> None:
    unknown_cfg = tmp_path / "unknown.json"
    unknown_cfg.write_text(json.dumps({"target": "http://127.0.0.1:18080/", "bogus_key": 1}), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown key"):
        agentic_presets.load_run_config(unknown_cfg)

    real_cfg = tmp_path / "real.json"
    real_cfg.write_text(json.dumps({"target": "http://127.0.0.1:18080/"}), encoding="utf-8")
    link_cfg = tmp_path / "link.json"
    link_cfg.symlink_to(real_cfg)
    with pytest.raises(ValueError, match="symlink"):
        agentic_presets.load_run_config(link_cfg)


def test_precedence_defaults_preset_config_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / "run.json"
    out_dir = tmp_path / "out-merged"
    cfg.write_text(
        json.dumps({
            "schema": "cco-run/1",
            "preset": "bounty-safe",
            "target": "http://127.0.0.1:18080/",
            "provider_config": str(REPO_ROOT / "config" / "llm.example.json"),
            "output_dir": str(out_dir),
            "http_budget": 175,
            "custom_headers": {
                "Pentest": "FromConfig",
                "X-Only-Config": "CfgVal",
            },
        }),
        encoding="utf-8",
    )

    rc = agent_cli.main([
        "plan",
        "--config", str(cfg),
        "--max-rps", "1.5",
        "--no-auto-crawl",
        "-H", "Pentest: FromCLI",
        "-H", "X-Only-CLI: CliVal",
    ])
    assert rc == 0
    cli_out = json.loads(capsys.readouterr().out)
    assert cli_out["mode"] == "plan_only"
    assert cli_out["preset"] == "bounty-safe"
    assert cli_out["target_requests"] == 0
    assert cli_out["llm_calls"] == 0

    plan = json.loads((out_dir / "agentic-plan.json").read_text(encoding="utf-8"))
    # From preset: sharded mode, max_shards=2, max_degradation_streak=3, allowed_methods=[GET, HEAD]
    assert plan["ablation"]["execution_mode"] == "sharded"
    assert plan["sharding"]["max_shards"] == 2
    assert plan["scope"]["max_degradation_streak"] == 3
    assert plan["allowed_methods"] == ["GET", "HEAD"]
    # From config overriding preset: http_budget=175
    assert plan["limits"]["http_requests"] == 175
    # From CLI overriding config/preset: max_rps=1.5, auto_crawl=False
    assert plan["limits"]["max_rps"] == 1.5
    assert plan["stage0_crawl"]["enabled"] is False
    # Custom headers merged (names only, no values)
    assert plan["request_headers"] == ["Pentest", "X-Only-CLI", "X-Only-Config"]
    serialized = json.dumps(plan)
    for val in ("FromConfig", "CfgVal", "FromCLI", "CliVal"):
        assert val not in serialized


def test_plan_command_rejects_execute_flag(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        agent_cli.main([
            "plan",
            "--preset", "quick",
            "--target", "http://127.0.0.1:18080/",
            "--provider-config", str(REPO_ROOT / "config" / "llm.example.json"),
            "--output-dir", str(tmp_path / "nope"),
            "--execute",
        ])
    assert excinfo.value.code == 2


def test_run_alias_and_status_command_work_for_plan_and_manifest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out_dir = tmp_path / "run-alias"
    rc = agent_cli.main([
        "run",
        "--preset", "quick",
        "--target", "http://127.0.0.1:18080/",
        "--provider-config", str(REPO_ROOT / "config" / "llm.example.json"),
        "--output-dir", str(out_dir),
    ])
    assert rc == 0
    _ = capsys.readouterr()

    rc_status = agent_cli.main(["status", str(out_dir)])
    assert rc_status == 0
    status_doc = json.loads(capsys.readouterr().out)
    assert status_doc["mode"] == "plan_only"
    assert status_doc["status"] == "planned"
    assert status_doc["preset"] == "quick"
    assert status_doc["target_requests"] == 0

    # Simulate completed manifest.json and verify status prefers manifest.json
    (out_dir / "manifest.json").write_text(
        json.dumps({
            "mode": "agentic",
            "status": "completed",
            "target": "http://127.0.0.1:18080/",
            "preset": "quick",
            "findings_count": 2,
            "target_requests": 42,
            "llm_calls": 9,
            "wall_clock_seconds": 12.5,
            "report_md": str(out_dir / "report.md"),
            "report_sarif": str(out_dir / "report.sarif"),
        }),
        encoding="utf-8",
    )
    rc_status2 = agent_cli.main(["status", str(out_dir)])
    assert rc_status2 == 0
    status_doc2 = json.loads(capsys.readouterr().out)
    assert status_doc2["status"] == "completed"
    assert status_doc2["findings_count"] == 2
    assert status_doc2["target_requests"] == 42
    assert status_doc2["report_md"].endswith("report.md")


def test_python_api_run_agentic_target_applies_preset(tmp_path: Path) -> None:
    _, plan = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18080/",
        provider_config=REPO_ROOT / "config" / "llm.example.json",
        output_dir=tmp_path / "py-preset",
        preset="standard",
        execute=False,
    )
    assert plan["preset"] == "standard"
    assert plan["ablation"]["execution_mode"] == "sharded"
    assert plan["stage0_crawl"]["enabled"] is True
    assert plan["limits"]["http_requests"] == 300
