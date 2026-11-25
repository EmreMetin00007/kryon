"""Tests for read-only live TUI monitor (`cco-agent watch` and `--tui`)."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import threading

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agent_cli  # noqa: E402
import agentic_tui  # noqa: E402


def _seed_sample_run_dir(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "manifest.json").write_text(
        json.dumps({
            "schema": "agentic-target-run/1",
            "mode": "agentic",
            "status": "completed",
            "target": "http://127.0.0.1:18080/",
            "preset": "bounty-safe",
            "allowed_methods": ["GET", "HEAD"],
            "request_headers": ["Pentest", "User-Agent"],
            "auth": {
                "authenticated_actors": ["member-a"],
                "unauthenticated_credentialed_actors": ["admin-a"],
            },
            "ablation": {"execution_mode": "sharded"},
            "scope": {"max_degradation_streak": 3},
            "limits": {"http_requests": 200, "llm_tokens": 750000, "seconds": 900},
            "budget": {"http_used": 42, "tokens_used": 125000, "elapsed_seconds": 65.4},
            "llm_calls": 11,
            "target_requests": 42,
            "wall_clock_seconds": 65.4,
            "stage0_crawl": {"enabled": True, "status": "completed"},
            "sharding_summary": {
                "shards": [
                    {"shard_id": "shard-1", "status": "completed", "turns": 8, "findings_count": 1},
                    {"shard_id": "shard-2", "status": "completed", "turns": 6, "findings_count": 0},
                ]
            },
            "report_md": str(run_dir / "report.md"),
            "report_sarif": str(run_dir / "report.sarif"),
        }),
        encoding="utf-8",
    )
    receipts_dir = run_dir / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    for idx, (actor, method, path, status, ms) in enumerate(
        [
            ("anon", "GET", "/", 200, 14.2),
            ("member-a", "GET", "/api/orders/1", 200, 22.8),
            ("member-a", "GET", "/api/orders/2", 429, 31.0),
        ],
        start=1,
    ):
        rid = f"req-{idx:04d}"
        (receipts_dir / f"{rid}.json").write_text(
            json.dumps({
                "receipt_id": rid,
                "actor": actor,
                "method": method,
                "path": path,
                "status": status,
                "elapsed_ms": ms,
                "request_headers": {"Authorization": "Bearer <REDACTED:len=16,sha256_8=12345678>"},
            }),
            encoding="utf-8",
        )
    (run_dir / "findings.json").write_text(
        json.dumps([
            {
                "severity": "low",
                "vuln_class": "info_disclosure",
                "method": "GET",
                "path": "/debug",
                "actor": "anon",
                "proof_receipt_ids": ["req-0001"],
            },
            {
                "severity": "high",
                "vuln_class": "idor",
                "method": "GET",
                "path": "/api/orders/2",
                "actor": "member-a",
                "proof_receipt_ids": ["req-0002"],
            },
        ]),
        encoding="utf-8",
    )
    (run_dir / "telemetry.jsonl").write_text(
        "\n".join([
            json.dumps({"ts": "2026-11-25T10:00:01Z", "event": "tool_call", "tool": "http_request", "actor": "member-a"}),
            json.dumps({"ts": "2026-11-25T10:00:02Z", "event": "waf_block", "status": 403, "path": "/admin"}),
            json.dumps({"ts": "2026-11-25T10:00:03Z", "event": "oracle_verdict", "verdict": "VERIFIED", "vuln_class": "idor"}),
        ]) + "\n",
        encoding="utf-8",
    )


def test_load_run_snapshot_empty_and_completed_run(tmp_path: Path) -> None:
    empty_snap = agentic_tui.load_run_snapshot(tmp_path / "missing")
    assert empty_snap.status == "waiting"
    assert empty_snap.receipt_count == 0
    assert empty_snap.findings == []

    run_dir = tmp_path / "sample-run"
    _seed_sample_run_dir(run_dir)
    snap = agentic_tui.load_run_snapshot(run_dir)

    assert snap.artifact_kind == "manifest"
    assert snap.status == "completed"
    assert snap.preset == "bounty-safe"
    assert snap.execution_mode == "sharded"
    assert snap.http_used == 42
    assert snap.http_limit == 200
    assert snap.tokens_used == 125000
    assert snap.receipt_count == 3
    assert snap.degraded_responses == 1
    assert snap.waf_blocks == 1
    assert snap.request_headers == ["Pentest", "User-Agent"]
    assert snap.authenticated_actors == ["member-a"]
    assert snap.unauthenticated_actors == ["admin-a"]
    assert len(snap.shards) == 2
    # Sorted high before low
    assert [f["severity"] for f in snap.findings] == ["HIGH", "LOW"]
    assert snap.findings[0]["vuln_class"] == "idor"
    assert len(snap.recent_receipts) == 3
    assert len(snap.recent_events) == 3


def test_render_plain_and_rich_dashboards(tmp_path: Path) -> None:
    run_dir = tmp_path / "render-run"
    _seed_sample_run_dir(run_dir)
    snap = agentic_tui.load_run_snapshot(run_dir)

    plain = agentic_tui.render_plain_dashboard(snap)
    assert "KRYON WATCH" in plain
    assert "COMPLETED" in plain
    assert "preset=bounty-safe" in plain
    assert "Pentest, User-Agent" in plain
    assert "idor" in plain
    assert "req-0003" in plain
    assert "oracle_verdict" in plain
    assert "report.md" in plain

    if agentic_tui.HAS_RICH:
        from rich.console import Console

        console = Console(record=True, width=120, height=40)
        console.print(agentic_tui.build_rich_dashboard(snap))
        rendered = console.export_text()
        assert "KRYON" in rendered
        assert "Budgets & Pipeline" in rendered
        assert "Verified Findings (2)" in rendered
        assert "Recent HTTP Receipts (3)" in rendered
        assert "Live Telemetry" in rendered


def test_cli_watch_once_and_exit_on_complete(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run_dir = tmp_path / "cli-watch"
    _seed_sample_run_dir(run_dir)

    rc = agent_cli.main(["watch", str(run_dir), "--once", "--plain"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "KRYON WATCH" in out
    assert "idor" in out

    # exit_on_complete returns immediately for completed run without sleeping
    rc2 = agentic_tui.watch_run_dir(
        run_dir,
        refresh_seconds=0.1,
        plain=True,
        exit_on_complete=True,
        sleep_fn=lambda _s: pytest.fail("should not sleep once status is terminal"),
    )
    assert rc2 == 0
    _ = capsys.readouterr()

    # stop_event exits polling loop cleanly
    stop_ev = threading.Event()
    stop_ev.set()
    rc3 = agentic_tui.watch_run_dir(
        tmp_path / "not-created-yet",
        refresh_seconds=0.1,
        plain=True,
        stop_event=stop_ev,
    )
    assert rc3 == 0


def test_cli_run_with_tui_in_plan_mode_prints_snapshot_and_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out_dir = tmp_path / "plan-tui"
    rc = agent_cli.main([
        "run",
        "--preset", "quick",
        "--target", "http://127.0.0.1:18080/",
        "--provider-config", str(REPO_ROOT / "config" / "llm.example.json"),
        "--output-dir", str(out_dir),
        "-H", "Pentest: NeverShownInTUI",
        "--tui",
    ])
    assert rc == 0
    combined = capsys.readouterr().out
    assert "NeverShownInTUI" not in combined
    assert "Pentest" in combined
    # Final line is the machine-readable JSON summary
    last_line = combined.strip().splitlines()[-1]
    summary = json.loads(last_line)
    assert summary["mode"] == "plan_only"
    assert summary["preset"] == "quick"
    assert summary["target_requests"] == 0
