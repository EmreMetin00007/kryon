"""Tests for Faz A-C bridges: AssetGraph run loader, Live TUI metrics, and Wizard recon/HAR wiring."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agent_cli  # noqa: E402
import agentic_presets  # noqa: E402
import agentic_recon  # noqa: E402
import agentic_tui  # noqa: E402
import agentic_wizard  # noqa: E402


def _make_inputs(answers: list[str]) -> Any:
    it = iter(answers)
    return lambda _prompt: next(it)


def _sample_har_payload() -> dict[str, Any]:
    return {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "startedDateTime": "2026-11-26T10:00:00Z",
                    "request": {
                        "method": "POST",
                        "url": "https://api.shop.example/v1/cart",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer har-secret-token-should-redact"},
                            {"name": "X-Storefront", "value": "web-tr"},
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"sku": "SKU-1", "qty": 1}),
                        },
                    },
                    "response": {
                        "status": 201,
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"cartId": "cart-101"}),
                        },
                    },
                },
                {
                    "startedDateTime": "2026-11-26T10:00:02Z",
                    "request": {
                        "method": "POST",
                        "url": "https://api.shop.example/v1/cart/cart-101/checkout",
                        "headers": [
                            {"name": "X-Storefront", "value": "web-tr"},
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"total": 100}),
                        },
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"orderId": "ord-555"}),
                        },
                    },
                },
            ],
        }
    }


def _sample_asset_graph_payload() -> dict[str, Any]:
    return {
        "schema": agentic_recon.SCHEMA,
        "target": "https://www.shop.example",
        "nodes": [
            {
                "origin": "https://www.shop.example",
                "scheme": "https",
                "host": "www.shop.example",
                "port": 443,
                "in_scope": True,
                "role": "storefront",
                "alive": True,
                "status": 200,
                "title": "Shop Home",
                "waf_vendor": "cloudflare",
                "tech_signals": ["nextjs", "waf:cloudflare"],
                "sample_paths": ["/products", "/logout", "/"],
            },
            {
                "origin": "https://cdn.shop.example",
                "scheme": "https",
                "host": "cdn.shop.example",
                "port": 443,
                "in_scope": True,
                "role": "cdn",
                "alive": True,
                "status": 200,
                "sample_paths": ["/bundle.js", "/assets/main.css"],
            },
            {
                "origin": "https://auth.shop.example",
                "scheme": "https",
                "host": "auth.shop.example",
                "port": 443,
                "in_scope": True,
                "role": "auth",
                "alive": True,
                "status": 200,
                "sample_paths": ["/oauth/authorize"],
            },
            {
                "origin": "https://graphql.shop.example",
                "scheme": "https",
                "host": "graphql.shop.example",
                "port": 443,
                "in_scope": True,
                "role": "graphql",
                "alive": None,
                "sample_paths": ["/graphql"],
            },
            {
                "origin": "https://api.shop.example",
                "scheme": "https",
                "host": "api.shop.example",
                "port": 443,
                "in_scope": True,
                "role": "api",
                "alive": True,
                "status": 200,
                "tech_signals": ["openapi"],
                "sample_paths": ["/v1/orders?secret=shouldStrip", "/v1/cart"],
            },
            {
                "origin": "https://admin.shop.example",
                "scheme": "https",
                "host": "admin.shop.example",
                "port": 443,
                "in_scope": True,  # Tampered in_scope; must be dropped by ScopeGuard!
                "role": "admin",
                "alive": True,
                "status": 200,
                "sample_paths": ["/users"],
            },
            {
                "origin": "https://evil.example",
                "scheme": "https",
                "host": "evil.example",
                "port": 443,
                "in_scope": True,  # Out-of-scope; must be dropped by ScopeGuard!
                "role": "api",
                "sample_paths": ["/steal"],
            },
        ],
        "edges": [
            {
                "source": "https://www.shop.example",
                "target": "https://api.shop.example",
                "relation": "calls_api",
                "evidence": "/v1/orders?secretQuery=dropMe",
            },
            {
                "source": "https://www.shop.example",
                "target": "https://evil.example",
                "relation": "redirects_to",
                "evidence": "/steal",
            },
        ],
    }


# ---------------------------------------------------------------------------
# 1. agentic_recon.load_asset_graph_for_run
# ---------------------------------------------------------------------------


def test_load_asset_graph_for_run_prioritizes_filters_and_builds_bounded_handoff(tmp_path: Path) -> None:
    graph_path = tmp_path / "asset-graph.json"
    graph_path.write_text(json.dumps(_sample_asset_graph_payload()), encoding="utf-8")

    result = agentic_recon.load_asset_graph_for_run(
        graph_path,
        base_url="https://www.shop.example/",
        excluded_paths=("/logout",),
        in_scope_assets=("*.shop.example",),
        out_of_scope_assets=("admin.shop.example",),
        max_hints=12,
    )

    assert result["schema"] == agentic_recon.SCHEMA
    assert result["base_url"] == "https://www.shop.example/"
    assert result["waf_vendors"] == ["cloudflare"]

    hints = result["discovery_hints"]
    assert len(hints) <= 12
    # API, GraphQL, Auth hints are prioritized ahead of same-origin storefront paths
    assert "https://api.shop.example/v1/orders" in hints
    assert "https://graphql.shop.example/graphql" in hints
    assert "https://auth.shop.example/oauth/authorize" in hints
    assert "/products" in hints

    assert hints.index("https://api.shop.example/v1/orders") < hints.index("/products")
    assert hints.index("https://graphql.shop.example/graphql") < hints.index("/products")
    assert hints.index("https://auth.shop.example/oauth/authorize") < hints.index("/products")

    # CDN, excluded paths, and out-of-scope hosts must not appear in discovery_hints
    assert not any("cdn.shop.example" in h for h in hints)
    assert not any("admin.shop.example" in h for h in hints)
    assert not any("evil.example" in h for h in hints)
    assert "/logout" not in hints

    # api_hosts excludes storefront and cdn, and out-of-scope admin/evil
    assert result["api_hosts"] == [
        "https://api.shop.example",
        "https://graphql.shop.example",
        "https://auth.shop.example",
    ]
    in_scope_origins = [h["origin"] for h in result["in_scope_hosts"]]
    assert "https://admin.shop.example" not in in_scope_origins
    assert "https://evil.example" not in in_scope_origins
    assert in_scope_origins[0] == "https://api.shop.example"

    stats = result["stats"]
    assert stats["nodes_total"] == 7
    assert stats["in_scope_hosts_count"] == 5
    assert stats["api_hosts_count"] == 3
    # 2 out-of-scope hosts (admin.shop.example, evil.example) + 1 excluded path (/logout)
    assert stats["dropped_out_of_scope"] == 3
    assert stats["hints_count"] == len(hints)
    # Only the in-scope edge (www -> api) is counted
    assert stats["edges_count"] == 1

    handoff = result["handoff"]
    assert handoff.startswith("[ASSET GRAPH]")
    assert len(handoff) <= 1600
    assert "https://api.shop.example" in handoff
    assert "shouldStrip" not in handoff
    assert "secretQuery" not in handoff
    assert "evil.example" not in handoff
    assert "admin.shop.example" not in handoff


def test_load_asset_graph_for_run_rejects_symlinks_wrong_schema_and_oversized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_graph = tmp_path / "real-graph.json"
    real_graph.write_text(json.dumps(_sample_asset_graph_payload()), encoding="utf-8")

    # Reject missing file
    with pytest.raises(ValueError):
        agentic_recon.load_asset_graph_for_run(tmp_path / "missing.json", base_url="http://127.0.0.1:8000/")

    # Reject directory
    with pytest.raises(ValueError):
        agentic_recon.load_asset_graph_for_run(tmp_path, base_url="http://127.0.0.1:8000/")

    # Reject symlink
    sym = tmp_path / "link-graph.json"
    os.symlink(real_graph, sym)
    with pytest.raises(ValueError, match="symlink"):
        agentic_recon.load_asset_graph_for_run(sym, base_url="https://www.shop.example/")

    # Reject wrong schema
    bad_schema = tmp_path / "bad-schema.json"
    bad_schema.write_text(json.dumps({"schema": "other-graph/99", "nodes": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        agentic_recon.load_asset_graph_for_run(bad_schema, base_url="http://127.0.0.1:8000/")

    # Reject invalid JSON
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON"):
        agentic_recon.load_asset_graph_for_run(bad_json, base_url="http://127.0.0.1:8000/")

    # Reject oversized file
    monkeypatch.setattr(agentic_recon, "MAX_SEED_FILE_BYTES", 128)
    with pytest.raises(ValueError, match="maximum size"):
        agentic_recon.load_asset_graph_for_run(real_graph, base_url="https://www.shop.example/")


def test_load_asset_graph_for_run_bounds_hints_and_handoff(tmp_path: Path) -> None:
    many_nodes = []
    for idx in range(30):
        many_nodes.append({
            "origin": f"https://api{idx}.shop.example",
            "scheme": "https",
            "host": f"api{idx}.shop.example",
            "port": 443,
            "in_scope": True,
            "role": "api",
            "alive": True,
            "status": 200,
            "tech_signals": ["openapi", "json"],
            "sample_paths": [f"/v1/resource-{idx}", f"/v1/items-{idx}"],
        })
    graph_path = tmp_path / "big-graph.json"
    graph_path.write_text(
        json.dumps({"schema": agentic_recon.SCHEMA, "target": "https://www.shop.example", "nodes": many_nodes, "edges": []}),
        encoding="utf-8",
    )
    result = agentic_recon.load_asset_graph_for_run(
        graph_path,
        base_url="https://www.shop.example/",
        in_scope_assets=("*.shop.example",),
        max_hints=5,
    )
    assert len(result["discovery_hints"]) == 5
    assert result["stats"]["hints_count"] == 5
    assert len(result["handoff"]) <= 1600


# ---------------------------------------------------------------------------
# 2. agentic_tui Faz A-C surface (manifest + fallback artifacts + WAF pivot)
# ---------------------------------------------------------------------------


def test_tui_surfaces_faz_abc_metrics_from_manifest_and_rich_plain(tmp_path: Path) -> None:
    run_dir = tmp_path / "faz-abc-manifest"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "manifest.json").write_text(
        json.dumps({
            "schema": "agentic-target-run/1",
            "mode": "agentic",
            "status": "running",
            "target": "https://www.shop.example/",
            "preset": "bounty-safe",
            "limits": {"http_requests": 200, "llm_tokens": 750000, "seconds": 900},
            "budget": {"http_used": 18, "tokens_used": 12000, "elapsed_seconds": 14.5},
            "stage0_crawl": {"enabled": True, "status": "completed"},
            "prescan": {
                "enabled": True,
                "status": "ok",
                "leads_count": 4,
                "waf_vendors_seen": ["cloudflare"],
            },
            "har_flows": {
                "flows_count": 2,
                "chained_steps_count": 3,
            },
            "asset_graph": {
                "in_scope_hosts_count": 5,
                "api_hosts_count": 3,
            },
            "waf_pivot": {
                "total_blocks": 3,
                "should_pivot": True,
            },
        }),
        encoding="utf-8",
    )

    snap = agentic_tui.load_run_snapshot(run_dir)
    assert snap.prescan_enabled is True
    assert snap.prescan_status == "ok"
    assert snap.prescan_leads == 4
    assert snap.prescan_waf_vendors == ["cloudflare"]
    assert snap.har_flows_count == 2
    assert snap.har_chained_steps == 3
    assert snap.asset_graph_hosts == 5
    assert snap.asset_graph_api_hosts == 3
    assert snap.waf_pivot_active is True

    plain = agentic_tui.render_plain_dashboard(snap)
    assert "Pipeline:" in plain
    assert "Prescan=ok(4 leads" in plain
    assert "HAR Flows=2(3 chained)" in plain
    assert "AssetGraph=5(3 api)" in plain
    assert "WAF Pivot: ACTIVE" in plain

    if agentic_tui.HAS_RICH:
        from rich.console import Console

        console = Console(record=True, width=120, height=40)
        console.print(agentic_tui.build_rich_dashboard(snap))
        rendered = console.export_text()
        assert "Budgets & Pipeline" in rendered
        assert "Prescan=ok(4 leads" in rendered
        assert "HAR Flows=2(3 chained)" in rendered
        assert "AssetGraph=5(3 api)" in rendered
        assert "WAF Pivot: ACTIVE" in rendered


def test_tui_fallback_files_and_telemetry_waf_pivot(tmp_path: Path) -> None:
    run_dir = tmp_path / "faz-abc-fallback"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "manifest.json").write_text(
        json.dumps({
            "schema": "agentic-target-run/1",
            "mode": "agentic",
            "status": "starting",
            "target": "http://127.0.0.1:18080/",
            "prescan": {"enabled": True, "max_requests": 16},
        }),
        encoding="utf-8",
    )
    (run_dir / "prescan-summary.json").write_text(
        json.dumps({
            "schema": "agentic-prescan/1",
            "status": "ok",
            "leads": [{"kind": "bola_candidate"}, {"kind": "cors_misconfiguration"}],
            "waf_vendors_seen": ["akamai"],
            "stats": {"leads_total": 2},
        }),
        encoding="utf-8",
    )
    (run_dir / "har-flows.json").write_text(
        json.dumps({
            "schema": "har-flow/1",
            "flows": [{"flow_id": "flow_1", "steps": [{"step_index": 1}, {"step_index": 2, "chained_from_step": 1}]}],
            "stats": {"flows_count": 1, "chained_steps_count": 1},
        }),
        encoding="utf-8",
    )
    (run_dir / "telemetry.jsonl").write_text(
        "\n".join([
            json.dumps({"ts": "2026-11-26T10:00:01Z", "event": "waf_block", "status": 403}),
            json.dumps({"ts": "2026-11-26T10:00:02Z", "event": "waf_block", "status": 403}),
        ]) + "\n",
        encoding="utf-8",
    )

    snap = agentic_tui.load_run_snapshot(run_dir)
    assert snap.prescan_enabled is True
    assert snap.prescan_status == "ok"
    assert snap.prescan_leads == 2
    assert snap.prescan_waf_vendors == ["akamai"]
    assert snap.har_flows_count == 1
    assert snap.har_chained_steps == 1
    assert snap.waf_blocks == 2
    assert snap.waf_pivot_active is True

    plain = agentic_tui.render_plain_dashboard(snap)
    assert "Prescan=ok(2 leads, waf=akamai)" in plain
    assert "HAR Flows=1(1 chained)" in plain
    assert "WAF Pivot: ACTIVE" in plain


# ---------------------------------------------------------------------------
# 3. agentic_wizard AssetGraph & Seed Surface (HAR) forwarding
# ---------------------------------------------------------------------------


def test_wizard_forwards_asset_graph_and_seed_surface_without_shifting_prompts(tmp_path: Path) -> None:
    scope_file = tmp_path / ".codex" / "scope.json"
    scope_file.parent.mkdir(parents=True, exist_ok=True)
    scope_file.write_text(
        json.dumps({
            "in_scope": ["https://www.shop.example", "*.shop.example"],
            "out_of_scope": ["admin.shop.example", "/logout"],
        }),
        encoding="utf-8",
    )

    graph_file = tmp_path / "asset-graph.json"
    graph_file.write_text(json.dumps(_sample_asset_graph_payload()), encoding="utf-8")

    har_file = tmp_path / "capture.har"
    har_file.write_text(json.dumps(_sample_har_payload()), encoding="utf-8")

    out_dir = tmp_path / "wizard-recon-out"
    called_runner: list[list[str]] = []
    logs: list[str] = []

    rc = agentic_wizard.run_wizard(
        provider_config=REPO_ROOT / "config" / "llm.example.json",
        input_fn=_make_inputs([
            "https://www.shop.example/",  # 1) target
            "",                           # 2) accept auto-detected .codex/scope.json
            "3",                          # 3) bounty-safe (prescan=True)
            "",                           # 4) default methods
            "Pentest: SecretWizardVal",   # 5) custom header
            "",                           # 5) done headers
            "",                           # 6) anon
            str(out_dir),                 # 7) output_dir
            "e",                          # confirm live run
        ]),
        output_fn=logs.append,
        runner_main=lambda argv: (called_runner.append(argv), 0)[1],
        workdir=tmp_path,
        cwd=tmp_path,
        environ={},
        asset_graph_file=graph_file,
        seed_surface_files=[har_file],
    )
    assert rc == 0
    assert len(called_runner) == 1

    # Verify plan & reusable run.json
    plan = json.loads((out_dir / "agentic-plan.json").read_text(encoding="utf-8"))
    assert plan["prescan"]["enabled"] is True
    assert plan["har_flows"] is not None
    assert plan["har_flows"]["flows_count"] >= 1
    assert "https://api.shop.example/v1/orders" in plan["discovery_hints"]
    assert not any("evil.example" in h for h in plan["discovery_hints"])
    assert not any("cdn.shop.example" in h for h in plan["discovery_hints"])

    cfg = agentic_presets.load_run_config(out_dir / "run.json")
    assert cfg["seed_surface_files"] == [har_file]
    assert "https://api.shop.example/v1/orders" in cfg["discovery_hints"]

    # Verify exec_argv forwards both --seed-surface and --discovery-hint
    argv = called_runner[0]
    assert "--seed-surface" in argv
    assert str(har_file) in argv
    assert "--discovery-hint" in argv
    assert "https://api.shop.example/v1/orders" in argv

    # Verify summary output prints Prescan, HAR Akis, and AssetGraph without secrets
    joined_logs = "\n".join(logs)
    assert "Prescan" in joined_logs
    assert "HAR Akis" in joined_logs
    assert "AssetGraph" in joined_logs
    assert "SecretWizardVal" not in joined_logs
    assert "har-secret-token-should-redact" not in joined_logs


def test_wizard_cli_accepts_asset_graph_and_seed_surface_flags_and_rejects_bad_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad_graph = tmp_path / "bad-graph.json"
    bad_graph.write_text(json.dumps({"schema": "wrong/1"}), encoding="utf-8")

    logs: list[str] = []
    rc_bad = agentic_wizard.run_wizard(
        provider_config=REPO_ROOT / "config" / "llm.example.json",
        input_fn=_make_inputs([
            "http://127.0.0.1:18080/",
            "",
            "1",
            "",
            "",
            "",
            str(tmp_path / "bad-out"),
        ]),
        output_fn=logs.append,
        workdir=tmp_path,
        cwd=tmp_path,
        environ={},
        asset_graph_file=bad_graph,
    )
    assert rc_bad == 2
    assert any("AssetGraph" in line for line in logs)

    # Verify CLI flag parsing on `cco-agent start` passes kwargs through to run_wizard
    captured: dict[str, Any] = {}

    def _fake_run_wizard(**kwargs: Any) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(agentic_wizard, "run_wizard", _fake_run_wizard)
    rc_cli = agent_cli.main([
        "start",
        "--provider-config", str(REPO_ROOT / "config" / "llm.example.json"),
        "--asset-graph", str(tmp_path / "ag.json"),
        "--seed-surface", str(tmp_path / "a.har"),
        "--seed-surface", str(tmp_path / "b.json"),
    ])
    assert rc_cli == 0
    assert captured["asset_graph_file"] == tmp_path / "ag.json"
    assert captured["seed_surface_files"] == [tmp_path / "a.har", tmp_path / "b.json"]
