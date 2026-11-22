"""Unit and integration tests for Stage 0 seed handoff, schema/multipart seed ingestion,
generalized sharding prefix & single-umbrella API namespace expansion, and CLI runner wiring.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import types
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_investigator  # noqa: E402
import agentic_runner  # noqa: E402
from agentic_seed import (  # noqa: E402
    apply_seed_surface,
    load_seed_surface_files,
    merge_seed_surfaces,
)
from agentic_sharding import (  # noqa: E402
    build_shard_prompts,
    cluster_discovered_surface,
    extract_resource_family,
)
from agentic_surface import SurfaceFrontierTracker  # noqa: E402

BASE_URL = "http://127.0.0.1:18080"


# ---------------------------------------------------------------------------
# 1. Stage 0 seed file loading, secret hygiene, ScopeGuard, & priority ranking
# ---------------------------------------------------------------------------


def test_load_stage0_seed_file_sanitizes_secrets_enforces_scope_and_ranks_high_value_routes(
    tmp_path: Path,
) -> None:
    secret_pw = "SuperSecretStage0Pass!99"
    secret_tok = "eyJhbGciOiJIUzI1NiJ9.stage0_secret_payload.sig"
    secret_bearer = "Bearer top_secret_bearer_token_4242"

    stage0_doc = {
        "schema": "stage0-seed/1",
        "url": f"{BASE_URL}/",
        "links": [
            {"method": "GET", "url": "/about", "params": []},
            {"method": "GET", "url": "/help", "params": []},
            {"method": "GET", "url": "/pricing", "params": []},
            {"method": "GET", "url": "/docs/overview", "params": []},
            {
                "method": "GET",
                "url": "/download/report?file=summary.pdf&secret_q=QUERY_SECRET_VAL",
                "params": ["file", "path:file="],
            },
            {
                "method": "POST",
                "url": "/api/2.0/acme/runs/101/update",
                "body_template": {"name": "run-a", "password": secret_pw},
            },
            {
                "method": "POST",
                "url": "/api/2.0/acme/runs/202/update",
                "body_template": {
                    "name": "run-b",
                    "status": "ACTIVE",
                    "tags": ["alpha"],
                    "api_token": secret_tok,
                    "auth_note": secret_bearer,
                },
            },
            # Off-origin & excluded routes must be dropped by ScopeGuard
            {"method": "GET", "url": "http://evil.example.test/api/leak"},
            {"method": "POST", "url": "/logout", "body_template": {"confirm": True}},
            # Static asset must be dropped
            {"method": "GET", "url": "/assets/theme.css"},
        ],
        "forms": [
            {
                "method": "POST",
                "url": "/files/upload",
                "multipart_schema": {
                    "fields": ["folder", "bad field!", "folder", "description"],
                    "files": ["attachment", "invalid\nname"],
                },
            }
        ],
        "body_templates": {
            "POST /api/2.0/acme/experiments/search": {
                "max_results": 25,
                "filter": {"state": "ACTIVE"},
                "client_secret": "cs_secret_should_be_redacted",
            },
            "POST http://evil.example.test/steal": {"data": "nope"},
        },
        "multipart_schemas": {
            "POST /files/upload": {
                "fields": ["description", "visibility"],
                "files": ["attachment", "thumbnail"],
            },
            "POST /api/2.0/acme/artifacts/upload": {
                "fields": ["run_id"],
                "files": ["artifact_file"],
            },
        },
        "ws_endpoints": [
            {"url": f"ws://127.0.0.1:18080/ws/events?token={secret_tok}", "path": "/ws/events"},
            {"url": "ws://evil.example.test/ws/leak", "path": "/ws/leak"},
            {"url": "wss://127.0.0.1:18080/ws/wrong-scheme", "path": "/ws/wrong-scheme"},
        ],
    }

    seed_file = tmp_path / "stage0-seed.json"
    seed_file.write_text(json.dumps(stage0_doc), encoding="utf-8")

    result = load_seed_surface_files(
        [seed_file],
        base_url=BASE_URL,
        excluded_paths=("/logout",),
        max_routes=6,
    )

    serialized = json.dumps(result)
    for forbidden in (
        secret_pw,
        secret_tok,
        secret_bearer,
        "top_secret_bearer_token_4242",
        "cs_secret_should_be_redacted",
        "QUERY_SECRET_VAL",
        "evil.example.test",
        "bad field!",
        "invalid\nname",
    ):
        assert forbidden not in serialized

    assert result["stats"]["files_loaded"] == 1
    assert result["stats"]["formats_detected"] == ["stage0_seed"]
    assert result["stats"]["routes_dropped_scope"] >= 5
    assert result["stats"]["routes_dropped_static"] == 1
    assert result["stats"]["routes_accepted"] == 6

    # High-value POST/multipart/body_template/file-param routes must outrank passive GETs (/about, /help, /pricing).
    kept_entries = [*result["links"], *result["forms"]]
    kept_keys = {(item["method"], item["url"]) for item in kept_entries}
    assert ("POST", "/api/2.0/acme/experiments/search") in kept_keys
    assert ("POST", "/api/2.0/acme/artifacts/upload") in kept_keys
    assert ("POST", "/files/upload") in kept_keys
    assert ("GET", "/download/report") in kept_keys
    assert ("GET", "/about") not in kept_keys
    assert ("GET", "/help") not in kept_keys
    assert ("GET", "/pricing") not in kept_keys

    # Body templates clustered by route_template_of(path), preferring richer dict and redacting secrets.
    bt_map = result["body_templates"]
    assert "POST /api/2.0/acme/runs/{id}/update" in bt_map
    runs_bt = bt_map["POST /api/2.0/acme/runs/{id}/update"]
    assert runs_bt["name"] == "run-b"
    assert runs_bt["status"] == "ACTIVE"
    assert runs_bt["api_token"] == "<redacted>"
    assert runs_bt["auth_note"] == "<redacted>"

    exp_bt = bt_map["POST /api/2.0/acme/experiments/search"]
    assert exp_bt["max_results"] == 25
    assert exp_bt["client_secret"] == "<redacted>"

    # Multipart schemas merged (union of fields and files, sorted, sanitized).
    mp_map = result["multipart_schemas"]
    assert mp_map["POST /files/upload"] == {
        "fields": ["description", "folder", "visibility"],
        "files": ["attachment", "thumbnail"],
    }
    assert mp_map["POST /api/2.0/acme/artifacts/upload"] == {
        "fields": ["run_id"],
        "files": ["artifact_file"],
    }

    # Same-origin WS endpoint kept with query token stripped; off-origin & wrong-scheme dropped.
    assert result["ws_endpoints"] == [
        {"url": "ws://127.0.0.1:18080/ws/events", "path": "/ws/events"},
    ]

    # Path-embedded param marker preserved on /download/report.
    dl_entry = next(e for e in kept_entries if e["url"] == "/download/report")
    assert "file" in dl_entry["params"]
    assert "path:file=" in dl_entry["params"]


# ---------------------------------------------------------------------------
# 2. merge_seed_surfaces combining operator seed + Stage 0 seed cleanly
# ---------------------------------------------------------------------------


def test_merge_seed_surfaces_deduplicates_and_merges_templates_multipart_ws_and_hints(
    tmp_path: Path,
) -> None:
    assert merge_seed_surfaces([None, {}], base_url=BASE_URL) is None

    har_file = tmp_path / "operator.har"
    har_file.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": f"{BASE_URL}/api/v1/projects?org=alpha",
                            },
                            "response": {"status": 200},
                        },
                        {
                            "request": {
                                "method": "POST",
                                "url": f"{BASE_URL}/api/v1/projects",
                                "postData": {
                                    "mimeType": "application/json",
                                    "text": json.dumps({"title": "demo"}),
                                },
                            },
                            "response": {"status": 201},
                        },
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    op_seed = load_seed_surface_files([har_file], base_url=BASE_URL)

    stage0_seed = {
        "schema": "stage0-seed/1",
        "url": f"{BASE_URL}/",
        "links": [
            {"method": "GET", "url": "/api/v1/projects?sort=updated", "params": ["sort"]},
            {"method": "GET", "url": "/api/v1/tasks", "params": ["state"]},
            {
                "method": "POST",
                "url": "/api/v1/projects",
                "body_template": {"title": "demo", "visibility": "private", "api_key": "RAW_KEY_123"},
            },
            {"method": "GET", "url": "http://offscope.example/leak"},
        ],
        "forms": [
            {
                "method": "POST",
                "url": "/api/v1/uploads",
                "multipart_schema": {"fields": ["project_id"], "files": ["file"]},
            }
        ],
        "multipart_schemas": {
            "POST /api/v1/uploads": {"fields": ["caption"], "files": ["file", "preview"]},
        },
        "ws_endpoints": [
            {"url": "ws://127.0.0.1:18080/ws/notifications", "path": "/ws/notifications"},
        ],
        "discovery_hints": ["/api/v1/tasks", "/dashboard"],
    }

    merged = merge_seed_surfaces([op_seed, stage0_seed, None], base_url=BASE_URL)
    assert merged is not None
    assert "RAW_KEY_123" not in json.dumps(merged)
    assert "offscope.example" not in json.dumps(merged)

    entries = {(item["method"], item["url"]): item for item in [*merged["links"], *merged["forms"]]}
    assert len(entries) == len(merged["links"]) + len(merged["forms"])
    assert set(entries[("GET", "/api/v1/projects")]["params"]) == {"org", "sort"}
    assert ("GET", "/api/v1/tasks") in entries
    assert merged["body_templates"]["POST /api/v1/projects"] == {
        "title": "demo",
        "visibility": "private",
        "api_key": "<redacted>",
    }
    assert merged["multipart_schemas"]["POST /api/v1/uploads"] == {
        "fields": ["caption", "project_id"],
        "files": ["file", "preview"],
    }
    assert merged["ws_endpoints"] == [
        {"url": "ws://127.0.0.1:18080/ws/notifications", "path": "/ws/notifications"}
    ]
    assert "/api/v1/projects" in merged["discovery_hints"]
    assert "/api/v1/tasks" in merged["discovery_hints"]
    assert "/dashboard" in merged["discovery_hints"]


# ---------------------------------------------------------------------------
# 3. apply_seed_surface -> SurfaceFrontierTracker -> cluster_discovered_surface
# ---------------------------------------------------------------------------


def test_apply_seed_surface_populates_tracker_and_forwards_schemas_to_shard_prompts() -> None:
    seed_data = {
        "schema": "stage0-seed/1",
        "url": f"{BASE_URL}/",
        "links": [
            {"method": "GET", "url": "/api/v1/orders", "params": ["status"]},
            {"method": "GET", "url": "/api/v1/orders/42", "params": []},
            {"method": "GET", "url": "/api/v1/invoices", "params": ["year"]},
            {"method": "GET", "url": "/api/v1/invoices/99", "params": []},
            {"method": "GET", "url": "/api/v1/files", "params": []},
            {"method": "GET", "url": "/api/v1/files/7", "params": []},
            {"method": "GET", "url": "/api/v1/events", "params": []},
            {
                "method": "POST",
                "url": "/api/v1/orders",
                "params": ["sku", "qty"],
                "body_template": {"sku": "ITEM-1", "qty": 2, "password": "secret"},
            },
        ],
        "forms": [
            {
                "method": "POST",
                "url": "/api/v1/files/upload",
                "params": ["folder", "doc"],
                "multipart_schema": {"fields": ["folder"], "files": ["doc"]},
            }
        ],
        "body_templates": {
            "PUT /api/v1/invoices/99": {"status": "paid", "currency": "USD"},
        },
        "multipart_schemas": {
            "POST /api/v1/files/upload": {"fields": ["tag"], "files": ["doc"]},
        },
        "ws_endpoints": [
            {"url": "ws://127.0.0.1:18080/api/v1/events/stream", "path": "/api/v1/events/stream"},
        ],
    }

    tracker = SurfaceFrontierTracker(
        base_url=BASE_URL,
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    ingested = apply_seed_surface(tracker, seed_data)
    assert ingested == 9

    # Routes, write ops, body templates, params, and schema hints all populated
    assert ("POST", "/api/v1/orders") in tracker.discovered_routes
    assert ("PUT", "/api/v1/invoices/99") in tracker.discovered_routes
    assert ("GET", "/api/v1/events/stream") in tracker.discovered_routes
    assert ("POST", "/api/v1/orders") in tracker.discovered_write_ops
    assert ("POST", "/api/v1/files/upload") in tracker.discovered_write_ops
    assert ("PUT", "/api/v1/invoices/{id}") in tracker.discovered_write_ops

    assert tracker.discovered_body_templates[("POST", "/api/v1/orders")] == {
        "sku": "ITEM-1",
        "qty": 2,
        "password": "<redacted>",
    }
    assert tracker.discovered_body_templates[("PUT", "/api/v1/invoices/{id}")] == {
        "status": "paid",
        "currency": "USD",
    }

    assert {"folder", "tag", "doc"}.issubset(tracker.discovered_params["/api/v1/files/upload"])
    assert tracker.discovered_schema_hints["/api/v1/files/upload"] == {
        "multipart:file=doc",
        "multipart:field=folder",
        "multipart:field=tag",
    }
    assert "ws:upgrade" in tracker.discovered_schema_hints["/api/v1/events/stream"]

    # Standalone body_templates/multipart_schemas without links/forms still ingest cleanly
    standalone_tracker = SurfaceFrontierTracker(base_url=BASE_URL, allowed_methods=("GET", "POST"))
    standalone_count = apply_seed_surface(
        standalone_tracker,
        {
            "url": f"{BASE_URL}/",
            "body_templates": {"POST /api/v1/jobs": {"command": "run"}},
            "ws_endpoints": [{"path": "/ws/status"}],
        },
    )
    assert standalone_count == 2
    assert ("POST", "/api/v1/jobs") in standalone_tracker.discovered_body_templates
    assert "ws:upgrade" in standalone_tracker.discovered_schema_hints["/ws/status"]

    # Clustering forwards body_templates and multipart/WS schema_hints into shard prompts
    clusters = cluster_discovered_surface(tracker, max_shards=3, min_routes_for_sharding=8)
    assert len(clusters) == 3

    orders_cluster = next(c for c in clusters if "orders" in c.families)
    files_cluster = next(c for c in clusters if "files" in c.families)
    events_cluster = next(c for c in clusters if "events" in c.families)

    assert "POST /api/v1/orders" in orders_cluster.body_templates
    assert "multipart:file=doc" in files_cluster.schema_hints.get("/api/v1/files/upload", [])
    assert "ws:upgrade" in events_cluster.schema_hints.get("/api/v1/events/stream", [])

    sys_orders, _ = build_shard_prompts(orders_cluster, base_system_prompt="BASE")
    sys_files, _ = build_shard_prompts(files_cluster, base_system_prompt="BASE")
    sys_events, _ = build_shard_prompts(events_cluster, base_system_prompt="BASE")

    assert "POST /api/v1/orders" in sys_orders
    assert "ITEM-1" in sys_orders
    assert "multipart:file=doc" in sys_files
    assert "multipart:field=folder" in sys_files
    assert "ws:upgrade" in sys_events


# ---------------------------------------------------------------------------
# 4. Generalized API prefixes & single-umbrella API namespace expansion
# ---------------------------------------------------------------------------


def test_sharding_generalized_prefixes_and_umbrella_api_expansion() -> None:
    assert extract_resource_family("/api/2.0/runs/search") == "runs"
    assert extract_resource_family("/ajax-api/2.0/experiments/search") == "experiments"
    assert extract_resource_family("/api/v2.1/projects/123") == "projects"
    assert extract_resource_family("/rpc/1.0/tasks/create") == "tasks"
    assert extract_resource_family("/ajax_api/2.0/models/list") == "models"
    assert extract_resource_family("/") == "root"
    assert extract_resource_family("/api/v1/orders/42") == "orders"
    assert extract_resource_family("/rest/v2/invoices/{id}") == "invoices"

    # Single-umbrella API namespace (/api/2.0/acme/<subfamily>/...) expands cleanly into multiple shards
    tracker = SurfaceFrontierTracker(
        base_url=BASE_URL,
        allowed_methods=("GET", "POST", "PUT"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )
    umbrella_routes = [
        ("POST", "/api/2.0/acme/runs/search"),
        ("POST", "/api/2.0/acme/runs/create"),
        ("GET", "/api/2.0/acme/runs/101"),
        ("POST", "/api/2.0/acme/experiments/search"),
        ("POST", "/api/2.0/acme/experiments/create"),
        ("GET", "/api/2.0/acme/experiments/202"),
        ("GET", "/api/2.0/acme/models/list"),
        ("POST", "/api/2.0/acme/models/register"),
        ("GET", "/api/2.0/acme/artifacts/list"),
        ("POST", "/api/2.0/acme/artifacts/upload"),
        ("GET", "/api/2.0/acme"),
        ("GET", "/"),
    ]
    for method, path in umbrella_routes:
        tracker.discovered_routes[(method, path)] = path
    tracker.declared_write_ops.add(("POST", "/api/2.0/acme/runs/create"))
    tracker.declared_write_ops.add(("POST", "/api/2.0/acme/experiments/create"))
    tracker.discovered_objects["/api/2.0/acme/runs/101"] = {
        "path": "/api/2.0/acme/runs/101",
        "template": "/api/2.0/acme/runs/{id}",
        "owner_actor": "alice",
        "seen_by": {"alice"},
        "listed_by": {"alice"},
        "tested_by": set(),
        "verified_2xx": True,
    }
    tracker.discovered_params["/api/2.0/acme/artifacts/list"] = {"path"}
    tracker.discovered_body_templates[("POST", "/api/2.0/acme/runs/search")] = {"experiment_ids": ["0"]}
    tracker.discovered_schema_hints["/api/2.0/acme/artifacts/upload"] = {"multipart:file=artifact"}

    clusters = cluster_discovered_surface(tracker, max_shards=3, min_routes_for_sharding=8)
    assert len(clusters) == 3

    all_fams = {fam for c in clusters for fam in c.families}
    assert {"runs", "experiments", "models", "artifacts"}.issubset(all_fams)

    runs_cluster = next(c for c in clusters if "runs" in c.families)
    assert "/api/2.0/acme/runs/search" in runs_cluster.routes
    assert "POST /api/2.0/acme/runs/create" in runs_cluster.write_ops
    assert "/api/2.0/acme/runs/101" in runs_cluster.objects
    assert "POST /api/2.0/acme/runs/search" in runs_cluster.body_templates

    artifacts_cluster = next(c for c in clusters if "artifacts" in c.families)
    assert "path" in artifacts_cluster.params.get("/api/2.0/acme/artifacts/list", [])
    assert "multipart:file=artifact" in artifacts_cluster.schema_hints.get("/api/2.0/acme/artifacts/upload", [])

    # Non-API UI bloat (/docs/section-*) must NEVER expand into sub-families
    ui_only = SurfaceFrontierTracker(base_url=BASE_URL, allowed_methods=("GET",))
    for sub in ("intro", "install", "usage", "faq", "guide", "ref", "changelog", "license"):
        p = f"/docs/{sub}/page"
        ui_only.discovered_routes[("GET", p)] = p
    ui_clusters = cluster_discovered_surface(ui_only, max_shards=3, min_routes_for_sharding=8)
    assert len(ui_clusters) == 1
    assert ui_clusters[0].families == ["docs"]


# ---------------------------------------------------------------------------
# 5. agentic_runner Stage 0 plan_only, live handoff, & graceful skip
# ---------------------------------------------------------------------------


def _write_local_provider_config(tmp_path: Path, base_url: str, key_env: str = "TEST_STAGE0_KEY") -> Path:
    cfg = tmp_path / "llm.json"
    cfg.write_text(
        json.dumps(
            {
                "schema": "cco-llm/1",
                "model": "local/test-model",
                "providers": {
                    "local": {
                        "base_url": base_url,
                        "models": ["test-model"],
                        "api_key_env": key_env,
                        "api_key_header": "Authorization",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return cfg


def test_runner_plan_only_stage0_records_config_with_zero_network_or_crawl_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _write_local_provider_config(tmp_path, "https://api.example.test/v1")

    called = False

    def _boom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        raise AssertionError("Stage 0 crawler must not run during plan_only")

    fake_mod = types.ModuleType("agentic_stage0_crawl")
    fake_mod.run_stage0_crawl = _boom  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agentic_stage0_crawl", fake_mod)

    # 1. --auto-crawl-forms without POST in --allowed-methods -> enabled=True, forms_allowed=False
    out_ro = tmp_path / "plan_ro"
    rc = agentic_runner.main(
        [
            "--target",
            "http://127.0.0.1:18991",
            "--provider-config",
            str(cfg),
            "--output-dir",
            str(out_ro),
            "--allowed-methods",
            "GET,HEAD",
            "--auto-crawl-forms",
            "--auto-crawl-max-pages",
            "9",
            "--auto-crawl-max-actions",
            "15",
        ]
    )
    assert rc == 0
    assert called is False
    plan_ro = json.loads((out_ro / "agentic-plan.json").read_text(encoding="utf-8"))
    assert plan_ro["mode"] == "plan_only"
    assert plan_ro["target_requests"] == 0
    assert plan_ro["llm_calls"] == 0
    assert plan_ro["stage0_crawl"] == {
        "enabled": True,
        "forms_requested": True,
        "forms_allowed": False,
        "max_pages": 9,
        "max_actions": 15,
    }

    # 2. --auto-crawl-forms WITH POST allowed -> forms_allowed=True
    out_rw = tmp_path / "plan_rw"
    _, plan_rw = agentic_runner.run_agentic_target(
        target="http://127.0.0.1:18991",
        provider_config=cfg,
        output_dir=out_rw,
        allowed_methods=["GET", "POST"],
        auto_crawl_forms=True,
        execute=False,
    )
    assert called is False
    assert plan_rw["stage0_crawl"] == {
        "enabled": True,
        "forms_requested": True,
        "forms_allowed": True,
        "max_pages": 12,
        "max_actions": 24,
    }


def test_runner_live_stage0_auth_order_seed_merge_tracker_handoff_and_graceful_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    lock = threading.Lock()

    class _TargetHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            data = json.loads(raw)
            with lock:
                events.append(f"login:{data.get('email', '')}")
            resp = json.dumps({"access_token": f"tok-{data.get('email', '')}"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def do_GET(self) -> None:
            body = b"<html><body>home</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class _ProviderHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            resp = {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call_finish_stage0",
                                    "type": "function",
                                    "function": {
                                        "name": "finish",
                                        "arguments": json.dumps({"summary": "done", "untested_areas": []}),
                                    },
                                }
                            ],
                        }
                    }
                ],
                "usage": {"prompt_tokens": 60, "completion_tokens": 12, "total_tokens": 72},
            }
            payload = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    target_srv = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    prov_srv = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    threading.Thread(target=target_srv.serve_forever, daemon=True).start()
    threading.Thread(target=prov_srv.serve_forever, daemon=True).start()

    target_base = f"http://127.0.0.1:{target_srv.server_port}/"
    cfg = _write_local_provider_config(tmp_path, f"http://127.0.0.1:{prov_srv.server_port}/v1")
    creds = tmp_path / "creds.json"
    creds.write_text(
        json.dumps(
            {
                "target_url": target_base,
                "test_accounts": [
                    {"alias": "alice", "email": "alice@example.test", "password": "pw1", "role": "member", "tenant": "t1"}
                ],
            }
        ),
        encoding="utf-8",
    )
    seed_file = tmp_path / "operator-seed.txt"
    seed_file.write_text("/api/v1/operator-route?filter=active\n", encoding="utf-8")
    monkeypatch.setenv("TEST_STAGE0_KEY", "dummy-local-key")

    captured_investigators: list[agentic_investigator.AgenticInvestigator] = []
    orig_inv_cls = agentic_runner.AgenticInvestigator

    class _CapturingInvestigator(orig_inv_cls):  # type: ignore[valid-type, misc]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            captured_investigators.append(self)

    monkeypatch.setattr(agentic_runner, "AgenticInvestigator", _CapturingInvestigator)

    stage0_call_info: dict[str, Any] = {}

    def _fake_stage0_crawl(
        http_client: Any,
        *,
        output_dir: Path,
        start_paths: list[str],
        max_pages: int,
        max_actions: int,
        allow_forms: bool,
    ) -> dict[str, Any]:
        with lock:
            events.append("stage0")
        alice_sess = http_client.actors.actors["alice"]
        stage0_call_info["alice_authenticated"] = bool(alice_sess.authenticated)
        stage0_call_info["start_paths"] = list(start_paths)
        stage0_call_info["max_pages"] = max_pages
        stage0_call_info["max_actions"] = max_actions
        stage0_call_info["allow_forms"] = allow_forms
        seed_path = output_dir / "stage0-seed.json"
        return {
            "schema": "stage0-seed/1",
            "url": target_base,
            "seed_file": str(seed_path),
            "links": [
                {"method": "GET", "url": "/api/2.0/runs/search", "params": ["experiment_id"]},
                {
                    "method": "POST",
                    "url": "/api/2.0/runs/create",
                    "body_template": {"experiment_id": "0", "run_name": "stage0-run", "api_token": "SECRET_TOK"},
                },
            ],
            "forms": [
                {
                    "method": "POST",
                    "url": "/api/2.0/artifacts/upload",
                    "multipart_schema": {"fields": ["run_id"], "files": ["artifact"]},
                }
            ],
            "ws_endpoints": [{"url": f"ws://127.0.0.1:{target_srv.server_port}/ws/live", "path": "/ws/live"}],
            "discovery_hints": ["/api/2.0/runs/search"],
            "stats": {"status": "completed", "pages_visited": 3, "actions_executed": 5},
        }

    fake_mod = types.ModuleType("agentic_stage0_crawl")
    fake_mod.run_stage0_crawl = _fake_stage0_crawl  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agentic_stage0_crawl", fake_mod)

    try:
        # 1. Live run with --auto-crawl + --auto-crawl-forms + --seed-surface
        _, manifest = agentic_runner.run_agentic_target(
            credentials_file=creds,
            provider_config=cfg,
            output_dir=tmp_path / "run-stage0",
            allowed_methods=["GET", "POST"],
            seed_surface_files=[seed_file],
            auto_crawl=True,
            auto_crawl_forms=True,
            auto_crawl_max_pages=7,
            auto_crawl_max_actions=14,
            execute=True,
            max_turns=3,
        )
        assert manifest["status"] == "finished"
        # Actors authenticated BEFORE Stage 0 ran
        assert events == ["login:alice@example.test", "stage0"]
        assert stage0_call_info["alice_authenticated"] is True
        assert stage0_call_info["max_pages"] == 7
        assert stage0_call_info["max_actions"] == 14
        assert stage0_call_info["allow_forms"] is True
        assert "/api/v1/operator-route" in stage0_call_info["start_paths"]

        # Manifest records Stage 0 stats and merged seed surface + discovery hints
        assert manifest["stage0_crawl"]["enabled"] is True
        assert manifest["stage0_crawl"]["status"] == "completed"
        assert manifest["stage0_crawl"]["pages_visited"] == 3
        assert manifest["stage0_crawl"]["actions_executed"] == 5
        assert manifest["stage0_crawl"]["seed_file"].endswith("stage0-seed.json")
        assert "/api/v1/operator-route" in manifest["discovery_hints"]
        assert "/api/2.0/runs/search" in manifest["discovery_hints"]
        assert manifest["seed_surface"]["routes_accepted"] == 4

        # Investigator SurfaceFrontierTracker received merged routes, body_templates, multipart_schemas, and WS hints
        assert len(captured_investigators) == 1
        tracker = captured_investigators[0].dispatcher.surface_tracker
        assert ("GET", "/api/v1/operator-route") in tracker.discovered_routes
        assert ("GET", "/api/2.0/runs/search") in tracker.discovered_routes
        assert ("POST", "/api/2.0/runs/create") in tracker.discovered_body_templates
        assert tracker.discovered_body_templates[("POST", "/api/2.0/runs/create")] == {
            "experiment_id": "0",
            "run_name": "stage0-run",
            "api_token": "<redacted>",
        }
        assert tracker.discovered_schema_hints["/api/2.0/artifacts/upload"] == {
            "multipart:file=artifact",
            "multipart:field=run_id",
        }
        assert "ws:upgrade" in tracker.discovered_schema_hints["/ws/live"]
        assert "SECRET_TOK" not in (tmp_path / "run-stage0" / "manifest.json").read_text(encoding="utf-8")

        # 2. Graceful skip when Stage 0 returns skipped_no_playwright
        def _fake_stage0_skip(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {
                "schema": "stage0-seed/1",
                "status": "skipped_no_playwright",
                "links": [],
                "forms": [],
                "discovery_hints": [],
                "stats": {"status": "skipped_no_playwright", "pages_visited": 0},
            }

        fake_mod.run_stage0_crawl = _fake_stage0_skip  # type: ignore[attr-defined]
        _, manifest_skip = agentic_runner.run_agentic_target(
            target=target_base,
            provider_config=cfg,
            output_dir=tmp_path / "run-stage0-skip",
            allowed_methods=["GET"],
            auto_crawl=True,
            execute=True,
            max_turns=3,
        )
        assert manifest_skip["status"] == "finished"
        assert manifest_skip["stage0_crawl"]["status"] == "skipped_no_playwright"
        assert manifest_skip["stage0_crawl"]["pages_visited"] == 0
    finally:
        prov_srv.shutdown()
        prov_srv.server_close()
        target_srv.shutdown()
        target_srv.server_close()
