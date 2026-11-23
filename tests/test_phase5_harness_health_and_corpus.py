"""Faz 5E tests: Deterministic Harness Self-Health Anomaly Detector and
Offline Multi-Framework Surface/Redaction/Health Corpus & Invariant Suite.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, str(_p))

from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_preview import _build_surface_hints, _extract_surface_summary  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
import agentic_report  # noqa: E402
from agentic_stage0_crawl import _Stage0Collector, _finalize_routes  # noqa: E402
from agentic_surface import SurfaceFrontierTracker, route_template_of  # noqa: E402
from agentic_telemetry import (  # noqa: E402
    compute_harness_health_checks,
    compute_process_metrics,
    render_process_metrics_markdown,
    write_process_metrics,
)
from kryon_core.surface.extract import is_hashed_asset_chunk_path  # noqa: E402
from kryon_core.surface.normalize import (  # noqa: E402
    is_os_filesystem_path,
    is_port_in_path_artifact,
    is_third_party_sdk_static_route,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _make_client(tmp_path: Path, base_url: str) -> AgenticHTTPClient:
    return AgenticHTTPClient(
        base_url=base_url,
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        actors=ActorManager([{"alias": "anon", "role": "anonymous"}]),
        allowed_methods=("GET", "HEAD", "POST", "PUT", "DELETE"),
        max_requests=50,
    )


def _http_events(statuses: list[int]) -> list[dict[str, Any]]:
    return [
        {
            "event": "http_event",
            "method": "GET",
            "path": f"/api/item/{idx}",
            "route_template": "/api/item/{id}",
            "actor": "user-a",
            "status": st,
            "delta_v": 1 if st == 200 else 0,
            "delta_e": 0,
        }
        for idx, st in enumerate(statuses, start=1)
    ]


# ===========================================================================
# Part 1: Deterministic Harness Self-Health Anomaly Detector
# ===========================================================================


def test_harness_health_clean_run_and_non_trigger_boundaries() -> None:
    """Healthy runs and exact below-threshold boundaries produce zero warnings."""
    events: list[dict[str, Any]] = [
        *_http_events([200] * 12 + [404] * 8),  # 8/20 == exactly 0.40 (must NOT trigger > 0.40)
        {
            "event": "oracle_verdict",
            "node_id": "ep:/api/v1/orders/{id}",
            "verdict": "VERIFIED",
            "stages": {
                "stage1_control": "passed",
                "stage2_diff": "passed",
                "stage3_clean_replay": "passed",
            },
        },
        {
            "event": "oracle_verdict",
            "node_id": "ep:/api/v1/admin",
            "verdict": "REFUTED",
            "stages": {
                "stage1_control": "passed",
                "stage2_diff": "passed",
                "stage3_clean_replay": "failed_status_401",
            },
        },
        {
            "event": "oracle_verdict",
            "node_id": "ep:/api/v1/decoy",
            "verdict": "DECEPTION_DETECTED",
            "stages": {
                "stage1_control": "deception_identical_control",
                "stage2_diff": "skipped",
                "stage3_clean_replay": "failed_status_404",
            },
        },
    ]
    manifest = {
        "status": "finished",
        "auth": {
            "authenticated_actors": ["alice"],
            "unauthenticated_credentialed_actors": ["bob"],  # partially authenticated -> healthy
        },
        "sharding_summary": {
            "shards": [
                {"shard_id": "shard-1", "status": "finished"},
                {"shard_id": "shard-2", "status": "finished"},
            ],
            "post_auth_stage0_crawl": {
                "triggered": True,
                "status": "ok",
                "routes_ingested": 6,
                "new_routes_added": 6,
                "routes_accepted": 6,
            },
        },
    }
    clean_report = (
        "### Finding F-001\n"
        "- URL: `http://127.0.0.1:8080/admin/upload/index.html?password=<REDACTED>&username=admin`\n"
        "- Query redacted form: `http://127.0.0.1:8080/login?token=<REDACTED_SECRET:sha256_8=deadbeef>`\n"
        "- JWT path: `http://127.0.0.1:8080/reset/<REDACTED_JWT>`\n"
    )

    health = compute_harness_health_checks(
        events=events,
        manifest=manifest,
        report_text=clean_report,
    )
    assert health == {
        "status": "healthy",
        "warning_count": 0,
        "anomalies": [],
        "checks_evaluated": 6,
    }

    # < 20 HTTP requests with 100% 404s must NOT trigger high_404_ratio
    small_run = compute_harness_health_checks(events=_http_events([404] * 19))
    assert small_run["status"] == "healthy"
    assert small_run["anomalies"] == []

    # Disabled / skipped post_auth_stage0_crawl must NOT trigger post_auth_zero_new_routes
    skipped_pa = compute_harness_health_checks(
        post_auth_stage0_crawl={"enabled": False, "new_routes_added": 0},
    )
    assert skipped_pa["status"] == "healthy"
    skipped_status = compute_harness_health_checks(
        post_auth_stage0_crawl={"status": "skipped", "routes_accepted": 0},
    )
    assert skipped_status["status"] == "healthy"


def test_harness_health_triggers_high_404_ratio() -> None:
    events = _http_events([200] * 14 + [404] * 11)  # 11/25 = 0.44 > 0.40
    health = compute_harness_health_checks(events=events)
    assert health["status"] == "warnings"
    assert health["warning_count"] == 1
    assert health["checks_evaluated"] == 6
    anomaly = health["anomalies"][0]
    assert anomaly["code"] == "high_404_ratio"
    assert anomaly["severity"] == "medium"
    assert anomaly["metrics"] == {"ratio": 0.44, "count_404": 11, "total_http": 25}
    assert "44.00%" in anomaly["detail"]


def test_harness_health_triggers_credentials_unauthenticated() -> None:
    health_from_manifest = compute_harness_health_checks(
        manifest={
            "status": "finished",
            "auth": {
                "authenticated_actors": [],
                "unauthenticated_credentialed_actors": ["member_a", "admin"],
            },
        },
    )
    assert health_from_manifest["status"] == "warnings"
    assert health_from_manifest["warning_count"] == 1
    a = health_from_manifest["anomalies"][0]
    assert a["code"] == "credentials_unauthenticated"
    assert a["severity"] == "high"
    assert a["metrics"]["unauthenticated_credentialed_actors"] == ["member_a", "admin"]
    assert a["metrics"]["authenticated_actors"] == []

    # Explicit auth_metadata overrides manifest
    health_explicit = compute_harness_health_checks(
        auth_metadata={
            "authenticated_actors": [],
            "unauthenticated_credentialed_actors": ["qa_user"],
        },
    )
    assert [item["code"] for item in health_explicit["anomalies"]] == ["credentials_unauthenticated"]


def test_harness_health_triggers_oracle_state_transition_friction() -> None:
    events = [
        {
            "event": "oracle_verdict",
            "node_id": "ep:/api/v1/orders/{id}",
            "verdict": "REFUTED",
            "stages": {
                "stage1_control": "passed",
                "stage2_diff": "passed",
                "stage3_clean_replay": "failed_status_404",
            },
        },
        {
            "event": "oracle_verdict",
            "route_template": "/api/v1/coupons/redeem",
            "verdict": "REFUTED",
            "stages": {
                "stage1_control": "passed_oob_callback",
                "stage2_diff": "passed_oob_callback",
                "stage3_clean_replay": "failed_status_409",
            },
        },
        {
            "event": "oracle_verdict",
            "path": "/api/v1/invites/accept",
            "verdict": "REFUTED",
            "stages": {
                "stage1_control": "passed",
                "stage2_diff": "passed",
                "stage3_clean_replay": "failed_status_400",
            },
        },
    ]
    health = compute_harness_health_checks(events=events)
    assert health["status"] == "warnings"
    assert health["warning_count"] == 1
    anomaly = health["anomalies"][0]
    assert anomaly["code"] == "oracle_state_transition_friction"
    assert anomaly["severity"] == "medium"
    assert anomaly["metrics"]["count"] == 3
    assert anomaly["metrics"]["endpoints"] == [
        "/api/v1/orders/{id}",
        "/api/v1/coupons/redeem",
        "/api/v1/invites/accept",
    ]
    assert anomaly["metrics"]["stage3_reasons"] == {
        "failed_status_400": 1,
        "failed_status_404": 1,
        "failed_status_409": 1,
    }


def test_harness_health_triggers_url_path_redaction_corruption() -> None:
    corrupted_report = (
        "## Findings\n"
        "- Endpoint: `http://127.0.0.1:8080/<REDACTED_SECRET:sha256_8=8c6976e5>/upload/index.html`\n"
        "- Replay: curl \"https://app.example.test/api/userdata/<REDACTED_SECRET:sha256_8=ba9c736f>.txt\"\n"
    )
    health = compute_harness_health_checks(report_text=corrupted_report)
    assert health["status"] == "warnings"
    assert health["warning_count"] == 1
    anomaly = health["anomalies"][0]
    assert anomaly["code"] == "url_path_redaction_corruption"
    assert anomaly["severity"] == "high"
    assert anomaly["metrics"]["count"] == 2
    assert any("8c6976e5" in u for u in anomaly["metrics"]["sample_urls"])
    assert any("ba9c736f" in u for u in anomaly["metrics"]["sample_urls"])


@pytest.mark.parametrize(
    "pa_kwargs",
    [
        {"post_auth_stage0_crawl": {"enabled": True, "status": "ok", "new_routes_added": 0}},
        {"post_auth_stage0_crawl": {"status": "ok", "routes_accepted": 0}},
        {"post_auth_stage0_crawl": {"enabled": True, "new_routes_added": 0}},
        {
            "sharding_summary": {
                "shards": [],
                "post_auth_stage0_crawl": {
                    "triggered": True,
                    "status": "ok",
                    "routes_ingested": 0,
                },
            }
        },
    ],
)
def test_harness_health_triggers_post_auth_zero_new_routes(pa_kwargs: dict[str, Any]) -> None:
    health = compute_harness_health_checks(**pa_kwargs)
    assert health["status"] == "warnings"
    assert [a["code"] for a in health["anomalies"]] == ["post_auth_zero_new_routes"]
    assert health["anomalies"][0]["severity"] == "medium"


def test_harness_health_triggers_service_degradation() -> None:
    h_run = compute_harness_health_checks(manifest={"status": "service_degraded"})
    assert h_run["status"] == "warnings"
    assert h_run["anomalies"][0]["code"] == "service_degradation_triggered"
    assert h_run["anomalies"][0]["severity"] == "high"
    assert h_run["anomalies"][0]["metrics"]["run_status"] == "service_degraded"

    h_shard = compute_harness_health_checks(
        manifest={
            "status": "finished",
            "sharding_summary": {
                "shards": [
                    {"shard_id": "shard-1", "status": "finished"},
                    {"shard_id": "shard-2", "status": "service_degraded"},
                ],
            },
        },
    )
    assert h_shard["status"] == "warnings"
    assert h_shard["anomalies"][0]["code"] == "service_degradation_triggered"
    assert h_shard["anomalies"][0]["metrics"]["degraded_shards"] == ["shard-2"]
    assert h_shard["anomalies"][0]["metrics"]["degraded_shard_count"] == 1


def test_process_metrics_wiring_backward_compat_and_markdown_rendering(tmp_path: Path) -> None:
    # 1. Existing callers passing no health kwargs remain 100% compatible.
    legacy_call = compute_process_metrics(events=[], findings=[], token_usage={"total_tokens": 500})
    assert legacy_call["schema"] == "agentic-process-metrics/1"
    assert legacy_call["verification_precision"] == 0.0
    assert legacy_call["tokens_per_verified_finding"] is None
    assert legacy_call["harness_health"] == {
        "status": "healthy",
        "warning_count": 0,
        "anomalies": [],
        "checks_evaluated": 6,
    }

    # 2. Legacy metrics dict without harness_health still renders cleanly.
    stripped = dict(legacy_call)
    stripped.pop("harness_health")
    md_legacy = render_process_metrics_markdown(stripped)
    assert "# Process Metrics Summary" in md_legacy
    assert "## Harness Health Checks" not in md_legacy

    # 3. Healthy write_process_metrics renders clean Harness Health Checks section.
    healthy_dir = tmp_path / "healthy_run"
    _, healthy_md_path, healthy_metrics = write_process_metrics(
        healthy_dir,
        events=_http_events([200] * 10),
        findings=[],
        token_usage={"total_tokens": 1200},
    )
    assert healthy_metrics["harness_health"]["status"] == "healthy"
    healthy_md = healthy_md_path.read_text(encoding="utf-8")
    assert "## Harness Health Checks" in healthy_md
    assert "`healthy`" in healthy_md
    assert "No harness anomalies detected." in healthy_md

    # 4. Run with multiple anomalies writes structured JSON and compact Markdown table.
    warn_dir = tmp_path / "warn_run"
    warn_events: list[dict[str, Any]] = [
        *_http_events([404] * 12 + [200] * 10),  # 12/22 > 0.40
        {
            "event": "oracle_verdict",
            "route_template": "/api/v1/cart/checkout",
            "verdict": "REFUTED",
            "stages": {
                "stage1_control": "passed",
                "stage2_diff": "passed",
                "stage3_clean_replay": "failed_status_409",
            },
        },
    ]
    warn_json_path, warn_md_path, warn_metrics = write_process_metrics(
        warn_dir,
        events=warn_events,
        manifest={
            "status": "service_degraded",
            "auth": {
                "authenticated_actors": [],
                "unauthenticated_credentialed_actors": ["alice"],
            },
            "sharding_summary": {
                "shards": [{"shard_id": "shard-1", "status": "service_degraded"}],
                "post_auth_stage0_crawl": {"enabled": True, "status": "ok", "new_routes_added": 0},
            },
        },
        report_text="PoC URL: http://127.0.0.1:8080/<REDACTED_SECRET:sha256_8=8c6976e5>/admin",
    )
    loaded = json.loads(warn_json_path.read_text(encoding="utf-8"))
    health = loaded["harness_health"]
    assert health == warn_metrics["harness_health"]
    assert health["status"] == "warnings"
    assert health["warning_count"] == 6
    assert health["checks_evaluated"] == 6
    assert {a["code"] for a in health["anomalies"]} == {
        "high_404_ratio",
        "credentials_unauthenticated",
        "oracle_state_transition_friction",
        "url_path_redaction_corruption",
        "post_auth_zero_new_routes",
        "service_degradation_triggered",
    }

    warn_md = warn_md_path.read_text(encoding="utf-8")
    assert "## Harness Health Checks" in warn_md
    assert "`warnings`" in warn_md
    for code in (
        "high_404_ratio",
        "credentials_unauthenticated",
        "oracle_state_transition_friction",
        "url_path_redaction_corruption",
        "post_auth_zero_new_routes",
        "service_degradation_triggered",
    ):
        assert f"`{code}`" in warn_md


# ===========================================================================
# Part 2: Offline Multi-Framework Corpus (7 Web Stacks) & Invariants
# ===========================================================================


def _build_multi_framework_corpus() -> list[dict[str, Any]]:
    """Build anonymized offline fixtures for 7 distinct web stacks (zero Docker/network/LLM)."""
    return [
        # 1. PHP / ThinkPHP-style HTML + debug stack trace + HTML-escaped SQL error
        {
            "name": "php_thinkphp",
            "origin": "http://127.0.0.1:50759",
            "firebase_context": False,
            "receipt": {
                "receipt_id": "req-php-1",
                "url": "http://127.0.0.1:50759/index/index/search.html?q=news",
                "method": "GET",
                "status": 500,
                "content_type": "text/html; charset=utf-8",
                "response_headers": {"Content-Type": "text/html; charset=utf-8"},
                "actor": "anon",
                "body": (
                    "<!doctype html><html><body>"
                    "<div class='think-exception'>"
                    "<h1>SQLSTATE[42000]: Syntax error or access violation</h1>"
                    "<p>SELECT * FROM &#039;cms_article&#039; WHERE title LIKE &quot;%test%&quot;</p>"
                    "<ul>"
                    "<li>GET : http://127.0.0.1:50759/index/Article/info.html?id=1</li>"
                    "<li>127.0.0.1:50759/index/index/search.html</li>"
                    "<li>in /var/www/html/app/index/controller/Article.php line 87</li>"
                    "<li>at /var/www/html/vendor/topthink/framework/src/think/Db.php line 214</li>"
                    "</ul></div>"
                    '<a href="/index/Article/info.html?id=1">Read Article</a>'
                    '<a href="/index/index/search.html">Search</a>'
                    "</body></html>"
                ),
            },
            "expected_routes": {"/index/Article/info.html"},
            "expected_templates": {"/index/article/info.html"},
            "expected_summary_routes": {"/index/Article/info.html"},
            "expected_form_params": set(),
        },
        # 2. Vue / Vite + Firebase SDK SPA bundle
        {
            "name": "vue_vite_firebase",
            "origin": "http://127.0.0.1:8188",
            "firebase_context": True,
            "receipt": {
                "receipt_id": "req-vue-1",
                "url": "http://127.0.0.1:8188/assets/index-B9xK2mQp.js",
                "method": "GET",
                "status": 200,
                "content_type": "application/javascript; charset=utf-8",
                "response_headers": {"Content-Type": "application/javascript"},
                "actor": "anon",
                "body": "\n".join([
                    'const AUTH_BASE = "https://identitytoolkit.googleapis.com";',
                    'const TOKEN_BASE = "https://securetoken.googleapis.com";',
                    'const SIGN_IN = "/v1/accounts:signInWithPassword";',
                    'const RECAPTCHA = "/v2/recaptchaConfig";',
                    'const SDK_TOKEN = "/v1/token";',
                    'const DEV_WORKSPACE = "/Users/dev/Documents/App/src/App.vue";',
                    'const LAZY_CHUNK = "/assets/Panel-D6a37zVp.js";',
                    'const LAZY_STYLE = "/assets/Panel-D6a37zVp.css";',
                    'fetch("/v1/accounts:signInWithPassword", {method: "POST"});',
                    'fetch("/v2/recaptchaConfig");',
                    'fetch("/v1/token", {method: "POST"});',
                    'fetch("/api/settings");',
                    'fetch("/api/upload", {method: "POST"});',
                ]),
            },
            "expected_routes": {"/api/settings", "/api/upload"},
            "expected_templates": {"/api/settings", "/api/upload"},
            "expected_summary_routes": {"/api/settings", "/api/upload"},
            "expected_form_params": set(),
        },
        # 3. Django HTML form + CSRF + traceback noise
        {
            "name": "django",
            "origin": "http://127.0.0.1:8000",
            "firebase_context": False,
            "receipt": {
                "receipt_id": "req-django-1",
                "url": "http://127.0.0.1:8000/admin/login/",
                "method": "GET",
                "status": 200,
                "content_type": "text/html; charset=utf-8",
                "response_headers": {"Content-Type": "text/html"},
                "actor": "anon",
                "body": (
                    "<!doctype html><html><body>"
                    '<form method="post" action="/admin/login/">'
                    '<input type="hidden" name="csrfmiddlewaretoken" value="djTokenExample123456"/>'
                    '<input type="text" name="username"/>'
                    '<input type="password" name="password"/>'
                    '<button type="submit">Log in</button>'
                    "</form>"
                    '<a href="/api/v1/orders/">Orders API</a>'
                    "<pre>File /usr/local/lib/python3.12/site-packages/django/core/handlers/base.py, line 197</pre>"
                    "</body></html>"
                ),
            },
            "expected_routes": {"/admin/login", "/api/v1/orders"},
            "expected_templates": {"/admin/login", "/api/v1/orders"},
            "expected_summary_routes": {"/admin/login/", "/api/v1/orders/"},
            "expected_form_params": {"csrfmiddlewaretoken", "username", "password"},
        },
        # 4. Laravel HTML / Blade with _token and csrf-token meta
        {
            "name": "laravel",
            "origin": "http://127.0.0.1:8001",
            "firebase_context": False,
            "receipt": {
                "receipt_id": "req-laravel-1",
                "url": "http://127.0.0.1:8001/dashboard",
                "method": "GET",
                "status": 200,
                "content_type": "text/html; charset=utf-8",
                "response_headers": {"Content-Type": "text/html"},
                "actor": "user-a",
                "body": (
                    "<!doctype html><html><head>"
                    '<meta name="csrf-token" content="larCsrfTokenExample987654"/>'
                    "</head><body>"
                    '<form method="POST" action="/dashboard/users">'
                    '<input type="hidden" name="_token" value="larCsrfTokenExample987654"/>'
                    '<input type="email" name="email"/>'
                    "</form>"
                    '<a href="/dashboard/users">Manage Users</a>'
                    "<!-- /var/www/html/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php -->"
                    "</body></html>"
                ),
            },
            "expected_routes": {"/dashboard/users"},
            "expected_templates": {"/dashboard/users"},
            "expected_summary_routes": {"/dashboard/users"},
            "expected_form_params": {"_token", "email"},
        },
        # 5. Ruby on Rails HTML with authenticity_token
        {
            "name": "rails",
            "origin": "http://127.0.0.1:3000",
            "firebase_context": False,
            "receipt": {
                "receipt_id": "req-rails-1",
                "url": "http://127.0.0.1:3000/projects/42",
                "method": "GET",
                "status": 200,
                "content_type": "text/html; charset=utf-8",
                "response_headers": {"Content-Type": "text/html"},
                "actor": "user-a",
                "body": (
                    "<!doctype html><html><head>"
                    '<meta name="csrf-param" content="authenticity_token"/>'
                    '<meta name="csrf-token" content="railsAuthTokenExample555"/>'
                    "</head><body>"
                    '<form action="/projects/42/tasks" method="post">'
                    '<input type="hidden" name="authenticity_token" value="railsAuthTokenExample555"/>'
                    '<input type="text" name="title"/>'
                    "</form>"
                    '<a href="/projects/42/tasks">Project Tasks</a>'
                    "<pre>/usr/local/bundle/gems/actionpack-7.1/lib/action_controller/metal.rb:190</pre>"
                    "</body></html>"
                ),
            },
            "expected_routes": {"/projects/42/tasks"},
            "expected_templates": {"/projects/{id}/tasks"},
            "expected_summary_routes": {"/projects/42/tasks"},
            "expected_form_params": {"authenticity_token", "title"},
        },
        # 6. FastAPI / OpenAPI 3.0 JSON spec (outside Firebase context)
        {
            "name": "fastapi_openapi",
            "origin": "http://127.0.0.1:8002",
            "firebase_context": False,
            "receipt": {
                "receipt_id": "req-fastapi-1",
                "url": "http://127.0.0.1:8002/openapi.json",
                "method": "GET",
                "status": 200,
                "content_type": "application/json",
                "response_headers": {"Content-Type": "application/json"},
                "actor": "anon",
                "body": json.dumps({
                    "openapi": "3.1.0",
                    "info": {"title": "FastAPI Inventory", "version": "1.0.0"},
                    "paths": {
                        "/api/v1/token": {
                            "post": {
                                "summary": "OAuth2 access token",
                                "requestBody": {
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "type": "object",
                                                "properties": {
                                                    "username": {"type": "string"},
                                                    "password": {"type": "string"},
                                                },
                                            }
                                        }
                                    }
                                },
                                "responses": {"200": {"description": "OK"}},
                            }
                        },
                        "/api/v1/items/{item_id}": {
                            "get": {
                                "summary": "Read item",
                                "parameters": [
                                    {"name": "item_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                                    {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}},
                                ],
                                "responses": {"200": {"description": "OK"}},
                            }
                        },
                    },
                }),
            },
            "expected_routes": {"/api/v1/token", "/api/v1/items/{item_id}"},
            "expected_templates": {"/api/v1/token", "/api/v1/items/{id}"},
            "expected_summary_routes": {"/api/v1/token", "/api/v1/items/{item_id}"},
            "expected_form_params": set(),
        },
        # 7. Spring Boot / Windows IIS error trace
        {
            "name": "spring_boot_iis",
            "origin": "http://127.0.0.1:8080",
            "firebase_context": False,
            "receipt": {
                "receipt_id": "req-spring-1",
                "url": "http://127.0.0.1:8080/error",
                "method": "GET",
                "status": 500,
                "content_type": "text/html; charset=utf-8",
                "response_headers": {"Content-Type": "text/html"},
                "actor": "anon",
                "body": (
                    "<!doctype html><html><body>"
                    "<h1>Whitelabel Error Page</h1>"
                    "<pre>"
                    "IIS Handler: C:/inetpub/wwwroot/app.aspx\n"
                    "Config: C:\\inetpub\\wwwroot\\web.config\n"
                    "Catalina: /usr/local/tomcat/webapps/ROOT/WEB-INF/classes/AccountController.class\n"
                    "Upstream: http://127.0.0.1:8080/api/v2/accounts\n"
                    "</pre>"
                    '<a href="/api/v2/accounts">Accounts Service</a>'
                    "</body></html>"
                ),
            },
            "expected_routes": {"/api/v2/accounts"},
            "expected_templates": {"/api/v2/accounts"},
            "expected_summary_routes": {"/api/v2/accounts"},
            "expected_form_params": set(),
        },
    ]


@pytest.mark.parametrize("case", _build_multi_framework_corpus(), ids=lambda c: c["name"])
def test_multi_framework_corpus_surface_invariants(tmp_path: Path, case: dict[str, Any]) -> None:
    """Every framework fixture satisfies strict noise-exclusion and route-preservation invariants."""
    origin = case["origin"]
    receipt = case["receipt"]
    firebase_ctx = bool(case["firebase_context"])

    # 1. Preview summary & inline hints
    summary = _extract_surface_summary(receipt, origin)
    inline_hints = _build_surface_hints(receipt, origin)

    # 2. Stage 0 collector + finalization (links, forms, discovery_hints)
    client = _make_client(tmp_path / case["name"], origin)
    try:
        collector = _Stage0Collector(client)
        collector.ingest_surface_summary(summary, source_url=receipt["url"])
        links, forms, _bt, _mp, discovery_hints = _finalize_routes(collector)
    finally:
        client.close()

    # 3. SurfaceFrontierTracker passive ingestion
    tracker = SurfaceFrontierTracker(base_url=origin, allowed_methods=("GET", "POST", "PUT", "DELETE"))
    tracker.ingest_receipt(receipt)

    # Gather all emitted paths across Stage 0, tracker, and inline hints
    stage0_paths = {urlsplit(item["url"]).path for item in [*links, *forms]}
    hint_paths = {urlsplit(h).path for h in discovery_hints}
    inline_hint_paths = {
        urlsplit(u).path
        for u in [*(inline_hints.get("api_endpoints") or []), *(inline_hints.get("links") or [])]
    }
    tracker_paths = {p for _, p in tracker.discovered_routes}
    all_emitted_paths = stage0_paths | hint_paths | inline_hint_paths | tracker_paths

    # Invariant A: ZERO OS filesystem paths anywhere
    for path in all_emitted_paths:
        assert is_os_filesystem_path(path) is False, f"[{case['name']}] OS filesystem path leaked: {path}"
        assert not path.startswith(("/var/www", "/Users/", "/usr/local", "/C:", "C:/")), (
            f"[{case['name']}] Raw OS path leaked: {path}"
        )

    # Invariant B: ZERO port-in-path corruptions anywhere
    for path in all_emitted_paths:
        assert is_port_in_path_artifact(path, origin_url=origin) is False, (
            f"[{case['name']}] Port-in-path artifact leaked: {path}"
        )

    # Invariant C: ZERO cloud auth SDK static routes
    for path in all_emitted_paths:
        assert is_third_party_sdk_static_route(path, sdk_context=firebase_ctx) is False, (
            f"[{case['name']}] Third-party cloud SDK route leaked: {path}"
        )
        assert "/v1/accounts:" not in path, f"[{case['name']}] Firebase accounts route leaked: {path}"
        assert path != "/v2/recaptchaConfig", f"[{case['name']}] Firebase recaptchaConfig leaked: {path}"

    # Invariant D: ZERO hashed JS/CSS chunk paths in discovery_hints (or tracker/links)
    for hint in discovery_hints:
        assert is_hashed_asset_chunk_path(hint) is False, (
            f"[{case['name']}] Hashed chunk leaked into discovery_hints: {hint}"
        )
    for path in all_emitted_paths:
        assert is_hashed_asset_chunk_path(path) is False, (
            f"[{case['name']}] Hashed chunk leaked into surface: {path}"
        )

    # Invariant E: All real application routes and normalized templates are preserved
    summary_paths = {
        urlsplit(str(item.get("url") or item.get("path") or "")).path
        for item in [
            *(summary.get("links") or []),
            *(summary.get("forms") or []),
            *(summary.get("js_calls") or []),
            *(summary.get("spa_routes") or []),
            *(summary.get("openapi_operations") or []),
        ]
    }
    combined_routes = stage0_paths | tracker_paths
    combined_templates = {route_template_of(p) for p in combined_routes}
    for expected_raw in case["expected_summary_routes"]:
        assert expected_raw in summary_paths, (
            f"[{case['name']}] Missing raw route {expected_raw!r} in summary; got {sorted(summary_paths)}"
        )
    for expected in case["expected_routes"]:
        assert expected in combined_routes, (
            f"[{case['name']}] Missing expected route {expected!r}; got {sorted(combined_routes)}"
        )
    for expected_tmpl in case["expected_templates"]:
        assert expected_tmpl in combined_templates, (
            f"[{case['name']}] Missing expected route template {expected_tmpl!r}; got {sorted(combined_templates)}"
        )

    # Invariant F: Framework CSRF / form parameters are captured on forms
    if case["expected_form_params"]:
        extracted_form_params: set[str] = set()
        for f in [*(summary.get("forms") or []), *forms]:
            for p in f.get("params") or ():
                extracted_form_params.add(str(p))
        for expected_param in case["expected_form_params"]:
            assert expected_param in extracted_form_params, (
                f"[{case['name']}] Missing form param {expected_param!r}; got {sorted(extracted_form_params)}"
            )


def test_cross_framework_redaction_invariant_and_health_integration(tmp_path: Path) -> None:
    """Common short words (admin, probe, test, user, login) never corrupt URL paths in agentic_report.py."""
    run_dir = tmp_path / "run-redaction-corpus"
    real_secret = "OpaqueToken-2026-XyZ987!"
    real_session = "a9b8c7d6e5f40123456789abcdef0123"

    _write_json(
        run_dir / "manifest.json",
        {
            "run_id": "run-redaction-corpus-001",
            "target": "http://127.0.0.1:8080",
            "status": "finished",
            "finished": True,
            "untested_areas": [
                "Not tested: /admin/login/audit, /test/user/export, /api/userdata/probe.txt",
            ],
        },
    )
    _write_json(
        run_dir / "receipts" / "req-0001.json",
        {
            "schema": "agentic-receipt/1",
            "receipt_id": "req-0001",
            "actor": "anon",
            "method": "GET",
            "url": (
                "http://127.0.0.1:8080/admin/login/check"
                "?password=admin&token=probe&secret=test&key=user&passwd=login&username=user"
            ),
            "path": "/admin/login/check",
            "query": "password=admin&token=probe&secret=test&key=user&passwd=login&username=user",
            "request_headers": {
                "X-API-Key": "probe",
                "Authorization": f"Bearer {real_secret}",
                "Cookie": f"SESSIONID={real_session}",
            },
            "request_body": "",
            "status": 200,
            "response_headers": {
                "Content-Type": "application/json",
                "Set-Cookie": f"SESSIONID={real_session}; HttpOnly; Path=/",
            },
            "body": json.dumps({
                "ok": True,
                "next": "/admin/login/panel",
                "probe_file": "/api/userdata/probe.txt",
                "test_profile": "/test/user/profile",
            }),
        },
    )
    _write_json(
        run_dir / "findings.json",
        [
            {
                "finding_id": "F-001",
                "title": "Auth bypass across admin login and test user endpoints",
                "class_type": "auth_bypass",
                "severity": "high",
                "method": "GET",
                "url": (
                    "http://127.0.0.1:8080/admin/login/check"
                    "?password=admin&token=probe&secret=test&key=user&passwd=login"
                ),
                "path": "/admin/login/check",
                "route_template": "/admin/login/check",
                "actor": "anon",
                "status": "verified",
                "oracle_verdict": "VERIFIED",
                "evidence": (
                    "Accessed /admin/login/panel, /api/userdata/probe.txt, and /test/user/profile "
                    f"with leaked token={real_secret}"
                ),
                "summary": (
                    "Unauthenticated user accessed /admin/login/panel, /api/userdata/probe.txt, "
                    "and /test/user/profile via login probe test."
                ),
                "proof_receipt_ids": ["req-0001"],
                "control_receipt_ids": [],
            }
        ],
    )

    artifacts = agentic_report.load_run_artifacts(run_dir)
    collected_secrets = agentic_report._collect_secret_values(artifacts)
    for common_word in ("admin", "probe", "test", "user", "login"):
        assert common_word not in collected_secrets, f"Common short word promoted globally: {common_word}"
    assert real_secret in collected_secrets
    assert real_session in collected_secrets

    report_summary = agentic_report.generate_run_reports(run_dir)
    md_text = Path(report_summary["markdown_path"]).read_text(encoding="utf-8")
    sarif_text = Path(report_summary["sarif_path"]).read_text(encoding="utf-8")

    # All URL paths containing admin/probe/test/user/login stay intact in report.md and report.sarif
    for preserved_path in (
        "/admin/login/check",
        "/admin/login/panel",
        "/api/userdata/probe.txt",
        "/test/user/profile",
    ):
        assert preserved_path in md_text, f"Path corrupted in report.md: {preserved_path}"
        assert preserved_path in sarif_text, f"Path corrupted in report.sarif: {preserved_path}"

    # Sensitive query parameters and real secrets are properly redacted
    assert "password=<REDACTED>" in md_text
    assert "token=<REDACTED>" in md_text
    assert "secret=<REDACTED>" in md_text
    assert "key=<REDACTED>" in md_text
    assert "passwd=<REDACTED>" in md_text
    assert real_secret not in md_text
    assert real_secret not in sarif_text
    assert real_session not in md_text
    assert real_session not in sarif_text

    # Health check confirms zero URL path redaction corruption in generated report.md
    health = compute_harness_health_checks(events=_http_events([200] * 5), report_text=md_text)
    assert health["status"] == "healthy"
    assert health["anomalies"] == []
