"""Tests for offline seed surface importer and optional tech-hints helper (scripts/agentic_seed.py)."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

import agentic_seed
from agentic_seed import (
    MAX_SEED_FILE_BYTES,
    apply_seed_surface,
    enrich_tech_discovery_hints,
    load_seed_surface_files,
)
from agentic_surface import SurfaceFrontierTracker

BASE_URL = "https://app.example.com"


def _all_entries(seed_data: dict) -> list[dict]:
    return [*seed_data["links"], *seed_data["forms"]]


def _by_key(seed_data: dict) -> dict[tuple[str, str], dict]:
    return {(item["method"], item["url"]): item for item in _all_entries(seed_data)}


def test_mitm_scope_nested_flat_and_list_formats(tmp_path: Path) -> None:
    nested_file = tmp_path / "mitm-nested.json"
    nested_file.write_text(
        json.dumps(
            {
                "app.example.com": {
                    "GET /api/orders": {
                        "count": 3,
                        "sample_url": "https://app.example.com/api/orders?status=open&api_key=TOPSECRETVAL",
                        "statuses": {"200": 3},
                    },
                    "POST /api/orders": {
                        "count": 1,
                        "params": [
                            {"name": "item_id", "in": "json", "sample": "LEAK_IF_KEPT"},
                            {"name": "quantity", "in": "json", "sample": "5"},
                        ],
                        "statuses": {"201": 1},
                    },
                },
                "evil.example.com": {
                    "GET /internal/secret": {"count": 2},
                },
            }
        ),
        encoding="utf-8",
    )

    flat_file = tmp_path / "scope-routes-live.json"
    flat_file.write_text(
        json.dumps(
            {
                "GET /api/orders": {
                    "count": 4,
                    "host": "app.example.com",
                    "sample_url": "https://app.example.com/api/orders?sort=desc",
                    "sample_query": "cursor=CURS_SECRET",
                    "statuses": {"200": 4},
                },
                "DELETE /api/orders/42": {
                    "count": 1,
                    "host": "app.example.com",
                    "sample_url": "https://app.example.com/api/orders/42",
                    "statuses": {"204": 1},
                },
                "GET /other-host-leak": {
                    "count": 1,
                    "host": "other.example.com",
                },
            }
        ),
        encoding="utf-8",
    )

    list_file = tmp_path / "mitm-list.json"
    list_file.write_text(
        json.dumps(
            [
                {
                    "method": "PATCH",
                    "url": "https://app.example.com/api/orders/42?reason=refund_val",
                    "params": ["notes"],
                }
            ]
        ),
        encoding="utf-8",
    )

    result = load_seed_surface_files(
        [nested_file, flat_file, list_file],
        base_url=BASE_URL,
    )

    serialized = json.dumps(result)
    assert "TOPSECRETVAL" not in serialized
    assert "LEAK_IF_KEPT" not in serialized
    assert "CURS_SECRET" not in serialized
    assert "refund_val" not in serialized

    assert result["url"] == "https://app.example.com/"
    assert result["stats"]["files_loaded"] == 3
    assert result["stats"]["routes_dropped_scope"] == 2
    assert result["stats"]["routes_dropped_static"] == 0
    assert result["stats"]["formats_detected"] == ["mitm_scope"]

    entries = _by_key(result)
    assert ("GET", "/api/orders") in entries
    assert set(entries[("GET", "/api/orders")]["params"]) == {"api_key", "cursor", "sort", "status"}
    assert ("POST", "/api/orders") in entries
    assert set(entries[("POST", "/api/orders")]["params"]) == {"item_id", "quantity"}
    assert ("DELETE", "/api/orders/42") in entries
    assert ("PATCH", "/api/orders/42") in entries
    assert set(entries[("PATCH", "/api/orders/42")]["params"]) == {"notes", "reason"}


def test_har_v12_strips_all_secrets_headers_and_cookies_while_preserving_param_names(
    tmp_path: Path,
) -> None:
    bearer_secret = "Bearer " + "s3cr3t_" + "tok_998877665544332211"
    cookie_secret = "session_id=c00k1e_s3cr3t_abc123xyz"
    api_key_secret = "xkey_super_private_value_999"
    query_secret = "q_secret_token_value_888"
    json_pw_secret = "MyUltraSecretPassphrase!42"
    form_csrf_secret = "csrf_secret_nonce_777"
    multipart_secret = "multipart_hidden_payload_666"
    resp_secret = "response_body_private_ssn_555"

    har_payload = {
        "log": {
            "version": "1.2",
            "creator": {"name": "browser", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": f"https://app.example.com/api/v1/transfers?auth_token={query_secret}&currency=USD",
                        "headers": [
                            {"name": "Authorization", "value": bearer_secret},
                            {"name": "Cookie", "value": cookie_secret},
                            {"name": "X-API-Key", "value": api_key_secret},
                        ],
                        "cookies": [{"name": "session_id", "value": "c00k1e_s3cr3t_abc123xyz"}],
                        "queryString": [
                            {"name": "auth_token", "value": query_secret},
                            {"name": "currency", "value": "USD"},
                            {"name": "dry_run", "value": "true"},
                        ],
                        "postData": {
                            "mimeType": "application/json; charset=utf-8",
                            "text": json.dumps(
                                {
                                    "to_account": "acct-99",
                                    "amount": 250,
                                    "confirm_pin": json_pw_secret,
                                }
                            ),
                        },
                    },
                    "response": {
                        "status": 200,
                        "content": {"text": resp_secret},
                    },
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://app.example.com/profile/update",
                        "headers": [{"name": "Cookie", "value": cookie_secret}],
                        "postData": {
                            "mimeType": "application/x-www-form-urlencoded",
                            "text": f"display_name=Alice&csrf_token={form_csrf_secret}",
                            "params": [
                                {"name": "display_name", "value": "Alice"},
                                {"name": "csrf_token", "value": form_csrf_secret},
                                {"name": "bio", "value": "private_bio_text"},
                            ],
                        },
                    },
                    "response": {"status": 302},
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://app.example.com/documents/upload",
                        "postData": {
                            "mimeType": "multipart/form-data; boundary=----B",
                            "text": (
                                "------B\r\n"
                                'Content-Disposition: form-data; name="doc_title"\r\n\r\n'
                                f"{multipart_secret}\r\n"
                                "------B--\r\n"
                            ),
                        },
                    },
                    "response": {"status": 201},
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://app.example.com/static/bundle.css?v=123",
                    },
                    "response": {"status": 200},
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://analytics.thirdparty.example/collect?id=1",
                    },
                    "response": {"status": 204},
                },
            ],
        }
    }

    har_file = tmp_path / "capture.har"
    har_file.write_text(json.dumps(har_payload), encoding="utf-8")

    result = load_seed_surface_files([har_file], base_url=BASE_URL)
    serialized = json.dumps(result)

    for forbidden in (
        bearer_secret,
        "s3cr3t_tok_998877665544332211",
        cookie_secret,
        "c00k1e_s3cr3t_abc123xyz",
        api_key_secret,
        query_secret,
        json_pw_secret,
        form_csrf_secret,
        multipart_secret,
        resp_secret,
        "private_bio_text",
        "Authorization",
        "X-API-Key",
    ):
        assert forbidden not in serialized

    assert result["stats"]["formats_detected"] == ["har"]
    assert result["stats"]["routes_dropped_scope"] == 1
    assert result["stats"]["routes_dropped_static"] == 1
    assert result["stats"]["routes_accepted"] == 3

    link_map = {(item["method"], item["url"]): item for item in result["links"]}
    form_map = {(item["method"], item["url"]): item for item in result["forms"]}

    assert ("POST", "/api/v1/transfers") in link_map
    assert "?" not in link_map[("POST", "/api/v1/transfers")]["url"]
    assert set(link_map[("POST", "/api/v1/transfers")]["params"]) == {
        "amount",
        "auth_token",
        "confirm_pin",
        "currency",
        "dry_run",
        "to_account",
    }

    assert ("POST", "/profile/update") in form_map
    assert set(form_map[("POST", "/profile/update")]["params"]) == {
        "bio",
        "csrf_token",
        "display_name",
    }

    assert ("POST", "/documents/upload") in form_map
    assert form_map[("POST", "/documents/upload")]["params"] == ["doc_title"]


def test_zap_site_and_snapshot_json_formats(tmp_path: Path) -> None:
    zap_site_file = tmp_path / "zap-report.json"
    zap_site_file.write_text(
        json.dumps(
            {
                "@version": "2.15.0",
                "site": [
                    {
                        "@name": "https://app.example.com",
                        "@host": "app.example.com",
                        "@port": "443",
                        "@ssl": "true",
                        "alerts": [
                            {
                                "pluginid": "40018",
                                "alert": "SQL Injection",
                                "instances": [
                                    {
                                        "uri": "https://app.example.com/api/search?q=secret_query_val",
                                        "method": "GET",
                                        "param": "q",
                                    },
                                    {
                                        "uri": "/api/checkout",
                                        "method": "POST",
                                        "param": "coupon_code",
                                    },
                                ],
                            }
                        ],
                    },
                    {
                        "@name": "https://offscope.example.net",
                        "alerts": [
                            {
                                "instances": [
                                    {"uri": "/leak", "method": "GET", "param": "id"},
                                ]
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    zap_snap_file = tmp_path / "zap-snapshot.json"
    zap_snap_file.write_text(
        json.dumps(
            {
                "urls": [
                    "https://app.example.com/api/invoices?year=2026",
                    "https://app.example.com/assets/logo.svg",
                ],
                "alerts": [
                    {
                        "url": "https://app.example.com/api/invoices",
                        "method": "GET",
                        "param": "tenant_id",
                        "alert": "IDOR",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = load_seed_surface_files([zap_site_file, zap_snap_file], base_url=BASE_URL)
    assert result["stats"]["formats_detected"] == ["zap"]
    assert result["stats"]["routes_dropped_scope"] == 1
    assert result["stats"]["routes_dropped_static"] == 1
    assert "secret_query_val" not in json.dumps(result)

    entries = _by_key(result)
    assert entries[("GET", "/api/search")]["params"] == ["q"]
    assert entries[("POST", "/api/checkout")]["params"] == ["coupon_code"]
    assert set(entries[("GET", "/api/invoices")]["params"]) == {"tenant_id", "year"}


def test_ffuf_json_and_nuclei_jsonl_formats(tmp_path: Path) -> None:
    ffuf_file = tmp_path / "ffuf.json"
    ffuf_file.write_text(
        json.dumps(
            {
                "commandline": "ffuf -u https://app.example.com/FUZZ",
                "config": {"method": "GET"},
                "results": [
                    {"url": "https://app.example.com/admin/audit?page=1", "status": 403},
                    {"url": "https://app.example.com/img/banner.png", "status": 200},
                    {"url": "https://evil.example.com/admin", "status": 200},
                ],
            }
        ),
        encoding="utf-8",
    )

    nuclei_file = tmp_path / "nuclei.jsonl"
    nuclei_lines = [
        json.dumps(
            {
                "template-id": "exposed-openapi",
                "type": "http",
                "host": "https://app.example.com",
                "matched-at": "https://app.example.com/api/v1/openapi.json?key=SECRETKEY",
            }
        ),
        json.dumps(
            {
                "template-id": "webhook-check",
                "type": "http",
                "url": "https://app.example.com/api/webhooks",
                "request": "POST /api/webhooks HTTP/1.1\r\nAuthorization: Bearer HIDDEN_NUCLEI_TOK\r\n\r\n",
            }
        ),
        json.dumps(
            {
                "template-id": "offscope-check",
                "type": "http",
                "matched-at": "https://other.example.com/debug",
            }
        ),
    ]
    nuclei_file.write_text("\n".join(nuclei_lines) + "\n", encoding="utf-8")

    result = load_seed_surface_files([ffuf_file, nuclei_file], base_url=BASE_URL)
    serialized = json.dumps(result)
    assert "SECRETKEY" not in serialized
    assert "HIDDEN_NUCLEI_TOK" not in serialized

    assert result["stats"]["formats_detected"] == ["ffuf", "nuclei"]
    assert result["stats"]["routes_dropped_scope"] == 2
    assert result["stats"]["routes_dropped_static"] == 1

    entries = _by_key(result)
    assert ("GET", "/admin/audit") in entries
    assert entries[("GET", "/admin/audit")]["params"] == ["page"]
    assert ("GET", "/api/v1/openapi.json") in entries
    assert entries[("GET", "/api/v1/openapi.json")]["params"] == ["key"]
    assert ("POST", "/api/webhooks") in entries
    assert all(item["method"] != "HTTP" for item in _all_entries(result))


def test_generic_json_and_plain_text_formats(tmp_path: Path) -> None:
    generic_file = tmp_path / "surface.json"
    generic_file.write_text(
        json.dumps(
            {
                "routes": [
                    "https://app.example.com/api/reports?format=csv",
                    {"method": "PUT", "path": "/api/settings", "params": ["theme", "locale"]},
                ],
                "forms": [
                    {"method": "POST", "action": "/feedback", "fields": ["message", "rating"]},
                ],
            }
        ),
        encoding="utf-8",
    )

    text_file = tmp_path / "gau-urls.txt"
    text_file.write_text(
        "\n".join(
            [
                "# Exported from gau / wayback",
                "",
                "https://app.example.com/api/reports?owner=alice_secret",
                "/api/v2/export?range=30d",
                "POST /api/v2/export",
                "https://app.example.com/static/font.woff2",
                "https://sub.app.example.com/leaked",
                "evil.example.com/schemeless-offorigin",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = load_seed_surface_files([generic_file, text_file], base_url=BASE_URL)
    assert "alice_secret" not in json.dumps(result)
    assert result["stats"]["formats_detected"] == ["generic_json", "text"]
    assert result["stats"]["routes_dropped_scope"] == 2
    assert result["stats"]["routes_dropped_static"] == 1

    entries = _by_key(result)
    assert set(entries[("GET", "/api/reports")]["params"]) == {"format", "owner"}
    assert set(entries[("PUT", "/api/settings")]["params"]) == {"locale", "theme"}
    assert entries[("GET", "/api/v2/export")]["params"] == ["range"]
    assert ("POST", "/api/v2/export") in entries
    assert any(
        f["method"] == "POST" and f["url"] == "/feedback" and set(f["params"]) == {"message", "rating"}
        for f in result["forms"]
    )


def test_strict_scope_guard_and_excluded_paths(tmp_path: Path) -> None:
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text(
        "\n".join(
            [
                "https://app.example.com/api/orders",
                "http://app.example.com/api/wrong-scheme",
                "https://app.example.com:8443/api/wrong-port",
                "https://evil.example.com/api/orders",
                "//evil.example.com/scheme-relative",
                "javascript:alert(1)",
                "mailto:sec@example.com",
                "https://user:pass@app.example.com/api/creds-in-url",
                "https://app.example.com/logout",
                "https://app.example.com/LOGOUT/confirm",
                "https://app.example.com/api/../logout",
                "https://app.example.com/%6cogout",
                "https://app.example.com/internal/metrics",
                "https://app.example.com/assets/app.CSS",
                "https://app.example.com/images/photo.jpg?size=large",
                "https://app.example.com/favicon.ico",
            ]
        ),
        encoding="utf-8",
    )

    result = load_seed_surface_files(
        [urls_file],
        base_url=BASE_URL,
        excluded_paths=("/logout", "/internal/*"),
    )

    assert result["stats"]["routes_accepted"] == 1
    assert result["stats"]["routes_dropped_scope"] == 12
    assert result["stats"]["routes_dropped_static"] == 3
    assert result["links"] == [{"method": "GET", "url": "/api/orders", "params": []}]


def test_safe_file_reader_rejects_symlinks_non_regular_and_oversized_files(tmp_path: Path) -> None:
    real_file = tmp_path / "real.txt"
    real_file.write_text("/api/orders\n", encoding="utf-8")

    link_file = tmp_path / "link.txt"
    link_file.symlink_to(real_file)
    with pytest.raises(ValueError, match="symlink"):
        load_seed_surface_files([link_file], base_url=BASE_URL)

    broken_link = tmp_path / "broken.txt"
    broken_link.symlink_to(tmp_path / "does-not-exist.txt")
    with pytest.raises(ValueError, match="symlink"):
        load_seed_surface_files([broken_link], base_url=BASE_URL)

    subdir = tmp_path / "adir"
    subdir.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        load_seed_surface_files([subdir], base_url=BASE_URL)

    with pytest.raises(ValueError, match="missing or unreadable"):
        load_seed_surface_files([tmp_path / "missing.json"], base_url=BASE_URL)

    big_file = tmp_path / "oversized.txt"
    with big_file.open("wb") as fh:
        fh.truncate(MAX_SEED_FILE_BYTES + 1)
    with pytest.raises(ValueError, match="maximum size"):
        load_seed_surface_files([big_file], base_url=BASE_URL)


def test_max_routes_prioritization_and_discovery_hints_cap(tmp_path: Path) -> None:
    lines = ["/", "/about", "/contact", "/terms", "/privacy"]
    lines.extend(f"/page-{i}" for i in range(1, 25))
    lines.extend(
        [
            "POST /api/v1/orders?item=1&qty=2",
            "PUT /api/v1/users/profile?role=member",
            "GET /api/v1/orders/101",
            "GET /api/v1/orders/102",
            "GET /api/v1/orders/103",
            "GET /api/v1/invoices?status=paid",
            "GET /admin/reports/export?format=csv",
            "GET /api/v1/users?search=bob",
        ]
    )

    seed_file = tmp_path / "many.txt"
    seed_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = load_seed_surface_files(
        [seed_file],
        base_url=BASE_URL,
        max_routes=8,
        max_discovery_hints=4,
    )

    assert result["stats"]["routes_accepted"] == 8
    assert len(result["links"]) + len(result["forms"]) == 8

    kept_keys = {(item["method"], item["url"]) for item in _all_entries(result)}
    assert ("POST", "/api/v1/orders") in kept_keys
    assert ("PUT", "/api/v1/users/profile") in kept_keys
    assert ("GET", "/api/v1/invoices") in kept_keys
    assert ("GET", "/admin/reports/export") in kept_keys
    assert ("GET", "/") not in kept_keys
    assert ("GET", "/about") not in kept_keys

    hints = result["discovery_hints"]
    assert len(hints) == 4
    assert all(h.startswith("/") and "?" not in h for h in hints)
    # Template diversity: /api/v1/orders/{id} should not consume multiple hint slots when other GET endpoints exist.
    order_id_hints = [h for h in hints if h.startswith("/api/v1/orders/")]
    assert len(order_id_hints) <= 1


def test_apply_seed_surface_feeds_surface_frontier_tracker(tmp_path: Path) -> None:
    seed_file = tmp_path / "seed.json"
    seed_file.write_text(
        json.dumps(
            {
                "routes": [
                    "https://app.example.com/api/orders?status=open",
                    "https://app.example.com/api/orders/42",
                    {"method": "POST", "path": "/api/orders", "params": ["item_id"]},
                ],
                "forms": [
                    {"method": "POST", "action": "/profile/update", "fields": ["bio"]},
                ],
            }
        ),
        encoding="utf-8",
    )

    seed_data = load_seed_surface_files([seed_file], base_url=BASE_URL)
    tracker = SurfaceFrontierTracker(
        base_url=BASE_URL,
        allowed_methods=("GET", "POST"),
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
    )

    assert apply_seed_surface(tracker, {}) == 0

    ingested = apply_seed_surface(tracker, seed_data)
    assert ingested == 4

    unvisited = tracker.unvisited_routes()
    assert any(r.startswith("GET /api/orders") and "status=" in r for r in unvisited)
    assert any(r == "GET /api/orders/42" for r in unvisited)
    assert any(r.startswith("POST /api/orders") and "item_id=" in r for r in unvisited)
    assert any(r.startswith("POST /profile/update") and "bio=" in r for r in unvisited)

    assert "/api/orders/42" in tracker.discovered_objects
    assert tracker.discovered_objects["/api/orders/42"]["owner_actor"] == ""
    assert "seed" in tracker.discovered_objects["/api/orders/42"]["seen_by"]


def test_enrich_tech_discovery_hints_dedup_cap_and_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    # Empty tags keep normalized existing hints without additions.
    assert enrich_tech_discovery_hints([], existing_hints=["/", "/api/orders/", "/api/orders"]) == [
        "/",
        "/api/orders",
    ]

    # Stack-specific hints + deduplication + max_added cap.
    enriched_spring = enrich_tech_discovery_hints(
        ["Spring Boot"],
        existing_hints=["/actuator/", "/api/health"],
        max_added=4,
    )
    assert enriched_spring[:2] == ["/actuator", "/api/health"]
    assert len(enriched_spring) == 6
    assert len({h.lower() for h in enriched_spring}) == len(enriched_spring)
    assert "/actuator/health" in enriched_spring
    assert all(h.startswith("/") for h in enriched_spring)

    # max_added=0 appends nothing.
    assert enrich_tech_discovery_hints(["django"], existing_hints=["/"], max_added=0) == ["/"]

    # Built-in fallback still works cleanly even if tech_routes module is unavailable.
    monkeypatch.setitem(sys.modules, "tech_routes", None)
    enriched_next = enrich_tech_discovery_hints(
        ["Next.js", "GraphQL", "FastAPI"],
        existing_hints=["/graphql"],
        max_added=5,
    )
    assert enriched_next[0] == "/graphql"
    assert len(enriched_next) == 6
    assert enriched_next.count("/graphql") == 1
    assert any(h.startswith("/api/") or h == "/openapi.json" for h in enriched_next[1:])


def test_agentic_seed_has_zero_legacy_engine_imports() -> None:
    src = Path(agentic_seed.__file__).read_text(encoding="utf-8")
    for forbidden in ("full_agent_", "policy_engine", "campaign_", "urllib.request", "import requests"):
        assert forbidden not in src
