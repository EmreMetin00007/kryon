"""Sprint B Slice 1 tests: discovery & extraction of form and JSON POST carriers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

_SURFACE_DIR = Path(__file__).resolve().parents[1] / "mcp-servers/mcp-memory-server"
if str(_SURFACE_DIR) not in sys.path:
    sys.path.append(str(_SURFACE_DIR))

from cco_surface_core.extract import extract_html, extract_js_calls
from cco_surface_core.parsers import parse_browser_crawl
from full_agent_python_solver import CRAWL_TOOL, PythonSolver
from python_discovery_runtime import extract_json_hypermedia
from test_full_agent_python_solver import python_broker, terminal


def test_extract_html_distinguishes_form_urlencoded_and_json_enctype():
    html = (
        '<form action="/api/search" method="POST">'
        '<input name="q" value="alpha">'
        '<input type="hidden" name="cat" value="books">'
        "</form>"
        '<form action="/api/render" method="POST" enctype="application/json; charset=utf-8">'
        '<input name="template_name" value="welcome">'
        "</form>"
    )
    recs = extract_html(html, "http://127.0.0.1:9000/")
    search = next(r for r in recs if r["url"] == "http://127.0.0.1:9000/api/search")
    assert search["method"] == "POST"
    assert search["content_type"] == "application/x-www-form-urlencoded"
    assert search["params"] == [
        {"name": "q", "in": "body", "sample": "alpha"},
        {"name": "cat", "in": "body", "sample": "books"},
    ]

    render = next(r for r in recs if r["url"] == "http://127.0.0.1:9000/api/render")
    assert render["method"] == "POST"
    assert render["content_type"] == "application/json"
    assert render["params"] == [
        {"name": "template_name", "in": "json", "sample": "welcome"},
    ]


def test_extract_js_calls_marks_json_post_content_type():
    js = """
    fetch('/api/items/search', {method: 'POST', body: JSON.stringify({query: 'x', page: 1})});
    """
    recs = extract_js_calls(js, "http://127.0.0.1:9000/")
    assert len(recs) == 1
    assert recs[0]["method"] == "POST"
    assert recs[0]["content_type"] == "application/json"
    assert {p["name"] for p in recs[0]["params"]} == {"query", "page"}
    assert all(p["in"] == "json" for p in recs[0]["params"])


def test_extract_json_hypermedia_extracts_post_json_and_form_without_inventing_urls():
    payload = {
        "actions": [
            {
                "action": "/api/search",
                "method": "POST",
                "operation_id": "op-search-json",
                "json_body": {"query": "secret-sample", "limit": 10},
            },
            {
                "url": "/api/filter",
                "method": "POST",
                "operation_id": "op-filter-form",
                "form": {"tag": "secret-tag"},
            },
            {
                "url": "https://evil.example/steal",
                "method": "POST",
                "json_body": {"x": "1"},
            },
        ],
        "items": [{"id": 42, "name": "widget"}],
    }
    extracted, truncated = extract_json_hypermedia(payload, "http://127.0.0.1:9000/")
    assert not truncated
    assert len(extracted) == 2

    json_item = next(row for row in extracted if row["url"].endswith("/api/search"))
    assert json_item["method"] == "POST"
    assert json_item["content_type"] == "application/json"
    assert json_item["operation_id"] == "op-search-json"
    assert json_item["params"] == [
        {"name": "query", "in": "json", "sample": "secret-sample"},
        {"name": "limit", "in": "json", "sample": "10"},
    ]

    form_item = next(row for row in extracted if row["url"].endswith("/api/filter"))
    assert form_item["method"] == "POST"
    assert form_item["content_type"] == "application/x-www-form-urlencoded"
    assert form_item["operation_id"] == "op-filter-form"
    assert form_item["params"] == [
        {"name": "tag", "in": "form", "sample": "secret-tag"},
    ]


def test_surface_records_and_discovery_frontier_preserve_carrier_and_redact_values(python_broker):
    solver = PythonSolver(python_broker, model="model")
    recon, enum_spec = python_broker.tasks.specs[0], python_broker.tasks.specs[1]
    body = json.dumps({
        "actions": [
            {
                "url": "/api/search",
                "method": "POST",
                "operation_id": "op-search",
                "json_body": {"query": "sensitive-body-sample"},
            },
            {
                "url": "/api/notes",
                "method": "POST",
                "form": {"note": "unauthorized-sample"},
            },
        ]
    })
    python_broker.is_readonly_post_authorized = (
        lambda url, carrier="", operation_id="": url.endswith("/api/search") and carrier == "json"
    )
    recon_view = python_broker.view({"status_code": 200, "text": body})
    python_broker.results.append({
        "spec_id": recon.id,
        "tool": "kali-tools_curl_request",
        "arguments": {"url": recon.target, "follow_redirects": False},
        **recon_view,
    })
    solver.summaries[recon.id] = solver.compile_summary(recon, terminal(recon))

    context = solver.context(enum_spec)
    frontier = context["discovery_frontier"]
    raw_frontier = json.dumps(frontier)
    assert "sensitive-body-sample" not in raw_frontier
    assert "unauthorized-sample" not in raw_frontier

    search_action = next(item for item in frontier["frontier"] if item["route_shape"].endswith("/api/search"))
    assert search_action["status"] == "completed"
    assert search_action["method"] == "POST"
    assert search_action["carrier"] == "json"
    assert search_action["content_type"] == "application/json"
    assert search_action["param_names"] == ["query"]

    notes_action = next(item for item in frontier["frontier"] if item["status"] == "blocked")
    assert notes_action["reason_code"] == "unsupported_readonly_method"
    assert notes_action["carrier"] == "form"
    assert notes_action["param_names"] == ["note"]


def test_crawl_json_asset_extracts_hypermedia_and_marks_crawled_json_completed(python_broker):
    solver = PythonSolver(python_broker, model="model")
    recon, enum_spec = python_broker.tasks.specs[0], python_broker.tasks.specs[1]
    catalog_url = f"{enum_spec.target.rstrip('/')}/catalog"
    notes_url = f"{enum_spec.target.rstrip('/')}/notes"
    raw_crawl = {
        "ok": True,
        "url": enum_spec.target,
        "pages": [
            {"url": enum_spec.target, "status": 200, "content_type": "text/html"},
            {"url": catalog_url, "status": 200, "content_type": "application/json"},
            {"url": notes_url, "status": 200, "content_type": "application/json"},
        ],
        "asset_texts": [
            {
                "url": catalog_url,
                "content_type": "application/json",
                "text": json.dumps({
                    "actions": [{
                        "url": "/api/catalog/query",
                        "method": "POST",
                        "operation_id": "op-catalog-query",
                        "json_body": {"term": "widget"},
                    }]
                }),
            },
            {
                "url": notes_url,
                "content_type": "application/json",
                "text": json.dumps({"notes": [{"id": 1, "title": "public"}]}),
            },
        ],
    }
    records = parse_browser_crawl(raw_crawl, target="127.0.0.1", base=enum_spec.target)
    python_broker.is_readonly_post_authorized = (
        lambda url, carrier="", operation_id="": url.endswith("/api/catalog/query") and carrier == "json"
    )
    crawl_view = python_broker.view({
        "ok": True,
        "target": "127.0.0.1",
        "base_url": enum_spec.target,
        "pages": raw_crawl["pages"],
        "records": records,
    })
    python_broker.results.append({
        "spec_id": enum_spec.id,
        "tool": CRAWL_TOOL,
        "arguments": {"target": enum_spec.target},
        **crawl_view,
    })
    solver.summaries[recon.id] = solver.compile_summary(recon, terminal(recon))

    frontier = solver.context(enum_spec)["discovery_frontier"]["frontier"]
    actions = [a for state in solver.hydrate_discovery_state(enum_spec).values() for a in state.actions.values()]
    catalog_action = next(item for item in actions if item["url"] == catalog_url)
    notes_action = next(item for item in actions if item["url"] == notes_url)
    post_raw = next(item for item in actions if item["url"].endswith("/api/catalog/query"))
    post_action = next(item for item in frontier if item["action_id"] == post_raw["action_id"])

    assert catalog_action["status"] == "completed"
    assert "json_link" not in catalog_action.get("link_relations", [])
    assert notes_action["status"] == "completed"
    assert "json_link" not in notes_action.get("link_relations", [])
    assert post_action["method"] == "POST"
    assert post_action["carrier"] == "json"
    assert post_action["param_names"] == ["term"]

    submitted = {"status": "done", "next": "", "steps": []}
    assert solver._is_premature_enum_summary(enum_spec, submitted) is False

    # Direct asset_texts in tool value also parses hypermedia and marks JSON pages completed.
    solver_direct = PythonSolver(python_broker, model="model")
    solver_direct.summaries[recon.id] = solver.summaries[recon.id]
    python_broker.results[-1] = {
        "spec_id": enum_spec.id,
        "tool": CRAWL_TOOL,
        "arguments": {"target": enum_spec.target},
        **python_broker.view(raw_crawl),
    }
    solver_direct.context(enum_spec)
    direct_actions = [a for state in solver_direct.hydrate_discovery_state(enum_spec).values() for a in state.actions.values()]
    direct_notes = next(item for item in direct_actions if item["url"] == notes_url)
    assert direct_notes["status"] == "completed"
    assert any(item["url"].endswith("/api/catalog/query") and item["method"] == "POST" for item in direct_actions)
    assert solver_direct._is_premature_enum_summary(enum_spec, submitted) is False


def test_surface_records_ignores_synthetic_work_queue_operation_id(python_broker):
    solver = PythonSolver(python_broker, model="model")
    enum_spec = python_broker.tasks.specs[1]
    coupon_url = f"{enum_spec.target.rstrip('/')}/biz/coupon/test-1"
    view = python_broker.view({
        "ok": True,
        "target": "127.0.0.1",
        "base_url": enum_spec.target,
        "records": [
            {
                "url": coupon_url,
                "method": "POST",
                "content_type": "application/json",
                "params": [{"name": "op", "in": "json", "sample": ""}],
            }
        ],
        "work_queue": [
            {
                "url": coupon_url,
                "method": "POST",
                "content_type": "application/json",
                "params": [{"name": "op", "in": "json", "sample": ""}],
                "operation": {"protocol": "http", "kind": "http", "name": "", "selection": "route"},
                "operation_id": "op-f426f88557326a76916b91350ba6e77d",
            }
        ],
    })
    recs = solver.surface_records(view["result"], {"target": enum_spec.target}, enum_spec, view["content_ref"])
    post_rec = next(r for r in recs if r["url"] == coupon_url and r["method"] == "POST")
    assert "operation_id" not in post_rec
