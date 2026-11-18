"""Sprint D Slice 1 tests: SPA surface discovery (JS routes, hash/router/XHR, OpenAPI, candidate eligibility)."""
from __future__ import annotations

import hashlib
import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

_SURFACE_DIR = Path(__file__).resolve().parents[1] / "mcp-servers/mcp-memory-server"
if str(_SURFACE_DIR) not in sys.path:
    sys.path.append(str(_SURFACE_DIR))
_LAB_DIR = Path(__file__).resolve().parents[1] / "scripts/lab"
if str(_LAB_DIR) not in sys.path:
    sys.path.append(str(_LAB_DIR))

from cco_surface_core.extract import (  # noqa: E402
    extract_inline_scripts,
    extract_js_calls,
    extract_spa_routes,
)
from cco_surface_core.parsers import parse_browser_crawl, parse_xhr  # noqa: E402
import python_candidate_runtime as cand  # noqa: E402
from full_agent_python_solver import PythonSolver  # noqa: E402
from test_full_agent_python_solver import python_broker, terminal  # noqa: E402


def test_extract_inline_scripts_and_spa_routes_and_form_js_calls():
    html = """
    <html>
      <head><script src="/assets/bundle.js"></script></head>
      <body>
        <a href="#/xss/search?q=hello">Search</a>
        <script>
          const SPEC_URL = '/assets/spec-v9.json';
          router.push('/orders/:orderId');
          fetch('/api/search', {method: 'GET'});
          axios.get('/api/filter', {params: {q: term, sort: 'asc'}});
          fetch('/api/form-login', {method: 'POST', body: new URLSearchParams('user=alice&code=123')});
        </script>
      </body>
    </html>
    """
    base = "http://127.0.0.1:9100/"
    scripts = extract_inline_scripts(html)
    assert len(scripts) == 1
    assert "SPEC_URL" in scripts[0]

    spa_recs = extract_spa_routes(html + "\n" + scripts[0], base)
    spa_by_url = {r["url"]: r for r in spa_recs}
    assert "http://127.0.0.1:9100/xss/search?q=hello" in spa_by_url
    assert spa_by_url["http://127.0.0.1:9100/xss/search?q=hello"]["sources"] == ["spa-hash"]
    assert spa_by_url["http://127.0.0.1:9100/xss/search?q=hello"]["params"] == [
        {"name": "q", "in": "query", "sample": "hello"}
    ]
    assert "http://127.0.0.1:9100/orders/{orderId}" in spa_by_url
    assert spa_by_url["http://127.0.0.1:9100/orders/{orderId}"]["params"] == [
        {"name": "orderId", "in": "path", "sample": ""}
    ]

    js_recs = extract_js_calls(scripts[0], base)
    filter_rec = next(r for r in js_recs if r["url"] == "http://127.0.0.1:9100/api/filter")
    assert filter_rec["method"] == "GET"
    assert {p["name"] for p in filter_rec["params"]} == {"q", "sort"}
    assert all(p["in"] == "query" for p in filter_rec["params"])

    form_rec = next(r for r in js_recs if r["url"] == "http://127.0.0.1:9100/api/form-login")
    assert form_rec["method"] == "POST"
    assert form_rec["content_type"] == "application/x-www-form-urlencoded"
    assert {p["name"] for p in form_rec["params"]} == {"user", "code"}
    assert all(p["in"] == "body" for p in form_rec["params"])


def test_parse_xhr_and_browser_crawl_preserve_body_fields_enctype_and_hash_routes():
    payload = {
        "url": "http://127.0.0.1:9100/",
        "pages": [{"url": "http://127.0.0.1:9100/", "status": 200, "content_type": "text/html"}],
        "hash_routes": ["#/preview/card?comment=hi"],
        "forms": [{
            "page": "http://127.0.0.1:9100/",
            "action": "/api/submit",
            "method": "POST",
            "content_type": "application/json",
            "fields": [{"name": "coupon", "value": "SAVE10"}],
        }],
        "xhr": [{
            "method": "POST",
            "url": "http://127.0.0.1:9100/api/redeem",
            "content_type": "application/json",
            "body_fields": ["coupon", "resource_id"],
            "status": 200,
        }],
    }
    recs = parse_browser_crawl(payload, target="127.0.0.1", base="http://127.0.0.1:9100/")
    hash_rec = next(r for r in recs if r["url"] == "http://127.0.0.1:9100/preview/card?comment=hi")
    assert hash_rec["method"] == "GET"
    assert hash_rec["params"] == [{"name": "comment", "in": "query", "sample": "hi"}]
    assert "spa-hash" in hash_rec["sources"]

    form_rec = next(r for r in recs if r["url"] == "http://127.0.0.1:9100/api/submit")
    assert form_rec["content_type"] == "application/json"
    assert form_rec["params"] == [{"name": "coupon", "in": "json", "sample": "SAVE10"}]

    xhr_rec = next(r for r in recs if r["url"] == "http://127.0.0.1:9100/api/redeem")
    assert xhr_rec["method"] == "POST"
    assert xhr_rec["content_type"] == "application/json"
    assert {p["name"] for p in xhr_rec["params"]} == {"coupon", "resource_id"}
    assert all(p["in"] == "json" for p in xhr_rec["params"])

    direct_xhr = parse_xhr(
        {"api_requests": [{"method": "POST", "url": "http://127.0.0.1:9100/api/checkout", "body_fields": ["qty"]}]},
        target="127.0.0.1",
        base="http://127.0.0.1:9100/",
    )
    assert direct_xhr[0]["content_type"] == "application/x-www-form-urlencoded"
    assert direct_xhr[0]["params"] == [{"name": "qty", "in": "body", "sample": ""}]


def test_solver_surface_records_parses_js_bundles_openapi_and_blocks_template_probes(python_broker):
    import spa_lab

    solver = PythonSolver(python_broker, model="model")
    recon, enum_spec, access_spec = python_broker.tasks.specs[:3]

    # Simulate recon fetching the SPA shell HTML with inline hash route + script src.
    html_shell = (
        '<html><head><script src="/assets/app.js"></script></head>'
        '<body><a href="#/xss/inline?q=hello">SPA XSS</a>'
        "<script>fetch('/api/inline?q=alpha');</script></body></html>"
    )
    ref_html = python_broker.archive({"status_code": 200, "text": html_shell, "headers": {"Content-Type": "text/html"}}, "html")
    shell_records = solver.surface_records(
        {"status_code": 200, "text": html_shell, "headers": {"Content-Type": "text/html"}},
        {"url": recon.target},
        enum_spec,
        ref_html,
    )
    shell_urls = {r["url"] for r in shell_records}
    assert f"{recon.target.rstrip('/')}/assets/app.js" in shell_urls
    assert f"{recon.target.rstrip('/')}/xss/inline?q=hello" in shell_urls
    assert f"{recon.target.rstrip('/')}/api/inline?q=alpha" in shell_urls

    # Simulate enum fetching JS bundle (spa_lab.APP_JS) and OpenAPI spec (spa_lab.SPEC).
    js_url = f"{recon.target.rstrip('/')}/assets/app.js"
    ref_js = python_broker.archive({"status_code": 200, "text": spa_lab.APP_JS}, "js")
    js_records = solver.surface_records(
        {"status_code": 200, "text": spa_lab.APP_JS, "headers": {"Content-Type": "application/javascript"}},
        {"url": js_url},
        enum_spec,
        ref_js,
    )
    js_by_url = {(r["method"], urlsplit(r["url"]).path): r for r in js_records}
    assert ("GET", "/assets/spec-v9.json") in js_by_url
    assert ("GET", "/api/search") in js_by_url
    assert ("POST", "/api/notes") in js_by_url
    assert ("PUT", "/api/orders/{orderId}") in js_by_url
    assert ("POST", "/graphql") in js_by_url

    spec_url = f"{recon.target.rstrip('/')}/assets/spec-v9.json"
    ref_spec = python_broker.archive({"status_code": 200, "text": json.dumps(spa_lab.SPEC)}, "spec")
    spec_records = solver.surface_records(
        {"status_code": 200, "text": json.dumps(spa_lab.SPEC), "headers": {"Content-Type": "application/json"}},
        {"url": spec_url},
        enum_spec,
        ref_spec,
    )
    spec_paths = {(r["method"], urlsplit(r["url"]).path) for r in spec_records}
    assert ("GET", "/api/invoices/{invoiceId}") in spec_paths
    assert ("DELETE", "/api/invoices/{invoiceId}") in spec_paths
    assert ("POST", "/api/upload") in spec_paths

    # Candidate planning keeps uninstantiated {template} URLs blocked with requires_request_context,
    # keeps unauthorized mutating POST/PUT/DELETE blocked, and admits concrete GET XSS/SQLi routes.
    for r in [*shell_records, *js_records, *spec_records]:
        r["source_spec_id"] = "enum-2"
    dummy_spec = SimpleNamespace(
        id="access-3",
        target=recon.target,
        vector="access",
        tools={
            "validator_validate_sqli",
            "validator_validate_ssti",
            "validator_validate_xss_reflection",
            "validator_validate_open_redirect",
        },
    )
    cands = cand.parameter_candidates(
        dummy_spec,
        [*shell_records, *js_records, *spec_records],
        {},
        profile_eligibility=lambda _s, _u, _p, _c, _prof, **_kw: {"eligible": True, "reason_code": ""},
    )
    tmpl = [c for c in cands if "{orderId}" in c["route"]]
    assert tmpl and all(not c["eligible"] and c["reason_code"] == "requires_request_context" for c in tmpl)
    xss_inline = next(
        c for c in cands
        if urlsplit(c["route"]).path == "/xss/inline" and c.get("validation_profile") == "readonly_xss_reflection"
    )
    assert xss_inline["eligible"] is True
