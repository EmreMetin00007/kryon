"""Attack-surface compiler: normalize, parse, ingest, queue (offline)."""

import json
import os
import sqlite3
import sys

from conftest import load_server, list_tool_names

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SURFACE_DIR = os.path.join(REPO, "mcp-servers", "mcp-memory-server")
if SURFACE_DIR not in sys.path:
    sys.path.insert(0, SURFACE_DIR)

from cco_surface_core.extract import extract_html, extract_js, extract_robots, extract_sitemap, is_sitemap_index
from cco_surface_core.fuzz import build_canary_plan, remaining_classes
from cco_surface_core.normalize import normalize_record, normalize_url, score_record
from cco_surface_core.parsers import (
    parse_artifact,
    parse_browser_crawl,
    parse_ffuf,
    parse_gau,
    parse_nuclei,
    parse_openapi,
    parse_sqlmap,
    parse_xhr,
    parse_zap,
)
from cco_surface_core.probe import fingerprint_response
from cco_surface_core.store import ingest_records, mark_tested, memory_db_path, next_work, queue_classes
from cco_surface_core.wordlist import compile_wordlist


def test_normalize_url_strips_fragment_and_default_port():
    assert normalize_url("https://EX.com:443/a?b=1#x") == "https://ex.com/a?b=1"
    assert normalize_url("/search?q=1", base="http://t.local") == "http://t.local/search?q=1"


def test_fingerprint_ignores_query_values():
    left = normalize_record({"url": "http://t.local/item?id=1", "method": "GET"}, target="t.local")
    right = normalize_record({"url": "http://t.local/item?id=99", "method": "GET"}, target="t.local")
    assert left["fingerprint"] == right["fingerprint"]
    assert left["params"][0]["name"] == "id"


def test_score_prefers_api_id_params():
    low = score_record({"url": "http://t.local/about", "path": "/about", "params": []})
    high = score_record({
        "url": "http://t.local/api/orders?id=1",
        "path": "/api/orders",
        "params": [{"name": "id", "in": "query"}],
        "status": 200,
    })
    assert high > low


def test_extract_html_forms_and_links():
    html = """
    <html><a href="/item?id=1">item</a>
    <form action="/search" method="GET"><input name="q"></form>
    </html>
    """
    recs = extract_html(html, "http://t.local")
    urls = {item["url"] for item in recs}
    assert "http://t.local/item?id=1" in urls
    assert any(item["url"] == "http://t.local/search" and item["method"] == "GET" for item in recs)
    search = next(item for item in recs if item["url"].endswith("/search"))
    assert any(param["name"] == "q" for param in search["params"])


def test_extract_html_hidden_and_js_query_keys():
    html = """<form action="/login" method="POST">
      <input type="hidden" name="csrf" value="tok">
      <input name="username">
    </form>
    <script src="/app.js"></script>"""
    recs = extract_html(html, "http://t.local")
    login = next(item for item in recs if item["url"].endswith("/login"))
    assert login["method"] == "POST"
    assert {p["name"] for p in login["params"]} >= {"csrf", "username"}
    js = extract_js(
        "fetch('/api/notes?debug=1'); window.SEARCH='/search?q=test&sort=new';",
        "http://t.local",
    )
    urls = {item["url"] for item in js}
    assert any("/api/notes" in url and "debug=" in url for url in urls)
    assert any("sort=" in url for url in urls)


def test_extract_js_calls_harvests_method_and_body_schema():
    from cco_surface_core.extract import extract_js_calls
    js = """
    fetch('/api/search?q=laptop');
    fetch('/api/notes', {method: 'POST', body: JSON.stringify({title: t, body: b})});
    axios.put(`/api/orders/${orderId}`, {total: 5, note: 'x'});
    axios({url: '/api/login', method: 'post', data: {username: u, password: p}});
    """
    recs = extract_js_calls(js, "http://t.local")
    by_url = {(r["method"], r["url"]): r for r in recs}
    search = by_url[("GET", "http://t.local/api/search?q=laptop")]
    assert {p["name"] for p in search["params"]} >= {"q"}
    notes = by_url[("POST", "http://t.local/api/notes")]
    assert {p["name"] for p in notes["params"]} >= {"title", "body"}
    assert all(p["in"] == "json" for p in notes["params"])
    orders = next(r for r in recs if "/api/orders/" in r["url"])
    assert orders["method"] == "PUT"
    assert "{orderId}" in orders["url"]
    assert {p["name"] for p in orders["params"]} >= {"total", "orderId"}
    login = by_url[("POST", "http://t.local/api/login")]
    assert {p["name"] for p in login["params"]} >= {"username", "password"}


def test_extract_js_calls_graphql_variables_and_spec_urls():
    from cco_surface_core.extract import extract_js_calls, find_spec_urls
    js = """
    fetch('/graphql', {method: 'POST', body: JSON.stringify({
      query: 'query GetOrder($id: ID!, $verbose: Boolean) { order(id: $id) { total } }',
      variables: {id: oid, verbose: true}})});
    const SPEC = '/api/openapi.json';
    """
    recs = extract_js_calls(js, "http://t.local")
    gql = next(r for r in recs if r["url"].endswith("/graphql"))
    assert gql["method"] == "POST" and gql["sources"] == ["graphql"]
    assert {p["name"] for p in gql["params"]} >= {"id", "verbose"}
    assert find_spec_urls(js, "http://t.local") == ["http://t.local/api/openapi.json"]
    # Dosya adı openapi içermese de spec ataması/adlandırması bulunur.
    assert find_spec_urls("const SPEC_URL = '/assets/spec-v9.json';",
                          "http://t.local") == ["http://t.local/assets/spec-v9.json"]


def test_probe_fingerprint_title_tech_hash():
    fp = fingerprint_response(
        "http://t.local/",
        200,
        {"Server": "nginx/1.24", "Content-Type": "text/html", "X-Powered-By": "PHP/8.2"},
        b"<html><title>VulnLab</title>wordpress</html>",
    )
    assert fp["title"] == "VulnLab"
    assert fp["body_hash"]
    assert "nginx" in fp["tech"]
    assert "php" in fp["tech"] or "wordpress" in fp["tech"]


def test_parse_openapi_and_wordlist():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Lab"},
        "servers": [{"url": "http://t.local"}],
        "paths": {
            "/search": {"get": {"parameters": [
                {"name": "q", "in": "query"}, {"name": "sort", "in": "query"},
            ]}},
            "/api/notes": {"post": {"requestBody": {"content": {
                "application/json": {"schema": {"properties": {"title": {}, "body": {}}}}
            }}}},
        },
    }
    recs = parse_openapi(spec, target="t.local", base="http://t.local")
    methods = {(item["method"], item["url"]) for item in recs}
    assert ("GET", "http://t.local/search") in methods
    notes = next(item for item in recs if item["url"].endswith("/api/notes"))
    assert notes["method"] == "POST"
    assert {p["name"] for p in notes["params"]} >= {"title", "body"}
    tokens = compile_wordlist(recs)
    assert "sort" in tokens
    assert "title" in tokens


def test_extract_robots_and_sitemap():
    robots = extract_robots("User-agent: *\nDisallow: /admin\n", "http://t.local/app")
    assert any(item["url"].endswith("/admin") for item in robots)
    sitemap = extract_sitemap(
        "<urlset><url><loc>http://t.local/checkout?price=10&amp;quantity=1</loc></url></urlset>",
        "http://t.local",
    )
    assert sitemap[0]["url"] == "http://t.local/checkout?price=10&quantity=1"
    assert {p["name"] for p in sitemap[0]["params"]} == {"price", "quantity"}
    index = (
        "<sitemapindex><sitemap><loc>http://t.local/sitemap-pages.xml</loc></sitemap></sitemapindex>"
    )
    assert is_sitemap_index(index) is True
    child = extract_sitemap(index, "http://t.local")
    assert child[0]["url"] == "http://t.local/sitemap-pages.xml"
    assert child[0]["sources"] == ["sitemapindex"]


def test_parsers_ffuf_nuclei_gau_sqlmap():
    ffuf = parse_ffuf({
        "results": [{"url": "http://t.local/admin", "status": 200, "length": 12}]
    }, target="t.local")
    assert ffuf[0]["url"] == "http://t.local/admin"
    assert ffuf[0]["sources"] == ["ffuf"]

    nuclei = parse_nuclei(
        json.dumps({"matched-at": "http://t.local/wp-json", "info": {"name": "wp", "tags": "wordpress"}}),
        target="t.local",
    )
    assert nuclei[0]["url"].endswith("/wp-json")

    gau = parse_gau("http://t.local/old?id=3\nhttp://t.local/x\n", target="t.local")
    assert len(gau) == 2

    sqlmap = parse_sqlmap({
        "target": "http://t.local/item?id=1",
        "vulnerable": True,
        "dbms": "MySQL 5",
        "injectable_params": [{"param": "id", "place": "GET"}],
    }, target="t.local")
    assert sqlmap[0]["params"][0]["name"] == "id"
    assert "MySQL" in sqlmap[0]["tech"][0]


def test_parse_browser_crawl_and_xhr():
    recs = parse_browser_crawl({
        "url": "http://t.local/",
        "pages": [{"url": "http://t.local/", "status": 200, "title": "Home"},
                  {"url": "http://t.local/account", "status": 401, "title": "login required"}],
        "forms": [{"page": "http://t.local/", "action": "/login", "method": "POST",
                   "fields": [{"name": "csrf", "type": "hidden"}, {"name": "username", "type": "text"}]}],
        "links": ["http://t.local/portal", "http://t.local/portal/secret?token=lab"],
        "js_files": ["http://t.local/app.js"],
        "xhr": [{"method": "POST", "url": "http://t.local/api/notes?debug=1",
                 "post_data": '{"title":"x","body":"y"}', "content_type": "application/json"}],
    }, target="t.local")
    urls = {item["url"] for item in recs}
    assert "http://t.local/portal/secret?token=lab" in urls
    account = next(item for item in recs if item["url"].endswith("/account"))
    assert account["status"] == 401
    assert account["auth_required"] is True
    login = next(item for item in recs if item["url"].endswith("/login"))
    assert login["method"] == "POST"
    assert {p["name"] for p in login["params"]} >= {"csrf", "username"}
    notes = next(item for item in recs if "/api/notes" in item["url"])
    assert notes["method"] == "POST"
    assert {p["name"] for p in notes["params"]} >= {"title", "body"}
    xhr = parse_xhr({
        "api_requests": [{"method": "GET", "url": "http://t.local/api/orders/1001"}]
    }, target="t.local")
    assert xhr[0]["sources"] == ["xhr"]
    via_artifact = parse_artifact({
        "pages": [{"url": "http://t.local/portal", "status": 200}],
        "links": ["http://t.local/portal/secret?token=1"],
    }, "browser", target="t.local")
    assert any("secret" in (item.get("url") or "") for item in via_artifact)


def test_parse_zap_alerts_are_hypotheses():
    recs = parse_zap({
        "urls": ["http://t.local/search?q=1"],
        "alerts": [{
            "url": "http://t.local/item?id=1",
            "method": "GET",
            "param": "id",
            "alert": "SQL Injection",
            "risk": "High",
            "pluginId": "40018",
        }],
    }, target="t.local")
    assert all(item.get("sources") == ["zap"] for item in recs)
    assert all("CONFIRMED" not in json.dumps(item) for item in recs)
    item = next(row for row in recs if "/item" in row["url"])
    assert any(p["name"] == "id" for p in item["params"])
    assert "sql_injection" in item["tech"]
    assert parse_artifact({"urls": ["http://t.local/a"]}, "zap", target="t.local")


def test_ingest_dedupes_and_next_work_ranks(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    db = memory_db_path()
    first = ingest_records([
        {"url": "http://t.local/about", "sources": ["html"]},
        {"url": "http://t.local/api/orders?id=1", "sources": ["html"], "status": 200},
    ], target="t.local", db_path=db)
    assert first["inserted"] == 2
    second = ingest_records([
        {"url": "http://t.local/api/orders?id=99", "sources": ["gau"], "status": 200},
    ], target="t.local", db_path=db)
    assert second["inserted"] == 0
    assert second["updated"] == 1
    queue = next_work("t.local", limit=5, db_path=db)
    assert queue["total_surface"] == 2
    assert queue["queue"][0]["path"] == "/api/orders"
    assert "gau" in queue["queue"][0]["sources"]
    conn = sqlite3.connect(db)
    mirrored = conn.execute(
        "SELECT url_or_port FROM endpoints WHERE target='t.local'"
    ).fetchall()
    conn.close()
    assert any("/api/orders" in row[0] for row in mirrored)


def test_next_work_matches_target_key_variants(tmp_path, monkeypatch):
    """Aşamalar farklı anahtar yazsa da kuyruk boş dönmemeli (lab bulgusu)."""
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    db = memory_db_path()
    ingest_records([
        {"url": "https://lab.example.net/filter?category=Gifts", "sources": ["crawl"], "status": 200},
    ], target="lab.example.net", db_path=db)
    ingest_records([
        {"url": "https://lab.example.net/product?id=1", "sources": ["html"], "status": 200},
    ], target="https://lab.example.net", db_path=db)
    for key in ("https://lab.example.net/", "https://lab.example.net", "lab.example.net"):
        queue = next_work(key, limit=5, db_path=db)
        assert queue["total_surface"] == 2, key
        assert queue["count"] == 2, key


def test_memory_tools_ingest_and_drop():
    memory = load_server("memory-server")
    names = list_tool_names(memory)
    assert "ingest_surface" in names
    assert "next_surface_work" in names
    ingested = json.loads(memory.ingest_surface(
        "surf.test",
        records_json=json.dumps([
            {"url": "http://surf.test/api/users?id=1", "method": "GET", "status": 200},
        ]),
    ))
    assert ingested["inserted"] >= 1
    queue = json.loads(memory.next_surface_work("surf.test"))
    assert queue["count"] >= 1
    assert queue["queue"][0]["params"][0]["name"] == "id"
    dumped = json.loads(memory.get_target_memory("surf.test"))
    assert dumped["attack_surface"]["total"] >= 1
    memory.drop_target_memory("surf.test")
    gone = json.loads(memory.next_surface_work("surf.test"))
    assert gone["total_surface"] == 0


def test_hunter_reads_attack_surface_as_endpoints():
    hunter = load_server("hunter")
    ingest_records(
        [{"url": "http://htgt-surface/api/orders?id=1", "sources": ["discover"], "status": 200}],
        target="htgt-surface",
        db_path=hunter.MEM_DB,
    )
    endpoints = hunter._read_endpoints("htgt-surface")
    assert any("/api/orders" in (item.get("url_or_port") or "") for item in endpoints)


def test_kali_exposes_discover_tool():
    kali = load_server("kali-tools")
    names = list_tool_names(kali)
    assert "discover_web_surface" in names
    assert "compile_target_wordlist" in names
    assert "crawl_web_surface" in names
    assert "zap_map_surface" in names
    assert kali.HAS_SURFACE is True


def test_ffuf_calibrate_uses_ac_unless_custom_filter(monkeypatch, tmp_path):
    import inspect
    kali = load_server("kali-tools")
    assert "calibrate" in inspect.signature(kali.ffuf_fuzz).parameters
    captured = []
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nlogin\n")

    def fake_run(cmd, timeout=600, cwd=None, retries=1):
        captured.append(cmd)
        return {"stdout": "", "stderr": "", "returncode": 0, "success": True}

    def fake_supervised(cmd, timeout=180, early_stop=1000):
        captured.append(cmd)
        return {"stdout": "", "stderr": "", "returncode": 0, "success": True, "stopped_early": False}

    monkeypatch.setattr(kali, "run_command", fake_run)
    monkeypatch.setattr(kali, "_run_ffuf_supervised", fake_supervised)
    monkeypatch.setattr(kali, "HAS_SURFACE", False)
    kali.ffuf_fuzz("http://t.local/FUZZ", wordlist=str(wl))
    assert " -ac" in captured[-1]
    assert " -mc " not in captured[-1]
    kali.ffuf_fuzz("http://t.local/FUZZ", wordlist=str(wl), filter_code="404")
    assert " -ac" not in captured[-1]
    assert " -fc 404" in captured[-1]
    kali.ffuf_fuzz("http://t.local/FUZZ", wordlist=str(wl), match_code="200")
    assert " -ac" not in captured[-1]
    assert " -mc 200" in captured[-1]
    kali.ffuf_fuzz("http://t.local/FUZZ", wordlist=str(wl), calibrate=False)
    assert " -ac" not in captured[-1]
    assert " -mc 200,301,302,403" in captured[-1]


def test_compile_target_wordlist_offline(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    kali = load_server("kali-tools")
    ingest_records(
        [{"url": "http://t.local/search?q=1&sort=new", "sources": ["js"], "status": 200}],
        target="t.local",
        db_path=memory_db_path(),
    )
    out = json.loads(kali.compile_target_wordlist("t.local"))
    assert out["size"] >= 2
    assert os.path.isfile(out["path"])
    text = open(out["path"], encoding="utf-8").read()
    assert "sort" in text or "search" in text


def test_canary_plan_uses_recorded_params_only():
    rec = normalize_record(
        {"url": "http://t.local/search?q=test", "method": "GET", "status": 200},
        target="t.local",
    )
    plan = build_canary_plan(rec)
    assert plan
    assert all(item.get("param") == "q" for item in plan if not item.get("skip"))
    classes = {item["vuln_class"] for item in plan}
    assert "xss_reflected" in classes
    assert "sql_injection" in classes
    assert "ssrf" not in classes
    assert "idor" not in classes


def test_mark_tested_keeps_partial_queue(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    db = memory_db_path()
    ingest_records(
        [{"url": "http://t.local/search?q=1", "sources": ["html"], "status": 200}],
        target="t.local",
        db_path=db,
    )
    queue = next_work("t.local", db_path=db)
    rec = queue["queue"][0]
    leftover = remaining_classes(rec)
    assert leftover
    mark_tested("t.local", rec["fingerprint"], ["xss_reflected"], db_path=db)
    again = next_work("t.local", db_path=db)
    assert again["count"] >= 1
    assert "xss_reflected" not in again["queue"][0]["remaining_classes"]
    assert again["queue"][0]["remaining_classes"]
    mark_tested("t.local", rec["fingerprint"], again["queue"][0]["remaining_classes"], db_path=db)
    done = next_work("t.local", db_path=db)
    assert done["untested"] == 0
    assert done["queue"] == []


def test_queued_classes_keep_gap_in_queue(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    db = memory_db_path()
    ingest_records(
        [{"url": "http://t.local/search?q=1", "sources": ["html"], "status": 200}],
        target="t.local",
        db_path=db,
    )
    rec = next_work("t.local", db_path=db)["queue"][0]
    mark_tested("t.local", rec["fingerprint"], rec["remaining_classes"], db_path=db)
    assert next_work("t.local", db_path=db)["queue"] == []
    queue_classes("t.local", rec["fingerprint"], ["idor"], db_path=db)
    again = next_work("t.local", db_path=db)
    assert again["count"] >= 1
    assert "idor" in again["queue"][0]["remaining_classes"]


def test_sqlmap_requires_confirmed_validation():
    kali = load_server("kali-tools")
    blocked = json.loads(kali.sqlmap_test_structured("http://t.local/item?id=1"))
    assert blocked.get("ok") is False
    assert "validation_id" in (blocked.get("error") or "")
    dumped = json.loads(kali.sqlmap_test(
        url="http://t.local/item?id=1", action="dump",
        validation_id="c" * 32, allow_deepen=False,
    ))
    assert dumped.get("ok") is False


def test_zap_map_refuses_without_daemon_and_skips_ascan(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    monkeypatch.delenv("CCO_ZAP_AUTOSTART", raising=False)
    from cco_surface_core.zap import run_zap_map

    missing = run_zap_map("http://t.local/", request_fn=lambda path, params: (_ for _ in ()).throw(OSError("down")))
    assert missing.get("ok") is False
    assert "ZAP" in (missing.get("error") or "")

    calls = []
    mapped = run_zap_map("http://t.local/", ajax=True, allow_ascan=True,
                         request_fn=lambda path, params: calls.append(path))
    assert mapped["ok"] is False and mapped["ascan"]["ran"] is False
    assert "request-level policy" in mapped["error"] and not calls


def test_crawl_web_surface_without_playwright_is_explicit(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    kali = load_server("kali-tools")
    monkeypatch.setattr(kali, "HAS_PLAYWRIGHT", False)

    def fake_crawl(*args, **kwargs):
        from cco_surface_core.crawl import PLAYWRIGHT_MSG
        return {"ok": False, "error": PLAYWRIGHT_MSG, "records": []}

    monkeypatch.setattr(kali, "crawl_site", fake_crawl)
    out = json.loads(kali.crawl_web_surface("http://t.local/"))
    assert out.get("ok") is False
    assert "playwright" in (out.get("error") or "").lower()


def test_run_playwright_sync_offloads_from_asyncio_loop():
    import asyncio
    from cco_surface_core.crawl import run_playwright_sync

    def probe():
        try:
            asyncio.get_running_loop()
            return "inside-loop"
        except RuntimeError:
            return "no-loop"

    async def call():
        return run_playwright_sync(probe)

    assert asyncio.run(call()) == "no-loop"
    assert probe() == "no-loop"


def test_browser_headers_from_asyncio_does_not_hit_sync_api_error():
    import asyncio
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    mod = load_server("browser")
    if not mod.HAS_PLAYWRIGHT:
        res = asyncio.run(asyncio.to_thread(mod.browser_security_headers, "https://example.com"))
        assert "playwright" in res.lower()
        return

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    try:
        async def call():
            return mod.browser_security_headers(url)
        out = asyncio.run(call())
    finally:
        server.shutdown()
        server.server_close()

    assert "asyncio loop" not in out.lower()
    assert "HATA: playwright" not in out.lower()
    data = json.loads(out)
    assert data.get("status") == 200
    assert "x-content-type-options" in (data.get("present_security_headers") or {})


def test_crawl_site_from_asyncio_does_not_hit_sync_api_error(tmp_path, monkeypatch):
    import asyncio
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    from cco_surface_core.crawl import HAS_PLAYWRIGHT, crawl_site

    if not HAS_PLAYWRIGHT:
        out = crawl_site("http://127.0.0.1/")
        assert out.get("ok") is False
        assert "playwright" in (out.get("error") or "").lower()
        return

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><a href='/next'>n</a></body></html>")

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({"in_scope": [{"asset": url}], "allow_loopback": True}))
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"allow_loopback": True}))
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope_file))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(policy_file))
    from policy_engine import PolicyEngine
    PolicyEngine(cco_home=str(tmp_path / "home"), scope_file=str(scope_file),
                 program_policy_file=str(policy_file)).grant_approval(
        "kali-tools_crawl_web_surface", "127.0.0.1", ttl_seconds=600, reason="loopback test")
    try:
        async def call():
            return crawl_site(url, max_pages=2, wait_ms=50, timeout_ms=8000)
        out = asyncio.run(call())
    finally:
        server.shutdown()
        server.server_close()

    assert out.get("ok") is True, out.get("error")
    assert "asyncio loop" not in str(out.get("error") or "").lower()
    assert out.get("pages")


def test_form_value_and_sibling_params_preserved_in_canary_and_fuzz(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    html = """<form action="/checkout" method="POST">
      <input type="hidden" name="csrf" value="REAL_TOKEN">
      <input name="quantity" value="2">
    </form>"""
    recs = extract_html(html, "http://t.local")
    form_rec = next(r for r in recs if r["url"].endswith("/checkout"))
    samples = {p["name"]: p["sample"] for p in form_rec["params"]}
    assert samples["csrf"] == "<redacted>"
    assert samples["quantity"] == "2"

    normalized = normalize_record(form_rec, target="t.local")
    normalized["suggested_classes"] = ["sql_injection"]
    from cco_hunter_core.request_context import materialize_record, request_fields
    with request_fields({"body:csrf": "REAL_TOKEN"}):
        hydrated, missing = materialize_record(normalized)
        probes = build_canary_plan(hydrated)
    assert not missing
    qty_probe = next(p for p in probes if p["param"] == "quantity")
    assert "csrf=REAL_TOKEN" in (qty_probe.get("data") or "")
    assert "csrf=REAL_TOKEN" in (qty_probe.get("baseline_data") or "")
    assert "quantity=2" in (qty_probe.get("baseline_data") or "")


def test_fuzz_attack_surface_does_not_mark_tested_on_401_or_schema_400(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    hunter = load_server("hunter")
    db = hunter.MEM_DB
    ingest_records(
        [{
            "url": "http://htgt-auth/api/orders",
            "method": "POST",
            "params": [
                {"name": "item_id", "in": "json", "sample": "10"},
                {"name": "q", "in": "json", "sample": "bolt"},
            ],
            "sources": ["xhr"],
            "status": 200,
        }],
        target="htgt-auth",
        db_path=db,
    )
    sent_bodies = []

    def fake_live_401(method, url, headers=None, data=None, json_body=None, cookies=None, files=None):
        sent_bodies.append(json_body)
        return {"ok": True, "status": 401, "text": "unauthorized", "len": 12, "headers": {}}

    monkeypatch.setattr(hunter, "_live_request", fake_live_401)
    out = json.loads(hunter.fuzz_attack_surface("http://htgt-auth", limit=2, max_requests=4, live=True, sleep_s=0))
    # Sibling json field item_id must be present in both baseline and probe requests
    assert any(isinstance(b, dict) and b.get("item_id") == "10" for b in sent_bodies)
    # Because response was 401 (dead session), tested_classes must NOT be marked
    assert out["marked_tested"] == []
    still_queued = next_work("htgt-auth", db_path=db)
    assert still_queued["untested"] >= 1


def test_discover_web_surface_forwards_cookie_and_headers(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path))
    kali = load_server("kali-tools")
    seen_calls = []

    class _FakeResp:
        url = "http://t.local/"
        status_code = 200
        headers = {"Content-Type": "text/html"}
        content = b"<html><title>AuthHome</title></html>"
        text = "<html><title>AuthHome</title></html>"
        cookies = []

    def fake_get(url, timeout=12, headers=None, cookie=""):
        seen_calls.append({"url": url, "headers": headers, "cookie": cookie})
        return _FakeResp()

    monkeypatch.setattr(kali, "_http_get", fake_get)
    res = json.loads(kali.discover_web_surface(
        "http://t.local", mode="passive", cookie="sid=live123", headers="X-Tenant: acme"
    ))
    assert res["probe"]["title"] == "AuthHome"
    assert seen_calls and seen_calls[0]["cookie"] == "sid=live123"
    assert seen_calls[0]["headers"] == "X-Tenant: acme"



def test_canonical_target_merges_scheme_variants():
    from cco_surface_core.normalize import canonical_target, fingerprint
    assert canonical_target("https://example.com:8443/app") == "example.com:8443"
    assert canonical_target("example.com") == "example.com"
    assert canonical_target("EXAMPLE.com/") == "example.com"
    assert canonical_target("http://user@example.com/x") == "example.com"
    assert canonical_target("10.0.0.0/24") == "10.0.0.0/24"
    assert canonical_target("") == ""
    url = "https://example.com:8443/upload?x=1"
    fp1 = fingerprint(canonical_target("https://example.com:8443"),
                      "POST", url, [{"name": "f", "in": "body"}])
    fp2 = fingerprint(canonical_target("example.com:8443"),
                      "POST", url, [{"name": "f", "in": "body"}])
    assert fp1 == fp2


def test_ingest_merges_same_entity_across_target_spellings(tmp_path, monkeypatch):
    import cco_surface_core.store as store
    monkeypatch.setattr(store, "memory_db_path", lambda: str(tmp_path / "mem.db"))
    rec = {"url": "https://example.com:8443/upload", "method": "POST",
           "params": [{"name": "f", "in": "body", "sample": "a"}], "sources": ["probe"]}
    store.ingest_records([dict(rec, target="https://example.com:8443")])
    store.ingest_records([dict(rec, target="example.com:8443")])
    conn = store.sqlite3.connect(str(tmp_path / "mem.db"))
    try:
        n = conn.execute("SELECT COUNT(*) FROM attack_surface").fetchone()[0]
        targets = {row[0] for row in conn.execute("SELECT DISTINCT target FROM attack_surface")}
    finally:
        conn.close()
    assert n == 1
    assert targets == {"example.com:8443"}
    work = store.next_work("example.com:8443")
    assert work["total_surface"] >= 1


def test_apply_canary_multipart_keeps_siblings_and_baseline():
    from cco_surface_core.fuzz import apply_canary
    record = {"url": "https://example.com:8443/upload", "method": "POST",
              "params": [{"name": "title", "in": "body", "sample": "rapor"},
                         {"name": "avatar", "in": "body", "sample": "a.png"}]}
    probe = apply_canary(record, "avatar", "multipart", "PAYLOAD")
    assert probe["files"] == {"avatar": ("cco_probe.txt", "PAYLOAD")}
    assert probe["data"] == "title=rapor"
    assert probe["baseline_data"] == "title=rapor"
    assert probe["baseline_files"] == {"avatar": ("cco_probe.txt", "1")}


def test_baseline_contract_xml_vs_multipart():
    # Sozlesme: hunter guard'i, baseline anahtari OLMAYAN xml/multipart
    # probunu 4xx/405'ta gommez; multipart artik gercek baseline tasir,
    # xml tasimaz (sema bilinmiyor). Bu test uretim kodunun sozlesmesini kilitler.
    from cco_surface_core.fuzz import apply_canary
    record = {"url": "https://example.com/api", "method": "POST",
              "params": [{"name": "doc", "in": "body", "sample": "<a/>"}]}
    xml_probe = apply_canary(record, "doc", "xml", "PAYLOAD")
    assert not any(k in xml_probe for k in ("baseline_data", "baseline_json",
                                            "baseline_cookies", "baseline_headers",
                                            "baseline_url", "baseline_files"))
    assert xml_probe["data"] == "PAYLOAD"
    mp_probe = apply_canary(record, "doc", "multipart", "PAYLOAD")
    assert mp_probe["data"] is None  # kardes yok
    assert mp_probe["baseline_files"] == {"doc": ("cco_probe.txt", "1")}
    assert mp_probe["files"] == {"doc": ("cco_probe.txt", "PAYLOAD")}


def test_extract_http_headers_parses_standard_discovery_headers():
    from cco_surface_core.extract import extract_http_headers

    headers = {
        "location": "/redirected?step=1",
        "Content-Location": "/v1/canonical",
        "REFRESH": "10; url=/delayed/next",
        "Link": '</api/items?page=2>; rel="next", <https://other.example/x>; rel="canonical", <./sibling>; rel="prev"',
    }
    recs = extract_http_headers(headers, "http://t.local/app/")
    urls = {r["url"] for r in recs}
    assert urls == {
        "http://t.local/redirected?step=1",
        "http://t.local/v1/canonical",
        "http://t.local/delayed/next",
        "http://t.local/api/items?page=2",
        "http://t.local/app/sibling",
    }
    assert all(r["method"] == "GET" and r["sources"] == ["header"] for r in recs)
    page2 = next(r for r in recs if "page=2" in r["url"])
    assert page2["params"] == [{"name": "page", "in": "query", "sample": "2"}]


def test_extract_css_handles_import_and_url_and_skips_data_and_fragments():
    from cco_surface_core.extract import extract_css

    css = """
    @import "/styles/base.css";
    @import url('../styles/theme.css');
    @font-face { src: url("/fonts/inter.woff2") format("woff2"); }
    .hero { background: url(images/banner.png?v=2); mask: url(#clip); icon: url(data:image/svg+xml,<svg/>); }
    .ext { background: url(https://cdn.other.test/a.png); }
    """
    recs = extract_css(css, "http://t.local/assets/main.css")
    urls = {r["url"] for r in recs}
    assert urls == {
        "http://t.local/styles/base.css",
        "http://t.local/styles/theme.css",
        "http://t.local/fonts/inter.woff2",
        "http://t.local/assets/images/banner.png?v=2",
    }
    assert all(r["method"] == "GET" and r["sources"] == ["css"] for r in recs)


def test_extract_html_handles_w3c_tags_base_meta_srcdoc_svg_css_and_text():
    html = """<!DOCTYPE html SYSTEM "/dtd/custom.dtd">
    <html>
      <head>
        <base href="http://t.local/sub/">
        <meta http-equiv="refresh" content="3; url=refreshed.html">
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; report-uri /csp-report; report-to /csp-v2">
        <meta name="msapplication-config" content="./browserconfig.xml">
        <meta name="reading" content="<a href='meta-link.html'>read</a>">
        <style>@import "inline.css"; .b { background: url(bg/pic.png); }</style>
      </head>
      <body>
        <img srcset="img/one.png 1x,
                     /img/two.png 2x">
        <a href=unquoted.html ping="ping1 /ping2">go</a>
        <a ng-href="{{'ng/target'}}">ng</a>
        <button formaction="/alt-action">btn</button>
        <svg><use xlink:href="icons.svg#i"/></svg>
        <object data="data:image/svg+xml,%3Csvg%3E%3Ca%20xlink:href%3D%22svg-inner.html%22%3E%3C/a%3E%3C/svg%3E"></object>
        <param name="movie" value="player.swf">
        <param name="src" value="/param/stream">
        <param name="autoplay" value="true">
        <iframe srcdoc="&lt;a href=&quot;frame-link.html&quot;&gt;in&lt;/a&gt;"></iframe>
        <!--[if IE]><link rel="stylesheet" href="ie-only.css"><![endif]-->
        <form action="submit-form" method="POST"><input name="item" value="1"></form>
        <p>Check https://t.local/docs/manual.pdf and ./rel/guide.html or ../up/notes.txt and api/v1/schema.json.</p>
        <p>Ignore prose like and/or, text/html, 12px/1.5em, example.com/foo.</p>
      </body>
    </html>
    """
    recs = extract_html(html, "http://t.local/start/page.html")
    get_urls = {r["url"] for r in recs if r["method"] == "GET"}
    assert "http://t.local/sub/" in get_urls
    assert "http://t.local/dtd/custom.dtd" in get_urls
    assert "http://t.local/sub/refreshed.html" in get_urls
    assert "http://t.local/csp-report" in get_urls
    assert "http://t.local/csp-v2" in get_urls
    assert "http://t.local/sub/browserconfig.xml" in get_urls
    assert "http://t.local/sub/meta-link.html" in get_urls
    assert "http://t.local/sub/inline.css" in get_urls
    assert "http://t.local/sub/bg/pic.png" in get_urls
    assert "http://t.local/sub/img/one.png" in get_urls
    assert "http://t.local/img/two.png" in get_urls
    assert "http://t.local/sub/unquoted.html" in get_urls
    assert "http://t.local/sub/ping1" in get_urls
    assert "http://t.local/ping2" in get_urls
    assert "http://t.local/sub/ng/target" in get_urls
    assert "http://t.local/alt-action" in get_urls
    assert "http://t.local/sub/icons.svg" in get_urls
    assert "http://t.local/sub/svg-inner.html" in get_urls
    assert "http://t.local/sub/player.swf" in get_urls
    assert "http://t.local/param/stream" in get_urls
    assert "http://t.local/sub/frame-link.html" in get_urls
    assert "http://t.local/sub/ie-only.css" in get_urls
    assert "https://t.local/docs/manual.pdf" in get_urls
    assert "http://t.local/sub/rel/guide.html" in get_urls
    assert "http://t.local/up/notes.txt" in get_urls
    assert "http://t.local/sub/api/v1/schema.json" in get_urls
    assert not any(u.endswith(("/true", "/or", "/html", "/1.5em", "/foo")) for u in get_urls)
    # <form action="submit-form" method="POST"> must not duplicate as GET html link
    assert not any(r["url"] == "http://t.local/sub/submit-form" and r["method"] == "GET" for r in recs)
    form_rec = next(r for r in recs if r["url"] == "http://t.local/sub/submit-form")
    assert form_rec["method"] == "POST" and form_rec["sources"] == ["form"]


def test_extract_js_comments_concat_and_spa_angular_react_basename():
    from cco_surface_core.extract import extract_spa_routes

    js = """
    // Debug endpoint: https://t.local/debug/metrics
    /* Legacy path: ./legacy/report.json */
    var domain = 'http://t.local/';
    var ver = 'api/v2';
    var full = domain + ver;
    var seg = 'users';
    fetch("/a/" + seg);
    const localRel = './cfg/app.json';
    const subPath = 'v1/items?active=1';
    """
    js_recs = extract_js(js, "http://t.local/")
    js_urls = {r["url"] for r in js_recs}
    assert {
        "https://t.local/debug/metrics",
        "http://t.local/legacy/report.json",
        "http://t.local/api/v2",
        "http://t.local/a/users",
        "http://t.local/cfg/app.json",
        "http://t.local/v1/items?active=1",
    } <= js_urls

    spa_src = """
    $routeProvider.when('/ng-items/:itemId', {templateUrl: 't.html'});
    $stateProvider.state('detail', {url: '/ui-detail/:uid'});
    <BrowserRouter basename="/portal">
      <Route path="/billing" element={<Billing />} />
      <Link to="/settings">Settings</Link>
    </BrowserRouter>
    """
    spa_recs = extract_spa_routes(spa_src, "http://t.local/")
    spa_urls = {r["url"] for r in spa_recs}
    assert {
        "http://t.local/ng-items/{itemId}",
        "http://t.local/ui-detail/{uid}",
        "http://t.local/portal/billing",
        "http://t.local/portal/settings",
    } <= spa_urls
