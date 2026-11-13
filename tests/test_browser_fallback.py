"""Plain-HTTP fallback for link extraction when the browser times out."""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "mcp-browser"))

from cco_browser_core.fallback import extract_links_plain


def test_plain_extract_splits_links_scripts_forms():
    html = """
    <html><head><script src="/assets/app.js"></script>
    <script src="https://cdn.example.test/lib.js"></script></head>
    <body>
    <a href="/docs">docs</a><a href="/search?q=1&r=2">s</a>
    <a href="https://other.test/x">o</a>
    <form action="/login" method="post"></form>
    </body></html>"""
    out = extract_links_plain(html, "http://target.test/")
    assert "/docs" in " ".join(out["internal_links"])
    assert any("other.test" in u for u in out["external_links"])
    assert any("app.js" in u for u in out["js_files"])
    assert any("cdn.example.test" in u for u in out["js_files"])
    assert any("login" in u for u in out["form_actions"])
    assert any("q=1" in u for u in out["urls_with_params"])
    assert out["fallback"] == "plain-http"
