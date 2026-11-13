"""Legacy browser tools cannot bypass request interception."""
import json

import pytest

from conftest import load_server


def test_legacy_crawl_uses_policy_controlled_adapter(monkeypatch):
    kali = load_server("kali-tools")
    seen = {}
    def fake_crawl(url, **kwargs):
        seen.update({"url": url, **kwargs})
        return {"ok": True, "pages": [], "forms": [1], "links": [2], "js_files": [3], "records": [4]}
    monkeypatch.setattr(kali, "HAS_SURFACE", True)
    monkeypatch.setattr(kali, "crawl_site", fake_crawl)
    monkeypatch.setattr(kali, "run_command", lambda *a, **kw: pytest.fail("legacy script must not run"))
    out = json.loads(kali.browser_crawl("https://owned.test/", max_pages=100, extract_forms=False))
    assert seen["tool_name"] == "kali-tools_browser_crawl" and seen["max_pages"] == 40
    assert out["forms"] == [] and "records" not in out


def test_legacy_login_and_dom_tools_refuse_without_starting_browser(monkeypatch):
    kali = load_server("kali-tools")
    monkeypatch.setattr(kali, "run_command", lambda *a, **kw: pytest.fail("legacy script must not run"))
    assert "unavailable" in kali.browser_dom_xss("https://owned.test/")
    assert "disabled" in kali.browser_auth_test("https://owned.test/")
