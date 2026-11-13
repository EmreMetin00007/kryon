"""Plain-HTTP fallback for link extraction.

When Playwright cannot reach a page (goto timeout), the browser tools
fail closed and the whole enum phase dies. SSR pages carry the full
surface in raw HTML, so a dependency-free parser recovers links,
scripts, forms, and parameterized URLs from a plain GET.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs_map = {str(k).lower(): str(v) for k, v in attrs if v}
        if tag == "a" and "href" in attrs_map:
            self.links.append(attrs_map["href"])
        elif tag == "script" and "src" in attrs_map:
            self.scripts.append(attrs_map["src"])
        elif tag == "form":
            self.forms.append(attrs_map.get("action", ""))


def extract_links_plain(html: str, base_url: str) -> dict:
    """Parse links/scripts/forms from raw HTML. Never raises."""
    parser = _LinkParser()
    try:
        parser.feed(html or "")
    except Exception:
        pass
    origin = ""
    try:
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}".lower()
    except Exception:
        origin = ""
    internal: list[str] = []
    external: list[str] = []
    seen: set[str] = set()
    for href in parser.links:
        absolute = urljoin(base_url, href)
        if absolute in seen:
            continue
        seen.add(absolute)
        try:
            parsed = urlparse(absolute)
        except Exception:
            continue
        if f"{parsed.scheme}://{parsed.netloc}".lower() == origin:
            internal.append(absolute)
        else:
            external.append(absolute)
    scripts = [urljoin(base_url, src) for src in dict.fromkeys(parser.scripts) if src]
    forms = [urljoin(base_url, action) for action in dict.fromkeys(parser.forms) if action]
    with_params = [u for u in internal + external if "?" in u and "=" in u]
    return {
        "internal_links": internal[:300],
        "external_links": external[:200],
        "js_files": scripts[:100],
        "form_actions": forms,
        "urls_with_params": with_params[:150],
        "fallback": "plain-http",
    }
