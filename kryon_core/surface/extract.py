"""Extract URLs, forms, and params from HTML, robots, sitemap, and JS text."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import copy
import re
from html import unescape
from typing import Any
from urllib.parse import unquote, urljoin, urlparse, urlsplit

from .normalize import normalize_url, params_from_url, safe_sample, same_host

HREF_RE = re.compile(r"""(?:href|src)\s*=\s*['"]([^'"]+)['"]""", re.I)
FORM_RE = re.compile(
    r"<form\b([^>]*)>(.*?)</form>",
    re.I | re.S,
)
FORM_ACTION_RE = re.compile(r"""action\s*=\s*['"]([^'"]+)['"]""", re.I)
FORM_METHOD_RE = re.compile(r"""method\s*=\s*['"]([^'"]+)['"]""", re.I)
FORM_ENCTYPE_RE = re.compile(r"""enctype\s*=\s*['"]([^'"]+)['"]""", re.I)
INPUT_TAG_RE = re.compile(
    r"<(?:input|textarea|select)\b([^>]*)>",
    re.I,
)
INPUT_NAME_RE = re.compile(r"""\bname\s*=\s*['"]([^'"]+)['"]""", re.I)
INPUT_VAL_RE = re.compile(r"""\bvalue\s*=\s*['"]([^'"]*)['"]""", re.I)
INPUT_RE = re.compile(
    r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
ROBOTS_RE = re.compile(r"(?i)^\s*(?:disallow|allow)\s*:\s*(\S+)", re.M)
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
SITEMAPINDEX_RE = re.compile(r"<sitemapindex\b", re.I)
JS_PATTERNS = [
    re.compile(r"""['"]((?:https?:)?//[^'"]{4,})['"]"""),
    re.compile(r"""['"](/[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{3,})['"]"""),
    re.compile(r"""fetch\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""axios\.[a-z]+\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""(?:url|path|endpoint|href)\s*[:=]\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""['"`](\.{1,2}/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+)['"`]"""),
    re.compile(r"""['"`](/[A-Za-z0-9._~-][A-Za-z0-9._~/?#=&%-]*)['"`]"""),
    re.compile(
        r"""['"`]([A-Za-z0-9_-]+(?:/[A-Za-z0-9._~-]+)+"""
        r"""(?:\.[A-Za-z][A-Za-z0-9]{1,5}(?:\?[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*)?"""
        r"""|\?[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+))['"`]"""
    ),
    re.compile(
        r"""(?:window\.)?location(?:\.(?:assign|replace))?\s*(?:=|\()\s*['"`]([^'"`\s]+)['"`]""",
        re.I,
    ),
]

_REFRESH_URL_RE = re.compile(
    r"""(?:^|[;\s,])url\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;,"']+))""",
    re.I,
)
_LINK_HEADER_URI_RE = re.compile(r"<([^<>\s][^<>]*)>")
_CSS_IMPORT_RE = re.compile(
    r"""@import\s+(?:url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]+))\s*\)|"([^"]*)"|'([^']*)'|([^\s;]+))""",
    re.I,
)
_CSS_URL_RE = re.compile(
    r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^)"'\s][^)]*?))\s*\)""",
    re.I,
)
_SCRIPT_BLOCK_RE = re.compile(r"<script\b([^>]*)>[\s\S]*?</script>", re.I)
_STYLE_BLOCK_RE = re.compile(r"<style\b([^>]*)>([\s\S]*?)</style>", re.I)
_HTML_COMMENT_RE = re.compile(r"<!--([\s\S]*?)-->")
_BASE_HREF_RE = re.compile(
    r"""<base\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""",
    re.I,
)
_DOCTYPE_SYSTEM_RE = re.compile(
    r"""<!DOCTYPE\b[^>]*\bSYSTEM\s+(?:"([^"]+)"|'([^']+)')""",
    re.I,
)
_TAG_START_RE = re.compile(r"<([A-Za-z][A-Za-z0-9:_-]*)(?=[\s/>])")
_HTML_ATTR_RE = re.compile(
    r"""([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"""
)
_NG_HREF_LITERAL_RE = re.compile(r"""\{\{\s*(['"])(.*?)\1\s*\}\}""")
_EMBEDDED_HTML_ATTR_RE = re.compile(
    r"<[A-Za-z][^>]*(?:href|src|formaction|xlink:href|action)\s*=",
    re.I,
)
_URL_LIKE_PARAM_RE = re.compile(
    r"^(?:(?:https?:)?//\S+|/\S+|\./\S+|\.\./\S+|[A-Za-z0-9._~/-]+\.[A-Za-z][A-Za-z0-9]{1,7}(?:[?#].*)?)$",
    re.I,
)
_HTML_URL_ATTRS = frozenset({
    "href", "src", "formaction", "action", "poster", "cite", "longdesc",
    "lowsrc", "dynsrc", "background", "data", "codebase", "archive",
    "manifest", "profile", "implementation", "xlink:href", "ng-href",
})
_META_URL_KEY_HINTS = (
    "url", "uri", "image", "img", "icon", "config", "tile",
    "endpoint", "src", "href", "link", "redirect", "next", "starturl",
)
_TEXT_ABS_URL_RE = re.compile(r"""https?://[^\s<>"'`()]+""", re.I)
_TEXT_REL_DOT_RE = re.compile(r"""(?:^|[\s(\["'=,:;])(\.{1,2}/[^\s<>"'`(),;]+)""")
_TEXT_DOT_PREFIX_RE = re.compile(r"^(?:\.\.?/)+")
_TEXT_REL_FILE_RE = re.compile(
    r"""(?:^|[\s(\["'=,:;])((?:[A-Za-z0-9_-]+(?:/[A-Za-z0-9._~-]+)+|/(?!/)[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)\."""
    r"""(?:html?|xhtml|shtml|php\d?|phtml|aspx?|ashx|asmx|jspx?|do|action|cgi|pl|py|rb|"""
    r"""json|xml|txt|md|csv|ya?ml|js|mjs|ts|css|svg|pdf|zip|tar|gz|bak|old|orig|conf|"""
    r"""cfg|ini|log|sql|env|map|wasm|swf|jar|woff2?|ttf|eot|png|jpe?g|gif|webp|ico|bmp|"""
    r"""mp4|webm|mp3|wav)(?:\?[A-Za-z0-9._~:/?#\[\]@!$&'*+,;=%-]+)?)""",
    re.I,
)


def _record(url: str, method: str = "GET", source: str = "", params=None, extra=None):
    item = {"url": url, "method": method, "sources": [source] if source else []}
    if params:
        item["params"] = params
    if extra:
        item.update(extra)
    return item


def _extract_refresh_url(value: str) -> str:
    match = _REFRESH_URL_RE.search(value or "")
    if not match:
        return ""
    return (match.group(1) or match.group(2) or match.group(3) or "").strip()


def _looks_url_like(value: str) -> bool:
    text = (value or "").strip()
    if not text or any(ch.isspace() or ord(ch) < 32 for ch in text):
        return False
    return bool(_URL_LIKE_PARAM_RE.match(text))


def _iter_header_pairs(headers: Any) -> list[tuple[str, str]]:
    if headers is None:
        return []
    if hasattr(headers, "multi_items"):
        raw_pairs = headers.multi_items()
    elif isinstance(headers, Mapping):
        raw_pairs = headers.items()
    elif isinstance(headers, (list, tuple)):
        raw_pairs = headers
    else:
        return []
    pairs: list[tuple[str, str]] = []
    for item in raw_pairs:
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        pairs.append((str(item[0]).strip().lower(), str(item[1]).strip()))
    return pairs


def extract_http_headers(
    headers: Any,
    base: str,
    allow_subdomains: bool = False,
) -> list[dict]:
    """Extract normalized same-host URLs from Location, Content-Location, Refresh, and Link headers."""
    records: list[dict] = []
    seen: set[str] = set()

    def _emit(raw_target: str) -> None:
        candidate = (raw_target or "").strip()
        if not candidate:
            return
        url = normalize_url(candidate, base=base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            return
        if url in seen:
            return
        seen.add(url)
        records.append(_record(url, "GET", "header", params_from_url(url)))

    for name, value in _iter_header_pairs(headers):
        if not value:
            continue
        if name in {"location", "content-location"}:
            _emit(value)
        elif name == "refresh":
            _emit(_extract_refresh_url(value))
        elif name == "link":
            for match in _LINK_HEADER_URI_RE.finditer(value):
                _emit(match.group(1))
    return records


def extract_css(
    text: str,
    base: str,
    allow_subdomains: bool = False,
    limit: int | None = 120,
) -> list[dict]:
    """Extract @import and url(...) resource URLs from CSS text."""
    if limit is not None and limit <= 0:
        return []
    source = text or ""
    records: list[dict] = []
    seen: set[str] = set()

    def _emit(raw_target: str) -> bool:
        candidate = (raw_target or "").strip()
        if not candidate or candidate.startswith("#") or candidate.lower().startswith("data:"):
            return False
        url = normalize_url(candidate, base=base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            return False
        if url in seen:
            return False
        seen.add(url)
        records.append(_record(url, "GET", "css", params_from_url(url)))
        return limit is not None and len(records) >= limit

    for match in _CSS_IMPORT_RE.finditer(source):
        candidate = next((g for g in match.groups() if g is not None), "")
        if _emit(candidate):
            return records
    for match in _CSS_URL_RE.finditer(source):
        candidate = next((g for g in match.groups() if g is not None), "")
        if _emit(candidate):
            return records
    return records


def _iter_html_tags(fragment: str) -> list[tuple[str, str, int, int]]:
    """Return quote-aware (tag_lower, attrs_str, start, end) tuples in linear time."""
    tags: list[tuple[str, str, int, int]] = []
    length = len(fragment)
    pos = 0
    while pos < length:
        match = _TAG_START_RE.search(fragment, pos)
        if not match:
            break
        tag = match.group(1).lower()
        cursor = match.end()
        quote: str | None = None
        limit = min(length, cursor + 16384)
        gt_pos = -1
        while cursor < limit:
            ch = fragment[cursor]
            if quote:
                if ch == quote:
                    quote = None
            else:
                if ch in ("'", '"'):
                    quote = ch
                elif ch == ">":
                    gt_pos = cursor
                    break
            cursor += 1
        if gt_pos < 0:
            pos = match.end()
            continue
        tags.append((tag, fragment[match.end():gt_pos], match.start(), gt_pos + 1))
        pos = gt_pos + 1
    return tags


def _decode_svg_data_uri(uri: str) -> str:
    _, sep, payload = uri.partition(",")
    if not sep or not payload:
        return ""
    header = uri[:len(uri) - len(payload) - 1].lower()
    if ";base64" in header:
        try:
            return base64.b64decode(payload.strip(), validate=False).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return ""
    return unquote(payload)


def _extract_hash_route_from_attr(raw_value: str) -> str:
    """Return the route segment embedded after ``#!`` or ``#/`` in an HTML link attribute."""
    val = (raw_value or "").strip()
    if "#!" in val:
        route = val.partition("#!")[2].strip()
    elif "#/" in val:
        route = "/" + val.partition("#/")[2].strip()
    else:
        return ""
    if not route or route == "/" or any(ch.isspace() or ord(ch) < 32 for ch in route):
        return ""
    if any(ch in route for ch in ('"', "'", "<", ">", "{", "}")):
        return ""
    return route


def _extract_html_impl(
    html: str,
    base: str,
    allow_subdomains: bool = False,
    depth: int = 0,
) -> list[dict]:
    raw = html or ""
    records: list[dict] = []
    seen_get: set[str] = set()

    style_blocks: list[str] = [m.group(2) or "" for m in _STYLE_BLOCK_RE.finditer(raw)]
    stripped_bodies = _SCRIPT_BLOCK_RE.sub(lambda m: f"<script{m.group(1)}></script>", raw)
    stripped_bodies = _STYLE_BLOCK_RE.sub(lambda m: f"<style{m.group(1)}></style>", stripped_bodies)
    comment_bodies: list[str] = [m.group(1) or "" for m in _HTML_COMMENT_RE.finditer(stripped_bodies)]
    no_comments = _HTML_COMMENT_RE.sub(" ", stripped_bodies)

    effective_base = base

    def _emit_html(raw_target: str, *, resolve_base: str | None = None) -> str:
        candidate = (raw_target or "").strip()
        if not candidate:
            return ""
        url = normalize_url(candidate, base=resolve_base or effective_base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            return ""
        if url not in seen_get:
            seen_get.add(url)
            rec = _record(url, "GET", "html")
            rec["params"] = params_from_url(url)
            records.append(rec)
        return url

    base_match = _BASE_HREF_RE.search(no_comments)
    if base_match:
        raw_base = unescape(base_match.group(1) or base_match.group(2) or base_match.group(3) or "").strip()
        resolved_base = _emit_html(raw_base, resolve_base=base)
        if resolved_base:
            effective_base = resolved_base

    for dtd_m in _DOCTYPE_SYSTEM_RE.finditer(no_comments):
        _emit_html(unescape(dtd_m.group(1) or dtd_m.group(2) or ""))

    def _scan_text_segment(segment: str) -> None:
        if not segment or not segment.strip():
            return
        for m in _TEXT_ABS_URL_RE.finditer(segment):
            _emit_html(m.group(0).rstrip(".,;:!?]"))
        for m in _TEXT_REL_DOT_RE.finditer(segment):
            rel_text = m.group(1).rstrip(".,;:!?]")
            _emit_html(rel_text)
            stripped = _TEXT_DOT_PREFIX_RE.sub("", rel_text)
            if stripped and "/" in stripped and not stripped.startswith("/"):
                _emit_html("/" + stripped)
        for m in _TEXT_REL_FILE_RE.finditer(segment):
            _emit_html(m.group(1).rstrip(".,;:!?]"))

    def _emit_hash_route(route_part: str) -> None:
        if not route_part:
            return
        if not route_part.startswith("/"):
            _emit_html(route_part)
            return
        if base_match:
            base_prefix = urlsplit(effective_base).path.rstrip("/")
            _emit_html(_join_spa_basename(base_prefix, route_part))
            return
        _emit_html(route_part)

    def _scan_fragment(fragment: str, frag_depth: int) -> None:
        tags = _iter_html_tags(fragment)
        text_cursor = 0
        for tag, attrs_str, tag_start, tag_end in tags:
            if tag_start > text_cursor:
                _scan_text_segment(fragment[text_cursor:tag_start])
            text_cursor = tag_end

            meta_attrs: dict[str, str] = {}
            param_value = ""
            for attr_m in _HTML_ATTR_RE.finditer(attrs_str):
                attr_name = attr_m.group(1).lower()
                raw_val = attr_m.group(2) if attr_m.group(2) is not None else (
                    attr_m.group(3) if attr_m.group(3) is not None else (attr_m.group(4) or "")
                )
                val = unescape(raw_val).strip()

                if tag == "meta" and attr_name in {"http-equiv", "name", "property", "content"}:
                    meta_attrs[attr_name] = val
                elif tag == "param" and attr_name == "value":
                    param_value = val
                elif tag == "iframe" and attr_name == "srcdoc" and frag_depth < 3 and val:
                    for sub_rec in _extract_html_impl(
                        val,
                        effective_base,
                        allow_subdomains=allow_subdomains,
                        depth=frag_depth + 1,
                    ):
                        if sub_rec.get("sources") == ["form"]:
                            records.append(sub_rec)
                        elif sub_rec.get("url") and sub_rec["url"] not in seen_get:
                            seen_get.add(sub_rec["url"])
                            records.append(sub_rec)
                elif attr_name == "ping":
                    for item in val.split():
                        _emit_html(item)
                elif attr_name == "srcset":
                    for part in val.split(","):
                        tokens = part.strip().split()
                        if tokens:
                            _emit_html(tokens[0])
                elif attr_name in _HTML_URL_ATTRS:
                    if tag == "form" and attr_name == "action":
                        continue
                    if attr_name == "ng-href":
                        val = _NG_HREF_LITERAL_RE.sub(r"\2", val)
                    if val.lower().startswith("data:image/svg+xml"):
                        if frag_depth < 3:
                            svg_text = _decode_svg_data_uri(val)
                            if svg_text:
                                _scan_fragment(svg_text, frag_depth + 1)
                    else:
                        _emit_html(val)
                        frag_route = _extract_hash_route_from_attr(val)
                        if frag_route:
                            _emit_hash_route(frag_route)

            if tag == "param" and param_value and _looks_url_like(param_value):
                _emit_html(param_value)
            elif tag == "meta" and meta_attrs.get("content"):
                content = meta_attrs["content"]
                http_equiv = meta_attrs.get("http-equiv", "").strip().lower()
                if http_equiv == "refresh":
                    _emit_html(_extract_refresh_url(content))
                elif http_equiv.startswith("content-security-policy"):
                    for directive in content.split(";"):
                        tokens = directive.strip().split()
                        if not tokens:
                            continue
                        dname = tokens[0].lower()
                        if dname == "report-uri":
                            for tok in tokens[1:]:
                                _emit_html(tok.strip("'\""))
                        elif dname == "report-to":
                            for tok in tokens[1:]:
                                cand = tok.strip("'\"")
                                if _looks_url_like(cand):
                                    _emit_html(cand)
                elif frag_depth < 3 and "<" in content and _EMBEDDED_HTML_ATTR_RE.search(content):
                    _scan_fragment(content, frag_depth + 1)
                else:
                    meta_key = (meta_attrs.get("name") or meta_attrs.get("property") or "").lower()
                    if any(hint in meta_key for hint in _META_URL_KEY_HINTS):
                        stripped_content = content.strip()
                        if stripped_content.lower().startswith(("http://", "https://", "//", "/", "./", "../")):
                            _emit_html(stripped_content)

        if text_cursor < len(fragment):
            _scan_text_segment(fragment[text_cursor:])

    _scan_fragment(no_comments, depth)
    for comment_body in comment_bodies:
        _scan_fragment(comment_body, depth)

    for css_body in style_blocks:
        if not css_body.strip():
            continue
        for css_rec in extract_css(css_body, effective_base, allow_subdomains=allow_subdomains):
            css_url = css_rec["url"]
            if css_url not in seen_get:
                seen_get.add(css_url)
                records.append(css_rec)

    for form in FORM_RE.finditer(no_comments):
        attrs, body = form.group(1), form.group(2)
        action_m = FORM_ACTION_RE.search(attrs or "")
        method_m = FORM_METHOD_RE.search(attrs or "")
        enctype_m = FORM_ENCTYPE_RE.search(attrs or "")
        action = action_m.group(1) if action_m else ""
        method = (method_m.group(1) if method_m else "GET").upper() or "GET"
        enctype = (enctype_m.group(1) if enctype_m else "").split(";", 1)[0].strip().lower()
        url = normalize_url(action or ".", base=effective_base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            continue
        norm_method = method if method in {"GET", "POST", "PUT", "PATCH", "DELETE"} else "POST"
        content_type = ""
        if norm_method != "GET":
            content_type = enctype or "application/x-www-form-urlencoded"
        param_in = "query" if norm_method == "GET" else ("json" if content_type == "application/json" else "body")
        params = []
        for tag_m in INPUT_TAG_RE.finditer(body or ""):
            tag_attrs = tag_m.group(1) or ""
            nm = INPUT_NAME_RE.search(tag_attrs)
            if not nm or not nm.group(1):
                continue
            vm = INPUT_VAL_RE.search(tag_attrs)
            val = safe_sample(nm.group(1), unescape(vm.group(1))) if vm else ""
            params.append({
                "name": nm.group(1),
                "in": param_in,
                "sample": val,
            })
        if norm_method == "GET":
            params = params or params_from_url(url)
        extra = {"content_type": content_type} if content_type else None
        rec = _record(url, norm_method, "form", params, extra=extra)
        records.append(rec)
    return records


def extract_html(html: str, base: str, allow_subdomains: bool = False) -> list[dict]:
    return _extract_html_impl(html, base, allow_subdomains=allow_subdomains, depth=0)


def extract_robots(text: str, base: str) -> list[dict]:
    records = []
    seen = set()
    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for match in ROBOTS_RE.finditer(text or ""):
        path = match.group(1).strip()
        if not path or path == "/":
            continue
        url = normalize_url(urljoin(origin + "/", path.lstrip("/")), base=origin)
        if not url or url in seen:
            continue
        seen.add(url)
        records.append(_record(url, "GET", "robots", params_from_url(url)))
    return records


def is_sitemap_index(text: str) -> bool:
    return bool(SITEMAPINDEX_RE.search(text or ""))


def extract_sitemap(text: str, base: str, allow_subdomains: bool = False) -> list[dict]:
    records = []
    seen = set()
    source = "sitemapindex" if is_sitemap_index(text) else "sitemap"
    for loc in SITEMAP_LOC_RE.findall(text or ""):
        url = normalize_url(unescape(loc), base=base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            continue
        if url in seen:
            continue
        seen.add(url)
        records.append(_record(url, "GET", source, params_from_url(url)))
    return records


_FETCH_CALL_RE = re.compile(r"fetch\s*\(\s*(['\"`])([^'\"`]+)\1", re.I)
_AXIOS_METHOD_RE = re.compile(
    r"axios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*(['\"`])([^'\"`]+)\2", re.I)
_AXIOS_CONFIG_RE = re.compile(r"axios\s*\(\s*\{", re.I)
_METHOD_OPT_RE = re.compile(r"method\s*:\s*['\"]([A-Za-z]+)['\"]")
_CONFIG_URL_RE = re.compile(r"url\s*:\s*(['\"`])([^'\"`]+)\1")
_BODY_OBJECT_RE = re.compile(r"(?:body|data)\s*:\s*(?:JSON\.stringify\s*\(\s*)?\{")
_QUERY_PARAMS_OBJECT_RE = re.compile(r"\bparams\s*:\s*\{")
_FORM_URLENCODED_RE = re.compile(r"application/x-www-form-urlencoded|URLSearchParams", re.I)
_URLSEARCHPARAMS_STR_RE = re.compile(r"new\s+URLSearchParams\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.I)
_INLINE_SCRIPT_RE = re.compile(r"<script\b([^>]*)>([\s\S]*?)</script>", re.I)
_SCRIPT_SRC_ATTR_RE = re.compile(r"\bsrc\s*=", re.I)
_SPA_HASH_ROUTE_RE = re.compile(r"""(?:href\s*=\s*)?(['"`])(#/[^'"`\s<>]+)\1""", re.I)
_SPA_ROUTER_CALL_RE = re.compile(
    r"""(?:router\.(?:push|replace)|navigate|history\.pushState\s*\([^,]*,[^,]*,)\s*\(\s*(['"`])(/[^'"`\s<>]+)\1""",
    re.I,
)
_SPA_ROUTE_PATH_RE = re.compile(
    r"""\bpath\s*:\s*(['"`])(/[^'"`\s<>]{2,})\1""",
    re.I,
)
_SPA_ANGULAR_WHEN_RE = re.compile(
    r"""\.when\s*\(\s*(['"`])(/[^'"`\s<>]+)\1""",
    re.I,
)
_SPA_UI_ROUTER_URL_RE = re.compile(
    r"""\burl\s*:\s*(['"`])(/[^'"`\s<>]{2,})\1""",
    re.I,
)
_SPA_REACT_BASENAME_TAG_RE = re.compile(
    r"""<[A-Za-z]*Router\b[^>]*\bbasename\s*=\s*(?:(['"])([^'"]+)\1|\{\s*(['"])([^'"]+)\3\s*\})""",
    re.I,
)
_SPA_REACT_BASENAME_OPT_RE = re.compile(
    r"""\bbasename\s*:\s*(['"`])(/[^'"`\s<>]*)\1""",
    re.I,
)
_SPA_REACT_ROUTE_RE = re.compile(
    r"""<Route\b[^>]*\bpath\s*=\s*(?:(['"])([^'"]+)\1|\{\s*(['"])([^'"]+)\3\s*\})""",
    re.I,
)
_SPA_REACT_LINK_RE = re.compile(
    r"""<(?:Nav)?Link\b[^>]*\bto\s*=\s*(?:(['"])([^'"]+)\1|\{\s*(['"])([^'"]+)\3\s*\})""",
    re.I,
)
_SPA_COLON_PARAM_RE = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
_SPA_BRACKET_PARAM_RE = re.compile(r"\[{1,2}(?:\.\.\.)?([A-Za-z_][A-Za-z0-9_]*)(?:=[^\]/]+)?\]{1,2}")
_SPA_SEGMENT_BRACKET_PARAM_RE = re.compile(r"^\[{1,2}(?:\.\.\.)?([A-Za-z_][A-Za-z0-9_]*)(?:=[^\]/]+)?\]{1,2}$")
_SPA_VIRTUAL_GROUP_RE = re.compile(r"^\([A-Za-z0-9_-]+\)$")
_STATIC_SPA_EXT_RE = re.compile(r"\.(?:png|jpe?g|gif|css|ico|svg|woff2?|ttf|map|js|mjs)(?:\?|$)", re.I)
_NON_ENDPOINT_SOURCE_EXTS = (
    ".d.ts",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".vue",
    ".svelte",
    ".scss",
    ".sass",
    ".less",
    ".styl",
    ".map",
    ".wasm",
    ".avif",
    ".webmanifest",
)
_BUNDLER_PATH_MARKERS = (
    "/node_modules/",
    "/@vite/",
    "/@fs/",
    "/@id/",
    "/__vite",
    "/@react-refresh",
    "/_app/immutable/",
    "/_app/version.json",
    "/_next/static/",
    "/_next/data/",
)
_BUNDLER_EXACT_PATHS = frozenset({
    "/node_modules",
    "/@vite",
    "/@fs",
    "/@id",
    "/@react-refresh",
    "/_app/immutable",
    "/_app/version.json",
    "/_next/static",
    "/_next/data",
})
_FRONTEND_SOURCE_DIR_PREFIXES = (
    "/components/ui/",
    "/src/components/",
)
_JSON_SCHEMA_POINTER_RE = re.compile(
    r"(?:^|/)\$(?:defs|schema|ref|id|anchor|dynamicref|dynamicanchor|vocabulary|comment|_[A-Za-z0-9_-]*)(?:/|$)",
    re.IGNORECASE,
)
_HASHED_CHUNK_RE = re.compile(r"(?:^|/)chunks/[A-Za-z0-9_.-]{6,}\.(?:js|mjs|cjs)$", re.I)
_NODE_CHUNK_RE = re.compile(r"/nodes/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{6,}\.(?:js|mjs|cjs)$", re.I)
_REPEATED_LETTER_RUN_RE = re.compile(r"([A-Za-z])\1{4,}")
_LOWER_HEX_HYPHEN_RE = re.compile(r"[0-9a-f]+(?:-[0-9a-f]+)*")
_UUID_SEG_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_PATH_TEMPLATE_SEG_RE = re.compile(r"\{[A-Za-z0-9_.:-]+\}")
_PATH_KV_SCHEME_RE = re.compile(r"(?:(?<=^)|(?<=/))([A-Za-z][A-Za-z0-9_-]{0,31}=[A-Za-z][A-Za-z0-9+.-]{0,15}://)")
_ALLOWED_EMPTY_RHS_KV_KEYS = frozenset({
    "id", "q", "file", "filename", "filepath", "path", "pathname", "dir", "directory",
    "folder", "url", "uri", "href", "redirect", "dest", "destination", "target", "goto",
    "callback", "proxy", "forward", "upstream", "template", "tpl", "include", "src",
    "source", "next", "return", "location",
})
_FORBIDDEN_PATH_CHARS = frozenset("(),;*\"'`\\")
_LEADING_TEMPLATE_VAR_RE = re.compile(r"^(?:\$\{[^}]+\}|\{[A-Za-z_$][A-Za-z0-9_$]*\})(.*)$")
_BARE_TEMPLATE_VAR_RE = re.compile(r"^(?:\$\{[^}]+\}|\{[A-Za-z_$][A-Za-z0-9_$]*\})$")
_JS_LINE_COMMENT_RE = re.compile(r"(?:^|[\s;{}(),])//([^\n\r]*)")
_JS_BLOCK_COMMENT_RE = re.compile(r"/\*([\s\S]*?)\*/")
_JS_COMMENT_SLASH_PATH_RE = re.compile(
    r"""(?:^|[\s(\["'=,:;])(/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*(?:\?[A-Za-z0-9._~:/?#\[\]@!$&'*+,;=%-]+)?)"""
)
_JS_VAR_ASSIGN_RE = re.compile(
    r"""(?:^|[;\n\r{},])\s*(?:export\s+)?(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(['"`])([^'"`\n\r\\]{0,512})\2""",
    re.M,
)
_JS_CONCAT_ASSIGN_RE = re.compile(
    r"""(?:^|[;\n\r{},])\s*(?:export\s+)?(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=(?!=)\s*([^;\n\r{}()]{1,512}?\+[^;\n\r{}()]{1,512})""",
    re.M,
)
_JS_CONCAT_EXPR_RE = re.compile(
    r"""(?:^|[^\w$'"`.])((?:['"`][^'"`\n\r]*['"`]|[A-Za-z_$][\w$]*)(?:\s*\+\s*(?:['"`][^'"`\n\r]*['"`]|[A-Za-z_$][\w$]*)){1,11})(?=$|[^\w$'"`.])"""
)
_JS_OPERAND_TOK_RE = re.compile(
    r"""'([^'\n\r]*)'|"([^"\n\r]*)"|`([^`\n\r]*)`|([A-Za-z_$][\w$]*)"""
)
_JS_STATIC_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".css", ".ico", ".svg", ".woff", ".woff2")
_GRAPHQL_VAR_RE = re.compile(
    r"(?:query|mutation|subscription)\s*(?:[A-Za-z_]\w*\s*)?\(([^)]*)\)", re.S)
_GRAPHQL_VAR_NAME_RE = re.compile(r"\$([A-Za-z_]\w*)\s*:")
_SPEC_URL_RE = re.compile(r"""['"`]([^'"`]+?(?:openapi|swagger|api-docs)[^'"`]*?\.json)['"`]""", re.I)
_SPEC_NAME_RE = re.compile(r"""['"`]([^'"`]+?spec[^'"`]*?\.json)['"`]""", re.I)
_SPEC_ASSIGN_RE = re.compile(
    r"""(?:SPEC|OPENAPI|SWAGGER|API_?DOCS?)\w*\s*[:=]\s*['"`]([^'"`]+\.json)['"`]""", re.I)
_TEMPLATE_EXPR_RE = re.compile(r"\$\{([^}]+)\}")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def _object_span(text: str, start: int) -> str:
    """start'taki '{' için tırnak-duyarlı eşleşen süslü parantez aralığı."""
    depth, quote, escaped = 0, None, False
    for index in range(start, min(len(text), start + 4000)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return text[start:start + 4000]


def _top_level_keys(span: str) -> list[str]:
    keys, seen = [], set()
    inner = span[1:-1] if span.startswith("{") and span.endswith("}") else span
    depth, quote, escaped, index = 0, None, False, 0
    while index < len(inner):
        char = inner[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"`":
            if depth == 0:
                end = inner.find(char, index + 1)
                if end > index and inner[end + 1:end + 3].strip().startswith(":"):
                    name = inner[index + 1:end]
                    if name and name not in seen:
                        seen.add(name)
                        keys.append(name)
                    index = end + 1
                    continue
            quote = char
            index += 1
            continue
        if char in "{[(":
            depth += 1
        elif char in "}])":
            depth -= 1
        elif depth == 0 and (char.isalpha() or char in "_$"):
            match = _IDENTIFIER_RE.match(inner, index)
            if match:
                name = match.group(0)
                rest = inner[match.end():].lstrip()
                if rest.startswith(":"):
                    if name not in seen:
                        seen.add(name)
                        keys.append(name)
                index = match.end()
                continue
        index += 1
    return keys


def has_double_slash_path(path: str) -> bool:
    """Return True if a URL path contains ``//`` outside a valid ``key=scheme://`` parameter."""
    if "//" not in path:
        return False
    sanitized = _PATH_KV_SCHEME_RE.sub(lambda m: m.group(1)[:-1], path)
    return "//" in sanitized


def _split_url_path_for_validation(url_or_path: str) -> tuple[str, str, bool] | None:
    """Extract raw pre-query path, parsed path, and relative flag; return None if structurally invalid."""
    raw = str(url_or_path or "").strip()
    if not raw:
        return "", "", False
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    raw_no_qf = raw.split("#", 1)[0].split("?", 1)[0]
    path = (parsed.path or "").strip()
    if (not path or path == "/") and parsed.fragment.startswith("/"):
        raw_no_qf = raw.partition("#")[2].split("?", 1)[0].strip()
        path = parsed.fragment.strip().split("?", 1)[0]
    if not parsed.scheme and not parsed.netloc and raw_no_qf.startswith("///"):
        return None
    if not parsed.scheme and raw_no_qf.startswith("//"):
        if not parsed.netloc or ("." not in parsed.netloc and ":" not in parsed.netloc):
            return None
    is_unrooted_rel = not parsed.scheme and not parsed.netloc and not raw_no_qf.startswith("/")
    return raw_no_qf, path, is_unrooted_rel


def _is_implausible_path_parts(
    raw_no_qf: str,
    path: str,
    is_unrooted_rel: bool,
    *,
    allow_virtual_groups: bool = False,
) -> bool:
    """Return True when the URL path component looks like binary/base64/code-syntax noise."""
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 or ch == "\\" for ch in raw_no_qf):
        return True
    if not path or path == "/":
        return False
    if has_double_slash_path(path) or "==" in path or "${" in path:
        return True
    if any(ch in _FORBIDDEN_PATH_CHARS for ch in path):
        if not allow_virtual_groups:
            return True
        if any(ch in path for ch in (",", ";", "*", '"', "'", "`", "\\")):
            return True
    check_path = path
    if is_unrooted_rel:
        while check_path.startswith(("./", "../")):
            check_path = check_path[2:] if check_path.startswith("./") else check_path[3:]
        if not check_path or check_path in {".", ".."}:
            return True
    in_path_kv_tail = False
    for seg in (s for s in check_path.split("/") if s):
        if allow_virtual_groups and _SPA_VIRTUAL_GROUP_RE.fullmatch(seg):
            in_path_kv_tail = False
            continue
        if in_path_kv_tail and seg in {".", ".."}:
            continue
        in_path_kv_tail = False
        if "(" in seg or ")" in seg or "+" in seg:
            return True
        is_tmpl_seg = bool(_PATH_TEMPLATE_SEG_RE.fullmatch(seg))
        if is_tmpl_seg and not any(ch.isalnum() for ch in seg[1:-1]):
            return True
        if not any(ch.isalnum() for ch in seg) and not is_tmpl_seg:
            return True
        if "=" in seg:
            lhs, _, rhs = seg.partition("=")
            if not lhs or seg.endswith("==") or rhs.startswith("="):
                return True
            is_allowed_kv = lhs in _ALLOWED_EMPTY_RHS_KV_KEYS
            if not rhs and not is_allowed_kv:
                return True
            if is_allowed_kv and (rhs in {"", ".", ".."} or rhs.lower() in {"http:", "https:"}):
                in_path_kv_tail = True
        if (
            not _LOWER_HEX_HYPHEN_RE.fullmatch(seg)
            and not _UUID_SEG_RE.fullmatch(seg)
            and not is_tmpl_seg
            and _REPEATED_LETTER_RUN_RE.search(seg)
        ):
            return True
    return False


def _is_implausible_url_path(url_or_path: str, *, allow_virtual_groups: bool = False) -> bool:
    """Return True if `url_or_path` has implausible path syntax, base64 blobs, or code fragments."""
    raw = str(url_or_path or "").strip()
    if not raw:
        return False
    split_res = _split_url_path_for_validation(raw)
    if split_res is None:
        return True
    raw_no_qf, path, is_unrooted_rel = split_res
    return _is_implausible_path_parts(
        raw_no_qf,
        path,
        is_unrooted_rel,
        allow_virtual_groups=allow_virtual_groups,
    )


def is_non_endpoint_noise_path(url_or_path: str) -> bool:
    """Return True for frontend source modules, bundler chunk internals, schema pointers, and path noise.

    Preserves `.js` bundle URLs (e.g. `/assets/app.js`), query payloads, and valid endpoints while
    filtering SvelteKit/Next.js build internals (`/_app/immutable/`, `/_app/version.json`,
    `/_next/static/`, `/_next/data/`, `/chunks/<hash>.js`, `/nodes/<id>.<hash>.js`), dollar-prefixed
    schema refs, and implausible base64/WASM/JS-syntax path fragments.
    """
    raw = str(url_or_path or "").strip()
    if not raw:
        return False
    split_res = _split_url_path_for_validation(raw)
    if split_res is None:
        return True
    raw_no_qf, path, is_unrooted_rel = split_res
    if _is_implausible_path_parts(raw_no_qf, path, is_unrooted_rel):
        return True
    if not path or path == "/":
        return False
    norm_path = path.lower()
    if is_unrooted_rel:
        while norm_path.startswith(("./", "../")):
            norm_path = norm_path[2:] if norm_path.startswith("./") else norm_path[3:]
    else:
        while norm_path.startswith("./"):
            norm_path = norm_path[2:]
    if norm_path and not norm_path.startswith("/"):
        norm_path = "/" + norm_path
    trimmed = norm_path.rstrip("/")
    if not trimmed:
        return False
    if trimmed.endswith(_NON_ENDPOINT_SOURCE_EXTS):
        return True
    if _HASHED_CHUNK_RE.search(trimmed) or _NODE_CHUNK_RE.search(trimmed):
        return True
    if trimmed in _BUNDLER_EXACT_PATHS or any(marker in norm_path for marker in _BUNDLER_PATH_MARKERS):
        return True
    if norm_path.startswith(_FRONTEND_SOURCE_DIR_PREFIXES):
        return True
    if _JSON_SCHEMA_POINTER_RE.search(trimmed):
        return True
    return False


def _is_js_url_prefix_value(value: str) -> bool:
    """Return True if a constant JS string value looks like a safe URL or path prefix."""
    val = (value or "").strip()
    if not val or len(val) > 256:
        return False
    if any(ch.isspace() or ord(ch) < 32 or ch in ("\\", '"', "'", "`") for ch in val):
        return False
    if "${" in val or val.startswith("//"):
        return False
    low = val.lower()
    if low.startswith(("http://", "https://")):
        return bool(urlparse(val).netloc)
    return val.startswith(("/", "./", "../"))


def _resolve_js_call_raw_url(raw_url: str, symtab: dict[str, str]) -> str | None:
    """Resolve same-file URL/path prefix constants and strip unresolved leading base placeholders."""
    candidate = (raw_url or "").strip()
    if not candidate:
        return None

    if "${" in candidate and symtab:
        parts: list[str] = []
        pos = 0
        for match in _TEMPLATE_EXPR_RE.finditer(candidate):
            lit_before = candidate[pos:match.start()]
            parts.append(lit_before)
            ident = match.group(1).strip()
            preceded_by_slash = candidate[:match.start()].endswith("/")
            val = symtab.get(ident, "") if _IDENTIFIER_RE.fullmatch(ident) else ""
            if not preceded_by_slash and _is_js_url_prefix_value(val):
                spliced_so_far = "".join(parts)
                if spliced_so_far.endswith("/") and val.startswith("/"):
                    val = val.lstrip("/")
                if val.endswith("/") and candidate[match.end():].startswith("/"):
                    val = val[:-1]
                parts.append(val)
            else:
                parts.append(match.group(0))
            pos = match.end()
        parts.append(candidate[pos:])
        candidate = "".join(parts)

    if _BARE_TEMPLATE_VAR_RE.fullmatch(candidate):
        return None
    leading_m = _LEADING_TEMPLATE_VAR_RE.match(candidate)
    if leading_m:
        remainder = leading_m.group(1).strip()
        if not remainder or remainder.startswith("#"):
            return None
        if remainder.startswith(("/", "//")):
            return remainder
        if remainder.startswith("?"):
            return "/" + remainder
        return "/" + remainder.lstrip("./")
    return candidate


def _template_url(raw: str) -> tuple[str, list[str]]:
    names = []

    def repl(match):
        inner = match.group(1)
        found = _IDENTIFIER_RE.findall(inner)
        name = found[-1] if found else "id"
        names.append(name)
        return "{" + name + "}"

    return _TEMPLATE_EXPR_RE.sub(repl, raw), names


def find_spec_urls(text: str, base: str, allow_subdomains: bool = False) -> list[str]:
    urls, seen = [], set()
    matches: list[re.Match[str]] = []
    for pattern in (_SPEC_URL_RE, _SPEC_NAME_RE, _SPEC_ASSIGN_RE):
        matches.extend(pattern.finditer(text or ""))
    for match in matches:
        url = normalize_url(match.group(1), base=base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def extract_js_calls(text: str, base: str, allow_subdomains: bool = False,
                     limit: int | None = 80) -> list[dict]:
    """JS çağrılarından metot + parametre şeması hasadı (WS2).

    fetch/axios çağrılarındaki URL, HTTP metodu, gövde anahtarları ve
    şablon parametreleri surface kaydı olur. GraphQL uçlarında sorgu
    değişkenleri parametre sayılır. Değerlendirme yok; sınırlı regex taraması.
    """
    source = text or ""
    symtab = _collect_js_string_symtab(source)
    parsed_base = urlparse(base or "")
    if (
        parsed_base.scheme in ("http", "https")
        and parsed_base.netloc
        and parsed_base.path.lower().endswith((".js", ".mjs"))
    ):
        call_base = f"{parsed_base.scheme}://{parsed_base.netloc}/"
    else:
        call_base = base
    calls = []  # (raw_url, method, body_keys, is_graphql_hint)

    def option_slice(start: int) -> str:
        # Seçenekler yalnız bu çağrının parantez aralığında aranır; sonraki
        # çağrıya taşan dilim metot/gövdeyi karıştırır.
        open_paren = source.find("(", start)
        if open_paren < 0:
            return source[start:start + 2000]
        depth, quote, escaped = 0, None, False
        for index in range(open_paren, min(len(source), open_paren + 4000)):
            char = source[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in "'\"`":
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return source[start:index + 1]
        return source[start:start + 2000]

    def body_keys(slice_text: str, *, axios_positional: bool = False) -> list[str]:
        match = _BODY_OBJECT_RE.search(slice_text)
        if not match and axios_positional:
            # axios.<metot>(url, {gövde}) — gövde ikinci konum argümanıdır.
            match = re.search(r"\(\s*(['\"`])[^'\"`]+\1\s*,\s*\{", slice_text)
        if not match:
            usp = _URLSEARCHPARAMS_STR_RE.search(slice_text)
            if usp:
                from urllib.parse import parse_qsl as _parse_qsl
                return [k for k, _ in _parse_qsl(usp.group(1), keep_blank_values=True) if k]
            return []
        brace = match.end() - 1  # desen eşleşmesi gövde "{" ile biter
        return _top_level_keys(_object_span(slice_text, brace))

    def query_option_keys(slice_text: str) -> list[str]:
        match = _QUERY_PARAMS_OBJECT_RE.search(slice_text)
        if not match:
            return []
        return _top_level_keys(_object_span(slice_text, match.end() - 1))

    for match in _FETCH_CALL_RE.finditer(source):
        opts = option_slice(match.start())
        method_match = _METHOD_OPT_RE.search(opts[:400])
        method = (method_match.group(1).upper() if method_match else "GET")
        calls.append((match.group(2), method, body_keys(opts), opts))
    for match in _AXIOS_METHOD_RE.finditer(source):
        opts = option_slice(match.start())
        meth = match.group(1).upper()
        bkeys = [] if meth == "GET" else body_keys(opts, axios_positional=True)
        calls.append((match.group(3), meth, bkeys, opts))
    for match in _AXIOS_CONFIG_RE.finditer(source):
        opts = option_slice(match.start())
        url_match = _CONFIG_URL_RE.search(opts[:600])
        if not url_match:
            continue
        method_match = _METHOD_OPT_RE.search(opts[:600])
        method = (method_match.group(1).upper() if method_match else "GET")
        calls.append((url_match.group(2), method, body_keys(opts), opts))

    records, seen = [], set()
    for raw_url, method, keys, opts in calls:
        resolved_raw = _resolve_js_call_raw_url(raw_url, symtab)
        if not resolved_raw:
            continue
        templated, template_names = _template_url(resolved_raw)
        if _is_implausible_url_path(templated):
            continue
        url = normalize_url(templated, base=call_base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            continue
        parsed_url = urlparse(url)
        if parsed_url.path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".css", ".ico",
                                             ".svg", ".woff", ".woff2", ".js")):
            continue
        if is_non_endpoint_noise_path(url):
            continue
        is_graphql = "graphql" in parsed_url.path.lower()
        is_form_encoded = method != "GET" and bool(_FORM_URLENCODED_RE.search(opts))
        params = params_from_url(url)
        present = {param["name"] for param in params}
        for name in query_option_keys(opts):
            if name not in present:
                params.append({"name": name, "in": "query", "sample": ""})
                present.add(name)
        for name in template_names:
            if name not in present:
                params.append({"name": name, "in": "path", "sample": ""})
                present.add(name)
        body_in = "body" if is_form_encoded else "json"
        for name in keys:
            if is_graphql and name in {"query", "variables", "operationName"}:
                continue
            if name not in present:
                params.append({"name": name, "in": body_in, "sample": ""})
                present.add(name)
        if is_graphql:
            query_match = re.search(r"\bquery\s*:\s*(['\"`])((?:\\.|(?!\1)[\s\S])*?)\1", opts)
            document = query_match.group(2) if query_match else ""
            # Literal discovery only; runtime interpolation requires a capture.
            if "${" in document:
                document = ""
            operation_match = re.search(r"\boperationName\s*:\s*['\"]([_A-Za-z][_0-9A-Za-z]*)['\"]", opts)
            operation_name = operation_match.group(1) if operation_match else ""
            from .operation import graphql_operation
            operation = graphql_operation(document, operation_name)
            graphql_vars = {v["name"] for v in operation.get("variables") or []}
            from .normalize import safe_sample
            params.append({"name": "query", "in": "json", "sample": safe_sample("query", document)
                           if document and '"' not in document else "<unavailable>"})
            if operation_name:
                params.append({"name": "operationName", "in": "json", "sample": operation_name})
            for name in sorted(graphql_vars):
                if name not in present:
                    variable_type = next(v["type"] for v in operation["variables"] if v["name"] == name)
                    params.append({"name": name, "in": "json", "path": ["variables", name], "sample": "<unavailable>",
                                   "required": variable_type.endswith("!"), "graphql_type": variable_type})
                    present.add(name)
        else:
            operation = None
        key = (method, url, (operation or {}).get("document_hash"))
        if key in seen:
            continue
        seen.add(key)
        record = _record(url, method, "graphql" if is_graphql else "js-call", params)
        if method != "GET":
            if is_form_encoded and any(p.get("in") == "body" for p in params):
                record["content_type"] = "application/x-www-form-urlencoded"
            elif any(p.get("in") == "json" for p in params):
                record["content_type"] = "application/json"
        if operation:
            record["operation"] = operation
        records.append(record)
        if limit is not None and len(records) >= limit:
            break
    return records


def extract_inline_scripts(html: str) -> list[str]:
    """Return non-empty inline <script> bodies from HTML without fetching external srcs."""
    scripts: list[str] = []
    for match in _INLINE_SCRIPT_RE.finditer(html or ""):
        attrs, body = match.group(1) or "", match.group(2) or ""
        if _SCRIPT_SRC_ATTR_RE.search(attrs):
            continue
        if body.strip():
            scripts.append(body)
    return scripts


def _normalize_spa_basename(raw: str) -> str:
    cleaned = (raw or "").strip()
    if not cleaned or cleaned == "/":
        return ""
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    return cleaned.rstrip("/")


def _join_spa_basename(basename: str, raw_path: str) -> str:
    path = (raw_path or "").strip()
    if not path or "*" in path:
        return ""
    if not basename:
        return path
    if path.startswith("#/"):
        return path
    if path == basename or path.startswith(basename + "/"):
        return path
    if path == "/":
        return basename
    return basename + "/" + path.lstrip("/")


def _normalize_spa_route_path(
    raw_path: str,
    *,
    normalize_colon: bool = True,
    drop_empty_root: bool = False,
) -> str:
    """Normalize `:param`/`[param]` syntax and strip virtual router group segments like `(app)`."""
    cleaned = str(raw_path or "").strip()
    if not cleaned:
        return ""
    if cleaned.startswith("#/"):
        cleaned = cleaned[1:]
    if not cleaned.startswith("/"):
        return ""
    path_part, sep, query_part = cleaned.partition("?")
    if "*" in path_part:
        return ""
    if normalize_colon:
        path_part = _SPA_COLON_PARAM_RE.sub(r"{\1}", path_part)
    bracket_re = _SPA_BRACKET_PARAM_RE if normalize_colon else _SPA_SEGMENT_BRACKET_PARAM_RE
    raw_segs = [seg for seg in path_part.split("/") if seg]
    norm_segs = [
        bracket_re.sub(r"{\1}", seg)
        for seg in raw_segs
        if not _SPA_VIRTUAL_GROUP_RE.fullmatch(seg)
    ]
    if drop_empty_root and not norm_segs and not query_part:
        return ""
    norm_path = "/" + "/".join(norm_segs)
    return f"{norm_path}{sep}{query_part}" if sep else norm_path


def extract_spa_routes(
    text: str,
    base: str,
    allow_subdomains: bool = False,
    limit: int | None = 80,
) -> list[dict]:
    """Extract SPA hash routes (#/path?q=1) and client router route definitions."""
    source = text or ""
    records: list[dict] = []
    seen: set[str] = set()

    basename = ""
    bn_match = _SPA_REACT_BASENAME_TAG_RE.search(source)
    if bn_match:
        basename = _normalize_spa_basename(bn_match.group(2) or bn_match.group(4) or "")
    else:
        bn_opt = _SPA_REACT_BASENAME_OPT_RE.search(source)
        if bn_opt:
            basename = _normalize_spa_basename(bn_opt.group(2) or "")

    def _emit_route(raw_path: str, source_tag: str) -> None:
        if limit is not None and len(records) >= limit:
            return
        if _is_implausible_url_path(raw_path, allow_virtual_groups=True):
            return
        cleaned = _normalize_spa_route_path(raw_path)
        if not cleaned or _STATIC_SPA_EXT_RE.search(cleaned):
            return
        if is_non_endpoint_noise_path(cleaned):
            return
        url = normalize_url(cleaned, base=base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            return
        if urlparse(url).path == "/" and not urlparse(url).query:
            return
        if url in seen:
            return
        seen.add(url)
        params = params_from_url(url)
        present = {p["name"] for p in params}
        for pname in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", cleaned):
            if pname not in present:
                params.append({"name": pname, "in": "path", "sample": ""})
                present.add(pname)
        records.append(_record(url, "GET", source_tag, params))

    for match in _SPA_HASH_ROUTE_RE.finditer(source):
        _emit_route(match.group(2), "spa-hash")
    for pattern in (_SPA_ROUTER_CALL_RE, _SPA_ROUTE_PATH_RE, _SPA_ANGULAR_WHEN_RE, _SPA_UI_ROUTER_URL_RE):
        for match in pattern.finditer(source):
            _emit_route(match.group(2), "spa-route")
    for pattern in (_SPA_REACT_ROUTE_RE, _SPA_REACT_LINK_RE):
        for match in pattern.finditer(source):
            raw_p = match.group(2) or match.group(4) or ""
            _emit_route(_join_spa_basename(basename, raw_p), "spa-route")
    return records


def _eval_js_concat(expr: str, symtab: dict[str, str]) -> str | None:
    parts: list[str] = []
    pos = 0
    s = (expr or "").strip()
    while pos < len(s):
        m = _JS_OPERAND_TOK_RE.match(s, pos)
        if not m:
            return None
        if m.group(1) is not None or m.group(2) is not None or m.group(3) is not None:
            lit = m.group(1) if m.group(1) is not None else (
                m.group(2) if m.group(2) is not None else (m.group(3) or "")
            )
            if "${" in lit:
                return None
            parts.append(lit)
        else:
            ident = m.group(4)
            if not ident or ident not in symtab:
                return None
            parts.append(symtab[ident])
        pos = m.end()
        rest = s[pos:].lstrip()
        if not rest:
            break
        if not rest.startswith("+"):
            return None
        pos = len(s) - len(rest) + 1
        while pos < len(s) and s[pos].isspace():
            pos += 1
        if pos >= len(s):
            return None
    if len(parts) < 2:
        return None
    return "".join(parts)


def _looks_js_url_or_path(val: str) -> bool:
    if not val or any(ch.isspace() or ord(ch) < 32 for ch in val):
        return False
    low = val.lower()
    if low.startswith(("http://", "https://", "//", "/", "./", "../")):
        return True
    if re.fullmatch(r"[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)+(?:\?[^\s]*)?", val):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9._~-]+\.[A-Za-z][A-Za-z0-9]{1,5}(?:\?[^\s]*)?", val))


def _eval_js_template_literal(raw_tmpl: str, symtab: dict[str, str]) -> str | None:
    """Resolve a simple template literal if every `${ident}` binding exists in `symtab`."""
    if "${" not in raw_tmpl:
        return raw_tmpl
    parts: list[str] = []
    last = 0
    for match in _TEMPLATE_EXPR_RE.finditer(raw_tmpl):
        parts.append(raw_tmpl[last:match.start()])
        ident = match.group(1).strip()
        if not _IDENTIFIER_RE.fullmatch(ident) or ident not in symtab:
            return None
        val = symtab[ident]
        if "${" in val:
            return None
        parts.append(val)
        last = match.end()
    parts.append(raw_tmpl[last:])
    return "".join(parts)


def _collect_js_string_symtab(
    source: str,
    *,
    max_chars: int = 262_144,
    max_entries: int = 2048,
) -> dict[str, str]:
    """Collect bounded same-file constant JS string, concat, and simple template bindings."""
    js_slice = (source or "")[:max_chars]
    symtab: dict[str, str] = {}
    pending_templates: list[tuple[str, str]] = []

    for vm in _JS_VAR_ASSIGN_RE.finditer(js_slice):
        var_name, quote, raw_val = vm.group(1), vm.group(2), vm.group(3)
        if quote == "`" and "${" in raw_val:
            if len(pending_templates) < max_entries:
                pending_templates.append((var_name, raw_val))
            continue
        if var_name not in symtab and len(symtab) >= max_entries:
            if not _is_js_url_prefix_value(raw_val) or len(symtab) >= max_entries + 256:
                continue
        symtab[var_name] = raw_val

    for _ in range(2):
        changed = False
        for am in _JS_CONCAT_ASSIGN_RE.finditer(js_slice):
            var_name = am.group(1)
            if var_name not in symtab and len(symtab) >= max_entries + 256:
                continue
            resolved = _eval_js_concat(am.group(2), symtab)
            if resolved is not None and "${" not in resolved:
                if symtab.get(var_name) != resolved:
                    symtab[var_name] = resolved
                    changed = True
        for var_name, raw_tmpl in pending_templates:
            if var_name not in symtab and len(symtab) >= max_entries + 256:
                continue
            resolved = _eval_js_template_literal(raw_tmpl, symtab)
            if resolved is not None:
                if symtab.get(var_name) != resolved:
                    symtab[var_name] = resolved
                    changed = True
        if not changed:
            break

    return symtab


def extract_js(text: str, base: str, allow_subdomains: bool = False, limit: int | None = 80) -> list[dict]:
    if limit is not None and limit <= 0:
        return []
    source = text or ""
    records: list[dict] = []
    seen: set[str] = set()

    def _emit_js(candidate: str) -> bool:
        cand = (candidate or "").strip()
        if not cand or "${" in cand:
            return False
        if _is_implausible_url_path(cand, allow_virtual_groups=True):
            return False
        if cand.startswith("/") and not cand.startswith("//"):
            cand = _normalize_spa_route_path(cand, normalize_colon=False, drop_empty_root=True)
            if not cand:
                return False
        if cand.lower().endswith(_JS_STATIC_EXTS):
            return False
        url = normalize_url(cand, base=base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            return False
        if urlparse(url).path.lower().endswith(_JS_STATIC_EXTS):
            return False
        if is_non_endpoint_noise_path(url):
            return False
        if url in seen:
            return False
        seen.add(url)
        records.append(_record(url, "GET", "js", params_from_url(url)))
        return limit is not None and len(records) >= limit

    for pattern in JS_PATTERNS:
        for match in pattern.findall(source):
            candidate = match if isinstance(match, str) else match[0]
            if _emit_js(candidate):
                return records

    for comment_re in (_JS_LINE_COMMENT_RE, _JS_BLOCK_COMMENT_RE):
        for cm in comment_re.finditer(source):
            cbody = cm.group(1) or ""
            for m in _TEXT_ABS_URL_RE.finditer(cbody):
                if _emit_js(m.group(0).rstrip(".,;:!?]")):
                    return records
            for m in _TEXT_REL_DOT_RE.finditer(cbody):
                if _emit_js(m.group(1).rstrip(".,;:!?]")):
                    return records
            for m in _JS_COMMENT_SLASH_PATH_RE.finditer(cbody):
                if _emit_js(m.group(1).rstrip(".,;:!?]")):
                    return records

    symtab = _collect_js_string_symtab(source)
    js_slice = source[:262_144]
    for em in _JS_CONCAT_EXPR_RE.finditer(js_slice):
        resolved = _eval_js_concat(em.group(1), symtab)
        if resolved is not None and _looks_js_url_or_path(resolved):
            if _emit_js(resolved):
                return records

    return records


def extract_source_urls(text: str, base: str) -> list[str]:
    """Record external sources and literal lazy bundles without executing JS.

    No host filtering: the frontier records these as approval prerequisites.
    Runtime-computed import names require actual browser observations.
    """
    patterns = [HREF_RE, re.compile(r"['\"`]((?:https?:)?//[^'\"`\s]+)['\"`]"),
                re.compile(r"['\"`]([^'\"`\s]+\.(?:js|mjs)(?:\?[^'\"`\s]*)?)['\"`]")]
    urls = []
    for pattern in patterns:
        for match in pattern.finditer(text or ""):
            url = normalize_url(match.group(1), base=base)
            if url and url not in urls:
                urls.append(url)
    return urls


MAX_JSON_DISCOVERY_ITEMS = 64
MAX_JSON_DISCOVERY_DEPTH = 5
MAX_JSON_DISCOVERY_NODES = 1024
_PAGINATION_KEYS = frozenset({"next", "next_url", "prev", "previous", "prev_url", "first", "last"})
_DIRECT_LINK_KEYS = frozenset({"url", "href", "uri", "link", "action", "endpoint", "self"})
_ENVELOPE_LINK_LIST_KEYS = frozenset({
    "links", "internal_links", "urls_sample", "pages", "urls_with_params", "form_actions", "js_files", "actions", "forms",
    "endpoints", "routes", "apis", "resources",
})
_ENVELOPE_RECORD_LIST_KEYS = frozenset({"records", "work_queue"})
_COLLECTION_CONTAINER_KEYS = frozenset({
    "items", "results", "data", "entries", "pagination", "paging", "page_info", "meta", "_links", "hal", "surface",
})
_DISCOVERY_SPEC_KEYS = frozenset({
    "openapi", "openapi_url", "swagger", "swagger_url", "spec", "spec_url", "discovery", "discovery_url",
})
_PAGINATION_CONTAINER_KEYS = frozenset({"pagination", "paging", "page_info"})
_VALID_PARAM_NAME_RE = re.compile(r"[A-Za-z0-9_.:\[\]-]{1,96}")


def _valid_param_name(value: Any) -> bool:
    return isinstance(value, str) and _VALID_PARAM_NAME_RE.fullmatch(value) is not None


def _normalize_candidate_link(
    raw: Any,
    base_url: str,
    origin_url: str,
    *,
    allow_bare_relative: bool = True,
) -> str | None:
    """Resolve explicit relative/same-origin URLs without inventing links from arbitrary scalars."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text or len(text) > 2048 or text.startswith("#"):
        return None
    if any(ch.isspace() or ord(ch) < 32 for ch in text):
        return None
    if not allow_bare_relative and not text.startswith(("http://", "https://", "/", "./", "../", "?")):
        return None
    if text.isdigit():
        return None
    parsed_raw = urlsplit(text)
    if parsed_raw.scheme and parsed_raw.scheme.lower() not in {"http", "https"}:
        return None
    resolved = urljoin(base_url, text)
    parsed = urlsplit(resolved)
    origin = urlsplit(origin_url)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc)
        or parsed.username is not None
    ):
        return None
    return parsed._replace(fragment="").geturl()


def structured_params_from_node(node: dict[str, Any], method: str = "GET") -> tuple[list[dict[str, Any]] | None, str]:
    """Extract normalized form/json param declarations and content_type from a descriptor object."""
    norm_method = str(method or "GET").upper()
    raw_ctype = node.get("content_type")
    ctype = raw_ctype.split(";", 1)[0].strip().lower() if isinstance(raw_ctype, str) else ""
    if isinstance(node.get("params"), list):
        return copy.deepcopy(node["params"]), ctype
    if norm_method == "GET":
        return None, ctype
    json_obj = node.get("json_body") if isinstance(node.get("json_body"), dict) else (
        node.get("body") if isinstance(node.get("body"), dict) and ctype in {"", "application/json"} else None
    )
    if isinstance(json_obj, dict):
        derived = [
            {
                "name": k,
                "in": "json",
                "sample": "" if v is None else ("true" if v is True else "false" if v is False else str(v)),
            }
            for k, v in json_obj.items()
            if _valid_param_name(k) and (v is None or isinstance(v, (str, int, float, bool)))
        ]
        return derived, ctype or "application/json"
    form_obj = (
        node.get("form") if isinstance(node.get("form"), dict)
        else node.get("form_fields") if isinstance(node.get("form_fields"), dict)
        else node.get("fields") if isinstance(node.get("fields"), dict)
        else None
    )
    if isinstance(form_obj, dict):
        param_in = "json" if ctype == "application/json" else "form"
        derived = [
            {
                "name": k,
                "in": param_in,
                "sample": "" if v is None else ("true" if v is True else "false" if v is False else str(v)),
            }
            for k, v in form_obj.items()
            if _valid_param_name(k) and (v is None or isinstance(v, (str, int, float, bool)))
        ]
        return derived, ctype or ("application/json" if param_in == "json" else "application/x-www-form-urlencoded")
    return None, ctype


def extract_json_hypermedia(
    payload: Any,
    base_url: str,
    *,
    origin_url: str | None = None,
    from_http_body: bool = True,
    max_items: int = MAX_JSON_DISCOVERY_ITEMS,
    max_depth: int = MAX_JSON_DISCOVERY_DEPTH,
    max_nodes: int = MAX_JSON_DISCOVERY_NODES,
) -> tuple[list[dict[str, Any]], bool]:
    """Bounded extraction of relative/same-origin JSON hypermedia and pagination links.

    Never invents request URLs from arbitrary scalars or object IDs.
    """
    if not isinstance(payload, (dict, list)) or not isinstance(base_url, str) or not base_url:
        return [], False
    effective_origin = origin_url or base_url
    extracted: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    truncated = False
    nodes_visited = 0

    _unset = object()

    def _emit(
        raw_url: Any,
        *,
        method: str = "GET",
        params: Any = _unset,
        link_relation: str = "json_link",
        extra: dict[str, Any] | None = None,
        allow_bare_relative: bool = True,
    ) -> None:
        nonlocal truncated
        if len(extracted) >= max_items:
            truncated = True
            return
        resolved = _normalize_candidate_link(
            raw_url,
            base_url,
            effective_origin,
            allow_bare_relative=allow_bare_relative,
        )
        if not resolved:
            return
        norm_method = str(method or "GET").upper()
        ident = ""
        ctype = ""
        if isinstance(extra, dict):
            raw_ident = extra.get("identity_ref", extra.get("identity", ""))
            ident = str(raw_ident) if isinstance(raw_ident, str) else ""
            derived_params, ctype = structured_params_from_node(extra, norm_method)
            if params is _unset and derived_params is not None:
                params = derived_params
        dedup_key = (norm_method, resolved, ident, link_relation, ctype)
        if dedup_key in seen:
            return
        seen.add(dedup_key)
        item: dict[str, Any] = {
            "url": resolved,
            "method": norm_method,
        }
        if link_relation:
            item["link_relation"] = link_relation
        if params is not _unset:
            item["params"] = copy.deepcopy(params)
        if ctype:
            item["content_type"] = ctype
        if isinstance(extra, dict):
            has_storage_op = isinstance(extra.get("operation"), dict)
            for field in ("identity_ref", "identity", "candidate_reason", "operation_id"):
                if field == "operation_id" and has_storage_op:
                    continue
                if field in extra:
                    item[field] = copy.deepcopy(extra[field])
        extracted.append(item)

    def _walk(node: Any, *, depth: int, parent_key: str, in_pagination: bool) -> None:
        nonlocal nodes_visited, truncated
        if truncated:
            return
        if depth > max_depth:
            return
        nodes_visited += 1
        if nodes_visited > max_nodes:
            truncated = True
            return
        if isinstance(node, list):
            for element in node:
                if truncated:
                    return
                if isinstance(element, str) and parent_key in _ENVELOPE_LINK_LIST_KEYS:
                    rel = "pagination" if in_pagination else ("json_link" if from_http_body or parent_key == "links" else "")
                    _emit(element, link_relation=rel)
                elif isinstance(element, dict):
                    _walk(element, depth=depth + 1, parent_key=parent_key, in_pagination=in_pagination)
                elif isinstance(element, list):
                    _walk(element, depth=depth + 1, parent_key=parent_key, in_pagination=in_pagination)
            return
        if not isinstance(node, dict):
            return

        rel_value = str(node.get("rel") or "").strip().lower()
        node_pagination = in_pagination or rel_value in _PAGINATION_KEYS
        default_rel = "json_link" if (from_http_body or parent_key in {"items", "results", "data", "entries", "_links", "links"}) else ""
        direct_url = (
            node.get("url") if "url" in node
            else node.get("href") if "href" in node
            else (node.get("action") if "action" in node and "method" in node
                  else node.get("endpoint") if "endpoint" in node and "method" in node
                  else None)
        )
        if isinstance(direct_url, str) and (
            parent_key in _ENVELOPE_LINK_LIST_KEYS
            or parent_key in _ENVELOPE_RECORD_LIST_KEYS
            or parent_key in _COLLECTION_CONTAINER_KEYS
            or parent_key in _PAGINATION_KEYS
            or parent_key in _DIRECT_LINK_KEYS
            or depth == 0
        ):
            _emit(
                direct_url,
                method=str(node.get("method") or "GET"),
                params=node["params"] if "params" in node else _unset,
                link_relation="pagination" if node_pagination else ("self" if rel_value == "self" else default_rel),
                extra=node,
            )

        for key, value in node.items():
            if truncated:
                return
            if not isinstance(key, str):
                continue
            low = key.lower()
            if low in {"url", "href", "action", "endpoint"} and value is direct_url:
                continue
            if low in _PAGINATION_KEYS:
                if isinstance(value, str):
                    _emit(value, link_relation="pagination")
                elif isinstance(value, dict):
                    _walk(value, depth=depth + 1, parent_key=low, in_pagination=True)
            elif low in _DISCOVERY_SPEC_KEYS and from_http_body and isinstance(value, str):
                _emit(value, link_relation="schema", allow_bare_relative=False)
            elif low in _DIRECT_LINK_KEYS:
                if isinstance(value, str):
                    rel = "self" if low == "self" else ("pagination" if node_pagination else default_rel)
                    _emit(value, link_relation=rel)
                elif isinstance(value, dict):
                    _walk(value, depth=depth + 1, parent_key=low, in_pagination=node_pagination)
            elif low in _ENVELOPE_LINK_LIST_KEYS or low in _ENVELOPE_RECORD_LIST_KEYS or low in _COLLECTION_CONTAINER_KEYS:
                if not from_http_body and (
                    low in _ENVELOPE_RECORD_LIST_KEYS
                    or (low in _ENVELOPE_LINK_LIST_KEYS and not (low == "links" and isinstance(value, dict)))
                ):
                    continue
                child_pag = node_pagination or (low in _PAGINATION_CONTAINER_KEYS)
                if low in {"_links", "links"} and isinstance(value, dict):
                    for rel_name, target_val in value.items():
                        rel_low = str(rel_name).lower()
                        rel_tag = "pagination" if rel_low in _PAGINATION_KEYS else ("self" if rel_low == "self" else "json_link")
                        if isinstance(target_val, str):
                            _emit(target_val, link_relation=rel_tag)
                        elif isinstance(target_val, dict):
                            _walk(target_val, depth=depth + 1, parent_key=rel_low, in_pagination=rel_tag == "pagination")
                        elif isinstance(target_val, list):
                            _walk(target_val, depth=depth + 1, parent_key="links", in_pagination=rel_tag == "pagination")
                elif isinstance(value, (dict, list)):
                    _walk(value, depth=depth + 1, parent_key=low, in_pagination=child_pag)

    _walk(payload, depth=0, parent_key="", in_pagination=False)
    return extracted, truncated
