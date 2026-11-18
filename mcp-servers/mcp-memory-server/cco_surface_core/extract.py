"""Extract URLs, forms, and params from HTML, robots, sitemap, and JS text."""

from __future__ import annotations

import copy
import re
from html import unescape
from typing import Any
from urllib.parse import urljoin, urlparse, urlsplit

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
]


def _record(url: str, method: str = "GET", source: str = "", params=None, extra=None):
    item = {"url": url, "method": method, "sources": [source] if source else []}
    if params:
        item["params"] = params
    if extra:
        item.update(extra)
    return item


def extract_html(html: str, base: str, allow_subdomains: bool = False) -> list[dict]:
    records = []
    seen = set()
    for match in HREF_RE.finditer(html or ""):
        url = normalize_url(match.group(1), base=base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            continue
        key = ("GET", url)
        if key in seen:
            continue
        seen.add(key)
        rec = _record(url, "GET", "html")
        rec["params"] = params_from_url(url)
        records.append(rec)
    for form in FORM_RE.finditer(html or ""):
        attrs, body = form.group(1), form.group(2)
        action_m = FORM_ACTION_RE.search(attrs or "")
        method_m = FORM_METHOD_RE.search(attrs or "")
        enctype_m = FORM_ENCTYPE_RE.search(attrs or "")
        action = action_m.group(1) if action_m else ""
        method = (method_m.group(1) if method_m else "GET").upper() or "GET"
        enctype = (enctype_m.group(1) if enctype_m else "").split(";", 1)[0].strip().lower()
        url = normalize_url(action or ".", base=base)
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
_SPA_COLON_PARAM_RE = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
_STATIC_SPA_EXT_RE = re.compile(r"\.(?:png|jpe?g|gif|css|ico|svg|woff2?|ttf|map|js|mjs)(?:\?|$)", re.I)
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
    matches = []
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
        templated, template_names = _template_url(raw_url)
        url = normalize_url(templated, base=base)
        if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
            continue
        if url.endswith((".png", ".jpg", ".jpeg", ".gif", ".css", ".ico",
                         ".svg", ".woff", ".woff2", ".js")):
            continue
        is_graphql = "graphql" in urlparse(url).path.lower()
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

    def _emit_route(raw_path: str, source_tag: str) -> None:
        if limit is not None and len(records) >= limit:
            return
        cleaned = _SPA_COLON_PARAM_RE.sub(r"{\1}", str(raw_path or "").strip())
        if not cleaned or _STATIC_SPA_EXT_RE.search(cleaned):
            return
        if cleaned.startswith("#/"):
            cleaned = cleaned[1:]
        if not cleaned.startswith("/"):
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
    for pattern in (_SPA_ROUTER_CALL_RE, _SPA_ROUTE_PATH_RE):
        for match in pattern.finditer(source):
            _emit_route(match.group(2), "spa-route")
    return records


def extract_js(text: str, base: str, allow_subdomains: bool = False, limit: int | None = 80) -> list[dict]:
    records = []
    seen = set()
    for pattern in JS_PATTERNS:
        for match in pattern.findall(text or ""):
            candidate = match if isinstance(match, str) else match[0]
            if candidate.endswith((".png", ".jpg", ".jpeg", ".gif", ".css", ".ico", ".svg", ".woff", ".woff2")):
                continue
            url = normalize_url(candidate, base=base)
            if not url or not same_host(url, base, allow_subdomains=allow_subdomains):
                continue
            if url in seen:
                continue
            seen.add(url)
            records.append(_record(url, "GET", "js", params_from_url(url)))
            if limit is not None and len(records) >= limit:
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
})
_ENVELOPE_RECORD_LIST_KEYS = frozenset({"records", "work_queue"})
_COLLECTION_CONTAINER_KEYS = frozenset({
    "items", "results", "data", "entries", "pagination", "paging", "page_info", "meta", "_links", "hal", "surface",
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
