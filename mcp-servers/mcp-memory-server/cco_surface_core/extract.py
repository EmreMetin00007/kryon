"""Extract URLs, forms, and params from HTML, robots, sitemap, and JS text."""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import urljoin, urlparse

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
            return []
        brace = match.end() - 1  # desen eşleşmesi gövde "{" ile biter
        return _top_level_keys(_object_span(slice_text, brace))

    for match in _FETCH_CALL_RE.finditer(source):
        opts = option_slice(match.start())
        method_match = _METHOD_OPT_RE.search(opts[:400])
        method = (method_match.group(1).upper() if method_match else "GET")
        calls.append((match.group(2), method, body_keys(opts), opts))
    for match in _AXIOS_METHOD_RE.finditer(source):
        calls.append((match.group(3), match.group(1).upper(),
                      body_keys(option_slice(match.start()), axios_positional=True), option_slice(match.start())))
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
        params = params_from_url(url)
        present = {param["name"] for param in params}
        for name in template_names:
            if name not in present:
                params.append({"name": name, "in": "path", "sample": ""})
                present.add(name)
        for name in keys:
            if is_graphql and name in {"query", "variables", "operationName"}:
                continue
            if name not in present:
                params.append({"name": name, "in": "json", "sample": ""})
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
        if method != "GET" and any(p.get("in") == "json" for p in params):
            record["content_type"] = "application/json"
        if operation:
            record["operation"] = operation
        records.append(record)
        if limit is not None and len(records) >= limit:
            break
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
