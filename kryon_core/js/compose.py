"""Deterministic JS route composer.

LinkFinder / quoted-string regex miss concatenations and index-array
builders. This module expands those into concrete paths and {id} templates
without an LLM.

No network, no filesystem. Input is source text.
"""

from __future__ import annotations

import re
from typing import Any

from kryon_core.surface.normalize import is_third_party_sdk_static_route

MAX_SOURCE = 400_000
MAX_RESULTS = 80

STRING_ARRAY_RE = re.compile(
    r"\[((?:\s*[\"'][^\"']{1,80}[\"']\s*,){3,}\s*[\"'][^\"']{1,80}[\"']\s*)\]"
)
INDEX_RE = re.compile(r"(?:\b\w+\.)*_k\[(\d+)\]|(?:\b\w+\.)*_i\[(\d+)\]")
QUOTED_RE = re.compile(r"[\"'](/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{2,180})[\"']")
TEMPLATE_RE = re.compile(r"`(/[^`]{2,180})`")
IDENT_RE = re.compile(r"^[A-Za-z_$][\w$]*$")
HEADER_RE = re.compile(
    r"[\"']((?:X-[A-Za-z0-9-]+)|Authorization|User-Agent|Content-Type|"
    r"X-Requested-With|X-CSRF-Token|X-Api-Key|X-Org-Id|X-Organization-Id|"
    r"X-Request-Id|X-Cluster-Region)[\"']",
    re.I,
)
HEADER_PAIR_RE = re.compile(
    r"[\"']((?:X-[A-Za-z0-9-]+)|Authorization|User-Agent|Content-Type|"
    r"X-Requested-With|X-CSRF-Token|X-Api-Key|X-Org-Id|X-Organization-Id|"
    r"X-Request-Id|X-Cluster-Region)[\"']\]?\s*[:=]\s*[\"']([^\"']{1,180})[\"']",
    re.I,
)
HEADER_SET_RE = re.compile(
    r"\.set\(\s*[\"']([A-Za-z][A-Za-z0-9-]{1,39})[\"']\s*,\s*[\"']([^\"']{1,180})[\"']"
)
HEADER_ARG_RE = re.compile(
    r"\bsetRequestHeader\(\s*[\"']([A-Za-z][A-Za-z0-9-]{1,39})[\"']\s*,\s*[\"']([^\"']{1,180})[\"']"
)
SENSITIVE_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key", "x-csrf-token", "x-auth-token", "x-api-token",
})
UA_VALUE_RE = re.compile(
    r"[\"']([A-Za-z][A-Za-z0-9._ -]{1,60}/v?\d+(?:\.\d+){0,2})[\"']"
)
PATHISH_RE = re.compile(r"^/(api|v\d|graphql|admin|internal|users|auth|org|cluster)")
STATIC_SKIP = re.compile(r"\.(png|jpe?g|gif|css|ico|svg|woff2?|map|js)(\?|$)", re.I)
CONCAT_CHUNK_RE = re.compile(
    r"[\"']([^\"']{0,120})[\"']|`([^`]{0,120})`|(\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
)

ID_IDENTS = {
    "id", "userid", "user_id", "userId", "oid", "objectid", "uuid",
    "sid", "accountid", "orderid", "orgid", "tenantid", "n", "i",
}


def _unescape(value: str) -> str:
    return value.replace("\\/", "/").replace("\\n", "").strip()


def _looks_path(value: str) -> bool:
    value = value.strip()
    if len(value) < 2 or len(value) > 180:
        return False
    if STATIC_SKIP.search(value):
        return False
    if is_third_party_sdk_static_route(value):
        return False
    if value.startswith("http://") or value.startswith("https://"):
        return True
    probe = re.sub(r"\{[^}]+\}", "x", value)
    if not probe.startswith("/"):
        return False
    if probe in {"/api", "/api/", "/v1", "/v2"}:
        return False
    return bool(
        PATHISH_RE.search(probe)
        or (probe.count("/") >= 2 and "api" in probe.lower())
    )


def _mask(value: str) -> str:
    """Mask sensitive header values: keep shape, expose nothing usable."""
    value = value.strip()
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-2:]


def _extract_header_values(source: str) -> dict[str, str]:
    """name→value pairs (deterministic). Sensitive names are masked; UA-like
    product tokens (e.g. `NexusWorks-Cluster-Monitor/2.0`) pass through."""
    pairs: dict[str, str] = {}
    for match in HEADER_PAIR_RE.finditer(source):
        name, value = match.group(1), match.group(2).strip()
        if not name or not value:
            continue
        if name.lower() in SENSITIVE_HEADERS:
            value = _mask(value)
        pairs.setdefault(name, value)
    for match in HEADER_SET_RE.finditer(source):
        name, value = match.group(1), match.group(2).strip()
        if not name or not value:
            continue
        if name.lower() in SENSITIVE_HEADERS:
            value = _mask(value)
        pairs.setdefault(name, value)
    for match in HEADER_ARG_RE.finditer(source):
        name, value = match.group(1), match.group(2).strip()
        if not name or not value:
            continue
        if name.lower() in SENSITIVE_HEADERS:
            value = _mask(value)
        pairs.setdefault(name, value)
    if not pairs:
        for match in UA_VALUE_RE.finditer(source):
            pairs.setdefault("User-Agent", match.group(1))
            break
    return pairs


def _extract_arrays(source: str) -> list[list[str]]:
    arrays: list[list[str]] = []
    for match in STRING_ARRAY_RE.finditer(source):
        items = re.findall(r"[\"']([^\"']+)[\"']", match.group(1))
        if len(items) >= 4:
            arrays.append(items)
    arrays.sort(key=len, reverse=True)
    return arrays[:4]


def _substitute_indexes(source: str, arrays: list[list[str]]) -> str:
    if not arrays:
        return source
    table = arrays[0]

    def repl(match: re.Match) -> str:
        raw = match.group(1) or match.group(2)
        idx = int(raw)
        if 0 <= idx < len(table):
            return json_quote(table[idx])
        return match.group(0)

    return INDEX_RE.sub(repl, source)


def json_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


ASSIGN_RE = re.compile(
    r"""(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*((?:[\"'][^\"']*[\"']\s*\+\s*)+[\"'][^\"']*[\"'])"""
)


def _fold_string_assigns(source: str, rounds: int = 4) -> str:
    """Replace `var _auth="/api/"+"v2"+"/auth"` (and later `_reg=_auth+"/x"`)."""
    text = source
    for _ in range(rounds):
        bindings: dict[str, str] = {}
        for match in ASSIGN_RE.finditer(text):
            name, expr = match.group(1), match.group(2)
            chunks = re.findall(r"[\"']([^\"']*)[\"']", expr)
            if chunks:
                bindings[name] = "".join(chunks)
        # Also capture already-folded quoted assigns.
        for match in re.finditer(
            r"""(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*[\"'](/[^\"']{2,160})[\"']""",
            text,
        ):
            bindings.setdefault(match.group(1), match.group(2))
        if not bindings:
            break
        for name, value in sorted(bindings.items(), key=lambda kv: -len(kv[0])):
            quoted = json_quote(value)
            pattern = re.compile(rf"\b{re.escape(name)}\b")
            out_chunks: list[str] = []
            last = 0
            for match in pattern.finditer(text):
                rest = text[match.end():]
                if rest.lstrip().startswith("="):
                    continue
                out_chunks.append(text[last:match.start()])
                out_chunks.append(quoted)
                last = match.end()
            if last:
                text = "".join(out_chunks) + text[last:]
    return text


def _join_concat_line(line: str) -> list[str]:
    """Turn `'a'+foo+'/b'` into ['/a/{id}/b'] when the line has + joins."""
    if "+" not in line or not re.search(r"[\"'`]", line):
        return []
    parts: list[tuple[str, str]] = []
    last_was_ident = False
    for match in CONCAT_CHUNK_RE.finditer(line):
        lit, tmpl, ident = match.group(1), match.group(2), match.group(3)
        if lit is not None:
            parts.append(("lit", _unescape(lit)))
            last_was_ident = False
        elif tmpl is not None:
            parts.append(("tmpl", tmpl))
            last_was_ident = False
        elif ident and IDENT_RE.match(ident.split(".")[-1]):
            name = ident.split(".")[-1]
            if last_was_ident:
                continue
            parts.append(("id", name))
            last_was_ident = True
        else:
            last_was_ident = False
    # Drop leading idents until a slash-bearing literal starts the path.
    while parts and not (
        parts[0][0] == "lit" and (parts[0][1].startswith("/") or "/" in parts[0][1])
        or parts[0][0] == "tmpl"
    ):
        parts.pop(0)
    if len(parts) < 2:
        return []
    if not any(kind == "lit" and "/" in text for kind, text in parts):
        return []
    built = ""
    for kind, text in parts:
        if kind == "lit":
            built += text
        elif kind == "tmpl":
            built += re.sub(r"\$\{[^}]+\}", "{id}", text)
        else:
            slot = "{id}" if (
                text.lower().replace("_", "") in {x.lower().replace("_", "") for x in ID_IDENTS}
                or "id" in text.lower()
            ) else "{param}"
            built += slot
    scheme_match = re.match(r"^(https?://)", built, re.I)
    if scheme_match:
        prefix = scheme_match.group(1)
        built = prefix + re.sub(r"/{2,}", "/", built[len(prefix):])
    else:
        built = re.sub(r"/{2,}", "/", built)
        if not built.startswith("/"):
            if "/" in built:
                built = "/" + built.split("/", 1)[-1] if not built.startswith("{") else built
            else:
                return []
    if is_third_party_sdk_static_route(built):
        return []
    return [built] if _looks_path(built) or "{id}" in built else []


def _template_paths(source: str) -> list[str]:
    found: list[str] = []
    for match in TEMPLATE_RE.finditer(source):
        raw = match.group(1)
        templated = re.sub(r"\$\{[^}]+\}", "{id}", raw)
        if is_third_party_sdk_static_route(templated):
            continue
        if _looks_path(templated) or "{id}" in templated:
            found.append(templated)
    return found


def _inline_api_join(source: str) -> list[str]:
    """`return "/api/"+a+"/"+b` style helpers used as _r("v2","users")."""
    found: list[str] = []
    for match in re.finditer(
        r"""(?:\b_r|\bjoin|\bpath)\s*\(\s*[\"']([^\"']+)[\"']\s*,\s*[\"']([^\"']+)[\"']\s*\)""",
        source,
    ):
        found.append(f"/api/{match.group(1)}/{match.group(2)}")
    return found


def compose_js_routes(source: str) -> dict[str, Any]:
    """Return literals, composed paths, {id} templates, and header names."""
    text = (source or "")[:MAX_SOURCE]
    arrays = _extract_arrays(text)
    expanded = _substitute_indexes(text, arrays)
    expanded = _fold_string_assigns(expanded)

    literals: list[str] = []
    for match in QUOTED_RE.finditer(expanded):
        value = _unescape(match.group(1))
        if _looks_path(value):
            literals.append(value)

    composed: list[str] = []
    templates: list[str] = list(_template_paths(expanded))
    for line in expanded.splitlines():
        if "+" not in line:
            continue
        composed.extend(_join_concat_line(line))
    composed.extend(_inline_api_join(expanded))

    headers: list[str] = []
    for match in HEADER_RE.finditer(text):
        headers.append(match.group(1))
    header_values = _extract_header_values(text)
    for name in header_values:
        if name not in headers:
            headers.append(name)

    def uniq(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            item = item.strip()
            if not item or item in seen:
                continue
            seen.add(item)
            out.append(item)
            if len(out) >= MAX_RESULTS:
                break
        return out

    templates = [p for p in uniq(templates + composed) if "{id}" in p and _looks_path(p)]
    concrete = [p for p in uniq(literals + composed) if "{" not in p and _looks_path(p)]

    id_templates = []
    for path in concrete:
        # `/api/v2/users` is a collection — IDOR sibling candidates.
        if re.search(r"/(users|orders|accounts|orgs|tenants|items|docs)$", path):
            id_templates.append(f"{path}/{{id}}")
            id_templates.append(f"{path}/{{id}}/profile")

    return {
        "literals": uniq(literals),
        "composed": uniq([p for p in composed if "{" not in p]),
        "templates": uniq(templates + id_templates),
        "headers": uniq(headers),
        "header_values": header_values,
        "index_arrays": arrays[:2],
        "notes": [
            "Call these paths before guessing; templates are IDOR/BOLA candidates.",
            "Header names are observed keys, not guessed values.",
            "header_values carries observed name→value pairs; sensitive names (Authorization/Cookie/secret keys) are masked — use vault refs, never literals.",
        ],
    }
