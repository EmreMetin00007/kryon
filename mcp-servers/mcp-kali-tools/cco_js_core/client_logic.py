"""Deterministic Client Logic Map v1.

This module turns already-fetched JavaScript source into a machine-readable
map of request endpoints, request-building logic, signing indicators and
client-side validation hints. It is intentionally conservative: dynamic
expressions are marked as requiring runtime observation instead of guessed.

No network, no filesystem, no JavaScript execution. Input is source text.
"""

from __future__ import annotations

import re
from typing import Any

from .compose import MAX_SOURCE, compose_js_routes
from .parsers import parse_javascript
from .sourcemap import original_position_for, parse_source_map

SCHEMA = "cco-client-logic-map/1"

SENSITIVE_NAMES = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key", "x-api-token", "x-auth-token", "x-csrf-token",
    "x-signature", "signature", "token", "secret", "password",
}

REQUEST_RE = re.compile(
    r"\bfetch\s*\(|\baxios\.(get|post|put|patch|delete|head|options|request)\s*\("
    r"|\baxios\s*\(|\.open\s*\(",
    re.I,
)
FUNCTION_RE = re.compile(
    r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
    r"|([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{",
)
SIGN_NAME_RE = re.compile(r"sign|signature|hmac|sha(?:1|224|256|384|512)|md5", re.I)
VALIDATION_FIELD_RE = re.compile(
    r"(email|password|username|phone|credit_card|card|iban|token|otp|search|query)",
    re.I,
)
STORAGE_RE = re.compile(
    r"\b(?:localStorage|sessionStorage)\.setItem\(\s*[\"']([^\"']{1,80})[\"']",
)
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")
STRING_ARG_RE = re.compile(
    r"\s*(?:`([^`]*)`|\"([^\"]*)\"|'([^']*)'|([A-Za-z_$][\w$.]*(?:\s*\+\s*(?:\"[^\"]*\"|'[^']*'|`[^`]*`|[A-Za-z_$][\w$.]*))+)|([A-Za-z_$][\w$.]*))",
)
KEY_RE = re.compile(r"([A-Za-z_$][\w$-]*)\s*:")
QUOTED_KEY_RE = re.compile(r"[\"']([A-Za-z][A-Za-z0-9_-]{0,60})[\"']\s*:")


def _line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _norm_path(raw: str) -> str:
    path = (raw or "").strip()
    path = re.sub(r"\$\{[^}]+\}", "{id}", path)
    path = re.sub(r"\{[^}/]+\}", "{id}", path)
    path = path.split("#", 1)[0]
    if "?" in path:
        path = path.split("?", 1)[0]
    path = re.sub(r"/{2,}", "/", path)
    if len(path) > 240:
        path = path[:240]
    return path


def _query_params(raw: str) -> list[str]:
    if "?" not in raw:
        return []
    query = raw.split("?", 1)[1].split("#", 1)[0]
    out: list[str] = []
    for part in query.split("&"):
        name = part.split("=", 1)[0].strip()
        name = re.sub(r"\$\{[^}]+\}", "", name)
        if name and name not in out:
            out.append(name)
    return out


def _keys_from_object(block: str) -> list[str]:
    text = (block or "").strip()
    if text.startswith("{") and text.endswith("}"):
        text = text[1:-1]
    out: list[str] = []
    for segment in text.split(","):
        match = re.match(
            r"\s*(?:[\"']([^\"']+)[\"']|([A-Za-z_$][\w$]*))\s*(?::|,|$)",
            segment,
        )
        if not match:
            continue
        name = match.group(1) or match.group(2)
        if name and name not in out:
            out.append(name)
    return out


def _object_block(text: str, marker: str) -> str:
    idx = text.lower().find(marker.lower())
    if idx < 0:
        return ""
    brace = text.find("{", idx)
    if brace < 0:
        return ""
    depth = 0
    for pos in range(brace, min(len(text), brace + 2500)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:pos + 1]
    return text[brace:brace + 2500]


def _snippet(text: str, start: int, end: int) -> str:
    return text[start:min(len(text), end)]


def _functions(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in FUNCTION_RE.finditer(text):
        name = next((g for g in match.groups() if g), "")
        if not name or name in {"if", "for", "while", "switch", "catch"}:
            continue
        out.append({"name": name, "start": match.start(), "line": _line_number(text, match.start())})
    return out


def _function_context(functions: list[dict[str, Any]], pos: int) -> dict[str, Any] | None:
    current = None
    for fn in functions:
        if fn["start"] <= pos:
            current = fn
        else:
            break
    return current


def _next_function_start(functions: list[dict[str, Any]], current: dict[str, Any] | None, default: int) -> int:
    if not current:
        return default
    seen = False
    for fn in functions:
        if seen:
            return fn["start"]
        if fn is current:
            seen = True
    return default


def _expression_end(text: str, pos: int) -> int:
    depth = 0
    quote = ""
    i = pos
    while i < min(len(text), pos + 1800):
        ch = text[i]
        if quote:
            if ch == quote and text[i - 1] != "\\":
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif ch == "," and depth == 0:
            return i
        i += 1
    return i


def _parse_first_arg(text: str, pos: int) -> tuple[str, str, bool]:
    end = _expression_end(text, pos)
    expr = text[pos:end].strip()
    if not expr:
        return "", "", True
    if "+" in expr:
        built = ""
        dynamic = False
        for token in re.finditer(r"`([^`]*)`|\"([^\"]*)\"|'([^']*)'|([A-Za-z_$][\w$.]*)", expr):
            literal = token.group(1) or token.group(2) or token.group(3)
            if literal is not None:
                built += re.sub(r"\$\{[^}]+\}", "{id}", literal)
            elif token.group(4):
                dynamic = True
                built += "{id}"
        return built, expr, dynamic
    match = STRING_ARG_RE.match(expr)
    if not match:
        return "", expr, True
    template, double_q, single_q, _concat, ident = match.groups()
    raw = template or double_q or single_q or ""
    if ident:
        return "", ident, True
    return raw, expr, bool(re.search(r"\$\{[^}]+\}", raw))


def _headers(block: str) -> list[str]:
    headers_block = _object_block(block, "headers")
    names = _keys_from_object(headers_block)
    return [name for name in names if name.lower() not in {"method", "body"}]


def _body_fields(block: str) -> list[str]:
    body = _object_block(block, "body")
    if not body:
        body = _object_block(block, "data")
    fields = _keys_from_object(body)
    return [f for f in fields if f not in {"headers", "method", "url"}]


def _call_kind(prefix: str) -> tuple[str, str]:
    low = prefix.lower()
    if "axios." in low:
        method = low.rsplit("axios.", 1)[1].split("(", 1)[0]
        return "axios", method.upper()
    if "axios" in low:
        return "axios", ""
    if ".open" in low:
        return "xhr", ""
    return "fetch", ""


def _kind_from_callee(callee: str) -> tuple[str, str] | None:
    low = (callee or "").lower()
    if low == "fetch":
        return "fetch", ""
    if low == "axios":
        return "axios", ""
    if low.startswith("axios."):
        return "axios", low.rsplit(".", 1)[1].upper()
    if low.endswith(".open") or low == "open":
        return "xhr", ""
    return None


def _sanitize_expression(expr: str) -> str:
    out = re.sub(r"([?&][^=\s&]+)=([^\s&\"'`]+)", r"\1=<value>", expr or "")
    out = re.sub(
        r"(Authorization\s*[:=]\s*[\"'])([^\"']+)([\"'])",
        r"\1<redacted>\3", out, flags=re.I,
    )
    return out[:240]


def _extract_calls(
    text: str,
    functions: list[dict[str, Any]],
    calls: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    call_iter: list[tuple[int, str, str]] = []
    if calls is None:
        for match in REQUEST_RE.finditer(text):
            kind, method = _call_kind(match.group(0))
            call_iter.append((match.start(), kind, method))
    else:
        for call in calls:
            parsed_kind = _kind_from_callee(str(call.get("callee") or ""))
            if not parsed_kind:
                continue
            kind, method = parsed_kind
            call_iter.append((int(call.get("start") or 0), kind, method))
    for call_start, kind, method in sorted(call_iter):
        paren = text.find("(", call_start)
        if paren < 0:
            continue
        after_paren = paren + 1
        if kind == "xhr":
            method_raw, _expr, _dyn = _parse_first_arg(text, after_paren)
            method = (method_raw or method or "GET").upper()
            comma = text.find(",", after_paren)
            if comma < 0:
                continue
            raw, expr, dynamic = _parse_first_arg(text, comma + 1)
        else:
            raw, expr, dynamic = _parse_first_arg(text, after_paren)
        block = _snippet(text, call_start, min(len(text), after_paren + 2500))
        if not method:
            m = re.search(r"\bmethod\s*:\s*[\"']([A-Za-z]+)[\"']", block, re.I)
            method = m.group(1).upper() if m else "GET"
        if kind == "xhr":
            headers = []
            tail = text[call_start:min(len(text), call_start + 2500)]
            for hm in re.finditer(r"setRequestHeader\(\s*[\"']([^\"']+)[\"']", tail):
                if hm.group(1) not in headers:
                    headers.append(hm.group(1))
        else:
            headers = _headers(block)
        fn = _function_context(functions, call_start)
        fn_end = _next_function_start(functions, fn, min(len(text), call_start + 2500))
        local = text[(fn["start"] if fn else call_start):fn_end]
        signers = sorted({
            name for name in re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", local)
            if SIGN_NAME_RE.search(name)
        })
        path = _norm_path(raw)
        endpoints.append({
            "method": method,
            "path": path,
            "url_expression": _sanitize_expression(expr),
            "source_kind": kind,
            "query_params": _query_params(raw),
            "body_fields": _body_fields(block),
            "headers": headers,
            "function_context": fn["name"] if fn else None,
            "signer_functions": signers,
            "runtime_required": bool(dynamic or not path or signers),
            "evidence_line": _line_number(text, call_start),
            "evidence_column": call_start - (text.rfind("\n", 0, call_start) + 1),
            "confidence": "high" if path and not dynamic else ("medium" if path else "low"),
        })
    return endpoints


def _dedupe_endpoints(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        key = (item["method"], item["path"], item["source_kind"])
        if key not in merged:
            merged[key] = item
            continue
        cur = merged[key]
        for field in ("query_params", "body_fields", "headers", "signer_functions"):
            for value in item[field]:
                if value not in cur[field]:
                    cur[field].append(value)
        cur["runtime_required"] = cur["runtime_required"] or item["runtime_required"]
    return sorted(merged.values(), key=lambda x: (x["path"], x["method"], x["source_kind"]))


def _logic_functions(text: str, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, fn in enumerate(functions):
        end = functions[i + 1]["start"] if i + 1 < len(functions) else min(len(text), fn["start"] + 4000)
        body = text[fn["start"]:end]
        roles = []
        if re.search(r"\bfetch\s*\(|axios\.|\.open\s*\(", body):
            roles.append("request_builder")
        if SIGN_NAME_RE.search(fn["name"]) or re.search(r"Hmac|createSign|sign\s*\(", body):
            roles.append("signer")
        if ".test(" in body or "RegExp" in body:
            roles.append("validator")
        if roles:
            out.append({"name": fn["name"], "roles": roles, "line": fn["line"]})
    return out


def _validation_rules(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pattern = re.compile(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*/((?:\\.|[^/\\\n]){3,160})/",
    )
    for match in pattern.finditer(text):
        var = match.group(1)
        field_match = VALIDATION_FIELD_RE.search(var)
        if not field_match:
            continue
        field = field_match.group(1).lower()
        if not any(item["field"] == field for item in out):
            out.append({
                "field": field,
                "source_name": var,
                "pattern_length": len(match.group(2)),
                "line": _line_number(text, match.start()),
            })
    return out


def build_client_logic_map(
    source: str,
    source_map: Any = None,
    parser: str = "auto",
) -> dict[str, Any]:
    """Build Client Logic Map v1 from JavaScript source text."""
    text = (source or "")[:MAX_SOURCE]
    parsed, parser_meta = parse_javascript(text, parser=parser)
    functions = parsed.get("functions") or _functions(text)
    endpoints = _dedupe_endpoints(_extract_calls(text, functions, parsed.get("calls")))
    logic_functions = _logic_functions(text, functions)
    signing_functions = sorted({
        fn["name"] for fn in logic_functions if "signer" in fn["roles"]
    } | {
        ep_name for ep in endpoints for ep_name in ep["signer_functions"]
    })
    inventory = compose_js_routes(text) if text.strip() else {
        "literals": [], "templates": [], "headers": [],
    }
    source_map_meta, source_contents = parse_source_map(source_map, text)
    if source_map_meta.get("valid") and source_contents:
        original_endpoints: list[dict[str, Any]] = []
        sources = source_map_meta.get("sources") or []
        for idx, content in enumerate(source_contents):
            if not content:
                continue
            original = build_client_logic_map(content, parser="static")
            for endpoint in original.get("endpoints") or []:
                endpoint = dict(endpoint)
                endpoint["original_source"] = sources[idx] if idx < len(sources) else None
                original_endpoints.append(endpoint)
        source_map_meta["original_endpoints"] = original_endpoints
    segments = source_map_meta.get("segments") or []
    sources = source_map_meta.get("sources") or []
    for endpoint in endpoints:
        pos = original_position_for(
            segments,
            int(endpoint.get("evidence_line") or 0),
            int(endpoint.get("evidence_column") or 0),
        )
        if pos and "source_index" in pos and pos["source_index"] < len(sources):
            endpoint["original_source"] = sources[pos["source_index"]]
            endpoint["original_line"] = pos.get("source_line")
    return {
        "schema": SCHEMA,
        "parser": parser_meta,
        "endpoints": endpoints,
        "logic_functions": logic_functions,
        "signing": {
            "functions": signing_functions,
            "requires_runtime": bool(signing_functions),
        },
        "validation_rules": _validation_rules(text),
        "storage_keys": sorted(set(STORAGE_RE.findall(text))),
        "source_map": source_map_meta,
        "inventory": {
            "literals": inventory.get("literals", []),
            "templates": inventory.get("templates", []),
            "headers": inventory.get("headers", []),
        },
        "unknowns": [
            (
                "AST backend parsed the source; dynamic expressions are still marked runtime_required."
                if parser_meta.get("ast_available")
                else "Static parser fallback used; dynamic expressions are marked runtime_required."
            ),
            "Header and storage values are never emitted; only names and fields are mapped.",
        ],
        "notes": [
            "Use runtime_required endpoints with browser instrumentation before probing.",
            "Templates remain BOLA/IDOR candidates until validator evidence exists.",
        ],
    }


