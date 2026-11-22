"""HTML preview pruning, structural diffing, attack-surface summary, and inline hints."""
from __future__ import annotations

from difflib import SequenceMatcher
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from agentic_http import is_static_asset_url

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_CLIENT_LOGIC_LOADED = False
_BUILD_CLIENT_LOGIC_MAP: Callable[..., dict[str, Any]] | None = None
_POSTMAN_VAR_PREFIX_RE = re.compile(r"^\{\{[^}]+\}\}(/.*)$")
_SIGNING_HEADER_RE = re.compile(r"(?:sign|signature|hmac|digest)", re.I)


def _load_build_client_logic_map() -> Callable[..., dict[str, Any]] | None:
    """Lazily import kryon_core.js.client_logic.build_client_logic_map if available."""
    global _CLIENT_LOGIC_LOADED, _BUILD_CLIENT_LOGIC_MAP
    if _CLIENT_LOGIC_LOADED:
        return _BUILD_CLIENT_LOGIC_MAP
    _CLIENT_LOGIC_LOADED = True
    try:
        if str(_REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(_REPO_ROOT))
        from kryon_core.js.client_logic import build_client_logic_map

        _BUILD_CLIENT_LOGIC_MAP = build_client_logic_map
    except Exception:
        _BUILD_CLIENT_LOGIC_MAP = None
    return _BUILD_CLIENT_LOGIC_MAP

from kryon_core.surface.extract import (  # noqa: E402
    extract_css,
    extract_html,
    extract_http_headers,
    extract_inline_scripts,
    extract_js,
    extract_js_calls,
    extract_json_hypermedia,
    extract_robots,
    extract_sitemap,
    extract_spa_routes,
    find_spec_urls,
)
from kryon_core.surface.openapi import LocalSchema  # noqa: E402

_ID_VALUE_RE = re.compile(
    r"\b(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z]+-[a-z0-9_-]{3,24}|\d{1,10})\b",
    re.I,
)
_ID_KEY_HINTS = ("id", "uuid", "code", "tag", "serial", "slug", "key", "ref", "number")

_EVENT_OR_JS_RE = re.compile(r"(?:\bon[a-z]+\s*=|javascript\s*:)", re.I)
_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.I | re.S)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_STYLE_BLOCK_RE = re.compile(r"<style\b[^>]*>.*?</style>", re.I | re.S)
_SVG_OPEN_RE = re.compile(r"<svg(?=[\s/>])", re.I)
_SVG_CLOSE_RE = re.compile(r"</svg\s*>", re.I)
_HTML_TAG_RE = re.compile(r"""<([a-zA-Z][a-zA-Z0-9:-]*)(\s+(?:"[^"]*"|'[^']*'|[^>"'])*)?>""")
_TAG_ATTR_RE = re.compile(
    r"""\s+([a-zA-Z_:][a-zA-Z0-9_.:-]*)(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?"""
)


def _notable_headers(headers: dict[str, str]) -> dict[str, str]:
    """Select security- and routing-relevant HTTP response headers for preview output."""
    keep: dict[str, str] = {}
    for k, v in (headers or {}).items():
        lk = k.lower()
        if lk in {
            "location", "content-type", "retry-after", "x-challenge",
            "x-lab-injected", "x-lab-stream-cut", "www-authenticate", "cache-control",
        }:
            keep[k] = v
    return keep


def _find_tag_end(text: str, start: int) -> int:
    """Return index of closing '>' for an HTML tag starting at `start`, respecting quotes."""
    quote = ""
    i = start + 1
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
        else:
            if ch in ('"', "'"):
                quote = ch
            elif ch == ">":
                return i
        i += 1
    return -1


def _strip_passive_svgs(html: str, *, protected_marker: str = "") -> str:
    """Strip passive decorative <svg> blocks while preserving any with event handlers, javascript:, or scripts."""
    out: list[str] = []
    pos = 0
    n = len(html)
    while pos < n:
        match = _SVG_OPEN_RE.search(html, pos)
        if not match:
            out.append(html[pos:])
            break
        start = match.start()
        out.append(html[pos:start])
        tag_end = _find_tag_end(html, start)
        if tag_end == -1:
            out.append(html[start:])
            break
        open_tag = html[start : tag_end + 1]
        if _EVENT_OR_JS_RE.search(open_tag):
            out.append(open_tag)
            pos = tag_end + 1
            continue
        if open_tag.rstrip()[:-1].rstrip().endswith("/"):
            pos = tag_end + 1
            continue
        depth = 1
        scan = tag_end + 1
        end_pos = -1
        while depth > 0 and scan < n:
            next_open = _SVG_OPEN_RE.search(html, scan)
            next_close = _SVG_CLOSE_RE.search(html, scan)
            if not next_close:
                break
            if next_open and next_open.start() < next_close.start():
                sub_end = _find_tag_end(html, next_open.start())
                if sub_end == -1:
                    break
                sub_tag = html[next_open.start() : sub_end + 1]
                if not sub_tag.rstrip()[:-1].rstrip().endswith("/"):
                    depth += 1
                scan = sub_end + 1
            else:
                depth -= 1
                scan = next_close.end()
                if depth == 0:
                    end_pos = scan
                    break
        if end_pos == -1:
            out.append(open_tag)
            pos = tag_end + 1
            continue
        block = html[start:end_pos]
        has_script = "<script" in block.lower() or (bool(protected_marker) and protected_marker in block)
        if _EVENT_OR_JS_RE.search(block) or has_script:
            out.append(block)
        pos = end_pos
    return "".join(out)


def _strip_inline_style_attrs(html: str) -> str:
    """Remove inline style='...' / style=\"...\" attributes from tags without event handlers or javascript:."""
    def _clean_tag(match: re.Match[str]) -> str:
        full_tag = match.group(0)
        if _EVENT_OR_JS_RE.search(full_tag):
            return full_tag
        attrs = match.group(2)
        if not attrs or "style" not in attrs.lower():
            return full_tag
        rebuilt: list[str] = []
        last = 0
        for attr_m in _TAG_ATTR_RE.finditer(attrs):
            if attr_m.group(1).lower() == "style":
                rebuilt.append(attrs[last : attr_m.start()])
                last = attr_m.end()
        if last == 0:
            return full_tag
        rebuilt.append(attrs[last:])
        return f"<{match.group(1)}{''.join(rebuilt)}>"

    return _HTML_TAG_RE.sub(_clean_tag, html)


def prune_html_for_preview(html: str) -> str:
    """Prune CSS/comment/decorative-SVG noise from HTML for display preview only.

    Preserves <script> blocks, forms, inputs, links, tables, resource IDs, and
    any tag containing inline event handlers (`on*=`) or `javascript:` URIs verbatim.
    """
    if not html:
        return ""
    sentinel_prefix = "__KRYON_SCRIPT_BLOCK_"
    while sentinel_prefix in html:
        sentinel_prefix += "_"

    script_blocks: list[str] = []

    def _protect_script(match: re.Match[str]) -> str:
        idx = len(script_blocks)
        script_blocks.append(match.group(0))
        return f"{sentinel_prefix}{idx}__"

    text = _SCRIPT_BLOCK_RE.sub(_protect_script, html)
    text = _HTML_COMMENT_RE.sub("", text)
    text = _STYLE_BLOCK_RE.sub(
        lambda m: m.group(0) if _EVENT_OR_JS_RE.search(m.group(0)) else "",
        text,
    )
    text = _strip_passive_svgs(text, protected_marker=sentinel_prefix)
    text = _strip_inline_style_attrs(text)

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    compact_lines: list[str] = []
    for line in text.split("\n"):
        cleaned = re.sub(r"[ \t]{2,}", " ", line).strip()
        if cleaned:
            compact_lines.append(cleaned)
    text = "\n".join(compact_lines)

    for idx, script_block in enumerate(script_blocks):
        text = text.replace(f"{sentinel_prefix}{idx}__", script_block)
    return text


def _format_receipt_preview(receipt: dict[str, Any], *, preview_chars: int = 2400) -> dict[str, Any]:
    """Format a bounded receipt preview dictionary with HTML pruning and truncation notes."""
    body = receipt.get("body") or ""
    ctype = (receipt.get("content_type") or "").lower()
    is_html = "html" in ctype or body.lstrip().startswith(("<!", "<html", "<HTML"))
    preview_source = prune_html_for_preview(body) if (is_html and body) else body
    shown = preview_source[:preview_chars]
    remaining = max(0, len(preview_source) - len(shown))
    out: dict[str, Any] = {
        "receipt_id": receipt["receipt_id"],
        "cached": bool(receipt.get("cached", False)),
        "actor": receipt["actor"],
        "method": receipt["method"],
        "url": receipt["url"],
        "status": receipt["status"],
        "elapsed_ms": receipt["elapsed_ms"],
        "content_type": receipt["content_type"],
        "response_length": receipt["response_length"],
        "redirect_location": receipt.get("redirect_location", ""),
        "notable_headers": _notable_headers(receipt.get("response_headers") or {}),
        "body_preview": shown if shown else "<empty>",
    }
    if receipt.get("saved_session"):
        out["saved_session"] = receipt["saved_session"]
    if receipt.get("error"):
        out["error"] = receipt["error"]
    if remaining > 0:
        if is_html and len(preview_source) != len(body):
            out["truncation_note"] = (
                f"Pruned HTML preview truncated; {remaining} more pruned chars "
                f"({len(body)} raw chars in store). Use read_receipt('{receipt['receipt_id']}', offset=0) or regex."
            )
        else:
            out["truncation_note"] = (
                f"Body truncated; {remaining} more chars in store. "
                f"Use read_receipt('{receipt['receipt_id']}', offset={len(shown)}) or regex."
            )
    return out


def _flatten_json_keys(
    obj: Any,
    prefix: str = "",
    out: dict[str, str] | None = None,
    limit: int = 200,
) -> dict[str, str]:
    """Flatten a nested JSON structure into dotted key -> repr(value) pairs up to `limit`."""
    if out is None:
        out = {}
    if len(out) >= limit:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                _flatten_json_keys(v, key, out, limit)
            else:
                out[key] = repr(v)[:80]
                if len(out) >= limit:
                    break
    elif isinstance(obj, list):
        out[f"{prefix}[]"] = f"len={len(obj)}"
        for idx, item in enumerate(obj[:5]):
            _flatten_json_keys(item, f"{prefix}[{idx}]", out, limit)
    else:
        out[prefix or "$"] = repr(obj)[:80]
    return out


def _compute_structural_diff(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compute status, length, redirect, and JSON/text structural diff between two receipts."""
    diff: dict[str, Any] = {
        "status_diff": [baseline.get("status"), current.get("status")],
        "length_diff": int(current.get("response_length", 0)) - int(baseline.get("response_length", 0)),
        "sha256_same": baseline.get("response_sha256") == current.get("response_sha256"),
        "redirect_diff": [baseline.get("redirect_location", ""), current.get("redirect_location", "")],
    }
    b_body = baseline.get("body") or ""
    c_body = current.get("body") or ""
    try:
        b_json = json.loads(b_body)
        c_json = json.loads(c_body)
    except ValueError:
        b_json = None
        c_json = None

    if b_json is not None and c_json is not None:
        b_flat = _flatten_json_keys(b_json)
        c_flat = _flatten_json_keys(c_json)
        b_keys = set(b_flat)
        c_keys = set(c_flat)
        added = sorted(c_keys - b_keys)[:20]
        removed = sorted(b_keys - c_keys)[:20]
        changed = [
            {"key": k, "baseline": b_flat[k], "replay": c_flat[k]}
            for k in sorted(b_keys & c_keys)
            if b_flat[k] != c_flat[k]
        ][:20]
        diff["json_diff"] = {
            "json_equal": b_json == c_json,
            "added_keys": added,
            "removed_keys": removed,
            "changed_values": changed,
        }
    else:
        sample_b = b_body[:8000]
        sample_c = c_body[:8000]
        ratio = SequenceMatcher(None, sample_b, sample_c).ratio()
        diff["text_similarity"] = round(ratio, 3)
        if sample_b != sample_c:
            mismatch = next((i for i, (x, y) in enumerate(zip(sample_b, sample_c)) if x != y), min(len(sample_b), len(sample_c)))
            diff["first_diff_offset"] = mismatch
            diff["replay_diff_snippet"] = sample_c[max(0, mismatch - 40) : mismatch + 200]
    return diff


def _extract_openapi_operations(spec: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    """Extract normalized endpoints, methods, params, and body fields from OpenAPI 2/3 JSON."""
    resolver = LocalSchema(spec)
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    operations: list[dict[str, Any]] = []
    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(path_item, dict):
            continue
        raw_path_params = path_item.get("parameters")
        path_params = raw_path_params if isinstance(raw_path_params, list) else []
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            params: list[dict[str, str]] = []
            raw_op_params = op.get("parameters")
            op_params = raw_op_params if isinstance(raw_op_params, list) else []
            for p in [*path_params, *op_params]:
                resolved_p = resolver.resolve(p) if isinstance(p, dict) else {}
                pname = resolved_p.get("name")
                if pname:
                    params.append({"name": str(pname), "in": str(resolved_p.get("in") or "query")})
            body_fields: list[str] = []
            req_body = resolver.resolve(op.get("requestBody")) if isinstance(op.get("requestBody"), dict) else {}
            raw_content = req_body.get("content")
            content = raw_content if isinstance(raw_content, dict) else {}
            for media in content.values():
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    schema = resolver.schema(media["schema"])
                    props = schema.get("properties")
                    if isinstance(props, dict):
                        body_fields.extend(str(k) for k in props.keys())
            operations.append({
                "method": method.upper(),
                "path": raw_path,
                "url": base_url.rstrip("/") + (raw_path if raw_path.startswith("/") else "/" + raw_path),
                "params": params[:25],
                "body_fields": list(dict.fromkeys(body_fields))[:25],
                "summary": str(op.get("summary") or "")[:120],
            })
            if len(operations) >= 120:
                return operations
    return operations


def _extract_candidate_ids(obj: Any, *, limit: int = 40) -> list[dict[str, str]]:
    """Collect sample resource IDs / tags from JSON payloads to aid cross-actor testing."""
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 6 or len(found) >= limit:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                lk = str(k).lower()
                if isinstance(v, (str, int)) and not isinstance(v, bool):
                    sval = str(v).strip()
                    if sval and len(sval) <= 64 and (
                        lk == "id" or any(h in lk for h in _ID_KEY_HINTS)
                    ):
                        if _ID_VALUE_RE.fullmatch(sval) or len(sval) <= 36:
                            pair = (str(k), sval)
                            if pair not in seen:
                                seen.add(pair)
                                found.append({"field": str(k), "value": sval})
                elif isinstance(v, (dict, list)):
                    walk(v, depth + 1)
        elif isinstance(node, list):
            for item in node[:20]:
                walk(item, depth + 1)

    walk(obj)
    return found


def _extract_graphql_operations(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract compact GraphQL query/mutation operations from an introspection __schema."""
    schema: dict[str, Any] | None = None
    raw_data = parsed.get("data")
    if isinstance(raw_data, dict) and isinstance(raw_data.get("__schema"), dict):
        schema = raw_data["__schema"]
    elif isinstance(parsed.get("__schema"), dict):
        schema = parsed["__schema"]
    if schema is None:
        return []

    raw_types = schema.get("types")
    if not isinstance(raw_types, list):
        return []

    if "queryType" in schema:
        qt = schema.get("queryType")
        query_name = str(qt.get("name") or "").strip() if isinstance(qt, dict) else ""
    else:
        query_name = "Query"

    if "mutationType" in schema:
        mt = schema.get("mutationType")
        mutation_name = str(mt.get("name") or "").strip() if isinstance(mt, dict) else ""
    else:
        mutation_name = "Mutation"

    ops: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for type_obj in raw_types:
        if not isinstance(type_obj, dict):
            continue
        tname = str(type_obj.get("name") or "").strip()
        if not tname:
            continue
        if query_name and tname == query_name:
            kind = "query"
        elif mutation_name and tname == mutation_name:
            kind = "mutation"
        else:
            continue
        fields = type_obj.get("fields")
        if not isinstance(fields, list):
            continue
        for field in fields:
            if not isinstance(field, dict):
                continue
            fname = str(field.get("name") or "").strip()
            if not fname or fname.startswith("__"):
                continue
            dedup_key = (kind, fname)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            args: list[str] = []
            raw_args = field.get("args")
            if isinstance(raw_args, list):
                for arg in raw_args:
                    if not isinstance(arg, dict):
                        continue
                    aname = str(arg.get("name") or "").strip()
                    if aname and aname not in args:
                        args.append(aname[:80])
                        if len(args) >= 20:
                            break
            ops.append({"kind": kind, "name": fname[:120], "args": args})
            if len(ops) >= 60:
                return ops
    return ops


def _postman_request_url(req_url: Any) -> str:
    """Normalize a Postman v2.x request URL field (string or structured dict)."""
    if isinstance(req_url, str):
        return req_url.strip()
    if not isinstance(req_url, dict):
        return ""
    raw = str(req_url.get("raw") or "").strip()
    if raw:
        return raw
    protocol = str(req_url.get("protocol") or "https").strip()
    host_val = req_url.get("host")
    if isinstance(host_val, list):
        host = ".".join(str(part).strip() for part in host_val if str(part).strip())
    else:
        host = str(host_val or "").strip()
    port = str(req_url.get("port") or "").strip()
    path_val = req_url.get("path")
    if isinstance(path_val, list):
        path = "/" + "/".join(str(seg).strip("/") for seg in path_val if str(seg).strip("/"))
    else:
        path_str = str(path_val or "").strip()
        path = path_str if (not path_str or path_str.startswith("/")) else "/" + path_str
    query_parts: list[str] = []
    raw_query = req_url.get("query")
    if isinstance(raw_query, list):
        for q in raw_query:
            if isinstance(q, dict) and q.get("key") and not q.get("disabled"):
                query_parts.append(str(q["key"]).strip())
    q_suffix = ("?" + "&".join(f"{k}=" for k in query_parts[:15])) if query_parts else ""
    if host:
        if host.startswith("{{") and host.endswith("}}"):
            return f"{host}{path}{q_suffix}"
        authority = f"{host}:{port}" if port else host
        return f"{protocol}://{authority}{path}{q_suffix}"
    return f"{path}{q_suffix}" if path else ""


def _postman_body_keys(req_body: Any) -> list[str]:
    """Extract only key names (never values) from a Postman v2.x request body."""
    if not isinstance(req_body, dict):
        return []
    keys: list[str] = []

    def _add(name: Any) -> None:
        clean = str(name or "").strip()[:80]
        if clean and clean not in keys and len(keys) < 25:
            keys.append(clean)

    mode = str(req_body.get("mode") or "").strip().lower()
    raw_text = req_body.get("raw")
    if (mode == "raw" or (not mode and isinstance(raw_text, str))) and isinstance(raw_text, str):
        stripped = raw_text.strip()
        if stripped.startswith("{"):
            try:
                parsed_body = json.loads(stripped)
            except ValueError:
                parsed_body = None
            if isinstance(parsed_body, dict):
                for k in parsed_body.keys():
                    _add(k)

    for field_name in ("urlencoded", "formdata"):
        entries = req_body.get(field_name)
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and entry.get("key") and not entry.get("disabled"):
                    _add(entry["key"])

    if mode == "graphql" and isinstance(req_body.get("graphql"), dict):
        gql_vars = req_body["graphql"].get("variables")
        if isinstance(gql_vars, str) and gql_vars.strip().startswith("{"):
            try:
                parsed_vars = json.loads(gql_vars)
            except ValueError:
                parsed_vars = None
            if isinstance(parsed_vars, dict):
                for k in parsed_vars.keys():
                    _add(k)
        elif isinstance(gql_vars, dict):
            for k in gql_vars.keys():
                _add(k)
    return keys


def _extract_postman_operations(
    parsed: dict[str, Any],
    base_url: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Recursively extract up to 60 operations and same-origin links from Postman v2.x JSON."""
    if not isinstance(parsed.get("info"), dict) or not isinstance(parsed.get("item"), list):
        return [], []

    base_netloc = urlsplit(base_url).netloc
    ops: list[dict[str, Any]] = []
    same_origin_links: list[dict[str, Any]] = []

    def _walk(items: list[Any], depth: int = 0) -> None:
        if depth > 16 or len(ops) >= 60:
            return
        for entry in items:
            if len(ops) >= 60:
                return
            if not isinstance(entry, dict):
                continue
            req = entry.get("request")
            if isinstance(req, str):
                method = "GET"
                raw_url = req.strip()
                body_keys: list[str] = []
            elif isinstance(req, dict):
                method = str(req.get("method") or "GET").strip().upper() or "GET"
                raw_url = _postman_request_url(req.get("url"))
                body_keys = _postman_body_keys(req.get("body"))
            else:
                raw_url = ""
                method = "GET"
                body_keys = []

            if raw_url:
                ops.append({
                    "method": method,
                    "url": raw_url[:240],
                    "body_keys": body_keys,
                })
                var_match = _POSTMAN_VAR_PREFIX_RE.match(raw_url)
                resolved = ""
                if var_match:
                    resolved = urljoin(base_url.rstrip("/") + "/", var_match.group(1))
                elif raw_url.startswith("/"):
                    resolved = urljoin(base_url.rstrip("/") + "/", raw_url)
                else:
                    parsed_u = urlsplit(raw_url)
                    if parsed_u.scheme in {"http", "https"} and parsed_u.netloc and parsed_u.netloc == base_netloc:
                        resolved = raw_url
                if resolved and not is_static_asset_url(resolved):
                    same_origin_links.append({
                        "method": method,
                        "url": resolved,
                        "params": body_keys,
                    })

            children = entry.get("item")
            if isinstance(children, list):
                _walk(children, depth + 1)

    _walk(parsed["item"])
    return ops, same_origin_links


def _extract_js_client_logic(
    body: str,
    url: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Run passive kryon_core.js Client Logic Map on JS source without exposing secret values."""
    if not body or not body.strip():
        return [], [], {}
    build_fn = _load_build_client_logic_map()
    if build_fn is None:
        return [], [], {}
    try:
        cl_map = build_fn(body, parser="static")
    except Exception:
        return [], [], {}
    if not isinstance(cl_map, dict):
        return [], [], {}

    raw_endpoints: list[dict[str, Any]] = []
    for ep in cl_map.get("endpoints") or []:
        if isinstance(ep, dict):
            raw_endpoints.append(ep)
    sm = cl_map.get("source_map")
    if isinstance(sm, dict):
        for orig_ep in sm.get("original_endpoints") or []:
            if isinstance(orig_ep, dict):
                raw_endpoints.append(orig_ep)

    merged_calls: list[dict[str, Any]] = []
    merged_links: list[dict[str, Any]] = []
    compact_endpoints: list[dict[str, Any]] = []
    signing_indicators: list[str] = []
    coverage_gaps: list[str] = []

    def _add_unique(target: list[str], value: str, cap: int) -> None:
        clean = value.strip()
        if clean and clean not in target and len(target) < cap:
            target.append(clean)

    signing_meta = cl_map.get("signing")
    if isinstance(signing_meta, dict):
        for fn_name in signing_meta.get("functions") or []:
            _add_unique(signing_indicators, str(fn_name)[:80], 20)

    seen_ep_keys: set[tuple[str, str]] = set()
    for ep in raw_endpoints:
        method = str(ep.get("method") or "GET").strip().upper() or "GET"
        path = str(ep.get("path") or "").strip()[:240]
        q_params = [str(p)[:64] for p in (ep.get("query_params") or []) if p][:15]
        b_fields = [str(f)[:64] for f in (ep.get("body_fields") or []) if f][:20]
        h_names = [str(h)[:64] for h in (ep.get("headers") or []) if h][:15]
        signers = [str(s)[:80] for s in (ep.get("signer_functions") or []) if s][:10]
        runtime_required = bool(ep.get("runtime_required"))

        for s in signers:
            _add_unique(signing_indicators, s, 20)
        for h in h_names:
            if _SIGNING_HEADER_RE.search(h):
                _add_unique(signing_indicators, h, 20)

        if path and (method, path) not in seen_ep_keys and len(compact_endpoints) < 40:
            seen_ep_keys.add((method, path))
            compact_endpoints.append({
                "method": method,
                "path": path,
                "query_params": q_params,
                "body_fields": b_fields,
                "headers": h_names,
                "signer_functions": signers,
                "runtime_required": runtime_required,
            })

        if path.startswith(("/", "http://", "https://")):
            resolved = urljoin(url, path)
            if not is_static_asset_url(resolved):
                all_params = list(dict.fromkeys([*q_params, *b_fields]))[:15]
                merged_calls.append({
                    "method": method,
                    "url": resolved,
                    "sources": ["client-logic"],
                    "params": [{"name": p, "in": "body" if p in b_fields else "query", "sample": ""} for p in all_params],
                })
                merged_links.append({
                    "method": method,
                    "url": resolved,
                    "params": all_params,
                })

        if runtime_required:
            if not path:
                expr = str(ep.get("url_expression") or "<dynamic>").strip()[:80]
                _add_unique(coverage_gaps, f"dynamic_endpoint_runtime_required:{method} {expr}", 20)
            elif signers:
                _add_unique(coverage_gaps, f"signed_endpoint_runtime_required:{method} {path}", 20)
            elif "{id}" in path:
                _add_unique(coverage_gaps, f"dynamic_endpoint_runtime_required:{method} {path}", 20)

    validation_fields: list[str] = []
    for rule in cl_map.get("validation_rules") or []:
        if isinstance(rule, dict) and rule.get("field"):
            _add_unique(validation_fields, str(rule["field"])[:64], 30)

    storage_keys: list[str] = []
    for sk in cl_map.get("storage_keys") or []:
        _add_unique(storage_keys, str(sk)[:80], 30)

    source_maps: list[str] = []
    if isinstance(sm, dict):
        if sm.get("url"):
            _add_unique(source_maps, str(sm["url"])[:200], 20)
        for src in sm.get("sources") or []:
            _add_unique(source_maps, str(src)[:200], 20)
        if sm.get("present") and not source_maps:
            _add_unique(source_maps, "inline", 20)

    for gap in cl_map.get("coverage_gaps") or []:
        if isinstance(gap, dict):
            code = str(gap.get("code") or gap.get("reason_code") or "").strip()
            detail = str(gap.get("detail") or gap.get("message") or "").strip()
            label = f"{code}: {detail}" if (code and detail) else (code or detail)
            _add_unique(coverage_gaps, label[:160], 20)

    if not any((
        compact_endpoints,
        signing_indicators,
        validation_fields,
        storage_keys,
        source_maps,
        coverage_gaps,
    )):
        return merged_calls, merged_links, {}

    client_logic: dict[str, Any] = {
        "endpoints": compact_endpoints,
        "signing_indicators": signing_indicators,
        "validation_fields": validation_fields,
        "storage_keys": storage_keys,
        "source_maps": source_maps,
        "coverage_gaps": coverage_gaps,
    }
    return merged_calls, merged_links, client_logic


def _extract_surface_summary(receipt: dict[str, Any], base_url: str) -> dict[str, Any]:
    """Extract normalized attack-surface artifacts from a stored receipt at 0 HTTP cost."""
    body = receipt.get("body") or ""
    url = receipt["url"]
    ctype = (receipt.get("content_type") or "").lower()
    base = base_url

    links: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    js_calls: list[dict[str, Any]] = []
    spa_routes: list[dict[str, Any]] = []
    spec_urls: list[str] = []
    openapi_ops: list[dict[str, Any]] = []
    graphql_ops: list[dict[str, Any]] = []
    postman_ops: list[dict[str, Any]] = []
    client_logic: dict[str, Any] = {}
    candidate_ids: list[dict[str, str]] = []

    raw_headers = receipt.get("response_headers") or receipt.get("headers")
    redir_loc = str(receipt.get("redirect_location") or "").strip()
    hdr_input: Any = {}
    if isinstance(raw_headers, dict):
        hdr_input = dict(raw_headers)
        if redir_loc and not any(str(k).lower() == "location" for k in hdr_input):
            hdr_input["Location"] = redir_loc
    elif raw_headers:
        hdr_input = raw_headers
    elif redir_loc:
        hdr_input = {"Location": redir_loc}
    if hdr_input:
        for rec in extract_http_headers(hdr_input, url):
            if not is_static_asset_url(rec.get("url", "")):
                links.append(rec)

    stripped = body.lstrip()
    if "json" in ctype or stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            if isinstance(parsed, dict):
                if "paths" in parsed and ("openapi" in parsed or "swagger" in parsed):
                    openapi_ops = _extract_openapi_operations(parsed, base)
                graphql_ops = _extract_graphql_operations(parsed)
                postman_ops, postman_links = _extract_postman_operations(parsed, base)
                if postman_links:
                    links.extend(postman_links)
            hypermedia, _ = extract_json_hypermedia(parsed, url, origin_url=base)
            for item in hypermedia:
                if not is_static_asset_url(item.get("url", "")):
                    links.append(item)
            candidate_ids = _extract_candidate_ids(parsed)
            spec_urls = find_spec_urls(body, url)

    if "html" in ctype or "<html" in body[:512].lower() or "<form" in body.lower() or "href=" in body.lower():
        for rec in extract_html(body, url):
            if rec.get("sources") == ["form"]:
                forms.append(rec)
            elif not is_static_asset_url(rec.get("url", "")):
                links.append(rec)
        for script in extract_inline_scripts(body):
            js_calls.extend(extract_js_calls(script, url, limit=40))
            spa_routes.extend(extract_spa_routes(script, url, limit=40))
            spec_urls.extend(find_spec_urls(script, url))
        # Also capture concrete UUID/resource IDs appearing inside HTML links/attributes.
        seen_html_ids = {(c["field"], c["value"]) for c in candidate_ids}
        for link_item in links:
            for seg in urlsplit(link_item.get("url", "")).path.split("/"):
                if len(seg) >= 8 and _ID_VALUE_RE.fullmatch(seg) and any(ch.isdigit() for ch in seg):
                    if ("path_id", seg) not in seen_html_ids and len(candidate_ids) < 40:
                        seen_html_ids.add(("path_id", seg))
                        candidate_ids.append({"field": "path_id", "value": seg})

    if "javascript" in ctype or "ecmascript" in ctype or urlsplit(url).path.lower().endswith((".js", ".mjs")):
        js_calls.extend(extract_js_calls(body, url, limit=80))
        for rec in extract_js(body, url, limit=60):
            if not is_static_asset_url(rec.get("url", "")):
                links.append(rec)
        spa_routes.extend(extract_spa_routes(body, url, limit=60))
        spec_urls.extend(find_spec_urls(body, url))
        cl_calls, cl_links, client_logic = _extract_js_client_logic(body, url)
        seen_js_call_keys = {
            (str(c.get("method") or "GET").upper(), str(c.get("url") or ""))
            for c in js_calls
        }
        for call in cl_calls:
            ckey = (str(call.get("method") or "GET").upper(), str(call.get("url") or ""))
            if ckey not in seen_js_call_keys:
                seen_js_call_keys.add(ckey)
                js_calls.append(call)
        links.extend(cl_links)

    if "css" in ctype or urlsplit(url).path.lower().endswith(".css"):
        for rec in extract_css(body, url, limit=120):
            if not is_static_asset_url(rec.get("url", "")):
                links.append(rec)

    if urlsplit(url).path.lower().endswith("/robots.txt"):
        links.extend(extract_robots(body, url))
    if "xml" in ctype or "<urlset" in body[:512].lower() or "<sitemapindex" in body[:512].lower():
        links.extend(extract_sitemap(body, url))

    # Deduplicate and compact links/forms so high-signal routes, forms, and IDs appear first without verbose boilerplate.
    base_netloc = urlsplit(base).netloc

    def _compact_surface_item(item: dict[str, Any]) -> dict[str, Any]:
        raw_u = str(item.get("url") or "")
        parsed_u = urlsplit(raw_u)
        if not parsed_u.netloc or parsed_u.netloc == base_netloc:
            short_u = (parsed_u.path or "/") + (f"?{parsed_u.query}" if parsed_u.query else "")
        else:
            short_u = raw_u
        p_list: list[str] = []
        for p in (item.get("params") or []):
            pname = str(p.get("name") if isinstance(p, dict) else p or "").strip()
            if pname and pname not in p_list:
                p_list.append(pname)
        compact: dict[str, Any] = {"method": str(item.get("method") or "GET").upper(), "url": short_u}
        if p_list:
            compact["params"] = p_list[:15]
        return compact

    dedup_links: list[dict[str, Any]] = []
    seen_links: set[tuple[str, str]] = set()
    for item in links:
        comp = _compact_surface_item(item)
        key = (comp["method"], comp["url"])
        if key not in seen_links:
            seen_links.add(key)
            dedup_links.append(comp)

    # Sort deeper/API/parameterized links ahead of 1-segment top nav links
    dedup_links.sort(
        key=lambda x: (
            0 if ("/api/" in x["url"] or "?" in x["url"] or x.get("params") or x["url"].count("/") >= 2) else 1,
            x["url"],
        )
    )
    compact_forms = [_compact_surface_item(f) for f in forms[:30]]

    summary: dict[str, Any] = {
        "receipt_id": receipt["receipt_id"],
        "url": url,
        "content_type": ctype,
        "forms": compact_forms,
        "openapi_operations": openapi_ops[:80],
        "js_calls": js_calls[:60],
        "candidate_ids": candidate_ids[:40],
        "spec_urls": list(dict.fromkeys(spec_urls))[:20],
        "spa_routes": spa_routes[:40],
        "links": dedup_links[:60],
    }
    if client_logic:
        summary["client_logic"] = client_logic
    if graphql_ops:
        summary["graphql_ops"] = graphql_ops[:60]
    if postman_ops:
        summary["postman_ops"] = postman_ops[:60]
    return summary


def _build_surface_hints(
    receipt: dict[str, Any],
    base_url: str,
    *,
    max_chars: int = 900,
) -> dict[str, Any]:
    """Build a compact, strictly bounded surface_hints dict for inline http_request previews."""
    summary = _extract_surface_summary(receipt, base_url)
    base_netloc = urlsplit(base_url).netloc
    ctype = (receipt.get("content_type") or "").lower()
    url_path = urlsplit(str(receipt.get("url") or "")).path.lower()
    is_js = "javascript" in ctype or "ecmascript" in ctype or url_path.endswith((".js", ".mjs"))

    def _short_same_origin(raw_u: str) -> tuple[str, str, bool]:
        parsed_u = urlsplit(str(raw_u or "").strip())
        same_origin = not parsed_u.netloc or parsed_u.netloc == base_netloc
        path = parsed_u.path or "/"
        short = path + (f"?{parsed_u.query}" if parsed_u.query else "")
        return path[:120], short[:120], same_origin

    forms: list[dict[str, Any]] = []
    for f in (summary.get("forms") or [])[:4]:
        forms.append({
            "method": str(f.get("method") or "GET").upper(),
            "url": str(f.get("url") or "")[:120],
            "params": [str(p)[:32] for p in (f.get("params") or [])[:8]],
        })

    openapi_ops: list[str] = []
    seen_ops: set[str] = set()
    for op in summary.get("openapi_operations") or []:
        op_str = f"{str(op.get('method') or '').upper()} {str(op.get('path') or '')}".strip()[:120]
        if op_str and op_str not in seen_ops:
            seen_ops.add(op_str)
            openapi_ops.append(op_str)
            if len(openapi_ops) >= 10:
                break

    api_endpoints: list[str] = []
    api_path_set: set[str] = set()

    def _add_api(raw_u: str) -> None:
        if len(api_endpoints) >= 8:
            return
        path, _, same_origin = _short_same_origin(raw_u)
        if not same_origin or not path or path == "/" or is_static_asset_url(path):
            return
        if path not in api_path_set:
            api_path_set.add(path)
            api_endpoints.append(path)

    for op in summary.get("openapi_operations") or []:
        _add_api(str(op.get("path") or ""))
    for call in summary.get("js_calls") or []:
        _add_api(str(call.get("url") or ""))
    for spec_u in summary.get("spec_urls") or []:
        _add_api(str(spec_u))
    for item in summary.get("links") or []:
        u = str(item.get("url") or "")
        path, _, _ = _short_same_origin(u)
        if is_js or "/api/" in path or path.startswith("/api") or "/graphql" in path:
            _add_api(u)

    ids: list[str] = []
    seen_ids: set[str] = set()
    for cand in summary.get("candidate_ids") or []:
        val = str(cand.get("value") or "").strip()[:48]
        if val and val not in seen_ids:
            seen_ids.add(val)
            ids.append(val)
            if len(ids) >= 6:
                break

    links: list[str] = []
    seen_links: set[str] = set()
    for item in [*(summary.get("links") or []), *(summary.get("spa_routes") or [])]:
        if len(links) >= 6:
            break
        raw_u = str(item.get("url") or "")
        path, short, same_origin = _short_same_origin(raw_u)
        if not same_origin or is_static_asset_url(raw_u):
            continue
        if path == "/" and "?" not in short:
            continue
        if path in api_path_set or short in api_path_set:
            continue
        if short not in seen_links:
            seen_links.add(short)
            links.append(short)

    hints: dict[str, Any] = {}
    if forms:
        hints["forms"] = forms
    if api_endpoints:
        hints["api_endpoints"] = api_endpoints
    if openapi_ops:
        hints["openapi_ops"] = openapi_ops
    if ids:
        hints["ids"] = ids
    if links:
        hints["links"] = links

    trim_order = ("links", "ids", "api_endpoints", "openapi_ops", "forms")
    while hints and len(json.dumps(hints, ensure_ascii=False)) > max_chars:
        trimmed = False
        for key in trim_order:
            seq = hints.get(key)
            if isinstance(seq, list) and seq:
                seq.pop()
                if not seq:
                    del hints[key]
                trimmed = True
                break
        if not trimmed:
            break
    return hints
