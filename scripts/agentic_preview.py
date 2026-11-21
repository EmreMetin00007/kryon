"""HTML preview pruning, structural diffing, attack-surface summary, and inline hints."""
from __future__ import annotations

from difflib import SequenceMatcher
import json
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlsplit

from agentic_http import is_static_asset_url

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SURFACE_CORE_PARENT = _REPO_ROOT / "mcp-servers" / "mcp-memory-server"
if str(_SURFACE_CORE_PARENT) not in sys.path:
    sys.path.insert(0, str(_SURFACE_CORE_PARENT))

from cco_surface_core.extract import (  # noqa: E402
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
from cco_surface_core.openapi import LocalSchema  # noqa: E402

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
            if isinstance(parsed, dict) and "paths" in parsed and ("openapi" in parsed or "swagger" in parsed):
                openapi_ops = _extract_openapi_operations(parsed, base)
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

    if "javascript" in ctype or urlsplit(url).path.lower().endswith((".js", ".mjs")):
        js_calls.extend(extract_js_calls(body, url, limit=80))
        for rec in extract_js(body, url, limit=60):
            if not is_static_asset_url(rec.get("url", "")):
                links.append(rec)
        spa_routes.extend(extract_spa_routes(body, url, limit=60))
        spec_urls.extend(find_spec_urls(body, url))

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

    return {
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
