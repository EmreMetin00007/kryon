"""Variant/fanout parameter policy and safe URL mutation helpers."""

import json
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


COMMON_PARAMS = {
    "sql_injection": ["id", "user", "search", "q", "category", "sort", "order", "filter", "name", "page"],
    "idor": ["id", "uid", "user_id", "account", "order", "invoice", "doc", "file", "pid", "ref"],
    "bola": ["id", "uid", "user_id", "account", "order", "object_id", "doc_id", "ref"],
    "xss_reflected": ["q", "search", "name", "message", "comment", "redirect", "lang", "ref"],
    "ssrf": ["url", "uri", "path", "dest", "callback", "webhook", "image", "proxy", "next"],
    "lfi": ["file", "page", "path", "include", "template", "doc", "lang", "view"],
    "path_traversal": ["file", "path", "name", "download", "doc", "page"],
    "open_redirect": ["redirect", "url", "next", "return", "returnto", "continue", "dest", "goto"],
    "command_injection": ["cmd", "host", "ip", "ping", "domain", "exec", "query", "name"],
    "ssti": ["name", "template", "msg", "search", "title", "content"],
}

DEFAULT_PAYLOADS = {
    "sql_injection": "'\"`)--", "xss_reflected": "cco<svg/onload=alert(1)>",
    "xss_stored": "cco<svg/onload=alert(1)>", "ssti": "${{7*7}}", "lfi": "../../../../etc/passwd",
    "path_traversal": "../../../../etc/passwd", "command_injection": ";id",
    "open_redirect": "//cco.evil.example", "ssrf": "http://169.254.169.254/latest/meta-data/",
}

DESTRUCTIVE_CLASSES = {"file_upload", "deserialization", "rce", "command_injection"}


def set_query_param(url, param, value):
    parsed = urlparse(url)
    from cco_surface_core.mutation import replace_pairs
    query = replace_pairs(parse_qsl(parsed.query, keep_blank_values=True), param, value)
    return urlunparse(parsed._replace(query=urlencode(query)))


def build_executable_variants(vclass, target, param, endpoint, payload=None, *,
                              observed_request=None, carrier="query", parameter_path=None):
    """Derive one variant from a real slot, never invent sibling names/carriers."""
    from cco_surface_core.mutation import mutate_request
    if not param or vclass in DESTRUCTIVE_CLASSES or vclass == "ssrf":
        return []
    baseline = observed_request or {"method": "GET", "url": endpoint or target, "headers": {}}
    if payload is None:
        payload = DEFAULT_PAYLOADS.get(vclass)
    if payload is None:
        return []
    try:
        changed = mutate_request(baseline, carrier, param, payload, parameter_path)
    except (ValueError, TypeError, KeyError, IndexError):
        return []
    return [{**changed, "strategy": "origin_param" if carrier == "query" else "observed_slot", "location": f"{carrier}:{param}",
             "param": param, "payload": payload}]


def curl_for_variant(variant, extra_headers=None):
    parts = ["curl -sk"]
    method = (variant.get("method") or "GET").upper()
    if method != "GET":
        parts.append(f"-X {method}")
    if variant.get("strategy") == "header_location":
        parts.append(f"-H '{variant['header']}: {variant['payload']}'")
    if variant.get("strategy") == "cookie" or variant.get("cookies"):
        cookies = variant.get("cookies") or {variant.get("param"): variant.get("payload")}
        cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())
        parts.append(f"-b '{cookie}'")
    headers = dict(extra_headers or {})
    headers.update(variant.get("headers") or {})
    for key, value in headers.items():
        parts.append(f"-H '{key}: {value}'")
    if variant.get("data"):
        parts.append(f"-d '{variant['data']}'")
    elif variant.get("json_body") is not None:
        parts.append(f"-d '{json.dumps(variant['json_body'])}'")
    parts.append(f"'{variant.get('url') or ''}'")
    return " ".join(parts)
