"""Class-aware canary plan for attack-surface injection fuzz."""

from __future__ import annotations

import copy
import json
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .normalize import suggested_classes

SAFE_LIVE_CLASSES = (
    "sql_injection",
    "xss_reflected",
    "ssti",
    "lfi",
    "path_traversal",
    "open_redirect",
    "xxe",
    "file_upload",
)

SKIP_LIVE_CLASSES = {
    "ssrf", "idor", "bola", "bfla", "command_injection", "rce",
    "file_upload", "deserialization", "xxe",
}

CANARY_PAYLOADS = {
    "sql_injection": ["'", "'\"`)--"],
    "xss_reflected": ["cco<svg/onload=alert(1)>"],
    "ssti": ["{{7*7}}", "${{7*7}}"],
    "lfi": ["../../../../etc/passwd"],
    "path_traversal": ["../../../../etc/passwd"],
    "open_redirect": ["//cco.evil.example"],
    "xxe": ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
            '"file:///etc/passwd">]><r>&xxe;</r>'],
    "file_upload": ["cco-upload-probe"],
}

_FILE_PARAM_HINTS = ("file", "upload", "image", "avatar", "photo", "attachment")

VALIDATOR_HOOK = {
    "deserialization": "mcp__validator__validate_deserialization",
    "sql_injection": "mcp__validator__validate_sqli",
    "xss_reflected": "mcp__validator__validate_xss_reflection",
    "ssti": "mcp__validator__validate_ssti",
    "lfi": "mcp__validator__validate_path_traversal",
    "path_traversal": "mcp__validator__validate_path_traversal",
    "open_redirect": "mcp__validator__validate_open_redirect",
}


def remaining_classes(record: dict) -> list[str]:
    suggested = list(record.get("suggested_classes") or suggested_classes(record))
    queued = [str(item) for item in (record.get("queued_classes") or []) if item]
    tested = {str(item) for item in (record.get("tested_classes") or [])}
    out, seen = [], set()
    for item in suggested + queued:
        if item and item not in tested and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def set_query_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = [(name, value if name == param else sample)
             for name, sample in parse_qsl(parsed.query, keep_blank_values=True)]
    if not any(name == param for name, _ in query):
        query.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def drop_query_param(url: str, param: str) -> str:
    parsed = urlparse(url)
    kept = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != param]
    return urlunparse(parsed._replace(query=urlencode(kept, doseq=True)))


def _sibling_map(record: dict, location: str, default_empty: str = "1") -> dict:
    """Return recorded parameters for `location` with their sample values preserved."""
    out: dict[str, str] = {}
    loc = (location or "query").lower()
    for item in record.get("params") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        item_loc = str(item.get("in") or "query").lower()
        if not name or item_loc != loc:
            continue
        sample = item.get("sample", default_empty)
        if loc == "json" and "sample" in item:
            sample = copy.deepcopy(sample)
        else:
            sample = copy.deepcopy(sample)
        if loc == "json" and item.get("body_root"):
            return sample
        path = item.get("path") if loc == "json" else None
        if isinstance(path, list) and path and all(isinstance(part, str) and part for part in path):
            cursor = out
            for part in path[:-1]:
                child = cursor.setdefault(part, {})
                if not isinstance(child, dict):
                    break
                cursor = child
            else:
                cursor[path[-1]] = sample
        else:
            def scalar(value):
                return json.dumps(value, separators=(",", ":"), ensure_ascii=False) if (
                    isinstance(value, (dict, list, bool)) or value is None) else str(value)
            out[name] = (sample if loc == "json" else [scalar(value) for value in sample]
                         if item.get("repeated") and isinstance(sample, list) else scalar(sample))
    return out


def _json_param_path(record: dict, param_name: str) -> list[str]:
    for item in record.get("params") or []:
        if isinstance(item, dict) and item.get("name") == param_name and item.get("in") == "json":
            path = item.get("path")
            if isinstance(path, list) and path and all(
                    isinstance(part, str) and part or isinstance(part, int) and not isinstance(part, bool) and part >= 0
                    for part in path):
                return path
    return [param_name]


def _set_json_path(value: dict, path: list[str], replacement) -> None:
    from .mutation import json_slot
    # Inventory assembly happens in _sibling_map. Mutation never repairs a
    # malformed baseline or creates a field that was absent from the packet.
    json_slot(value, path)
    parent = json_slot(value, path[:-1])
    parent[path[-1]] = replacement


def _apply_canary(record: dict, param_name: str, location: str, payload: str) -> dict:
    url = record.get("url") or ""
    location = (location or "query").lower()
    method = str(record.get("method") or ("POST" if location in {"json", "body"} else "GET")).upper()
    json_fields = _sibling_map(record, "json")
    if isinstance((record.get("_captured_wire") or {}).get("body"), (dict, list)):
        json_fields = copy.deepcopy(record["_captured_wire"]["body"])
    form_fields = _sibling_map(record, "body")
    from .serialization import form_pairs
    form_data = urlencode(form_pairs(record.get("params") or []))
    baseline_body = ({"baseline_json": json_fields} if any(p.get("in") == "json" for p in record.get("params") or []) else
                     {"baseline_data": form_data} if form_fields else {})
    if location == "json":
        base_json = json_fields
        param_path = _json_param_path(record, param_name)
        probe_json = copy.deepcopy(base_json)
        if any(p.get("name") == param_name and p.get("body_root") for p in record.get("params") or []):
            probe_json = payload
        else:
            _set_json_path(probe_json, param_path, payload)
        return {
            "method": method,
            "url": url,
            "headers": {"Content-Type": "application/json"},
            "data": None,
            "json_body": probe_json,
            "cookies": None,
            "baseline_method": method,
            "baseline_json": base_json,
            "parameter_path": param_path,
        }
    if location == "body":
        return {
            "method": method,
            "url": url,
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": urlencode(form_pairs(record.get("params") or [], {param_name: payload})),
            "json_body": None,
            "cookies": None,
            "baseline_method": method,
            "baseline_data": form_data,
        }
    if location == "cookie":
        base_cookies = _sibling_map(record, "cookie")
        probe_cookies = {**base_cookies, param_name: payload}
        return {
            "method": method,
            "url": url,
            "headers": {},
            "data": baseline_body.get("baseline_data"),
            "json_body": baseline_body.get("baseline_json"),
            "cookies": probe_cookies,
            "baseline_cookies": base_cookies or None,
            **baseline_body,
        }
    if location == "xml":
        return {
            "method": "POST",
            "url": url,
            "headers": {"Content-Type": "application/xml"},
            "data": payload,
            "json_body": None,
            "cookies": None,
        }
    if location == "multipart":
        base_fields = {k: v for k, v in _sibling_map(record, "body").items()
                       if k != param_name}
        base_data = urlencode(base_fields) if base_fields else None
        return {
            "method": "POST",
            "url": drop_query_param(url, param_name) or url,
            "headers": {},
            "data": base_data,
            "json_body": None,
            "cookies": None,
            "files": {param_name: ("cco_probe.txt", payload)},
            "baseline_method": "POST",
            "baseline_data": base_data,
            "baseline_files": {param_name: ("cco_probe.txt", "1")},
        }
    if location == "header":
        base_headers = _sibling_map(record, "header")
        probe_headers = {**base_headers, param_name: payload}
        return {
            "method": method,
            "url": url,
            "headers": probe_headers,
            "data": baseline_body.get("baseline_data"),
            "json_body": baseline_body.get("baseline_json"),
            "cookies": None,
            "baseline_headers": base_headers or None,
            **baseline_body,
        }
    if location == "path":
        placeholder = "{" + param_name + "}"
        if placeholder not in url:
            return {
                "method": method,
                "url": url,
                "headers": {},
                "data": None,
                "json_body": None,
                "cookies": None,
                "skip_reason": "path placeholder yok",
            }
        from urllib.parse import quote as _q
        path_samples = _sibling_map(record, "path", default_empty="1")
        base_url = url
        probe_url = url.replace(placeholder, _q(payload, safe=""))
        template_url = url
        for pname, psample in path_samples.items():
            ph = "{" + pname + "}"
            base_url = base_url.replace(ph, _q(psample, safe=""))
            if pname != param_name:
                probe_url = probe_url.replace(ph, _q(psample, safe=""))
                template_url = template_url.replace(ph, _q(psample, safe=""))
        return {
            "method": method,
            "url": probe_url,
            "baseline_url": base_url,
            "template_url": template_url,
            "headers": {},
            "data": baseline_body.get("baseline_data"),
            "json_body": baseline_body.get("baseline_json"),
            "cookies": None,
            **baseline_body,
        }
    return {
        "method": method,
        "url": set_query_param(url, param_name, payload),
        "headers": {},
        "data": baseline_body.get("baseline_data"),
        "json_body": baseline_body.get("baseline_json"),
        "cookies": None,
        **baseline_body,
    }


def apply_canary(record: dict, param_name: str, location: str, payload: str) -> dict:
    """Preserve the complete baseline while replacing one recorded field."""
    prepared = copy.deepcopy(record)
    parsed = urlparse(str(prepared.get("url") or ""))
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    present = {name for name, _ in pairs}
    for name, sample in _sibling_map(prepared, "query").items():
        if name not in present:
            pairs.append((name, sample))
    url = urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))
    if location != "path":
        from urllib.parse import quote
        for name, sample in _sibling_map(prepared, "path").items():
            url = url.replace("{" + name + "}", quote(sample, safe=""))
    prepared["url"] = url
    applied = _apply_canary(prepared, param_name, location, payload)
    if location == "xml":
        return applied
    samples = _sibling_map(prepared, location)
    if isinstance(samples, dict) and param_name in samples and isinstance(samples[param_name], str):
        applied["baseline_value"] = samples[param_name]
    headers = _sibling_map(prepared, "header")
    cookies = _sibling_map(prepared, "cookie")
    applied["headers"] = {**headers, **(applied.get("headers") or {})}
    applied["baseline_headers"] = {**headers, **(applied.get("baseline_headers") or {})}
    if cookies:
        applied["cookies"] = {**cookies, **(applied.get("cookies") or {})}
        applied["baseline_cookies"] = {**cookies, **(applied.get("baseline_cookies") or {})}
    applied.setdefault("baseline_url", url)
    applied.setdefault("baseline_method", prepared.get("method") or "GET")
    from .serialization import media_type, multipart_files
    kind = media_type(prepared.get("content_type"))
    if kind == "multipart/form-data" and location != "xml":
        base_files = multipart_files(prepared.get("params") or [])
        mutated = copy.deepcopy(prepared.get("params") or [])
        if location == "body":
            for param in mutated:
                if param.get("name") == param_name and param.get("in") == "body":
                    if param.get("file_part") and isinstance(param.get("sample"), dict):
                        param["sample"]["content"] = payload
                        param["sample"]["content_encoding"] = "utf-8"
                    else:
                        param["sample"] = payload
                        param.pop("repeated", None)
        applied.update(data=None, json_body=None, baseline_data=None, baseline_json=None,
                       files=multipart_files(mutated), baseline_files=base_files)
        for key in ("headers", "baseline_headers"):
            applied[key] = {name: value for name, value in applied[key].items() if name.lower() != "content-type"}
    elif kind and location != "xml":
        for key in ("headers", "baseline_headers"):
            if any(p.get("in") in {"json", "body"} for p in prepared.get("params") or []):
                applied[key] = {name: value for name, value in applied[key].items() if name.lower() != "content-type"}
                applied[key]["Content-Type"] = prepared["content_type"]
        if kind == "application/graphql":
            query = next((p.get("sample") for p in prepared.get("params") or [] if p.get("name") == "query"), None)
            applied.update(data=query, baseline_data=query, json_body=None, baseline_json=None)
    wire = prepared.get("_captured_wire")
    if wire and location != "xml":
        # The attested packet is the baseline. Parameter inventory may have
        # fewer fields or a different order and must not reconstruct it.
        body = copy.deepcopy(wire["body"])
        applied["baseline_url"] = wire["url"]
        applied["baseline_method"] = wire["method"]
        applied["baseline_headers"] = copy.deepcopy(wire["headers"])
        applied["headers"] = {**wire["headers"], **applied["headers"]}
        applied["baseline_files"] = None
        if "json" in kind or isinstance(body, (dict, list)):
            applied.update(baseline_json=body, baseline_data=None)
            mutated = copy.deepcopy(body)
            if location == "json":
                if any(p.get("name") == param_name and p.get("body_root") for p in prepared.get("params") or []):
                    mutated = payload
                else:
                    _set_json_path(mutated, _json_param_path(prepared, param_name), payload)
            applied.update(json_body=mutated, data=None, files=None)
        else:
            applied.update(baseline_data=body, baseline_json=None)
            if kind == "multipart/form-data":
                # The probe uses parsed parts; requests generates its boundary.
                applied["headers"] = {name: value for name, value in applied["headers"].items()
                                      if name.lower() not in {"content-type", "content-length"}}
            elif location == "body":
                pairs = parse_qsl(body, keep_blank_values=True)
                applied["data"] = urlencode([(name, payload if name == param_name else value)
                                             for name, value in pairs])
            else:
                applied.update(data=body, json_body=None)
        if location == "query":
            applied["url"] = set_query_param(wire["url"], param_name, payload)
        for name in list(applied["headers"]):
            if name.lower() == "content-length":
                del applied["headers"][name]
    if any(p.get("body_root") and p.get("sample") is None for p in prepared.get("params") or []):
        applied.update(baseline_json=None, baseline_data="null",
                       data=json.dumps(applied.get("json_body")), json_body=None)
    if record.get("operation_id"):
        applied["operation_id"] = record["operation_id"]
    if record.get("observation_id"):
        applied["observation_id"] = record["observation_id"]
    if record.get("capture_ref"):
        applied["capture_ref"] = record["capture_ref"]
    if record.get("operation"):
        applied["operation"] = copy.deepcopy(record["operation"])
    return applied


def build_canary_plan(record: dict, already_tested=None) -> list[dict]:
    """Build safe live canaries from recorded params only (no invented names)."""
    tested = {str(item) for item in (already_tested if already_tested is not None
                                     else (record.get("tested_classes") or []))}
    classes = [
        item for item in (record.get("suggested_classes") or suggested_classes(record) or [])
        if item in SAFE_LIVE_CLASSES and item not in tested
    ]
    def _param_allowed(item):
        if (record.get("operation") or {}).get("protocol") == "graphql":
            if item.get("name") in {"query", "operationName", "variables"}:
                return False
        # Kimlik/oturum değerini taşıyan parametreler sondalanmaz (değer
        # değişimi oturumu bozar). Tek istisna: başlık konumundaki api-key —
        # sonda tek istekte başlık değerini değiştirir, oturum çerezi
        # taşınmaz; başlık enjeksiyonu meşru test yüzeyidir.
        name = str(item.get("name"))
        loc = str(item.get("in") or "query").lower()
        if re.search(r"(^|[._-])(csrf|xsrf|password|passwd|secret|session|authorization|token)([._-]|$)",
                     name, re.I):
            return False
        if loc != "header" and re.search(r"(^|[._-])api[_-]?key([._-]|$)", name, re.I):
            return False
        return True

    params = [
        item for item in (record.get("params") or [])
        if isinstance(item, dict) and item.get("name")
        and str(item.get("in") or "query").lower() in {"query", "body", "json", "cookie", "header", "path"}
        and _param_allowed(item)
    ]
    probes = []
    if not classes:
        return probes
    operation = record.get("operation") or {}
    if operation.get("protocol") == "graphql" and operation.get("kind") != "query":
        return [{"fingerprint": record.get("fingerprint"), "url": record.get("url"),
                 "method": record.get("method") or "GET", "operation_id": record.get("operation_id"),
                 "vuln_class": classes[0], "param": "", "location": "", "payload": "",
                 "skip": "missing_context", "reason": "graphql_operation_not_read_only"}]
    if not params:
        return [{
            "fingerprint": record.get("fingerprint"),
            "url": record.get("url"),
            "method": record.get("method") or "GET",
            "param": "",
            "location": "",
            "vuln_class": classes[0],
            "payload": "",
            "skip": "no_params",
            "classes_to_mark": classes,
        }]
    for vclass in classes:
        for payload in CANARY_PAYLOADS.get(vclass, ["cco-test"]):
            for param in params:
                location = str(param.get("in") or "query").lower()
                if vclass == "xxe":
                    location = "xml"  # XXE gövdeyle gider, parametre konumu fark etmez
                elif vclass == "file_upload":
                    if not any(h in param["name"].lower() for h in _FILE_PARAM_HINTS):
                        continue
                    location = "multipart"
                applied = apply_canary(record, param["name"], location, payload)
                if applied.get("skip_reason"):
                    continue
                probes.append({
                    "fingerprint": record.get("fingerprint"),
                    "vuln_class": vclass,
                    "param": param["name"],
                    "location": location,
                    "payload": payload,
                    "validator_hook": VALIDATOR_HOOK.get(vclass, ""),
                    "skip": "",
                    "classes_to_mark": [vclass],
                    "baseline_url": record.get("url"),
                    "baseline_method": record.get("method") or "GET",
                    **applied,
                })
    return probes
