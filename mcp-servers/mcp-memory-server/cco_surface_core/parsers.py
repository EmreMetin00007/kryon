"""Parse ffuf / nuclei / gau / sqlmap artifacts into surface records."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlparse

from .normalize import params_from_url


def _as_data(payload):
    if payload is None:
        return None
    if isinstance(payload, (dict, list)):
        return payload
    text = str(payload).strip()
    if not text:
        return None
    path = Path(text)
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
    text = text.strip()
    if not text:
        return None
    if text[0] in "[{":
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line[0] == "{":
            try:
                lines.append(json.loads(line))
                continue
            except json.JSONDecodeError:
                pass
        lines.append(line)
    return lines


def parse_ffuf(payload, target: str = "") -> list[dict]:
    data = _as_data(payload)
    results = []
    if isinstance(data, dict):
        results = data.get("results") or data.get("Results") or []
    elif isinstance(data, list):
        results = data
    records = []
    for item in results:
        if isinstance(item, str):
            url = item
            status = None
            length = None
        elif isinstance(item, dict):
            url = item.get("url") or item.get("URL") or ""
            status = item.get("status") or item.get("status_code")
            length = item.get("length") or item.get("content-length")
        else:
            continue
        if not url:
            continue
        records.append({
            "target": target,
            "url": url,
            "method": "GET",
            "status": status,
            "body_len": length,
            "params": params_from_url(url),
            "sources": ["ffuf"],
        })
    return records


def parse_nuclei(payload, target: str = "") -> list[dict]:
    data = _as_data(payload)
    if data is None:
        return []
    items = data if isinstance(data, list) else [data]
    records = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = item.get("matched-at") or item.get("matched_at") or item.get("url") or ""
        if not url and item.get("host"):
            url = str(item.get("host"))
        if not url:
            continue
        info = item.get("info") or {}
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [part.strip() for part in tags.split(",") if part.strip()]
        records.append({
            "target": target,
            "url": url,
            "method": (item.get("type") or "GET").upper() if str(item.get("type", "")).isalpha() else "GET",
            "params": params_from_url(url),
            "sources": ["nuclei"],
            "tech": tags[:8],
            "title": str(info.get("name") or item.get("template-id") or "")[:180],
        })
    return records


def parse_gau(payload, target: str = "") -> list[dict]:
    data = _as_data(payload)
    if data is None:
        return []
    lines = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                lines.append(item)
            elif isinstance(item, dict) and item.get("url"):
                lines.append(item["url"])
    elif isinstance(data, dict) and data.get("urls"):
        lines = list(data["urls"])
    else:
        lines = str(payload).splitlines()
    return parse_url_list(lines, target=target, source="gau")


def parse_url_list(urls, target: str = "", source: str = "urls") -> list[dict]:
    records = []
    for item in urls or []:
        url = str(item).strip()
        if not url or url.startswith("#"):
            continue
        records.append({
            "target": target,
            "url": url,
            "method": "GET",
            "params": params_from_url(url),
            "sources": [source],
        })
    return records


def parse_sqlmap(payload, target: str = "") -> list[dict]:
    data = _as_data(payload)
    if not isinstance(data, dict):
        return []
    url = data.get("target") or data.get("target_url") or target
    if not url:
        return []
    params = []
    for item in data.get("injectable_params") or []:
        if isinstance(item, dict):
            name = item.get("param") or item.get("name")
            place = str(item.get("place") or "GET").upper()
        else:
            name, place = str(item), "GET"
        if not name:
            continue
        params.append({
            "name": name,
            "in": "query" if place in {"GET", "QUERY"} else "body",
            "sample": "",
        })
    if not params:
        params = params_from_url(url)
    tech = []
    dbms = str(data.get("dbms") or "").strip()
    if dbms:
        tech.append(dbms.split()[0])
    parsed = urlparse(url)
    method = "GET" if parsed.query or not params else "POST"
    return [{
        "target": target or parsed.hostname or "",
        "url": url,
        "method": method,
        "params": params,
        "sources": ["sqlmap"],
        "tech": tech,
        "title": "sqlmap " + ("vulnerable" if data.get("vulnerable") else "probed"),
    }]


def _openapi_params(meta: dict, document: dict | None = None, inherited=None) -> list[dict]:
    from .openapi import openapi_parameters
    return openapi_parameters(document or {}, meta, inherited)


def _params_from_post(post_data: str, content_type: str = "") -> list[dict]:
    from .serialization import body_parameters
    return body_parameters(post_data, content_type) if post_data else []


def _form_params(fields, method: str) -> list[dict]:
    params = []
    seen = set()
    location = "query" if (method or "GET").upper() == "GET" else "body"
    for field in fields or []:
        sample = ""
        if isinstance(field, str):
            name = field
        elif isinstance(field, dict):
            name = str(field.get("name") or "").strip()
            from .normalize import safe_sample
            sample = safe_sample(name, str(field.get("value") if field.get("value") is not None else (field.get("sample") or "")))
        else:
            continue
        if not name or name in seen:
            continue
        seen.add(name)
        params.append({"name": name, "in": location, "sample": sample})
    return params


def parse_xhr(payload, target: str = "", base: str = "") -> list[dict]:
    data = _as_data(payload)
    items = []
    if isinstance(data, dict):
        items = data.get("api_requests") or data.get("xhr") or data.get("requests") or []
        if not items and data.get("url") and data.get("method"):
            items = [data]
    elif isinstance(data, list):
        items = data
    records = []
    for item in items or []:
        if isinstance(item, str):
            url = item
            method = "GET"
            post = ""
            ctype = ""
        elif isinstance(item, dict):
            url = item.get("url") or ""
            method = str(item.get("method") or "GET").upper() or "GET"
            post = item.get("post_data", item.get("body", ""))
            ctype = item.get("content_type") or item.get("contentType") or ""
            if not ctype and isinstance(item.get("headers"), dict):
                ctype = next((value for name, value in item["headers"].items()
                              if str(name).lower() == "content-type"), "")
        else:
            continue
        if not url:
            continue
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            method = "GET"
        from .serialization import body_parameters, graphql_envelope, pair_parameters
        params = pair_parameters(parse_qsl(urlparse(url).query, keep_blank_values=True), "query")
        if method != "GET":
            params += body_parameters(post, str(ctype)) if post != "" else []
        envelope = graphql_envelope(post, ctype, url, method, resolve_files=False)
        from .operation import graphql_operation
        operation = (graphql_operation(envelope.get("query"), envelope.get("operationName") or "")
                     if "query" in envelope else None)
        if operation and operation.get("selection") != "selected" and "graphql" not in urlparse(url).path.lower():
            operation = None
        if operation:
            document = str(envelope.get("query") or "")
            if '"' in document:
                for param in params:
                    if param["name"] == "query":
                        param["sample"] = "<unavailable>"
        if isinstance(item, dict) and isinstance(item.get("headers"), dict):
            from .normalize import safe_sample
            params += [{"name": name, "in": "header", "sample": safe_sample(name, value)}
                       for name, value in item["headers"].items()
                       if not re.search(r"authorization|cookie|api[-_]?key|token|secret|csrf|xsrf", name, re.I)
                       and str(name).lower() not in {"content-type", "content-length", "host"}]
        records.append({
            "target": target,
            "url": url,
            "method": method,
            "params": params,
            "sources": ["xhr"],
            "content_type": ctype,
            **({key: item[key] for key in ("status", "body_hash", "body_len", "identity", "resource_owner", "run_id")
                if key in item} if isinstance(item, dict) else {}),
            **({"operation": operation} if operation else {}),
        })
    return records


def parse_browser_crawl(payload, target: str = "", base: str = "") -> list[dict]:
    data = _as_data(payload)
    if not isinstance(data, dict):
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict) and item.get("url")]
        return []
    start = data.get("url") or data.get("base") or base or ""
    records = []
    seen = set()

    def _add(rec):
        url = rec.get("url") or ""
        method = (rec.get("method") or "GET").upper()
        from .operation import operation_descriptor, operation_id
        key = (method, url, operation_id(url, method, operation_descriptor(rec)))
        if not url or key in seen:
            return
        seen.add(key)
        rec.setdefault("target", target)
        records.append(rec)

    for page in data.get("pages") or []:
        if isinstance(page, str):
            _add({"url": page, "method": "GET", "sources": ["crawl"], "params": params_from_url(page)})
            continue
        if not isinstance(page, dict):
            continue
        url = page.get("url") or ""
        if not url:
            continue
        status = page.get("status")
        page_rec = {
            "url": url,
            "method": "GET",
            "status": status,
            "title": page.get("title") or "",
            "auth_required": True if status == 401 else None,
            "params": params_from_url(url),
            "sources": ["crawl"],
        }
        if page.get("content_type"):
            page_rec["content_type"] = str(page["content_type"])
        _add(page_rec)
    for form in data.get("forms") or []:
        if not isinstance(form, dict):
            continue
        page_url = form.get("page") or start
        action = form.get("action") or page_url or start
        from urllib.parse import urljoin as _join
        url = action if str(action).startswith("http") else _join(page_url or start or "", action or ".")
        method = str(form.get("method") or "GET").upper() or "GET"
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            method = "POST"
        params = _form_params(form.get("fields") or form.get("inputs") or [], method)
        if method == "GET":
            params = params or params_from_url(url)
        _add({"url": url, "method": method, "params": params, "sources": ["form", "crawl"]})
    for href in (data.get("links") or []) + (data.get("internal_links") or []) + (data.get("urls_with_params") or []):
        if isinstance(href, dict):
            href = href.get("url") or ""
        href = str(href or "").strip()
        if href:
            _add({"url": href, "method": "GET", "params": params_from_url(href), "sources": ["crawl"]})
    for href in data.get("form_actions") or []:
        href = str(href or "").strip()
        if href:
            _add({"url": href, "method": "GET", "params": params_from_url(href), "sources": ["form", "crawl"]})
    for src in data.get("js_files") or []:
        src = str(src or "").strip()
        if src:
            _add({"url": src, "method": "GET", "params": params_from_url(src), "sources": ["js", "crawl"]})
    for rec in parse_xhr(data, target=target, base=start):
        rec["sources"] = list(dict.fromkeys((rec.get("sources") or []) + ["crawl"]))
        # Captures carry values and ordering, including A -> B -> A. Route
        # deduplication would lose them; persistence merges observation IDs.
        records.append(rec)
    return records


_ZAP_ALERT_CLASSES = [
    ("sql", "sql_injection"),
    ("xss", "xss_reflected"),
    ("cross-site scripting", "xss_reflected"),
    ("ssti", "ssti"),
    ("template", "ssti"),
    ("command", "command_injection"),
    ("os command", "command_injection"),
    ("path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("lfi", "path_traversal"),
    ("xxe", "xxe"),
    ("ssrf", "ssrf"),
    ("redirect", "open_redirect"),
    ("idor", "idor"),
    ("access control", "broken_access_control"),
    ("csrf", "csrf"),
]


def parse_zap(payload, target: str = "") -> list[dict]:
    """ZAP urls + pasif alert JSON → surface records. Verdict/CONFIRMED yok."""
    data = _as_data(payload)
    urls = []
    alerts = []
    if isinstance(data, dict):
        raw_urls = data.get("urls") or data.get("urlsInScope") or []
        if isinstance(raw_urls, dict):
            raw_urls = raw_urls.get("urls") or []
        urls = list(raw_urls or [])
        raw_alerts = data.get("alerts") or data.get("alert") or []
        if isinstance(raw_alerts, dict):
            raw_alerts = raw_alerts.get("alerts") or raw_alerts.get("alert") or []
        alerts = list(raw_alerts or [])
    elif isinstance(data, list):
        if data and isinstance(data[0], str):
            urls = data
        else:
            alerts = data
    records = []
    seen = set()
    for item in urls:
        url = item if isinstance(item, str) else (item.get("url") if isinstance(item, dict) else "")
        url = str(url or "").strip()
        if not url:
            continue
        key = ("GET", url, "")
        if key in seen:
            continue
        seen.add(key)
        records.append({
            "target": target,
            "url": url,
            "method": "GET",
            "params": params_from_url(url),
            "sources": ["zap"],
            "tech": ["zap"],
        })
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        url = str(alert.get("url") or alert.get("uri") or "").strip()
        if not url:
            continue
        method = str(alert.get("method") or "GET").upper() or "GET"
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            method = "GET"
        param = str(alert.get("param") or alert.get("parameter") or "").strip()
        params = params_from_url(url)
        if param and param not in {p["name"] for p in params}:
            place = "query" if method == "GET" else "body"
            params.append({"name": param, "in": place, "sample": ""})
        name = str(alert.get("alert") or alert.get("name") or "")[:180]
        risk = str(alert.get("risk") or alert.get("riskdesc") or "")
        plugin = str(alert.get("pluginId") or alert.get("pluginid") or "")
        blob = f"{name} {risk}".lower()
        tech = ["zap"]
        if plugin:
            tech.append(f"plugin-{plugin}")
        for needle, cls in _ZAP_ALERT_CLASSES:
            if needle in blob:
                tech.append(cls)
                break
        key = (method, url, param)
        records.append({
            "target": target,
            "url": url,
            "method": method,
            "params": params,
            "sources": ["zap"],
            "tech": tech[:8],
            "title": (name + (f" [{risk}]" if risk else ""))[:180],
        })
        seen.add(key)
    return records


def parse_openapi(payload, target: str = "", base: str = "") -> list[dict]:
    data = payload if isinstance(payload, dict) else _as_data(payload)
    if not isinstance(data, dict):
        text = str(payload or "").strip()
        if text and text[0] not in "[{":
            try:
                import yaml
                data = yaml.safe_load(text)
            except Exception:
                return []
        else:
            return []
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return []
    servers = data.get("servers") or []
    spec_base = ""
    if servers and isinstance(servers[0], dict):
        spec_base = str(servers[0].get("url") or "")
    origin = (spec_base or base or "").rstrip("/")
    from .openapi import LocalSchema, request_media
    resolver = LocalSchema(data)
    records = []
    for path, methods in data["paths"].items():
        if not isinstance(methods, dict):
            continue
        methods = resolver.resolve(methods)
        for method, meta in methods.items():
            method_u = str(method or "").upper()
            if method_u not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                continue
            if not isinstance(meta, dict):
                meta = {}
            joined = path if str(path).startswith("http") else urljoin(origin + "/", str(path).lstrip("/"))
            if not joined.startswith("http"):
                continue
            params = _openapi_params(meta, data, methods.get("parameters"))
            if method_u == "GET":
                params = params or params_from_url(joined)
            info = data.get("info") if isinstance(data.get("info"), dict) else {}
            records.append({
                "target": target or urlparse(joined).hostname or "",
                "url": joined,
                "method": method_u,
                "params": params,
                "content_type": request_media(data, meta)[0] or (
                    "application/json" if any(p["in"] == "json" for p in params) else
                    "application/x-www-form-urlencoded" if any(p["in"] == "body" for p in params) else ""),
                "sources": ["openapi"],
                "tech": ["openapi"],
                "title": str(meta.get("summary") or info.get("title") or "")[:180],
            })
    return records


def parse_artifact(payload, source_format: str, target: str = "") -> list[dict]:
    fmt = (source_format or "records").lower().strip()
    if fmt in {"ffuf"}:
        return parse_ffuf(payload, target=target)
    if fmt in {"nuclei", "nuclei-jsonl", "nuclei_jsonl"}:
        return parse_nuclei(payload, target=target)
    if fmt in {"gau", "wayback", "waybackurls"}:
        source = "wayback" if "wayback" in fmt else "gau"
        records = parse_gau(payload, target=target)
        for rec in records:
            rec["sources"] = [source]
        return records
    if fmt in {"sqlmap"}:
        return parse_sqlmap(payload, target=target)
    if fmt in {"openapi", "swagger"}:
        return parse_openapi(payload, target=target)
    if fmt in {"browser", "crawl", "browser_crawl"}:
        return parse_browser_crawl(payload, target=target)
    if fmt in {"xhr", "fetch", "api_requests"}:
        return parse_xhr(payload, target=target)
    if fmt in {"zap", "owasp-zap", "zaproxy"}:
        return parse_zap(payload, target=target)
    if fmt in {"urls", "url", "txt"}:
        return parse_url_list(
            payload if isinstance(payload, list) else str(payload).splitlines(),
            target=target,
            source="urls",
        )
    data = _as_data(payload)
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        return data["records"]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict) and data.get("url"):
        return [data]
    return []
