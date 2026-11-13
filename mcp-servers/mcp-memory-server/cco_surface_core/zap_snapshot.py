"""Import existing ZAP observations without starting ZAP or making requests."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .parsers import parse_zap

_MAX_BYTES = 2_000_000
_MAX_ENTRIES = 10_000


def _origin(url: str):
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
            return None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        return (parsed.scheme, parsed.hostname.lower(), port) if port > 0 else None
    except ValueError:
        return None


def _without_values(url: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       urlencode([(name, "<redacted>") for name, _ in pairs]), ""))


def import_zap_snapshot(target: str, snapshot_json: str) -> dict:
    """Return scope-filtered hypotheses; original query values are discarded."""
    url = str(target or "").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    origin = _origin(url)
    if not origin:
        return {"ok": False, "error": "invalid target URL"}
    if not isinstance(snapshot_json, str) or len(snapshot_json.encode("utf-8")) > _MAX_BYTES:
        return {"ok": False, "error": "invalid or oversized ZAP snapshot"}
    try:
        payload = json.loads(snapshot_json)
    except (TypeError, ValueError):
        return {"ok": False, "error": "invalid ZAP snapshot JSON"}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "ZAP snapshot must be an object"}
    urls, alerts = payload.get("urls", []), payload.get("alerts", [])
    if not isinstance(urls, list) or not isinstance(alerts, list):
        return {"ok": False, "error": "ZAP urls and alerts must be lists"}
    if len(urls) + len(alerts) > _MAX_ENTRIES:
        return {"ok": False, "error": "too many ZAP snapshot entries"}
    scripts = str(Path(__file__).resolve().parents[3] / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    try:
        from policy_engine import ScopeResolver
        scope = ScopeResolver()
        if not scope.permits_url(url):
            return {"ok": False, "error": "target URL is outside active scope"}
        def filtered(raw):
            return _origin(raw) == origin and scope.permits_url(raw)

        safe_urls, safe_alerts, discarded = [], [], 0
        for item in urls:
            raw = item if isinstance(item, str) else item.get("url", "") if isinstance(item, dict) else ""
            if not isinstance(raw, str) or not filtered(raw):
                discarded += 1
                continue
            try:
                safe_urls.append(_without_values(raw))
            except ValueError:
                discarded += 1
        for alert in alerts:
            if not isinstance(alert, dict):
                discarded += 1
                continue
            raw = alert.get("url") or alert.get("uri") or ""
            method = str(alert.get("method") or "GET").upper()
            if not isinstance(raw, str) or not filtered(raw) or method not in {"GET", "HEAD", "OPTIONS"}:
                discarded += 1
                continue
            try:
                clean_url = _without_values(raw)
            except ValueError:
                discarded += 1
                continue
            safe_alerts.append({"url": clean_url, "method": method,
                                "param": str(alert.get("param") or alert.get("parameter") or "")[:160],
                                "alert": str(alert.get("alert") or alert.get("name") or "")[:180],
                                "risk": str(alert.get("risk") or "")[:80],
                                "pluginId": str(alert.get("pluginId") or "")[:80]})
    except (ImportError, OSError, RuntimeError, ValueError):
        return {"ok": False, "error": "scope policy unavailable"}
    records = parse_zap({"urls": safe_urls, "alerts": safe_alerts}, target=origin[1])
    try:
        safe_target = _without_values(url)
    except ValueError:
        return {"ok": False, "error": "target query has too many parameters"}
    return {"ok": True, "target": safe_target, "urls": safe_urls, "alerts": safe_alerts,
            "records": records, "discarded": discarded, "calls": [], "verdict": None,
            "ascan": {"skipped": True, "ran": False}, "ajax": {"skipped": True},
            "mode": "offline_snapshot"}
