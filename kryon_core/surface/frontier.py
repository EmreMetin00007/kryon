"""Shared, I/O-free source frontier and page/identity/screen visit ledger.

Discovery is never scope authorization. Pending work survives call budgets;
public snapshots contain metadata, not credentials or query values.
"""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def origin(url: str) -> tuple[str, str, int] | None:
    try:
        p = urlsplit(url)
        if p.scheme not in {"http", "https"} or not p.hostname or p.username is not None:
            return None
        port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
        return (p.scheme, p.hostname.lower(), port) if port > 0 else None
    except ValueError:
        return None


def metadata_url(url: str) -> str:
    try:
        p = urlsplit(url)
        if p.username is not None:
            return ""
        pairs = parse_qsl(p.query, keep_blank_values=True)
        return urlunsplit((
            p.scheme,
            p.netloc,
            p.path,
            urlencode([(k, "<redacted>") for k, _ in pairs]),
            p.fragment,
        ))
    except ValueError:
        return ""


class UnifiedFrontier:
    def __init__(self, start: str, permits: Any, identity: str = "anonymous") -> None:
        self.start = start
        self.permits = permits
        self.identity = identity or "anonymous"
        self.items: dict[str, dict[str, Any]] = {}
        self.visits: dict[str, dict[str, Any]] = {}
        self._visit_operations: dict[str, set[Any]] = {}
        self.features: list[dict[str, Any]] = []

    def add(
        self,
        url: Any,
        *,
        source: str,
        kind: str = "page",
        method: str = "GET",
        screen: str = "default",
        operation: Any = None,
        executable: bool = True,
    ) -> dict[str, Any] | None:
        joined = urljoin(self.start, str(url or ""))
        if not origin(joined):
            return None
        norm_method = str(method or "GET").upper()
        key = digest([joined, norm_method, kind, self.identity, screen, operation])
        if key in self.items:
            if source not in self.items[key]["sources"]:
                self.items[key]["sources"].append(source)
            return self.items[key]
        allowed = origin(joined) == origin(self.start) and self.permits(joined)
        reason = ""
        if not allowed:
            reason = "requires_scope_approval"
        elif "{" in joined or "}" in joined:
            reason = "requires_request_context"
        elif norm_method not in {"GET", "HEAD", "OPTIONS"} or not executable:
            reason = "inventory_only"
        item: dict[str, Any] = {
            "id": key,
            "url": joined,
            "method": norm_method,
            "kind": kind,
            "identity": self.identity,
            "screen": screen,
            "sources": [source],
            "status": "blocked" if reason else "pending",
            "reason": reason,
        }
        self.items[key] = item
        return item

    def add_records(self, records: Any, source: str = "inventory") -> None:
        for rec in records:
            if not isinstance(rec, dict) or not rec.get("url"):
                continue
            kind = "bundle" if urlsplit(rec["url"]).path.endswith((".js", ".mjs")) else "operation"
            for src in rec.get("sources") or [source]:
                self.add(
                    rec["url"],
                    source=src,
                    kind=kind,
                    method=rec.get("method", "GET"),
                    operation=rec.get("operation"),
                )

    def add_html(self, text: str, base: str | None = None) -> None:
        frontier = self

        class Sources(HTMLParser):
            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                attr_map = dict(attrs)
                value = attr_map.get("src") if tag == "script" else attr_map.get("href") if tag in {"a", "link"} else None
                if value:
                    url = urljoin(base or frontier.start, value)
                    kind = "bundle" if urlsplit(url).path.endswith((".js", ".mjs")) else "page"
                    frontier.add(url, source="html", kind=kind)

        Sources().feed(text or "")

    def add_js_imports(self, text: str, base: str) -> None:
        pattern = r'''(?:\bimport\s*\(\s*|\bfrom\s*|\bimport\s*)['"]([^'"\s]+)['"]'''
        for match in re.finditer(pattern, text or ""):
            value = match.group(1)
            if value.startswith((".", "/", "http://", "https://")):
                self.add(urljoin(base, value), source="js-import", kind="bundle")

    def pending(self, *kinds: str) -> list[dict[str, Any]]:
        return [
            item
            for item in self.items.values()
            if item["status"] == "pending" and (not kinds or item["kind"] in kinds)
        ]

    def take(self, *kinds: str) -> dict[str, Any] | None:
        pending = self.pending(*kinds)
        if not pending:
            return None
        item = pending[0]
        item["status"] = "running"
        return item

    def finish(self, item: dict[str, Any], reason: str = "") -> None:
        item.update(status="done", reason=reason)

    def visit(self, page: str, screen: Any, operations: Any = ()) -> bool:
        key = digest([page, self.identity, screen])
        self._visit_operations.setdefault(key, set()).update(operations)
        if key in self.visits:
            self.visits[key]["operation_yield"] = len(self._visit_operations[key])
            return False
        self.visits[key] = {
            "key": key,
            "page": metadata_url(page),
            "identity": self.identity,
            "screen": digest(screen),
            "operation_yield": len(self._visit_operations[key]),
        }
        return True

    def snapshot(self) -> dict[str, Any]:
        items = [{**item, "url": metadata_url(item["url"])} for item in self.items.values()]
        return {
            "frontier": items,
            "continuation_queue": [item for item in items if item["status"] in {"pending", "running"}],
            "external_sources": [item for item in items if item["reason"] == "requires_scope_approval"],
            "visited_states": list(self.visits.values()),
            "feature_map": list(self.features),
        }
