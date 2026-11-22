"""Read-only browser runtime instrumentation.

The injected script observes request metadata before page code runs. It does
not read storage values, cookie values, request bodies or response bodies.
Only names, field keys, URLs with redacted query values, status and timing
metadata are collected.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

SCHEMA = "cco-browser-runtime/1"
MAX_EVENTS = 500


def build_runtime_hook_script(max_events: int = MAX_EVENTS) -> str:
    """Return the Playwright ``add_init_script`` payload."""
    limit = max(1, min(int(max_events or MAX_EVENTS), 2000))
    return """
(() => {
  const MAX_EVENTS = %d;
  const runtime = { events: [], installed: true };
  window.__ccoRuntime = runtime;
  const push = (event) => {
    try { if (runtime.events.length < MAX_EVENTS) runtime.events.push(event); } catch (_) {}
  };
  const headerNames = (headers) => {
    const names = [];
    try {
      if (!headers) return names;
      if (typeof Headers !== "undefined" && headers instanceof Headers) {
        headers.forEach((_, name) => names.push(name));
      } else if (Array.isArray(headers)) {
        headers.forEach((pair) => { if (pair && pair[0]) names.push(String(pair[0])); });
      } else if (typeof headers === "object") {
        Object.keys(headers).forEach((name) => names.push(name));
      }
    } catch (_) {}
    return [...new Set(names)].slice(0, 40);
  };
  const bodyFields = (body) => {
    try {
      if (!body) return [];
      if (typeof FormData !== "undefined" && body instanceof FormData) {
        return [...new Set([...body.keys()])].slice(0, 40);
      }
      if (typeof body === "string") {
        const parsed = JSON.parse(body);
        if (parsed && typeof parsed === "object") return Object.keys(parsed).slice(0, 40);
      }
      if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        return [...new Set([...body.keys()])].slice(0, 40);
      }
    } catch (_) {}
    return [];
  };
  const now = () => (window.performance && performance.now ? performance.now() : Date.now());
  try {
    const originalFetch = window.fetch;
    if (typeof originalFetch === "function") {
      window.fetch = function(input, init) {
        const started = now();
        let method = "GET", url = "", headers = [], fields = [];
        try {
          url = typeof input === "string" ? input : (input && input.url) || "";
          method = (init && init.method) || (input && input.method) || "GET";
          headers = headerNames((init && init.headers) || (input && input.headers));
          fields = bodyFields(init && init.body);
        } catch (_) {}
        const promise = originalFetch.apply(this, arguments);
        return Promise.resolve(promise).then((response) => {
          push({kind: "fetch", method: String(method).toUpperCase(), url: String(url),
                header_names: headers, body_fields: fields,
                status: response && response.status,
                duration_ms: Math.round((now() - started) * 1000) / 1000});
          return response;
        }, (error) => {
          push({kind: "fetch", method: String(method).toUpperCase(), url: String(url),
                header_names: headers, body_fields: fields, status: 0,
                duration_ms: Math.round((now() - started) * 1000) / 1000,
                error: String(error && error.name || "fetch_error")});
          throw error;
        });
      };
    }
  } catch (_) {}
  try {
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    const originalSetHeader = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.open = function(method, url) {
      this.__cco = {method: String(method || "GET").toUpperCase(), url: String(url || ""), header_names: []};
      return originalOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
      try {
        if (this.__cco && name) this.__cco.header_names.push(String(name));
      } catch (_) {}
      return originalSetHeader.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function(body) {
      const started = now();
      const meta = this.__cco || {method: "GET", url: "", header_names: []};
      const fields = bodyFields(body);
      this.addEventListener("loadend", () => {
        let responseHeaders = [];
        try {
          const raw = this.getAllResponseHeaders() || "";
          responseHeaders = raw.split(/\\r?\\n/).map((line) => line.split(":")[0].trim()).filter(Boolean);
        } catch (_) {}
        push({kind: "xhr", method: meta.method, url: meta.url,
              header_names: [...new Set(meta.header_names)].slice(0, 40),
              body_fields: fields, status: this.status,
              duration_ms: Math.round((now() - started) * 1000) / 1000,
              response_header_names: responseHeaders.slice(0, 40)});
      });
      return originalSend.apply(this, arguments);
    };
  } catch (_) {}
  try {
    const OriginalWebSocket = window.WebSocket;
    if (typeof OriginalWebSocket === "function") {
      window.WebSocket = function(url, protocols) {
        push({kind: "websocket", url: String(url || "")});
        return protocols === undefined
          ? new OriginalWebSocket(url)
          : new OriginalWebSocket(url, protocols);
      };
      window.WebSocket.prototype = OriginalWebSocket.prototype;
    }
  } catch (_) {}
  runtime.snapshot = () => {
    const frameworkHints = {};
    try {
      frameworkHints.react = !!document.querySelector("[data-reactroot], [data-reactid]") ||
        !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
      frameworkHints.next = !!document.getElementById("__NEXT_DATA__");
      frameworkHints.vue = !!document.querySelector("[data-v-app]") || !!window.__VUE__;
      frameworkHints.webpack = Object.keys(window).some((k) => k.startsWith("webpackChunk"));
    } catch (_) {}
    let signerCandidates = [];
    try {
      signerCandidates = Object.keys(window)
        .filter((k) => /sign|hmac|sha256/i.test(k)).slice(0, 40);
    } catch (_) {}
    return {
      storage_keys: (() => { try { return Object.keys(localStorage).slice(0, 100); } catch (_) { return []; } })(),
      session_storage_keys: (() => { try { return Object.keys(sessionStorage).slice(0, 100); } catch (_) { return []; } })(),
      cookie_names: (() => {
        try {
          return document.cookie.split(";").map((part) => part.split("=")[0].trim()).filter(Boolean).slice(0, 100);
        } catch (_) { return []; }
      })(),
      framework_hints: frameworkHints,
      signer_candidates: signerCandidates,
    };
  };
})();
""" % limit


def _redact_url(url: str) -> tuple[str, str, list[str]]:
    raw = str(url or "")
    try:
        parsed = urlparse(raw)
        path = parsed.path or "/"
        query_params = sorted({k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        safe = parsed._replace(
            query="&".join(f"{k}=<value>" for k in query_params),
            fragment="",
        ).geturl()
        return safe, path, query_params
    except Exception:
        return re.sub(r"([?&][^=]+)=[^&]+", r"\1=<value>", raw), raw, []


def _safe_names(values: Any, limit: int = 100) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    out: list[str] = []
    for value in values:
        name = str(value or "").strip()
        if name and name not in out:
            out.append(name[:120])
        if len(out) >= limit:
            break
    return out


def normalize_runtime_events(events: Any, state: Any = None) -> dict[str, Any]:
    """Normalize hook events without retaining values or bodies."""
    requests: list[dict[str, Any]] = []
    websockets: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        kind = str(event.get("kind") or "fetch").lower()
        safe_url, path, query_params = _redact_url(str(event.get("url") or ""))
        item: dict[str, Any] = {
            "kind": kind,
            "method": str(event.get("method") or "GET").upper(),
            "url": safe_url,
            "path": path,
            "query_params": query_params,
            "header_names": _safe_names(event.get("header_names"), 40),
            "body_fields": _safe_names(event.get("body_fields"), 40),
            "status": event.get("status"),
            "duration_ms": event.get("duration_ms"),
            "response_header_names": _safe_names(event.get("response_header_names"), 40),
        }
        key = (
            kind, item["method"], safe_url, item["status"],
            tuple(item["header_names"]), tuple(item["body_fields"]),
        )
        if key in seen:
            continue
        seen.add(key)
        if kind == "websocket":
            websockets.append(item)
        else:
            requests.append(item)
    state = state if isinstance(state, dict) else {}
    return {
        "schema": SCHEMA,
        "requests": requests,
        "websockets": websockets,
        "state": {
            "storage_keys": _safe_names(state.get("storage_keys")),
            "session_storage_keys": _safe_names(state.get("session_storage_keys")),
            "cookie_names": _safe_names(state.get("cookie_names")),
            "framework_hints": state.get("framework_hints") if isinstance(state.get("framework_hints"), dict) else {},
            "signer_candidates": _safe_names(state.get("signer_candidates"), 40),
        },
        "summary": {"requests": len(requests), "websockets": len(websockets)},
    }


def _template_path(path: str) -> str:
    parts = []
    for part in (path or "/").split("/"):
        if re.fullmatch(r"\d+", part or "") or re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", part or ""
        ):
            parts.append("{id}")
        else:
            parts.append(part)
    return "/".join(parts) or "/"


def merge_runtime_into_client_map(client_map: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    """Mark runtime-observed endpoints and append newly observed routes."""
    merged = dict(client_map or {})
    endpoints = [dict(e) for e in merged.get("endpoints") or []]
    index = {(e.get("method"), e.get("path")): e for e in endpoints}
    for request in runtime.get("requests") or []:
        path = _template_path(str(request.get("path") or "/"))
        method = str(request.get("method") or "GET").upper()
        key = (method, path)
        if key in index:
            index[key]["runtime_observed"] = True
            index[key]["runtime_required"] = False
            continue
        endpoint = {
            "method": method,
            "path": path,
            "url_expression": request.get("url") or path,
            "source_kind": "runtime",
            "query_params": request.get("query_params") or [],
            "body_fields": request.get("body_fields") or [],
            "headers": request.get("header_names") or [],
            "function_context": None,
            "signer_functions": [],
            "runtime_required": False,
            "runtime_observed": True,
            "evidence_line": None,
            "evidence_column": None,
            "confidence": "high",
        }
        endpoints.append(endpoint)
        index[key] = endpoint
    merged["endpoints"] = sorted(endpoints, key=lambda e: (e.get("path") or "", e.get("method") or ""))
    merged["runtime"] = {
        "schema": runtime.get("schema"),
        "state": runtime.get("state") or {},
        "summary": runtime.get("summary") or {},
    }
    return merged
