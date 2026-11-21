"""Strict loopback-only out-of-band HTTP callback listener for async/SSRF QA."""
from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import socket
import threading
from typing import Any
from urllib.parse import urlsplit

from agentic_receipts import redact_headers, redact_secrets

_ALLOWED_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
DEFAULT_MAX_HITS = 200
DEFAULT_MAX_BODY_CHARS = 2048
_MAX_READ_BYTES = 65536


class _LoopbackThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class _LoopbackIPv6ThreadingHTTPServer(_LoopbackThreadingHTTPServer):
    address_family = socket.AF_INET6


class LoopbackCallbackServer:
    """Thread-safe loopback-only HTTP callback server for webhook/SSRF verification."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        max_hits: int = DEFAULT_MAX_HITS,
        max_body_chars: int = DEFAULT_MAX_BODY_CHARS,
    ) -> None:
        clean_host = str(host or "127.0.0.1").strip()
        if clean_host not in _ALLOWED_LOOPBACK_HOSTS:
            raise ValueError(
                f"LoopbackCallbackServer rejects non-loopback bind address {host!r}; "
                "only '127.0.0.1' or '::1' is permitted"
            )
        port_num = int(port)
        if not (0 <= port_num <= 65535):
            raise ValueError(f"invalid port: {port!r}")
        self.host = clean_host
        self._requested_port = port_num
        self._bound_port = 0
        self.max_hits = max(1, int(max_hits))
        self.max_body_chars = max(64, int(max_body_chars))
        self._lifecycle_lock = threading.Lock()
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._tokens: dict[str, dict[str, str]] = {}
        self._hits: list[dict[str, Any]] = []
        self._dropped_hits = 0

    @property
    def port(self) -> int:
        return self._bound_port

    @property
    def base_url(self) -> str:
        host_fmt = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host_fmt}:{self.port}"

    @property
    def is_running(self) -> bool:
        with self._lifecycle_lock:
            return self._server is not None

    def start(self) -> LoopbackCallbackServer:
        """Start the loopback HTTP server idempotently on a background daemon thread."""
        with self._lifecycle_lock:
            if self._server is not None:
                return self
            owner = self

            class _CallbackHandler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                    return

                def _read_bounded_body(self) -> tuple[bytes, int]:
                    raw_len = self.headers.get("Content-Length")
                    if not raw_len:
                        return b"", 0
                    try:
                        content_len = max(0, int(raw_len.strip()))
                    except ValueError:
                        return b"", 0
                    if content_len == 0:
                        return b"", 0
                    to_read = min(content_len, _MAX_READ_BYTES)
                    data = self.rfile.read(to_read)
                    return data, content_len

                def _dispatch_cb(self, *, send_body: bool) -> None:
                    raw_body, declared_len = self._read_bounded_body()
                    parsed = urlsplit(self.path)
                    req_path = parsed.path or "/"
                    token = ""
                    if req_path.startswith("/cb/"):
                        rest = req_path[4:]
                        token = rest.split("/", 1)[0].strip()

                    raw_headers = {str(k): str(v) for k, v in self.headers.items()}
                    remote_addr = str(self.client_address[0]) if self.client_address else ""
                    body_text = raw_body.decode("utf-8", errors="replace")
                    body_preview = redact_secrets(body_text)[: owner.max_body_chars]

                    recorded = owner._record_hit(
                        token=token,
                        method=str(self.command or "GET").upper(),
                        path=req_path,
                        query=parsed.query or "",
                        headers=raw_headers,
                        body_preview=body_preview,
                        body_length=max(len(raw_body), declared_len),
                        remote_addr=remote_addr,
                    )
                    if not recorded:
                        payload = b'{"ok":false,"error":"unknown_token"}'
                        self.send_response(404)
                    else:
                        payload = b'{"ok":true}'
                        self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if send_body:
                        self.wfile.write(payload)

                def do_GET(self) -> None:
                    self._dispatch_cb(send_body=True)

                def do_POST(self) -> None:
                    self._dispatch_cb(send_body=True)

                def do_PUT(self) -> None:
                    self._dispatch_cb(send_body=True)

                def do_PATCH(self) -> None:
                    self._dispatch_cb(send_body=True)

                def do_DELETE(self) -> None:
                    self._dispatch_cb(send_body=True)

                def do_OPTIONS(self) -> None:
                    self._dispatch_cb(send_body=True)

                def do_HEAD(self) -> None:
                    self._dispatch_cb(send_body=False)

            server_cls = _LoopbackIPv6ThreadingHTTPServer if ":" in self.host else _LoopbackThreadingHTTPServer
            srv = server_cls((self.host, self._requested_port), _CallbackHandler)
            self._bound_port = int(srv.server_address[1])
            self._server = srv
            thread = threading.Thread(target=srv.serve_forever, name="kryon-loopback-oob", daemon=True)
            self._thread = thread
            thread.start()
            return self

    def close(self) -> None:
        """Stop and close the HTTP server idempotently."""
        with self._lifecycle_lock:
            srv = self._server
            thread = self._thread
            self._server = None
            self._thread = None
            self._bound_port = 0
        if srv is not None:
            try:
                srv.shutdown()
            except Exception:
                pass
            try:
                srv.server_close()
            except Exception:
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def __enter__(self) -> LoopbackCallbackServer:
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _record_hit(
        self,
        *,
        token: str,
        method: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body_preview: str,
        body_length: int,
        remote_addr: str,
    ) -> bool:
        if not token:
            return False
        with self._lock:
            meta = self._tokens.get(token)
            if meta is None:
                return False
            if len(self._hits) >= self.max_hits:
                self._dropped_hits += 1
                return True
            self._hits.append({
                "token": token,
                "label": meta.get("label", ""),
                "method": method,
                "path": path,
                "query": query,
                "headers": redact_headers(headers),
                "body_preview": body_preview,
                "body_length": int(body_length),
                "remote_addr": remote_addr,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return True

    def create_token(self, label: str = "") -> dict[str, Any]:
        """Register a fresh URL-safe correlation token and return its loopback URL."""
        self.start()
        clean_label = str(label or "").strip()[:120]
        with self._lock:
            tok = secrets.token_urlsafe(12)
            while tok in self._tokens:
                tok = secrets.token_urlsafe(12)
            self._tokens[tok] = {
                "label": clean_label,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            url = f"{self.base_url}/cb/{tok}"
        return {"token": tok, "url": url, "label": clean_label}

    def registered_tokens(self) -> list[str]:
        """Return all registered correlation tokens."""
        with self._lock:
            return list(self._tokens.keys())

    def poll(self, token: str = "") -> dict[str, Any]:
        """Return recorded callback hits for `token`, or a summary of all hits when empty."""
        tok = str(token or "").strip()
        with self._lock:
            if tok:
                meta = self._tokens.get(tok)
                tok_hits = [dict(h) for h in self._hits if h["token"] == tok]
                return {
                    "token": tok,
                    "registered": meta is not None,
                    "label": meta.get("label", "") if meta is not None else "",
                    "hit_count": len(tok_hits),
                    "hits": tok_hits,
                    "total_hits": len(self._hits),
                }
            per_token: dict[str, dict[str, Any]] = {
                t: {"label": m.get("label", ""), "hit_count": 0}
                for t, m in self._tokens.items()
            }
            for hit in self._hits:
                entry = per_token.get(hit["token"])
                if entry is not None:
                    entry["hit_count"] += 1
            return {
                "total_hits": len(self._hits),
                "dropped_hits": self._dropped_hits,
                "token_count": len(self._tokens),
                "tokens": per_token,
                "hits": [dict(h) for h in self._hits],
            }
