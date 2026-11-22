"""Loopback-default (with opt-in private Docker-bridge) OOB HTTP callback listener for async/SSRF/XXE QA."""
from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
from typing import Any
from urllib.parse import urlsplit

from agentic_receipts import redact_headers, redact_secrets

_ALLOWED_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
_HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_FORBIDDEN_ADVERTISE_CHARS = frozenset({"/", "\\", "?", "#", "@", "[", "]"})
DEFAULT_MAX_HITS = 200
DEFAULT_MAX_BODY_CHARS = 2048
_MAX_READ_BYTES = 65536


def _validate_bind_host(host: str, *, allow_private_bridge: bool) -> str:
    """Validate callback bind host (strict loopback by default; opt-in private bridge IP)."""
    clean_host = str(host or "127.0.0.1").strip()
    if not allow_private_bridge:
        if clean_host not in _ALLOWED_LOOPBACK_HOSTS:
            raise ValueError(
                f"LoopbackCallbackServer rejects non-loopback bind address {host!r}; "
                "only '127.0.0.1' or '::1' is permitted"
            )
        return clean_host

    if not clean_host or "%" in clean_host or any(ch.isspace() or ord(ch) < 32 or ch == "\x7f" for ch in clean_host):
        raise ValueError(
            f"LoopbackCallbackServer rejects invalid bind address {host!r}; "
            "only literal loopback or private bridge IP addresses are permitted"
        )
    try:
        ip = ipaddress.ip_address(clean_host)
    except ValueError:
        raise ValueError(
            f"LoopbackCallbackServer rejects non-IP bind address {host!r}; "
            "only literal loopback or private bridge IP addresses are permitted"
        ) from None

    if not (ip.is_loopback or (ip.is_private and not ip.is_unspecified and not ip.is_multicast)):
        raise ValueError(
            f"LoopbackCallbackServer rejects bind address {host!r}; "
            "only literal loopback or private non-unspecified IP addresses are permitted"
        )
    return clean_host


def _validate_advertise_host(advertise_host: str) -> str:
    """Validate optional advertise_host as a clean hostname or IP (no scheme, path, port, whitespace, or '@')."""
    if advertise_host == "":
        return ""
    if not isinstance(advertise_host, str):
        raise ValueError(f"invalid advertise_host: {advertise_host!r}")
    if any(ch.isspace() or ord(ch) < 32 or ch == "\x7f" for ch in advertise_host):
        raise ValueError(f"advertise_host must not contain whitespace or control characters: {advertise_host!r}")
    if any(ch in _FORBIDDEN_ADVERTISE_CHARS for ch in advertise_host) or "%" in advertise_host:
        raise ValueError(f"advertise_host must be a bare hostname or IP address: {advertise_host!r}")

    try:
        ip = ipaddress.ip_address(advertise_host)
    except ValueError:
        ip = None

    if ip is not None:
        if ip.is_unspecified or ip.is_multicast:
            raise ValueError(f"advertise_host rejects unspecified or multicast IP: {advertise_host!r}")
        return advertise_host

    if ":" in advertise_host:
        raise ValueError(f"advertise_host must not include a scheme or port: {advertise_host!r}")
    if len(advertise_host) > 253 or advertise_host.startswith(".") or advertise_host.endswith("."):
        raise ValueError(f"invalid advertise_host hostname: {advertise_host!r}")
    labels = advertise_host.split(".")
    if not all(_HOSTNAME_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError(f"invalid advertise_host hostname: {advertise_host!r}")
    return advertise_host


class _LoopbackThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class _LoopbackIPv6ThreadingHTTPServer(_LoopbackThreadingHTTPServer):
    address_family = socket.AF_INET6


class LoopbackCallbackServer:
    """Thread-safe loopback-default HTTP callback server for webhook/SSRF/XXE verification."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        max_hits: int = DEFAULT_MAX_HITS,
        max_body_chars: int = DEFAULT_MAX_BODY_CHARS,
        allow_private_bridge: bool = False,
        advertise_host: str = "",
    ) -> None:
        allow_bridge = bool(allow_private_bridge)
        clean_host = _validate_bind_host(host, allow_private_bridge=allow_bridge)
        clean_advertise = _validate_advertise_host(advertise_host)
        port_num = int(port)
        if not (0 <= port_num <= 65535):
            raise ValueError(f"invalid port: {port!r}")
        self.host = clean_host
        self.allow_private_bridge = allow_bridge
        self.advertise_host = clean_advertise
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

    @classmethod
    def from_env(
        cls,
        *,
        port: int = 0,
        max_hits: int = DEFAULT_MAX_HITS,
        max_body_chars: int = DEFAULT_MAX_BODY_CHARS,
    ) -> LoopbackCallbackServer:
        """Create a callback server from optional CCO_OOB_BIND_HOST / CCO_OOB_ADVERTISE_HOST env vars."""
        bind_host = str(os.environ.get("CCO_OOB_BIND_HOST") or "").strip()
        advertise_host = str(os.environ.get("CCO_OOB_ADVERTISE_HOST") or "").strip()
        if not bind_host:
            return cls(
                host="127.0.0.1",
                port=port,
                max_hits=max_hits,
                max_body_chars=max_body_chars,
                allow_private_bridge=False,
                advertise_host=advertise_host,
            )
        allow_private = bind_host not in _ALLOWED_LOOPBACK_HOSTS
        return cls(
            host=bind_host,
            port=port,
            max_hits=max_hits,
            max_body_chars=max_body_chars,
            allow_private_bridge=allow_private,
            advertise_host=advertise_host,
        )

    @property
    def port(self) -> int:
        return self._bound_port

    @property
    def base_url(self) -> str:
        target_host = self.advertise_host or self.host
        host_fmt = f"[{target_host}]" if ":" in target_host else target_host
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
