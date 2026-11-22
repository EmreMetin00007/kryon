"""Thin scope-locked HTTP transport with WireBudget, multi-actor auth/CSRF, and GET dedup."""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import gzip
import json
import math
from pathlib import Path
import re
import socket
import sys
import threading
import time
from typing import Any, Callable, Sequence
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
import uuid
import zlib

import requests
from urllib3 import exceptions as urllib3_exceptions

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agentic_receipts import ReceiptStore  # noqa: E402
from kryon_core.protocol.grpc_web import decode_grpc_web_frames, is_grpc_web_content_type  # noqa: E402
from kryon_core.protocol.websocket_probe import probe_websocket  # noqa: E402
from target_bootstrap import ScopeGuard  # noqa: E402
from wire_budget import WireBudget  # noqa: E402

DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
STATIC_EXTENSIONS = frozenset({
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_AUTH_OVERRIDE_HEADERS = frozenset({"authorization", "cookie"})
_DEGRADATION_STATUS_CODES = frozenset({429, 502, 503, 504})
_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS = 5
_SSE_DEFAULT_MAX_BYTES = 16384
_SSE_DEFAULT_MAX_DURATION_S = 1.5
_MULTIPART_MAX_FILES = 8
_MULTIPART_MAX_FILE_BYTES = 256 * 1024
_MULTIPART_MAX_TOTAL_BYTES = 512 * 1024


class ScopeViolationError(ValueError):
    """Raised when a requested URL leaves the authorized target origin or hits an excluded path."""


class MethodNotAllowedError(ValueError):
    """Raised when an HTTP method is outside operator-allowed methods."""


class BudgetExhaustedError(RuntimeError):
    """Raised when WireBudget refuses another live HTTP request."""


class ServiceDegradationError(RuntimeError):
    """Raised when consecutive 429/502/503/504 or connection-error (status=0) responses indicate target degradation."""


def normalize_origin(raw_url: str) -> str:
    """Validate and normalize an explicit http(s) origin URL."""
    raw = str(raw_url or "").strip()
    if not raw:
        raise ValueError("target URL is required")
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"invalid origin URL: {raw_url!r}")
    if parsed.username or parsed.password:
        raise ValueError("target URL must not embed credentials")
    return f"{parsed.scheme}://{parsed.netloc}/"


def is_static_asset_url(url: str) -> bool:
    """Return True for static media/font/style assets skipped during discovery."""
    path = urlsplit(str(url or "")).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def _canonical_url(url: str) -> str:
    parsed = urlsplit(url)
    query_items = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    norm_query = urlencode(query_items, doseq=True)
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, norm_query, ""))


def _extract_token_from_auth(auth_header: str) -> str:
    parts = str(auth_header or "").strip().split(None, 1)
    return parts[1].strip() if len(parts) == 2 else ""


@dataclass
class ActorSession:
    """In-memory credentials and active session state for one actor."""

    alias: str
    role: str = "member"
    tenant: str = ""
    login_payload: dict[str, str] = field(default_factory=dict)
    login_graphql_query: str = ""
    password: str = ""
    base_headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    local_storage: dict[str, str] = field(default_factory=dict)
    access_token: str = ""
    refresh_token: str = ""
    csrf_token: str = ""
    authenticated: bool = False
    dynamic: bool = False
    source_receipt_id: str = ""
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False, compare=False)

    def collect_secrets(self) -> list[str]:
        with self._lock:
            secrets: list[str] = []
            for candidate in (self.password, self.access_token, self.refresh_token, self.csrf_token):
                if candidate and len(candidate) >= 4:
                    secrets.append(candidate)
            for k, v in self.base_headers.items():
                if k.lower() in {"authorization", "cookie", "x-api-key", "x-csrf-token"} and v:
                    secrets.append(v)
                    tok = _extract_token_from_auth(v)
                    if tok:
                        secrets.append(tok)
            for val in self.cookies.values():
                if val and len(val) >= 4:
                    secrets.append(val)
            for val in self.local_storage.values():
                if val and len(val) >= 4:
                    secrets.append(val)
            return secrets

    def build_headers(self, method: str, extra_headers: dict[str, str] | None = None) -> dict[str, str]:
        with self._lock:
            headers = dict(self.base_headers)
            if self.access_token and not any(k.lower() == "authorization" for k in headers):
                headers["Authorization"] = f"Bearer {self.access_token}"
            if self.cookies and not any(k.lower() == "cookie" for k in headers):
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in sorted(self.cookies.items()))
            if method.upper() in _MUTATING_METHODS and self.csrf_token:
                headers.setdefault("X-CSRF-Token", self.csrf_token)
            if extra_headers:
                for k, v in extra_headers.items():
                    key_str = str(k)
                    key_low = key_str.lower()
                    for existing_key in [ek for ek in headers if ek.lower() == key_low and ek != key_str]:
                        headers.pop(existing_key, None)
                    headers[key_str] = str(v)
            return headers


def _extract_session_material_from_response(
    *,
    headers: dict[str, str],
    cookies: dict[str, str],
    body_text: str,
) -> tuple[dict[str, str], str, str, str]:
    """Extract (cookies, bearer_token, refresh_token, csrf_token) from an HTTP response."""
    captured_cookies = {str(k): str(v) for k, v in (cookies or {}).items() if k and v}
    lower_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    csrf_token = (lower_headers.get("x-csrf-token-next") or lower_headers.get("x-csrf-token") or "").strip()
    bearer_token = ""
    auth_hdr = lower_headers.get("authorization", "").strip()
    if auth_hdr:
        bearer_token = _extract_token_from_auth(auth_hdr)
    refresh_token = ""

    stripped = (body_text or "").lstrip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(body_text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            candidates: list[dict[str, Any]] = [parsed]
            for subkey in ("data", "session", "auth", "user"):
                sub = parsed.get(subkey)
                if isinstance(sub, dict):
                    candidates.append(sub)
            # Support GraphQL mutation responses such as {"data": {"login": {"access_token": ...}}}.
            data_obj = parsed.get("data")
            if isinstance(data_obj, dict):
                nested_count = 0
                for sub_val in data_obj.values():
                    if isinstance(sub_val, dict):
                        candidates.append(sub_val)
                        nested_count += 1
                        if nested_count >= 8:
                            break
            for obj in candidates:
                if not bearer_token:
                    for tkey in (
                        "access_token",
                        "accessToken",
                        "token",
                        "jwt",
                        "id_token",
                        "idToken",
                        "auth_token",
                        "authToken",
                        "bearer_token",
                        "bearerToken",
                    ):
                        val = obj.get(tkey)
                        if isinstance(val, str) and val.strip():
                            bearer_token = val.strip()
                            break
                if not refresh_token:
                    for rkey in ("refresh_token", "refreshToken"):
                        ref_val = obj.get(rkey)
                        if isinstance(ref_val, str) and ref_val.strip():
                            refresh_token = ref_val.strip()
                            break
                if not csrf_token:
                    for ckey in ("csrf_token", "csrfToken", "csrf", "xsrf_token", "xsrfToken"):
                        cval = obj.get(ckey)
                        if isinstance(cval, str) and cval.strip():
                            csrf_token = cval.strip()
                            break
    elif body_text and ("<meta" in body_text.lower() or "csrf" in body_text.lower()):
        if not csrf_token:
            for pattern in (
                r'<meta[^>]+name=["\'](?:csrf-token|xsrf-token)["\'][^>]+content=["\']([^"\']+)["\']',
                r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\'](?:csrf-token|xsrf-token)["\']',
                r'<input[^>]+name=["\'](?:csrf_token|_csrf|csrf)["\'][^>]+value=["\']([^"\']+)["\']',
                r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\'](?:csrf_token|_csrf|csrf)["\']',
            ):
                match = re.search(pattern, body_text, re.IGNORECASE)
                if match and match.group(1).strip():
                    csrf_token = match.group(1).strip()
                    break

    if not csrf_token and captured_cookies:
        lower_cookies = {k.lower(): v for k, v in captured_cookies.items()}
        for ckey in ("csrftoken", "csrf_token", "xsrf-token", "xsrf_token", "_csrf"):
            cval = (lower_cookies.get(ckey) or "").strip()
            if cval:
                csrf_token = cval
                break

    return captured_cookies, bearer_token, refresh_token, csrf_token


class ActorManager:
    """Manage multi-actor sessions, keeping credentials strictly in harness memory."""

    def __init__(
        self,
        accounts: Sequence[dict[str, Any]] = (),
        *,
        login_path: str = "/api/v1/access/sign-in",
        session_check_path: str = "/api/v1/access/session",
        refresh_path: str = "/api/v1/access/refresh",
    ):
        self.login_path = login_path
        self.session_check_path = session_check_path
        self.refresh_path = refresh_path
        self._lock = threading.Lock()
        self.actors: dict[str, ActorSession] = {
            "anon": ActorSession(alias="anon", role="anonymous", tenant="", authenticated=True)
        }
        for raw in accounts:
            if not isinstance(raw, dict) or not raw.get("alias"):
                continue
            alias = str(raw["alias"]).strip()
            if not alias or alias == "anon":
                continue
            base_headers: dict[str, str] = {}
            if isinstance(raw.get("headers"), dict):
                base_headers.update({str(k): str(v) for k, v in raw["headers"].items() if k and v is not None})
            if isinstance(raw.get("auth_header"), str) and raw["auth_header"].strip():
                base_headers.setdefault("Authorization", raw["auth_header"].strip())
            access_token = str(raw.get("session_token") or raw.get("access_token") or "").strip()
            if not access_token and "Authorization" in base_headers:
                access_token = _extract_token_from_auth(base_headers["Authorization"])
            cookies: dict[str, str] = {}
            if isinstance(raw.get("cookies"), dict):
                cookies.update({str(k): str(v) for k, v in raw["cookies"].items() if k and v is not None})
            if isinstance(raw.get("cookie"), str) and raw["cookie"].strip():
                base_headers.setdefault("Cookie", raw["cookie"].strip())
            local_storage: dict[str, str] = {}
            if isinstance(raw.get("local_storage"), dict):
                for lk, lv in raw["local_storage"].items():
                    if isinstance(lk, str) and isinstance(lv, str) and lk.strip():
                        local_storage[lk.strip()] = lv
            login_graphql_query = str(raw.get("login_graphql_query") or "").strip()
            password = str(raw.get("password") or "")
            login_payload: dict[str, str] = {}
            if password:
                login_payload["password"] = password
                for key in ("work_email", "email", "username"):
                    val = raw.get(key)
                    if isinstance(val, str) and val.strip():
                        login_payload[key] = val.strip()
                        break
            has_preauth = bool(base_headers or access_token or cookies or local_storage)
            self.actors[alias] = ActorSession(
                alias=alias,
                role=str(raw.get("role") or "member").strip() or "member",
                tenant=str(raw.get("tenant") or "").strip(),
                login_payload=login_payload,
                login_graphql_query=login_graphql_query,
                password=password,
                base_headers=base_headers,
                cookies=cookies,
                local_storage=local_storage,
                access_token=access_token,
                csrf_token=str(raw.get("csrf_token") or "").strip(),
                authenticated=has_preauth,
            )

    def get(self, alias: str) -> ActorSession:
        key = str(alias or "anon").strip() or "anon"
        with self._lock:
            if key not in self.actors:
                raise ValueError(f"unknown actor alias: {alias!r}; available: {sorted(self.actors)}")
            return self.actors[key]

    def summaries(self) -> list[dict[str, str]]:
        """Return public non-secret actor metadata safe to show the LLM."""
        with self._lock:
            return [
                {"alias": s.alias, "role": s.role, "tenant": s.tenant}
                for s in self.actors.values()
            ]

    def all_secrets(self) -> list[str]:
        with self._lock:
            sessions = list(self.actors.values())
        secrets: list[str] = []
        for session in sessions:
            secrets.extend(session.collect_secrets())
        return secrets

    def register_dynamic_session(
        self,
        alias: str,
        *,
        role: str = "member",
        tenant: str = "",
        cookies: dict[str, str] | None = None,
        bearer_token: str | None = None,
        refresh_token: str | None = None,
        csrf_token: str | None = None,
        source_receipt_id: str = "",
        base_headers: dict[str, str] | None = None,
    ) -> ActorSession:
        """Register or update a dynamic session strictly in harness memory (never exposing secrets)."""
        clean_alias = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(alias or "").strip())[:48]
        if not clean_alias or clean_alias == "anon":
            raise ValueError(f"invalid dynamic session alias: {alias!r}")
        clean_cookies = {str(k): str(v) for k, v in (cookies or {}).items() if k and v}
        clean_bearer = str(bearer_token or "").strip()
        clean_refresh = str(refresh_token or "").strip()
        clean_csrf = str(csrf_token or "").strip()
        clean_headers = {str(k): str(v) for k, v in (base_headers or {}).items() if k and v}
        is_auth = bool(clean_cookies or clean_bearer or clean_headers)
        with self._lock:
            existing = self.actors.get(clean_alias)
            if existing is not None:
                with existing._lock:
                    existing.cookies.update(clean_cookies)
                    if clean_bearer:
                        existing.access_token = clean_bearer
                        existing.base_headers.pop("Authorization", None)
                    if clean_refresh:
                        existing.refresh_token = clean_refresh
                    if clean_csrf:
                        existing.csrf_token = clean_csrf
                    if clean_headers:
                        existing.base_headers.update(clean_headers)
                    if role:
                        existing.role = str(role).strip() or existing.role
                    if tenant:
                        existing.tenant = str(tenant).strip()
                    if source_receipt_id:
                        existing.source_receipt_id = str(source_receipt_id)
                    existing.authenticated = bool(existing.authenticated or is_auth)
                    existing.dynamic = True
                return existing
            session = ActorSession(
                alias=clean_alias,
                role=str(role or "member").strip() or "member",
                tenant=str(tenant or "").strip(),
                base_headers=clean_headers,
                cookies=clean_cookies,
                access_token=clean_bearer,
                refresh_token=clean_refresh,
                csrf_token=clean_csrf,
                authenticated=is_auth,
                dynamic=True,
                source_receipt_id=str(source_receipt_id or ""),
            )
            self.actors[clean_alias] = session
            return session

    def set_source_receipt_id(self, alias: str, receipt_id: str) -> None:
        with self._lock:
            session = self.actors.get(alias)
        if session is not None:
            with session._lock:
                session.source_receipt_id = str(receipt_id or "")

    def update_from_response(
        self,
        alias: str,
        *,
        headers: dict[str, str],
        cookies: dict[str, str],
        body_text: str,
    ) -> None:
        """Capture rotated CSRF tokens, refreshed tokens, and session cookies."""
        if alias == "anon":
            return
        with self._lock:
            session = self.actors.get(alias)
        if session is None:
            return
        cap_cookies, cap_bearer, cap_refresh, cap_csrf = _extract_session_material_from_response(
            headers=headers,
            cookies=cookies,
            body_text=body_text,
        )
        with session._lock:
            for k, v in cap_cookies.items():
                session.cookies[k] = v
            if cap_csrf:
                session.csrf_token = cap_csrf
            if cap_bearer:
                session.access_token = cap_bearer
                session.base_headers.pop("Authorization", None)
                session.authenticated = True
            if cap_refresh:
                session.refresh_token = cap_refresh

    def get_browser_auth_state(self, actor_alias: str) -> dict[str, Any]:
        """Return host-side cookies, auth headers, and local_storage for browser contexts (never expose to LLM)."""
        session = self.get(actor_alias)
        if session.alias == "anon":
            return {"cookies": {}, "headers": {}}
        with session._lock:
            if not session.authenticated:
                return {"cookies": {}, "headers": {}}
            cookies: dict[str, str] = dict(session.cookies)
            auth_headers: dict[str, str] = {}
            for key, val in session.base_headers.items():
                if key.lower() == "cookie":
                    for part in str(val).split(";"):
                        if "=" in part:
                            ck, cv = part.split("=", 1)
                            ck_clean = ck.strip()
                            cv_clean = cv.strip()
                            if ck_clean and cv_clean:
                                cookies.setdefault(ck_clean, cv_clean)
                else:
                    auth_headers[str(key)] = str(val)
            if session.access_token and not any(k.lower() == "authorization" for k in auth_headers):
                auth_headers["Authorization"] = f"Bearer {session.access_token}"
            if session.csrf_token and not any(k.lower() == "x-csrf-token" for k in auth_headers):
                auth_headers["X-CSRF-Token"] = session.csrf_token
            state: dict[str, Any] = {"cookies": cookies, "headers": auth_headers}
            if session.local_storage:
                state["local_storage"] = dict(session.local_storage)
            return state


def _get_raw_socket(raw_stream: Any) -> Any:
    """Best-effort unwrap of the underlying socket from a urllib3/http.client stream."""
    for attr in ("_connection", "connection"):
        conn = getattr(raw_stream, attr, None)
        sock = getattr(conn, "sock", None)
        if sock is not None and callable(getattr(sock, "settimeout", None)):
            return sock
    fp = getattr(raw_stream, "_fp", None)
    fp_inner = getattr(fp, "fp", None)
    raw_sock = getattr(getattr(fp_inner, "raw", None), "_sock", None)
    if raw_sock is not None and callable(getattr(raw_sock, "settimeout", None)):
        return raw_sock
    return None


def _read_sse_bounded(
    resp: Any,
    max_bytes: int = _SSE_DEFAULT_MAX_BYTES,
    max_duration_s: float = _SSE_DEFAULT_MAX_DURATION_S,
) -> bytes:
    """Read an open-ended text/event-stream response up to byte or wall-time bounds.

    Captures an initial event preview without hanging until the full HTTP timeout
    and closes unfinished streams cleanly so status remains intact (e.g. 200).
    """
    cap = max(0, int(max_bytes))
    dur = max(0.01, float(max_duration_s))
    raw = getattr(resp, "raw", None)
    if raw is None or cap == 0:
        return b""

    buf = bytearray()
    deadline = time.monotonic() + dur
    sock = _get_raw_socket(raw)
    orig_timeout: float | None = None
    if sock is not None:
        try:
            orig_timeout = sock.gettimeout()
        except OSError:
            orig_timeout = None

    eof_reached = False
    timed_out = False
    timeout_exc_types: tuple[type[BaseException], ...] = (
        TimeoutError,
        socket.timeout,
        requests.exceptions.ReadTimeout,
        urllib3_exceptions.ReadTimeoutError,
        urllib3_exceptions.TimeoutError,
    )

    try:
        is_chunked = bool(getattr(raw, "chunked", False))
        supports_chunked = callable(getattr(raw, "supports_chunked_reads", None)) and raw.supports_chunked_reads()
        if is_chunked and supports_chunked and callable(getattr(raw, "read_chunked", None)):
            if sock is not None:
                try:
                    sock.settimeout(max(0.01, deadline - time.monotonic()))
                except OSError:
                    pass
            for chunk in raw.read_chunked(amt=min(4096, cap), decode_content=False):
                if not chunk:
                    break
                take = cap - len(buf)
                if len(chunk) >= take:
                    buf.extend(chunk[:take])
                    break
                buf.extend(chunk)
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    break
                if sock is not None:
                    try:
                        sock.settimeout(max(0.01, remaining))
                    except OSError:
                        pass
            else:
                eof_reached = True
        else:
            read_fn = getattr(raw, "read1", None) or getattr(raw, "read", None)
            if callable(read_fn):
                while len(buf) < cap:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0.0:
                        break
                    if sock is not None:
                        try:
                            sock.settimeout(max(0.01, remaining))
                        except OSError:
                            pass
                    to_read = min(4096, cap - len(buf))
                    try:
                        chunk = read_fn(to_read, decode_content=False)
                    except TypeError:
                        chunk = read_fn(to_read)
                    if not chunk:
                        eof_reached = True
                        break
                    take = cap - len(buf)
                    buf.extend(chunk[:take])
    except timeout_exc_types:
        timed_out = True
    except (urllib3_exceptions.ProtocolError, OSError):
        # Partial stream close / reset after headers were received -> keep captured bytes.
        pass
    finally:
        if eof_reached and not timed_out and sock is not None:
            try:
                sock.settimeout(orig_timeout)
            except OSError:
                pass
        else:
            close_raw = getattr(raw, "close", None)
            if callable(close_raw):
                try:
                    close_raw()
                except Exception:
                    pass

    return bytes(buf)


def _decode_raw_response(raw_bytes: bytes, content_encoding: str) -> bytes:
    """Best-effort decompression that survives mismatched gzip headers."""
    enc = (content_encoding or "").strip().lower()
    if enc == "gzip":
        try:
            return gzip.decompress(raw_bytes)
        except (OSError, EOFError, zlib.error):
            return raw_bytes
    if enc == "deflate":
        try:
            return zlib.decompress(raw_bytes)
        except zlib.error:
            try:
                return zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
            except zlib.error:
                return raw_bytes
    return raw_bytes


def _sanitize_multipart_header_value(raw: str, *, label: str) -> str:
    """Validate and strip CR/LF from multipart header metadata, rejecting NUL bytes."""
    if "\x00" in raw:
        raise ValueError(f"multipart {label} must not contain NUL bytes")
    return raw.replace("\r", "").replace("\n", "")


def _encode_multipart_form_data(
    files: Sequence[dict[str, Any]],
    form_fields: dict[str, Any] | None = None,
) -> tuple[bytes, str, str]:
    """Encode files and optional form fields as RFC 7578 multipart/form-data.

    Returns ``(body_bytes, content_type_header, body_preview)`` where ``body_preview``
    is a compact summary string that never dumps raw binary bytes into receipts.
    """
    if isinstance(files, (str, bytes, bytearray, dict)) or not isinstance(files, Sequence):
        raise ValueError("files must be a list of file objects")
    if len(files) == 0:
        raise ValueError("files must contain at least one file entry")
    if len(files) > _MULTIPART_MAX_FILES:
        raise ValueError(
            f"multipart files count {len(files)} exceeds limit of {_MULTIPART_MAX_FILES}"
        )
    if form_fields is not None and not isinstance(form_fields, dict):
        raise ValueError("form_fields must be a dict when used with multipart files")

    boundary = f"----kryonBoundary{uuid.uuid4().hex}"
    boundary_bytes = boundary.encode("ascii")
    closing = b"--" + boundary_bytes + b"--\r\n"

    parts: list[bytes] = []
    total_size = len(closing)
    form_field_names: list[str] = []
    file_summaries: list[dict[str, Any]] = []

    if form_fields:
        for raw_k, raw_v in form_fields.items():
            clean_key = _sanitize_multipart_header_value(str(raw_k), label="form field name").strip()
            if not clean_key:
                raise ValueError("multipart form field name must not be empty")
            escaped_key = clean_key.replace('"', '\\"')
            val_bytes = ("" if raw_v is None else str(raw_v)).encode("utf-8")
            part = (
                b"--" + boundary_bytes + b"\r\n"
                + f'Content-Disposition: form-data; name="{escaped_key}"\r\n\r\n'.encode("utf-8")
                + val_bytes + b"\r\n"
            )
            total_size += len(part)
            if total_size > _MULTIPART_MAX_TOTAL_BYTES:
                raise ValueError(
                    f"multipart payload size {total_size} exceeds total limit of {_MULTIPART_MAX_TOTAL_BYTES} bytes"
                )
            parts.append(part)
            form_field_names.append(clean_key)

    for idx, item in enumerate(files):
        if not isinstance(item, dict):
            raise ValueError(f"multipart file entry at index {idx} must be a dict")
        raw_field = "file" if item.get("field") is None else str(item["field"])
        clean_field = _sanitize_multipart_header_value(raw_field, label="field").strip() or "file"
        escaped_field = clean_field.replace('"', '\\"')

        raw_filename = "upload.bin" if item.get("filename") is None else str(item["filename"])
        clean_filename = _sanitize_multipart_header_value(raw_filename, label="filename")
        if not clean_filename.strip():
            clean_filename = "upload.bin"
        escaped_filename = clean_filename.replace('"', '\\"')

        raw_ct = "application/octet-stream" if item.get("content_type") is None else str(item["content_type"])
        clean_ct = _sanitize_multipart_header_value(raw_ct, label="content_type").strip() or "application/octet-stream"

        has_text = item.get("content") is not None
        has_b64 = item.get("content_base64") is not None
        if has_text and has_b64:
            raise ValueError(
                f"multipart file entry at index {idx} cannot specify both 'content' and 'content_base64'"
            )
        if has_b64:
            b64_val = item["content_base64"]
            if not isinstance(b64_val, str):
                raise ValueError(f"multipart file entry at index {idx} content_base64 must be a string")
            compact_b64 = "".join(b64_val.split())
            if len(compact_b64) > ((_MULTIPART_MAX_FILE_BYTES + 3) * 4 // 3) + 4:
                raise ValueError(
                    f"multipart file {clean_filename!r} exceeds per-file limit of {_MULTIPART_MAX_FILE_BYTES} bytes"
                )
            try:
                file_bytes = base64.b64decode(compact_b64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError(
                    f"invalid base64 in multipart file {clean_filename!r}: {exc}"
                ) from exc
        elif has_text:
            raw_content = item["content"]
            if isinstance(raw_content, (bytes, bytearray)):
                file_bytes = bytes(raw_content)
            else:
                file_bytes = str(raw_content).encode("utf-8")
        else:
            file_bytes = b""

        if len(file_bytes) > _MULTIPART_MAX_FILE_BYTES:
            raise ValueError(
                f"multipart file {clean_filename!r} size {len(file_bytes)} "
                f"exceeds per-file limit of {_MULTIPART_MAX_FILE_BYTES} bytes"
            )

        part = (
            b"--" + boundary_bytes + b"\r\n"
            + f'Content-Disposition: form-data; name="{escaped_field}"; filename="{escaped_filename}"\r\n'.encode("utf-8")
            + f"Content-Type: {clean_ct}\r\n\r\n".encode("utf-8")
            + file_bytes + b"\r\n"
        )
        total_size += len(part)
        if total_size > _MULTIPART_MAX_TOTAL_BYTES:
            raise ValueError(
                f"multipart payload size {total_size} exceeds total limit of {_MULTIPART_MAX_TOTAL_BYTES} bytes"
            )
        parts.append(part)
        file_summaries.append({
            "field": clean_field,
            "filename": clean_filename,
            "content_type": clean_ct,
            "bytes": len(file_bytes),
        })

    parts.append(closing)
    body_bytes = b"".join(parts)
    preview_doc: dict[str, Any] = {"files": file_summaries}
    if form_field_names:
        preview_doc["fields"] = form_field_names
    body_preview = f"multipart/form-data {json.dumps(preview_doc, ensure_ascii=False, separators=(',', ':'))}"
    return body_bytes, f"multipart/form-data; boundary={boundary}", body_preview


class AgenticHTTPClient:
    """Scope-locked, WireBudget-accounted HTTP/WS client with dedup, pacing, and auto re-auth."""

    def __init__(
        self,
        *,
        base_url: str,
        receipt_store: ReceiptStore,
        actors: ActorManager | None = None,
        allowed_methods: Sequence[str] = ("GET", "HEAD"),
        max_requests: int = 300,
        wire_budget: WireBudget | None = None,
        timeout_s: float = 15.0,
        max_response_bytes: int = 4 * 1024 * 1024,
        excluded_paths: Sequence[str] = (),
        max_degradation_streak: int = 5,
        max_rps: float = 0.0,
        _sleep_fn: Callable[[float], None] | None = None,
        _monotonic_fn: Callable[[], float] | None = None,
    ):
        if isinstance(max_rps, bool):
            raise ValueError("max_rps must be a finite number >= 0.0")
        eff_max_rps = float(max_rps)
        if not math.isfinite(eff_max_rps) or eff_max_rps < 0.0:
            raise ValueError(f"max_rps must be a finite number >= 0.0, got {max_rps!r}")

        self.base_url = normalize_origin(base_url)
        parsed_origin = urlsplit(self.base_url)
        self._origin = (parsed_origin.scheme, parsed_origin.netloc)
        self.scope_guard = ScopeGuard(self.base_url, tuple(excluded_paths or ()))
        self.excluded_paths: tuple[str, ...] = self.scope_guard.excluded_paths
        self.max_degradation_streak: int = max(0, int(max_degradation_streak))
        self._degradation_streak: int = 0
        self.max_rps: float = eff_max_rps
        self._sleep_fn: Callable[[float], None] = _sleep_fn or time.sleep
        self._monotonic_fn: Callable[[], float] = _monotonic_fn or time.monotonic
        self._rate_lock = threading.Lock()
        self._next_allowed_at: float | None = None
        self.receipt_store = receipt_store
        self.actors = actors or ActorManager()
        self.allowed_methods = frozenset(
            str(m).strip().upper() for m in allowed_methods if str(m).strip()
        ) or frozenset({"GET"})
        self.budget = wire_budget or WireBudget(int(max_requests), uuid.uuid4().hex)
        self.timeout_s = float(timeout_s)
        self.max_response_bytes = int(max_response_bytes)
        self._thread_local = threading.local()
        self._sessions: list[requests.Session] = []
        self._sessions_lock = threading.Lock()
        self._cache: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._auth_lock = threading.Lock()

    def _acquire_rate_limit_slot(self) -> None:
        """Pace live wire calls monotonically to stay at or below self.max_rps."""
        if self.max_rps <= 0.0:
            return
        interval = 1.0 / self.max_rps
        with self._rate_lock:
            now = float(self._monotonic_fn())
            if self._next_allowed_at is None or now >= self._next_allowed_at:
                scheduled = now
            else:
                scheduled = self._next_allowed_at
            self._next_allowed_at = scheduled + interval
            wait_s = scheduled - now
        if wait_s > 0.0:
            self._sleep_fn(wait_s)

    def _get_session(self) -> requests.Session:
        sess = getattr(self._thread_local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.trust_env = False
            sess.headers["User-Agent"] = DEFAULT_BROWSER_USER_AGENT
            self._thread_local.session = sess
            with self._sessions_lock:
                self._sessions.append(sess)
        return sess

    def close(self) -> None:
        with self._sessions_lock:
            sessions = list(self._sessions)
            self._sessions.clear()
        for sess in sessions:
            try:
                sess.close()
            except Exception:
                pass
        if hasattr(self._thread_local, "session"):
            try:
                delattr(self._thread_local, "session")
            except AttributeError:
                pass

    def resolve_in_scope(
        self,
        url_or_path: str,
        *,
        allow_websocket: bool = True,
    ) -> tuple[str, str, str]:
        """Resolve relative path or URL and verify exact origin match and excluded paths."""
        raw = str(url_or_path or "").strip()
        if not raw:
            raise ScopeViolationError("URL is required")
        if raw.startswith("//"):
            raise ScopeViolationError(f"scheme-relative cross-origin URL blocked: {raw}")
        if any(ch in raw for ch in ("\x00", "\r", "\n")):
            raise ScopeViolationError(f"URL contains control characters: {raw!r}")

        lower_raw = raw.lower()
        if lower_raw.startswith(("ws://", "wss://")):
            if not allow_websocket:
                raise ScopeViolationError(
                    f"WebSocket URL not allowed in HTTP context: {raw!r}"
                )
            parsed_ws = urlsplit(raw)
            ws_scheme = parsed_ws.scheme.lower()
            if parsed_ws.username is not None or parsed_ws.password is not None or "@" in parsed_ws.netloc:
                raise ScopeViolationError(f"WebSocket URL must not embed credentials: {raw!r}")
            expected_http_scheme = "http" if ws_scheme == "ws" else "https"
            ws_host = (parsed_ws.hostname or "").strip().lower().rstrip(".")
            default_port = 443 if ws_scheme == "wss" else 80
            try:
                ws_port = parsed_ws.port if parsed_ws.port is not None else default_port
            except ValueError as exc:
                raise ScopeViolationError(f"invalid WebSocket port in {raw!r}") from exc
            if (expected_http_scheme, ws_host, ws_port) != self.scope_guard._origin_key:
                raise ScopeViolationError(
                    f"out-of-scope WebSocket URL {raw!r}; allowed origin is {self.base_url}"
                )
            ws_path = parsed_ws.path or "/"
            equiv_http_url = urlunsplit((expected_http_scheme, self._origin[1], ws_path, parsed_ws.query, ""))
            try:
                self.scope_guard.check_url(equiv_http_url)
            except ValueError as exc:
                raise ScopeViolationError(str(exc)) from exc
            clean_ws_url = urlunsplit((ws_scheme, parsed_ws.netloc, ws_path, parsed_ws.query, ""))
            return clean_ws_url, ws_path, parsed_ws.query

        resolved = urljoin(self.base_url, raw)
        parsed = urlsplit(resolved)
        if (parsed.scheme, parsed.netloc) != self._origin:
            raise ScopeViolationError(
                f"out-of-scope URL {resolved!r}; allowed origin is {self.base_url}"
            )
        clean_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        try:
            self.scope_guard.check_url(clean_url)
        except ValueError as exc:
            raise ScopeViolationError(str(exc)) from exc
        return clean_url, parsed.path or "/", parsed.query

    def _merge_query(
        self,
        url: str,
        query_params: dict[str, Any] | None,
        *,
        allow_websocket: bool = True,
    ) -> tuple[str, str, str]:
        if not query_params:
            return self.resolve_in_scope(url, allow_websocket=allow_websocket)
        clean_url, _, _ = self.resolve_in_scope(url, allow_websocket=allow_websocket)
        parsed = urlsplit(clean_url)
        existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
        for k, v in query_params.items():
            if v is None:
                existing.pop(str(k), None)
            else:
                existing[str(k)] = str(v)
        new_query = urlencode(sorted(existing.items()))
        rebuilt = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", new_query, ""))
        return self.resolve_in_scope(rebuilt, allow_websocket=allow_websocket)

    def _record_degradation_status(self, *, status: int, url: str) -> None:
        """Track consecutive degraded/unreachable responses (status=0 or 429/502/503/504) and stop gracefully."""
        if self.max_degradation_streak <= 0 or status < 0:
            return
        streak = 0
        with self._lock:
            if status == 0 or status in _DEGRADATION_STATUS_CODES:
                self._degradation_streak += 1
                streak = self._degradation_streak
            else:
                self._degradation_streak = 0
        if streak >= self.max_degradation_streak:
            raise ServiceDegradationError(
                f"target service degradation detected after {streak} consecutive "
                f"degraded/unreachable responses (status={status}, url={url})"
            )

    def _send_wire(
        self,
        *,
        actor: str,
        method: str,
        url: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body_bytes: bytes | None,
        body_preview: str,
        record_receipt: bool = True,
        save_session_as: str = "",
        out_cookies: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        allowed, reason = self.budget.consume()
        if not allowed:
            raise BudgetExhaustedError(reason)

        self._acquire_rate_limit_slot()

        wire_headers = dict(headers)
        if not any(k.lower() == "user-agent" for k in wire_headers):
            wire_headers["User-Agent"] = DEFAULT_BROWSER_USER_AGENT

        started = time.monotonic()
        status = 0
        resp_headers: dict[str, str] = {}
        raw_bytes = b""
        text = ""
        content_type = ""
        redirect_location = ""
        error = ""
        saved_session_meta: dict[str, Any] | None = None

        try:
            # Clear thread-local session cookie jar before & after each wire call so per-actor
            # cookies (managed strictly via ActorSession.build_headers) never leak across actors.
            http_session = self._get_session()
            http_session.cookies.clear()
            # Read raw stream directly so mismatched Content-Encoding never crashes requests.
            resp = http_session.request(
                method=method,
                url=url,
                headers=wire_headers,
                data=body_bytes,
                allow_redirects=False,
                timeout=self.timeout_s,
                stream=True,
            )
            try:
                status = int(resp.status_code)
                resp_headers = {str(k): str(v) for k, v in resp.headers.items()}
                content_type = resp_headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                redirect_location = resp_headers.get("Location", "")
                if content_type == "text/event-stream":
                    raw_stream = _read_sse_bounded(
                        resp,
                        max_bytes=min(_SSE_DEFAULT_MAX_BYTES, self.max_response_bytes),
                        max_duration_s=min(_SSE_DEFAULT_MAX_DURATION_S, max(0.05, self.timeout_s)),
                    )
                else:
                    raw_stream = resp.raw.read(self.max_response_bytes + 1, decode_content=False)
                    if len(raw_stream) > self.max_response_bytes:
                        raw_stream = raw_stream[: self.max_response_bytes]
                raw_bytes = _decode_raw_response(raw_stream, resp_headers.get("Content-Encoding", ""))
                if is_grpc_web_content_type(content_type):
                    decoded_grpc = decode_grpc_web_frames(raw_bytes, content_type=content_type)
                    text = json.dumps(decoded_grpc, ensure_ascii=False)
                else:
                    text = raw_bytes.decode("utf-8", errors="replace")
                cookies = {c.name: c.value for c in resp.cookies}
                if not cookies and "Set-Cookie" in resp_headers:
                    for part in resp_headers["Set-Cookie"].split(","):
                        nv = part.strip().split(";", 1)[0]
                        if "=" in nv:
                            ck, cv = nv.split("=", 1)
                            if ck.strip() and cv.strip() and ck.strip().lower() not in {"path", "expires", "max-age", "domain", "samesite"}:
                                cookies[ck.strip()] = cv.strip()
                if out_cookies is not None and cookies:
                    out_cookies.update(cookies)
                http_session.cookies.clear()
                clean_save_alias = str(save_session_as or "").strip()
                if clean_save_alias and clean_save_alias != "anon" and 200 <= status < 400:
                    cap_cookies, cap_bearer, cap_refresh, cap_csrf = _extract_session_material_from_response(
                        headers=resp_headers,
                        cookies=cookies,
                        body_text=text,
                    )
                    if cap_cookies or cap_bearer or cap_csrf:
                        dyn = self.actors.register_dynamic_session(
                            clean_save_alias,
                            cookies=cap_cookies,
                            bearer_token=cap_bearer,
                            refresh_token=cap_refresh,
                            csrf_token=cap_csrf,
                        )
                        saved_session_meta = {
                            "alias": dyn.alias,
                            "role": dyn.role,
                            "authenticated": dyn.authenticated,
                            "has_cookies": bool(dyn.cookies),
                            "has_bearer": bool(dyn.access_token),
                            "has_csrf": bool(dyn.csrf_token),
                        }
                elif not clean_save_alias:
                    self.actors.update_from_response(
                        actor, headers=resp_headers, cookies=cookies, body_text=text
                    )
            finally:
                http_session.cookies.clear()
                resp.close()
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:200]}"

        elapsed_ms = (time.monotonic() - started) * 1000.0
        if not record_receipt:
            self._record_degradation_status(status=int(status), url=str(url))
            graphql_has_errors = False
            stripped_body = text.lstrip()
            if stripped_body.startswith("{"):
                try:
                    parsed_auth = json.loads(text)
                except ValueError:
                    parsed_auth = None
                if isinstance(parsed_auth, dict) and isinstance(parsed_auth.get("errors"), list) and parsed_auth["errors"]:
                    graphql_has_errors = True
            return {
                "receipt_id": "",
                "actor": str(actor or "anon"),
                "method": str(method or "GET").upper(),
                "url": str(url),
                "path": str(path or "/"),
                "query": str(query or ""),
                "status": int(status),
                "elapsed_ms": round(float(elapsed_ms), 2),
                "content_type": str(content_type or ""),
                "response_length": len(raw_bytes),
                "redirect_location": redirect_location,
                "body": "",
                "error": str(error or ""),
                "_body_mentions_csrf": "csrf" in text.lower(),
                "_graphql_has_errors": graphql_has_errors,
            }
        rec = self.receipt_store.record(
            actor=actor,
            method=method,
            url=url,
            path=path,
            query=query,
            request_headers=wire_headers,
            request_body=body_preview,
            status=status,
            elapsed_ms=elapsed_ms,
            content_type=content_type,
            response_headers=resp_headers,
            redirect_location=redirect_location,
            raw_response_bytes=raw_bytes,
            response_text=text,
            error=error,
            secret_values=self.actors.all_secrets(),
        )
        if saved_session_meta is not None:
            self.actors.set_source_receipt_id(saved_session_meta["alias"], rec["receipt_id"])
            saved_session_meta["source_receipt_id"] = rec["receipt_id"]
            rec = dict(rec)
            rec["saved_session"] = saved_session_meta
        self._record_degradation_status(status=int(status), url=str(url))
        return rec

    def _send_websocket_wire(
        self,
        *,
        actor: str,
        url: str,
        path: str,
        query: str,
        headers: dict[str, str],
        send_messages: Sequence[str] | None,
        body_preview: str,
    ) -> dict[str, Any]:
        """Execute a scope-verified, budgeted, rate-limited RFC-6455 WebSocket probe."""
        allowed, reason = self.budget.consume()
        if not allowed:
            raise BudgetExhaustedError(reason)

        self._acquire_rate_limit_slot()

        wire_headers = dict(headers)
        if not any(k.lower() == "user-agent" for k in wire_headers):
            wire_headers["User-Agent"] = DEFAULT_BROWSER_USER_AGENT
        if not any(k.lower() == "origin" for k in wire_headers):
            wire_headers["Origin"] = self.base_url.rstrip("/")

        started = time.monotonic()
        ws_result = probe_websocket(
            url,
            headers=wire_headers,
            send_messages=send_messages,
            timeout_s=min(self.timeout_s, 5.0),
        )
        elapsed_ms = (time.monotonic() - started) * 1000.0

        status = int(ws_result.get("status") or 0)
        resp_headers = ws_result.get("response_headers")
        if not isinstance(resp_headers, dict):
            resp_headers = {}
        err_text = str(ws_result.get("error") or "")
        summary_doc = {
            "upgraded": bool(ws_result.get("upgraded")),
            "frames_received": ws_result.get("frames_received") or [],
            "close_code": ws_result.get("close_code"),
            "error": err_text,
        }
        summary_text = json.dumps(summary_doc, ensure_ascii=False)
        summary_bytes = summary_text.encode("utf-8")

        rec = self.receipt_store.record(
            actor=actor,
            method="WS",
            url=url,
            path=path,
            query=query,
            request_headers=wire_headers,
            request_body=body_preview,
            status=status,
            elapsed_ms=elapsed_ms,
            content_type="application/json",
            response_headers={str(k): str(v) for k, v in resp_headers.items()},
            redirect_location="",
            raw_response_bytes=summary_bytes,
            response_text=summary_text,
            error=err_text,
            secret_values=self.actors.all_secrets(),
        )
        self._record_degradation_status(status=status, url=url)
        return rec

    def _budget_remaining(self) -> int:
        lock = getattr(self.budget, "_lock", None)
        if lock is not None:
            with lock:
                return int(self.budget.limit - self.budget.used)
        return int(self.budget.limit - self.budget.used)

    def authenticate_actor(self, alias: str, *, force_login: bool = False) -> bool:
        """Sign in an actor via configured login_path if not yet authenticated."""
        session = self.actors.get(alias)
        if alias == "anon":
            return True
        with self._auth_lock:
            with session._lock:
                already_auth = session.authenticated
                refresh_tok = session.refresh_token
                login_payload = dict(session.login_payload)
                login_graphql_query = session.login_graphql_query
            if already_auth and not force_login:
                return True
            # Try refresh endpoint first if refresh_token exists and force_login was requested.
            if force_login and refresh_tok and self.actors.refresh_path:
                try:
                    r_url, r_path, r_query = self.resolve_in_scope(self.actors.refresh_path)
                    r_body = json.dumps({"refresh_token": refresh_tok}).encode("utf-8")
                    r_headers = session.build_headers("POST", {"Content-Type": "application/json"})
                    receipt = self._send_wire(
                        actor=alias,
                        method="POST",
                        url=r_url,
                        path=r_path,
                        query=r_query,
                        headers=r_headers,
                        body_bytes=r_body,
                        body_preview='{"refresh_token":"<REDACTED>"}',
                        record_receipt=False,
                    )
                    if 200 <= receipt["status"] < 300:
                        return True
                except (BudgetExhaustedError, ServiceDegradationError):
                    raise
                except Exception:
                    pass

            if not login_payload:
                with session._lock:
                    return session.authenticated
            login_url, login_path, login_query = self.resolve_in_scope(self.actors.login_path)
            redacted_vars = {k: ("<REDACTED>" if k == "password" else v) for k, v in login_payload.items()}
            active_content_type = "application/json"
            if login_graphql_query:
                active_body_bytes = json.dumps(
                    {"query": login_graphql_query, "variables": login_payload}
                ).encode("utf-8")
                active_body_preview = json.dumps({"query": login_graphql_query[:120], "variables": redacted_vars})
            else:
                active_body_bytes = json.dumps(login_payload).encode("utf-8")
                active_body_preview = json.dumps(redacted_vars)

            receipt = self._send_wire(
                actor=alias,
                method="POST",
                url=login_url,
                path=login_path,
                query=login_query,
                headers=session.build_headers("POST", {"Content-Type": active_content_type}),
                body_bytes=active_body_bytes,
                body_preview=active_body_preview,
                record_receipt=False,
            )
            if not login_graphql_query and receipt["status"] in {400, 415}:
                active_content_type = "application/x-www-form-urlencoded"
                active_body_bytes = urlencode(login_payload).encode("utf-8")
                active_body_preview = "<REDACTED_FORM_LOGIN>"
                receipt = self._send_wire(
                    actor=alias,
                    method="POST",
                    url=login_url,
                    path=login_path,
                    query=login_query,
                    headers=session.build_headers("POST", {"Content-Type": active_content_type}),
                    body_bytes=active_body_bytes,
                    body_preview=active_body_preview,
                    record_receipt=False,
                )

            # Pre-login CSRF harvesting: if login POST returns 403 mentioning CSRF and session.csrf_token
            # is still empty, issue one bounded GET to login_path (falling back to "/" on 404/405)
            # to capture CSRF cookie/token via update_from_response, then retry POST once.
            with session._lock:
                has_csrf = bool(session.csrf_token)
            if receipt["status"] == 403 and not has_csrf and bool(receipt.get("_body_mentions_csrf")):
                candidate_paths = [self.actors.login_path]
                if self.actors.login_path != "/":
                    candidate_paths.append("/")
                harvested = False
                for c_path in candidate_paths:
                    try:
                        h_url, h_path, h_query = self.resolve_in_scope(c_path)
                    except ScopeViolationError:
                        continue
                    h_rec = self._send_wire(
                        actor=alias,
                        method="GET",
                        url=h_url,
                        path=h_path,
                        query=h_query,
                        headers=session.build_headers("GET"),
                        body_bytes=None,
                        body_preview="",
                        record_receipt=False,
                    )
                    if h_rec["status"] not in {404, 405}:
                        harvested = True
                        break
                if harvested:
                    receipt = self._send_wire(
                        actor=alias,
                        method="POST",
                        url=login_url,
                        path=login_path,
                        query=login_query,
                        headers=session.build_headers("POST", {"Content-Type": active_content_type}),
                        body_bytes=active_body_bytes,
                        body_preview=active_body_preview,
                        record_receipt=False,
                    )
                    if (
                        not login_graphql_query
                        and active_content_type == "application/json"
                        and receipt["status"] in {400, 415}
                    ):
                        active_content_type = "application/x-www-form-urlencoded"
                        active_body_bytes = urlencode(login_payload).encode("utf-8")
                        active_body_preview = "<REDACTED_FORM_LOGIN>"
                        receipt = self._send_wire(
                            actor=alias,
                            method="POST",
                            url=login_url,
                            path=login_path,
                            query=login_query,
                            headers=session.build_headers("POST", {"Content-Type": active_content_type}),
                            body_bytes=active_body_bytes,
                            body_preview=active_body_preview,
                            record_receipt=False,
                        )

            if 200 <= receipt["status"] < 400:
                if login_graphql_query and receipt.get("_graphql_has_errors"):
                    with session._lock:
                        has_session_mat = bool(session.cookies or session.access_token)
                    if not has_session_mat:
                        return False
                with session._lock:
                    session.authenticated = True
                return True
            return False

    def authenticate_all_actors(self) -> dict[str, bool]:
        """Eagerly authenticate all non-anon actors with login credentials not yet authenticated."""
        with self.actors._lock:
            candidates = list(self.actors.actors.items())
        results: dict[str, bool] = {}
        for alias, session in candidates:
            if alias == "anon":
                continue
            with session._lock:
                needs_login = bool(session.login_payload) and not session.authenticated
            if not needs_login:
                continue
            try:
                results[alias] = bool(self.authenticate_actor(alias, force_login=False))
            except (BudgetExhaustedError, ServiceDegradationError):
                raise
            except Exception:
                results[alias] = False
        return results

    def _refresh_csrf_from_session(self, alias: str) -> None:
        session = self.actors.get(alias)
        if alias == "anon" or not self.actors.session_check_path:
            return
        with self._auth_lock:
            try:
                c_url, c_path, c_query = self.resolve_in_scope(self.actors.session_check_path)
                headers = session.build_headers("GET")
                self._send_wire(
                    actor=alias,
                    method="GET",
                    url=c_url,
                    path=c_path,
                    query=c_query,
                    headers=headers,
                    body_bytes=None,
                    body_preview="",
                    record_receipt=False,
                )
            except (BudgetExhaustedError, ServiceDegradationError):
                raise
            except Exception:
                pass

    @staticmethod
    def _merge_hop_cookies(headers: dict[str, str], hop_cookies: dict[str, str]) -> dict[str, str]:
        """Overlay cookies received during earlier redirect hops onto a request header dict."""
        if not hop_cookies:
            return headers
        merged_headers = dict(headers)
        existing_cookie_key = next((k for k in merged_headers if k.lower() == "cookie"), None)
        cookie_map: dict[str, str] = {}
        if existing_cookie_key is not None:
            for part in str(merged_headers[existing_cookie_key]).split(";"):
                if "=" in part:
                    ck, cv = part.split("=", 1)
                    if ck.strip():
                        cookie_map[ck.strip()] = cv.strip()
        cookie_map.update(hop_cookies)
        if existing_cookie_key is not None and existing_cookie_key != "Cookie":
            merged_headers.pop(existing_cookie_key, None)
        merged_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in sorted(cookie_map.items()))
        return merged_headers

    def request(
        self,
        *,
        method: str = "GET",
        url: str,
        actor: str = "anon",
        headers: dict[str, str] | None = None,
        query: dict[str, Any] | None = None,
        json_body: Any = None,
        form_body: dict[str, Any] | None = None,
        raw_body: str | None = None,
        files: Sequence[dict[str, Any]] | None = None,
        force: bool = False,
        save_session_as: str = "",
        follow_redirects: bool = False,
    ) -> dict[str, Any]:
        """Execute a scope-locked, metered, receipted HTTP or WebSocket request."""
        raw_url_str = str(url or "").strip()
        norm_method = str(method or "GET").strip().upper()
        is_ws = raw_url_str.lower().startswith(("ws://", "wss://")) or norm_method == "WS"
        if is_ws:
            if norm_method not in self.allowed_methods and not (norm_method == "WS" and "GET" in self.allowed_methods):
                raise MethodNotAllowedError(
                    f"HTTP method {norm_method!r} not allowed; permitted: {sorted(self.allowed_methods)}"
                )
        elif norm_method not in self.allowed_methods:
            raise MethodNotAllowedError(
                f"HTTP method {norm_method!r} not allowed; permitted: {sorted(self.allowed_methods)}"
            )
        clean_url, path, norm_query = self._merge_query(url, query, allow_websocket=is_ws)
        if is_ws and clean_url.lower().startswith(("http://", "https://")):
            ws_scheme = "wss://" if clean_url.lower().startswith("https://") else "ws://"
            clean_url = ws_scheme + clean_url.split("://", 1)[1]
        session = self.actors.get(actor)

        extra_headers = {str(k): str(v) for k, v in (headers or {}).items()}
        has_auth_override = any(k.lower() in _AUTH_OVERRIDE_HEADERS for k in extra_headers)
        if actor != "anon" and not has_auth_override and not session.authenticated:
            self.authenticate_actor(actor, force_login=False)

        if is_ws:
            ws_messages: list[str] | None = None
            ws_preview = ""
            if json_body is not None:
                ws_preview = json.dumps(json_body, ensure_ascii=False)
                ws_messages = [ws_preview]
            elif raw_body is not None:
                ws_preview = str(raw_body)
                ws_messages = [ws_preview]
            ws_headers = session.build_headers("GET", extra_headers)
            ws_receipt = self._send_websocket_wire(
                actor=actor,
                url=clean_url,
                path=path,
                query=norm_query,
                headers=ws_headers,
                send_messages=ws_messages,
                body_preview=ws_preview,
            )
            ws_result = dict(ws_receipt)
            ws_result["cached"] = False
            return ws_result

        has_files = False
        if files is not None:
            if isinstance(files, (str, bytes, bytearray, dict)) or not isinstance(files, Sequence):
                raise ValueError("files must be a list of file objects")
            has_files = len(files) > 0

        body_bytes: bytes | None = None
        body_preview = ""
        if has_files:
            assert files is not None
            if json_body is not None or raw_body is not None:
                raise ValueError("files cannot be combined with json_body or raw_body")
            body_bytes, multipart_ct, body_preview = _encode_multipart_form_data(
                files,
                form_fields=form_body,
            )
            if not any(k.lower() == "content-type" for k in extra_headers):
                extra_headers["Content-Type"] = multipart_ct
        elif json_body is not None:
            body_preview = json.dumps(json_body, ensure_ascii=False)
            body_bytes = body_preview.encode("utf-8")
            if not any(k.lower() == "content-type" for k in extra_headers):
                extra_headers["Content-Type"] = "application/json"
        elif form_body is not None:
            body_preview = urlencode({str(k): str(v) for k, v in form_body.items()})
            body_bytes = body_preview.encode("utf-8")
            if not any(k.lower() == "content-type" for k in extra_headers):
                extra_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif raw_body is not None:
            body_preview = str(raw_body)
            body_bytes = body_preview.encode("utf-8")

        cache_key = (
            actor,
            norm_method,
            _canonical_url(clean_url),
            tuple(sorted((k.lower(), v) for k, v in extra_headers.items())),
            bool(follow_redirects),
        )
        if norm_method in {"GET", "HEAD"} and not force and not save_session_as:
            with self._lock:
                cached = self._cache.get(cache_key)
                if cached is not None:
                    result = dict(cached)
                    result["cached"] = True
                    return result

        req_headers = session.build_headers(norm_method, extra_headers)
        hop_cookies: dict[str, str] = {}
        receipt = self._send_wire(
            actor=actor,
            method=norm_method,
            url=clean_url,
            path=path,
            query=norm_query,
            headers=req_headers,
            body_bytes=body_bytes,
            body_preview=body_preview,
            save_session_as=save_session_as,
            out_cookies=hop_cookies if follow_redirects else None,
        )

        # Auto re-auth once on 401 when not testing explicit auth header overrides.
        if receipt["status"] == 401 and actor != "anon" and not has_auth_override and path != self.actors.login_path:
            if self.authenticate_actor(actor, force_login=True):
                req_headers = session.build_headers(norm_method, extra_headers)
                hop_cookies.clear()
                receipt = self._send_wire(
                    actor=actor,
                    method=norm_method,
                    url=clean_url,
                    path=path,
                    query=norm_query,
                    headers=req_headers,
                    body_bytes=body_bytes,
                    body_preview=body_preview,
                    out_cookies=hop_cookies if follow_redirects else None,
                )

        # Auto CSRF refresh once on mutating 403 mentioning CSRF when caller didn't override X-CSRF-Token.
        has_csrf_override = any(k.lower() == "x-csrf-token" for k in extra_headers)
        if (
            receipt["status"] == 403
            and norm_method in _MUTATING_METHODS
            and actor != "anon"
            and not has_csrf_override
            and "csrf" in (receipt.get("body") or "").lower()
        ):
            self._refresh_csrf_from_session(actor)
            req_headers = session.build_headers(norm_method, extra_headers)
            hop_cookies.clear()
            receipt = self._send_wire(
                actor=actor,
                method=norm_method,
                url=clean_url,
                path=path,
                query=norm_query,
                headers=req_headers,
                body_bytes=body_bytes,
                body_preview=body_preview,
                out_cookies=hop_cookies if follow_redirects else None,
            )

        # Polite bounded single retry on HTTP 429 if budget has headroom.
        if receipt["status"] == 429 and self._budget_remaining() > 4:
            retry_after_raw = receipt.get("response_headers", {}).get("Retry-After", "1")
            try:
                delay_s = min(max(0.2, float(retry_after_raw)), 3.0)
            except ValueError:
                delay_s = 1.0
            self._sleep_fn(delay_s)
            hop_cookies.clear()
            receipt = self._send_wire(
                actor=actor,
                method=norm_method,
                url=clean_url,
                path=path,
                query=norm_query,
                headers=req_headers,
                body_bytes=body_bytes,
                body_preview=body_preview,
                out_cookies=hop_cookies if follow_redirects else None,
            )

        redirect_chain: list[dict[str, Any]] = []
        if follow_redirects:
            cur_method = norm_method
            cur_url = clean_url
            cur_body_bytes = body_bytes
            cur_body_preview = body_preview
            cur_extra_headers = dict(extra_headers)
            for _ in range(_MAX_REDIRECTS):
                status_code = int(receipt["status"])
                location = str(receipt.get("redirect_location") or "").strip()
                if status_code not in _REDIRECT_STATUS_CODES or not location:
                    break
                if location.startswith("//"):
                    raise ScopeViolationError(f"scheme-relative redirect blocked: {location!r}")
                joined_target = urljoin(cur_url, location)
                next_url, next_path, next_query = self.resolve_in_scope(
                    joined_target,
                    allow_websocket=False,
                )
                redirect_chain.append({
                    "receipt_id": str(receipt.get("receipt_id") or ""),
                    "method": cur_method,
                    "url": cur_url,
                    "status": status_code,
                    "location": location,
                })
                if status_code == 303 and cur_method != "HEAD":
                    cur_method = "GET"
                    cur_body_bytes = None
                    cur_body_preview = ""
                    cur_extra_headers = {
                        k: v for k, v in cur_extra_headers.items()
                        if k.lower() not in {"content-type", "content-length"}
                    }
                elif status_code in {301, 302} and cur_method == "POST":
                    cur_method = "GET"
                    cur_body_bytes = None
                    cur_body_preview = ""
                    cur_extra_headers = {
                        k: v for k, v in cur_extra_headers.items()
                        if k.lower() not in {"content-type", "content-length"}
                    }
                # 307/308 preserve method and request body intact.
                if cur_method not in self.allowed_methods:
                    raise MethodNotAllowedError(
                        f"Redirect follow-up method {cur_method!r} not allowed; "
                        f"permitted: {sorted(self.allowed_methods)}"
                    )
                cur_url = next_url
                hop_headers = session.build_headers(cur_method, cur_extra_headers)
                if hop_cookies:
                    hop_headers = self._merge_hop_cookies(hop_headers, hop_cookies)
                new_hop_cookies: dict[str, str] = {}
                receipt = self._send_wire(
                    actor=actor,
                    method=cur_method,
                    url=next_url,
                    path=next_path,
                    query=next_query,
                    headers=hop_headers,
                    body_bytes=cur_body_bytes,
                    body_preview=cur_body_preview,
                    save_session_as=save_session_as,
                    out_cookies=new_hop_cookies,
                )
                if new_hop_cookies:
                    hop_cookies.update(new_hop_cookies)

        result = dict(receipt)
        if redirect_chain:
            result["redirect_chain"] = redirect_chain

        if norm_method in _MUTATING_METHODS and 200 <= receipt["status"] < 400:
            with self._lock:
                self._cache.clear()
        elif norm_method in {"GET", "HEAD"} and 200 <= receipt["status"] < 500 and receipt["status"] != 429:
            with self._lock:
                self._cache[cache_key] = dict(result)

        result["cached"] = False
        return result
