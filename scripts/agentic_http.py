"""Thin scope-locked HTTP transport with WireBudget, multi-actor auth/CSRF, and GET dedup."""
from __future__ import annotations

from dataclasses import dataclass, field
import gzip
import json
from pathlib import Path
import re
import threading
import time
from typing import Any, Sequence
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
import uuid
import zlib

import requests

from agentic_receipts import ReceiptStore
from wire_budget import WireBudget

STATIC_EXTENSIONS = frozenset({
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_AUTH_OVERRIDE_HEADERS = frozenset({"authorization", "cookie"})


class ScopeViolationError(ValueError):
    """Raised when a requested URL leaves the authorized target origin."""


class MethodNotAllowedError(ValueError):
    """Raised when an HTTP method is outside operator-allowed methods."""


class BudgetExhaustedError(RuntimeError):
    """Raised when WireBudget refuses another live HTTP request."""


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
    password: str = ""
    base_headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    access_token: str = ""
    refresh_token: str = ""
    csrf_token: str = ""
    authenticated: bool = False
    dynamic: bool = False
    source_receipt_id: str = ""

    def collect_secrets(self) -> list[str]:
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
        return secrets

    def build_headers(self, method: str, extra_headers: dict[str, str] | None = None) -> dict[str, str]:
        headers = dict(self.base_headers)
        if self.access_token and not any(k.lower() == "authorization" for k in headers):
            headers["Authorization"] = f"Bearer {self.access_token}"
        if self.cookies and not any(k.lower() == "cookie" for k in headers):
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in sorted(self.cookies.items()))
        if method.upper() in _MUTATING_METHODS and self.csrf_token:
            headers.setdefault("X-CSRF-Token", self.csrf_token)
        if extra_headers:
            for k, v in extra_headers.items():
                headers[str(k)] = str(v)
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
            for obj in candidates:
                if not bearer_token:
                    for tkey in ("access_token", "token", "jwt", "id_token", "auth_token", "bearer_token"):
                        val = obj.get(tkey)
                        if isinstance(val, str) and val.strip():
                            bearer_token = val.strip()
                            break
                if not refresh_token:
                    ref_val = obj.get("refresh_token")
                    if isinstance(ref_val, str) and ref_val.strip():
                        refresh_token = ref_val.strip()
                if not csrf_token:
                    for ckey in ("csrf_token", "csrf", "xsrf_token"):
                        cval = obj.get(ckey)
                        if isinstance(cval, str) and cval.strip():
                            csrf_token = cval.strip()
                            break
    elif body_text and ("<meta" in body_text.lower() or "csrf" in body_text.lower()):
        meta_m = re.search(
            r'<meta[^>]+name=["\'](?:csrf-token|xsrf-token)["\'][^>]+content=["\']([^"\']+)["\']',
            body_text,
            re.IGNORECASE,
        )
        if meta_m and not csrf_token:
            csrf_token = meta_m.group(1).strip()
        else:
            inp_m = re.search(
                r'<input[^>]+name=["\'](?:csrf_token|_csrf|csrf)["\'][^>]+value=["\']([^"\']+)["\']',
                body_text,
                re.IGNORECASE,
            )
            if inp_m and not csrf_token:
                csrf_token = inp_m.group(1).strip()

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
            if isinstance(raw.get("cookie"), str) and raw["cookie"].strip():
                base_headers.setdefault("Cookie", raw["cookie"].strip())
            password = str(raw.get("password") or "")
            login_payload: dict[str, str] = {}
            if password:
                login_payload["password"] = password
                for key in ("work_email", "email", "username"):
                    val = raw.get(key)
                    if isinstance(val, str) and val.strip():
                        login_payload[key] = val.strip()
                        break
            has_preauth = bool(base_headers or access_token or cookies)
            self.actors[alias] = ActorSession(
                alias=alias,
                role=str(raw.get("role") or "member").strip() or "member",
                tenant=str(raw.get("tenant") or "").strip(),
                login_payload=login_payload,
                password=password,
                base_headers=base_headers,
                cookies=cookies,
                access_token=access_token,
                csrf_token=str(raw.get("csrf_token") or "").strip(),
                authenticated=has_preauth,
            )

    def get(self, alias: str) -> ActorSession:
        key = str(alias or "anon").strip() or "anon"
        if key not in self.actors:
            raise ValueError(f"unknown actor alias: {alias!r}; available: {sorted(self.actors)}")
        return self.actors[key]

    def summaries(self) -> list[dict[str, str]]:
        """Return public non-secret actor metadata safe to show the LLM."""
        return [
            {"alias": s.alias, "role": s.role, "tenant": s.tenant}
            for s in self.actors.values()
        ]

    def all_secrets(self) -> list[str]:
        with self._lock:
            secrets: list[str] = []
            for session in self.actors.values():
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


class AgenticHTTPClient:
    """Scope-locked, WireBudget-accounted HTTP client with dedup and auto re-auth."""

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
    ):
        self.base_url = normalize_origin(base_url)
        parsed_origin = urlsplit(self.base_url)
        self._origin = (parsed_origin.scheme, parsed_origin.netloc)
        self.receipt_store = receipt_store
        self.actors = actors or ActorManager()
        self.allowed_methods = frozenset(
            str(m).strip().upper() for m in allowed_methods if str(m).strip()
        ) or frozenset({"GET"})
        self.budget = wire_budget or WireBudget(int(max_requests), uuid.uuid4().hex)
        self.timeout_s = float(timeout_s)
        self.max_response_bytes = int(max_response_bytes)
        self._session = requests.Session()
        self._session.trust_env = False
        self._cache: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._lock = threading.Lock()

    def close(self) -> None:
        self._session.close()

    def resolve_in_scope(self, url_or_path: str) -> tuple[str, str, str]:
        """Resolve relative path or URL and verify exact origin match."""
        raw = str(url_or_path or "").strip()
        if not raw:
            raise ScopeViolationError("URL is required")
        if raw.startswith("//"):
            raise ScopeViolationError(f"scheme-relative cross-origin URL blocked: {raw}")
        resolved = urljoin(self.base_url, raw)
        parsed = urlsplit(resolved)
        if (parsed.scheme, parsed.netloc) != self._origin:
            raise ScopeViolationError(
                f"out-of-scope URL {resolved!r}; allowed origin is {self.base_url}"
            )
        clean_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        return clean_url, parsed.path or "/", parsed.query

    def _merge_query(self, url: str, query_params: dict[str, Any] | None) -> tuple[str, str, str]:
        if not query_params:
            return self.resolve_in_scope(url)
        clean_url, _, _ = self.resolve_in_scope(url)
        parsed = urlsplit(clean_url)
        existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
        for k, v in query_params.items():
            if v is None:
                existing.pop(str(k), None)
            else:
                existing[str(k)] = str(v)
        new_query = urlencode(sorted(existing.items()))
        rebuilt = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", new_query, ""))
        return self.resolve_in_scope(rebuilt)

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
    ) -> dict[str, Any]:
        allowed, reason = self.budget.consume()
        if not allowed:
            raise BudgetExhaustedError(reason)

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
            # Clear shared session cookie jar before & after each wire call so per-actor
            # cookies (managed strictly via ActorSession.build_headers) never leak across actors.
            self._session.cookies.clear()
            # Read raw stream directly so mismatched Content-Encoding never crashes requests.
            resp = self._session.request(
                method=method,
                url=url,
                headers=headers,
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
                raw_stream = resp.raw.read(self.max_response_bytes + 1, decode_content=False)
                if len(raw_stream) > self.max_response_bytes:
                    raw_stream = raw_stream[: self.max_response_bytes]
                raw_bytes = _decode_raw_response(raw_stream, resp_headers.get("Content-Encoding", ""))
                text = raw_bytes.decode("utf-8", errors="replace")
                cookies = {c.name: c.value for c in resp.cookies}
                if not cookies and "Set-Cookie" in resp_headers:
                    for part in resp_headers["Set-Cookie"].split(","):
                        nv = part.strip().split(";", 1)[0]
                        if "=" in nv:
                            ck, cv = nv.split("=", 1)
                            if ck.strip() and cv.strip() and ck.strip().lower() not in {"path", "expires", "max-age", "domain", "samesite"}:
                                cookies[ck.strip()] = cv.strip()
                self._session.cookies.clear()
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
                self._session.cookies.clear()
                resp.close()
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:200]}"

        elapsed_ms = (time.monotonic() - started) * 1000.0
        if not record_receipt:
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
            }
        rec = self.receipt_store.record(
            actor=actor,
            method=method,
            url=url,
            path=path,
            query=query,
            request_headers=headers,
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
            dyn_sess = self.actors.actors.get(saved_session_meta["alias"])
            if dyn_sess is not None:
                dyn_sess.source_receipt_id = rec["receipt_id"]
            saved_session_meta["source_receipt_id"] = rec["receipt_id"]
            rec = dict(rec)
            rec["saved_session"] = saved_session_meta
        return rec

    def authenticate_actor(self, alias: str, *, force_login: bool = False) -> bool:
        """Sign in an actor via configured login_path if not yet authenticated."""
        session = self.actors.get(alias)
        if alias == "anon":
            return True
        if session.authenticated and not force_login:
            return True
        # Try refresh endpoint first if refresh_token exists and force_login was requested.
        if force_login and session.refresh_token and self.actors.refresh_path:
            try:
                r_url, r_path, r_query = self.resolve_in_scope(self.actors.refresh_path)
                r_body = json.dumps({"refresh_token": session.refresh_token}).encode("utf-8")
                receipt = self._send_wire(
                    actor=alias,
                    method="POST",
                    url=r_url,
                    path=r_path,
                    query=r_query,
                    headers={"Content-Type": "application/json"},
                    body_bytes=r_body,
                    body_preview='{"refresh_token":"<REDACTED>"}',
                    record_receipt=False,
                )
                if 200 <= receipt["status"] < 300:
                    return True
            except BudgetExhaustedError:
                raise
            except Exception:
                pass

        if not session.login_payload:
            return session.authenticated
        login_url, login_path, login_query = self.resolve_in_scope(self.actors.login_path)
        payload_bytes = json.dumps(session.login_payload).encode("utf-8")
        receipt = self._send_wire(
            actor=alias,
            method="POST",
            url=login_url,
            path=login_path,
            query=login_query,
            headers={"Content-Type": "application/json"},
            body_bytes=payload_bytes,
            body_preview=json.dumps({k: ("<REDACTED>" if k == "password" else v) for k, v in session.login_payload.items()}),
            record_receipt=False,
        )
        if receipt["status"] in {400, 415}:
            form_bytes = urlencode(session.login_payload).encode("utf-8")
            receipt = self._send_wire(
                actor=alias,
                method="POST",
                url=login_url,
                path=login_path,
                query=login_query,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body_bytes=form_bytes,
                body_preview="<REDACTED_FORM_LOGIN>",
                record_receipt=False,
            )
        if 200 <= receipt["status"] < 400:
            session.authenticated = True
            return True
        return False

    def _refresh_csrf_from_session(self, alias: str) -> None:
        session = self.actors.get(alias)
        if alias == "anon" or not self.actors.session_check_path:
            return
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
        except Exception:
            pass

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
        force: bool = False,
        save_session_as: str = "",
    ) -> dict[str, Any]:
        """Execute a scope-locked, metered, receipted HTTP request."""
        norm_method = str(method or "GET").strip().upper()
        if norm_method not in self.allowed_methods:
            raise MethodNotAllowedError(
                f"HTTP method {norm_method!r} not allowed; permitted: {sorted(self.allowed_methods)}"
            )
        clean_url, path, norm_query = self._merge_query(url, query)
        session = self.actors.get(actor)

        extra_headers = {str(k): str(v) for k, v in (headers or {}).items()}
        has_auth_override = any(k.lower() in _AUTH_OVERRIDE_HEADERS for k in extra_headers)
        if actor != "anon" and not has_auth_override and not session.authenticated:
            self.authenticate_actor(actor, force_login=False)

        body_bytes: bytes | None = None
        body_preview = ""
        if json_body is not None:
            body_preview = json.dumps(json_body, ensure_ascii=False)
            body_bytes = body_preview.encode("utf-8")
            extra_headers.setdefault("Content-Type", "application/json")
        elif form_body is not None:
            body_preview = urlencode({str(k): str(v) for k, v in form_body.items()})
            body_bytes = body_preview.encode("utf-8")
            extra_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif raw_body is not None:
            body_preview = str(raw_body)
            body_bytes = body_preview.encode("utf-8")

        cache_key = (
            actor,
            norm_method,
            _canonical_url(clean_url),
            tuple(sorted((k.lower(), v) for k, v in extra_headers.items())),
        )
        if norm_method in {"GET", "HEAD"} and not force and not save_session_as:
            with self._lock:
                cached = self._cache.get(cache_key)
                if cached is not None:
                    result = dict(cached)
                    result["cached"] = True
                    return result

        req_headers = session.build_headers(norm_method, extra_headers)
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
        )

        # Auto re-auth once on 401 when not testing explicit auth header overrides.
        if receipt["status"] == 401 and actor != "anon" and not has_auth_override and path != self.actors.login_path:
            if self.authenticate_actor(actor, force_login=True):
                req_headers = session.build_headers(norm_method, extra_headers)
                receipt = self._send_wire(
                    actor=actor,
                    method=norm_method,
                    url=clean_url,
                    path=path,
                    query=norm_query,
                    headers=req_headers,
                    body_bytes=body_bytes,
                    body_preview=body_preview,
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
            receipt = self._send_wire(
                actor=actor,
                method=norm_method,
                url=clean_url,
                path=path,
                query=norm_query,
                headers=req_headers,
                body_bytes=body_bytes,
                body_preview=body_preview,
            )

        # Polite bounded single retry on HTTP 429 if budget has headroom.
        if receipt["status"] == 429 and (self.budget.limit - self.budget.used) > 4:
            retry_after_raw = receipt.get("response_headers", {}).get("Retry-After", "1")
            try:
                delay_s = min(max(0.2, float(retry_after_raw)), 3.0)
            except ValueError:
                delay_s = 1.0
            time.sleep(delay_s)
            receipt = self._send_wire(
                actor=actor,
                method=norm_method,
                url=clean_url,
                path=path,
                query=norm_query,
                headers=req_headers,
                body_bytes=body_bytes,
                body_preview=body_preview,
            )

        if norm_method in _MUTATING_METHODS and 200 <= receipt["status"] < 400:
            with self._lock:
                self._cache.clear()
        elif norm_method in {"GET", "HEAD"} and 200 <= receipt["status"] < 500 and receipt["status"] != 429:
            with self._lock:
                self._cache[cache_key] = receipt

        result = dict(receipt)
        result["cached"] = False
        return result
