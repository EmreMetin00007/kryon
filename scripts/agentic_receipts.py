"""Lossless redacted HTTP receipt store for the agentic investigator."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Sequence

SENSITIVE_HEADER_NAMES = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-csrf-token-next",
    "x-xsrf-token",
})

_AUTH_SCHEME_RE = re.compile(r"^([A-Za-z0-9_-]{1,24})\s+(.+)$")
_GENERIC_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(password[\"']?\s*[:=]\s*[\"'])([^\"']+)([\"'])"),
    re.compile(r"(?i)\b(access_token[\"']?\s*[:=]\s*[\"'])([^\"']+)([\"'])"),
    re.compile(r"(?i)\b(csrf_token[\"']?\s*[:=]\s*[\"'])([^\"']+)([\"'])"),
)
_SHORT_SECRET_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "credential",
    "session",
    "phpsessid",
    "jsessionid",
    "csrf",
    "xsrf",
    "jwt",
    "cookie",
    "authorization",
)
_SHORT_SECRET_KEY_TOKENS = frozenset({
    "pass",
    "pwd",
    "key",
    "auth",
    "cred",
    "creds",
    "sid",
    "sig",
    "signature",
})
DEFAULT_MAX_DISK_BODY_CHARS = 4 * 1024 * 1024  # 4 MiB chars max on disk
DEFAULT_PREVIEW_CHARS = 4000


def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".receipt-", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _digest8(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]


def redact_header_value(name: str, value: str) -> str:
    """Redact sensitive header values while preserving scheme/length metadata."""
    raw = str(value or "")
    if name.strip().lower() not in SENSITIVE_HEADER_NAMES:
        return raw
    if name.strip().lower() == "authorization":
        match = _AUTH_SCHEME_RE.match(raw.strip())
        if match:
            scheme, token = match.group(1), match.group(2)
            return f"{scheme} <REDACTED:len={len(token)},sha256_8={_digest8(token)}>"
    return f"<REDACTED:len={len(raw)},sha256_8={_digest8(raw)}>"


def redact_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Return a copy of HTTP headers with credential/cookie/CSRF values redacted."""
    if not headers:
        return {}
    return {str(k): redact_header_value(str(k), str(v)) for k, v in headers.items()}


def _is_short_plain_word(secret: str) -> bool:
    """Return True for short pure-lowercase-alpha tokens (4 <= len < 8), e.g. 'admin', 'probe', 'test'."""
    return 4 <= len(secret) < 8 and secret.isascii() and secret.isalpha() and secret.islower()


def _is_sensitive_key_name(name: str) -> bool:
    """Return True when a field/header/parameter name denotes a credential or secret carrier."""
    low = name.strip().lower()
    if any(sub in low for sub in _SHORT_SECRET_KEY_SUBSTRINGS):
        return True
    tokens = re.split(r"[_.-]+", low)
    return any(tok in _SHORT_SECRET_KEY_TOKENS for tok in tokens)


def _redact_short_plain_secret(text: str, secret: str, replacement: str) -> str:
    """Redact a short pure-lowercase-alpha secret only in credential contexts.

    Preserves unrelated URL path segments (e.g. ``/admin/upload/index.html``),
    prose (``admin panel``), and larger identifiers (``administrator``, ``shard2_probe``,
    ``probe.txt``, ``probe-value-123``) while still scrubbing credential assignments
    (``password=admin``, ``{"password": "admin"}``, ``X-API-Key: admin``, ``Bearer admin``,
    ``http://user:admin@host/...``).
    """
    escaped = re.escape(secret)
    assign_re = re.compile(
        rf"(?<![A-Za-z0-9_.-])([A-Za-z0-9_][A-Za-z0-9_.-]{{1,63}})(['\"]?[ \t]*[:=][ \t]*['\"]?){escaped}(?![A-Za-z0-9_./-])"
    )
    cleaned = assign_re.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{replacement}" if _is_sensitive_key_name(m.group(1)) else m.group(0),
        text,
    )
    scheme_re = re.compile(
        rf"((?i:\b(?:bearer|basic|token|digest|apikey))[ \t]+){escaped}(?![A-Za-z0-9_./-])"
    )
    cleaned = scheme_re.sub(lambda m: f"{m.group(1)}{replacement}", cleaned)
    userinfo_re = re.compile(rf"(://[^/\s:@]+:){escaped}(?=@)")
    cleaned = userinfo_re.sub(lambda m: f"{m.group(1)}{replacement}", cleaned)
    return cleaned


def redact_secrets(text: str, secret_values: Sequence[str] = ()) -> str:
    """Scrub known credential/token values and generic auth patterns from text."""
    if not text:
        return ""
    cleaned = text
    # Sort longest-first so shorter substrings do not partially corrupt longer tokens.
    unique_secrets = sorted(
        {s for s in secret_values if isinstance(s, str) and len(s) >= 4},
        key=len,
        reverse=True,
    )
    for secret in unique_secrets:
        if secret not in cleaned:
            continue
        replacement = f"<REDACTED_SECRET:sha256_8={_digest8(secret)}>"
        if _is_short_plain_word(secret):
            cleaned = _redact_short_plain_secret(cleaned, secret, replacement)
        else:
            cleaned = cleaned.replace(secret, replacement)
    for idx, pattern in enumerate(_GENERIC_SECRET_PATTERNS):
        if idx == 0:
            cleaned = pattern.sub(r"\1<REDACTED_TOKEN>", cleaned)
        else:
            cleaned = pattern.sub(
                lambda m: m.group(0) if "<REDACTED" in m.group(2) else f"{m.group(1)}<REDACTED_SECRET>{m.group(3)}",
                cleaned,
            )
    return cleaned


class ReceiptStore:
    """Persistent, thread-safe, redacted HTTP receipt store (`receipts/req-NNNN.json`)."""

    def __init__(self, root_dir: str | Path, *, max_disk_body_chars: int = DEFAULT_MAX_DISK_BODY_CHARS):
        self.root_dir = Path(root_dir).expanduser().resolve()
        self.receipts_dir = self.root_dir / "receipts"
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        self.max_disk_body_chars = max(4096, int(max_disk_body_chars))
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any]] = {}
        self._counter = self._discover_max_counter()

    def _discover_max_counter(self) -> int:
        highest = 0
        for path in self.receipts_dir.glob("req-*.json"):
            stem = path.stem
            if stem.startswith("req-") and stem[4:].isdigit():
                highest = max(highest, int(stem[4:]))
        return highest

    @staticmethod
    def validate_receipt_id(receipt_id: str) -> str:
        rid = str(receipt_id or "").strip()
        if not re.fullmatch(r"req-\d{4,}", rid):
            raise ValueError(f"invalid receipt_id: {receipt_id!r}")
        return rid

    def record(
        self,
        *,
        actor: str,
        method: str,
        url: str,
        path: str,
        query: str = "",
        request_headers: dict[str, str] | None = None,
        request_body: str = "",
        status: int,
        elapsed_ms: float,
        content_type: str = "",
        response_headers: dict[str, str] | None = None,
        redirect_location: str = "",
        raw_response_bytes: bytes = b"",
        response_text: str = "",
        error: str = "",
        secret_values: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Redact and atomically write a new HTTP receipt to disk."""
        safe_req_headers = redact_headers(request_headers)
        safe_resp_headers = redact_headers(response_headers)
        safe_req_body = redact_secrets(request_body or "", secret_values)[:16384]
        safe_resp_body = redact_secrets(response_text or "", secret_values)
        truncated = len(safe_resp_body) > self.max_disk_body_chars
        if truncated:
            safe_resp_body = safe_resp_body[: self.max_disk_body_chars]
        safe_location = redact_secrets(redirect_location or "", secret_values)
        sha256_hex = hashlib.sha256(raw_response_bytes).hexdigest()

        with self._lock:
            self._counter += 1
            receipt_id = f"req-{self._counter:04d}"
            receipt: dict[str, Any] = {
                "schema": "agentic-receipt/1",
                "receipt_id": receipt_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": str(actor or "anon"),
                "method": str(method or "GET").upper(),
                "url": str(url),
                "path": str(path or "/"),
                "query": str(query or ""),
                "request_headers": safe_req_headers,
                "request_body": safe_req_body,
                "status": int(status),
                "elapsed_ms": round(float(elapsed_ms), 2),
                "content_type": str(content_type or ""),
                "response_length": len(raw_response_bytes),
                "response_sha256": sha256_hex,
                "redirect_location": safe_location,
                "response_headers": safe_resp_headers,
                "body": safe_resp_body,
                "body_truncated": truncated,
                "error": str(error or ""),
            }
            _atomic_write_json(self.receipts_dir / f"{receipt_id}.json", receipt)
            self._cache[receipt_id] = receipt
            return dict(receipt)

    def get(self, receipt_id: str) -> dict[str, Any]:
        """Load a receipt by ID from cache or disk."""
        rid = self.validate_receipt_id(receipt_id)
        with self._lock:
            if rid in self._cache:
                return dict(self._cache[rid])
        path = self.receipts_dir / f"{rid}.json"
        if not path.is_file():
            raise KeyError(f"receipt not found: {rid}")
        data = json.loads(path.read_text(encoding="utf-8"))
        with self._lock:
            self._cache[rid] = data
        return dict(data)

    def list_ids(self) -> list[str]:
        """Return sorted receipt IDs on disk."""
        with self._lock:
            return sorted(p.stem for p in self.receipts_dir.glob("req-*.json") if p.stem[4:].isdigit())

    def count(self) -> int:
        return len(self.list_ids())

    def read_slice(
        self,
        receipt_id: str,
        *,
        offset: int = 0,
        limit: int = DEFAULT_PREVIEW_CHARS,
        regex: str = "",
    ) -> dict[str, Any]:
        """Read a bounded slice or regex match view of a stored receipt body at 0 HTTP cost."""
        receipt = self.get(receipt_id)
        body = receipt.get("body") or ""
        total_chars = len(body)
        safe_offset = max(0, int(offset))
        safe_limit = max(1, min(int(limit), 12000))

        if regex:
            try:
                pattern = re.compile(regex, re.IGNORECASE)
            except re.error as exc:
                return {
                    "receipt_id": receipt["receipt_id"],
                    "error": f"invalid regex: {exc}",
                    "total_chars": total_chars,
                }
            matches: list[dict[str, Any]] = []
            used_chars = 0
            total_matches = 0
            for m in pattern.finditer(body):
                total_matches += 1
                start = max(0, m.start() - 120)
                end = min(total_chars, m.end() + 240)
                snippet = body[start:end]
                if used_chars + len(snippet) <= safe_limit:
                    matches.append({"offset": start, "match": m.group(0)[:120], "snippet": snippet})
                    used_chars += len(snippet)
            return {
                "receipt_id": receipt["receipt_id"],
                "actor": receipt["actor"],
                "method": receipt["method"],
                "url": receipt["url"],
                "status": receipt["status"],
                "content_type": receipt["content_type"],
                "total_chars": total_chars,
                "regex": regex,
                "total_matches": total_matches,
                "matches_shown": len(matches),
                "matches": matches,
            }

        excerpt = body[safe_offset : safe_offset + safe_limit]
        return {
            "receipt_id": receipt["receipt_id"],
            "actor": receipt["actor"],
            "method": receipt["method"],
            "url": receipt["url"],
            "status": receipt["status"],
            "content_type": receipt["content_type"],
            "response_length": receipt["response_length"],
            "total_chars": total_chars,
            "offset": safe_offset,
            "returned_chars": len(excerpt),
            "has_more": (safe_offset + len(excerpt)) < total_chars,
            "body": excerpt,
        }
