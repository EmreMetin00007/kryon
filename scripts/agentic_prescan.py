"""Faz B deterministic 0-LLM-token pre-scanner and multi-actor BOLA/BFLA pre-matrix.

Runs strictly in Python at zero LLM token cost, routing all live probes through
`AgenticHTTPClient.request(...)` so ScopeGuard, WireBudget, max_rps, allowed_methods,
custom headers, ServiceDegradationError, and ReceiptStore redaction always apply.

Emits prioritized `PrescanLead` hypotheses (`high > medium > low`) pointing to exact
`receipt_id`s for downstream verification by the LLM + `DifferentialOracle`. Never
records confirmed findings and never echoes raw secret values.
"""
from __future__ import annotations

from difflib import SequenceMatcher
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from typing import Any, Sequence, TypedDict
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

_REPO_ROOT = _SCRIPTS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agentic_http import (  # noqa: E402
    AgenticHTTPClient,
    BudgetExhaustedError,
    MethodNotAllowedError,
    ScopeViolationError,
    ServiceDegradationError,
    is_static_asset_url,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_surface import (  # noqa: E402
    is_catalog_route,
    is_id_segment,
    is_non_endpoint_source_path,
    normalize_path,
    route_template_of,
)
from agentic_waf import detect_waf_block  # noqa: E402
from target_bootstrap import is_destructive_lifecycle_route, is_logout_route  # noqa: E402

SCHEMA = "agentic-prescan/1"
CORS_PROBE_ORIGIN = "https://cors-check.example.invalid"
REDIRECT_PROBE_HOST = "redirect-check.example.invalid"
REDIRECT_PROBE_URL = f"https://{REDIRECT_PROBE_HOST}/kryon-probe"
GRAPHQL_INTROSPECTION_QUERY = "{ __schema { queryType { name } } }"

_PRIORITY_RANK: dict[str, int] = {"high": 0, "medium": 1, "low": 2}
_ADMIN_ROLES = frozenset({"admin", "superadmin", "platform_admin", "tenant_admin", "owner", "root"})

_DEFAULT_OFFLINE_RECEIPT_TAIL = 100
_DEFAULT_MAX_CORS_PROBES = 4
_DEFAULT_MAX_REDIRECT_PROBES = 4
_DEFAULT_MAX_GRAPHQL_PROBES = 3
_DEFAULT_MAX_MATRIX_ENDPOINTS = 8
_MAX_HTML_LINK_EXTRACT_CHARS = 262_144

_REDIRECT_PARAM_NAMES = frozenset({
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "return",
    "returnurl",
    "return_url",
    "return_to",
    "returnto",
    "continue",
    "url",
    "callback",
    "callback_url",
    "dest",
    "destination",
    "goto",
    "target",
})

_GRAPHQL_PATH_SEGMENTS = frozenset({"graphql", "gql"})

_PREMATRIX_SKIP_EXACT_PATHS = frozenset({
    "/login",
    "/log-in",
    "/signin",
    "/sign-in",
    "/signup",
    "/sign-up",
    "/register",
    "/auth/login",
    "/auth/signin",
    "/auth/register",
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/livez",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger-ui",
    "/swagger-ui.html",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
})

_API_PATH_PREFIX_RE = re.compile(
    r"^/(?:(?:ajax[-_]?)?api(?:/v\d+)?|v\d+(?:\.\d+)?|rest|rpc|graphql)(?:/|$)",
    re.IGNORECASE,
)

_SENSITIVE_ROUTE_TOKENS = frozenset({
    "admin",
    "administrator",
    "internal",
    "stats",
    "audit",
    "config",
    "settings",
    "user",
    "users",
    "account",
    "accounts",
    "order",
    "orders",
    "invoice",
    "invoices",
    "billing",
    "payment",
    "payments",
    "wallet",
    "ticket",
    "tickets",
    "report",
    "reports",
    "export",
    "member",
    "members",
    "profile",
    "profiles",
    "dashboard",
    "panel",
    "console",
    "me",
    "note",
    "notes",
    "document",
    "documents",
    "record",
    "records",
})

_EPHEMERAL_JSON_KEYS = frozenset({
    "timestamp",
    "created_at",
    "updated_at",
    "expires_at",
    "date",
    "time",
    "request_id",
    "trace_id",
    "correlation_id",
    "span_id",
    "nonce",
    "etag",
    "iat",
    "exp",
    "jti",
    "viewer",
})

_OWNER_JSON_KEYS = frozenset({
    "owner",
    "owner_id",
    "owner_alias",
    "user",
    "username",
    "user_id",
    "userid",
    "created_by",
    "author",
    "actor",
    "assigned_to",
    "member",
    "member_id",
    "customer",
    "customer_id",
    "account",
    "account_id",
})

_STRONG_PRIVATE_JSON_KEYS = _OWNER_JSON_KEYS | frozenset({
    "order",
    "order_id",
    "orderid",
    "email",
    "phone",
    "address",
    "balance",
    "total",
    "amount",
    "items",
    "line_items",
    "secret",
    "note",
    "notes",
    "profile",
    "role",
    "tenant",
    "tenant_id",
    "org_id",
    "invoice",
    "invoice_id",
    "ticket",
    "ticket_id",
    "payment",
    "ssn",
    "iban",
    "token",
})

_CATALOG_ONLY_JSON_KEYS = frozenset({
    "category",
    "categories",
    "brand",
    "sku",
    "catalog",
    "slug",
    "thumbnail",
    "in_stock",
    "products",
})

_TRIVIAL_ACK_KEYS = frozenset({
    "ok",
    "success",
    "status",
    "healthy",
    "alive",
    "pong",
    "ping",
    "version",
    "build",
    "uptime",
    "ready",
    "cors",
    "message",
})

_BFLA_ADMIN_JSON_KEYS = _STRONG_PRIVATE_JSON_KEYS | frozenset({
    "users",
    "total_users",
    "accounts",
    "orders",
    "revenue",
    "monthly_revenue",
    "tenants",
    "active_tenants",
    "audit",
    "audit_events",
    "permissions",
    "roles",
    "admin",
    "config",
    "settings",
    "secrets",
    "credentials",
    "api_key",
    "private",
    "reports",
    "invoices",
})

_SOFT_DENY_MESSAGES = (
    "unauthorized",
    "forbidden",
    "access denied",
    "permission denied",
    "not found",
    "login required",
    "authentication required",
    "unauthenticated",
)

# Secret scanning regexes (carefully crafted to avoid triggering static governance rules).
_AWS_ACCESS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
_PRIVATE_KEY_HEADER_RE = re.compile(
    r"-----BEGIN\s+(?:[A-Z]+\s+){0,3}PRIVATE\s+KEY-----"
)
_KNOWN_TOKEN_RE = re.compile(
    r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|sk_live_[0-9A-Za-z]{16,}"
    r"|xox[baprs]-[0-9A-Za-z-]{10,}"
    r"|AIza[0-9A-Za-z_-]{30,})\b"
)
_QUOTED_SECRET_ASSIGN_RE = re.compile(
    r"""(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_.-]{1,63})['"]?\s*[:=]\s*"""
    r"""(?:"([^"\r\n]{6,256})"|'([^'\r\n]{6,256})'|`([^`\r\n]{6,256})`)"""
)
_UNQUOTED_SECRET_ASSIGN_RE = re.compile(
    r"""(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_.-]{1,63})\s*=\s*([^\s"'`&;,)}\]]{8,128})"""
)
_CLIENT_CREDENTIALS_GRANT_RE = re.compile(
    r"""(?i)(?:grant_type['"]?\s*[:=]\s*['"]?client_credentials\b|\bclient_credentials\b)"""
)

_SECRET_ASSIGN_KEY_SUBSTRINGS = (
    "m2m_password",
    "m2m_secret",
    "client_secret",
    "clientsecret",
    "api_secret",
    "apisecret",
    "api_key",
    "apikey",
    "aws_secret",
    "secret_key",
    "secretkey",
    "jwt_secret",
    "jwtsecret",
    "app_secret",
    "appsecret",
    "auth_secret",
    "authsecret",
    "signing_key",
    "encryption_key",
    "private_key",
    "privatekey",
    "service_role_key",
    "db_password",
    "database_password",
    "admin_password",
    "bot_token",
    "slack_token",
    "github_token",
    "access_key_secret",
)
_SECRET_ASSIGN_SUFFIXES = (
    "_secret",
    "_password",
    "_passwd",
    "_api_key",
    "_apikey",
    "_private_key",
    "_auth_token",
    "_access_key",
)
_PLACEHOLDER_SECRET_VALUES = frozenset({
    "null",
    "none",
    "true",
    "false",
    "undefined",
    "placeholder",
    "changeme",
    "example",
    "redacted",
    "your_api_key",
    "your-api-key",
    "your_secret",
    "your-secret",
    "client_credentials",
})

_HTML_HREF_ACTION_RE = re.compile(
    r"""(?:href|action|src)\s*=\s*(?:"([^"<>]{1,512})"|'([^'<>]{1,512})')""",
    re.IGNORECASE,
)
_HTML_FORM_TAG_RE = re.compile(r"<form\b([^>]*)>([\s\S]{0,8192}?)</form>", re.IGNORECASE)
_HTML_INPUT_NAME_RE = re.compile(
    r"""<input\b[^>]*\bname\s*=\s*(?:"([A-Za-z0-9_.\-\[\]$]{1,64})"|'([A-Za-z0-9_.\-\[\]$]{1,64})')""",
    re.IGNORECASE,
)
_HTML_ATTR_ACTION_RE = re.compile(
    r"""\baction\s*=\s*(?:"([^"<>]{1,512})"|'([^'<>]{1,512})')""",
    re.IGNORECASE,
)
_HTML_ATTR_METHOD_RE = re.compile(
    r"""\bmethod\s*=\s*(?:"([A-Za-z]{3,10})"|'([A-Za-z]{3,10})'|([A-Za-z]{3,10}))""",
    re.IGNORECASE,
)


class PrescanLead(TypedDict, total=False):
    """Structured unverified hypothesis emitted by the deterministic pre-scanner."""

    lead_id: str
    kind: str
    suggested_class: str
    severity_hint: str
    priority: str
    status: str
    receipt_id: str
    proof_receipt_id: str
    control_receipt_id: str
    url: str
    method: str
    actor: str
    control_actor: str
    key_name: str
    redacted_preview: str
    param: str
    location: str
    probe_origin: str
    acao: str
    acac: str
    similarity: float
    summary: str
    next_step: str


class _PrescanBudget:
    """Bounded request allowance enforced on top of `AgenticHTTPClient.budget`."""

    def __init__(self, http_client: AgenticHTTPClient, max_requests: int) -> None:
        self.http_client = http_client
        self.soft_cap = max(0, int(max_requests))
        self.total_limit = int(getattr(http_client.budget, "limit", 0))
        self.initial_used = self._current_used()
        rem_now = max(0, self.total_limit - self.initial_used)
        if self.total_limit > 20:
            self.effective_cap = min(self.soft_cap, max(0, rem_now - 10))
        else:
            self.effective_cap = min(self.soft_cap, rem_now)
        self.exhausted = False
        self.requests_attempted = 0
        self.waf_blocks_skipped = 0
        self.waf_vendors_seen: set[str] = set()

    def _current_used(self) -> int:
        budget_obj = self.http_client.budget
        lock = getattr(budget_obj, "_lock", None)
        if lock is not None:
            with lock:
                return int(budget_obj.used)
        return int(budget_obj.used)

    @property
    def spent(self) -> int:
        return max(0, self._current_used() - self.initial_used)

    def remaining(self) -> int:
        if self.exhausted:
            return 0
        rem_cap = max(0, self.effective_cap - self.spent)
        rem_global = max(0, self.total_limit - self._current_used())
        if self.total_limit > 20:
            rem_global = max(0, rem_global - 10)
        return min(rem_cap, rem_global)

    def can_request(self) -> bool:
        return self.remaining() > 0


def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".prescan-", suffix=".tmp", dir=path.parent)
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


def _redacted_preview(raw_secret: str) -> str:
    return f"<REDACTED:len={len(raw_secret)},sha256_8={_digest8(raw_secret)}>"


def _response_header_ci(receipt: dict[str, Any], header_name: str) -> str:
    headers = receipt.get("response_headers")
    if not isinstance(headers, dict):
        return ""
    target = header_name.strip().lower()
    for hk, hv in headers.items():
        if str(hk).strip().lower() == target:
            return str(hv or "").strip()
    return ""


def _make_lead(
    *,
    kind: str,
    suggested_class: str,
    severity_hint: str,
    receipt_id: str,
    url: str,
    actor: str,
    summary: str,
    next_step: str,
    **extra: Any,
) -> PrescanLead:
    sev = severity_hint.lower() if severity_hint.lower() in _PRIORITY_RANK else "low"
    lead: PrescanLead = {
        "kind": kind,
        "suggested_class": suggested_class,
        "severity_hint": sev,
        "priority": sev,
        "status": "unverified_lead",
        "receipt_id": receipt_id,
        "url": url,
        "actor": actor,
        "summary": summary,
        "next_step": next_step,
    }
    for key, val in extra.items():
        if val is not None:
            lead[key] = val  # type: ignore[literal-required]
    return lead


def _safe_request(
    http_client: AgenticHTTPClient,
    budget: _PrescanBudget,
    *,
    method: str = "GET",
    url: str,
    actor: str = "anon",
    headers: dict[str, str] | None = None,
    query: dict[str, Any] | None = None,
    json_body: Any = None,
    follow_redirects: bool = False,
) -> tuple[dict[str, Any] | None, bool]:
    """Execute one scope/budget-guarded request through `http_client.request`."""
    if not budget.can_request():
        return None, False
    budget.requests_attempted += 1
    try:
        receipt = http_client.request(
            method=method,
            url=url,
            actor=actor,
            headers=headers,
            query=query,
            json_body=json_body,
            follow_redirects=follow_redirects,
        )
    except ServiceDegradationError:
        raise
    except BudgetExhaustedError:
        budget.exhausted = True
        return None, False
    except (ScopeViolationError, MethodNotAllowedError, ValueError):
        return None, False

    waf_info = detect_waf_block(receipt)
    if waf_info is not None:
        budget.waf_blocks_skipped += 1
        vendor = str(waf_info.get("vendor") or "generic").strip()
        if vendor:
            budget.waf_vendors_seen.add(vendor)
        return receipt, True
    return receipt, False


def _is_secret_assignment_key(key_name: str) -> bool:
    low = key_name.strip().lower().replace("-", "_")
    if not low:
        return False
    if any(sub in low for sub in _SECRET_ASSIGN_KEY_SUBSTRINGS):
        return True
    return low.endswith(_SECRET_ASSIGN_SUFFIXES)


def _is_trivial_secret_value(raw_val: str) -> bool:
    val = raw_val.strip()
    if len(val) < 6:
        return True
    if "<redacted" in val.lower() or val.startswith(("${", "{{", "{env:")):
        return True
    if val.lower() in _PLACEHOLDER_SECRET_VALUES:
        return True
    if len(set(val)) <= 2 and all(ch in "*.-_xX" for ch in val):
        return True
    return False


def _scan_body_for_secrets(
    body: str,
    *,
    receipt_id: str,
    url: str,
    actor: str,
    collected_secrets: set[str],
) -> list[PrescanLead]:
    """Extract redacted secret leads from a single response body."""
    leads: list[PrescanLead] = []
    seen_keys: set[tuple[str, str]] = set()

    def _emit(
        kind: str,
        key_name: str,
        raw_secret: str,
        severity_hint: str,
        preview_override: str = "",
    ) -> None:
        dedup_key = (kind, key_name.lower())
        if dedup_key in seen_keys:
            return
        seen_keys.add(dedup_key)
        if raw_secret and len(raw_secret) >= 4:
            collected_secrets.add(raw_secret)
        preview = preview_override or _redacted_preview(raw_secret)
        leads.append(
            _make_lead(
                kind=kind,
                suggested_class="other",
                severity_hint=severity_hint,
                receipt_id=receipt_id,
                url=url,
                actor=actor,
                key_name=key_name,
                redacted_preview=preview,
                summary=(
                    f"Potential exposed {kind} ({key_name}, {preview}) in public "
                    f"{actor} response {receipt_id} at {url}."
                ),
                next_step=(
                    f"Inspect {receipt_id} via read_receipt (regex={key_name}) and verify "
                    "whether a sensitive credential/key is exposed to unauthenticated users."
                ),
            )
        )

    if _PRIVATE_KEY_HEADER_RE.search(body):
        match = _PRIVATE_KEY_HEADER_RE.search(body)
        assert match is not None
        _emit(
            "private_key",
            "PRIVATE_KEY",
            match.group(0),
            "high",
            preview_override=f"<REDACTED_PRIVATE_KEY:len={len(match.group(0))}>",
        )

    for match in _AWS_ACCESS_KEY_RE.finditer(body):
        raw_key = match.group(1)
        _emit("aws_access_key", "AWS_ACCESS_KEY_ID", raw_key, "high")

    for match in _KNOWN_TOKEN_RE.finditer(body):
        raw_tok = match.group(1)
        _emit("hardcoded_api_key", "API_TOKEN", raw_tok, "high")

    for match in _QUOTED_SECRET_ASSIGN_RE.finditer(body):
        key_name = match.group(1).strip()
        raw_val = (match.group(2) or match.group(3) or match.group(4) or "").strip()
        if not _is_secret_assignment_key(key_name) or _is_trivial_secret_value(raw_val):
            continue
        _emit("exposed_secret", key_name, raw_val, "high")

    for match in _UNQUOTED_SECRET_ASSIGN_RE.finditer(body):
        key_name = match.group(1).strip()
        raw_val = match.group(2).strip()
        if not _is_secret_assignment_key(key_name) or _is_trivial_secret_value(raw_val):
            continue
        _emit("exposed_secret", key_name, raw_val, "high")

    if _CLIENT_CREDENTIALS_GRANT_RE.search(body):
        has_secret_sibling = any(
            lead.get("kind") in {"exposed_secret", "hardcoded_api_key"} for lead in leads
        )
        _emit(
            "oauth_client_credentials",
            "grant_type:client_credentials",
            "",
            "high" if has_secret_sibling else "medium",
            preview_override="grant_type=client_credentials (len=18)",
        )

    return leads


def scan_offline_secret_leads(
    receipt_store: ReceiptStore,
    *,
    max_receipts: int = _DEFAULT_OFFLINE_RECEIPT_TAIL,
    waf_vendors_out: set[str] | None = None,
    _secret_sink: set[str] | None = None,
) -> tuple[list[PrescanLead], int]:
    """Check 1 (0 HTTP requests): triage public `anon` receipts for exposed credentials/keys.

    CRITICAL SECRET HYGIENE: never emits raw secret substrings anywhere in returned
    leads; only records `kind`, `key_name`, `receipt_id`, `url`, `actor`, and redacted
    `len=...` preview.
    """
    ids = receipt_store.list_ids()
    tail_ids = ids[-max(1, int(max_receipts)) :] if ids else []
    leads: list[PrescanLead] = []
    collected_secrets: set[str] = _secret_sink if _secret_sink is not None else set()
    scanned = 0

    for rid in tail_ids:
        try:
            rec = receipt_store.get(rid)
        except (KeyError, ValueError):
            continue
        actor = str(rec.get("actor") or "anon").strip() or "anon"
        if actor != "anon":
            continue
        status = int(rec.get("status") or 0)
        if not (200 <= status < 400):
            continue
        url = str(rec.get("url") or rec.get("path") or "/")
        if is_static_asset_url(url):
            continue
        waf_info = detect_waf_block(rec)
        if waf_info is not None:
            if waf_vendors_out is not None:
                vendor = str(waf_info.get("vendor") or "generic").strip()
                if vendor:
                    waf_vendors_out.add(vendor)
            continue
        body = str(rec.get("body") or "")
        if not body:
            continue
        scanned += 1
        leads.extend(
            _scan_body_for_secrets(
                body,
                receipt_id=str(rec.get("receipt_id") or rid),
                url=url,
                actor=actor,
                collected_secrets=collected_secrets,
            )
        )

    return leads, scanned


class _SurfaceCandidates:
    """Normalized, scope-filtered candidate URLs and param hints collected offline."""

    def __init__(self) -> None:
        self.all_urls: list[str] = []
        self.seen_norm_paths: set[str] = set()
        self.redirect_targets: list[tuple[str, str]] = []
        self.seen_redirect_keys: set[tuple[str, str]] = set()
        self.graphql_urls: list[str] = []
        self.seen_graphql_paths: set[str] = set()
        self.get_eligible_paths: set[str] = set()

    def add_candidate(
        self,
        http_client: AgenticHTTPClient,
        raw_url: str,
        *,
        params: Sequence[str] = (),
        method: str = "GET",
    ) -> None:
        raw = str(raw_url or "").strip()
        if not raw:
            return
        try:
            clean_url, norm_path, norm_query = http_client.resolve_in_scope(
                raw,
                allow_websocket=False,
            )
        except (ScopeViolationError, ValueError):
            return

        if (
            is_static_asset_url(clean_url)
            or is_non_endpoint_source_path(norm_path)
            or is_catalog_route(norm_path)
            or is_logout_route(norm_path)
            or is_destructive_lifecycle_route(norm_path)
        ):
            return

        if "{" in norm_path or "}" in norm_path or "/:" in norm_path:
            return

        norm_p = normalize_path(norm_path)
        norm_m = str(method or "GET").strip().upper() or "GET"
        base_no_query = urlunsplit(
            (urlsplit(clean_url).scheme, urlsplit(clean_url).netloc, norm_path, "", "")
        )

        if norm_p not in self.seen_norm_paths:
            self.seen_norm_paths.add(norm_p)
            self.all_urls.append(base_no_query)
        if norm_m in {"GET", "HEAD"}:
            self.get_eligible_paths.add(norm_p)

        segs = [s.lower() for s in norm_p.split("/") if s]
        if any(seg in _GRAPHQL_PATH_SEGMENTS for seg in segs) and norm_p not in self.seen_graphql_paths:
            self.seen_graphql_paths.add(norm_p)
            self.graphql_urls.append(base_no_query)

        if norm_m in {"GET", "HEAD"}:
            query_pairs = parse_qsl(norm_query, keep_blank_values=True)
            for qk, _ in query_pairs:
                self._maybe_add_redirect(clean_url, norm_p, qk)
            for pname in params:
                self._maybe_add_redirect(clean_url, norm_p, str(pname))

    def _maybe_add_redirect(self, clean_url: str, norm_p: str, param_name: str) -> None:
        clean_p = str(param_name or "").strip()
        low_p = clean_p.lower()
        if low_p not in _REDIRECT_PARAM_NAMES:
            return
        key = (norm_p, low_p)
        if key in self.seen_redirect_keys:
            return
        self.seen_redirect_keys.add(key)
        self.redirect_targets.append((clean_url, clean_p))


def _collect_candidates(
    http_client: AgenticHTTPClient,
    *,
    seed_surface: dict[str, Any] | None,
    candidate_urls: Sequence[str],
) -> _SurfaceCandidates:
    """Gather scope-checked endpoints and parameter hints from inputs and recent receipts."""
    cand = _SurfaceCandidates()

    for raw_u in candidate_urls:
        cand.add_candidate(http_client, str(raw_u))

    if isinstance(seed_surface, dict):
        for section, default_method in (
            ("links", "GET"),
            ("forms", "GET"),
            ("routes", "GET"),
            ("endpoints", "GET"),
        ):
            items = seed_surface.get(section)
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, str):
                    cand.add_candidate(http_client, item, method=default_method)
                elif isinstance(item, dict):
                    raw_target = item.get("url") or item.get("path") or ""
                    raw_params = item.get("params")
                    p_list = [str(p) for p in raw_params] if isinstance(raw_params, list) else []
                    item_method = str(item.get("method") or default_method).upper()
                    cand.add_candidate(http_client, str(raw_target), params=p_list, method=item_method)
        hints = seed_surface.get("discovery_hints")
        if isinstance(hints, list):
            for hint in hints:
                if isinstance(hint, str):
                    cand.add_candidate(http_client, hint)

    # Also harvest observed paths/query params/HTML links from recent stored receipts (0 HTTP).
    ids = http_client.receipt_store.list_ids()
    for rid in ids[-60:]:
        try:
            rec = http_client.receipt_store.get(rid)
        except (KeyError, ValueError):
            continue
        rec_url = str(rec.get("url") or rec.get("path") or "")
        rec_method = str(rec.get("method") or "GET").upper()
        if rec_url:
            cand.add_candidate(http_client, rec_url, method=rec_method)
        status = int(rec.get("status") or 0)
        ctype = str(rec.get("content_type") or "").lower()
        body = str(rec.get("body") or "")[:_MAX_HTML_LINK_EXTRACT_CHARS]
        if 200 <= status < 400 and body and ("html" in ctype or "<a " in body.lower() or "<form" in body.lower()):
            base_for_join = rec_url or http_client.base_url
            for m in _HTML_HREF_ACTION_RE.finditer(body):
                href = (m.group(1) or m.group(2) or "").strip()
                if href and not href.startswith(("#", "javascript:", "mailto:", "data:")):
                    cand.add_candidate(http_client, urljoin(base_for_join, href), method="GET")
            for fm in _HTML_FORM_TAG_RE.finditer(body):
                attrs_str, inner_html = fm.group(1), fm.group(2)
                method_m = _HTML_ATTR_METHOD_RE.search(attrs_str)
                f_method = (
                    (method_m.group(1) or method_m.group(2) or method_m.group(3) or "GET").upper()
                    if method_m
                    else "GET"
                )
                act_m = _HTML_ATTR_ACTION_RE.search(attrs_str)
                raw_action = (act_m.group(1) or act_m.group(2) or "").strip() if act_m else ""
                action_url = urljoin(base_for_join, raw_action) if raw_action else base_for_join
                input_names = [
                    (im.group(1) or im.group(2) or "").strip()
                    for im in _HTML_INPUT_NAME_RE.finditer(inner_html)
                ]
                cand.add_candidate(http_client, action_url, params=input_names, method=f_method)

    # Always keep root "/" as fallback candidate if nothing else was seeded.
    if not cand.all_urls:
        cand.add_candidate(http_client, "/")

    return cand


def _is_api_path(path: str) -> bool:
    return bool(_API_PATH_PREFIX_RE.search(normalize_path(path)))


def _select_cors_targets(candidates: _SurfaceCandidates, max_endpoints: int = _DEFAULT_MAX_CORS_PROBES) -> list[str]:
    """Select up to `max_endpoints` prioritized non-catalog API/root endpoints for CORS checks."""
    scored: list[tuple[int, int, str]] = []
    seen_id_templates: set[str] = set()
    for idx, url in enumerate(candidates.all_urls):
        norm_p = normalize_path(urlsplit(url).path or "/")
        if norm_p not in candidates.get_eligible_paths and norm_p != "/":
            continue
        tmpl = route_template_of(norm_p)
        has_id = "{id}" in tmpl
        if has_id:
            if tmpl in seen_id_templates:
                continue
            seen_id_templates.add(tmpl)
        is_api = _is_api_path(norm_p)
        if norm_p == "/":
            tier = 1
        elif is_api and not has_id:
            tier = 0
        elif not is_api and not has_id:
            tier = 2
        elif is_api and has_id:
            tier = 3
        else:
            tier = 4
        # Prefer non-login/functional endpoints and shorter API prefixes first.
        segs = [s.lower() for s in norm_p.split("/") if s]
        bonus = -1 if any(tok in segs for tok in ("cors", "config", "auth", "user", "profile", "session")) else 0
        scored.append((tier * 10 + bonus, idx, url))

    scored.sort(key=lambda item: (item[0], len(item[2]), item[1]))
    return [url for _, _, url in scored[: max(0, int(max_endpoints))]]


def probe_cors_leads(
    http_client: AgenticHTTPClient,
    budget: _PrescanBudget,
    candidates: _SurfaceCandidates,
    *,
    max_endpoints: int = _DEFAULT_MAX_CORS_PROBES,
) -> tuple[list[PrescanLead], int]:
    """Check 2: Probe up to 4 non-catalog API/root endpoints for CORS origin reflection."""
    if "GET" not in http_client.allowed_methods or not budget.can_request():
        return [], 0

    targets = _select_cors_targets(candidates, max_endpoints=max_endpoints)
    leads: list[PrescanLead] = []
    probed = 0

    for url in targets:
        if not budget.can_request():
            break
        rec, waf_blocked = _safe_request(
            http_client,
            budget,
            method="GET",
            url=url,
            actor="anon",
            headers={"Origin": CORS_PROBE_ORIGIN},
            follow_redirects=False,
        )
        if rec is None:
            if budget.exhausted:
                break
            continue
        probed += 1
        if waf_blocked:
            continue

        acao = _response_header_ci(rec, "access-control-allow-origin")
        acac = _response_header_ci(rec, "access-control-allow-credentials").lower()
        if not acao:
            continue

        reflected = acao.lower() == CORS_PROBE_ORIGIN.lower()
        wildcard_with_creds = acao == "*" and acac == "true"
        if not reflected and not wildcard_with_creds:
            continue

        if reflected and acac == "true":
            sev = "high"
            pattern = "reflected_origin_with_credentials"
        else:
            sev = "medium"
            pattern = "wildcard_with_credentials" if wildcard_with_creds else "reflected_origin"

        rid = str(rec.get("receipt_id") or "")
        leads.append(
            _make_lead(
                kind="cors_misconfiguration",
                suggested_class="cors_misconfiguration",
                severity_hint=sev,
                receipt_id=rid,
                url=str(rec.get("url") or url),
                actor=str(rec.get("actor") or "anon"),
                status=int(rec.get("status") or 0),
                probe_origin=CORS_PROBE_ORIGIN,
                acao=acao,
                acac=acac,
                summary=(
                    f"CORS {pattern} at {rec.get('url') or url}: "
                    f"ACAO={acao!r}, ACAC={acac!r} ({rid})."
                ),
                next_step=(
                    f"Verify cors_misconfiguration on {rid} with DifferentialOracle "
                    "(compare untrusted Origin vs same-origin/absent Origin baseline)."
                ),
            )
        )

    return leads, probed


def probe_open_redirect_leads(
    http_client: AgenticHTTPClient,
    budget: _PrescanBudget,
    candidates: _SurfaceCandidates,
    *,
    max_candidates: int = _DEFAULT_MAX_REDIRECT_PROBES,
) -> tuple[list[PrescanLead], int]:
    """Check 3: Probe routes with redirect-like query parameter names without following redirects."""
    if "GET" not in http_client.allowed_methods or not budget.can_request():
        return [], 0

    leads: list[PrescanLead] = []
    probed = 0

    for target_url, param_name in candidates.redirect_targets[: max(0, int(max_candidates))]:
        if not budget.can_request():
            break
        rec, waf_blocked = _safe_request(
            http_client,
            budget,
            method="GET",
            url=target_url,
            actor="anon",
            query={param_name: REDIRECT_PROBE_URL},
            follow_redirects=False,
        )
        if rec is None:
            if budget.exhausted:
                break
            continue
        probed += 1
        if waf_blocked:
            continue

        status = int(rec.get("status") or 0)
        if not (300 <= status < 400):
            continue

        location = str(rec.get("redirect_location") or "").strip()
        if not location:
            location = _response_header_ci(rec, "location")
        if not location:
            continue

        parsed_loc = urlsplit(location)
        loc_host = (parsed_loc.hostname or "").strip().lower().rstrip(".")
        if loc_host != REDIRECT_PROBE_HOST:
            continue

        rid = str(rec.get("receipt_id") or "")
        leads.append(
            _make_lead(
                kind="open_redirect",
                suggested_class="open_redirect",
                severity_hint="medium",
                receipt_id=rid,
                url=str(rec.get("url") or target_url),
                actor=str(rec.get("actor") or "anon"),
                param=param_name,
                status=status,
                location=location,
                summary=(
                    f"Open redirect candidate on param {param_name!r} at {rec.get('url') or target_url}: "
                    f"HTTP {status} -> Location={location!r} ({rid})."
                ),
                next_step=(
                    f"Verify open_redirect on {rid} against a benign relative path baseline "
                    f"({param_name}=/) using DifferentialOracle."
                ),
            )
        )

    return leads, probed


def _is_graphql_introspection_200(receipt: dict[str, Any]) -> bool:
    if int(receipt.get("status") or 0) != 200:
        return False
    body = str(receipt.get("body") or "")
    if '"queryType"' not in body and "queryType" not in body:
        return False
    stripped = body.lstrip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            data = parsed.get("data")
            if isinstance(data, dict):
                schema = data.get("__schema")
                if isinstance(schema, dict) and "queryType" in schema:
                    return True
            if "__schema" in parsed and "queryType" in str(parsed["__schema"]):
                return True
            if parsed.get("errors") and not data:
                return False
    return '"queryType"' in body and '"errors"' not in body


def probe_graphql_leads(
    http_client: AgenticHTTPClient,
    budget: _PrescanBudget,
    candidates: _SurfaceCandidates,
    *,
    max_endpoints: int = _DEFAULT_MAX_GRAPHQL_PROBES,
) -> tuple[list[PrescanLead], int]:
    """Check 4: Probe discovered GraphQL endpoints for enabled schema introspection."""
    can_post = "POST" in http_client.allowed_methods
    can_get = "GET" in http_client.allowed_methods
    if (not can_post and not can_get) or not budget.can_request():
        return [], 0

    leads: list[PrescanLead] = []
    probed = 0
    auth_actors = http_client.actors.authenticated_non_anon_aliases()

    for gql_url in candidates.graphql_urls[: max(0, int(max_endpoints))]:
        if not budget.can_request():
            break

        method = "POST" if can_post else "GET"
        rec, waf_blocked = _safe_request(
            http_client,
            budget,
            method=method,
            url=gql_url,
            actor="anon",
            json_body={"query": GRAPHQL_INTROSPECTION_QUERY} if method == "POST" else None,
            query={"query": GRAPHQL_INTROSPECTION_QUERY} if method == "GET" else None,
            follow_redirects=False,
        )
        if rec is None:
            if budget.exhausted:
                break
            continue
        probed += 1
        if waf_blocked:
            continue

        # Fallback to GET if POST returned 405 Method Not Allowed.
        if method == "POST" and int(rec.get("status") or 0) == 405 and can_get and budget.can_request():
            method = "GET"
            rec, waf_blocked = _safe_request(
                http_client,
                budget,
                method="GET",
                url=gql_url,
                actor="anon",
                query={"query": GRAPHQL_INTROSPECTION_QUERY},
                follow_redirects=False,
            )
            if rec is None:
                if budget.exhausted:
                    break
                continue
            probed += 1
            if waf_blocked:
                continue

        # If anon was denied (401/403) and an authenticated actor exists, check once as auth actor.
        if int(rec.get("status") or 0) in {401, 403} and auth_actors and budget.can_request():
            rec_auth, waf_auth = _safe_request(
                http_client,
                budget,
                method=method,
                url=gql_url,
                actor=auth_actors[0],
                json_body={"query": GRAPHQL_INTROSPECTION_QUERY} if method == "POST" else None,
                query={"query": GRAPHQL_INTROSPECTION_QUERY} if method == "GET" else None,
                follow_redirects=False,
            )
            if rec_auth is not None:
                probed += 1
                if not waf_auth:
                    rec = rec_auth

        if _is_graphql_introspection_200(rec):
            rid = str(rec.get("receipt_id") or "")
            leads.append(
                _make_lead(
                    kind="graphql_introspection",
                    suggested_class="other",
                    severity_hint="low",
                    receipt_id=rid,
                    url=str(rec.get("url") or gql_url),
                    method=method,
                    actor=str(rec.get("actor") or "anon"),
                    status=200,
                    summary=(
                        f"GraphQL introspection enabled at {rec.get('url') or gql_url} "
                        f"via {method} ({rid})."
                    ),
                    next_step=(
                        f"Read {rid} to map GraphQL types/mutations and test queries/mutations "
                        "for BOLA/BFLA/injection."
                    ),
                )
            )

    return leads, probed


def _is_error_or_soft_deny_json(parsed: Any) -> bool:
    if not isinstance(parsed, dict):
        return False
    has_data_key = any(
        k in parsed and parsed[k] not in (None, "", [], {})
        for k in ("data", "result", "rows", "items")
    )
    if (parsed.get("error") or parsed.get("errors")) and not has_data_key:
        return True
    if (parsed.get("ok") is False or parsed.get("success") is False) and not has_data_key:
        return True
    code_raw = parsed.get("code")
    if isinstance(code_raw, int) and not isinstance(code_raw, bool):
        if code_raw in {400, 401, 403, 404} and not has_data_key:
            return True
    msg = str(parsed.get("message") or parsed.get("detail") or "").lower()
    if msg and not has_data_key and any(tok in msg for tok in _SOFT_DENY_MESSAGES):
        return True
    if parsed.get("not_found") is True and not has_data_key:
        return True
    return False


def _is_substantive_non_html_response(receipt: dict[str, Any]) -> tuple[bool, Any, bool]:
    """Return `(is_substantive, parsed_json_or_none, is_json)` for HTTP 200 non-HTML bodies."""
    if int(receipt.get("status") or 0) != 200:
        return False, None, False
    ctype = str(receipt.get("content_type") or "").lower()
    body = str(receipt.get("body") or "")
    stripped = body.strip()
    if not stripped:
        return False, None, False
    if "html" in ctype or stripped[:64].lower().startswith(("<!doctype", "<html")):
        return False, None, False

    looks_json = "json" in ctype or stripped.startswith(("{", "["))
    if looks_json:
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None
        if parsed is not None:
            if isinstance(parsed, dict):
                if not parsed or _is_error_or_soft_deny_json(parsed):
                    return False, parsed, True
                lower_keys = {str(k).strip().lower() for k in parsed.keys()}
                if lower_keys <= _TRIVIAL_ACK_KEYS and all(
                    not isinstance(v, (dict, list)) for v in parsed.values()
                ):
                    return False, parsed, True
                return True, parsed, True
            if isinstance(parsed, list):
                if not parsed:
                    return False, parsed, True
                return True, parsed, True
            return False, parsed, True

    if len(stripped) < 10:
        return False, None, False
    low = stripped.lower()
    if len(stripped) <= 200 and any(tok in low for tok in _SOFT_DENY_MESSAGES):
        return False, None, False
    return True, None, False


def _flatten_json_tokens(
    obj: Any,
    *,
    prefix: str = "",
    depth: int = 0,
    keys_out: set[str],
    kv_out: set[str],
    owners_out: dict[str, str],
) -> None:
    if depth > 4 or len(kv_out) >= 200:
        return
    if isinstance(obj, dict):
        for raw_k, val in obj.items():
            k = str(raw_k)
            k_low = k.lower()
            if k_low in _EPHEMERAL_JSON_KEYS:
                continue
            path_k = f"{prefix}.{k_low}" if prefix else k_low
            keys_out.add(path_k)
            if k_low in _OWNER_JSON_KEYS and isinstance(val, (str, int)) and not isinstance(val, bool):
                sval = str(val).strip().lower()
                if sval:
                    owners_out.setdefault(k_low, sval)
            _flatten_json_tokens(
                val,
                prefix=path_k,
                depth=depth + 1,
                keys_out=keys_out,
                kv_out=kv_out,
                owners_out=owners_out,
            )
    elif isinstance(obj, list):
        for idx, item in enumerate(obj[:12]):
            _flatten_json_tokens(
                item,
                prefix=f"{prefix}[{idx}]",
                depth=depth + 1,
                keys_out=keys_out,
                kv_out=kv_out,
                owners_out=owners_out,
            )
    elif obj is not None:
        kv_out.add(f"{prefix}={str(obj)[:80]}")


def _payload_similarity(receipt_a: dict[str, Any], receipt_b: dict[str, Any], parsed_a: Any, parsed_b: Any) -> float:
    """Compute structural + value similarity between two substantive HTTP 200 responses."""
    body_a = str(receipt_a.get("body") or "").strip()
    body_b = str(receipt_b.get("body") or "").strip()
    if body_a == body_b:
        return 1.0

    if parsed_a is not None and parsed_b is not None:
        keys_a: set[str] = set()
        keys_b: set[str] = set()
        kv_a: set[str] = set()
        kv_b: set[str] = set()
        owners_a: dict[str, str] = {}
        owners_b: dict[str, str] = {}
        _flatten_json_tokens(parsed_a, keys_out=keys_a, kv_out=kv_a, owners_out=owners_a)
        _flatten_json_tokens(parsed_b, keys_out=keys_b, kv_out=kv_b, owners_out=owners_b)

        # Distinct owner/user values in the two responses indicate actor-scoped objects, not BOLA.
        for ok in set(owners_a) & set(owners_b):
            if owners_a[ok] != owners_b[ok]:
                return 0.0

        if not keys_a and not keys_b:
            return 1.0 if body_a == body_b else 0.0
        key_jaccard = len(keys_a & keys_b) / max(1, len(keys_a | keys_b))
        if kv_a or kv_b:
            val_jaccard = len(kv_a & kv_b) / max(1, len(kv_a | kv_b))
            return round(0.7 * val_jaccard + 0.3 * key_jaccard, 3)
        return round(key_jaccard, 3)

    return round(SequenceMatcher(None, body_a[:4000], body_b[:4000]).ratio(), 3)


def _looks_like_private_json_payload(parsed: Any, path: str) -> bool:
    """Return True if a substantive JSON payload looks like private/domain data rather than a catalog shell."""
    if parsed is None:
        return False
    dicts_to_inspect: list[dict[str, Any]] = []
    if isinstance(parsed, dict):
        if _is_error_or_soft_deny_json(parsed):
            return False
        dicts_to_inspect.append(parsed)
        for sub in parsed.values():
            if isinstance(sub, dict):
                dicts_to_inspect.append(sub)
            elif isinstance(sub, list):
                dicts_to_inspect.extend(item for item in sub[:5] if isinstance(item, dict))
    elif isinstance(parsed, list):
        dicts_to_inspect = [item for item in parsed[:5] if isinstance(item, dict)]

    all_keys: set[str] = set()
    for d in dicts_to_inspect:
        for k in d.keys():
            all_keys.add(str(k).strip().lower())

    if not all_keys:
        return False
    if all_keys & _STRONG_PRIVATE_JSON_KEYS:
        return True
    if all_keys <= (_CATALOG_ONLY_JSON_KEYS | {"id", "name", "title", "price", "description"}):
        return False

    segs = {
        tok
        for seg in normalize_path(path).lower().split("/")
        if seg and not is_id_segment(seg)
        for tok in re.split(r"[^a-z0-9]+", seg)
        if tok
    }
    if segs & _SENSITIVE_ROUTE_TOKENS:
        return True
    return len(all_keys - {"id", "status", "ok"}) >= 2


def _has_object_id(url: str) -> bool:
    parsed = urlsplit(url)
    norm_p = normalize_path(parsed.path or "/")
    if "{id}" in route_template_of(norm_p):
        return True
    for qk, _ in parse_qsl(parsed.query, keep_blank_values=True):
        low = qk.strip().lower()
        if low == "id" or low.endswith("_id") or low == "uuid":
            return True
    return False


def _is_privileged_or_admin_path(path: str) -> bool:
    segs = {
        tok
        for seg in normalize_path(path).lower().split("/")
        if seg and not is_id_segment(seg)
        for tok in re.split(r"[^a-z0-9]+", seg)
        if tok
    }
    return bool(segs & {"admin", "administrator", "internal", "audit", "stats", "metrics", "export", "config", "users"})


def _is_bfla_relevant_target(path: str, parsed: Any) -> bool:
    """Return True when endpoint path or JSON payload represents sensitive/API/admin data for BFLA."""
    norm_p = normalize_path(path)
    if _has_object_id(norm_p) or _is_privileged_or_admin_path(norm_p):
        return True
    segs = {
        tok
        for seg in norm_p.lower().split("/")
        if seg and not is_id_segment(seg)
        for tok in re.split(r"[^a-z0-9]+", seg)
        if tok
    }
    if segs & (_SENSITIVE_ROUTE_TOKENS | {"debug", "private", "secret", "secrets", "keys", "token", "tokens", "role", "roles", "permission", "permissions"}):
        return True
    if isinstance(parsed, dict):
        keys = {str(k).strip().lower() for k in parsed.keys()}
        if keys & _BFLA_ADMIN_JSON_KEYS:
            return True
    elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
        keys = {str(k).strip().lower() for k in parsed[0].keys()}
        if keys & _BFLA_ADMIN_JSON_KEYS:
            return True
    return parsed is None  # Non-HTML non-JSON export/data (e.g. CSV/text dump)


def _select_prematrix_endpoints(
    candidates: _SurfaceCandidates,
    max_endpoints: int = _DEFAULT_MAX_MATRIX_ENDPOINTS,
) -> list[str]:
    """Select up to `max_endpoints` high-value non-catalog GET endpoints for BOLA/BFLA checks."""
    scored: list[tuple[int, int, str]] = []
    template_counts: dict[str, int] = {}

    for idx, url in enumerate(candidates.all_urls):
        norm_p = normalize_path(urlsplit(url).path or "/")
        if norm_p in _PREMATRIX_SKIP_EXACT_PATHS or norm_p == "/":
            continue
        if norm_p not in candidates.get_eligible_paths:
            continue
        segs = [s.lower() for s in norm_p.split("/") if s]
        if any(seg in _GRAPHQL_PATH_SEGMENTS for seg in segs):
            continue

        tmpl = route_template_of(norm_p)
        has_id = _has_object_id(url)
        is_api = _is_api_path(norm_p)
        tokens = {tok for seg in segs for tok in re.split(r"[^a-z0-9]+", seg) if tok}
        is_sensitive = bool(tokens & _SENSITIVE_ROUTE_TOKENS)

        if not (has_id or is_api or is_sensitive):
            continue

        seen_for_tmpl = template_counts.get(tmpl, 0)
        max_per_tmpl = 3 if has_id else 2
        if seen_for_tmpl >= max_per_tmpl:
            continue
        template_counts[tmpl] = seen_for_tmpl + 1

        score = 0
        if has_id:
            score += 50
        if is_sensitive:
            score += 40
        if is_api:
            score += 30
        if _is_privileged_or_admin_path(norm_p):
            score += 15
        # Keep diversity across route templates before testing second/third IDs of the same template.
        score -= seen_for_tmpl * 12
        scored.append((-score, idx, url))

    scored.sort(key=lambda item: (item[0], item[1]))
    return [url for _, _, url in scored[: max(0, int(max_endpoints))]]


def _pick_bola_actor_pair(
    auth_aliases: Sequence[str],
    actor_meta: dict[str, dict[str, str]],
) -> tuple[str, str, bool]:
    """Pick `(actor_a, actor_b, require_explicit_other_owner)` for BOLA probing."""
    non_admins = [
        alias
        for alias in auth_aliases
        if str((actor_meta.get(alias) or {}).get("role") or "").strip().lower() not in _ADMIN_ROLES
    ]
    if len(non_admins) >= 2:
        # Prefer same-tenant peer actors first for classic horizontal BOLA.
        for idx, actor_a in enumerate(non_admins):
            t_a = str((actor_meta.get(actor_a) or {}).get("tenant") or "").strip().lower()
            for actor_b in non_admins[idx + 1 :]:
                t_b = str((actor_meta.get(actor_b) or {}).get("tenant") or "").strip().lower()
                if t_a == t_b:
                    return actor_a, actor_b, False
        return non_admins[0], non_admins[1], False
    if len(non_admins) == 1 and len(auth_aliases) >= 2:
        other = next(a for a in auth_aliases if a != non_admins[0])
        return non_admins[0], other, True
    return "", "", False


def _extract_owner_value(parsed: Any) -> str:
    if not isinstance(parsed, dict):
        return ""
    for key in ("owner", "owner_id", "owner_alias", "user", "username", "actor", "created_by", "author"):
        val = parsed.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip().lower()
    return ""


def run_bola_bfla_prematrix(
    http_client: AgenticHTTPClient,
    budget: _PrescanBudget,
    candidates: _SurfaceCandidates,
    *,
    max_endpoints: int = _DEFAULT_MAX_MATRIX_ENDPOINTS,
) -> tuple[list[PrescanLead], int]:
    """Check 5: Compare `anon` and authenticated actors across prioritized non-catalog GET endpoints."""
    if "GET" not in http_client.allowed_methods or not budget.can_request():
        return [], 0

    auth_aliases = http_client.actors.authenticated_non_anon_aliases()
    if not auth_aliases:
        return [], 0

    actor_meta = {
        str(row["alias"]): row
        for row in http_client.actors.summaries()
        if isinstance(row, dict) and row.get("alias")
    }
    non_admins = [
        a for a in auth_aliases if str((actor_meta.get(a) or {}).get("role") or "").lower() not in _ADMIN_ROLES
    ]
    admins = [
        a for a in auth_aliases if str((actor_meta.get(a) or {}).get("role") or "").lower() in _ADMIN_ROLES
    ]
    bola_a, bola_b, bola_require_explicit_other_owner = _pick_bola_actor_pair(auth_aliases, actor_meta)

    endpoints = _select_prematrix_endpoints(candidates, max_endpoints=max_endpoints)
    leads: list[PrescanLead] = []
    endpoints_probed = 0

    for url in endpoints:
        if not budget.can_request():
            break

        norm_p = normalize_path(urlsplit(url).path or "/")
        is_object_route = _has_object_id(url)
        is_priv_route = _is_privileged_or_admin_path(norm_p)
        endpoints_probed += 1

        # 1. Fetch as anon baseline
        rec_anon, waf_anon = _safe_request(
            http_client,
            budget,
            method="GET",
            url=url,
            actor="anon",
            follow_redirects=False,
        )
        if rec_anon is None and budget.exhausted:
            break

        # Choose reference authenticated actor for BFLA check
        if is_priv_route and admins:
            ref_actor = admins[0]
        elif non_admins:
            ref_actor = non_admins[0]
        else:
            ref_actor = auth_aliases[0]

        actor_receipts: dict[str, tuple[dict[str, Any], bool, Any, bool]] = {}

        def _fetch_actor(alias: str) -> tuple[dict[str, Any] | None, bool, Any, bool]:
            if alias in actor_receipts:
                rec_c, sub_c, par_c, is_j_c = actor_receipts[alias]
                return rec_c, sub_c, par_c, is_j_c
            if not budget.can_request():
                return None, False, None, False
            rec_x, waf_x = _safe_request(
                http_client,
                budget,
                method="GET",
                url=url,
                actor=alias,
                follow_redirects=False,
            )
            if rec_x is None or waf_x:
                return rec_x, False, None, False
            sub_x, par_x, is_j_x = _is_substantive_non_html_response(rec_x)
            actor_receipts[alias] = (rec_x, sub_x, par_x, is_j_x)
            return rec_x, sub_x, par_x, is_j_x

        # 2. Fetch primary actor(s) needed for BFLA and/or BOLA
        if is_object_route and bola_a:
            rec_a, sub_a, par_a, _ = _fetch_actor(bola_a)
            if rec_a is None and budget.exhausted:
                break
        rec_ref, sub_ref, par_ref, _ = _fetch_actor(ref_actor)
        if rec_ref is None and budget.exhausted:
            break

        # 3. BFLA Check (anon vs authenticated reference actor)
        bfla_emitted = False
        if rec_anon is not None and not waf_anon and rec_ref is not None and sub_ref:
            anon_sub, anon_parsed, _ = _is_substantive_non_html_response(rec_anon)
            if anon_sub and _is_bfla_relevant_target(norm_p, anon_parsed):
                sim_anon = _payload_similarity(rec_anon, rec_ref, anon_parsed, par_ref)
                if sim_anon >= 0.70:
                    anon_rid = str(rec_anon.get("receipt_id") or "")
                    ref_rid = str(rec_ref.get("receipt_id") or "")
                    leads.append(
                        _make_lead(
                            kind="bfla_candidate",
                            suggested_class="auth_bypass",
                            severity_hint="high",
                            receipt_id=anon_rid,
                            proof_receipt_id=anon_rid,
                            control_receipt_id=ref_rid,
                            url=str(rec_anon.get("url") or url),
                            actor="anon",
                            control_actor=ref_actor,
                            similarity=sim_anon,
                            summary=(
                                f"Unauthenticated access / BFLA candidate at {url}: "
                                f"anon ({anon_rid}) got 200 matching {ref_actor} ({ref_rid}, sim={sim_anon:.2f})."
                            ),
                            next_step=(
                                f"Verify auth_bypass/bfla via DifferentialOracle using proof={anon_rid} "
                                f"and control={ref_rid} (note: anon 200 -> record as auth_bypass)."
                            ),
                        )
                    )
                    bfla_emitted = True

        # 3b. Vertical BFLA when anon was denied (401/403) on a privileged route and non-admin can access it
        if (
            not bfla_emitted
            and is_priv_route
            and rec_anon is not None
            and int(rec_anon.get("status") or 0) in {401, 403}
            and admins
            and non_admins
            and rec_ref is not None
            and sub_ref
        ):
            member_actor = non_admins[0]
            rec_mem, sub_mem, par_mem, _ = _fetch_actor(member_actor)
            if rec_mem is not None and sub_mem:
                sim_vert = _payload_similarity(rec_mem, rec_ref, par_mem, par_ref)
                if sim_vert >= 0.70:
                    mem_rid = str(rec_mem.get("receipt_id") or "")
                    anon_rid = str(rec_anon.get("receipt_id") or "")
                    leads.append(
                        _make_lead(
                            kind="bfla_candidate",
                            suggested_class="bfla",
                            severity_hint="high",
                            receipt_id=mem_rid,
                            proof_receipt_id=mem_rid,
                            control_receipt_id=anon_rid,
                            url=str(rec_mem.get("url") or url),
                            actor=member_actor,
                            control_actor="anon",
                            similarity=sim_vert,
                            summary=(
                                f"Vertical BFLA candidate at {url}: non-admin {member_actor} ({mem_rid}) "
                                f"got 200 matching {ref_actor} while anon ({anon_rid}) got {rec_anon.get('status')}."
                            ),
                            next_step=(
                                f"Verify bfla via DifferentialOracle using proof={mem_rid} "
                                f"and control={anon_rid}."
                            ),
                        )
                    )

        # 4. BOLA / Cross-Actor IDOR Check (object-ID routes across >= 2 authenticated actors)
        if is_object_route and bola_a and bola_b:
            rec_a, sub_a, par_a, is_json_a = _fetch_actor(bola_a)
            if rec_a is None and budget.exhausted:
                break
            if rec_a is not None and sub_a and is_json_a and _looks_like_private_json_payload(par_a, norm_p):
                rec_b, sub_b, par_b, is_json_b = _fetch_actor(bola_b)
                if rec_b is None and budget.exhausted:
                    break
                if (
                    rec_b is not None
                    and sub_b
                    and is_json_b
                    and _looks_like_private_json_payload(par_b, norm_p)
                ):
                    sim_bola = _payload_similarity(rec_a, rec_b, par_a, par_b)
                    if sim_bola >= 0.70:
                        owner_val = _extract_owner_value(par_a) or _extract_owner_value(par_b)
                        # Avoid flagging an admin actor legitimately inspecting a member's own object.
                        if bola_require_explicit_other_owner and owner_val != bola_b.lower():
                            continue
                        if owner_val == bola_b.lower():
                            proof_actor, proof_rec = bola_a, rec_a
                            ctrl_actor, ctrl_rec = bola_b, rec_b
                        else:
                            proof_actor, proof_rec = bola_b, rec_b
                            ctrl_actor, ctrl_rec = bola_a, rec_a
                        proof_rid = str(proof_rec.get("receipt_id") or "")
                        ctrl_rid = str(ctrl_rec.get("receipt_id") or "")
                        leads.append(
                            _make_lead(
                                kind="bola_candidate",
                                suggested_class="bola",
                                severity_hint="high",
                                receipt_id=proof_rid,
                                proof_receipt_id=proof_rid,
                                control_receipt_id=ctrl_rid,
                                url=str(proof_rec.get("url") or url),
                                actor=proof_actor,
                                control_actor=ctrl_actor,
                                similarity=sim_bola,
                                summary=(
                                    f"Cross-actor BOLA candidate at {url}: both {ctrl_actor} ({ctrl_rid}) "
                                    f"and {proof_actor} ({proof_rid}) got 200 with matching private JSON "
                                    f"(sim={sim_bola:.2f})."
                                ),
                                next_step=(
                                    f"Verify bola/tenant_isolation via DifferentialOracle using "
                                    f"proof={proof_rid} and control={ctrl_rid}."
                                ),
                            )
                        )

    return leads, endpoints_probed


def _dedup_and_sort_leads(leads: Sequence[PrescanLead]) -> list[PrescanLead]:
    deduped: list[PrescanLead] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for lead in leads:
        dedup_key = (
            str(lead.get("kind") or ""),
            str(lead.get("url") or ""),
            str(lead.get("key_name") or lead.get("param") or ""),
            str(lead.get("receipt_id") or ""),
            str(lead.get("control_receipt_id") or ""),
        )
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        deduped.append(dict(lead))  # type: ignore[arg-type]

    deduped.sort(
        key=lambda item: (
            _PRIORITY_RANK.get(str(item.get("severity_hint") or "low").lower(), 9),
            str(item.get("kind") or ""),
            str(item.get("url") or ""),
            str(item.get("receipt_id") or ""),
        )
    )
    for idx, item in enumerate(deduped, start=1):
        item["lead_id"] = f"prescan-{idx:03d}"
    return deduped


def _scrub_secrets_recursive(value: Any, secrets: Sequence[str]) -> Any:
    """Ensure no matched or known raw secret substring ever appears in prescan output."""
    if isinstance(value, str):
        out = value
        for sec in secrets:
            if sec and sec in out:
                out = out.replace(sec, _redacted_preview(sec))
        return out
    if isinstance(value, list):
        return [_scrub_secrets_recursive(item, secrets) for item in value]
    if isinstance(value, dict):
        return {str(k): _scrub_secrets_recursive(v, secrets) for k, v in value.items()}
    return value


def run_deterministic_prescan(
    http_client: AgenticHTTPClient,
    *,
    output_dir: Path | None = None,
    seed_surface: dict[str, Any] | None = None,
    candidate_urls: Sequence[str] = (),
    max_requests: int = 24,
) -> dict[str, Any]:
    """Run the 5 deterministic 0-LLM-token pre-scanner checks through `http_client`."""
    started = time.monotonic()
    budget = _PrescanBudget(http_client, max_requests=max_requests)
    discovered_secrets: set[str] = set()
    for sec in http_client.actors.all_secrets():
        if isinstance(sec, str) and len(sec) >= 4:
            discovered_secrets.add(sec)

    # Check 1 (0 HTTP): Triage already-stored receipts before live probing.
    offline_leads_pre, receipts_scanned = scan_offline_secret_leads(
        http_client.receipt_store,
        waf_vendors_out=budget.waf_vendors_seen,
        _secret_sink=discovered_secrets,
    )

    candidates = _collect_candidates(
        http_client,
        seed_surface=seed_surface,
        candidate_urls=candidate_urls,
    )

    # Checks 2-5: bounded live probes via http_client.request (ServiceDegradationError propagates).
    cors_leads, cors_probed = probe_cors_leads(http_client, budget, candidates)
    redirect_leads, redirect_probed = probe_open_redirect_leads(http_client, budget, candidates)
    graphql_leads, graphql_probed = probe_graphql_leads(http_client, budget, candidates)
    matrix_leads, matrix_probed = run_bola_bfla_prematrix(http_client, budget, candidates)

    # Re-scan receipts at 0 HTTP cost so any anon responses fetched in Checks 2-5 are also triaged.
    offline_leads_post, receipts_scanned_post = scan_offline_secret_leads(
        http_client.receipt_store,
        waf_vendors_out=budget.waf_vendors_seen,
        _secret_sink=discovered_secrets,
    )

    all_leads = _dedup_and_sort_leads([
        *offline_leads_pre,
        *offline_leads_post,
        *cors_leads,
        *redirect_leads,
        *graphql_leads,
        *matrix_leads,
    ])

    priority_counts = {"high": 0, "medium": 0, "low": 0}
    kind_counts: dict[str, int] = {}
    for lead in all_leads:
        sev = str(lead.get("severity_hint") or "low").lower()
        if sev in priority_counts:
            priority_counts[sev] += 1
        kind = str(lead.get("kind") or "other")
        kind_counts[kind] = kind_counts.get(kind, 0) + 1

    prescan_doc: dict[str, Any] = {
        "schema": SCHEMA,
        "base_url": http_client.base_url,
        "status": "budget_exhausted" if budget.exhausted else "ok",
        "leads": all_leads,
        "waf_vendors_seen": sorted(budget.waf_vendors_seen),
        "stats": {
            "requests_sent": budget.spent,
            "requests_attempted": budget.requests_attempted,
            "max_requests": int(max_requests),
            "effective_request_cap": budget.effective_cap,
            "budget_exhausted": budget.exhausted,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "leads_total": len(all_leads),
            "leads_by_priority": priority_counts,
            "leads_by_kind": dict(sorted(kind_counts.items())),
            "waf_blocks_skipped": budget.waf_blocks_skipped,
            "checks": {
                "offline_secrets": {
                    "receipts_scanned": max(receipts_scanned, receipts_scanned_post),
                    "leads": sum(
                        1
                        for lead in all_leads
                        if lead.get("kind")
                        in {"exposed_secret", "aws_access_key", "private_key", "hardcoded_api_key", "oauth_client_credentials"}
                    ),
                },
                "cors": {"probed": cors_probed, "leads": len(cors_leads)},
                "open_redirect": {"probed": redirect_probed, "leads": len(redirect_leads)},
                "graphql": {"probed": graphql_probed, "leads": len(graphql_leads)},
                "bola_bfla": {"endpoints_probed": matrix_probed, "leads": len(matrix_leads)},
            },
        },
    }

    sorted_secrets = sorted(discovered_secrets, key=len, reverse=True)
    clean_doc: dict[str, Any] = _scrub_secrets_recursive(prescan_doc, sorted_secrets)

    if output_dir is not None:
        summary_path = Path(output_dir) / "prescan-summary.json"
        _atomic_write_json(summary_path, clean_doc)
        clean_doc["summary_file"] = str(summary_path)

    return clean_doc


def _format_lead_line(lead: dict[str, Any]) -> str:
    sev = str(lead.get("severity_hint") or "low").upper()
    kind = str(lead.get("kind") or "lead")
    url = str(lead.get("url") or "/")
    rid = str(lead.get("receipt_id") or "")
    ctrl_rid = str(lead.get("control_receipt_id") or "")
    suggested = str(lead.get("suggested_class") or "other")

    if kind in {"bfla_candidate", "bola_candidate"}:
        proof_rid = str(lead.get("proof_receipt_id") or rid)
        actor = str(lead.get("actor") or "")
        ctrl_actor = str(lead.get("control_actor") or "")
        sim = lead.get("similarity")
        sim_txt = f" sim={float(sim):.2f}" if isinstance(sim, (int, float)) else ""
        return (
            f"- [{sev}] {kind} ({suggested}) {url}: proof={proof_rid}({actor}) vs "
            f"ctrl={ctrl_rid}({ctrl_actor}){sim_txt}"
        )
    if kind == "cors_misconfiguration":
        acao = str(lead.get("acao") or "")
        acac = str(lead.get("acac") or "")
        return (
            f"- [{sev}] {kind} {url} [{rid}]: ACAO={acao} ACAC={acac or 'absent'}"
        )
    if kind == "open_redirect":
        param = str(lead.get("param") or "")
        status = lead.get("status")
        loc = str(lead.get("location") or "")[:96]
        return f"- [{sev}] {kind} {url} [{rid}]: param={param} status={status} Location={loc}"
    if kind == "graphql_introspection":
        method = str(lead.get("method") or "POST")
        return f"- [{sev}] {kind} {url} [{rid}]: method={method} schema queryType exposed"
    key_name = str(lead.get("key_name") or "secret")
    preview = str(lead.get("redacted_preview") or "<REDACTED>")
    return f"- [{sev}] {kind} {url} [{rid}]: key={key_name} {preview}"


def format_prescan_handoff(prescan_doc: dict[str, Any] | None, *, max_chars: int = 2400) -> str:
    """Render a compact, bounded Turn-1 verification handoff block from `prescan_doc`."""
    if max_chars <= 0 or not isinstance(prescan_doc, dict):
        return ""
    leads = [item for item in (prescan_doc.get("leads") or []) if isinstance(item, dict)]
    waf_vendors = [str(v) for v in (prescan_doc.get("waf_vendors_seen") or []) if str(v)]
    if not leads and not waf_vendors:
        return ""

    raw_stats = prescan_doc.get("stats")
    stats: dict[str, Any] = raw_stats if isinstance(raw_stats, dict) else {}
    reqs = int(stats.get("requests_sent") or 0)
    header = (
        f"[PRESCAN LEADS] Deterministic pre-scan ({reqs} reqs, {len(leads)} unverified leads). "
        "Verify with DifferentialOracle / record_finding on Turn 1 (never treat as confirmed without control):"
    )
    if waf_vendors:
        header = f"{header}\nWAF vendors observed: {', '.join(waf_vendors)}"

    lines: list[str] = [header]
    used_len = len(header)
    omitted = 0

    for idx, lead in enumerate(leads):
        line = _format_lead_line(lead)
        added_len = 1 + len(line)
        reserve_footer = 32 if idx < len(leads) - 1 else 0
        if used_len + added_len + reserve_footer > max_chars:
            omitted = len(leads) - idx
            break
        lines.append(line)
        used_len += added_len

    if omitted > 0:
        footer = f"... (+{omitted} more leads in prescan-summary.json)"
        if used_len + 1 + len(footer) <= max_chars:
            lines.append(footer)

    rendered = "\n".join(lines)
    if len(rendered) > max_chars:
        if max_chars <= 3:
            return rendered[:max_chars]
        return rendered[: max_chars - 3].rstrip() + "..."
    return rendered


__all__ = [
    "CORS_PROBE_ORIGIN",
    "GRAPHQL_INTROSPECTION_QUERY",
    "PrescanLead",
    "REDIRECT_PROBE_HOST",
    "REDIRECT_PROBE_URL",
    "SCHEMA",
    "format_prescan_handoff",
    "probe_cors_leads",
    "probe_graphql_leads",
    "probe_open_redirect_leads",
    "run_bola_bfla_prematrix",
    "run_deterministic_prescan",
    "scan_offline_secret_leads",
]
