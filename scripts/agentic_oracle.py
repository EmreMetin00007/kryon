"""Layer 4: Protocol-level, vuln-class-agnostic 3-stage Clean-Replay Differential Oracle."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import uuid

import requests

from agentic_http import AgenticHTTPClient, BudgetExhaustedError, _decode_raw_response
from agentic_receipts import ReceiptStore
from agentic_surface import is_id_segment, normalize_path, route_template_of

VALID_VERIFICATION_GATES = frozenset({"differential", "llm_self_judge"})

_BOLA_OWNER_KEYS = (
    "owner",
    "owner_id",
    "owner_alias",
    "requested_by",
    "created_by",
    "author",
    "user",
    "username",
    "actor",
    "assigned_to",
)
_BOLA_TENANT_KEYS = (
    "tenant",
    "tenant_slug",
    "tenant_id",
    "org",
    "organization",
    "company",
)

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
    "csrf_token",
    "csrf",
    "xsrf_token",
    "etag",
    "iat",
    "exp",
    "jti",
})
_ISO_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_NON_REPLAY_REQ_HEADERS = frozenset({
    "authorization",
    "cookie",
    "x-csrf-token",
    "x-xsrf-token",
    "content-length",
    "host",
})
_INPUT_DIFF_CLASSES = frozenset({
    "reflected_xss",
    "stored_xss",
    "sqli",
    "sqli_read",
    "open_redirect",
    "mass_assignment",
    "ssti",
    "path_traversal",
    "csrf",
    "ssrf",
})
_ACCESS_CLASSES = frozenset({"auth_bypass", "bfla", "bola", "tenant_isolation"})
_CONCURRENCY_CLASSES = frozenset({"race_condition", "business_logic"})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
_PERSISTENT_CLASSES = frozenset({"stored_xss", "mass_assignment", "ssti"})
_API_PREFIX_SEGMENTS = frozenset({"api", "v1", "v2", "v3", "v4"})
_API_VERSION_SEG_RE = re.compile(r"^v\d+$", re.I)


def _extract_owner_and_tenant_from_receipt(
    receipt: dict[str, Any],
    actor_meta_map: dict[str, dict[str, str]],
) -> tuple[str, str]:
    """Extract explicit owner alias and tenant string from a JSON response receipt."""
    body = str(receipt.get("body") or "").strip()
    if not body.startswith("{"):
        return "", ""
    try:
        parsed = json.loads(body)
    except ValueError:
        return "", ""
    if not isinstance(parsed, dict):
        return "", ""

    owner_actor = ""
    for key in _BOLA_OWNER_KEYS:
        val = parsed.get(key)
        if isinstance(val, str):
            clean = val.strip()
            if clean and clean != "anon" and (clean in actor_meta_map or not actor_meta_map):
                owner_actor = clean
                break

    record_tenant = ""
    for key in _BOLA_TENANT_KEYS:
        val = parsed.get(key)
        if isinstance(val, str) and val.strip():
            record_tenant = val.strip().lower()
            break
    if not record_tenant and owner_actor and owner_actor in actor_meta_map:
        record_tenant = str(actor_meta_map[owner_actor].get("tenant") or "").strip().lower()
    return owner_actor, record_tenant


def _receipt_store_lists_object_for_actor(
    receipt_store: ReceiptStore,
    concrete_path: str,
    actor: str,
) -> bool:
    """Return True if `receipt_store` shows `actor` received this concrete object ID in a 2xx collection response."""
    norm_p = normalize_path(concrete_path)
    parts = [seg for seg in norm_p.split("/") if seg]
    if len(parts) < 2 or not is_id_segment(parts[-1]):
        return False
    concrete_id = parts[-1]
    concrete_id_low = concrete_id.lower()
    resource_family = parts[-2].lower()
    parent_path = "/" + "/".join(parts[:-1])
    singular = resource_family[:-1] if len(resource_family) > 2 and resource_family.endswith("s") else resource_family
    short_singular = singular.replace("-", "_").split("_")[-1]
    id_keys = {"id", "uuid", f"{singular}_id", f"{short_singular}_id"}
    html_link_re = re.compile(
        rf"""(?:{re.escape(parent_path)}|/{re.escape(resource_family)})/{re.escape(concrete_id)}(?:["'/?#\s>]|$)""",
        re.IGNORECASE,
    )

    for rid in receipt_store.list_ids():
        try:
            rec = receipt_store.get(rid)
        except (KeyError, ValueError):
            continue
        if str(rec.get("actor") or "").strip() != actor:
            continue
        if str(rec.get("method") or "").upper() != "GET":
            continue
        if not (200 <= int(rec.get("status") or 0) < 300):
            continue
        rec_path = normalize_path(str(rec.get("url") or rec.get("path") or ""))
        if "{id}" in route_template_of(rec_path):
            continue
        if not (
            rec_path == parent_path
            or rec_path == f"/{resource_family}"
            or rec_path.endswith(f"/{resource_family}")
        ):
            continue
        body = str(rec.get("body") or "")
        if not body:
            continue
        stripped = body.lstrip()
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
            items: list[dict[str, Any]] = []
            if isinstance(parsed, list):
                items = [x for x in parsed[:100] if isinstance(x, dict)]
            elif isinstance(parsed, dict):
                for v in parsed.values():
                    if isinstance(v, list):
                        items.extend(x for x in v[:100] if isinstance(x, dict))
            for item in items:
                for k, v in item.items():
                    if str(k).lower() in id_keys and isinstance(v, (str, int)) and not isinstance(v, bool):
                        if str(v).strip().lower() == concrete_id_low:
                            return True
        ctype = str(rec.get("content_type") or "").lower()
        if ("html" in ctype or "href=" in body.lower()) and html_link_re.search(body):
            return True
    return False


def check_bola_false_positive(
    *,
    primary_proof: dict[str, Any],
    proof_receipts: Sequence[dict[str, Any]],
    control_receipts: Sequence[dict[str, Any]],
    actor_meta_map: dict[str, dict[str, str]] | None,
    receipt_store: ReceiptStore | None = None,
    surface_tracker: Any | None = None,
    inferred_owner: str = "",
) -> tuple[str, str] | None:
    """Detect common BOLA false positives; return `(stage_code, reason)` if rejected, else None."""
    p_actor = str(primary_proof.get("actor") or "").strip()
    meta_map = actor_meta_map or {}
    p_tenant = str((meta_map.get(p_actor) or {}).get("tenant") or "").strip().lower()
    p_method = str(primary_proof.get("method") or "GET").strip().upper()
    p_path = normalize_path(str(primary_proof.get("url") or primary_proof.get("path") or ""))
    p_tmpl = route_template_of(p_path)

    # Guard 2: Read-only GET/HEAD BOLA cannot claim a shared-tenant resource that appeared in the
    # claiming actor's own 2xx collection listing.
    if p_method in {"GET", "HEAD"} and p_actor and p_actor != "anon" and "{id}" in p_tmpl:
        listed_in_tracker = (
            surface_tracker is not None
            and hasattr(surface_tracker, "was_object_listed_for_actor")
            and bool(surface_tracker.was_object_listed_for_actor(p_path, p_actor))
        )
        listed_in_store = (
            receipt_store is not None
            and _receipt_store_lists_object_for_actor(receipt_store, p_path, p_actor)
        )
        if listed_in_tracker or listed_in_store:
            return (
                "failed_bola_shared_collection_resource",
                (
                    f"Read-only BOLA rejected: actor {p_actor!r} legitimately received concrete object "
                    f"{p_path!r} in its own 2xx collection listing (shared-tenant resource, not BOLA)."
                ),
            )

    # Guard 1: Same-tenant BOLA cannot rely solely on cross-tenant or anon denied controls.
    explicit_owner, record_tenant = _extract_owner_and_tenant_from_receipt(primary_proof, meta_map)
    eff_owner = explicit_owner or str(inferred_owner or "").strip()
    if not eff_owner and surface_tracker is not None:
        obj_entry = (getattr(surface_tracker, "discovered_objects", None) or {}).get(p_path)
        if isinstance(obj_entry, dict):
            eff_owner = str(obj_entry.get("owner_actor") or "").strip()
    if not eff_owner:
        proof_actors = {str(r.get("actor") or "").strip() for r in proof_receipts}
        for ctrl in control_receipts:
            c_actor = str(ctrl.get("actor") or "").strip()
            if c_actor and c_actor != "anon" and c_actor not in proof_actors and 200 <= int(ctrl.get("status") or 0) < 300:
                eff_owner = c_actor
                break
    owner_tenant = record_tenant or str((meta_map.get(eff_owner) or {}).get("tenant") or "").strip().lower()

    if p_tenant and owner_tenant and p_tenant == owner_tenant:
        denied_controls = [c for c in control_receipts if int(c.get("status") or 0) in {401, 403, 404}]
        if denied_controls:
            has_same_tenant_denied = False
            has_cross_tenant_denied = False
            for ctrl in denied_controls:
                c_actor = str(ctrl.get("actor") or "").strip()
                c_tenant = str((meta_map.get(c_actor) or {}).get("tenant") or "").strip().lower()
                if c_actor and c_actor != "anon":
                    if c_tenant == p_tenant:
                        has_same_tenant_denied = True
                    elif c_tenant and c_tenant != p_tenant:
                        has_cross_tenant_denied = True
            distinct_tenants = {
                str(m.get("tenant") or "").strip().lower()
                for m in meta_map.values()
                if str(m.get("tenant") or "").strip()
            }
            if not has_same_tenant_denied:
                if has_cross_tenant_denied:
                    return (
                        "failed_bola_cross_tenant_only_control",
                        (
                            "Same-tenant BOLA rejected: all denied control receipts belong only to cross-tenant "
                            "actors or 'anon'. Cross-tenant denial proves tenant isolation, not same-tenant peer "
                            "restriction; provide a same-tenant peer denial control (403/404) or verify "
                            "cross-tenant access as 'tenant_isolation'."
                        ),
                    )
                if len(distinct_tenants) >= 2 or not explicit_owner:
                    return (
                        "failed_bola_anon_only_control",
                        (
                            "Same-tenant BOLA rejected: all denied control receipts belong only to 'anon' with "
                            "no same-tenant peer denial control. Anonymous denial proves authentication, not "
                            "same-tenant peer restriction; provide a same-tenant peer denial control (403/404)."
                        ),
                    )
    return None


def _receipt_contains_evidence(receipt: dict[str, Any], evidence_value: str) -> bool:
    ev = str(evidence_value or "").strip().lower()
    if not ev:
        return True
    body = str(receipt.get("body") or "")
    loc = str(receipt.get("redirect_location") or "")
    hdrs = json.dumps(receipt.get("response_headers") or {}, ensure_ascii=False)
    return ev in f"{body}\n{loc}\n{hdrs}".lower()


def _receipt_content_type(receipt: dict[str, Any]) -> str:
    """Return normalized lowercase media type from receipt metadata or Content-Type header."""
    ctype = str(receipt.get("content_type") or "").strip().lower()
    if ctype:
        return ctype.split(";", 1)[0].strip()
    headers = receipt.get("response_headers") or {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "content-type":
                return str(v).split(";", 1)[0].strip().lower()
    return ""


def is_html_receipt(receipt: dict[str, Any]) -> bool:
    """Return True if the receipt has an HTML content-type (e.g. text/html or application/xhtml+xml)."""
    return "html" in _receipt_content_type(receipt)


def receipt_body_contains_verbatim(receipt: dict[str, Any], evidence_value: str) -> bool:
    """Return True if non-empty `evidence_value` appears verbatim (unescaped) in the receipt body."""
    ev = str(evidence_value or "").strip()
    if not ev:
        return False
    body = str(receipt.get("body") or "")
    return ev in body or ev.lower() in body.lower()


def _receipt_seq_num(receipt: dict[str, Any]) -> int:
    rid = str(receipt.get("receipt_id") or "").strip()
    if rid.startswith("req-") and rid[4:].isdigit():
        return int(rid[4:])
    return 0


def _norm_url_path(url_or_path: str) -> str:
    path = urlsplit(str(url_or_path or "")).path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return path.lower()


def _strip_api_prefix(segs: list[str]) -> list[str]:
    idx = 0
    while idx < len(segs):
        seg = segs[idx]
        if seg in _API_PREFIX_SEGMENTS or _API_VERSION_SEG_RE.fullmatch(seg):
            idx += 1
        else:
            break
    return segs[idx:] if idx < len(segs) else segs


def _segments_related(w_segs: list[str], r_segs: list[str]) -> bool:
    if w_segs == r_segs:
        return True
    # Parent/ancestor read: /<res>/<id>/reply -> /<res>/<id> or /<res>
    if r_segs and len(r_segs) < len(w_segs) and w_segs[: len(r_segs)] == r_segs:
        return True
    # Top-level collection write rendering on root page: /posts -> /
    if not r_segs and len(w_segs) == 1:
        return True
    # Child read after collection write: /<res> -> /<res>/<id>
    if w_segs and len(w_segs) < len(r_segs) and r_segs[: len(w_segs)] == w_segs:
        return True
    # Sibling under same non-API-root parent: /<res>/<id>/reply -> /<res>/<id>/thread
    if len(w_segs) >= 2 and len(r_segs) >= 2 and w_segs[:-1] == r_segs[:-1]:
        parent = w_segs[-2]
        if parent not in _API_PREFIX_SEGMENTS and not _API_VERSION_SEG_RE.fullmatch(parent):
            return True
    return False


def is_persistent_read_path_related(
    write_receipt_or_url: dict[str, Any] | str,
    read_url_or_path: str,
) -> bool:
    """Return True if a read GET path is the same, parent/ancestor, child, sibling, or redirect target of a write."""
    if isinstance(write_receipt_or_url, dict):
        w_url = str(write_receipt_or_url.get("url") or write_receipt_or_url.get("path") or "")
        redir = str(write_receipt_or_url.get("redirect_location") or "").strip()
        if redir and _norm_url_path(redir) == _norm_url_path(read_url_or_path):
            return True
    else:
        w_url = str(write_receipt_or_url or "")

    w_path = _norm_url_path(w_url)
    r_path = _norm_url_path(read_url_or_path)
    if w_path == r_path:
        return True

    w_segs = [s for s in w_path.split("/") if s]
    r_segs = [s for s in r_path.split("/") if s]
    if _segments_related(w_segs, r_segs):
        return True

    w_stripped = _strip_api_prefix(w_segs)
    r_stripped = _strip_api_prefix(r_segs)
    if (w_stripped != w_segs or r_stripped != r_segs) and _segments_related(w_stripped, r_stripped):
        return True
    return False


def find_persistent_render_get_receipt(
    write_receipt: dict[str, Any],
    candidates: Sequence[dict[str, Any]],
    evidence_value: str,
    *,
    canonical_class: str = "",
) -> dict[str, Any] | None:
    """Select the strongest 2xx GET persistence/render proof matching a mutating write receipt."""
    w_actor = str(write_receipt.get("actor") or "")
    w_path = _norm_url_path(str(write_receipt.get("url") or write_receipt.get("path") or ""))
    ev = str(evidence_value or "").strip()

    matched: list[dict[str, Any]] = []
    for r in candidates:
        if str(r.get("method") or "").upper() != "GET":
            continue
        status = int(r.get("status") or 0)
        if not (200 <= status < 300):
            continue
        r_url = str(r.get("url") or r.get("path") or "")
        if not is_persistent_read_path_related(write_receipt, r_url):
            continue
        if canonical_class == "stored_xss":
            if not is_html_receipt(r):
                continue
            if ev and not receipt_body_contains_verbatim(r, ev):
                continue
        elif ev and not _receipt_contains_evidence(r, ev):
            continue
        matched.append(r)

    if not matched:
        return None
    matched.sort(
        key=lambda r: (
            1 if (ev and receipt_body_contains_verbatim(r, ev)) else 0,
            1 if is_html_receipt(r) else 0,
            1 if _norm_url_path(str(r.get("url") or r.get("path") or "")) == w_path else 0,
            1 if str(r.get("actor") or "") == w_actor else 0,
            _receipt_seq_num(r),
        ),
        reverse=True,
    )
    return matched[0]


def _select_mutating_get_proof(
    primary_proof: dict[str, Any],
    proof_receipts: list[dict[str, Any]],
    evidence_value: str,
    *,
    canonical_class: str = "",
) -> dict[str, Any] | None:
    """Select the best 2xx GET persistence proof for a mutating primary receipt.

    Non-idempotent mutations (e.g. ownership/tenant transfers or stored XSS/SSTI
    writes) may be unsafe to replay directly or may render on a parent/sibling GET
    endpoint, so replaying the follow-up 2xx GET is safer and more accurate.
    """
    p_method = str(primary_proof.get("method") or "").upper()
    if p_method not in _MUTATING_METHODS:
        return None
    p_actor = str(primary_proof.get("actor") or "")
    p_path = _norm_url_path(str(primary_proof.get("url") or primary_proof.get("path") or ""))
    ev = str(evidence_value or "").strip()

    if canonical_class == "stored_xss":
        return find_persistent_render_get_receipt(
            primary_proof,
            proof_receipts,
            ev,
            canonical_class="stored_xss",
        )

    candidates = [
        r
        for r in proof_receipts
        if str(r.get("method") or "").upper() == "GET" and 200 <= int(r.get("status") or 0) < 300
    ]
    if not candidates:
        return None
    if ev:
        ev_matching = [r for r in candidates if _receipt_contains_evidence(r, ev)]
        if ev_matching:
            candidates = ev_matching
    candidates.sort(
        key=lambda r: (
            1 if (ev and _receipt_contains_evidence(r, ev)) else 0,
            1 if is_persistent_read_path_related(primary_proof, str(r.get("url") or r.get("path") or "")) else 0,
            1 if _norm_url_path(str(r.get("url") or r.get("path") or "")) == p_path else 0,
            1 if str(r.get("actor") or "") == p_actor else 0,
            _receipt_seq_num(r),
        ),
        reverse=True,
    )
    return candidates[0]


def mask_dynamic_fields(text: str, *, preserve_values: Sequence[str] = ()) -> str:
    """Mask ephemeral timestamps, nonces, and request/trace UUIDs before structural comparison."""
    raw = str(text or "")
    if not raw:
        return ""
    preserved = [str(p) for p in preserve_values if isinstance(p, str) and len(p) >= 3]
    placeholders: dict[str, str] = {}
    working = raw
    for idx, val in enumerate(preserved):
        if val in working:
            token = f"__PRESERVE_{idx}__"
            placeholders[token] = val
            working = working.replace(val, token)

    stripped = working.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(working)
        except ValueError:
            parsed = None
        if parsed is not None:
            def _scrub(obj: Any) -> Any:
                if isinstance(obj, dict):
                    out: dict[str, Any] = {}
                    for k, v in sorted(obj.items(), key=lambda kv: str(kv[0])):
                        lk = str(k).lower()
                        if lk in _EPHEMERAL_JSON_KEYS:
                            out[str(k)] = "<MASKED>"
                        else:
                            out[str(k)] = _scrub(v)
                    return out
                if isinstance(obj, list):
                    return [_scrub(x) for x in obj]
                if isinstance(obj, str):
                    s = _ISO_TS_RE.sub("<TS>", obj)
                    return s
                return obj

            working = json.dumps(_scrub(parsed), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            for token, orig in placeholders.items():
                working = working.replace(token, orig)
            return working

    working = _ISO_TS_RE.sub("<TS>", working)
    working = _UUID_RE.sub("<UUID>", working)
    working = re.sub(r"\s+", " ", working).strip()
    for token, orig in placeholders.items():
        working = working.replace(token, orig)
    return working


@dataclass
class OracleVerdict:
    """Result of Layer 4 Differential Oracle verification."""

    verified: bool
    verdict: str  # VERIFIED | REFUTED | DECEPTION_DETECTED
    reason: str = ""
    deception_detected: bool = False
    mode: str = "differential"
    stages: dict[str, Any] = field(default_factory=dict)
    clean_replay_receipt_id: str = ""
    control_probe_receipt_id: str = ""


class DifferentialOracle:
    """3-stage protocol-level verification gate: Control/Falsification -> Masked Diff -> Clean Replay."""

    def __init__(
        self,
        *,
        http_client: AgenticHTTPClient,
        receipt_store: ReceiptStore,
        mode: str = "differential",
        timeout_s: float = 15.0,
        oob_server: Any | None = None,
    ):
        norm_mode = str(mode or "differential").strip().lower()
        if norm_mode not in VALID_VERIFICATION_GATES:
            raise ValueError(f"invalid verification_gate mode: {mode!r}")
        self.http = http_client
        self.receipts = receipt_store
        self.mode = norm_mode
        self.timeout_s = float(timeout_s)
        self.oob_server = oob_server

    def _has_budget(self, needed: int = 1) -> bool:
        return (self.http.budget.limit - self.http.budget.used) >= needed

    def _run_clean_session_request(
        self,
        *,
        actor: str,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        raw_body: str = "",
    ) -> dict[str, Any]:
        """Execute a single HTTP request inside a brand-new isolated requests.Session()."""
        allowed, reason = self.http.budget.consume()
        if not allowed:
            raise BudgetExhaustedError(reason)

        clean_url, path, query = self.http.resolve_in_scope(url)
        session_obj = self.http.actors.get(actor)
        safe_extra = {
            str(k): str(v)
            for k, v in (headers or {}).items()
            if k.lower() not in _NON_REPLAY_REQ_HEADERS and "<REDACTED" not in str(v)
        }
        req_headers = session_obj.build_headers(method, safe_extra)
        body_bytes = raw_body.encode("utf-8") if raw_body else None

        fresh = requests.Session()
        fresh.trust_env = False
        status = 0
        resp_headers: dict[str, str] = {}
        raw_bytes = b""
        text = ""
        content_type = ""
        redirect_location = ""
        error = ""
        try:
            resp = fresh.request(
                method=method,
                url=clean_url,
                headers=req_headers,
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
                raw_stream = resp.raw.read(self.http.max_response_bytes + 1, decode_content=False)
                if len(raw_stream) > self.http.max_response_bytes:
                    raw_stream = raw_stream[: self.http.max_response_bytes]
                raw_bytes = _decode_raw_response(raw_stream, resp_headers.get("Content-Encoding", ""))
                text = raw_bytes.decode("utf-8", errors="replace")
            finally:
                resp.close()
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:200]}"
        finally:
            fresh.cookies.clear()
            fresh.close()

        return self.receipts.record(
            actor=actor,
            method=method,
            url=clean_url,
            path=path,
            query=query,
            request_headers=req_headers,
            request_body=raw_body,
            status=status,
            elapsed_ms=1.0,
            content_type=content_type,
            response_headers=resp_headers,
            redirect_location=redirect_location,
            raw_response_bytes=raw_bytes,
            response_text=text,
            error=error,
            secret_values=self.http.actors.all_secrets(),
        )

    def _benign_control_url(self, url: str) -> str:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            return url
        benign_pairs = [(k, "baseline_value") for k, _ in pairs]
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(benign_pairs), ""))

    def verify(
        self,
        *,
        canonical_class: str,
        primary_proof: dict[str, Any],
        proof_receipts: list[dict[str, Any]],
        control_receipts: list[dict[str, Any]],
        evidence_value: str,
        actor_meta_map: dict[str, dict[str, str]] | None = None,
        surface_tracker: Any | None = None,
        inferred_owner: str = "",
        oob_server: Any | None = None,
        oob_hits: Sequence[dict[str, Any]] | None = None,
    ) -> OracleVerdict:
        """Run verification gate before promoting a CLAIMED hypothesis to VERIFIED."""
        if self.mode == "llm_self_judge":
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="llm_self_judge mode: accepted after receipt structural check",
                mode=self.mode,
                stages={"stage1_control": "skipped", "stage2_diff": "skipped", "stage3_clean_replay": "skipped"},
            )

        stages: dict[str, Any] = {}
        ev = str(evidence_value or "").strip()
        active_oob = oob_server if oob_server is not None else self.oob_server
        effective_oob_hits: list[dict[str, Any]] = [dict(h) for h in (oob_hits or []) if isinstance(h, dict)]
        oob_tokens_submitted: list[str] = []
        if canonical_class == "ssrf" and active_oob is not None and hasattr(active_oob, "registered_tokens"):
            try:
                reg_tokens = list(active_oob.registered_tokens())
            except Exception:
                reg_tokens = []
            for tok in reg_tokens:
                if not tok:
                    continue
                if any(
                    tok in str(r.get("url") or "")
                    or tok in str(r.get("query") or "")
                    or tok in str(r.get("request_body") or "")
                    or tok in json.dumps(r.get("request_headers") or {}, ensure_ascii=False)
                    for r in proof_receipts
                ):
                    oob_tokens_submitted.append(tok)
                    if not effective_oob_hits and hasattr(active_oob, "poll"):
                        polled = active_oob.poll(tok)
                        effective_oob_hits.extend(polled.get("hits") or [])
            if oob_tokens_submitted and not effective_oob_hits:
                stages["stage1_control"] = "failed_oob_zero_hits"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="SSRF callback claim rejected: callback_listener recorded 0 hits for submitted token(s).",
                    mode=self.mode,
                    stages=stages,
                )
        is_oob_ssrf = canonical_class == "ssrf" and bool(effective_oob_hits)
        render_proof: dict[str, Any] | None = None
        if canonical_class == "stored_xss":
            if str(primary_proof.get("method") or "").upper() == "GET" and 200 <= int(primary_proof.get("status") or 0) < 300:
                render_proof = primary_proof
            else:
                render_proof = _select_mutating_get_proof(
                    primary_proof,
                    proof_receipts,
                    ev,
                    canonical_class="stored_xss",
                )
            if render_proof is None:
                stages["stage1_control"] = "failed_missing_render_get"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="stored_xss requires a 2xx text/html GET render receipt containing evidence_value unescaped verbatim.",
                    mode=self.mode,
                    stages=stages,
                )
            if not is_html_receipt(render_proof):
                stages["stage1_control"] = "failed_non_html_render"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="stored_xss render GET receipt must have HTML (text/html) content-type.",
                    mode=self.mode,
                    stages=stages,
                )
            if ev and not receipt_body_contains_verbatim(render_proof, ev):
                stages["stage1_control"] = "failed_missing_unescaped_evidence"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="stored_xss render GET receipt does not contain evidence_value unescaped verbatim in HTML body.",
                    mode=self.mode,
                    stages=stages,
                )
        elif canonical_class in _PERSISTENT_CLASSES:
            render_proof = _select_mutating_get_proof(
                primary_proof,
                proof_receipts,
                ev,
                canonical_class=canonical_class,
            )

        diff_target = primary_proof
        if canonical_class == "stored_xss" and render_proof is not None:
            diff_target = render_proof
        elif (
            canonical_class in _PERSISTENT_CLASSES
            and render_proof is not None
            and (
                not ev
                or not _receipt_contains_evidence(primary_proof, ev)
                or any(str(c.get("method") or "").upper() == "GET" for c in control_receipts)
            )
        ):
            diff_target = render_proof

        p_actor = str(diff_target.get("actor") or "anon")
        p_status = int(diff_target.get("status") or 0)
        p_masked = mask_dynamic_fields(str(diff_target.get("body") or ""), preserve_values=(ev,))
        p_loc = str(diff_target.get("redirect_location") or "")

        # --- Stage 1: Falsification / Control Baseline Check ---
        ctrl_probe_rid = ""
        eff_controls = list(control_receipts)
        if not eff_controls and not is_oob_ssrf and canonical_class not in _CONCURRENCY_CLASSES and self._has_budget(2):
            try:
                if canonical_class in _INPUT_DIFF_CLASSES:
                    ctrl_url = self._benign_control_url(str(diff_target.get("url") or "/"))
                    probe = self._run_clean_session_request(
                        actor=p_actor,
                        method="GET" if diff_target.get("method") == "GET" else str(diff_target.get("method") or "GET"),
                        url=ctrl_url,
                    )
                    ctrl_probe_rid = probe["receipt_id"]
                    eff_controls.append(probe)
                elif canonical_class == "auth_bypass":
                    probe = self._run_clean_session_request(
                        actor="anon",
                        method="GET",
                        url=f"/{uuid.uuid4().hex[:12]}-control-check",
                    )
                    ctrl_probe_rid = probe["receipt_id"]
                    eff_controls.append(probe)
            except Exception:
                pass

        diff_controls = eff_controls
        if str(diff_target.get("method") or "").upper() == "GET":
            get_ctrls = [c for c in eff_controls if str(c.get("method") or "").upper() == "GET"]
            if get_ctrls:
                diff_controls = get_ctrls

        # Catch-all / soft-404 decoy check for auth_bypass HTML responses
        if (
            canonical_class == "auth_bypass"
            and "html" in str(primary_proof.get("content_type") or "").lower()
            and self._has_budget(2)
        ):
            try:
                catchall_probe = self._run_clean_session_request(
                    actor="anon",
                    method="GET",
                    url=f"/{uuid.uuid4().hex[:12]}-control-check",
                )
                ctrl_probe_rid = catchall_probe["receipt_id"]
                c_masked = mask_dynamic_fields(str(catchall_probe.get("body") or ""), preserve_values=(ev,))
                if int(catchall_probe.get("status") or 0) == p_status and c_masked == p_masked:
                    stages["stage1_control"] = "deception_catchall_html"
                    return OracleVerdict(
                        verified=False,
                        verdict="DECEPTION_DETECTED",
                        reason="Catch-all HTML response returned identical output on non-existent control path.",
                        deception_detected=True,
                        mode=self.mode,
                        stages=stages,
                        control_probe_receipt_id=ctrl_probe_rid,
                    )
            except Exception:
                pass

        # Check benign control equivalence and stored_xss baseline absence for input/mutation classes
        if canonical_class in _INPUT_DIFF_CLASSES and not is_oob_ssrf:
            if canonical_class == "stored_xss" and ev:
                p_count = str(diff_target.get("body") or "").lower().count(ev.lower())
                for ctrl in diff_controls:
                    c_count = str(ctrl.get("body") or "").lower().count(ev.lower())
                    if c_count >= p_count or c_count > 0 and p_count <= c_count:
                        stages["stage1_control"] = "failed_evidence_in_baseline"
                        return OracleVerdict(
                            verified=False,
                            verdict="REFUTED",
                            reason="Benign baseline GET control already contains the claimed stored_xss evidence_value.",
                            mode=self.mode,
                            stages=stages,
                            control_probe_receipt_id=ctrl_probe_rid,
                        )
            same_actor_ctrls = [c for c in diff_controls if str(c.get("actor") or "") == p_actor]
            for ctrl in same_actor_ctrls:
                c_masked = mask_dynamic_fields(str(ctrl.get("body") or ""), preserve_values=(ev,))
                c_status = int(ctrl.get("status") or 0)
                c_loc = str(ctrl.get("redirect_location") or "")
                if (
                    c_status == p_status
                    and c_masked == p_masked
                    and urlsplit(c_loc).netloc == urlsplit(p_loc).netloc
                ):
                    stages["stage1_control"] = "deception_identical_control"
                    return OracleVerdict(
                        verified=False,
                        verdict="DECEPTION_DETECTED",
                        reason="Benign control returned identical masked status, body, and redirect as claimed proof.",
                        deception_detected=True,
                        mode=self.mode,
                        stages=stages,
                        control_probe_receipt_id=ctrl_probe_rid,
                    )
        elif canonical_class in _CONCURRENCY_CLASSES:
            success_rids = {
                str(r.get("receipt_id") or "")
                for r in proof_receipts
                if r.get("receipt_id") and 200 <= int(r.get("status") or 0) < 400
            }
            if canonical_class == "race_condition" and len(success_rids) < 2:
                stages["stage1_control"] = "failed_missing_concurrent_proofs"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="race_condition requires at least 2 distinct 2xx/3xx concurrent proof receipts.",
                    mode=self.mode,
                    stages=stages,
                )
            if not eff_controls:
                stages["stage1_control"] = "failed_missing_control"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason=f"{canonical_class} requires at least one sequential or baseline control receipt.",
                    mode=self.mode,
                    stages=stages,
                )
            p_method = str(diff_target.get("method") or "").upper()
            if all(
                int(c.get("status") or 0) == p_status
                and mask_dynamic_fields(str(c.get("body") or ""), preserve_values=(ev,)) == p_masked
                and str(c.get("method") or "").upper() == p_method
                and str(c.get("actor") or "") == p_actor
                for c in eff_controls
            ):
                stages["stage1_control"] = "deception_identical_control"
                return OracleVerdict(
                    verified=False,
                    verdict="DECEPTION_DETECTED",
                    reason=f"{canonical_class} control receipt is identical to primary proof.",
                    deception_detected=True,
                    mode=self.mode,
                    stages=stages,
                )
        elif canonical_class in _ACCESS_CLASSES:
            # Check if a negative control (e.g. different path returning 403/404, or anon returning 401/403)
            # accidentally returned the exact same masked body + evidence_value for an unrelated/denied check.
            for ctrl in eff_controls:
                c_actor = str(ctrl.get("actor") or "")
                c_status = int(ctrl.get("status") or 0)
                c_path = str(ctrl.get("path") or "")
                p_path = str(primary_proof.get("path") or "")
                if (
                    c_actor == p_actor
                    and c_path != p_path
                    and 200 <= c_status < 300
                    and c_status == p_status
                ):
                    c_masked = mask_dynamic_fields(str(ctrl.get("body") or ""), preserve_values=(ev,))
                    if c_masked == p_masked and ev and ev.lower() in str(ctrl.get("body") or "").lower():
                        stages["stage1_control"] = "deception_static_access_response"
                        return OracleVerdict(
                            verified=False,
                            verdict="DECEPTION_DETECTED",
                            reason="Different control path returned identical masked body and evidence_value.",
                            deception_detected=True,
                            mode=self.mode,
                            stages=stages,
                            control_probe_receipt_id=ctrl_probe_rid,
                        )
        stages["stage1_control"] = "passed_oob_callback" if is_oob_ssrf else "passed"

        # --- Stage 2: Dynamic-Field-Masked Structural & Access-Boundary Diff ---
        if canonical_class in _INPUT_DIFF_CLASSES and not is_oob_ssrf:
            has_masked_diff = False
            for ctrl in diff_controls:
                c_masked = mask_dynamic_fields(str(ctrl.get("body") or ""), preserve_values=(ev,))
                c_status = int(ctrl.get("status") or 0)
                c_loc = str(ctrl.get("redirect_location") or "")
                if c_status != p_status or c_masked != p_masked or urlsplit(c_loc).netloc != urlsplit(p_loc).netloc:
                    has_masked_diff = True
                    break
            if diff_controls and not has_masked_diff:
                stages["stage2_diff"] = "failed_masked_equivalence"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="Proof and control differ only in masked dynamic fields (timestamps/nonces/request IDs).",
                    deception_detected=True,
                    mode=self.mode,
                    stages=stages,
                    control_probe_receipt_id=ctrl_probe_rid,
                )
        elif canonical_class in _CONCURRENCY_CLASSES:
            p_method = str(diff_target.get("method") or "").upper()
            has_diff = any(
                int(c.get("status") or 0) != p_status
                or mask_dynamic_fields(str(c.get("body") or ""), preserve_values=(ev,)) != p_masked
                or str(c.get("method") or "").upper() != p_method
                or str(c.get("actor") or "") != p_actor
                for c in eff_controls
            )
            if not has_diff:
                stages["stage2_diff"] = "failed_masked_equivalence"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason=f"{canonical_class} proof and control receipts show no differential behavior.",
                    deception_detected=True,
                    mode=self.mode,
                    stages=stages,
                )
        elif canonical_class in _ACCESS_CLASSES:
            meta_map = actor_meta_map or {}
            if canonical_class == "bfla":
                role = str((meta_map.get(p_actor) or {}).get("role") or "").lower()
                if any(tok in role for tok in ("admin", "superadmin", "superuser")):
                    stages["stage2_diff"] = "failed_admin_actor_for_bfla"
                    return OracleVerdict(
                        verified=False,
                        verdict="REFUTED",
                        reason="BFLA proof cannot rely on an admin actor.",
                        mode=self.mode,
                        stages=stages,
                    )
            elif canonical_class == "bola":
                bola_fp = check_bola_false_positive(
                    primary_proof=primary_proof,
                    proof_receipts=proof_receipts,
                    control_receipts=eff_controls,
                    actor_meta_map=meta_map,
                    receipt_store=self.receipts,
                    surface_tracker=surface_tracker,
                    inferred_owner=inferred_owner,
                )
                if bola_fp is not None:
                    stage_code, reason = bola_fp
                    stages["stage2_diff"] = stage_code
                    return OracleVerdict(
                        verified=False,
                        verdict="REFUTED",
                        reason=reason,
                        mode=self.mode,
                        stages=stages,
                        control_probe_receipt_id=ctrl_probe_rid,
                    )
        stages["stage2_diff"] = "passed_oob_callback" if is_oob_ssrf else "passed"

        # --- Stage 3: Clean-Session Replay in fresh isolated requests.Session() ---
        if canonical_class == "race_condition" or (
            canonical_class == "business_logic"
            and (str(primary_proof.get("method") or "").upper() in _MUTATING_METHODS or len(proof_receipts) >= 2)
        ):
            stages["stage3_clean_replay"] = "skipped_non_idempotent_concurrency"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="Verified across concurrency proof receipts and sequential/state control without re-triggering mutating bursts.",
                mode=self.mode,
                stages=stages,
                control_probe_receipt_id=ctrl_probe_rid,
            )

        if is_oob_ssrf and str(primary_proof.get("method") or "").upper() in _MUTATING_METHODS:
            stages["stage3_clean_replay"] = "passed_oob_verified"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="Verified by recorded out-of-band loopback callback hit(s) matching submitted token.",
                mode=self.mode,
                stages=stages,
                control_probe_receipt_id=ctrl_probe_rid,
            )
        if not self._has_budget(1):
            stages["stage3_clean_replay"] = "skipped_budget"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="Verified by Stages 1-2 (budget too low for clean replay).",
                mode=self.mode,
                stages=stages,
                control_probe_receipt_id=ctrl_probe_rid,
            )

        # Prefer replaying a 2xx GET persistence proof receipt when one is present
        # (including cross-actor GETs after non-idempotent ownership/tenant transfers
        # and read/render GETs for stored_xss / ssti / mass_assignment).
        replay_target = (
            render_proof
            or _select_mutating_get_proof(
                primary_proof,
                proof_receipts,
                ev,
                canonical_class=canonical_class,
            )
            or primary_proof
        )
        replayed_via_stateful_fallback = False

        try:
            replay_rec = self._run_clean_session_request(
                actor=str(replay_target.get("actor") or "anon"),
                method=str(replay_target.get("method") or "GET"),
                url=str(replay_target.get("url") or "/"),
                headers=replay_target.get("request_headers") or {},
                raw_body=str(replay_target.get("request_body") or ""),
            )
        except BudgetExhaustedError:
            stages["stage3_clean_replay"] = "skipped_budget"
            return OracleVerdict(
                verified=True,
                verdict="VERIFIED",
                reason="Verified by Stages 1-2 (HTTP budget exhausted before clean replay).",
                mode=self.mode,
                stages=stages,
                control_probe_receipt_id=ctrl_probe_rid,
            )

        r_status = int(replay_rec.get("status") or 0)
        t_status = int(replay_target.get("status") or 0)

        # Stateful persistence fallback: when re-executing a non-idempotent write as
        # the original actor returns 403/404/409 (e.g. ownership/tenant already moved),
        # check previously-denied control actors on the same path and (when evidence is
        # specified) up to 2 distinct-tenant/admin actors from the harness roster to
        # verify the mutated state persisted in a fresh clean session.
        if (
            replay_target is primary_proof
            and str(primary_proof.get("method") or "").upper() in _MUTATING_METHODS
            and r_status in {403, 404, 409}
            and self._has_budget(1)
        ):
            p_path = urlsplit(str(primary_proof.get("url") or primary_proof.get("path") or "")).path.rstrip("/")
            actor_rows = list(self.http.actors.summaries())
            actor_by_alias = {str(a.get("alias") or ""): a for a in actor_rows}
            p_tenant = str((actor_by_alias.get(p_actor) or {}).get("tenant") or "").strip().lower()

            fallback_actors: list[str] = []
            for ctrl in eff_controls:
                c_actor = str(ctrl.get("actor") or "")
                c_status = int(ctrl.get("status") or 0)
                c_path = urlsplit(str(ctrl.get("url") or ctrl.get("path") or "")).path.rstrip("/")
                if (
                    c_actor
                    and c_actor != p_actor
                    and c_actor in actor_by_alias
                    and c_actor not in fallback_actors
                    and c_status in {401, 403, 404}
                    and c_path == p_path
                ):
                    fallback_actors.append(c_actor)

            if ev:
                roster_candidates = [
                    a
                    for a in actor_rows
                    if str(a.get("alias") or "") not in {"", "anon", p_actor}
                    and str(a.get("alias") or "") not in fallback_actors
                ]
                roster_candidates.sort(
                    key=lambda a: (
                        1 if (p_tenant and str(a.get("tenant") or "").strip().lower() not in {"", p_tenant}) else 0,
                        1 if "admin" in str(a.get("role") or "").lower() else 0,
                    ),
                    reverse=True,
                )
                for row in roster_candidates[:2]:
                    fallback_actors.append(str(row.get("alias") or ""))

            for fb_actor in fallback_actors[:3]:
                if not self._has_budget(1):
                    break
                try:
                    fb_rec = self._run_clean_session_request(
                        actor=fb_actor,
                        method="GET",
                        url=str(primary_proof.get("url") or "/"),
                    )
                except BudgetExhaustedError:
                    break
                fb_status = int(fb_rec.get("status") or 0)
                if 200 <= fb_status < 300 and _receipt_contains_evidence(fb_rec, ev):
                    replay_rec = fb_rec
                    r_status = fb_status
                    t_status = 200
                    replayed_via_stateful_fallback = True
                    break

        if not (200 <= r_status < 400) or (r_status // 100) != (t_status // 100):
            stages["stage3_clean_replay"] = f"failed_status_{r_status}"
            return OracleVerdict(
                verified=False,
                verdict="REFUTED",
                reason=f"Clean-session replay returned status {r_status} (expected {t_status // 100}xx).",
                mode=self.mode,
                stages=stages,
                clean_replay_receipt_id=replay_rec["receipt_id"],
                control_probe_receipt_id=ctrl_probe_rid,
            )

        if canonical_class == "open_redirect":
            orig_host = urlsplit(str(replay_target.get("redirect_location") or "")).netloc
            rep_host = urlsplit(str(replay_rec.get("redirect_location") or "")).netloc
            if not rep_host or rep_host != orig_host:
                stages["stage3_clean_replay"] = "failed_redirect_host"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="Clean-session replay did not reproduce external redirect Location host.",
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=replay_rec["receipt_id"],
                    control_probe_receipt_id=ctrl_probe_rid,
                )
        elif canonical_class == "stored_xss":
            if not is_html_receipt(replay_rec):
                stages["stage3_clean_replay"] = "failed_non_html_replay"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="Clean-session GET replay did not return HTML (text/html) content-type.",
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=replay_rec["receipt_id"],
                    control_probe_receipt_id=ctrl_probe_rid,
                )
            if ev and not receipt_body_contains_verbatim(replay_rec, ev):
                stages["stage3_clean_replay"] = "failed_missing_evidence"
                return OracleVerdict(
                    verified=False,
                    verdict="REFUTED",
                    reason="Clean-session GET replay did not persist unescaped evidence_value in HTML body.",
                    mode=self.mode,
                    stages=stages,
                    clean_replay_receipt_id=replay_rec["receipt_id"],
                    control_probe_receipt_id=ctrl_probe_rid,
                )
        else:
            if ev and not _receipt_contains_evidence(replay_rec, ev):
                ev_in_oob = is_oob_ssrf and any(
                    ev.lower() in json.dumps(h, ensure_ascii=False).lower()
                    for h in effective_oob_hits
                )
                if not ev_in_oob:
                    stages["stage3_clean_replay"] = "failed_missing_evidence"
                    return OracleVerdict(
                        verified=False,
                        verdict="REFUTED",
                        reason="Clean-session replay did not reproduce the claimed evidence_value.",
                        mode=self.mode,
                        stages=stages,
                        clean_replay_receipt_id=replay_rec["receipt_id"],
                        control_probe_receipt_id=ctrl_probe_rid,
                    )

        stages["stage3_clean_replay"] = (
            "passed_oob_verified"
            if is_oob_ssrf
            else ("passed_stateful_persistence" if replayed_via_stateful_fallback else "passed")
        )
        return OracleVerdict(
            verified=True,
            verdict="VERIFIED",
            reason="Verified across control baseline, masked structural diff, and isolated clean-session replay.",
            mode=self.mode,
            stages=stages,
            clean_replay_receipt_id=replay_rec["receipt_id"],
            control_probe_receipt_id=ctrl_probe_rid,
        )
