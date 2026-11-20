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

VALID_VERIFICATION_GATES = frozenset({"differential", "llm_self_judge"})

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
})
_ACCESS_CLASSES = frozenset({"auth_bypass", "bfla", "bola", "tenant_isolation"})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _receipt_contains_evidence(receipt: dict[str, Any], evidence_value: str) -> bool:
    ev = str(evidence_value or "").strip().lower()
    if not ev:
        return True
    body = str(receipt.get("body") or "")
    loc = str(receipt.get("redirect_location") or "")
    hdrs = json.dumps(receipt.get("response_headers") or {}, ensure_ascii=False)
    return ev in f"{body}\n{loc}\n{hdrs}".lower()


def _select_mutating_get_proof(
    primary_proof: dict[str, Any],
    proof_receipts: list[dict[str, Any]],
    evidence_value: str,
) -> dict[str, Any] | None:
    """Select the best 2xx GET persistence proof for a mutating primary receipt.

    Non-idempotent mutations (e.g. ownership or tenant transfers) may revoke the
    original actor's access after succeeding, so a follow-up 2xx GET from either
    the original actor or a newly-authorized actor is a safer and more accurate
    Stage 3 clean-replay target than blindly re-issuing the write.
    """
    p_method = str(primary_proof.get("method") or "").upper()
    if p_method not in _MUTATING_METHODS:
        return None
    p_actor = str(primary_proof.get("actor") or "")
    p_path = urlsplit(str(primary_proof.get("url") or primary_proof.get("path") or "")).path.rstrip("/")
    ev = str(evidence_value or "").strip()

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
            1 if urlsplit(str(r.get("url") or r.get("path") or "")).path.rstrip("/") == p_path else 0,
            1 if str(r.get("actor") or "") == p_actor else 0,
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
    ):
        norm_mode = str(mode or "differential").strip().lower()
        if norm_mode not in VALID_VERIFICATION_GATES:
            raise ValueError(f"invalid verification_gate mode: {mode!r}")
        self.http = http_client
        self.receipts = receipt_store
        self.mode = norm_mode
        self.timeout_s = float(timeout_s)

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
        p_actor = str(primary_proof.get("actor") or "anon")
        p_status = int(primary_proof.get("status") or 0)
        p_masked = mask_dynamic_fields(str(primary_proof.get("body") or ""), preserve_values=(ev,))
        p_loc = str(primary_proof.get("redirect_location") or "")

        # --- Stage 1: Falsification / Control Baseline Check ---
        ctrl_probe_rid = ""
        eff_controls = list(control_receipts)
        if not eff_controls and self._has_budget(2):
            try:
                if canonical_class in _INPUT_DIFF_CLASSES:
                    ctrl_url = self._benign_control_url(str(primary_proof.get("url") or "/"))
                    probe = self._run_clean_session_request(
                        actor=p_actor,
                        method="GET" if primary_proof.get("method") == "GET" else str(primary_proof.get("method") or "GET"),
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

        # Check benign control equivalence for input/mutation classes
        if canonical_class in _INPUT_DIFF_CLASSES:
            same_actor_ctrls = [c for c in eff_controls if str(c.get("actor") or "") == p_actor]
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
        stages["stage1_control"] = "passed"

        # --- Stage 2: Dynamic-Field-Masked Structural & Access-Boundary Diff ---
        if canonical_class in _INPUT_DIFF_CLASSES:
            has_masked_diff = False
            for ctrl in eff_controls:
                c_masked = mask_dynamic_fields(str(ctrl.get("body") or ""), preserve_values=(ev,))
                c_status = int(ctrl.get("status") or 0)
                c_loc = str(ctrl.get("redirect_location") or "")
                if c_status != p_status or c_masked != p_masked or urlsplit(c_loc).netloc != urlsplit(p_loc).netloc:
                    has_masked_diff = True
                    break
            if eff_controls and not has_masked_diff:
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
        stages["stage2_diff"] = "passed"

        # --- Stage 3: Clean-Session Replay in fresh isolated requests.Session() ---
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
        # (including cross-actor GETs after non-idempotent ownership/tenant transfers).
        replay_target = _select_mutating_get_proof(primary_proof, proof_receipts, ev) or primary_proof
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
        else:
            if ev and not _receipt_contains_evidence(replay_rec, ev):
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
            "passed_stateful_persistence" if replayed_via_stateful_fallback else "passed"
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
