"""Layer 5: Unified telemetry logger (telemetry.jsonl) and process metrics generator."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Sequence
from urllib.parse import parse_qsl, urlsplit

from agentic_bsag import STATUS_REFUTED, STATUS_SUSPECT_DECOY, BeliefStateAttackGraph
from agentic_surface import route_template_of

_HEALTH_CHECK_COUNT = 6
_HIGH_404_MIN_HTTP_EVENTS = 20
_HIGH_404_RATIO_THRESHOLD = 0.40
_ORACLE_FRICTION_STAGE3_REASONS = frozenset({
    "failed_status_404",
    "failed_status_409",
    "failed_status_400",
})
_URL_PATH_REDACTION_CORRUPTION_RE = re.compile(
    r"https?://[^/\s\"'<>`()\[\]]+/[^\s?\"'<>`()\[\]]*<REDACTED_SECRET[^\s\"'`()\[\]]*"
)


def _safe_int(value: Any) -> int | None:
    """Convert an integer or numeric string to int, returning None for bools or invalid values."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and (stripped.isdigit() or (stripped[0] in {"+", "-"} and stripped[1:].isdigit())):
            return int(stripped)
    return None


def _extract_oracle_endpoint(event: dict[str, Any]) -> str:
    """Resolve a human-readable endpoint identifier from an `oracle_verdict` event."""
    for key in ("route_template", "endpoint", "path", "url"):
        raw = str(event.get(key) or "").strip()
        if raw:
            return raw
    node_id = str(event.get("node_id") or "").strip()
    if node_id:
        return node_id[3:] if node_id.startswith("ep:") and len(node_id) > 3 else node_id
    return "unknown"


def compute_harness_health_checks(
    *,
    events: Sequence[dict[str, Any]] = (),
    manifest: dict[str, Any] | None = None,
    auth_metadata: dict[str, Any] | None = None,
    sharding_summary: dict[str, Any] | None = None,
    post_auth_stage0_crawl: dict[str, Any] | None = None,
    run_status: str | None = None,
    report_text: str | None = None,
) -> dict[str, Any]:
    """Deterministically evaluate run telemetry, metadata, and report text for harness anomalies."""
    anomalies: list[dict[str, Any]] = []

    http_events = [e for e in events if isinstance(e, dict) and e.get("event") == "http_event"]
    oracle_events = [e for e in events if isinstance(e, dict) and e.get("event") == "oracle_verdict"]

    # 1. high_404_ratio
    total_http = len(http_events)
    count_404 = sum(1 for e in http_events if _safe_int(e.get("status")) == 404)
    if total_http >= _HIGH_404_MIN_HTTP_EVENTS and (count_404 / total_http) > _HIGH_404_RATIO_THRESHOLD:
        ratio = round(count_404 / total_http, 4)
        anomalies.append({
            "code": "high_404_ratio",
            "severity": "medium",
            "detail": (
                f"HTTP 404 ratio {ratio:.2%} ({count_404}/{total_http}) exceeds "
                f"{_HIGH_404_RATIO_THRESHOLD:.0%} threshold."
            ),
            "metrics": {
                "ratio": ratio,
                "count_404": count_404,
                "total_http": total_http,
            },
        })

    # 2. credentials_unauthenticated
    auth_block: dict[str, Any] | None = None
    if isinstance(auth_metadata, dict):
        auth_block = auth_metadata
    elif isinstance(manifest, dict):
        raw_auth = manifest.get("auth")
        if isinstance(raw_auth, dict):
            auth_block = raw_auth
        elif "unauthenticated_credentialed_actors" in manifest or "authenticated_actors" in manifest:
            auth_block = manifest

    if auth_block is not None:
        raw_unauth = auth_block.get("unauthenticated_credentialed_actors")
        raw_authed = auth_block.get("authenticated_actors")
        unauth = (
            [str(a).strip() for a in raw_unauth if str(a).strip()]
            if isinstance(raw_unauth, (list, tuple, set))
            else []
        )
        authed = (
            [str(a).strip() for a in raw_authed if str(a).strip()]
            if isinstance(raw_authed, (list, tuple, set))
            else []
        )
        if unauth and not authed:
            anomalies.append({
                "code": "credentials_unauthenticated",
                "severity": "high",
                "detail": (
                    f"{len(unauth)} credentialed actor(s) failed authentication "
                    f"({', '.join(unauth[:5])}) with 0 authenticated actors."
                ),
                "metrics": {
                    "unauthenticated_credentialed_actors": unauth,
                    "authenticated_actors": authed,
                    "unauthenticated_count": len(unauth),
                    "authenticated_count": 0,
                },
            })

    # 3. oracle_state_transition_friction
    friction_count = 0
    friction_endpoints: list[str] = []
    seen_friction_endpoints: set[str] = set()
    friction_reasons: Counter[str] = Counter()
    for ev in oracle_events:
        raw_stages = ev.get("stages")
        stages = raw_stages if isinstance(raw_stages, dict) else {}
        s1 = str(stages.get("stage1_control") or ev.get("stage1_control") or "").strip()
        s2 = str(stages.get("stage2_diff") or ev.get("stage2_diff") or "").strip()
        s3 = str(stages.get("stage3_clean_replay") or ev.get("stage3_clean_replay") or "").strip()
        if s1.startswith("passed") and s2.startswith("passed") and s3 in _ORACLE_FRICTION_STAGE3_REASONS:
            friction_count += 1
            friction_reasons[s3] += 1
            ep = _extract_oracle_endpoint(ev)
            if ep not in seen_friction_endpoints:
                seen_friction_endpoints.add(ep)
                friction_endpoints.append(ep)
    if friction_count > 0:
        reasons_summary = ", ".join(f"{k}={v}" for k, v in sorted(friction_reasons.items()))
        anomalies.append({
            "code": "oracle_state_transition_friction",
            "severity": "medium",
            "detail": (
                f"{friction_count} oracle verdict(s) passed Stage 1-2 but failed Stage 3 "
                f"({reasons_summary}) on {', '.join(friction_endpoints[:5])}."
            ),
            "metrics": {
                "count": friction_count,
                "endpoints": friction_endpoints,
                "stage3_reasons": dict(sorted(friction_reasons.items())),
            },
        })

    # 4. url_path_redaction_corruption
    if isinstance(report_text, str) and report_text:
        corrupted_urls = list(dict.fromkeys(_URL_PATH_REDACTION_CORRUPTION_RE.findall(report_text)))
        if corrupted_urls:
            anomalies.append({
                "code": "url_path_redaction_corruption",
                "severity": "high",
                "detail": (
                    f"Detected {len(corrupted_urls)} URL(s) in report output whose path segment "
                    "contains <REDACTED_SECRET (over-redaction corruption)."
                ),
                "metrics": {
                    "count": len(corrupted_urls),
                    "sample_urls": corrupted_urls[:10],
                },
            })

    # Resolve sharding_summary once for checks 5 & 6
    eff_sharding: dict[str, Any] | None = (
        sharding_summary
        if isinstance(sharding_summary, dict)
        else (
            manifest.get("sharding_summary")
            if isinstance(manifest, dict) and isinstance(manifest.get("sharding_summary"), dict)
            else None
        )
    )

    # 5. post_auth_zero_new_routes
    pa_meta: dict[str, Any] | None = None
    if isinstance(post_auth_stage0_crawl, dict):
        pa_meta = post_auth_stage0_crawl
    elif isinstance(eff_sharding, dict) and isinstance(eff_sharding.get("post_auth_stage0_crawl"), dict):
        pa_meta = eff_sharding["post_auth_stage0_crawl"]
    elif isinstance(manifest, dict) and isinstance(manifest.get("post_auth_stage0_crawl"), dict):
        pa_meta = manifest["post_auth_stage0_crawl"]

    if pa_meta is not None:
        pa_status = str(pa_meta.get("status") or "").strip().lower()
        pa_enabled = pa_meta.get("enabled")
        pa_triggered = pa_meta.get("triggered")
        explicitly_disabled = (
            pa_enabled is False
            or pa_triggered is False
            or pa_status in {"skipped", "disabled", "not_run"}
        )
        pa_ran = (not explicitly_disabled) and (
            pa_status == "ok"
            or (not pa_status and (pa_enabled is True or pa_triggered is True))
        )
        if pa_ran:
            raw_pa_stats = pa_meta.get("stats")
            pa_stats: dict[str, Any] = raw_pa_stats if isinstance(raw_pa_stats, dict) else {}
            new_added = _safe_int(pa_meta.get("new_routes_added"))
            accepted = _safe_int(pa_meta.get("routes_accepted"))
            if accepted is None:
                accepted = _safe_int(pa_stats.get("routes_accepted"))
            ingested = _safe_int(pa_meta.get("routes_ingested"))

            zero_metric_key = ""
            if new_added == 0:
                zero_metric_key = "new_routes_added"
            elif accepted == 0:
                zero_metric_key = "routes_accepted"
            elif new_added is None and accepted is None and ingested == 0:
                zero_metric_key = "routes_ingested"

            if zero_metric_key:
                pa_metrics: dict[str, Any] = {
                    "status": pa_status or "enabled",
                    "trigger_field": zero_metric_key,
                }
                if new_added is not None:
                    pa_metrics["new_routes_added"] = new_added
                if accepted is not None:
                    pa_metrics["routes_accepted"] = accepted
                if ingested is not None:
                    pa_metrics["routes_ingested"] = ingested
                anomalies.append({
                    "code": "post_auth_zero_new_routes",
                    "severity": "medium",
                    "detail": (
                        f"Post-auth Stage 0 crawl ran ({pa_status or 'enabled'}) "
                        f"but added 0 new routes ({zero_metric_key}=0)."
                    ),
                    "metrics": pa_metrics,
                })

    # 6. service_degradation_triggered
    eff_run_status = str(
        run_status
        if run_status is not None
        else (manifest.get("status") if isinstance(manifest, dict) else "")
        or ""
    ).strip().lower()
    degraded_shards: list[str] = []
    if isinstance(eff_sharding, dict):
        raw_shards = eff_sharding.get("shards")
        if isinstance(raw_shards, (list, tuple)):
            for idx, shard in enumerate(raw_shards):
                if isinstance(shard, dict) and str(shard.get("status") or "").strip().lower() == "service_degraded":
                    label = str(shard.get("shard_id") or shard.get("name") or f"shard-{idx + 1}")
                    degraded_shards.append(label)
        s3_meta = eff_sharding.get("stage3_synthesis")
        if isinstance(s3_meta, dict) and str(s3_meta.get("status") or "").strip().lower() == "service_degraded":
            degraded_shards.append("stage3_synthesis")

    if eff_run_status == "service_degraded" or degraded_shards:
        if eff_run_status == "service_degraded" and degraded_shards:
            detail = (
                f"Run status and {len(degraded_shards)} shard(s) ({', '.join(degraded_shards[:5])}) "
                "terminated with service_degraded."
            )
        elif eff_run_status == "service_degraded":
            detail = "Run terminated with status=service_degraded (circuit breaker triggered)."
        else:
            detail = (
                f"{len(degraded_shards)} shard(s) ({', '.join(degraded_shards[:5])}) "
                "terminated with status=service_degraded."
            )
        anomalies.append({
            "code": "service_degradation_triggered",
            "severity": "high",
            "detail": detail,
            "metrics": {
                "run_status": eff_run_status or "unknown",
                "degraded_shards": degraded_shards,
                "degraded_shard_count": len(degraded_shards),
            },
        })

    return {
        "status": "warnings" if anomalies else "healthy",
        "warning_count": len(anomalies),
        "anomalies": anomalies,
        "checks_evaluated": _HEALTH_CHECK_COUNT,
    }


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".metrics-", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _entropy_bits(labels: Sequence[str]) -> float:
    freq = Counter(str(x) for x in labels if str(x))
    total = sum(freq.values())
    if total <= 0:
        return 0.0
    h_val = 0.0
    for cnt in freq.values():
        p = cnt / total
        if p > 0:
            h_val -= p * math.log2(p)
    return round(h_val, 4)


class TelemetryLogger:
    """Thread-safe JSONL event logger writing to `telemetry.jsonl`."""

    def __init__(self, root_dir: str | Path, *, filename: str = "telemetry.jsonl"):
        self.root_dir = Path(root_dir).expanduser().resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.root_dir / filename
        self._lock = threading.Lock()
        self._events: list[dict[str, Any]] = []
        if self.path.is_file():
            try:
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line:
                        self._events.append(json.loads(line))
            except (OSError, ValueError):
                pass

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": str(event),
            **fields,
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"
        with self._lock:
            self._events.append(record)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
        return record

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)


def _http_status_class(status: int | None) -> str:
    """Return normalized HTTP status bucket for non-BSAG novelty tracking."""
    if status is None or status <= 0:
        return "error"
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if status in (401, 403):
        return "401/403"
    if status == 404:
        return "404"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "other"


def _extract_http_event_query_keys(event: dict[str, Any]) -> frozenset[str]:
    """Extract normalized query parameter key set from an `http_event` record."""
    keys: set[str] = set()
    for field in ("query_keys", "params"):
        raw_seq = event.get(field)
        if isinstance(raw_seq, (list, tuple, set, frozenset)):
            for item in raw_seq:
                k = str(item.get("name") if isinstance(item, dict) else item or "").strip()
                if k:
                    keys.add(k)
    for raw_q in (
        str(event.get("query") or ""),
        urlsplit(str(event.get("path") or "")).query,
        urlsplit(str(event.get("url") or "")).query,
    ):
        if raw_q:
            for k, _ in parse_qsl(raw_q, keep_blank_values=True):
                clean_k = k.strip()
                if clean_k:
                    keys.add(clean_k)
    return frozenset(keys)


def compute_process_metrics(
    *,
    events: Sequence[dict[str, Any]],
    bsag: BeliefStateAttackGraph | None = None,
    surface_tracker: Any | None = None,
    findings: Sequence[dict[str, Any]] = (),
    token_usage: dict[str, Any] | None = None,
    ablation_config: dict[str, Any] | None = None,
    reference_endpoints: Sequence[str] = (),
    manifest: dict[str, Any] | None = None,
    auth_metadata: dict[str, Any] | None = None,
    sharding_summary: dict[str, Any] | None = None,
    post_auth_stage0_crawl: dict[str, Any] | None = None,
    run_status: str | None = None,
    report_text: str | None = None,
) -> dict[str, Any]:
    """Compute Thin-Control, Thick-State process metrics from telemetry and BSAG."""
    http_events = [e for e in events if e.get("event") == "http_event"]
    delta_events = [e for e in events if e.get("event") in {"http_event", "bsag_delta", "step_delta"}]
    worker_starts = [e for e in events if e.get("event") == "worker_start"]
    interventions = [e for e in events if e.get("event") == "intervention"]
    oracle_events = [e for e in events if e.get("event") == "oracle_verdict"]

    # 1. Exposure rate
    if bsag is not None:
        snap = bsag.metrics_snapshot()
        discovered_eps = int(snap["endpoints_discovered"])
        visited_eps = int(snap["endpoints_visited"])
        discovered_templates = set(snap["endpoint_templates"])
    elif surface_tracker is not None:
        raw_discovered = {
            route_template_of(str(path))
            for _, path in getattr(surface_tracker, "discovered_routes", {})
            if str(path or "").strip()
        }
        visited_templates = {
            str(tmpl)
            for _, tmpl in getattr(surface_tracker, "visited_method_templates", set())
            if str(tmpl or "").strip()
        }
        discovered_templates = raw_discovered | visited_templates
        discovered_eps = len(discovered_templates)
        visited_eps = len(visited_templates)
    else:
        discovered_templates = {str(e.get("route_template") or e.get("path") or "") for e in http_events if e.get("path")}
        discovered_eps = len(discovered_templates)
        visited_eps = discovered_eps

    exposure_ratio = min(1.0, round(visited_eps / max(1, discovered_eps), 4)) if discovered_eps > 0 else 0.0
    exposure_block: dict[str, Any] = {
        "unique_endpoints_discovered": discovered_eps,
        "unique_endpoints_visited": visited_eps,
        "coverage_ratio": exposure_ratio,
    }
    if reference_endpoints:
        ref_set = {str(x).strip().lower() for x in reference_endpoints if str(x).strip()}
        matched = len(ref_set & {t.lower() for t in discovered_templates})
        exposure_block["reference_matched"] = matched
        exposure_block["reference_total"] = len(ref_set)
        exposure_block["reference_exposure_rate"] = round(matched / max(1, len(ref_set)), 4)

    # 2. Fixation ratio: fraction of steps/events producing zero delta
    step_samples = [e for e in delta_events if "delta_v" in e and "delta_e" in e]
    has_nonzero_bsag_delta = any(
        int(e.get("delta_v") or 0) != 0 or int(e.get("delta_e") or 0) != 0
        for e in step_samples
    )
    if bsag is None and not has_nonzero_bsag_delta and http_events:
        seen_method_tmpls: set[tuple[str, str]] = set()
        seen_tmpl_actors: set[tuple[str, str]] = set()
        seen_tmpl_statuses: set[tuple[str, str]] = set()
        seen_tmpl_qkeys: set[tuple[str, frozenset[str]]] = set()
        zero_delta_count = 0
        for ev in http_events:
            method = str(ev.get("method") or "GET").strip().upper() or "GET"
            raw_tmpl = str(ev.get("route_template") or "").strip()
            if raw_tmpl:
                tmpl = route_template_of(raw_tmpl)
            else:
                raw_target = str(ev.get("path") or ev.get("url") or "/").strip() or "/"
                tmpl = route_template_of(raw_target)
            actor = str(ev.get("actor") or "anon").strip() or "anon"
            status_cls = _http_status_class(_safe_int(ev.get("status")))
            q_keys = _extract_http_event_query_keys(ev)

            m_key = (method, tmpl)
            a_key = (tmpl, actor)
            s_key = (tmpl, status_cls)
            q_key = (tmpl, q_keys)
            novel = (
                m_key not in seen_method_tmpls
                or a_key not in seen_tmpl_actors
                or s_key not in seen_tmpl_statuses
                or q_key not in seen_tmpl_qkeys
            )
            seen_method_tmpls.add(m_key)
            seen_tmpl_actors.add(a_key)
            seen_tmpl_statuses.add(s_key)
            seen_tmpl_qkeys.add(q_key)
            if not novel:
                zero_delta_count += 1
        step_sample_count = len(http_events)
        fixation_ratio = round(zero_delta_count / max(1, step_sample_count), 4)
    else:
        step_sample_count = len(step_samples)
        zero_delta_count = sum(
            1
            for e in step_samples
            if int(e.get("delta_v") or 0) == 0 and int(e.get("delta_e") or 0) == 0
        )
        fixation_ratio = round(zero_delta_count / max(1, step_sample_count), 4) if step_sample_count else 0.0

    # 3. Category entropy H(C)
    cat_labels = [str(e.get("category") or "") for e in worker_starts if e.get("category")]
    if not cat_labels:
        cat_labels = [str(e.get("category") or "") for e in http_events if e.get("category")]
    category_entropy = _entropy_bits(cat_labels)

    # 4. Decoy dwell steps
    decoy_nodes: set[str] = set()
    if bsag is not None:
        for n in bsag.nodes.values():
            if n.status == STATUS_SUSPECT_DECOY or n.decoy_suspicion_score >= 2.0:
                decoy_nodes.add(n.node_id)
        for h in bsag.nodes.values():
            if h.status == STATUS_REFUTED and h.attributes.get("endpoint_node_id"):
                decoy_nodes.add(str(h.attributes["endpoint_node_id"]))
    for oe in oracle_events:
        if oe.get("verdict") in {"REFUTED", "DECEPTION_DETECTED"} and oe.get("node_id"):
            decoy_nodes.add(str(oe["node_id"]))

    steps_per_decoy: dict[str, int] = {}
    for ev in http_events:
        nid = str(ev.get("node_id") or "")
        if nid and nid in decoy_nodes:
            steps_per_decoy[nid] = steps_per_decoy.get(nid, 0) + 1
    decoy_dwell_steps = (
        round(sum(steps_per_decoy.values()) / len(steps_per_decoy), 4)
        if steps_per_decoy
        else 0.0
    )

    # 5. Verification precision (VERIFIED / CLAIMED)
    verified_claims = sum(1 for oe in oracle_events if oe.get("verdict") == "VERIFIED")
    refuted_claims = sum(1 for oe in oracle_events if oe.get("verdict") in {"REFUTED", "DECEPTION_DETECTED"})
    deception_claims = sum(1 for oe in oracle_events if oe.get("verdict") == "DECEPTION_DETECTED")
    claimed_total = verified_claims + refuted_claims
    if claimed_total == 0 and findings:
        verified_claims = len(findings)
        claimed_total = len(findings)
    verification_precision = round(verified_claims / claimed_total, 4) if claimed_total > 0 else 0.0

    # 6. Tokens per verified finding
    total_tokens = int((token_usage or {}).get("total_tokens") or 0)
    verified_findings_count = len(findings)
    tokens_per_verified_finding = (
        round(total_tokens / verified_findings_count, 2) if verified_findings_count > 0 else None
    )

    interventions_by_trigger = dict(Counter(str(e.get("trigger") or "unknown") for e in interventions))
    harness_health = compute_harness_health_checks(
        events=events,
        manifest=manifest,
        auth_metadata=auth_metadata,
        sharding_summary=sharding_summary,
        post_auth_stage0_crawl=post_auth_stage0_crawl,
        run_status=run_status,
        report_text=report_text,
    )

    return {
        "schema": "agentic-process-metrics/1",
        "exposure_rate": exposure_block,
        "fixation_ratio": fixation_ratio,
        "category_entropy": category_entropy,
        "decoy_dwell_steps": decoy_dwell_steps,
        "verification_precision": verification_precision,
        "tokens_per_verified_finding": tokens_per_verified_finding,
        "claims": {
            "claimed_total": claimed_total,
            "verified": verified_claims,
            "refuted": refuted_claims,
            "deception_detected": deception_claims,
        },
        "counts": {
            "http_events": len(http_events),
            "zero_delta_steps": zero_delta_count,
            "step_samples": step_sample_count,
            "workers_spawned": len(worker_starts),
            "interventions_total": len(interventions),
            "interventions_by_trigger": interventions_by_trigger,
            "verified_findings_count": verified_findings_count,
            "total_tokens": total_tokens,
        },
        "ablation_config": dict(ablation_config or {}),
        "harness_health": harness_health,
    }


def render_process_metrics_markdown(metrics: dict[str, Any]) -> str:
    """Render a concise Markdown summary of process metrics."""
    exp = metrics.get("exposure_rate") or {}
    claims = metrics.get("claims") or {}
    counts = metrics.get("counts") or {}
    ablation = metrics.get("ablation_config") or {}
    lines = [
        "# Process Metrics Summary",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| Endpoints Discovered | {exp.get('unique_endpoints_discovered', 0)} |",
        f"| Endpoints Visited | {exp.get('unique_endpoints_visited', 0)} |",
        f"| Exposure Coverage Ratio | {exp.get('coverage_ratio', 0.0)} |",
        f"| Fixation Ratio (zero-delta) | {metrics.get('fixation_ratio', 0.0)} |",
        f"| Category Entropy H(C) (bits) | {metrics.get('category_entropy', 0.0)} |",
        f"| Decoy Dwell Steps (avg) | {metrics.get('decoy_dwell_steps', 0.0)} |",
        f"| Verification Precision | {metrics.get('verification_precision', 0.0)} ({claims.get('verified', 0)}/{claims.get('claimed_total', 0)}) |",
        f"| Deception Detected Claims | {claims.get('deception_detected', 0)} |",
        f"| Verified Findings | {counts.get('verified_findings_count', 0)} |",
        f"| Total Tokens | {counts.get('total_tokens', 0)} |",
        f"| Tokens per Verified Finding | {metrics.get('tokens_per_verified_finding')} |",
        f"| Workers Spawned | {counts.get('workers_spawned', 0)} |",
        f"| Interventions | {counts.get('interventions_total', 0)} ({json.dumps(counts.get('interventions_by_trigger', {}))}) |",
        "",
        f"**Ablation Config:** `{json.dumps(ablation, sort_keys=True)}`",
        "",
    ]
    health = metrics.get("harness_health")
    if isinstance(health, dict):
        h_status = str(health.get("status") or "healthy")
        h_warnings = int(health.get("warning_count") or 0)
        h_checked = int(health.get("checks_evaluated") or 0)
        h_anomalies = health.get("anomalies") or []
        lines.extend([
            "## Harness Health Checks",
            "",
            f"- **Status:** `{h_status}` ({h_warnings} warning(s), {h_checked} checks evaluated)",
        ])
        if h_anomalies:
            lines.extend([
                "",
                "| Code | Severity | Detail |",
                "| :--- | :--- | :--- |",
            ])
            for item in h_anomalies:
                if not isinstance(item, dict):
                    continue
                code = str(item.get("code") or "")
                sev = str(item.get("severity") or "")
                detail = str(item.get("detail") or "").replace("|", "\\|").replace("\n", " ")
                lines.append(f"| `{code}` | `{sev}` | {detail} |")
        else:
            lines.append("- No harness anomalies detected.")
        lines.append("")
    return "\n".join(lines)


def write_process_metrics(
    root_dir: str | Path,
    *,
    events: Sequence[dict[str, Any]],
    bsag: BeliefStateAttackGraph | None = None,
    surface_tracker: Any | None = None,
    findings: Sequence[dict[str, Any]] = (),
    token_usage: dict[str, Any] | None = None,
    ablation_config: dict[str, Any] | None = None,
    reference_endpoints: Sequence[str] = (),
    manifest: dict[str, Any] | None = None,
    auth_metadata: dict[str, Any] | None = None,
    sharding_summary: dict[str, Any] | None = None,
    post_auth_stage0_crawl: dict[str, Any] | None = None,
    run_status: str | None = None,
    report_text: str | None = None,
) -> tuple[Path, Path, dict[str, Any]]:
    """Compute and atomically write `process_metrics.json` and `process_metrics.md`."""
    out_dir = Path(root_dir).expanduser().resolve()
    metrics = compute_process_metrics(
        events=events,
        bsag=bsag,
        surface_tracker=surface_tracker,
        findings=findings,
        token_usage=token_usage,
        ablation_config=ablation_config,
        reference_endpoints=reference_endpoints,
        manifest=manifest,
        auth_metadata=auth_metadata,
        sharding_summary=sharding_summary,
        post_auth_stage0_crawl=post_auth_stage0_crawl,
        run_status=run_status,
        report_text=report_text,
    )
    json_path = out_dir / "process_metrics.json"
    md_path = out_dir / "process_metrics.md"
    _atomic_write_text(json_path, json.dumps(metrics, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    _atomic_write_text(md_path, render_process_metrics_markdown(metrics))
    return json_path, md_path, metrics
