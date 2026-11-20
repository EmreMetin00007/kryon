"""Layer 5: Unified telemetry logger (telemetry.jsonl) and process metrics generator."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import tempfile
import threading
from typing import Any, Sequence

from agentic_bsag import STATUS_REFUTED, STATUS_SUSPECT_DECOY, BeliefStateAttackGraph


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


def compute_process_metrics(
    *,
    events: Sequence[dict[str, Any]],
    bsag: BeliefStateAttackGraph | None = None,
    surface_tracker: Any | None = None,
    findings: Sequence[dict[str, Any]] = (),
    token_usage: dict[str, Any] | None = None,
    ablation_config: dict[str, Any] | None = None,
    reference_endpoints: Sequence[str] = (),
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
        discovered_templates = {
            tmpl for _, tmpl in getattr(surface_tracker, "discovered_routes", {})
        }
        visited_templates = {
            tmpl for _, tmpl in getattr(surface_tracker, "visited_method_templates", set())
        }
        discovered_eps = len(discovered_templates)
        visited_eps = len(visited_templates)
    else:
        discovered_templates = {str(e.get("route_template") or e.get("path") or "") for e in http_events if e.get("path")}
        discovered_eps = len(discovered_templates)
        visited_eps = discovered_eps

    exposure_ratio = round(visited_eps / max(1, discovered_eps), 4) if discovered_eps > 0 else 0.0
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

    # 2. Fixation ratio: fraction of steps/events producing delta_v == 0 and delta_e == 0
    step_samples = [e for e in delta_events if "delta_v" in e and "delta_e" in e]
    zero_delta_count = sum(1 for e in step_samples if int(e.get("delta_v") or 0) == 0 and int(e.get("delta_e") or 0) == 0)
    fixation_ratio = round(zero_delta_count / max(1, len(step_samples)), 4) if step_samples else 0.0

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
            "step_samples": len(step_samples),
            "workers_spawned": len(worker_starts),
            "interventions_total": len(interventions),
            "interventions_by_trigger": interventions_by_trigger,
            "verified_findings_count": verified_findings_count,
            "total_tokens": total_tokens,
        },
        "ablation_config": dict(ablation_config or {}),
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
    )
    json_path = out_dir / "process_metrics.json"
    md_path = out_dir / "process_metrics.md"
    _atomic_write_text(json_path, json.dumps(metrics, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    _atomic_write_text(md_path, render_process_metrics_markdown(metrics))
    return json_path, md_path, metrics
