#!/usr/bin/env python3
"""Read-only live TUI monitor (`cco-agent watch`) for Kryon runs.

Reads strictly redacted on-disk run artifacts (`manifest.json`, `agentic-plan.json`,
`findings.json`, `telemetry.jsonl`, `receipts/req-*.json`, and numeric counters in
`private/budget.json`) so it never touches credentials or alters engine execution.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any, Callable

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except Exception:  # pragma: no cover - optional fallback when rich is unavailable
    Console = None  # type: ignore[assignment,misc]
    Layout = None  # type: ignore[assignment,misc]
    Live = None  # type: ignore[assignment,misc]
    Panel = None  # type: ignore[assignment,misc]
    Table = None  # type: ignore[assignment,misc]
    Text = None  # type: ignore[assignment,misc]
    HAS_RICH = False

TERMINAL_STATUSES: frozenset[str] = frozenset({
    "completed",
    "done",
    "failed",
    "interrupted",
    "service_degraded",
    "stopped",
})

_RECEIPT_FILE_RE = re.compile(r"^req-(\d+)\.json$")
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}


@dataclass
class RunSnapshot:
    """Point-in-time read-only snapshot of a Kryon run directory."""

    run_dir: Path
    artifact_kind: str = "waiting"
    target: str = ""
    mode: str = ""
    status: str = "waiting"
    preset: str = ""
    execution_mode: str = ""
    allowed_methods: list[str] = field(default_factory=list)
    request_headers: list[str] = field(default_factory=list)
    authenticated_actors: list[str] = field(default_factory=list)
    unauthenticated_actors: list[str] = field(default_factory=list)
    http_used: int = 0
    http_limit: int = 0
    tokens_used: int = 0
    tokens_limit: int = 0
    seconds_used: float = 0.0
    seconds_limit: float = 0.0
    llm_calls: int = 0
    receipt_count: int = 0
    degraded_responses: int = 0
    waf_blocks: int = 0
    max_degradation_streak: int = 0
    stage0_enabled: bool = False
    stage0_status: str = ""
    prescan_enabled: bool = False
    prescan_status: str = ""
    prescan_leads: int = 0
    prescan_waf_vendors: list[str] = field(default_factory=list)
    har_flows_count: int = 0
    har_chained_steps: int = 0
    asset_graph_hosts: int = 0
    asset_graph_api_hosts: int = 0
    waf_pivot_active: bool = False
    shards: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    recent_receipts: list[dict[str, Any]] = field(default_factory=list)
    recent_events: list[dict[str, Any]] = field(default_factory=list)
    report_md: str = ""
    report_sarif: str = ""
    error: str = ""
    error_detail: str = ""


def _read_json_safe(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _receipt_sort_key(path: Path) -> tuple[int, str]:
    match = _RECEIPT_FILE_RE.match(path.name)
    if match:
        return int(match.group(1)), path.name
    return 0, path.name


def _read_tail_jsonl(path: Path, *, max_lines: int = 200) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in raw_lines[-max_lines:]:
        clean = line.strip()
        if not clean:
            continue
        try:
            obj = json.loads(clean)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _short_ts(raw_ts: Any) -> str:
    text = str(raw_ts or "").strip()
    if not text:
        return "--:--:--"
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%H:%M:%S")
    except ValueError:
        return text[-8:] if len(text) >= 8 else text


def _severity_rank(finding: dict[str, Any]) -> tuple[int, str]:
    sev = str(finding.get("severity") or "info").strip().lower()
    return _SEVERITY_ORDER.get(sev, 5), str(finding.get("vuln_class") or finding.get("category") or "")


def _format_event_detail(ev: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("shard_id", "shard", "worker", "tool", "actor", "method", "path", "status", "verdict", "vuln_class", "reason"):
        val = ev.get(key)
        if val is None or val == "":
            continue
        sval = str(val)
        if len(sval) > 48:
            sval = sval[:45] + "..."
        parts.append(f"{key}={sval}")
    if not parts:
        for k, v in ev.items():
            if k in {"ts", "event"} or v is None or v == "":
                continue
            sval = str(v)
            if len(sval) > 36:
                sval = sval[:33] + "..."
            parts.append(f"{k}={sval}")
            if len(parts) >= 3:
                break
    return " ".join(parts)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _extract_asset_graph_counts(ag_doc: dict[str, Any]) -> tuple[int, int]:
    """Extract (in_scope_hosts_count, api_hosts_count) from an asset_graph metadata or JSON dict."""
    ag_stats = _as_dict(ag_doc.get("stats"))
    raw_in_scope = ag_doc.get("in_scope_hosts")
    raw_nodes = ag_doc.get("nodes")
    nodes_list: list[dict[str, Any]] = (
        [n for n in raw_nodes if isinstance(n, dict)]
        if isinstance(raw_nodes, list)
        else []
    )
    in_scope_nodes = [n for n in nodes_list if n.get("in_scope")]

    hosts_count = 0
    if ag_doc.get("in_scope_hosts_count") is not None:
        hosts_count = max(0, int(ag_doc.get("in_scope_hosts_count") or 0))
    elif isinstance(raw_in_scope, int):
        hosts_count = max(0, raw_in_scope)
    elif isinstance(raw_in_scope, list):
        hosts_count = len(raw_in_scope)
    elif ag_doc.get("hosts") is not None:
        hosts_count = max(0, int(ag_doc.get("hosts") or 0))
    elif ag_stats.get("in_scope_hosts_count") is not None:
        hosts_count = max(0, int(ag_stats.get("in_scope_hosts_count") or 0))
    elif ag_stats.get("in_scope_hosts") is not None:
        hosts_count = max(0, int(ag_stats.get("in_scope_hosts") or 0))
    elif in_scope_nodes:
        hosts_count = len(in_scope_nodes)

    api_count = 0
    raw_api_hosts = ag_doc.get("api_hosts")
    if ag_doc.get("api_hosts_count") is not None:
        api_count = max(0, int(ag_doc.get("api_hosts_count") or 0))
    elif isinstance(raw_api_hosts, int):
        api_count = max(0, raw_api_hosts)
    elif isinstance(raw_api_hosts, list):
        api_count = len(raw_api_hosts)
    elif ag_stats.get("api_hosts_count") is not None:
        api_count = max(0, int(ag_stats.get("api_hosts_count") or 0))
    elif in_scope_nodes:
        api_count = sum(
            1 for n in in_scope_nodes if n.get("role") in {"api", "graphql", "auth", "admin"}
        )

    return hosts_count, api_count


def load_run_snapshot(
    run_dir: Path | str,
    *,
    max_receipts: int = 12,
    max_events: int = 12,
    max_findings: int = 20,
) -> RunSnapshot:
    """Load a thread-safe, fault-tolerant snapshot of ``run_dir``."""
    root = Path(run_dir).expanduser().resolve()
    snap = RunSnapshot(run_dir=root)

    manifest_path = root / "manifest.json"
    plan_path = root / "agentic-plan.json"
    meta = _read_json_safe(manifest_path)
    if isinstance(meta, dict):
        snap.artifact_kind = "manifest"
    else:
        meta = _read_json_safe(plan_path)
        if isinstance(meta, dict):
            snap.artifact_kind = "plan"
        else:
            meta = {}

    if isinstance(meta, dict) and meta:
        snap.target = str(meta.get("target") or "")
        snap.mode = str(meta.get("mode") or "")
        raw_status = str(meta.get("status") or "").strip()
        if not raw_status and snap.mode == "plan_only":
            raw_status = "planned"
        snap.status = raw_status or "running"
        snap.preset = str(meta.get("preset") or "")
        ablation = meta.get("ablation")
        if isinstance(ablation, dict):
            snap.execution_mode = str(ablation.get("execution_mode") or "")
        methods = meta.get("allowed_methods")
        if isinstance(methods, list):
            snap.allowed_methods = [str(m) for m in methods if str(m).strip()]
        req_hdrs = meta.get("request_headers")
        if isinstance(req_hdrs, list):
            snap.request_headers = [str(h) for h in req_hdrs if str(h).strip()]
        auth = meta.get("auth")
        if isinstance(auth, dict):
            snap.authenticated_actors = [str(a) for a in (auth.get("authenticated_actors") or []) if str(a).strip()]
            snap.unauthenticated_actors = [
                str(a) for a in (auth.get("unauthenticated_credentialed_actors") or []) if str(a).strip()
            ]
        scope = meta.get("scope")
        if isinstance(scope, dict):
            snap.max_degradation_streak = int(scope.get("max_degradation_streak") or 0)
        limits = meta.get("limits")
        if isinstance(limits, dict):
            snap.http_limit = int(limits.get("http_requests") or 0)
            snap.tokens_limit = int(limits.get("llm_tokens") or 0)
            snap.seconds_limit = float(limits.get("seconds") or 0.0)
        budget = meta.get("budget")
        if isinstance(budget, dict):
            snap.http_used = int(budget.get("http_used") or budget.get("http") or 0)
            snap.tokens_used = int(budget.get("tokens_used") or budget.get("tokens") or 0)
            snap.seconds_used = float(budget.get("elapsed_seconds") or budget.get("seconds_used") or 0.0)
        snap.llm_calls = int(meta.get("llm_calls") or 0)
        if meta.get("target_requests") is not None:
            snap.http_used = max(snap.http_used, int(meta.get("target_requests") or 0))
        if meta.get("wall_clock_seconds") is not None:
            snap.seconds_used = max(snap.seconds_used, float(meta.get("wall_clock_seconds") or 0.0))
        stage0 = meta.get("stage0_crawl")
        if isinstance(stage0, dict):
            snap.stage0_enabled = bool(stage0.get("enabled"))
            snap.stage0_status = str(stage0.get("status") or ("enabled" if snap.stage0_enabled else "off"))
        prescan = meta.get("prescan")
        if isinstance(prescan, dict):
            snap.prescan_enabled = bool(prescan.get("enabled"))
            snap.prescan_status = str(prescan.get("status") or ("enabled" if snap.prescan_enabled else "off"))
            raw_leads = prescan.get("leads_count") if prescan.get("leads_count") is not None else prescan.get("leads_total")
            if raw_leads is not None:
                snap.prescan_leads = max(0, int(raw_leads or 0))
            vendors = prescan.get("waf_vendors_seen")
            if isinstance(vendors, list):
                snap.prescan_waf_vendors = [str(v).strip() for v in vendors if str(v).strip()]
        har_flows = meta.get("har_flows")
        if isinstance(har_flows, dict):
            snap.har_flows_count = max(0, int(har_flows.get("flows_count") or 0))
            snap.har_chained_steps = max(0, int(har_flows.get("chained_steps_count") or 0))
        ag_meta = meta.get("asset_graph")
        if isinstance(ag_meta, dict):
            snap.asset_graph_hosts, snap.asset_graph_api_hosts = _extract_asset_graph_counts(ag_meta)
        sharding_summary = meta.get("sharding_summary")
        if isinstance(sharding_summary, dict) and isinstance(sharding_summary.get("shards"), list):
            for idx, item in enumerate(sharding_summary["shards"]):
                if isinstance(item, dict):
                    snap.shards.append({
                        "name": str(item.get("shard_id") or item.get("name") or f"shard-{idx + 1}"),
                        "status": str(item.get("status") or "unknown"),
                        "turns": int(item.get("turns") or 0),
                        "findings": int(item.get("findings_count") or 0),
                    })
        snap.report_md = str(meta.get("report_md") or "")
        snap.report_sarif = str(meta.get("report_sarif") or "")
        snap.error = str(meta.get("error") or "")
        snap.error_detail = str(meta.get("error_detail") or "")

    # Optional live numeric budget snapshot written by runner
    budget_file = _read_json_safe(root / "private" / "budget.json")
    if isinstance(budget_file, dict):
        snap.http_used = max(snap.http_used, int(budget_file.get("http_used") or budget_file.get("http") or 0))
        snap.tokens_used = max(snap.tokens_used, int(budget_file.get("tokens_used") or budget_file.get("tokens") or 0))
        snap.seconds_used = max(
            snap.seconds_used,
            float(budget_file.get("elapsed_seconds") or budget_file.get("seconds_used") or 0.0),
        )

    # Receipts (tail-only read for O(max_receipts) performance during large runs)
    receipts_dir = root / "receipts"
    if receipts_dir.is_dir():
        try:
            receipt_files = sorted(
                (p for p in receipts_dir.iterdir() if p.is_file() and p.suffix == ".json"),
                key=_receipt_sort_key,
            )
        except OSError:
            receipt_files = []
        snap.receipt_count = len(receipt_files)
        snap.http_used = max(snap.http_used, snap.receipt_count)
        tail_files = receipt_files[-max(1, int(max_receipts)):]
        for rpath in tail_files:
            rec = _read_json_safe(rpath)
            if not isinstance(rec, dict):
                continue
            status_code = int(rec.get("status") or 0)
            if status_code == 0 or status_code in {429, 502, 503, 504}:
                snap.degraded_responses += 1
            snap.recent_receipts.append({
                "receipt_id": str(rec.get("receipt_id") or rpath.stem),
                "actor": str(rec.get("actor") or "anon"),
                "method": str(rec.get("method") or "GET").upper(),
                "path": str(rec.get("path") or "/"),
                "status": status_code,
                "elapsed_ms": round(float(rec.get("elapsed_ms") or 0.0), 1),
                "error": str(rec.get("error") or ""),
            })

    # Findings
    raw_findings = _read_json_safe(root / "findings.json")
    if isinstance(raw_findings, list):
        valid_findings = [f for f in raw_findings if isinstance(f, dict)]
        valid_findings.sort(key=_severity_rank)
        for item in valid_findings[: max(1, int(max_findings))]:
            proof_ids = item.get("proof_receipt_ids") or []
            proof_ref = str(item.get("receipt_id") or (proof_ids[0] if isinstance(proof_ids, list) and proof_ids else ""))
            snap.findings.append({
                "severity": str(item.get("severity") or "info").upper(),
                "vuln_class": str(item.get("vuln_class") or item.get("category") or item.get("type") or "finding"),
                "method": str(item.get("method") or "").upper(),
                "path": str(item.get("path") or item.get("endpoint") or ""),
                "actor": str(item.get("actor") or ""),
                "receipt_id": proof_ref,
                "title": str(item.get("title") or item.get("summary") or "")[:64],
            })

    # Telemetry tail
    events = _read_tail_jsonl(root / "telemetry.jsonl", max_lines=200)
    if events:
        if not snap.shards:
            seen_shards: dict[str, dict[str, Any]] = {}
            for ev in events:
                sh_name = str(ev.get("shard_id") or ev.get("shard") or "").strip()
                if not sh_name:
                    continue
                row = seen_shards.setdefault(sh_name, {"name": sh_name, "status": "running", "turns": 0, "findings": 0})
                if ev.get("event") in {"turn", "llm_turn", "tool_call"}:
                    row["turns"] += 1
                if ev.get("status"):
                    row["status"] = str(ev.get("status"))
            snap.shards = list(seen_shards.values())

        for ev in events:
            ev_name = str(ev.get("event") or "").lower()
            if "waf" in ev_name or ev.get("waf_block"):
                snap.waf_blocks += 1
            toks = ev.get("total_tokens") or ev.get("tokens_used")
            if isinstance(toks, int) and toks > snap.tokens_used:
                snap.tokens_used = toks

        for ev in events[-max(1, int(max_events)):]:
            snap.recent_events.append({
                "ts": _short_ts(ev.get("ts")),
                "event": str(ev.get("event") or "event"),
                "detail": _format_event_detail(ev),
            })

    # Optional fallback reads for Faz A-C summary artifacts when not yet mirrored in manifest.json
    prescan_summary = _read_json_safe(root / "prescan-summary.json")
    if isinstance(prescan_summary, dict):
        snap.prescan_enabled = True
        if not snap.prescan_status or snap.prescan_status in {"enabled", "off"}:
            snap.prescan_status = str(prescan_summary.get("status") or "ok")
        p_stats = _as_dict(prescan_summary.get("stats"))
        fallback_leads = p_stats.get("leads_total")
        raw_p_leads = prescan_summary.get("leads")
        if fallback_leads is None and isinstance(raw_p_leads, list):
            fallback_leads = len(raw_p_leads)
        if fallback_leads is not None:
            snap.prescan_leads = max(snap.prescan_leads, int(fallback_leads or 0))
        summary_vendors = prescan_summary.get("waf_vendors_seen")
        if isinstance(summary_vendors, list):
            seen_v = set(snap.prescan_waf_vendors)
            for v in summary_vendors:
                vs = str(v).strip()
                if vs and vs not in seen_v:
                    seen_v.add(vs)
                    snap.prescan_waf_vendors.append(vs)

    har_flows_file = _read_json_safe(root / "har-flows.json")
    if isinstance(har_flows_file, dict):
        h_stats = _as_dict(har_flows_file.get("stats"))
        raw_h_flows = har_flows_file.get("flows")
        h_flows: list[dict[str, Any]] = (
            [fl for fl in raw_h_flows if isinstance(fl, dict)]
            if isinstance(raw_h_flows, list)
            else []
        )
        fallback_flows = int(h_stats.get("flows_count") or len(h_flows))
        chained_from_steps = 0
        for fl in h_flows:
            raw_steps = fl.get("steps")
            if not isinstance(raw_steps, list):
                continue
            for st in raw_steps:
                if isinstance(st, dict) and st.get("chained_from_step") is not None:
                    chained_from_steps += 1
        fallback_chained = int(h_stats.get("chained_steps_count") or chained_from_steps)
        snap.har_flows_count = max(snap.har_flows_count, fallback_flows)
        snap.har_chained_steps = max(snap.har_chained_steps, fallback_chained)

    if snap.asset_graph_hosts == 0:
        ag_file = _read_json_safe(root / "asset-graph.json")
        if isinstance(ag_file, dict) and ag_file.get("schema") == "cco-asset-graph/1":
            snap.asset_graph_hosts, snap.asset_graph_api_hosts = _extract_asset_graph_counts(ag_file)

    waf_pivot_meta = _as_dict(meta.get("waf_pivot")) if isinstance(meta, dict) else {}
    snap.waf_pivot_active = bool(waf_pivot_meta.get("should_pivot")) or snap.waf_blocks >= 2

    if snap.status == "starting" and (snap.receipt_count > 0 or snap.recent_events):
        snap.status = "running"

    return snap


def _progress_bar(used: float, limit: float, *, width: int = 18) -> str:
    if limit <= 0:
        return f"[{'-' * width}] {int(used)}/∞"
    ratio = max(0.0, min(1.0, float(used) / float(limit)))
    filled = int(round(ratio * width))
    pct = int(round(ratio * 100))
    return f"[{'#' * filled}{'.' * (width - filled)}] {pct:3d}% ({int(used)}/{int(limit)})"


def _pipeline_summary_parts(snap: RunSnapshot) -> list[str]:
    parts: list[str] = []
    if snap.prescan_enabled:
        p_state = snap.prescan_status or "on"
        waf_suffix = f", waf={','.join(snap.prescan_waf_vendors)}" if snap.prescan_waf_vendors else ""
        parts.append(f"Prescan={p_state}({snap.prescan_leads} leads{waf_suffix})")
    else:
        parts.append(f"Prescan={snap.prescan_status or 'off'}")
    if snap.har_flows_count > 0:
        parts.append(f"HAR Flows={snap.har_flows_count}({snap.har_chained_steps} chained)")
    if snap.asset_graph_hosts > 0:
        parts.append(f"AssetGraph={snap.asset_graph_hosts}({snap.asset_graph_api_hosts} api)")
    if snap.waf_pivot_active:
        parts.append("WAF Pivot: ACTIVE")
    return parts


def render_plain_dashboard(snap: RunSnapshot) -> str:
    """Render a deterministic, dependency-free plain-text dashboard."""
    lines: list[str] = []
    lines.append(f"=== KRYON WATCH | {snap.run_dir} ===")
    preset_part = f" | preset={snap.preset}" if snap.preset else ""
    mode_part = f" | mode={snap.execution_mode or snap.mode or 'n/a'}"
    lines.append(f"Target : {snap.target or '(waiting for manifest/plan)'}")
    lines.append(f"Status : {snap.status.upper()}{preset_part}{mode_part}")
    if snap.allowed_methods:
        lines.append(f"Methods: {', '.join(snap.allowed_methods)}")
    if snap.request_headers:
        lines.append(f"Headers: {', '.join(snap.request_headers)} (values redacted)")
    auth_ok = ", ".join(snap.authenticated_actors) or "none"
    auth_bad = ", ".join(snap.unauthenticated_actors) or "none"
    lines.append(f"Actors : auth=[{auth_ok}] unauth=[{auth_bad}]")
    if snap.error:
        lines.append(f"Error  : {snap.error} {snap.error_detail}".strip())

    lines.append("")
    lines.append("--- Budgets & Health ---")
    lines.append(f"HTTP   : {_progress_bar(snap.http_used, snap.http_limit)}")
    lines.append(f"Tokens : {_progress_bar(snap.tokens_used, snap.tokens_limit)}")
    lines.append(f"Time(s): {_progress_bar(snap.seconds_used, snap.seconds_limit)}")
    lines.append(
        f"Health : receipts={snap.receipt_count} llm_calls={snap.llm_calls} "
        f"degraded_tail={snap.degraded_responses} waf_events={snap.waf_blocks} "
        f"stage0={snap.stage0_status or ('on' if snap.stage0_enabled else 'off')}"
    )
    lines.append(f"Pipeline: {' | '.join(_pipeline_summary_parts(snap))}")

    if snap.shards:
        lines.append("")
        lines.append("--- Shards ---")
        for sh in snap.shards:
            lines.append(f"  {sh['name']:<18} status={sh['status']:<14} turns={sh['turns']} findings={sh['findings']}")

    lines.append("")
    lines.append(f"--- Verified Findings ({len(snap.findings)}) ---")
    if not snap.findings:
        lines.append("  (none yet)")
    else:
        for f in snap.findings:
            lines.append(
                f"  [{f['severity']:<8}] {f['vuln_class']:<20} {f['method']:<6} {f['path']} "
                f"(actor={f['actor'] or '-'}, ref={f['receipt_id'] or '-'})"
            )

    lines.append("")
    lines.append(f"--- Recent Receipts (last {len(snap.recent_receipts)} of {snap.receipt_count}) ---")
    if not snap.recent_receipts:
        lines.append("  (no receipts yet)")
    else:
        for rec in snap.recent_receipts:
            err = f" err={rec['error']}" if rec["error"] else ""
            lines.append(
                f"  {rec['receipt_id']} | {rec['actor']:<10} | {rec['method']:<6} {rec['path']:<32} "
                f"| {rec['status']:>3} | {rec['elapsed_ms']:>6.1f}ms{err}"
            )

    lines.append("")
    lines.append(f"--- Recent Telemetry ({len(snap.recent_events)}) ---")
    if not snap.recent_events:
        lines.append("  (no telemetry events yet)")
    else:
        for ev in snap.recent_events:
            lines.append(f"  {ev['ts']} | {ev['event']:<18} | {ev['detail']}")

    if snap.report_md or snap.report_sarif:
        lines.append("")
        lines.append("--- Reports ---")
        if snap.report_md:
            lines.append(f"  Markdown: {snap.report_md}")
        if snap.report_sarif:
            lines.append(f"  SARIF   : {snap.report_sarif}")

    return "\n".join(lines)


def _status_style(status: str) -> str:
    low = status.lower()
    if low in {"completed", "done", "planned"}:
        return "bold green"
    if low in {"running", "starting"}:
        return "bold cyan"
    if low in {"service_degraded", "interrupted"}:
        return "bold yellow"
    if low in {"failed"}:
        return "bold red"
    return "white"


def _severity_style(severity: str) -> str:
    low = severity.lower()
    if low == "critical":
        return "bold red"
    if low == "high":
        return "red"
    if low == "medium":
        return "yellow"
    if low == "low":
        return "cyan"
    return "dim"


def build_rich_dashboard(snap: RunSnapshot) -> Any:
    """Build a multi-panel ``rich.layout.Layout`` dashboard for ``snap``."""
    if not HAS_RICH:
        return render_plain_dashboard(snap)
    assert Layout is not None and Panel is not None and Table is not None and Text is not None

    # 1. Header panel
    header_text = Text()
    header_text.append("KRYON ", style="bold magenta")
    header_text.append(f"[{snap.status.upper()}] ", style=_status_style(snap.status))
    header_text.append(snap.target or "(waiting for manifest/plan)", style="bold white")
    if snap.preset:
        header_text.append(f"  preset={snap.preset}", style="cyan")
    if snap.execution_mode or snap.mode:
        header_text.append(f"  mode={snap.execution_mode or snap.mode}", style="dim")
    header_text.append("\n")
    auth_ok = ", ".join(snap.authenticated_actors) or "anon-only"
    header_text.append(f"Actors: {auth_ok}", style="green")
    if snap.unauthenticated_actors:
        header_text.append(f"  (unauth: {', '.join(snap.unauthenticated_actors)})", style="yellow")
    if snap.allowed_methods:
        header_text.append(f"  |  Methods: {','.join(snap.allowed_methods)}", style="dim")
    if snap.request_headers:
        header_text.append(f"  |  Headers: {', '.join(snap.request_headers)}", style="cyan")
    if snap.error:
        header_text.append(f"\nError: {snap.error} {snap.error_detail}".strip(), style="bold red")
    header_panel = Panel(header_text, title=str(snap.run_dir), border_style="bright_blue")

    # 2. Budgets & Shards panel
    budget_table = Table.grid(padding=(0, 1))
    budget_table.add_column(style="bold", width=10)
    budget_table.add_column()
    budget_table.add_row("HTTP", _progress_bar(snap.http_used, snap.http_limit))
    budget_table.add_row("Tokens", _progress_bar(snap.tokens_used, snap.tokens_limit))
    budget_table.add_row("Time(s)", _progress_bar(snap.seconds_used, snap.seconds_limit))
    budget_table.add_row(
        "Health",
        f"receipts={snap.receipt_count}  llm={snap.llm_calls}  degraded={snap.degraded_responses}  waf={snap.waf_blocks}",
    )
    budget_table.add_row("Stage 0", snap.stage0_status or ("enabled" if snap.stage0_enabled else "off"))
    pipeline_parts = _pipeline_summary_parts(snap)
    pipeline_text = Text()
    for idx, part in enumerate(pipeline_parts):
        if idx > 0:
            pipeline_text.append("\n")
        style = "bold yellow" if part == "WAF Pivot: ACTIVE" else ""
        pipeline_text.append(part, style=style)
    budget_table.add_row("Pipeline", pipeline_text)
    if snap.shards:
        shard_str = ", ".join(f"{s['name']}:{s['status']}({s['turns']}t)" for s in snap.shards[:6])
        budget_table.add_row("Shards", shard_str)
    if snap.report_md:
        budget_table.add_row("Report", snap.report_md)
    left_panel = Panel(budget_table, title="Budgets & Pipeline", border_style="cyan")

    # 3. Findings table
    findings_table = Table(expand=True, box=None, pad_edge=False)
    findings_table.add_column("Sev", width=8)
    findings_table.add_column("Class", width=18)
    findings_table.add_column("Endpoint")
    findings_table.add_column("Ref", width=10)
    if not snap.findings:
        findings_table.add_row("-", "No verified findings", "", "")
    else:
        for f in snap.findings[:10]:
            findings_table.add_row(
                Text(f["severity"], style=_severity_style(f["severity"])),
                f["vuln_class"][:18],
                f"{f['method']} {f['path']}".strip()[:42],
                f["receipt_id"] or "-",
            )
    right_panel = Panel(findings_table, title=f"Verified Findings ({len(snap.findings)})", border_style="green")

    # 4. Recent HTTP receipts
    receipts_table = Table(expand=True, box=None, pad_edge=False)
    receipts_table.add_column("ID", width=9)
    receipts_table.add_column("Actor", width=10)
    receipts_table.add_column("Request")
    receipts_table.add_column("Code", width=5, justify="right")
    receipts_table.add_column("ms", width=7, justify="right")
    if not snap.recent_receipts:
        receipts_table.add_row("-", "-", "(waiting for receipts)", "-", "-")
    else:
        for rec in snap.recent_receipts[-10:]:
            code = int(rec["status"])
            cstyle = "green" if 200 <= code < 300 else ("yellow" if 300 <= code < 400 else "red")
            receipts_table.add_row(
                rec["receipt_id"],
                rec["actor"][:10],
                f"{rec['method']} {rec['path']}"[:44],
                Text(str(code), style=cstyle),
                f"{rec['elapsed_ms']:.0f}",
            )
    receipts_panel = Panel(receipts_table, title=f"Recent HTTP Receipts ({snap.receipt_count})", border_style="blue")

    # 5. Telemetry feed
    events_table = Table(expand=True, box=None, pad_edge=False)
    events_table.add_column("UTC", width=8, style="dim")
    events_table.add_column("Event", width=16, style="bold")
    events_table.add_column("Detail")
    if not snap.recent_events:
        events_table.add_row("--:--:--", "idle", "waiting for telemetry.jsonl")
    else:
        for ev in snap.recent_events[-10:]:
            events_table.add_row(ev["ts"], ev["event"][:16], ev["detail"][:52])
    events_panel = Panel(events_table, title="Live Telemetry", border_style="magenta")

    layout = Layout(name="root")
    layout.split_column(
        Layout(header_panel, name="header", size=5),
        Layout(name="middle", ratio=1),
        Layout(name="bottom", ratio=1),
    )
    layout["middle"].split_row(
        Layout(left_panel, name="budgets", ratio=1),
        Layout(right_panel, name="findings", ratio=1),
    )
    layout["bottom"].split_row(
        Layout(receipts_panel, name="receipts", ratio=1),
        Layout(events_panel, name="events", ratio=1),
    )
    return layout


def watch_run_dir(
    run_dir: Path | str,
    *,
    refresh_seconds: float = 0.75,
    once: bool = False,
    plain: bool = False,
    exit_on_complete: bool = False,
    stop_event: threading.Event | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> int:
    """Render a live or one-shot TUI monitor for ``run_dir``."""
    interval = max(0.1, float(refresh_seconds))
    use_rich = HAS_RICH and not plain and (once or sys.stdout.isatty())

    if once:
        snap = load_run_snapshot(run_dir)
        if use_rich and Console is not None:
            console = Console()
            console.print(build_rich_dashboard(snap))
        else:
            print(render_plain_dashboard(snap))
        return 0

    if use_rich and Console is not None and Live is not None:
        console = Console()
        try:
            with Live(build_rich_dashboard(load_run_snapshot(run_dir)), console=console, screen=False, refresh_per_second=4) as live:
                while True:
                    snap = load_run_snapshot(run_dir)
                    live.update(build_rich_dashboard(snap))
                    if stop_event is not None and stop_event.is_set():
                        break
                    if exit_on_complete and snap.status.lower() in TERMINAL_STATUSES:
                        break
                    sleep_fn(interval)
        except KeyboardInterrupt:
            pass
        return 0

    # Plain-text polling loop fallback
    try:
        while True:
            snap = load_run_snapshot(run_dir)
            print(render_plain_dashboard(snap), flush=True)
            if stop_event is not None and stop_event.is_set():
                break
            if exit_on_complete and snap.status.lower() in TERMINAL_STATUSES:
                break
            sleep_fn(interval)
    except KeyboardInterrupt:
        pass
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cco-agent watch",
        description="Read-only live TUI monitor for a Kryon run directory.",
    )
    parser.add_argument("run_dir", type=Path, help="Run output directory containing manifest.json / receipts / telemetry.jsonl")
    parser.add_argument("--refresh", type=float, default=0.75, help="Refresh interval in seconds (default: 0.75)")
    parser.add_argument("--once", action="store_true", help="Render a single snapshot and exit")
    parser.add_argument("--plain", action="store_true", help="Render dependency-free plain text instead of Rich TUI")
    parser.add_argument(
        "--exit-on-complete",
        action="store_true",
        help="Exit automatically once run status reaches completed/failed/interrupted/service_degraded",
    )
    args = parser.parse_args(argv)
    return watch_run_dir(
        args.run_dir,
        refresh_seconds=args.refresh,
        once=args.once,
        plain=args.plain,
        exit_on_complete=args.exit_on_complete,
    )


if __name__ == "__main__":
    raise SystemExit(main())
