#!/usr/bin/env python3
"""Autonomous bug bounty loop (L3 campaign-grant supervised autonomy).

Tek komutla hedefe karsi yardimsiz kosu:
  recon -> intel -> plan -> webloop -> validate -> fanout -> finding gate -> rapor

Guvenlik siniri:
- Her task CampaignRuntime policy gate'inden gecer (scope + approval + rate limit).
- Loopback disinda grant sarti: init asamasinda PolicyEngine.grant_approval ile
  kampanya suresiyle sinirli tek onay (L3). Grant yoksa worker task'lari
  waiting_approval'da bekler, hicbir aktif istek atilmaz.
- Yikici teknikler, dump/ascan, gercek kullanici verisi exfiltration: varsayilan YASAK.
- Kill switch: campaign kill veya --max-tasks / --max-seconds asimi donguyu durdurur.

Kullanim:
  python3 scripts/autonomous_bounty.py auto --embedded-lab --max-tasks 40
  python3 scripts/autonomous_bounty.py auto --target http://127.0.0.1:8899 --max-tasks 40
  python3 scripts/autonomous_bounty.py report --campaign-id 1
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from campaign_runtime import CampaignRuntime
from campaign_worker import CampaignWorker, LocalMCPExecutor, dry_run_executor
from policy_engine import PolicyEngine

REPO_ROOT = SCRIPT_DIR.parent

DEFAULT_ALLOWED_TOOLS = (
    "kali-tools_discover_web_surface,"
    "kali-tools_compile_target_wordlist,"
    "kali-tools_curl_request,"
    "hunter_*,"
    "validator_validate_*,"
    "validator_confirm_oob_callback,"
    "validator_generate_validation_report,"
    "reasoning_*,"
    "memory-server_*,"
    "telemetry_*"
)

LAB_IDENTITIES = {
    "owner": {"Authorization": "Bearer userA"},
    "attacker": {"Authorization": "Bearer userB"},
    "admin": {"Authorization": "Bearer admin"},
}

SEVERITY_BY_CLASS = {
    "sql_injection": "high",
    "sqli": "high",
    "bola": "high",
    "idor": "high",
    "auth_bypass": "high",
    "bfla": "high",
    "command_injection": "critical",
    "ssti": "high",
    "xss_reflected": "medium",
    "xss": "medium",
    "open_redirect": "low",
    "path_traversal": "high",
    "ssrf": "high",
    "xxe": "high",
    "price_manipulation": "medium",
    "business_logic": "medium",
}

FANOUT_BY_VALIDATOR = {
    "validator_validate_sqli": "sql_injection",
    "validator_validate_xss_reflection": "xss_reflected",
    "validator_validate_open_redirect": "open_redirect",
    "validator_validate_idor": "idor",
    "validator_validate_auth_bypass": "auth_bypass",
    "validator_validate_ssti": "ssti",
    "validator_validate_command_injection": "command_injection",
    "validator_validate_path_traversal": "path_traversal",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_loopback_target(target: str) -> bool:
    try:
        host = urlparse(target).hostname or target
    except ValueError:
        return False
    return host in {"localhost", "127.0.0.1", "::1"} or host.startswith("127.")


def _parse_tool_output(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except (json.JSONDecodeError, TypeError):
            return {"raw": raw[:2000]}
    return {"value": str(raw)[:2000]}


def _task_output(task_result: dict) -> dict:
    try:
        output = task_result.get("output")
        return _parse_tool_output(output)
    except (AttributeError, TypeError):
        return {}


def _redact_excerpt(text: str, limit: int = 600) -> str:
    redacted = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1<redacted>", text or "")
    redacted = re.sub(r"(?i)(cookie|sessionid|api[_-]?key|secret|password)(=|:)\s*\S+", r"\1\2<redacted>", redacted)
    return redacted[:limit]


def _finding_fingerprint(vuln_class: str, url: str, param: str) -> str:
    try:
        parsed = urlparse(url)
        norm = f"{parsed.hostname or ''}{parsed.path.rstrip('/')}|{param}|{vuln_class}".lower()
    except ValueError:
        norm = f"{url}|{param}|{vuln_class}".lower()
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


class BountyManifest:
    """L3 kampanya manifestosu: tek onayin kapsadigi sinirlar."""

    def __init__(self, campaign_id: int, target: str, scope_file: str = "",
                 budget_requests: int = 500, budget_usd: float = 5.0,
                 allowed_tools: str = DEFAULT_ALLOWED_TOOLS,
                 grant_ttl_seconds: int = 7200, notes: str = ""):
        self.campaign_id = campaign_id
        self.target = target
        self.scope_file = scope_file
        self.budget_requests = budget_requests
        self.budget_usd = budget_usd
        self.allowed_tools = allowed_tools
        self.grant_ttl_seconds = grant_ttl_seconds
        self.notes = notes
        self.created_at = _utc_now()

    def to_dict(self) -> dict:
        return {
            "schema": "cco-bounty-manifest/1",
            "campaign_id": self.campaign_id,
            "target": self.target,
            "scope_file": self.scope_file,
            "budget_requests": self.budget_requests,
            "budget_usd": self.budget_usd,
            "allowed_tools": self.allowed_tools,
            "grant_ttl_seconds": self.grant_ttl_seconds,
            "notes": self.notes,
            "created_at": self.created_at,
            "prohibited": ["destructive", "dump", "ascan", "dos", "brute_force_unbounded", "real_user_data_exfil"],
        }

    def save(self, cco_home: Path) -> Path:
        path = cco_home / "bounty" / f"campaign-{self.campaign_id}" / "manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))
        return path


def ensure_grant(target: str, ttl_seconds: int = 7200) -> dict:
    """L3 tek-onay: loopback'te gerekmez, gercek hedefte grant sart."""
    if _is_loopback_target(target):
        return {"granted": True, "reason": "loopback-exempt"}
    engine = PolicyEngine(repo_root=str(REPO_ROOT))
    try:
        host = urlparse(target).hostname or target
    except ValueError:
        host = target
    grant = engine.grant_approval(
        tool_pattern="*",
        target_pattern=host,
        ttl_seconds=ttl_seconds,
        reason="L3-BOUNTY-CAMPAIGN-GRANT",
    )
    return {"granted": True, "reason": "campaign-grant", "grant_id": grant.id, "expires_at": grant.expires_at}


def plan_campaign(runtime: CampaignRuntime, campaign_id: int, target: str,
                  *, include_lab_vectors: bool | None = None) -> list[int]:
    """Deterministik planner: scope hedefinden task DAG uret ve enqueue et."""
    base = target.rstrip("/")
    task_ids: list[int] = []
    if include_lab_vectors is None:
        include_lab_vectors = _is_loopback_target(base)

    def enqueue(kind: str, tool: str, args: dict, parent: int | None = None,
                cost: int = 1, key_suffix: str = "") -> int:
        key = f"plan:{kind}:{tool}:{key_suffix or hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:12]}"
        task_id = runtime.enqueue_task(
            campaign_id, kind, tool_name=tool, args=args, parent_id=parent,
            max_attempts=2, request_cost=cost, idempotency_key=key,
        )
        task_ids.append(task_id)
        return task_id

    t_discover = enqueue("recon", "kali-tools_discover_web_surface",
                         {"target": base, "mode": "active", "probe_limit": 16}, cost=4)
    t_predict = enqueue("intel", "hunter_predict_vulnerabilities",
                        {"target": base, "fingerprint": "php mysql rest api checkout admin" if include_lab_vectors else ""},
                        parent=t_discover)
    t_plan = enqueue("plan", "reasoning_plan_attack_tree",
                     {"target": base}, parent=t_predict)
    t_loop = enqueue("webloop", "hunter_run_web_loop",
                     {"target": base, "live": True, "crawl": False, "zap": False,
                      "fuzz_limit": 12, "max_validations": 5, "sleep_s": 0.05},
                     parent=t_plan, cost=16, key_suffix="webloop-main")
    if include_lab_vectors:
        # Authz + kritik vektorler: gomulu VulnLab (loopback) dogrulamalari.
        t_idor = enqueue("validate", "validator_validate_idor",
                         {"object_url": f"{base}/api/orders/1001",
                          "owner_headers_json": json.dumps(LAB_IDENTITIES["owner"]),
                          "attacker_headers_json": json.dumps(LAB_IDENTITIES["attacker"]),
                          "owner_marker": "alice@lab.local"},
                         parent=t_loop, cost=8, key_suffix="idor-main")
        t_auth = enqueue("validate", "validator_validate_auth_bypass",
                         {"protected_url": f"{base}/admin/export",
                          "authorized_headers_json": json.dumps(LAB_IDENTITIES["admin"]),
                          "protected_marker": "all-customer-pii"},
                         parent=t_loop, cost=8, key_suffix="auth-main")
        t_sqli = enqueue("validate", "validator_validate_sqli",
                         {"target_url": f"{base}/item?id=1", "param": "id"},
                         parent=t_loop, cost=8, key_suffix="sqli-main")
        t_redirect = enqueue("validate", "validator_validate_open_redirect",
                             {"target_url": f"{base}/go?next=/home", "param": "next"},
                             parent=t_loop, cost=8, key_suffix="redirect-main")
        enqueue("intel", "hunter_generate_abuse_cases",
                {"target": base, "endpoint": f"{base}/checkout", "params": "price,quantity"},
                parent=t_predict, key_suffix="abuse-checkout")
        enqueue("validate", "validator_validate_sqli",
                {"target_url": f"{base}/safe/item?id=1", "param": "id"},
                parent=t_loop, cost=8, key_suffix="sqli-safe-negative")
        _ = (t_idor, t_auth, t_sqli, t_redirect)
    t_coverage = enqueue("report", "hunter_coverage_report", {"target": base}, parent=t_loop)
    _ = t_coverage
    return task_ids


def _enqueue_followup(runtime: CampaignRuntime, campaign_id: int, kind: str,
                      tool: str, args: dict, key: str, cost: int = 1) -> int | None:
    try:
        return runtime.enqueue_task(campaign_id, kind, tool_name=tool, args=args,
                                    max_attempts=2, request_cost=cost, idempotency_key=key)
    except ValueError:
        return None


def followups_for_task(runtime: CampaignRuntime, task: dict, output: dict) -> list[int]:
    """Worker sonucuna gore otomatik takip gorevleri (fanout + store)."""
    campaign_id = int(task["campaign_id"])
    tool = str(task.get("tool_name") or "")
    created: list[int] = []

    def add(kind: str, tool_name: str, args: dict, suffix: str, cost: int = 1):
        key = f"follow:{task['id']}:{suffix}"
        task_id = _enqueue_followup(runtime, campaign_id, kind, tool_name, args, key, cost)
        if task_id:
            created.append(task_id)

    # 1) Validator CONFIRMED -> fanout + validated store.
    if tool.startswith("validator_validate_"):
        verdict = str(output.get("verdict") or "").upper()
        if verdict == "CONFIRMED":
            vuln_class = str(output.get("vuln_type") or output.get("validator") or tool)
            target_url = str(output.get("target") or output.get("target_url") or "")
            evidence = output.get("evidence") or {}
            param = str(evidence.get("param") or output.get("param") or "")
            finding_type = FANOUT_BY_VALIDATOR.get(tool, "sql_injection")
            if target_url:
                add("fanout", "hunter_auto_fanout_variants",
                    {"finding_type": finding_type, "target": target_url,
                     "param": param, "endpoint": target_url, "live": True, "max_requests": 6},
                    f"fanout-{finding_type}", cost=6)
            add("store", "memory-server_store_finding",
                {"target": target_url or vuln_class,
                 "type": finding_type,
                 "severity": SEVERITY_BY_CLASS.get(finding_type, "medium"),
                 "description": f"Autonomous L3 confirmed: {finding_type} @ {target_url}",
                 "payload": "",
                 "validation_result_json": json.dumps(output)[:12000]},
                f"store-{finding_type}-{_finding_fingerprint(finding_type, target_url, param)}")
        return created

    # 2) Webloop confirmed -> exploit pack + validated store.
    if tool == "hunter_run_web_loop":
        for item in output.get("confirmed") or []:
            if not isinstance(item, dict):
                continue
            validation_id = str(item.get("validation_id") or "")
            vuln_class = str(item.get("vuln_class") or item.get("type") or "unknown")
            url = str(item.get("url") or item.get("target") or "")
            # NOT: exploit_confirmed su an worker task olarak enqueue edilmiyor cunku
            # policy validation_id-opaque hedefi cozemez (blocked_missing_target).
            # Gerekli duzeltme: artifact-aware policy (validation_id -> artifact -> target).
            # V1'de validator JSON'un kendisi kanit pack olarak saklaniyor.
            _ = validation_id
            add("store", "memory-server_store_finding",
                {"target": url or vuln_class, "type": vuln_class,
                 "severity": SEVERITY_BY_CLASS.get(vuln_class, "medium"),
                 "description": f"Autonomous L3 webloop confirmed: {vuln_class} @ {url}",
                 "payload": "",
                 "validation_result_json": json.dumps(item)[:12000]},
                f"store-loop-{_finding_fingerprint(vuln_class, url, '')}")
        # LIKELY ama validate edilmemis -> dogrudan validator'a gonder.
        for item in (output.get("fuzz") or {}).get("likely_hits") or []:
            if not isinstance(item, dict):
                continue
            vuln_class = str(item.get("vuln_class") or "")
            url = str(item.get("url") or "")
            param = str(item.get("param") or "")
            if not vuln_class or not url:
                continue
            key_part = _finding_fingerprint(vuln_class, url, param)
            if vuln_class in {"sql_injection", "sqli"}:
                add("validate", "validator_validate_sqli",
                    {"target_url": url, "param": param or "id"}, f"val-{key_part}", cost=8)
            elif vuln_class in {"xss_reflected", "xss"}:
                add("validate", "validator_validate_xss_reflection",
                    {"target_url": url, "param": param or "q"}, f"val-{key_part}", cost=8)
        return created

    # 3) Fanout likely -> validator'a gonder.
    if tool == "hunter_auto_fanout_variants":
        for item in output.get("likely_hits") or []:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or item.get("endpoint") or "")
            param = str(item.get("param") or "")
            vclass = str(item.get("vuln_class") or output.get("finding_type") or "")
            if not url:
                continue
            key_part = _finding_fingerprint(vclass or "fanout", url, param)
            add("validate", "validator_validate_finding",
                {"vuln_type": vclass or "sqli", "target_url": url,
                 "params_json": json.dumps({"param": param} if param else {})},
                f"fanval-{key_part}", cost=8)
        return created

    # 4) Brainstorm / next_best_action -> worker gorevine bagla (otonom dongu).
    if tool == "reasoning_next_best_action" or task.get("kind") == "brainstorm":
        nba = output.get("next_best_action")
        if isinstance(nba, dict):
            rec_tool = nba.get("validate_with") or nba.get("recommended_tool") or output.get("recommended_tool")
            tgt = str(nba.get("target") or "")
            args = nba.get("args") if isinstance(nba.get("args"), dict) else ({"target": tgt} if tgt else {})
            if rec_tool:
                key_part = hashlib.sha256(f"{rec_tool}:{tgt}".encode()).hexdigest()[:12]
                add("probe", rec_tool, args, f"brainstorm-{key_part}", cost=4)
        return created

    return created


def run_loop(runtime: CampaignRuntime, worker: CampaignWorker, campaign_id: int,
             max_tasks: int = 60, max_seconds: int = 1800, idle_rounds: int = 3) -> dict:
    """Yardimsiz ana dongu: claim -> execute -> followup, bitene/kill'e kadar."""
    started = time.monotonic()
    done = failed = followups = 0
    idle = 0
    errors: list[str] = []
    while done + failed < max_tasks and (time.monotonic() - started) < max_seconds:
        campaign = runtime.show_campaign(campaign_id) or {}
        if campaign.get("status") != "active":
            errors.append(f"campaign not active: {campaign.get('status')}")
            break
        result = worker.run_once(campaign_id)
        if not result.get("claimed"):
            # Bekleyen is varsa (rate_limited geri sayimi dahil) bekle ve devam et;
            # hicbir sey kalmadiysa bitir. Ust sinir max_seconds ile korunur.
            tasks = runtime.list_tasks(campaign_id)
            waiting = [t for t in tasks if t["status"] in {"waiting_approval", "rate_limited", "pending", "running"}]
            if not waiting:
                break
            idle += 1
            if idle % 4 == 0:
                errors.append(f"idle wait: {len(waiting)} tasks pending/rate-limited")
            time.sleep(15)
            continue
        idle = 0
        if result.get("status") == "done":
            done += 1
            task_id = int(result["task_id"])
            tasks = {t["id"]: t for t in runtime.list_tasks(campaign_id)}
            task = tasks.get(task_id, {})
            output = _task_output(result.get("result") or {})
            try:
                created = followups_for_task(runtime, {"id": task_id, "campaign_id": campaign_id,
                                                       "tool_name": task.get("tool_name", "")}, output)
                followups += len(created)
            except (ValueError, TypeError, KeyError) as exc:
                errors.append(f"followup error task={task_id}: {exc}")
        else:
            failed += 1
            errors.append(f"task={result.get('task_id')} failed: {result.get('error')}")
    return {"done": done, "failed": failed, "followups": followups,
            "elapsed_s": round(time.monotonic() - started, 1), "errors": errors[:20]}


def collect_confirmed(runtime: CampaignRuntime, campaign_id: int) -> list[dict]:
    """Finding gate: done task'lardan CONFIRMED kanitlari topla + dedup."""
    seen: dict[str, dict] = {}
    for task in runtime.list_tasks(campaign_id, status="done"):
        tool = str(task.get("tool_name") or "")
        try:
            result = json.loads(task.get("result_json") or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        output = _task_output(result)
        candidates: list[dict] = []
        if tool.startswith("validator_validate_") and str(output.get("verdict") or "").upper() == "CONFIRMED":
            vclass = FANOUT_BY_VALIDATOR.get(tool, str(output.get("vuln_type") or tool))
            url = str(output.get("target") or output.get("target_url") or output.get("object_url")
                      or output.get("protected_url") or "")
            evidence = output.get("evidence") or {}
            param = str(evidence.get("param") or "")
            candidates.append({"vuln_class": vclass, "url": url, "param": param,
                               "source": tool, "task_id": task["id"], "output": output})
        elif tool == "hunter_run_web_loop":
            for item in output.get("confirmed") or []:
                if not isinstance(item, dict):
                    continue
                vclass = str(item.get("vuln_class") or "unknown")
                url = str(item.get("url") or item.get("target") or "")
                candidates.append({"vuln_class": vclass, "url": url,
                                   "param": str(item.get("param") or ""), "source": tool,
                                   "task_id": task["id"], "output": item})
        for cand in candidates:
            fp = _finding_fingerprint(cand["vuln_class"], cand["url"], cand["param"])
            if fp not in seen:
                # Ayni URL+sinif farkli param normalize ile gelmisse birlestir
                # (validator evidence param bos birakabilir, webloop doldurur).
                merged = False
                for existing in seen.values():
                    if (existing["vuln_class"] == cand["vuln_class"]
                            and existing["url"].split("?")[0] == cand["url"].split("?")[0]):
                        if not existing["param"] and cand["param"]:
                            existing["param"] = cand["param"]
                        merged = True
                        break
                if merged:
                    continue
                cand["fingerprint"] = fp
                cand["severity"] = SEVERITY_BY_CLASS.get(cand["vuln_class"], "medium")
                seen[fp] = cand
    return sorted(seen.values(), key=lambda c: (c["severity"], c["vuln_class"]))


def write_findings(cco_home: Path, campaign_id: int, confirmed: list[dict]) -> Path:
    out_dir = cco_home / "bounty" / f"campaign-{campaign_id}" / "findings"
    out_dir.mkdir(parents=True, exist_ok=True)
    for cand in confirmed:
        excerpt = _redact_excerpt(json.dumps(cand["output"], ensure_ascii=False))
        artifact = {
            "schema": "cco-finding/1",
            "fingerprint": cand["fingerprint"],
            "vuln_class": cand["vuln_class"],
            "severity": cand["severity"],
            "url": cand["url"],
            "param": cand["param"],
            "source": cand["source"],
            "task_id": cand["task_id"],
            "campaign_id": campaign_id,
            "verdict": "CONFIRMED",
            "evidence_excerpt": excerpt,
            "evidence_hash": hashlib.sha256(excerpt.encode()).hexdigest(),
            "created_at": _utc_now(),
        }
        (out_dir / f"{cand['fingerprint']}.json").write_text(
            json.dumps(artifact, indent=2, ensure_ascii=False))
    return out_dir


def build_report(runtime: CampaignRuntime, campaign_id: int, target: str,
                 loop_stats: dict, confirmed: list[dict]) -> str:
    campaign = runtime.show_campaign(campaign_id) or {}
    counts = campaign.get("task_counts", {})
    lines = [
        f"# Autonomous Bounty Report — campaign {campaign_id}",
        "",
        f"- Target: `{target}`",
        f"- Date: {_utc_now()}",
        f"- Tasks: done={loop_stats.get('done', 0)} failed={loop_stats.get('failed', 0)} "
        f"followups={loop_stats.get('followups', 0)} elapsed={loop_stats.get('elapsed_s', 0)}s",
        f"- Queue: {json.dumps(counts, ensure_ascii=False)}",
        f"- Budget: requests_used={campaign.get('requests_used', 0)}/{campaign.get('budget_requests', 0)}",
        "",
        f"## Confirmed findings ({len(confirmed)})",
        "",
    ]
    if not confirmed:
        lines.append("No CONFIRMED findings. All hypotheses stayed unconfirmed (good FP discipline).")
    for cand in confirmed:
        lines += [
            f"### {cand['vuln_class']} — {cand['severity']} — `{cand['url']}`",
            f"- fingerprint: `{cand['fingerprint']}` · source: `{cand['source']}` · task: {cand['task_id']}",
            f"- param: `{cand['param'] or '-'}`",
            "",
        ]
    if loop_stats.get("errors"):
        lines += ["## Loop notes", ""] + [f"- {e}" for e in loop_stats["errors"][:10]]
    lines += ["", "Yalnizca CONFIRMED bulgular listelenir; UNCONFIRMED/INCONCLUSIVE rapor disi birakilir."]
    return "\n".join(lines) + "\n"


def start_embedded_lab() -> tuple[str, object]:
    sys.path.insert(0, str(REPO_ROOT / "scripts" / "lab"))
    import vuln_lab  # noqa: E402

    server = vuln_lab.serve(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    return base, server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCO autonomous bug bounty loop (L3)")
    sub = parser.add_subparsers(dest="command", required=True)

    auto = sub.add_parser("auto", help="init + plan + run + report tek komutta")
    auto.add_argument("--target", default="")
    auto.add_argument("--embedded-lab", action="store_true")
    auto.add_argument("--scope-file", default="")
    auto.add_argument("--campaign-name", default="autonomous-bounty")
    auto.add_argument("--budget-requests", type=int, default=500)
    auto.add_argument("--budget-usd", type=float, default=5.0)
    auto.add_argument("--max-tasks", type=int, default=60)
    auto.add_argument("--max-seconds", type=int, default=1800)
    auto.add_argument("--mode", choices=["local-mcp", "dry-run"], default="local-mcp")
    auto.add_argument("--worker-id", default="bounty-worker-1")

    rep = sub.add_parser("report", help="Mevcut kampanyadan rapor uret")
    rep.add_argument("--campaign-id", type=int, required=True)
    rep.add_argument("--target", default="")

    args = parser.parse_args(argv)
    runtime = CampaignRuntime()
    cco_home = runtime.cco_home

    if args.command == "report":
        confirmed = collect_confirmed(runtime, args.campaign_id)
        out_dir = write_findings(cco_home, args.campaign_id, confirmed)
        report = build_report(runtime, args.campaign_id, args.target or "unknown",
                              {"done": 0, "failed": 0, "followups": 0, "elapsed_s": 0}, confirmed)
        report_path = cco_home / "bounty" / f"campaign-{args.campaign_id}" / "report.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report)
        print(json.dumps({"campaign_id": args.campaign_id, "confirmed": len(confirmed),
                          "findings_dir": str(out_dir), "report": str(report_path)},
                         indent=2, ensure_ascii=False))
        return 0

    # --- auto ---
    lab_server = None
    target = (args.target or "").strip()
    if args.embedded_lab or not target:
        target, lab_server = start_embedded_lab()
        print(f"[lab] embedded VulnLab -> {target}", flush=True)
    try:
        os.environ.setdefault("CCO_WORKER_ALLOWED_TOOLS", DEFAULT_ALLOWED_TOOLS)
        os.environ.setdefault("CCO_PROGRAM_POLICY_FILE", str(REPO_ROOT / "config" / "bounty-program-policy.json"))
        grant = ensure_grant(target)
        print(f"[grant] {json.dumps(grant, ensure_ascii=False)}", flush=True)

        campaign_id = runtime.create_campaign(
            args.campaign_name, scope_file=args.scope_file,
            budget_requests=args.budget_requests, budget_usd=args.budget_usd,
            notes=f"autonomous L3 target={target}")
        manifest = BountyManifest(campaign_id, target, args.scope_file,
                                  args.budget_requests, args.budget_usd)
        manifest_path = manifest.save(cco_home)
        print(f"[campaign] id={campaign_id} manifest={manifest_path}", flush=True)

        planned = plan_campaign(runtime, campaign_id, target)
        print(f"[plan] {len(planned)} tasks enqueued: {planned}", flush=True)

        if args.mode == "local-mcp":
            from executor_isolation import ResourceLimits
            limits = ResourceLimits.from_mapping(
                {"cpu_seconds": 300, "cpu_cores": 1.0, "memory_mb": 1024,
                 "pids": 128, "network": "inherit", "cgroup_mode": "best_effort"},
                backend="process")
            executor = LocalMCPExecutor(cco_home, timeout_seconds=300, limits=limits)
        else:
            executor = dry_run_executor
        worker = CampaignWorker(runtime, args.worker_id, executor,
                                claim_timeout_seconds=300, heartbeat_interval_seconds=30)
        stats = run_loop(runtime, worker, campaign_id,
                         max_tasks=args.max_tasks, max_seconds=args.max_seconds)
        print(f"[loop] {json.dumps(stats, ensure_ascii=False)}", flush=True)

        confirmed = collect_confirmed(runtime, campaign_id)
        out_dir = write_findings(cco_home, campaign_id, confirmed)
        report = build_report(runtime, campaign_id, target, stats, confirmed)
        report_path = cco_home / "bounty" / f"campaign-{campaign_id}" / "report.md"
        report_path.write_text(report)
        print(f"[report] confirmed={len(confirmed)} dir={out_dir} report={report_path}", flush=True)
        for cand in confirmed:
            print(f"  CONFIRMED {cand['severity']:8s} {cand['vuln_class']:16s} {cand['url']}", flush=True)
        return 0
    finally:
        if lab_server is not None:
            try:
                lab_server.shutdown()
            except (OSError, RuntimeError):
                pass


if __name__ == "__main__":
    raise SystemExit(main())
