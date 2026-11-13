#!/usr/bin/env python3
"""Operator-facing CCO dashboard and health checks."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from runtime_paths import runtime_root
REPO_ROOT = runtime_root()

from campaign_runtime import CampaignRuntime
from governance_audit import run_audit
from policy_engine import PolicyEngine


def _cco_home() -> Path:
    return Path(os.environ.get("CCO_HOME", REPO_ROOT / ".cco")).expanduser()


def _load_evidence_module():
    import importlib.util

    path = REPO_ROOT / "mcp-servers" / "mcp-validator" / "cco_validator_core" / "evidence.py"
    spec = importlib.util.spec_from_file_location("cco_operator_evidence", path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _artifact_summary(cco_home: Path) -> dict:
    validations = cco_home / "validations"
    summary = {
        "root": str(validations),
        "total_json": 0,
        "valid": 0,
        "invalid": 0,
        "reportable": 0,
        "invalid_samples": [],
    }
    if not validations.exists():
        return summary
    evidence = _load_evidence_module()
    for path in sorted(validations.rglob("*.json")):
        summary["total_json"] += 1
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            valid = False
            record = {}
        else:
            valid = bool(evidence and evidence.artifact_is_valid(record, expected_path=str(path)))
        if valid:
            summary["valid"] += 1
            if (record.get("verdict") == "CONFIRMED" and bool(record.get("reportable"))
                    and evidence.artifact_is_current(record, expected_path=str(path))):
                summary["reportable"] += 1
        else:
            summary["invalid"] += 1
            if len(summary["invalid_samples"]) < 5:
                summary["invalid_samples"].append(str(path))
    return summary


def build_dashboard(campaign_id: int | None = None, audit_limit: int = 20) -> dict:
    cco_home = _cco_home()
    runtime = CampaignRuntime(str(cco_home))
    policy = PolicyEngine(cco_home=str(cco_home), repo_root=str(REPO_ROOT))
    campaigns = [runtime.show_campaign(campaign_id)] if campaign_id else runtime.list_campaigns(limit=10, include_terminal=True)
    campaigns = [item for item in campaigns if item]
    active_campaign = campaigns[0] if campaigns else None
    tasks = runtime.list_tasks(active_campaign["id"]) if active_campaign else []
    governance = run_audit(REPO_ROOT, include_runtime=False, max_file_bytes=256_000)
    return {
        "cco_home": str(cco_home),
        "scope_file": str(policy.scope_file) if policy.scope_file else "",
        "scope": {
            "targets": sorted(policy.scope["targets"]),
            "domains": sorted(policy.scope["domains"]),
            "cidr_ranges": sorted(policy.scope["cidr_ranges"]),
            "url_prefixes": sorted(policy.scope["url_prefixes"]),
            "explicit_only": bool(policy.scope["explicit_only"]),
        },
        "active_approvals": policy.list_approvals(active_only=True),
        "recent_audit": policy.audit(limit=audit_limit),
        "campaigns": campaigns,
        "tasks": tasks,
        "artifact_summary": _artifact_summary(cco_home),
        "governance_summary": governance["summary"],
    }


def build_doctor() -> dict:
    dashboard = build_dashboard(audit_limit=5)
    warnings = []
    scope = dashboard["scope"]
    if not dashboard["scope_file"]:
        warnings.append("scope file missing; active tools will fail closed")
    if not any(scope[key] for key in ("targets", "domains", "cidr_ranges", "url_prefixes")):
        warnings.append("scope contains no explicit assets")
    if dashboard["artifact_summary"]["invalid"]:
        warnings.append("invalid validation artifacts present")
    if dashboard["governance_summary"]["high"]:
        warnings.append("high severity secret/PII governance findings present")
    return {"ok": not warnings, "warnings": warnings, **dashboard}


def _print_markdown(data: dict) -> None:
    print("# CCO Operator Dashboard")
    print(f"\nCCO_HOME: `{data['cco_home']}`")
    print(f"Scope file: `{data['scope_file'] or 'missing'}`")
    print(f"Active approvals: **{len(data['active_approvals'])}**")
    artifacts = data["artifact_summary"]
    print(f"Artifacts: **{artifacts['valid']} valid**, **{artifacts['invalid']} invalid**, **{artifacts['reportable']} reportable**")
    governance = data["governance_summary"]
    print(f"Governance findings: high={governance['high']} medium={governance['medium']} low={governance['low']}")
    print("\n## Campaigns")
    if not data["campaigns"]:
        print("No campaigns.")
    for campaign in data["campaigns"]:
        print(f"- #{campaign['id']} `{campaign['name']}` status={campaign['status']} tasks={campaign.get('task_counts', {})}")
    print("\n## Current Tasks")
    if not data["tasks"]:
        print("No tasks for selected campaign.")
    for task in data["tasks"][:20]:
        print(f"- task #{task['id']} {task['kind']} {task['tool_name'] or '-'} status={task['status']} attempts={task['attempts']}/{task['max_attempts']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCO operator UX")
    sub = parser.add_subparsers(dest="command", required=True)

    dashboard = sub.add_parser("dashboard")
    dashboard.add_argument("--campaign-id", type=int)
    dashboard.add_argument("--json", action="store_true")

    doctor = sub.add_parser("doctor")
    doctor.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "dashboard":
        data = build_dashboard(args.campaign_id)
        if args.json:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        else:
            _print_markdown(data)
        return 0
    if args.command == "doctor":
        data = build_doctor()
        if args.json:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        else:
            _print_markdown(data)
            if data["warnings"]:
                print("\n## Warnings")
                for warning in data["warnings"]:
                    print(f"- {warning}")
        return 0 if data["ok"] else 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
