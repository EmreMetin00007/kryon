#!/usr/bin/env python3
"""Kör recall ölçümü (WS1): operatör labı kurar, ajan alt süreci kör koşar,
değerlendirici koşu sonrası cevap anahtarıyla puanlar.

Ajan alt sürecine yalnız base URL + test hesabı başlıkları gider; truth,
seed ve işaretler operatör tarafında kalır. Bütçe: uygulama istek sayacı.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlparse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "lab"))
import blind_lab  # noqa: E402

EVALUATOR_VERSION = "blind-score/4"

_CLASS_ALIASES = {
    "sql injection": "sql_injection", "sql_injection": "sql_injection",
    "xss": "xss_reflected", "reflected xss": "xss_reflected",
    "xss_reflected": "xss_reflected", "ssti": "ssti",
    "server-side template injection": "ssti",
    "open redirect": "open_redirect", "open_redirect": "open_redirect",
    "path traversal": "path_traversal", "path_traversal": "path_traversal",
    "lfi": "path_traversal", "bola": "bola", "idor": "bola",
    "insecure direct object reference (idor)": "bola",
    "bfla": "bfla", "authentication_bypass": "authentication_bypass",
    "auth bypass": "authentication_bypass",
}


def _norm_class(item: dict) -> str:
    raw = str(item.get("vuln_class") or item.get("vuln_type")
              or item.get("type") or "").strip().lower()
    return _CLASS_ALIASES.get(raw, raw)


def _path_of(item: dict) -> str:
    url = str(item.get("url") or item.get("target") or "")
    return urlparse(url).path or url


def _origin(url: str) -> tuple | None:
    try:
        parsed = urlparse(str(url or ""))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        return (parsed.scheme, parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80))
    except ValueError:
        return None


def _rows(value) -> list[dict]:
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _matches_case(case: dict, item: dict, target: str, *, candidate: bool = False) -> bool:
    """Missing actor/owner is acceptable for a lead, never for a verdict."""
    if (_origin(item.get("url") or item.get("target")) != _origin(target)
            or _path_of(item) != case["path"]
            or _norm_class(item) != _norm_class({"type": case["class"]})
            or str(item.get("method") or ("GET" if candidate else "")).upper()
            != str(case.get("method") or "GET").upper()):
        return False
    dimensions = {"param": "param", "carrier": "carrier", "operation_id": "operation_id"}
    if not candidate:
        dimensions.update(actor="identity", owner="resource_owner")
    return all(case.get(expected) is None or item.get(actual) == case[expected]
               for expected, actual in dimensions.items())


def _confirmation_key(event: dict) -> tuple:
    """Count repeated observations of the same unmapped context only once."""
    return (_origin(event.get("url")), _path_of(event), _norm_class(event),
            *(str(event.get(key) or "") for key in
              ("method", "param", "carrier", "identity", "resource_owner", "operation_id")))


def _unmapped_details(truth: list[dict], events: list[dict], target: str) -> list[dict]:
    """Expose exact unmatched dimensions without relaxing case matching.

    Query values and response bodies are deliberately absent. Separate
    observations/validation IDs of one request context remain one entry.
    """
    groups = {}
    for event in events:
        if any(_matches_case(case, event, target) for case in truth):
            continue
        key = _confirmation_key(event)
        if key not in groups:
            related = []
            for case in truth:
                if case["path"] != _path_of(event) or _norm_class({"type": case["class"]}) != _norm_class(event):
                    continue
                mismatches = {}
                dimensions = {"actor": "identity", "owner": "resource_owner", "param": "param",
                              "carrier": "carrier", "operation_id": "operation_id"}
                for expected, actual in dimensions.items():
                    if case.get(expected) is not None and case[expected] != event.get(actual):
                        mismatches[expected] = {"expected": case[expected], "observed": event.get(actual)}
                method = str(case.get("method") or "GET").upper()
                if method != str(event.get("method") or "").upper():
                    mismatches["method"] = {"expected": method, "observed": event.get("method")}
                related.append({"case": case["case"], "expected": case["expected"], "mismatches": mismatches})
            groups[key] = {"path": _path_of(event), "class": _norm_class(event),
                           **{name: event.get(name) for name in
                              ("method", "param", "carrier", "identity", "resource_owner", "operation_id")},
                           "related_cases": related, "validation_ids": set()}
        groups[key]["validation_ids"].add(str(event["validation_id"]))
    return [{**row, "validation_ids": sorted(row["validation_ids"])}
            for _, row in sorted(groups.items(), key=lambda item: repr(item[0]))]


def _pipeline(case: dict, loop: dict, events: list[dict], inventory: dict | None) -> dict:
    """Diagnose progress from telemetry; only verified events establish results."""
    target = str(loop.get("target") or "")
    fuzz = loop.get("fuzz") if isinstance(loop.get("fuzz"), dict) else {}

    def leads(rows):
        matched = []
        for raw in _rows(rows):
            if raw.get("run_id") not in (None, "", loop.get("run_id")):
                continue
            row = {**raw, "carrier": raw.get("carrier") or raw.get("location")}
            if _matches_case(case, row, target, candidate=True):
                matched.append(row)
        return matched

    inventory_ok = (isinstance(inventory, dict) and bool(_origin(target)) and bool(loop.get("run_id"))
                    and loop.get("run_id") != "unspecified"
                    and inventory.get("run_id") == loop["run_id"]
                    and inventory.get("source") == "isolated_run_surface_snapshot")
    observed = []
    discovery_rows = [row for row in _rows(loop.get("discovery_operations"))
                      if row.get("run_id") == loop.get("run_id")]
    if inventory_ok:
        discovery_rows += _rows(inventory.get("records"))
    for row in discovery_rows:
        # Discovery identifies an operation, not a vulnerability or actor.
        if (_origin(row.get("url")) == _origin(target)
                and _path_of(row) == case["path"]
                and (case.get("operation_id") is None or row.get("operation_id") == case["operation_id"])
                and str(row.get("method") or "").upper() == str(case.get("method") or "GET").upper()):
            observed.append(row)
    candidates = leads(loop.get("validation_candidates")) + leads(fuzz.get("validator_queue")) + leads(fuzz.get("likely_hits"))
    queued = leads(loop.get("validation_queue"))
    attempted = [row for row in leads(loop.get("validations")) if _matches_case(case, row, target)]
    skipped = leads(loop.get("skipped"))
    probes = leads(fuzz.get("fanout"))
    matched = [event for event in events if _matches_case(case, event, target)]
    statuses = {event["status"] for event in matched}
    reasons = sorted({str(row["reason"])[:240] for row in skipped if row.get("reason")})
    complete = inventory_ok and inventory.get("complete") is True
    discovered = True if observed else False if complete else None
    context_mismatch = any(not _matches_case(case, event, target) for event in leads(events))
    if "confirmed" in statuses or (case["expected"] == "negative" and "tested_clean" in statuses):
        stage = None
    elif "inconclusive" in statuses:
        stage = "validation_inconclusive"
    elif "blocked" in statuses:
        stage = "validation_blocked"
    elif "tested_clean" in statuses:
        stage = "validation_not_confirmed"
    elif attempted:
        stage = "evidence_missing"
    elif context_mismatch:
        stage = "validation_context_mismatch"
    elif skipped:
        stage = "validation_budget" if reasons and all(reason == "max_validations" for reason in reasons) else "validation_prerequisite"
    elif queued or candidates:
        stage = "validation_selection"
    elif loop.get("ok") is False and (loop.get("stopped") or loop.get("skipped")):
        stage = "run_blocked"
        reasons = [str(loop.get("stopped") or row.get("reason") or "")[:240]
                   for row in _rows(loop.get("skipped")) if row.get("step") == "remaining"]
        if loop.get("stopped"):
            reasons = [str(loop["stopped"])[:240]]
    elif probes:
        stage = ("probe_blocked" if any(row.get("coverage_status") == "blocked" for row in probes)
                 else "probe_not_executed" if not any(row.get("live") for row in probes)
                 else "probe_no_candidate")
        reasons = sorted({str(row["reason"])[:240] for row in probes if row.get("reason")})
    elif discovered:
        stage = "candidate_generation"
    elif complete and "discover" in (loop.get("steps") or []):
        stage = "discovery_missing"
    else:
        stage = "discovery_unknown"
    return {"loss_stage": stage, "pipeline": {
        "surface_observed": discovered,
        "candidate_generated": bool(candidates or queued or attempted or matched),
        "validation_queued": bool(queued or attempted or matched),
        "validation_invoked": bool(attempted), "validation_verified": bool(matched),
        "reasons": reasons,
    }}


def evaluate(truth: list[dict], loop: dict, *, verified_coverage: list[dict] | None = None,
             surface_inventory: dict | None = None) -> dict:
    """Score current-run events verified by Hunter against signed artifacts.

    The lab runner obtains these via `_verified_coverage_events` in the same
    isolated policy/session environment as execution. Bare loop verdicts or
    `coverage_recorded` booleans cannot establish tested/confirmed results.
    This is the pure scoring layer, not an alternative artifact verifier.
    """
    target = str(loop.get("target") or "")
    run_id = str(loop.get("run_id") or "")
    events = [event for event in _rows(verified_coverage)
              if _origin(target) and run_id and run_id != "unspecified"
              and event.get("schema") == "hunter-coverage/1"
              and event.get("run_id") == run_id and event.get("validation_id")
              and _origin(event.get("url")) == _origin(target)
              and event.get("status") in {"confirmed", "tested_clean", "inconclusive", "blocked"}]
    confirmed = [event for event in events if event["status"] == "confirmed"]
    fuzz = loop.get("fuzz") if isinstance(loop.get("fuzz"), dict) else {}
    likely = _rows(fuzz.get("likely_hits"))
    cases = []
    for case in truth:
        matched = [event for event in events if _matches_case(case, event, target)]
        statuses = {event["status"] for event in matched}
        hit_c = "confirmed" in statuses
        hit_l = any(_matches_case(case, item, target, candidate=True) for item in likely)
        if case["expected"] == "positive":
            blocked = loop.get("ok") is False and bool(
                loop.get("stopped") or loop.get("skipped"))
            status = ("proven" if hit_c else "candidate" if hit_l
                      else "inconclusive" if "inconclusive" in statuses
                      else "blocked" if blocked or "blocked" in statuses else "missed")
        else:
            status = ("false_positive" if hit_c
                      else "inconclusive" if "inconclusive" in statuses
                      else "blocked" if "blocked" in statuses
                      else "clean" if "tested_clean" in statuses else "not_tested")
        cases.append({**case, "result": status,
                      "validation_ids": sorted({str(event["validation_id"]) for event in matched}),
                      **_pipeline(case, loop, events, surface_inventory)})
    unmapped = _unmapped_details(truth, confirmed, target)
    pos = [c for c in cases if c["expected"] == "positive"]
    neg = [c for c in cases if c["expected"] == "negative"]
    evaluated_neg = [c for c in neg if c["result"] in {"clean", "false_positive"}]
    proven = sum(c["result"] == "proven" for c in pos)
    false_positives = sum(c["result"] == "false_positive" for c in neg)
    loss_stages = {}
    for case in pos:
        if case["loss_stage"]:
            loss_stages[case["loss_stage"]] = loss_stages.get(case["loss_stage"], 0) + 1
    return {
        "evaluator_version": EVALUATOR_VERSION,
        "run_id": run_id,
        "coverage_evidence": "missing" if verified_coverage is None else "verified_hunter_events",
        "cases": cases,
        "proven": proven,
        "candidate_only": sum(1 for c in pos if c["result"] == "candidate"),
        "missed": sum(1 for c in pos if c["result"] == "missed"),
        "blocked": sum(1 for c in pos if c["result"] == "blocked"),
        "inconclusive": sum(c["result"] == "inconclusive" for c in pos),
        "positives": len(pos),
        "recall": proven / len(pos) if pos else None,
        "false_positives": false_positives,
        "negatives_total": len(neg),
        "negatives_evaluated": len(evaluated_neg),
        "negatives_clean": sum(c["result"] == "clean" for c in neg),
        "negatives_not_tested": sum(c["result"] == "not_tested" for c in neg),
        "negatives_inconclusive": sum(c["result"] == "inconclusive" for c in neg),
        "negatives_blocked": sum(c["result"] == "blocked" for c in neg),
        "negative_coverage": len(evaluated_neg) / len(neg) if neg else None,
        "fp_rate": false_positives / len(evaluated_neg) if evaluated_neg else None,
        "unmapped_confirmed": len(unmapped),
        "unmapped_confirmations": unmapped,
        "positive_loss_stages": loss_stages,
        "loop_ok": loop.get("ok"),
        "loop_stopped": loop.get("stopped") or "",
        "requests_authorized": loop.get("requests_authorized"),
    }


def _isolated_env(home: str, *, differential: bool = False) -> dict:
    env = dict(os.environ)
    env["CCO_HOME"] = home
    env["CCO_GRAPH_BACKEND"] = "networkx"
    scope_p = os.path.join(home, "lab-scope.json")
    policy_p = os.path.join(home, "lab-policy.json")
    with open(scope_p, "w", encoding="utf-8") as fh:
        json.dump({"allow_loopback": True, "allow_public_labs": True,
                   "rules": {}}, fh)
    try:
        with open(os.path.join(REPO, "config", "program-profiles",
                               "lab.json"), encoding="utf-8") as fh:
            policy = json.load(fh)
    except (OSError, ValueError):
        policy = {}
    policy["rate_limits"] = {
        "default": {"window_seconds": 60, "max_calls": 600},
        "conservative": {"window_seconds": 60, "max_calls": 600}}
    if differential:
        policy["blind_discovery"] = {"synthetic_accounts_only": True,
                                     "differential_ownership": True}
    with open(policy_p, "w", encoding="utf-8") as fh:
        json.dump(policy, fh)
    env["CCO_SCOPE_FILE"] = scope_p
    env["CCO_PROGRAM_POLICY_FILE"] = policy_p
    env["CCO_STUCK_THRESHOLD"] = "10000"
    for key in ("OPENROUTER_API_KEY", "ANTHROPIC_AUTH_TOKEN", "DEEPSEEK_API_KEY"):
        env.pop(key, None)
    return env


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--report", default="")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--differential", action="store_true",
                    help="WS4 küme farkı keşfiyle ölç (opt-in)")
    args = ap.parse_args()
    seed = args.seed if args.seed is not None else secrets.randbelow(10**9)
    server = blind_lab.serve(seed, 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    state = server.blind_state
    try:
        identities = {label: {"headers": {
            "Authorization": f"Bearer {acct['token']}"}}
            for label, acct in state["accounts"].items()}
        home = tempfile.mkdtemp(prefix="cco_blind_")
        out_path = os.path.join(home, "agent-out.json")
        command = [sys.executable, os.path.join(REPO, "scripts", "lab",
                                                "blind_agent_run.py"),
                   "--base", base, "--identities", json.dumps(identities),
                   "--out", out_path]
        if args.differential:
            command.append("--blind-differential")
        proc = subprocess.run(
            command,
            env=_isolated_env(home, differential=args.differential),
            capture_output=True, text=True, timeout=args.timeout)
        if proc.returncode != 0 or not os.path.exists(out_path):
            report = {"seed": seed, "status": "invalid",
                      "error": (proc.stderr or proc.stdout)[-500:]}
            print(json.dumps(report, ensure_ascii=False))
            return 2
        with open(out_path, encoding="utf-8") as fh:
            agent_output = json.load(fh)
        loop = agent_output["loop"]
        score = evaluate(state["truth"], loop,
                         verified_coverage=agent_output.get("verified_coverage"),
                         surface_inventory=agent_output.get("surface_inventory"))
        report = {"seed": seed, "status": "measured", "base": base,
                  "solver": "deterministic+differential" if args.differential else "deterministic",
                  "app_requests": state["requests"], "agent_artifact": out_path, **score}
        if args.report:
            with open(args.report, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=1, ensure_ascii=False)
        print(json.dumps(report, indent=1, ensure_ascii=False))
        return 0
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
