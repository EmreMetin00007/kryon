#!/usr/bin/env python3
"""Audit saved acceptance losses using public signatures and local lab models.

No network requests, browser sessions, credentials or signing keys are used.
The original 8-positive/8-negative score and supplemental account matrix are
kept separate. A supplemental case never repairs a primary case's recall.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from urllib.parse import urlencode, urlsplit
import hashlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp-servers/mcp-validator"))
from cco_validator_core import evidence  # noqa: E402
import evidence_trust as trust  # noqa: E402
from http_chromium_acceptance import assess_results  # noqa: E402
from lab.blind_lab import make_lab  # noqa: E402

spec = importlib.util.spec_from_file_location("loss_analysis_score", ROOT / "scripts/blind-validate.py")
scorer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scorer)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@contextmanager
def public_home(home):
    previous = os.environ.get("CCO_HOME")
    os.environ["CCO_HOME"] = str(home)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("CCO_HOME", None)
        else:
            os.environ["CCO_HOME"] = previous


def read_db(path, query):
    with sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True) as db:
        return db.execute(query).fetchall()


def verify_events(directory, base, run_id):
    """Reject incomplete evidence instead of scoring raw verdicts as proof."""
    home = directory / "home"
    paths = {"scope": directory / "scope.json", "policy": directory / "policy.json",
             "public_trust": home / "public-trust/verification.json",
             "coverage_db": home / "agent_memory.db"}
    scope_hash, policy_hash = "sha256:" + sha256(paths["scope"]), "sha256:" + sha256(paths["policy"])
    scope = json.loads(paths["scope"].read_text())
    if not any(row.get("asset") == base for row in scope.get("in_scope", [])):
        raise ValueError("saved scope does not contain the exact acceptance origin")
    events, records = [], {}
    with public_home(home):
        for (raw,) in read_db(paths["coverage_db"], "SELECT signed_json FROM hunter_coverage_events ORDER BY id"):
            signed = json.loads(raw)
            event = signed["payload"]
            if event.get("schema") != "hunter-coverage/1" or event.get("run_id") != run_id:
                continue
            if not trust.verify(trust.canonical_bytes(event), signed, "coverage-attempt"):
                raise ValueError("invalid coverage signature")
            path = Path(event["artifact_path"]).resolve(strict=True)
            if path.parent != (home / "validations").resolve() or path.suffix != ".json":
                raise ValueError("validation path is outside this seed's evidence directory")
            record = json.loads(path.read_text())
            # Do not let a legacy HMAC verifier read a private signing key.
            if (record.get("artifact", {}).get("signature", {}).get("algorithm") != trust.ALGORITHM
                    or not evidence.artifact_is_valid(record, trusted_root=str(home / "validations"),
                        expected_path=str(path), expected_target=base,
                        expected_scope_revision=scope_hash, expected_policy_hash=policy_hash)):
                raise ValueError("invalid or differently scoped validator artifact")
            context = {key: event[key] for key in ("url", "vuln_class", "method", "param", "carrier", "identity",
                       "resource_owner", "run_id", "operation_id", "observation_id", "access_rule_hash") if key in event}
            kind = evidence.normalize_finding_type(event["vuln_class"])
            actual = record["binding"]["finding_type"]
            if (record.get("execution_context") != context
                    or record.get("validation_id") != event["validation_id"]
                    or record["artifact"]["content_sha256"] != event["artifact_sha256"]
                    or evidence.redact_url(record["target"]) != event["url"]
                    or (kind != actual and {kind, actual} != {"bola", "idor"})):
                raise ValueError("coverage/validator request dimensions do not match")
            expected = {"CONFIRMED": "confirmed", "UNCONFIRMED": "tested_clean",
                        "INCONCLUSIVE": "inconclusive"}.get(record["verdict"])
            if event["status"] != expected and not (event["status"] == "blocked" and expected == "inconclusive"):
                raise ValueError("coverage status does not match the validator verdict")
            if event["status"] in {"confirmed", "tested_clean"}:
                if (not record.get("guard", {}).get("transport_ok") or not any(
                        row.get("transport_ok") and row.get("method") == event["method"]
                        and scorer._origin(row.get("request_url")) == scorer._origin(base)
                        and urlsplit(row.get("request_url", "")).path == urlsplit(event["url"]).path
                        for row in record.get("request_evidence", []))):
                    raise ValueError("completed verdict lacks successful request evidence")
            events.append(event)
            records[event["validation_id"]] = record
            paths["validation:" + event["validation_id"]] = path
    return events, records, paths


def supplemental_access_truth(state):
    """Operator-side matrix from the lab and declared private-object contract.

    All non-owners, including the admin test account, are denied by the
    owned_objects_private declaration. Both member accounts are denied the
    admin functions. These expectations must never enter solver inputs.
    """
    primary = {(row["class"], row["path"], row.get("owner"), row.get("actor")) for row in state["truth"]}
    rows = []
    for oid, order in state["orders"].items():
        for actor in state["accounts"]:
            if actor == order["owner"]:
                continue
            rows.append({"case": f"extra-bola-{oid}-{actor}", "class": "bola", "path": "/orders/" + oid,
                         "owner": order["owner"], "actor": actor,
                         "expected": "positive" if order["vuln"] else "negative"})
    for path, vulnerable in (("/admin/export", True), ("/admin/users", False)):
        for actor, account in state["accounts"].items():
            if account["role"] == "member":
                rows.append({"case": f"extra-bfla-{path.rsplit('/', 1)[1]}-{actor}", "class": "bfla",
                             "path": path, "owner": "admin-a", "actor": actor,
                             "expected": "positive" if vulnerable else "negative"})
    return [row for row in rows if (row["class"], row["path"], row["owner"], row["actor"]) not in primary]


def traversal_model(handler, rule, base):
    """Reproduce boundary controls on the handler, independently of wire runs."""
    from cco_validator_core.traversal import application_files
    files = application_files(rule, base + "file?name=notes.txt", "name", "query", lambda url: url.startswith(base))
    file = files[0]
    rows = []
    for role, value in (("baseline", "notes.txt"), ("direct-name", file["path"].rsplit("/", 1)[1]),
                        ("missing-file", "../cco-missing-local-model.txt"), ("traversal-probe", file["path"]),
                        ("traversal-repeat", file["path"])):
        instance = handler.__new__(handler)
        instance.path, instance.headers = "/file?" + urlencode({"name": value}), {}
        replies = []
        instance._send = lambda code, body, *_args, **_kwargs: replies.append((code, body))
        instance.do_GET()
        code, body = replies[0]
        rows.append({"role": role, "status": code, "marker_present": file["marker"] in body})
    return {"mode": "local_handler_model", "counts_toward_acceptance": False, "controls": rows,
            "boundary_established": rows[0]["status"] in {200, 206}
                and all(not row["marker_present"] for row in rows[:3])
                and all(row["marker_present"] and row["status"] in {200, 206} for row in rows[3:])}


def analyze_seed(directory):
    row = json.loads((directory / "automatic-campaign-controls.json").read_text())
    wire = json.loads((directory / "received-wire.json").read_text())
    base, run_id = wire["base"], row["score"]["run_id"]
    sources = list((directory / "home/artifacts/surface").glob("webloop-*.json"))
    source = [path for path in sources if json.loads(path.read_text()).get("run_id") == run_id]
    if len(source) != 1:
        raise ValueError("exactly one saved discovery report required")
    loop = json.loads(source[0].read_text())
    tasks = [{"id": task_id, "status": status, "result": json.loads(raw)} for task_id, status, raw in
             read_db(directory / "home/campaigns.db", "SELECT id,status,result_json FROM tasks ORDER BY id")]
    reports = [json.loads(task["result"]["output"]) for task in tasks if "output" in task["result"]]
    if not reports or any(report.get("run_id") != run_id for report in reports):
        raise ValueError("campaign report belongs to a different run")
    merged = {**loop, "validations": [v for r in reports for v in r.get("validations", [])],
              "confirmed": [v for r in reports for v in r.get("confirmed", [])]}
    events, records, paths = verify_events(directory, base, run_id)
    # Blocked tasks retain a compact result instead of the raw loop output.
    # Signed request artifacts still establish their validation attempts.
    attempted_ids = {item.get("validation_id") for item in merged["validations"]}
    merged["validations"] += [event for event in events if event["validation_id"] not in attempted_ids]
    handler, state = make_lab(row["seed"], version=row["lab_version"])
    try:
        primary = scorer.evaluate(state["truth"], merged, verified_coverage=events)
        for key in ("proven", "negatives_clean", "false_positives", "unmapped_confirmed", "positive_loss_stages"):
            if primary[key] != row["score"][key]:
                raise ValueError("replayed primary score differs from saved acceptance")
        supplemental = supplemental_access_truth(state)
        extra_events = [event for event in events if any(
            scorer._matches_case(case, event, base) for case in supplemental)]
        extra_score = scorer.evaluate(supplemental, merged, verified_coverage=extra_events)
        combined = scorer.evaluate(state["truth"] + supplemental, merged, verified_coverage=events)
        audited = []
        for item in primary["unmapped_confirmations"]:
            matched = [case for case in supplemental if scorer._matches_case(case, {
                "url": base.rstrip("/") + item["path"], "vuln_class": item["class"], **item}, base)]
            audited.append({**item, "supplemental_cases": [case["case"] for case in matched],
                            "assessment": "expected_additional_violation" if matched and all(
                                case["expected"] == "positive" for case in matched) else "unresolved_or_false_positive"})
        policy = json.loads((directory / "policy.json").read_text())
        if policy.get("blind_discovery", {}).get("owned_objects_private") is not True:
            raise ValueError("supplemental private-object expectation was not declared")
        model = traversal_model(handler, policy["path_traversal"], base)
        losses = []
        for case in primary["cases"]:
            if case["case"] not in {"xss-search", "traversal-file"}:
                continue
            losses.append({"case": case["case"], "loss_stage": case["loss_stage"],
                "validation_ids": case["validation_ids"],
                "validator_evidence": [{"validation_id": vid, "verdict": records[vid]["verdict"],
                    "oracle": records[vid]["oracle"], "evidence": records[vid]["evidence"],
                    "notes": records[vid]["notes"]} for vid in case["validation_ids"]]})
        fuzz_paths = list((directory / "home/artifacts/surface").glob("fuzz-*.json"))
        if len(fuzz_paths) != 1:
            raise ValueError("exactly one raw fuzz report required")
        fuzz = json.loads(fuzz_paths[0].read_text())
        probes = [{key: probe.get(key) for key in ("payload", "status", "baseline_eligible", "triage_verdict")}
                  for probe in fuzz["fanout"] if probe.get("vuln_class") == "path_traversal"
                  and urlsplit(probe.get("baseline_url", "")).path == "/file"]
        paths.update(source_report=source[0], raw_fuzz=fuzz_paths[0], campaign_db=directory / "home/campaigns.db",
                     saved_score=directory / "automatic-campaign-controls.json", wire=directory / "received-wire.json")
        return {"seed": row["seed"], "mode": row["mode"], "requests": row["requests"],
                "verified_events": len(events), "primary_score": primary, "losses": losses,
                "blocked_tasks": [{"id": task["id"], "reason": task["result"].get("reason"),
                                   "coverage_gap": task["result"].get("coverage_gap")}
                                  for task in tasks if task["status"] == "blocked"],
                "traversal_probes": probes, "traversal_model": model, "unmapped_audit": audited,
                "supplemental_score": extra_score, "remaining_unmapped": combined["unmapped_confirmed"],
                "evidence_sha256": {key: {"path": str(path), "sha256": sha256(path)} for key, path in paths.items()}}
    finally:
        state["db"].close()


def analyze_run(directory):
    directory = Path(directory).resolve(strict=True)
    manifest = json.loads((directory / "acceptance.json").read_text())
    assessed = assess_results(directory / "junit.xml", directory / "tests")
    if manifest.get("status") != "passed" or any(manifest[key] != assessed[key] for key in ("tests", "runs")):
        raise ValueError("saved acceptance manifest does not match its measurements")
    paths = {path.resolve() for path in (directory / "tests").glob("test_real_chromium_surface_to_*/automatic-campaign-controls.json")}
    runs = sorted((analyze_seed(path.parent) for path in paths), key=lambda row: row["seed"])
    return {"schema": "http-chromium-loss-analysis/1", "mode": "saved_artifact_audit",
            "new_wire_requests": 0, "source_acceptance": str(directory / "acceptance.json"),
            "code_sha256": {str(path.relative_to(ROOT)): sha256(path) for path in
                            (ROOT / "scripts/lab/blind_lab.py", ROOT / "scripts/blind-validate.py", Path(__file__))},
            "source_sha256": sha256(directory / "acceptance.json"), "runs": runs}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/cco-work/http-chromium-loss-analysis"))
    args = parser.parse_args(argv)
    output = args.output_dir.expanduser().resolve()
    source = args.run_directory.expanduser().resolve()
    if output == ROOT or ROOT in output.parents or output == source or source in output.parents:
        parser.error("analysis output must be outside the repository and original evidence")
    result = analyze_run(source)
    output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="analysis-", dir=output))
    path = directory / "analysis.json"
    path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"artifact": str(path), "seeds": len(result["runs"]), "new_wire_requests": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
