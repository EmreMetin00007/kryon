"""Pure host candidate contracts. Observations and queue completion are not proof."""
from __future__ import annotations

import hashlib
import json
import copy
from typing import Any
from urllib.parse import parse_qsl, urlsplit

PROFILES = {
    "readonly_sqli_boolean": ("injection-sqli", "validator_validate_sqli", "differential_boolean"),
    "readonly_ssti_arithmetic": ("injection-ssti", "validator_validate_ssti", "arithmetic_eval"),
}
STAGES = ("observed", "eligible", "admitted", "executed", "evidence_accepted")
CARD_LIMIT = 8
CARD_BYTES = 2000


def upstream_ids(spec: Any, specs: list[Any]) -> list[str]:
    """Only the declared dependency DAG, never a phase name or latest result."""
    registry = {item.id: item for item in specs}
    visited: set[str] = set()
    result = []

    def visit(ident: str) -> None:
        if ident in visited:
            return
        visited.add(ident)
        source = registry[ident]
        for dep in source.depends_on:
            visit(dep)
        if source.target == spec.target:
            result.append(ident)

    for dep in spec.depends_on:
        visit(dep)
    return result


def gap(reason: str, *, category: str = "prerequisites", task: str = "",
        candidate: str = "", provenance: Any = None) -> dict[str, Any]:
    return {"schema": "python-coverage-gap/1", "status": "NOT TESTED",
            "category": category, "reason_code": reason, "task_spec_id": task,
            "candidate_id": candidate, "provenance": provenance or []}


def dedup_gaps(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [json.loads(raw) for raw in dict.fromkeys(
        json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows)]


def parser_gaps(value: dict[str, Any], task: str, ref: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize singular/plural gaps in known result envelopes, never verdicts."""
    output = []
    for envelope in (value, value.get("surface")):
        if not isinstance(envelope, dict):
            continue
        for key in ("coverage_gap", "coverage_gaps"):
            details = envelope.get(key, [])
            for detail in details if isinstance(details, list) else [details]:
                if not detail:
                    continue
                reason = detail.get("reason_code") if isinstance(detail, dict) else None
                # Only stable codes enter semantic cards; arbitrary source text
                # remains in the exact archive, not the host's reason contract.
                if not isinstance(reason, str) or not reason.replace("_", "").isalnum() or len(reason) > 96:
                    reason = "parser_coverage_incomplete"
                output.append(gap(reason, category="parser", task=task, provenance=[ref]))
    return dedup_gaps(output)


def matches_model_call(row: dict[str, Any], tool: str, args: dict[str, Any]) -> bool:
    """A model can select a host slice, not widen it or supply raw identity data."""
    if row["tool"] != tool or not row["eligible"] or row["executed"] or row["evidence_accepted"]:
        return False
    expected = row["arguments"]
    required = {"target", "validation_profile"} if tool == "hunter_run_web_loop" else {"target_url", "param"}
    if row["vector"] == "access-idor":
        required = {"target", "session_bindings"}
    elif expected.get("session_bindings"):
        required.add("session_bindings")
    if tool == "validator_validate_sqli":
        required.add("boolean_only")
    if not required <= args.keys():
        return False
    for key, value in args.items():
        if key == "session_bindings":
            try:
                if json.loads(value) != json.loads(expected.get(key, "{}")):
                    return False
            except (ValueError, TypeError):
                return False
        elif value != expected.get(key, {"headers_json": "{}", "body_template": ""}.get(key)):
            return False
    return True


def candidate(task: str, *, route: str, param: str = "", identity: Any = "anon",
              vector: str = "", tool: str = "", arguments: Any = None,
              provenance: Any = None, reason: str = "") -> dict[str, Any]:
    # Provenance is merged on the semantic key: repeated pages/sources do not
    # inflate the funnel. Task identity is part of the key, so branches cannot
    # spend each other's reservations or reuse each other's coverage.
    key = [task, "GET", route, param, identity, vector]
    ident = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()
    return {"candidate_id": ident, "task_spec_id": task, "method": "GET",
            "route": route, "param": param, "identity_ref": identity,
            "vector": vector, "tool": tool, "arguments": arguments or {},
            "provenance": provenance or [], "observed": True, "eligible": not reason,
            "admitted": False, "executed": False, "evidence_accepted": False,
            "validation_state": "NOT TESTED", "reason_code": reason,
            "evidence_refs": []}


def parameter_candidates(spec: Any, records: list[dict[str, Any]],
                         bindings: dict[str, Any]) -> list[dict[str, Any]]:
    """Select read-only oracle capabilities from records, not names or truth."""
    output = []
    binding_reason = ""
    if bindings and (len(bindings) > 8 or any(
            item.get("target") != spec.target or item.get("test_data_only") is not True
            or item.get("owned_objects_private") is not True for item in bindings.values())):
        binding_reason = "missing_synthetic_owned_session_prerequisite"
    for record in records:
        url = record["url"]
        provenance = [{key: record[key] for key in
                       ("source_spec_id", "source_artifact", "source_sha256")}]
        params = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        if record.get("method", "GET") != "GET":
            output.append(candidate(spec.id, route=url, provenance=provenance,
                                    reason="unsupported_readonly_method"))
            continue
        declared = {item["name"]: item.get("in", "query") for item in record.get("params", [])}
        for param in dict.fromkeys([*params, *declared]):
            for profile, (vector, direct, _) in PROFILES.items():
                if spec.vector not in ("", "access", vector):
                    continue
                # Direct validators have no session-ref argument. Authenticated
                # records use Hunter's existing vault-only profile rather than
                # projecting credentials or silently testing anonymously.
                tool = "hunter_run_web_loop" if bindings or direct not in spec.tools else direct
                args: dict[str, Any]
                if tool == direct:
                    args = {"target_url": url, "param": param, "method": "GET", "carrier": "query"}
                    if profile == "readonly_sqli_boolean":
                        args["boolean_only"] = True
                else:
                    args = {"target": url, "live": True, "crawl": False,
                            "validation_profile": profile, "fuzz_limit": 4,
                            "max_validations": 16, "candidate_sample_limit": 16, "sleep_s": 0.2}
                    if bindings:
                        # The host's member-first ordering selects Hunter's
                        # primary discovery session; sorting labels would undo it.
                        args["session_bindings"] = json.dumps(bindings)
                output.append(candidate(spec.id, route=url, param=param,
                    identity=sorted(bindings) if bindings else "anon", vector=vector,
                    tool=tool, arguments=args, provenance=provenance,
                    reason=binding_reason or ("unsupported_parameter_carrier" if declared.get(param, "query") != "query"
                        else "missing_observed_query_sample" if param not in params
                        else "validator_not_declared" if tool not in spec.tools else "")))
    return output


def compact_cards(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda row: (row["evidence_accepted"], not row["eligible"],
                                           row["vector"] != "access-idor", row["candidate_id"])):
        card = {key: row[key] for key in ("candidate_id", "method", "route", "param", "identity_ref",
            "vector", "tool", "provenance", "validation_state", "reason_code")}
        # Complete provenance remains in the discovery archive and candidate
        # state. A card needs one exact pointer, not every repeated source.
        card["provenance"] = row["provenance"][:1]
        if len(json.dumps([*cards, card]).encode()) > CARD_BYTES or len(cards) == CARD_LIMIT:
            break
        cards.append(card)
    return cards


def compact_gaps(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bound semantic gaps too; exact rows/provenance stay in host archives."""
    cards: list[dict[str, Any]] = []
    for row in rows:
        card: dict[str, Any] = {key: row[key] for key in ("status", "category", "reason_code", "candidate_id") if key in row}
        card["provenance"] = copy.deepcopy(row.get("provenance", [])[:1])
        if len(json.dumps([*cards, card]).encode()) > CARD_BYTES or len(cards) == 12:
            break
        cards.append(card)
    return cards


def page_cards(cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One compact candidate pointer leaves room for a full fresh archive page."""
    output: list[dict[str, Any]] = []
    for source in cards:
        card: dict[str, Any] = {key: source[key] for key in
            ("candidate_id", "route", "param", "identity_ref", "vector", "validation_state", "reason_code")}
        card["provenance"] = [{"source_artifact": item["source_artifact"]}
                              for item in source.get("provenance", [])[:1]]
        if len(json.dumps([*output, card]).encode()) > 768:
            break
        output.append(card)
    return output


def funnel(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema": "python-validation-funnel/1", "unit": "deduplicated_task_candidate",
             **{stage: sum(bool(row[stage]) for row in rows) for stage in STAGES},
            "candidates": copy.deepcopy(rows)}
