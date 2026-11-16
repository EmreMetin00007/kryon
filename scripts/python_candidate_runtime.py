"""Pure host candidate contracts. Observations and queue completion are not proof."""
from __future__ import annotations

import hashlib
import json
import copy
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

PROFILES = {
    "readonly_sqli_boolean": ("injection-sqli", "validator_validate_sqli", "differential_boolean"),
    "readonly_ssti_arithmetic": ("injection-ssti", "validator_validate_ssti", "arithmetic_eval"),
}
STAGES = ("observed", "eligible", "admitted", "executed", "evidence_accepted")
CARD_LIMIT = 8
CARD_BYTES = 2000


def query_parameters(url: str) -> dict[str, str]:
    """Reject ambiguous carriers before a dict can silently collapse duplicates."""
    raw = urlsplit(url).query
    if re.search(r"%(?![0-9a-fA-F]{2})", raw) or ";" in raw:
        raise ValueError("malformed_observed_query")
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True, errors="strict", max_num_fields=256)
    except ValueError:
        raise ValueError("malformed_observed_query") from None
    names = [name for name, _ in pairs]
    if any(not valid_parameter_name(name) for name in names):
        raise ValueError("malformed_observed_parameter")
    if len(set(names)) != len(names):
        raise ValueError("ambiguous_duplicate_parameter")
    return dict(pairs)


def valid_parameter_name(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:\[\]-]{1,96}", value) is not None


def parameter_declarations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict)
            or not valid_parameter_name(item.get("name")) or not isinstance(item.get("in", "query"), str)
            for item in value):
        raise ValueError("malformed_parameter_declaration")
    if len({item["name"] for item in value}) != len(value):
        raise ValueError("ambiguous_duplicate_parameter")
    return copy.deepcopy(value)


def card_route(url: str) -> str:
    """Cards are semantic pointers, not a second credential-bearing query archive."""
    from python_identity_discovery import public_export
    # Dynamic owned path atoms are values too, not merely query samples. The
    # host candidate/arguments keep the exact route; model cards keep its shape.
    safe = public_export({"validation_queue": [{"url": url}]})["validation_queue"][0]["url"]
    parsed = urlsplit(safe)
    return parsed._replace(query="", fragment="").geturl()


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


def recipe_arguments(row: dict[str, Any], tool: str) -> dict[str, Any] | None:
    """Return the host-bound argument recipe for an allowed executor tool on this candidate."""
    if row.get("tool") == tool:
        args = row.get("arguments")
        return args if isinstance(args, dict) else None
    recipes = row.get("recipes")
    if isinstance(recipes, dict):
        args = recipes.get(tool)
        return args if isinstance(args, dict) else None
    return None


def matches_model_call(row: dict[str, Any], tool: str, args: dict[str, Any]) -> bool:
    """A model can select a host slice, not widen it or supply raw identity data."""
    if not row["eligible"] or row["executed"] or row["evidence_accepted"]:
        return False
    expected = recipe_arguments(row, tool)
    if expected is None:
        return False
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
              provenance: Any = None, reason: str = "",
              validation_profile: str = "",
              recipes: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    # Provenance is merged on the semantic key: repeated pages/sources do not
    # inflate the funnel. Task identity is part of the key, so branches cannot
    # spend each other's reservations or reuse each other's coverage.
    key = [task, "GET", route, param, identity, vector]
    ident = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()
    row: dict[str, Any] = {
        "candidate_id": ident, "task_spec_id": task, "method": "GET",
        "route": route, "param": param, "identity_ref": identity,
        "vector": vector, "tool": tool, "arguments": arguments or {},
        "provenance": provenance or [], "observed": True, "eligible": not reason,
        "admitted": False, "executed": False, "evidence_accepted": False,
        "validation_state": "NOT TESTED", "reason_code": reason,
        "evidence_refs": [],
    }
    if validation_profile:
        row["validation_profile"] = validation_profile
    if recipes:
        row["recipes"] = recipes
    return row


def authorization_controls_complete(record: dict[str, Any]) -> bool:
    """Signed verdicts still need same-object owner/attacker/anonymous wire controls."""
    context = record.get("execution_context")
    evidence = record.get("evidence")
    if (not isinstance(context, dict) or not isinstance(evidence, dict)
            or record.get("oracle") != "content_match" or context.get("url") != record.get("target")
            or not context.get("identity") or not context.get("resource_owner")
            or context["identity"] == context["resource_owner"] or context.get("method") != "GET"):
        return False
    responses = record.get("request_evidence")
    if not isinstance(responses, list):
        return False
    roles: dict[str, dict[str, Any]] = {}
    for response in responses:
        if not isinstance(response, dict):
            return False
        role = response.get("role")
        if role not in {"owner", "attacker", "anonymous"}:
            return False
        if (role in roles or response.get("transport_ok") is not True
                or response.get("request_url") != record.get("target") or response.get("method") != "GET"
                or not re.fullmatch(r"[0-9a-f]{64}", str(response.get("response_sha256", "")))
                or type(response.get("response_length")) is not int or response["response_length"] < 0):
            return False
        roles[role] = response
    if not {"owner", "attacker"} <= roles.keys() or roles["owner"].get("status") not in {200, 206}:
        return False
    if "identity_fingerprints_distinct" in evidence and evidence["identity_fingerprints_distinct"] is not True:
        return False
    if "owner_marker_in_owner_response" in evidence and evidence["owner_marker_in_owner_response"] is not True:
        return False
    if "owner_status" in evidence and evidence["owner_status"] != roles["owner"].get("status"):
        return False
    if "attacker_status" in evidence and evidence["attacker_status"] != roles["attacker"].get("status"):
        return False
    if ("anonymous" in roles and "anonymous_status" in evidence
            and evidence["anonymous_status"] != roles["anonymous"].get("status")):
        return False
    verdict = record.get("verdict")
    if verdict == "CONFIRMED":
        return (
            "anonymous" in roles
            and roles["attacker"].get("status") in {200, 206}
            and evidence.get("owner_marker_in_attacker_response") is True
            and roles["anonymous"].get("status") in {401, 403, 404}
            and evidence.get("owner_marker_in_anonymous_response") is False
        )
    if verdict == "UNCONFIRMED":
        if "anonymous" in roles and (
            roles["anonymous"].get("status") not in {401, 403, 404}
            or evidence.get("owner_marker_in_anonymous_response") is True
        ):
            return False
        attacker_status = roles["attacker"].get("status")
        if attacker_status in {200, 206}:
            return (
                roles["attacker"]["response_sha256"] != roles["owner"]["response_sha256"]
                and evidence.get("owner_marker_in_attacker_response") is False
            )
        return (
            attacker_status in {401, 403, 404}
            and evidence.get("owner_marker_in_attacker_response") is not True
        )
    return False


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
        keys = ("source_spec_id", "source_artifact", "source_sha256")
        provenance = [{key: record[key] for key in keys}] if (all(isinstance(record.get(key), str)
            and record[key] for key in keys) and re.fullmatch(r"[0-9a-f]{64}", record["source_sha256"])) else []
        reason = record.get("candidate_reason", "")
        if not provenance:
            reason = "missing_discovery_provenance"
        try:
            params = query_parameters(url)
            declarations = parameter_declarations(record.get("params", []))
        except ValueError as exc:
            reason = reason or str(exc)
            params, declarations = {}, []
        # Unattributed observations default to anonymous; never infer a vault member.
        identity = record.get("identity_ref", "anon")
        if identity == "anonymous":
            identity = "anon"
        if identity not in ("anon", "anonymous") and (not isinstance(identity, str) or identity not in bindings):
            reason = reason or "missing_observed_identity_binding"
        if reason:
            output.append(candidate(spec.id, route=url, provenance=provenance, reason=reason))
            continue
        if record.get("method", "GET") != "GET":
            output.append(candidate(spec.id, route=url, provenance=provenance,
                                    reason="unsupported_readonly_method"))
            continue
        declared = {item["name"]: item.get("in", "query") for item in declarations}
        for param in dict.fromkeys([*params, *declared]):
            for profile, (vector, direct, _) in PROFILES.items():
                if spec.vector not in ("", "access", vector):
                    continue
                # Direct validators have no session-ref argument. Authenticated
                # records use Hunter's existing vault-only profile rather than
                # projecting credentials or silently testing anonymously.
                direct_args: dict[str, Any] = {
                    "target_url": url, "param": param, "method": "GET", "carrier": "query",
                }
                if profile == "readonly_sqli_boolean":
                    direct_args["boolean_only"] = True
                hunter_args: dict[str, Any] = {
                    "target": url, "live": True, "crawl": False,
                    "validation_profile": profile, "fuzz_limit": 4,
                    "max_validations": 16, "candidate_sample_limit": 16, "sleep_s": 0.2,
                }
                if identity in bindings:
                    hunter_args["session_bindings"] = json.dumps({identity: bindings[identity]})
                use_hunter = bool(bindings and identity != "anon") or direct not in spec.tools
                tool = "hunter_run_web_loop" if use_hunter else direct
                args = hunter_args if use_hunter else direct_args
                recipes: dict[str, dict[str, Any]] = {}
                if not (bindings and identity != "anon") and direct in spec.tools:
                    recipes[direct] = copy.deepcopy(direct_args)
                if "hunter_run_web_loop" in spec.tools:
                    recipes["hunter_run_web_loop"] = copy.deepcopy(hunter_args)
                output.append(candidate(
                    spec.id, route=url, param=param,
                    identity=identity, vector=vector,
                    tool=tool, arguments=args, provenance=provenance,
                    reason=(binding_reason if identity in bindings else "") or (
                        "unsupported_parameter_carrier" if declared.get(param, "query") != "query"
                        else "missing_observed_query_sample" if param not in params
                        else "validator_not_declared" if tool not in spec.tools else ""
                    ),
                    validation_profile=profile,
                    recipes=recipes or None,
                ))
    # Prefer a provenance-backed anonymous observation of the identical slice.
    # Invalid/contradictory rows remain visible and cannot be hidden by it.
    public = {(row["route"], row["param"], row["vector"]): row for row in output
              if row["identity_ref"] == "anon" and row["eligible"]}
    selected = []
    for row in output:
        anonymous = public.get((row["route"], row["param"], row["vector"]))
        if anonymous is not None and row["identity_ref"] != "anon" and row["eligible"]:
            anonymous["provenance"].extend(row["provenance"])
        else:
            selected.append(row)
    return selected


def compact_cards(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda row: (row["evidence_accepted"], not row["eligible"],
                                           row["vector"] != "access-idor", row["candidate_id"])):
        card = {key: row[key] for key in ("candidate_id", "method", "route", "param", "identity_ref",
            "vector", "tool", "provenance", "validation_state", "reason_code")}
        # Complete provenance remains in the discovery archive and candidate
        # state. A card needs one exact pointer, not every repeated source.
        card["provenance"] = row["provenance"][:1]
        card["route"] = card_route(row["route"])
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


LEAF_STATUSES = ("accepted", "pending", "indeterminate", "invalid_evidence")


def leaf_outcome(
    *,
    task: str,
    candidate_id: str,
    vector: str,
    url: str,
    method: str = "GET",
    param: str = "",
    carrier: str = "",
    identity: str = "anon",
    resource_owner: str = "",
    operation_id: str | None = None,
    vuln_class: str = "",
    pair_identities: list[str] | None = None,
    url_sha256: str = "",
    execution_state: str = "pending",
    status: str = "pending",
    verdict: str = "",
    validation_id: str = "",
    source_artifact: str = "",
    source_sha256: str = "",
    reason_code: str = "",
) -> dict[str, Any]:
    """Build a canonical leaf outcome record distinct from candidate-level aggregates."""
    if status not in LEAF_STATUSES:
        raise ValueError(f"unsupported leaf status: {status!r}")
    key_parts = [
        task,
        vector,
        method,
        url,
        url_sha256,
        param,
        carrier,
        identity,
        resource_owner,
        operation_id,
        vuln_class,
        list(pair_identities or []),
    ]
    leaf_id = hashlib.sha256(json.dumps(key_parts, sort_keys=True).encode()).hexdigest()
    accepted = status == "accepted"
    signed_result: dict[str, Any] | None = None
    if accepted:
        signed_result = {
            "validation_id": validation_id,
            "verdict": verdict,
            "source_artifact": source_artifact,
            "source_sha256": source_sha256,
        }
    elif status == "indeterminate" and validation_id:
        signed_result = {
            "validation_id": validation_id,
            "verdict": verdict or "INCONCLUSIVE",
        }
    row: dict[str, Any] = {
        "leaf_id": leaf_id,
        "task_spec_id": task,
        "candidate_id": candidate_id,
        "vector": vector,
        "url": url,
        "method": method,
        "param": param,
        "carrier": carrier,
        "identity": identity,
        "resource_owner": resource_owner,
        "operation_id": operation_id,
        "vuln_class": vuln_class,
        "pair_identities": list(pair_identities or []),
        "execution_state": execution_state,
        "status": status,
        "evidence_accepted": accepted,
        "validation_state": "TESTED" if accepted else "NOT TESTED",
        "verdict": verdict,
        "validation_id": validation_id,
        "signed_result": signed_result,
        "reason_code": "" if accepted else reason_code,
    }
    if url_sha256:
        row["url_sha256"] = url_sha256
    return row


def leaf_funnel(leaves: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate leaf outcomes without altering candidate-unit validation_funnel()."""
    return {
        "schema": "python-leaf-validation-funnel/1",
        "unit": "signed_validation_leaf",
        "observed": len(leaves),
        "accepted": sum(1 for row in leaves if row.get("status") == "accepted"),
        "pending": sum(1 for row in leaves if row.get("status") == "pending"),
        "indeterminate": sum(1 for row in leaves if row.get("status") == "indeterminate"),
        "invalid_evidence": sum(1 for row in leaves if row.get("status") == "invalid_evidence"),
        "outcomes": copy.deepcopy(leaves),
    }


def pair_progress_entry(
    identities: list[str],
    leaves: list[dict[str, Any]],
    *,
    complete: bool = False,
    categories: list[str] | None = None,
    reason_code: str = "",
) -> dict[str, Any]:
    """Summarize leaf-level progress and completeness for one identity pair."""
    observed = len(leaves)
    accepted = sum(1 for row in leaves if row.get("status") == "accepted")
    pending = sum(1 for row in leaves if row.get("status") == "pending")
    indeterminate = sum(1 for row in leaves if row.get("status") == "indeterminate")
    invalid = sum(1 for row in leaves if row.get("status") == "invalid_evidence")
    partial = bool(not complete and accepted > 0 and invalid == 0)
    coverage_state = (
        "tested"
        if complete
        else ("partial_coverage" if partial else "not_tested")
    )
    return {
        "identities": list(identities),
        "categories": list(categories or []),
        "observed": observed,
        "accepted": accepted,
        "pending": pending,
        "indeterminate": indeterminate,
        "invalid_evidence": invalid,
        "complete": bool(complete),
        "partial_coverage": partial,
        "status": "TESTED" if complete else "NOT TESTED",
        "coverage_state": coverage_state,
        "reason_code": "" if complete else reason_code,
        "leaves": copy.deepcopy(leaves),
    }


def pair_progress_summary(pairs: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate pair-level leaf progress across all identity pairs in a task."""
    return {
        "schema": "python-pair-progress/1",
        "unit": "identity_pair_leaf",
        "total_pairs": len(pairs),
        "complete_pairs": sum(1 for row in pairs if row.get("complete")),
        "partial_pairs": sum(1 for row in pairs if row.get("partial_coverage")),
        "observed": sum(int(row.get("observed", 0)) for row in pairs),
        "accepted": sum(int(row.get("accepted", 0)) for row in pairs),
        "pending": sum(int(row.get("pending", 0)) for row in pairs),
        "indeterminate": sum(int(row.get("indeterminate", 0)) for row in pairs),
        "invalid_evidence": sum(int(row.get("invalid_evidence", 0)) for row in pairs),
        "pairs": copy.deepcopy(pairs),
    }
