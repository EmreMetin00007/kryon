"""Pure host candidate contracts. Observations and queue completion are not proof."""
from __future__ import annotations

import hashlib
import inspect
import json
import copy
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

PROFILES = {
    "readonly_sqli_boolean": ("injection-sqli", "validator_validate_sqli", "differential_boolean"),
    "readonly_ssti_arithmetic": ("injection-ssti", "validator_validate_ssti", "arithmetic_eval"),
    "readonly_traversal_application_files": ("file-access", "validator_validate_path_traversal", "file_signature"),
    "readonly_xss_reflection": ("xss-stored", "validator_validate_xss_reflection", "browser_execution"),
    "readonly_open_redirect": ("authn-session", "validator_validate_open_redirect", "redirect_location"),
    "stateful_business_logic": ("race-business", "validator_validate_business_logic", "business_logic"),
}


def profile_oracles(profile: str, verdict: str = "") -> frozenset[str]:
    """Return acceptable validator oracles for a profile and verdict.

    Reflected XSS confirmation strictly requires browser_execution; clean
    negative/inconclusive reflection controls may report unescaped_reflection.
    """
    entry = PROFILES.get(profile)
    if entry is None:
        return frozenset()
    primary = entry[2]
    if profile == "readonly_xss_reflection" and str(verdict or "").upper() != "CONFIRMED":
        return frozenset({primary, "unescaped_reflection"})
    if profile == "readonly_sqli_boolean":
        return frozenset({primary, "differential_order_by", "timing_statistical"})
    return frozenset({primary})
STAGES = ("observed", "eligible", "admitted", "executed", "evidence_accepted")
OUTCOME_BUCKETS = (
    "ineligible",
    "completed_negative",
    "positive",
    "budget_deferred",
    "failed",
    "invalid_evidence",
    "pending",
)
BUDGET_DEFERRED_REASONS = frozenset({
    "deferred_budget",
    "phase_tool_budget_exhausted",
    "http_budget_exhausted",
    "token_budget_exhausted",
    "wall_clock_budget_exhausted",
    "insufficient_time_for_rate_window",
    "validator_execution_budget_exhausted",
    "remaining_leaves_not_validated",
    "remaining_leaf_not_validated",
})
FAILED_EXECUTION_REASONS = frozenset({
    "validator_execution_denied",
    "archive_size_limit_exceeded",
    "consecutive_tool_failure_limit",
    "execution_failed",
    "indeterminate_leaf_outcome",
    "indeterminate_dispatch_not_replayed",
})
_TRAVERSAL_PARAM_NAMES = frozenset({
    "file", "filepath", "filename", "path", "doc", "document",
    "page", "download", "export", "attachment", "template_file", "view", "include",
})
_TRAVERSAL_PATH_RE = re.compile(r"/(?:files?|downloads?|exports?|documents?|attachments?|reads?)(?:/|$)", re.I)
_FILENAME_SAMPLE_RE = re.compile(r"^[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,8}\Z")
_TEMPLATE_PATH_RE = re.compile(r"/(?:templates?|ssti[-_/])(?:/|$)", re.I)
_SQL_LOOKUP_PATH_RE = re.compile(r"/(?:lookup|items/sqli[-_/])(?:/|$)", re.I)
_XSS_PARAM_NAMES = frozenset({
    "xss", "html", "comment", "msg", "message", "bio", "title",
    "label", "banner", "snippet", "heading", "caption", "description",
    "preview", "echo", "tag", "badge", "highlight", "keyword",
})
_HIGH_RECALL_XSS_PARAM_NAMES = _XSS_PARAM_NAMES | frozenset({
    "q", "query", "search", "term", "filter", "keyword", "input", "value",
})
_XSS_PATH_RE = re.compile(
    r"/(?:xss[-_/]?|reflect(?:ion|ed)?|comments?|messages?|preview|echo|banner|dom[-_/]?|feedback|guestbook|highlight|widget)(?:/|$)",
    re.I,
)
_HIGH_RECALL_XSS_PATH_RE = re.compile(
    r"/(?:xss[-_/]?|reflect(?:ion|ed)?|comments?|messages?|preview|echo|banner|dom[-_/]?|feedback|guestbook|highlight|widget|search)(?:/|$)",
    re.I,
)
_SEARCH_FILTER_SUBPATH_RE = re.compile(
    r"/(?:search|filter|query|find|lookup|list|browse|redirect|continue|auth)(?:/|$)",
    re.I,
)
_NON_TRAVERSAL_QUERY_PARAMS = frozenset({
    "q", "query", "search", "term", "filter", "keyword",
    "sort", "order", "order_by", "orderby", "sort_by", "sortby", "dir",
    "next", "return", "return_to", "returnto", "redirect", "redirect_to", "url", "continue",
})
_LOGOUT_OR_STATIC_PATH_RE = re.compile(
    r"(?:/(?:logout|sign-out|signout|health|healthz|readyz)(?:/|$)|\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|map|woff2?|ttf|eot)$)",
    re.I,
)
_SORT_PARAM_NAMES = frozenset({
    "sort", "order", "order_by", "orderby", "sort_by", "sortby", "dir",
})
_REDIRECT_PARAM_NAMES = frozenset({
    "redirect", "redirect_to", "redirect_url", "redirect_uri",
    "next", "return", "return_to", "returnto", "return_url",
    "goto", "dest", "destination", "continue", "url", "uri", "rurl", "out",
})
_REDIRECT_PATH_RE = re.compile(
    r"/(?:go|redirects?|out|bounce|jump|leave|forward)(?:/|$)",
    re.I,
)
_REDIRECT_SAMPLE_RE = re.compile(r"^(?:/[A-Za-z0-9_./-]*|https?://[^\s]+|//[^\s]+)\Z", re.I)
_BIZ_PARAM_NAMES = frozenset({
    "op", "coupon", "redeem", "server_tag", "qty", "quantity",
    "discount", "step", "resource_id",
})
_BIZ_PATH_RE = re.compile(
    r"/(?:biz[-_/]?|business[-_/]?|coupons?|redeem|checkout|workflows?|state)(?:/|$)",
    re.I,
)
CARD_LIMIT = 8
CARD_BYTES = 2000


def infer_business_logic_kind(url: str, samples: dict[str, str] | None = None) -> str:
    """Infer P7 business-logic scenario kind deterministically from observed route/fields."""
    low = (urlsplit(url).path or "").lower()
    sample_op = str((samples or {}).get("op") or "").strip().lower()
    keys = {str(k).lower() for k in (samples or {})}
    if "coupon" in keys or sample_op == "redeem" or any(t in low for t in ("coupon", "redeem", "idempotency", "replay")):
        return "idempotency_replay"
    if sample_op in {"prepare", "complete"} or "step" in keys or any(t in low for t in ("workflow", "step", "sequence", "complete")):
        return "sequence_step_skip"
    if "server_tag" in keys or sample_op == "server_tag" or any(t in low for t in ("tag", "schema", "mass")):
        return "schema_symmetry"
    if sample_op in {"share", "private"} or any(t in low for t in ("share", "state", "transition", "privacy")):
        return "state_transition"
    if "qty" in keys or "quantity" in keys or any(t in low for t in ("qty", "price", "cart", "checkout", "arithmetic")):
        return "arithmetic_invariant"
    if any(t in low for t in ("auth", "owner")):
        return "write_authorization"
    return "idempotency_replay"


def normalize_carrier(value: Any, *, method: str = "GET", content_type: str = "") -> str:
    """Normalize parameter carrier without implicitly coercing GET body declarations."""
    norm_method = str(method or "GET").upper()
    raw = str(value or "").strip().lower()
    if raw == "body":
        return "form" if norm_method != "GET" else "body"
    if raw:
        return raw
    if norm_method == "GET":
        return "query"
    norm_ctype = str(content_type or "").split(";", 1)[0].strip().lower()
    if norm_ctype == "application/json":
        return "json"
    if norm_ctype == "application/x-www-form-urlencoded":
        return "form"
    return ""


def build_post_body_template(
    declarations: list[dict[str, Any]],
    param: str,
    carrier: str,
) -> tuple[str, str, str]:
    """Build a deterministic POST body template and Content-Type header from observed fields."""
    norm_carrier = normalize_carrier(carrier, method="POST")
    fields = [
        item for item in declarations
        if normalize_carrier(item.get("in", ""), method="POST") == norm_carrier
    ]
    target_item = next((item for item in fields if item.get("name") == param), None)
    if target_item is None:
        raise ValueError("missing_observed_body_parameter")
    baseline_value = str(target_item.get("sample", ""))
    if norm_carrier == "form":
        pairs = [
            (item["name"], "{{PAYLOAD}}" if item["name"] == param else str(item.get("sample", "")))
            for item in fields
        ]
        body_template = urlencode(pairs).replace("%7B%7BPAYLOAD%7D%7D", "{{PAYLOAD}}")
        headers_json = json.dumps({"Content-Type": "application/x-www-form-urlencoded"}, separators=(",", ":"))
        return body_template, headers_json, baseline_value
    if norm_carrier == "json":
        obj = {
            item["name"]: ("{{PAYLOAD}}" if item["name"] == param else str(item.get("sample", "")))
            for item in fields
        }
        body_template = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        headers_json = json.dumps({"Content-Type": "application/json"}, separators=(",", ":"))
        return body_template, headers_json, baseline_value
    raise ValueError("unsupported_parameter_carrier")


def _call_profile_eligibility(
    profile_eligibility: Any,
    spec: Any,
    url: str,
    param: str,
    carrier: str,
    profile: str,
    method: str,
) -> dict[str, Any] | None:
    if not callable(profile_eligibility):
        return None
    try:
        sig = inspect.signature(profile_eligibility)
        params = sig.parameters
        accepts_method = (
            "method" in params
            or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
        )
    except (ValueError, TypeError):
        accepts_method = False
    if accepts_method:
        res = profile_eligibility(spec, url, param, carrier, profile, method=method)
    elif str(method or "GET").upper() == "GET":
        res = profile_eligibility(spec, url, param, carrier, profile)
    else:
        return {"eligible": False, "reason_code": "unsupported_readonly_method"}
    return res if isinstance(res, dict) else None


def surface_profile_applicability(
    url: str,
    param: str,
    sample: str,
    profile: str,
    *,
    high_recall: bool = False,
) -> tuple[bool, bool, str]:
    """Evaluate ordinary surface applicability strictly from discovered surface fields.

    Returns (should_materialize, surface_eligible, reason_code).
    """
    path = urlsplit(url).path or "/"
    lower_path = path.lower()
    lower_param = str(param or "").lower()
    sample_text = str(sample or "")
    traversal_path_match = bool(_TRAVERSAL_PATH_RE.search(lower_path))
    if high_recall and traversal_path_match and (
        bool(_SEARCH_FILTER_SUBPATH_RE.search(lower_path))
        or lower_param in _NON_TRAVERSAL_QUERY_PARAMS
    ):
        traversal_path_match = False
    is_traversal_surface = (
        lower_param in _TRAVERSAL_PARAM_NAMES
        or traversal_path_match
        or bool(_FILENAME_SAMPLE_RE.fullmatch(sample_text))
    )
    is_template_only = bool(_TEMPLATE_PATH_RE.search(lower_path)) or (
        lower_param == "name"
        and bool(sample_text)
        and not sample_text.isdigit()
        and not _FILENAME_SAMPLE_RE.fullmatch(sample_text)
        and "search" not in lower_path
        and "render" not in lower_path
    )
    is_sql_lookup_only = bool(_SQL_LOOKUP_PATH_RE.search(lower_path)) or (
        lower_param == "id"
        and (not sample_text or sample_text.isdigit())
        and "search" not in lower_path
        and "render" not in lower_path
    )
    is_redirect_surface = (
        not is_traversal_surface
        and not is_sql_lookup_only
        and not is_template_only
        and (
            lower_param in _REDIRECT_PARAM_NAMES
            or bool(_REDIRECT_PATH_RE.search(lower_path))
            or (bool(sample_text) and bool(_REDIRECT_SAMPLE_RE.fullmatch(sample_text)))
        )
    )
    xss_param_names = _HIGH_RECALL_XSS_PARAM_NAMES if high_recall else _XSS_PARAM_NAMES
    xss_path_re = _HIGH_RECALL_XSS_PATH_RE if high_recall else _XSS_PATH_RE
    is_xss_surface = (
        not is_traversal_surface
        and not is_sql_lookup_only
        and not is_template_only
        and not is_redirect_surface
        and (
            lower_param in xss_param_names
            or bool(xss_path_re.search(lower_path))
        )
    )
    is_business_surface = (
        not is_traversal_surface
        and not is_sql_lookup_only
        and not is_template_only
        and not is_redirect_surface
        and not is_xss_surface
        and (
            lower_param in _BIZ_PARAM_NAMES
            or bool(_BIZ_PATH_RE.search(lower_path))
        )
    )
    if high_recall and profile in {
        "readonly_xss_reflection",
        "readonly_open_redirect",
        "readonly_sqli_boolean",
        "readonly_ssti_arithmetic",
    }:
        if _LOGOUT_OR_STATIC_PATH_RE.search(lower_path):
            return False, False, "profile_not_applicable_to_surface"
        return True, True, ""
    if profile == "stateful_business_logic":
        if not is_business_surface:
            return False, False, "profile_not_applicable_to_surface"
        return True, True, ""
    if profile == "readonly_traversal_application_files":
        if not is_traversal_surface:
            return False, False, "profile_not_applicable_to_surface"
        return True, True, ""
    if profile == "readonly_xss_reflection":
        if not is_xss_surface:
            return False, False, "profile_not_applicable_to_surface"
        return True, True, ""
    if profile == "readonly_open_redirect":
        if not is_redirect_surface:
            return False, False, "profile_not_applicable_to_surface"
        return True, True, ""
    if profile == "readonly_sqli_boolean":
        if is_traversal_surface or is_template_only or is_xss_surface or is_redirect_surface or is_business_surface:
            return True, False, "profile_not_applicable_to_surface"
        return True, True, ""
    if profile == "readonly_ssti_arithmetic":
        if is_traversal_surface or is_sql_lookup_only or is_xss_surface or is_redirect_surface or is_business_surface:
            return True, False, "profile_not_applicable_to_surface"
        return True, True, ""
    return True, True, ""


def _synthesize_query_sample(param: str, sample: str = "") -> str:
    """Synthesize a safe non-empty baseline query sample for form/link parameters."""
    clean = str(sample or "").strip()
    if clean and clean not in {"<unavailable>", "<redacted>"}:
        return clean
    lp = str(param or "").lower()
    if lp in _REDIRECT_PARAM_NAMES:
        return "/dashboard"
    if lp == "dir":
        return "asc"
    if lp in _SORT_PARAM_NAMES or lp in {"id", "page", "limit", "offset", "count", "num", "year"} or lp.endswith("_id"):
        return "1"
    return "test"


def _with_query_sample(url: str, param: str, sample: str) -> str:
    """Ensure a GET URL includes `param=sample` in its query string."""
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated: list[tuple[str, str]] = []
    replaced = False
    for key, val in pairs:
        if key == param and not replaced:
            updated.append((key, sample))
            replaced = True
        else:
            updated.append((key, val))
    if not replaced:
        updated.append((param, sample))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(updated, doseq=True), ""))


def _profile_priority(url: str, param: str, sample: str, profile: str) -> int:
    """Order naturally matching vectors ahead of high-recall cross-profile fallbacks."""
    lower_path = (urlsplit(url).path or "/").lower()
    lower_param = str(param or "").lower()
    if profile == "readonly_open_redirect" and (
        lower_param in _REDIRECT_PARAM_NAMES or _REDIRECT_PATH_RE.search(lower_path) or "/auth/" in lower_path
    ):
        return 0
    if profile == "readonly_xss_reflection" and (
        lower_param in _HIGH_RECALL_XSS_PARAM_NAMES or _HIGH_RECALL_XSS_PATH_RE.search(lower_path)
    ):
        return 0
    if profile == "readonly_sqli_boolean" and (
        lower_param in _SORT_PARAM_NAMES
        or lower_param in {"id", "user_id", "item_id", "filter", "category"}
        or _SQL_LOOKUP_PATH_RE.search(lower_path)
    ):
        return 0
    _, strict_ok, _ = surface_profile_applicability(url, param, sample, profile, high_recall=False)
    return 0 if strict_ok else 1


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
    if tool == "validator_validate_business_logic":
        required.update({"method", "carrier", "kind"})
    elif expected.get("method", "GET") != "GET" and tool != "hunter_run_web_loop":
        required.update({"method", "carrier", "body_template"})
    if not required <= args.keys():
        return False
    for key, value in args.items():
        if key == "session_bindings":
            try:
                if json.loads(value) != json.loads(expected.get(key, "{}")):
                    return False
            except (ValueError, TypeError):
                return False
        elif key == "headers_json" and expected.get("headers_json"):
            try:
                if not isinstance(value, str) or json.loads(value) != json.loads(expected["headers_json"]):
                    return False
            except (ValueError, TypeError):
                return False
        elif value != expected.get(key, {"headers_json": "{}", "body_template": "", "baseline_value": ""}.get(key)):
            return False
    return True


def candidate(task: str, *, route: str, param: str = "", identity: Any = "anon",
              vector: str = "", tool: str = "", arguments: Any = None,
              provenance: Any = None, reason: str = "",
              validation_profile: str = "",
              recipes: dict[str, dict[str, Any]] | None = None,
              method: str = "GET",
              carrier: str = "") -> dict[str, Any]:
    # Provenance is merged on the semantic key: repeated pages/sources do not
    # inflate the funnel. Task identity is part of the key, so branches cannot
    # spend each other's reservations or reuse each other's coverage.
    norm_method = str(method or "GET").upper()
    norm_carrier = str(carrier if carrier != "" else ("query" if norm_method == "GET" else "")).strip().lower()
    key = [task, norm_method, route, param, identity, vector]
    ident = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()
    row: dict[str, Any] = {
        "candidate_id": ident, "task_spec_id": task, "method": norm_method,
        "carrier": norm_carrier,
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
                         bindings: dict[str, Any], *,
                         profile_eligibility: Any = None,
                         hydrated_routes: dict[str, list[dict[str, Any]]] | None = None,
                         high_recall: bool = False) -> list[dict[str, Any]]:
    """Select read-only oracle capabilities from records, not names or truth."""
    output = []
    binding_reason = ""
    if bindings and (len(bindings) > 8 or any(
            item.get("target") != spec.target or item.get("test_data_only") is not True
            or item.get("owned_objects_private") is not True for item in bindings.values())):
        binding_reason = "missing_synthetic_owned_session_prerequisite"
    expanded_records: list[dict[str, Any]] = []
    for record in records:
        url = str(record.get("url") or "")
        method = str(record.get("method", "GET") or "GET").upper()
        if ("{" in url or "}" in url) and (hydrated_routes or record.get("hydrated_urls")):
            hydrated = (hydrated_routes or {}).get(f"{method} {url}") or record.get("hydrated_urls") or []
            if isinstance(hydrated, list) and hydrated:
                for h_item in hydrated:
                    if not isinstance(h_item, dict) or not isinstance(h_item.get("url"), str):
                        continue
                    slot_name = str(h_item.get("param_name") or "")
                    filtered_params = [
                        p for p in (record.get("params") or [])
                        if not (isinstance(p, dict) and p.get("in") == "path" and (not slot_name or p.get("name") == slot_name))
                    ]
                    hydrated_rec = {
                        **record,
                        "url": h_item["url"],
                        "route_template": url,
                        "params": filtered_params,
                    }
                    if h_item.get("identity_ref"):
                        hydrated_rec["identity_ref"] = h_item["identity_ref"]
                    expanded_records.append(hydrated_rec)
                continue
        expanded_records.append(record)

    for record in expanded_records:
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
        method = str(record.get("method", "GET") or "GET").upper()
        if not reason and ("{" in url or "}" in url):
            reason = "requires_request_context"
        if reason:
            output.append(candidate(spec.id, route=url, provenance=provenance, reason=reason, method=method,
                                    carrier="query" if method == "GET" else ""))
            continue
        if method not in {"GET", "POST", "PUT", "PATCH"}:
            output.append(candidate(spec.id, route=url, provenance=provenance,
                                    reason="unsupported_readonly_method", method=method, carrier=""))
            continue
        ctype = str(record.get("content_type") or "").split(";", 1)[0].strip().lower()
        if method in {"POST", "PUT", "PATCH"}:
            probe_carrier = "json" if ctype == "application/json" else "form"
            post_ro = (
                _call_profile_eligibility(
                    profile_eligibility, spec, url, "", probe_carrier, "readonly_sqli_boolean", "POST"
                )
                if method == "POST"
                else None
            )
            post_biz = _call_profile_eligibility(
                profile_eligibility, spec, url, "", probe_carrier, "stateful_business_logic", method
            )
            ro_ok = isinstance(post_ro, dict) and post_ro.get("reason_code") != "unsupported_readonly_method"
            biz_ok = isinstance(post_biz, dict) and post_biz.get("reason_code") != "unsupported_readonly_method"
            if not ro_ok and not biz_ok:
                output.append(candidate(
                    spec.id, route=url, identity=identity, provenance=provenance,
                    reason="unsupported_readonly_method", method=method, carrier="",
                ))
                continue
        declared = {
            item["name"]: normalize_carrier(item.get("in", ""), method=method, content_type=ctype)
            for item in declarations
        }
        declared_samples = {item["name"]: str(item.get("sample", "")) for item in declarations}
        if method in {"POST", "PUT", "PATCH"} and not declared:
            output.append(candidate(
                spec.id, route=url, identity=identity, provenance=provenance,
                reason="missing_parameter_or_synthetic_identity_pair", method=method,
                carrier="json" if ctype == "application/json" else ("form" if params else ""),
            ))
            continue
        emitted_biz_routes: set[tuple[str, str]] = set()
        param_order = list(dict.fromkeys([*params, *declared]))
        for param in param_order:
            carrier = declared.get(param, "query")
            sample = params.get(param, declared_samples.get(param, ""))
            effective_url = url
            synthesized_sample = False
            if high_recall and method == "GET" and carrier == "query" and param not in params:
                sample = _synthesize_query_sample(param, sample)
                effective_url = _with_query_sample(url, param, sample)
                synthesized_sample = True
            for profile, (vector, direct, _) in PROFILES.items():
                if spec.vector not in ("", "access", vector):
                    continue
                if profile == "stateful_business_logic" and method == "GET":
                    continue
                materialize, surface_ok, surface_reason = surface_profile_applicability(
                    effective_url, param, sample, profile, high_recall=high_recall,
                )
                if not materialize:
                    continue
                if profile == "stateful_business_logic":
                    preferred_biz_param = "op" if "op" in declared else (next(iter(declared), param))
                    if param != preferred_biz_param:
                        continue
                    biz_route_key = (method, effective_url)
                    if biz_route_key in emitted_biz_routes:
                        continue
                    emitted_biz_routes.add(biz_route_key)
                policy_reason = ""
                if method in {"POST", "PUT", "PATCH"}:
                    if profile in {
                        "readonly_traversal_application_files",
                        "readonly_xss_reflection",
                        "readonly_open_redirect",
                    }:
                        policy_reason = "unsupported_readonly_method"
                    elif surface_ok:
                        decision = _call_profile_eligibility(
                            profile_eligibility, spec, effective_url, param, carrier, profile, method
                        )
                        if not isinstance(decision, dict) or decision.get("eligible") is not True:
                            policy_reason = str(
                                (decision or {}).get("reason_code") if isinstance(decision, dict) else ""
                            ) or "unsupported_readonly_method"
                        elif carrier not in {"form", "json"}:
                            policy_reason = "unsupported_parameter_carrier"
                elif surface_ok and profile == "readonly_traversal_application_files":
                    decision = _call_profile_eligibility(
                        profile_eligibility, spec, effective_url, param, carrier, profile, method
                    )
                    if isinstance(decision, dict):
                        if decision.get("eligible") is not True:
                            policy_reason = str(decision.get("reason_code") or "") or "traversal_policy_not_declared"
                    else:
                        policy_reason = "traversal_policy_not_declared"
                elif surface_ok and profile in {"readonly_xss_reflection", "readonly_open_redirect"}:
                    decision = _call_profile_eligibility(
                        profile_eligibility, spec, effective_url, param, carrier, profile, method
                    )
                    if isinstance(decision, dict) and decision.get("eligible") is not True:
                        default_reason = (
                            "xss_execution_disabled"
                            if profile == "readonly_xss_reflection"
                            else "redirect_policy_invalid"
                        )
                        policy_reason = str(decision.get("reason_code") or "") or default_reason
                if not surface_ok or policy_reason:
                    output.append(candidate(
                        spec.id, route=effective_url, param=param,
                        identity=identity, vector=vector,
                        provenance=provenance,
                        reason=surface_reason or policy_reason,
                        validation_profile=profile,
                        method=method,
                        carrier=carrier,
                    ))
                    continue
                # Direct validators have no session-ref argument. Authenticated
                # records use Hunter's existing vault-only profile rather than
                # projecting credentials or silently testing anonymously.
                if profile == "stateful_business_logic":
                    direct_args = {
                        "target_url": effective_url,
                        "kind": infer_business_logic_kind(effective_url, declared_samples),
                        "method": method,
                        "carrier": carrier,
                        "param": param,
                    }
                    if isinstance(record.get("operation_id"), str) and record["operation_id"]:
                        direct_args["operation_id"] = record["operation_id"]
                elif method == "POST":
                    body_template, headers_json, baseline_val = build_post_body_template(
                        declarations, param, carrier
                    )
                    direct_args = {
                        "target_url": effective_url,
                        "param": param,
                        "method": "POST",
                        "carrier": carrier,
                        "body_template": body_template,
                        "headers_json": headers_json,
                    }
                    if baseline_val and profile == "readonly_sqli_boolean":
                        direct_args["baseline_value"] = baseline_val
                else:
                    direct_args = {
                        "target_url": effective_url, "param": param, "method": "GET", "carrier": "query",
                    }
                if profile == "readonly_sqli_boolean":
                    direct_args["boolean_only"] = not bool(high_recall)
                hunter_args: dict[str, Any] = {
                    "target": effective_url, "live": True, "crawl": False,
                    "validation_profile": profile, "fuzz_limit": 4,
                    "max_validations": 16, "candidate_sample_limit": 16, "sleep_s": 0.2,
                }
                if high_recall:
                    hunter_args["high_recall"] = True
                if identity in bindings:
                    hunter_args["session_bindings"] = json.dumps({identity: bindings[identity]})
                if profile == "stateful_business_logic":
                    use_hunter = False
                    tool = direct
                    args = direct_args
                    recipes = {direct: copy.deepcopy(direct_args)} if direct in spec.tools else {}
                else:
                    use_hunter = bool(bindings and identity != "anon") or direct not in spec.tools
                    tool = "hunter_run_web_loop" if use_hunter else direct
                    args = hunter_args if use_hunter else direct_args
                    recipes = {}
                    if not (bindings and identity != "anon") and direct in spec.tools:
                        recipes[direct] = copy.deepcopy(direct_args)
                    if "hunter_run_web_loop" in spec.tools:
                        recipes["hunter_run_web_loop"] = copy.deepcopy(hunter_args)
                carrier_or_sample_reason = (
                    ""
                    if method in {"POST", "PUT", "PATCH"}
                    else (
                        "unsupported_parameter_carrier" if carrier != "query"
                        else "missing_observed_query_sample" if (param not in params and not synthesized_sample)
                        else ""
                    )
                )
                output.append(candidate(
                    spec.id, route=effective_url, param=param,
                    identity=identity, vector=vector,
                    tool=tool, arguments=args, provenance=provenance,
                    reason=(
                        (binding_reason if identity in bindings else "")
                        or surface_reason
                        or policy_reason
                        or carrier_or_sample_reason
                        or ("validator_not_declared" if tool not in spec.tools else "")
                    ),
                    validation_profile=profile,
                    recipes=recipes or None,
                    method=method,
                    carrier=carrier,
                ))
    # Conflicting carriers on the same (candidate_id) slice must fail closed.
    carriers_by_id: dict[str, set[str]] = {}
    for row in output:
        if row.get("carrier"):
            carriers_by_id.setdefault(row["candidate_id"], set()).add(row["carrier"])
    for row in output:
        if len(carriers_by_id.get(row["candidate_id"], set())) > 1:
            row["eligible"] = False
            row["reason_code"] = "conflicting_parameter_carrier"
            row["tool"] = ""
            row["arguments"] = {}
            row.pop("recipes", None)
    if high_recall:
        # In high-recall blind mode, prefer authenticated observations over anon
        # so auth-gated endpoints do not fail with 401 when both exist.
        authed = {
            (row.get("method", "GET"), row["route"], row["param"], row["vector"]): row
            for row in output
            if row["identity_ref"] != "anon" and row["eligible"]
        }
        selected = []
        for row in output:
            auth_row = authed.get((row.get("method", "GET"), row["route"], row["param"], row["vector"]))
            if auth_row is not None and row["identity_ref"] == "anon" and row["eligible"]:
                auth_row["provenance"].extend(row["provenance"])
            else:
                selected.append(row)
        selected.sort(
            key=lambda row: (
                0 if row.get("eligible") else 1,
                _profile_priority(row["route"], row["param"], "", row.get("validation_profile", "")),
            )
        )
        return selected
    # Prefer a provenance-backed anonymous observation of the identical slice.
    # Invalid/contradictory rows remain visible and cannot be hidden by it.
    public = {(row.get("method", "GET"), row["route"], row["param"], row["vector"]): row for row in output
              if row["identity_ref"] == "anon" and row["eligible"]}
    selected = []
    for row in output:
        anonymous = public.get((row.get("method", "GET"), row["route"], row["param"], row["vector"]))
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


def classify_candidate_outcome(row: dict[str, Any]) -> str:
    """Classify one candidate row into explicit, non-overlapping outcome buckets."""
    if not row.get("eligible"):
        return "ineligible"
    if row.get("evidence_accepted"):
        if row.get("outcome") == "positive" or row.get("accepted_verdict") == "CONFIRMED":
            return "positive"
        return "completed_negative"
    reason = str(row.get("reason_code") or "")
    if reason in BUDGET_DEFERRED_REASONS:
        return "budget_deferred"
    if reason in FAILED_EXECUTION_REASONS:
        return "failed"
    if row.get("executed") or reason == "invalid_or_missing_signed_evidence":
        return "invalid_evidence"
    return "pending"


def funnel(rows: list[dict[str, Any]]) -> dict[str, Any]:
    outcomes = {bucket: 0 for bucket in OUTCOME_BUCKETS}
    for row in rows:
        outcomes[classify_candidate_outcome(row)] += 1
    counts = {stage: sum(bool(row[stage]) for row in rows) for stage in STAGES}
    return {
        "schema": "python-validation-funnel/1",
        "unit": "deduplicated_task_candidate",
        **counts,
        "denominators": {
            "discovered_pairs": counts["observed"],
            "eligible_pairs": counts["eligible"],
            "admitted_pairs": counts["admitted"],
            "executed_pairs": counts["executed"],
            "evidence_accepted_executions": counts["evidence_accepted"],
        },
        "outcomes": outcomes,
        "candidates": [
            {key: value for key, value in row.items() if key != "recipes"}
            for row in copy.deepcopy(rows)
        ],
    }


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
