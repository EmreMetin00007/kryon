"""General-purpose subsystem clustering and prompt builders for sharded execution."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from agentic_surface import (
    _HIGH_RISK_SCORE_THRESHOLD,
    _NON_PROBE_PARAM_NAMES,
    _order_params_by_risk,
    _split_path_kv_segment,
    is_catalog_route,
    is_id_segment,
    is_logout_or_destructive_route,
    is_non_endpoint_source_path,
    is_virgin_state_sensitive_path,
    route_template_of,
    score_route_input_risk,
)

_PREFIX_SEGMENT_RE = re.compile(
    r"^(?:api|ajax[-_]?api|rest|rpc|v\d+(?:\.\d+)?|\d+\.\d+)$",
    re.IGNORECASE,
)
_API_ROUTE_RE = re.compile(
    r"^/(?:api|ajax[-_]?api|rest|rpc|v\d+(?:\.\d+)?|graphql)(?:/|$)|/graphql(?:/|$)",
    re.IGNORECASE,
)
_METHOD_PREFIX_RE = re.compile(
    r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+((?:/|https?://).*)$",
    re.IGNORECASE,
)
_AUTH_UTILITY_SEGMENTS = frozenset({
    "login",
    "log-in",
    "signin",
    "sign-in",
    "signup",
    "sign-up",
    "register",
    "logout",
    "log-out",
    "signout",
    "sign-out",
    "session",
    "refresh",
})
_INTERNAL_URL_RE = re.compile(
    r"https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]):\d+[^\s\"'<>\\]*",
    re.IGNORECASE,
)
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "0.0.0.0", "::1"})
_CAMEL_SPLIT_RE = re.compile(r"([a-z0-9])([A-Z])")
_KEY_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_SYNTHESIS_INFO_KEY_TOKENS = frozenset({
    "partner",
    "connector",
    "diagnostics",
    "diagnostic",
    "key",
    "secret",
    "code",
    "pin",
    "upgrade",
    "endpoint",
    "tier",
    "admin",
    "token",
    "header",
    "webhook",
    "callback",
})
_SYNTHESIS_PASSWORD_KEY_TOKENS = frozenset({
    "password",
    "passwd",
    "pwd",
    "passphrase",
})
_SYNTHESIS_TRIVIAL_CODE_INTS = frozenset({0, 200, 201, 202, 204, 301, 302, 304, 400, 401, 403, 404, 409, 422, 500, 502, 503})
_SYNTHESIS_TRIVIAL_CODE_STRS = frozenset({"0", "200", "201", "204", "400", "401", "403", "404", "500", "ok", "success", "error"})
_SYNTHESIS_CAPABILITY_CLASSES: dict[str, str] = {
    "jwt_weakness": "forged/weak JWT auth",
    "auth_bypass": "unauthenticated access bypass",
    "bfla": "function-level privilege bypass",
    "bola": "cross-actor object access",
    "tenant_isolation": "cross-tenant data access",
    "mass_assignment": "privileged field mass assignment",
    "ssti": "server-side template execution",
    "command_injection": "server-side command execution",
    "insecure_deserialization": "insecure object deserialization",
    "sqli": "SQL injection data extraction/bypass",
    "sqli_read": "SQL injection read extraction",
    "ssrf": "server-side request forgery",
    "xxe": "XML external entity read/SSRF",
    "path_traversal": "arbitrary file/path read",
    "file_upload": "unrestricted file upload",
}
_SYNTHESIS_CAPABILITY_TEXT_HINTS = (
    "forged",
    "alg=none",
    "key confusion",
    "hs256",
    "sqli",
    "sql injection",
    "union select",
    "data extraction",
    "privilege escalation",
    "admin token",
)
_SYNTHESIS_BLOCKER_KEYWORDS = (
    "other shard",
    "another shard",
    "out of shard",
    "out of scope",
    "owned by",
    "requires",
    "prerequisite",
    "blocked",
    "balance",
    "tier",
    "enterprise",
    "partner",
    "connector",
    "internal",
    "virgin",
    "already claimed",
    "403",
    "401",
    "budget exhausted",
)
_WRITE_HTTP_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_METHOD_DISPLAY_ORDER: dict[str, int] = {
    "POST": 0,
    "PUT": 1,
    "PATCH": 2,
    "DELETE": 3,
    "GET": 4,
    "HEAD": 5,
    "OPTIONS": 6,
}
_SECURITY_BUCKET_TIER1_TOKENS = frozenset({
    "auth",
    "login",
    "signin",
    "signup",
    "register",
    "password",
    "passwd",
    "reset",
    "role",
    "roles",
    "permission",
    "permissions",
    "admin",
    "user",
    "users",
    "account",
    "accounts",
    "hesabim",
    "puanlarim",
    "siparislerim",
    "kuponlarim",
    "adreslerim",
    "oauth",
    "oauth2",
    "sso",
    "session",
    "sessions",
    "refresh",
    "payment",
    "payments",
    "checkout",
    "billing",
    "wallet",
    "token",
    "secret",
    "upload",
    "uploads",
    "import",
    "script",
    "scripts",
    "exec",
    "eval",
    "command",
    "cmd",
    "shell",
    "proxy",
    "webhook",
    "webhooks",
})
_SECURITY_BUCKET_TIER2_TOKENS = frozenset({
    "file",
    "files",
    "download",
    "export",
    "query",
    "search",
    "callback",
    "fetch",
    "redirect",
    "forward",
    "sepetim",
    "sepet",
    "cart",
    "basket",
    "pay",
})
_MAX_CATALOG_ROUTES_PER_SHARD = 5
_LOW_RISK_METADATA_TOKENS = frozenset({
    "dictionary",
    "dict",
    "count",
    "counts",
    "stat",
    "stats",
    "metadata",
    "meta",
    "health",
    "healthz",
    "ready",
    "readyz",
    "livez",
    "version",
    "ping",
    "enum",
    "enums",
    "tree",
    "about",
    "help",
    "faq",
    "changelog",
    "license",
})
_TEXT_KV_RE = re.compile(
    r"(?i)\b([A-Za-z][A-Za-z0-9_.-]{1,48})\s*[:=]\s*([\"']?)([^\s\"'`,;}{\\]{2,120})\2"
)


def _method_sort_key(method: str) -> tuple[int, str]:
    """Sort mutating methods before safe methods using canonical HTTP display order."""
    m = str(method or "").strip().upper()
    return (_METHOD_DISPLAY_ORDER.get(m, 9), m)


def _route_path_tokens(route_template: str) -> set[str]:
    """Extract normalized alphanumeric path tokens, ignoring `{param}` placeholders."""
    tokens: set[str] = set()
    for seg in str(route_template or "").lower().split("/"):
        if not seg or seg.startswith("{"):
            continue
        stem = seg.rsplit(".", 1)[0] if "." in seg else seg
        for tok in _KEY_TOKEN_SPLIT_RE.split(stem):
            if tok:
                tokens.add(tok)
    return tokens


def _adjust_route_risk_score(
    tmpl: str,
    *,
    base_score: int,
    methods: Sequence[str],
    params: Sequence[str],
    is_form: bool = False,
    has_body_template: bool = False,
) -> int:
    """Apply security-bucket, path-ID BOLA, and metadata risk adjustments to base score."""
    score = int(base_score)
    if is_logout_or_destructive_route(tmpl):
        return score

    norm_methods = [str(m or "").strip().upper() for m in methods if str(m or "").strip()]
    mutating_count = sum(1 for m in norm_methods if m in _WRITE_HTTP_METHODS)
    has_mutating = mutating_count > 0
    has_path_id = "{id}" in tmpl or "{val}" in tmpl
    has_interactive = has_mutating or bool(params) or has_path_id or is_form or has_body_template

    tokens = _route_path_tokens(tmpl)
    tier1_hit = bool(tokens & _SECURITY_BUCKET_TIER1_TOKENS)
    tier2_hit = bool(tokens & _SECURITY_BUCKET_TIER2_TOKENS)

    if tier1_hit:
        score += 12 if has_interactive else 8
    if tier2_hit:
        score += 6 if has_interactive else 5
    if "{id}" in tmpl:
        score += 4
    if mutating_count > 1:
        score += min(4, (mutating_count - 1) * 2)

    if not has_interactive and not tier1_hit and not tier2_hit and (tokens & _LOW_RISK_METADATA_TOKENS):
        score = max(0, score - 2)
    return score


def _is_virgin_state_action_path(path_or_url: str) -> bool:
    """Return True when any whole URL path segment targets a single-use/race action, ignoring static/auth paths."""
    raw = str(path_or_url or "").strip()
    m = _METHOD_PREFIX_RE.match(raw)
    if m:
        raw = m.group(1).strip()
    if not raw or is_non_endpoint_source_path(raw):
        return False
    return is_virgin_state_sensitive_path(raw)


def _is_api_route(path: str) -> bool:
    return bool(_API_ROUTE_RE.search(str(path or "")))


@dataclass
class SubsystemCluster:
    """A balanced cluster of resource families and surface metadata assigned to one shard."""

    shard_id: str
    name: str
    families: list[str]
    routes: list[str]
    write_ops: list[str]
    objects: list[str]
    params: dict[str, list[str]]
    body_templates: dict[str, Any] = field(default_factory=dict)
    schema_hints: dict[str, list[str]] = field(default_factory=dict)
    methods_by_route: dict[str, list[str]] = field(default_factory=dict)


def extract_resource_family(path: str) -> str:
    """Return the normalized top-level resource family for a URL or path.

    Strips leading `/api`, `/v[0-9]+`, and `/rest` prefixes before selecting the
    first resource segment. SEO/storefront catalog template paths collapse into
    `"catalog"`. Root `/`, root-level static files, malformed paths, and
    punctuation-only segments map to `"root"`.
    """
    raw = str(path or "")
    if is_non_endpoint_source_path(raw):
        return "root"
    if is_catalog_route(raw):
        return "catalog"
    raw_path = urlsplit(raw.strip()).path or "/"
    segments = [seg for seg in raw_path.split("/") if seg]
    while segments and (
        _PREFIX_SEGMENT_RE.fullmatch(segments[0])
        or not any(ch.isalnum() for ch in segments[0])
    ):
        segments.pop(0)
    if not segments:
        return "root"
    first = segments[0]
    if first.startswith("{") and first.endswith("}"):
        return "root"
    if first.startswith("$"):
        return "root"
    kv = _split_path_kv_segment(first)
    if kv is not None:
        return kv[0]
    if "=" in first:
        return "root"
    if len(segments) == 1 and "." in first:
        return "root"
    if not any(ch.isalnum() for ch in first):
        return "root"
    return first.lower()


def _extract_subfamily_after(path: str, umbrella: str) -> str | None:
    """Return the normalized non-ID sub-family immediately following stripped prefix + `umbrella`."""
    raw = str(path or "")
    if is_non_endpoint_source_path(raw):
        return None
    raw_path = urlsplit(raw.strip()).path or "/"
    segments = [seg for seg in raw_path.split("/") if seg]
    while segments and (
        _PREFIX_SEGMENT_RE.fullmatch(segments[0])
        or not any(ch.isalnum() for ch in segments[0])
    ):
        segments.pop(0)
    if len(segments) < 2 or segments[0].lower() != umbrella.lower():
        return None
    sub = segments[1]
    if is_id_segment(sub) or (sub.startswith("{") and sub.endswith("}")):
        return None
    if not any(ch.isalnum() for ch in sub):
        return None
    kv = _split_path_kv_segment(sub)
    if kv is not None:
        return kv[0]
    if "=" in sub:
        return None
    if len(segments) == 2 and "." in sub:
        return None
    return sub.lower()


def _rank_routes_by_input_risk(
    routes: Sequence[str],
    *,
    write_ops: Sequence[str] = (),
    params: Mapping[str, Sequence[str]] | None = None,
    body_templates: Mapping[str, Any] | None = None,
    schema_hints: Mapping[str, Sequence[str]] | None = None,
    methods_by_route: Mapping[str, set[str]] | None = None,
    form_templates: set[str] | None = None,
    surface_tracker: Any | None = None,
) -> list[dict[str, Any]]:
    """Score and deterministically sort routes by descending input attack-surface risk."""
    route_set: set[str] = set()
    inferred_methods: dict[str, set[str]] = {}
    body_template_routes: set[str] = set()
    params_map = params or {}
    schema_map = schema_hints or {}
    forms_set = set(form_templates or ())
    if surface_tracker is not None:
        forms_set.update(getattr(surface_tracker, "discovered_form_templates", ()) or ())

    def _register_route(raw_path: str, method: str = "") -> str | None:
        raw = str(raw_path or "").strip()
        if not raw or is_non_endpoint_source_path(raw):
            return None
        tmpl = route_template_of(raw)
        if is_non_endpoint_source_path(tmpl):
            return None
        route_set.add(tmpl)
        if method:
            inferred_methods.setdefault(tmpl, set()).add(str(method).strip().upper())
        return tmpl

    for r in routes:
        _register_route(str(r))

    for w in write_ops:
        parts = str(w or "").strip().split(None, 1)
        if len(parts) == 2:
            _register_route(parts[1], method=parts[0])
        elif parts:
            _register_route(parts[0], method="POST")

    for op_key in (body_templates or {}):
        parts = str(op_key or "").strip().split(None, 1)
        if len(parts) == 2:
            tmpl = _register_route(parts[1], method=parts[0])
            if tmpl is not None:
                body_template_routes.add(tmpl)

    for tmpl in params_map:
        _register_route(str(tmpl))

    for tmpl in schema_map:
        _register_route(str(tmpl))

    for tmpl, mset in (methods_by_route or {}).items():
        clean_t = _register_route(str(tmpl))
        if clean_t is not None and mset:
            inferred_methods.setdefault(clean_t, set()).update(
                str(m).strip().upper() for m in mset if str(m).strip()
            )

    tracker_allowed = getattr(surface_tracker, "allowed_methods", None)
    tracker_probed_fn = getattr(surface_tracker, "is_route_actively_probed", None)
    tracker_known_methods_fn = getattr(surface_tracker, "_template_known_methods", None)

    ranked: list[dict[str, Any]] = []
    for tmpl in sorted(route_set):
        mset = set(inferred_methods.get(tmpl) or ())
        if callable(tracker_known_methods_fn):
            try:
                _all_m, allowed_m = tracker_known_methods_fn(tmpl)
                if allowed_m:
                    mset.update(allowed_m)
            except Exception:
                pass
        if isinstance(tracker_allowed, (set, frozenset)) and mset:
            filtered = mset & set(tracker_allowed)
            if filtered:
                mset = filtered
        if not mset:
            mset = {"GET"}

        ordered_methods = sorted(mset, key=_method_sort_key)
        p_raw = list(params_map.get(tmpl) or ())
        ordered_params = _order_params_by_risk(p_raw)
        hints = [str(h).strip() for h in (schema_map.get(tmpl) or ()) if str(h).strip()]
        is_form = tmpl in forms_set
        has_bt = tmpl in body_template_routes
        base_score, reason = score_route_input_risk(
            tmpl,
            methods=ordered_methods,
            params=ordered_params,
            schema_hints=hints,
            is_form=is_form,
            has_body_template=has_bt,
        )
        risk_score = _adjust_route_risk_score(
            tmpl,
            base_score=base_score,
            methods=ordered_methods,
            params=ordered_params,
            is_form=is_form,
            has_body_template=has_bt,
        )
        actively_probed = False
        if callable(tracker_probed_fn):
            try:
                actively_probed = bool(tracker_probed_fn(tmpl, methods=ordered_methods))
            except Exception:
                actively_probed = False
        ranked.append({
            "route_template": tmpl,
            "methods": ordered_methods,
            "params": ordered_params,
            "risk_score": risk_score,
            "reason": reason,
            "actively_probed": actively_probed,
        })

    ranked.sort(key=lambda item: (-int(item["risk_score"]), str(item["route_template"])))
    return ranked


def _is_low_priority_catalog_route(
    tmpl: str,
    *,
    methods: Sequence[str] = (),
    params: Sequence[str] = (),
    is_form: bool = False,
    has_body_template: bool = False,
    risk_score: int = 0,
) -> bool:
    """Return True for pure storefront/SEO catalog templates lacking mutating/high-risk inputs."""
    if _is_api_route(tmpl):
        return False
    if is_form or has_body_template or int(risk_score) >= _HIGH_RISK_SCORE_THRESHOLD:
        return False
    norm_methods = {str(m or "").strip().upper() for m in methods if str(m or "").strip()}
    if norm_methods & _WRITE_HTTP_METHODS:
        return False
    active_params = [
        str(p or "").strip()
        for p in params
        if str(p or "").strip() and str(p or "").strip().lower() not in _NON_PROBE_PARAM_NAMES
    ]
    if active_params:
        return False
    return extract_resource_family(tmpl) == "catalog" or is_catalog_route(tmpl)


def _cap_catalog_cluster_routes(
    ranked_entries: Sequence[dict[str, Any]],
    *,
    form_templates: set[str] | None = None,
    body_template_routes: set[str] | None = None,
    max_catalog_routes: int = _MAX_CATALOG_ROUTES_PER_SHARD,
) -> list[dict[str, Any]]:
    """Keep all non-catalog/high-risk routes while capping low-priority catalog sample routes per shard."""
    forms = form_templates or set()
    bts = body_template_routes or set()
    cap = max(1, int(max_catalog_routes))
    kept: list[dict[str, Any]] = []
    catalog_count = 0
    for entry in ranked_entries:
        tmpl = str(entry.get("route_template") or "")
        if _is_low_priority_catalog_route(
            tmpl,
            methods=entry.get("methods") or (),
            params=entry.get("params") or (),
            is_form=tmpl in forms,
            has_body_template=tmpl in bts,
            risk_score=int(entry.get("risk_score") or 0),
        ):
            if catalog_count >= cap:
                continue
            catalog_count += 1
        kept.append(dict(entry))
    return kept


def _is_low_risk_metadata_entry(entry: Mapping[str, Any], *, single_family: str | None) -> bool:
    """Return True for parameterless read-only dictionary/count/metadata or pure catalog routes."""
    if int(entry.get("risk_score") or 0) >= 8:
        return False
    methods = [str(m or "").strip().upper() for m in (entry.get("methods") or ())]
    if any(m in _WRITE_HTTP_METHODS for m in methods):
        return False
    if entry.get("params"):
        return False
    tmpl = str(entry.get("route_template") or "")
    if "{id}" in tmpl or "{val}" in tmpl:
        return False
    if _is_low_priority_catalog_route(
        tmpl,
        methods=methods,
        params=entry.get("params") or (),
        risk_score=int(entry.get("risk_score") or 0),
    ):
        return True
    tokens = _route_path_tokens(tmpl)
    if tokens & _LOW_RISK_METADATA_TOKENS:
        return True
    return single_family is not None


def _select_diverse_top_entries(
    entries: Sequence[dict[str, Any]],
    *,
    limit: int = 35,
    max_per_family_pass1: int = 3,
    route_key: str = "route_template",
    tie_key: str | None = None,
) -> list[dict[str, Any]]:
    """Select top items via family-diverse risk-bucketed round-robin, then descending risk."""
    eff_limit = max(0, int(limit))
    eff_pass1 = max(0, int(max_per_family_pass1))
    if eff_limit == 0 or not entries:
        return []

    def _entry_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
        return (
            -int(item.get("risk_score") or 0),
            int(item.get("method_rank") or 0),
            str(item.get(tie_key or route_key) or ""),
        )

    sorted_all = sorted(entries, key=_entry_sort_key)
    max_global_score = max(int(item.get("risk_score") or 0) for item in sorted_all)

    top_families = {
        extract_resource_family(str(item.get(route_key) or "/"))
        for item in sorted_all
    }
    single_family = next(iter(top_families)) if len(top_families) == 1 else None

    buckets: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for idx, item in enumerate(sorted_all):
        tmpl = str(item.get(route_key) or "/")
        bkey = extract_resource_family(tmpl)
        if single_family is not None:
            sub = _extract_subfamily_after(tmpl, single_family)
            if sub is not None:
                bkey = sub
        buckets.setdefault(bkey, []).append((idx, item))

    ordered_bucket_keys = sorted(
        buckets,
        key=lambda bkey: (
            -int(buckets[bkey][0][1].get("risk_score") or 0),
            -sum(int(entry.get("risk_score") or 0) for _, entry in buckets[bkey][: max(1, eff_pass1)]),
            bkey,
        ),
    )

    selected: list[dict[str, Any]] = []
    selected_indices: set[int] = set()

    # Pass 1: round-robin up to `eff_pass1` highest-risk entries per bucket,
    # keeping low-risk metadata GET routes out of Pass 1 when high-risk routes exist.
    for round_idx in range(eff_pass1):
        if len(selected) >= eff_limit:
            break
        progressed = False
        for bkey in ordered_bucket_keys:
            bucket = buckets[bkey]
            if round_idx >= len(bucket):
                continue
            cand_idx, cand = bucket[round_idx]
            if max_global_score >= 20 and _is_low_risk_metadata_entry(cand, single_family=single_family):
                continue
            selected.append(cand)
            selected_indices.add(cand_idx)
            progressed = True
            if len(selected) >= eff_limit:
                break
        if not progressed:
            break

    # Pass 2: fill remaining slots strictly by descending risk_score
    if len(selected) < eff_limit:
        for idx, item in enumerate(sorted_all):
            if idx in selected_indices:
                continue
            selected.append(item)
            selected_indices.add(idx)
            if len(selected) >= eff_limit:
                break

    return selected


def _select_diverse_top_routes(
    ranked_entries: Sequence[dict[str, Any]],
    *,
    limit: int = 35,
    max_per_family_pass1: int = 3,
) -> list[dict[str, Any]]:
    """Select top routes ensuring every active family is represented before filling by risk."""
    return _select_diverse_top_entries(
        ranked_entries,
        limit=limit,
        max_per_family_pass1=max_per_family_pass1,
        route_key="route_template",
    )


def _format_assigned_route_line(item: Mapping[str, Any]) -> str:
    """Format an assigned route with compact method tags (e.g. `/api/role/{id} [PUT, DELETE, GET]`)."""
    tmpl = str(item.get("route_template") or "")
    methods = [str(m).strip().upper() for m in (item.get("methods") or ()) if str(m).strip()]
    if methods:
        return f"{tmpl} [{', '.join(methods)}]"
    return tmpl


def _rank_and_select_write_ops(
    write_ops: Sequence[str],
    *,
    cluster_params: Mapping[str, Sequence[str]],
    cluster_schema_hints: Mapping[str, Sequence[str]],
    cluster_body_templates: Mapping[str, Any],
    form_templates: set[str],
    limit: int = 25,
) -> list[str]:
    """Score write operations individually and select a family-diverse high-risk slice."""
    write_entries: list[dict[str, Any]] = []
    for raw_op in write_ops:
        op_str = str(raw_op or "").strip()
        if not op_str:
            continue
        parts = op_str.split(None, 1)
        if len(parts) == 2:
            op_method, op_path = parts[0].strip().upper(), parts[1].strip()
        else:
            op_method, op_path = "POST", op_str
        op_tmpl = route_template_of(op_path)
        op_params = _order_params_by_risk(list(cluster_params.get(op_tmpl) or ()))
        op_hints = [str(h).strip() for h in (cluster_schema_hints.get(op_tmpl) or ()) if str(h).strip()]
        is_form = op_tmpl in form_templates
        has_bt = f"{op_method} {op_tmpl}" in cluster_body_templates
        base_score, _ = score_route_input_risk(
            op_tmpl,
            methods=[op_method],
            params=op_params,
            schema_hints=op_hints,
            is_form=is_form,
            has_body_template=has_bt,
        )
        score = _adjust_route_risk_score(
            op_tmpl,
            base_score=base_score,
            methods=[op_method],
            params=op_params,
            is_form=is_form,
            has_body_template=has_bt,
        )
        write_entries.append({
            "route_template": op_tmpl,
            "op": op_str,
            "methods": [op_method],
            "params": op_params,
            "method_rank": _method_sort_key(op_method)[0],
            "risk_score": score,
        })
    selected = _select_diverse_top_entries(
        write_entries,
        limit=limit,
        max_per_family_pass1=3,
        route_key="route_template",
        tie_key="op",
    )
    return [str(item["op"]) for item in selected]


def cluster_discovered_surface(
    surface_tracker: Any,
    *,
    max_shards: int = 3,
    min_routes_for_sharding: int = 8,
) -> list[SubsystemCluster]:
    """Cluster discovered attack-surface items into balanced `SubsystemCluster`s."""
    eff_max = max(1, int(max_shards))
    eff_min_routes = max(1, int(min_routes_for_sharding))

    family_routes: dict[str, set[str]] = {}
    family_methods: dict[str, dict[str, set[str]]] = {}
    family_writes: dict[str, set[str]] = {}
    family_objects: dict[str, set[str]] = {}
    family_params: dict[str, dict[str, set[str]]] = {}
    family_body_templates: dict[str, dict[str, Any]] = {}
    family_schema_hints: dict[str, dict[str, set[str]]] = {}
    form_templates: set[str] = {
        str(t)
        for t in (getattr(surface_tracker, "discovered_form_templates", ()) or ())
        if str(t).strip()
    }

    def _add_route(raw_path: str, *, method: str = "") -> str | None:
        raw = str(raw_path or "")
        if is_non_endpoint_source_path(raw):
            return None
        tmpl = route_template_of(raw)
        if is_non_endpoint_source_path(tmpl):
            return None
        fam = extract_resource_family(tmpl)
        family_routes.setdefault(fam, set()).add(tmpl)
        if method:
            family_methods.setdefault(fam, {}).setdefault(tmpl, set()).add(str(method).strip().upper())
        return tmpl

    for method, raw_path in getattr(surface_tracker, "discovered_routes", {}):
        _add_route(str(raw_path), method=str(method or "GET"))

    for method, tmpl in getattr(surface_tracker, "visited_method_templates", set()):
        _add_route(str(tmpl), method=str(method or "GET"))

    write_ops_seen: set[tuple[str, str]] = set()
    for method, tmpl in getattr(surface_tracker, "declared_write_ops", set()):
        write_ops_seen.add((str(method or "POST").upper(), str(tmpl)))
    for method, tmpl in getattr(surface_tracker, "discovered_write_ops", {}):
        write_ops_seen.add((str(method or "POST").upper(), str(tmpl)))
    for method, raw_tmpl in write_ops_seen:
        tmpl = _add_route(raw_tmpl, method=method)
        if tmpl is None:
            continue
        fam = extract_resource_family(tmpl)
        family_writes.setdefault(fam, set()).add(f"{method} {tmpl}")

    for concrete_path in getattr(surface_tracker, "discovered_objects", {}):
        raw_obj = str(concrete_path or "")
        if is_non_endpoint_source_path(raw_obj):
            continue
        clean_obj = urlsplit(raw_obj.strip()).path or "/"
        tmpl = _add_route(clean_obj)
        if tmpl is None:
            continue
        fam = extract_resource_family(tmpl)
        family_objects.setdefault(fam, set()).add(clean_obj)

    for raw_tmpl, param_set in getattr(surface_tracker, "discovered_params", {}).items():
        tmpl = _add_route(str(raw_tmpl))
        if tmpl is None:
            continue
        fam = extract_resource_family(tmpl)
        cleaned = {str(p).strip() for p in (param_set or ()) if str(p).strip()}
        if cleaned:
            family_params.setdefault(fam, {}).setdefault(tmpl, set()).update(cleaned)

    for raw_key, tmpl_doc in (getattr(surface_tracker, "discovered_body_templates", {}) or {}).items():
        if not isinstance(raw_key, tuple) or len(raw_key) != 2 or not isinstance(tmpl_doc, dict) or not tmpl_doc:
            continue
        method = str(raw_key[0] or "POST").strip().upper()
        tmpl = _add_route(str(raw_key[1] or ""), method=method)
        if tmpl is None:
            continue
        fam = extract_resource_family(tmpl)
        family_body_templates.setdefault(fam, {})[f"{method} {tmpl}"] = tmpl_doc

    for raw_tmpl, hint_set in (getattr(surface_tracker, "discovered_schema_hints", {}) or {}).items():
        tmpl = _add_route(str(raw_tmpl))
        if tmpl is None:
            continue
        fam = extract_resource_family(tmpl)
        cleaned_hints = {str(h).strip() for h in (hint_set or ()) if str(h).strip()}
        if cleaned_hints:
            family_schema_hints.setdefault(fam, {}).setdefault(tmpl, set()).update(cleaned_hints)

    # Single-umbrella API namespace expansion: when one API family accounts for >=70%
    # of all API routes (e.g. /api/2.0/<namespace>/<subfamily>/...) and has >=2 distinct
    # valid non-ID sub-families, re-bucket it into those sub-families so sharding can
    # balance work across subsystems without expanding non-API UI bloat.
    api_routes_by_family: dict[str, set[str]] = {
        fam: {r for r in routes if _is_api_route(r)}
        for fam, routes in family_routes.items()
    }
    non_root_api_families = [
        fam for fam, ars in api_routes_by_family.items() if ars and fam != "root"
    ]
    total_api_routes = sum(len(ars) for ars in api_routes_by_family.values())
    if total_api_routes > 0 and non_root_api_families:
        non_root_api_families.sort(key=lambda fam: (-len(api_routes_by_family[fam]), fam))
        umbrella = non_root_api_families[0]
        umbrella_api_routes = api_routes_by_family[umbrella]
        if (
            len(umbrella_api_routes) * 10 >= total_api_routes * 7
            and (len(non_root_api_families) == 1 or len(family_routes) < eff_max)
            and len(family_routes.get(umbrella, ())) >= 4
        ):
            api_subfamilies = {
                sub
                for r in umbrella_api_routes
                if (sub := _extract_subfamily_after(r, umbrella)) is not None
            }
            if len(api_subfamilies) >= 2:
                def _retarget(route_path: str) -> str:
                    sub = _extract_subfamily_after(route_path, umbrella)
                    return sub if sub is not None else umbrella

                u_routes = family_routes.pop(umbrella, set())
                u_methods = family_methods.pop(umbrella, {})
                u_writes = family_writes.pop(umbrella, set())
                u_objects = family_objects.pop(umbrella, set())
                u_params = family_params.pop(umbrella, {})
                u_bt = family_body_templates.pop(umbrella, {})
                u_sh = family_schema_hints.pop(umbrella, {})

                for r in u_routes:
                    family_routes.setdefault(_retarget(r), set()).add(r)
                for tmpl, mset in u_methods.items():
                    if mset:
                        family_methods.setdefault(_retarget(tmpl), {}).setdefault(tmpl, set()).update(mset)
                for w in u_writes:
                    w_path = w.split(" ", 1)[1] if " " in w else w
                    family_writes.setdefault(_retarget(w_path), set()).add(w)
                for o in u_objects:
                    family_objects.setdefault(_retarget(o), set()).add(o)
                for tmpl, pset in u_params.items():
                    if pset:
                        family_params.setdefault(_retarget(tmpl), {}).setdefault(tmpl, set()).update(pset)
                for op_key, tmpl_doc in u_bt.items():
                    op_path = op_key.split(" ", 1)[1] if " " in op_key else op_key
                    family_body_templates.setdefault(_retarget(op_path), {})[op_key] = tmpl_doc
                for tmpl, hset in u_sh.items():
                    if hset:
                        family_schema_hints.setdefault(_retarget(tmpl), {}).setdefault(tmpl, set()).update(hset)

    all_families = sorted(family_routes)
    all_routes_raw = sorted({r for rs in family_routes.values() for r in rs})
    all_writes = sorted({w for ws in family_writes.values() for w in ws})
    all_objects = sorted({o for os_ in family_objects.values() for o in os_})
    all_methods: dict[str, set[str]] = {}
    for mmap in family_methods.values():
        for tmpl, mset in mmap.items():
            if mset:
                all_methods.setdefault(tmpl, set()).update(mset)
    all_params: dict[str, list[str]] = {}
    for pmap in family_params.values():
        for tmpl, pset in pmap.items():
            if pset:
                all_params[tmpl] = sorted(set(all_params.get(tmpl, [])) | pset)
    all_body_templates: dict[str, Any] = {}
    for btmap in family_body_templates.values():
        for op_key, tmpl_doc in btmap.items():
            all_body_templates[op_key] = tmpl_doc
    all_schema_hints: dict[str, list[str]] = {}
    for shmap in family_schema_hints.values():
        for tmpl, hset in shmap.items():
            if hset:
                all_schema_hints[tmpl] = sorted(set(all_schema_hints.get(tmpl, [])) | hset)

    if eff_max <= 1 or len(all_routes_raw) < eff_min_routes or len(all_families) <= 1:
        single_name = all_families[0] if len(all_families) == 1 else "all"
        ranked_all = _rank_routes_by_input_risk(
            all_routes_raw,
            write_ops=all_writes,
            params=all_params,
            body_templates=all_body_templates,
            schema_hints=all_schema_hints,
            methods_by_route=all_methods,
            form_templates=form_templates,
        )
        all_bt_routes = {
            route_template_of(op_key.split(" ", 1)[1])
            for op_key in all_body_templates
            if " " in op_key
        }
        capped_all = _cap_catalog_cluster_routes(
            ranked_all,
            form_templates=form_templates,
            body_template_routes=all_bt_routes,
        )
        all_routes = [str(item["route_template"]) for item in capped_all]
        return [
            SubsystemCluster(
                shard_id="shard-1",
                name=single_name,
                families=all_families,
                routes=all_routes,
                write_ops=all_writes,
                objects=all_objects,
                params=dict(sorted(all_params.items())),
                body_templates=dict(sorted(all_body_templates.items())),
                schema_hints=dict(sorted(all_schema_hints.items())),
                methods_by_route={
                    tmpl: sorted(mset, key=_method_sort_key)
                    for tmpl, mset in sorted(all_methods.items())
                },
            )
        ]

    # Weight interactive/API/functional signals (write ops, concrete objects, params, API routes,
    # auth/account/payment/cart/search routes) higher than raw route counts, and cap pure read-only
    # non-API / catalog route bloat so storefront templates cannot monopolize shards.
    scored_families: list[tuple[int, int, int, int, int, str]] = []
    for fam in all_families:
        f_routes = family_routes.get(fam, set())
        w_cnt = len(family_writes.get(fam, ()))
        o_cnt = len(family_objects.get(fam, ()))
        p_cnt = sum(len(ps) for ps in family_params.get(fam, {}).values())
        api_r_cnt = sum(1 for r in f_routes if _is_api_route(r))
        non_api_r_cnt = len(f_routes) - api_r_cnt
        interactive_score = (w_cnt * 4) + (o_cnt * 3) + (p_cnt * 2)
        api_route_score = min(api_r_cnt, 8) * 3
        functional_score = 0
        for r in f_routes:
            toks = _route_path_tokens(r)
            if toks & _SECURITY_BUCKET_TIER1_TOKENS:
                functional_score = max(functional_score, 6)
            elif toks & _SECURITY_BUCKET_TIER2_TOKENS:
                functional_score = max(functional_score, 3)
        if fam == "catalog" and interactive_score == 0 and api_r_cnt == 0:
            non_api_route_score = min(non_api_r_cnt, 1)
            eff_r_cnt = min(non_api_r_cnt, 1)
        else:
            non_api_route_score = (
                min(non_api_r_cnt, 2)
                if (interactive_score == 0 and api_r_cnt == 0)
                else min(non_api_r_cnt, 4)
            )
            eff_r_cnt = api_r_cnt + min(non_api_r_cnt, 3)
        richness = interactive_score + api_route_score + non_api_route_score + functional_score
        is_non_catalog = 1 if fam not in {"catalog", "root"} else 0
        scored_families.append((richness, is_non_catalog, interactive_score, api_r_cnt, eff_r_cnt, fam))

    scored_families.sort(key=lambda item: (-item[0], -item[1], -item[2], -item[3], -item[4], item[5]))

    num_shards = min(eff_max, len(scored_families))
    bins: list[dict[str, Any]] = [
        {"idx": i, "weight": 0, "routes": 0, "families": []}
        for i in range(num_shards)
    ]

    for richness, _is_non_cat, _interactive, _api_r, eff_r_cnt, fam in scored_families:
        target_bin = min(bins, key=lambda b: (b["weight"], b["routes"], b["idx"]))
        target_bin["families"].append(fam)
        target_bin["weight"] += richness
        target_bin["routes"] += eff_r_cnt

    clusters: list[SubsystemCluster] = []
    for i, b in enumerate(bins, start=1):
        fams = list(b["families"])
        if not fams:
            continue
        c_routes_raw = sorted({r for fam in fams for r in family_routes.get(fam, ())})
        c_writes = sorted({w for fam in fams for w in family_writes.get(fam, ())})
        c_objects = sorted({o for fam in fams for o in family_objects.get(fam, ())})
        c_methods: dict[str, set[str]] = {}
        c_params: dict[str, list[str]] = {}
        c_body_templates: dict[str, Any] = {}
        c_schema_hints: dict[str, list[str]] = {}
        for fam in fams:
            for tmpl, mset in family_methods.get(fam, {}).items():
                if mset:
                    c_methods.setdefault(tmpl, set()).update(mset)
            for tmpl, pset in family_params.get(fam, {}).items():
                if pset:
                    c_params[tmpl] = sorted(pset)
            for op_key, tmpl_doc in family_body_templates.get(fam, {}).items():
                c_body_templates[op_key] = tmpl_doc
            for tmpl, hset in family_schema_hints.get(fam, {}).items():
                if hset:
                    c_schema_hints[tmpl] = sorted(set(c_schema_hints.get(tmpl, [])) | hset)
        ranked_cluster = _rank_routes_by_input_risk(
            c_routes_raw,
            write_ops=c_writes,
            params=c_params,
            body_templates=c_body_templates,
            schema_hints=c_schema_hints,
            methods_by_route=c_methods,
            form_templates=form_templates,
        )
        c_bt_routes = {
            route_template_of(op_key.split(" ", 1)[1])
            for op_key in c_body_templates
            if " " in op_key
        }
        capped_cluster = _cap_catalog_cluster_routes(
            ranked_cluster,
            form_templates=form_templates,
            body_template_routes=c_bt_routes,
        )
        c_routes = [str(item["route_template"]) for item in capped_cluster]
        c_name = "+".join(fams[:3]) + (f"+{len(fams) - 3}" if len(fams) > 3 else "")
        clusters.append(
            SubsystemCluster(
                shard_id=f"shard-{i}",
                name=c_name,
                families=sorted(fams),
                routes=c_routes,
                write_ops=c_writes,
                objects=c_objects,
                params=dict(sorted(c_params.items())),
                body_templates=dict(sorted(c_body_templates.items())),
                schema_hints=dict(sorted(c_schema_hints.items())),
                methods_by_route={
                    tmpl: sorted(mset, key=_method_sort_key)
                    for tmpl, mset in sorted(c_methods.items())
                },
            )
        )
    return clusters


def build_shard_prompts(
    cluster: SubsystemCluster,
    *,
    base_system_prompt: str,
    bootstrap_findings: Sequence[dict[str, Any]] = (),
    receipts: Any | None = None,
    state_banner: str = "",
    surface_tracker: Any | None = None,
) -> tuple[str, str]:
    """Construct focused system and initial user prompts for one subsystem shard."""
    findings_lines: list[str] = []
    for f in list(bootstrap_findings)[:30]:
        if not isinstance(f, dict):
            continue
        ev = str(f.get("evidence_value") or "")[:70]
        findings_lines.append(
            f"  - {f.get('finding_id', '')} [{f.get('class_type', '')}] "
            f"{f.get('method', '')} {f.get('path') or f.get('url', '')} "
            f"actor={f.get('actor_alias') or f.get('actor', '')} ev={ev!r}"
        )
    findings_block = "\n".join(findings_lines) if findings_lines else "  (none yet)"

    methods_map: dict[str, set[str]] = {
        str(tmpl): {str(m).strip().upper() for m in mlist if str(m).strip()}
        for tmpl, mlist in (getattr(cluster, "methods_by_route", {}) or {}).items()
        if mlist
    }
    form_templates: set[str] = {
        str(t)
        for t in (getattr(surface_tracker, "discovered_form_templates", ()) or ())
        if str(t).strip()
    }
    bt_routes = {
        route_template_of(op_key.split(" ", 1)[1])
        for op_key in (getattr(cluster, "body_templates", {}) or {})
        if isinstance(op_key, str) and " " in op_key
    }
    ranked_entries = _cap_catalog_cluster_routes(
        _rank_routes_by_input_risk(
            cluster.routes,
            write_ops=cluster.write_ops,
            params=cluster.params,
            body_templates=cluster.body_templates,
            schema_hints=cluster.schema_hints,
            methods_by_route=methods_map or None,
            form_templates=form_templates,
            surface_tracker=surface_tracker,
        ),
        form_templates=form_templates,
        body_template_routes=bt_routes,
    )
    risk_score_by_route = {
        str(item["route_template"]): int(item["risk_score"])
        for item in ranked_entries
    }
    methods_by_tmpl: dict[str, list[str]] = {
        str(item["route_template"]): list(item.get("methods") or ())
        for item in ranked_entries
    }
    ordered_routes = [str(item["route_template"]) for item in ranked_entries]
    selected_route_entries = _select_diverse_top_routes(
        ranked_entries,
        limit=35,
        max_per_family_pass1=3,
    )
    route_lines = [_format_assigned_route_line(item) for item in selected_route_entries]
    if len(ordered_routes) > len(selected_route_entries):
        omitted_count = len(ordered_routes) - len(selected_route_entries)
        route_lines.append(
            f"(+{omitted_count} of {len(ordered_routes)} total lower-priority routes omitted; "
            "prioritize high-risk mutating/auth/ID routes above first)"
        )

    is_large_shard = len(ordered_routes) > 35
    if cluster.write_ops and (is_large_shard or len(cluster.write_ops) > 25):
        selected_write_ops = _rank_and_select_write_ops(
            cluster.write_ops,
            cluster_params=cluster.params,
            cluster_schema_hints=cluster.schema_hints,
            cluster_body_templates=cluster.body_templates,
            form_templates=form_templates,
            limit=25,
        )
    else:
        selected_write_ops = list(cluster.write_ops[:25])

    ordered_param_items = sorted(
        cluster.params.items(),
        key=lambda kv: (-risk_score_by_route.get(route_template_of(kv[0]), 0), kv[0]),
    )
    if ordered_param_items and (is_large_shard or len(ordered_param_items) > 20):
        param_entries = [
            {
                "route_template": route_template_of(tmpl),
                "raw_tmpl": tmpl,
                "pnames": pnames,
                "methods": methods_by_tmpl.get(route_template_of(tmpl), []),
                "params": list(pnames),
                "risk_score": risk_score_by_route.get(route_template_of(tmpl), 0),
            }
            for tmpl, pnames in ordered_param_items
        ]
        selected_param_entries = _select_diverse_top_entries(
            param_entries,
            limit=20,
            max_per_family_pass1=3,
            route_key="route_template",
            tie_key="raw_tmpl",
        )
        selected_param_items = [
            (str(entry["raw_tmpl"]), entry["pnames"])
            for entry in selected_param_entries
        ]
    else:
        selected_param_items = ordered_param_items[:20]

    params_lines = [
        f"  - {tmpl}: {', '.join(_order_params_by_risk(pnames)[:10])}"
        for tmpl, pnames in selected_param_items
    ]
    has_path_params = any(
        str(p).startswith("path:")
        for pnames in cluster.params.values()
        for p in pnames
    )
    scope_sections = [
        f"SUBSYSTEM SHARD SCOPE ({cluster.shard_id}: {cluster.name}):",
        f"- Assigned resource families: {', '.join(cluster.families) or '(all)'}",
        "- Focus strictly on testing your assigned routes, concrete objects, parameters, and write operations thoroughly. "
        "Do NOT duplicate work on unrelated subsystems or already-verified bootstrap findings.",
        "- Assigned routes:\n  " + ("\n  ".join(route_lines) if route_lines else "(none)"),
    ]
    if selected_write_ops:
        scope_sections.append("- Assigned write operations:\n  " + "\n  ".join(selected_write_ops))
    if any(_is_virgin_state_action_path(r) for r in (*ordered_routes, *cluster.write_ops)):
        scope_sections.append(
            "- Virgin-state race priority: run concurrent_check BEFORE sequential single mutations on primary actors "
            "for claim/redeem/promo/coupon/bonus actions so single-use state is not consumed prematurely."
        )
    if cluster.objects:
        scope_sections.append("- Assigned concrete objects:\n  " + "\n  ".join(cluster.objects[:30]))
    if params_lines:
        params_header = "- Assigned parameters"
        if has_path_params:
            params_header += (
                " (treat `path:...` entries as path-embedded inputs — test path traversal, "
                "URL/redirect handling, and injection by substituting the path segment/value)"
            )
        scope_sections.append(params_header + ":\n" + "\n".join(params_lines))
    if cluster.body_templates:
        bt_lines: list[str] = []
        bt_chars = 0
        for op_key, tmpl_doc in sorted(cluster.body_templates.items())[:10]:
            try:
                compact = json.dumps(tmpl_doc, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                continue
            if len(compact) > 240:
                compact = compact[:237] + "..."
            line = f"  - {op_key}: {compact}"
            if bt_lines and bt_chars + len(line) > 1800:
                break
            bt_lines.append(line)
            bt_chars += len(line)
        if bt_lines:
            scope_sections.append(
                "- Observed working JSON body templates (mutate leaf values rather than inventing schemas):\n"
                + "\n".join(bt_lines)
            )
    if cluster.schema_hints:
        sh_lines: list[str] = []
        sh_chars = 0
        for tmpl, hints in sorted(cluster.schema_hints.items())[:15]:
            clean_hints = [str(h).strip() for h in (hints or []) if str(h).strip()][:8]
            if not clean_hints:
                continue
            line = f"  - {tmpl}: {', '.join(clean_hints)}"
            if sh_lines and sh_chars + len(line) > 1200:
                break
            sh_lines.append(line)
            sh_chars += len(line)
        if sh_lines:
            scope_sections.append(
                "- Validation schema hints (from 400/422):\n"
                + "\n".join(sh_lines)
            )
    scope_sections.append(f"- Already-verified bootstrap findings (DO NOT DUPLICATE):\n{findings_block}")
    scope_sections.append(
        "- Breadth & hygiene: cover all assigned routes/sub-tabs (avoid >5 turns on one static/upload endpoint while assigned interactive routes remain unvisited); never call `/reboot`, `/restart`, `/shutdown` or overwrite active actor credentials."
    )
    scope_sections.append(
        "- QA edge checks: verify `weak_credentials` (with invalid-login baseline), `.svg` upload `Content-Type` readback, `%252F` double-encoded path checks on `403`, and `%2F` percent-encoded slashes on nested `404` paths."
    )
    scope_sections.append(
        "- Call `record_finding` immediately as each vulnerability is confirmed, and call `finish` when your assigned subsystem slice is complete."
    )

    sys_prompt = base_system_prompt.rstrip() + "\n\n" + "\n".join(scope_sections)

    must_test_candidates = [
        item
        for item in ranked_entries
        if not is_logout_or_destructive_route(str(item["route_template"]))
        and (
            int(item["risk_score"]) >= _HIGH_RISK_SCORE_THRESHOLD
            or (bool(item["params"]) and int(item["risk_score"]) >= 18)
        )
    ]
    unprobed_must = [item for item in must_test_candidates if not item.get("actively_probed")]
    probed_must = [item for item in must_test_candidates if item.get("actively_probed")]
    selected_must = _select_diverse_top_routes(unprobed_must, limit=6, max_per_family_pass1=2)
    if len(selected_must) < 6 and probed_must:
        selected_must.extend(
            _select_diverse_top_routes(probed_must, limit=6 - len(selected_must), max_per_family_pass1=2)
        )
    must_test_lines: list[str] = []
    for item in selected_must[:6]:
        methods_str = ",".join(item.get("methods") or ["GET"])
        route_str = str(item["route_template"])
        p_list = list(item.get("params") or [])[:6]
        params_part = f" | params: {', '.join(p_list)}" if p_list else ""
        must_test_lines.append(f"  - {methods_str} {route_str}{params_part}")
    must_test_block = (
        "\n[MUST-TEST HIGH-RISK INPUTS] Actively probe these assigned parameterized/upload/auth routes before calling `finish`:\n"
        + "\n".join(must_test_lines)
        if must_test_lines
        else ""
    )

    cluster_fams = set(cluster.families)
    cluster_routes = set(ordered_routes)
    receipt_lines: list[str] = []
    if receipts is not None and hasattr(receipts, "list_ids") and hasattr(receipts, "get"):
        seen_sig: set[tuple[str, str, str, int]] = set()
        for rid in receipts.list_ids():
            try:
                rec = receipts.get(rid)
            except Exception:
                continue
            path_or_url = str(rec.get("path") or rec.get("url") or "/")
            if is_non_endpoint_source_path(path_or_url):
                continue
            if cluster_fams:
                rec_fam = extract_resource_family(path_or_url)
                rec_sub = _extract_subfamily_after(path_or_url, rec_fam)
                rec_tmpl = route_template_of(path_or_url)
                if (
                    rec_fam not in cluster_fams
                    and rec_tmpl not in cluster_routes
                    and (rec_sub is None or rec_sub not in cluster_fams)
                ):
                    continue
            actor = str(rec.get("actor") or "anon")
            method = str(rec.get("method") or "GET")
            parsed = urlsplit(str(rec.get("url") or path_or_url))
            short_path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
            if len(short_path) > 72:
                short_path = short_path[:69] + "..."
            status = int(rec.get("status") or 0)
            sig = (actor, method, short_path, status)
            if sig in seen_sig:
                continue
            seen_sig.add(sig)
            rlen = int(rec.get("response_length") or len(str(rec.get("body") or "")))
            receipt_lines.append(f"  {rid} {actor} {method} {short_path} -> {status} ({rlen}B)")
            if len(receipt_lines) >= 30:
                break

    receipt_block = (
        "\n[RELEVANT BOOTSTRAP RECEIPTS]\n" + "\n".join(receipt_lines)
        if receipt_lines
        else "\n[RELEVANT BOOTSTRAP RECEIPTS] none recorded yet for these families"
    )
    user_prompt = (
        f"Execute deep security verification for subsystem shard `{cluster.shard_id}` "
        f"(families: {', '.join(cluster.families) or cluster.name}). "
        "Reuse relevant bootstrap receipts with `replay_as` where helpful, test all assigned objects across peers/tenants, "
        "probe all assigned parameters and write operations, record verified findings immediately, and call `finish` when done."
        f"{must_test_block}"
        f"{receipt_block}"
        f"{state_banner}"
    )
    return sys_prompt, user_prompt


_PROSE_STOPWORDS = frozenset({
    "use",
    "the",
    "and",
    "for",
    "from",
    "with",
    "not",
    "already",
    "missing",
    "denied",
    "blocked",
    "required",
    "requires",
    "returned",
    "failed",
    "found",
    "none",
    "null",
    "was",
    "were",
    "are",
    "is",
    "can",
    "may",
    "will",
    "this",
    "that",
    "another",
    "other",
    "same",
    "only",
    "via",
    "into",
    "when",
    "after",
    "before",
    "check",
    "test",
})


def _is_target_own_origin_url(url_str: str, base_url: str) -> bool:
    """Return True if `url_str` points to the target's own origin (same scheme/netloc or same loopback port)."""
    if not base_url:
        return False
    parsed_base = urlsplit(base_url)
    if not parsed_base.netloc:
        return False
    try:
        parsed_u = urlsplit(url_str)
        u_port = parsed_u.port
        base_port = parsed_base.port
    except ValueError:
        return False
    if (parsed_u.scheme.lower(), parsed_u.netloc.lower()) == (
        parsed_base.scheme.lower(),
        parsed_base.netloc.lower(),
    ):
        return True
    base_host = (parsed_base.hostname or "").lower()
    u_host = (parsed_u.hostname or "").lower()
    if (
        base_port is not None
        and u_port == base_port
        and base_host in _LOOPBACK_HOSTS
        and u_host in _LOOPBACK_HOSTS
    ):
        return True
    return False


def _extract_internal_urls_from_text(
    text: str,
    *,
    base_url: str,
    dst: list[str],
    seen: set[str],
    limit: int = 20,
) -> None:
    """Scan `text` for distinct-port loopback/internal service URLs."""
    if not text or len(dst) >= limit:
        return
    for match in _INTERNAL_URL_RE.finditer(text):
        cand = match.group(0).rstrip(",;.`'\"")
        if cand.endswith(")") and "(" not in cand:
            cand = cand[:-1]
        if not cand or "<redacted" in cand.lower():
            continue
        try:
            parsed_cand = urlsplit(cand)
            _ = parsed_cand.port
        except ValueError:
            continue
        if _is_target_own_origin_url(cand, base_url):
            continue
        if cand not in seen:
            seen.add(cand)
            dst.append(cand)
            if len(dst) >= limit:
                break


def _is_informative_synthesis_key(key: str) -> bool:
    """Return True for non-password informative JSON/header keys useful for cross-shard chaining."""
    raw = str(key or "").strip()
    if not raw:
        return False
    snake = _CAMEL_SPLIT_RE.sub(r"\1_\2", raw).lower()
    if "password" in snake or "passwd" in snake or "passphrase" in snake:
        return False
    tokens = [tok for tok in _KEY_TOKEN_SPLIT_RE.split(snake) if tok]
    if any(tok in _SYNTHESIS_PASSWORD_KEY_TOKENS for tok in tokens):
        return False
    return any(tok in _SYNTHESIS_INFO_KEY_TOKENS for tok in tokens)


def _format_synthesis_scalar(key_path: str, leaf_key: str, val: Any) -> str | None:
    """Format a scalar operational value into `key=value`, filtering empty/redacted/trivial values."""
    if val is None or isinstance(val, (dict, list)) or val is False:
        return None
    if val is True:
        return f"{key_path}=true"
    leaf_low = leaf_key.strip().lower()
    if isinstance(val, (int, float)):
        if leaf_low == "code" and val in _SYNTHESIS_TRIVIAL_CODE_INTS:
            return None
        text = str(val)
    else:
        text = str(val).strip()
    if not text or len(text) > 120 or "<redacted" in text.lower():
        return None
    low = text.lower()
    if low in {"none", "null", "n/a", "false", "undefined"}:
        return None
    if leaf_low == "code" and low in _SYNTHESIS_TRIVIAL_CODE_STRS:
        return None
    return f"{key_path}={text}"


def _append_extracted_value(
    entry: str | None,
    *,
    dst: list[str],
    seen: set[str],
    limit: int = 25,
) -> None:
    if entry is None or len(dst) >= limit:
        return
    if entry not in seen:
        seen.add(entry)
        dst.append(entry)


def _extract_json_synthesis_values(
    obj: Any,
    *,
    dst: list[str],
    seen: set[str],
    limit: int = 25,
    prefix: str = "",
    leaf_key: str = "",
    depth: int = 0,
) -> None:
    """Recursively collect concise informative `key=value` items from parsed JSON."""
    if len(dst) >= limit or depth > 5:
        return
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:40]:
            k_str = str(k or "").strip()
            if not k_str:
                continue
            next_prefix = f"{prefix}.{k_str}" if prefix else k_str
            if isinstance(v, (dict, list)):
                _extract_json_synthesis_values(
                    v,
                    dst=dst,
                    seen=seen,
                    limit=limit,
                    prefix=next_prefix,
                    leaf_key=k_str,
                    depth=depth + 1,
                )
            elif _is_informative_synthesis_key(k_str):
                _append_extracted_value(
                    _format_synthesis_scalar(next_prefix, k_str, v),
                    dst=dst,
                    seen=seen,
                    limit=limit,
                )
            if len(dst) >= limit:
                break
    elif isinstance(obj, list):
        scalar_count = 0
        for item in obj[:25]:
            if isinstance(item, (dict, list)):
                _extract_json_synthesis_values(
                    item,
                    dst=dst,
                    seen=seen,
                    limit=limit,
                    prefix=prefix,
                    leaf_key=leaf_key,
                    depth=depth + 1,
                )
            elif leaf_key and _is_informative_synthesis_key(leaf_key) and scalar_count < 5:
                _append_extracted_value(
                    _format_synthesis_scalar(prefix, leaf_key, item),
                    dst=dst,
                    seen=seen,
                    limit=limit,
                )
                scalar_count += 1
            if len(dst) >= limit:
                break


def _extract_text_synthesis_values(
    text: str,
    *,
    dst: list[str],
    seen: set[str],
    limit: int = 25,
) -> None:
    """Extract informative JSON snippets and explicit key=value / header: value items from text."""
    if not text or len(dst) >= limit:
        return
    decoder = json.JSONDecoder()
    pos = 0
    decodes = 0
    while pos < len(text) and decodes < 10 and len(dst) < limit:
        brace_idx = text.find("{", pos)
        if brace_idx == -1:
            break
        try:
            parsed, end_idx = decoder.raw_decode(text, brace_idx)
        except ValueError:
            pos = brace_idx + 1
            continue
        decodes += 1
        if isinstance(parsed, dict):
            _extract_json_synthesis_values(parsed, dst=dst, seen=seen, limit=limit)
        pos = max(brace_idx + 1, end_idx)

    if len(dst) >= limit:
        return
    for match in _TEXT_KV_RE.finditer(text):
        k_raw, quote, v_raw = match.group(1), match.group(2), match.group(3)
        if not _is_informative_synthesis_key(k_raw):
            continue
        if not quote and v_raw.lower() in _PROSE_STOPWORDS:
            continue
        _append_extracted_value(
            _format_synthesis_scalar(k_raw, k_raw, v_raw),
            dst=dst,
            seen=seen,
            limit=limit,
        )
        if len(dst) >= limit:
            break


def _is_auth_utility_endpoint(path_or_url: str) -> bool:
    raw_path = urlsplit(str(path_or_url or "").strip()).path or "/"
    segments = [seg.strip().lower() for seg in raw_path.split("/") if seg.strip()]
    return any(seg in _AUTH_UTILITY_SEGMENTS for seg in segments)


def _iter_finding_texts(finding: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    for key in ("summary", "evidence", "excerpt"):
        val = finding.get(key)
        if isinstance(val, str) and val.strip():
            texts.append(val)
    ev_val = finding.get("evidence_value")
    if isinstance(ev_val, str) and ev_val.strip():
        texts.append(ev_val)
    for item in (finding.get("evidence_excerpts") or ()):
        if isinstance(item, dict):
            ex = item.get("excerpt")
            if isinstance(ex, str) and ex.strip():
                texts.append(ex)
    return texts


def collect_cross_shard_synthesis_context(
    *,
    shard_results: Sequence[dict[str, Any]],
    findings: Sequence[dict[str, Any]],
    receipts: Any,
    surface_tracker: Any,
    actor_summaries: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Deterministically gather cross-shard chaining artifacts, capabilities, blockers, and untested/blocked writes."""
    _ = actor_summaries
    base_url = str(getattr(surface_tracker, "base_url", "") or "").strip()

    internal_urls: list[str] = []
    seen_urls: set[str] = set()
    extracted_values: list[str] = []
    seen_values: set[str] = set()
    auth_capabilities: list[str] = []
    seen_caps: set[str] = set()
    compact_findings: list[dict[str, str]] = []

    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("finding_id") or "")
        cls = str(f.get("class_type") or "").strip().lower()
        method = str(f.get("method") or "").strip().upper()
        path = str(f.get("path") or f.get("url") or "").strip()
        actor = str(f.get("actor_alias") or f.get("actor") or "").strip()
        ev = str(f.get("evidence_value") or "").strip()
        summary = str(f.get("summary") or "").strip()
        title = str(f.get("title") or "").strip()

        safe_ev = "" if "<redacted" in ev.lower() else ev[:120]
        compact_findings.append({
            "finding_id": fid,
            "class_type": cls,
            "method": method,
            "path": path,
            "actor": actor,
            "evidence_value": safe_ev,
            "summary": summary[:200],
        })

        for txt in _iter_finding_texts(f):
            _extract_internal_urls_from_text(
                txt,
                base_url=base_url,
                dst=internal_urls,
                seen=seen_urls,
            )
            _extract_text_synthesis_values(
                txt,
                dst=extracted_values,
                seen=seen_values,
            )

        if (
            safe_ev
            and 4 <= len(safe_ev) <= 120
            and not safe_ev.startswith(("/", "<"))
            and not any(safe_ev in existing for existing in extracted_values)
        ):
            _append_extracted_value(
                f"finding_evidence={safe_ev}",
                dst=extracted_values,
                seen=seen_values,
            )

        if cls in _SYNTHESIS_CAPABILITY_CLASSES:
            cap = f"{cls} ({_SYNTHESIS_CAPABILITY_CLASSES[cls]}): {method} {path}".strip()
            if actor:
                cap += f" as {actor}"
            if cap not in seen_caps and len(auth_capabilities) < 20:
                seen_caps.add(cap)
                auth_capabilities.append(cap)
        else:
            combined_low = f"{title} {summary} {f.get('evidence', '')}".lower()
            if any(hint in combined_low for hint in _SYNTHESIS_CAPABILITY_TEXT_HINTS):
                cap = f"{cls or 'capability'}: {method} {path} - {(title or summary)[:90]}".strip()
                if cap not in seen_caps and len(auth_capabilities) < 20:
                    seen_caps.add(cap)
                    auth_capabilities.append(cap)

    blockers: list[str] = []
    seen_blockers: set[str] = set()
    for sres in shard_results:
        if not isinstance(sres, dict):
            continue
        sid = str(sres.get("shard_id") or "").strip()
        candidates: list[str] = []
        for area in (sres.get("untested_areas") or ()):
            candidates.append(str(area))
        finish_text = str(sres.get("finish_summary") or "")
        if finish_text:
            candidates.extend(finish_text.splitlines())

        for raw_line in candidates:
            clean = " ".join(raw_line.split())
            if not clean:
                continue
            low = clean.lower()
            if not any(kw in low for kw in _SYNTHESIS_BLOCKER_KEYWORDS):
                continue
            _extract_internal_urls_from_text(
                clean,
                base_url=base_url,
                dst=internal_urls,
                seen=seen_urls,
            )
            formatted = f"[{sid}] {clean}" if (sid and not clean.startswith(f"[{sid}]")) else clean
            if len(formatted) > 260:
                formatted = formatted[:257] + "..."
            norm_key = formatted.lower()
            if norm_key not in seen_blockers:
                seen_blockers.add(norm_key)
                blockers.append(formatted)
                if len(blockers) >= 20:
                    break
        if len(blockers) >= 20:
            break

    untested_writes_and_blocked: list[str] = []
    seen_write_keys: set[tuple[str, str]] = set()
    if surface_tracker is not None:
        untested_fn = getattr(surface_tracker, "untested_write_ops", None)
        raw_write_labels: list[str] = []
        if callable(untested_fn):
            raw_write_labels = [str(x) for x in (untested_fn() or ())]
        else:
            tested_w = {
                (str(m).upper(), str(t))
                for m, t in (getattr(surface_tracker, "tested_write_ops", ()) or ())
            }
            seen_cand: set[tuple[str, str]] = set()
            for m, t in (getattr(surface_tracker, "declared_write_ops", ()) or ()):
                pair = (str(m or "POST").upper(), str(t))
                if pair not in tested_w and pair not in seen_cand:
                    seen_cand.add(pair)
                    raw_write_labels.append(f"{pair[0]} {pair[1]}")
            for m, t in (getattr(surface_tracker, "discovered_write_ops", {}) or {}):
                pair = (str(m or "POST").upper(), str(t))
                if pair not in tested_w and pair not in seen_cand:
                    seen_cand.add(pair)
                    raw_write_labels.append(f"{pair[0]} {pair[1]}")

        for label in raw_write_labels:
            parts = label.strip().split(None, 1)
            if len(parts) != 2:
                continue
            w_method, w_path = parts[0].upper(), parts[1].strip()
            w_key = (w_method, route_template_of(w_path))
            if w_key not in seen_write_keys:
                seen_write_keys.add(w_key)
                untested_writes_and_blocked.append(f"{w_method} {w_path}")
                if len(untested_writes_and_blocked) >= 25:
                    break

    write_2xx_tmpls: set[tuple[str, str]] = set()
    write_401_403: dict[tuple[str, str], tuple[str, int]] = {}
    any_2xx_paths: set[str] = set()
    any_401_403_paths: set[str] = set()
    recent_2xx_receipts: list[dict[str, Any]] = []

    if receipts is not None and hasattr(receipts, "list_ids") and hasattr(receipts, "get"):
        all_rids = list(receipts.list_ids())
        for rid in all_rids[-500:]:
            try:
                rec = receipts.get(rid)
            except Exception:
                continue
            if not isinstance(rec, dict):
                continue
            status = int(rec.get("status") or 0)
            method = str(rec.get("method") or "GET").strip().upper()
            raw_path = str(rec.get("path") or rec.get("url") or "/")

            if 200 <= status < 300:
                recent_2xx_receipts.append(rec)

            if not is_non_endpoint_source_path(raw_path) and not _is_auth_utility_endpoint(raw_path):
                tmpl = route_template_of(raw_path)
                if 200 <= status < 300:
                    any_2xx_paths.add(tmpl)
                elif status in {401, 403}:
                    any_401_403_paths.add(tmpl)

            if (
                method in _WRITE_HTTP_METHODS
                and not is_non_endpoint_source_path(raw_path)
                and not _is_auth_utility_endpoint(raw_path)
            ):
                tmpl = route_template_of(raw_path)
                w_key = (method, tmpl)
                if 200 <= status < 300:
                    write_2xx_tmpls.add(w_key)
                elif status in {401, 403} and w_key not in write_401_403:
                    concrete_path = urlsplit(str(rec.get("url") or raw_path)).path or "/"
                    write_401_403[w_key] = (concrete_path, status)

    for w_key, (sample_path, status) in write_401_403.items():
        if w_key in write_2xx_tmpls or w_key in seen_write_keys:
            continue
        if len(untested_writes_and_blocked) >= 25:
            break
        seen_write_keys.add(w_key)
        untested_writes_and_blocked.append(f"{w_key[0]} {sample_path} (observed {status}, no 2xx)")

    for rec in recent_2xx_receipts[-150:]:
        resp_loc = str(rec.get("redirect_location") or "")
        if resp_loc:
            _extract_internal_urls_from_text(
                resp_loc,
                base_url=base_url,
                dst=internal_urls,
                seen=seen_urls,
            )
        resp_hdrs = rec.get("response_headers") or {}
        if isinstance(resp_hdrs, dict):
            for hval in resp_hdrs.values():
                if isinstance(hval, str) and hval:
                    _extract_internal_urls_from_text(
                        hval,
                        base_url=base_url,
                        dst=internal_urls,
                        seen=seen_urls,
                    )
        body = str(rec.get("body") or "")
        if not body:
            continue
        _extract_internal_urls_from_text(
            body,
            base_url=base_url,
            dst=internal_urls,
            seen=seen_urls,
        )
        ctype = str(rec.get("content_type") or "").lower()
        stripped = body.lstrip()
        if "json" in ctype or stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(stripped)
            except ValueError:
                parsed = None
            if isinstance(parsed, (dict, list)):
                _extract_json_synthesis_values(
                    parsed,
                    dst=extracted_values,
                    seen=seen_values,
                )

    high_risk_unprobed_routes: list[dict[str, Any]] = []
    if surface_tracker is not None:
        hr_fn = getattr(surface_tracker, "high_risk_unprobed_routes", None)
        if callable(hr_fn):
            raw_hr = hr_fn(limit=6) or ()
            for entry in raw_hr:
                if isinstance(entry, dict) and entry.get("route_template"):
                    high_risk_unprobed_routes.append({
                        "route_template": str(entry["route_template"]),
                        "methods": [str(m) for m in (entry.get("methods") or ())],
                        "params": [str(p) for p in (entry.get("params") or ())[:8]],
                        "risk_score": int(entry.get("risk_score") or 0),
                        "reason": str(entry.get("reason") or ""),
                    })
                if len(high_risk_unprobed_routes) >= 6:
                    break

    truncated_shard = any(
        isinstance(s, dict) and str(s.get("status") or "") in {"budget_exhausted", "max_turns_reached"}
        for s in shard_results
    )
    unresolved_restricted_routes = bool(any_401_403_paths - any_2xx_paths)
    has_remaining_work = bool(truncated_shard or unresolved_restricted_routes)
    has_signal = bool(
        internal_urls
        or blockers
        or untested_writes_and_blocked
        or high_risk_unprobed_routes
        or ((extracted_values or auth_capabilities) and has_remaining_work)
    )
    return {
        "should_trigger": len(shard_results) >= 2 and has_signal,
        "shard_count": len(shard_results),
        "internal_urls": internal_urls,
        "extracted_values": extracted_values,
        "auth_capabilities": auth_capabilities,
        "blockers": blockers,
        "untested_writes_and_blocked": untested_writes_and_blocked,
        "high_risk_unprobed_routes": high_risk_unprobed_routes,
        "findings": compact_findings[:30],
    }


def _strip_shard_scope_fences(system_prompt: str) -> str:
    """Remove any subsystem shard scope suffix from a base system prompt."""
    text = str(system_prompt or "")
    cleaned = re.split(r"\n*SUBSYSTEM SHARD SCOPE \(", text, maxsplit=1)[0]
    return cleaned.rstrip()


def build_cross_shard_synthesis_prompts(
    *,
    base_system_prompt: str,
    synthesis_context: dict[str, Any],
    actor_summaries: Sequence[dict[str, Any]],
    http_budget_remaining: int,
    state_banner: str = "",
) -> tuple[str, str]:
    """Construct Stage 3 system and initial user prompts with shard fences removed and chain artifacts embedded."""
    clean_base = _strip_shard_scope_fences(base_system_prompt)
    ctx = synthesis_context if isinstance(synthesis_context, dict) else {}

    findings = [f for f in (ctx.get("findings") or ()) if isinstance(f, dict)][:30]
    internal_urls = [str(u) for u in (ctx.get("internal_urls") or ()) if str(u).strip()][:20]
    extracted_values = [str(v) for v in (ctx.get("extracted_values") or ()) if str(v).strip()][:25]
    auth_capabilities = [str(c) for c in (ctx.get("auth_capabilities") or ()) if str(c).strip()][:20]
    blockers = [str(b) for b in (ctx.get("blockers") or ()) if str(b).strip()][:20]
    untested_writes = [str(w) for w in (ctx.get("untested_writes_and_blocked") or ()) if str(w).strip()][:25]
    high_risk_unprobed = [
        item
        for item in (ctx.get("high_risk_unprobed_routes") or ())
        if isinstance(item, dict) and str(item.get("route_template") or "").strip()
    ][:6]

    finding_lines: list[str] = []
    for f in findings:
        ev = str(f.get("evidence_value") or "")[:70]
        finding_lines.append(
            f"  - {f.get('finding_id', '')} [{f.get('class_type', '')}] "
            f"{f.get('method', '')} {f.get('path') or f.get('url', '')} "
            f"actor={f.get('actor_alias') or f.get('actor', '')} ev={ev!r}"
        )
    findings_block = "\n".join(finding_lines) if finding_lines else "  (none yet)"

    stage3_sections = [
        "UNIFIED CROSS-SHARD CHAIN SYNTHESIS (Stage 3):",
        "- All subsystem shard fences and route boundaries are LIFTED. Test freely across ALL endpoints, actors, sessions, internal service URLs, and subsystems.",
        "- Do NOT re-verify or duplicate already-recorded findings below. Focus strictly on cross-subsystem attack chains, privilege pivots, multi-step `POST`/`PUT`/`PATCH` workflows, and previously blocked endpoints.",
        "- Chain extracted operational keys/codes/headers, forged/elevated auth capabilities (JWT forging, SQLi extraction, auth/role bypass), and discovered internal service URLs across subsystems.",
        "- Apply extracted headers/keys/forged tokens or upgraded actor sessions to unlock `401`/`403` blocked write endpoints and multi-step `POST` workflows.",
        "- Where virgin/untested actors remain on single-use or stateful actions (`claim`, `redeem`, `promo`, `coupon`, `bonus`, `withdraw`), call `concurrent_check` (`count=3..5`) FIRST before single sequential mutations.",
        "- Maintain breadth across unvisited routes/sub-tabs (avoid >5 turns on one static/upload endpoint), include `weak_credentials`, `.svg` upload `Content-Type` readback, `%252F` (`403`), and `%2F` (`404`) checks where relevant, and NEVER call `/reboot`, `/restart`, `/shutdown` or modify active actor credentials.",
        "- Call `record_finding` immediately as each chained or newly unlocked finding is verified with proof + control receipts, and call `finish` when Stage 3 synthesis is complete.",
        f"- Already-verified findings (DO NOT DUPLICATE):\n{findings_block}",
    ]
    sys_prompt = clean_base + "\n\n" + "\n".join(stage3_sections)

    safe_actors = [
        {
            "alias": str(row.get("alias") or ""),
            "role": str(row.get("role") or ""),
            "tenant": str(row.get("tenant") or ""),
        }
        for row in actor_summaries
        if isinstance(row, dict) and row.get("alias")
    ]
    payload = {
        "http_budget_remaining": max(0, int(http_budget_remaining)),
        "actors": safe_actors,
        "findings": findings,
        "artifacts": {
            "internal_urls": internal_urls,
            "extracted_values": extracted_values,
            "auth_capabilities": auth_capabilities,
        },
        "blockers": blockers,
        "untested_writes_and_blocked": untested_writes,
        "high_risk_unprobed_routes": high_risk_unprobed,
    }
    compact_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    user_prompt = (
        "Execute UNIFIED CROSS-SHARD CHAIN SYNTHESIS (Stage 3) across all subsystems.\n"
        f"Remaining HTTP budget: {max(0, int(http_budget_remaining))}\n"
        f"Stage 3 Synthesis Context (JSON):\n{compact_json}\n\n"
        "Instructions: chain the extracted keys, codes, headers, forged/elevated auth tokens, and internal URLs "
        "across subsystems to resolve cross-shard blockers and unlock `401`/`403` or untested `POST`/write workflows "
        "(using `concurrent_check` first where virgin actors remain on single-use actions). "
        "Call `record_finding` immediately for each newly verified vulnerability and call `finish` when done."
        f"{state_banner}"
    )
    return sys_prompt, user_prompt
