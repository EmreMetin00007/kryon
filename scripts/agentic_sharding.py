"""General-purpose subsystem clustering and prompt builders for sharded execution."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Sequence
from urllib.parse import urlsplit

from agentic_surface import (
    _split_path_kv_segment,
    is_id_segment,
    is_non_endpoint_source_path,
    is_virgin_state_sensitive_path,
    route_template_of,
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
_TEXT_KV_RE = re.compile(
    r"(?i)\b([A-Za-z][A-Za-z0-9_.-]{1,48})\s*[:=]\s*([\"']?)([^\s\"'`,;}{\\]{2,120})\2"
)


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


def extract_resource_family(path: str) -> str:
    """Return the normalized top-level resource family for a URL or path.

    Strips leading `/api`, `/v[0-9]+`, and `/rest` prefixes before selecting the
    first resource segment. Root `/`, root-level static files, malformed paths,
    and punctuation-only segments map to `"root"`.
    """
    raw = str(path or "")
    if is_non_endpoint_source_path(raw):
        return "root"
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
    family_writes: dict[str, set[str]] = {}
    family_objects: dict[str, set[str]] = {}
    family_params: dict[str, dict[str, set[str]]] = {}
    family_body_templates: dict[str, dict[str, Any]] = {}
    family_schema_hints: dict[str, dict[str, set[str]]] = {}

    def _add_route(raw_path: str) -> str | None:
        raw = str(raw_path or "")
        if is_non_endpoint_source_path(raw):
            return None
        tmpl = route_template_of(raw)
        if is_non_endpoint_source_path(tmpl):
            return None
        fam = extract_resource_family(tmpl)
        family_routes.setdefault(fam, set()).add(tmpl)
        return tmpl

    for _, raw_path in getattr(surface_tracker, "discovered_routes", {}):
        _add_route(str(raw_path))

    for _, tmpl in getattr(surface_tracker, "visited_method_templates", set()):
        _add_route(str(tmpl))

    write_ops_seen: set[tuple[str, str]] = set()
    for method, tmpl in getattr(surface_tracker, "declared_write_ops", set()):
        write_ops_seen.add((str(method or "POST").upper(), str(tmpl)))
    for method, tmpl in getattr(surface_tracker, "discovered_write_ops", {}):
        write_ops_seen.add((str(method or "POST").upper(), str(tmpl)))
    for method, raw_tmpl in write_ops_seen:
        tmpl = _add_route(raw_tmpl)
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
        tmpl = _add_route(str(raw_key[1] or ""))
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
                u_writes = family_writes.pop(umbrella, set())
                u_objects = family_objects.pop(umbrella, set())
                u_params = family_params.pop(umbrella, {})
                u_bt = family_body_templates.pop(umbrella, {})
                u_sh = family_schema_hints.pop(umbrella, {})

                for r in u_routes:
                    family_routes.setdefault(_retarget(r), set()).add(r)
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
    all_routes = sorted({r for rs in family_routes.values() for r in rs})
    all_writes = sorted({w for ws in family_writes.values() for w in ws})
    all_objects = sorted({o for os_ in family_objects.values() for o in os_})
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

    if eff_max <= 1 or len(all_routes) < eff_min_routes or len(all_families) <= 1:
        single_name = all_families[0] if len(all_families) == 1 else "all"
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
            )
        ]

    # Weight interactive/API signals (write ops, concrete objects, params, API routes)
    # higher than raw route counts, and cap pure read-only non-API route bloat so
    # static/UI path proliferation cannot monopolize a shard over real API families.
    scored_families: list[tuple[int, int, int, int, str]] = []
    for fam in all_families:
        f_routes = family_routes.get(fam, set())
        w_cnt = len(family_writes.get(fam, ()))
        o_cnt = len(family_objects.get(fam, ()))
        p_cnt = sum(len(ps) for ps in family_params.get(fam, {}).values())
        api_r_cnt = sum(1 for r in f_routes if _is_api_route(r))
        non_api_r_cnt = len(f_routes) - api_r_cnt
        interactive_score = (w_cnt * 4) + (o_cnt * 3) + (p_cnt * 2)
        api_route_score = min(api_r_cnt, 8) * 3
        non_api_route_score = (
            min(non_api_r_cnt, 2)
            if (interactive_score == 0 and api_r_cnt == 0)
            else min(non_api_r_cnt, 4)
        )
        richness = interactive_score + api_route_score + non_api_route_score
        eff_r_cnt = api_r_cnt + min(non_api_r_cnt, 3)
        scored_families.append((richness, interactive_score, api_r_cnt, eff_r_cnt, fam))

    scored_families.sort(key=lambda item: (-item[0], -item[1], -item[2], -item[3], item[4]))

    num_shards = min(eff_max, len(scored_families))
    bins: list[dict[str, Any]] = [
        {"idx": i, "weight": 0, "routes": 0, "families": []}
        for i in range(num_shards)
    ]

    for richness, _interactive, _api_r, eff_r_cnt, fam in scored_families:
        target_bin = min(bins, key=lambda b: (b["weight"], b["routes"], b["idx"]))
        target_bin["families"].append(fam)
        target_bin["weight"] += richness
        target_bin["routes"] += eff_r_cnt

    clusters: list[SubsystemCluster] = []
    for i, b in enumerate(bins, start=1):
        fams = list(b["families"])
        if not fams:
            continue
        c_routes = sorted({r for fam in fams for r in family_routes.get(fam, ())})
        c_writes = sorted({w for fam in fams for w in family_writes.get(fam, ())})
        c_objects = sorted({o for fam in fams for o in family_objects.get(fam, ())})
        c_params: dict[str, list[str]] = {}
        c_body_templates: dict[str, Any] = {}
        c_schema_hints: dict[str, list[str]] = {}
        for fam in fams:
            for tmpl, pset in family_params.get(fam, {}).items():
                if pset:
                    c_params[tmpl] = sorted(pset)
            for op_key, tmpl_doc in family_body_templates.get(fam, {}).items():
                c_body_templates[op_key] = tmpl_doc
            for tmpl, hset in family_schema_hints.get(fam, {}).items():
                if hset:
                    c_schema_hints[tmpl] = sorted(set(c_schema_hints.get(tmpl, [])) | hset)
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

    params_lines = [
        f"  - {tmpl}: {', '.join(pnames[:10])}"
        for tmpl, pnames in sorted(cluster.params.items())[:20]
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
        "- Assigned routes:\n  " + ("\n  ".join(cluster.routes[:35]) if cluster.routes else "(none)"),
    ]
    if cluster.write_ops:
        scope_sections.append("- Assigned write operations:\n  " + "\n  ".join(cluster.write_ops[:25]))
    if any(_is_virgin_state_action_path(r) for r in (*cluster.routes, *cluster.write_ops)):
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

    cluster_fams = set(cluster.families)
    cluster_routes = set(cluster.routes)
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
        parsed_base.port is not None
        and parsed_u.port == parsed_base.port
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
        cand = match.group(0).rstrip(",;.")
        if cand.endswith(")") and "(" not in cand:
            cand = cand[:-1]
        if not cand or "<redacted" in cand.lower():
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
