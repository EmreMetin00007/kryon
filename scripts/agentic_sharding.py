"""General-purpose subsystem clustering and prompt builders for sharded execution."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Sequence
from urllib.parse import urlsplit

from agentic_surface import (
    _split_path_kv_segment,
    is_malformed_url_path,
    is_non_endpoint_source_path,
    route_template_of,
)

_PREFIX_SEGMENT_RE = re.compile(r"^(?:api|rest|v\d+)$", re.IGNORECASE)
_API_ROUTE_RE = re.compile(r"^/(?:api|rest|v\d+|graphql)(?:/|$)|/graphql(?:/|$)", re.IGNORECASE)


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
    if is_malformed_url_path(raw):
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
    kv = _split_path_kv_segment(first)
    if kv is not None:
        return kv[0]
    if len(segments) == 1 and "." in first:
        return "root"
    if not any(ch.isalnum() for ch in first):
        return "root"
    return first.lower()


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
        "- Call `record_finding` immediately as each vulnerability is confirmed, and call `finish` when your assigned subsystem slice is complete."
    )

    sys_prompt = base_system_prompt.rstrip() + "\n\n" + "\n".join(scope_sections)

    cluster_fams = set(cluster.families)
    receipt_lines: list[str] = []
    if receipts is not None and hasattr(receipts, "list_ids") and hasattr(receipts, "get"):
        seen_sig: set[tuple[str, str, str, int]] = set()
        for rid in receipts.list_ids():
            try:
                rec = receipts.get(rid)
            except Exception:
                continue
            path_or_url = str(rec.get("path") or rec.get("url") or "/")
            if cluster_fams and extract_resource_family(path_or_url) not in cluster_fams:
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
