"""Host-owned Sprint E orchestration for Blind Mode and Policy-Verified QA Mode."""
from __future__ import annotations

import copy
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urljoin, urlsplit

import requests

from qa_expectation_policy import match_access_rule, match_field_binding_rule
from policy_engine import ScopeResolver
from runtime_paths import runtime_root
from verdict_ledger import summarize_ledger, verdict_to_ledger_status
from write_isolation import verify_attestation

_HUNTER_DIR = str(runtime_root() / "mcp-servers" / "mcp-hunter")
if _HUNTER_DIR not in sys.path:
    sys.path.insert(0, _HUNTER_DIR)
_MEMORY_DIR = str(runtime_root() / "mcp-servers" / "mcp-memory-server")
if _MEMORY_DIR not in sys.path:
    sys.path.insert(0, _MEMORY_DIR)
_VALIDATOR_DIR = str(runtime_root() / "mcp-servers" / "mcp-validator")
if _VALIDATOR_DIR not in sys.path:
    sys.path.insert(0, _VALIDATOR_DIR)

from cco_hunter_core.blind_discovery import canonical_resource_type, discover_typed_resources  # noqa: E402
from cco_surface_core import session_store  # noqa: E402
from cco_surface_core.extract import extract_html  # noqa: E402
from cco_validator_core import load_validation  # noqa: E402

_TEMPLATE_SLOT_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_UUID_SEG_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_STATIC_EXT_RE = re.compile(r"\.(?:js|mjs|css|png|jpg|jpeg|gif|svg|ico|map|woff2?|ttf|eot|html|txt)$", re.I)
_INFRA_TAIL_SEGMENTS = frozenset({
    "sign-in", "signin", "login", "logout", "sign-out", "signout", "register", "signup", "sign-up",
    "session", "refresh", "csrf", "discovery", "openapi", "openapi.json",
    "swagger", "swagger.json", "health", "healthz", "readyz", "metrics",
})
_NON_ITEM_TAIL_SEGMENTS = frozenset({
    "v1", "v2", "v3", "search", "new", "edit", "export", "overview", "summary",
    "create", "list", "all", "dashboard", "reports", "settings", "profile",
    "audit", "audit-export", "telemetry", "users", "admin", "internal",
})
_PRIVILEGE_FIELD_RE = re.compile(
    r"(?:tier|role|plan|admin|privileg|approved|approval|verified|status|state|"
    r"quota|credit|balance|limit|scope|level|priority|billing|owner|custodian|tenant|org_id|organization)",
    re.I,
)
_BORING_NON_PROBE_FIELDS = frozenset({
    "id", "uuid", "created_at", "updated_at", "deleted_at", "timestamp", "version",
    "href", "url", "self", "uri", "links",
})
_READONLY_APP_ROLES = frozenset({"viewer", "readonly", "auditor", "guest"})


def _is_infra_or_auth_url(url: str, *, extra_skip_paths: set[str]) -> bool:
    parsed = urlsplit(str(url or ""))
    path = parsed.path or "/"
    norm_path = "/" + path.strip("/") if path.strip("/") else "/"
    if norm_path == "/" or norm_path in extra_skip_paths:
        return True
    if _STATIC_EXT_RE.search(path):
        return True
    segments = [seg.lower() for seg in path.split("/") if seg]
    if not segments:
        return True
    if segments[-1] in _INFRA_TAIL_SEGMENTS:
        return True
    if len(segments) >= 2 and segments[-2] in {"access", "auth"} and segments[-1] in {"sign-in", "session", "logout", "refresh"}:
        return True
    return False


def classify_discovery_surface(
    records: Sequence[dict[str, Any]],
    origin: str,
    allowed_methods: Sequence[str],
    external_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Group discovered endpoint records generically into collections, templates, and writes."""
    cfg = external_config or {}
    allowed_set = {str(m or "GET").strip().upper() for m in allowed_methods if str(m or "").strip()}
    extra_skip: set[str] = set()
    for key in ("login_path", "session_check_path"):
        raw = str(cfg.get(key) or "").strip()
        if raw:
            extra_skip.add("/" + urlsplit(urljoin(origin, raw.lstrip("/"))).path.strip("/"))
    for hint in cfg.get("discovery_hints") or []:
        if isinstance(hint, str) and hint.strip():
            h_path = urlsplit(urljoin(origin, hint.lstrip("/"))).path.strip("/")
            extra_skip.add("/" + h_path if h_path else "/")

    collection_urls: list[str] = []
    seen_cols: set[str] = set()
    template_routes: dict[str, dict[str, Any]] = {}
    write_routes: dict[tuple[str, str], dict[str, Any]] = {}

    for rec in records:
        if not isinstance(rec, dict):
            continue
        raw_url = str(rec.get("url") or "").strip()
        if not raw_url:
            continue
        full_url = urljoin(origin, raw_url.lstrip("/")) if "://" not in raw_url else raw_url
        parsed = urlsplit(full_url)
        orig_parsed = urlsplit(origin)
        if (parsed.scheme, parsed.netloc) != (orig_parsed.scheme, orig_parsed.netloc):
            continue
        clean_url = parsed._replace(query="", fragment="").geturl()
        if _is_infra_or_auth_url(clean_url, extra_skip_paths=extra_skip):
            continue

        method = str(rec.get("method") or "GET").strip().upper()
        params = [dict(p) for p in (rec.get("params") or []) if isinstance(p, dict)]
        operation_id = str(rec.get("operation_id") or "").strip()
        slots = _TEMPLATE_SLOT_RE.findall(parsed.path)

        if method == "GET":
            if len(slots) == 1:
                existing = template_routes.get(clean_url)
                if existing is None or len(params) > len(existing["params"]):
                    template_routes[clean_url] = {
                        "url": clean_url,
                        "method": "GET",
                        "param_name": slots[0],
                        "resource_type": canonical_resource_type(clean_url),
                        "params": params,
                        "operation_id": operation_id,
                    }
                base_col = urljoin(origin, canonical_resource_type(clean_url).lstrip("/"))
                if (
                    "{" not in base_col
                    and "}" not in base_col
                    and not _is_infra_or_auth_url(base_col, extra_skip_paths=extra_skip)
                    and base_col not in seen_cols
                ):
                    seen_cols.add(base_col)
                    collection_urls.append(base_col)
            elif not slots and clean_url not in seen_cols:
                seen_cols.add(clean_url)
                collection_urls.append(clean_url)
        elif method in {"POST", "PUT", "PATCH"} and method in allowed_set:
            if len(slots) <= 1:
                wkey = (method, clean_url)
                existing_w = write_routes.get(wkey)
                if existing_w is None or len(params) > len(existing_w["params"]):
                    write_routes[wkey] = {
                        "url": clean_url,
                        "method": method,
                        "slot": slots[0] if slots else "",
                        "resource_type": canonical_resource_type(clean_url),
                        "params": params,
                        "operation_id": operation_id,
                    }

    return {
        "collection_urls": collection_urls,
        "template_routes": list(template_routes.values()),
        "write_routes": list(write_routes.values()),
    }


def _is_concrete_item_url(url: str) -> tuple[bool, str, str]:
    """Detect generic /<collection>/<item_id> URLs even when /openapi.json is absent."""
    path = urlsplit(str(url or "")).path or "/"
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return False, "", ""
    tail = parts[-1]
    low = tail.lower()
    if low in _INFRA_TAIL_SEGMENTS or low in _NON_ITEM_TAIL_SEGMENTS:
        return False, "", ""
    is_id = (
        tail.isdigit()
        or bool(_UUID_SEG_RE.fullmatch(tail))
        or bool(re.fullmatch(r"[0-9a-f]{8,64}", tail, re.I))
        or (len(tail) >= 6 and any(c.isdigit() for c in tail) and bool(re.fullmatch(r"[A-Za-z0-9_-]+", tail)))
    )
    if not is_id:
        return False, "", ""
    return True, "/" + "/".join(parts[:-1]), tail


def _extract_json_links_generic(data: Any) -> list[str]:
    links: list[str] = []
    stack: list[Any] = [data]
    visited = 0
    while stack and visited < 500:
        node = stack.pop()
        visited += 1
        if isinstance(node, dict):
            for key, val in node.items():
                kl = str(key).lower()
                if isinstance(val, str) and kl in {"href", "url", "self", "uri", "link"} and val.strip():
                    links.append(val.strip())
                elif kl in {"endpoints", "links", "routes"} and isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and item.strip():
                            links.append(item.strip())
                        elif isinstance(item, (dict, list)):
                            stack.append(item)
                elif isinstance(val, (dict, list)):
                    stack.append(val)
        elif isinstance(node, list):
            for elem in node[:200]:
                if isinstance(elem, (dict, list)):
                    stack.append(elem)
    return links


def _select_crawl_actors(identities: dict[str, dict[str, Any]], max_actors: int = 6) -> list[str]:
    """Pick 1 representative per (role, tenant) including admins, plus same-tenant peer(s)."""
    selected: list[str] = []
    seen_buckets: set[tuple[str, str]] = set()
    ordered = sorted(
        identities,
        key=lambda a: (0 if identities[a].get("role") == "admin" else 1, a),
    )
    for alias in ordered:
        info = identities[alias]
        bucket = (str(info.get("app_role") or info.get("role") or "member"), str(info.get("tenant") or ""))
        if bucket not in seen_buckets:
            seen_buckets.add(bucket)
            selected.append(alias)
        if len(selected) >= max_actors:
            return selected
    for alias in ordered:
        if alias not in selected:
            selected.append(alias)
        if len(selected) >= max_actors:
            break
    return selected


def _collect_multi_actor_surface(
    origin: str,
    identities: dict[str, dict[str, Any]],
    fetch,
    permits,
    *,
    seed_urls: Sequence[str] = (),
    extra_skip_paths: set[str] | None = None,
    max_requests: int = 48,
    max_pages_per_actor: int = 12,
) -> dict[str, Any]:
    """Discover HTML/JSON routes, role-exclusive endpoints, and concrete item URLs across roles & tenants."""
    skip_paths = set(extra_skip_paths or set())
    selected_actors = _select_crawl_actors(identities)
    orig_parsed = urlsplit(origin)

    def _norm_same_origin(raw: str, base: str) -> str:
        full = urljoin(base, str(raw or "").strip())
        parsed = urlsplit(full)
        if parsed.scheme.lower() not in {"http", "https"} or (parsed.scheme, parsed.netloc) != (orig_parsed.scheme, orig_parsed.netloc):
            return ""
        clean = parsed._replace(query="", fragment="").geturl()
        if not permits(clean):
            return ""
        return clean

    routes_by_actor: dict[str, set[str]] = {a: set() for a in selected_actors}
    texts_by_actor: dict[str, dict[str, str]] = {a: {} for a in selected_actors}
    item_observers: dict[str, list[str]] = {}
    requests_used = 0

    for alias in selected_actors:
        headers = identities[alias]["headers"]
        queue: list[tuple[str, int]] = [(origin, 0)]
        for s_url in seed_urls:
            norm = _norm_same_origin(s_url, origin)
            if (
                norm
                and not _is_concrete_item_url(norm)[0]
                and not _is_infra_or_auth_url(norm, extra_skip_paths=skip_paths)
                and all(u != norm for u, _ in queue)
            ):
                queue.append((norm, 0))
        visited: set[str] = set()
        pages_for_actor = 0
        while queue and pages_for_actor < max_pages_per_actor and requests_used < max_requests:
            cur_url, depth = queue.pop(0)
            if cur_url in visited:
                continue
            visited.add(cur_url)
            requests_used += 1
            pages_for_actor += 1
            resp = fetch(cur_url, dict(headers))
            if not isinstance(resp, dict) or not resp.get("ok"):
                continue
            status = resp.get("status")
            resp_headers = resp.get("headers") or {}
            if status in {301, 302, 303, 307, 308}:
                loc = next((str(v) for k, v in resp_headers.items() if str(k).lower() == "location"), "")
                redir_url = _norm_same_origin(loc, cur_url)
                if (redir_url and redir_url not in visited and depth < 2
                        and not _is_infra_or_auth_url(redir_url, extra_skip_paths=skip_paths)):
                    queue.append((redir_url, depth + 1))
                continue
            if status != 200:
                continue
            text = str(resp.get("text") or "")
            if not _is_infra_or_auth_url(cur_url, extra_skip_paths=skip_paths):
                routes_by_actor[alias].add(cur_url)
                texts_by_actor[alias][cur_url] = text
                is_item, _, _ = _is_concrete_item_url(cur_url)
                if is_item:
                    obs = item_observers.setdefault(cur_url, [])
                    if alias not in obs:
                        obs.append(alias)

            ctype = next((str(v).lower() for k, v in resp_headers.items() if str(k).lower() == "content-type"), "")
            discovered_links: list[str] = []
            stripped = text.lstrip()
            if stripped.startswith(("{", "[")) or "application/json" in ctype:
                try:
                    parsed_json = json.loads(text)
                except ValueError:
                    parsed_json = None
                if parsed_json is not None:
                    discovered_links.extend(_extract_json_links_generic(parsed_json))
            elif "<html" in text.lower() or "<!doctype" in text.lower() or "text/html" in ctype:
                for rec in extract_html(text, cur_url):
                    if str(rec.get("method") or "GET").upper() == "GET" and isinstance(rec.get("url"), str):
                        discovered_links.append(rec["url"])

            for raw_link in discovered_links:
                next_url = _norm_same_origin(raw_link, cur_url)
                if not next_url or _is_infra_or_auth_url(next_url, extra_skip_paths=skip_paths):
                    continue
                routes_by_actor[alias].add(next_url)
                is_item, _, _ = _is_concrete_item_url(next_url)
                if is_item:
                    obs = item_observers.setdefault(next_url, [])
                    if alias not in obs:
                        obs.append(alias)
                elif depth < 2 and next_url not in visited and all(u != next_url for u, _ in queue):
                    # Enqueue collection/nav pages ahead of deep leaves.
                    queue.append((next_url, depth + 1))

    member_routes: set[str] = set()
    admin_routes: set[str] = set()
    for alias, rset in routes_by_actor.items():
        if identities[alias].get("role") == "admin":
            admin_routes.update(rset)
        else:
            member_routes.update(rset)

    discovered_collections: list[str] = []
    admin_exclusive_urls: list[str] = []
    concrete_items: list[dict[str, Any]] = []
    seen_cols: set[str] = set()
    all_routes = sorted(member_routes | admin_routes)
    for r_url in all_routes:
        is_item, col_path, item_id = _is_concrete_item_url(r_url)
        if is_item:
            concrete_items.append({
                "url": r_url,
                "collection_path": col_path,
                "item_id": item_id,
                "observed_by": list(item_observers.get(r_url, [])),
            })
            continue
        if r_url not in seen_cols:
            seen_cols.add(r_url)
            discovered_collections.append(r_url)
            if r_url in admin_routes and r_url not in member_routes:
                admin_exclusive_urls.append(r_url)

    return {
        "requests": requests_used,
        "routes_by_actor": routes_by_actor,
        "texts_by_actor": texts_by_actor,
        "discovered_collections": discovered_collections,
        "admin_exclusive_urls": admin_exclusive_urls,
        "concrete_items": concrete_items,
    }


def _build_gated_fetcher(broker: Any):
    engine = broker.engine
    budget = broker.budget
    session = requests.Session()
    session.trust_env = False

    def _fetch(url: str, headers: dict[str, Any]) -> dict[str, Any]:
        decision = engine.validate_wire_invocation(
            "kali-tools_curl_request",
            {"url": url, "method": "GET", "headers": dict(headers or {})},
        )
        if not decision.get("allowed"):
            return {"ok": False, "status": None, "blocked": "policy", "error": decision.get("reason", "blocked")}
        if not budget.remaining_seconds():
            return {"ok": False, "status": None, "error": "wall_clock_budget_exhausted"}
        ticket = budget.reserve("http", 1)
        sent = 0
        try:
            resp = session.get(url, headers=dict(headers or {}), timeout=10, allow_redirects=False)
            sent = 1
            return {
                "ok": True,
                "status": resp.status_code,
                "text": resp.text,
                "headers": dict(resp.headers),
            }
        except requests.RequestException as exc:
            return {"ok": False, "status": None, "error": type(exc).__name__}
        finally:
            budget.settle(ticket, sent, tool="sprint_e_typed_discovery", origin="solver")

    return _fetch


def _actor_identifiers(alias: str, info: dict[str, Any]) -> set[str]:
    vals = {alias}
    for item in info.get("identifiers") or []:
        if isinstance(item, str) and item.strip():
            vals.add(item.strip())
    return vals


def _pick_owner_actor(
    entry: dict[str, Any],
    actors: dict[str, dict[str, Any]],
) -> str:
    owners = {str(x) for x in (entry.get("owners") or []) if str(x)}
    tenants = {str(x) for x in (entry.get("tenants") or []) if str(x)}
    observed = [a for a in (entry.get("observed_by") or []) if a in actors]
    non_admin_obs = [a for a in observed if actors[a].get("role") == "member"]

    for alias in non_admin_obs:
        if owners and (_actor_identifiers(alias, actors[alias]) & owners):
            return alias
    for alias, info in actors.items():
        if info.get("role") == "member" and owners and (_actor_identifiers(alias, info) & owners):
            return alias
    for alias in non_admin_obs:
        t = str(actors[alias].get("tenant") or "")
        if not tenants or t in tenants:
            return alias
    return (non_admin_obs or observed or [""])[0]


def _pick_absent_from_collection(
    collection_observations: dict[tuple[str, str], dict[str, Any]],
    caller_alias: str,
    resource_type: str,
    key: str,
) -> bool:
    matching = [
        obs
        for (actor, _col_url), obs in collection_observations.items()
        if actor == caller_alias and obs.get("resource_type") == resource_type and obs.get("status") == 200
    ]
    if not matching:
        return True
    return all(key not in (obs.get("keys") or []) for obs in matching)


def _sample_value_for_param(param: dict[str, Any]) -> Any:
    if "sample" in param and param["sample"] not in (None, "", "<unavailable>"):
        return param["sample"]
    values = param.get("values") or param.get("enum")
    if isinstance(values, list) and values:
        return values[0]
    typ = str(param.get("type") or "string").lower()
    if typ in {"integer", "number"}:
        return 1
    if typ == "boolean":
        return False
    return "control_probe_item"


def _candidate_probe_value(
    name: str,
    param_meta: dict[str, Any] | None,
    pre_val: Any,
) -> Any:
    values = (param_meta or {}).get("values") or (param_meta or {}).get("enum")
    if isinstance(values, list) and values:
        alts = [v for v in values if str(v) != str(pre_val)]
        if alts:
            return alts[-1]
        return values[-1]
    if isinstance(pre_val, bool):
        return not pre_val
    if isinstance(pre_val, int):
        return pre_val + 100
    if param_meta and str(param_meta.get("type") or "").lower() == "boolean":
        return True
    if param_meta and str(param_meta.get("type") or "").lower() in {"integer", "number"}:
        return 999
    return f"elevated_{name}"


def _infer_write_probe_inputs(
    route: dict[str, Any],
    actor_alias: str,
    typed_resources: dict[str, dict[str, Any]],
    detail_observations: dict[tuple[str, str], dict[str, Any]],
    collection_observations: dict[tuple[str, str], dict[str, Any]],
    *,
    concrete_url: str,
    policy_rule: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Construct allowed-field control payload and restricted candidate probes without hardcoding."""
    body_params = [
        p for p in (route.get("params") or [])
        if isinstance(p, dict) and str(p.get("location") or "json").lower() in {"json", "body", "form"}
        and isinstance(p.get("name"), str) and p["name"].strip()
    ]
    param_by_name = {str(p["name"]): p for p in body_params}

    detail_json: dict[str, Any] = {}
    obs = detail_observations.get((actor_alias, concrete_url))
    if isinstance(obs, dict) and isinstance(obs.get("parsed"), dict):
        detail_json = obs["parsed"]
    else:
        for (_a, _u), d_obs in detail_observations.items():
            if (
                isinstance(d_obs, dict)
                and d_obs.get("resource_type") == route.get("resource_type")
                and isinstance(d_obs.get("parsed"), dict)
            ):
                detail_json = d_obs["parsed"]
                break

    if not detail_json:
        for (a_name, _col_url), c_obs in collection_observations.items():
            if a_name != actor_alias or not isinstance(c_obs, dict):
                continue
            parsed = c_obs.get("parsed")
            items: list[Any] = []
            if isinstance(parsed, list):
                items = parsed
            elif isinstance(parsed, dict):
                items = next((parsed[k] for k in ("items", "results", "data", "records") if isinstance(parsed.get(k), list) and parsed[k]), [])
                if not items:
                    items = next((v for v in parsed.values() if isinstance(v, list) and v and isinstance(v[0], dict)), [])
            if items and isinstance(items[0], dict):
                detail_json = items[0]
                if c_obs.get("resource_type") == route.get("resource_type"):
                    break

    def _hydrate_fk(param_name: str) -> Any:
        if not param_name.endswith("_id"):
            return None
        stem = param_name[:-3].lower().replace("_", "-")
        for res in typed_resources.values():
            if actor_alias not in (res.get("observed_by") or []):
                continue
            rtype = str(res.get("resource_type") or "").lower()
            if stem in rtype or rtype.rstrip("s").endswith(stem):
                key_val = res.get("key")
                key_str = str(key_val) if key_val is not None else ""
                return int(key_str) if key_str.isdigit() else key_val
        return None

    allowed_payload: dict[str, Any] = {}
    rule_allowed = set((policy_rule or {}).get("allowed_fields") or [])
    rule_restricted = list((policy_rule or {}).get("restricted_fields") or [])
    rule_restricted_set = set(rule_restricted)

    for pname, pmeta in param_by_name.items():
        if "." in pname:
            continue
        is_restricted = (pname in rule_restricted_set) or (bool(_PRIVILEGE_FIELD_RE.search(pname)) and pname not in rule_allowed)
        if not is_restricted and (pmeta.get("required") or pname in rule_allowed or not allowed_payload):
            fk_val = _hydrate_fk(pname)
            if fk_val is not None:
                allowed_payload[pname] = fk_val
            elif pname in detail_json and detail_json[pname] is not None and not isinstance(detail_json[pname], (dict, list)):
                val = detail_json[pname]
                if isinstance(val, str) and not pmeta.get("values"):
                    allowed_payload[pname] = f"{val[:40]} (ctrl)" if "(ctrl)" not in val else val
                else:
                    allowed_payload[pname] = val
            else:
                allowed_payload[pname] = _sample_value_for_param(pmeta)

    if not allowed_payload and detail_json:
        # When OpenAPI omits requestBody, build safe control payload from non-PK, non-privilege writable fields.
        pref_order = sorted(
            detail_json.items(),
            key=lambda kv: (
                0 if any(tok in kv[0].lower() for tok in ("note", "summary", "description", "title", "zone", "label", "comment", "name")) else 1,
                0 if kv[0].endswith("_id") else 1,
                kv[0],
            ),
        )
        for k, v in pref_order:
            kl = k.lower()
            if kl in _BORING_NON_PROBE_FIELDS or _PRIVILEGE_FIELD_RE.search(k):
                continue
            if route.get("method") == "POST" and k.endswith("_id"):
                fk_val = _hydrate_fk(k)
                if fk_val is not None:
                    allowed_payload[k] = fk_val
                elif isinstance(v, (int, str)):
                    allowed_payload[k] = v
                continue
            if k.endswith("_id") or k.endswith("_code") or k.endswith("_tag") or k.startswith("serial"):
                continue
            if isinstance(v, (str, int, float, bool)):
                allowed_payload[k] = f"{v[:40]} (ctrl)" if isinstance(v, str) and "(ctrl)" not in v else v
                if route.get("method") != "POST" or len(allowed_payload) >= 2:
                    break

    if not allowed_payload:
        allowed_payload["note"] = "control"

    candidate_names: list[str] = []
    if rule_restricted:
        candidate_names.extend(rule_restricted)
    else:
        for pname in param_by_name:
            if "." not in pname and _PRIVILEGE_FIELD_RE.search(pname) and pname not in _BORING_NON_PROBE_FIELDS:
                candidate_names.append(pname)
        for k in detail_json:
            if k not in _BORING_NON_PROBE_FIELDS and k not in allowed_payload:
                if _PRIVILEGE_FIELD_RE.search(k) or (bool(param_by_name) and k not in param_by_name):
                    if not k.endswith("_id"):
                        candidate_names.append(k)
        # Inspect privilege-semantic keys seen across other observed resource types (generic POST protection)
        for (_a, _u), d_obs in detail_observations.items():
            parsed = d_obs.get("parsed") if isinstance(d_obs, dict) else None
            if isinstance(parsed, dict):
                for k in parsed:
                    if k not in _BORING_NON_PROBE_FIELDS and _PRIVILEGE_FIELD_RE.search(k) and k not in allowed_payload and not k.endswith("_id"):
                        candidate_names.append(k)
        # Test non-tenant/non-owner privilege fields before tenant/ownership rebinding fields.
        candidate_names.sort(key=lambda fn: (
            1 if re.search(r"(?:tenant|org|owner|custodian|requested_by|created_by)", fn, re.I) else 0,
            fn,
        ))

    seen_cands: set[str] = set()
    candidates: list[dict[str, Any]] = []
    for cname in candidate_names:
        if cname in seen_cands or cname in _BORING_NON_PROBE_FIELDS or cname in allowed_payload:
            continue
        seen_cands.add(cname)
        candidates.append({
            "name": cname,
            "value": _candidate_probe_value(cname, param_by_name.get(cname), detail_json.get(cname)),
        })
        if len(candidates) >= 6:
            break

    return allowed_payload, candidates


def _invoke_tool_full(broker: Any, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    view = broker.invoke(tool_name, args)
    out: dict[str, Any] = {}
    if isinstance(view, dict) and view.get("omitted") and view.get("content_ref"):
        try:
            loaded = broker.read_reference(view["content_ref"])
            if isinstance(loaded, dict):
                out = loaded
        except (ValueError, OSError, TypeError):
            pass
    if not out:
        res = view.get("result") if isinstance(view, dict) else {}
        out = res if isinstance(res, dict) else {}
    vid = out.get("validation_id")
    if isinstance(vid, str) and vid:
        valid_dir = str(broker.private / "state" / "validations")
        disk_rec = load_validation(vid, directory=valid_dir) or load_validation(vid)
        if isinstance(disk_rec, dict):
            return disk_rec
    return out


def _ledger_entry(
    *,
    check_id: str,
    category: str,
    method: str,
    target: str,
    verdict: str,
    tool: str,
    validation_id: str = "",
    blocked_reason: str = "",
    execution_error: str = "",
    oracle_gap_reason: str = "",
    requests_emitted: int = 0,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status = verdict_to_ledger_status(
        verdict,
        blocked_reason=blocked_reason,
        execution_error=execution_error,
        oracle_gap_reason=oracle_gap_reason,
    )
    return {
        "check_id": check_id,
        "category": category,
        "method": method,
        "target": target,
        "verdict": verdict,
        "status": status,
        "tool": tool,
        "validation_id": validation_id,
        "blocked_reason": blocked_reason,
        "execution_error": execution_error,
        "oracle_gap_reason": oracle_gap_reason,
        "requests_emitted": requests_emitted,
        "details": details or {},
    }


def _record_tool_result(
    *,
    check_id: str,
    category: str,
    method: str,
    target: str,
    tool: str,
    res: dict[str, Any],
) -> dict[str, Any]:
    verdict = str(res.get("verdict") or ("ERROR" if res.get("error") or res.get("execution_failed") else "INCONCLUSIVE"))
    raw_details = res.get("evidence") if isinstance(res.get("evidence"), dict) else res.get("details")
    details: dict[str, Any] = raw_details if isinstance(raw_details, dict) else {}
    blocked_reason = str(details.get("blocked_reason") or "") if details.get("blocked") else ""
    oracle_gap_reason = str(details.get("reason") or "oracle_gap") if details.get("oracle_gap") else ""
    exec_err = str(res.get("error") or details.get("argument_error") or ("execution_error" if verdict == "ERROR" else ""))
    return _ledger_entry(
        check_id=check_id,
        category=category,
        method=method,
        target=target,
        verdict=verdict,
        tool=tool,
        validation_id=str(res.get("validation_id") or ""),
        blocked_reason=blocked_reason,
        execution_error=exec_err,
        oracle_gap_reason=oracle_gap_reason,
        requests_emitted=int(res.get("requests_sent") or len(res.get("request_evidence") or [])),
        details={k: v for k, v in details.items() if k in {"mode", "caller_status", "anonymous_status", "persisted_fields", "detail_reason", "foreign_tenants_observed"}},
    )


def run_sprint_e_checks(solver: Any, spec: Any) -> list[dict[str, Any]]:
    """Run generic Sprint E discovery hydration, A3 access checks, and A4 field-binding checks."""
    cfg = solver.external_config or {}
    broker = solver.broker
    origin = spec.target
    actors: dict[str, dict[str, Any]] = {
        alias: dict(info)
        for alias, info in (cfg.get("actors") or {}).items()
        if isinstance(alias, str) and isinstance(info, dict)
    }
    if not actors:
        return []

    home = str(broker.private / "state") if (broker.private / "state").is_dir() else os.environ.get("CCO_HOME")
    identities: dict[str, dict[str, Any]] = {}
    for alias in sorted(actors):
        entry = session_store.get_session(origin, alias, home=home) or session_store.get_session(origin.rstrip("/"), alias, home=home)
        if isinstance(entry, dict) and isinstance(entry.get("headers"), dict):
            identities[alias] = {"headers": dict(entry["headers"]), **actors[alias]}
    if not identities:
        return []

    records = solver.discovery(spec).get("records") or []
    allowed_methods = cfg.get("allowed_methods") or ["GET"]
    surface = classify_discovery_surface(records, origin, allowed_methods, cfg)

    scope_resolver = ScopeResolver(scope_file=str(broker.engine.scope_file)) if getattr(broker.engine, "scope_file", None) else None
    permits_fn = (
        (lambda url: url.startswith(origin) and scope_resolver.permits_url(url))
        if scope_resolver is not None
        else (lambda url: url.startswith(origin))
    )
    fetcher = _build_gated_fetcher(broker)
    extra_skip: set[str] = set()
    for key in ("login_path", "session_check_path"):
        raw = str(cfg.get(key) or "").strip()
        if raw:
            extra_skip.add("/" + urlsplit(urljoin(origin, raw.lstrip("/"))).path.strip("/"))
    for hint in cfg.get("discovery_hints") or []:
        if isinstance(hint, str) and hint.strip():
            h_path = urlsplit(urljoin(origin, hint.lstrip("/"))).path.strip("/")
            extra_skip.add("/" + h_path if h_path else "/")

    qa_policy = cfg.get("qa_policy")
    mode = "policy" if isinstance(qa_policy, dict) else "blind"
    multi_actor_surface: dict[str, Any] = {
        "routes_by_actor": {},
        "texts_by_actor": {},
        "discovered_collections": [],
        "admin_exclusive_urls": [],
        "concrete_items": [],
    }
    if mode == "blind" or not surface["template_routes"]:
        non_item_seeds = [u for u in surface["collection_urls"] if not _is_concrete_item_url(u)[0]]
        multi_actor_surface = _collect_multi_actor_surface(
            origin,
            identities,
            fetcher,
            permits_fn,
            seed_urls=non_item_seeds,
            extra_skip_paths=extra_skip,
            max_requests=max(24, min(60, broker.budget.available("http") // 5 or 36)),
            max_pages_per_actor=12,
        )
        # Reclassify any concrete /<collection>/<id> URLs out of collection_urls and merge discovered collections.
        raw_cols = list(surface["collection_urls"])
        merged_cols: list[str] = []
        seen_col_set: set[str] = set()
        admin_excl_set = set(multi_actor_surface["admin_exclusive_urls"])
        existing_item_urls = {row["url"] for row in multi_actor_surface["concrete_items"]}
        for u in [*multi_actor_surface["admin_exclusive_urls"], *raw_cols, *multi_actor_surface["discovered_collections"]]:
            is_item, col_path, item_id = _is_concrete_item_url(u)
            if is_item:
                if u not in existing_item_urls:
                    existing_item_urls.add(u)
                    multi_actor_surface["concrete_items"].append({
                        "url": u,
                        "collection_path": col_path,
                        "item_id": item_id,
                        "observed_by": [a for a, rset in multi_actor_surface["routes_by_actor"].items() if u in rset],
                    })
                continue
            if u not in seen_col_set and not _is_infra_or_auth_url(u, extra_skip_paths=extra_skip):
                seen_col_set.add(u)
                merged_cols.append(u)
        merged_cols.sort(key=lambda u: (0 if u in admin_excl_set else 1, 0 if "/api/" in urlsplit(u).path.lower() else 1, u))
        surface["collection_urls"] = merged_cols

    html_already_fetched = {
        u
        for actor_texts in multi_actor_surface["texts_by_actor"].values()
        for u, body in actor_texts.items()
        if not body.lstrip().startswith(("{", "["))
    }
    typed_collection_urls = [
        u for u in surface["collection_urls"]
        if "/api/" in urlsplit(u).path.lower() or u not in html_already_fetched
    ]
    typed_report = discover_typed_resources(
        origin,
        identities,
        fetcher,
        permits_fn,
        collection_urls=typed_collection_urls,
        template_routes=surface["template_routes"],
        max_requests=max(40, min(160, broker.budget.available("http") // 3 or 60)),
        max_detail_per_actor=8,
    )
    typed_resources: dict[str, dict[str, Any]] = typed_report.get("resources") or {}
    col_obs = typed_report.get("collection_observations") or {}
    det_obs = typed_report.get("detail_observations") or {}

    available_tools = {t["function"]["name"] for t in solver.tool_schemas(spec)}
    policy_obj = broker.runtime_policy
    entries: list[dict[str, Any]] = []
    tested_detail_checks: set[tuple[str, str, str]] = set()

    def _has_tool_budget() -> bool:
        return policy_obj.tool_allowance(spec) > 0 and broker.budget.available("http") > 0 and bool(broker.budget.remaining_seconds())

    members = [a for a in sorted(identities) if actors[a].get("role") == "member"]
    admins = [a for a in sorted(identities) if actors[a].get("role") == "admin"]

    def _run_access_check(
        *,
        check_id: str,
        category: str,
        target_url: str,
        caller_alias: str,
        owner_alias: str = "",
        owner_tenant: str = "",
        list_fields: Sequence[str] = (),
        absent: bool = False,
    ) -> None:
        caller_info = actors.get(caller_alias, {})
        caller_role = str(caller_info.get("app_role") or caller_info.get("role") or "member")
        caller_tenant = str(caller_info.get("tenant") or "")
        rule_arg: dict[str, Any] = {}
        if mode == "policy":
            matched, gap_reason = match_access_rule(qa_policy, method="GET", path=target_url, category=category)
            if gap_reason:
                entries.append(_ledger_entry(
                    check_id=check_id,
                    category=category,
                    method="GET",
                    target=target_url,
                    verdict="INCONCLUSIVE",
                    tool="qa_policy_matcher",
                    oracle_gap_reason=gap_reason,
                    requests_emitted=0,
                ))
                return
            rule_arg = matched or {}

        if "validator_validate_access_control" not in available_tools or not _has_tool_budget():
            entries.append(_ledger_entry(
                check_id=check_id,
                category=category,
                method="GET",
                target=target_url,
                verdict="INCONCLUSIVE",
                tool="validator_validate_access_control",
                blocked_reason="tool_or_budget_unavailable",
            ))
            return

        caller_hdrs = identities[caller_alias]["headers"]
        owner_hdrs = identities[owner_alias]["headers"] if owner_alias in identities else {}
        res = _invoke_tool_full(broker, "validator_validate_access_control", {
            "target_url": target_url,
            "check_category": category,
            "caller_headers_json": json.dumps(caller_hdrs),
            "caller_alias": caller_alias,
            "caller_role": caller_role,
            "caller_tenant": caller_tenant,
            "owner_headers_json": json.dumps(owner_hdrs),
            "owner_alias": owner_alias,
            "owner_tenant": owner_tenant,
            "mode": mode,
            "expected_rule_json": json.dumps(rule_arg),
            "list_fields_json": json.dumps(list(list_fields)),
            "absent_from_caller_collection": bool(absent),
            "repeat_check": True,
        })
        entries.append(_record_tool_result(
            check_id=check_id,
            category=category,
            method="GET",
            target=target_url,
            tool="validator_validate_access_control",
            res=res,
        ))

    # A3.1 Cross-tenant & A3.2 Same-tenant cross-custodian detail checks across hydrated templates
    for tpl in surface["template_routes"]:
        rtype = tpl["resource_type"]
        matching_entries = [
            entry for entry in typed_resources.values()
            if entry.get("resource_type") == rtype and entry.get("detail_urls")
        ]
        tested_cross_tenants: set[tuple[str, str]] = set()
        tested_same_tenant: set[tuple[str, str]] = set()
        for entry in matching_entries:
            owner_alias = _pick_owner_actor(entry, actors)
            owner_info = actors.get(owner_alias, {})
            owner_tenant = str(owner_info.get("tenant") or (entry.get("tenants") or [""])[0])
            detail_url = next(
                (u for u in entry["detail_urls"] if canonical_resource_type(u) == rtype and tpl["url"].split("{", 1)[0] in u),
                entry["detail_urls"][0],
            )
            key = str(entry["key"])
            list_fields = entry.get("list_fields") or []

            # Cross-tenant caller(s)
            for caller in members:
                c_tenant = str(actors[caller].get("tenant") or "")
                if not owner_tenant or not c_tenant or c_tenant == owner_tenant:
                    continue
                pair_key = (owner_tenant, c_tenant)
                if pair_key in tested_cross_tenants:
                    continue
                tested_cross_tenants.add(pair_key)
                absent = _pick_absent_from_collection(col_obs, caller, rtype, key)
                tested_detail_checks.add((detail_url, caller, "cross_tenant_read"))
                _run_access_check(
                    check_id=f"cross_tenant:{rtype}:{key}:{owner_alias}->{caller}",
                    category="cross_tenant_read",
                    target_url=detail_url,
                    caller_alias=caller,
                    owner_alias=owner_alias,
                    owner_tenant=owner_tenant,
                    list_fields=list_fields,
                    absent=absent,
                )
                if len(tested_cross_tenants) >= 2:
                    break

            # Same-tenant cross-custodian peer(s)
            owner_ids = _actor_identifiers(owner_alias, owner_info)
            record_owners = {str(x) for x in (entry.get("owners") or [])}
            for caller in members:
                if caller == owner_alias:
                    continue
                c_tenant = str(actors[caller].get("tenant") or "")
                c_ids = _actor_identifiers(caller, actors[caller])
                if owner_tenant and c_tenant != owner_tenant:
                    continue
                if c_ids & record_owners or (owner_ids & c_ids):
                    continue
                c_app_role = str(actors[caller].get("app_role") or "")
                role_bucket = (owner_tenant, c_app_role)
                if role_bucket in tested_same_tenant:
                    continue
                tested_same_tenant.add(role_bucket)
                absent = _pick_absent_from_collection(col_obs, caller, rtype, key)
                tested_detail_checks.add((detail_url, caller, "same_tenant_peer_read"))
                _run_access_check(
                    check_id=f"same_tenant_peer:{rtype}:{key}:{owner_alias}->{caller}",
                    category="same_tenant_peer_read",
                    target_url=detail_url,
                    caller_alias=caller,
                    owner_alias=owner_alias,
                    owner_tenant=owner_tenant,
                    list_fields=list_fields,
                    absent=absent,
                )
                if len(tested_same_tenant) >= 2:
                    break

    # A3.2b Template-free concrete item URLs (/<collection>/<item_id>) discovered without /openapi.json
    if multi_actor_surface["concrete_items"] and (mode == "blind" or not surface["template_routes"]):
        items_by_owner: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for item in multi_actor_surface["concrete_items"]:
            obs_actors = [a for a in (item.get("observed_by") or []) if a in identities]
            member_obs = [a for a in obs_actors if actors.get(a, {}).get("role") == "member"]
            # Prefer a member who exclusively observed this item (avoid shared items masking real owners).
            if len(member_obs) == 1:
                owner_alias = member_obs[0]
            elif member_obs:
                owner_alias = member_obs[0]
            elif obs_actors:
                owner_alias = obs_actors[0]
            else:
                continue
            if actors.get(owner_alias, {}).get("role") != "member":
                continue
            owner_tenant = str(actors[owner_alias].get("tenant") or "")
            grp_key = (item["collection_path"], owner_alias, owner_tenant)
            bucket = items_by_owner.setdefault(grp_key, [])
            if len(bucket) < 2:
                bucket.append(item)

        cross_tested_per_col: dict[str, set[tuple[str, str]]] = {}
        peer_tested_per_col: dict[str, set[tuple[str, str, str]]] = {}
        for (col_path, owner_alias, owner_tenant), group_items in sorted(items_by_owner.items()):
            for item in group_items:
                detail_url = item["url"]
                item_id = item["item_id"]
                typed_entry = typed_resources.get(f"{col_path}::{item_id}") or {}
                list_fields = typed_entry.get("list_fields") or []

                # Cross-tenant read checks
                ct_seen = cross_tested_per_col.setdefault(col_path, set())
                for caller in members:
                    c_tenant = str(actors[caller].get("tenant") or "")
                    if not owner_tenant or not c_tenant or c_tenant == owner_tenant:
                        continue
                    pair_key = (owner_tenant, c_tenant)
                    if pair_key in ct_seen:
                        continue
                    if (detail_url, caller, "cross_tenant_read") in tested_detail_checks:
                        continue
                    ct_seen.add(pair_key)
                    tested_detail_checks.add((detail_url, caller, "cross_tenant_read"))
                    caller_routes = multi_actor_surface["routes_by_actor"].get(caller, set())
                    caller_texts = "\n".join(multi_actor_surface["texts_by_actor"].get(caller, {}).values())
                    absent = (
                        detail_url not in caller_routes
                        and item_id not in caller_texts
                        and _pick_absent_from_collection(col_obs, caller, col_path, item_id)
                    )
                    _run_access_check(
                        check_id=f"cross_tenant:{col_path}:{item_id}:{owner_alias}->{caller}",
                        category="cross_tenant_read",
                        target_url=detail_url,
                        caller_alias=caller,
                        owner_alias=owner_alias,
                        owner_tenant=owner_tenant,
                        list_fields=list_fields,
                        absent=absent,
                    )
                    if len(ct_seen) >= 2:
                        break

                # Same-tenant peer read checks
                st_seen = peer_tested_per_col.setdefault(col_path, set())
                for caller in members:
                    if caller == owner_alias:
                        continue
                    c_tenant = str(actors[caller].get("tenant") or "")
                    if owner_tenant and c_tenant != owner_tenant:
                        continue
                    peer_key = (owner_alias, caller, c_tenant)
                    if peer_key in st_seen:
                        continue
                    if (detail_url, caller, "same_tenant_peer_read") in tested_detail_checks:
                        continue
                    st_seen.add(peer_key)
                    tested_detail_checks.add((detail_url, caller, "same_tenant_peer_read"))
                    caller_routes = multi_actor_surface["routes_by_actor"].get(caller, set())
                    caller_texts = "\n".join(multi_actor_surface["texts_by_actor"].get(caller, {}).values())
                    absent = (
                        detail_url not in caller_routes
                        and item_id not in caller_texts
                        and _pick_absent_from_collection(col_obs, caller, col_path, item_id)
                    )
                    _run_access_check(
                        check_id=f"same_tenant_peer:{col_path}:{item_id}:{owner_alias}->{caller}",
                        category="same_tenant_peer_read",
                        target_url=detail_url,
                        caller_alias=caller,
                        owner_alias=owner_alias,
                        owner_tenant=owner_tenant,
                        list_fields=list_fields,
                        absent=absent,
                    )
                    if len(st_seen) >= 2:
                        break

    # A3.3 Parameterless role / admin-vs-non-admin & telemetry control checks
    admin_baseline = next(
        (a for a in admins if "platform" in str(actors[a].get("app_role") or "").lower()),
        admins[0] if admins else "",
    )
    rep_non_admins: list[str] = []
    seen_non_admin_roles: set[str] = set()
    for alias in members:
        arole = str(actors[alias].get("app_role") or actors[alias].get("role") or "")
        if arole not in seen_non_admin_roles:
            seen_non_admin_roles.add(arole)
            rep_non_admins.append(alias)
        if len(rep_non_admins) >= 2:
            break

    for col_url in surface["collection_urls"]:
        is_telemetry = False
        if mode == "policy":
            t_rule, t_gap = match_access_rule(qa_policy, method="GET", path=col_url, category="telemetry_control")
            if t_rule is not None and not t_gap:
                is_telemetry = True
                caller = rep_non_admins[0] if rep_non_admins else (admins[0] if admins else "")
                if caller:
                    _run_access_check(
                        check_id=f"telemetry:{urlsplit(col_url).path}:{caller}",
                        category="telemetry_control",
                        target_url=col_url,
                        caller_alias=caller,
                        owner_alias=admin_baseline,
                        owner_tenant=str(actors.get(admin_baseline, {}).get("tenant") or ""),
                    )
        if is_telemetry:
            continue
        for caller in rep_non_admins[:1 if mode == "policy" else 2]:
            _run_access_check(
                check_id=f"role_access:{urlsplit(col_url).path}:{caller}",
                category="function_role_access",
                target_url=col_url,
                caller_alias=caller,
                owner_alias=admin_baseline,
                owner_tenant=str(actors.get(admin_baseline, {}).get("tenant") or ""),
            )

    # Policy Mode extra: evaluate any telemetry_control paths listed in policy that were not in collection_urls
    if isinstance(qa_policy, dict) and mode == "policy" and isinstance(qa_policy.get("telemetry_controls"), list):
        tested_paths = {urlsplit(u).path for u in surface["collection_urls"]}
        for tc in qa_policy["telemetry_controls"]:
            if not isinstance(tc, dict):
                continue
            tc_path = str(tc.get("path_pattern") or tc.get("path") or "").strip()
            if not tc_path or "{" in tc_path or "*" in tc_path:
                continue
            tc_url = urljoin(origin, tc_path.lstrip("/"))
            if urlsplit(tc_url).path in tested_paths:
                continue
            caller = rep_non_admins[0] if rep_non_admins else (admins[0] if admins else "")
            if caller:
                _run_access_check(
                    check_id=f"telemetry:{tc_path}:{caller}",
                    category="telemetry_control",
                    target_url=tc_url,
                    caller_alias=caller,
                    owner_alias=admin_baseline,
                    owner_tenant=str(actors.get(admin_baseline, {}).get("tenant") or ""),
                )

    # A4 Write-endpoint Field-Binding / Mass-Assignment checks (fail-closed on write_isolation)
    write_isolation_att = cfg.get("write_isolation")
    session_check_url = urljoin(origin, str(cfg.get("session_check_path") or "/api/v1/access/session").lstrip("/"))
    for w_route in surface["write_routes"]:
        w_method = w_route["method"]
        w_tpl_url = w_route["url"]
        rtype = w_route["resource_type"]
        rule_arg: dict[str, Any] = {}
        if mode == "policy":
            w_rule, w_gap = match_field_binding_rule(qa_policy, method=w_method, path=w_tpl_url)
            if w_gap:
                entries.append(_ledger_entry(
                    check_id=f"field_binding:{w_method}:{urlsplit(w_tpl_url).path}",
                    category="field_binding",
                    method=w_method,
                    target=w_tpl_url,
                    verdict="INCONCLUSIVE",
                    tool="qa_policy_matcher",
                    oracle_gap_reason=w_gap,
                    requests_emitted=0,
                ))
                continue
            rule_arg = w_rule or {}

        concrete_target = w_tpl_url
        read_url = w_tpl_url
        actor_alias = next(
            (a for a in members if str(actors[a].get("app_role") or "").lower() not in _READONLY_APP_ROLES),
            members[0] if members else "",
        )
        if w_route["slot"]:
            matching = [
                entry for entry in typed_resources.values()
                if entry.get("resource_type") == rtype and entry.get("key")
            ]
            chosen_entry = None
            for entry in matching:
                cand_owner = _pick_owner_actor(entry, actors)
                if cand_owner in identities and actors.get(cand_owner, {}).get("role") == "member":
                    chosen_entry = entry
                    actor_alias = cand_owner
                    break
            if chosen_entry is None:
                entries.append(_ledger_entry(
                    check_id=f"field_binding:{w_method}:{urlsplit(w_tpl_url).path}",
                    category="field_binding",
                    method=w_method,
                    target=w_tpl_url,
                    verdict="INCONCLUSIVE",
                    tool="validator_validate_field_binding",
                    blocked_reason="no_owned_resource_for_template",
                    requests_emitted=0,
                ))
                continue
            concrete_target = w_tpl_url.replace("{" + w_route["slot"] + "}", str(chosen_entry["key"]))
            read_url = next(
                (u for u in chosen_entry.get("detail_urls") or [] if str(chosen_entry["key"]) in u),
                concrete_target,
            )

        att_ok, att_reason = verify_attestation(
            write_isolation_att,
            expected_origin=concrete_target,
            expected_run_id=solver.run_id,
        )
        if not att_ok:
            if "validator_validate_field_binding" in available_tools and _has_tool_budget():
                res = _invoke_tool_full(broker, "validator_validate_field_binding", {
                    "target_url": concrete_target,
                    "method": w_method,
                    "carrier": "json",
                    "read_url": read_url,
                    "identity": actor_alias,
                    "allowed_payload_json": "{}",
                    "candidate_fields_json": "[]",
                    "write_isolation_json": json.dumps(write_isolation_att) if isinstance(write_isolation_att, dict) else str(write_isolation_att or ""),
                    "expected_run_id": solver.run_id,
                    "session_check_url": session_check_url,
                    "mode": mode,
                    "expected_rule_json": json.dumps(rule_arg),
                    "operation_id": w_route.get("operation_id") or "",
                })
                entries.append(_record_tool_result(
                    check_id=f"field_binding:{w_method}:{urlsplit(concrete_target).path}",
                    category="field_binding",
                    method=w_method,
                    target=concrete_target,
                    tool="validator_validate_field_binding",
                    res=res,
                ))
            else:
                entries.append(_ledger_entry(
                    check_id=f"field_binding:{w_method}:{urlsplit(concrete_target).path}",
                    category="field_binding",
                    method=w_method,
                    target=concrete_target,
                    verdict="INCONCLUSIVE",
                    tool="validator_validate_field_binding",
                    blocked_reason="write_isolation_unattested",
                    requests_emitted=0,
                    details={"detail": att_reason},
                ))
            continue

        if not actor_alias or actor_alias not in identities:
            entries.append(_ledger_entry(
                check_id=f"field_binding:{w_method}:{urlsplit(concrete_target).path}",
                category="field_binding",
                method=w_method,
                target=concrete_target,
                verdict="INCONCLUSIVE",
                tool="validator_validate_field_binding",
                blocked_reason="no_member_actor_for_write",
                requests_emitted=0,
            ))
            continue

        allowed_payload, candidates = _infer_write_probe_inputs(
            w_route,
            actor_alias,
            typed_resources,
            det_obs,
            col_obs,
            concrete_url=concrete_target,
            policy_rule=rule_arg if mode == "policy" else None,
        )
        if not candidates:
            entries.append(_ledger_entry(
                check_id=f"field_binding:{w_method}:{urlsplit(concrete_target).path}",
                category="field_binding",
                method=w_method,
                target=concrete_target,
                verdict="INCONCLUSIVE",
                tool="validator_validate_field_binding",
                oracle_gap_reason="no_candidate_restricted_fields",
                requests_emitted=0,
            ))
            continue

        if "validator_validate_field_binding" not in available_tools or not _has_tool_budget():
            entries.append(_ledger_entry(
                check_id=f"field_binding:{w_method}:{urlsplit(concrete_target).path}",
                category="field_binding",
                method=w_method,
                target=concrete_target,
                verdict="INCONCLUSIVE",
                tool="validator_validate_field_binding",
                blocked_reason="tool_or_budget_unavailable",
                requests_emitted=0,
            ))
            continue

        res = _invoke_tool_full(broker, "validator_validate_field_binding", {
            "target_url": concrete_target,
            "method": w_method,
            "carrier": "json",
            "read_url": read_url,
            "headers_json": json.dumps(identities[actor_alias]["headers"]),
            "identity": actor_alias,
            "allowed_payload_json": json.dumps(allowed_payload),
            "candidate_fields_json": json.dumps(candidates),
            "write_isolation_json": json.dumps(write_isolation_att) if isinstance(write_isolation_att, dict) else str(write_isolation_att or ""),
            "expected_run_id": solver.run_id,
            "session_check_url": session_check_url,
            "mode": mode,
            "expected_rule_json": json.dumps(rule_arg),
            "operation_id": w_route.get("operation_id") or "",
            "param": candidates[0]["name"],
        })
        entries.append(_record_tool_result(
            check_id=f"field_binding:{w_method}:{urlsplit(concrete_target).path}",
            category="field_binding",
            method=w_method,
            target=concrete_target,
            tool="validator_validate_field_binding",
            res=res,
        ))

    return entries


def summarize_sprint_e_ledger(entries: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Build aggregate Sprint E verdict ledger counts and adjudication coverage."""
    return summarize_ledger(entries, planned=len(entries))
