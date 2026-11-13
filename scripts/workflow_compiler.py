#!/usr/bin/env python3
"""Browser / MITM Traffic → Session Vault, Attack Surface & Business-Logic Chain Compiler.

Bridges UI-driven runs (`scripts/agent_browse.py` / `mcp-browser`) with:
  1. Shared session stores (`session-jar.json` + `session_vault.json`)
  2. `agent_memory.db` (`attack_surface` + `endpoints`)
  3. Executable `action-manifest/1.0` business-logic chains for `ChainExecutor`
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
try:
    from .runtime_paths import runtime_root
except ImportError:
    from runtime_paths import runtime_root
REPO_ROOT = runtime_root()
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from action_manifest import SCHEMA_VERSION, validate_manifest
from business_logic import contract_errors, evaluate_normal_control


def compile_evidence_chain(graph, spec, diagnostics=None):
    """Compile explicit P8 source hashes; prerequisite gaps affect this chain."""
    from evidence_chaining import EvidenceError
    try:
        manifest = graph.build_plan(spec)
        check = validate_manifest(manifest)
        if not check['valid']:
            raise EvidenceError('; '.join(check['errors']))
        return {'status': 'ready', 'runnable': True, 'verdict': 'NOT_TESTED',
                'manifest': manifest, 'severity': None}
    except (EvidenceError, KeyError, TypeError, ValueError) as exc:
        gap = {'status': 'blocked', 'runnable': False, 'reason': str(exc),
               'edge_status': 'unvalidated_edge', 'verdict': 'INCONCLUSIVE', 'severity': None}
        if diagnostics is not None:
            diagnostics.append(gap)
        return {**gap, 'manifest': None}


def compile_business_logic_chain(graph, capture_hashes, context, *, target_ref):
    """Recompile P7 from immutable, TTL-checked captures in the evidence store.

    Each exchange carries its original compiler input in ``capture``. The
    request/response and identity must agree with that input; a manifest alone
    is never evidence that its HTTP actions were observed.
    """
    from evidence_chaining import EvidenceError
    records = []
    for h in capture_hashes:
        source = graph.evidence(h, context)
        record = source.get('capture', {})
        observed = record.get('observed_context', {})
        request = {'url': record.get('url'), 'method': record.get('method'),
                   'body': record.get('req_body', '')}
        if (source.get('kind') != 'exchange' or not _captured(record)
                or source.get('request') != request
                or source.get('identity_ref') != observed.get('identity_ref')
                or observed.get('session_id') != context['session_id']
                or source.get('response') != {'ok': True, 'status': record.get('status'),
                                              'body': _resp_json_from_item(record)}):
            raise EvidenceError('capture_binding_mismatch')
        records.append(record)
    return compile_workflow_manifests(records, target_ref=target_ref)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _is_in_allowlist(host: str, allow: set[str] | frozenset | None) -> bool:
    """Allowlist denetimi: allow=None ise filtre yok; loopback her zaman izinli."""
    if allow is None:
        return True
    h = (host or "").strip().lower()
    if not h:
        return False
    if h in LOOPBACK_HOSTS:
        return True
    return any(h == d or h.endswith("." + d) for d in allow)


_SENSITIVE_NAMES = frozenset({
    "token", "password", "passwd", "secret", "session", "sessionid",
    "auth", "access_token", "refresh_token", "api_key", "apikey", "credential", "csrf", "xsrf",
})
_NUMERIC_PARAM_RE = re.compile(
    r"(?:^|_)(price|amount|total|cost|fee|sum|balance|subtotal|qty|quantity|count|discount|credit)(?:_|$)",
    re.I,
)
_READONLY_CANDIDATES = ("role", "is_admin", "plan", "verified", "is_verified")
_TOTAL_FIELD_CANDIDATES = ("total", "grand_total", "subtotal", "balance", "amount", "price")
_STATIC_EXT_RE = re.compile(r"\.(?:css|png|jpg|jpeg|gif|svg|woff2?|ttf|ico|map)(?:\?|$)", re.I)


def _is_sensitive_key(name: str) -> bool:
    low = (name or "").strip().lower()
    return any(tok in low for tok in _SENSITIVE_NAMES)


def _redact_obj(obj):
    if isinstance(obj, dict):
        return {
            k: ("<redacted>" if _is_sensitive_key(str(k)) else _redact_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_obj(x) for x in obj]
    return obj


def _host_of(url_or_host: str) -> str:
    raw = (url_or_host or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        return (urlparse(raw).hostname or "").lower().lstrip(".")
    return raw.split("/")[0].split(":")[0].lower().lstrip(".")


def sync_browser_cookies_to_vault(
    cookies: list[dict] | dict,
    *,
    default_url: str = "",
    headers: dict[str, str] | None = None,
    identity: str = "browser",
    source: str = "agent_browse",
    cco_home: str | None = None,
    allow: set[str] | frozenset | None = None,
) -> dict:
    """Sync browser cookies into both session-jar.json and session_vault.json.

    Cookie values are never returned in the summary.
    allow verilirse kapsam dışı host'ların çerezleri kasaya yazılmaz.
    """
    home = str(Path(cco_home or os.environ.get("CCO_HOME", "~/.cco")).expanduser())
    default_host = _host_of(default_url)
    by_host: dict[str, dict[str, str]] = {}
    filtered_out = 0

    if isinstance(cookies, dict):
        if default_host:
            by_host[default_host] = {
                str(k): str(v) for k, v in cookies.items() if k and v is not None
            }
    elif isinstance(cookies, list):
        for item in cookies:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            val = item.get("value")
            if not name or val is None:
                continue
            dom = _host_of(str(item.get("domain") or item.get("url") or default_host))
            if not dom:
                continue
            by_host.setdefault(dom, {})[name] = str(val)

    if allow is not None:
        for host in list(by_host):
            if not _is_in_allowlist(host, allow):
                del by_host[host]
                filtered_out += 1

    if not by_host and default_host and headers and _is_in_allowlist(default_host, allow):
        by_host[default_host] = {}

    mem_dir = str(REPO_ROOT / "mcp-servers" / "mcp-memory-server")
    val_dir = str(REPO_ROOT / "mcp-servers" / "mcp-validator")
    if mem_dir not in sys.path:
        sys.path.insert(0, mem_dir)
    if val_dir not in sys.path:
        sys.path.insert(0, val_dir)

    vault_synced = 0
    jar_synced = 0
    cookie_keys: set[str] = set()

    for host, cdict in by_host.items():
        cookie_keys.update(cdict.keys())
        cookie_str = "; ".join(f"{k}={v}" for k, v in cdict.items())
        try:
            from cco_surface_core import session_store
            session_store.put_session(
                host,
                identity,
                headers=headers or {},
                cookies=cdict,
                check_url=default_url if default_host == host else f"https://{host}",
                home=home,
            )
            vault_synced += 1
        except Exception:
            pass
        try:
            from cco_validator_core.egress import save_shared_session
            if cookie_str or headers:
                save_shared_session(
                    default_url if default_host == host and "://" in default_url else host,
                    cookie=cookie_str,
                    headers=headers or {},
                    state="active",
                    source=source,
                    cco_home=home,
                )
                jar_synced += 1
        except Exception:
            pass

    return {
        "hosts": sorted(by_host.keys()),
        "cookie_keys": sorted(cookie_keys),
        "vault_synced": vault_synced,
        "jar_synced": jar_synced,
        "filtered_out": filtered_out,
    }


def _extract_params(url: str, body: str, content_type: str = "") -> list[dict]:
    mem_dir = str(REPO_ROOT / "mcp-servers" / "mcp-memory-server")
    if mem_dir not in sys.path:
        sys.path.insert(0, mem_dir)
    from cco_surface_core.normalize import json_parameters, safe_sample

    params: list[dict] = []
    seen: set[tuple[str, str]] = set()
    parsed = urlparse(url)
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        name = k.strip()
        if not name or ("query", name) in seen:
            continue
        seen.add(("query", name))
        sample = safe_sample(name, v)
        params.append({"name": name, "in": "query", "sample": sample})

    raw = (body or "").strip()
    if not raw:
        return params
    ctype = (content_type or "").lower()
    if "json" in ctype or raw.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                params.extend(json_parameters(data))
                return params
        except Exception:
            pass
    if "form" in ctype or ("=" in raw and not raw.startswith("<")):
        try:
            for k, v in parse_qsl(raw, keep_blank_values=True)[:32]:
                name = str(k).strip()
                if not name or ("body", name) in seen:
                    continue
                seen.add(("body", name))
                sample = safe_sample(name, str(v))
                params.append({"name": name, "in": "body", "sample": sample})
        except Exception:
            pass
    return params


def ingest_captured_requests(
    requests_list: list[dict],
    *,
    target_hint: str = "",
    source: str = "agent_browse",
    cco_home: str | None = None,
    allow: set[str] | frozenset | None = None,
    session_binding: dict | None = None,
) -> dict:
    """Ingest captured browser/MITM HTTP requests into attack_surface.

    allow verilirse kapsam dışı host'ların istekleri DB'ye yazılmaz.
    """
    home = str(Path(cco_home or os.environ.get("CCO_HOME", "~/.cco")).expanduser())
    mem_dir = str(REPO_ROOT / "mcp-servers" / "mcp-memory-server")
    if mem_dir not in sys.path:
        sys.path.insert(0, mem_dir)
    from cco_surface_core.parsers import parse_xhr
    from cco_surface_core.store import ingest_records

    records: list[dict] = []
    filtered_out = 0
    for item in requests_list or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url or not url.startswith(("http://", "https://")) or _STATIC_EXT_RE.search(url):
            continue
        if not _is_in_allowlist(_host_of(url), allow):
            filtered_out += 1
            continue
        method = str(item.get("method") or "GET").upper()
        body_value = next((item[key] for key in ("req_body", "post_data", "body") if key in item), "")
        request_headers = item.get("req_headers") or item.get("headers") or {}
        ctype = str(item.get("content_type") or item.get("contentType") or "")
        if not ctype and isinstance(request_headers, dict):
            for hk, hv in request_headers.items():
                if str(hk).lower() == "content-type":
                    ctype = str(hv)
                    break
        status = item.get("status")
        # The shared parser computes GraphQL identity from the original envelope
        # before samples are redacted, and keeps each parameter's carrier.
        record = parse_xhr([{**item, "url": url, "method": method, "body": body_value,
                             "post_data": body_value, "headers": request_headers,
                             "content_type": ctype}])[0]
        if isinstance(item.get("params"), list):
            record["params"] = [*item["params"], *(p for p in record["params"] if p["in"] == "header")]
        record.update({
            "target": _host_of(target_hint) or _host_of(url),
            "status": status,
            "sources": list(dict.fromkeys(["xhr", source])),
            "auth_required": True if status in (401, 403) else None,
        })
        if session_binding is not None:
            from cco_surface_core.request_store import canonical_request, prepare_capture
            wire = canonical_request({**item, "url": url, "method": method,
                                      "headers": request_headers, "req_headers": request_headers,
                                      "body": body_value, "content_type": ctype})
            record["capture_binding"] = prepare_capture(wire, session_binding, home=home)
            record["_captured_request"] = wire
        records.append(record)

    if not records:
        return {"inserted": 0, "updated": 0, "skipped": 0, "total_touched": 0,
                "filtered_out": filtered_out}
    target = _host_of(target_hint) or records[0]["target"]
    db_path = os.path.join(home, "agent_memory.db")
    result = ingest_records(records, target=target, db_path=db_path)
    result["filtered_out"] = filtered_out
    return result


def _slug(text: str, index: int) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", (text or "").strip().lower()).strip("-")
    return f"s{index}-{cleaned[:28] or 'step'}"


def _body_dict_from_item(item: dict) -> dict:
    raw = item.get("req_body") or item.get("post_data") or item.get("body")
    if isinstance(raw, dict):
        return _redact_obj(dict(raw))
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("{"):
            try:
                d = json.loads(stripped)
                if isinstance(d, dict):
                    return _redact_obj(d)
            except Exception:
                pass
        elif "=" in stripped and not stripped.startswith("<"):
            try:
                return {
                    k.strip(): ("<redacted>" if _is_sensitive_key(k) else v[:80])
                    for k, v in parse_qsl(stripped, keep_blank_values=True)[:32]
                    if k.strip()
                }
            except Exception:
                pass
    out: dict = {}
    for p in item.get("params") or []:
        if isinstance(p, dict) and p.get("name") and p.get("in") in ("json", "body"):
            name = str(p["name"])
            sample = p.get("sample")
            if _is_sensitive_key(name):
                out[name] = "<redacted>"
            else:
                out[name] = sample if sample not in (None, "", "<redacted>") else "1"
    return out


def _resp_json_from_item(item: dict) -> dict:
    raw = item.get("resp_body") or item.get("response_body") or ""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip().startswith("{"):
        try:
            d = json.loads(raw)
            if isinstance(d, dict):
                return d
        except Exception:
            pass
    return {}


def _captured(item):
    ctx = item.get('observed_context') or {}
    return (isinstance(ctx, dict) and ctx.get('source') == 'capture'
            and all(isinstance(ctx.get(k), str) and ctx[k]
                    for k in ('capture_id', 'workflow_id', 'session_id', 'resource_id'))
            and isinstance(item.get('status'), int) and 100 <= item['status'] < 600
            and not item.get('capture_redacted') and not item.get('synthetic')
            and item.get('status_label') != 'draft_hypothesis')


def _value(data, path):
    for key in str(path).split('.'):
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def _request_value(item, ref):
    location, _, key = str(ref).partition('.')
    if location == 'body':
        return _value(_body_dict_from_item(item), key)
    if location == 'query':
        values = [v for k, v in parse_qsl(urlparse(item['url']).query) if k == key]
        return values[0] if len(values) == 1 else None
    if location == 'path':
        try:
            return urlparse(item['url']).path.strip('/').split('/')[int(key)]
        except (ValueError, IndexError):
            return None
    return None


def _linked(producer, consumer):
    a, b = producer['observed_context'], consumer['observed_context']
    for link in b.get('response_links') or []:
        if not isinstance(link, dict) or link.get('producer') != a['capture_id']:
            continue
        produced = _value(_resp_json_from_item(producer), link.get('response_field'))
        consumed = _request_value(consumer, link.get('request_field'))
        if (produced is not None and not isinstance(produced, (dict, list, bool))
                and str(produced) == str(consumed) == a['resource_id'] == b['resource_id']):
            return True
    return False


def _same_workflow(a, b):
    ac, bc = a['observed_context'], b['observed_context']
    ap, bp = urlparse(a['url']), urlparse(b['url'])
    return ((ap.scheme, ap.netloc) == (bp.scheme, bp.netloc)
            and all(ac[k] == bc[k] for k in ('workflow_id', 'session_id', 'resource_id')))


def _find_observer_url(mutator_url, gets, *, mutator=None):
    """Require a captured resource link. No URL-prefix or same-host fallback."""
    if not isinstance(mutator, dict) or mutator.get('url') != mutator_url or not _captured(mutator):
        return '', {}
    matches = [g for g in gets if _captured(g) and g.get('method', 'GET') == 'GET' and 200 <= g['status'] < 300
               and str(_value(_resp_json_from_item(g), g['observed_context'].get('resource_field', 'id')))
                   == g['observed_context']['resource_id']
               and _same_workflow(mutator, g) and (_linked(g, mutator) or _linked(mutator, g))]
    urls = {g['url'] for g in matches}
    if len(urls) != 1:
        return '', {}
    return matches[0]['url'], _resp_json_from_item(matches[0])


def compile_workflow_manifests(requests_list, *, target_ref='target', allow=None,
                               max_variants_per_endpoint=3, diagnostics=None):
    """Compile only explicitly sourced rules, normal controls and captured actions.

    Missing context is returned through ``diagnostics`` as prerequisite gaps.
    Synthetic bodies, inferred observers, automatic races and guessed business
    effects never produce an executable action manifest.
    """
    import copy

    diagnostics = diagnostics if diagnostics is not None else []
    records = [r for r in requests_list or [] if isinstance(r, dict)
               and str(r.get('url', '')).startswith(('http://', 'https://'))
               and _is_in_allowlist(_host_of(r['url']), allow)]
    indexed = {}
    for record in records:
        if _captured(record):
            cid = record['observed_context']['capture_id']
            if cid in indexed and indexed[cid] != record:
                diagnostics.append({'status': 'missing_prerequisite', 'reason': 'ambiguous_capture_id'})
                return []
            indexed[cid] = record
    gets = [r for r in indexed.values() if r.get('method') == 'GET']
    manifests, counts = [], {}

    def gap(reason, url):
        diagnostics.append({'status': 'missing_prerequisite', 'reason': reason, 'url': url})

    for mutator in records:
        if mutator.get('method') not in {'POST', 'PUT', 'PATCH'}:
            continue
        if not _captured(mutator):
            gap('unobserved_context', mutator['url'])
            continue
        obs_url, _ = _find_observer_url(mutator['url'], gets, mutator=mutator)
        if not obs_url:
            gap('unobserved_observer', mutator['url'])
            continue
        ctx = mutator['observed_context']
        rules = ctx.get('business_rules') or []
        if not rules:
            gap('unobserved_business_rule', mutator['url'])
        for rule in rules:
            if (not isinstance(rule, dict) or not isinstance(rule.get('contract'), dict)
                    or not all(isinstance(rule.get(role), dict) for role in ('control', 'probe'))):
                gap('invalid_business_rule', mutator['url'])
                continue
            contract = {**copy.deepcopy(rule.get('contract') or {}),
                        **{k: ctx[k] for k in ('workflow_id', 'session_id', 'resource_id')}}
            errors = contract_errors(contract)
            if errors:
                gap(errors[0], mutator['url'])
                continue
            steps, valid = [], True
            for role in ('control', 'probe'):
                flow = rule.get(role) or {}
                actions = flow.get('actions')
                if not isinstance(actions, list) or not all(isinstance(cid, str) for cid in actions):
                    gap('unobserved_' + role + '_workflow', mutator['url'])
                    valid = False
                    break
                ids = [flow.get('before'), *actions, flow.get('after')]
                if len(ids) < 3 or any(not isinstance(cid, str) or cid not in indexed for cid in ids):
                    gap('unobserved_' + role + '_workflow', mutator['url'])
                    valid = False
                    break
                if role == 'probe' and ctx['capture_id'] not in flow.get('actions', []):
                    gap('unobserved_probe_action', mutator['url'])
                    valid = False
                    break
                selected = [indexed[cid] for cid in ids]
                before, after = selected[0], selected[-1]
                if (before.get('method') != 'GET' or after.get('method') != 'GET'
                        or before['url'] != after['url']
                        or not _same_workflow(before, after)
                        or any(not _same_workflow(before, r) for r in selected)):
                    gap('mismatched_' + role + '_resource', mutator['url'])
                    valid = False
                    break
                if (role == 'probe' and (before['url'] != obs_url or not _same_workflow(before, mutator))):
                    gap('mismatched_probe_observer', mutator['url'])
                    valid = False
                    break
                # Every action must actually consume/produce this observer's resource.
                if any(r.get('method') not in {'POST', 'PUT', 'PATCH'} or not
                       (_linked(before, r) or _linked(r, before)) for r in selected[1:-1]):
                    gap('unobserved_action_resource_link', mutator['url'])
                    valid = False
                    break
                if (role == 'control' and (before['observed_context']['workflow_id'] != ctx['workflow_id']
                        or before['observed_context']['session_id'] != ctx['session_id']
                        or (urlparse(before['url']).scheme, urlparse(before['url']).netloc)
                           != (urlparse(obs_url).scheme, urlparse(obs_url).netloc)
                        or before['observed_context']['resource_id'] == ctx['resource_id'])):
                    gap('independent_normal_control_required', mutator['url'])
                    valid = False
                    break
                if role == 'control':
                    control_passed, _ = evaluate_normal_control(
                        {'contract': contract, 'control_before': 'before', 'control_after': 'after'},
                        {key: {'ok': True, 'status': record['status'],
                               'fulltext': json.dumps(_resp_json_from_item(record))}
                         for key, record in (('before', before), ('after', after))})
                    if not control_passed:
                        gap('unobserved_normal_effect', mutator['url'])
                        valid = False
                        break
                for i, record in enumerate(selected):
                    sid = role + ('-before' if i == 0 else '-after' if i == len(selected)-1 else f'-action-{i}')
                    is_get = record['method'] == 'GET'
                    args = {'url': record['url']}
                    if not is_get:
                        args.update(method=record['method'], body=copy.deepcopy(_body_dict_from_item(record)))
                    steps.append({'id': sid, 'tool': 'http_get' if is_get else 'http_post',
                                  'args': args, 'identity_refs': [record['observed_context'].get('identity_ref', 'owner')],
                                  'expect': {'oracle': 'status_code', 'status': [200, 201, 204, 400, 403, 409]},
                                  'on_success': 'succeed', 'on_failure': 'abort',
                                  'object_url': before['url'],
                                  'resource_id': before['observed_context']['resource_id'],
                                  'resource_field': before['observed_context'].get('resource_field', 'id'),
                                  'lifecycle_phase': 'pre_state' if i == 0 else 'post_state' if i == len(selected)-1 else 'experiment'})
            if not valid:
                continue
            # The normal workflow is a prerequisite, evaluated before probe traffic.
            for step, following in zip(steps, steps[1:]):
                step['on_success'] = following['id']
            expect = {'oracle': 'business_logic', 'contract': contract,
                      **{key: key.replace('_', '-') for key in
                         ('control_before', 'control_after', 'probe_before', 'probe_after')}}
            control_after = next(s for s in steps if s['id'] == 'control-after')
            control_after['expect'] = {**copy.deepcopy(expect), 'oracle': 'business_control'}
            steps[-1]['expect'] = expect
            m = {'schema_version': SCHEMA_VERSION, 'kind': contract['kind'],
                 'objective': contract['expected_rule'], 'target_ref': target_ref,
                 'risk': 'active_state_changing', 'status': 'runnable',
                 'business_logic': expect, 'observed_context': copy.deepcopy(ctx),
                 'budget': {'max_requests': len(steps), 'max_duration_seconds': 60},
                 'identity_refs': sorted({ref for s in steps for ref in s['identity_refs']}), 'steps': steps}
            signature = json.dumps(m, sort_keys=True)
            limit_key = (mutator['url'], contract['kind'])
            if counts.get(limit_key, 0) >= max(1, int(max_variants_per_endpoint)):
                continue
            if any(json.dumps({k: v for k, v in old.items() if k != 'manifest_hash'}, sort_keys=True) == signature for old in manifests):
                continue
            check = validate_manifest(m)
            if check['valid']:
                m['manifest_hash'] = check['manifest_hash']
                manifests.append(m)
                counts[limit_key] = counts.get(limit_key, 0) + 1
    return manifests
