"""Wire discover → crawl → fuzz → validator → exploit_confirmed into one loop.

Dump/ascan/sqlmap yok. IDOR/SSRF/XXE otomatik değil (ek kimlik/OOB gerekir).
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlsplit

from .experiments import ROUTES, PASSIVE_ADAPTERS, tool_lifecycle, protocol_access

AUTO_VALIDATE = {
    **{kind: ROUTES[kind]["tool"] for kind in (
        "sql_injection", "ssti", "open_redirect", "path_traversal", "xss_reflected")},
    "lfi": ROUTES["path_traversal"]["tool"],
    "command_injection": "validate_command_injection",
    "xxe": "validate_xxe",
    "deserialization": "validate_deserialization",
    "opaque_token": "validate_token_differential",
}

SKIP_AUTO = {
    "idor", "bola", "bfla", "ssrf", "authentication_bypass",
    "broken_access_control", "csrf",
}

# Faz 5/6-tool: salt-okunur (GET) authz alt kumesi — kimlik + authz oracle ile otomatik.
AUTHZ_AUTO = {"idor", "bola", "bfla", "authentication_bypass"}

# OOB gerektiren siniflar: yalnizca oob_validate enjekte edilirse otomatik.
OOB_AUTO = {"ssrf"}


def loop_plan(target: str, crawl: bool = True, zap: bool = False) -> list[dict]:
    steps = [
        {"step": "discover", "tool": "discover_web_surface", "target": target},
        {"step": "crawl", "tool": "crawl_web_surface", "target": target, "optional": not crawl,
         "skip_if": "crawl=False or playwright missing"},
        {"step": "fuzz", "tool": "fuzz_attack_surface", "live": True},
        {"step": "validate", "tool": "validator.validate_*", "classes": sorted(AUTO_VALIDATE),
         "authz_classes": sorted(AUTHZ_AUTO),
         "authz_note": "GET + kimlik (auth_bypass 1, digerleri 2)",
         "oob_classes": sorted(OOB_AUTO), "oob_note": "oob_validate (CCO_OOB_DOMAIN) gerekli",
         "surface_hooks": [], "passive_adapters": list(PASSIVE_ADAPTERS),
         "skip": sorted(SKIP_AUTO - AUTHZ_AUTO - OOB_AUTO)},
        {"step": "exploit", "tool": "exploit_confirmed", "if": "verdict==CONFIRMED",
         "allow_deepen": False},
    ]
    if zap:
        steps.insert(2, {"step": "zap", "tool": "zap_map_surface", "allow_ascan": False})
    return steps


def _as_dict(payload):
    if payload is None:
        return {}
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return {}
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {"ok": False, "error": text[:300], "raw": text[:300]}
        return data if isinstance(data, dict) else {"value": data}
    return {"value": payload}


def _pipeline_context(item, identity="unspecified", run_id=""):
    """Return operation metadata only; request refs, samples and secrets stay private."""
    return {"url": item.get("url") or "", "method": str(item.get("method") or "GET").upper(),
            "vuln_class": item.get("vuln_class") or "", "param": item.get("param") or "",
            "carrier": item.get("carrier") or item.get("location") or "query",
            "identity": item.get("attacker_identity") or item.get("identity") or identity,
            "resource_owner": item.get("owner_identity") or item.get("resource_owner") or "unspecified",
            "run_id": item.get("run_id") or run_id or "unspecified",
            **{key: item[key] for key in ("fingerprint", "operation_id", "observation_id", "candidate_source", "candidate_reason", "access_rule_hash", "resource_key", "resource_family", "state_key", "variant_key") if item.get(key)}}


_MUTATION_HINT = ("create", "update", "delete", "remove", "login", "signin",
                  "signup", "register", "reset", "upload", "set", "add")
_ID_HINT = ("user", "order", "account", "profile", "invoice", "payment", "file")


def parse_suggested_fields(probe_text: str) -> list:
    """graphql_suggestion çıktısından ('probex' → a, b) field isimlerini çek."""
    import re
    fields: list = []
    for line in str(probe_text or "").splitlines():
        if "→" not in line:
            continue
        rhs = line.split("→", 1)[1]
        for name in rhs.split(","):
            name = name.strip().strip("'")
            if name and name not in fields:
                fields.append(name)
    return fields


def plan_graphql_operations(fields) -> list:
    """Operasyon kapsama planı (Faz 5): her field için denenecek test sınıfları."""
    plan = []
    for name in fields or []:
        low = str(name).lower()
        if any(h in low for h in _MUTATION_HINT):
            tests = ["authz_matrix", "mass_assignment"]
        elif any(h in low for h in _ID_HINT):
            tests = ["bola", "authz_matrix"]
        else:
            tests = ["authz_matrix"]
        plan.append({"operation": str(name), "tests": tests})
    return plan


def _is_confirmed(result: dict) -> bool:
    if (result.get("verdict") or "").upper() == "CONFIRMED":
        return True
    evidence = result.get("evidence") or {}
    if isinstance(evidence, dict):
        reflection = evidence.get("reflection") or {}
        if isinstance(reflection, dict) and (reflection.get("verdict") or "").upper() == "CONFIRMED":
            return False  # XSS reflection-only: merdivene girme
    return False


def _origin(value: str) -> tuple[str, str, int | None]:
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
            return "", "", None
        return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or (
            443 if parsed.scheme.lower() == "https" else 80 if parsed.scheme.lower() == "http" else None)
    except ValueError:
        return "", "", None


def _matches_observed(candidate: str, owned_url: str) -> bool:
    """Match the exact observed resource or one explicit path template."""
    try:
        left, right = urlsplit(candidate), urlsplit(owned_url)
    except ValueError:
        return False
    if _origin(candidate) != _origin(owned_url) or not left.hostname or not right.hostname:
        return False
    if left.query != right.query:
        return False
    pieces = re.split(r"(\{[A-Za-z_][A-Za-z0-9_]*\})", left.path)
    pattern = "".join(r"[^/]+" if re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*\}", p)
                      else re.escape(p) for p in pieces)
    return bool(re.fullmatch(pattern, right.path))


def _owned_authz_items(item: dict, identities: dict) -> list[dict]:
    """Bind a candidate to explicit own objects and distinct test identities."""
    if not isinstance(identities, dict):
        return []
    if item.get("vuln_class") in {"bfla", "authentication_bypass"}:
        from .access_context import bind_declared_access
        declared = bind_declared_access(item, identities, _matches_observed)
        return declared
    bound = []
    for owner, identity in identities.items():
        if not isinstance(identity, dict) or not isinstance(identity.get("headers"), dict):
            continue
        for obj in identity.get("objects") or []:
            if not isinstance(obj, dict):
                continue
            url, marker = str(obj.get("url") or ""), str(obj.get("marker") or "")
            if not marker or not _matches_observed(str(item.get("url") or ""), url):
                continue
            for attacker, other in identities.items():
                if attacker == owner or not isinstance(other, dict):
                    continue
                from authz_matrix import object_access_blocked
                if object_access_blocked(obj, identity, other):
                    continue
                attacker_headers = other.get("headers") if isinstance(other.get("headers"), dict) else other
                if not attacker_headers or attacker_headers == identity["headers"]:
                    continue
                owner_role, attacker_role = str(identity.get("role") or ""), str(other.get("role") or "")
                if item.get("vuln_class") == "bfla" and (not owner_role or not attacker_role
                                                          or owner_role == attacker_role):
                    continue
                bound.append({**item, "url": url, "owner_identity": owner,
                              "attacker_identity": attacker, "owner_marker": marker,
                              "owner_role": owner_role, "attacker_role": attacker_role,
                              "owned_object": True})
    return bound


def _session_request_fields(cookie: str, headers: str, identities: dict) -> dict:
    """Use transient fields only when the supplied credentials match one identity."""
    try:
        supplied = json.loads(headers) if str(headers or "").strip().startswith("{") else {}
    except (TypeError, ValueError):
        supplied = {}
    if not isinstance(supplied, dict):
        supplied = {}
    if not supplied and headers:
        for part in re.split(r"\n|;(?=\s*[A-Za-z0-9-]+\s*:)", str(headers)):
            name, sep, value = part.partition(":")
            if sep and name.strip():
                supplied[name.strip()] = value.strip()
    if cookie and not any(str(key).lower() == "cookie" for key in supplied):
        supplied["Cookie"] = cookie
    credential_names = {"cookie", "authorization", "proxy-authorization", "x-api-key", "api-key"}
    actual = {str(k).lower(): str(v) for k, v in supplied.items() if str(k).lower() in credential_names}
    if not actual or not isinstance(identities, dict):
        return {}
    matches = []
    for identity in identities.values():
        if not isinstance(identity, dict) or not isinstance(identity.get("headers"), dict):
            continue
        expected = {str(k).lower(): str(v) for k, v in identity["headers"].items()
                    if str(k).lower() in credential_names}
        if expected == actual and isinstance(identity.get("request_fields"), dict):
            matches.append(identity["request_fields"])
    if len(matches) != 1:
        return {}
    return dict(matches[0])


_DISCOVER_QUEUE_BLOAT_KEYS = frozenset({
    "work_queue", "frontier", "probe", "wordlist_sample",
    "visited_states", "feature_map", "continuation_queue", "external_sources",
})


def compact_loop_discover(report: dict) -> dict:
    """Return a shallow copy of report without bulky inline discover or matrix arrays."""
    if not isinstance(report, dict):
        return report
    updated = report
    discover_row = report.get("discover")
    if isinstance(discover_row, dict) and any(key in discover_row for key in _DISCOVER_QUEUE_BLOAT_KEYS):
        trimmed = {key: val for key, val in discover_row.items() if key not in _DISCOVER_QUEUE_BLOAT_KEYS}
        updated = {**updated, "discover": trimmed}
    matrix_doc = report.get("identity_matrix")
    if isinstance(matrix_doc, dict):
        matrix_rows = matrix_doc.get("matrix") if isinstance(matrix_doc.get("matrix"), list) else []
        missing_rows = matrix_doc.get("missing_coverage") if isinstance(matrix_doc.get("missing_coverage"), list) else []
        if len(matrix_rows) + len(missing_rows) > 8:
            updated = {
                **updated,
                "identity_matrix": {
                    "matrix": [],
                    "missing_coverage": [],
                    "count": len(matrix_rows),
                    "total": len(missing_rows),
                },
            }
    return updated


def public_loop_report(report: dict) -> dict:
    """Project an execute_web_loop report without bloating inline discover queues."""
    from .request_context import public_discovery_report
    return public_discovery_report(compact_loop_discover(report))


def execute_web_loop(
    target: str,
    *,
    live: bool = False,
    crawl: bool = True,
    zap: bool = False,
    cookie: str = "",
    headers: str = "",
    fuzz_limit: int = 8,
    max_validations: int = 6,
    sleep_s: float = 0.15,
    discover=None,
    crawl_fn=None,
    zap_fn=None,
    fuzz=None,
    validate=None,
    exploit=None,
    identities=None,
    authz_validate=None,
    oob_validate=None,
    surface_hooks=None,
    on_validation=None,
    on_confirmation=None,
    on_plan=None,
    run_id="",
    identity="unspecified",
    identity_discover=None,
    on_discovery_state=None,
    on_private_report=None,
) -> dict:
    """Callable'lar inject edilir (test) veya hunter facade bağlar."""
    plan = loop_plan(target, crawl=crawl, zap=zap)
    report = {
        "ok": True,
        "engine": "run_web_loop (discover→crawl→fuzz→validate→exploit_confirmed)",
        "target": target,
        "mode": "LIVE" if live else "PLAN",
        "plan": plan,
        "allow_deepen": False,
        "ascan": False,
        "steps": [],
        "discover": {},
        "discovery_operations": [],
        "crawl": {},
        "zap": {},
        "fuzz": {},
        "validations": [],
        "validation_candidates": [],
        "validation_queue": [],
        "budgets": {"validation_limit": max(0, int(max_validations)), "validations_used": 0},
        "confirmed": [],
        "surface_probes": [],
        "tool_states": [{"adapter": kind, "mode": "passive_inventory", **tool_lifecycle(
            available=bool((surface_hooks or {}).get(kind)),
            reason="active_adapter_deferred")} for kind in PASSIVE_ADAPTERS],
        "skipped": [],
        "exploits": [],
        "errors": [],
        "next": "CONFIRMED paketleri store_validated_finding. Dump yok.",
    }
    def finish():
        if on_private_report is not None:
            import copy
            on_private_report(copy.deepcopy(report))
        return public_loop_report(report)
    from authz_matrix import build_identity_matrix
    matrix_objects = [dict(obj, owner_identity=name) for name, actor in (identities or {}).items()
                      if isinstance(actor, dict) for obj in actor.get("resources", actor.get("objects", []))
                      if isinstance(obj, dict) and all(k in obj for k in ("resource_id", "tenant", "family"))]
    report["identity_matrix"] = build_identity_matrix(identities or {}, matrix_objects)
    if not live:
        report["next"] = "live=True ile aynı tool zinciri koşar (scope/onay tek grant)."
        return finish()

    def record_validation(item, result, row):
        # Diagnostic text is mapped to a fixed reason before report output.
        from .feedback import reason_action
        report["budgets"]["validations_used"] = len(report["validations"])
        row["feedback_reason"] = reason_action(result.get("error") or result.get("notes") or "")[0]
        row["tool_lifecycle"] = tool_lifecycle(available=True, applicable=True, runnable=True,
            executed=bool(result.get("validation_id")), reason=row["feedback_reason"])
        if on_validation is None:
            return
        try:
            row["coverage_recorded"] = bool(on_validation(target, item, result))
            row["tool_lifecycle"]["executed"] = bool(row["coverage_recorded"] or result.get("validation_id"))
            row["tool_lifecycle"]["validated"] = bool(row["coverage_recorded"] and row["verdict"] in {"CONFIRMED", "UNCONFIRMED"})
        except Exception as exc:
            row["coverage_recorded"] = False
            report["errors"].append(f"coverage record: {type(exc).__name__}")

    def confirmed_with_evidence(item, result, row):
        if not _is_confirmed(result):
            return False
        if on_confirmation is None:
            return True
        try:
            valid = bool(row.get("coverage_recorded") and on_confirmation(target, item, result))
        except Exception as exc:
            valid = False
            report["errors"].append(f"confirmation evidence: {type(exc).__name__}")
        if not valid:
            row["verdict"] = "INCONCLUSIVE"
            row["tool_lifecycle"]["validated"] = False
            row["error"] = "confirmed result lacks trusted matching request evidence"
        return valid
    seen = set()

    def consume_candidates(candidates):
        queue = []
        for item in candidates:
            if not isinstance(item, dict):
                continue
            if not item.get("operation_id") and (item.get("authz_candidate") or item.get("owned_object")):
                from cco_surface_core.operation import operation_id, operation_descriptor
                item = {**item, "operation_id": operation_id(item.get("url") or "", item.get("method") or "GET",
                                                             operation_descriptor(item))}
            report["validation_candidates"].append(_pipeline_context(item, identity, run_id))
            if item.get("authz_candidate"):
                if _origin(str(item.get("url") or "")) != _origin(target):
                    report["skipped"].append({**_pipeline_context(item, identity, run_id),
                                              "reason": "candidate outside target origin"})
                    continue
                bound = _owned_authz_items(item, identities or {})
                if not bound:
                    from .access_context import access_prerequisites
                    if on_plan is not None and item.get("vuln_class") in {"bfla", "authentication_bypass"}:
                        # Preserve the observed candidate privately for later binding.
                        # This is a not-tested plan, never an executable task.
                        try:
                            on_plan(target, {**item, "run_id": run_id or "unspecified", "identity": identity,
                                             "resource_owner": "unspecified"})
                        except Exception:
                            pass
                    report["skipped"].append({**_pipeline_context(item, identity, run_id),
                                              "reason": "authz test identities or declared test resource prerequisites missing",
                                              "reason_code": "missing_access_context",
                                              "preconditions": access_prerequisites(item.get("vuln_class"))})
                    continue
                queue.extend(bound)
            else:
                queue.append(item)
        from .candidates import candidate_key, fair_queue
        queue = fair_queue(queue)
        queue = [{**item, "identity": item.get("attacker_identity") or identity,
                  "resource_owner": item.get("owner_identity") or "unspecified",
                  "run_id": run_id or "unspecified"} for item in queue]
        unique = []
        for item in queue:
            key = candidate_key(item)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        queue = unique
        report["validation_queue"].extend(_pipeline_context(item, identity, run_id) for item in queue)
        if on_plan is not None:
            for item in queue:
                try:
                    item["coverage_plan_recorded"] = bool(on_plan(target, item))
                except Exception:
                    item["coverage_plan_recorded"] = False

        for item in queue:
            from .request_context import current_policy_gate
            gate = current_policy_gate()
            gate_stopped = gate.stop_reason() if gate is not None and callable(getattr(gate, "stop_reason", None)) else ""
            if gate_stopped:
                report["ok"] = False
                report["stopped"] = gate_stopped
                report["skipped"].append({"step": "remaining", "reason": gate_stopped})
                break
            vclass = str(item.get("vuln_class") or "")
            context = _pipeline_context(item, identity, run_id)
            context["access_dimensions"] = protocol_access(item)
            if vclass in OOB_AUTO:
                if oob_validate is None:
                    report["skipped"].append({**context,
                                              "reason": "oob auto: needs oob_validate (CCO_OOB_DOMAIN)"})
                    continue
                if len(report["validations"]) >= max(0, int(max_validations)):
                    report["skipped"].append({**context, "reason": "max_validations"})
                    continue
                try:
                    result = _as_dict(oob_validate(item))
                except Exception as exc:
                    result = {"verdict": "INCONCLUSIVE", "error": str(exc)}
                row = {**context,
                       "verdict": result.get("verdict"),
                       "validation_id": result.get("validation_id") or "",
                       "hook": "oob_oracle"}
                report["validations"].append(row)
                record_validation(item, result, row)
                if confirmed_with_evidence(item, result, row):
                    report["confirmed"].append(row)
                continue
            if vclass in AUTHZ_AUTO:
                if on_plan is not None and item.get("authz_candidate") and not item.get("coverage_plan_recorded"):
                    report["skipped"].append({**context,
                                              "reason": "signed coverage plan unavailable"})
                    continue
                method = str(item.get("method") or "GET").upper()
                if method != "GET":
                    report["skipped"].append({**context,
                                              "reason": "authz auto: only GET"})
                    continue
                needed = 1 if vclass == "authentication_bypass" else 2
                if not identities or len(identities) < needed:
                    report["skipped"].append({**context,
                                              "reason": f"authz auto: needs {needed} identities"})
                    continue
                if authz_validate is None:
                    report["skipped"].append({**context,
                                              "reason": "authz auto: no authz validator"})
                    continue
                if len(report["validations"]) >= max(0, int(max_validations)):
                    report["skipped"].append({**context, "reason": "max_validations"})
                    continue
                try:
                    result = _as_dict(authz_validate(item, identities))
                except Exception as exc:
                    result = {"verdict": "INCONCLUSIVE", "error": str(exc)}
                row = {
                    **context,
                    "verdict": result.get("verdict"),
                    "validation_id": result.get("validation_id") or "",
                    "hook": "authz_oracle",
                }
                if item.get("owned_object") or item.get("test_resource"):
                    row.update(owner_identity=item.get("owner_identity"),
                               attacker_identity=item.get("attacker_identity"))
                report["validations"].append(row)
                record_validation(item, result, row)
                if confirmed_with_evidence(item, result, row):
                    report["confirmed"].append(row)
                continue
            if vclass in SKIP_AUTO or vclass not in AUTO_VALIDATE:
                report["skipped"].append({**context, "reason": "not auto-validated"})
                continue
            if len(report["validations"]) >= max(0, int(max_validations)):
                report["skipped"].append({**context, "reason": "max_validations"})
                continue
            if validate is None:
                report["skipped"].append({**context, "reason": "no validator"})
                continue
            try:
                result = _as_dict(validate(item, headers=headers, cookie=cookie))
            except Exception as exc:
                result = {"verdict": "INCONCLUSIVE", "error": str(exc)}
            row = {
                **context,
                "verdict": result.get("verdict"),
                "validation_id": result.get("validation_id") or "",
                "hook": AUTO_VALIDATE[vclass],
            }
            report["validations"].append(row)
            record_validation(item, result, row)
            if confirmed_with_evidence(item, result, row):
                report["confirmed"].append(row)
                if exploit is not None and row["validation_id"]:
                    try:
                        packed = _as_dict(exploit(row["validation_id"]))
                    except Exception as exc:
                        packed = {"ok": False, "error": str(exc)}
                    report["exploits"].append({
                        "ok": packed.get("ok"),
                        "validation_id": row["validation_id"],
                        "vuln_class": packed.get("vuln_class") or vclass,
                        "error": packed.get("error") or "",
                    })
                    report["steps"].append("exploit")

    if not (target or "").strip():
        report["ok"] = False
        report["errors"].append("target gerekli")
        return finish()

    discovered_candidates = []
    if identity_discover is not None:
        try:
            summary, identities, discovered_candidates = identity_discover(target, identities or {})
            if not isinstance(summary, dict) or not isinstance(identities, dict) or not isinstance(discovered_candidates, list):
                raise ValueError("invalid discovery result")
        except Exception:
            summary = {"status": "blocked", "reasons": ["identity discovery unavailable"]}
            discovered_candidates = []
        report["identity_discovery"] = summary
        if summary.get("status") == "ready" and not summary.get("reasons") and not summary.get("budget_limited"):
            from .request_context import capture_state
            try:
                private_state = capture_state(identities)
                report["identity_discovery_state"] = private_state
                if on_discovery_state is not None:
                    on_discovery_state(private_state)
            except ImportError:
                if os.environ.get("CCO_PYTHON_DISCOVERY_INVOCATION"):
                    raise
        matrix_objects = [dict(obj, owner_identity=name) for name, actor in identities.items()
                          if isinstance(actor, dict) for obj in actor.get("resources", [])
                          if isinstance(obj, dict) and all(k in obj for k in ("resource_id", "tenant", "family"))]
        report["identity_matrix"] = build_identity_matrix(identities, matrix_objects)
        report["steps"].append("identity_discovery")
        reasons = summary.get("reasons") or []
        if summary.get("status") == "blocked":
            report["ok"] = False
            report["skipped"].append({"step": "remaining", "reason": str(reasons[0] if reasons else "identity discovery blocked")})
            return finish()
        report["discovery_operations"] = [{**_pipeline_context(item, identity, run_id),
                                            "sources": ["identity_discovery"]}
                                           for item in discovered_candidates if isinstance(item, dict)]
        if summary.get("status") != "ready" or reasons:
            report["skipped"].append({"step": "identity_discovery",
                                      "reason": str(reasons[0] if reasons else "owned object discovery incomplete")})

    if discovered_candidates:
        consume_candidates(discovered_candidates)

    identity_only = (identity_discover is not None and not crawl and not zap and int(fuzz_limit) == 0)
    if identity_only:
        report["skipped"].append({"step": "discover", "reason": "identity-only slice has its own observed discovery"})
    if discover is not None and not identity_only:
        try:
            discovered = _as_dict(discover(target, cookie=cookie, headers=headers))
        except Exception as exc:
            discovered = {"ok": False, "error": str(exc)}
        report["discover"] = discovered
        report["steps"].append("discover")
        if discovered.get("error") and not discovered.get("ingested"):
            report["errors"].append(str(discovered.get("error")))
        if discovered.get("stop_reason"):
            report["ok"] = False
            report["skipped"].append({"step": "remaining", "reason": discovered["stop_reason"]})
            return finish()
    if crawl and crawl_fn is not None:
        try:
            crawled = _as_dict(crawl_fn(target, cookie=cookie, headers=headers))
        except Exception as exc:
            crawled = {"ok": False, "error": str(exc)}
        report["crawl"] = crawled
        report["steps"].append("crawl")
        if crawled.get("ok") is False:
            report["errors"].append(str(crawled.get("error") or "crawl failed"))
        if crawled.get("stop_reason"):
            report["ok"] = False
            report["skipped"].append({"step": "remaining", "reason": crawled["stop_reason"]})
            return finish()
    elif crawl:
        report["skipped"].append("crawl: no crawl_fn")
    if zap and zap_fn is not None:
        try:
            zapped = _as_dict(zap_fn(target))
        except Exception as exc:
            zapped = {"ok": False, "error": str(exc)}
        report["zap"] = zapped
        report["steps"].append("zap")
        if zapped.get("ok") is False:
            report["errors"].append(str(zapped.get("error") or "zap skipped"))

    # Advanced adapters are inventory only in P6. A registered hook is not
    # an executed or validated probe, even when the caller injects a callable.
    hooks = surface_hooks or {}
    for name in hooks:
        if name != "jwt_kid_jku":
            report["skipped"].append({"step": name, "reason": "active_adapter_deferred"})
    jwt = re.search(r"\bBearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", headers or "", re.I)
    if jwt and callable(hooks.get("jwt_kid_jku")):
        state = {"adapter": "jwt_kid_jku", **tool_lifecycle(available=True, applicable=True, runnable=True)}
        report["tool_states"].append(state)
        try:
            hooks["jwt_kid_jku"](target, jwt.group(1))
            state["executed"] = True
            report["surface_probes"].append({"hook": "jwt_kid_jku", "url": target, "validated": False})
            report["steps"].append("jwt_kid_jku")
        except Exception:
            state["reason"] = "jwt_validator_failed"
    elif "jwt_kid_jku" in hooks:
        report["skipped"].append({"step": "jwt_kid_jku", "reason": "observed_flow_required"})

    fuzzed = {}
    if fuzz is not None and not identity_only:
        try:
            from .candidates import candidate_listener
            with candidate_listener(lambda item: consume_candidates([item])):
                fuzzed = _as_dict(fuzz(
                    target, live=True, limit=fuzz_limit, headers=headers, cookie=cookie,
                    request_field_values=_session_request_fields(cookie, headers, identities or {}),
                    sleep_s=sleep_s,
                ))
        except Exception as exc:
            fuzzed = {"ok": False, "error": str(exc)}
        report["fuzz"] = {
            "candidate_sampling": fuzzed.get("candidate_sampling") or {},
            "likely_hits": fuzzed.get("likely_hits") or [],
            "validator_queue": fuzzed.get("validator_queue") or [],
            "probes": fuzzed.get("probes"),
            "executed_live": fuzzed.get("executed_live"),
            "requests_sent": fuzzed.get("requests_sent"),
            "stopped": fuzzed.get("stopped") or "",
            "marked_tested": fuzzed.get("marked_tested") or [],
            "fanout": [{**_pipeline_context({**row, "url": row.get("baseline_url") or row.get("url"),
                                              "method": row.get("baseline_method") or row.get("method")}, identity, run_id),
                        **{key: row[key] for key in ("live", "status", "baseline_eligible", "triage_verdict",
                                                    "coverage_status", "reason") if key in row}}
                       for row in fuzzed.get("fanout") or [] if isinstance(row, dict)],
        }
        report["steps"].append("fuzz")
        if fuzzed.get("error"):
            report["errors"].append(str(fuzzed.get("error")))
        if fuzzed.get("stopped"):
            report["ok"] = False
            report["skipped"].append({"step": "remaining", "reason": fuzzed["stopped"]})
            return finish()
        if not fuzzed.get("probes"):
            # Sessiz boş koşu yok: kuyruk boşsa raporda görünür ol
            report["skipped"].append({
                "step": "fuzz", "reason": "yuzey kuyrugu bos (0 probe) — discover/crawl kaydi yok veya hedef anahtari uyumsuz"})

    consume_candidates([*discovered_candidates, *(fuzzed.get("validator_queue") or [])])
    # Faz 5: ikinci derece revisit — confirmed uçlar varyant/zincir için aday
    report["revisit_candidates"] = sorted(
        {str(r.get("url")) for r in report["confirmed"] if r.get("url")})
    if report["validations"]:
        report["steps"].append("validate")
    if report["errors"] and not (report["discover"] or report["fuzz"] or report["confirmed"]):
        report["ok"] = False
    return finish()
