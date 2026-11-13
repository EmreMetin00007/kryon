"""Chain-runner executor (13b) — doğrulanmış manifestleri çalıştırır.

Her ağ adımı policy gate'ten geçer (fail-closed), bütçe + süre izlenir,
oracle'lar adım sonuçlarından deterministik değerlendirilir. Kimlikler
ctx üzerinden enjekte edilir (vault'a executor dokunmaz).
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from urllib.parse import urljoin

from action_manifest import ORACLES, validate_manifest
from chain_transport import ChainAbort, ChainTransport
from runtime_paths import runtime_root
from business_logic import is_business_type, evaluate_business_logic, evaluate_normal_control

STEP_TOOLS = frozenset({"http_get", "http_post", "mailbox_poll", "batch_probe", "race_burst",
                         "oob_poll", "wait", "validate", "store_finding", "extract"})

HTTP_FAMILY = frozenset({"http_get", "http_post", "mailbox_poll"})

MAX_BATCH_ITEMS = 200
MAX_BATCH_RPS = 5.0
DEFAULT_BATCH_RPS = 2.0

MAX_BURST_ITEMS = 100
MAX_BURST_CONCURRENCY = 50
MAX_BURST_ROUNDS = 20
BURST_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"})

_SERVER_MODULES: dict = {}


def _lazy_server(name: str):
    """mcp-<name>/server.py modülünü repo içinden yükle (gecikmeli)."""
    import importlib.util
    import sys

    if name in _SERVER_MODULES:
        return _SERVER_MODULES[name]
    repo_root = str(runtime_root())
    path = os.path.join(repo_root, "mcp-servers", f"mcp-{name}", "server.py")
    spec = importlib.util.spec_from_file_location(f"cco_chain_{name.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _SERVER_MODULES[name] = module
    return module


def default_validate_provider(payload: dict) -> dict:
    """Validator artifact'ı üret (kayıtlı kanıt üzerinden, yeni ağ isteği yok)."""
    import json as _json

    validator = _lazy_server("validator")
    verdict = payload.get("verdict", "UNCONFIRMED")
    if is_business_type(payload.get('vuln_type')):
        detail = payload.get('evidence') or {}
        if not (payload.get('oracle') == 'business_logic'
                and detail.get('normal_control_passed') is True
                and detail.get('violation_effect_observed') is True
                and detail.get('business_rule_ref')):
            verdict = 'UNCONFIRMED'
    out = _json.loads(validator._result(
        payload.get("vuln_type", "unknown"),
        payload.get("target_url", ""),
        verdict,
        payload.get("oracle", ""),
        payload.get("evidence", {}),
        payload.get("reproduction", "-"),
        notes=payload.get("notes", "chain-runner: kayıtlı adım kanıtı üzerinden oracle."),
        severity=payload.get("severity", "high"),
        guard={
            "prerequisites": ["recorded chain step evidence"],
            "controls": ["deterministic oracle on recorded responses", "no new network probes"],
            "transport_ok": True,
            "decision_rule": payload.get("oracle", ""),
            "limitations": ["evidence recorded by chain steps, not live re-probed"],
        },
        request_evidence=payload.get("request_evidence", []),
    ))
    artifact = out.get("artifact") or {}
    return {"verdict": out.get("verdict", verdict),
            "validation_id": out.get("validation_id", ""),
            "artifact_path": artifact.get("path", ""),
            "oracle": out.get("oracle", "")}


def default_finding_store(payload: dict) -> dict:
    """Bulguyu memory'ye kaydet (artifact-backed ise reportable)."""
    memory = _lazy_server("memory-server")
    stored = memory._store_finding_internal(
        payload.get("target", ""),
        payload.get("type", ""),
        payload.get("severity", "medium"),
        payload.get("description", ""),
        payload=payload.get("payload", ""),
        validation_result_json=payload.get("validation_result_json", ""),
        validation_artifact_path=payload.get("validation_artifact_path", ""),
    )
    validation = stored.get("validation", {})
    return {"finding_id": stored.get("finding_id"),
            "validation_state": validation.get("validation_state", ""),
            "validation_verdict": validation.get("validation_verdict", ""),
            "reportable": bool(validation.get("reportable"))}

_REF_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")


class ResilientSession:
    """401'de otomatik re-login + tek retry (SessionGuardian).

    login_provider: () -> {"headers": {...}} çağrılabilirı. Provider yoksa
    veya retry de 401 dönerse yanıt aynen geçilir (sonsuza retry yok).
    """

    def __init__(self, login_provider=None, sender=None, max_retries: int = 1):
        self.login_provider = login_provider
        self.sender = sender or _default_sender
        self.max_retries = max(0, int(max_retries))
        self.relogins = 0
        self.jar = CookieJar()

    def request(self, method: str, url: str, headers: dict, body, timeout: int) -> dict:
        active = dict(headers or {})
        jar_cookie = self.jar.header_value()
        if jar_cookie and not any(k.lower() == "cookie" for k in active):
            active["Cookie"] = jar_cookie
        resp = self.sender(method, url, active, body, timeout)
        self.jar.absorb(resp.get("headers"))
        attempts = 0
        while (resp.get("ok") and resp.get("status") == 401
               and self.login_provider is not None and attempts < self.max_retries):
            attempts += 1
            try:
                fresh = self.login_provider() or {}
            except Exception:
                break
            new_headers = fresh.get("headers", fresh) if isinstance(fresh, dict) else {}
            if not isinstance(new_headers, dict) or not new_headers:
                break
            for key, value in new_headers.items():
                active[str(key)] = str(value)
            self.relogins += 1
            resp = self.sender(method, url, active, body, timeout)
            self.jar.absorb(resp.get("headers"))
        resp = dict(resp)
        resp["relogins_used"] = attempts
        return resp


def totp_code(secret_b32: str, timestamp: float | None = None,
              digits: int = 6, period: int = 30) -> str:
    """RFC 6238 TOTP (SHA-1). Test vektoru: JBSWY3DPEHPK3PXP."""
    import base64
    import hashlib as _hashlib
    import hmac as _hmac
    import struct
    import time as _time

    key = base64.b32decode(secret_b32.strip().upper())
    counter = int((timestamp if timestamp is not None else _time.time()) // period)
    digest = _hmac.new(key, struct.pack(">Q", counter), _hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


class CookieJar:
    """Basit cookie kavanozu: Set-Cookie em, Cookie header uret."""

    def __init__(self):
        self._cookies: dict[str, str] = {}

    def absorb(self, headers: dict | None) -> None:
        raw = ""
        for key, value in (headers or {}).items():
            if str(key).lower() == "set-cookie":
                raw = value if isinstance(value, str) else "; ".join(map(str, value))
                break
        if not raw:
            return
        for part in re.split(r", (?=[^;,= ]+=[^;,]*)", raw):
            first = part.split(";", 1)[0].strip()
            if "=" in first:
                name, val = first.split("=", 1)
                if val:
                    self._cookies[name.strip()] = val.strip()
                else:
                    self._cookies.pop(name.strip(), None)

    def header_value(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())

    def __len__(self) -> int:
        return len(self._cookies)


def _dig(data, dotted: str):
    node = data
    for part in str(dotted or "").split("."):
        if not part:
            continue
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return None
    return node


class SessionRuntime:
    """Kimlik oturumu: cookie jar + login tarifi + expire durumu.

    Tarif (recipe): {url, method, body, token_path, token_header,
    token_scheme, csrf_path, csrf_header, totp_field, totp_secret}.
    Durumlar: anonymous -> active -> expired (re-login basarisiz/401 kalici).
    """

    def __init__(self, recipe: dict | None = None, sender=None, max_retries: int = 1):
        self.recipe = dict(recipe or {})
        self.sender = sender or _default_sender
        self.max_retries = max(0, int(max_retries))
        self.jar = CookieJar()
        self.state = "anonymous"
        self.relogins = 0
        self._auth_headers: dict[str, str] = {}
        # ResilientSession uyumu (butce hesabi bu alanlara bakar)
        self.login_provider = self._login if self.recipe.get("url") else None

    def _login(self) -> dict:
        recipe = self.recipe
        body = recipe.get("body")
        if isinstance(body, dict):
            payload = dict(body)
            if recipe.get("totp_field") and recipe.get("totp_secret"):
                payload[recipe["totp_field"]] = totp_code(str(recipe["totp_secret"]))
            import json as _json
            body = _json.dumps(payload)
        resp = self.sender(str(recipe.get("method", "POST")).upper(),
                           str(recipe["url"]), dict(recipe.get("headers") or {}), body, 20)
        self.jar.absorb(resp.get("headers"))
        headers: dict[str, str] = {}
        text = resp.get("text") or ""
        data = None
        try:
            import json as _json
            data = _json.loads(text) if text else None
        except Exception:
            data = None
        token = _dig(data, recipe.get("token_path", "")) if data is not None else None
        if token:
            name = str(recipe.get("token_header", "Authorization"))
            headers[name] = f"{recipe.get('token_scheme', 'Bearer ')}{token}"
        csrf = _dig(data, recipe.get("csrf_path", "")) if data is not None else None
        if csrf and recipe.get("csrf_header"):
            headers[str(recipe["csrf_header"])] = str(csrf)
        if resp.get("ok") and (headers or len(self.jar)):
            self._auth_headers = headers
            self.state = "active"
            self._sync_shared_jar(str(recipe.get("url") or ""), state="active")
            return {"headers": headers}
        self.state = "expired"
        self._sync_shared_jar(str(recipe.get("url") or ""), state="expired")
        return {"headers": {}}

    def _sync_shared_jar(self, url: str, state: str) -> None:
        try:
            import sys
            val_dir = str(runtime_root() / "mcp-servers" / "mcp-validator")
            if val_dir not in sys.path:
                sys.path.insert(0, val_dir)
            from cco_validator_core.egress import save_shared_session
            save_shared_session(
                url,
                cookie=self.jar.header_value(),
                headers=self._auth_headers,
                state=state,
                source="chain_executor",
            )
        except Exception:
            pass

    def request(self, method: str, url: str, headers: dict, body, timeout: int) -> dict:
        active = dict(self._auth_headers)
        active.update(headers or {})
        cookie = self.jar.header_value()
        if cookie and not any(k.lower() == "cookie" for k in active):
            active["Cookie"] = cookie
        resp = self.sender(method, url, active, body, timeout)
        self.jar.absorb(resp.get("headers"))
        attempts = 0
        while (resp.get("ok") and resp.get("status") == 401
               and self.login_provider is not None and attempts < self.max_retries):
            attempts += 1
            self._login()
            if self.state != "active":
                break
            retry_headers = dict(self._auth_headers)
            retry_headers.update(headers or {})
            cookie = self.jar.header_value()
            if cookie:
                retry_headers["Cookie"] = cookie
            resp = self.sender(method, url, retry_headers, body, timeout)
            self.jar.absorb(resp.get("headers"))
            self.relogins += 1
        if resp.get("ok") and resp.get("status") == 401 and attempts:
            self.state = "expired"
            self._sync_shared_jar(url, state="expired")
        elif resp.get("ok") and resp.get("status") in (200, 201, 204) and (self._auth_headers or len(self.jar)):
            self._sync_shared_jar(url, state="active")
        resp = dict(resp)
        resp["relogins_used"] = attempts
        resp["session_state"] = self.state
        return resp


def _resolve_refs(value, context: dict):
    if isinstance(value, str):
        def repl(match):
            node = context
            for part in match.group(1).split("."):
                if not isinstance(node, dict) or part not in node:
                    raise ChainAbort(f"çözülemeyen referans: {match.group(0)}")
                node = node[part]
            if isinstance(node, (dict, list)):
                raise ChainAbort(f"skaler olmayan referans: {match.group(0)}")
            return str(node)

        return _REF_RE.sub(repl, value)
    if isinstance(value, dict):
        return {key: _resolve_refs(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_refs(item, context) for item in value]
    return value


def _default_sender(method: str, url: str, headers: dict, body, timeout: int) -> dict:
    import requests

    try:
        resp = requests.request(
            method.upper(), url, headers=headers, data=body,
            allow_redirects=False, timeout=timeout, verify=False,
        )
        text = resp.text or ""
        return {
            "ok": True, "status": resp.status_code, "len": len(resp.content),
            "text": text, "headers": dict(resp.headers),
            "location": resp.headers.get("Location", ""), "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - transport hatası oracle girdisi
        return {"ok": False, "status": None, "len": 0, "text": "",
                "headers": {}, "location": "", "error": str(exc)}


_KEY_RE = re.compile(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:')


def _spec_keys_near_endpoint(spec: str, endpoint: str, limit: int = 8) -> list[str]:
    """Spec metninde endpoint geçen penceredeki JSON anahtar adayları."""
    if not spec:
        return []
    window = spec
    if endpoint and endpoint in spec:
        idx = spec.find(endpoint)
        window = spec[max(0, idx - 1500):idx + 1500]
    seen: list[str] = []
    for match in _KEY_RE.finditer(window):
        key = match.group(1)
        if key not in seen:
            seen.append(key)
        if len(seen) >= max(1, limit):
            break
    return seen


def _summarize_response(resp: dict) -> dict:
    text = str(resp.get("text") or "")
    return {
        "ok": bool(resp.get("ok")),
        "status": resp.get("status"),
        "len": int(resp.get("len") or 0),
        "sha256": hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest(),
        "excerpt": text[:500],
        "location": str(resp.get("location") or ""),
        "error": resp.get("error"),
    }


def _parse_json_obj(step_dict: dict) -> dict:
    import json as _json

    if not isinstance(step_dict, dict):
        return {}
    raw = str(step_dict.get("fulltext") or step_dict.get("excerpt") or "").strip()
    if not raw:
        return {}
    try:
        data = _json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _is_2xx(rec: dict) -> bool:
    if not isinstance(rec, dict) or rec.get("ok") is False:
        return False
    st = rec.get("status")
    return st is None or (isinstance(st, int) and 200 <= st < 300)


def _round_diverged(round_items: list[dict]) -> tuple[bool, str]:
    """Tur içi ayrışma: status kümesi bölündüyse veya uzunluk belirgin saptıysa."""
    statuses = {r.get("status") for r in round_items}
    if len(statuses) > 1:
        return True, f"status:{sorted(s for s in statuses if s is not None)}"
    lens = [int(r.get("len") or 0) for r in round_items]
    if lens and max(lens) - min(lens) > 2048:
        return True, f"length:{min(lens)}->{max(lens)}"
    return False, ""


def _eval_state_invariant(expect: dict, step_result: dict, steps: dict) -> tuple[bool, dict]:
    before_id = str(expect.get("before_step") or expect.get("baseline_step") or "")
    after_id = str(expect.get("after_step") or "")
    before_rec = steps.get(before_id, {}) if before_id else {}
    after_rec = steps.get(after_id, step_result) if after_id else step_result
    before_json = _parse_json_obj(before_rec)
    after_json = _parse_json_obj(after_rec)
    violations: list[str] = []
    detail: dict = {"before_step": before_id, "after_step": after_id or "self"}

    if not _is_2xx(after_rec) or not after_json:
        detail["violations"] = []
        detail["skipped_reason"] = "after_step_not_2xx_json"
        return False, detail
    if before_id and (not _is_2xx(before_rec) or not before_json):
        detail["violations"] = []
        detail["skipped_reason"] = "before_step_not_2xx_json"
        return False, detail

    num_field = str(expect.get("numeric_field") or "").strip()
    if num_field:
        rule = str(expect.get("rule") or "decreased").lower()
        raw_after = _dig(after_json, num_field)
        raw_before = _dig(before_json, num_field) if before_json else None
        try:
            val_after = float(raw_after) if raw_after is not None else None
            val_before = float(raw_before) if raw_before is not None else None
        except (TypeError, ValueError):
            val_after = val_before = None
        detail["numeric"] = {"field": num_field, "rule": rule, "before": val_before, "after": val_after}
        if val_after is not None:
            if rule == "negative" and val_after < 0:
                violations.append(f"numeric_negative:{num_field}={val_after}")
            elif rule == "non_positive" and val_after <= 0 and (val_before is None or val_before > 0):
                violations.append(f"numeric_non_positive:{num_field}={val_after}")
            elif rule == "decreased" and val_before is not None and val_after < val_before:
                violations.append(f"numeric_decreased:{num_field}:{val_before}->{val_after}")
            elif rule == "increased" and val_before is not None and val_after > val_before:
                violations.append(f"numeric_increased:{num_field}:{val_before}->{val_after}")
            elif rule == "delta_gt" and val_before is not None:
                try:
                    threshold = float(expect.get("threshold", 0))
                except (TypeError, ValueError):
                    threshold = 0.0
                if abs(val_after - val_before) > threshold:
                    violations.append(f"numeric_delta_gt:{num_field}:delta={abs(val_after - val_before)}")
            elif rule == "stable" and val_before is not None and val_after is not None:
                if val_after != val_before:
                    violations.append(f"numeric_changed:{num_field}:{val_before}->{val_after}")
            elif rule == "collapsed" and val_after is not None and val_before is not None:
                try:
                    band_max = float(expect.get("threshold", 0))
                except (TypeError, ValueError):
                    band_max = 0.0
                if val_after < val_before and 0 <= val_after < band_max:
                    violations.append(f"numeric_collapsed:{num_field}:{val_before}->{val_after}")

    mutated_fields = expect.get("mutated_fields") or []
    if isinstance(mutated_fields, list) and mutated_fields:
        expected_val = expect.get("expected_value")
        changed: dict[str, dict] = {}
        for f in mutated_fields:
            fname = str(f).strip()
            if not fname:
                continue
            aval = _dig(after_json, fname)
            bval = _dig(before_json, fname) if before_json else None
            if aval is None:
                continue
            if expected_val is not None:
                if str(aval).lower() == str(expected_val).lower() and str(bval).lower() != str(expected_val).lower():
                    changed[fname] = {"before": bval, "after": aval}
                    violations.append(f"readonly_mutated:{fname}={aval}")
            elif before_json and bval is not None and aval != bval:
                changed[fname] = {"before": bval, "after": aval}
                violations.append(f"readonly_mutated:{fname}:{bval}->{aval}")
        detail["mutated_fields"] = changed

    state_field = str(expect.get("state_field") or "").strip()
    if state_field and "expected_state" in expect:
        target_state = expect.get("expected_state")
        aval = _dig(after_json, state_field)
        bval = _dig(before_json, state_field) if before_json else None
        detail["state"] = {"field": state_field, "before": bval, "after": aval, "expected": target_state}
        if aval is not None and str(aval).lower() == str(target_state).lower():
            if bval is not None and str(bval).lower() != str(target_state).lower():
                violations.append(f"state_transition:{state_field}:{bval}->{aval}")

    detail["violations"] = violations
    return bool(violations), detail


def _eval_oracle(oracle: str, expect: dict, step_result: dict, steps: dict) -> tuple[bool, dict]:
    if oracle == 'business_logic':
        return evaluate_business_logic(expect, steps)
    if oracle == 'business_control':
        return evaluate_normal_control(expect, steps)
    if oracle == "state_invariant":
        return _eval_state_invariant(expect, step_result, steps)
    if oracle == "extract_ok":
        found = bool(isinstance(step_result, dict) and step_result.get("found"))
        return found, {"saved_as": (step_result or {}).get("save_as", ""),
                       "preview": (step_result or {}).get("value_preview", "")}
    if oracle == "response_divergence":
        items = step_result.get("items") if isinstance(step_result, dict) else None
        if not items:
            return False, {"skipped_reason": "no_burst_items"}
        by_round: dict = {}
        for it in items:
            if isinstance(it, dict):
                by_round.setdefault(it.get("round", 0), []).append(it)
        diverged_rounds = []
        for rnd in sorted(by_round):
            diverged, reason = _round_diverged(by_round[rnd])
            if diverged:
                diverged_rounds.append({"round": rnd, "reason": reason})
        return bool(diverged_rounds), {"rounds": len(by_round),
                                       "diverged_rounds": diverged_rounds}
    if oracle == "status_code":
        wanted = expect.get("status", 200)
        wanted = wanted if isinstance(wanted, list) else [wanted]
        if isinstance(step_result.get("items"), list):
            actual = sorted({item.get("status") for item in step_result["items"]
                             if item.get("status") is not None})
            matched = [item.get("url", "") for item in step_result["items"]
                       if item.get("status") in wanted]
            return bool(matched), {"actual": actual, "wanted": wanted, "matched_urls": matched}
        actual = step_result.get("status")
        return actual in wanted, {"actual": actual, "wanted": wanted}
    if oracle == "marker_present":
        marker = str(expect.get("marker", ""))
        if not marker:
            return False, {"error": "marker boş"}
        if isinstance(step_result.get("items"), list):
            matched = [item.get("url", "") for item in step_result["items"]
                       if marker in str(item.get("excerpt", ""))]
            return bool(matched), {"matched_urls": matched,
                                   "marker_sha256": hashlib.sha256(marker.encode()).hexdigest()}
        # Oracle tam metinde arar; rapor çıktısında yalnızca excerpt + hash durur.
        found = marker in str(step_result.get("fulltext", step_result.get("excerpt", "")))
        detail = {"marker_sha256": hashlib.sha256(marker.encode()).hexdigest(), "found": found}
        return found, detail
    if oracle == "differential_content":
        owner = steps.get(str(expect.get("owner_step", "")), {})
        attacker = steps.get(str(expect.get("attacker_step", "")), {})
        marker = str(expect.get("marker", ""))
        if not marker:
            return False, {"error": "marker boş"}
        owner_has = marker in str(owner.get("fulltext", ""))
        attacker_has = marker in str(attacker.get("fulltext", ""))
        detail = {"owner_has_marker": owner_has, "attacker_has_marker": attacker_has,
                  "marker_sha256": hashlib.sha256(marker.encode()).hexdigest()}
        return bool(owner_has and attacker_has), detail
    if oracle == "oob_callback":
        matched = bool(step_result.get("matched"))
        return matched, {"matched": matched, "token_sha256": step_result.get("token_sha256", "")}
    if oracle == "validator_verdict":
        wanted = str(expect.get("verdict", "CONFIRMED"))
        actual = str(step_result.get("verdict", ""))
        return actual == wanted, {"actual": actual, "wanted": wanted}
    if oracle == "artifact_exists":
        path = str(expect.get("path", ""))
        exists = bool(path) and os.path.exists(path)
        return exists, {"path": path, "exists": exists}
    return False, {"error": f"bilinmeyen oracle: {oracle}"}


class ChainExecutor:
    """Manifest çalıştırıcı. Ağ/kimlik/policy enjekte edilebilir (test edilebilir)."""

    def __init__(self, policy_engine=None, sender=None, identities=None,
                 target_bases=None, sleeper=None,
                 validate_provider=None, finding_store=None,
                 login_provider=None, session_max_retries: int = 1,
                 login_recipe: dict | None = None, write_context: dict | None = None,
                 evidence_graph=None, evidence_context: dict | None = None):
        self.policy_engine = policy_engine
        self.transport = ChainTransport(sender or _default_sender, self._gate)
        base_sender = self.transport.request
        if login_recipe:
            self.session = SessionRuntime(
                recipe=login_recipe, sender=base_sender,
                max_retries=session_max_retries)
        else:
            self.session = ResilientSession(
                login_provider=login_provider, sender=base_sender,
                max_retries=session_max_retries)
        self.sender = self.session.request
        self.identities = identities or {}
        self.target_bases = target_bases or {}
        self.sleeper = sleeper or time.sleep
        self.validate_provider = validate_provider or default_validate_provider
        self.finding_store = finding_store or default_finding_store
        self.write_context = dict(write_context or {})
        self.evidence_graph = evidence_graph
        self.evidence_context = dict(evidence_context or {})
        # Host bindings may impose fresh evidence/identity checks at the final
        # wire boundary. Legacy standalone manifests keep their existing gates.
        self.prerequisite_check = None

    def _gate(self, tool: str, url: str, method: str,
              headers: dict) -> tuple[bool, str]:
        if self.policy_engine is None:
            return False, "policy engine yok (fail-closed)"
        try:
            if self.prerequisite_check is not None:
                self.prerequisite_check(tool, url, method, headers)
            decision = self.policy_engine.validate_tool_invocation(
                f"chain_runner_{tool}", {"url": url, "method": method,
                                         "headers": headers})
        except Exception as exc:  # noqa: BLE001 - gate hatası = deny
            return False, f"gate hatası: {exc}"
        if not decision.get("allowed"):
            reason = decision.get("reason") or decision.get("result") or "denied"
            return False, f"gate reddetti: {reason}"
        if self.prerequisite_check is not None:
            try:
                self.prerequisite_check(tool, url, method, headers)
            except Exception as exc:
                return False, f"prerequisite denied: {exc}"
        return True, ""

    def _headers_for(self, step: dict, url: str = "") -> dict:
        headers: dict = {"User-Agent": "cco-chain-runner/1.0"}
        refs = step.get("identity_refs", []) or []
        for ref in refs:
            identity = self.identities.get(ref)
            if not isinstance(identity, dict):
                raise ChainAbort(f"bilinmeyen identity_ref: {ref!r}")
            for key, value in identity.items():
                headers[str(key)] = str(value)
        if not refs and url:
            try:
                import sys
                val_dir = str(runtime_root() / "mcp-servers" / "mcp-validator")
                if val_dir not in sys.path:
                    sys.path.insert(0, val_dir)
                from cco_validator_core.egress import load_shared_session
                shared = load_shared_session(url, require_origin=True)
                if isinstance(shared, dict):
                    if shared.get("state") != "active" or shared.get("stale"):
                        raise ChainAbort("shared session expired or stale; restore it before continuing")
                    for hk, hv in (shared.get("headers") or {}).items():
                        headers.setdefault(str(hk), str(hv))
                    if shared.get("cookie") and not any(k.lower() == "cookie" for k in headers):
                        headers["Cookie"] = str(shared["cookie"])
            except ChainAbort:
                raise
            except Exception as exc:
                raise ChainAbort("shared session store unavailable") from exc
        return headers

    def _run_batch(self, step: dict, resolved_args: dict, headers: dict,
                   manifest: dict, budget: dict, requests_sent: int) -> tuple[dict, int]:
        """Bütçeli, gate'li, rate-limited toplu prob (açık terminal yerine)."""
        import json as _json

        wire_before = self.transport.snapshot()["sent"]
        items = resolved_args.get("requests", [])
        if not isinstance(items, list) or not items:
            raise ChainAbort("batch_probe boş olmayan requests listesi gerektirir")
        if len(items) > MAX_BATCH_ITEMS:
            raise ChainAbort(f"batch_probe en fazla {MAX_BATCH_ITEMS} istek")
        if requests_sent + len(items) > budget["max_requests"]:
            raise ChainAbort("istek bütçesi aşıldı")
        try:
            rps = float(resolved_args.get("max_rps", DEFAULT_BATCH_RPS))
        except (TypeError, ValueError):
            raise ChainAbort("max_rps sayı olmalı")
        rps = min(max(rps, 0.1), MAX_BATCH_RPS)
        gap = 1.0 / rps
        timeout = int(resolved_args.get("timeout_seconds", 15))
        base = self.target_bases.get(manifest.get("target_ref", ""), "")
        results: list[dict] = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ChainAbort(f"batch item dict olmalı: {index}")
            if item.get("url"):
                url = str(item["url"])
            elif item.get("path") and base:
                url = urljoin(base.rstrip("/") + "/", str(item["path"]).lstrip("/"))
            else:
                raise ChainAbort(f"batch item url/path gerektirir: {index}")
            method = str(item.get("method", "GET")).upper()
            if method not in ("GET", "HEAD", "OPTIONS"):
                raise ChainAbort(f"batch_probe yazan metoda kapalı: {method}")
            body = item.get("body", "")
            item_headers = dict(headers)
            for key, value in (item.get("headers") or {}).items():
                item_headers[str(key)] = str(value)
            if isinstance(body, dict):
                body = _json.dumps(body)
            if index > 0:
                self.sleeper(gap)
            resp = self.sender(method, url, item_headers, body, timeout)
            text = str(resp.get("text") or "")
            results.append({
                "url": url, "ok": bool(resp.get("ok")), "status": resp.get("status"),
                "len": int(resp.get("len") or 0),
                "sha256": hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest(),
                "excerpt": text[:200],
            })
        return {"ok": True, "items": results, "count": len(results)}, self.transport.snapshot()["sent"] - wire_before

    def _run_extract(self, step: dict, resolved_args: dict, context: dict) -> tuple[dict, int]:
        """Önceki adım çıktısından regex ile değer alıp context'e yaz (ağ isteği yok).

        mode=first: ilk eşleşme (varsayılan). mode=all: tüm eşleşmeler listesi
        (kanıta yönelik; argümanlarda skaler beklenir, liste oralarda kullanılmaz).
        """
        import re as _re
        from_step = str(resolved_args.get("from_step") or "")
        pattern = str(resolved_args.get("pattern") or "")
        save_as = str(resolved_args.get("save_as") or "")
        source = str(resolved_args.get("source") or "text")
        mode = str(resolved_args.get("mode") or "first").lower()
        if not from_step or not pattern or not save_as:
            raise ChainAbort("extract from_step/pattern/save_as gerektirir")
        if mode not in ("first", "all"):
            raise ChainAbort("extract mode first/all olmalı")
        try:
            group = int(resolved_args.get("group", 1 if mode == "first" else 0))
        except (TypeError, ValueError):
            raise ChainAbort("extract group tamsayı olmalı")
        prev = (context.get("steps") or {}).get(from_step)
        if not isinstance(prev, dict):
            raise ChainAbort(f"extract kaynak adım yok: {from_step}")
        if source == "text":
            hay = str(prev.get("fulltext") or prev.get("excerpt") or prev.get("text") or "")
        elif source == "status":
            hay = str(prev.get("status"))
        elif source == "location":
            hay = str(prev.get("location") or "")
        elif source.startswith("header:"):
            name = source.split(":", 1)[1].strip().lower()
            hay = ""
            for k, v in (prev.get("headers") or {}).items():
                if str(k).lower() == name:
                    hay = v if isinstance(v, str) else str(v)
                    break
        else:
            raise ChainAbort(f"extract source geçersiz: {source}")
        try:
            rx = _re.compile(pattern, _re.S)
        except _re.error as exc:
            raise ChainAbort(f"extract regex hatası: {exc}")
        if mode == "all":
            found = [m.group(0) if group == 0 else (m.groups()[group - 1] if len(m.groups()) >= group else None)
                     for m in rx.finditer(hay or "")]
            found = [f for f in found if f is not None][:50]
            if not found:
                return {"ok": False, "found": False, "save_as": save_as,
                        "error": "eşleşme yok"}, 0
            context.setdefault("extracted", {})[save_as] = found
            preview = " | ".join(str(v) for v in found)
            if len(preview) > 2000:
                preview = preview[:2000] + "..."
            return {"ok": True, "found": True, "save_as": save_as, "count": len(found),
                    "value": found, "value_preview": preview}, 0
        m = rx.search(hay or "")
        if not m:
            return {"ok": False, "found": False, "save_as": save_as,
                    "error": "eşleşme yok"}, 0
        try:
            value = m.group(group)
        except IndexError:
            raise ChainAbort(f"extract grup yok: {group}")
        context.setdefault("extracted", {})[save_as] = value
        preview = value if len(value) <= 500 else (value[:24] + "...")
        return {"ok": True, "found": True, "save_as": save_as,
                "value": value, "value_preview": preview}, 0

    def _run_burst(self, step: dict, resolved_args: dict, headers: dict,
                   manifest: dict, budget: dict, requests_sent: int) -> tuple[dict, int]:
        """Bariyer-senkron paralel salıverme (race istisnası, onay referanslı)."""
        import gc as _gc
        import json as _json
        import threading
        import time as _time
        from concurrent.futures import ThreadPoolExecutor

        wire_before = self.transport.snapshot()["sent"]
        approval = str(resolved_args.get("approval_ref", "") or "").strip()
        if not approval:
            raise ChainAbort("race_burst approval_ref gerektirir (burst istisnası kayda girer)")
        items = resolved_args.get("requests", [])
        if not isinstance(items, list) or not items:
            raise ChainAbort("race_burst boş olmayan requests listesi gerektirir")
        if len(items) > MAX_BURST_ITEMS:
            raise ChainAbort(f"race_burst tur başına en fazla {MAX_BURST_ITEMS} istek")
        try:
            rounds = int(resolved_args.get("rounds", 3))
            concurrency = int(resolved_args.get("concurrency", min(len(items), 10)))
        except (TypeError, ValueError):
            raise ChainAbort("rounds/concurrency tamsayı olmalı")
        if not 1 <= rounds <= MAX_BURST_ROUNDS:
            raise ChainAbort(f"rounds 1-{MAX_BURST_ROUNDS} aralığında olmalı")
        if not 1 <= concurrency <= MAX_BURST_CONCURRENCY:
            raise ChainAbort(f"concurrency 1-{MAX_BURST_CONCURRENCY} aralığında olmalı")
        try:
            timing_probe = int(resolved_args.get("timing_probe", 0))
        except (TypeError, ValueError):
            raise ChainAbort("timing_probe tamsayı olmalı")
        if timing_probe < 0 or timing_probe > 5:
            raise ChainAbort("timing_probe 0-5 aralığında olmalı")
        stop_on_divergence = bool(resolved_args.get("stop_on_divergence", False))
        total = len(items) * rounds + timing_probe
        if requests_sent + total > budget["max_requests"]:
            raise ChainAbort("istek bütçesi aşıldı")
        timeout = int(resolved_args.get("timeout_seconds", 15))
        base = self.target_bases.get(manifest.get("target_ref", ""), "")
        prepared = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ChainAbort(f"burst item dict olmalı: {index}")
            if item.get("url"):
                url = str(item["url"])
            elif item.get("path") and base:
                url = urljoin(base.rstrip("/") + "/", str(item["path"]).lstrip("/"))
            else:
                raise ChainAbort(f"burst item url/path gerektirir: {index}")
            method = str(item.get("method", "GET")).upper()
            if method not in BURST_METHODS:
                raise ChainAbort(f"race_burst metoda kapalı: {method}")
            try:
                delay_ms = float(item.get("delay_ms", 0) or 0)
            except (TypeError, ValueError):
                raise ChainAbort(f"burst delay_ms sayı olmalı: {index}")
            if delay_ms < 0 or delay_ms > 2000:
                raise ChainAbort(f"burst delay_ms 0-2000ms aralığında olmalı: {index}")
            body = item.get("body", "")
            item_headers = dict(headers)
            for key, value in (item.get("headers") or {}).items():
                item_headers[str(key)] = str(value)
            if isinstance(body, dict):
                body = _json.dumps(body)
                item_headers.setdefault("Content-Type", "application/json")
            prepared.append((method, url, item_headers, body, delay_ms))
        flat: list[dict] = []
        round_stats: list[dict] = []
        degraded: list[dict] = []
        probe_ms: list[float] = []
        stopped_early = False
        stop_reason = ""
        _gc_was_enabled = _gc.isenabled()
        if _gc_was_enabled:
            _gc.collect()
            _gc.disable()
        try:
            # Zamanlama kalibrasyonu: tur öncesi sıralı prob, RTT dagilimini olcer.
            # Bütçeye dahildir (total içinde sayılır); pencere genisligi bilinmiyorsa
            # rapor dürüstçe 0/N yazar, halüsinasyon yok.
            if timing_probe and prepared:
                method, url, hdrs, body, _delay = prepared[0]
                for _ in range(timing_probe):
                    start = _time.monotonic()
                    try:
                        self.sender(method, url, hdrs, body, timeout)
                    except ChainAbort:
                        raise
                    except Exception:
                        pass
                    probe_ms.append(round((_time.monotonic() - start) * 1000.0, 2))
            for round_no in range(rounds):
                # Isci sayisi istekten azsa tek bariyer kilitlenir; concurrency
                # buyuklugunde dalgalar halinde senkron saliver (her dalga kendi
                # bariyerini kullanir, sarkan dalga kalmaz).
                round_items = []
                waves = [prepared[i:i + concurrency]
                         for i in range(0, len(prepared), concurrency)]

                def fire(prepped, _barrier=None):
                    method, url, hdrs, body, delay_ms = prepped
                    start = _time.monotonic()
                    try:
                        _barrier.wait(timeout=30)
                    except threading.BrokenBarrierError:
                        return {"url": url, "ok": False, "status": None, "len": 0,
                                "sha256": "", "excerpt": "", "error": "bariyer kırıldı",
                                "elapsed_ms": round((_time.monotonic() - start) * 1000.0, 2)}
                    if delay_ms:
                        _time.sleep(delay_ms / 1000.0)
                    try:
                        resp = self.sender(method, url, hdrs, body, timeout)
                    except ChainAbort:
                        raise
                    except Exception as exc:
                        return {"url": url, "ok": False, "status": None, "len": 0,
                                "sha256": "", "excerpt": "", "error": f"gönderim hatası: {exc}",
                                "elapsed_ms": round((_time.monotonic() - start) * 1000.0, 2)}
                    text = str(resp.get("text") or "")
                    return {"url": url, "ok": bool(resp.get("ok")), "status": resp.get("status"),
                            "len": int(resp.get("len") or 0),
                            "sha256": hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest(),
                            "excerpt": text[:200],
                            "elapsed_ms": round((_time.monotonic() - start) * 1000.0, 2)}

                for wave in waves:
                    barrier = threading.Barrier(len(wave))
                    with ThreadPoolExecutor(max_workers=len(wave)) as pool:
                        round_items.extend(pool.map(lambda p, _b=barrier: fire(p, _b), wave))
                for r in round_items:
                    r["round"] = round_no
                flat.extend(round_items)
                rate_limited = sum(1 for r in round_items if r.get("status") == 429)
                diverged, diverge_reason = _round_diverged(round_items)
                round_stats.append({"requests": len(round_items),
                                    "ok": sum(1 for r in round_items if r["ok"]),
                                    "rate_limited": rate_limited,
                                    "concurrency": concurrency,
                                    "diverged": diverged,
                                    "diverge_reason": diverge_reason})
                # 429 kendini boguyor: yarıdan fazlası 429 ise concurrency yarıya.
                # En fazla 2 kısma; üstü park edilir (turlar aynen kosar).
                if rate_limited > len(round_items) / 2 and len(degraded) < 2 and concurrency > 1:
                    concurrency = max(1, concurrency // 2)
                    degraded.append({"round": round_no, "concurrency": concurrency,
                                     "rate_limited": rate_limited})
                if stop_on_divergence and diverged:
                    stopped_early = True
                    stop_reason = diverge_reason
                    break
        finally:
            if _gc_was_enabled:
                _gc.enable()
        return {"ok": True, "items": flat, "rounds": round_stats,
                "round_count": len(round_stats), "count": len(flat),
                "approval_ref": approval, "gc_disabled": _gc_was_enabled,
                "timing_probe_ms": probe_ms, "degraded": degraded,
                "stopped_early": stopped_early, "stop_reason": stop_reason}, self.transport.snapshot()["sent"] - wire_before

    def _url_for(self, manifest: dict, step: dict, resolved_args: dict) -> str:
        if resolved_args.get("url"):
            return str(resolved_args["url"])
        path = resolved_args.get("path")
        if not path:
            raise ChainAbort(f"adımda url/path yok: {step.get('id')}")
        base = self.target_bases.get(manifest.get("target_ref", ""), "")
        if not base:
            raise ChainAbort(f"target_ref için base URL yok: {manifest.get('target_ref')}")
        return urljoin(base.rstrip("/") + "/", str(path).lstrip("/"))

    def _run_tool(self, step: dict, resolved_args: dict, headers: dict,
                  steps_context: dict) -> tuple[dict, int]:
        tool = step["tool"]
        wire_before = self.transport.snapshot()["sent"]
        if tool in ("http_get", "http_post"):
            import json as _json

            if tool == "http_get":
                req_method = str(resolved_args.get("method", "GET") or "GET").upper()
                method = req_method if req_method in {"GET", "HEAD", "OPTIONS"} else "GET"
            else:
                req_method = str(resolved_args.get("method", "POST") or "POST").upper()
                method = req_method if req_method in {"POST", "PUT", "PATCH", "DELETE"} else "POST"
            body = resolved_args.get("body", "")
            body_obj = dict(body) if isinstance(body, dict) else None
            if body_obj is not None:
                body = _json.dumps(body_obj)
                headers.setdefault("Content-Type", "application/json")
            timeout = int(resolved_args.get("timeout_seconds", 15))
            resp = self.sender(method, resolved_args["_url"], headers, body, timeout)
            reflected_keys: list[str] = []
            reflect = resolved_args.get("reflect") or {}
            if (resp.get("ok") and resp.get("status") == 400 and body_obj is not None
                    and isinstance(reflect, dict) and reflect.get("spec")):
                # Schema reflection: spec penceresinden eksik anahtarları tek tur tamamla.
                spec = str(reflect.get("spec", ""))
                endpoint = str(reflect.get("endpoint", ""))
                keys = _spec_keys_near_endpoint(spec, endpoint,
                                               limit=int(reflect.get("max_keys", 8) or 8))
                missing = [key for key in keys if key not in body_obj]
                if missing:
                    body_obj.update({key: "" for key in missing})
                    body = _json.dumps(body_obj)
                    resp = self.sender(method, resolved_args["_url"], headers, body, timeout)
                    reflected_keys = missing
            summary = _summarize_response(resp)
            summary["fulltext"] = str(resp.get("text") or "")
            summary["relogins_used"] = int(resp.get("relogins_used", 0) or 0)
            summary["reflected_keys"] = reflected_keys
            return summary, self.transport.snapshot()["sent"] - wire_before
        if tool == "wait":
            seconds = float(resolved_args.get("seconds", 1))
            self.sleeper(min(max(seconds, 0.0), 300.0))
            return {"ok": True, "waited_seconds": seconds, "status": 200,
                    "text": f"waited {seconds}s"}, 0
        if tool == "mailbox_poll":
            import json as _json

            email = str(resolved_args.get("email", ""))
            if not email or "@" not in email:
                raise ChainAbort("mailbox_poll geçerli email gerektirir")
            url = resolved_args.get("_url", "")
            resp = self.sender("GET", url, headers, "", int(resolved_args.get("timeout_seconds", 15)))
            if not resp.get("ok"):
                return {"ok": False, "found": False, "error": resp.get("error")}, self.transport.snapshot()["sent"] - wire_before
            try:
                data = _json.loads(resp.get("text") or "{}")
            except (ValueError, TypeError):
                return {"ok": False, "found": False, "error": "inbox JSON parse edilemedi"}, self.transport.snapshot()["sent"] - wire_before
            items = data.get("items", []) if isinstance(data, dict) else []
            body = ""
            for msg in items:
                if not isinstance(msg, dict):
                    continue
                to_field = _json.dumps(msg.get("To", ""), ensure_ascii=False)
                if email.lower() in to_field.lower():
                    content = msg.get("Content") or {}
                    body = str(content.get("Body", "") or msg.get("Body", "") or "")
                    break
            pattern = str(resolved_args.get("otp_pattern", r"\b(\d{4,8})\b"))
            try:
                match = re.search(pattern, body)
            except re.error:
                raise ChainAbort(f"geçersiz otp_pattern: {pattern!r}")
            summary = {"ok": True, "found": bool(body),
                       "messages_scanned": len(items),
                       "otp": match.group(1) if match else "",
                       "excerpt": body[:500],
                       "sha256": hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()}
            summary["fulltext"] = body
            return summary, self.transport.snapshot()["sent"] - wire_before
        if tool == "oob_poll":
            token = str(resolved_args.get("token", ""))
            callbacks = str(resolved_args.get("callbacks_text", ""))
            if not token:
                raise ChainAbort("oob_poll token gerektirir")
            matched = token in callbacks
            return {"ok": True, "matched": matched,
                    "token_sha256": hashlib.sha256(token.encode()).hexdigest()}, 0
        if tool == "validate":
            oracle = str(resolved_args.get("oracle", ""))
            if oracle not in ORACLES:
                raise ChainAbort(f"validate bilinmeyen oracle: {oracle!r}")
            oracle_args = resolved_args.get("oracle_args", {})
            if not isinstance(oracle_args, dict):
                raise ChainAbort("validate oracle_args dict olmalı")
            probe: dict = {}
            ref_step = str(oracle_args.get("step", oracle_args.get("attacker_step", "")))
            if ref_step:
                probe = steps_context.get(ref_step, {})
            passed, detail = _eval_oracle(oracle, oracle_args, probe, steps_context)
            if is_business_type(resolved_args.get('vuln_type')) and oracle != 'business_logic':
                passed, detail = False, {'reason': 'business_effect_and_normal_control_required'}
            provided = self.validate_provider({
                "vuln_type": str(resolved_args.get("vuln_type", "unknown")),
                "target_url": str(resolved_args.get("target_url", "")),
                "verdict": "CONFIRMED" if passed else "UNCONFIRMED",
                "oracle": oracle,
                "evidence": detail,
                "reproduction": resolved_args.get("reproduction", "-"),
                "severity": str(resolved_args.get("severity", "high")),
                "notes": str(resolved_args.get(
                    "notes", "chain-runner: kayıtlı adım kanıtı üzerinden oracle.")),
                "request_evidence": [
                    {"role": sid,
                     "status": (srec.get("status") if isinstance(srec, dict) else None),
                     "excerpt": (srec.get("excerpt", "") if isinstance(srec, dict) else "")}
                    for sid, srec in steps_context.items()
                ],
            })
            return {"ok": True, "oracle_passed": passed,
                    "verdict": provided.get("verdict", ""),
                    "validation_id": provided.get("validation_id", ""),
                    "artifact_path": provided.get("artifact_path", ""),
                    "oracle_detail": detail}, 0
        if tool == "store_finding":
            ref = str(resolved_args.get("validation_step", ""))
            validation = steps_context.get(ref, {}) if ref else {}
            if ref and not validation.get("validation_id"):
                raise ChainAbort(f"validation_step artifact üretmedi: {ref!r}")
            stored = self.finding_store({
                "target": str(resolved_args.get("target", "")),
                "type": str(resolved_args.get("type", "")),
                "severity": str(resolved_args.get("severity", "medium")),
                "description": str(resolved_args.get("description", "")),
                "payload": str(resolved_args.get("payload", "")),
                "validation_artifact_path": str(validation.get("artifact_path", "")),
            })
            if not stored.get("finding_id"):
                raise ChainAbort("finding kaydedilemedi")
            return {"ok": True, "finding_id": stored["finding_id"],
                    "validation_state": stored.get("validation_state", ""),
                    "reportable": bool(stored.get("reportable"))}, 0
        raise ChainAbort(f"bilinmeyen step tool: {tool}")

    def plan(self, manifest: dict) -> dict:
        """Dry-run: ağa dokunmadan akışı + çözülmüş URL'leri listele."""
        check = validate_manifest(manifest)
        if not check["valid"]:
            return {"valid": False, "errors": check["errors"], "plan": []}
        if 'evidence_chain' in manifest:
            from evidence_chaining import EvidenceError
            try:
                if self.evidence_graph is None:
                    raise EvidenceError('missing_evidence_store')
                self.evidence_graph.check_plan(manifest, self.evidence_context, self.identities)
                return {'valid': True, 'status': 'ready', 'runnable': True,
                        'plan': manifest['steps'], 'manifest_hash': check['manifest_hash']}
            except (EvidenceError, KeyError, TypeError, ValueError) as exc:
                return {'valid': False, 'status': 'not_runnable', 'runnable': False,
                        'errors': [str(exc)], 'plan': []}
        context: dict = {"steps": {}, "extracted": {}, "identities": {
            name: f"<identity:{name}>" for name in self.identities}}
        ordered = []
        try:
            for step in manifest["steps"]:
                resolved = _resolve_refs(step.get("args", {}), context)
                entry = {"id": step["id"], "tool": step["tool"],
                         "on_success": step["on_success"], "on_failure": step["on_failure"]}
                if step["tool"] in HTTP_FAMILY:
                    entry["url"] = self._url_for(manifest, step, resolved)
                if step["tool"] == "batch_probe":
                    entry["batch_count"] = len(resolved.get("requests", []) or [])
                if step["tool"] == "race_burst":
                    entry["burst_per_round"] = len(resolved.get("requests", []) or [])
                    entry["rounds"] = resolved.get("rounds", 3)
                    entry["approval_ref"] = bool(resolved.get("approval_ref"))
                ordered.append(entry)
        except ChainAbort as exc:
            return {"valid": False, "errors": [str(exc)], "plan": []}
        return {"valid": True, "errors": [], "plan": ordered,
                "manifest_hash": check["manifest_hash"]}

    def execute(self, manifest: dict) -> dict:
        check = validate_manifest(manifest)
        if not check["valid"]:
            return {"success": False, "terminal": "invalid_manifest",
                    "errors": check["errors"], "steps_executed": [],
                    "requests_sent": 0, "elapsed_s": 0.0}
        if 'evidence_chain' in manifest:
            return self._execute_evidence_chain(manifest, check)
        if 'business_logic' in manifest:
            import write_set
            try:
                ctx = self.write_context
                if not all(ctx.get(k) for k in ('db_path', 'run_id', 'session_id')):
                    raise ChainAbort('missing_prerequisite: WS7 run/session context required')
                if ctx['session_id'] != manifest['observed_context']['session_id']:
                    raise ChainAbort('cross_run_rejected')
                for url in {s.get('object_url') for s in manifest['steps']}:
                    row = write_set.inspect_object(ctx['db_path'], url)
                    if not row or (row['run_id'], row['session_id']) != (ctx['run_id'], ctx['session_id']):
                        raise ChainAbort('cross_run_rejected')
                    if not write_set.is_sealed(ctx['db_path'], url):
                        raise ChainAbort('missing_prerequisite: active sealed test object required')
            except (ChainAbort, write_set.WriteSetError, KeyError, TypeError) as exc:
                return {'success': False, 'terminal': 'abort', 'terminal_error': str(exc),
                        'steps_executed': [], 'requests_sent': 0, 'elapsed_s': 0.0}
        budget = manifest["budget"]
        deadline = time.monotonic() + budget["max_duration_seconds"]
        by_id = {step["id"]: step for step in manifest["steps"]}
        current = manifest["steps"][0]["id"]
        context: dict = {"steps": {}, "extracted": {}, "identities": dict(self.identities)}
        executed: list[dict] = []
        requests_sent = 0
        started = time.monotonic()
        terminal = "abort"
        terminal_error = ""
        self.transport.begin(budget)
        try:
            while True:
                if time.monotonic() > deadline:
                    raise ChainAbort("süre bütçesi aşıldı")
                step = by_id[current]
                record = {"id": current, "tool": step["tool"], "ok": False,
                          "oracle": step["expect"]["oracle"], "oracle_passed": False}
                try:
                    self.transport.begin_step(step)
                    # Faz 2: önkoşullar etikete değil, canlı oracle sonucuna bakılır
                    passed_ids = {r["id"] for r in executed if r.get("oracle_passed")}
                    for req in step.get("requires") or []:
                        if req not in passed_ids:
                            raise ChainAbort(f"önkoşul sağlanmadı: {req} (adım {current})")
                    resolved = _resolve_refs(step.get("args", {}), context)
                    if step["tool"] == "extract":
                        result, cost = self._run_extract(step, resolved, context)
                        record["ok"] = bool(result.get("ok"))
                        record["result"] = result
                        context["steps"][current] = result
                        requests_sent = self.transport.snapshot()["sent"]
                        passed, detail = _eval_oracle(
                            step["expect"]["oracle"], step.get("expect", {}),
                            result, context["steps"])
                        record["oracle_passed"] = passed
                        record["oracle_detail"] = detail
                        current = step["on_success"] if passed else step["on_failure"]
                        executed.append(record)
                        if current in ("succeed", "fail", "abort"):
                            terminal = current
                            break
                        continue
                    if step["tool"] in ("batch_probe", "race_burst"):
                        headers = self._headers_for(step)
                        runner = self._run_burst if step["tool"] == "race_burst" else self._run_batch
                        result, cost = runner(
                            step, resolved, headers, manifest, budget, requests_sent)
                        record["ok"] = True
                        record["result"] = result
                        context["steps"][current] = result
                        requests_sent = self.transport.snapshot()["sent"]
                        passed, detail = _eval_oracle(
                            step["expect"]["oracle"], step.get("expect", {}),
                            result, context["steps"])
                        record["oracle_passed"] = passed
                        record["oracle_detail"] = detail
                        current = step["on_success"] if passed else step["on_failure"]
                        executed.append(record)
                        if current in ("succeed", "fail", "abort"):
                            terminal = current
                            break
                        continue
                    if step["tool"] in HTTP_FAMILY:
                        if (step["tool"] == "mailbox_poll" and not resolved.get("url")
                                and not resolved.get("path")):
                            resolved["path"] = "/api/v2/messages"
                        url = self._url_for(manifest, step, resolved)
                        resolved["_url"] = url
                        record["url"] = url
                    headers = self._headers_for(step, resolved.get("_url", ""))
                    if 'business_logic' in manifest and step.get('lifecycle_phase') == 'experiment':
                        ctx = self.write_context
                        url = step['object_url']
                        row = write_set.inspect_object(ctx['db_path'], url)
                        if row['state'] == 'pre_state':
                            write_set.mark_state(ctx['db_path'], url, 'experiment',
                                run_id=ctx['run_id'], session_id=ctx['session_id'],
                                evidence={'manifest': check['manifest_hash'], 'step': current})
                        allowed, reason = write_set.mutation_permitted(ctx['db_path'], url,
                            write_set.fingerprint_credentials(headers),
                            run_id=ctx['run_id'], session_id=ctx['session_id'])
                        if not allowed:
                            raise ChainAbort(reason)
                    result, cost = self._run_tool(step, resolved, headers, context["steps"])
                    requests_sent = self.transport.snapshot()["sent"]
                    record["ok"] = bool(result.get("ok"))
                    record["result"] = {k: v for k, v in result.items() if k != "fulltext"}
                    context["steps"][current] = result
                    if 'business_logic' in manifest and step.get('lifecycle_phase') in {'pre_state', 'post_state'}:
                        import json
                        try:
                            snapshot = json.loads(result.get('fulltext', ''))
                            if not isinstance(snapshot, dict) or not result.get('ok') or not 200 <= result.get('status', 0) < 300:
                                raise ValueError('invalid observation')
                            if str(_dig(snapshot, step['resource_field'])) != step['resource_id']:
                                raise ValueError('observer resource identity mismatch')
                            ctx = self.write_context
                            write_set.mark_state(ctx['db_path'], step['object_url'], step['lifecycle_phase'],
                                run_id=ctx['run_id'], session_id=ctx['session_id'], evidence=snapshot)
                        except (ValueError, TypeError, write_set.WriteSetError) as exc:
                            raise ChainAbort('invalid lifecycle observation: ' + str(exc)) from exc
                    if step["tool"] == "store_finding":
                        passed = bool(result.get("ok"))
                        detail = {"finding_id": result.get("finding_id"),
                                  "reportable": bool(result.get("reportable"))}
                    else:
                        passed, detail = _eval_oracle(
                            step["expect"]["oracle"], step.get("expect", {}),
                            result, context["steps"])
                    record["oracle_passed"] = passed
                    record["oracle_detail"] = detail
                    current = step["on_success"] if passed else step["on_failure"]
                except ChainAbort as exc:
                    record["error"] = str(exc)
                    terminal_error = str(exc)
                    current = "abort"
                executed.append(record)
                if current in ("succeed", "fail", "abort"):
                    terminal = current
                    break
        except ChainAbort as exc:
            terminal_error = str(exc)
        finally:
            wire = self.transport.finish()
            elapsed = round(time.monotonic() - started, 3)
        # fulltext kanıt için hash'te durur; raporda excerpt kullanılır.
        return {"success": terminal == "succeed", "terminal": terminal,
                "terminal_error": terminal_error, "steps_executed": executed,
                "requests_sent": wire["sent"], "elapsed_s": elapsed,
                "route_counts": wire["route_counts"],
                "manifest_hash": check["manifest_hash"]}

    def _execute_evidence_chain(self, manifest, check):
        """Typed P8 reads use the same fail-closed wire gate and budgets.

        Identity sessions stay explicit: no shared cookie jar or automatic login
        can silently replace the tested principal. Only this chain is blocked.
        """
        import json
        from evidence_chaining import EvidenceError, bound_request, field, response, has_field
        ready = self.plan(manifest)
        if not ready.get('runnable'):
            return {'success': False, 'terminal': 'not_runnable', 'status': 'blocked',
                    'verdict': 'INCONCLUSIVE', 'errors': ready.get('errors', []),
                    'requests_sent': 0, 'steps_executed': [], 'elapsed_s': 0.0}
        graph, contract = self.evidence_graph, manifest['evidence_chain']
        spec = contract['spec']
        exchanges, executed, proof = {}, [], {}
        terminal, error = 'abort', ''
        start = time.monotonic()
        self.transport.begin(manifest['budget'])
        try:
            for step in manifest['steps']:
                graph.check_plan(manifest, self.evidence_context, self.identities)
                self.transport.begin_step(step)
                args = dict(step['args'])
                for binding in contract['bindings']:
                    if binding['consumer_step'] == step['id']:
                        value = field(response(exchanges[binding['producer_step']]), binding['response_field'])
                        if type(value) is not type(binding['value']) or value != binding['value']:
                            raise EvidenceError('new_reference_requires_replan')
                        args = bound_request(args, binding['request_field'], value)
                headers = self._headers_for(step, args['url'])
                # The transport checks scope, approvals and quotas for each wire
                # request, including redirects. Captured scope facts are no grant.
                result = self.transport.request('GET', args['url'], headers, args.get('body', ''), 15)
                try:
                    body = json.loads(result.get('text', ''))
                except (TypeError, ValueError):
                    body = None
                h = spec['captures'][step['id']]
                source = graph.evidence(h)
                exchange = {'kind': 'exchange', 'context': spec['context'],
                            'observed_at': graph.clock(), 'expires_at': source['expires_at'],
                            'identity_ref': step['identity_refs'][0],
                            'credential_hash': source['credential_hash'], 'request': args,
                            'response': {'ok': result.get('ok') is True, 'status': result.get('status'), 'body': body}}
                exchanges[step['id']] = exchange
                record = {'id': step['id'], 'tool': step['tool'], 'ok': result.get('ok') is True,
                          'oracle': step['expect']['oracle'], 'oracle_passed': False,
                          'exchange_hash': graph.observe(exchange)}
                executed.append(record)
                graph.check_plan(manifest, self.evidence_context, self.identities)
                if step['id'] == 'producer':
                    value = field(response(exchange), spec['response_field'])
                    if type(value) is not type(contract['bindings'][0]['value']) or value != contract['bindings'][0]['value']:
                        raise EvidenceError('new_reference_requires_replan')
                elif step['id'] == 'owner':
                    data = response(exchange)
                    expected_value = contract['bindings'][0]['value']
                    if (type(field(data, spec['resource_field'])) is not type(expected_value)
                            or field(data, spec['resource_field']) != expected_value
                            or not isinstance(field(data, spec['private_field']), str)
                            or not field(data, spec['private_field'])):
                        raise EvidenceError('owner_resource_or_private_evidence_mismatch')
                elif step['id'] == 'negative':
                    if (result.get('ok') is not True or result.get('status') not in {403, 404}
                            or has_field(body, spec['private_field'])):
                        raise EvidenceError('negative_control_failed')
                record['oracle_passed'] = True
            graph.check_plan(manifest, self.evidence_context, self.identities)
            proof = graph.seal_replay(manifest, exchanges)
            terminal = 'succeed' if proof['verdict'] == 'CONFIRMED' else 'fail'
            executed[-1]['oracle_passed'] = terminal == 'succeed'
            executed[-1]['oracle_detail'] = proof['effect']
        except (EvidenceError, ChainAbort, KeyError, TypeError, ValueError) as exc:
            error = str(exc)
            graph.sweep()
        finally:
            wire = self.transport.finish()
        return {'success': terminal == 'succeed', 'terminal': terminal,
                'status': 'completed' if terminal in {'succeed', 'fail'} else 'blocked',
                'terminal_error': error, 'verdict': proof.get('verdict', 'INCONCLUSIVE'),
                'requests_sent': wire['sent'], 'steps_executed': executed,
                'elapsed_s': round(time.monotonic()-start, 3), 'route_counts': wire['route_counts'],
                'manifest_hash': check['manifest_hash'], **proof}


def execute_and_complete(runtime, task_id: int, worker_id: str, lease_token: str,
                         manifest: dict, executor: ChainExecutor | None = None) -> dict:
    """Zinciri çalıştır ve runtime task'ını sonucu ile kapat (kuyruk bağlaması)."""
    runner = executor or ChainExecutor()
    out = runner.execute(manifest)
    runtime.complete_task(
        task_id, worker_id, lease_token,
        result={"manifest_hash": out.get("manifest_hash", ""),
                "terminal": out.get("terminal", ""),
                "success": out.get("success", False),
                "terminal_error": out.get("terminal_error", ""),
                "requests_sent": out.get("requests_sent", 0),
                "steps": [(s.get("id"), s.get("tool"), bool(s.get("oracle_passed")))
                          for s in out.get("steps_executed", [])]},
        checkpoint={"manifest_hash": out.get("manifest_hash", ""),
                    "terminal": out.get("terminal", "")},
        actual_request_cost=out.get("requests_sent", 0),
    )
    return out


def _load_json_file(path: str) -> dict:
    import json as _json

    if not path:
        return {}
    with open(path, encoding="utf-8") as handle:
        data = _json.load(handle)
    return data if isinstance(data, dict) else {}


def main(argv=None) -> int:
    import argparse
    import json as _json
    import sys as _sys

    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(prog="chain_executor",
                                     description="Action manifest zincir koşturucu")
    parser.add_argument("action", choices=["plan", "run"],
                        help="plan: ağa dokunmadan akışı göster; run: çalıştır")
    parser.add_argument("manifest", help="Manifest JSON dosya yolu")
    parser.add_argument("--target-bases", default="",
                        help="target_ref -> base URL JSON dosyası")
    parser.add_argument("--identities", default="",
                        help="identity adı -> header JSON dosyası (lab kullanımı; "
                             "secret'lar dosyada durur, shell history'e yazılmaz)")
    parser.add_argument("--task-id", type=int, default=0,
                        help="Varsa runtime task'ı sonuçla kapatılır")
    parser.add_argument("--worker-id", default="")
    parser.add_argument("--lease-token", default="")
    args = parser.parse_args(argv)

    with open(args.manifest, encoding="utf-8") as handle:
        manifest = _json.load(handle)
    try:
        from policy_engine import PolicyEngine

        engine = PolicyEngine()
    except Exception as exc:
        print(_json.dumps({"error": f"policy engine yüklenemedi: {exc}"}))
        return 2
    runner = ChainExecutor(
        policy_engine=engine,
        target_bases=_load_json_file(args.target_bases),
        identities=_load_json_file(args.identities),
    )
    if args.action == "plan":
        print(_json.dumps(runner.plan(manifest), indent=2, ensure_ascii=False))
        return 0
    if args.task_id and args.worker_id and args.lease_token:
        from campaign_runtime import CampaignRuntime

        out = execute_and_complete(
            CampaignRuntime(), args.task_id, args.worker_id,
            args.lease_token, manifest, executor=runner)
    else:
        out = runner.execute(manifest)
    print(_json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
