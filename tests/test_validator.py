"""
mcp-validator deterministik doğrulama — offline birim testleri.
Network gerektiren validator tool'ları test edilmez; saf oracle/yardımcı
fonksiyonlar, dispatcher routing ve rapor üretimi doğrulanır.
"""
import json
import os
import re

import pytest

from conftest import load_server, list_tool_names


def _v():
    return load_server("validator")


def test_validator_imports_and_tool_count():
    mod = _v()
    assert hasattr(mod, "mcp")
    names = list_tool_names(mod)
    assert names == [
        "validate_sqli",
        "validate_ssti",
        "validate_command_injection",
        "validate_path_traversal",
        "validate_xss_reflection",
        "validate_stored_reflection",
        "validate_open_redirect",
        "validate_business_logic",
        "validate_field_binding",
        "validate_access_control",
        "validate_ssrf_oob",
        "confirm_oob_callback",
        "validate_blind_oob",
        "validate_csrf",
        "validate_second_order",
        "validate_xxe",
        "validate_auth_bypass",
        "validate_idor",
        "validate_file_upload",
        "validate_deserialization",
        "validate_token_differential",
        "forge_cbc_token",
        "splice_cbc_token",
        "validate_token_roundtrip",
        "analyze_differential_observations",
        "validate_finding",
        "generate_validation_report",
        "session_vault_put",
        "session_vault_bind_resources",
        "session_vault_check",
    ]


def test_ssti_arithmetic_oracle():
    mod = _v()
    # render edilmiş: sonuç var, ifade yok → True
    assert mod._ssti_oracle("Hello 49 world", 7, 7) is True
    # render edilmemiş: ifade aynen yansımış → False
    assert mod._ssti_oracle("Hello {{7*7}} -> 7*7", 7, 7) is False
    # sonuç hiç yok → False
    assert mod._ssti_oracle("nothing here", 7, 7) is False


def test_boolean_differential_oracle():
    mod = _v()
    base = {"ok": True, "status": 200, "len": 1000, "text": "A" * 1000}
    true_r = {"ok": True, "status": 200, "len": 1000, "text": "A" * 1000}
    false_r = {"ok": True, "status": 200, "len": 50, "text": "B" * 50}
    assert mod._boolean_confirms(base, true_r, false_r) is True
    # TRUE/FALSE aynıysa (fark yok) → onaylanmaz
    assert mod._boolean_confirms(base, true_r, true_r) is False


def test_file_signatures():
    mod = _v()
    assert mod.LINUX_FILE_SIG.search("root:x:0:0:root:/root:/bin/bash")
    assert mod.WIN_FILE_SIG.search("[fonts]\nrandom=1")
    assert not mod.LINUX_FILE_SIG.search("just a normal page")


def test_dispatcher_unknown_type():
    mod = _v()
    out = json.loads(mod.validate_finding("totally-unknown-vuln", "http://x/"))
    assert out["verdict"] == "ERROR"
    assert "supported" in out


def test_report_generation_confirmed():
    mod = _v()
    result = json.dumps({
        "vuln_type": "SQL Injection (boolean-based)",
        "target": "http://t/item?id=1",
        "verdict": "CONFIRMED",
        "confidence": 0.9,
        "severity": "high",
        "oracle": "differential_boolean",
        "evidence": {"true_payload": "1 AND 1=1"},
        "reproduction": ["curl -sk 'http://t/item?id=1 AND 1=1'"],
        "false_positive_guard": "deterministik",
        "notes": "ok",
        "timestamp": "2026-06-14T00:00:00Z",
    })
    md = mod.generate_validation_report(result)
    assert "# ⚠️ Doğrulama Raporu" in md
    assert "Reproduction" in md
    assert "Remediation" in md
    assert "prepared statement" in md.lower()
    assert "LEGACY / UNVERIFIED INPUT" in md
    assert "UNVERIFIED_INPUT" in md


def test_confidence_zero_when_unconfirmed():
    mod = _v()
    out = json.loads(mod._result("XSS", "http://t/", mod.UNCONFIRMED,
                                 "unescaped_reflection", {}, "-"))
    assert out["confidence"] == 0.0
    assert out["severity"] == "info"


def test_result_persists_v2_artifact_and_hash():
    mod = _v()
    out = json.loads(mod._result("XSS", "http://t/", mod.UNCONFIRMED,
                                 "unescaped_reflection", {"k": "v"}, "-"))
    assert out["schema_version"] == "2.0"
    assert out["artifact"]["persisted"] is True
    assert os.path.exists(out["audit_trail"])
    with open(out["audit_trail"], encoding="utf-8") as handle:
        stored = json.load(handle)
    assert stored["validation_id"] == out["validation_id"]
    assert stored["artifact"]["content_sha256"] == out["artifact"]["content_sha256"]
    assert stored["artifact"]["signature"]["algorithm"] == "ed25519:v1"
    assert len(stored["artifact"]["signature"]["key_id"]) == 64
    assert stored["artifact"]["signature"]["value"]
    loaded = mod.load_validation(out["validation_id"])
    assert loaded and loaded["validation_id"] == out["validation_id"]
    assert stored["binding"]["target"] == "t"
    assert stored["binding"]["finding_type"] == "xss"
    assert stored["binding"]["scope_revision"]
    assert stored["binding"]["policy_hash"]
    assert mod.artifact_is_valid(out) is True


def test_artifact_rejects_relabelled_submitted_record():
    mod = _v()
    out = json.loads(mod._result("XSS", "http://t/", mod.UNCONFIRMED,
                                 "unescaped_reflection", {"k": "v"}, "-"))
    tampered = json.loads(json.dumps(out))
    tampered["verdict"] = "CONFIRMED"
    tampered["reportable"] = True
    tampered["target"] = "http://evil/"
    assert mod.artifact_is_valid(tampered) is False


def test_safe_curl_redacts_credentials_and_query_secrets():
    mod = _v()
    cmd = mod._curl(
        "GET",
        "http://t.local/path?token=abc123&x=1",
        headers={"Authorization": "Bearer super-secret", "X-Test": "ok"},
    )
    assert "super-secret" not in cmd
    assert "abc123" not in cmd
    assert "<redacted>" in cmd
    assert "x=1" in cmd


def test_validate_auth_bypass_requires_credential_header():
    mod = _v()
    out = json.loads(mod.validate_auth_bypass("http://t.local/protected", "{}"))
    assert out["verdict"] == "ERROR"
    assert "credential header" in out["notes"]


@pytest.mark.parametrize("marker,status,body", [
    ("", 403, "forbidden"),
    ("private-test-marker", 200, "private-test-marker forbidden"),
    ("private-test-marker", 403, "private-test-marker"),
    ("private-test-marker", 404, "missing"),
])
def test_auth_bypass_ambiguous_control_cannot_become_tested_clean(monkeypatch, marker, status, body):
    mod = _v()
    url = "https://synthetic.test/protected"
    replies = iter([
        {"ok": True, "status": 200, "text": "private-test-marker",
         "request_method": "GET", "final_url": url},
        {"ok": True, "status": status, "text": body, "request_method": "GET", "final_url": url},
    ])
    monkeypatch.setattr(mod, "_request", lambda *a, **kw: next(replies))
    result = json.loads(mod.validate_auth_bypass(url, '{"Cookie":"sid=synthetic"}', protected_marker=marker))
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["reportable"] is False and mod.artifact_is_valid(result)
    assert [e["role"] for e in result["request_evidence"]] == ["authorized", "anonymous"]


def test_validate_idor_rejects_same_identity():
    mod = _v()
    same = json.dumps({"Authorization": "Bearer userA"})
    out = json.loads(mod.validate_idor("http://t.local/object/1", same, same))
    assert out["verdict"] == "ERROR"
    assert "aynı" in out["notes"]


def test_xss_reflection_requires_execution_proof(monkeypatch):
    mod = _v()

    def fake_send(url, payload, **kwargs):
        return {
            "ok": True,
            "status": 200,
            "len": len(payload),
            "time": 0.01,
            "text": f"<html><body>{payload}</body></html>",
            "headers": {"Content-Type": "text/html"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    out = json.loads(mod.validate_xss_reflection("http://t.local/search?q=1", param="q"))
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["evidence"]["reflection"]["verdict"] == "CONFIRMED"
    assert out["evidence"]["execution"]["verdict"] == "INCONCLUSIVE"


def test_sqli_error_only_is_inconclusive(monkeypatch):
    mod = _v()

    def fake_send(url, payload, **kwargs):
        if payload.endswith("'"):
            text = "Database error: You have an error in your SQL syntax"
        else:
            text = "normal page"
        return {
            "ok": True,
            "status": 200,
            "len": len(text),
            "time": 0.05,
            "text": text,
            "headers": {"Content-Type": "text/html"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    out = json.loads(mod.validate_sqli("http://t.local/item?id=1", param="id"))
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["vuln_type"] == "SQL Injection candidate (error disclosure)"


def test_ssti_single_arithmetic_hit_is_inconclusive(monkeypatch):
    mod = _v()
    counts = {"probe": 0}

    def fake_send(url, payload, **kwargs):
        match = re.search(r"(\d+)\*(\d+)", payload)
        if payload == "cco_probe":
            text = "normal page"
        elif match and payload.startswith("{{") and payload.endswith("}}") and not payload.endswith("*}}"):
            counts["probe"] += 1
            text = str(int(match.group(1)) * int(match.group(2))) if counts["probe"] == 1 else "literal"
        elif payload.startswith("{{") and payload.endswith("*}}"):
            text = "template syntax error"
        else:
            text = "literal"
        return {
            "ok": True,
            "status": 200,
            "len": len(text),
            "time": 0.01,
            "text": text,
            "headers": {"Content-Type": "text/html"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    out = json.loads(mod.validate_ssti("http://t.local/render", param="tpl"))
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["vuln_type"] == "Server-Side Template Injection candidate"


def test_ssti_two_distinct_arithmetic_hits_confirm(monkeypatch):
    mod = _v()

    def fake_send(url, payload, **kwargs):
        match = re.search(r"(\d+)\*(\d+)", payload)
        if payload == "cco_probe":
            text = "normal page"
        elif match and not payload.endswith("*}}") and payload.startswith("{{"):
            text = str(int(match.group(1)) * int(match.group(2)))
        elif payload.startswith("{{") and payload.endswith("*}}"):
            text = "template syntax error"
        else:
            text = "literal"
        return {
            "ok": True,
            "status": 200,
            "len": len(text),
            "time": 0.01,
            "text": text,
            "headers": {"Content-Type": "text/html"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    out = json.loads(mod.validate_ssti("http://t.local/render", param="tpl"))
    assert out["verdict"] == "CONFIRMED"
    assert out["oracle"] == "arithmetic_eval"


def test_command_injection_reflection_only_is_not_confirmed(monkeypatch):
    mod = _v()

    def fake_send(url, payload, **kwargs):
        return {
            "ok": True,
            "status": 200,
            "len": len(payload),
            "time": 0.02,
            "text": payload,
            "headers": {"Content-Type": "text/plain"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    out = json.loads(mod.validate_command_injection("http://t.local/run", param="cmd"))
    assert out["verdict"] == "UNCONFIRMED"


def test_path_traversal_baseline_signature_is_inconclusive(monkeypatch):
    mod = _v()

    def fake_send(url, payload, **kwargs):
        text = "root:x:0:0:root:/root:/bin/bash" if payload == "index" else "not-used"
        return {
            "ok": True,
            "status": 200,
            "len": len(text),
            "time": 0.01,
            "text": text,
            "headers": {"Content-Type": "text/plain"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    out = json.loads(mod.validate_path_traversal("http://t.local/file?name=index", param="name"))
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["evidence"]["baseline_contains_file_signature"] is True


def test_open_redirect_requires_3xx_status(monkeypatch):
    mod = _v()

    def fake_send(url, payload, **kwargs):
        return {
            "ok": True,
            "status": 200,
            "len": 0,
            "time": 0.01,
            "text": "",
            "headers": {"Content-Type": "text/plain"},
            "location": payload,
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    out = json.loads(mod.validate_open_redirect("http://t.local/go?next=/", param="next"))
    assert out["verdict"] == "UNCONFIRMED"


def test_oob_confirmation_requires_issued_pending_challenge(monkeypatch):
    mod = _v()

    def fake_send(url, payload, **kwargs):
        return {
            "ok": True,
            "status": 200,
            "len": 0,
            "time": 0.01,
            "text": "ok",
            "headers": {"Content-Type": "text/plain"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    monkeypatch.setattr(mod, "_oob_host_in_scope", lambda host: True)
    pending = json.loads(mod.validate_ssrf_oob("http://t.local/fetch?url=1", "oast.test", param="url"))
    token = pending["evidence"]["callback_correlation_id"]
    host = pending["evidence"]["callback_host"]
    confirmed = json.loads(mod.confirm_oob_callback(token, f"DNS callback for {host}"))
    assert confirmed["verdict"] == "INCONCLUSIVE"
    assert confirmed["evidence"]["matched_untrusted_text"] is True

    missing = json.loads(mod.confirm_oob_callback("unknown-token", "DNS callback for unknown-token.oast.test"))
    assert missing["verdict"] == "ERROR"


def test_xxe_static_signature_control_is_inconclusive(monkeypatch):
    mod = _v()

    def fake_request(method, url, **kwargs):
        return {
            "ok": True,
            "status": 200,
            "len": 32,
            "time": 0.01,
            "text": "root:x:0:0:root:/root:/bin/bash",
            "headers": {"Content-Type": "application/xml"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_xxe("http://t.local/xml"))
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["evidence"]["primitive_detected"] == "static_file_signature"


def test_sqli_waf_retry_confirms_with_comment_mutation(monkeypatch):
    mod = _v()

    def fake_send(url, payload, **kwargs):
        blocked = (
            "/**/" not in payload
            and bool(re.search(r"\bAND\b", payload, re.I))
        )
        if blocked:
            text = "This error was generated by Mod_Security"
            return {
                "ok": True, "status": 403, "len": len(text), "time": 0.01,
                "text": text, "headers": {"Server": "Mod_Security"},
                "location": "", "final_url": url, "error": None,
            }
        if "1=2" in payload.replace(" ", ""):
            text = "<html><body>Ürün bulunamadı</body></html>"
        else:
            text = "<html><body>Ürün #1: Widget extra-marker</body></html>"
        return {
            "ok": True, "status": 200, "len": len(text), "time": 0.01,
            "text": text, "headers": {"Content-Type": "text/html"},
            "location": "", "final_url": url, "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    out = json.loads(mod.validate_sqli("http://t.local/waf/item?id=1", param="id"))
    assert out["verdict"] == "CONFIRMED"
    assert out["evidence"].get("waf_retry")
    true_pl = out["evidence"].get("true_payload") or ""
    assert true_pl != "1 AND 1=1"
    assert "/**/" in true_pl or "%0" in true_pl or "AN/**/" in true_pl


def test_waf_retry_resolves_reasoning_core():
    from pathlib import Path

    _v()
    from cco_validator_core import waf_retry

    reasoning = Path(waf_retry._REASONING_DIR)
    assert reasoning.is_dir(), reasoning
    assert (reasoning / "cco_reasoning_core" / "payloads.py").is_file()
    assert waf_retry.generate_variants is not None
    assert waf_retry.classify_http is not None


def test_sqli_unstable_baseline_is_inconclusive(monkeypatch):
    mod = _v()
    calls = {"n": 0}

    def fake_send(url, payload, **kwargs):
        calls["n"] += 1
        if payload == "1":
            text = f"page-variant-{calls['n']}-{ 'X' * calls['n'] * 50}"
        elif "1=1" in payload or "'1'='1" in payload:
            text = "normal page"
        else:
            text = "empty"
        return {
            "ok": True, "status": 200, "len": len(text), "time": 0.02,
            "text": text, "headers": {"Content-Type": "text/html"},
            "location": "", "final_url": url, "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    out = json.loads(mod.validate_sqli("http://t.local/item?id=1", param="id"))
    assert out["verdict"] == "INCONCLUSIVE"
    assert "kararsız" in out["notes"]
    assert out["evidence"]["baseline_similarity"] < 0.95


def test_idor_anonymous_baseline_flags_public_object(monkeypatch):
    mod = _v()

    def fake_request(method, url, **kwargs):
        headers = kwargs.get("headers") or {}
        cookie = headers.get("Cookie", "")
        if cookie in ("owner=1", "atk=2"):
            text, status = "order of alice@example.com", 200
        else:
            text, status = "order of alice@example.com", 200
        return {
            "ok": True, "status": status, "len": len(text), "time": 0.01,
            "text": text, "headers": {}, "location": "", "final_url": url, "error": None,
        }

    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_idor(
        "http://t.local/order/9",
        json.dumps({"Cookie": "owner=1"}),
        json.dumps({"Cookie": "atk=2"}),
        owner_marker="alice@example.com",
    ))
    assert out["verdict"] == "CONFIRMED"
    assert out["evidence"]["owner_marker_in_anonymous_response"] is True
    assert "herkese açık" in out["notes"]


def test_idor_anonymous_baseline_clean_when_private(monkeypatch):
    mod = _v()

    def fake_request(method, url, **kwargs):
        headers = kwargs.get("headers") or {}
        cookie = headers.get("Cookie", "")
        if cookie in ("owner=1", "atk=2"):
            text, status = "order of alice@example.com", 200
        else:
            text, status = "login required", 403
        return {
            "ok": True, "status": status, "len": len(text), "time": 0.01,
            "text": text, "headers": {}, "location": "", "final_url": url, "error": None,
        }

    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_idor(
        "http://t.local/order/9",
        json.dumps({"Cookie": "owner=1"}),
        json.dumps({"Cookie": "atk=2"}),
        owner_marker="alice@example.com",
    ))
    assert out["verdict"] == "CONFIRMED"
    assert out["evidence"]["owner_marker_in_anonymous_response"] is False
    assert "herkese açık" not in out["notes"]


def test_open_redirect_follows_same_host_chain(monkeypatch):
    mod = _v()
    state = {"payload": ""}

    def fake_send(url, payload, **kwargs):
        state["payload"] = payload
        return {
            "ok": True, "status": 302, "len": 0, "time": 0.01, "text": "",
            "headers": {}, "location": "/hop2", "final_url": url, "error": None,
        }

    def fake_request(method, url, **kwargs):
        match = re.search(r"https://([^/\"']+)", state["payload"])
        sentinel = match.group(1) if match else "none.test"
        return {
            "ok": True, "status": 302, "len": 0, "time": 0.01, "text": "",
            "headers": {}, "location": f"https://{sentinel}/",
            "final_url": url, "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_open_redirect("http://t.local/go?next=/", param="next"))
    assert out["verdict"] == "CONFIRMED"
    assert out["evidence"]["hop_index"] == 1
    assert "same-host chained hops" in out["guard"]["controls"]


def test_open_redirect_stops_at_external_hop(monkeypatch):
    mod = _v()

    def fake_send(url, payload, **kwargs):
        return {
            "ok": True, "status": 302, "len": 0, "time": 0.01, "text": "",
            "headers": {}, "location": "https://other.example/welcome",
            "final_url": url, "error": None,
        }

    def fake_request(method, url, **kwargs):
        raise AssertionError("harici hop takip edilmemeli")

    monkeypatch.setattr(mod, "_send_payload", fake_send)
    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_open_redirect("http://t.local/go?next=/", param="next"))
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["guard"]["transport_ok"] is False


def test_validate_finding_introspection_and_class_agnostic_behavioral_oracle(monkeypatch):
    mod = _v()
    info = json.loads(mod.validate_finding("?"))
    assert info["verdict"] == "INFO"
    assert "validate_token_roundtrip" in info["validator_signatures"]
    assert "validate_second_order" in info["validator_signatures"]
    assert "csrf" in info["supported"]

    def fake_request(method, url, **kwargs):
        data = str(kwargs.get("data") or "")
        if "coupon=VIP100" in data:
            return {"ok": True, "status": 200, "len": 24, "time": 0.01,
                    "text": '{"total": 0, "status": "FREE_ORDER"}', "headers": {}, "location": "", "final_url": url, "error": None}
        return {"ok": True, "status": 200, "len": 24, "time": 0.01,
                "text": '{"total": 100, "status": "PAID"}', "headers": {}, "location": "", "final_url": url, "error": None}

    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_finding(
        "unlisted_coupon_logic_flaw",
        "http://t.local/api/checkout",
        json.dumps({
            "method": "POST",
            "control_data": "item=1&coupon=NONE",
            "probe_data": "item=1&coupon=VIP100",
            "expected_marker": "FREE_ORDER",
        }),
    ))
    assert out["verdict"] == "CONFIRMED"
    assert out["oracle"] == "behavioral_invariant"
    assert out.get("validation_id")


def test_access_control_anon_200_api_vs_public_html_and_reports_html_noise_filter(monkeypatch):
    mod = _v()

    # 1. Non-public /api/ telemetry endpoint returning operational JSON anonymously -> CONFIRMED
    def fake_api_anon(method, url, **kwargs):
        return {
            "ok": True,
            "status": 200,
            "len": 64,
            "time": 0.01,
            "text": '{"tenants":["t1","t2"],"events":42}',
            "headers": {"Content-Type": "application/json"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_request", fake_api_anon)
    api_res = json.loads(mod.validate_access_control(
        target_url="http://t.local/api/v1/telemetry/overview",
        check_category="function_role_access",
        caller_headers_json=json.dumps({"Authorization": "Bearer tok-member"}),
        caller_alias="member-a",
        caller_role="member",
        caller_tenant="t1",
        mode="blind",
    ))
    assert api_res["verdict"] == "CONFIRMED"
    assert api_res["oracle"] == "unauthenticated_api_access"
    assert api_res["reportable"] is True

    # 2. Public HTML landing page -> UNCONFIRMED
    def fake_public_html(method, url, **kwargs):
        return {
            "ok": True,
            "status": 200,
            "len": 45,
            "time": 0.01,
            "text": "<!doctype html><html><body>Welcome</body></html>",
            "headers": {"Content-Type": "text/html"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_request", fake_public_html)
    pub_res = json.loads(mod.validate_access_control(
        target_url="http://t.local/welcome",
        check_category="function_role_access",
        caller_headers_json=json.dumps({"Authorization": "Bearer tok-member"}),
        caller_alias="member-a",
        mode="blind",
    ))
    assert pub_res["verdict"] == "UNCONFIRMED"
    assert pub_res["evidence"]["public_or_unauthenticated"] is True

    # 3. Plain HTML /reports navigation shell (anon 302 -> /login) -> UNCONFIRMED (no noisy PROBABLE)
    def fake_reports_html(method, url, **kwargs):
        hdrs = kwargs.get("headers") or {}
        if not hdrs.get("Authorization"):
            return {
                "ok": True, "status": 302, "len": 0, "time": 0.01, "text": "",
                "headers": {"Location": "/login"}, "location": "/login", "final_url": url, "error": None,
            }
        return {
            "ok": True,
            "status": 200,
            "len": 90,
            "time": 0.01,
            "text": "<html><body><h1>Reports</h1>\n<nav>Menu</nav>\n<p>Pick a view</p></body></html>",
            "headers": {"Content-Type": "text/html"},
            "location": "",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(mod, "_request", fake_reports_html)
    rep_res = json.loads(mod.validate_access_control(
        target_url="http://t.local/reports",
        check_category="function_role_access",
        caller_headers_json=json.dumps({"Authorization": "Bearer tok-member"}),
        caller_alias="member-a",
        caller_role="member",
        caller_tenant="t1",
        owner_headers_json=json.dumps({"Authorization": "Bearer tok-admin"}),
        owner_alias="admin-a",
        mode="blind",
    ))
    assert rep_res["verdict"] == "UNCONFIRMED"


def test_sqli_order_by_asc_desc_and_case_when_oracles_with_negative_control(monkeypatch):
    mod = _v()

    # 1. Reversible ASC/DESC differential on ?sort=score
    def fake_asc_desc(url, payload, **kwargs):
        if payload == "score DESC":
            text = "<ul><li>doc-b (20)</li><li>doc-a (10)</li></ul>"
        elif payload in {"score", "score ASC"}:
            text = "<ul><li>doc-a (10)</li><li>doc-b (20)</li></ul>"
        else:
            text = "<ul><li>doc-a (10)</li><li>doc-b (20)</li></ul>"
        return {
            "ok": True, "status": 200, "len": len(text), "time": 0.01,
            "text": text, "headers": {"Content-Type": "text/html"},
            "location": "", "final_url": url, "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_asc_desc)
    asc_res = json.loads(mod.validate_sqli("http://t.local/documents?sort=score", param="sort", boolean_only=False))
    assert asc_res["verdict"] == "CONFIRMED"
    assert asc_res["oracle"] == "differential_order_by"
    assert asc_res["evidence"]["order_by_oracle"] == "reversible_direction_differential"

    # 2. Conditional CASE WHEN error differential on ?sort=score
    def fake_case_when(url, payload, **kwargs):
        if "1=2" in payload and ("1/0" in payload or "ABS(" in payload or "UNION" in payload):
            return {
                "ok": True, "status": 500, "len": 21, "time": 0.01,
                "text": "Internal Server Error", "headers": {"Content-Type": "text/html"},
                "location": "", "final_url": url, "error": None,
            }
        text = "<ul><li>doc-a (10)</li><li>doc-b (20)</li></ul>"
        return {
            "ok": True, "status": 200, "len": len(text), "time": 0.01,
            "text": text, "headers": {"Content-Type": "text/html"},
            "location": "", "final_url": url, "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_case_when)
    cw_res = json.loads(mod.validate_sqli("http://t.local/documents?sort=score", param="sort", boolean_only=False))
    assert cw_res["verdict"] == "CONFIRMED"
    assert cw_res["oracle"] == "differential_order_by"
    assert cw_res["evidence"]["order_by_oracle"] == "conditional_error_differential"

    # 3. Negative control: whitelisted/parameterized sort ignores injected SQL clauses identically
    def fake_safe_sort(url, payload, **kwargs):
        text = "<ul><li>doc-a (10)</li><li>doc-b (20)</li></ul>"
        return {
            "ok": True, "status": 200, "len": len(text), "time": 0.01,
            "text": text, "headers": {"Content-Type": "text/html"},
            "location": "", "final_url": url, "error": None,
        }

    monkeypatch.setattr(mod, "_send_payload", fake_safe_sort)
    safe_res = json.loads(mod.validate_sqli("http://t.local/documents?sort=score", param="sort", boolean_only=False))
    assert safe_res["verdict"] == "UNCONFIRMED"


