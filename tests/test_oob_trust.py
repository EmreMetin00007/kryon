"""Callback text and failed sends cannot become confirmed findings."""
import json
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import pytest

from conftest import load_server


@pytest.fixture
def validator(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_HOME", str(tmp_path / "home"))
    return load_server("validator")


def test_oob_requires_scoped_callback_and_readonly_probe(validator, monkeypatch):
    monkeypatch.setattr(validator, "_send_payload", lambda *a, **kw: pytest.fail("must not send"))
    monkeypatch.setattr(validator, "_oob_host_in_scope", lambda host: False)
    out = json.loads(validator.validate_ssrf_oob("https://owned.test/fetch?url=x", "callback.test", param="url"))
    assert out["verdict"] == "INCONCLUSIVE" and "outside active scope" in out["evidence"]["error"]
    for domain, method in (("127.0.0.1", "GET"), ("callback.test", "POST"), ("localhost", "GET")):
        out = json.loads(validator.validate_ssrf_oob("https://owned.test/fetch?url=x", domain, param="url", method=method))
        assert out["verdict"] == "INCONCLUSIVE" and not out["guard"]["transport_ok"]


def test_callback_scope_uses_actual_central_resolver(validator, tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_scope": [{"asset": "*.callback.test"}],
                                 "allow_osint": False, "allow_public_labs": False, "allow_loopback": False}))
    monkeypatch.setenv("CCO_SCOPE_FILE", str(scope))
    assert validator._oob_host_in_scope("nonce.callback.test")
    assert not validator._oob_host_in_scope("nonce.other.test")


def test_failed_oob_send_does_not_create_pending_challenge(validator, monkeypatch):
    monkeypatch.setattr(validator, "_oob_host_in_scope", lambda host: True)
    monkeypatch.setattr(validator, "_send_payload", lambda *a, **kw: {"ok": False, "status": None})
    monkeypatch.setattr(validator, "_store_oob_challenge", lambda *a: pytest.fail("must not issue challenge"))
    out = json.loads(validator.validate_ssrf_oob("https://owned.test/fetch?url=x", "callback.test", param="url"))
    assert out["verdict"] == "INCONCLUSIVE" and "callback_correlation_id" not in out["evidence"]


@pytest.mark.parametrize("status", [401, 429])
def test_session_or_rate_failure_does_not_create_pending_challenge(validator, monkeypatch, status):
    monkeypatch.setattr(validator, "_oob_host_in_scope", lambda host: True)
    monkeypatch.setattr(validator, "_send_payload", lambda *a, **kw: {"ok": True, "status": status})
    monkeypatch.setattr(validator, "_store_oob_challenge", lambda *a: pytest.fail("must not issue challenge"))
    result = json.loads(validator.validate_ssrf_oob("https://owned.test/fetch?url=x", "callback.test", param="url"))
    assert result["verdict"] == "INCONCLUSIVE" and "callback_correlation_id" not in result["evidence"]
    assert result["guard"]["transport_ok"] and result["evidence"]["status"] == status


@pytest.mark.parametrize("location", ["/login", "/log%69n", "/%256cogin"])
def test_login_redirect_does_not_create_pending_challenge(validator, monkeypatch, location):
    monkeypatch.setattr(validator, "_oob_host_in_scope", lambda host: True)
    monkeypatch.setattr(validator, "_send_payload", lambda *a, **kw: {
        "ok": True, "status": 302, "location": location})
    monkeypatch.setattr(validator, "_store_oob_challenge", lambda *a: pytest.fail("must not issue challenge"))
    result = json.loads(validator.validate_ssrf_oob("https://owned.test/fetch?url=x", "callback.test", param="url"))
    assert result["verdict"] == "INCONCLUSIVE" and "redirected to login" in result["evidence"]["error"]
    assert result["guard"]["transport_ok"] and "callback_correlation_id" not in result["evidence"]


def test_probe_binding_requires_the_exact_sent_request_and_uses_a_fresh_key(validator):
    target = "https://owned.test/fetch?url=old&session=synthetic-private-value"
    payload = "https://nonce.callback.test/"
    parsed = urlparse(target)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["url"] = payload
    sent = urlunparse(parsed._replace(query=urlencode(query)))
    response = {"request_method": "GET", "requests_sent": 1, "final_url": sent}
    first = validator._oob_sent_request_binding(target, "url", payload, response, b"a" * 32)
    second = validator._oob_sent_request_binding(target, "url", payload, response, b"b" * 32)
    assert len(first) == 64 and first != second and "synthetic-private-value" not in first
    assert not validator._oob_sent_request_binding(target, "url", payload,
                                                  {**response, "final_url": sent + "&extra=1"}, b"a" * 32)
    assert not validator._oob_sent_request_binding(target, "url", payload,
                                                  {**response, "requests_sent": 2}, b"a" * 32)


def test_scope_change_during_send_does_not_create_challenge(validator, monkeypatch):
    monkeypatch.setenv("CCO_SCOPE_REVISION", "scope-before")
    monkeypatch.setattr(validator, "_oob_host_in_scope", lambda host: True)
    def send(*args, **kwargs):
        monkeypatch.setenv("CCO_SCOPE_REVISION", "scope-after")
        return {"ok": True, "status": 200}
    monkeypatch.setattr(validator, "_send_payload", send)
    monkeypatch.setattr(validator, "_store_oob_challenge", lambda *a: pytest.fail("must not issue challenge"))
    result = json.loads(validator.validate_ssrf_oob("https://owned.test/fetch?url=x", "callback.test", param="url"))
    assert result["verdict"] == "INCONCLUSIVE" and "scope or policy changed" in result["evidence"]["error"]


def test_forged_callback_text_and_target_override_are_not_confirmed(validator, monkeypatch):
    sent = []
    monkeypatch.setattr(validator, "_oob_host_in_scope", lambda host: True)
    def send(url, payload, **kwargs):
        sent.append((url, payload, kwargs))
        return {"ok": True, "status": 200}
    monkeypatch.setattr(validator, "_send_payload", send)
    pending = json.loads(validator.validate_ssrf_oob("https://owned.test/fetch?url=x", "callback.test", param="url"))
    token, host = pending["evidence"]["callback_correlation_id"], pending["evidence"]["callback_host"]
    assert len(sent) == 1 and sent[0][1] == f"https://{host}/" and sent[0][2]["method"] == "GET"
    assert sent[0][2]["allow_redirects"] is False
    untrusted = json.loads(validator.confirm_oob_callback(token, f"DNS callback for {host}"))
    assert untrusted["verdict"] == "INCONCLUSIVE" and not untrusted["evidence"]["correlated"]
    assert untrusted["target"] == "https://owned.test/fetch?url=x"
    mismatch = json.loads(validator.confirm_oob_callback(token, host, target_url="https://other.test/"))
    assert mismatch["verdict"] == "ERROR"
    wrong_type = json.loads(validator.confirm_oob_callback(token, host, vuln_type="xss"))
    assert wrong_type["verdict"] == "ERROR"


def test_callback_poll_returns_metadata_without_claiming_a_finding(tmp_path):
    kali = load_server("kali-tools")
    log = tmp_path / "callback.jsonl"
    log.write_text(json.dumps({"protocol": "dns", "full-id": "nonce.callback.test",
                               "raw-request": "Cookie: private-value", "remote-address": "private-ip"}) + "\n")
    kali._interactsh_sessions["test"] = {"log_file": str(log)}
    try:
        output = kali.interactsh_poll("test")
    finally:
        del kali._interactsh_sessions["test"]
    assert "nonce.callback.test" in output and "doğrulanmalı" in output
    assert "private-value" not in output and "private-ip" not in output and "DOĞRULANDI" not in output
