"""Faz 7: negatif kontrol — sertlestirilmis /safe yuzeyde FP olmamali."""
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "negative_control_test", REPO_ROOT / "scripts" / "negative-control.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_negative_control_zero_false_positives():
    mod = _load_script()
    out = mod.run_battery(rounds=1)
    assert out["total"] >= 6
    errors = [c for c in out["checks"] if str(c["verdict"]).startswith("ERROR")]
    assert not errors, f"batarya gercekten kosamadi: {errors}"
    assert out["false_positives"] == 0, out["checks"]
    assert out["fp_rate"] == 0.0


@pytest.mark.parametrize("verdict", ["ERROR", "ERROR:TimeoutError", "INCONCLUSIVE", "SKIPPED", ""])
def test_negative_control_evaluation_rejects_unresolved_or_failed_oracle(verdict):
    mod = _load_script()
    out = mod.summarize_checks([{"name": "safe", "verdict": verdict, "false_positive": False}])
    assert out["passed"] is False
    assert out["unresolved"] == 1


def test_negative_control_evaluation_requires_nonempty_definitive_results():
    mod = _load_script()
    assert mod.summarize_checks([])["passed"] is False
    assert mod.summarize_checks([{"verdict": "UNCONFIRMED"}])["passed"] is True
    result = mod.summarize_checks([{"verdict": "CONFIRMED"}])
    assert result["false_positives"] == 1 and result["passed"] is False
    assert mod._verdict("[]") == "ERROR"


def test_entire_battery_and_cli_fail_when_all_oracles_error(monkeypatch, capsys):
    import requests
    import threading

    mod = _load_script()
    server = SimpleNamespace(server_address=("127.0.0.1", 1), serve_forever=lambda: None,
                             shutdown=lambda: None, server_close=lambda: None)
    error = lambda *a, **kw: '{"verdict":"ERROR"}'
    fake_validator = SimpleNamespace(validate_sqli=error, validate_xss_reflection=error,
                                     validate_idor=error, validate_auth_bypass=error,
                                     validate_open_redirect=error)
    fake_hunter = SimpleNamespace(analyze_authz_result=error)
    objects = {"neg_vuln_lab": SimpleNamespace(serve=lambda port: server),
               "neg_validator": fake_validator, "neg_hunter": fake_hunter}
    monkeypatch.setattr(mod, "_load", lambda alias, path: objects[alias])
    monkeypatch.setattr(threading, "Thread", lambda **kw: SimpleNamespace(start=lambda: None))
    monkeypatch.setattr(requests, "get", lambda *a, **kw: SimpleNamespace(status_code=403, text="denied"))
    out = mod.run_battery(rounds=1)
    assert out["total"] == out["unresolved"] == 6
    assert out["false_positives"] == 0 and out["passed"] is False
    monkeypatch.setattr(mod, "run_battery", lambda rounds: out)
    assert mod.main(["--rounds", "1", "--json"]) == 1
    assert '"passed": false' in capsys.readouterr().out


def test_entire_battery_passes_with_definitive_safe_results(monkeypatch, capsys):
    import requests
    import threading

    mod = _load_script()
    closed = []
    server = SimpleNamespace(server_address=("127.0.0.1", 1), serve_forever=lambda: None,
                             shutdown=lambda: closed.append("shutdown"),
                             server_close=lambda: closed.append("close"))
    safe = lambda *a, **kw: '{"verdict":"UNCONFIRMED"}'
    fake_validator = SimpleNamespace(validate_sqli=safe, validate_xss_reflection=safe,
                                     validate_idor=safe, validate_auth_bypass=safe,
                                     validate_open_redirect=safe)
    objects = {"neg_vuln_lab": SimpleNamespace(serve=lambda port: server),
               "neg_validator": fake_validator,
               "neg_hunter": SimpleNamespace(analyze_authz_result=safe)}
    monkeypatch.setattr(mod, "_load", lambda alias, path: objects[alias])
    monkeypatch.setattr(threading, "Thread", lambda **kw: SimpleNamespace(start=lambda: None))
    monkeypatch.setattr(requests, "get", lambda *a, **kw: SimpleNamespace(status_code=403, text="denied"))
    out = mod.run_battery(rounds=1)
    assert out["total"] == 6 and out["unresolved"] == 0 and out["passed"] is True
    assert closed == ["shutdown", "close"]
    monkeypatch.setattr(mod, "run_battery", lambda rounds: out)
    assert mod.main(["--rounds", "1", "--json"]) == 0
    assert '"passed": true' in capsys.readouterr().out
