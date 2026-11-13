"""F1/F2/F3 fuzz guardrails: MCP budget, sane defaults, early-stop (offline)."""

import inspect
import time

import pytest

from conftest import load_server


def _wl(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("".join(f"w{i}\n" for i in range(lines)))
    return str(p)


def test_ffuf_refuses_over_budget_without_spawning(tmp_path, monkeypatch):
    kali = load_server("kali-tools")
    wl = _wl(tmp_path, "big.txt", 6000)

    def boom(*a, **k):
        raise AssertionError("must not spawn ffuf over budget")

    monkeypatch.setattr(kali, "run_command", boom)
    monkeypatch.setattr(kali, "_run_ffuf_supervised", boom)
    out = kali.ffuf_fuzz("http://t.local/FUZZ", wordlist=wl)
    assert "REFUSED (fuzz-budget)" in out
    assert "6000" in out


def test_ffuf_refuses_unreadable_wordlist(tmp_path, monkeypatch):
    kali = load_server("kali-tools")

    def boom(*a, **k):
        raise AssertionError("must not spawn ffuf without wordlist")

    monkeypatch.setattr(kali, "run_command", boom)
    monkeypatch.setattr(kali, "_run_ffuf_supervised", boom)
    out = kali.ffuf_fuzz("http://t.local/FUZZ", wordlist=str(tmp_path / "nope.txt"))
    assert "ERROR: wordlist unreadable" in out


def test_gobuster_refuses_over_budget(tmp_path, monkeypatch):
    kali = load_server("kali-tools")
    wl = _wl(tmp_path, "big.txt", 6000)

    def boom(*a, **k):
        raise AssertionError("must not spawn gobuster over budget")

    monkeypatch.setattr(kali, "run_command", boom)
    out = kali.gobuster_scan("http://t.local", wordlist=wl)
    assert "REFUSED (fuzz-budget)" in out


def test_estimate_counts_extensions_multiplier(tmp_path):
    kali = load_server("kali-tools")
    wl = _wl(tmp_path, "w.txt", 3000)
    lines, total = kali._fuzz_request_estimate(wl, "php,html")
    assert (lines, total) == (3000, 9000)


def test_estimate_counts_extra_w_wordlist(tmp_path):
    kali = load_server("kali-tools")
    wl = _wl(tmp_path, "w.txt", 100)
    extra = _wl(tmp_path, "e.txt", 50)
    lines, total = kali._fuzz_request_estimate(wl, "", f"-w {extra}")
    assert (lines, total) == (150, 150)


def test_budget_env_override(tmp_path, monkeypatch):
    kali = load_server("kali-tools")
    monkeypatch.setenv("CCO_FUZZ_BUDGET", "10")
    wl = _wl(tmp_path, "w.txt", 20)
    out = kali.ffuf_fuzz("http://t.local/FUZZ", wordlist=wl)
    assert "REFUSED (fuzz-budget)" in out
    assert "(10)" in out


def test_budget_from_program_profile(tmp_path, monkeypatch):
    import json
    kali = load_server("kali-tools")
    prof = tmp_path / "strict.json"
    prof.write_text(json.dumps({"fuzz_max_requests_per_call": 50}))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(prof))
    monkeypatch.delenv("CCO_FUZZ_BUDGET", raising=False)
    assert kali._fuzz_budget() == 50
    wl = _wl(tmp_path, "w.txt", 100)
    out = kali.ffuf_fuzz("http://t.local/FUZZ", wordlist=wl)
    assert "REFUSED (fuzz-budget)" in out
    assert "(50)" in out


def test_budget_env_beats_profile(tmp_path, monkeypatch):
    import json
    kali = load_server("kali-tools")
    prof = tmp_path / "strict.json"
    prof.write_text(json.dumps({"fuzz_max_requests_per_call": 50}))
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(prof))
    monkeypatch.setenv("CCO_FUZZ_BUDGET", "5000")
    assert kali._fuzz_budget() == 5000


def test_budget_default_without_profile(tmp_path, monkeypatch):
    kali = load_server("kali-tools")
    # Hermetik: operatorun repo .codex/program-policy.json dosyasi sizmamali.
    empty_policy = tmp_path / "program-policy.json"
    empty_policy.write_text("{}")
    monkeypatch.setenv("CCO_PROGRAM_POLICY_FILE", str(empty_policy))
    monkeypatch.delenv("CCO_FUZZ_BUDGET", raising=False)
    assert kali._fuzz_budget() == 5000


def test_safe_defaults():
    kali = load_server("kali-tools")
    sig = inspect.signature(kali.ffuf_fuzz).parameters
    assert sig["timeout"].default == 180
    assert sig["wordlist"].default.endswith("common.txt")
    assert sig["early_stop"].default == 1000
    gsig = inspect.signature(kali.gobuster_scan).parameters
    assert gsig["timeout"].default == 180
    assert gsig["wordlist"].default.endswith("common.txt")


def test_supervised_early_stop_kills_on_404_streak():
    kali = load_server("kali-tools")
    cmd = "for i in $(seq 1 50); do echo \":: Progress: [$i/50] :: Job [1/1]\" >&2; sleep 0.05; done"
    start = time.monotonic()
    res = kali._run_ffuf_supervised(cmd, timeout=30, early_stop=3)
    elapsed = time.monotonic() - start
    assert res["stopped_early"] is True
    assert "EARLY-STOP" in res["stderr"]
    assert elapsed < 10


def test_supervised_keeps_running_when_matches_found():
    kali = load_server("kali-tools")
    cmd = (
        "echo 'admin [Status: 200, Size: 10]'; "
        "for i in $(seq 1 5); do echo \":: Progress: [$i/5] :: Job [1/1]\" >&2; sleep 0.05; done"
    )
    res = kali._run_ffuf_supervised(cmd, timeout=30, early_stop=3)
    assert res["stopped_early"] is False
    assert res["success"] is True


def test_supervised_waits_for_inflight_match_before_killing():
    kali = load_server("kali-tools")
    cmd = (
        "echo ':: Progress: [5/50] :: Job [1/1]' >&2; sleep 1; "
        "echo 'admin [Status: 200, Size: 10]'; sleep 3"
    )
    res = kali._run_ffuf_supervised(cmd, timeout=30, early_stop=3)
    assert res["stopped_early"] is False
    assert res["success"] is True


def test_supervised_timeout_reports_progress():
    kali = load_server("kali-tools")
    res = kali._run_ffuf_supervised("sleep 30", timeout=1, early_stop=1000)
    assert res["success"] is False
    assert "TIMEOUT" in res["stderr"]
