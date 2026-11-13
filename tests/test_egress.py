"""Egress disiplini testleri: background gate, fuzz butcesi, watchdog."""

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _load(name, relpath):
    path = REPO_ROOT / relpath
    spec = importlib.util.spec_from_file_location(f"{name}_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _egress():
    return _load("egress_policy", "scripts/egress_policy.py")


def _watchdog():
    return _load("egress_watchdog", "scripts/egress_watchdog.py")


def _engine(tmp_path, policy_extra=None):
    module = _load("policy_engine", "scripts/policy_engine.py")
    codex = tmp_path / ".codex"
    codex.mkdir(exist_ok=True)
    (codex / "scope.json").write_text(json.dumps({
        "in_scope": [{"asset": "example.com", "type": "web"}],
    }))
    if policy_extra is not None:
        base = {"rate_limits": {
            "default": {"window_seconds": 60, "max_calls": 1000},
            "overrides": {}}}
        base.update(policy_extra)
        (codex / "program-policy.json").write_text(json.dumps(base))
    return module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))


# --- background tespiti ---

def test_is_backgrounded_variants():
    eg = _egress()
    assert eg.is_backgrounded("nohup python3 -u fuzz.py > f.log 2>&1 &") is True
    assert eg.is_backgrounded("curl -s https://example.com &") is True
    assert eg.is_backgrounded("curl -s https://example.com && echo ok") is False
    assert eg.is_backgrounded("python3 x.py 2>&1 | tee out.log") is False
    assert eg.is_backgrounded('echo "a & b"') is False
    assert eg.is_backgrounded("setsid ./scan.sh") is True


def test_background_network_job_needs_network_signal():
    eg = _egress()
    assert eg.is_background_network_job(
        "curl -s https://example.com/app &", ["https://example.com/app"]) is True
    assert eg.is_background_network_job("make -j8 &", []) is False
    assert eg.is_background_network_job("curl -s https://example.com/app",
                                        ["https://example.com/app"]) is False


def test_background_network_job_reads_script_urls(tmp_path):
    eg = _egress()
    script = tmp_path / "fuzz9.py"
    script.write_text('BASE="http://example.com:8088/api"\nimport requests\n')
    old = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert eg.is_background_network_job(
            "cd /tmp && nohup python3 -u fuzz9.py > fuzz9.log 2>&1 & echo started", []) is True
    finally:
        os.chdir(old)


def test_listener_excluded():
    eg = _egress()
    assert eg.is_background_network_job("python3 -m http.server 8000 &", []) is False
    assert eg.is_background_network_job("php -S 127.0.0.1:8000 &", []) is False


# --- fuzz butcesi ---

def test_estimate_counts_wordlist_times_targets(tmp_path):
    eg = _egress()
    wl = tmp_path / "common.txt"
    wl.write_text("a\n" * 120)
    total, details = eg.estimate_fuzz_requests(
        f"ffuf -u https://example.com/FUZZ -w {wl}",
        ["https://example.com/FUZZ"])
    assert total == 120
    assert "common.txt" in details[0]


def test_estimate_excludes_loopback_proxy(tmp_path):
    eg = _egress()
    wl = tmp_path / "common.txt"
    wl.write_text("a\n" * 120)
    total, details = eg.estimate_fuzz_requests(
        f"ffuf -u https://example.com/FUZZ -w {wl} -x http://127.0.0.1:8080",
        ["https://example.com/FUZZ", "http://127.0.0.1:8080"])
    assert total == 120
    assert "x 1 hedef" in details[0]


def test_estimate_counts_remote_proxy(tmp_path):
    eg = _egress()
    wl = tmp_path / "common.txt"
    wl.write_text("a\n" * 120)
    total, _ = eg.estimate_fuzz_requests(
        f"ffuf -u https://example.com/FUZZ -w {wl} -x http://10.9.9.9:8080",
        ["https://example.com/FUZZ", "http://10.9.9.9:8080"])
    assert total == 240


def test_estimate_zero_without_target(tmp_path):
    eg = _egress()
    wl = tmp_path / "common.txt"
    wl.write_text("a\n" * 120)
    total, _ = eg.estimate_fuzz_requests(f"wc -l {wl}", [])
    assert total == 0


def test_estimate_skips_missing_file():
    eg = _egress()
    total, _ = eg.estimate_fuzz_requests(
        "ffuf -u https://example.com/FUZZ -w /nonexistent/raft-large-files.txt",
        ["https://example.com/FUZZ"])
    assert total == 0


def test_modes_resolution(monkeypatch):
    eg = _egress()
    assert eg.background_jobs_mode({}) == "approval"
    assert eg.background_jobs_mode({"background_network_jobs": "deny"}) == "deny"
    assert eg.fuzz_budget({}) == 5000
    assert eg.fuzz_budget({"fuzz_max_requests_per_call": 50}) == 50
    monkeypatch.setenv("CCO_FUZZ_BUDGET", "7")
    assert eg.fuzz_budget({"fuzz_max_requests_per_call": 50}) == 7
    monkeypatch.setenv("CCO_BACKGROUND_NET_JOBS", "allow")
    assert eg.background_jobs_mode({"background_network_jobs": "deny"}) == "allow"


# --- policy entegrasyonu ---

def test_background_job_requires_grant_then_passes(tmp_path):
    engine = _engine(tmp_path)
    cmd = {"command": "curl -s https://example.com/app &"}
    blocked = engine.validate_tool_invocation("bash", cmd)
    assert blocked["allowed"] is False
    assert blocked["reason"] == "blocked_approval_required"
    assert blocked["background_job"] is True
    assert "grant" in blocked["guidance"].lower()
    engine.grant_approval("bash", "example.com", ttl_seconds=600, reason="test")
    allowed = engine.validate_tool_invocation("bash", cmd)
    assert allowed["allowed"] is True
    assert allowed["background_job"] is True


def test_background_job_deny_mode(tmp_path):
    engine = _engine(tmp_path, {"background_network_jobs": "deny"})
    engine.grant_approval("bash", "example.com", ttl_seconds=600, reason="test")
    result = engine.validate_tool_invocation(
        "bash", {"command": "curl -s https://example.com/app &"})
    assert result["allowed"] is False
    assert result["reason"] == "blocked_background_job"


def test_fuzz_budget_blocks_with_guidance(tmp_path):
    engine = _engine(tmp_path)
    engine.grant_approval("bash", "example.com", ttl_seconds=600, reason="test")
    wl = tmp_path / "raft-small-files.txt"
    wl.write_text("a\n" * 5100)
    result = engine.validate_tool_invocation(
        "bash", {"command": f"ffuf -u https://example.com/FUZZ -w {wl}"})
    assert result["allowed"] is False
    assert result["reason"] == "blocked_fuzz_budget"
    assert result["fuzz_estimate"] == 5100
    assert "control file" in result["guidance"]


def test_small_wordlist_passes(tmp_path):
    engine = _engine(tmp_path)
    engine.grant_approval("bash", "example.com", ttl_seconds=600, reason="test")
    wl = tmp_path / "common.txt"
    wl.write_text("a\n" * 100)
    result = engine.validate_tool_invocation(
        "bash", {"command": f"ffuf -u https://example.com/FUZZ -w {wl}"})
    assert result["allowed"] is True


def test_wordlist_path_not_treated_as_host(tmp_path):
    engine = _engine(tmp_path)
    inv = engine.extract_invocation_data(
        "bash", {"command": "ffuf -u https://example.com/FUZZ -w /tmp/x/big.txt"})
    assert "big.txt" not in inv["standalone_targets"]
    assert inv["url_targets"] == ["example.com"]


def test_malformed_policy_keys_rejected(tmp_path):
    module = _load("policy_engine", "scripts/policy_engine.py")
    codex = tmp_path / ".codex"
    codex.mkdir(exist_ok=True)
    (codex / "scope.json").write_text(json.dumps({
        "in_scope": [{"asset": "example.com", "type": "web"}],
    }))
    (codex / "program-policy.json").write_text(json.dumps({
        "rate_limits": {"default": {"window_seconds": 60, "max_calls": 60},
                        "overrides": {}},
        "background_network_jobs": "sometimes",
    }))
    try:
        module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
        raised = False
    except ValueError:
        raised = True
    assert raised is True


# --- watchdog ---

SS_FIXTURE = """State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB 0      0      10.0.0.5:51234   93.184.216.34:443  users:(("python3",pid=4242,fd=5))
ESTAB 0      0      10.0.0.5:51235   93.184.216.34:443  users:(("python3",pid=4242,fd=6))
ESTAB 0      0      10.0.0.5:22      10.0.0.9:60001
ESTAB 0      0      [::1]:8080       [::1]:41234       users:(("curl",pid=9999,fd=3))
"""


def test_parse_ss():
    wd = _watchdog()
    conns = wd.parse_ss(SS_FIXTURE)
    assert len(conns) == 4
    assert conns[0] == {"state": "ESTAB", "peer_host": "93.184.216.34",
                        "peer_port": "443", "proc": "python3", "pid": 4242}
    assert conns[2]["pid"] == 0
    assert conns[3]["peer_host"] == "::1"


def test_assess_verdicts(tmp_path):
    wd = _watchdog()
    engine = _engine(tmp_path)
    grants = []
    proc = {"pid": 4242, "proc": "python3", "conns": 30,
            "peers": ["93.184.216.34:443"], "cmdline": "python3 fuzz.py", "age": 600.0}
    assert wd.assess(proc, engine, grants)["verdict"] == "out_of_scope"
    proc2 = dict(proc, peers=["example.com:443"])
    assert wd.assess(proc2, engine, grants)["verdict"] == "unleased"
    engine.grant_approval("bash", "example.com", ttl_seconds=600, reason="test")
    grants = wd._live_grants(engine)
    assert wd.assess(proc2, engine, grants)["verdict"] == "ok"


def test_killable_protections():
    wd = _watchdog()
    ancestry = wd._own_ancestry()
    assert os.getpid() in ancestry
    proc = {"pid": os.getpid(), "proc": "python3", "conns": 99,
            "peers": [], "cmdline": "python3 -m pytest", "age": 9999.0}
    ok, why = wd.killable(proc, {"verdict": "out_of_scope"}, ancestry, 5, 120.0)
    assert ok is False and "ancestry" in why
    sys_proc = {"pid": 4242, "proc": "node", "conns": 99, "peers": [],
                "cmdline": "node /opt/opencode/bin/opencode", "age": 9999.0}
    ok, _ = wd.killable(sys_proc, {"verdict": "out_of_scope"}, set(), 5, 120.0)
    assert ok is False
    young = {"pid": 4243, "proc": "curl", "conns": 99, "peers": [],
             "cmdline": "curl -s https://evil.com", "age": 2.0}
    ok, _ = wd.killable(young, {"verdict": "out_of_scope"}, set(), 5, 120.0)
    assert ok is False
    fuzzer = {"pid": 4244, "proc": "python3", "conns": 60, "peers": [],
              "cmdline": "python3 -u fuzz3.py", "age": 900.0}
    ok, why = wd.killable(fuzzer, {"verdict": "out_of_scope"}, set(), 5, 120.0)
    assert ok is True


def test_terminate_process_kills_spawned_sleep():
    wd = _watchdog()
    proc = subprocess.Popen(["sleep", "120"])
    try:
        assert wd.terminate_process(proc.pid) is True
        time.sleep(0.3)
        assert proc.poll() is not None
    finally:
        try:
            proc.kill()
        except OSError:
            pass
