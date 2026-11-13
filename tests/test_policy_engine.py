import importlib.util
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_policy_engine():
    path = REPO_ROOT / "scripts" / "policy_engine.py"
    spec = importlib.util.spec_from_file_location("policy_engine_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_scope(tmp_path, data):
    codex = tmp_path / ".codex"
    codex.mkdir()
    scope = codex / "scope.json"
    scope.write_text(json.dumps(data))
    return scope


def _write_policy(tmp_path, data):
    codex = tmp_path / ".codex"
    codex.mkdir(exist_ok=True)
    policy = codex / "program-policy.json"
    policy.write_text(json.dumps(data))
    return policy


def test_explicit_scope_allows_exact_host_only(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))

    blocked = engine.validate_tool_invocation("kali-tools_curl_request", {"url": "https://example.com/account"})
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    allowed = engine.validate_tool_invocation("kali-tools_curl_request", {"url": "https://example.com/account"})
    denied = engine.validate_tool_invocation("kali-tools_curl_request", {"url": "https://api.example.com/account"})
    assert blocked["allowed"] is False
    assert blocked["reason"] == "blocked_approval_required"
    assert allowed["allowed"] is True
    assert denied["allowed"] is False
    assert denied["reason"] == "blocked_scope"


def test_scope_url_prefix_does_not_allow_host_prefix_confusion(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "https://example.com", "type": "web"}],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    result = engine.validate_tool_invocation("kali-tools_curl_request", {"url": "https://example.com.evil.com/pwn"})
    assert result["allowed"] is False
    assert result["reason"] == "blocked_scope"


def test_scope_url_prefix_is_path_scoped(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "https://example.com/app", "type": "web"}],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")

    allowed = engine.validate_tool_invocation("kali-tools_curl_request", {"url": "https://example.com/app/dashboard"})
    denied_sibling = engine.validate_tool_invocation("kali-tools_curl_request", {"url": "https://example.com/admin"})
    denied_prefix_confusion = engine.validate_tool_invocation("kali-tools_curl_request", {"url": "https://example.com/application"})

    assert allowed["allowed"] is True
    assert denied_sibling["allowed"] is False
    assert denied_sibling["reason"] == "blocked_scope"
    assert denied_prefix_confusion["allowed"] is False
    assert denied_prefix_confusion["reason"] == "blocked_scope"


def test_scope_cidr_entries_are_honored(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "10.0.0.0/24", "type": "cidr"}],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    blocked = engine.validate_tool_invocation("kali-tools_nmap_scan", {"target": "10.0.0.5"})
    engine.grant_approval("kali-tools_*", "10.0.0.5", ttl_seconds=600, reason="test")
    allowed = engine.validate_tool_invocation("kali-tools_nmap_scan", {"target": "10.0.0.5"})
    denied = engine.validate_tool_invocation("kali-tools_nmap_scan", {"target": "10.0.1.5"})
    assert blocked["allowed"] is False
    assert blocked["reason"] == "blocked_approval_required"
    assert allowed["allowed"] is True
    assert denied["allowed"] is False


def test_loopback_allowed_without_scope(tmp_path):
    module = _load_policy_engine()
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    result = engine.validate_tool_invocation("browser_browser_security_headers", {"url": "http://127.0.0.1:8899/healthz"})
    assert result["allowed"] is True


def test_active_approval_required_for_live_target(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "example.com", "type": "web"}],
        "rules": {"active_requires": "ACTIVE_OK from user"},
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    blocked = engine.validate_tool_invocation("kali-tools_curl_request", {"url": "https://example.com"})
    assert blocked["allowed"] is False
    assert blocked["reason"] == "blocked_approval_required"

    grant = engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="ACTIVE_OK")
    allowed = engine.validate_tool_invocation("kali-tools_curl_request", {"url": "https://example.com"})
    assert grant.tool_pattern == "kali-tools_*"
    assert allowed["allowed"] is True


def test_approval_requires_all_invocation_targets(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "scope_policy": "explicit_only",
        "in_scope": [
            {"asset": "example.com", "type": "web"},
            {"asset": "api.example.com", "type": "web"},
        ],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    args = {"target": "example.com,api.example.com"}

    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    blocked = engine.validate_tool_invocation("kali-tools_parallel_recon", args)
    engine.grant_approval("kali-tools_*", "api.example.com", ttl_seconds=600, reason="test")
    allowed = engine.validate_tool_invocation("kali-tools_parallel_recon", args)

    assert blocked["allowed"] is False
    assert blocked["reason"] == "blocked_approval_required"
    assert allowed["allowed"] is True


def test_program_policy_blocks_http_method(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "https://example.com", "type": "web"}],
    })
    _write_policy(tmp_path, {
        "blocked_http_methods": ["DELETE"],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    result = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/resource",
        "method": "DELETE",
    })
    assert result["allowed"] is False
    assert result["reason"] == "blocked_http_method"


def test_program_policy_blocks_path(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "https://example.com", "type": "web"}],
    })
    _write_policy(tmp_path, {
        "blocked_paths": ["/admin/delete"],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    result = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/admin/delete?id=1",
        "method": "GET",
    })
    assert result["allowed"] is False
    assert result["reason"] == "blocked_path"


def test_bash_target_extraction_and_destructive_block(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    data = engine.extract_invocation_data("bash", {"command": "curl -X GET https://example.com/health"})
    assert data["targets"] == ["example.com"]
    blocked = engine.validate_tool_invocation("bash", {"command": "curl -X GET https://example.com/health"})
    assert blocked["allowed"] is False
    assert blocked["reason"] == "blocked_approval_required"
    destructive = engine.validate_tool_invocation("bash", {"command": "rm -rf /tmp/foo"})
    assert destructive["allowed"] is False
    assert destructive["reason"] == "blocked_destructive_bash"


def test_bash_u_flag_url_is_target_but_credentials_masked(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    # ffuf `-u <URL>`: hedef cikarilmali (eski bug: maskelenip missing_target);
    # `-w` dosya yolu hedef olmamali, `-x` proxy hedef olmali
    cmd = ("ffuf -u http://example.com/FUZZ -w /usr/share/seclists/words.txt "
           "-x http://127.0.0.1:8080 -rate 10")
    data = engine.extract_invocation_data("bash", {"command": cmd})
    assert data["targets"] == ["127.0.0.1", "example.com"]
    needs_grant = engine.validate_tool_invocation("bash", {"command": cmd})
    assert needs_grant["allowed"] is False
    assert needs_grant["reason"] == "blocked_approval_required"
    engine.grant_approval("bash", "example.com", ttl_seconds=600, reason="test")
    engine.grant_approval("bash", "127.0.0.1", ttl_seconds=600, reason="test")
    allowed = engine.validate_tool_invocation("bash", {"command": cmd})
    assert allowed["allowed"] is True
    # curl `-u user:pass`: kimlik hedef olmamali, konumsal URL korunmali
    data = engine.extract_invocation_data(
        "bash", {"command": "curl -u admin:s3cret https://example.com/"})
    assert data["targets"] == ["example.com"]


def test_local_safe_tool_skips_scope(tmp_path):
    module = _load_policy_engine()
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    result = engine.validate_tool_invocation("read", {"filePath": "/root/hackagent-opencode/README.md"})
    assert result["allowed"] is True


def test_network_tool_without_declared_target_fails_closed(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")

    result = engine.validate_tool_invocation("kali-tools_curl_request", {
        "method": "POST",
        "data": json.dumps({"url": "https://example.com/should-not-count"}),
    })

    assert result["allowed"] is False
    assert result["reason"] == "blocked_missing_target"
    assert result["targets"] == []


def test_non_network_tool_without_target_is_allowed(tmp_path):
    module = _load_policy_engine()
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    result = engine.validate_tool_invocation("kali-tools_cvss_calculate", {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "H",
        "a": "H",
    })
    assert result["allowed"] is True


def test_validator_params_json_target_fields_are_extracted(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("validator_*", "example.com", ttl_seconds=600, reason="test")

    result = engine.validate_tool_invocation("validator_validate_finding", {
        "vuln_type": "idor",
        "params_json": json.dumps({"object_url": "https://example.com/api/orders/1001"}),
    })

    assert result["allowed"] is True
    assert result["targets"] == ["example.com"]


def test_targetless_approval_capability_requires_tool_wide_grant(tmp_path):
    module = _load_policy_engine()
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    args = {"target": "example.com", "service": "api", "username": "alice", "password": "secret"}

    blocked = engine.validate_tool_invocation("memory-server_store_credential", args)
    engine.grant_approval("memory-server_store_credential", "example.com", ttl_seconds=600, reason="test")
    target_only = engine.validate_tool_invocation("memory-server_store_credential", args)
    engine.grant_approval("memory-server_store_credential", "*", ttl_seconds=600, reason="test")
    allowed = engine.validate_tool_invocation("memory-server_store_credential", args)

    assert blocked["reason"] == "blocked_approval_required"
    assert blocked["requires_approval"] is True
    assert target_only["reason"] == "blocked_approval_required"
    assert allowed["allowed"] is True


@pytest.mark.parametrize("target", ["github.com", "scanme.nmap.org"])
def test_public_exemptions_do_not_bypass_active_scope_or_approval(tmp_path, target):
    module = _load_policy_engine()
    unscoped = module.PolicyEngine(cco_home=str(tmp_path / ".cco-unscoped"), repo_root=str(tmp_path))

    active_unscoped = unscoped.validate_tool_invocation(
        "kali-tools_curl_request", {"url": f"https://{target}/"}
    )
    passive = unscoped.validate_tool_invocation("osint-tools_lookup", {"domain": target})

    scope_file = _write_scope(tmp_path, {"in_scope": [{"asset": target, "type": "web"}]})
    scoped = module.PolicyEngine(
        cco_home=str(tmp_path / ".cco-scoped"), repo_root=str(tmp_path), scope_file=str(scope_file)
    )
    active_unapproved = scoped.validate_tool_invocation(
        "kali-tools_curl_request", {"url": f"https://{target}/"}
    )
    scoped.grant_approval("kali-tools_*", target, ttl_seconds=600, reason="test")
    active_approved = scoped.validate_tool_invocation(
        "kali-tools_curl_request", {"url": f"https://{target}/"}
    )

    assert active_unscoped["reason"] == "blocked_scope"
    assert passive["allowed"] is True
    assert active_unapproved["reason"] == "blocked_approval_required"
    assert active_approved["allowed"] is True


def test_cidr_requests_preserve_and_validate_the_full_network(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "10.0.0.0/24", "type": "cidr"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))

    engine.grant_approval("kali-tools_nmap_scan", "10.0.0.5", ttl_seconds=600, reason="host only")
    host_only = engine.validate_tool_invocation("kali-tools_nmap_scan", {"target": "10.0.0.5/24"})
    engine.grant_approval("kali-tools_nmap_scan", "10.0.0.0/24", ttl_seconds=600, reason="network")
    network_approved = engine.validate_tool_invocation("kali-tools_nmap_scan", {"target": "10.0.0.5/24"})
    too_broad = engine.validate_tool_invocation("kali-tools_nmap_scan", {"target": "10.0.0.5/16"})

    assert host_only["targets"] == ["10.0.0.5/24"]
    assert host_only["reason"] == "blocked_approval_required"
    assert network_approved["allowed"] is True
    assert too_broad["targets"] == ["10.0.0.5/16"]
    assert too_broad["reason"] == "blocked_scope"


def test_ip_ranges_require_every_address_to_be_in_scope_and_approved(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "10.0.0.0/24", "type": "cidr"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_nmap_scan", "10.0.0.0/24", ttl_seconds=600, reason="network")

    inside = engine.validate_tool_invocation("kali-tools_nmap_scan", {"target": "10.0.0.5-10"})
    crossing_boundary = engine.validate_tool_invocation(
        "kali-tools_nmap_scan", {"target": "10.0.0.250-10.0.1.5"}
    )

    assert inside["targets"] == ["10.0.0.5-10.0.0.10"]
    assert inside["allowed"] is True
    assert crossing_boundary["reason"] == "blocked_scope"


def test_nonempty_opaque_command_arguments_fail_closed_but_empty_is_safe(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")

    safe_empty = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://example.com", "extra_args": "  "}
    )
    opaque = engine.validate_tool_invocation(
        "kali-tools_curl_request",
        {"url": "https://example.com", "extra_args": "-X DELETE https://outside.example"},
    )

    assert safe_empty["allowed"] is True
    assert opaque["allowed"] is False
    assert opaque["reason"] == "blocked_unsafe_arguments: extra_args '-X'"
    assert opaque["unsafe_arguments"] == ["extra_args"]


def _curl_engine(tmp_path, monkeypatch, tag="main"):
    module = _load_policy_engine()
    if not (tmp_path / ".codex" / "scope.json").exists():
        _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path / "work"))
    engine = module.PolicyEngine(cco_home=str(tmp_path / f".cco-{tag}"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    return engine


def test_metered_preflight_keeps_scope_and_grants_without_debiting_wire_counters(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_STUCK_THRESHOLD", "2")
    engine = _curl_engine(tmp_path, monkeypatch)
    tool, args = "kali-tools_curl_request", {"url": "https://example.com/one", "method": "GET"}
    for _ in range(5):
        assert engine.validate_tool_invocation(tool, args, _policy_preflight=True)["allowed"]
    with engine._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM rate_limit_reservations").fetchone()[0] == 0
    assert not engine.validate_tool_invocation(tool, {"url": "https://outside.invalid/"}, _policy_preflight=True)["allowed"]
    # The caller cannot turn a real request into a preview through tool args.
    for _ in range(2):
        assert engine.validate_wire_invocation(tool, {**args, "_policy_preflight": True})["allowed"]
    rejected = engine.validate_wire_invocation(tool, args)
    assert rejected["reason"].startswith("blocked_stuck_detected")
    with engine._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM stuck_probes").fetchone()[0] == 2
        assert conn.execute("SELECT SUM(weight) FROM rate_limit_reservations").fetchone()[0] == 2
    engine.revoke_approval(engine.list_approvals()[0]["id"])
    assert engine.validate_tool_invocation(tool, args, _policy_preflight=True)["reason"] == "blocked_approval_required"


def test_curl_safe_extra_args_inside_workdir_allowed(tmp_path, monkeypatch):
    engine = _curl_engine(tmp_path, monkeypatch)
    body = tmp_path / "work" / "ev" / "body.txt"
    hdr = tmp_path / "work" / "ev" / "hdr.txt"
    res = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a",
        "extra_args": f"-s -S -i -L --compressed -o {body} -D {hdr} -m 10 -w '%{{http_code}}'",
    })
    assert res["allowed"] is True, res
    tmp_res = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a", "extra_args": "-D /tmp/cco-test-hdr.txt"})
    assert tmp_res["allowed"] is True, tmp_res


def test_curl_output_path_outside_workdir_blocked(tmp_path, monkeypatch):
    engine = _curl_engine(tmp_path, monkeypatch)
    res = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a", "extra_args": "-o /etc/x"})
    assert res["allowed"] is False
    assert res["reason"] == "blocked_unsafe_arguments: extra_args '/etc/x'"


def test_curl_timeout_values_validated(tmp_path, monkeypatch):
    engine = _curl_engine(tmp_path, monkeypatch)
    ok = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a",
        "extra_args": "-m 10 --max-time 5.5 --connect-timeout 3"})
    assert ok["allowed"] is True, ok
    for index, bad_value in enumerate(("-m abc", "-m 0", "-m 999", "--max-time -5")):
        fresh = _curl_engine(tmp_path, monkeypatch, tag=f"timeout-{index}")
        bad = fresh.validate_tool_invocation("kali-tools_curl_request", {
            "url": "https://example.com/a", "extra_args": bad_value})
        assert bad["allowed"] is False, bad_value
        assert bad["reason"].startswith("blocked_unsafe_arguments: extra_args"), bad


def test_curl_writeout_format_validated(tmp_path, monkeypatch):
    engine = _curl_engine(tmp_path, monkeypatch)
    ok = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a",
        "extra_args": "-w '%{http_code} %{size_download}'"})
    assert ok["allowed"] is True, ok
    for index, bad_format in enumerate(("-w '%{nope_not_a_field}'", "-w 'a;rm -rf /'", '-w "%{http_code"')):
        fresh = _curl_engine(tmp_path, monkeypatch, tag=f"writeout-{index}")
        bad = fresh.validate_tool_invocation("kali-tools_curl_request", {
            "url": "https://example.com/a", "extra_args": bad_format})
        assert bad["allowed"] is False, bad_format
        assert bad["reason"].startswith("blocked_unsafe_arguments: extra_args"), bad
    unparseable = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a", "extra_args": "-w '%{http_code"})
    assert unparseable["allowed"] is False
    assert unparseable["reason"] == "blocked_unsafe_arguments"


def test_curl_disallowed_flags_stay_blocked(tmp_path, monkeypatch):
    engine = _curl_engine(tmp_path, monkeypatch)
    res = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a",
        "extra_args": '-A "x" --data-binary @/etc/passwd'})
    assert res["allowed"] is False
    assert res["reason"] == "blocked_unsafe_arguments: extra_args '-A'"
    shellish = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a", "extra_args": "shell=true"})
    assert shellish["allowed"] is False
    assert shellish["reason"] == "blocked_unsafe_arguments: extra_args 'shell=true'"
    assert "curl extra_args allowlist" in res["guidance"]


def test_curl_shell_metachars_blocked(tmp_path, monkeypatch):
    payloads = [
        "-o /tmp/x;id", "-o /tmp/x|id", "-o /tmp/x&&id", "-o /tmp/x$(id)",
        "-o /tmp/x`id`", "-o /tmp/x>/tmp/pwn", "-w %{http_code}|id",
    ]
    for index, extra in enumerate(payloads):
        fresh = _curl_engine(tmp_path, monkeypatch, tag=f"meta-{index}")
        res = fresh.validate_tool_invocation("kali-tools_curl_request", {
            "url": "https://example.com/a", "extra_args": extra})
        assert res["allowed"] is False, extra
        assert res["reason"].startswith("blocked_unsafe_arguments"), res


def test_curl_combined_and_relative_forms(tmp_path, monkeypatch):
    engine = _curl_engine(tmp_path, monkeypatch)
    body = tmp_path / "work" / "ev" / "body.txt"
    combined = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a",
        "extra_args": f"-sS -m10 --max-time=5 -o{body} --output=/tmp/cco-h.txt -w=%{{http_code}}"})
    assert combined["allowed"] is True, combined
    monkeypatch.setenv("CCO_WORKDIR", "/root/cco-test-work")
    relative = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a", "extra_args": "-o ev/body.txt"})
    assert relative["allowed"] is True, relative
    escaping = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a", "extra_args": "-o ../escape.txt"})
    assert escaping["allowed"] is False
    stdout = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a", "extra_args": "-o - -w '%{http_code}%%'"})
    assert stdout["allowed"] is True, stdout
    meta_inline = engine.validate_tool_invocation("kali-tools_curl_request", {
        "url": "https://example.com/a", "extra_args": "-o/tmp/x;id"})
    assert meta_inline["allowed"] is False


def test_repeat_brake_keeps_offending_token(tmp_path, monkeypatch):
    engine = _curl_engine(tmp_path, monkeypatch, tag="brake")
    last = None
    for flag in ("-A", "-K", "-x"):
        last = engine.validate_tool_invocation("kali-tools_curl_request", {
            "url": "https://example.com/a", "extra_args": f"{flag} probe"})
    assert last is not None and last["allowed"] is False
    assert last["reason"].startswith(
        "blocked_repeat_brake: blocked_unsafe_arguments: extra_args '-x'"), last


def test_malformed_explicit_scope_file_fails_at_startup(tmp_path):
    module = _load_policy_engine()
    scope_file = tmp_path / "scope.json"
    scope_file.write_text("{not-json")

    with pytest.raises(ValueError, match=r"malformed scope file .*line 1"):
        module.PolicyEngine(
            cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path), scope_file=str(scope_file)
        )


def test_malformed_explicit_program_policy_fails_at_startup(tmp_path):
    module = _load_policy_engine()
    policy_file = tmp_path / "program-policy.json"
    policy_file.write_text("[")

    with pytest.raises(ValueError, match=r"malformed program policy file .*line 1"):
        module.PolicyEngine(
            cco_home=str(tmp_path / ".cco"),
            repo_root=str(tmp_path),
            program_policy_file=str(policy_file),
        )


def test_malformed_tool_capability_file_fails_at_startup(tmp_path):
    module = _load_policy_engine()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "tool-capabilities.json").write_text("{")

    with pytest.raises(ValueError, match=r"malformed tool capability policy file .*line 1"):
        module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))


def test_unreadable_explicit_policy_files_fail_at_startup(tmp_path):
    module = _load_policy_engine()
    scope_dir = tmp_path / "scope-dir"
    policy_dir = tmp_path / "policy-dir"
    scope_dir.mkdir()
    policy_dir.mkdir()

    with pytest.raises(RuntimeError, match=r"unable to read scope file"):
        module.PolicyEngine(
            cco_home=str(tmp_path / ".cco-scope"), repo_root=str(tmp_path), scope_file=str(scope_dir)
        )
    with pytest.raises(RuntimeError, match=r"unable to read program policy file"):
        module.PolicyEngine(
            cco_home=str(tmp_path / ".cco-policy"),
            repo_root=str(tmp_path),
            program_policy_file=str(policy_dir),
        )

    capability_root = tmp_path / "capability-root"
    capability_file = capability_root / "config" / "tool-capabilities.json"
    capability_file.mkdir(parents=True)
    with pytest.raises(RuntimeError, match=r"unable to read tool capability policy file"):
        module.PolicyEngine(cco_home=str(tmp_path / ".cco-capability"), repo_root=str(capability_root))


def test_weighted_rate_limit_reservation_is_atomic_under_concurrency(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_STUCK_ENABLED", "0")
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    _write_policy(tmp_path, {
        "rate_limits": {
            "default": {"window_seconds": 60, "max_calls": 16},
            "overrides": {},
        }
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("validator_*", "example.com", ttl_seconds=600, reason="test")

    def invoke(_):
        return engine.validate_tool_invocation(
            "validator_validate_sqli", {"target_url": "https://example.com/items?id=1"}
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(invoke, range(12)))

    assert sum(result["allowed"] for result in results) == 2
    assert all(result["allowed"] or result["reason"] == "blocked_rate_limit" for result in results)


def test_audit_redacts_url_credentials_and_credential_query_values(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    secret_url = (
        "https://alice:hunter2@example.com/account?view=full&access_token=token-secret&api_key=key-secret"
    )

    result = engine.validate_tool_invocation(
        "kali-tools_curl_request",
        {"url": secret_url},
        extra_metadata={"request_url": secret_url, "authorization": "Bearer metadata-secret"},
    )
    row = engine.audit(limit=1)[0]
    persisted = " ".join([row["target"], row["targets_json"], row["metadata"]])
    metadata = json.loads(row["metadata"])

    assert result["allowed"] is True
    assert "alice" not in persisted
    assert "hunter2" not in persisted
    assert "token-secret" not in persisted
    assert "key-secret" not in persisted
    assert "metadata-secret" not in persisted
    assert "REDACTED" in persisted
    assert "view=full" in metadata["request_url"]


def test_repo_scope_json_is_loadable(tmp_path):
    module = _load_policy_engine()
    scope_file = REPO_ROOT / ".codex" / "scope.json"
    engine = module.PolicyEngine(
        cco_home=str(tmp_path / ".cco"),
        repo_root=str(REPO_ROOT),
        scope_file=str(scope_file),
    )
    assert isinstance(engine.scope["raw"].get("rules"), dict)
    assert engine.scope["targets"] or engine.scope["domains"] or engine.scope["url_prefixes"]


def test_js_route_queue_blocks_nmap_until_template_probed(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_STUCK_ENABLED", "0")
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    source = (
        'const list = () => fetch("/api/v2/users");\n'
        "getProfile: function(userId) { return fetch(this.api.v2.users + '/' + userId + '/profile'); }\n"
    )
    composed = engine.validate_tool_invocation(
        "kali-tools_compose_js_routes",
        {"source": source, "target": "http://example.com"},
    )
    assert composed["allowed"] is True
    nmap = engine.validate_tool_invocation(
        "kali-tools_nmap_scan_structured", {"target": "example.com"}
    )
    assert nmap["allowed"] is False
    assert nmap["reason"].startswith("blocked_js_route_queue")
    assert "users/1/profile" in nmap["guidance"]
    probed = engine.validate_tool_invocation(
        "kali-tools_curl_request",
        {"url": "http://example.com/api/v2/users/1/profile"},
    )
    assert probed["allowed"] is True
    nmap_after = engine.validate_tool_invocation(
        "kali-tools_nmap_scan_structured", {"target": "example.com"}
    )
    assert nmap_after["allowed"] is True


def _write_strict(tmp_path, monkeypatch, handle="tester"):
    monkeypatch.setenv("HACKERONE_HANDLE", handle)
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "https://prog.example/v1", "type": "api"}],
    })
    _write_policy(tmp_path, {
        "required_request_headers": {
            "User-Agent": "HackerOne/{handle}",
            "X-HackerOne": "{handle}",
        },
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("*", "prog.example", ttl_seconds=600, reason="test")
    return engine


def test_missing_headers_blocks_bash_curl(tmp_path, monkeypatch):
    engine = _write_strict(tmp_path, monkeypatch)
    res = engine.validate_tool_invocation("bash", {"command": "curl -s https://prog.example/v1/wpb"})
    assert res["allowed"] is False
    assert res["reason"] == "blocked_missing_headers"
    assert "User-Agent" in res["guidance"]


def test_present_headers_allow_bash_curl(tmp_path, monkeypatch):
    engine = _write_strict(tmp_path, monkeypatch)
    res = engine.validate_tool_invocation("bash", {"command": (
        "curl -s -H 'User-Agent: HackerOne/tester' -H 'X-HackerOne: tester' https://prog.example/v1/wpb"
    )})
    assert res["allowed"] is True


def test_missing_handle_blocks_with_guidance(tmp_path, monkeypatch):
    engine = _write_strict(tmp_path, monkeypatch, handle="")
    res = engine.validate_tool_invocation("bash", {"command": (
        "curl -s -H 'User-Agent: HackerOne/tester' -H 'X-HackerOne: tester' https://prog.example/v1/wpb"
    )})
    assert res["allowed"] is False
    assert res["reason"] == "blocked_missing_headers"


def test_osint_urls_exempt_from_headers(tmp_path, monkeypatch):
    engine = _write_strict(tmp_path, monkeypatch)
    assert engine._missing_required_headers(
        "bash", {"command": "curl -s 'https://crt.sh/?q=%25prog.example'"},
        ["https://crt.sh/?q=%25prog.example"]) == []
    assert engine._missing_required_headers(
        "bash", {"command": "curl -s http://127.0.0.1:8899/poc"},
        ["http://127.0.0.1:8899/poc"]) == []


def test_curl_request_tool_headers_checked(tmp_path, monkeypatch):
    engine = _write_strict(tmp_path, monkeypatch)
    bare = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://prog.example/v1/wpb"})
    assert bare["allowed"] is False
    assert bare["reason"] == "blocked_missing_headers"
    with_headers = engine.validate_tool_invocation(
        "kali-tools_curl_request",
        {"url": "https://prog.example/v1/wpb",
         "headers": "User-Agent: HackerOne/tester\nX-HackerOne: tester"})
    assert with_headers["allowed"] is True


def test_excluded_assets_deny_subdomain(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_STUCK_ENABLED", "0")
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "*.prog.example", "type": "domain"}],
        "excluded_assets": ["help.prog.example", "explorer.prog.example"],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("*", "*.prog.example", ttl_seconds=600, reason="test")
    ok = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://app.prog.example/login"})
    assert ok["allowed"] is True
    blocked = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://help.prog.example/login"})
    assert blocked["allowed"] is False
    assert blocked["reason"] == "blocked_scope"
    blocked2 = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://explorer.prog.example/"})
    assert blocked2["allowed"] is False
    assert blocked2["reason"] == "blocked_scope"


def test_excluded_assets_covers_nested_subdomain(tmp_path, monkeypatch):
    monkeypatch.setenv("CCO_STUCK_ENABLED", "0")
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "*.prog.example", "type": "domain"}],
        "excluded_assets": ["help.prog.example"],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    assert engine._is_excluded_host("deep.help.prog.example") is True
    assert engine._is_excluded_host("help.prog.example.evil.com") is False
    assert engine._is_excluded_host("app.prog.example") is False


def test_malformed_required_headers_rejected(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "prog.example", "type": "api"}]})
    _write_policy(tmp_path, {"required_request_headers": ["not-a-dict"]})
    with pytest.raises(ValueError, match="required_request_headers"):
        module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))


def test_shipped_profiles_load(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "prog.example", "type": "api"}]})
    for profile in ("strict-bounty", "strict-bounty-coupang", "strict-bounty-anduril", "strict-bounty-rapyd", "lab", "ctf"):
        engine = module.PolicyEngine(
            cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path),
            program_policy_file=str(REPO_ROOT / "config" / "program-profiles" / f"{profile}.json"),
        )
        assert engine.program_policy["profile"] == profile
    strict = module.PolicyEngine(
        cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path),
        program_policy_file=str(REPO_ROOT / "config" / "program-profiles" / "strict-bounty.json"),
    )
    assert strict.program_policy["fuzz_max_requests_per_call"] == 50
    assert "kali-tools_nuclei_scan" in strict.program_policy["denied_tools"]


def test_coupang_scope_and_profile_integration(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKERONE_HANDLE", "tester")
    monkeypatch.setenv("CCO_STUCK_ENABLED", "0")
    module = _load_policy_engine()
    engine = module.PolicyEngine(
        cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path),
        scope_file=str(REPO_ROOT / ".codex" / "scope.coupang.json"),
        program_policy_file=str(REPO_ROOT / "config" / "program-profiles" / "strict-bounty-coupang.json"),
    )
    assert len(engine.scope["targets"]) == 45
    engine.grant_approval("*", "*.coupang.com", ttl_seconds=600, reason="test")
    bare = engine.validate_tool_invocation(
        "bash", {"command": "curl -s https://shop.tw.coupang.com/"})
    assert bare["allowed"] is False
    assert bare["reason"] == "blocked_missing_headers"
    headed = engine.validate_tool_invocation(
        "bash", {"command": "curl -s -H 'X-HackerOne-Researcher: tester' https://shop.tw.coupang.com/"})
    assert headed["allowed"] is True
    unlisted = engine.validate_tool_invocation(
        "bash", {"command": "curl -s -H 'X-HackerOne-Researcher: tester' https://evil.tw.coupang.com/"})
    assert unlisted["allowed"] is False
    assert unlisted["reason"] == "blocked_scope"


def test_anduril_scope_and_profile_integration(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKERONE_HANDLE", "tester")
    monkeypatch.setenv("CCO_STUCK_ENABLED", "0")
    module = _load_policy_engine()
    engine = module.PolicyEngine(
        cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path),
        scope_file=str(REPO_ROOT / ".codex" / "scope.anduril.json"),
        program_policy_file=str(REPO_ROOT / "config" / "program-profiles" / "strict-bounty-anduril.json"),
    )
    assert "anduril.com" in engine.scope["domains"]
    assert "andurilgear.com" in engine.scope["excluded"]
    engine.grant_approval("*", "*anduril*", ttl_seconds=600, reason="test")
    bare = engine.validate_tool_invocation(
        "bash", {"command": "curl -s https://www.anduril.com/"})
    assert bare["allowed"] is False
    assert bare["reason"] == "blocked_missing_headers"
    headed = engine.validate_tool_invocation(
        "bash", {"command": "curl -s -H 'X-HackerOne-Research: tester' https://www.anduril.com/"})
    assert headed["allowed"] is True
    apex = engine.validate_tool_invocation(
        "bash", {"command": "curl -s -H 'X-HackerOne-Research: tester' https://anduril.com/"})
    assert apex["allowed"] is True
    gear = engine.validate_tool_invocation(
        "bash", {"command": "curl -s -H 'X-HackerOne-Research: tester' https://andurilgear.com/"})
    assert gear["allowed"] is False
    assert gear["reason"] == "blocked_scope"


def test_rapyd_scope_and_profile_integration(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKERONE_HANDLE", "tester")
    monkeypatch.setenv("CCO_STUCK_ENABLED", "0")
    module = _load_policy_engine()
    engine = module.PolicyEngine(
        cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path),
        scope_file=str(REPO_ROOT / ".codex" / "scope.rapyd.json"),
        program_policy_file=str(REPO_ROOT / "config" / "program-profiles" / "strict-bounty-rapyd.json"),
    )
    assert "rapyd.net" in engine.scope["domains"]
    assert "support.rapyd.net" in engine.scope["excluded"]
    engine.grant_approval("*", "*rapyd*", ttl_seconds=600, reason="test")
    bare = engine.validate_tool_invocation(
        "bash", {"command": "curl -s https://dashboard.rapyd.net/"})
    assert bare["allowed"] is False
    assert bare["reason"] == "blocked_missing_headers"
    headed = engine.validate_tool_invocation(
        "bash", {"command": "curl -s -H 'X-Bugcrowd: Bugcrowd-tester' https://dashboard.rapyd.net/"})
    assert headed["allowed"] is True
    ghost = engine.validate_tool_invocation(
        "bash", {"command": "curl -s -H 'X-Bugcrowd: Bugcrowd-tester' https://ghost.rapyd.net/"})
    assert ghost["allowed"] is False
    assert ghost["reason"] == "blocked_scope"



def _blind_engine(module, tmp_path, monkeypatch, blind=True):
    _write_scope(tmp_path, {
        "scope_policy": "explicit_only",
        "blind_mode": blind,
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    work = tmp_path / "work"
    work.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setenv("CCO_WORKDIR", str(work))
    # tmp_path zaten /tmp altinda; /tmp izniyle carpisma olmamasi icin
    # testlerde TMPDIR izole edilir (uretimde /tmp serbest, zararsiz).
    monkeypatch.setenv("TMPDIR", str(scratch))
    return module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))


def test_blind_mode_off_allows_repo_write(tmp_path, monkeypatch):
    module = _load_policy_engine()
    engine = _blind_engine(module, tmp_path, monkeypatch, blind=False)
    res = engine.validate_tool_invocation("edit", {"filePath": str(tmp_path / "a.py")})
    assert res["reason"] != "blocked_blind_write"


def test_blind_mode_denies_repo_write(tmp_path, monkeypatch):
    module = _load_policy_engine()
    engine = _blind_engine(module, tmp_path, monkeypatch, blind=True)
    res = engine.validate_tool_invocation("edit", {"filePath": str(tmp_path / "mcp-servers" / "x.py")})
    assert res["allowed"] is False
    assert res["reason"].startswith("blocked_blind_write")


def test_blind_mode_allows_workdir_write(tmp_path, monkeypatch):
    module = _load_policy_engine()
    engine = _blind_engine(module, tmp_path, monkeypatch, blind=True)
    res = engine.validate_tool_invocation(
        "write", {"filePath": str(tmp_path / "work" / "run" / "note.md"),
                  "content": "mr.example config v1.2 Roses are red."})
    assert res["reason"] != "blocked_blind_write"


def test_blind_mode_denies_scope_write(tmp_path, monkeypatch):
    module = _load_policy_engine()
    engine = _blind_engine(module, tmp_path, monkeypatch, blind=True)
    res = engine.validate_tool_invocation("edit", {"filePath": str(tmp_path / ".codex" / "scope.json")})
    assert res["allowed"] is False
    assert res["reason"].startswith("blocked_blind_write")


def test_blind_mode_denies_bash_redirect_into_repo(tmp_path, monkeypatch):
    module = _load_policy_engine()
    engine = _blind_engine(module, tmp_path, monkeypatch, blind=True)
    res = engine.validate_tool_invocation("bash", {"command": "echo hi > notes.txt"})
    assert res["allowed"] is False
    assert res["reason"].startswith("blocked_blind_write")
    scratch = tmp_path / "scratch" / "probe.txt"
    ok = engine.validate_tool_invocation("bash", {"command": f"echo hi > {scratch}"})
    assert ok["reason"] != "blocked_blind_write"


def test_blind_mode_allows_real_tmp_without_disk_touch(tmp_path, monkeypatch):
    module = _load_policy_engine()
    engine = _blind_engine(module, tmp_path, monkeypatch, blind=True)
    monkeypatch.setenv("TMPDIR", "/tmp")
    ok = engine.validate_tool_invocation("bash", {"command": "echo hi > /tmp/blind-probe-guard.txt"})
    assert ok["reason"] != "blocked_blind_write"


def test_blind_mode_malformed_flag_fails_closed(tmp_path, monkeypatch):
    import pytest
    module = _load_policy_engine()
    _write_scope(tmp_path, {"blind_mode": "yes"})
    with pytest.raises(ValueError):
        module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))


def test_scope_and_policy_files_always_read_only_even_when_blind_off(tmp_path, monkeypatch):
    module = _load_policy_engine()
    engine = _blind_engine(module, tmp_path, monkeypatch, blind=False)
    for target in (
        tmp_path / ".codex" / "scope.json",
        tmp_path / ".codex" / "program-policy.json",
        tmp_path / ".cco" / "audit.db",
    ):
        res = engine.validate_tool_invocation("write", {"filePath": str(target), "content": "{}"})
        assert res["allowed"] is False
        assert res["reason"].startswith("blocked_blind_write")
    bash_res = engine.validate_tool_invocation(
        "bash", {"command": "python3 -c \"open('.codex/scope.json', 'w').write('{}')\""}
    )
    assert bash_res["allowed"] is False
    assert bash_res["reason"].startswith("blocked_blind_write")


def test_blind_mode_blocks_patch_multiedit_sed_tee_cp_and_inline_python(tmp_path, monkeypatch):
    module = _load_policy_engine()
    engine = _blind_engine(module, tmp_path, monkeypatch, blind=True)

    patch_res = engine.validate_tool_invocation(
        "patch",
        {"patchText": "--- a/mcp-servers/mcp-validator/server.py\n+++ b/mcp-servers/mcp-validator/server.py\n@@ -1 +1 @@\n"},
    )
    assert patch_res["allowed"] is False
    assert patch_res["reason"].startswith("blocked_blind_write")

    multi_res = engine.validate_tool_invocation(
        "multiedit",
        {"edits": [{"filePath": str(tmp_path / "mcp-servers" / "mcp-validator" / "server.py")}]},
    )
    assert multi_res["allowed"] is False

    for cmd in (
        "sed -i 's/UNCONFIRMED/CONFIRMED/g' mcp-servers/mcp-validator/server.py",
        "echo '{}' | tee .codex/scope.json",
        "cp /tmp/fake.py mcp-servers/mcp-validator/server.py",
        "python3 -c \"import pathlib; pathlib.Path('mcp-servers/mcp-validator/server.py').write_text('x')\"",
    ):
        r = engine.validate_tool_invocation("bash", {"command": cmd})
        assert r["allowed"] is False, f"expected blocked for: {cmd}"
        assert r["reason"].startswith("blocked_blind_write")

    # /dev/null redirection must remain allowed in blind mode
    devnull_ok = engine.validate_tool_invocation(
        "bash", {"command": f"ls {tmp_path / 'work'} 2>/dev/null"}
    )
    assert devnull_ok["reason"] != "blocked_blind_write"


def _seed_old_allowed_call(engine, host, age_seconds):
    import sqlite3
    from datetime import datetime, timedelta, timezone

    stamp = (datetime.now(timezone.utc) - timedelta(seconds=age_seconds)).isoformat()
    conn = sqlite3.connect(engine.audit_db)
    conn.execute(
        "INSERT INTO audit_log (timestamp, tool_name, action, target, targets_json,"
        " scope_valid, permission, result, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (stamp, "kali-tools_curl_request", "execute", host,
         json.dumps([host]), 1, "allow", "allowed", "{}"),
    )
    conn.commit()
    conn.close()


def test_time_budget_blocks_after_budget_elapsed(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    _write_policy(tmp_path, {"time_budget_max_seconds": 60})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=3600, reason="test")
    # Continuous activity spanning past the 60s budget, still active now.
    for age in (3600, 1800, 600, 30):
        _seed_old_allowed_call(engine, "example.com", age_seconds=age)

    result = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://example.com/account"})
    assert result["allowed"] is False
    assert result["reason"].startswith("blocked_time_budget")


def test_time_budget_clock_resets_after_idle_gap(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    _write_policy(tmp_path, {"time_budget_max_seconds": 60})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=3600, reason="test")
    # A finished run hours ago must not eat the next run's budget.
    for age in (7200, 7000, 6900):
        _seed_old_allowed_call(engine, "example.com", age_seconds=age)

    result = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://example.com/account"})
    assert result["allowed"] is True


def test_time_budget_allows_within_budget_and_disabled(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    _write_policy(tmp_path, {"time_budget_max_seconds": 3600})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=3600, reason="test")
    _seed_old_allowed_call(engine, "example.com", age_seconds=60)

    within = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://example.com/account"})
    assert within["allowed"] is True

    _write_policy(tmp_path, {"time_budget_max_seconds": 0})
    disabled = module.PolicyEngine(cco_home=str(tmp_path / ".cco2"), repo_root=str(tmp_path))
    disabled.grant_approval("kali-tools_*", "example.com", ttl_seconds=3600, reason="test")
    _seed_old_allowed_call(disabled, "example.com", age_seconds=86400)
    off = disabled.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://example.com/account"})
    assert off["allowed"] is True


def test_sandbox_wrapped_command_is_validated_on_inner_command(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("*", "*", ttl_seconds=600, reason="test")

    # The gate plugin rewrites bash into a bwrap call whose mask list names
    # .cco/.ssh paths; re-validating that wrapper must not self-block.
    wrapped_ok = (
        "'/usr/bin/bwrap' '--tmpfs' '/repo/.cco' '--tmpfs' '/root/.ssh' "
        "'--setenv' 'CCO_BASH_SANDBOXED' '1' '--' '/bin/bash' '-c' "
        "'curl https://example.com/'"
    )
    ok = engine.validate_tool_invocation("bash", {"command": wrapped_ok})
    assert ok["allowed"] is True, ok["reason"]

    # Unwrapping must not weaken the secret-path scan of the real command.
    wrapped_bad = (
        "'/usr/bin/bwrap' '--tmpfs' '/repo/.cco' "
        "'--setenv' 'CCO_BASH_SANDBOXED' '1' '--' '/bin/bash' '-c' "
        "'cat /root/.ssh/id_rsa https://example.com/'"
    )
    bad = engine.validate_tool_invocation("bash", {"command": wrapped_bad})
    assert bad["allowed"] is False
    assert bad["reason"] == "blocked_secret_path"


def test_time_budget_is_per_target(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "in_scope": [
            {"asset": "example.com", "type": "web"},
            {"asset": "other.test", "type": "web"},
        ],
    })
    _write_policy(tmp_path, {"time_budget_max_seconds": 60})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "*", ttl_seconds=3600, reason="test")
    _seed_old_allowed_call(engine, "example.com", age_seconds=3600)

    fresh = engine.validate_tool_invocation(
        "kali-tools_curl_request", {"url": "https://other.test/account"})
    assert fresh["allowed"] is True



def test_local_orchestration_bash_needs_no_approval(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    planner = engine.validate_tool_invocation("bash", {
        "command": "python3 scripts/brain.py plan --target http://example.com --workdir /tmp/x --kind web"})
    assert planner["allowed"] is True
    assert planner["targets"] == []
    local = engine.validate_tool_invocation("bash", {"command": "wc -l config/tool-capabilities.json"})
    assert local["allowed"] is True
    network = engine.validate_tool_invocation("bash", {"command": "curl http://example.com/"})
    assert network["allowed"] is False


def test_session_vault_readable_but_cco_secrets_stay_blocked(tmp_path):
    module = _load_policy_engine()
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    assert engine.validate_tool_invocation(
        "read", {"filePath": ".cco/session-vault.json"})["allowed"] is True
    assert engine.validate_tool_invocation(
        "read", {"filePath": ".cco/audit.db"})["allowed"] is False


def test_exact_capability_entry_inherits_pattern_target_fields(tmp_path):
    # Kesin kayit (ledger_prepare_handoff) kali-tools_* deseninin target
    # alanlarini ezmemeli; aksi halde dogru target ile bile cagri
    # blocked_missing_target alir ve hic cagrilamaz.
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    result = engine.validate_tool_invocation(
        "kali-tools_ledger_prepare_handoff",
        {"target": "http://example.com", "workdir": "/tmp/x"})
    assert result["allowed"] is True, result


def test_sandbox_wrapper_resubmit_judged_by_inner_command(tmp_path):
    # Ajan hata ciktisindaki bwrap komutunu kopyalayip yeniden gonderebilir;
    # kapı dis zarfi (.cco/.env belirtecleri) degil ic komutu yargilamali.
    module = _load_policy_engine()
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    wrap = ("/usr/bin/bwrap --die-with-parent --cap-drop ALL "
            "--tmpfs /root/.cco --bind /dev/null /root/x/.env "
            "-- /bin/bash -c '{inner}'")
    inner_ok = wrap.format(inner="wc -l config/tool-capabilities.json")
    result = engine.validate_tool_invocation("bash", {"command": inner_ok})
    assert result["reason"] != "blocked_secret_path", result
    inner_bad = wrap.format(inner="cat .cco/audit.db")
    result = engine.validate_tool_invocation("bash", {"command": inner_bad})
    assert result["reason"] == "blocked_secret_path", result


def test_workdir_mkdir_chain_is_local(tmp_path, monkeypatch):
    module = _load_policy_engine()
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("CCO_WORKDIR", str(work))
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    ok = engine.validate_tool_invocation("bash", {
        "command": f"mkdir -p {work}/run3/recon {work}/run3/summaries && ls -la {work}/run3"})
    assert ok["allowed"] is True
    outside = engine.validate_tool_invocation("bash", {"command": "mkdir -p /etc/evil-dir"})
    assert outside["allowed"] is False


def test_nmap_safe_extra_args_allowed_unsafe_still_blocked(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com", "type": "web"}]})
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600, reason="test")
    ok = engine.validate_tool_invocation("kali-tools_nmap_scan", {
        "target": "example.com", "extra_args": "-sV -T4"})
    assert ok["allowed"] is True, ok
    bad = engine.validate_tool_invocation("kali-tools_nmap_scan", {
        "target": "example.com", "extra_args": "-sV --script vuln"})
    assert bad["allowed"] is False
    assert bad["reason"] == "blocked_unsafe_arguments: extra_args '--script'"


def test_policy_gate_cli_approve_refuses_inside_sandbox(tmp_path):
    env = dict(os.environ, CCO_HOME=str(tmp_path / ".cco"), CCO_BASH_SANDBOXED="1")
    result = subprocess.run(
        [sys.executable, "scripts/policy_gate_cli.py", "approve",
         "--tool-pattern", "kali-tools_*", "--target-pattern", "192.0.2.10"],
        cwd=REPO_ROOT, env=env, text=True, capture_output=True)
    assert result.returncode == 2
    assert "operator-only" in result.stderr


def test_policy_gate_cli_revoke_refuses_inside_sandbox(tmp_path):
    env = dict(os.environ, CCO_HOME=str(tmp_path / ".cco"), CCO_BASH_SANDBOXED="1")
    result = subprocess.run(
        [sys.executable, "scripts/policy_gate_cli.py", "revoke", "1"],
        cwd=REPO_ROOT, env=env, text=True, capture_output=True)
    assert result.returncode == 2
    assert "operator-only" in result.stderr


def test_gate_allows_local_ledger_tools_without_target(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    calls = [
        ("kali-tools_ledger_attempt_add", {
            "workdir": "/tmp/run", "vector": "csrf", "endpoint": "/support",
            "identity": "own", "verdict": "probe"}),
        ("kali-tools_ledger_attempt_add_batch", {
            "workdir": "/tmp/run", "items_json": "[]"}),
        ("kali-tools_ledger_coverage", {"workdir": "/tmp/run", "vector": "csrf"}),
        ("kali-tools_ledger_checkpoint", {"workdir": "/tmp/run", "seal": True}),
        ("kali-tools_race_check", {"workdir": "/tmp/run"}),
    ]
    for tool, args in calls:
        verdict = engine.validate_tool_invocation(tool, args)
        assert verdict["allowed"] is True, (tool, verdict)


def test_bash_env_prefixed_orchestration_with_attestation_allowed(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    verdict = engine.validate_tool_invocation("bash", {
        "command": "CCO_HOME=/tmp/x python3 scripts/brain.py hypotheses mark "
                   "--workdir /tmp/x --vector ssrf --status active "
                   "--note \"auth:not-required: test\""})
    assert verdict["allowed"] is True, verdict


def test_bash_chained_mark_with_attestation_and_granted_target_allowed(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    engine.grant_approval("bash", "example.com", ttl_seconds=600, reason="test")
    verdict = engine.validate_tool_invocation("bash", {
        "command": "echo http://example.com/seen; python3 scripts/brain.py "
                   "hypotheses mark --workdir /tmp/x --vector ssrf "
                   "--status active --note auth:not-required: t"})
    assert verdict["allowed"] is True, verdict


def test_bash_bare_orchestration_with_attestation_allowed(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    verdict = engine.validate_tool_invocation("bash", {
        "command": "python3 scripts/brain.py hypotheses mark "
                   "--workdir /tmp/x --vector ssrf --status active "
                   "--note \"auth:recovered ok\""})
    assert verdict["allowed"] is True, verdict


def test_bash_env_prefix_non_orchestration_still_gated(tmp_path):
    module = _load_policy_engine()
    _write_scope(tmp_path, {
        "scope_policy": "explicit_only",
        "in_scope": [{"asset": "example.com", "type": "web"}],
    })
    engine = module.PolicyEngine(cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    verdict = engine.validate_tool_invocation("bash", {
        "command": "CCO_HOME=/tmp/x python3 /tmp/evil.py http://evil.example/x"})
    assert verdict["allowed"] is False, verdict


def test_policy_gate_cli_approve_works_outside_sandbox(tmp_path):
    env = dict(os.environ, CCO_HOME=str(tmp_path / ".cco"))
    env.pop("CCO_BASH_SANDBOXED", None)
    result = subprocess.run(
        [sys.executable, "scripts/policy_gate_cli.py", "approve",
         "--tool-pattern", "kali-tools_*", "--target-pattern", "192.0.2.10",
         "--reason", "test"],
        cwd=REPO_ROOT, env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    grant = json.loads(result.stdout)
    assert grant["tool_pattern"] == "kali-tools_*"
