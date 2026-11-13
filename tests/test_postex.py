"""Post-exploitation parsers + lateral planner tests (offline)."""

import json
import sqlite3
import sys
import os

import pytest

from conftest import load_server, list_tool_names

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "mcp-kali-tools"))

from cco_postex_core.parsers import parse_linpeas, parse_winpeas


LINPEAS_FIXTURE = """\
\x1b[95m[+] \x1b[0m-rwsr-xr-x 1 root root 12345 /usr/bin/sudo-test
/usr/bin/find has capabilities: cap_dac_read_search+ep
user may run the following commands: (ALL) NOPASSWD: /usr/bin/vim
writable PATH directory: /tmp/custom-bin
db_password: SuperSecret123 in /var/www/config.php
Linux version 5.15.0-kali (gcc)
"""

WINPEAS_FIXTURE = """\
[!] SeImpersonatePrivilege : Enabled
[X] SeTcbPrivilege : Disabled
[!] AlwaysInstallElevated is set to 1 in HKLM
[+] No quotes and Space detected in C:\\Program Files\\App\\svc.exe
[!] DefaultPassword found in registry autologon: P@ssw0rd!
[*] PowerShell history file: ConsoleHost_history.txt
"""


def test_parse_linpeas_core_classes():
    out = parse_linpeas(LINPEAS_FIXTURE)
    classes = {f["class"] for f in out["findings"]}
    assert {"suid_binary", "sudo_nopasswd", "writable_path", "credential_hint"} <= classes
    assert out["finding_count"] == len(out["findings"])
    assert out["findings"][0]["severity"] in {"critical", "high"}


def test_parse_linpeas_masks_secrets():
    out = parse_linpeas(LINPEAS_FIXTURE)
    cred = next(f for f in out["findings"] if f["class"] == "credential_hint")
    assert cred["sensitive"] is True
    assert "SuperSecret123" not in cred["evidence"]


def test_parse_linpeas_ignores_help_text():
    usage = "  -P Indicate a password that will be used to run 'sudo -l'\n  -f </FOLDER> search passwords inside a folder\n"
    out = parse_linpeas(usage)
    assert out["finding_count"] == 0


def test_parse_linpeas_ignores_env_pwd_and_decorations():
    noise = "PWD=/tmp\nOLDPWD=/root\n╚ https://book.hacktricks.wiki/writable-path\n"
    out = parse_linpeas(noise)
    assert out["finding_count"] == 0


def test_parse_winpeas_privileges():
    out = parse_winpeas(WINPEAS_FIXTURE)
    classes = {f["class"] for f in out["findings"]}
    assert "token_privilege" in classes
    assert "always_install_elevated" in classes
    assert "unquoted_service_path" in classes
    # Disabled privs must not alert
    assert not any("SeTcb" in f["evidence"] for f in out["findings"])


def test_parse_winpeas_masks_autologon():
    out = parse_winpeas(WINPEAS_FIXTURE)
    auto = next(f for f in out["findings"] if f["class"] == "autologon_credential")
    assert auto["sensitive"] is True
    assert "P@ssw0rd" not in auto["evidence"]


def test_kali_registers_postex_tools():
    names = list_tool_names(load_server("kali-tools"))
    assert "linpeas_fetch" in names
    assert "parse_privesc_report" in names
    assert "privesc_scan_local" in names


def test_kali_postex_group_loads():
    import asyncio
    import importlib.util
    path = os.path.join(REPO_ROOT, "mcp-servers", "mcp-kali-tools", "server.py")
    old = os.environ.get("CCO_KALI_GROUPS")
    os.environ["CCO_KALI_GROUPS"] = "core,web,exploit,llm,report,postex"
    try:
        spec = importlib.util.spec_from_file_location("cco_kali_postex_group", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        names = [t.name for t in asyncio.run(mod.mcp.list_tools())]
    finally:
        if old is None:
            os.environ.pop("CCO_KALI_GROUPS", None)
        else:
            os.environ["CCO_KALI_GROUPS"] = old
    assert "privesc_scan_local" in names
    assert "parse_privesc_report" in names


def test_memory_registers_lateral_planner():
    names = list_tool_names(load_server("memory-server"))
    assert "suggest_lateral_moves" in names


def _seed_postex_memory(mem):
    mem._ensure_initialized()
    conn = sqlite3.connect(mem.DB_PATH)
    conn.execute(
        "INSERT INTO credentials (target, service, username, password, secret_ref) "
        "VALUES (?, ?, ?, ?, ?)",
        ("10.10.0.5", "smb", "admin", "[REDACTED]", "vault-ref-1"),
    )
    conn.execute(
        "INSERT INTO endpoints (target, url_or_port, protocol, state, technologies) "
        "VALUES (?, ?, ?, ?, ?)",
        ("10.10.0.5", "445", "smb", "open", "samba"),
    )
    conn.commit()
    conn.close()


def test_suggest_lateral_moves_references_vault_not_secrets():
    mem = load_server("memory-server")
    _seed_postex_memory(mem)
    conn = sqlite3.connect(mem.DB_PATH)
    row = conn.execute(
        "SELECT id FROM credentials WHERE target=? ORDER BY id DESC LIMIT 1",
        ("10.10.0.5",),
    ).fetchone()
    conn.close()
    plan = json.loads(mem.suggest_lateral_moves("10.10.0.5"))
    assert plan["moves"], "beklenen lateral hamle uretilmedi"
    first = plan["moves"][0]
    assert first["needs_approval"] is True
    assert first["credential_ref"] == f"vault:credentials#{row[0]}"
    blob = json.dumps(plan)
    assert "vault-ref-1" not in blob
    assert "[REDACTED]" not in blob


def test_suggest_lateral_moves_empty_graph_guidance():
    mem = load_server("memory-server")
    plan = json.loads(mem.suggest_lateral_moves("192.0.2.99"))
    assert isinstance(plan["moves"], list)
    assert any("privesc" in note or "graph" in note.lower() for note in plan["notes"])


def test_postex_capability_overrides():
    from test_mcp_servers import EXPECTED_TOOL_COUNTS  # noqa: F401
    caps = json.loads(open(os.path.join(REPO_ROOT, "config", "tool-capabilities.json")).read())
    fetch = caps["tools"]["kali-tools_linpeas_fetch"]
    scan = caps["tools"]["kali-tools_privesc_scan_local"]
    parse = caps["tools"]["kali-tools_parse_privesc_report"]
    lateral = caps["tools"]["memory-server_suggest_lateral_moves"]
    assert fetch["network"] is True and fetch["requires_scope"] is False
    assert scan["requires_approval"] is True and scan["network"] is False
    assert parse["requires_approval"] is False
    assert lateral["sensitive_output"] is True and lateral["requires_approval"] is False
