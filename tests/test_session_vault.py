"""Merkezi oturum kasası: round-trip, 0600 izin, redaksiyon, tazelik probu."""
from __future__ import annotations

import json
import os
import pathlib
import stat
import sys
import sqlite3
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "mcp-servers" / "mcp-memory-server"))

from cco_surface_core import session_store as ss  # noqa: E402


def test_put_get_roundtrip_and_perms(tmp_path):
    out = ss.put_session("https://t.example", "wiener",
                         headers={"Authorization": "Bearer SECRET"},
                         cookies={"session": "SECRET2"},
                         check_url="https://t.example/me", marker="wiener",
                         home=str(tmp_path))
    blob = json.dumps(out)
    assert "SECRET" not in blob and "SECRET2" not in blob
    assert out["header_keys"] == ["Authorization"] and out["cookie_keys"] == ["session"]
    path = ss.vault_path(str(tmp_path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert "SECRET" not in path.read_text()
    raw_db = (tmp_path / "credential_vault.db").read_bytes()
    assert b"SECRET" not in raw_db and b"wiener" not in raw_db
    entry = ss.get_session("https://t.example", "wiener", home=str(tmp_path))
    assert entry["cookies"]["session"] == "SECRET2"


def test_fresh_and_stale_probe(tmp_path):
    ss.put_session("https://t.example", "a", cookies={"s": "1"},
                   check_url="https://t.example/me", marker="hello-a", home=str(tmp_path))
    fresh = ss.refresh_status("https://t.example", "a",
                              lambda u, h, c: (200, "welcome hello-a"), home=str(tmp_path))
    assert fresh["status"] == "fresh" and fresh["action"] == "ok"
    stale = ss.refresh_status("https://t.example", "a",
                              lambda u, h, c: (200, "login page"), home=str(tmp_path))
    assert stale["status"] == "stale" and "human_needed" in stale["action"]


def test_missing_session_needs_human(tmp_path):
    out = ss.refresh_status("https://none", "x", lambda u, h, c: (0, ""), home=str(tmp_path))
    assert out["status"] == "missing" and "human_needed" in out["action"]


def test_probe_error_is_stale_not_fresh(tmp_path):
    ss.put_session("https://t.example", "a", cookies={"s": "1"}, check_url="https://t.example/me",
                   marker="m", home=str(tmp_path))

    def boom(u, h, c):
        raise RuntimeError("net down")

    out = ss.refresh_status("https://t.example", "a", boom, home=str(tmp_path))
    assert out["status"] == "stale"


@pytest.mark.parametrize("status,expected", [(401, "expired"), (429, "rate_limited"),
                                               (302, "blocked"), (403, "stale")])
def test_marker_does_not_make_failed_http_response_fresh(tmp_path, status, expected):
    ss.put_session("https://t.example", "a", cookies={"s": "synthetic"},
                   check_url="https://t.example/me", marker="account-marker", home=str(tmp_path))
    calls = []
    def get(url, headers, cookies):
        calls.append(url)
        return status, "account-marker"
    result = ss.refresh_status("https://t.example", "a", get, home=str(tmp_path))
    action = "wait_and_reassess" if status == 429 else "human_needed"
    assert result["status"] == expected and result["action"].startswith(action)
    assert calls == ["https://t.example/me"]


@pytest.mark.parametrize("target,check", [
    ("https://t.example", "https://evil.example/me"),
    ("https://t.example", "https://t.example:444/me"),
    ("https://t.example", "http://t.example/me"),
    ("t.example", "https://t.example/me"),
])
def test_unbound_or_foreign_origin_never_receives_session(tmp_path, target, check):
    ss.put_session(target, "a", cookies={"s": "synthetic"}, check_url=check,
                   marker="expected", home=str(tmp_path))
    calls = []
    result = ss.refresh_status(target, "a", lambda *args: calls.append(args), home=str(tmp_path))
    assert result["status"] == "blocked" and calls == []


def test_session_rotation_cannot_mark_new_session_fresh_with_old_response(tmp_path):
    home = str(tmp_path)
    ss.put_session("https://t.example", "a", cookies={"s": "old"},
                   check_url="https://t.example/me", marker="old marker", home=home)
    old_ref = json.loads(ss.vault_path(home).read_text())["https://t.example::a"]["secret_ref"]
    def check(*args):
        ss.put_session("https://t.example", "a", cookies={"s": "new"},
                       check_url="https://t.example/me", marker="new marker", home=home)
        return 200, "old marker"
    result = ss.refresh_status("https://t.example", "a", check, home=home)
    assert result["status"] == "superseded"
    current = ss.get_session("https://t.example", "a", home=home)
    assert current["status"] == "unknown" and current["cookies"] == {"s": "new"}
    with sqlite3.connect(tmp_path / "credential_vault.db") as conn:
        deleted = conn.execute("SELECT deleted_at FROM vault_secrets WHERE id=?", (old_ref,)).fetchone()
    assert deleted[0]


def test_legacy_session_migrates_on_successful_check(tmp_path):
    entry = {"target": "https://t.example", "identity": "a", "headers": {},
             "cookies": {"s": "old-secret"}, "check_url": "https://t.example/me",
             "marker": "legacy-marker", "status": "unknown", "updated_at": 1}
    path = ss.vault_path(str(tmp_path))
    path.write_text(json.dumps({"https://t.example::a": entry}))
    result = ss.refresh_status("https://t.example", "a", lambda *_: (200, "legacy-marker"), home=str(tmp_path))
    assert result["status"] == "fresh"
    assert "old-secret" not in path.read_text() and "legacy-marker" not in path.read_text()
    assert ss.get_session("https://t.example", "a", home=str(tmp_path))["cookies"] == {"s": "old-secret"}


def test_ciphertext_reference_cannot_be_rebound_to_another_account(tmp_path):
    home = str(tmp_path)
    for name in ("a", "b"):
        ss.put_session("https://t.example", name, cookies={"s": name}, home=home)
    path = ss.vault_path(home)
    data = json.loads(path.read_text())
    data["https://t.example::b"]["secret_ref"] = data["https://t.example::a"]["secret_ref"]
    path.write_text(json.dumps(data))
    assert ss.get_session("https://t.example", "b", home=home) is None


@pytest.mark.parametrize("headers,cookies", [
    ({"Cookie": "s=one", "cookie": "s=two"}, {}),
    ({"Host": "elsewhere", "Authorization": "synthetic"}, {}),
    ({"Cookie": "s=one"}, {"s": "two"}),
    ({}, {"s": "bad\r\nInjected: header"}),
    ({"Authorization": "ok\r\nInjected: header"}, {}),
])
def test_invalid_or_ambiguous_session_material_never_reaches_transport(tmp_path, headers, cookies):
    target = "https://t.example"
    ss.put_session(target, "a", headers=headers, cookies=cookies,
                   check_url=target + "/me", marker="expected", home=str(tmp_path))
    calls = []
    out = ss.refresh_status(target, "a", lambda *args: calls.append(args), home=str(tmp_path))
    assert out["status"] == "blocked" and calls == []


def test_fresh_status_must_be_attested_and_unexpired(tmp_path, monkeypatch):
    home = str(tmp_path)
    target = "https://t.example"
    ss.put_session(target, "a", cookies={"s": "synthetic"},
                   check_url=target + "/me", marker="marker", home=home)
    path = ss.vault_path(home)
    data = json.loads(path.read_text())
    data[target + "::a"].update({"status": "fresh", "checked_at": int(time.time())})
    path.write_text(json.dumps(data))
    assert ss.verified_session(target, "a", home=home) is None
    assert ss.refresh_status(target, "a", lambda *_: (200, "marker"), home=home)["status"] == "fresh"
    verified = ss.verified_session(target, "a", home=home)
    assert verified and ss.same_verified_session(target, "a", verified, home=home)
    monkeypatch.setattr(ss.time, "time", lambda: verified["checked_at"] + 301)
    assert ss.verified_session(target, "a", home=home) is None
    assert not ss.same_verified_session(target, "a", verified, home=home)


def test_missing_session_key_does_not_silently_replace_the_vault_key(tmp_path, monkeypatch):
    monkeypatch.delenv("CCO_VAULT_KEY", raising=False)
    monkeypatch.setenv("CCO_USE_KEYRING", "0")
    home, target = str(tmp_path), "https://t.example"
    ss.put_session(target, "a", cookies={"s": "synthetic"},
                   check_url=target + "/me", marker="account marker", home=home)
    key = tmp_path / "vault.key"
    key.unlink()
    assert ss.get_session(target, "a", home=home) is None
    assert ss.verified_session(target, "a", home=home) is None
    assert ss.refresh_status(target, "a", lambda *_: pytest.fail("must not send"), home=home)["status"] == "missing"
    assert not key.exists()


def test_successive_checks_in_same_second_have_distinct_signed_versions(tmp_path, monkeypatch):
    target, home = "https://t.example", str(tmp_path)
    now = int(time.time())
    monkeypatch.setattr(ss.time, "time", lambda: now + 0.5)
    monkeypatch.setattr(ss.time, "time_ns", lambda: now * 10**9 + 500_000_000)
    ss.put_session(target, "a", cookies={"s": "synthetic"},
                   check_url=target + "/me", marker="marker", home=home)
    ss.refresh_status(target, "a", lambda *_: (200, "marker"), home=home)
    first = ss.verified_session(target, "a", home=home)
    ss.refresh_status(target, "a", lambda *_: (200, "marker"), home=home)
    second = ss.verified_session(target, "a", home=home)
    assert first["checked_at"] == second["checked_at"] == now
    assert first["check_id"] != second["check_id"]
    assert ss.check_fingerprint(target, "a", home=home, entry=first) != ss.check_fingerprint(target, "a", home=home, entry=second)
    assert not ss.same_verified_session(target, "a", first, home=home)


@pytest.mark.parametrize("field", ["check_id", "checked_at_ns"])
def test_check_nonce_and_precise_timestamp_cannot_be_tampered(tmp_path, field):
    target, home = "https://t.example", str(tmp_path)
    ss.put_session(target, "a", cookies={"s": "synthetic"},
                   check_url=target + "/me", marker="marker", home=home)
    ss.refresh_status(target, "a", lambda *_: (200, "marker"), home=home)
    path = ss.vault_path(home)
    data = json.loads(path.read_text())
    data[target + "::a"][field] = "0" * 32 if field == "check_id" else data[target + "::a"][field] + 1
    path.write_text(json.dumps(data))
    assert ss.verified_session(target, "a", home=home) is None


@pytest.mark.parametrize("with_nonce", [False, True])
def test_legacy_signed_checks_remain_readable_but_next_check_upgrades(tmp_path, with_nonce):
    target, home = "https://t.example", str(tmp_path)
    ss.put_session(target, "a", cookies={"s": "synthetic"},
                   check_url=target + "/me", marker="marker", home=home)
    ss.refresh_status(target, "a", lambda *_: (200, "marker"), home=home)
    path = ss.vault_path(home)
    data = json.loads(path.read_text())
    entry = data[target + "::a"]
    entry.pop("checked_at_ns")
    if not with_nonce:
        entry.pop("check_id")
    entry["verification"] = ss._attestation(entry, home)
    path.write_text(json.dumps(data))
    assert ss.verified_session(target, "a", home=home)
    ss.refresh_status(target, "a", lambda *_: (200, "marker"), home=home)
    assert ss.verified_session(target, "a", home=home)["checked_at_ns"] > 0
