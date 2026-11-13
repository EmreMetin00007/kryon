"""live_run giriş kapısı testleri (kapsam kapısı + kuru E2E)."""
import json
import os
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import live_run  # noqa: E402


def _scope_file(tmp_path, host):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({
        "in_scope": [{"asset": f"https://{host}/"}],
        "targets": [host],
    }), encoding="utf-8")
    return str(p)


def test_gate_rejects_out_of_scope_host(tmp_path):
    scope = _scope_file(tmp_path, "allowed.test")
    try:
        live_run.gate_target("https://evil.test/", scope)
    except SystemExit as exc:
        assert "KAPSAM DISI" in str(exc)
    else:
        raise AssertionError("kapsam dışı kabul edildi")


def test_gate_accepts_in_scope_host(tmp_path):
    scope = _scope_file(tmp_path, "lab.test")
    assert live_run.gate_target("https://lab.test/cart", scope) == "lab.test"


def test_live_run_dry_run_end_to_end(tmp_path, monkeypatch):
    home = tmp_path / "home"
    work = tmp_path / "work"
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.setenv("CCO_WORKDIR", str(work))
    scope = _scope_file(tmp_path, "lab.test")
    rc = live_run.main([
        "--target", "https://lab.test/",
        "--objective", "yüzey haritası",
        "--kinds", "recon,fuzz",
        "--workers", "2",
        "--max-tasks", "2",
        "--scope", scope,
        "--dry-run",
    ])
    assert rc == 0
    db = sqlite3.connect(home / "campaigns.db")
    rows = db.execute("SELECT kind, status FROM tasks ORDER BY id").fetchall()
    db.close()
    assert sorted(rows) == [("fuzz", "done"), ("recon", "done")]
    assert (work / "pool" / "w0").is_dir()
    assert (work / "pool" / "w1").is_dir()
