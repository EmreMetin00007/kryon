"""OS izolasyonu: bwrap altında repo yazısı reddedilir, workdir yazısı serbest."""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "blind_run.sh"

pytestmark = pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap yok")


def _run(workdir: pathlib.Path, inner: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, CCO_WORKDIR=str(workdir))
    return subprocess.run(["bash", str(SCRIPT), "bash", "-c", inner],
                          capture_output=True, text=True, env=env, timeout=60)


def test_repo_write_denied_workdir_allowed(tmp_path):
    workdir = tmp_path / "cco-work"
    workdir.mkdir()
    probe = _run(workdir, f"echo ok > {workdir}/probe.txt && echo WROTE")
    assert probe.returncode == 0 and "WROTE" in probe.stdout
    assert (workdir / "probe.txt").exists()

    victim = REPO / ".blind-probe-should-not-exist"
    denied = _run(workdir, f"echo x > {victim} && echo WROTE")
    assert denied.returncode != 0
    assert not victim.exists()


def test_missing_bwrap_fails_closed():
    # bwrap'sız ortamda script sessizce korumasız koşmamalı (PATH'i boşalt)
    out = subprocess.run(["/bin/bash", str(SCRIPT), "true"], capture_output=True,
                         text=True, env={"PATH": "/nonexistent", "HOME": "/root"}, timeout=30)
    assert out.returncode == 2
