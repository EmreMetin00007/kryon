"""Faz F: gecikmiş heartbeat, lease dolmuş ama devralınmamışsa yenileyebilmeli."""
import importlib.util
import os
import sqlite3
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_runtime():
    path = os.path.join(REPO_ROOT, "scripts", "campaign_runtime.py")
    spec = importlib.util.spec_from_file_location("campaign_runtime_hb", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _expire(runtime, task_id):
    conn = sqlite3.connect(runtime.db_path)
    conn.execute("UPDATE tasks SET claim_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",
                 (task_id,))
    conn.commit()
    conn.close()


def test_expired_lease_heartbeat_renews_only_with_flag(tmp_path):
    runtime = _load_runtime().CampaignRuntime(str(tmp_path / ".cco"))
    cid = runtime.create_campaign("hb")
    runtime.enqueue_task(cid, "recon", "kali-tools_cvss_calculate", {})
    task = runtime.claim_next_task("worker", cid)
    _expire(runtime, task["id"])

    with pytest.raises(ValueError):
        runtime.heartbeat_task_with_permit(task["execution_permit"], {"phase": "late"})
    refreshed = runtime.heartbeat_task_with_permit(
        task["execution_permit"], {"phase": "late"}, allow_expired_lease=True)
    assert refreshed
    runtime.complete_task_with_permit(refreshed, {"ok": True})
    assert runtime.list_tasks(cid)[0]["status"] == "done"


def test_expired_lease_heartbeat_cannot_steal_reclaimed_task(tmp_path):
    runtime = _load_runtime().CampaignRuntime(str(tmp_path / ".cco"))
    cid = runtime.create_campaign("hb2")
    runtime.enqueue_task(cid, "recon", "kali-tools_cvss_calculate", {})
    task = runtime.claim_next_task("worker-a", cid)
    _expire(runtime, task["id"])
    # Başka worker süresi dolmuş görevi devralır (lease/fencing değişir)
    reclaimed = runtime.claim_next_task("worker-b", cid)
    assert reclaimed and reclaimed["id"] == task["id"]
    with pytest.raises(ValueError):
        runtime.heartbeat_task_with_permit(
            task["execution_permit"], {"phase": "stale"}, allow_expired_lease=True)
