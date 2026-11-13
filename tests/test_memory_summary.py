import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_memory_server():
    path = REPO_ROOT / "mcp-servers" / "mcp-memory-server" / "server.py"
    spec = importlib.util.spec_from_file_location("memory_server_summary_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ms = _load_memory_server()


def _seed(db_path, n_findings=5, n_endpoints=5):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("CREATE TABLE findings (id INTEGER PRIMARY KEY, target TEXT, type TEXT, "
              "severity TEXT, description TEXT, payload TEXT, validation_state TEXT DEFAULT 'unvalidated', "
              "validation_artifact TEXT DEFAULT '', validation_id TEXT DEFAULT '', "
              "validation_verdict TEXT DEFAULT '', validation_oracle TEXT DEFAULT '', "
              "validation_evidence_grade TEXT DEFAULT '', validation_report_path TEXT DEFAULT '', "
              "reportable INTEGER DEFAULT 0, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    c.execute("CREATE TABLE credentials (id INTEGER PRIMARY KEY, target TEXT, service TEXT, "
              "username TEXT, password TEXT, secret_ref TEXT DEFAULT '', secret_backend TEXT DEFAULT '', "
              "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    c.execute("CREATE TABLE endpoints (id INTEGER PRIMARY KEY, target TEXT, url_or_port TEXT, "
              "protocol TEXT, state TEXT, technologies TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    for i in range(n_findings):
        c.execute("INSERT INTO findings (target,type,severity,description) VALUES (?,?,?,?)",
                  ("t1", f"type{i}", "low", f"d{i}"))
    for i in range(n_endpoints):
        c.execute("INSERT INTO endpoints (target,url_or_port) VALUES (?,?)", ("t1", f"https://t1/{i}"))
    conn.commit()
    conn.close()


class TestGetTargetMemoryLimits:
    def _call(self, tmp_path, monkeypatch, **kw):
        db = str(tmp_path / "mem.db")
        _seed(db)
        monkeypatch.setattr(ms, "DB_PATH", db)
        # kg/surface yardimcilari izole DB'de sessiz gecsin
        monkeypatch.setattr(ms.kg, "get_graph_summary", lambda *a, **k: {"total_nodes": 0})
        return json.loads(ms.get_target_memory("t1", **kw))

    def test_default_caps_at_20(self, tmp_path, monkeypatch):
        db = str(tmp_path / "mem.db")
        _seed(db, n_findings=30, n_endpoints=30)
        monkeypatch.setattr(ms, "DB_PATH", db)
        monkeypatch.setattr(ms.kg, "get_graph_summary", lambda *a, **k: {"total_nodes": 0})
        out = json.loads(ms.get_target_memory("t1"))
        assert len(out["findings"]) == 20
        assert out["findings_truncated"] == {"total": 30, "shown": 20}
        assert len(out["endpoints"]) == 20

    def test_summary_mode(self, tmp_path, monkeypatch):
        out = self._call(tmp_path, monkeypatch, summary=True)
        assert len(out["findings"]) == 3
        assert out["findings_truncated"] == {"total": 5, "shown": 3}

    def test_explicit_full_dump(self, tmp_path, monkeypatch):
        out = self._call(tmp_path, monkeypatch, limit=0)
        assert len(out["findings"]) == 5
        assert "findings_truncated" not in out

    def test_small_result_untouched(self, tmp_path, monkeypatch):
        out = self._call(tmp_path, monkeypatch)
        assert len(out["findings"]) == 5
        assert "findings_truncated" not in out
