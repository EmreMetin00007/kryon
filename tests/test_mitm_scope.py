import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_mitm_scope():
    path = REPO_ROOT / "scripts" / "mitm_scope.py"
    spec = importlib.util.spec_from_file_location("mitm_scope_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ms = _load_mitm_scope()


def _freeze_scope(exact, suffix):
    ms._WATCH_EXACT = frozenset(exact)
    ms._WATCH_SUFFIX = tuple(suffix)
    ms._SCOPE_MTIME = (REPO_ROOT / ".codex" / "scope.json").stat().st_mtime


class TestHostInScope:
    def setup_method(self):
        _freeze_scope({"a.example.com"}, ("wild.example.com",))

    def test_exact(self):
        assert ms.host_in_scope("a.example.com")

    def test_wildcard_sub(self):
        assert ms.host_in_scope("x.wild.example.com")
        assert ms.host_in_scope("a.b.wild.example.com")

    def test_wildcard_no_suffix_smuggle(self):
        assert not ms.host_in_scope("wild.example.com.evil.com")
        assert not ms.host_in_scope("evil.com")

    def test_case_and_space(self):
        assert ms.host_in_scope("  A.Example.COM ")


class FakeReq:
    def __init__(self, host, path="/x?a=1&token=sekret"):
        self.host = host
        self.method = "GET"
        self.path = path
        self.headers = {}
        self.text = ""
        self.pretty_url = f"https://{host}{path}"


class FakeResp:
    def __init__(self, code=200):
        self.status_code = code
        self.headers = {}
        self.text = "ok"


class FakeFlow:
    def __init__(self, host, code=200):
        self.request = FakeReq(host)
        self.response = FakeResp(code)


class TestCounters:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        _freeze_scope({"a.example.com"}, ())
        self.tmp = tmp_path
        monkeypatch.setattr(ms, "TRAFFIC", tmp_path / "t.jsonl")
        monkeypatch.setattr(ms, "ROUTES", tmp_path / "r.json")
        monkeypatch.setattr(ms, "HOSTSTATS", tmp_path / "h.json")
        monkeypatch.setattr(ms, "SAVE_INTERVAL_SEC", 0)
        monkeypatch.setattr(ms, "url_in_scope", lambda url: url.startswith("https://a.example.com/"))

    def test_counts_and_redaction(self):
        lg = ms.ScopeLogger()
        lg.response(FakeFlow("a.example.com", 200))
        lg.response(FakeFlow("a.example.com", 404))
        lg.response(FakeFlow("evil.com", 200))  # scope disi: sayilmaz
        hs = json.loads((self.tmp / "h.json").read_text())
        assert hs["a.example.com"]["n"] == 2
        assert hs["a.example.com"]["codes"] == {"200": 1, "404": 1}
        assert "evil.com" not in hs
        r = json.loads((self.tmp / "r.json").read_text())
        assert r["GET /x"]["count"] == 2
        assert "sekret" not in r["GET /x"]["sample_query"]

    def test_metadata_capture_never_persists_request_or_response_values(self):
        flow = FakeFlow("a.example.com")
        flow.request.headers = {"Authorization": "Bearer synthetic-credential",
                                "X-Custom-Secret": "synthetic-secret",
                                "Content-Type": "application/json"}
        flow.request.text = '{"email": "person-synthetic", "quantity": 27}'
        flow.response.text = '{"private": "response-synthetic"}'
        ms.ScopeLogger().response(flow)
        raw = (self.tmp / "t.jsonl").read_text()
        for value in ("synthetic-credential", "synthetic-secret", "person-synthetic",
                      "response-synthetic", "sekret", '"27"'):
            assert value not in raw
        entry = json.loads(raw)
        assert entry["capture_redacted"] is True
        assert {param["name"] for param in entry["params"]} == {"a", "token", "email", "quantity"}
        assert entry["req_body"] == entry["resp_body"] == ""
