import importlib.util
import asyncio
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_agent_browse():
    path = REPO_ROOT / "scripts" / "agent_browse.py"
    spec = importlib.util.spec_from_file_location("agent_browse_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ab = _load_agent_browse()


class TestAllowlist:
    def test_exact_and_subdomain(self):
        allow = {"nebius.com"}
        assert ab.in_allowlist("nebius.com", allow)
        assert ab.in_allowlist("console.nebius.com", allow)
        assert ab.in_allowlist("a.b.nebius.com", allow)

    def test_negative(self):
        allow = {"nebius.com"}
        assert not ab.in_allowlist("evil.com", allow)
        assert not ab.in_allowlist("nebius.com.evil.com", allow)
        assert not ab.in_allowlist("", allow)

    def test_loopback_always_allowed(self):
        assert ab.in_allowlist("127.0.0.1", set())
        assert ab.in_allowlist("localhost", set())
        assert ab.in_allowlist("::1", set())

    def test_host_of(self):
        assert ab.host_of("https://Example.COM:8443/a?b=c") == "example.com"
        assert ab.host_of("not a url") == ""
        assert ab.host_of("http://127.0.0.1:8899/") == "127.0.0.1"


class TestParseAllowlist:
    def test_comma(self):
        assert ab.parse_allowlist("a.com, B.com ,") == {"a.com", "b.com"}

    def test_file(self, tmp_path):
        f = tmp_path / "allow.txt"
        f.write_text("a.com\n# comment\n\nb.com\n")
        assert ab.parse_allowlist(f"@{f}") == {"a.com", "b.com"}

    def test_default_reads_scope(self, tmp_path, monkeypatch):
        # Hermetik: aktif operator scope.json'una degil, fikstur scope'a bak.
        codex = tmp_path / ".codex"
        codex.mkdir()
        (codex / "scope.json").write_text(json.dumps({
            "in_scope": [{"asset": "nebius.com", "type": "domain"}],
        }))
        monkeypatch.setattr(ab, "REPO", tmp_path)
        allow = ab.parse_allowlist(None)
        assert "nebius.com" in allow


class TestCreds:
    def _write(self, tmp_path, data, mode=0o600):
        p = tmp_path / "creds.json"
        p.write_text(json.dumps(data))
        p.chmod(mode)
        return p

    def test_ok_with_placeholders(self, tmp_path):
        p = self._write(tmp_path, {"user": "alice", "pw": "s3cr3t"})
        creds = ab.load_creds(p, "login as <user> with <pw>")
        assert creds == {"user": "alice", "pw": "s3cr3t"}

    def test_raw_value_in_task_refused(self, tmp_path):
        p = self._write(tmp_path, {"pw": "s3cr3t-value"})
        with pytest.raises(SystemExit) as e:
            ab.load_creds(p, "login with s3cr3t-value")
        assert e.value.code == ab.EXIT_ERROR

    def test_bad_perms_refused(self, tmp_path):
        p = self._write(tmp_path, {"pw": "x"}, mode=0o644)
        with pytest.raises(SystemExit) as e:
            ab.load_creds(p, "task")
        assert e.value.code == ab.EXIT_ERROR

    def test_non_dict_refused(self, tmp_path):
        p = self._write(tmp_path, ["not", "a", "dict"])
        with pytest.raises(SystemExit):
            ab.load_creds(p, "task")


class TestCaptchaPattern:
    @pytest.mark.parametrize("title", [
        "Just a moment... - Cloudflare",
        "Verify you are human - Turnstile",
        "Please solve the captcha to continue",
        "Attention Required! | PerimeterX",
    ])
    def test_detects(self, title):
        assert ab.CAPTCHA_PAT.search(title)

    @pytest.mark.parametrize("title", [
        "Console - Nebius AI",
        "Sign in - GitHub",
        "Directory listing for /",
    ])
    def test_no_false_positive(self, title):
        assert not ab.CAPTCHA_PAT.search(title)


def _load_mcp_server():
    path = REPO_ROOT / "mcp-servers" / "mcp-agent-browse" / "server.py"
    spec = importlib.util.spec_from_file_location("agent_browse_mcp_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestMcpTools:
    """Offline: only refusal paths (exit before browser launch, no network)."""

    @classmethod
    def setup_class(cls):
        cls.mcp = _load_mcp_server()

    def test_off_allowlist_refused(self):
        res = json.loads(self.mcp.agent_browse(
            task="x", start_url="https://evil.example.com/", allowlist="nebius.com"))
        assert res["ok"] is False
        assert res["exit_code"] == 2

    def test_live_url_check_refused(self):
        res = json.loads(self.mcp.agent_browse_check(start_url="https://example.com/"))
        assert res["ok"] is False
        assert res["exit_code"] == 2

    def test_out_dir_escape_refused(self):
        res = json.loads(self.mcp.agent_browse(
            task="x", start_url="http://127.0.0.1:9/", out_dir="/tmp/escape"))
        assert res["ok"] is False
        assert "outside repo" in res["error"]

    def test_missing_creds_refused(self):
        res = json.loads(self.mcp.agent_browse(
            task="x", start_url="http://127.0.0.1:9/", creds="/nonexistent.json"))
        assert res["ok"] is False
        assert "missing" in res["error"]

    def test_bad_extra_headers_refused(self):
        res = json.loads(self.mcp.agent_browse(
            task="x", start_url="http://127.0.0.1:9/", extra_headers="not-json"))
        assert res["ok"] is False
        assert "JSON" in res["error"]


class TestParserDefaults:
    def test_defaults(self):
        args = ab.build_parser().parse_args(
            ["--task", "t", "--start-url", "http://127.0.0.1:8899/"])
        assert args.max_steps == 25
        assert args.max_actions_per_step == 3
        assert args.proxy == "http://127.0.0.1:8080"
        assert args.headed is False
        assert args.check is False
        assert args.header == []

    def test_extra_headers(self):
        args = ab.build_parser().parse_args(
            ["--task", "t", "--start-url", "http://127.0.0.1:8899/",
             "--header", "X-HackerOne: letmet4y", "--header", "User-Agent: HackerOne/letmet4y"])
        assert args.header == ["X-HackerOne: letmet4y", "User-Agent: HackerOne/letmet4y"]


def test_agent_browser_refuses_before_proxy_or_browser(monkeypatch, capsys):
    monkeypatch.setattr(ab, "central_scope_permits", lambda url: True)
    monkeypatch.setattr(ab, "proxy_reachable", lambda url: pytest.fail("must not connect to proxy"))
    monkeypatch.setattr(sys, "argv", ["agent_browse", "--task", "test",
                                    "--start-url", "http://127.0.0.1:8899/"])
    assert ab.main() == ab.EXIT_ERROR
    assert "request-level policy is unavailable" in capsys.readouterr().err


def test_direct_agent_entrypoints_also_refuse_before_browser_import(tmp_path):
    assert asyncio.run(ab.run_check(None, set(), {})) == ab.EXIT_ERROR
    assert asyncio.run(ab.run_agent(None, "", set(), {}, {}, tmp_path)) == ab.EXIT_ERROR
