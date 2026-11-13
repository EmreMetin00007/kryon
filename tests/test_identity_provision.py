"""Faz 3: identity_provision — tariften oturum, human_needed görünürlüğü."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from identity_provision import provision  # noqa: E402


def _sender(method, url, headers, body, timeout):
    if url.endswith("/login"):
        return {"ok": True, "status": 200, "len": 30,
                "text": '{"access_token": "tok-1", "csrf": "c1"}',
                "headers": {"Set-Cookie": "sid=s1; Path=/"}, "error": None}
    if url.endswith("/me"):
        ok = headers.get("Authorization") == "Bearer tok-1"
        return {"ok": True, "status": 200 if ok else 401, "len": 2,
                "text": "{}", "headers": {}, "error": None}
    return {"ok": True, "status": 404, "len": 0, "text": "", "headers": {}, "error": None}


CONFIG = {"identities": [
    {"name": "userA", "login": {"url": "https://api.example.com/login",
                                "body": {"u": "a"}, "token_path": "access_token",
                                "csrf_path": "csrf", "csrf_header": "X-CSRF"},
     "probe_url": "https://api.example.com/me"},
    {"name": "userB", "headers": {"Authorization": "Bearer hazir"}},
    {"name": "admin", "kind": "browser"},
    {"name": "bozuk", "login": {"url": "https://api.example.com/login-yok",
                                "body": {}, "token_path": "access_token"}},
]}


def test_provision_mixed_outcomes():
    out = provision(CONFIG, sender=_sender)
    assert out["identities"]["userA"]["Authorization"] == "Bearer tok-1"
    assert out["identities"]["userA"]["Cookie"] == "sid=s1"
    assert out["identities"]["userB"] == {"Authorization": "Bearer hazir"}
    reasons = {h["name"]: h["reason"] for h in out["human_needed"]}
    assert "admin" in reasons and "tarayıcı" in reasons["admin"]
    assert "bozuk" in reasons
