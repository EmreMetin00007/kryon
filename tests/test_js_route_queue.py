"""JS compose queue: templates must be probed before jwt/nmap diversion."""

import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from js_route_queue import (  # noqa: E402
    evaluate,
    header_hints_from_source,
    instantiate,
    is_diversion,
    path_matches,
    paths_to_enqueue,
)


SOURCE = r"""
var _k=["v1","v2","auth","users","cluster"];
getProfile: function(userId) {
  return fetch(this.api.v2.users + '/' + userId + '/profile');
}
const list = () => fetch("/api/v2/users");
"""


def test_path_matches_id_slot():
    assert path_matches("/api/v2/users/{id}/profile", "/api/v2/users/8/profile")
    assert path_matches("/api/v2/users/{id}/profile", "/api/v2/users/1/profile")
    assert not path_matches("/api/v2/users/{id}/profile", "/api/v2/users/8")


def test_instantiate_id():
    assert instantiate("/api/v2/users/{id}/profile") == "/api/v2/users/1/profile"


def test_paths_to_enqueue_keeps_templates_only():
    sys.path.insert(0, str(REPO_ROOT / "mcp-servers" / "mcp-kali-tools"))
    from cco_js_core.compose import compose_js_routes

    queued = paths_to_enqueue(compose_js_routes(SOURCE))
    assert "/api/v2/users/{id}/profile" in queued
    assert all("{" in p for p in queued)


def test_jwt_blocked_until_template_curled():
    conn = sqlite3.connect(":memory:")
    allowed, _ = evaluate(
        conn, "kali-tools_compose_js_routes",
        {"source": SOURCE, "target": "http://example.com:8088"},
        [], [],
    )
    assert allowed is True
    blocked, detail = evaluate(
        conn, "web-advanced_jwt_analyze", {"token": "x"}, [], ["example.com"],
    )
    assert blocked is False
    assert "users/1/profile" in detail
    assert "JWT" in detail or "jwt" in detail.lower() or "unprobed" in detail

    allowed, _ = evaluate(
        conn, "kali-tools_curl_request", {},
        ["http://example.com:8088/api/v2/users/8/profile"], ["example.com"],
    )
    assert allowed is True
    allowed, detail = evaluate(
        conn, "web-advanced_jwt_analyze", {"token": "x"}, [], ["example.com"],
    )
    assert allowed is True


def test_nmap_and_jwt_bash_are_diversion():
    assert is_diversion("kali-tools_nmap_scan_structured", {})
    assert is_diversion("bash", {"command": "python3 nx_crack.py hmac jwt rockyou"})
    assert not is_diversion("kali-tools_curl_request", {})
    assert not is_diversion("bash", {"command": "sleep 80; date -u"})


def test_queue_disabled(monkeypatch):
    monkeypatch.setenv("CCO_JS_QUEUE_ENABLED", "0")
    conn = sqlite3.connect(":memory:")
    evaluate(
        conn, "kali-tools_compose_js_routes",
        {"source": SOURCE, "target": "http://example.com"},
        [], [],
    )
    allowed, _ = evaluate(conn, "web-advanced_jwt_analyze", {}, [], ["example.com"])
    assert allowed is True


NEXUS_SOURCE = r"""
var _0x4f2a=function(){var _i=["v1","v2","auth","users","cluster","admin","probe","build","info"];return _i};
var _nx={_k:_0x4f2a(),_r:function(a,b){return "/api/"+a+"/"+b;}};
var _cmon="/api/"+_nx._k[1]+"/"+_nx._k[4]+"/"+_nx._k[7]+"-"+_nx._k[8];
var _usr="/api/"+_nx._k[1]+"/"+_nx._k[3];
getProfile: function(userId) {
  return fetch(this.api.v2.users + '/' + userId + '/profile');
}
http.defaults.headers.common["User-Agent"] = "NexusWorks-Cluster-Monitor/2.0";
var h={"Content-Type":"application/json","X-Cluster-Region":"eu"};
this.setRequestHeader("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.secret.sig");
"""


def test_header_hints_from_source_ua_and_masking():
    hints = header_hints_from_source(NEXUS_SOURCE)
    assert any("User-Agent: NexusWorks-Cluster-Monitor/2.0" in h for h in hints)
    assert any("X-Cluster-Region: eu" in h for h in hints)
    # Masked sensitive values are excluded from verbatim curl hints by design.
    assert not any(h.lower().startswith('-h "authorization') for h in hints)
    assert all("eyJhbGciOiJIUzI1NiJ9.secret.sig" not in h for h in hints), "sır plaintext"
    assert all("Bear..." not in h for h in hints), "maskeli değer hint olarak verilmemeli"


def test_gate_message_includes_header_hint():
    conn = sqlite3.connect(":memory:")
    allowed, _ = evaluate(
        conn, "kali-tools_compose_js_routes",
        {"source": NEXUS_SOURCE, "target": "http://example.com:8088"},
        [], [],
    )
    assert allowed is True
    blocked, detail = evaluate(
        conn, "web-advanced_jwt_analyze", {"token": "x"}, [], ["example.com"],
    )
    assert blocked is False
    assert "users/1/profile" in detail, "queue'daki template probe'u önerilmeli"
    assert "User-Agent: NexusWorks-Cluster-Monitor/2.0" in detail, "gate mesajı UA ipucu vermiyor"
    assert "eyJhbGciOiJIUzI1NiJ9.secret.sig" not in detail, "sır gate mesajına sızmış"
