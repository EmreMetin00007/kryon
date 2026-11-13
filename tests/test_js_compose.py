"""Deterministic JS route composer (offline, no network)."""

import json
import os
import sys

from conftest import load_server, list_tool_names

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "mcp-kali-tools"))

from cco_js_core.compose import compose_js_routes


OBFUSCATED_BUNDLE = r"""
var _0x4f2a=function(){var _i=["v1","v2","auth","users","cluster","admin","probe","build","info","register","login","profile","status"];return _i};
var _nx={_k:_0x4f2a(),_r:function(a,b){return "/api/"+a+"/"+b;}};
var _base=_nx._r(_nx._k[1],_nx._k[4]);
var _auth=_nx._r(_nx._k[1],_nx._k[2]);
var _admBase="/api/"+_nx._k[1]+"/"+_nx._k[5];
var _cmon="/api/"+_nx._k[1]+"/"+_nx._k[4]+"/"+_nx._k[7]+"-"+_nx._k[8];
_s:"/api/"+_nx._k[0]+"/"+_nx._k[11],
_reg:_auth+"/"+_nx._k[9],
_usr:"/api/"+_nx._k[1]+"/"+_nx._k[3],
_adm:_admBase+"/"+_nx._k[4]+"/"+_nx._k[6],
_mon:_cmon
getProfile: function(userId) {
  return fetch(this.api.v2.users + '/' + userId + '/profile');
}
h={"Content-Type":"application/json","X-Cluster-Region":"eu"};
"""

REACT_FETCH = r"""
export function loadUser(id) {
  return fetch(`/users/${id}/profile`);
}
const list = () => axios.get('/api/v2/users');
"""


def test_index_array_and_concat_compose_idor_template():
    out = compose_js_routes(OBFUSCATED_BUNDLE)
    concrete = set(out["composed"]) | set(out["literals"])
    assert "/api/v2/users" in concrete
    assert "/api/v2/cluster/build-info" in concrete
    assert "/api/v2/admin/cluster/probe" in concrete
    assert "/api/v2/users/{id}/profile" in out["templates"]
    assert "Content-Type" in out["headers"]
    assert "X-Cluster-Region" in out["headers"]
    assert not any(p.count("/api/") > 1 for p in out["composed"])


def test_template_literal_users_id_profile():
    out = compose_js_routes(REACT_FETCH)
    assert "/users/{id}/profile" in out["templates"]
    assert "/api/v2/users/{id}/profile" in out["templates"]


def test_quoted_literals_alone_are_not_enough_for_concat():
    quoted_only = 'const x = "/api/v2/users";'
    out = compose_js_routes(quoted_only)
    assert "/api/v2/users" in out["literals"]
    assert "/api/v2/users/{id}/profile" in out["templates"]


def test_empty_source():
    out = compose_js_routes("")
    assert out["composed"] == []
    assert out["templates"] == []


def test_kali_registers_compose_js_routes():
    names = list_tool_names(load_server("kali-tools"))
    assert "compose_js_routes" in names


def test_mcp_tool_returns_json_templates():
    mod = load_server("kali-tools")
    raw = mod.compose_js_routes(OBFUSCATED_BUNDLE, target="http://example.com:8088")
    out = json.loads(raw)
    assert "/api/v2/users/{id}/profile" in out["templates"]
    assert any(p.endswith("/api/v2/users/1/profile") for p in out["next_probes"])


def test_compose_in_web_kali_group():
    import asyncio
    import importlib.util

    path = os.path.join(REPO_ROOT, "mcp-servers", "mcp-kali-tools", "server.py")
    old = os.environ.get("CCO_KALI_GROUPS")
    os.environ["CCO_KALI_GROUPS"] = "web"
    try:
        spec = importlib.util.spec_from_file_location("cco_kali_js_group", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        names = [t.name for t in asyncio.run(mod.mcp.list_tools())]
    finally:
        if old is None:
            os.environ.pop("CCO_KALI_GROUPS", None)
        else:
            os.environ["CCO_KALI_GROUPS"] = old
    assert "compose_js_routes" in names
    assert "linkfinder_scan" in names
    assert "nmap_scan" not in names
