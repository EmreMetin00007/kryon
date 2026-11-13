"""Faz 4: egress istemcisi — hop dogrulama, sayac, butce."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-validator"))

from cco_validator_core.egress import (  # noqa: E402
    egress_request, request_count, reset_request_count, scoped_wire_gate)


class _Resp:
    def __init__(self, status, text="", headers=None):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}


def _transport(routes, calls):
    def go(method, url, *, params, data, headers, timeout):
        calls.append(url)
        status, text, hdrs = routes[url]
        return _Resp(status, text, hdrs)
    return go


def test_same_host_redirect_followed_and_counted():
    reset_request_count()
    calls = []
    routes = {
        "http://lab.test/a": (302, "", {"Location": "/b"}),
        "http://lab.test/b": (200, "ok", {}),
    }
    out = egress_request("GET", "http://lab.test/a", transport=_transport(routes, calls))
    assert out["ok"] and out["status"] == 200 and out["final_url"].endswith("/b")
    assert out["requests_sent"] == 2
    assert request_count() == 2


def test_cross_host_redirect_blocked():
    reset_request_count()
    calls = []
    routes = {"http://lab.test/a": (302, "", {"Location": "http://169.254.169.254/latest"})}
    out = egress_request("GET", "http://lab.test/a", transport=_transport(routes, calls))
    assert out["blocked"] == "egress"
    assert calls == ["http://lab.test/a"], "kapsam disi hosta istek atilmamali"


def test_extra_host_allowed_and_budget_enforced():
    reset_request_count()
    calls = []
    routes = {
        "http://lab.test/a": (302, "", {"Location": "http://cdn.lab.test/b"}),
        "http://cdn.lab.test/b": (200, "ok", {}),
    }
    out = egress_request("GET", "http://lab.test/a", extra_hosts=("cdn.lab.test",),
                         transport=_transport(routes, calls))
    assert out["ok"]
    reset_request_count()
    out2 = egress_request("GET", "http://lab.test/a", request_budget=0,
                          transport=_transport(routes, calls))
    assert out2["blocked"] == "budget"


def test_no_redirect_when_disabled():
    reset_request_count()
    calls = []
    routes = {"http://lab.test/a": (302, "", {"Location": "/b"})}
    out = egress_request("GET", "http://lab.test/a", allow_redirects=False,
                         transport=_transport(routes, calls))
    assert out["status"] == 302 and out["requests_sent"] == 1


def test_scoped_redirect_cannot_change_origin_even_on_same_host():
    calls = []
    routes = {"https://lab.test/a": (302, "", {"Location": "http://lab.test/b"})}
    with scoped_wire_gate(lambda *args: (True, "allowed")):
        out = egress_request("GET", "https://lab.test/a", headers={"Cookie": "s=synthetic"},
                             transport=_transport(routes, calls), observe_session=False)
    assert out["blocked"] == "egress"
    assert calls == ["https://lab.test/a"]


def test_extra_host_redirect_never_forwards_custom_identity_headers():
    calls = []
    routes = {
        "https://lab.test/a": (302, "", {"Location": "https://cdn.lab.test/b"}),
        "https://cdn.lab.test/b": (200, "ok", {}),
    }
    out = egress_request("GET", "https://lab.test/a", extra_hosts=("cdn.lab.test",),
                         headers={"X-Custom-Credential": "synthetic"},
                         transport=_transport(routes, calls), observe_session=False)
    assert out["blocked"] == "egress"
    assert calls == ["https://lab.test/a"]
