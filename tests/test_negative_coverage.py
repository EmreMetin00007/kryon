"""Completed negative controls through real validators, signed coverage and scoring.

Cases are explicitly operator-selected: this does not measure blind discovery.
The lab handler runs in memory and every HTTP adapter request remains gated.
"""
import importlib.util
import json
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit

import pytest
import requests

from conftest import load_server
from test_campaign_gap_bridge import BASE, setup  # noqa: F401


def scorer():
    path = Path(__file__).resolve().parents[1] / "scripts/blind-validate.py"
    spec = importlib.util.spec_from_file_location("negative_coverage_score", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def lab_transport(monkeypatch, handler, *, fault=None):
    calls = []

    def send(method, url, **kwargs):
        assert method == "GET" and url.startswith(BASE)
        assert (kwargs.get("headers") or {}).get("X-Research") == "researcher"
        assert kwargs["allow_redirects"] is False
        if kwargs.get("params"):
            url += ("&" if "?" in url else "?") + urlencode(kwargs["params"], doseq=True)
        parsed = urlsplit(url)
        calls.append(url)
        if fault is not None and len(calls) == 3:
            status = fault
            if status == "transport":
                raise requests.ConnectionError("synthetic failed control")
            body = "unavailable"
        else:
            instance = handler.__new__(handler)
            relative = parsed.path.removeprefix("/allowed")
            instance.path = urlunsplit(("", "", relative, parsed.query, ""))
            instance.headers = kwargs.get("headers") or {}
            captured = []
            instance._send = lambda code, body, ctype="text/html", extra=None: captured.append((code, body, ctype, extra))
            instance.do_GET()
            status, body, ctype, extra = captured[0]
        response = requests.Response()
        response.url, response.encoding, response._content_consumed = url, "utf-8", True
        response.status_code = status
        response._content = body.encode() if isinstance(body, str) else body
        if fault is not None and len(calls) == 3:
            response.headers["Content-Type"] = "text/plain"
        else:
            response.headers.update({"Content-Type": ctype, **(extra or {})})
            # The handler is mounted below /allowed, so root-relative redirect
            # paths must be mounted there too. Preserve external destinations.
            location = response.headers.get("Location", "")
            if location.startswith("/") and not location.startswith("//"):
                response.headers["Location"] = "/allowed" + location
        return response

    monkeypatch.setattr(requests, "request", send)
    return calls


def test_operator_selected_lab_negatives_count_only_completed_controls(setup, monkeypatch, tmp_path):
    from scripts.lab.blind_lab import make_lab
    from scripts.lab.blind_agent_run import benchmark_payload

    hunter, _, _, _, policy = setup
    # Like the existing synthetic blind regression, allow this finite repeated
    # validator corpus to finish; production repeat/rate gates remain unchanged.
    monkeypatch.setenv("CCO_STUCK_THRESHOLD", "10000")
    handler, state = make_lab(20261104)
    try:
        cases = [row for row in state["truth"] if row["expected"] == "negative"]
        # This is an explicit validator contract; truth never enters the blind
        # solver. Paths and account/resource declarations are operator inputs.
        params = {"sql_injection": ("id", "1"), "xss_reflected": ("q", "laptop"),
                  "ssti": ("name", "guest"), "open_redirect": ("next", "/"),
                  "path_traversal": ("name", "notes.txt")}
        queue = []
        for case in cases:
            url = BASE + case["path"].lstrip("/")
            param, value = params.get(case["class"], ("", ""))
            queue.append({"url": url + ("?" + urlencode({param: value}) if param else ""),
                          "method": "GET", "param": param, "location": "query",
                          "vuln_class": case["class"], "authz_candidate": not bool(param)})
        file_marker = "root:x:0:0:synthetic:/root:/bin/bash"
        current = json.loads(policy.read_text())
        current["path_traversal"] = {"mode": "application_files", "files": [{
            "url": BASE + "safe/file", "param": "name", "carrier": "query",
            "path": "../secret.txt", "marker": file_marker, "test_data_only": True, "outside_root": True}]}
        policy.write_text(json.dumps(current))
        ids = {name: {"headers": {"Authorization": "Bearer " + account["token"]},
                      "role": account["role"], "test_data_only": True}
               for name, account in state["accounts"].items()}
        order_case = next(row for row in cases if row["class"] == "bola")
        oid = order_case["path"].rsplit("/", 1)[1]
        ids["member-a"]["objects"] = [{"url": BASE + "orders/" + oid, "marker": state["orders"][oid]["marker"]}]
        ids["admin-a"]["functions"] = [{"url": BASE + "admin/users", "marker": "member-b",
            "test_data_only": True, "denied_roles": ["member"]}]
        ids["member-a"]["protected_resources"] = [{"url": BASE + "account/settings",
            "marker": "member-a", "test_data_only": True, "authentication_required": True}]
        monkeypatch.setattr(hunter, "_loop_discover", lambda *a, **kw: {"ok": True})
        monkeypatch.setattr(hunter, "_loop_fuzz", lambda *a, **kw: {"probes": 0, "validator_queue": queue})
        calls = lab_transport(monkeypatch, handler)
        result = json.loads(hunter.run_web_loop(BASE, live=True, crawl=False,
            identities=json.dumps(ids), headers='{"X-Research":"researcher"}',
            max_validations=8, sleep_s=0))
        assert result["ok"], {key: result.get(key) for key in ("errors", "stopped", "skipped", "requests_authorized")}
        assert len(result["validations"]) == 8, result["validations"]
        assert result["requests_authorized"] == len(calls)
        exported = benchmark_payload(hunter, result, BASE)
        events = exported["verified_coverage"]
        assert len(events) == 8
        clean = [event for event in events if event["status"] == "tested_clean"]
        incomplete = [event for event in events if event["status"] == "inconclusive"]
        assert len(clean) == 7 and len(incomplete) == 1
        # The unchanged safe redirect handler accepts /\host/ and redirects
        # to a missing local route. That 404 cannot earn completed-control credit.
        assert incomplete[0]["vuln_class"] == "open_redirect"
        truth = [{**row, "path": "/allowed" + row["path"]} for row in cases]
        score = scorer().evaluate(truth, result, verified_coverage=events)
        assert score["negatives_clean"] == score["negatives_evaluated"] == 7
        assert score["negatives_inconclusive"] == 1
        assert score["negative_coverage"] == 7 / 8 and score["fp_rate"] == 0
        assert all(row["validation_ids"] for row in score["cases"])
        ids = {event["validation_id"] for event in events}
        completed_feedback = [row for row in result["feedback_queue"] if row.get("validation_id") in ids]
        assert len(completed_feedback) == 8
        assert sum(row["status"] == "tested_no_violation" for row in completed_feedback) == 7
        assert sum(row["status"] == "inconclusive" for row in completed_feedback) == 1
        for event in clean:
            record = hunter._validator_mod.load_validation(event["validation_id"])
            assert record["guard"]["transport_ok"] and record["request_evidence"]
            assert all(not row["excerpt"] for row in record["request_evidence"])
        assert all(account["token"] not in json.dumps(exported) for account in state["accounts"].values())
        # Deleted evidence must lose clean credit on re-export, even when the
        # SQLite event and submitted report still say UNCONFIRMED/tested_clean.
        removed = hunter._validator_mod.load_validation(clean[0]["validation_id"])
        Path(removed["artifact"]["path"]).unlink()
        after = benchmark_payload(hunter, result, BASE)
        after_score = scorer().evaluate(truth, result, verified_coverage=after["verified_coverage"])
        assert after_score["negatives_evaluated"] == 6
        assert after_score["negatives_inconclusive"] == 1
        (tmp_path / "negative-controls.json").write_text(json.dumps({
            "mode": "operator_selected_in_memory_validator_contract", "seed": 20261104,
            "requests": len(calls), "score": score}, indent=2))
    finally:
        state["db"].close()


@pytest.mark.parametrize("invalidate", [None, "scope", "policy", "artifact", "event_signature", "repeat_gate",
                                        "unobserved_redirect"])
def test_completed_redirect_rejections_have_signed_clean_coverage(setup, monkeypatch, invalidate):
    hunter, _, _, scope, policy = setup
    if invalidate != "repeat_gate":
        # As in the finite operator-selected corpus above, let this bounded
        # thirteen-request validator finish. The separate default-gate case
        # must stop and retain inconclusive coverage instead of clean credit.
        monkeypatch.setenv("CCO_STUCK_THRESHOLD", "10000")
    calls = []

    def reject(method, url, **kwargs):
        from urllib.parse import parse_qs
        assert method == "GET" and url.startswith(BASE)
        assert kwargs["allow_redirects"] is False
        assert kwargs["headers"]["X-Research"] == "researcher"
        calls.append(url)
        response = requests.Response()
        # A valid observed request must succeed; only the external redirect
        # mutations are rejected. An all-400 fixture has no usable baseline.
        benign = parse_qs(urlsplit(url).query).get("next") == ["/"]
        response.url, response.status_code = url, 200 if benign else 400
        response._content = b"home" if benign else b"invalid redirect"
        response.encoding, response._content_consumed = "utf-8", True
        response.headers["Content-Type"] = "text/plain"
        if not benign and invalidate == "unobserved_redirect":
            response.status_code = 302
            response.headers["Location"] = "https://outside.test/unobserved"
        return response

    monkeypatch.setattr(requests, "request", reject)
    item = {"url": BASE + "safe/go?next=/", "method": "GET", "param": "next", "location": "query",
            "vuln_class": "open_redirect", "run_id": "completed-redirect", "identity": "anonymous"}
    raw = hunter._loop_validate(item, headers='{"X-Research":"researcher"}')
    result = json.loads(raw) if isinstance(raw, str) else raw
    if invalidate in {"repeat_gate", "unobserved_redirect"}:
        assert result["verdict"] == "INCONCLUSIVE"
        assert 0 < len(calls) < 13 if invalidate == "repeat_gate" else len(calls) == 13
        assert not result["guard"]["transport_ok"]
        assert sum(row["transport_ok"] for row in result["request_evidence"]) == len(calls)
        assert hunter._record_coverage_validation(BASE, item, result)
        assert [row["status"] for row in hunter._verified_coverage_events(BASE)] == ["inconclusive"]
        return
    assert result["verdict"] == "UNCONFIRMED" and len(calls) == 13, (result, calls)
    assert [row["role"] for row in result["request_evidence"]].count("baseline") == 1
    assert [row["role"] for row in result["request_evidence"]].count("negative-control") == 6
    assert [row["status"] for row in result["request_evidence"]].count(400) == 6
    assert result["guard"]["transport_ok"] and len(result["request_evidence"]) == len(calls)
    assert hunter._record_coverage_validation(BASE, item, result)
    events = hunter._verified_coverage_events(BASE)
    assert len(events) == 1 and events[0]["status"] == "tested_clean"
    assert not hunter._record_coverage_validation(BASE, {**item, "run_id": "other-run"}, result)
    assert not hunter._record_coverage_validation(BASE, {**item, "url": BASE + "other?next=/"}, result)
    if invalidate in {"scope", "policy"}:
        path = scope if invalidate == "scope" else policy
        path.write_text(path.read_text() + "\n")
    elif invalidate == "artifact":
        path = Path(result["artifact"]["path"])
        stored = json.loads(path.read_text())
        stored["guard"]["transport_ok"] = False
        path.write_text(json.dumps(stored))
    elif invalidate == "event_signature":
        import sqlite3
        with sqlite3.connect(hunter.MEM_DB) as conn:
            row = conn.execute("SELECT id,signed_json FROM hunter_coverage_events").fetchone()
            signed = json.loads(row[1])
            signed["payload"]["status"] = "confirmed"
            conn.execute("UPDATE hunter_coverage_events SET signed_json=? WHERE id=?", (json.dumps(signed), row[0]))
    if invalidate:
        assert hunter._verified_coverage_events(BASE) == []


@pytest.mark.parametrize("status", [400, 422, 403, 404, 503])
def test_redirect_rejection_without_successful_baseline_stays_inconclusive(setup, monkeypatch, status):
    hunter, *_ = setup
    calls = []

    def reject(method, url, **kwargs):
        assert kwargs["allow_redirects"] is False and url.startswith(BASE)
        calls.append(url)
        response = requests.Response()
        response.url, response.status_code, response._content = url, status, b"baseline unavailable"
        response.encoding, response._content_consumed = "utf-8", True
        response.headers["Content-Type"] = "text/plain"
        return response

    monkeypatch.setattr(requests, "request", reject)
    item = {"url": BASE + "safe/go?next=/", "method": "GET", "param": "next", "location": "query",
            "vuln_class": "open_redirect", "run_id": "invalid-baseline", "identity": "anonymous"}
    result = json.loads(hunter._loop_validate(item, headers='{"X-Research":"researcher"}'))
    assert result["verdict"] == "INCONCLUSIVE" and len(calls) == 1
    assert not result["guard"]["transport_ok"]
    assert hunter._record_coverage_validation(BASE, item, result)
    assert [row["status"] for row in hunter._verified_coverage_events(BASE)] == ["inconclusive"]


@pytest.mark.parametrize("kind,path,param,value", [
    ("sql_injection", "safe/item", "id", "1"), ("ssti", "safe/hello", "name", "guest"),
    ("xss_reflected", "safe/search", "q", "laptop"), ("open_redirect", "safe/go", "next", "/")])
@pytest.mark.parametrize("status", ["transport", 429, 503, 404, 403])
def test_failed_controls_never_receive_negative_coverage(setup, monkeypatch, kind, path, param, value, status):
    from scripts.lab.blind_lab import make_lab

    hunter, *_ = setup
    handler, state = make_lab(20261104)
    try:
        calls = lab_transport(monkeypatch, handler, fault=status)
        # Single-request XSS and redirect probes must also reject their first
        # failed response, rather than depend on three calls being made.
        if kind == "xss_reflected":
            original = requests.request
            original("GET", BASE + "safe/search?q=warmup", headers={"X-Research": "researcher"}, allow_redirects=False)
            original("GET", BASE + "safe/search?q=warmup", headers={"X-Research": "researcher"}, allow_redirects=False)
        item = {"url": BASE + path + "?" + urlencode({param: value}), "method": "GET",
                "param": param, "location": "query", "vuln_class": kind,
                "run_id": "failed-control", "identity": "anonymous"}
        raw = hunter._loop_validate(item, headers='{"X-Research":"researcher"}')
        result = json.loads(raw) if isinstance(raw, str) else raw
        assert result["verdict"] == "INCONCLUSIVE" and calls
        assert not result["guard"]["transport_ok"]
        assert hunter._record_coverage_validation(BASE, item, result)
        assert all(row["status"] != "tested_clean" for row in hunter._verified_coverage_events(BASE))
    finally:
        state["db"].close()


@pytest.mark.parametrize("status", [None, 429, 503])
def test_failed_malformed_ssti_control_cannot_confirm(setup, monkeypatch, status):
    import re
    validator = load_server("validator")

    def send(url, payload, **kwargs):
        match = re.search(r"(\d+)\*(\d+)", payload)
        malformed = payload.endswith("*}}")
        body = str(int(match[1]) * int(match[2])) if match and payload.startswith("{{") else "literal"
        return {"ok": status is not None if malformed else True,
                "status": status if malformed else 200, "text": body, "len": len(body),
                "request_method": "GET", "final_url": url}

    monkeypatch.setattr(validator, "_send_payload", send)
    result = json.loads(validator.validate_ssti(BASE + "hello?name=guest", param="name"))
    assert result["verdict"] == "INCONCLUSIVE" and not result["reportable"]
