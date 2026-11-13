"""Tests for Browser/MITM → Session Vault + Attack Surface + Business-Logic Chain Executor bridge."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

from conftest import load_server

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))


class _AllowGate:
    def validate_tool_invocation(self, tool_name, args=None, **kwargs):
        return {"allowed": True}


def test_sync_browser_cookies_writes_both_vault_and_jar(tmp_path):
    from workflow_compiler import sync_browser_cookies_to_vault

    mem_dir = str(REPO_ROOT / "mcp-servers" / "mcp-memory-server")
    val_dir = str(REPO_ROOT / "mcp-servers" / "mcp-validator")
    for d in (mem_dir, val_dir):
        if d not in sys.path:
            sys.path.insert(0, d)
    from cco_surface_core import session_store
    from cco_validator_core.egress import load_shared_session

    cookies = [
        {"name": "sid", "value": "SUPER_SECRET_SID", "domain": ".shop.example.test"},
        {"name": "csrf", "value": "CSRF_VAL", "domain": "shop.example.test"},
    ]
    summary = sync_browser_cookies_to_vault(
        cookies,
        default_url="https://shop.example.test/cart",
        headers={"X-HackerOne-Research": "researcher1"},
        identity="agent_browse",
        source="agent_browse",
        cco_home=str(tmp_path),
    )
    assert "SUPER_SECRET_SID" not in json.dumps(summary)
    assert summary["hosts"] == ["shop.example.test"]
    assert summary["cookie_keys"] == ["csrf", "sid"]
    assert summary["vault_synced"] == 1
    assert summary["jar_synced"] == 1

    vault_entry = session_store.get_session("shop.example.test", "agent_browse", home=str(tmp_path))
    assert vault_entry is not None
    assert vault_entry["cookies"]["sid"] == "SUPER_SECRET_SID"

    jar_entry = load_shared_session("shop.example.test", cco_home=str(tmp_path))
    assert jar_entry is not None
    assert "sid=SUPER_SECRET_SID" in jar_entry["cookie"]


def _cart_coupon_traffic():
    return [
        {
            "method": "GET",
            "url": "http://shop.test/api/cart",
            "status": 200,
            "resp_body": '{"total": 100, "status": "pending"}',
        },
        {
            "method": "POST",
            "url": "http://shop.test/api/cart/coupon",
            "status": 200,
            "req_body": '{"coupon": "SAVE10", "discount": 10}',
            "resp_body": '{"total": 90}',
        },
        {
            "method": "POST",
            "url": "http://shop.test/api/cart/confirm",
            "status": 200,
            "req_body": '{"confirm": true}',
            "resp_body": '{"status": "paid"}',
        },
    ]


def _cart_sender(applies):
    state = {"total": 100, "applies": 0}

    def sender(method, url, headers, body, timeout):
        if method == "POST":
            state["applies"] += 1
            if state["applies"] <= applies:
                state["total"] -= 10
            return {"ok": True, "status": 200, "len": 11, "text": '{"ok":true}',
                    "headers": {}, "location": "", "error": None}
        return {"ok": True, "status": 200, "len": 20,
                "text": json.dumps({"total": state["total"], "status": "pending"}),
                "headers": {}, "location": "", "error": None}

    return sender


def test_new_manifest_kinds_cover_low_level_logic():
    from action_manifest import validate_manifest
    from workflow_compiler import compile_workflow_manifests
    from lab.business_logic_lab import KINDS, LogicLab

    kinds = set()
    for kind in KINDS:
        lab = LogicLab(vulnerable=True)
        urls = {role: lab.setup(kind, role) for role in ('control', 'probe')}
        manifests = compile_workflow_manifests(lab.capture(kind, urls, session_id='s'))
        assert len(manifests) == 1
        manifest = manifests[0]
        kinds.add(manifest['kind'])
        check = validate_manifest(manifest)
        assert check['valid'], check['errors']
        assert check['manifest_hash'] == manifest['manifest_hash']
        assert manifest['business_logic']['contract']['alternative_explanation']
    assert kinds == set(KINDS)
    assert 'race_replay' not in kinds


def test_redacted_traffic_does_not_produce_executable_workflows():
    from workflow_compiler import compile_workflow_manifests

    redacted = [{**item, "capture_redacted": True, "req_body": "", "resp_body": ""}
                for item in _cart_coupon_traffic()]
    assert compile_workflow_manifests(redacted, target_ref="shop.test") == []


def test_idempotency_replay_fires_on_double_effect(tmp_path):
    from test_p7_business_logic import write_validate

    for vulnerable in (False, True):
        result = write_validate.run_scenario('idempotency_replay',
            db_path=str(tmp_path / ('bug.db' if vulnerable else 'safe.db')),
            run_id='r', session_id='s', vulnerable=vulnerable)
        assert result['validated_effect'] is vulnerable
        assert result['steps_executed'][-1]['oracle_detail']['normal_control_passed']


def test_offset_to_zero_computes_exact_quantity():
    # A price delta without an evidenced business rule cannot justify a write.
    from workflow_compiler import compile_workflow_manifests
    captured = [
        {'method': 'GET', 'url': 'http://shop.test/api/cart',
         'status': 200, 'resp_body': '{"total": 1337.0}'},
        {'method': 'POST', 'url': 'http://shop.test/api/cart',
         'status': 200, 'req_body': '{"productId": 2, "quantity": 1}'},
        {'method': 'GET', 'url': 'http://shop.test/api/cart',
         'status': 200, 'resp_body': '{"total": 1407.34}'},
    ]
    gaps = []
    assert compile_workflow_manifests(captured, diagnostics=gaps) == []
    assert gaps == [{'status': 'missing_prerequisite', 'reason': 'unobserved_context',
                     'url': 'http://shop.test/api/cart'}]


def test_offset_to_zero_needs_measured_unit_price():
    from workflow_compiler import compile_workflow_manifests

    captured = [
        {"method": "POST", "url": "http://shop.test/api/cart",
         "status": 200, "req_body": '{"productId": 2, "quantity": 1}'},
    ]
    manifests = compile_workflow_manifests(captured, target_ref="shop.test")
    assert [m for m in manifests if m["kind"] == "offset_to_zero"] == []


def test_collapsed_rule_bounds():
    from chain_executor import _eval_state_invariant

    before = {"b": {"ok": True, "status": 200, "fulltext": '{"total": 1407.34}'}}
    ok, detail = _eval_state_invariant(
        {"before_step": "b", "numeric_field": "total", "rule": "collapsed",
         "threshold": 70.34},
        {"ok": True, "status": 200, "fulltext": '{"total": 0.54}'},
        before,
    )
    assert ok is True
    assert detail["violations"][0].startswith("numeric_collapsed:")

    ok_high, _ = _eval_state_invariant(
        {"before_step": "b", "numeric_field": "total", "rule": "collapsed",
         "threshold": 70.34},
        {"ok": True, "status": 200, "fulltext": '{"total": 900}'},
        before,
    )
    assert ok_high is False

    ok_neg, _ = _eval_state_invariant(
        {"before_step": "b", "numeric_field": "total", "rule": "collapsed",
         "threshold": 70.34},
        {"ok": True, "status": 200, "fulltext": '{"total": -5}'},
        before,
    )
    assert ok_neg is False


def test_stable_rule_negative_and_positive():
    from chain_executor import _eval_state_invariant

    before = {"b": {"ok": True, "status": 200, "fulltext": '{"total": 90}'}}
    ok, detail = _eval_state_invariant(
        {"before_step": "b", "numeric_field": "total", "rule": "stable"},
        {"ok": True, "status": 200, "fulltext": '{"total": 80}'},
        before,
    )
    assert ok is True
    assert detail["violations"] == ["numeric_changed:total:90.0->80.0"]

    ok2, detail2 = _eval_state_invariant(
        {"before_step": "b", "numeric_field": "total", "rule": "stable"},
        {"ok": True, "status": 200, "fulltext": '{"total": 90}'},
        before,
    )
    assert ok2 is False
    assert detail2["violations"] == []


def test_race_replay_manifest_is_approval_gated():
    # Capture compilation no longer invents concurrent writes from a coupon name.
    from workflow_compiler import compile_workflow_manifests
    gaps = []
    manifests = compile_workflow_manifests(_cart_coupon_traffic(), diagnostics=gaps)
    assert manifests == []
    assert all(g['status'] == 'missing_prerequisite' for g in gaps)


def test_compile_and_execute_business_logic_chains_with_state_invariant(tmp_path):
    from test_p7_business_logic import write_validate
    from lab.business_logic_lab import KINDS

    for kind in KINDS:
        result = write_validate.run_scenario(kind, db_path=str(tmp_path / (kind + '.db')),
            run_id='r', session_id='s', vulnerable=True)
        assert result['success'], result
        assert result['steps_executed'][-1]['oracle'] == 'business_logic'
        assert result['steps_executed'][-1]['oracle_detail']['violation_effect_observed']


def test_agent_browse_harvest_ingests_traffic_and_writes_manifests(tmp_path):
    import agent_browse

    traffic_file = tmp_path / "scope-traffic.jsonl"
    traffic_file.write_text(
        json.dumps({
            "method": "GET",
            "url": "https://app.example.test/api/cart",
            "status": 200,
            "req_headers": {},
            "req_body": "",
            "resp_body": '{"total": 50}',
        }) + "\n"
        + json.dumps({
            "method": "POST",
            "url": "https://app.example.test/api/cart/coupon",
            "status": 200,
            "req_headers": {"Content-Type": "application/json"},
            "req_body": '{"coupon": "SAVE10", "discount": 10, "api_key": "SECRET_KEY"}',
            "resp_body": '{"total": 40}',
        }) + "\n",
        encoding="utf-8",
    )

    out_dir = tmp_path / "evidence"
    out_dir.mkdir()
    harvest = agent_browse.harvest_agent_run(
        cookies=[{"name": "auth_sid", "value": "SID123", "domain": "app.example.test"}],
        start_url="https://app.example.test/cart",
        steps=[{"step": 1, "url": "https://app.example.test/cart", "title": "Cart"}],
        headers={"X-HackerOne-Research": "tester"},
        out=out_dir,
        traffic_offset=0,
        cco_home=str(tmp_path),
    )

    assert harvest["session_synced"]["vault_synced"] == 1
    assert harvest["surface_ingested"]["inserted"] >= 2
    assert harvest["workflow_manifests_count"] == 0
    assert harvest["workflow_manifests_path"] == ''
    assert harvest['workflow_missing_prerequisites']
    assert 'SECRET_KEY' not in json.dumps(harvest)

    conn = sqlite3.connect(tmp_path / "agent_memory.db")
    row = conn.execute(
        "SELECT params_json FROM attack_surface WHERE url='https://app.example.test/api/cart/coupon'"
    ).fetchone()
    conn.close()
    assert row is not None
    params = {p["name"]: p["sample"] for p in json.loads(row[0])}
    assert params["coupon"] == "SAVE10"
    assert params["api_key"] == "<redacted>"


def test_hunter_generate_abuse_cases_emits_executable_manifests():
    # Historical test ID retained; synthetic executable manifests are now forbidden.
    hunter = load_server('hunter')
    out = json.loads(hunter.generate_abuse_cases(target='shop.example.test',
        endpoint='https://shop.example.test/api/checkout', params='price,quantity,coupon',
        context='e-commerce checkout'))
    assert out['abuse_cases']
    assert out['status'] == 'draft_hypothesis'
    assert out['runnable'] is False and out['confirmed'] is False
    assert out['observed_context'] is None and out['executable_manifests'] == []
    assert all(case['status'] == 'draft_hypothesis' and not case['runnable']
               for case in out['abuse_cases'])


def test_state_invariant_negative_controls_and_shared_session_forwarding(tmp_path, monkeypatch):
    from chain_executor import ChainExecutor, _eval_state_invariant
    from workflow_compiler import sync_browser_cookies_to_vault

    monkeypatch.setenv("CCO_HOME", str(tmp_path))

    # 1) Non-2xx after_step must not trigger false positive
    ok_401, detail_401 = _eval_state_invariant(
        {"before_step": "b", "numeric_field": "total", "rule": "decreased"},
        {"ok": True, "status": 401, "fulltext": '{"total": 0}'},
        {"b": {"ok": True, "status": 200, "fulltext": '{"total": 100}'}},
    )
    assert ok_401 is False
    assert detail_401.get("skipped_reason") == "after_step_not_2xx_json"

    # 2) Optional field None -> False must not trigger readonly_mutated false positive
    ok_opt, _ = _eval_state_invariant(
        {"before_step": "b", "mutated_fields": ["is_admin"]},
        {"ok": True, "status": 200, "fulltext": '{"id": 1, "is_admin": false}'},
        {"b": {"ok": True, "status": 200, "fulltext": '{"id": 1}'}},
    )
    assert ok_opt is False

    # 3) Shared session synced by workflow_compiler is automatically used by ChainExecutor
    sync_browser_cookies_to_vault(
        [{"name": "sid", "value": "SYNCED_COOKIE", "domain": "shop.test"}],
        default_url="http://shop.test/api/cart",
        headers={"X-Research": "r1"},
        cco_home=str(tmp_path),
    )
    seen_headers: list[dict] = []

    def inspecting_sender(method, url, headers, body, timeout):
        seen_headers.append(dict(headers))
        return {"ok": True, "status": 200, "len": 11, "text": '{"ok":true}', "headers": {}, "location": "", "error": None}

    manifest = {
        "schema_version": "action-manifest/1.0",
        "objective": "session forwarding check",
        "target_ref": "shop.test",
        "risk": "active_read_only",
        "budget": {"max_requests": 3, "max_duration_seconds": 15},
        "identity_refs": [],
        "steps": [
            {
                "id": "check-session",
                "tool": "http_get",
                "args": {"url": "http://shop.test/api/cart"},
                "expect": {"oracle": "status_code", "status": [200]},
                "on_success": "succeed",
                "on_failure": "fail",
            }
        ],
    }
    res = ChainExecutor(policy_engine=_AllowGate(), sender=inspecting_sender).execute(manifest)
    assert res["success"] is True
    assert seen_headers
    assert "sid=SYNCED_COOKIE" in seen_headers[0].get("Cookie", "")
    assert seen_headers[0].get("X-Research") == "r1"


def test_harvest_allowlist_filters_out_of_scope_hosts(tmp_path):
    import agent_browse

    traffic_file = tmp_path / "scope-traffic.jsonl"
    traffic_file.write_text(
        json.dumps({"method": "GET", "url": "https://app.example.test/api/cart",
                    "status": 200, "resp_body": '{"total": 50}'}) + "\n"
        + json.dumps({"method": "POST", "url": "https://app.example.test/api/cart/coupon",
                      "status": 200, "req_body": '{"coupon": "SAVE10"}',
                      "resp_body": '{"total": 40}'}) + "\n"
        + json.dumps({"method": "GET", "url": "https://evil.example.net/steal",
                      "status": 200, "resp_body": '{"x": 1}'}) + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "evidence"
    out_dir.mkdir()
    harvest = agent_browse.harvest_agent_run(
        cookies=[
            {"name": "sid", "value": "IN_SCOPE", "domain": "app.example.test"},
            {"name": "sid", "value": "OUT_OF_SCOPE", "domain": "evil.example.net"},
        ],
        start_url="https://app.example.test/cart",
        steps=[
            {"step": 1, "url": "https://app.example.test/cart", "title": "cart"},
            {"step": 2, "url": "https://evil.example.net/steal", "title": "evil"},
        ],
        headers={"X-HackerOne-Research": "tester"},
        out=out_dir,
        traffic_offset=0,
        cco_home=str(tmp_path),
        allow={"app.example.test"},
    )
    assert harvest["allow_filtered"] >= 2  # 1 trafik + 1 step
    assert harvest["session_synced"]["hosts"] == ["app.example.test"]
    assert harvest["session_synced"]["filtered_out"] == 1
    assert harvest['workflow_manifests_count'] == 0
    assert not (out_dir / 'workflow_manifests.json').exists()
    assert all('evil.example.net' not in g.get('url', '')
               for g in harvest['workflow_missing_prerequisites'])
    conn = sqlite3.connect(tmp_path / "agent_memory.db")
    row = conn.execute(
        "SELECT COUNT(*) FROM attack_surface WHERE url LIKE '%evil.example.net%'"
    ).fetchone()
    conn.close()
    assert row[0] == 0


def test_compile_manifests_keeps_distinct_body_variants():
    from workflow_compiler import compile_workflow_manifests
    from lab.business_logic_lab import LogicLab

    lab = LogicLab(vulnerable=True)
    urls = {role: lab.setup('idempotency_replay', role) for role in ('control', 'probe')}
    captured = lab.capture('idempotency_replay', urls, session_id='s')
    second = next(r for r in captured if r['observed_context']['capture_id'] == 'probe-2')
    body = json.loads(second['req_body']); body['coupon'] = 'P7-TWO'; body['sibling'] = 'preserve'
    second['req_body'] = json.dumps(body)
    manifests = compile_workflow_manifests(captured)
    assert len(manifests) == 1
    actions = [s for s in manifests[0]['steps'] if s['id'].startswith('probe-action-')]
    assert [s['args']['body']['coupon'] for s in actions] == ['P7-ONE', 'P7-TWO']
    assert actions[1]['args']['body']['sibling'] == 'preserve'
