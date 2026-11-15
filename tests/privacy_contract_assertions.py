"""Assertion-only observation of the host/public boundary; no changed traffic."""
import copy
import hashlib
import json
from typing import Any


def capture_operational_report(hunter, monkeypatch):
    """Observe the producer before projection, without changing its return value.

    Ordinary direct Hunter tests have no broker invocation. Signed producer and
    receipt bindings are independently checked by the private-boundary wrappers
    and real-loopback tests; this hook does not synthesize or hydrate evidence.
    """
    from cco_hunter_core import request_context
    original = request_context.public_discovery_report
    captured: dict[str, Any] = {}

    def observe(value, *args, **kwargs):
        if (isinstance(value, dict) and "requests_authorized" in value
                and any(isinstance(state, dict) and state.get("identity_ref")
                        and not str(state["identity_ref"]).startswith("opaque:")
                        for state in value.get("identity_discovery_state", {}).values())):
            operational = copy.deepcopy(value)
            captured.clear()
            captured.update(operational)
        return original(value, *args, **kwargs)

    monkeypatch.setattr(request_context, "public_discovery_report", observe)
    return captured


def assert_route_contract(public, private, expected, *, private_values=()):
    """Keep exact object/control equality privately; public hashes cannot alias.

    expected maps each original operational URL to (owner, attacker, verdict).
    No URL template, unsigned flag, or mere observation gives validation credit.
    """
    from cco_validator_core import artifact_is_current, load_validation
    from python_candidate_runtime import authorization_controls_complete
    import python_identity_discovery as discovery

    assert private
    # Artifact annotations are appended after the operational projection; they
    # carry no executable route or control data (the producer does the same).
    private.update({key: public[key] for key in ("artifact", "artifact_error") if key in public})
    assert discovery.public_export(private) == public
    text = json.dumps(public)
    for value in (*expected, *private_values):
        assert value not in text
    private_rows = {row["url"]: row for row in private["validations"]}
    public_rows = {row["url_sha256"]: row for row in public["validations"]}
    assert len(private_rows) == len(private["validations"]) == len(expected)
    assert len(public_rows) == len(public["validations"]) == len(expected)
    assert set(private_rows) == set(expected)
    assert set(public_rows) == {hashlib.sha256(url.encode()).hexdigest() for url in expected}
    queue = private["validation_queue"]
    assert len(queue) == len(expected)
    assert {discovery.queue_key(row) for row in queue} == {
        discovery.queue_key(row) for row in private_rows.values()}
    for url, (owner, attacker, verdict) in expected.items():
        row = private_rows[url]
        projected = public_rows[hashlib.sha256(url.encode()).hexdigest()]
        assert row["resource_owner"] == projected["resource_owner"] == owner
        assert row["identity"] == projected["identity"] == attacker
        assert owner != attacker
        assert row["method"] == projected["method"] == "GET"
        assert row["validation_id"] == projected["validation_id"]
        assert projected["url"] != url and "{value}" in projected["url"]
        assert any(word in projected["url"] for word in ("/orders/", "/objects/"))
        record = load_validation(row["validation_id"])
        assert record and artifact_is_current(record)
        assert record["target"] == url
        assert record["verdict"] == verdict
        if "verdict" in row:
            assert row["verdict"] == projected["verdict"] == verdict
        assert discovery.queue_key(record["execution_context"]) == discovery.queue_key(row)
        assert authorization_controls_complete(record)
    for field in ("discovery_operations", "validation_candidates", "validation_queue"):
        if field not in private:
            continue
        assert len(public[field]) == len(private[field])
        assert {row["url_sha256"] for row in public[field]} == {
            hashlib.sha256(row["url"].encode()).hexdigest() for row in private[field]}
    for name, card in public.get("identity_discovery_state", {}).items():
        assert card["role"] == "member" and card["identity_ref"].startswith("opaque:")
        assert card["request_binding"] == discovery.public_state(private["identity_discovery_state"])[name]["request_binding"]
        assert "identity_facts" not in card
    return public_rows
