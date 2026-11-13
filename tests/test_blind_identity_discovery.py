"""Blind discovery follows observed links and keeps account data in memory."""
import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-hunter"))
sys.path.insert(0, str(ROOT / "mcp-servers" / "mcp-memory-server"))
from cco_hunter_core.blind_discovery import discover_owned_resources  # noqa: E402

BASE = "https://owned.test/allowed/"
IDS = {"alice": "d94e5fbb-862f-4a15-a811-4252eb9fccb5",
       "bob": "602532ac-42ba-4cc4-851e-326b4ed0ea91"}


def _identities(private=True):
    return {name: {"headers": {"Cookie": f"session={name}-secret", "X-Research": "researcher"},
                   "role": "member", "test_data_only": True, "owned_objects_private": private}
            for name in IDS}


def _fixture_transport(calls, *, owner_overrides=None, status_overrides=None):
    owner_overrides = owner_overrides or {}
    status_overrides = status_overrides or {}
    def fetch(url, headers):
        actor = next(name for name in IDS if headers["Cookie"] == f"session={name}-secret")
        calls.append((actor, url))
        status = status_overrides.get((actor, url), 200)
        if status != 200:
            return {"ok": True, "status": status, "text": ""}
        if url == BASE:
            body = {"current_user": {"id": f"{actor}-subject"}, "links": [
                {"href": "/allowed/orders"}, {"href": "https://evil.test/steal"},
                {"href": "/outside"}, {"href": "/allowed/logout"}, {"href": "/allowed/login"},
                {"href": "/allowed/%256cogout"}, {"href": "/allowed/orders?%2564elete=1"},
                {"href": "/allowed/orders?%2574oken=secret"},
                {"href": "/allowed/orders?delete=1"}, {"href": "/allowed/orders?token=secret"}]}
        elif url == BASE + "orders":
            body = {"results": [{"href": f"/allowed/orders/{IDS[actor]}"}]}
        else:
            body = {"id": IDS[actor], "owner_id": owner_overrides.get(actor, f"{actor}-subject"),
                    "private": f"{actor}-private-synthetic"}
        return {"ok": True, "status": status, "text": json.dumps(body), "truncated": False}
    return fetch


def _permit(url):
    return url.startswith(BASE)


def test_discovery_binds_observed_owned_objects_without_exposing_secrets():
    identities, calls = _identities(), []
    original = copy.deepcopy(identities)
    summary, enriched, candidates = discover_owned_resources(
        BASE, identities, _fixture_transport(calls), _permit, allow_private_owned=True)
    assert summary["status"] == "ready" and summary["identities"] == 2
    assert summary["requests"] == 6 and summary["owned_objects_observed"] == 2
    assert {item["url"] for item in candidates} == {BASE + "orders/" + item for item in IDS.values()}
    for actor in IDS:
        assert enriched[actor]["objects"] == [{"url": BASE + "orders/" + IDS[actor], "marker": IDS[actor]}]
    assert identities == original
    assert all(url.startswith(BASE) and "logout" not in url and "?" not in url for _, url in calls)
    public = json.dumps(summary)
    assert "secret" not in public and "private-synthetic" not in public
    assert all(value not in public for value in IDS.values())


def test_discovered_ownership_without_explicit_private_rule_is_not_tested():
    calls = []
    summary, enriched, candidates = discover_owned_resources(
        BASE, _identities(private=False), _fixture_transport(calls), _permit, allow_private_owned=True)
    assert summary["status"] == "incomplete" and summary["owned_objects_observed"] == 2
    assert candidates == [] and all("objects" not in item for item in enriched.values())
    assert "owner-only" in summary["reasons"][0]


def test_identity_flag_cannot_replace_program_private_access_policy():
    calls = []
    summary, _, candidates = discover_owned_resources(
        BASE, _identities(private=True), _fixture_transport(calls), _permit, allow_private_owned=False)
    assert summary["owned_objects_observed"] == 2 and candidates == []
    assert "owner-only" in summary["reasons"][0]


def test_missing_owner_binding_and_duplicate_credentials_fail_closed():
    calls = []
    summary, enriched, candidates = discover_owned_resources(
        BASE, _identities(), _fixture_transport(calls, owner_overrides={"alice": "someone-else"}), _permit,
        allow_private_owned=True)
    assert summary["owned_objects_observed"] == 1 and len(candidates) == 1
    assert "objects" not in enriched["alice"]
    duplicate = _identities()
    duplicate["bob"]["headers"]["Cookie"] = duplicate["alice"]["headers"]["Cookie"]
    calls.clear()
    summary, _, candidates = discover_owned_resources(BASE, duplicate, _fixture_transport(calls), _permit)
    assert summary["status"] == "blocked" and candidates == [] and calls == []
    missing_declaration = _identities()
    del missing_declaration["bob"]["test_data_only"]
    summary, _, candidates = discover_owned_resources(BASE, missing_declaration, _fixture_transport(calls), _permit)
    assert summary["status"] == "blocked" and candidates == [] and calls == []


@pytest.mark.parametrize("status", [401, 429])
def test_discovery_stops_before_next_identity_when_session_or_rate_fails(status):
    calls = []
    summary, _, candidates = discover_owned_resources(
        BASE, _identities(), _fixture_transport(calls, status_overrides={("alice", BASE): status}), _permit)
    assert summary["status"] == "blocked" and summary["requests"] == 1
    assert len(calls) == 1 and candidates == []


def test_discovery_respects_per_identity_budget_and_no_guessed_urls():
    calls = []
    summary, _, candidates = discover_owned_resources(
        BASE, _identities(), _fixture_transport(calls), _permit, max_requests=4, per_identity=8)
    assert summary["requests"] == 4 and candidates == []
    assert calls == [("alice", BASE), ("alice", BASE + "orders"),
                     ("bob", BASE), ("bob", BASE + "orders")]


def test_subjects_must_be_distinct_and_consistent():
    calls = []
    def fetch(url, headers):
        calls.append(url)
        return {"ok": True, "status": 200,
                "text": json.dumps({"current_user": {"id": "same-subject"}})}
    summary, _, candidates = discover_owned_resources(BASE, _identities(), fetch, _permit)
    assert len(calls) == 2 and candidates == []
    assert "distinct observed current-user" in summary["reasons"][0]


def _html_transport(calls, render):
    def fetch(url, headers):
        actor = next(name for name in IDS if headers["Cookie"] == f"session={name}-secret")
        calls.append((actor, url))
        return {"ok": True, "status": 200, "text": render(actor, url), "truncated": False}
    return fetch


@pytest.mark.parametrize("subject_markup", [
    '<body data-current-user-id="{actor}-subject">',
    '<meta name="current-user-id" content="{actor}-subject">',
    '<meta name="authenticated-user-id" content="{actor}-subject">',
    '<body data-viewer-id="{actor}-subject">',
])
def test_explicit_html_identity_and_same_element_ownership(subject_markup):
    calls = []
    def render(actor, url):
        subject = subject_markup.format(actor=actor)
        if url == BASE:
            return subject + f'<a href="/allowed/orders/{IDS[actor]}">Own order</a>'
        return subject + f'<article data-resource-id="{IDS[actor]}" data-owner-id="{actor}-subject">Order</article>'
    summary, enriched, candidates = discover_owned_resources(
        BASE, _identities(), _html_transport(calls, render), _permit, allow_private_owned=True)
    assert summary["status"] == "ready" and summary["owned_objects_observed"] == 2
    assert summary["requests"] == 4 and len(candidates) == 2
    assert all(enriched[actor]["objects"][0]["marker"] == IDS[actor] for actor in IDS)


def test_inert_json_blocks_supply_explicit_identity_and_record_attribution():
    calls = []
    def render(actor, url):
        data = {"current_user": {"id": actor + "-subject"}}
        if url == BASE:
            data["links"] = [{"href": "/allowed/orders/" + IDS[actor]}]
        else:
            data["resource"] = {"id": IDS[actor], "owner": {"id": actor + "-subject"}}
        return '<script type="application/json">' + json.dumps(data) + '</script>'
    summary, _, candidates = discover_owned_resources(
        BASE, _identities(), _html_transport(calls, render), _permit, allow_private_owned=True)
    assert summary["owned_objects_observed"] == 2 and len(candidates) == 2


@pytest.mark.parametrize("resource_markup", [
    '<p data-resource-id="{object_id}"></p><p data-owner-id="{actor}-subject"></p>',
    '<article data-resource-id="unrelated-object" data-owner-id="{actor}-subject">{object_id}</article>',
    '<article data-resource-id="{object_id}" data-owner-id="{actor}-subject" data-owner_id="someone-else"></article>',
    '<article data-resource-id="{object_id}" data-owner-id="{actor}-subject"></article>'
    '<article data-resource-id="{object_id}" data-owner-id="someone-else"></article>',
    '<script>window.resource = {{"id":"{object_id}","owner_id":"{actor}-subject"}}</script>',
    '<a href="/allowed/orders/{object_id}">My private order</a>',
])
def test_unrelated_ambiguous_or_executable_html_does_not_prove_ownership(resource_markup):
    calls = []
    def render(actor, url):
        subject = f'<meta name="current-user-id" content="{actor}-subject">'
        if url == BASE:
            return subject + f'<a href="/allowed/orders/{IDS[actor]}">Order</a>'
        return subject + resource_markup.format(actor=actor, object_id=IDS[actor])
    summary, enriched, candidates = discover_owned_resources(
        BASE, _identities(), _html_transport(calls, render), _permit, allow_private_owned=True)
    assert summary["owned_objects_observed"] == 0 and candidates == []
    assert all("objects" not in identity for identity in enriched.values())


@pytest.mark.parametrize("subject_markup", [
    '<h1>Welcome {actor}</h1>',
    '<span data-user-id="{actor}-subject"></span>',
    '<script>window.current_user = {{"id":"{actor}-subject"}}</script>',
    '<meta name="current-user-id" content="{actor}-subject">'
    '<meta name="current-user-id" content="another-subject">',
])
def test_display_names_generic_user_fields_and_conflicting_metadata_are_insufficient(subject_markup):
    calls = []
    def render(actor, url):
        if url == BASE:
            return subject_markup.format(actor=actor) + f'<a href="/allowed/orders/{IDS[actor]}">Order</a>'
        return f'<article data-resource-id="{IDS[actor]}" data-owner-id="{actor}-subject"></article>'
    summary, _, candidates = discover_owned_resources(
        BASE, _identities(), _html_transport(calls, render), _permit, allow_private_owned=True)
    assert candidates == [] and summary["owned_objects_observed"] == 0
    assert "distinct observed current-user" in summary["reasons"][0]


def test_json_owners_and_ids_in_different_records_are_never_joined():
    calls = []
    def render(actor, url):
        data = {"current_user": {"id": actor + "-subject"}}
        if url == BASE:
            data["links"] = [{"href": "/allowed/orders/" + IDS[actor]}]
        else:
            data["records"] = [{"id": IDS[actor]}, {"owner_id": actor + "-subject"}]
        return json.dumps(data)
    summary, _, candidates = discover_owned_resources(
        BASE, _identities(), _html_transport(calls, render), _permit, allow_private_owned=True)
    assert summary["owned_objects_observed"] == 0 and candidates == []


@pytest.mark.parametrize("current_user", [
    '"id":"{actor}-subject","id":"other-subject"',
    '"id":"{actor}-subject","user_id":"other-subject"',
])
def test_duplicate_or_conflicting_json_identity_fields_are_rejected(current_user):
    calls = []
    def render(actor, url):
        subject = '"current_user":{' + current_user.format(actor=actor) + '}'
        if url == BASE:
            return '{' + subject + ',"href":"/allowed/orders/' + IDS[actor] + '"}'
        return json.dumps({"id": IDS[actor], "owner_id": actor + "-subject"})
    summary, _, candidates = discover_owned_resources(
        BASE, _identities(), _html_transport(calls, render), _permit, allow_private_owned=True)
    assert summary["status"] == "incomplete" and candidates == []


def test_profile_links_are_prioritized_and_stylesheets_do_not_spend_identity_budget():
    calls = []
    def render(actor, url):
        if url == BASE:
            return ('<link rel="stylesheet" href="/allowed/style.css">'
                    '<a href="/allowed/help">Help</a><a rel="me" href="/allowed/me">Profile</a>')
        if url == BASE + "me":
            return json.dumps({"id": actor + "-subject", "links": [{"href": "/allowed/orders/" + IDS[actor]}]})
        if url == BASE + "help":
            return "Help"
        return f'<p data-resource-id="{IDS[actor]}" data-owner-id="{actor}-subject"></p>'
    summary, _, candidates = discover_owned_resources(
        BASE, _identities(), _html_transport(calls, render), _permit, allow_private_owned=True, per_identity=4)
    assert len(candidates) == 2 and summary["requests"] == 8
    for actor in IDS:
        urls = [url for name, url in calls if name == actor]
        assert urls[1] == BASE + "me" and BASE + "style.css" not in urls


def _differential_transport(calls, *, flaky=False, public=False):
    """Açık owner/current_user döndürmeyen liste yüzeyi (WS4 küme farkı)."""
    lists = {"alice": ["1001", "9001"], "bob": ["1002", "9001"]}
    if public:
        lists["alice"].append("1005")
    state = {"orders_calls": 0}

    def fetch(url, headers):
        cookie = (headers or {}).get("Cookie", "")
        actor = next((n for n in lists if cookie == f"session={n}-secret"), "anon")
        calls.append((actor, url))
        if url == BASE:
            return {"ok": True, "status": 200, "truncated": False,
                    "text": json.dumps({"links": [{"href": "/allowed/orders"}]})}
        if url == BASE + "orders":
            if actor == "anon":
                return {"ok": True, "status": 401, "text": ""}
            state["orders_calls"] += 1
            ids = list(lists[actor])
            if flaky and actor == "alice" and state["orders_calls"] % 4 == 1:
                ids.append("1003")  # yalnız ilk çekişte beliren kararsız kimlik
            return {"ok": True, "status": 200, "truncated": False,
                    "text": json.dumps({"results": [
                        {"id": item, "href": f"/allowed/orders/{item}"} for item in ids]})}
        details = {
            "1001": ("alice", {"id": "1001", "total": 50, "contact": "alice-marker@lab"}),
            "1002": ("bob", {"id": "1002", "total": 60, "contact": "bob-marker@lab"}),
            "9001": (None, {"id": "9001", "contact": "catalog@lab"}),
            "1005": ("alice", {"id": "1005", "visibility": "public",
                               "contact": "alice-marker@lab"}),
        }
        for oid, (owner, body) in details.items():
            if url == BASE + "orders/" + oid:
                if oid == "1001" and actor in {"alice", "bob"}:
                    return {"ok": True, "status": 200, "truncated": False,
                            "text": json.dumps(body)}
                if owner is None and actor in lists:
                    return {"ok": True, "status": 200, "truncated": False,
                            "text": json.dumps(body)}
                if actor == owner:
                    return {"ok": True, "status": 200, "truncated": False,
                            "text": json.dumps(body)}
                return {"ok": True, "status": 403, "text": ""}
        return {"ok": True, "status": 404, "text": ""}

    return fetch


def test_differential_candidates_without_explicit_owner():
    from cco_hunter_core.blind_discovery import discover_differential_resources
    identities = {name: {"headers": {"Cookie": f"session={name}-secret"},
                         "role": "member", "test_data_only": True}
                  for name in ("alice", "bob")}
    calls = []
    summary, enriched, candidates = discover_differential_resources(
        BASE, identities, _differential_transport(calls), _permit)
    assert summary["status"] == "ready", summary
    assert summary["differential_candidates"] == 2
    by_url = {item["url"]: item for item in candidates}
    # Sıralı tamsayı kimlikler elenmez; paylaşılan katalog (9001) aday olmaz.
    assert set(by_url) == {BASE + "orders/1001", BASE + "orders/1002"}
    assert all(item["source"] == "set_difference" for item in candidates)
    assert all(item["stability"] == "stable" for item in candidates)
    # Türetilmiş işaret sahip nesnesine bağlanır (mevcut authz bağlama yolu).
    assert enriched["alice"]["objects"] == [
        {"url": BASE + "orders/1001", "marker": "alice-marker@lab"}]
    assert enriched["bob"]["objects"] == [
        {"url": BASE + "orders/1002", "marker": "bob-marker@lab"}]
    assert summary["anon_baseline"] is False  # anon liste 401 verdi, etiket düştü


def test_differential_stability_and_public_visibility_filters():
    from cco_hunter_core.blind_discovery import discover_differential_resources
    identities = {name: {"headers": {"Cookie": f"session={name}-secret"},
                         "role": "member", "test_data_only": True}
                  for name in ("alice", "bob")}
    calls = []
    summary, _, candidates = discover_differential_resources(
        BASE, identities,
        _differential_transport(calls, flaky=True, public=True), _permit)
    urls = {item["url"] for item in candidates}
    assert BASE + "orders/1003" not in urls  # kararsız kimlik aday olmaz
    assert BASE + "orders/1005" not in urls  # visibility=public aday olmaz
    assert urls == {BASE + "orders/1001", BASE + "orders/1002"}


@pytest.mark.parametrize("block", [
    '<script type="application/json">' + ' ' * 262145 + '</script>',
    '<script type="application/json">{"current_user":{"id":"another-subject"}}',
])
def test_oversized_or_unclosed_json_metadata_cannot_establish_ownership(block):
    calls = []
    def render(actor, url):
        subject = f'<meta name="current-user-id" content="{actor}-subject">'
        if url == BASE:
            return subject + f'<a href="/allowed/orders/{IDS[actor]}">Order</a>' + block
        return f'<p data-resource-id="{IDS[actor]}" data-owner-id="{actor}-subject"></p>'
    summary, _, candidates = discover_owned_resources(
        BASE, _identities(), _html_transport(calls, render), _permit, allow_private_owned=True)
    assert summary["status"] == "incomplete" and candidates == []
