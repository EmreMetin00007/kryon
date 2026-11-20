"""Bounded, in-memory discovery of explicitly attributed owned resources.

Only observed links are followed. Resource ownership and owner-only access are
separate assertions: discovering the former never invents the latter.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import deque
from html.parser import HTMLParser
from typing import Any, Sequence
from urllib.parse import parse_qsl, unquote, urldefrag, urljoin, urlsplit, urlunsplit

from cco_surface_core.normalize import discovery_link_skip_reason

_CREDENTIALS = {"authorization", "cookie", "x-api-key", "api-key"}
_CURRENT_USER = {"currentuser", "authenticateduser", "viewer", "me"}
_CURRENT_FIELDS = {prefix + suffix for prefix in ("currentuser", "authenticateduser", "viewer")
                   for suffix in ("id", "uuid", "username")}
_SUBJECT_FIELDS = {"id", "userid", "uuid", "username"}
_OWNER_FIELDS = {"ownerid", "owneruuid", "ownerusername", "ownedby"}
_RESOURCE_FIELDS = {"id", "uuid", "resourceid", "objectid", "documentid"}
_LINK_FIELDS = {"href", "url", "uri"}
_MAX_JSON_NODES = 1000
_MAX_LINKS_PER_PAGE = 40
_MAX_JSON_BLOCKS = 16
_MAX_JSON_BLOCK_CHARS = 262144


def _key(value):
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _scalar(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    text = str(value).strip()
    return text if 1 <= len(text) <= 160 and not any(c in text for c in "\r\n\x00") else ""


def _origin(url):
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
            return None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme.lower() == "https" else 80)
        return (parsed.scheme.lower(), parsed.hostname.lower(), port) if port > 0 else None
    except (TypeError, ValueError):
        return None


def _safe_link(base, value, origin, permits):
    if not isinstance(value, str) or not value or len(value) > 2048:
        return ""
    try:
        url = urldefrag(urljoin(base, value.strip()))[0]
        parsed = urlsplit(url)
        if _origin(url) != origin or discovery_link_skip_reason(url):
            return ""
        clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        return clean if permits(clean) else ""
    except (TypeError, ValueError):
        return ""


def _fields(node, allowed):
    if not isinstance(node, dict):
        return set()
    return {value for key, raw in node.items() if _key(key) in allowed
            if (value := _scalar(raw))}


class _DuplicateJSONKey(ValueError):
    pass


def _load_json(text):
    def unique(pairs):
        data, keys = {}, set()
        for key, value in pairs:
            normalized = _key(key)
            if normalized in keys:
                raise _DuplicateJSONKey("ambiguous JSON metadata")
            keys.add(normalized)
            data[key] = value
        return data
    return json.loads(text, object_pairs_hook=unique)


def _slot(key):
    return "username" if key.endswith("username") else "uuid" if key.endswith("uuid") else "id"


def _subject_group(node):
    slots = {}
    if isinstance(node, dict):
        for key, raw in node.items():
            normalized = _key(key)
            if normalized in _SUBJECT_FIELDS and (value := _scalar(raw)):
                slots.setdefault(_slot(normalized), set()).add(value)
    return (_fields(node, _SUBJECT_FIELDS), any(len(values) > 1 for values in slots.values()))


def _attribution(node):
    """Keep owners and resource IDs together in the same declared record."""
    owners, ids = {}, {}
    for key, raw in node.items():
        normalized = _key(key)
        value = _scalar(raw)
        if value and normalized in _OWNER_FIELDS:
            owners.setdefault(_slot(normalized), set()).add(value)
        if value and normalized in _RESOURCE_FIELDS:
            ids.setdefault(_slot(normalized), set()).add(value)
        if normalized == "owner" and isinstance(raw, dict):
            for name, item in raw.items():
                if _key(name) in _SUBJECT_FIELDS and (owner := _scalar(item)):
                    owners.setdefault(_slot(_key(name)), set()).add(owner)
    owner_values = set().union(*owners.values()) if owners else set()
    object_ids = set().union(*ids.values()) if ids else set()
    if any(len(values) > 1 for values in [*owners.values(), *ids.values()]):
        owner_values = set()  # Preserve an ambiguous declaration so it cannot be ignored.
    return owner_values, object_ids


def _subject_union(groups):
    subjects, conflict = set(), False
    for group in groups:
        if subjects and group and not subjects.intersection(group):
            conflict = True
        subjects.update(group)
    return subjects, conflict


def _json_document(data, is_profile):
    profile_subjects, conflict = _subject_group(data) if is_profile else (set(), False)
    groups = [profile_subjects]
    records, links = [], []
    pending, seen = deque([data]), 0
    while pending and seen < _MAX_JSON_NODES:
        node = pending.popleft()
        seen += 1
        if isinstance(node, dict):
            direct_subjects = {}
            is_me = "me" in str(node.get("rel") or "").lower().split()
            for key, value in node.items():
                normalized = _key(key)
                if normalized in _CURRENT_USER:
                    subjects, ambiguous = _subject_group(value)
                    groups.append(subjects)
                    conflict |= ambiguous
                if normalized in _CURRENT_FIELDS and (subject := _scalar(value)):
                    direct_subjects.setdefault(_slot(normalized), set()).add(subject)
                if normalized in _LINK_FIELDS and isinstance(value, str) and len(links) < _MAX_LINKS_PER_PAGE:
                    links.append((value, is_me))
                if isinstance(value, (dict, list)):
                    pending.append(value)
            if direct_subjects:
                groups.append(set().union(*direct_subjects.values()))
                conflict |= any(len(values) > 1 for values in direct_subjects.values())
            owners, ids = _attribution(node)
            if ids and any(_key(key) in _OWNER_FIELDS | {"owner"} for key in node):
                records.append((owners, ids))
        elif isinstance(node, list):
            pending.extend(node[:_MAX_JSON_NODES])
            conflict |= len(node) > _MAX_JSON_NODES
    subjects, subject_conflict = _subject_union(groups)
    return subjects, records, links, conflict or subject_conflict or bool(pending)


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.subject_slots = {}
        self.records = []
        self.blocks = []
        self.conflict = False
        self._json_script = False
        self._buffer = []
        self._buffer_size = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attributes = {str(key).lower(): str(value or "") for key, value in attrs}
        if tag == "script":
            self._json_script = attributes.get("type", "").lower().split(";", 1)[0].strip() == "application/json"
            self._buffer, self._buffer_size = [], 0
            return
        fields, duplicate_fields = {}, set()
        for key, raw in attrs:
            normalized, value = _key(key), _scalar(raw)
            if normalized.startswith("data"):
                normalized = normalized[4:]
                if normalized in fields and fields[normalized] != value:
                    duplicate_fields.add(normalized)
                fields[normalized] = value
            if normalized in _CURRENT_FIELDS and value:
                self.subject_slots.setdefault(_slot(normalized), set()).add(value)
        if tag == "meta" and _key(attributes.get("name")) in _CURRENT_FIELDS:
            value = _scalar(attributes.get("content"))
            if value:
                self.subject_slots.setdefault(_slot(_key(attributes["name"])), set()).add(value)
        owners, ids = _attribution(fields)
        self.conflict |= bool(duplicate_fields & (_OWNER_FIELDS | _RESOURCE_FIELDS | _CURRENT_FIELDS))
        if ids and any(key in _OWNER_FIELDS for key in fields):
            self.records.append((set() if duplicate_fields else owners, ids))
        if tag not in {"a", "link"} or len(self.links) >= _MAX_LINKS_PER_PAGE:
            return
        href = attributes.get("href", "")
        rel = set(attributes.get("rel", "").lower().split())
        if href and (tag == "a" or "me" in rel):
            self.links.append((href, "me" in rel))

    def handle_data(self, data):
        if self._json_script:
            self._buffer_size += len(data)
            if self._buffer_size <= _MAX_JSON_BLOCK_CHARS:
                self._buffer.append(data)
            else:
                self.conflict = True
                self._buffer = []

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._json_script:
            if len(self.blocks) < _MAX_JSON_BLOCKS and self._buffer_size <= _MAX_JSON_BLOCK_CHARS:
                self.blocks.append("".join(self._buffer))
            else:
                self.conflict = True
            self._json_script, self._buffer = False, []


def _json_collection_entries(text):
    """Return same-node (link, owners, ids) tuples only from complete top-level JSON."""
    try:
        data = _load_json(text)
    except (TypeError, ValueError, RecursionError):
        return []
    if not isinstance(data, (dict, list)):
        return []
    entries, pending, seen = [], deque([data]), 0
    while pending and seen < _MAX_JSON_NODES:
        node = pending.popleft()
        seen += 1
        if isinstance(node, dict):
            node_links = []
            for key, value in node.items():
                if _key(key) in _LINK_FIELDS and isinstance(value, str) and len(node_links) < _MAX_LINKS_PER_PAGE:
                    node_links.append(value)
                if isinstance(value, (dict, list)):
                    pending.append(value)
            if node_links and any(_key(key) in _OWNER_FIELDS | {"owner"} for key in node):
                owners, ids = _attribution(node)
                if owners and ids:
                    for value in node_links:
                        entries.append((value, owners, ids))
        elif isinstance(node, list):
            pending.extend(node[:_MAX_JSON_NODES])
            if len(node) > _MAX_JSON_NODES:
                return []
    return [] if pending else entries


def _document(text, is_profile):
    """Parse explicit JSON/HTML attribution, without executing scripts."""
    try:
        data = _load_json(text)
    except _DuplicateJSONKey:
        return set(), [], [], True
    except (TypeError, ValueError, RecursionError):
        parser = _Links()
        try:
            parser.feed(text)
        except (TypeError, ValueError):
            return set(), [], [], True
        groups = [set().union(*parser.subject_slots.values())] if parser.subject_slots else []
        records, links = parser.records, parser.links
        conflict = parser.conflict or parser._json_script or any(
            len(values) > 1 for values in parser.subject_slots.values())
        for block in parser.blocks:
            try:
                data = _load_json(block)
            except _DuplicateJSONKey:
                conflict = True
                continue
            except (TypeError, ValueError, RecursionError):
                continue
            subjects, found_records, found_links, ambiguous = _json_document(data, False)
            groups.append(subjects)
            records.extend(found_records)
            links.extend(found_links)
            conflict |= ambiguous
        subjects, ambiguous = _subject_union(groups)
        return subjects, records, links[:_MAX_LINKS_PER_PAGE], conflict or ambiguous
    if not isinstance(data, (dict, list)):
        return set(), [], [], False
    return _json_document(data, is_profile)


def _marker(url, ids, *, allow_short_ids: bool = False):
    """Use only an observed resource ID that is bound to its URL."""
    try:
        parsed = urlsplit(url)
        tokens = {unquote(part) for part in parsed.path.split("/") if part}
        tokens.update(value for _, value in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=64))
        choices = sorted(
            item for item in ids
            if (len(item) >= 8 or (allow_short_ids and (item.isdigit() or len(item) >= 1)))
            and item in tokens
        )
        return choices[0] if len(choices) == 1 else ""
    except ValueError:
        return ""


def _owned_record(url, records, *, allow_short_ids: bool = False):
    matches = [(marker, owners) for owners, ids in records if (marker := _marker(url, ids, allow_short_ids=allow_short_ids))]
    if not matches or len({marker for marker, _ in matches}) != 1 or any(not owners for _, owners in matches):
        return "", set()
    return matches[0][0], set.intersection(*(owners for _, owners in matches))


def _credentials(headers):
    if not isinstance(headers, dict):
        return None
    clean = {}
    for key, value in headers.items():
        name, item = str(key).strip(), str(value)
        if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", name) or any(c in item for c in "\r\n\x00"):
            return None
        if name.lower() in {"host", "proxy-authorization", "content-length", "transfer-encoding"}:
            return None
        if name.lower() in clean:
            return None
        clean[name.lower()] = item
    material = [(name, clean[name]) for name in sorted(_CREDENTIALS & clean.keys()) if clean[name].strip()]
    if not material:
        return None
    digest = hashlib.sha256(json.dumps(material, separators=(",", ":")).encode()).digest()
    return digest


def _observed_exposure(text):
    """Keep explicit public/shared metadata attached to its own resource IDs."""
    try:
        data = _load_json(text)
    except (TypeError, ValueError, RecursionError):
        return {}
    exposure, queue = {}, deque([data])
    for _ in range(_MAX_JSON_NODES):
        if not queue:
            break
        node = queue.popleft()
        if isinstance(node, dict):
            ids = _fields(node, _RESOURCE_FIELDS)
            public = any(_key(k) in {"visibility", "audience", "access", "sharing"}
                         and str(v).lower() in {"public", "shared", "everyone", "anonymous"}
                         or _key(k) in {"public", "ispublic", "shared", "isshared"} and v is True
                         for k, v in node.items())
            if public:
                exposure.update({value: "public/shared" for value in ids})
            queue.extend(v for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            queue.extend(node[:_MAX_JSON_NODES])
    return exposure


def discover_owned_resources(target, identities, fetch, permits, *, stop_reason=None,
                              max_requests=24, per_identity=8, max_depth=3, pace=None,
                              allow_private_owned=False, observations=None,
                              seed_urls=()):
    """Return (safe summary, transient identities, transient candidates).

    The caller supplies a gate-backed GET transport and scope predicate. The
    returned candidates are eligible only when an operator explicitly states
    that their own test objects are private via ``owned_objects_private``.
    """
    enriched = copy.deepcopy(identities) if isinstance(identities, dict) else {}
    summary = {"status": "blocked", "identities": 0, "requests": 0,
               "owned_objects_observed": 0, "eligible_candidates": 0,
               "truncated_responses": 0, "budget_limited": False,
               "complete_coverage": False, "reasons": []}
    if not callable(fetch) or not callable(permits):
        summary["reasons"].append("discovery transport or scope unavailable")
        return summary, enriched, []
    start = str(target or "").strip()
    if "://" not in start:
        start = "https://" + start
    origin = _origin(start)
    try:
        start = _safe_link(start, start, origin, permits) if origin else ""
    except Exception:
        start = ""
    if not start:
        summary["reasons"].append("start URL is outside scope or not suitable for read-only discovery")
        return summary, enriched, []
    actors = []
    for name, identity in enriched.items():
        if (not isinstance(identity, dict) or identity.get("test_data_only") is not True
                or not isinstance(identity.get("headers"), dict)):
            continue
        fingerprint = _credentials(identity["headers"])
        if fingerprint:
            actors.append((name, identity, fingerprint))
    if (len(actors) != len(enriched) or len(actors) < 2 or len(actors) > 8
            or len({item[2] for item in actors}) != len(actors)):
        summary["reasons"].append("two to eight distinct, explicitly synthetic test identities are required")
        return summary, enriched, []
    summary["identities"] = len(actors)
    try:
        total_limit = max(0, min(int(max_requests), 40))
        per_limit = max(0, min(int(per_identity), 12, total_limit // len(actors)))
        depth_limit = max(0, min(int(max_depth), 4))
    except (TypeError, ValueError):
        summary["reasons"].append("invalid discovery budget")
        return summary, enriched, []
    if per_limit == 0:
        summary["reasons"].append("discovery request budget is insufficient")
        return summary, enriched, []

    # Only an admitted discovery can be incomplete. Failed prerequisites must
    # stop the caller's subsequent discover/crawl/fuzz traffic as well.
    summary["status"] = "incomplete"
    cached = observations or {}
    observations = {}
    for name, identity, _ in actors:
        if name in cached:
            state = cached[name]
            facts = state.get("identity_facts", [])
            subjects = {item["value"] for item in facts if item.get("field") == "principal"
                        and item.get("source") == "response_metadata" and item.get("confidence") == "observed"}
            objects = state.get("objects", [])
            if len(subjects) != 1 or not objects:
                summary["status"] = "blocked"
                summary["reasons"].append("completed discovery ownership context unavailable")
                return summary, copy.deepcopy(identities), []
            # Reuse discovery only. Each new owner/attacker comparison still
            # creates a new queue and executes its ordinary signed controls.
            enriched[name].update({key: copy.deepcopy(state[key]) for key in
                                   ("objects", "resources", "identity_facts") if key in state})
            enriched[name]["_discovery_observed_at"] = state["observed_at"]
            resources = []
            for obj in objects:
                url = _safe_link(start, obj.get("url"), origin, permits)
                if not url or not obj.get("marker"):
                    summary["status"] = "blocked"
                    summary["reasons"].append("completed discovery object is no longer permitted")
                    return summary, copy.deepcopy(identities), []
                resources.append((url, obj["marker"], subjects))
            observations[name] = (subjects, resources, False, {})
            continue
        subjects, resources, subject_conflict = set(), [], False
        exposures = {}
        queue, seen = deque([(start, 0, False)]), set()
        for extra in seed_urls or ():
            safe_extra = _safe_link(start, str(extra or ""), origin, permits)
            if safe_extra and safe_extra != start and all(item[0] != safe_extra for item in queue):
                queue.append((safe_extra, 0, False))
        requests = 0
        while queue and requests < per_limit and summary["requests"] < total_limit:
            current, depth, is_profile = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            if callable(pace) and summary["requests"]:
                pace()
            try:
                response = fetch(current, dict(identity["headers"]))
            except Exception:
                response = {"ok": False, "status": None}
            requests += 1
            summary["requests"] += 1
            status = response.get("status") if isinstance(response, dict) else None
            stopped = stop_reason() if callable(stop_reason) else ""
            if stopped or status in {401, 429} or not isinstance(response, dict) or not response.get("ok"):
                summary["status"] = "blocked"
                summary["reasons"].append("discovery stopped by session, rate limit, policy or transport")
                return summary, copy.deepcopy(identities), []
            if status in {301, 302, 303, 307, 308} and depth < depth_limit:
                try:
                    next_url = _safe_link(current, response.get("location") or "", origin, permits)
                except Exception:
                    next_url = ""
                if next_url and next_url not in seen:
                    queue.append((next_url, depth + 1, is_profile))
                continue
            if response.get("truncated"):
                summary["truncated_responses"] += 1
                continue
            if status != 200:
                continue
            text = response.get("text")
            if not isinstance(text, str):
                continue
            exposures.update(_observed_exposure(text))
            found_subjects, owned_records, links, ambiguous = _document(text, is_profile)
            subject_conflict |= ambiguous
            if subjects and found_subjects and not subjects.intersection(found_subjects):
                subject_conflict = True
            subjects.update(found_subjects)
            marker, owner_values = _owned_record(current, owned_records)
            if owner_values and marker and marker in text:
                resources.append((current, marker, owner_values))
            elided_links = set()
            if (allow_private_owned and identity.get("owned_objects_private") is True
                    and not ambiguous and not subject_conflict and subjects and depth < depth_limit):
                proven_by_link = {}
                ambiguous_proven = set()
                existing_objects = [item for item in (identity.get("objects") or []) if isinstance(item, dict)]
                for raw_link, entry_owners, entry_ids in _json_collection_entries(text):
                    try:
                        link = _safe_link(current, raw_link, origin, permits)
                    except Exception:
                        link = ""
                    if not link:
                        continue
                    node_marker = _marker(link, entry_ids)
                    rec_marker, rec_owners = _owned_record(link, owned_records)
                    proven_owners = entry_owners & rec_owners
                    if (not node_marker or node_marker != rec_marker or node_marker not in text
                            or node_marker in exposures or not (proven_owners & subjects)
                            or any(r_marker != node_marker for r_url, r_marker, _ in resources if r_url == link)
                            or any(item.get("url") == link and item.get("marker") != node_marker for item in existing_objects)):
                        ambiguous_proven.add(link)
                        proven_by_link.pop(link, None)
                        continue
                    if link in ambiguous_proven:
                        continue
                    if link in proven_by_link:
                        prev_marker, prev_owners = proven_by_link[link]
                        merged = prev_owners & proven_owners
                        if prev_marker != node_marker or not (merged & subjects):
                            ambiguous_proven.add(link)
                            proven_by_link.pop(link, None)
                        else:
                            proven_by_link[link] = (node_marker, merged)
                    else:
                        proven_by_link[link] = (node_marker, proven_owners)
                for link, (node_marker, proven_owners) in proven_by_link.items():
                    if link not in seen:
                        elided_links.add(link)
                        seen.add(link)
                        resources.append((link, node_marker, proven_owners))
            if depth < depth_limit:
                owned_links = []
                for value, is_me in sorted(links, key=lambda item: not item[1]):
                    try:
                        link = _safe_link(current, value, origin, permits)
                    except Exception:
                        link = ""
                    if link and link not in seen and link not in elided_links and len(queue) + len(owned_links) < per_limit * 3:
                        entry = (link, depth + 1, is_me)
                        if any(owners & subjects and _marker(link, ids) for owners, ids in owned_records):
                            # Resolve an observed owner's object while its list
                            # context is available, before unrelated navigation.
                            owned_links.append(entry)
                        else:
                            queue.append(entry)
                queue.extendleft(reversed(owned_links))
        if queue:
            summary["budget_limited"] = True
        observations[name] = (subjects, resources, subject_conflict, exposures)

    subject_sets = [observations[name][0] for name, _, _ in actors]
    if any(not subjects for subjects in subject_sets) or any(observations[name][2] for name, _, _ in actors) or any(
            subject_sets[i] & subject_sets[j] for i in range(len(subject_sets)) for j in range(i + 1, len(subject_sets))):
        summary["reasons"].append("distinct observed current-user identities are required")
        return summary, enriched, []
    candidates, seen_candidates, observed_actors = [], set(), set()
    for name, identity, _ in actors:
        subjects, resources, _, exposures = observations[name]
        if len(subjects) == 1:
            identity.setdefault("identity_facts", []).extend([
                {"field": field, "value": value, "source": "response_metadata",
                 "evidence": start, "confidence": "observed"}
                for field, value in (("principal", next(iter(subjects))), ("authority", str(origin)))])
        for url, marker, owners in resources:
            if not (owners & subjects):
                continue
            summary["owned_objects_observed"] += 1
            observed_actors.add(name)
            if marker in exposures:
                summary["reasons"].append("public/shared resource excluded from owner-only candidates")
                continue
            if not allow_private_owned or identity.get("owned_objects_private") is not True:
                continue
            identity.setdefault("objects", [])
            if not isinstance(identity["objects"], list):
                summary["reasons"].append("invalid identity objects")
                continue
            existing = [item for item in identity["objects"] if isinstance(item, dict) and item.get("url") == url]
            if existing and any(item.get("marker") != marker for item in existing):
                summary["reasons"].append("discovered object conflicts with existing ownership context")
                continue
            if not existing:
                from object_identity import normalize_object_id
                identity["objects"].append({"url": url, "marker": marker})
                from authz_matrix import identity_fact
                identity.setdefault("resources", []).append({
                    "resource_id": normalize_object_id(marker),
                    "tenant": identity_fact(identity, "tenant") or "unresolved:" + name,
                    "family": urlsplit(url).path.rsplit("/", 1)[0], "test_data_only": True,
                    "ownership_evidence": {"source": "response_metadata", "evidence": url, "confidence": "observed"}})
            if url not in seen_candidates:
                candidates.append({"vuln_class": "bola", "url": url, "method": "GET",
                                   "authz_candidate": True})
                seen_candidates.add(url)
    summary["eligible_candidates"] = len(candidates)
    if summary["owned_objects_observed"] and not candidates:
        summary["reasons"].append("owner-only access policy must be explicitly provided")
    elif not summary["owned_objects_observed"]:
        summary["reasons"].append("no explicit owner relationship observed")
    if summary["owned_objects_observed"] and len(observed_actors) < len(actors):
        summary["reasons"].append("one or more test identities have no observed owned object")
    if summary["budget_limited"]:
        summary["reasons"].append("identity discovery request budget limited coverage")
    if summary["truncated_responses"]:
        summary["reasons"].append("one or more responses exceeded the capture limit")
    summary["status"] = "ready" if candidates else "incomplete"
    return summary, enriched, candidates


_DIFF_ID_FIELDS = _RESOURCE_FIELDS | {"slug"}
_DIFF_SKIP_PATH = re.compile(r"recommend|suggest|feed", re.I)
_DIFF_PUBLIC_WORDS = ("public", "all", "shared", "everyone", "anonymous")
_DIFF_VISIBILITY_FIELDS = {"visibility", "audience", "access", "sharing"}


def _json_scalars(node, out, budget):
    if budget[0] <= 0:
        return
    budget[0] -= 1
    if isinstance(node, dict):
        for value in node.values():
            scalar = _scalar(value)
            if scalar:
                out.add(scalar)
            if isinstance(value, (dict, list)):
                _json_scalars(value, out, budget)
    elif isinstance(node, list):
        for value in node[:_MAX_JSON_NODES]:
            if isinstance(value, (dict, list)):
                _json_scalars(value, out, budget)


def _derive_marker(detail_text, other_texts, raw_id):
    """Owner detail yanıtından, başkalarında görünmeyen tekil işareti türet."""
    try:
        data = _load_json(detail_text)
    except Exception:
        cleaned = re.sub(r"<(?:script|style)\b[^>]*>.*?</(?:script|style)>", " ", detail_text or "", flags=re.I | re.S)
        cleaned = re.sub(r"<[^>]+>", "\n", cleaned)
        tokens = []
        for raw_line in cleaned.splitlines():
            line = " ".join(raw_line.split()).strip()
            if 5 <= len(line) <= 120:
                tokens.append(line)
            for word in line.split():
                w = word.strip(".,;:()[]{}\"'")
                if len(w) >= 5:
                    tokens.append(w)
        if raw_id and len(str(raw_id)) >= 5:
            tokens.append(str(raw_id))
        unique_html = [
            val for val in dict.fromkeys(tokens)
            if all(val not in text for text in other_texts)
        ]
        if not unique_html:
            return ""
        unique_html.sort(key=lambda v: (0 if "@" in v else 1 if v == raw_id else 2, -len(v), v))
        return unique_html[0]
    scalars = set()
    _json_scalars(data, scalars, [1000])
    unique = [value for value in scalars
              if len(value) >= 4 and all(value not in text for text in other_texts)]
    if not unique:
        return ""
    unique.sort(key=lambda v: (0 if "@" in v else 1 if v == raw_id else 2, -len(v), v))
    return unique[0]


def discover_differential_resources(target, identities, fetch, permits, *,
                                    stop_reason=None, max_requests=40,
                                    per_identity=12, max_depth=3, pace=None,
                                    seed_urls=()):
    """Küme farkı sahiplik çıkarımı (WS4): açık owner metaverisi olmadan,
    oturumlar arası görünürlük farkından BOLA adayları üretir.

    Aday kanıt değildir: türetilmiş işaret sahip nesnesine bağlanır ve hükmü
    mevcut validator verir. Dönüş biçimi discover_owned_resources ile aynı.
    """
    enriched = copy.deepcopy(identities) if isinstance(identities, dict) else {}
    summary = {"status": "blocked", "identities": 0, "requests": 0,
               "owned_objects_observed": 0, "eligible_candidates": 0,
               "differential_candidates": 0, "anon_baseline": False,
               "truncated_responses": 0, "budget_limited": False,
               "complete_coverage": False, "reasons": []}
    if not callable(fetch) or not callable(permits):
        summary["reasons"].append("discovery transport or scope unavailable")
        return summary, enriched, []
    start = str(target or "").strip()
    if "://" not in start:
        start = "https://" + start
    origin = _origin(start)
    try:
        start = _safe_link(start, start, origin, permits) if origin else ""
    except Exception:
        start = ""
    if not start:
        summary["reasons"].append("start URL is outside scope or not suitable for read-only discovery")
        return summary, enriched, []
    actors = []
    for name, identity in enriched.items():
        if (not isinstance(identity, dict) or identity.get("test_data_only") is not True
                or not isinstance(identity.get("headers"), dict)):
            continue
        fingerprint = _credentials(identity["headers"])
        if fingerprint:
            actors.append((name, identity, fingerprint))
    if (len(actors) != len(enriched) or len(actors) < 2 or len(actors) > 8
            or len({item[2] for item in actors}) != len(actors)):
        summary["reasons"].append("two to eight distinct, explicitly synthetic test identities are required")
        return summary, enriched, []
    summary["identities"] = len(actors)
    try:
        total_limit = max(0, min(int(max_requests), 40))
        per_limit = max(0, min(int(per_identity), 12, total_limit // len(actors)))
        depth_limit = max(0, min(int(max_depth), 4))
    except (TypeError, ValueError):
        summary["reasons"].append("invalid discovery budget")
        return summary, enriched, []
    if per_limit == 0:
        summary["reasons"].append("discovery request budget is insufficient")
        return summary, enriched, []

    summary["status"] = "incomplete"
    used = {name: 0 for name, _, _ in actors}
    anon_used = [0]

    def crawl(headers, allowance, *, tolerate_auth=False):
        """Tek aktör/anon için sınırlı gezinme; görünür kimlikleri toplar."""
        visible, texts, details = {}, [], {}
        visibility = {}
        paginated = False
        auth_denied = False
        queue, seen = deque([(start, 0)]), set()
        for extra in seed_urls or ():
            safe_extra = _safe_link(start, str(extra or ""), origin, permits)
            if safe_extra and safe_extra != start and all(item[0] != safe_extra for item in queue):
                queue.append((safe_extra, 0))
        made = 0
        while queue and made < allowance and summary["requests"] < total_limit:
            current, depth = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            if callable(pace) and summary["requests"]:
                pace()
            try:
                response = fetch(current, dict(headers))
            except Exception:
                response = {"ok": False, "status": None}
            made += 1
            summary["requests"] += 1
            status = response.get("status") if isinstance(response, dict) else None
            stopped = stop_reason() if callable(stop_reason) else ""
            if stopped or not isinstance(response, dict) or not response.get("ok"):
                return {"blocked": True, "visible": visible, "texts": texts,
                        "details": details, "visibility": visibility,
                        "paginated": paginated, "made": made, "auth_denied": auth_denied}
            if status in {401, 403} and tolerate_auth:
                auth_denied = True
            if status in {401, 429} and not tolerate_auth:
                return {"blocked": True, "visible": visible, "texts": texts,
                        "details": details, "visibility": visibility,
                        "paginated": paginated, "made": made, "auth_denied": auth_denied}
            if status in {301, 302, 303, 307, 308} and depth < depth_limit:
                next_url = ""
                try:
                    raw_loc = response.get("location") or ""
                    if not raw_loc and isinstance(response.get("headers"), dict):
                        raw_loc = next((str(v) for k, v in response["headers"].items() if str(k).lower() == "location"), "")
                    next_url = _safe_link(current, raw_loc, origin, permits)
                except Exception:
                    next_url = ""
                if next_url and next_url not in seen:
                    queue.append((next_url, depth + 1))
                continue
            if response.get("truncated"):
                summary["truncated_responses"] += 1
                continue
            if status != 200:
                continue
            text = response.get("text")
            if not isinstance(text, str):
                continue
            texts.append(text)
            details[current] = text
            _, _, links, _ = _document(text, False)
            if not _DIFF_SKIP_PATH.search(urlsplit(current).path):
                try:
                    data = _load_json(text)
                except Exception:
                    data = None
                if isinstance(data, dict) and data.get("next"):
                    paginated = True
                nodes = deque([data]) if isinstance(data, (dict, list)) else deque()
                visited_nodes = 0
                while nodes and visited_nodes < _MAX_JSON_NODES:
                    node = nodes.popleft()
                    visited_nodes += 1
                    if isinstance(node, dict):
                        ids = _fields(node, _DIFF_ID_FIELDS)
                        node_visibility = ""
                        for key, raw in node.items():
                            if _key(key) in _DIFF_VISIBILITY_FIELDS and (val := _scalar(raw)):
                                node_visibility = val.lower()
                        link_url = ""
                        for key, raw in node.items():
                            if _key(key) in _LINK_FIELDS and isinstance(raw, str):
                                try:
                                    link_url = _safe_link(current, raw, origin, permits)
                                except Exception:
                                    link_url = ""
                                if link_url:
                                    break
                        path_tokens = {part for part in urlsplit(current).path.split("/") if part}
                        for raw_id in ids:
                            detail = link_url or (current if raw_id in path_tokens else "")
                            if detail:
                                visible.setdefault(raw_id, {"raw": raw_id, "url": detail})
                                if node_visibility:
                                    visibility[raw_id] = node_visibility
                        for value in node.values():
                            if isinstance(value, (dict, list)):
                                nodes.append(value)
                    elif isinstance(node, list):
                        nodes.extend(node[:_MAX_JSON_NODES])
                last = urlsplit(current).path.rstrip("/").rsplit("/", 1)[-1]
                if last and (any(c.isdigit() for c in last) or len(last) >= 8) \
                        and last not in visible:
                    visible[last] = {"raw": last, "url": current}
                if data is None:
                    for value, _is_me in links:
                        try:
                            cand_link = _safe_link(current, value, origin, permits)
                        except Exception:
                            cand_link = ""
                        if not cand_link:
                            continue
                        seg = urlsplit(cand_link).path.rstrip("/").rsplit("/", 1)[-1]
                        if (seg and seg not in visible and not _DIFF_SKIP_PATH.search(urlsplit(cand_link).path)
                                and (seg.isdigit() or _UUID_SEG_RE.fullmatch(seg)
                                     or (len(seg) >= 8 and any(c.isdigit() for c in seg)))):
                            visible[seg] = {"raw": seg, "url": cand_link}
            if depth < depth_limit:
                for value, _is_me in sorted(links, key=lambda item: not item[1]):
                    try:
                        link = _safe_link(current, value, origin, permits)
                    except Exception:
                        link = ""
                    if link and link not in seen and len(queue) < per_limit * 3:
                        queue.append((link, depth + 1))
        if queue:
            summary["budget_limited"] = True
        return {"blocked": False, "visible": visible, "texts": texts,
                "details": details, "visibility": visibility,
                "paginated": paginated, "made": made, "auth_denied": auth_denied}

    passes = {}
    for name, identity, _ in actors:
        first = crawl(identity["headers"], per_limit)
        used[name] += first["made"]
        if first["blocked"]:
            summary["status"] = "blocked"
            summary["reasons"].append("discovery stopped by session, rate limit, policy or transport")
            return summary, copy.deepcopy(identities), []
        second_allowance = per_limit - used[name]
        second = crawl(identity["headers"], second_allowance) if second_allowance > 0 else None
        if second is not None:
            used[name] += second["made"]
            if second["blocked"]:
                summary["status"] = "blocked"
                summary["reasons"].append("discovery stopped by session, rate limit, policy or transport")
                return summary, copy.deepcopy(identities), []
        passes[name] = (first, second)

    # Anon küme kimlik bilgisi taşımaz ama program başlıklarını taşır;
    # başlıksız istek tel kapısının kilitlenmesine yol açar.
    first_headers = actors[0][1]["headers"]
    anon_headers = {key: value for key, value in first_headers.items()
                    if str(key).lower() not in _CREDENTIALS}
    anon = crawl(anon_headers, max(1, per_limit // 2), tolerate_auth=True)
    anon_used[0] += anon["made"]
    anon_ids = set(anon["visible"]) if not anon["blocked"] else set()
    summary["anon_baseline"] = not anon["blocked"] and not anon.get("auth_denied")

    paginated = any(p["paginated"] for pair in passes.values() for p in pair if p)
    if paginated:
        summary["reasons"].append("paginated list surface: differential candidates suppressed")
        return summary, enriched, []

    stable, stability_label = {}, {}
    for name, (first, second) in passes.items():
        if second is None or second["made"] == 0:
            stable[name] = first["visible"]
            stability_label[name] = "single_fetch"
        else:
            stable[name] = {key: value for key, value in first["visible"].items()
                            if key in second["visible"]}
            stability_label[name] = "stable"

    candidates, seen_candidates = [], set()
    for name, identity, _ in actors:
        others_ids = set()
        other_texts = list(anon["texts"])
        for other, _, _ in actors:
            if other != name:
                others_ids.update(stable[other])
                other_texts.extend(passes[other][0]["texts"])
                if passes[other][1]:
                    other_texts.extend(passes[other][1]["texts"])
        for raw_id in sorted(set(stable[name]) - others_ids - anon_ids):
            info = stable[name][raw_id]
            url = info["url"]
            if not url or url in seen_candidates:
                continue
            hint = passes[name][0]["visibility"].get(raw_id, "")
            if any(word in hint for word in _DIFF_PUBLIC_WORDS):
                continue  # herkese açık beyanı: sahiplik adayı değil
            detail_text = passes[name][0]["details"].get(url, "")
            if not detail_text and summary["requests"] < total_limit:
                try:
                    response = fetch(url, dict(identity["headers"]))
                except Exception:
                    response = {"ok": False, "status": None}
                summary["requests"] += 1
                if isinstance(response, dict) and response.get("status") == 200:
                    detail_text = str(response.get("text") or "")
            marker = _derive_marker(detail_text, other_texts, raw_id) if detail_text else ""
            if marker:
                identity.setdefault("objects", [])
                if not isinstance(identity["objects"], list):
                    summary["reasons"].append("invalid identity objects")
                    continue
                existing = [item for item in identity["objects"]
                            if isinstance(item, dict) and item.get("url") == url]
                if existing and any(item.get("marker") != marker for item in existing):
                    summary["reasons"].append("discovered object conflicts with existing ownership context")
                    continue
                if not existing:
                    identity["objects"].append({"url": url, "marker": marker})
            candidate = {"vuln_class": "bola", "url": url, "method": "GET",
                         "authz_candidate": True, "source": "set_difference",
                         "owner_identity": name,
                         "anon_baseline": summary["anon_baseline"],
                         "stability": stability_label[name]}
            if any(word in hint for word in ("role", "admin", "plan")):
                candidate["visibility_hint"] = "role"
            candidates.append(candidate)
            seen_candidates.add(url)
    summary["differential_candidates"] = len(candidates)
    summary["eligible_candidates"] = len(candidates)
    if not candidates:
        summary["reasons"].append("no differential ownership observed")
    if summary["budget_limited"]:
        summary["reasons"].append("identity discovery request budget limited coverage")
    summary["status"] = "ready" if candidates else "incomplete"
    return summary, enriched, candidates


_TYPED_OWNER_PREFIXES = (
    "owner",
    "custodian",
    "createdby",
    "requestedby",
    "assignedto",
    "author",
    "creator",
    "requester",
    "maintainer",
    "operator",
    "technician",
)
_TYPED_OWNER_EXACT = frozenset({
    "owner", "ownerid", "owneruuid", "ownerusername", "owneralias", "owneremail", "ownedby",
    "custodian", "custodianid", "custodianalias", "custodianemail", "custodianusername",
    "createdby", "createdbyid", "createdbyalias", "createdbyemail",
    "requestedby", "requestedbyid", "requestedbyalias", "requestedbyemail",
    "assignedto", "assignedtoid", "assignedtoalias",
    "authorid", "authoralias", "memberid", "userid", "useralias",
})
_TYPED_TENANT_EXACT = frozenset({
    "tenant", "tenantid", "tenantslug", "tenantname", "tenantcode",
    "org", "orgid", "orgslug", "organization", "organizationid",
    "company", "companyid", "workspace", "workspaceid", "plant", "plantid", "accountid",
})
_TYPED_ID_EXACT = frozenset({"id", "uuid", "resourceid", "objectid", "documentid", "recordid", "itemid"})
_TEMPLATE_SLOT_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_UUID_SEG_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def canonical_resource_type(url_or_path: str) -> str:
    """Derive a stable resource_type namespace from a collection, detail, or template URL."""
    raw = str(url_or_path or "").strip()
    if not raw:
        return "/"
    path = urlsplit(raw).path if "://" in raw else raw
    parts = [p for p in path.split("/") if p]
    while parts:
        tail = parts[-1]
        if (_TEMPLATE_SLOT_RE.fullmatch(tail)
                or tail.isdigit()
                or _UUID_SEG_RE.fullmatch(tail)
                or (len(tail) >= 16 and re.fullmatch(r"[A-Za-z0-9_-]+", tail) and any(c.isdigit() for c in tail))):
            parts.pop()
            continue
        break
    return "/" + "/".join(parts) if parts else "/"


def _is_owner_field_key(normalized_key: str) -> bool:
    if normalized_key in _TYPED_OWNER_EXACT:
        return True
    return any(normalized_key.startswith(prefix) for prefix in _TYPED_OWNER_PREFIXES) and (
        normalized_key.endswith(("id", "uuid", "alias", "email", "username", "name"))
    )


def _is_tenant_field_key(normalized_key: str) -> bool:
    if normalized_key in _TYPED_TENANT_EXACT:
        return True
    return normalized_key.startswith(("tenant", "org", "organization", "workspace", "plant")) and (
        normalized_key.endswith(("id", "slug", "name", "code"))
    )


def normalize_owner_values(node: Any) -> set[str]:
    """Extract normalized owner/custodian/creator identifiers from a JSON record."""
    if not isinstance(node, dict):
        return set()
    owners: set[str] = set()
    for key, raw in node.items():
        norm = _key(key)
        if _is_owner_field_key(norm):
            val = _scalar(raw)
            if val:
                owners.add(val)
            elif isinstance(raw, dict):
                for subk, subv in raw.items():
                    if _key(subk) in {"id", "uuid", "alias", "email", "workemail", "username", "sub"}:
                        sval = _scalar(subv)
                        if sval:
                            owners.add(sval)
    return owners


def normalize_tenant_values(node: Any) -> set[str]:
    """Extract normalized tenant/organization identifiers from a JSON record."""
    if not isinstance(node, dict):
        return set()
    tenants: set[str] = set()
    for key, raw in node.items():
        norm = _key(key)
        if _is_tenant_field_key(norm):
            val = _scalar(raw)
            if val:
                tenants.add(val)
            elif isinstance(raw, dict):
                for subk, subv in raw.items():
                    if _key(subk) in {"id", "slug", "name", "code"}:
                        sval = _scalar(subv)
                        if sval:
                            tenants.add(sval)
    return tenants


def normalize_resource_id(node: Any, *, preferred_param: str = "") -> str:
    """Extract a record's primary typed ID (including short ints like '1', '2')."""
    if not isinstance(node, dict):
        return ""
    pref = _key(preferred_param)
    candidates: list[tuple[int, str]] = []
    for key, raw in node.items():
        norm = _key(key)
        if _is_owner_field_key(norm) or _is_tenant_field_key(norm):
            continue
        val = _scalar(raw)
        if not val:
            continue
        if pref and norm == pref:
            candidates.append((0, val))
        elif norm == "id":
            candidates.append((1, val))
        elif norm in _TYPED_ID_EXACT:
            candidates.append((2, val))
        elif norm.endswith(("id", "uuid")) and norm not in {"parentid", "companyid"}:
            candidates.append((3, val))
    if not candidates:
        return ""
    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[0][1]


def hydrate_template_url(template_url: str, id_value: str, *, param_name: str = "") -> str:
    """Hydrate a single-slot OpenAPI path template (/{..._id}) with a typed ID."""
    slots = _TEMPLATE_SLOT_RE.findall(template_url)
    if len(slots) != 1:
        return ""
    slot = slots[0]
    if param_name and slot != param_name:
        return ""
    val = str(id_value or "").strip()
    if not val or any(ch in val for ch in "/?#\r\n\x00"):
        return ""
    from urllib.parse import quote
    return template_url.replace("{" + slot + "}", quote(val, safe=""))


def extract_typed_records(
    payload: Any,
    source_url: str,
    *,
    preferred_param: str = "",
) -> list[dict[str, Any]]:
    """Extract typed resource records from a JSON list/envelope/object using generic normalization."""
    if not isinstance(payload, (dict, list)):
        return []
    base_type = canonical_resource_type(source_url)
    rows: list[dict[str, Any]] = []
    seen_nodes: set[int] = set()
    queue: deque[tuple[Any, str]] = deque([(payload, base_type)])
    visited = 0
    while queue and visited < _MAX_JSON_NODES:
        node, rtype = queue.popleft()
        visited += 1
        if isinstance(node, list):
            for elem in node[:_MAX_JSON_NODES]:
                if isinstance(elem, (dict, list)):
                    queue.append((elem, rtype))
            continue
        if not isinstance(node, dict):
            continue
        oid = id(node)
        if oid in seen_nodes:
            continue
        seen_nodes.add(oid)
        link_raw = next(
            (node[k] for k in ("href", "url", "self", "uri") if isinstance(node.get(k), str) and node.get(k)),
            "",
        )
        node_type = canonical_resource_type(link_raw) if link_raw else rtype
        rec_id = normalize_resource_id(node, preferred_param=preferred_param)
        if rec_id:
            rows.append({
                "resource_type": node_type,
                "key": rec_id,
                "typed_key": f"{node_type}::{rec_id}",
                "link": link_raw,
                "tenants": sorted(normalize_tenant_values(node)),
                "owners": sorted(normalize_owner_values(node)),
                "fields": sorted(str(k) for k in node.keys()),
                "record": node,
            })
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                child_type = rtype
                if isinstance(v, list) and _key(k) not in {"items", "results", "data", "entries", "records"}:
                    child_type = rtype
                queue.append((v, child_type))
    return rows


def discover_typed_resources(
    target: str,
    identities: dict[str, dict[str, Any]],
    fetch,
    permits,
    *,
    collection_urls: Sequence[str] = (),
    template_routes: Sequence[dict[str, Any]] = (),
    max_requests: int = 80,
    max_detail_per_actor: int = 4,
    stop_reason=None,
) -> dict[str, Any]:
    """Actor-scoped typed resource discovery & OpenAPI {id} template hydration.

    Keeps distinct (resource_type, key) namespaces so colliding short integer IDs
    across different resource families never join.
    """
    start = str(target or "").strip()
    if "://" not in start:
        start = "http://" + start
    origin = _origin(start)
    if not origin or not callable(fetch) or not callable(permits):
        return {"status": "blocked", "reasons": ["invalid discovery target or transport"],
                "requests": 0, "resources": {}, "hydrated_templates": {}, "collection_observations": {}}

    safe_collections: list[str] = []
    for raw in collection_urls:
        safe = _safe_link(start, str(raw or ""), origin, permits)
        if safe and "{" not in safe and "}" not in safe and safe not in safe_collections:
            safe_collections.append(safe)

    requests_used = 0
    # Keyed strictly by (resource_type, key) so colliding IDs never merge.
    typed_registry: dict[tuple[str, str], dict[str, Any]] = {}
    collection_observations: dict[tuple[str, str], dict[str, Any]] = {}

    def _call(url: str, headers: dict[str, Any]) -> dict[str, Any]:
        nonlocal requests_used
        if requests_used >= max_requests:
            return {"ok": False, "status": None, "error": "budget_exhausted"}
        if callable(stop_reason) and stop_reason():
            return {"ok": False, "status": None, "error": str(stop_reason())}
        requests_used += 1
        try:
            resp = fetch(url, dict(headers))
            return resp if isinstance(resp, dict) else {"ok": False, "status": None}
        except Exception as exc:
            return {"ok": False, "status": None, "error": str(exc)}

    for actor_name, identity in identities.items():
        headers = identity.get("headers") if isinstance(identity, dict) else None
        if not isinstance(headers, dict):
            continue
        for col_url in safe_collections:
            if requests_used >= max_requests:
                break
            resp = _call(col_url, headers)
            status = resp.get("status")
            text = str(resp.get("text") or "")
            parsed = None
            if resp.get("ok") and status == 200:
                try:
                    parsed = _load_json(text)
                except Exception:
                    try:
                        parsed = json.loads(text)
                    except ValueError:
                        parsed = None
            col_type = canonical_resource_type(col_url)
            extracted = extract_typed_records(parsed, col_url) if parsed is not None else []
            if parsed is None and resp.get("ok") and status == 200 and text:
                parser = _Links()
                try:
                    parser.feed(text)
                except (TypeError, ValueError):
                    parser_links = []
                else:
                    parser_links = parser.links
                seen_html_items: set[tuple[str, str]] = set()
                for href, _ in parser_links:
                    safe_det = _safe_link(col_url, href, origin, permits)
                    if not safe_det:
                        continue
                    det_parts = [p for p in urlsplit(safe_det).path.split("/") if p]
                    if len(det_parts) < 2:
                        continue
                    tail = det_parts[-1]
                    if (tail.isdigit() or _UUID_SEG_RE.fullmatch(tail)
                            or (len(tail) >= 8 and re.fullmatch(r"[A-Za-z0-9_-]+", tail) and any(c.isdigit() for c in tail))):
                        item_type = canonical_resource_type(safe_det)
                        ns_key = (item_type, tail)
                        if ns_key in seen_html_items:
                            continue
                        seen_html_items.add(ns_key)
                        extracted.append({
                            "resource_type": item_type,
                            "key": tail,
                            "typed_key": f"{item_type}::{tail}",
                            "link": safe_det,
                            "tenants": [],
                            "owners": [],
                            "fields": [],
                            "record": {},
                        })
            collection_observations[(actor_name, col_url)] = {
                "actor": actor_name,
                "url": col_url,
                "resource_type": col_type,
                "status": status,
                "ok": bool(resp.get("ok")),
                "record_count": len(extracted),
                "keys": [row["key"] for row in extracted],
                "list_fields": sorted({f for row in extracted for f in row["fields"]}),
                "tenants": sorted({t for row in extracted for t in row["tenants"]}),
                "parsed": parsed,
            }
            for row in extracted:
                ns_key = (row["resource_type"], row["key"])
                entry = typed_registry.setdefault(ns_key, {
                    "resource_type": row["resource_type"],
                    "key": row["key"],
                    "typed_key": row["typed_key"],
                    "observed_by": [],
                    "tenants": set(),
                    "owners": set(),
                    "list_fields": set(),
                    "detail_urls": set(),
                    "collection_urls": set(),
                })
                if actor_name not in entry["observed_by"]:
                    entry["observed_by"].append(actor_name)
                entry["tenants"].update(row["tenants"])
                entry["owners"].update(row["owners"])
                entry["list_fields"].update(row["fields"])
                entry["collection_urls"].add(col_url)
                if row["link"]:
                    safe_det = _safe_link(col_url, row["link"], origin, permits)
                    if safe_det:
                        entry["detail_urls"].add(safe_det)

    hydrated_templates: dict[str, list[dict[str, Any]]] = {}
    for tpl in template_routes:
        tpl_url = str(tpl.get("url") or "").strip()
        tpl_method = str(tpl.get("method") or "GET").upper()
        slots = _TEMPLATE_SLOT_RE.findall(tpl_url)
        if len(slots) != 1:
            continue
        tpl_type = canonical_resource_type(tpl_url)
        matches = [entry for (rtype, _), entry in sorted(typed_registry.items()) if rtype == tpl_type]
        if not matches and any(tok in slots[0].lower() for tok in ("id", "plan", "item", "record")):
            # Bounded integer-seed hydration ONLY for collection-less detail templates (e.g. GET /plans returns 404).
            for seed_key in ("1", "2"):
                concrete_seed = hydrate_template_url(tpl_url, seed_key, param_name=slots[0])
                if not concrete_seed or not permits(concrete_seed):
                    continue
                for actor_name, identity in identities.items():
                    if requests_used >= max_requests:
                        break
                    headers = identity.get("headers") if isinstance(identity, dict) else None
                    if not isinstance(headers, dict):
                        continue
                    resp = _call(concrete_seed, headers)
                    if resp.get("ok") and resp.get("status") == 200:
                        try:
                            seed_parsed = json.loads(str(resp.get("text") or ""))
                        except ValueError:
                            seed_parsed = None
                        if isinstance(seed_parsed, dict):
                            ns_key = (tpl_type, seed_key)
                            entry = typed_registry.setdefault(ns_key, {
                                "resource_type": tpl_type,
                                "key": seed_key,
                                "typed_key": f"{tpl_type}::{seed_key}",
                                "observed_by": [],
                                "tenants": set(),
                                "owners": set(),
                                "list_fields": set(str(k) for k in seed_parsed.keys()),
                                "detail_urls": set(),
                                "collection_urls": set(),
                            })
                            if actor_name not in entry["observed_by"]:
                                entry["observed_by"].append(actor_name)
                            entry["tenants"].update(normalize_tenant_values(seed_parsed))
                            entry["owners"].update(normalize_owner_values(seed_parsed))
                            entry["detail_urls"].add(concrete_seed)
            matches = [entry for (rtype, _), entry in sorted(typed_registry.items()) if rtype == tpl_type]
        hydrated_list: list[dict[str, Any]] = []
        for entry in matches:
            concrete = hydrate_template_url(tpl_url, entry["key"], param_name=slots[0])
            if not concrete or not permits(concrete):
                continue
            entry["detail_urls"].add(concrete)
            hydrated_list.append({
                "template": tpl_url,
                "method": tpl_method,
                "url": concrete,
                "param_name": slots[0],
                "resource_type": tpl_type,
                "key": entry["key"],
                "observed_by": list(entry["observed_by"]),
                "tenants": sorted(entry["tenants"]),
                "owners": sorted(entry["owners"]),
                "list_fields": sorted(entry["list_fields"]),
            })
        if hydrated_list:
            hydrated_templates[f"{tpl_method} {tpl_url}"] = hydrated_list

    # Fetch bounded owner detail GETs round-robin across resource types so no family starves.
    detail_observations: dict[tuple[str, str], dict[str, Any]] = {}
    for actor_name, identity in identities.items():
        headers = identity.get("headers") if isinstance(identity, dict) else None
        if not isinstance(headers, dict):
            continue
        by_type: dict[str, list[tuple[tuple[str, str], dict[str, Any]]]] = {}
        for (rtype, key), entry in sorted(typed_registry.items()):
            if actor_name in entry["observed_by"] and entry["detail_urls"]:
                by_type.setdefault(rtype, []).append(((rtype, key), entry))
        ordered_entries: list[tuple[tuple[str, str], dict[str, Any]]] = []
        round_idx = 0
        while len(ordered_entries) < max_detail_per_actor:
            added = False
            for rtype in sorted(by_type):
                bucket = by_type[rtype]
                if round_idx < len(bucket):
                    ordered_entries.append(bucket[round_idx])
                    added = True
                    if len(ordered_entries) >= max_detail_per_actor:
                        break
            if not added:
                break
            round_idx += 1

        fetched_for_actor = 0
        for (rtype, key), entry in ordered_entries:
            if fetched_for_actor >= max_detail_per_actor or requests_used >= max_requests:
                break
            detail_url = next(iter(sorted(entry["detail_urls"])), "")
            if not detail_url:
                continue
            resp = _call(detail_url, headers)
            fetched_for_actor += 1
            text = str(resp.get("text") or "")
            parsed = None
            if resp.get("ok") and resp.get("status") == 200:
                try:
                    parsed = json.loads(text)
                except ValueError:
                    parsed = None
            if isinstance(parsed, dict):
                entry["tenants"].update(normalize_tenant_values(parsed))
                entry["owners"].update(normalize_owner_values(parsed))
            detail_observations[(actor_name, detail_url)] = {
                "actor": actor_name,
                "url": detail_url,
                "resource_type": rtype,
                "key": key,
                "status": resp.get("status"),
                "ok": bool(resp.get("ok")),
                "parsed": parsed,
                "text": text,
                "fields": sorted(str(k) for k in parsed.keys()) if isinstance(parsed, dict) else [],
            }

    serialized_registry = {
        f"{rtype}::{key}": {
            "resource_type": rtype,
            "key": key,
            "observed_by": list(entry["observed_by"]),
            "tenants": sorted(entry["tenants"]),
            "owners": sorted(entry["owners"]),
            "list_fields": sorted(entry["list_fields"]),
            "detail_urls": sorted(entry["detail_urls"]),
            "collection_urls": sorted(entry["collection_urls"]),
        }
        for (rtype, key), entry in sorted(typed_registry.items())
    }
    return {
        "status": "ready" if typed_registry else "incomplete",
        "requests": requests_used,
        "resources": serialized_registry,
        "hydrated_templates": hydrated_templates,
        "collection_observations": collection_observations,
        "detail_observations": detail_observations,
        "reasons": [] if typed_registry else ["no typed resources observed"],
    }
