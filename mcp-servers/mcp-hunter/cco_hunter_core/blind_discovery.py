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


def _marker(url, ids):
    """Use only an observed opaque resource ID that is bound to its URL."""
    try:
        parsed = urlsplit(url)
        tokens = {unquote(part) for part in parsed.path.split("/") if part}
        tokens.update(value for _, value in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=64))
        choices = sorted(item for item in ids if len(item) >= 8 and item in tokens)
        return choices[0] if len(choices) == 1 else ""
    except ValueError:
        return ""


def _owned_record(url, records):
    matches = [(marker, owners) for owners, ids in records if (marker := _marker(url, ids))]
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
                              allow_private_owned=False, observations=None):
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
        return ""
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
                                    per_identity=12, max_depth=3, pace=None):
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
                    next_url = _safe_link(current, response.get("location") or "", origin, permits)
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
