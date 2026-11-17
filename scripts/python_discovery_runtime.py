"""Versioned host-private discovery state and redacted semantic frontier."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit

from python_candidate_runtime import card_route, valid_parameter_name

SCHEMA = "python-discovery-state/1"
FRONTIER_SCHEMA = "python-discovery-frontier/1"
ACTION_STATUSES = ("pending", "dispatched", "completed", "blocked", "indeterminate")
MAX_JSON_DISCOVERY_ITEMS = 64
MAX_JSON_DISCOVERY_DEPTH = 5
MAX_JSON_DISCOVERY_NODES = 1024
_PAGINATION_KEYS = frozenset({"next", "next_url", "prev", "previous", "prev_url", "first", "last"})
_DIRECT_LINK_KEYS = frozenset({"url", "href", "uri", "link", "action", "endpoint", "self"})
_ENVELOPE_LINK_LIST_KEYS = frozenset({
    "links", "internal_links", "urls_sample", "pages", "urls_with_params", "form_actions", "js_files", "actions", "forms",
})
_ENVELOPE_RECORD_LIST_KEYS = frozenset({"records", "work_queue"})
_COLLECTION_CONTAINER_KEYS = frozenset({
    "items", "results", "data", "entries", "pagination", "paging", "page_info", "meta", "_links", "hal", "surface",
})
_PAGINATION_CONTAINER_KEYS = frozenset({"pagination", "paging", "page_info"})
_STATUS_RANK = {
    "pending": 0,
    "dispatched": 1,
    "indeterminate": 2,
    "blocked": 2,
    "completed": 3,
}
_FRONTIER_PRIORITY = {
    "pending": 0,
    "indeterminate": 1,
    "blocked": 2,
    "dispatched": 3,
    "completed": 4,
}
DISCOVERY_TOOLS = frozenset({
    "kali-tools_crawl_web_surface",
    "kali-tools_curl_request",
    "kali-tools_compose_js_routes",
    "browser_browser_extract_links",
    "browser_browser_capture_requests",
    "browser_browser_runtime_observe",
})
FRONTIER_LIMIT = 12
FRONTIER_BYTES = 3000
COMPACT_FRONTIER_LIMIT = 4
COMPACT_FRONTIER_BYTES = 1200
SUMMARY_FRONTIER_LIMIT = 3
SUMMARY_FRONTIER_BYTES = 768
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def normalize_identity(identity_ref: Any) -> str:
    """Normalize anonymous aliases while rejecting non-string identity refs."""
    if identity_ref in (None, "", "anonymous"):
        return "anon"
    if not isinstance(identity_ref, str):
        raise ValueError("invalid_discovery_identity")
    return identity_ref


def discovery_state_key(task_spec_id: str, target: str, identity_ref: str = "anon") -> str:
    """Return a deterministic host key for (task, target, identity)."""
    if not isinstance(task_spec_id, str) or not task_spec_id:
        raise ValueError("invalid_discovery_task")
    if not isinstance(target, str) or not target:
        raise ValueError("invalid_discovery_target")
    identity = normalize_identity(identity_ref)
    return hashlib.sha256(_canonical_json([task_spec_id, target, identity])).hexdigest()


def stable_action_id(
    task_spec_id: str,
    target: str,
    identity_ref: str = "anon",
    *,
    method: str = "GET",
    url: str,
    kind: str = "http_request",
    param_names: Sequence[str] = (),
) -> str:
    """Derive a stable action ID without exposing operational URL values."""
    if not isinstance(url, str) or not url:
        raise ValueError("invalid_discovery_url")
    identity = normalize_identity(identity_ref)
    norm_method = (method or "GET").upper()
    norm_kind = str(kind or "http_request")
    names = sorted(dict.fromkeys(str(name) for name in param_names if isinstance(name, str) and name))
    return hashlib.sha256(
        _canonical_json([task_spec_id, target, identity, norm_kind, norm_method, url, names])
    ).hexdigest()


def normalize_provenance(item: Any) -> dict[str, Any]:
    """Validate source-artifact provenance before admitting any discovery entry."""
    if not isinstance(item, dict):
        raise ValueError("missing_or_invalid_discovery_provenance")
    source_spec_id = item.get("source_spec_id")
    source_artifact = item.get("source_artifact")
    source_sha256 = item.get("source_sha256")
    if (
        not isinstance(source_spec_id, str)
        or not source_spec_id
        or not isinstance(source_artifact, str)
        or not source_artifact
        or not isinstance(source_sha256, str)
        or not _SHA256_RE.fullmatch(source_sha256)
    ):
        raise ValueError("missing_or_invalid_discovery_provenance")
    normalized: dict[str, Any] = {
        "source_spec_id": source_spec_id,
        "source_artifact": source_artifact,
        "source_sha256": source_sha256,
    }
    tool = item.get("tool")
    if isinstance(tool, str) and tool:
        normalized["tool"] = tool
    return normalized


def redact_route_shape(url: str) -> str:
    """Return a value-free route shape without query values, fragments, or secrets."""
    return card_route(url)


def _extract_param_names(url: str, params: Sequence[Any]) -> tuple[list[dict[str, Any]], list[str]]:
    stored_params: list[dict[str, Any]] = []
    names: list[str] = []
    seen: set[str] = set()
    for item in params:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]:
            name = item["name"]
            stored_params.append(copy.deepcopy(item))
            if valid_parameter_name(name) and name not in seen:
                seen.add(name)
                names.append(name)
        elif isinstance(item, str) and item:
            stored_params.append({"name": item, "in": "query"})
            if valid_parameter_name(item) and item not in seen:
                seen.add(item)
                names.append(item)
    raw_query = urlsplit(url).query
    if raw_query:
        for name, val in parse_qsl(raw_query, keep_blank_values=True):
            if valid_parameter_name(name) and name not in seen:
                seen.add(name)
                names.append(name)
                stored_params.append({"name": name, "in": "query", "sample": val})
    return stored_params, names


def _dedup_dicts(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [json.loads(raw) for raw in dict.fromkeys(_canonical_json(row).decode("utf-8") for row in rows)]


def _public_action_item(action: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "action_id": action["action_id"],
        "status": action["status"],
        "kind": action["kind"],
        "method": action["method"],
        "route_shape": action["route_shape"],
        "param_names": list(action.get("param_names", [])),
        "link_relation": action.get("link_relation", "observed"),
        "identity_ref": action["identity_ref"],
        "parent_action_id": action.get("parent_action_id"),
        "child_count": len(action.get("child_action_ids", [])),
        "provenance": copy.deepcopy(action.get("provenance", [])[:1]),
    }
    if action.get("carrier"):
        item["carrier"] = action["carrier"]
    if action.get("content_type"):
        item["content_type"] = action["content_type"]
    if action.get("reason_code"):
        item["reason_code"] = action["reason_code"]
    return item


class DiscoveryState:
    """Host-private discovery frontier keyed by task, target, and identity."""

    def __init__(
        self,
        *,
        task_spec_id: str,
        target: str,
        identity_ref: str = "anon",
        sources: Sequence[dict[str, Any]] | None = None,
        actions: dict[str, dict[str, Any]] | None = None,
        continuation: dict[str, Any] | None = None,
    ) -> None:
        if not isinstance(task_spec_id, str) or not task_spec_id:
            raise ValueError("invalid_discovery_task")
        if not isinstance(target, str) or not target:
            raise ValueError("invalid_discovery_target")
        self.schema = SCHEMA
        self.task_spec_id = task_spec_id
        self.target = target
        self.identity_ref = normalize_identity(identity_ref)
        self.sources: list[dict[str, Any]] = []
        for source in sources or ():
            self.add_source(source)
        self.actions: dict[str, dict[str, Any]] = {}
        if actions:
            for ident, action in actions.items():
                if not isinstance(action, dict) or action.get("action_id") != ident:
                    raise ValueError("invalid_discovery_action")
                if action.get("status") not in ACTION_STATUSES:
                    raise ValueError("invalid_discovery_action_status")
                prov_list = action.get("provenance")
                if not isinstance(prov_list, list) or not prov_list:
                    raise ValueError("missing_or_invalid_discovery_provenance")
                normalized_prov = [normalize_provenance(item) for item in prov_list]
                copy_action = copy.deepcopy(action)
                copy_action["provenance"] = _dedup_dicts(normalized_prov)
                copy_action["identity_ref"] = normalize_identity(copy_action.get("identity_ref", self.identity_ref))
                if copy_action["identity_ref"] != self.identity_ref:
                    raise ValueError("discovery_action_identity_mismatch")
                if copy_action.get("task_spec_id") != self.task_spec_id or copy_action.get("target") != self.target:
                    raise ValueError("discovery_action_scope_mismatch")
                self.actions[ident] = copy_action
        self.continuation: dict[str, Any] = copy.deepcopy(continuation) if isinstance(continuation, dict) else {
            "dispatched_count": 0,
            "last_reason": "",
        }

    @property
    def key(self) -> str:
        return discovery_state_key(self.task_spec_id, self.target, self.identity_ref)

    def add_source(self, provenance: dict[str, Any]) -> dict[str, Any]:
        normalized = normalize_provenance(provenance)
        self.sources = _dedup_dicts([*self.sources, normalized])
        return normalized

    def record_action(
        self,
        *,
        url: str,
        method: str = "GET",
        kind: str = "http_request",
        params: Sequence[Any] = (),
        link_relation: str = "observed",
        parent_action_id: str | None = None,
        provenance: dict[str, Any] | Sequence[dict[str, Any]],
        status: str = "pending",
        reason_code: str = "",
        http_status: int | None = None,
        result_artifact: str | None = None,
        result_sha256: str | None = None,
        carrier: str = "",
        content_type: str = "",
    ) -> dict[str, Any]:
        if status not in ACTION_STATUSES:
            raise ValueError("invalid_discovery_action_status")
        prov_items = [provenance] if isinstance(provenance, dict) else list(provenance)
        if not prov_items:
            raise ValueError("missing_or_invalid_discovery_provenance")
        normalized_prov = [self.add_source(item) for item in prov_items]
        norm_method = (method or "GET").upper()
        norm_kind = str(kind or "http_request")
        norm_carrier = str(carrier or "").strip().lower()
        norm_ctype = str(content_type or "").split(";", 1)[0].strip().lower()
        stored_params, param_names = _extract_param_names(url, params)
        action_id = stable_action_id(
            self.task_spec_id,
            self.target,
            self.identity_ref,
            method=norm_method,
            url=url,
            kind=norm_kind,
            param_names=param_names,
        )
        route_shape = redact_route_shape(url)
        relation = str(link_relation or "observed")
        depth = 0
        if parent_action_id and parent_action_id in self.actions and parent_action_id != action_id:
            depth = int(self.actions[parent_action_id].get("continuation_depth", 0)) + 1

        existing = self.actions.get(action_id)
        if existing is None:
            record: dict[str, Any] = {
                "action_id": action_id,
                "task_spec_id": self.task_spec_id,
                "target": self.target,
                "identity_ref": self.identity_ref,
                "kind": norm_kind,
                "method": norm_method,
                "url": url,
                "route_shape": route_shape,
                "params": stored_params,
                "param_names": param_names,
                "link_relation": relation,
                "link_relations": [relation],
                "parent_action_id": parent_action_id if parent_action_id != action_id else None,
                "parent_action_ids": [parent_action_id] if parent_action_id and parent_action_id != action_id else [],
                "child_action_ids": [],
                "status": status,
                "reason_code": str(reason_code or ""),
                "http_status": http_status,
                "provenance": _dedup_dicts(normalized_prov),
                "result_artifact": result_artifact,
                "result_sha256": result_sha256,
                "continuation_depth": depth,
            }
            if norm_carrier:
                record["carrier"] = norm_carrier
            if norm_ctype:
                record["content_type"] = norm_ctype
            self.actions[action_id] = record
        else:
            existing["provenance"] = _dedup_dicts([*existing["provenance"], *normalized_prov])
            if relation not in existing["link_relations"]:
                existing["link_relations"].append(relation)
            if relation == "pagination" or (
                relation == "json_link" and existing.get("link_relation") != "pagination"
            ):
                existing["link_relation"] = relation
            if norm_carrier and not existing.get("carrier"):
                existing["carrier"] = norm_carrier
            if norm_ctype and not existing.get("content_type"):
                existing["content_type"] = norm_ctype
            if parent_action_id and parent_action_id != action_id:
                if existing.get("parent_action_id") is None:
                    existing["parent_action_id"] = parent_action_id
                if parent_action_id not in existing["parent_action_ids"]:
                    existing["parent_action_ids"].append(parent_action_id)
            cur_rank = _STATUS_RANK[existing["status"]]
            new_rank = _STATUS_RANK[status]
            if new_rank > cur_rank or (new_rank == cur_rank and new_rank >= 1 and (
                result_artifact is not None or http_status is not None or reason_code
            )):
                existing["status"] = status
                if reason_code or status == "completed":
                    existing["reason_code"] = str(reason_code or "")
                if http_status is not None:
                    existing["http_status"] = http_status
                if result_artifact is not None:
                    existing["result_artifact"] = result_artifact
                if result_sha256 is not None:
                    existing["result_sha256"] = result_sha256

        if parent_action_id and parent_action_id in self.actions and parent_action_id != action_id:
            children = self.actions[parent_action_id].setdefault("child_action_ids", [])
            if action_id not in children:
                children.append(action_id)
        return self.actions[action_id]

    def _transition(
        self,
        action_id: str,
        status: str,
        *,
        reason_code: str = "",
        http_status: int | None = None,
        result_artifact: str | None = None,
        result_sha256: str | None = None,
    ) -> dict[str, Any]:
        if action_id not in self.actions:
            raise KeyError(f"unknown discovery action: {action_id}")
        if status not in ACTION_STATUSES:
            raise ValueError("invalid_discovery_action_status")
        action = self.actions[action_id]
        if _STATUS_RANK[status] < _STATUS_RANK[action["status"]]:
            raise ValueError("invalid_discovery_status_regression")
        action["status"] = status
        action["reason_code"] = str(reason_code or "")
        if http_status is not None:
            action["http_status"] = http_status
        if result_artifact is not None:
            action["result_artifact"] = result_artifact
        if result_sha256 is not None:
            action["result_sha256"] = result_sha256
        return action

    def mark_dispatched(self, action_id: str) -> dict[str, Any]:
        return self._transition(action_id, "dispatched")

    def mark_completed(
        self,
        action_id: str,
        *,
        http_status: int | None = None,
        result_artifact: str | None = None,
        result_sha256: str | None = None,
    ) -> dict[str, Any]:
        return self._transition(
            action_id,
            "completed",
            reason_code="",
            http_status=http_status,
            result_artifact=result_artifact,
            result_sha256=result_sha256,
        )

    def mark_blocked(
        self,
        action_id: str,
        *,
        reason_code: str = "blocked",
        http_status: int | None = None,
        result_artifact: str | None = None,
        result_sha256: str | None = None,
    ) -> dict[str, Any]:
        return self._transition(
            action_id,
            "blocked",
            reason_code=reason_code,
            http_status=http_status,
            result_artifact=result_artifact,
            result_sha256=result_sha256,
        )

    def mark_indeterminate(
        self,
        action_id: str,
        *,
        reason_code: str = "indeterminate",
        result_artifact: str | None = None,
        result_sha256: str | None = None,
    ) -> dict[str, Any]:
        return self._transition(
            action_id,
            "indeterminate",
            reason_code=reason_code,
            result_artifact=result_artifact,
            result_sha256=result_sha256,
        )

    def mark_interrupted_dispatched_indeterminate(self) -> int:
        updated = 0
        for action in self.actions.values():
            if action["status"] == "dispatched":
                action["status"] = "indeterminate"
                action["reason_code"] = "interrupted_dispatch"
                updated += 1
        return updated

    def resolve_action(self, action_id: str) -> dict[str, Any] | None:
        """Host-private lookup by action ID; never reconstruct from public cards."""
        action = self.actions.get(action_id)
        return copy.deepcopy(action) if action is not None else None

    def actions_by_status(self, *statuses: str) -> list[dict[str, Any]]:
        allowed = set(statuses) if statuses else set(ACTION_STATUSES)
        rows = [copy.deepcopy(action) for action in self.actions.values() if action["status"] in allowed]
        rows.sort(key=lambda row: (
            _FRONTIER_PRIORITY[row["status"]],
            int(row.get("continuation_depth", 0)),
            row["route_shape"],
            row["action_id"],
        ))
        return rows

    def pending_actions(self) -> list[dict[str, Any]]:
        return self.actions_by_status("pending")

    def counts(self) -> dict[str, int]:
        result = {"total": len(self.actions), **{status: 0 for status in ACTION_STATUSES}}
        for action in self.actions.values():
            result[action["status"]] += 1
        return result

    def public_projection(
        self,
        *,
        max_items: int = FRONTIER_LIMIT,
        max_bytes: int = FRONTIER_BYTES,
    ) -> dict[str, Any]:
        return project_discovery_frontier(
            [self],
            task_spec_id=self.task_spec_id,
            target=self.target,
            max_items=max_items,
            max_bytes=max_bytes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "task_spec_id": self.task_spec_id,
            "target": self.target,
            "identity_ref": self.identity_ref,
            "sources": copy.deepcopy(self.sources),
            "actions": copy.deepcopy(self.actions),
            "continuation": copy.deepcopy(self.continuation),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveryState:
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            raise ValueError("invalid_discovery_state_schema")
        return cls(
            task_spec_id=data.get("task_spec_id", ""),
            target=data.get("target", ""),
            identity_ref=data.get("identity_ref", "anon"),
            sources=data.get("sources"),
            actions=data.get("actions"),
            continuation=data.get("continuation"),
        )


def project_discovery_frontier(
    states: Sequence[DiscoveryState] | dict[str, DiscoveryState],
    *,
    task_spec_id: str = "",
    target: str = "",
    max_items: int = FRONTIER_LIMIT,
    max_bytes: int = FRONTIER_BYTES,
) -> dict[str, Any]:
    """Build a bounded, redacted semantic frontier from private DiscoveryState."""
    state_list = list(states.values()) if isinstance(states, dict) else list(states)
    counts = {"total": 0, **{status: 0 for status in ACTION_STATUSES}}
    identity_refs: list[str] = []
    all_actions: list[dict[str, Any]] = []
    inferred_task = task_spec_id
    inferred_target = target
    for state in state_list:
        if not inferred_task:
            inferred_task = state.task_spec_id
        if not inferred_target:
            inferred_target = state.target
        if state.identity_ref not in identity_refs:
            identity_refs.append(state.identity_ref)
        state_counts = state.counts()
        for key, value in state_counts.items():
            counts[key] += value
        all_actions.extend(state.actions.values())

    all_actions.sort(key=lambda row: (
        _FRONTIER_PRIORITY[row["status"]],
        int(row.get("continuation_depth", 0)),
        row["route_shape"],
        row["action_id"],
    ))
    frontier: list[dict[str, Any]] = []
    for action in all_actions:
        if len(frontier) >= max_items:
            break
        card = _public_action_item(action)
        candidate = [*frontier, card]
        if len(_canonical_json(candidate)) > max_bytes:
            break
        frontier.append(card)

    return {
        "schema": FRONTIER_SCHEMA,
        "task_spec_id": inferred_task,
        "target": inferred_target,
        "identity_refs": sorted(identity_refs),
        "counts": counts,
        "frontier": frontier,
        "frontier_total": len(all_actions),
        "truncated": len(frontier) < len(all_actions) or any(
            bool(s.continuation.get("slice_truncated")) for s in state_list
        ),
    }


def compact_frontier(
    frontier_doc: dict[str, Any] | None,
    *,
    max_items: int = COMPACT_FRONTIER_LIMIT,
    max_bytes: int = COMPACT_FRONTIER_BYTES,
) -> dict[str, Any] | None:
    """Shrink an already-redacted discovery_frontier payload for tight projections."""
    if not isinstance(frontier_doc, dict):
        return None
    items = frontier_doc.get("frontier")
    source_items = items if isinstance(items, list) else []
    selected: list[dict[str, Any]] = []
    for item in source_items:
        if len(selected) >= max_items or not isinstance(item, dict):
            break
        trimmed = {
            key: copy.deepcopy(item[key])
            for key in (
                "action_id",
                "status",
                "kind",
                "method",
                "carrier",
                "content_type",
                "route_shape",
                "param_names",
                "link_relation",
                "identity_ref",
                "parent_action_id",
                "child_count",
                "reason_code",
            )
            if key in item
        }
        if isinstance(item.get("provenance"), list) and item["provenance"]:
            prov = item["provenance"][0]
            if isinstance(prov, dict) and prov.get("source_artifact"):
                trimmed["provenance"] = [{"source_artifact": prov["source_artifact"]}]
        if len(_canonical_json([*selected, trimmed])) > max_bytes:
            break
        selected.append(trimmed)
    total = int(frontier_doc.get("frontier_total") or len(source_items))
    return {
        "schema": FRONTIER_SCHEMA,
        "task_spec_id": frontier_doc.get("task_spec_id", ""),
        "target": frontier_doc.get("target", ""),
        "identity_refs": list(frontier_doc.get("identity_refs", [])),
        "counts": copy.deepcopy(frontier_doc.get("counts", {})),
        "frontier": selected,
        "frontier_total": total,
        "truncated": bool(frontier_doc.get("truncated")) or len(selected) < len(source_items),
    }


def _normalize_candidate_link(
    raw: Any,
    base_url: str,
    origin_url: str,
    *,
    allow_bare_relative: bool = True,
) -> str | None:
    """Resolve explicit relative/same-origin URLs without inventing links from arbitrary scalars."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text or len(text) > 2048 or text.startswith("#"):
        return None
    if any(ch.isspace() or ord(ch) < 32 for ch in text):
        return None
    if not allow_bare_relative and not text.startswith(("http://", "https://", "/", "./", "../", "?")):
        return None
    if text.isdigit():
        return None
    parsed_raw = urlsplit(text)
    if parsed_raw.scheme and parsed_raw.scheme.lower() not in {"http", "https"}:
        return None
    resolved = urljoin(base_url, text)
    parsed = urlsplit(resolved)
    origin = urlsplit(origin_url)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc)
        or parsed.username is not None
    ):
        return None
    return parsed._replace(fragment="").geturl()


def structured_params_from_node(node: dict[str, Any], method: str = "GET") -> tuple[list[dict[str, Any]] | None, str]:
    """Extract normalized form/json param declarations and content_type from a descriptor object."""
    norm_method = str(method or "GET").upper()
    raw_ctype = node.get("content_type")
    ctype = raw_ctype.split(";", 1)[0].strip().lower() if isinstance(raw_ctype, str) else ""
    if isinstance(node.get("params"), list):
        return copy.deepcopy(node["params"]), ctype
    if norm_method == "GET":
        return None, ctype
    json_obj = node.get("json_body") if isinstance(node.get("json_body"), dict) else (
        node.get("body") if isinstance(node.get("body"), dict) and ctype in {"", "application/json"} else None
    )
    if isinstance(json_obj, dict):
        derived = [
            {
                "name": k,
                "in": "json",
                "sample": "" if v is None else ("true" if v is True else "false" if v is False else str(v)),
            }
            for k, v in json_obj.items()
            if valid_parameter_name(k) and (v is None or isinstance(v, (str, int, float, bool)))
        ]
        return derived, ctype or "application/json"
    form_obj = (
        node.get("form") if isinstance(node.get("form"), dict)
        else node.get("form_fields") if isinstance(node.get("form_fields"), dict)
        else node.get("fields") if isinstance(node.get("fields"), dict)
        else None
    )
    if isinstance(form_obj, dict):
        param_in = "json" if ctype == "application/json" else "form"
        derived = [
            {
                "name": k,
                "in": param_in,
                "sample": "" if v is None else ("true" if v is True else "false" if v is False else str(v)),
            }
            for k, v in form_obj.items()
            if valid_parameter_name(k) and (v is None or isinstance(v, (str, int, float, bool)))
        ]
        return derived, ctype or ("application/json" if param_in == "json" else "application/x-www-form-urlencoded")
    return None, ctype


def extract_json_hypermedia(
    payload: Any,
    base_url: str,
    *,
    origin_url: str | None = None,
    from_http_body: bool = True,
    max_items: int = MAX_JSON_DISCOVERY_ITEMS,
    max_depth: int = MAX_JSON_DISCOVERY_DEPTH,
    max_nodes: int = MAX_JSON_DISCOVERY_NODES,
) -> tuple[list[dict[str, Any]], bool]:
    """Bounded extraction of relative/same-origin JSON hypermedia and pagination links.

    Never invents request URLs from arbitrary scalars or object IDs.
    """
    if not isinstance(payload, (dict, list)) or not isinstance(base_url, str) or not base_url:
        return [], False
    effective_origin = origin_url or base_url
    extracted: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    truncated = False
    nodes_visited = 0

    _unset = object()

    def _emit(
        raw_url: Any,
        *,
        method: str = "GET",
        params: Any = _unset,
        link_relation: str = "json_link",
        extra: dict[str, Any] | None = None,
        allow_bare_relative: bool = True,
    ) -> None:
        nonlocal truncated
        if len(extracted) >= max_items:
            truncated = True
            return
        resolved = _normalize_candidate_link(
            raw_url,
            base_url,
            effective_origin,
            allow_bare_relative=allow_bare_relative,
        )
        if not resolved:
            return
        norm_method = str(method or "GET").upper()
        ident = ""
        ctype = ""
        if isinstance(extra, dict):
            raw_ident = extra.get("identity_ref", extra.get("identity", ""))
            ident = str(raw_ident) if isinstance(raw_ident, str) else ""
            derived_params, ctype = structured_params_from_node(extra, norm_method)
            if params is _unset and derived_params is not None:
                params = derived_params
        dedup_key = (norm_method, resolved, ident, link_relation, ctype)
        if dedup_key in seen:
            return
        seen.add(dedup_key)
        item: dict[str, Any] = {
            "url": resolved,
            "method": norm_method,
        }
        if link_relation:
            item["link_relation"] = link_relation
        if params is not _unset:
            item["params"] = copy.deepcopy(params)
        if ctype:
            item["content_type"] = ctype
        if isinstance(extra, dict):
            for field in ("identity_ref", "identity", "candidate_reason", "operation_id"):
                if field in extra:
                    item[field] = copy.deepcopy(extra[field])
        extracted.append(item)

    def _walk(node: Any, *, depth: int, parent_key: str, in_pagination: bool) -> None:
        nonlocal nodes_visited, truncated
        if truncated:
            return
        if depth > max_depth:
            return
        nodes_visited += 1
        if nodes_visited > max_nodes:
            truncated = True
            return
        if isinstance(node, list):
            for element in node:
                if truncated:
                    return
                if isinstance(element, str) and parent_key in _ENVELOPE_LINK_LIST_KEYS:
                    rel = "pagination" if in_pagination else ("json_link" if from_http_body or parent_key == "links" else "")
                    _emit(element, link_relation=rel)
                elif isinstance(element, dict):
                    _walk(element, depth=depth + 1, parent_key=parent_key, in_pagination=in_pagination)
                elif isinstance(element, list):
                    _walk(element, depth=depth + 1, parent_key=parent_key, in_pagination=in_pagination)
            return
        if not isinstance(node, dict):
            return

        rel_value = str(node.get("rel") or "").strip().lower()
        node_pagination = in_pagination or rel_value in _PAGINATION_KEYS
        default_rel = "json_link" if (from_http_body or parent_key in {"items", "results", "data", "entries", "_links", "links"}) else ""
        direct_url = (
            node.get("url") if "url" in node
            else node.get("href") if "href" in node
            else (node.get("action") if "action" in node and "method" in node
                  else node.get("endpoint") if "endpoint" in node and "method" in node
                  else None)
        )
        if isinstance(direct_url, str) and (
            parent_key in _ENVELOPE_LINK_LIST_KEYS
            or parent_key in _ENVELOPE_RECORD_LIST_KEYS
            or parent_key in _COLLECTION_CONTAINER_KEYS
            or parent_key in _PAGINATION_KEYS
            or parent_key in _DIRECT_LINK_KEYS
            or depth == 0
        ):
            _emit(
                direct_url,
                method=str(node.get("method") or "GET"),
                params=node["params"] if "params" in node else _unset,
                link_relation="pagination" if node_pagination else ("self" if rel_value == "self" else default_rel),
                extra=node,
            )

        for key, value in node.items():
            if truncated:
                return
            if not isinstance(key, str):
                continue
            low = key.lower()
            if low in {"url", "href", "action", "endpoint"} and value is direct_url:
                continue
            if low in _PAGINATION_KEYS:
                if isinstance(value, str):
                    _emit(value, link_relation="pagination")
                elif isinstance(value, dict):
                    _walk(value, depth=depth + 1, parent_key=low, in_pagination=True)
            elif low in _DIRECT_LINK_KEYS:
                if isinstance(value, str):
                    rel = "self" if low == "self" else ("pagination" if node_pagination else default_rel)
                    _emit(value, link_relation=rel)
                elif isinstance(value, dict):
                    _walk(value, depth=depth + 1, parent_key=low, in_pagination=node_pagination)
            elif low in _ENVELOPE_LINK_LIST_KEYS or low in _ENVELOPE_RECORD_LIST_KEYS or low in _COLLECTION_CONTAINER_KEYS:
                if not from_http_body and (
                    low in _ENVELOPE_RECORD_LIST_KEYS
                    or (low in _ENVELOPE_LINK_LIST_KEYS and not (low == "links" and isinstance(value, dict)))
                ):
                    continue
                child_pag = node_pagination or (low in _PAGINATION_CONTAINER_KEYS)
                if low in {"_links", "links"} and isinstance(value, dict):
                    for rel_name, target_val in value.items():
                        rel_low = str(rel_name).lower()
                        rel_tag = "pagination" if rel_low in _PAGINATION_KEYS else ("self" if rel_low == "self" else "json_link")
                        if isinstance(target_val, str):
                            _emit(target_val, link_relation=rel_tag)
                        elif isinstance(target_val, dict):
                            _walk(target_val, depth=depth + 1, parent_key=rel_low, in_pagination=rel_tag == "pagination")
                        elif isinstance(target_val, list):
                            _walk(target_val, depth=depth + 1, parent_key="links", in_pagination=rel_tag == "pagination")
                elif isinstance(value, (dict, list)):
                    _walk(value, depth=depth + 1, parent_key=low, in_pagination=child_pag)

    _walk(payload, depth=0, parent_key="", in_pagination=False)
    return extracted, truncated
