"""External Belief-State Attack Graph (BSAG) with SQLite and JSON persistence."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
from typing import Any, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit

from agentic_http import is_static_asset_url, normalize_origin
from agentic_surface import (
    _is_auth_utility_path,
    is_id_segment,
    normalize_path,
    route_template_of,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SURFACE_CORE_PARENT = _REPO_ROOT / "mcp-servers" / "mcp-memory-server"
if str(_SURFACE_CORE_PARENT) not in sys.path:
    sys.path.insert(0, str(_SURFACE_CORE_PARENT))

from cco_surface_core.extract import (  # noqa: E402
    extract_html,
    extract_inline_scripts,
    extract_js,
    extract_js_calls,
    extract_json_hypermedia,
    extract_robots,
    extract_sitemap,
    extract_spa_routes,
    find_spec_urls,
)
from cco_surface_core.openapi import LocalSchema  # noqa: E402

NODE_ENDPOINT = "ENDPOINT"
NODE_AUTH_CONTEXT = "AUTH_CONTEXT"
NODE_HYPOTHESIS = "HYPOTHESIS"
NODE_ARTIFACT = "ARTIFACT"
VALID_NODE_TYPES = frozenset({NODE_ENDPOINT, NODE_AUTH_CONTEXT, NODE_HYPOTHESIS, NODE_ARTIFACT})

EDGE_NAVIGATES_TO = "NAVIGATES_TO"
EDGE_REQUIRES_CONTEXT = "REQUIRES_CONTEXT"
EDGE_TRIGGERS_STATE_CHANGE = "TRIGGERS_STATE_CHANGE"
EDGE_SUPPORTS = "SUPPORTS"
EDGE_REFUTES = "REFUTES"
VALID_EDGE_TYPES = frozenset({
    EDGE_NAVIGATES_TO,
    EDGE_REQUIRES_CONTEXT,
    EDGE_TRIGGERS_STATE_CHANGE,
    EDGE_SUPPORTS,
    EDGE_REFUTES,
})

STATUS_UNEXPLORED = "UNEXPLORED"
STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_CLAIMED = "CLAIMED"
STATUS_VERIFIED = "VERIFIED"
STATUS_REFUTED = "REFUTED"
STATUS_SUSPECT_DECOY = "SUSPECT_DECOY"
VALID_STATUSES = frozenset({
    STATUS_UNEXPLORED,
    STATUS_IN_PROGRESS,
    STATUS_CLAIMED,
    STATUS_VERIFIED,
    STATUS_REFUTED,
    STATUS_SUSPECT_DECOY,
})

_SECRET_FIELD_HINTS = ("password", "secret", "token", "jwt", "cookie", "session_key", "api_key", "csrf")
_ID_FIELD_HINTS = ("id", "uuid", "code", "serial", "slug", "ref", "number", "handle", "key")
_DECOY_THRESHOLD = 2.0


def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".bsag-", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:10]


def _append_unique(items: list[str], value: str, *, limit: int = 16) -> bool:
    clean = str(value or "").strip()
    if not clean or clean in items:
        return False
    items.append(clean)
    if len(items) > limit:
        del items[:-limit]
    return True


@dataclass
class BSAGNode:
    """Typed node in the external Belief-State Attack Graph."""

    node_id: str
    node_type: str
    label: str
    status: str = STATUS_UNEXPLORED
    visit_count: int = 0
    information_gain_ema: float = 0.5
    decoy_suspicion_score: float = 0.0
    last_new_edge_step: int = 0
    discovered_at_step: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "status": self.status,
            "visit_count": int(self.visit_count),
            "information_gain_ema": round(float(self.information_gain_ema), 4),
            "decoy_suspicion_score": round(float(self.decoy_suspicion_score), 4),
            "last_new_edge_step": int(self.last_new_edge_step),
            "discovered_at_step": int(self.discovered_at_step),
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BSAGNode:
        raw_ema = data.get("information_gain_ema")
        return cls(
            node_id=str(data["node_id"]),
            node_type=str(data["node_type"]),
            label=str(data.get("label") or data["node_id"]),
            status=str(data.get("status") or STATUS_UNEXPLORED),
            visit_count=int(data.get("visit_count") or 0),
            information_gain_ema=float(0.5 if raw_ema is None else raw_ema),
            decoy_suspicion_score=float(data.get("decoy_suspicion_score") or 0.0),
            last_new_edge_step=int(data.get("last_new_edge_step") or 0),
            discovered_at_step=int(data.get("discovered_at_step") or 0),
            attributes=dict(data.get("attributes") or {}),
        )


@dataclass
class BSAGEdge:
    """Typed directed edge in the external Belief-State Attack Graph."""

    edge_id: str
    src: str
    dst: str
    edge_type: str
    status: str = STATUS_UNEXPLORED
    step: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "src": self.src,
            "dst": self.dst,
            "edge_type": self.edge_type,
            "status": self.status,
            "step": int(self.step),
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BSAGEdge:
        return cls(
            edge_id=str(data["edge_id"]),
            src=str(data["src"]),
            dst=str(data["dst"]),
            edge_type=str(data["edge_type"]),
            status=str(data.get("status") or STATUS_UNEXPLORED),
            step=int(data.get("step") or 0),
            attributes=dict(data.get("attributes") or {}),
        )


class BeliefStateAttackGraph:
    """SQLite + JSON-backed typed directed graph tracking surface, auth, artifacts, and hypotheses."""

    def __init__(
        self,
        *,
        base_url: str,
        root_dir: str | Path | None = None,
        allowed_methods: Sequence[str] = ("GET", "HEAD"),
        actor_summaries: Sequence[dict[str, Any]] = (),
    ):
        self.base_url = normalize_origin(base_url)
        parsed = urlsplit(self.base_url)
        self._origin = (parsed.scheme, parsed.netloc)
        self.allowed_methods = frozenset(
            str(m).strip().upper() for m in allowed_methods if str(m).strip()
        ) or frozenset({"GET"})
        self.root_dir = Path(root_dir).expanduser().resolve() if root_dir else None
        self.sqlite_path = (self.root_dir / "bsag.sqlite") if self.root_dir else None
        self.json_path = (self.root_dir / "bsag.json") if self.root_dir else None

        self._lock = threading.RLock()
        self.nodes: dict[str, BSAGNode] = {}
        self.edges: dict[str, BSAGEdge] = {}
        self.step: int = 0

        for row in actor_summaries:
            if isinstance(row, dict) and row.get("alias"):
                self.register_auth_context(
                    alias=str(row["alias"]),
                    role=str(row.get("role") or "member"),
                    tenant=str(row.get("tenant") or ""),
                    authenticated=bool(row.get("authenticated", row["alias"] == "anon")),
                    dynamic=bool(row.get("dynamic", False)),
                    source_receipt_id=str(row.get("source_receipt_id") or ""),
                )
        if "auth:anon" not in self.nodes:
            self.register_auth_context(alias="anon", role="anonymous", tenant="", authenticated=True)

    @staticmethod
    def endpoint_node_id(url_or_path: str) -> str:
        tmpl = route_template_of(url_or_path)
        return f"ep:{tmpl}"

    @staticmethod
    def auth_node_id(alias: str) -> str:
        clean = str(alias or "anon").strip() or "anon"
        return f"auth:{clean}"

    def _next_step(self, explicit_step: int | None = None) -> int:
        if explicit_step is not None:
            self.step = max(self.step, int(explicit_step))
        else:
            self.step += 1
        return self.step

    def _resolve_same_origin_path(self, raw_url: str, current_url: str = "") -> tuple[str, str] | None:
        raw = str(raw_url or "").strip()
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "//")):
            return None
        base_ref = current_url if current_url else self.base_url
        resolved = urljoin(base_ref, raw)
        parsed = urlsplit(resolved)
        if (parsed.scheme, parsed.netloc) != self._origin:
            return None
        if is_static_asset_url(parsed.path):
            return None
        return normalize_path(parsed.path), parsed.query

    def _ensure_node(
        self,
        node_id: str,
        *,
        node_type: str,
        label: str,
        status: str = STATUS_UNEXPLORED,
        step: int,
        attributes: dict[str, Any] | None = None,
    ) -> tuple[BSAGNode, bool]:
        if node_type not in VALID_NODE_TYPES:
            raise ValueError(f"invalid node_type: {node_type!r}")
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid status: {status!r}")
        existing = self.nodes.get(node_id)
        if existing is not None:
            return existing, False
        node = BSAGNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            status=status,
            discovered_at_step=step,
            last_new_edge_step=step,
            attributes=dict(attributes or {}),
        )
        self.nodes[node_id] = node
        return node, True

    def _ensure_edge(
        self,
        src: str,
        dst: str,
        edge_type: str,
        *,
        status: str = STATUS_VERIFIED,
        step: int,
        attributes: dict[str, Any] | None = None,
    ) -> tuple[BSAGEdge, bool]:
        if edge_type not in VALID_EDGE_TYPES:
            raise ValueError(f"invalid edge_type: {edge_type!r}")
        edge_id = f"{src}|{edge_type}|{dst}"
        existing = self.edges.get(edge_id)
        if existing is not None:
            if attributes:
                existing.attributes.update(attributes)
            if status != STATUS_UNEXPLORED:
                existing.status = status
            return existing, False
        edge = BSAGEdge(
            edge_id=edge_id,
            src=src,
            dst=dst,
            edge_type=edge_type,
            status=status,
            step=step,
            attributes=dict(attributes or {}),
        )
        self.edges[edge_id] = edge
        for nid in (src, dst):
            if nid in self.nodes:
                self.nodes[nid].last_new_edge_step = max(self.nodes[nid].last_new_edge_step, step)
        return edge, True

    def ensure_endpoint(
        self,
        url_or_path: str,
        *,
        method: str = "GET",
        params: Sequence[str] = (),
        body_fields: Sequence[str] = (),
        declared_write: bool = False,
        step: int | None = None,
    ) -> tuple[BSAGNode, int]:
        """Ensure an ENDPOINT node exists for the normalized route template."""
        with self._lock:
            eff_step = self._next_step(step) if step is not None else self.step
            norm_p = normalize_path(url_or_path)
            tmpl = route_template_of(norm_p)
            nid = f"ep:{tmpl}"
            node, created = self._ensure_node(
                nid,
                node_type=NODE_ENDPOINT,
                label=tmpl,
                status=STATUS_UNEXPLORED,
                step=eff_step,
                attributes={
                    "route_template": tmpl,
                    "sample_paths": [],
                    "methods": [],
                    "declared_write_methods": [],
                    "query_params": [],
                    "body_fields": [],
                    "actors_tested": [],
                    "actors_2xx": [],
                    "actors_denied": [],
                    "sample_receipt_ids": [],
                    "is_auth_utility": _is_auth_utility_path(tmpl),
                },
            )
            attrs = node.attributes
            if "{" not in norm_p:
                _append_unique(attrs.setdefault("sample_paths", []), norm_p, limit=8)
            norm_m = str(method or "GET").strip().upper()
            if norm_m in self.allowed_methods:
                _append_unique(attrs.setdefault("methods", []), norm_m, limit=8)
            if declared_write and norm_m in {"POST", "PUT", "PATCH", "DELETE"} and norm_m in self.allowed_methods:
                _append_unique(attrs.setdefault("declared_write_methods", []), norm_m, limit=6)
            for p in params:
                pname = str(p.get("name") if isinstance(p, dict) else p or "").strip()
                if pname:
                    _append_unique(attrs.setdefault("query_params", []), pname, limit=20)
            for bf in body_fields:
                bname = str(bf or "").strip()
                if bname:
                    _append_unique(attrs.setdefault("body_fields", []), bname, limit=20)
            return node, (1 if created else 0)

    def register_auth_context(
        self,
        *,
        alias: str,
        role: str = "member",
        tenant: str = "",
        authenticated: bool = True,
        dynamic: bool = False,
        source_receipt_id: str = "",
        step: int | None = None,
    ) -> tuple[BSAGNode, int]:
        """Add or update an AUTH_CONTEXT node without storing any raw secret material."""
        with self._lock:
            eff_step = self._next_step(step) if step is not None else self.step
            clean_alias = str(alias or "anon").strip() or "anon"
            nid = self.auth_node_id(clean_alias)
            node, created = self._ensure_node(
                nid,
                node_type=NODE_AUTH_CONTEXT,
                label=clean_alias,
                status=STATUS_VERIFIED if authenticated else STATUS_UNEXPLORED,
                step=eff_step,
                attributes={
                    "alias": clean_alias,
                    "role": str(role or "member").strip().lower(),
                    "tenant": str(tenant or "").strip().lower(),
                    "authenticated": bool(authenticated),
                    "dynamic": bool(dynamic),
                    "source_receipt_id": str(source_receipt_id or ""),
                },
            )
            node.attributes.update({
                "role": str(role or node.attributes.get("role") or "member").strip().lower(),
                "tenant": str(tenant if tenant else node.attributes.get("tenant") or "").strip().lower(),
                "authenticated": bool(authenticated or node.attributes.get("authenticated")),
                "dynamic": bool(dynamic or node.attributes.get("dynamic")),
            })
            if source_receipt_id:
                node.attributes["source_receipt_id"] = str(source_receipt_id)
            if authenticated:
                node.status = STATUS_VERIFIED
            return node, (1 if created else 0)

    def register_artifact(
        self,
        *,
        kind: str,
        label: str,
        value_preview: str,
        source_node_id: str = "",
        receipt_id: str = "",
        high_signal: bool = True,
        step: int | None = None,
    ) -> tuple[BSAGNode, int, int]:
        """Register a non-secret ARTIFACT node and link it from source_node_id."""
        with self._lock:
            eff_step = self._next_step(step) if step is not None else self.step
            safe_preview = str(value_preview or "").strip()[:120]
            if any(h in kind.lower() for h in _SECRET_FIELD_HINTS) and "ref" not in kind.lower():
                safe_preview = f"<redacted:{len(safe_preview)}chars>"
            art_key = f"{kind}:{label}:{safe_preview}"
            nid = f"art:{_short_hash(art_key)}"
            node, created = self._ensure_node(
                nid,
                node_type=NODE_ARTIFACT,
                label=f"{kind}:{label}"[:80],
                status=STATUS_VERIFIED if high_signal else STATUS_IN_PROGRESS,
                step=eff_step,
                attributes={
                    "kind": kind,
                    "field": label,
                    "value_preview": safe_preview,
                    "high_signal": bool(high_signal),
                    "receipt_id": str(receipt_id or ""),
                    "source_node_id": str(source_node_id or ""),
                },
            )
            delta_v = 1 if created else 0
            delta_e = 0
            if source_node_id and source_node_id in self.nodes:
                _, e_created = self._ensure_edge(
                    source_node_id,
                    nid,
                    EDGE_SUPPORTS,
                    status=STATUS_VERIFIED,
                    step=eff_step,
                    attributes={"receipt_id": str(receipt_id or "")},
                )
                delta_e += 1 if e_created else 0
            return node, delta_v, delta_e

    def _extract_receipt_artifacts(
        self,
        ep_nid: str,
        norm_p: str,
        parsed_json: Any,
        receipt_id: str,
        eff_step: int,
    ) -> tuple[int, int]:
        dv = 0
        de = 0
        added = 0

        # Synthesize plural REST collection item endpoints (/api/.../<items>/{id}) cleanly
        col_tmpl = route_template_of(norm_p)
        if "{id}" not in col_tmpl and norm_p.startswith("/api/"):
            last_seg = norm_p.rsplit("/", 1)[-1].lower().replace("-", "_")
            if last_seg.endswith("s") and not last_seg.endswith(
                ("ss", "us", "is", "status", "details", "settings", "metrics", "analytics")
            ):
                singular = last_seg[:-1] if len(last_seg) > 2 else last_seg
                short_singular = singular.split("_")[-1]
                cand_keys = {"id", "uuid", f"{singular}_id", f"{short_singular}_id"}
                items: list[dict[str, Any]] = []
                if isinstance(parsed_json, list):
                    items = [x for x in parsed_json[:15] if isinstance(x, dict)]
                elif isinstance(parsed_json, dict):
                    for v in parsed_json.values():
                        if isinstance(v, list):
                            items.extend(x for x in v[:15] if isinstance(x, dict))
                for obj in items[:8]:
                    for k, v in obj.items():
                        if str(k).lower() in cand_keys and isinstance(v, (str, int)) and not isinstance(v, bool):
                            sval = str(v).strip()
                            if sval and len(sval) <= 64 and is_id_segment(sval):
                                item_path = f"{norm_p}/{sval}"
                                dst_ep, ep_c = self.ensure_endpoint(item_path, method="GET", step=eff_step)
                                dv += ep_c
                                if dst_ep.node_id != ep_nid:
                                    _, ec = self._ensure_edge(
                                        ep_nid,
                                        dst_ep.node_id,
                                        EDGE_NAVIGATES_TO,
                                        status=STATUS_VERIFIED,
                                        step=eff_step,
                                        attributes={"via": "collection_item"},
                                    )
                                    de += 1 if ec else 0
                                break

        def walk(obj: Any, depth: int = 0) -> None:
            nonlocal dv, de, added
            if depth > 4 or added >= 5:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if added >= 5:
                        return
                    lk = str(k).lower()
                    if any(s in lk for s in _SECRET_FIELD_HINTS):
                        continue
                    if isinstance(v, (str, int)) and not isinstance(v, bool):
                        sval = str(v).strip()
                        if sval and len(sval) <= 64 and (
                            lk in {"id", "uuid"} or any(h in lk for h in _ID_FIELD_HINTS)
                        ):
                            if is_id_segment(sval) or len(sval) <= 36:
                                _, v_inc, e_inc = self.register_artifact(
                                    kind="resource_id",
                                    label=str(k),
                                    value_preview=sval,
                                    source_node_id=ep_nid,
                                    receipt_id=receipt_id,
                                    high_signal=True,
                                    step=eff_step,
                                )
                                dv += v_inc
                                de += e_inc
                                if v_inc or e_inc:
                                    added += 1
                    elif isinstance(v, (dict, list)):
                        walk(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj[:10]:
                    if added >= 5:
                        return
                    walk(item, depth + 1)

        walk(parsed_json)
        return dv, de

    def ingest_receipt(
        self,
        receipt: dict[str, Any],
        *,
        step: int | None = None,
        mark_visited: bool = True,
    ) -> tuple[int, int]:
        """Passively ingest one HTTP receipt into the BSAG, returning (delta_v, delta_e)."""
        if not isinstance(receipt, dict):
            return 0, 0
        with self._lock:
            eff_step = self._next_step(step)
            delta_v = 0
            delta_e = 0

            actor = str(receipt.get("actor") or "anon").strip() or "anon"
            method = str(receipt.get("method") or "GET").strip().upper()
            url = str(receipt.get("url") or receipt.get("path") or "/")
            status = int(receipt.get("status") or 0)
            body = str(receipt.get("body") or "")
            ctype = str(receipt.get("content_type") or "").lower()
            rid = str(receipt.get("receipt_id") or "")

            resolved_self = self._resolve_same_origin_path(url)
            if resolved_self is None:
                return 0, 0
            norm_p, query = resolved_self
            q_names = [k.strip() for k, _ in parse_qsl(query, keep_blank_values=True) if k.strip()]

            ep_node, ep_created = self.ensure_endpoint(
                norm_p,
                method=method,
                params=q_names,
                step=eff_step,
            )
            delta_v += ep_created
            ep_nid = ep_node.node_id

            if mark_visited:
                ep_node.visit_count += 1
                if ep_node.status == STATUS_UNEXPLORED:
                    ep_node.status = STATUS_IN_PROGRESS

            attrs = ep_node.attributes
            obs_sigs = attrs.setdefault("observed_behaviors", [])
            beh_sig = f"{actor}|{method}|{norm_p}|{status}|{','.join(sorted(q_names))}"
            if beh_sig not in obs_sigs:
                if len(obs_sigs) < 64:
                    obs_sigs.append(beh_sig)
                # Novel (actor, method, concrete_path, status, query_keys) observation on an endpoint
                # (e.g. second object ID, cross-actor 403/404 control, new param, or write probe) is real progress!
                delta_e += 1
            if actor not in (attrs.get("actors_tested") or []):
                delta_e += 1
            _append_unique(attrs.setdefault("actors_tested", []), actor, limit=16)
            if status > 0:
                _append_unique(attrs.setdefault("statuses", []), str(status), limit=12)
            if rid:
                _append_unique(attrs.setdefault("sample_receipt_ids", []), rid, limit=8)
            if 200 <= status < 300:
                _append_unique(attrs.setdefault("actors_2xx", []), actor, limit=16)
            elif status in {401, 403}:
                _append_unique(attrs.setdefault("actors_denied", []), actor, limit=16)

            auth_node, auth_created = self.register_auth_context(
                alias=actor,
                authenticated=(actor == "anon" or status not in {401}),
                step=eff_step,
            )
            delta_v += auth_created

            if status in {401, 403} and actor == "anon":
                _, e_c = self._ensure_edge(
                    ep_nid,
                    auth_node.node_id,
                    EDGE_REQUIRES_CONTEXT,
                    status=STATUS_VERIFIED,
                    step=eff_step,
                    attributes={"anon_status": status},
                )
                delta_e += 1 if e_c else 0
            elif 200 <= status < 300 and actor != "anon":
                _, e_c = self._ensure_edge(
                    ep_nid,
                    auth_node.node_id,
                    EDGE_REQUIRES_CONTEXT,
                    status=STATUS_VERIFIED,
                    step=eff_step,
                    attributes={"observed_status": status},
                )
                delta_e += 1 if e_c else 0

            if method in {"POST", "PUT", "PATCH", "DELETE"} and 200 <= status < 400:
                _, e_c = self._ensure_edge(
                    ep_nid,
                    ep_nid,
                    EDGE_TRIGGERS_STATE_CHANGE,
                    status=STATUS_VERIFIED,
                    step=eff_step,
                    attributes={"method": method, "status": status, "receipt_id": rid},
                )
                delta_e += 1 if e_c else 0

            loc = str(receipt.get("redirect_location") or "").strip()
            if loc:
                resolved_loc = self._resolve_same_origin_path(loc, current_url=url)
                if resolved_loc is not None:
                    loc_p, loc_q = resolved_loc
                    loc_q_names = [k.strip() for k, _ in parse_qsl(loc_q, keep_blank_values=True) if k.strip()]
                    dst_node, dst_created = self.ensure_endpoint(loc_p, method="GET", params=loc_q_names, step=eff_step)
                    delta_v += dst_created
                    _, e_c = self._ensure_edge(
                        ep_nid,
                        dst_node.node_id,
                        EDGE_NAVIGATES_TO,
                        status=STATUS_VERIFIED,
                        step=eff_step,
                        attributes={"via": "redirect"},
                    )
                    delta_e += 1 if e_c else 0

            def _link_discovered(
                raw_u: str,
                m: str = "GET",
                p_list: Sequence[Any] = (),
                b_fields: Sequence[str] = (),
                declared_write: bool = False,
                via: str = "passive",
            ) -> None:
                nonlocal delta_v, delta_e
                res = self._resolve_same_origin_path(raw_u, current_url=url)
                if res is None:
                    return
                dp, dq = res
                dq_names = [k.strip() for k, _ in parse_qsl(dq, keep_blank_values=True) if k.strip()]
                for item in p_list:
                    pname = str(item.get("name") if isinstance(item, dict) else item or "").strip()
                    if pname and pname not in dq_names:
                        dq_names.append(pname)
                dst_n, dst_c = self.ensure_endpoint(
                    dp,
                    method=m,
                    params=dq_names,
                    body_fields=b_fields,
                    declared_write=declared_write,
                    step=eff_step,
                )
                delta_v += dst_c
                if dst_n.node_id != ep_nid:
                    _, ec = self._ensure_edge(
                        ep_nid,
                        dst_n.node_id,
                        EDGE_NAVIGATES_TO,
                        status=STATUS_VERIFIED,
                        step=eff_step,
                        attributes={"via": via, "method": str(m or "GET").upper()},
                    )
                    delta_e += 1 if ec else 0

            stripped = body.lstrip()
            if body and status < 500:
                if "json" in ctype or stripped.startswith(("{", "[")):
                    try:
                        parsed = json.loads(body)
                    except ValueError:
                        parsed = None
                    if isinstance(parsed, (dict, list)):
                        if isinstance(parsed, dict) and "paths" in parsed and ("openapi" in parsed or "swagger" in parsed):
                            _, av, ae = self.register_artifact(
                                kind="openapi_spec",
                                label=norm_p,
                                value_preview=f"paths={len(parsed.get('paths') or {})}",
                                source_node_id=ep_nid,
                                receipt_id=rid,
                                high_signal=True,
                                step=eff_step,
                            )
                            delta_v += av
                            delta_e += ae
                            resolver = LocalSchema(parsed)
                            for raw_path, path_item in (parsed.get("paths") or {}).items():
                                if not isinstance(raw_path, str) or not isinstance(path_item, dict):
                                    continue
                                raw_pp = path_item.get("parameters")
                                p_params: list[Any] = raw_pp if isinstance(raw_pp, list) else []
                                for m_low in ("get", "post", "put", "patch", "delete", "head"):
                                    op = path_item.get(m_low)
                                    if not isinstance(op, dict):
                                        continue
                                    raw_op_p = op.get("parameters")
                                    op_params: list[Any] = raw_op_p if isinstance(raw_op_p, list) else []
                                    q_p: list[str] = []
                                    for prm in [*p_params, *op_params]:
                                        rp = resolver.resolve(prm) if isinstance(prm, dict) else {}
                                        if rp.get("name") and str(rp.get("in") or "query").lower() == "query":
                                            q_p.append(str(rp["name"]))
                                    b_f: list[str] = []
                                    rb = resolver.resolve(op.get("requestBody")) if isinstance(op.get("requestBody"), dict) else {}
                                    for media in (rb.get("content") or {}).values() if isinstance(rb.get("content"), dict) else ():
                                        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                                            props = resolver.schema(media["schema"]).get("properties")
                                            if isinstance(props, dict):
                                                b_f.extend(str(k) for k in props.keys())
                                    m_up = m_low.upper()
                                    _link_discovered(
                                        raw_path,
                                        m=m_up,
                                        p_list=q_p,
                                        b_fields=b_f,
                                        declared_write=(m_up in {"POST", "PUT", "PATCH", "DELETE"}),
                                        via="openapi",
                                    )
                        hypermedia, _ = extract_json_hypermedia(parsed, url, origin_url=self.base_url)
                        for item in hypermedia:
                            _link_discovered(
                                str(item.get("url") or ""),
                                m=str(item.get("method") or "GET"),
                                p_list=item.get("params") or (),
                                via="hypermedia",
                            )
                        for spec_u in find_spec_urls(body, url):
                            _link_discovered(spec_u, m="GET", via="spec_url")
                        if 200 <= status < 300:
                            av, ae = self._extract_receipt_artifacts(ep_nid, norm_p, parsed, rid, eff_step)
                            delta_v += av
                            delta_e += ae

                if "html" in ctype or "<html" in body[:512].lower() or "<form" in body.lower() or "href=" in body.lower():
                    for rec in extract_html(body, url):
                        rm = str(rec.get("method") or "GET").upper()
                        is_form = rec.get("sources") == ["form"]
                        _link_discovered(
                            str(rec.get("url") or ""),
                            m=rm,
                            p_list=rec.get("params") or (),
                            declared_write=(is_form and rm in {"POST", "PUT", "PATCH", "DELETE"}),
                            via="html",
                        )
                    for script in extract_inline_scripts(body):
                        for jc in extract_js_calls(script, url, limit=40):
                            _link_discovered(str(jc.get("url") or ""), m=str(jc.get("method") or "GET"), p_list=jc.get("params") or (), via="inline_js")
                        for sr in extract_spa_routes(script, url, limit=40):
                            _link_discovered(str(sr.get("url") or ""), m="GET", via="spa_route")
                        for spec_u in find_spec_urls(script, url):
                            _link_discovered(spec_u, m="GET", via="spec_url")

                if "javascript" in ctype or norm_p.lower().endswith((".js", ".mjs")):
                    for jc in extract_js_calls(body, url, limit=80):
                        _link_discovered(str(jc.get("url") or ""), m=str(jc.get("method") or "GET"), p_list=jc.get("params") or (), via="js_call")
                    for rec in extract_js(body, url, limit=60):
                        _link_discovered(str(rec.get("url") or ""), m=str(rec.get("method") or "GET"), p_list=rec.get("params") or (), via="js_link")
                    for sr in extract_spa_routes(body, url, limit=60):
                        _link_discovered(str(sr.get("url") or ""), m="GET", via="spa_route")
                    for spec_u in find_spec_urls(body, url):
                        _link_discovered(spec_u, m="GET", via="spec_url")

                if norm_p.lower().endswith("/robots.txt"):
                    for rec in extract_robots(body, url):
                        _link_discovered(str(rec.get("url") or ""), m="GET", via="robots")
                if "xml" in ctype or "<urlset" in body[:512].lower() or "<sitemapindex" in body[:512].lower():
                    for rec in extract_sitemap(body, url):
                        _link_discovered(str(rec.get("url") or ""), m="GET", via="sitemap")

            gain = 1.0 if (delta_v > 0 or delta_e > 0) else 0.0
            ep_node.information_gain_ema = 0.7 * ep_node.information_gain_ema + 0.3 * gain
            if delta_v > 0 or delta_e > 0:
                ep_node.last_new_edge_step = eff_step
            return delta_v, delta_e

    def ingest_surface(
        self,
        surface: dict[str, Any],
        *,
        actor: str = "",
        step: int | None = None,
    ) -> tuple[int, int]:
        """Ingest extract_surface output into BSAG, returning (delta_v, delta_e)."""
        if not isinstance(surface, dict):
            return 0, 0
        with self._lock:
            eff_step = self._next_step(step)
            delta_v = 0
            delta_e = 0
            curr_url = str(surface.get("url") or self.base_url)
            src_resolved = self._resolve_same_origin_path(curr_url)
            src_nid = ""
            if src_resolved is not None:
                src_node, src_c = self.ensure_endpoint(src_resolved[0], method="GET", step=eff_step)
                delta_v += src_c
                src_nid = src_node.node_id

            def _add_target(raw_u: str, method: str, params: Sequence[Any] = (), body_fields: Sequence[str] = (), declared_write: bool = False) -> None:
                nonlocal delta_v, delta_e
                resolved = self._resolve_same_origin_path(raw_u, current_url=curr_url)
                if resolved is None:
                    return
                t_path, t_query = resolved
                q_names = [k.strip() for k, _ in parse_qsl(t_query, keep_blank_values=True) if k.strip()]
                for p in params:
                    pname = str(p.get("name") if isinstance(p, dict) else p or "").strip()
                    if pname and pname not in q_names:
                        q_names.append(pname)
                dst_node, dst_c = self.ensure_endpoint(
                    t_path,
                    method=method,
                    params=q_names,
                    body_fields=body_fields,
                    declared_write=declared_write,
                    step=eff_step,
                )
                delta_v += dst_c
                if src_nid and dst_node.node_id != src_nid:
                    _, e_c = self._ensure_edge(
                        src_nid,
                        dst_node.node_id,
                        EDGE_NAVIGATES_TO,
                        status=STATUS_VERIFIED,
                        step=eff_step,
                        attributes={"actor": actor, "method": method.upper()},
                    )
                    delta_e += 1 if e_c else 0

            for item in [
                *(surface.get("links") or []),
                *(surface.get("js_calls") or []),
                *(surface.get("spa_routes") or []),
            ]:
                if isinstance(item, dict):
                    _add_target(
                        str(item.get("url") or ""),
                        str(item.get("method") or "GET"),
                        params=item.get("params") or (),
                    )
            for form in (surface.get("forms") or []):
                if isinstance(form, dict):
                    m = str(form.get("method") or "GET").upper()
                    _add_target(
                        str(form.get("url") or ""),
                        m,
                        params=form.get("params") or (),
                        declared_write=(m in {"POST", "PUT", "PATCH", "DELETE"}),
                    )
            for spec_u in (surface.get("spec_urls") or []):
                if isinstance(spec_u, str):
                    _add_target(spec_u, "GET")
                    _, av, ae = self.register_artifact(
                        kind="spec_url",
                        label="openapi",
                        value_preview=spec_u,
                        source_node_id=src_nid,
                        receipt_id=str(surface.get("receipt_id") or ""),
                        high_signal=True,
                        step=eff_step,
                    )
                    delta_v += av
                    delta_e += ae
            for op in (surface.get("openapi_operations") or []):
                if isinstance(op, dict):
                    m = str(op.get("method") or "GET").upper()
                    pnames = [
                        str(p.get("name"))
                        for p in (op.get("params") or [])
                        if isinstance(p, dict) and p.get("name") and p.get("in") == "query"
                    ]
                    _add_target(
                        str(op.get("path") or op.get("url") or ""),
                        m,
                        params=pnames,
                        body_fields=op.get("body_fields") or (),
                        declared_write=(m in {"POST", "PUT", "PATCH", "DELETE"}),
                    )
            for cid in (surface.get("candidate_ids") or [])[:10]:
                if isinstance(cid, dict) and cid.get("value"):
                    _, av, ae = self.register_artifact(
                        kind="resource_id",
                        label=str(cid.get("field") or "id"),
                        value_preview=str(cid.get("value") or ""),
                        source_node_id=src_nid,
                        receipt_id=str(surface.get("receipt_id") or ""),
                        high_signal=True,
                        step=eff_step,
                    )
                    delta_v += av
                    delta_e += ae
            return delta_v, delta_e

    def register_hypothesis(
        self,
        *,
        hypothesis_id: str | None = None,
        endpoint_node_id: str,
        category: str,
        vuln_class: str = "",
        actor: str = "",
        summary: str = "",
        status: str = STATUS_IN_PROGRESS,
        multi_hop: bool = False,
        proof_receipt_ids: Sequence[str] = (),
        control_receipt_ids: Sequence[str] = (),
        evidence_value: str = "",
        step: int | None = None,
    ) -> tuple[BSAGNode, int, int]:
        """Create or update a HYPOTHESIS node and link it to its target ENDPOINT."""
        with self._lock:
            eff_step = self._next_step(step)
            hid = str(hypothesis_id or "").strip() or f"hyp:{_short_hash(f'{endpoint_node_id}:{category}:{vuln_class}:{summary}:{eff_step}')}"
            if not hid.startswith("hyp:"):
                hid = f"hyp:{hid}"
            node, v_c = self._ensure_node(
                hid,
                node_type=NODE_HYPOTHESIS,
                label=f"{vuln_class or category}:{endpoint_node_id}",
                status=status,
                step=eff_step,
                attributes={
                    "endpoint_node_id": endpoint_node_id,
                    "category": category,
                    "vuln_class": vuln_class,
                    "actor": actor,
                    "summary": str(summary or "")[:300],
                    "multi_hop": bool(multi_hop),
                    "proof_receipt_ids": list(proof_receipt_ids),
                    "control_receipt_ids": list(control_receipt_ids),
                    "evidence_value": str(evidence_value or "")[:120],
                    "oracle_verdict": "",
                },
            )
            node.status = status
            if summary:
                node.attributes["summary"] = str(summary)[:300]
            if proof_receipt_ids:
                node.attributes["proof_receipt_ids"] = list(proof_receipt_ids)
            if control_receipt_ids:
                node.attributes["control_receipt_ids"] = list(control_receipt_ids)
            if evidence_value:
                node.attributes["evidence_value"] = str(evidence_value)[:120]
            e_type = EDGE_REFUTES if status == STATUS_REFUTED else EDGE_SUPPORTS
            de = 0
            if endpoint_node_id in self.nodes:
                _, e_c = self._ensure_edge(
                    hid,
                    endpoint_node_id,
                    e_type,
                    status=status,
                    step=eff_step,
                    attributes={"category": category, "vuln_class": vuln_class},
                )
                de += 1 if e_c else 0
            return node, (1 if v_c else 0), de

    def apply_oracle_verdict(
        self,
        *,
        hypothesis_id: str,
        endpoint_node_id: str,
        verdict: str,
        reason: str = "",
        deception_detected: bool = False,
        step: int | None = None,
    ) -> None:
        """Apply Layer 4 Oracle verdict to hypothesis and update endpoint decoy suspicion."""
        with self._lock:
            eff_step = self._next_step(step)
            hyp = self.nodes.get(hypothesis_id)
            ep = self.nodes.get(endpoint_node_id)
            norm_verdict = str(verdict or "").upper()
            if norm_verdict == STATUS_VERIFIED:
                if hyp is not None:
                    hyp.status = STATUS_VERIFIED
                    hyp.attributes["oracle_verdict"] = STATUS_VERIFIED
                if ep is not None:
                    ep.status = STATUS_VERIFIED
                    ep.information_gain_ema = min(2.0, ep.information_gain_ema + 0.5)
            else:
                if hyp is not None:
                    hyp.status = STATUS_REFUTED
                    hyp.attributes["oracle_verdict"] = norm_verdict or STATUS_REFUTED
                    hyp.attributes["oracle_reason"] = str(reason or "")[:240]
                    # Convert edge to REFUTES
                    old_eid = f"{hypothesis_id}|{EDGE_SUPPORTS}|{endpoint_node_id}"
                    self.edges.pop(old_eid, None)
                    if endpoint_node_id in self.nodes:
                        self._ensure_edge(
                            hypothesis_id,
                            endpoint_node_id,
                            EDGE_REFUTES,
                            status=STATUS_REFUTED,
                            step=eff_step,
                            attributes={"reason": str(reason or "")[:160]},
                        )
                if ep is not None:
                    delta = 2.0 if deception_detected else 0.6
                    ep.decoy_suspicion_score = round(ep.decoy_suspicion_score + delta, 4)
                    ep.information_gain_ema = max(0.0, ep.information_gain_ema * 0.6)
                    if ep.decoy_suspicion_score >= _DECOY_THRESHOLD:
                        ep.status = STATUS_SUSPECT_DECOY

    def mark_stagnant(self, endpoint_node_id: str, *, penalty: float = 0.75) -> None:
        """Increase decoy_suspicion_score when an endpoint yields repeated zero-delta steps."""
        with self._lock:
            ep = self.nodes.get(endpoint_node_id)
            if ep is None:
                return
            ep.decoy_suspicion_score = round(ep.decoy_suspicion_score + float(penalty), 4)
            ep.information_gain_ema = max(0.0, ep.information_gain_ema * 0.7)
            if ep.decoy_suspicion_score >= _DECOY_THRESHOLD and ep.status != STATUS_VERIFIED:
                ep.status = STATUS_SUSPECT_DECOY

    def ingest_worker_delta(
        self,
        delta: dict[str, Any],
        *,
        default_endpoint_id: str = "",
        default_category: str = "surface_discovery",
        step: int | None = None,
    ) -> tuple[int, int]:
        """Ingest a structured worker output delta into BSAG, returning (delta_v, delta_e)."""
        if not isinstance(delta, dict):
            return 0, 0
        with self._lock:
            eff_step = self._next_step(step)
            dv = 0
            de = 0
            for ent in (delta.get("discovered_entities") or []):
                if not isinstance(ent, dict):
                    continue
                etype = str(ent.get("type") or NODE_ENDPOINT).upper()
                if etype == NODE_ENDPOINT and ent.get("path"):
                    ep, vc = self.ensure_endpoint(
                        str(ent["path"]),
                        method=str(ent.get("method") or "GET"),
                        params=ent.get("params") or (),
                        declared_write=bool(ent.get("declared_write", False)),
                        step=eff_step,
                    )
                    dv += vc
                    if default_endpoint_id and default_endpoint_id in self.nodes and ep.node_id != default_endpoint_id:
                        _, e_added = self._ensure_edge(
                            default_endpoint_id,
                            ep.node_id,
                            EDGE_NAVIGATES_TO,
                            status=STATUS_VERIFIED,
                            step=eff_step,
                        )
                        de += 1 if e_added else 0
                elif etype == NODE_ARTIFACT and ent.get("label"):
                    _, vc, ec = self.register_artifact(
                        kind=str(ent.get("kind") or "note"),
                        label=str(ent.get("label")),
                        value_preview=str(ent.get("value") or ent.get("label")),
                        source_node_id=default_endpoint_id,
                        high_signal=bool(ent.get("high_signal", True)),
                        step=eff_step,
                    )
                    dv += vc
                    de += ec

            for obs in (delta.get("observed_behaviors") or []):
                if not isinstance(obs, dict):
                    continue
                ep_id = str(obs.get("endpoint_id") or default_endpoint_id)
                cat = str(obs.get("category") or default_category)
                outcome = str(obs.get("outcome") or "").lower()
                if ep_id in self.nodes:
                    ep = self.nodes[ep_id]
                    tested = ep.attributes.setdefault("categories_tested", {})
                    tested[cat] = int(tested.get(cat) or 0) + 1
                    if outcome in {"refuted", "negative", "denied"}:
                        _, vc, ec = self.register_hypothesis(
                            endpoint_node_id=ep_id,
                            category=cat,
                            vuln_class=str(obs.get("vuln_class") or cat),
                            summary=str(obs.get("note") or outcome),
                            status=STATUS_REFUTED,
                            step=eff_step,
                        )
                        dv += vc
                        de += ec

            claim = delta.get("claim_submission")
            if isinstance(claim, dict) and claim.get("url"):
                ep_id = self.endpoint_node_id(str(claim["url"]))
                _, vc, ec = self.register_hypothesis(
                    endpoint_node_id=ep_id if ep_id in self.nodes else default_endpoint_id,
                    category=default_category,
                    vuln_class=str(claim.get("class_type") or ""),
                    actor=str(claim.get("actor_alias") or ""),
                    summary=str(claim.get("summary") or claim.get("title") or ""),
                    status=STATUS_CLAIMED,
                    proof_receipt_ids=claim.get("proof_receipt_ids") or (),
                    control_receipt_ids=claim.get("control_receipt_ids") or (),
                    evidence_value=str(claim.get("evidence_value") or ""),
                    step=eff_step,
                )
                dv += vc
                de += ec
            return dv, de

    def slice_for_arm(self, node_id: str, category: str, *, max_chars: int = 2400) -> str:
        """Render a compact subgraph slice for (node_id, category) preserving multi-hop global context."""
        with self._lock:
            target = self.nodes.get(node_id)
            neighbors: list[dict[str, Any]] = []
            refuted_here: list[dict[str, Any]] = []
            verified_here: list[dict[str, Any]] = []

            for edge in self.edges.values():
                if edge.src != node_id and edge.dst != node_id:
                    continue
                other_id = edge.dst if edge.src == node_id else edge.src
                other = self.nodes.get(other_id)
                if other is None:
                    continue
                if other.node_type == NODE_HYPOTHESIS:
                    rec = {
                        "id": other.node_id,
                        "status": other.status,
                        "vuln_class": other.attributes.get("vuln_class"),
                        "summary": other.attributes.get("summary", "")[:120],
                    }
                    if other.status == STATUS_REFUTED:
                        refuted_here.append(rec)
                    elif other.status == STATUS_VERIFIED:
                        verified_here.append(rec)
                    else:
                        neighbors.append({"edge": edge.edge_type, "node": other.node_id, "type": other.node_type, "status": other.status, "summary": rec["summary"]})
                else:
                    neighbors.append({
                        "edge": edge.edge_type,
                        "dir": "out" if edge.src == node_id else "in",
                        "node": other.node_id,
                        "type": other.node_type,
                        "label": other.label,
                        "status": other.status,
                    })

            auth_contexts = [
                {
                    "alias": n.attributes.get("alias", n.label),
                    "role": n.attributes.get("role", ""),
                    "tenant": n.attributes.get("tenant", ""),
                    "authenticated": bool(n.attributes.get("authenticated")),
                    "dynamic": bool(n.attributes.get("dynamic")),
                }
                for n in sorted(self.nodes.values(), key=lambda x: x.node_id)
                if n.node_type == NODE_AUTH_CONTEXT
            ]

            global_artifacts = [
                {
                    "kind": n.attributes.get("kind"),
                    "field": n.attributes.get("field"),
                    "value": n.attributes.get("value_preview"),
                    "from": n.attributes.get("source_node_id"),
                }
                for n in sorted(
                    (x for x in self.nodes.values() if x.node_type == NODE_ARTIFACT and x.attributes.get("high_signal")),
                    key=lambda x: x.discovered_at_step,
                    reverse=True,
                )[:12]
            ]

            payload: dict[str, Any] = {
                "assigned_arm": {"node_id": node_id, "category": category},
                "target": target.to_dict() if target else {"node_id": node_id, "missing": True},
                "neighbors": neighbors[:16],
                "refuted_history": refuted_here[:8],
                "verified_here": verified_here[:6],
                "auth_contexts": auth_contexts[:12],
                "global_artifacts": global_artifacts,
            }
            rendered = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            if len(rendered) <= max_chars:
                return rendered
            # Trim neighbors and artifacts progressively to respect max_chars strictly.
            payload["neighbors"] = neighbors[:8]
            payload["global_artifacts"] = global_artifacts[:6]
            if target and isinstance(payload["target"], dict) and isinstance(payload["target"].get("attributes"), dict):
                attrs = dict(payload["target"]["attributes"])
                attrs["sample_paths"] = (attrs.get("sample_paths") or [])[:4]
                attrs["sample_receipt_ids"] = (attrs.get("sample_receipt_ids") or [])[:4]
                payload["target"]["attributes"] = attrs
            rendered = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            if len(rendered) <= max_chars:
                return rendered
            return rendered[: max(0, max_chars - 3)] + "..."

    def compact_summary(self, *, max_chars: int = 3200) -> str:
        """Render a compact whole-BSAG overview for periodic cross-endpoint synthesis."""
        with self._lock:
            endpoints = [
                {
                    "id": n.node_id,
                    "status": n.status,
                    "visits": n.visit_count,
                    "methods": n.attributes.get("methods", []),
                    "params": n.attributes.get("query_params", [])[:6],
                    "actors_2xx": n.attributes.get("actors_2xx", [])[:6],
                    "sample_paths": n.attributes.get("sample_paths", [])[:2],
                }
                for n in sorted(self.nodes.values(), key=lambda x: x.discovered_at_step)
                if n.node_type == NODE_ENDPOINT
            ]
            auths = [
                {
                    "alias": n.attributes.get("alias", n.label),
                    "role": n.attributes.get("role", ""),
                    "tenant": n.attributes.get("tenant", ""),
                    "auth": bool(n.attributes.get("authenticated")),
                }
                for n in self.nodes.values()
                if n.node_type == NODE_AUTH_CONTEXT
            ]
            artifacts = [
                {
                    "kind": n.attributes.get("kind"),
                    "field": n.attributes.get("field"),
                    "val": n.attributes.get("value_preview"),
                    "src": n.attributes.get("source_node_id"),
                }
                for n in sorted(self.nodes.values(), key=lambda x: x.discovered_at_step, reverse=True)
                if n.node_type == NODE_ARTIFACT
            ][:14]
            hyps = [
                {
                    "id": n.node_id,
                    "ep": n.attributes.get("endpoint_node_id"),
                    "cat": n.attributes.get("category"),
                    "cls": n.attributes.get("vuln_class"),
                    "status": n.status,
                }
                for n in self.nodes.values()
                if n.node_type == NODE_HYPOTHESIS
            ][-12:]
            summary = {
                "step": self.step,
                "auth_contexts": auths,
                "endpoints": endpoints[:28],
                "artifacts": artifacts,
                "hypotheses": hyps,
            }
            text = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
            if len(text) <= max_chars:
                return text
            summary["endpoints"] = endpoints[:16]
            summary["artifacts"] = artifacts[:8]
            text = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
            return text[:max_chars]

    def metrics_snapshot(self) -> dict[str, Any]:
        """Return structural counts for telemetry and process metrics."""
        with self._lock:
            endpoints = [n for n in self.nodes.values() if n.node_type == NODE_ENDPOINT]
            visited_eps = [n for n in endpoints if n.visit_count > 0]
            suspect_eps = [n for n in endpoints if n.status == STATUS_SUSPECT_DECOY or n.decoy_suspicion_score >= _DECOY_THRESHOLD]
            hyps = [n for n in self.nodes.values() if n.node_type == NODE_HYPOTHESIS]
            return {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "endpoints_discovered": len(endpoints),
                "endpoints_visited": len(visited_eps),
                "endpoint_templates": sorted(n.label for n in endpoints),
                "auth_contexts": sum(1 for n in self.nodes.values() if n.node_type == NODE_AUTH_CONTEXT),
                "artifacts": sum(1 for n in self.nodes.values() if n.node_type == NODE_ARTIFACT),
                "hypotheses_total": len(hyps),
                "hypotheses_verified": sum(1 for n in hyps if n.status == STATUS_VERIFIED),
                "hypotheses_refuted": sum(1 for n in hyps if n.status == STATUS_REFUTED),
                "suspect_decoys": len(suspect_eps),
            }

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "schema": "agentic-bsag/1",
                "base_url": self.base_url,
                "allowed_methods": sorted(self.allowed_methods),
                "step": self.step,
                "nodes": [n.to_dict() for n in sorted(self.nodes.values(), key=lambda x: x.node_id)],
                "edges": [e.to_dict() for e in sorted(self.edges.values(), key=lambda x: x.edge_id)],
            }

    def load_dict(self, data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        with self._lock:
            self.step = int(data.get("step") or 0)
            self.nodes = {}
            for row in (data.get("nodes") or []):
                if isinstance(row, dict) and row.get("node_id"):
                    node = BSAGNode.from_dict(row)
                    self.nodes[node.node_id] = node
            self.edges = {}
            for row in (data.get("edges") or []):
                if isinstance(row, dict) and row.get("edge_id"):
                    edge = BSAGEdge.from_dict(row)
                    self.edges[edge.edge_id] = edge

    def save(self) -> None:
        """Persist BSAG atomically to JSON snapshot and SQLite database."""
        with self._lock:
            snapshot = self.to_dict()
            if self.json_path is not None:
                _atomic_write_json(self.json_path, snapshot)
            if self.sqlite_path is not None:
                self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
                conn = sqlite3.connect(str(self.sqlite_path))
                try:
                    with conn:
                        conn.execute(
                            "CREATE TABLE IF NOT EXISTS nodes ("
                            "node_id TEXT PRIMARY KEY, node_type TEXT NOT NULL, label TEXT NOT NULL, "
                            "status TEXT NOT NULL, visit_count INTEGER NOT NULL, "
                            "information_gain_ema REAL NOT NULL, decoy_suspicion_score REAL NOT NULL, "
                            "last_new_edge_step INTEGER NOT NULL, discovered_at_step INTEGER NOT NULL, "
                            "attributes_json TEXT NOT NULL)"
                        )
                        conn.execute(
                            "CREATE TABLE IF NOT EXISTS edges ("
                            "edge_id TEXT PRIMARY KEY, src TEXT NOT NULL, dst TEXT NOT NULL, "
                            "edge_type TEXT NOT NULL, status TEXT NOT NULL, step INTEGER NOT NULL, "
                            "attributes_json TEXT NOT NULL)"
                        )
                        conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                        conn.execute("DELETE FROM nodes")
                        conn.execute("DELETE FROM edges")
                        conn.executemany(
                            "INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            [
                                (
                                    n["node_id"],
                                    n["node_type"],
                                    n["label"],
                                    n["status"],
                                    n["visit_count"],
                                    n["information_gain_ema"],
                                    n["decoy_suspicion_score"],
                                    n["last_new_edge_step"],
                                    n["discovered_at_step"],
                                    json.dumps(n["attributes"], ensure_ascii=False),
                                )
                                for n in snapshot["nodes"]
                            ],
                        )
                        conn.executemany(
                            "INSERT INTO edges VALUES (?, ?, ?, ?, ?, ?, ?)",
                            [
                                (
                                    e["edge_id"],
                                    e["src"],
                                    e["dst"],
                                    e["edge_type"],
                                    e["status"],
                                    e["step"],
                                    json.dumps(e["attributes"], ensure_ascii=False),
                                )
                                for e in snapshot["edges"]
                            ],
                        )
                        conn.execute(
                            "INSERT OR REPLACE INTO meta (key, value) VALUES ('step', ?)",
                            (str(self.step),),
                        )
                finally:
                    conn.close()

    def load_sqlite(self) -> bool:
        """Load BSAG state from SQLite if present; returns True if loaded."""
        if self.sqlite_path is None or not self.sqlite_path.is_file():
            return False
        with self._lock:
            conn = sqlite3.connect(str(self.sqlite_path))
            try:
                nodes_rows = conn.execute(
                    "SELECT node_id, node_type, label, status, visit_count, information_gain_ema, "
                    "decoy_suspicion_score, last_new_edge_step, discovered_at_step, attributes_json FROM nodes"
                ).fetchall()
                edges_rows = conn.execute(
                    "SELECT edge_id, src, dst, edge_type, status, step, attributes_json FROM edges"
                ).fetchall()
                meta_row = conn.execute("SELECT value FROM meta WHERE key='step'").fetchone()
            except sqlite3.Error:
                return False
            finally:
                conn.close()
            self.nodes = {}
            for row in nodes_rows:
                node = BSAGNode(
                    node_id=row[0],
                    node_type=row[1],
                    label=row[2],
                    status=row[3],
                    visit_count=int(row[4]),
                    information_gain_ema=float(row[5]),
                    decoy_suspicion_score=float(row[6]),
                    last_new_edge_step=int(row[7]),
                    discovered_at_step=int(row[8]),
                    attributes=json.loads(row[9] or "{}"),
                )
                self.nodes[node.node_id] = node
            self.edges = {}
            for row in edges_rows:
                edge = BSAGEdge(
                    edge_id=row[0],
                    src=row[1],
                    dst=row[2],
                    edge_type=row[3],
                    status=row[4],
                    step=int(row[5]),
                    attributes=json.loads(row[6] or "{}"),
                )
                self.edges[edge.edge_id] = edge
            if meta_row:
                self.step = int(meta_row[0])
            return True
