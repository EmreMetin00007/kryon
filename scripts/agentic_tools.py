"""General-purpose investigation and QA verification tools with anti-hallucination verification."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any
from urllib.parse import urlsplit

from agentic_evidence import (
    MAX_CONTROL_EXCERPT_CHARS as MAX_CONTROL_EXCERPT_CHARS,
    MAX_PROOF_EXCERPT_CHARS as MAX_PROOF_EXCERPT_CHARS,
    _ACTOR_IDENTITY_HEADERS as _ACTOR_IDENTITY_HEADERS,
    _ADMIN_ROLE_TOKENS as _ADMIN_ROLE_TOKENS,
    _CLASS_ALIASES as _CLASS_ALIASES,
    _HEX_ID_SEG_RE as _HEX_ID_SEG_RE,
    _HEX_SEGMENT_RE as _HEX_SEGMENT_RE,
    _HIGH_SPEC_THRESHOLD as _HIGH_SPEC_THRESHOLD,
    _IGNORED_EVIDENCE_JSON_KEYS as _IGNORED_EVIDENCE_JSON_KEYS,
    _IGNORED_EVIDENCE_KEY_PREFIXES as _IGNORED_EVIDENCE_KEY_PREFIXES,
    _IGNORED_EVIDENCE_KEY_SUFFIXES as _IGNORED_EVIDENCE_KEY_SUFFIXES,
    _ISO_TIMESTAMP_RE as _ISO_TIMESTAMP_RE,
    _JWT_FULL_RE as _JWT_FULL_RE,
    _LOWER_SLUG_YEAR_RE as _LOWER_SLUG_YEAR_RE,
    _PREFIXED_ID_SEG_RE as _PREFIXED_ID_SEG_RE,
    _PUBLIC_LANDING_PATHS as _PUBLIC_LANDING_PATHS,
    _RAW_TOKEN_SCAN_RE as _RAW_TOKEN_SCAN_RE,
    _READ_SQLI_HINTS as _READ_SQLI_HINTS,
    _READONLY_ROLES as _READONLY_ROLES,
    _RECORD_OWNER_KEYS as _RECORD_OWNER_KEYS,
    _RECORD_TENANT_KEYS as _RECORD_TENANT_KEYS,
    _SENSITIVE_JSON_EXACT_KEYS as _SENSITIVE_JSON_EXACT_KEYS,
    _SENSITIVE_JSON_KEY_PREFIXES as _SENSITIVE_JSON_KEY_PREFIXES,
    _SENSITIVE_JSON_KEY_SUFFIXES as _SENSITIVE_JSON_KEY_SUFFIXES,
    _SQLI_EVIDENCE_HINTS as _SQLI_EVIDENCE_HINTS,
    _TEMPLATE_SEG_RE as _TEMPLATE_SEG_RE,
    _TRIVIAL_EVIDENCE as _TRIVIAL_EVIDENCE,
    _UUID_FULL_RE as _UUID_FULL_RE,
    _UUID_SEG_RE as _UUID_SEG_RE,
    _XSS_EVENT_HINTS as _XSS_EVENT_HINTS,
    _actor_priority_key as _actor_priority_key,
    _best_secret_for_receipt as _best_secret_for_receipt,
    _build_control_haystacks as _build_control_haystacks,
    _extract_receipt_secret_candidates as _extract_receipt_secret_candidates,
    _extract_record_owner_and_tenant as _extract_record_owner_and_tenant,
    _filter_class_eligible_proofs as _filter_class_eligible_proofs,
    _find_exact_route_anon_2xx as _find_exact_route_anon_2xx,
    _infer_owner_actor as _infer_owner_actor,
    _is_admin_role as _is_admin_role,
    _is_genuine_anon_2xx as _is_genuine_anon_2xx,
    _is_hex_secret_token as _is_hex_secret_token,
    _is_high_entropy_token as _is_high_entropy_token,
    _is_ignored_json_key as _is_ignored_json_key,
    _is_readonly_role as _is_readonly_role,
    _is_sensitive_json_key as _is_sensitive_json_key,
    _norm_path as _norm_path,
    _receipt_contains_value as _receipt_contains_value,
    _resolve_route_auth_bypass_vs_bfla as _resolve_route_auth_bypass_vs_bfla,
    _select_stronger_evidence_from_receipts as _select_stronger_evidence_from_receipts,
    _shannon_entropy as _shannon_entropy,
    _value_in_controls as _value_in_controls,
    build_receipt_excerpt as build_receipt_excerpt,
    canonicalize_and_deduplicate_findings as canonicalize_and_deduplicate_findings,
    compose_finding_evidence as compose_finding_evidence,
    normalize_route_template as normalize_route_template,
    normalize_vuln_class as normalize_vuln_class,
    score_evidence_value as score_evidence_value,
    select_primary_proof as select_primary_proof,
)
from agentic_browser import (
    inspect_rendered_page as inspect_rendered_page,
    run_browser_crawl as run_browser_crawl,
)
from agentic_crypto import analyze_token as analyze_token
from agentic_http import (
    AgenticHTTPClient,
    BudgetExhaustedError,
    MethodNotAllowedError,
    ScopeViolationError,
    ServiceDegradationError,
    is_static_asset_url as is_static_asset_url,
)
from agentic_oob import LoopbackCallbackServer
from agentic_waf import detect_waf_block as detect_waf_block
from agentic_oracle import (
    check_bola_false_positive,
    find_persistent_render_get_receipt,
    is_html_receipt,
    is_persistent_read_path_related,
    receipt_body_contains_verbatim,
)
from agentic_preview import (
    _EVENT_OR_JS_RE as _EVENT_OR_JS_RE,
    _HTML_COMMENT_RE as _HTML_COMMENT_RE,
    _HTML_TAG_RE as _HTML_TAG_RE,
    _ID_KEY_HINTS as _ID_KEY_HINTS,
    _ID_VALUE_RE as _ID_VALUE_RE,
    _REPO_ROOT as _REPO_ROOT,
    _SCRIPT_BLOCK_RE as _SCRIPT_BLOCK_RE,
    _STYLE_BLOCK_RE as _STYLE_BLOCK_RE,
    _SVG_CLOSE_RE as _SVG_CLOSE_RE,
    _SVG_OPEN_RE as _SVG_OPEN_RE,
    _TAG_ATTR_RE as _TAG_ATTR_RE,
    LocalSchema as LocalSchema,
    _build_surface_hints as _build_surface_hints,
    _compute_structural_diff as _compute_structural_diff,
    _extract_candidate_ids as _extract_candidate_ids,
    _extract_openapi_operations as _extract_openapi_operations,
    _extract_surface_summary as _extract_surface_summary,
    _find_tag_end as _find_tag_end,
    _flatten_json_keys as _flatten_json_keys,
    _format_receipt_preview as _format_receipt_preview,
    _notable_headers as _notable_headers,
    _strip_inline_style_attrs as _strip_inline_style_attrs,
    _strip_passive_svgs as _strip_passive_svgs,
    extract_css as extract_css,
    extract_html as extract_html,
    extract_http_headers as extract_http_headers,
    extract_inline_scripts as extract_inline_scripts,
    extract_js as extract_js,
    extract_js_calls as extract_js_calls,
    extract_json_hypermedia as extract_json_hypermedia,
    extract_robots as extract_robots,
    extract_sitemap as extract_sitemap,
    extract_spa_routes as extract_spa_routes,
    find_spec_urls as find_spec_urls,
    prune_html_for_preview as prune_html_for_preview,
)
from agentic_receipts import DEFAULT_PREVIEW_CHARS, ReceiptStore
from agentic_surface import SurfaceFrontierTracker

_SKIP_REPLAY_HEADERS = frozenset({
    "authorization",
    "cookie",
    "x-csrf-token",
    "x-xsrf-token",
    "content-length",
    "host",
})
_PERSISTENT_VULN_CLASSES = frozenset({"stored_xss", "mass_assignment", "ssti"})
_MUTATING_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send scope-locked HTTP request as actor (or 'anon'). GETs cached unless force=true.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "description": "HTTP method (defaults GET; POST if body)."},
                    "url": {"type": "string"},
                    "actor": {"type": "string"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "query": {"type": "object", "additionalProperties": {"type": "string"}},
                    "json_body": {},
                    "base_receipt_id": {"type": "string", "description": "GET receipt_id for base JSON."},
                    "json_merge": {"type": "object"},
                    "form_body": {"type": "object", "additionalProperties": {"type": "string"}},
                    "raw_body": {"type": "string"},
                    "force": {"type": "boolean"},
                    "save_session_as": {"type": "string", "description": "Captured session alias."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_receipt",
            "description": "Read stored receipt body at 0 HTTP cost via offset/limit or regex.",
            "parameters": {
                "type": "object",
                "properties": {
                    "receipt_id": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                    "regex": {"type": "string"},
                },
                "required": ["receipt_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "replay_as",
            "description": "Replay a receipt_id as another actor or with overrides; returns diff.",
            "parameters": {
                "type": "object",
                "properties": {
                    "receipt_id": {"type": "string"},
                    "actor": {"type": "string"},
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "query_overrides": {"type": "object", "additionalProperties": {"type": "string"}},
                    "header_overrides": {"type": "object", "additionalProperties": {"type": "string"}},
                    "base_receipt_id": {"type": "string"},
                    "json_merge": {"type": "object"},
                    "json_overrides": {"type": "object"},
                    "force": {"type": "boolean"},
                },
                "required": ["receipt_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_surface",
            "description": "Extract links, forms, JS/client-logic, OpenAPI/GraphQL/Postman ops, and IDs at 0 HTTP cost.",
            "parameters": {
                "type": "object",
                "properties": {"receipt_id": {"type": "string"}},
                "required": ["receipt_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "notebook",
            "description": "Maintain investigation notebook (surface_notes, hypotheses, notes). 0 HTTP cost.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "update", "add_hypothesis", "update_hypothesis", "add_note"],
                    },
                    "surface_notes": {"type": "string"},
                    "hypothesis": {"type": "object", "description": "{id,target,vuln_class,status,notes}"},
                    "note": {"type": "string"},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "callback_listener",
            "description": "Local loopback OOB callback URLs (create_url/poll) for SSRF/webhook checks. 0 HTTP cost.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["create_url", "poll"]},
                    "label": {"type": "string"},
                    "token": {"type": "string"},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "concurrent_check",
            "description": "Send 2-5 synchronized parallel requests to test idempotency and race conditions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string"},
                    "actor": {"type": "string"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "query": {"type": "object", "additionalProperties": {"type": "string"}},
                    "json_body": {},
                    "form_body": {"type": "object", "additionalProperties": {"type": "string"}},
                    "raw_body": {"type": "string"},
                    "count": {"type": "integer", "description": "2-5 (default 3)."},
                },
                "required": ["url", "method", "actor"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_crawl",
            "description": "Read-only same-origin headless browser crawl (SPA/Shadow DOM/XHR) or rendered DOM/CSP inspect.",
            "parameters": {
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "enum": ["crawl", "inspect"]},
                    "url": {"type": "string"},
                    "actor": {"type": "string"},
                    "max_pages": {"type": "integer", "description": "1-12 (default 6)."},
                    "marker": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_token",
            "description": "Offline read-only inspection of JWTs, opaque tokens, or serialized blobs (0 HTTP cost).",
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "kind": {"type": "string", "enum": ["auto", "jwt", "opaque", "serialization"]},
                },
                "required": ["value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_finding",
            "description": "Record a verified finding backed by proof_receipt_ids, control_receipt_ids, and evidence_value.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "class_type": {
                        "type": "string",
                        "description": "bola, tenant_isolation, bfla, auth_bypass, mass_assignment, reflected_xss, stored_xss, sqli_read, sqli, open_redirect, csrf, ssti, xxe, ssrf, path_traversal, info_disclosure, business_logic, race_condition, other",
                    },
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "actor_alias": {"type": "string"},
                    "proof_receipt_ids": {"type": "array", "items": {"type": "string"}},
                    "control_receipt_ids": {"type": "array", "items": {"type": "string"}},
                    "evidence_value": {"type": "string"},
                    "summary": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                },
                "required": [
                    "title",
                    "class_type",
                    "method",
                    "url",
                    "actor_alias",
                    "proof_receipt_ids",
                    "control_receipt_ids",
                    "evidence_value",
                    "summary",
                ],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "Complete investigation and summarize findings plus untested areas.",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                    "untested_areas": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["summary"],
            },
        },
    },
]


def wrap_untrusted(payload: Any) -> str:
    """Wrap target-derived content in explicit prompt-injection isolation markers."""
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return (
        "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
        f"{text}\n"
        "<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    )


def _atomic_write_json(path: Path, data: Any) -> None:
    """Atomically write JSON with 0600 permissions to `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".tool-", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _deep_merge_json(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge `patch` into `base`, preserving existing unpatched keys."""
    merged = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_json(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


class ToolDispatcher:
    """Executes investigation and QA verification tools against the harness."""

    def __init__(
        self,
        *,
        http_client: AgenticHTTPClient,
        receipt_store: ReceiptStore,
        root_dir: str | Path,
        bsag: Any | None = None,
        oracle: Any | None = None,
        telemetry: Any | None = None,
        findings_path: str | Path | None = None,
        persist_findings: bool = True,
        oob_server: LoopbackCallbackServer | None = None,
    ):
        self.http = http_client
        self.receipts = receipt_store
        self.root_dir = Path(root_dir).expanduser().resolve()
        self.bsag = bsag
        self.oracle = oracle
        self.telemetry = telemetry
        self._oob_server: LoopbackCallbackServer | None = oob_server
        self._owns_oob_server: bool = False
        self._oob_lock = threading.Lock()
        self.active_worker_id: str = ""
        self.active_node_id: str = ""
        self.active_category: str = ""
        self._step_delta_v: int = 0
        self._step_delta_e: int = 0
        self._step_claim_submitted: bool = False
        self._findings_lock = threading.RLock()
        self._notebook_lock = threading.RLock()
        self.persist_findings: bool = bool(persist_findings)
        self.notebook_path = self.root_dir / "notebook.json"
        self.findings_path = (
            Path(findings_path).expanduser().resolve()
            if findings_path is not None
            else (self.root_dir / "findings.json")
        )
        self.notebook_state: dict[str, Any] = self._load_json(
            self.notebook_path,
            default={"surface_notes": "", "hypotheses": [], "notes": []},
        )
        self.findings: list[dict[str, Any]] = (
            self._load_json(self.findings_path, default=[])
            if self.persist_findings
            else []
        )
        self.surface_tracker = SurfaceFrontierTracker(
            base_url=self.http.base_url,
            allowed_methods=sorted(self.http.allowed_methods),
            actor_summaries=self.http.actors.summaries(),
        )
        self.coverage_gate_enabled: bool = True
        self.discovery_finish_gate: bool = False
        self._auth_barrier_or_write_seen: bool = False
        self._non_anon_2xx_reads: int = 0
        self.finish_rejections: int = 0
        self.max_finish_rejections: int = 3
        self.finished: bool = False
        self.finish_summary: str = ""
        self.untested_areas: list[str] = []

    def set_active_context(self, *, worker_id: str = "", node_id: str = "", category: str = "") -> None:
        self.active_worker_id = worker_id
        self.active_node_id = node_id
        self.active_category = category

    def consume_step_deltas(self) -> tuple[int, int, bool]:
        dv = self._step_delta_v
        de = self._step_delta_e
        claimed = self._step_claim_submitted
        self._step_delta_v = 0
        self._step_delta_e = 0
        self._step_claim_submitted = False
        return dv, de, claimed

    def _ingest_receipt_hooks(self, receipt: dict[str, Any]) -> None:
        self.surface_tracker.ingest_receipt(receipt)
        saved = receipt.get("saved_session")
        if isinstance(saved, dict) and saved.get("alias"):
            alias = str(saved["alias"])
            self.surface_tracker.actors[alias] = {
                "alias": alias,
                "role": str(saved.get("role") or "member").lower(),
                "tenant": "",
            }
            if self.bsag is not None:
                _, ac_v = self.bsag.register_auth_context(
                    alias=alias,
                    role=str(saved.get("role") or "member"),
                    authenticated=bool(saved.get("authenticated", True)),
                    dynamic=True,
                    source_receipt_id=str(saved.get("source_receipt_id") or receipt.get("receipt_id") or ""),
                )
                self._step_delta_v += ac_v
        dv, de = (0, 0)
        if self.bsag is not None:
            dv, de = self.bsag.ingest_receipt(receipt)
            self._step_delta_v += dv
            self._step_delta_e += de
        status = int(receipt.get("status") or 0)
        actor = str(receipt.get("actor") or "anon")
        method = str(receipt.get("method") or "GET").upper()
        if (
            status in {401, 403}
            or (300 <= status < 400 and actor == "anon")
            or bool(self.surface_tracker.declared_write_ops)
            or bool(self.surface_tracker.discovered_write_ops)
        ):
            self._auth_barrier_or_write_seen = True
        if actor != "anon" and method == "GET" and 200 <= status < 300:
            self._non_anon_2xx_reads += 1
        if self.telemetry is not None:
            ep_id = self.bsag.endpoint_node_id(receipt.get("url") or "/") if self.bsag is not None else self.active_node_id
            self.telemetry.emit(
                "http_event",
                worker_id=self.active_worker_id,
                node_id=self.active_node_id or ep_id,
                endpoint_id=ep_id,
                category=self.active_category,
                method=receipt.get("method"),
                path=receipt.get("path"),
                route_template=normalize_route_template(str(receipt.get("url") or "/")),
                actor=receipt.get("actor"),
                status=receipt.get("status"),
                cached=bool(receipt.get("cached", False)),
                delta_v=dv,
                delta_e=de,
                receipt_id=receipt.get("receipt_id"),
            )

    @staticmethod
    def _load_json(path: Path, default: Any) -> Any:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
        return json.loads(json.dumps(default))

    def _save_notebook(self) -> None:
        with self._notebook_lock:
            _atomic_write_json(self.notebook_path, self.notebook_state)

    def _save_findings(self) -> None:
        if not self.persist_findings:
            return
        with self._findings_lock:
            _atomic_write_json(self.findings_path, self.findings)

    def _get_oob_server(self, *, start: bool = False) -> LoopbackCallbackServer | None:
        with self._oob_lock:
            if self._oob_server is None:
                if not start:
                    return None
                self._oob_server = LoopbackCallbackServer()
                self._owns_oob_server = True
            if start:
                self._oob_server.start()
            return self._oob_server

    def close(self) -> None:
        """Cleanly shut down any lazily created loopback callback server."""
        with self._oob_lock:
            srv = self._oob_server
            owns = self._owns_oob_server
            if owns:
                self._oob_server = None
                self._owns_oob_server = False
        if srv is not None and owns:
            srv.close()

    def dispatch(self, name: str, args: dict[str, Any]) -> str:
        handlers = {
            "http_request": self._tool_http_request,
            "read_receipt": self._tool_read_receipt,
            "replay_as": self._tool_replay_as,
            "extract_surface": self._tool_extract_surface,
            "browser_crawl": self._tool_browser_crawl,
            "analyze_token": self._tool_analyze_token,
            "notebook": self._tool_notebook,
            "callback_listener": self._tool_callback_listener,
            "concurrent_check": self._tool_concurrent_check,
            "record_finding": self._tool_record_finding,
            "finish": self._tool_finish,
        }
        fn = handlers.get(name)
        if fn is None:
            return json.dumps({"error": f"unknown tool: {name}"})
        try:
            return fn(args or {})
        except ServiceDegradationError:
            raise
        except (ScopeViolationError, MethodNotAllowedError, BudgetExhaustedError, KeyError, ValueError) as exc:
            return json.dumps({"error": type(exc).__name__, "message": str(exc)})
        except Exception as exc:
            return json.dumps({"error": type(exc).__name__, "message": str(exc)[:300]})

    def _actor_meta_map(self) -> dict[str, dict[str, str]]:
        return {
            row["alias"]: {
                "alias": row["alias"],
                "role": str(row.get("role") or "").lower(),
                "tenant": str(row.get("tenant") or "").lower(),
            }
            for row in self.http.actors.summaries()
        }

    def _load_receipt_json_object(self, receipt_id: str) -> dict[str, Any]:
        rec = self.receipts.get(receipt_id)
        for field_name in ("body", "request_body"):
            raw = (rec.get(field_name) or "").strip()
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed
        raise ValueError(f"receipt {receipt_id} does not contain a JSON object")

    def _tool_http_request(self, args: dict[str, Any]) -> str:
        json_body = args.get("json_body")
        if isinstance(json_body, str) and json_body.lstrip().startswith(("{", "[")):
            try:
                parsed_json = json.loads(json_body)
            except ValueError:
                parsed_json = None
            if isinstance(parsed_json, (dict, list)):
                json_body = parsed_json
        form_body = args.get("form_body")
        if isinstance(form_body, str) and form_body.lstrip().startswith("{"):
            try:
                parsed_form = json.loads(form_body)
            except ValueError:
                parsed_form = None
            if isinstance(parsed_form, dict):
                form_body = parsed_form
        raw_body = args.get("raw_body")
        base_receipt_id = str(args.get("base_receipt_id") or "").strip()
        json_merge = args.get("json_merge") if isinstance(args.get("json_merge"), dict) else (
            args.get("mutate_json") if isinstance(args.get("mutate_json"), dict) else None
        )
        if base_receipt_id:
            merged_obj = self._load_receipt_json_object(base_receipt_id)
            if isinstance(json_body, dict):
                merged_obj = _deep_merge_json(merged_obj, json_body)
            if json_merge is not None:
                merged_obj = _deep_merge_json(merged_obj, json_merge)
            json_body = merged_obj
        elif json_merge is not None:
            if isinstance(json_body, dict):
                json_body = _deep_merge_json(json_body, json_merge)
            else:
                json_body = copy.deepcopy(json_merge)

        raw_method = str(args.get("method") or "").strip().upper()
        has_payload = (
            json_body is not None
            or form_body is not None
            or raw_body is not None
            or bool(base_receipt_id)
            or (json_merge is not None)
        )
        if raw_method:
            eff_method = raw_method
        elif has_payload and "POST" in self.http.allowed_methods:
            eff_method = "POST"
        else:
            eff_method = "GET"

        receipt = self.http.request(
            method=eff_method,
            url=str(args.get("url") or ""),
            actor=str(args.get("actor") or "anon"),
            headers=args.get("headers"),
            query=args.get("query"),
            json_body=json_body,
            form_body=form_body,
            raw_body=raw_body,
            force=bool(args.get("force", False)),
            save_session_as=str(args.get("save_session_as") or ""),
        )
        self._ingest_receipt_hooks(receipt)
        preview = _format_receipt_preview(receipt)
        if eff_method == "GET" and has_payload:
            preview["method_warning"] = (
                "GET request sent with request body; set method='POST' for form/JSON submissions."
            )
        status = int(receipt.get("status") or 0)
        ctype = (receipt.get("content_type") or "").lower()
        resp_headers = receipt.get("response_headers") or receipt.get("headers") or {}
        has_discovery_headers = (
            isinstance(resp_headers, dict)
            and any(
                str(k).lower() in {"link", "content-location", "refresh", "location"}
                and str(v or "").strip()
                for k, v in resp_headers.items()
            )
        ) or bool(str(receipt.get("redirect_location") or "").strip())
        url_path = urlsplit(str(receipt.get("url") or "")).path.lower()
        if 200 <= status < 400 and (
            "html" in ctype
            or "javascript" in ctype
            or "ecmascript" in ctype
            or "json" in ctype
            or "openapi" in ctype
            or "css" in ctype
            or url_path.endswith(".css")
            or has_discovery_headers
        ):
            hints = _build_surface_hints(receipt, self.http.base_url)
            if hints:
                preview["surface_hints"] = hints
        waf_info = detect_waf_block(receipt)
        if waf_info is not None:
            preview["waf_block"] = waf_info
        return wrap_untrusted(preview)

    def _tool_read_receipt(self, args: dict[str, Any]) -> str:
        safe_limit = max(1, min(int(args.get("limit", DEFAULT_PREVIEW_CHARS)), 4096))
        res = self.receipts.read_slice(
            str(args.get("receipt_id") or ""),
            offset=int(args.get("offset", 0)),
            limit=safe_limit,
            regex=str(args.get("regex") or ""),
        )
        if isinstance(res, dict) and "offset" in res and "returned_chars" in res:
            res["next_offset"] = int(res["offset"]) + int(res["returned_chars"])
        return wrap_untrusted(res)

    def _tool_replay_as(self, args: dict[str, Any]) -> str:
        baseline = self.receipts.get(str(args.get("receipt_id") or ""))
        target_actor = str(args.get("actor") or baseline["actor"])
        method = str(args.get("method") or baseline["method"]).upper()
        url = str(args.get("url") or baseline["url"])

        # Preserve safe non-auth request headers when replaying.
        req_headers: dict[str, str] = {}
        for k, v in (baseline.get("request_headers") or {}).items():
            if k.lower() not in _SKIP_REPLAY_HEADERS and "<REDACTED" not in str(v):
                req_headers[k] = str(v)
        if isinstance(args.get("header_overrides"), dict):
            for k, v in args["header_overrides"].items():
                req_headers[str(k)] = str(v)

        query_overrides = args.get("query_overrides") if isinstance(args.get("query_overrides"), dict) else None
        json_overrides = args.get("json_overrides") if isinstance(args.get("json_overrides"), dict) else None
        json_merge = args.get("json_merge") if isinstance(args.get("json_merge"), dict) else (
            args.get("mutate_json") if isinstance(args.get("mutate_json"), dict) else None
        )
        patch_obj: dict[str, Any] | None = None
        if json_overrides is not None and json_merge is not None:
            patch_obj = _deep_merge_json(json_overrides, json_merge)
        elif json_merge is not None:
            patch_obj = json_merge
        elif json_overrides is not None:
            patch_obj = json_overrides

        base_receipt_id = str(args.get("base_receipt_id") or "").strip()
        json_body = None
        raw_body = None
        base_body_str = baseline.get("request_body") or ""
        if base_receipt_id:
            base_obj = self._load_receipt_json_object(base_receipt_id)
            json_body = _deep_merge_json(base_obj, patch_obj) if patch_obj is not None else base_obj
        elif patch_obj is not None:
            parsed: Any = None
            if base_body_str:
                try:
                    parsed = json.loads(base_body_str)
                except ValueError:
                    parsed = None
            elif baseline.get("method") == "GET" and method in {"PUT", "PATCH", "POST"}:
                # Preserve existing JSON fields from baseline GET response when mutating via PUT/PATCH/POST.
                try:
                    resp_parsed = json.loads(baseline.get("body") or "")
                    if isinstance(resp_parsed, dict):
                        parsed = resp_parsed
                except ValueError:
                    parsed = None
            if isinstance(parsed, dict):
                json_body = _deep_merge_json(parsed, patch_obj)
            else:
                json_body = copy.deepcopy(patch_obj)
        elif base_body_str:
            try:
                json_body = json.loads(base_body_str)
            except ValueError:
                raw_body = base_body_str

        current = self.http.request(
            method=method,
            url=url,
            actor=target_actor,
            headers=req_headers or None,
            query=query_overrides,
            json_body=json_body,
            raw_body=raw_body,
            force=bool(args.get("force", False)),
        )
        self.surface_tracker.ingest_receipt(baseline)
        self._ingest_receipt_hooks(current)
        replay_preview = _format_receipt_preview(current, preview_chars=1800)
        waf_info = detect_waf_block(current)
        if waf_info is not None:
            replay_preview["waf_block"] = waf_info
        out = {
            "baseline_receipt_id": baseline["receipt_id"],
            "baseline_actor": baseline["actor"],
            "replay": replay_preview,
            "diff": _compute_structural_diff(baseline, current),
        }
        return wrap_untrusted(out)

    def _tool_browser_crawl(self, args: dict[str, Any]) -> str:
        mode = str(args.get("mode") or "crawl").strip().lower()
        url = str(args.get("url") or "/").strip() or "/"
        actor = str(args.get("actor") or "anon").strip() or "anon"
        if mode == "inspect":
            result = inspect_rendered_page(
                self.http,
                url=url,
                actor=actor,
                marker=str(args.get("marker") or ""),
            )
            return wrap_untrusted(result)
        raw_max_pages = args.get("max_pages", 6)
        try:
            max_pages = int(raw_max_pages)
        except (TypeError, ValueError):
            max_pages = 6
        result = run_browser_crawl(
            self.http,
            self.surface_tracker,
            url=url,
            actor=actor,
            max_pages=max_pages,
        )
        return wrap_untrusted(result)

    def _tool_analyze_token(self, args: dict[str, Any]) -> str:
        value = str(args.get("value") or "")
        kind = str(args.get("kind") or "auto").strip().lower() or "auto"
        result = analyze_token(value, kind=kind)
        return json.dumps(result, ensure_ascii=False)

    def _tool_extract_surface(self, args: dict[str, Any]) -> str:
        receipt = self.receipts.get(str(args.get("receipt_id") or ""))
        surface = _extract_surface_summary(receipt, self.http.base_url)
        self.surface_tracker.ingest_receipt(receipt)
        self.surface_tracker.ingest_surface(surface, actor=str(receipt.get("actor") or ""))
        if self.bsag is not None:
            dv1, de1 = self.bsag.ingest_receipt(receipt, mark_visited=False)
            dv2, de2 = self.bsag.ingest_surface(surface, actor=str(receipt.get("actor") or ""))
            self._step_delta_v += dv1 + dv2
            self._step_delta_e += de1 + de2
        compact_surface = {
            k: v
            for k, v in surface.items()
            if k in {"receipt_id", "url", "content_type"} or bool(v)
        }
        return wrap_untrusted(compact_surface)

    def _tool_notebook(self, args: dict[str, Any]) -> str:
        action = str(args.get("action") or "read").strip().lower()
        with self._notebook_lock:
            if action == "update" and args.get("surface_notes") is not None:
                self.notebook_state["surface_notes"] = str(args["surface_notes"])[:6000]
            elif action in {"add_hypothesis", "update_hypothesis"}:
                hyp = args.get("hypothesis")
                if not isinstance(hyp, dict) or not hyp.get("id"):
                    return json.dumps({"error": "hypothesis object with 'id' is required"})
                hid = str(hyp["id"])
                existing = [h for h in self.notebook_state["hypotheses"] if h.get("id") != hid]
                existing.append({
                    "id": hid,
                    "target": str(hyp.get("target") or ""),
                    "vuln_class": str(hyp.get("vuln_class") or ""),
                    "status": str(hyp.get("status") or "open"),
                    "notes": str(hyp.get("notes") or "")[:500],
                })
                self.notebook_state["hypotheses"] = existing[-50:]
            elif action == "add_note":
                note = str(args.get("note") or "").strip()
                if note:
                    self.notebook_state["notes"] = [*self.notebook_state.get("notes", []), note[:400]][-40:]
            elif action != "read":
                return json.dumps({"error": f"unsupported notebook action: {action}"})
            self._save_notebook()
            return json.dumps(self.notebook_state, ensure_ascii=False)

    def _tool_callback_listener(self, args: dict[str, Any]) -> str:
        action = str(args.get("action") or "").strip().lower()
        if action == "create_url":
            srv = self._get_oob_server(start=True)
            assert srv is not None
            info = srv.create_token(label=str(args.get("label") or ""))
            return json.dumps(info, ensure_ascii=False)
        if action == "poll":
            tok = str(args.get("token") or "").strip()
            srv = self._get_oob_server(start=False)
            if srv is None:
                return wrap_untrusted({
                    "token": tok,
                    "registered": False,
                    "hit_count": 0,
                    "total_hits": 0,
                    "hits": [],
                })
            return wrap_untrusted(srv.poll(tok))
        raise ValueError(f"unsupported callback_listener action: {action!r}; expected 'create_url' or 'poll'")

    def _tool_concurrent_check(self, args: dict[str, Any]) -> str:
        url = str(args.get("url") or "").strip()
        norm_method = str(args.get("method") or "GET").strip().upper()
        actor = str(args.get("actor") or "anon").strip() or "anon"

        raw_count = args.get("count", 3)
        if isinstance(raw_count, bool):
            raise ValueError("count must be an integer between 2 and 5")
        try:
            count_val = int(raw_count) if raw_count is not None else 3
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid count: {raw_count!r}") from exc
        count = max(2, min(5, count_val))

        if norm_method not in self.http.allowed_methods:
            raise MethodNotAllowedError(
                f"HTTP method {norm_method!r} not allowed; permitted: {sorted(self.http.allowed_methods)}"
            )
        headers = args.get("headers") if isinstance(args.get("headers"), dict) else None
        query = args.get("query") if isinstance(args.get("query"), dict) else None
        json_body = args.get("json_body")
        form_body = args.get("form_body") if isinstance(args.get("form_body"), dict) else None
        raw_body = str(args["raw_body"]) if args.get("raw_body") is not None else None

        clean_url, _, _ = self.http._merge_query(url, query)
        session = self.http.actors.get(actor)
        has_auth_override = any(str(k).lower() in {"authorization", "cookie"} for k in (headers or {}))
        if actor != "anon" and not has_auth_override and not session.authenticated:
            self.http.authenticate_actor(actor, force_login=False)

        remaining = self.http._budget_remaining()
        if remaining < count:
            raise BudgetExhaustedError(
                f"concurrent_check requires {count} HTTP requests, only {remaining} remaining in budget"
            )

        barrier = threading.Barrier(count, timeout=10.0)

        def _worker() -> dict[str, Any]:
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass
            return self.http.request(
                method=norm_method,
                url=url,
                actor=actor,
                headers=headers,
                query=query,
                json_body=json_body,
                form_body=form_body,
                raw_body=raw_body,
                force=True,
            )

        with ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(_worker) for _ in range(count)]
            receipts = [fut.result() for fut in futures]

        for rec in receipts:
            self._ingest_receipt_hooks(rec)

        status_counts: dict[str, int] = {}
        receipt_ids: list[str] = []
        distinct_hashes: list[str] = []
        seen_hashes: set[str] = set()
        results: list[dict[str, Any]] = []
        for rec in receipts:
            rid = str(rec.get("receipt_id") or "")
            st_key = str(int(rec.get("status") or 0))
            status_counts[st_key] = status_counts.get(st_key, 0) + 1
            if rid:
                receipt_ids.append(rid)
            sha = str(rec.get("response_sha256") or "")
            if sha and sha not in seen_hashes:
                seen_hashes.add(sha)
                distinct_hashes.append(sha)
            preview_body = str(rec.get("body") or "")[:300]
            item: dict[str, Any] = {
                "receipt_id": rid,
                "status": int(rec.get("status") or 0),
                "elapsed_ms": rec.get("elapsed_ms"),
                "response_sha256": sha[:16],
                "body_preview": preview_body if preview_body else "<empty>",
            }
            if rec.get("error"):
                item["error"] = rec["error"]
            results.append(item)

        return wrap_untrusted({
            "count": len(receipts),
            "method": norm_method,
            "url": clean_url,
            "actor": actor,
            "status_counts": status_counts,
            "receipt_ids": receipt_ids,
            "distinct_body_hashes": distinct_hashes,
            "results": results,
        })

    def _receipt_contains_evidence(self, receipt: dict[str, Any], evidence: str) -> tuple[bool, str]:
        needle = evidence.strip()
        lower_needle = needle.lower()
        body = receipt.get("body") or ""
        loc = receipt.get("redirect_location") or ""
        headers_text = json.dumps(receipt.get("response_headers") or {}, ensure_ascii=False)

        if needle in body or lower_needle in body.lower():
            return True, build_receipt_excerpt(receipt, needle, max_chars=MAX_PROOF_EXCERPT_CHARS)
        if needle in loc or lower_needle in loc.lower():
            return True, build_receipt_excerpt(receipt, needle, max_chars=MAX_PROOF_EXCERPT_CHARS)
        if lower_needle in headers_text.lower():
            return True, headers_text[:MAX_PROOF_EXCERPT_CHARS]
        return False, ""

    def _collect_oob_ssrf_context(
        self,
        proof_receipts: list[dict[str, Any]],
        evidence_value: str,
    ) -> tuple[str, list[str], list[dict[str, Any]]]:
        """Inspect proof receipts and evidence for callback_listener tokens/hits."""
        oob_srv = self._oob_server
        ev = str(evidence_value or "").strip()
        cb_pat = re.compile(r"/cb/([A-Za-z0-9_-]{6,})")
        cb_refs: list[str] = list(cb_pat.findall(ev))
        for rec in proof_receipts:
            req_blob = "\n".join([
                str(rec.get("url") or ""),
                str(rec.get("query") or ""),
                str(rec.get("request_body") or ""),
                json.dumps(rec.get("request_headers") or {}, ensure_ascii=False),
            ])
            cb_refs.extend(cb_pat.findall(req_blob))

        if oob_srv is None:
            if cb_refs:
                return "missing_server", list(dict.fromkeys(cb_refs)), []
            return "none", [], []

        reg_tokens = oob_srv.registered_tokens()
        matched_tokens: list[str] = []
        for tok in reg_tokens:
            if not tok:
                continue
            if tok in ev or any(
                tok in str(r.get("url") or "")
                or tok in str(r.get("query") or "")
                or tok in str(r.get("request_body") or "")
                or tok in json.dumps(r.get("request_headers") or {}, ensure_ascii=False)
                for r in proof_receipts
            ):
                matched_tokens.append(tok)

        if not matched_tokens and cb_refs:
            return "zero_hits", list(dict.fromkeys(cb_refs)), []
        if not matched_tokens:
            return "none", [], []

        matching_hits: list[dict[str, Any]] = []
        for tok in matched_tokens:
            polled = oob_srv.poll(tok)
            matching_hits.extend(polled.get("hits") or [])
        if not matching_hits:
            return "zero_hits", matched_tokens, []
        return "verified_hits", matched_tokens, matching_hits

    def _find_followup_persistent_get(
        self,
        *,
        primary: dict[str, Any],
        canonical_class: str,
        evidence_value: str,
        exclude_ids: set[str],
    ) -> dict[str, Any] | None:
        """Locate a newer 2xx GET render/persistence receipt in ReceiptStore for a write proof."""
        p_rid = str(primary.get("receipt_id") or "")
        p_seq = int(p_rid[4:]) if p_rid.startswith("req-") and p_rid[4:].isdigit() else 0
        p_ts = str(primary.get("timestamp") or "")
        ev = str(evidence_value or "").strip()
        candidates: list[dict[str, Any]] = []
        for rid in self.receipts.list_ids():
            if rid in exclude_ids:
                continue
            try:
                cand = self.receipts.get(rid)
            except (KeyError, ValueError):
                continue
            c_seq = int(rid[4:]) if rid.startswith("req-") and rid[4:].isdigit() else 0
            if p_seq > 0 and c_seq > 0:
                if c_seq <= p_seq:
                    continue
            elif p_ts and str(cand.get("timestamp") or "") < p_ts:
                continue
            if str(cand.get("method") or "").upper() != "GET":
                continue
            if not (200 <= int(cand.get("status") or 0) < 300):
                continue
            c_url = str(cand.get("url") or cand.get("path") or "")
            if not is_persistent_read_path_related(primary, c_url):
                continue
            if canonical_class == "stored_xss":
                if not is_html_receipt(cand):
                    continue
                if ev and not receipt_body_contains_verbatim(cand, ev):
                    continue
            elif ev and not self._receipt_contains_evidence(cand, ev)[0]:
                continue
            candidates.append(cand)
        if not candidates:
            return None
        return find_persistent_render_get_receipt(
            primary,
            candidates,
            ev,
            canonical_class=canonical_class,
        )

    def _try_merge_existing_finding_locked(
        self,
        *,
        canonical_class: str,
        route_template: str,
        raw_url: str,
        method: str,
        effective_actor: str,
        effective_norm_path: str,
        evidence_value: str,
        proof_ids: list[str],
        control_ids: list[str],
        actor_meta: dict[str, dict[str, str]],
    ) -> dict[str, Any] | None:
        """Merge into an existing finding sharing `(route_template, class_type)` under `_findings_lock`."""
        for existing in self.findings:
            existing_class = normalize_vuln_class(
                str(existing.get("class_type") or ""),
                method=str(existing.get("method") or ""),
                title=str(existing.get("title") or ""),
                summary=str(existing.get("summary") or ""),
            )
            existing_tmpl = str(
                existing.get("route_template")
                or normalize_route_template(str(existing.get("url") or existing.get("path") or ""))
            )
            same_or_overlap = existing_tmpl == route_template and (
                existing_class == canonical_class
                or ({existing_class, canonical_class} == {"auth_bypass", "bfla"})
            )
            if not same_or_overlap:
                continue

            merged_proof_ids = list(dict.fromkeys([*(existing.get("proof_receipt_ids") or []), *proof_ids]))
            merged_ctrl_ids = list(dict.fromkeys([*(existing.get("control_receipt_ids") or []), *control_ids]))
            all_proof_recs: list[dict[str, Any]] = []
            for rid in merged_proof_ids:
                try:
                    rec = self.receipts.get(rid)
                    if 200 <= int(rec.get("status", 0)) < 400:
                        all_proof_recs.append(rec)
                except (KeyError, ValueError):
                    continue
            all_ctrl_recs: list[dict[str, Any]] = []
            for rid in merged_ctrl_ids:
                try:
                    all_ctrl_recs.append(self.receipts.get(rid))
                except (KeyError, ValueError):
                    continue

            resolved_class = canonical_class
            if {existing_class, canonical_class} == {"auth_bypass", "bfla"}:
                resolved_class = _resolve_route_auth_bypass_vs_bfla(
                    route_template,
                    all_proof_recs,
                    all_ctrl_recs,
                    actor_meta_map=actor_meta,
                    receipt_store=self.receipts,
                    exact_path=effective_norm_path,
                    method=method,
                )
            existing["class_type"] = resolved_class
            existing["route_template"] = route_template
            existing["proof_receipt_ids"] = merged_proof_ids
            existing["control_receipt_ids"] = merged_ctrl_ids
            existing_ev = str(existing.get("evidence_value") or existing.get("marker") or "").strip()
            ex_score = score_evidence_value(existing_ev)
            in_score = score_evidence_value(evidence_value)
            ctrl_haystacks = _build_control_haystacks(all_ctrl_recs)
            if existing_ev and _value_in_controls(existing_ev, ctrl_haystacks) and ex_score < _HIGH_SPEC_THRESHOLD:
                ex_score = min(ex_score, 10)
            if evidence_value and _value_in_controls(evidence_value, ctrl_haystacks) and in_score < _HIGH_SPEC_THRESHOLD:
                in_score = min(in_score, 10)
            if not existing_ev or (in_score >= _HIGH_SPEC_THRESHOLD and in_score > ex_score) or (in_score >= ex_score + 15):
                ev_str = evidence_value
            else:
                ev_str = existing_ev
            if all_proof_recs and resolved_class not in {"open_redirect", "reflected_xss", "stored_xss"}:
                eligible_all = _filter_class_eligible_proofs(
                    resolved_class,
                    all_proof_recs,
                    all_ctrl_recs,
                    actor_meta_map=actor_meta,
                    receipt_store=self.receipts,
                    route_template=route_template,
                    evidence_value=ev_str,
                )
                promoted_ev, _ = _select_stronger_evidence_from_receipts(
                    resolved_class,
                    ev_str,
                    eligible_all,
                    all_ctrl_recs,
                )
                if promoted_ev:
                    ev_str = promoted_ev
            existing["evidence_value"] = ev_str
            existing["marker"] = ev_str

            if all_proof_recs:
                best, ordered_actors = select_primary_proof(
                    resolved_class,
                    all_proof_recs,
                    all_ctrl_recs,
                    actor_meta_map=actor_meta,
                    receipt_store=self.receipts,
                    route_template=route_template,
                    evidence_value=ev_str,
                )
                best_actor = str(best.get("actor") or effective_actor or "anon").strip() or "anon"
                existing["actor"] = best_actor
                existing["actor_alias"] = best_actor
                resolved_best_url, clean_best_path, _ = self.http.resolve_in_scope(best["url"] or raw_url)
                existing["observed_status"] = best["status"]
                existing["url"] = resolved_best_url
                existing["path"] = clean_best_path
                existing["method"] = best["method"]
                prior_actors = [str(a) for a in (existing.get("supporting_actors") or []) if str(a)]
                existing["supporting_actors"] = list(dict.fromkeys([*ordered_actors, *prior_actors]))
                existing["evidence_excerpts"] = [
                    {
                        "receipt_id": r["receipt_id"],
                        "actor": r["actor"],
                        "method": r["method"],
                        "url": r["url"],
                        "status": r["status"],
                        "excerpt": build_receipt_excerpt(r, ev_str, max_chars=MAX_PROOF_EXCERPT_CHARS),
                    }
                    for r in all_proof_recs
                ]
                existing["control_excerpts"] = [
                    {
                        "receipt_id": c["receipt_id"],
                        "actor": c["actor"],
                        "method": c["method"],
                        "url": c["url"],
                        "status": c["status"],
                        "excerpt": build_receipt_excerpt(c, "", max_chars=MAX_CONTROL_EXCERPT_CHARS),
                    }
                    for c in all_ctrl_recs
                ]
                existing["evidence"] = compose_finding_evidence(
                    best,
                    all_proof_recs,
                    all_ctrl_recs,
                    ev_str,
                    max_proof_chars=MAX_PROOF_EXCERPT_CHARS,
                    max_control_chars=MAX_CONTROL_EXCERPT_CHARS,
                )
            self._save_findings()
            return {
                "accepted": True,
                "duplicate": True,
                "merged": True,
                "finding_id": existing["finding_id"],
                "class_type": existing["class_type"],
                "primary_actor": existing.get("actor"),
                "supporting_actors": existing.get("supporting_actors", []),
            }
        return None

    def _tool_record_finding(self, args: dict[str, Any]) -> str:
        title = str(args.get("title") or "").strip()
        raw_class_type = str(args.get("class_type") or "").strip().lower().replace("-", "_")
        method = str(args.get("method") or "").strip().upper()
        raw_url = str(args.get("url") or "").strip()
        actor_alias = str(args.get("actor_alias") or args.get("actor") or "").strip()
        proof_ids = list(dict.fromkeys(str(r).strip() for r in (args.get("proof_receipt_ids") or []) if str(r).strip()))
        control_ids = list(dict.fromkeys(str(r).strip() for r in (args.get("control_receipt_ids") or []) if str(r).strip()))
        evidence_value = str(args.get("evidence_value") or "").strip()
        summary = str(args.get("summary") or "").strip()
        severity = str(args.get("severity") or "high").strip().lower()

        if not title or not raw_class_type or not method or not raw_url or not actor_alias or not summary:
            return json.dumps({"rejected": True, "reason": "all required string fields must be non-empty"})
        if not proof_ids or not control_ids:
            return json.dumps({"rejected": True, "reason": "both proof_receipt_ids and control_receipt_ids are required"})
        if set(proof_ids) & set(control_ids):
            return json.dumps({"rejected": True, "reason": "proof_receipt_ids and control_receipt_ids must not overlap"})

        canonical_class = normalize_vuln_class(raw_class_type, method=method, title=title, summary=summary)
        route_template = normalize_route_template(raw_url)
        actor_meta = self._actor_meta_map()

        try:
            proof_receipts = [self.receipts.get(rid) for rid in proof_ids]
            control_receipts = [self.receipts.get(rid) for rid in control_ids]
        except (KeyError, ValueError) as exc:
            return json.dumps({"rejected": True, "reason": str(exc)})

        # Resolve proof matching claimed actor_alias and target URL/path (anti-hallucination check).
        target_norm_path = _norm_path(raw_url)
        matching_proofs = [
            r for r in proof_receipts
            if r["actor"] == actor_alias and _norm_path(r["url"]) == target_norm_path
        ]
        if not matching_proofs:
            return json.dumps({
                "rejected": True,
                "reason": (
                    f"no proof receipt matches actor_alias={actor_alias!r} and path={target_norm_path!r}; "
                    f"proof receipts had: {[(r['receipt_id'], r['actor'], r['path']) for r in proof_receipts]}"
                ),
            })
        write_primary = matching_proofs[0]
        primary = write_primary
        if primary["method"] != method and not (canonical_class == "mass_assignment" and primary["method"] == "GET"):
            return json.dumps({
                "rejected": True,
                "reason": f"proof receipt {primary['receipt_id']} method {primary['method']} does not match {method}",
            })
        if not (200 <= primary["status"] < 400):
            return json.dumps({
                "rejected": True,
                "reason": f"primary proof receipt {primary['receipt_id']} has non-success status {primary['status']}",
            })

        # For persistent Write -> Read classes, auto-attach a newer 2xx GET render/persistence
        # receipt from ReceiptStore when the caller passed only the mutating write receipt.
        if (
            canonical_class in _PERSISTENT_VULN_CLASSES
            and str(write_primary.get("method") or "").upper() in _MUTATING_WRITE_METHODS
        ):
            existing_render = find_persistent_render_get_receipt(
                write_primary,
                proof_receipts,
                evidence_value,
                canonical_class=canonical_class,
            )
            if existing_render is None:
                followup_get = self._find_followup_persistent_get(
                    primary=write_primary,
                    canonical_class=canonical_class,
                    evidence_value=evidence_value,
                    exclude_ids=set(proof_ids) | set(control_ids),
                )
                if followup_get is not None:
                    proof_receipts.append(followup_get)
                    proof_ids.append(str(followup_get["receipt_id"]))

        def _is_compatible_proof_receipt(r: dict[str, Any]) -> bool:
            r_method = str(r.get("method") or "").upper()
            r_status = int(r.get("status") or 0)
            if not (200 <= r_status < 400):
                return False
            is_persistent_get = (
                canonical_class in _PERSISTENT_VULN_CLASSES
                and str(write_primary.get("method") or "").upper() in _MUTATING_WRITE_METHODS
                and r_method == "GET"
                and 200 <= r_status < 300
                and is_persistent_read_path_related(write_primary, str(r.get("url") or r.get("path") or ""))
            )
            if not is_persistent_get:
                if normalize_route_template(r["url"]) != route_template:
                    return False
                if r_method != method and not (canonical_class == "mass_assignment" and r_method == "GET"):
                    return False
            if canonical_class == "auth_bypass" and not _is_genuine_anon_2xx(r, actor_meta):
                return False
            return True

        compatible_proofs = [r for r in proof_receipts if _is_compatible_proof_receipt(r)]
        original_evidence_value = evidence_value
        excerpt = ""
        found_in_proof = False
        matching_oob_hits: list[dict[str, Any]] = []
        oob_matched_tokens: list[str] = []

        if canonical_class == "ssrf":
            oob_status, oob_matched_tokens, matching_oob_hits = self._collect_oob_ssrf_context(
                compatible_proofs or proof_receipts,
                evidence_value,
            )
            if oob_status in {"missing_server", "zero_hits"}:
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        "SSRF callback claim rejected: callback_listener poll recorded 0 hits "
                        f"for submitted token(s) {oob_matched_tokens}"
                    ),
                })

        if not evidence_value or evidence_value.lower() in _TRIVIAL_EVIDENCE or len(evidence_value) < 3:
            if len(proof_receipts) > 1 and compatible_proofs:
                eligible_init = _filter_class_eligible_proofs(
                    canonical_class,
                    compatible_proofs,
                    control_receipts,
                    actor_meta_map=actor_meta,
                    receipt_store=self.receipts,
                    route_template=route_template,
                    evidence_value="",
                )
                promoted_ev, promoted_rec = _select_stronger_evidence_from_receipts(
                    canonical_class,
                    "",
                    eligible_init,
                    control_receipts,
                )
                if promoted_rec is not None and promoted_ev:
                    evidence_value = promoted_ev
                    primary = promoted_rec
                    excerpt = build_receipt_excerpt(primary, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)
                    found_in_proof = True
            if not evidence_value or evidence_value.lower() in _TRIVIAL_EVIDENCE or len(evidence_value) < 3:
                return json.dumps({"rejected": True, "reason": "evidence_value must be a real observed value, not a status/placeholder"})

        if not found_in_proof:
            if canonical_class == "ssrf" and matching_oob_hits:
                ev_low = evidence_value.lower()
                oob_hit_match = any(
                    tok == evidence_value
                    or tok in evidence_value
                    or ev_low in json.dumps(h, ensure_ascii=False).lower()
                    for tok in oob_matched_tokens
                    for h in matching_oob_hits
                )
                if oob_hit_match:
                    found_in_proof = True
                    hit0 = matching_oob_hits[0]
                    hit_summary = (
                        f"OOB callback hit: {hit0.get('method')} {hit0.get('path')} "
                        f"from {hit0.get('remote_addr')} body={hit0.get('body_preview', '')[:300]}"
                    )
                    base_ex = build_receipt_excerpt(primary, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS // 2)
                    excerpt = f"{base_ex}\n{hit_summary}"[:MAX_PROOF_EXCERPT_CHARS]
            if not found_in_proof and canonical_class == "stored_xss":
                get_candidates: list[dict[str, Any]] = []
                seen_get_rids: set[str] = set()
                for r in [primary, *compatible_proofs]:
                    rid = str(r.get("receipt_id") or "")
                    if rid in seen_get_rids:
                        continue
                    seen_get_rids.add(rid)
                    if str(r.get("method") or "").upper() == "GET" and 200 <= int(r.get("status") or 0) < 300:
                        get_candidates.append(r)
                html_get_candidates = [r for r in get_candidates if is_html_receipt(r)]
                if not html_get_candidates:
                    return json.dumps({
                        "rejected": True,
                        "reason": (
                            "stored_xss requires a 2xx text/html GET render receipt "
                            "containing evidence_value unescaped verbatim"
                        ),
                    })
                for r in html_get_candidates:
                    if receipt_body_contains_verbatim(r, evidence_value):
                        found_in_proof = True
                        primary = r
                        excerpt = build_receipt_excerpt(r, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)
                        break
                if not found_in_proof:
                    return json.dumps({
                        "rejected": True,
                        "reason": (
                            f"evidence_value {evidence_value!r} was not found unescaped verbatim "
                            "in HTML GET render receipt(s)"
                        ),
                    })
            else:
                # Verify evidence_value appears verbatim in matching_proofs first, then any compatible proof receipt.
                for r in matching_proofs:
                    ok, ex = self._receipt_contains_evidence(r, evidence_value)
                    if ok:
                        found_in_proof = True
                        excerpt = ex
                        primary = r
                        break
                if not found_in_proof:
                    for r in compatible_proofs:
                        ok, ex = self._receipt_contains_evidence(r, evidence_value)
                        if ok:
                            found_in_proof = True
                            excerpt = ex
                            primary = r
                            break
        if not found_in_proof:
            return json.dumps({
                "rejected": True,
                "reason": f"evidence_value {evidence_value!r} was not found verbatim in proof receipt(s) for {actor_alias}",
            })

        # Multi-receipt specificity promotion: upgrade generic/low-specificity evidence when another
        # class-eligible proof receipt exposes a strictly higher-specificity unique secret (not in controls).
        if (
            len(proof_receipts) > 1
            and compatible_proofs
            and canonical_class not in {"open_redirect", "reflected_xss", "stored_xss", "race_condition"}
            and not matching_oob_hits
        ):
            eligible_proofs = _filter_class_eligible_proofs(
                canonical_class,
                compatible_proofs,
                control_receipts,
                actor_meta_map=actor_meta,
                receipt_store=self.receipts,
                route_template=route_template,
                evidence_value=evidence_value,
            )
            promoted_ev, promoted_rec = _select_stronger_evidence_from_receipts(
                canonical_class,
                evidence_value,
                eligible_proofs,
                control_receipts,
            )
            if promoted_rec is not None and promoted_ev:
                evidence_value = promoted_ev
                primary = promoted_rec
                excerpt = build_receipt_excerpt(primary, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)

        effective_actor = str(primary.get("actor") or actor_alias).strip() or actor_alias
        effective_norm_path = _norm_path(primary["url"])

        # Class-specific anti-false-positive checks.
        if canonical_class == "open_redirect":
            loc = primary.get("redirect_location") or ""
            if not (300 <= primary["status"] < 400 and loc):
                return json.dumps({"rejected": True, "reason": "open_redirect requires 3xx status with Location header"})
            loc_host = urlsplit(loc).netloc
            base_host = urlsplit(self.http.base_url).netloc
            if not loc_host or loc_host == base_host:
                return json.dumps({"rejected": True, "reason": f"redirect Location {loc!r} is not an external host"})
            if all(urlsplit(c.get("redirect_location") or "").netloc == loc_host for c in control_receipts):
                return json.dumps({"rejected": True, "reason": "control receipt also redirected to same external host"})

        elif canonical_class in {"reflected_xss", "stored_xss"}:
            ctype = (primary.get("content_type") or "").lower()
            if "json" in ctype:
                return json.dumps({"rejected": True, "reason": "JSON content-type reflection is not executable HTML XSS"})
            if canonical_class == "stored_xss" and not is_html_receipt(primary):
                return json.dumps({"rejected": True, "reason": "stored_xss requires HTML (text/html) content-type on render GET receipt"})
            if not any(c.get("response_sha256") != primary.get("response_sha256") for c in control_receipts):
                return json.dumps({"rejected": True, "reason": "control receipt is identical to proof receipt"})
            p_body = str(primary.get("body") or "")
            needle_low = evidence_value.lower()
            p_count = p_body.lower().count(needle_low)
            ctrl_pool = (
                [c for c in control_receipts if str(c.get("method") or "").upper() == "GET"] or control_receipts
                if canonical_class == "stored_xss"
                else control_receipts
            )
            c_counts = [str(c.get("body") or "").lower().count(needle_low) for c in ctrl_pool]
            if c_counts and p_count <= min(c_counts):
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        f"evidence_value {evidence_value!r} appears {p_count} time(s) in proof and "
                        f"{min(c_counts)} time(s) in control receipt (static template markup); "
                        "specify the exact reflected payload string that only appears in the proof response"
                    ),
                })

        elif canonical_class in {"sqli", "sqli_read"}:
            if not any(
                c.get("response_sha256") != primary.get("response_sha256") or c.get("status") != primary.get("status")
                for c in control_receipts
            ):
                return json.dumps({"rejected": True, "reason": "SQLi requires differential between proof and control receipts"})

        elif canonical_class == "auth_bypass":
            # Strictly require primary proof receipt executed by 'anon' with substantive 2xx response.
            if effective_actor != "anon" or str(primary.get("actor") or "") != "anon":
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        f"auth_bypass requires primary proof receipt executed by 'anon' (got actor_alias={effective_actor!r}); "
                        "use 'bfla' when anon is denied (401/403) and a non-admin authenticated actor gets 200"
                    ),
                })
            if not (200 <= int(primary.get("status") or 0) < 300):
                return json.dumps({
                    "rejected": True,
                    "reason": f"auth_bypass requires a substantive 2xx response from 'anon' (got status {primary.get('status')})",
                })
            if not _is_genuine_anon_2xx(primary, actor_meta):
                return json.dumps({
                    "rejected": True,
                    "reason": "auth_bypass rejected: public HTML landing/login page, empty body, or non-anon actor identity header present",
                })
            if not any(c["actor"] != "anon" for c in control_receipts):
                return json.dumps({"rejected": True, "reason": "anon auth_bypass requires an authenticated baseline control receipt"})

        elif canonical_class in {"bfla", "bola", "tenant_isolation"}:
            if canonical_class == "bfla" and effective_actor == "anon":
                # If anon genuinely got 2xx on protected data, it is auth_bypass, not bfla.
                if _is_genuine_anon_2xx(primary, actor_meta):
                    canonical_class = "auth_bypass"
                else:
                    return json.dumps({
                        "rejected": True,
                        "reason": "bfla requires an authenticated non-admin proof receipt (not 'anon')",
                    })
            if effective_actor != "anon":
                if not any(
                    c["actor"] != effective_actor or _norm_path(c["url"]) != effective_norm_path or c["status"] != primary["status"]
                    for c in control_receipts
                ):
                    return json.dumps({"rejected": True, "reason": "access-control finding requires cross-actor or differential control receipt"})

        elif canonical_class == "mass_assignment":
            if not any(c.get("response_sha256") != primary.get("response_sha256") or c["method"] != primary["method"] or c["actor"] == effective_actor for c in control_receipts):
                return json.dumps({"rejected": True, "reason": "mass_assignment requires baseline control receipt"})

        elif canonical_class in {"race_condition", "business_logic"}:
            if canonical_class == "race_condition":
                distinct_success_rids = {
                    str(r.get("receipt_id") or "")
                    for r in compatible_proofs
                    if r.get("receipt_id") and 200 <= int(r.get("status") or 0) < 400
                }
                if len(distinct_success_rids) < 2:
                    return json.dumps({
                        "rejected": True,
                        "reason": "race_condition requires at least 2 distinct 2xx/3xx proof receipts (e.g. from concurrent_check)",
                    })
            if not any(
                c.get("status") != primary.get("status")
                or c.get("response_sha256") != primary.get("response_sha256")
                or str(c.get("method") or "").upper() != str(primary.get("method") or "").upper()
                or c.get("actor") != effective_actor
                for c in control_receipts
            ):
                return json.dumps({
                    "rejected": True,
                    "reason": f"{canonical_class} requires a differential sequential or state control receipt",
                })

        # Collect all valid proofs among proof_receipts (across actors) on the same route_template.
        valid_proof_records: list[tuple[dict[str, Any], str]] = [(primary, excerpt)]
        seen_rids = {primary["receipt_id"]}
        for r in proof_receipts:
            if r["receipt_id"] in seen_rids:
                continue
            if not _is_compatible_proof_receipt(r):
                continue
            ok, ex = self._receipt_contains_evidence(r, evidence_value)
            if not ok and original_evidence_value and original_evidence_value != evidence_value:
                ok, ex = self._receipt_contains_evidence(r, original_evidence_value)
            if (
                not ok
                and canonical_class in _PERSISTENT_VULN_CLASSES
                and str(r.get("method") or "").upper() in _MUTATING_WRITE_METHODS
                and _norm_path(r["url"]) == target_norm_path
                and 200 <= int(r.get("status") or 0) < 400
            ):
                ok = True
                ex = build_receipt_excerpt(r, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)
            if not ok and len(proof_receipts) > 1 and canonical_class not in {"open_redirect", "reflected_xss", "stored_xss"}:
                ok = True
                ex = build_receipt_excerpt(r, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)
            if ok:
                valid_proof_records.append((r, ex))
                seen_rids.add(r["receipt_id"])

        valid_receipts_only = [r for r, _ in valid_proof_records]

        # For bola / tenant_isolation: ensure proof receipt shows another owner's data rather than the caller's own record.
        inferred_bola_owner = ""
        if canonical_class in {"bola", "tenant_isolation"}:
            explicit_owner, explicit_tenant = _extract_record_owner_and_tenant(primary, actor_meta)
            inferred_owner = _infer_owner_actor(
                valid_receipts_only,
                control_receipts,
                receipt_store=self.receipts,
                route_template=route_template,
                evidence_value=evidence_value,
                actor_meta_map=actor_meta,
                target_path=effective_norm_path,
            )
            eff_owner = explicit_owner or inferred_owner
            inferred_bola_owner = eff_owner
            if eff_owner and all(str(r.get("actor") or "") == eff_owner for r in valid_receipts_only):
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        f"proof receipt shows {eff_owner!r}'s own record accessed by {eff_owner!r}; "
                        f"{canonical_class} requires a proof receipt executed by a non-owner peer/cross-tenant actor accessing another owner's data"
                    ),
                })
            if canonical_class == "tenant_isolation" and explicit_tenant:
                caller_tenant = str((actor_meta.get(effective_actor) or {}).get("tenant") or "").lower()
                if caller_tenant and caller_tenant == explicit_tenant:
                    if eff_owner and eff_owner != effective_actor:
                        canonical_class = "bola"
                    else:
                        return json.dumps({
                            "rejected": True,
                            "reason": (
                                f"proof receipt record belongs to caller's own tenant ({explicit_tenant!r}); "
                                "tenant_isolation requires accessing a record owned by a different tenant"
                            ),
                        })

        # Resolve auth_bypass <-> bfla bidirectionally and deterministically from observed receipts.
        if canonical_class == "bfla":
            anon_rec, anon_denied = _find_exact_route_anon_2xx(
                effective_norm_path,
                method,
                valid_receipts_only,
                control_receipts,
                actor_meta_map=actor_meta,
                receipt_store=self.receipts,
                evidence_value=evidence_value,
            )
            if anon_rec is not None and not anon_denied:
                canonical_class = "auth_bypass"
                anon_rid = str(anon_rec.get("receipt_id") or "")
                if anon_rid and anon_rid not in seen_rids:
                    anon_ex = build_receipt_excerpt(anon_rec, evidence_value, max_chars=MAX_PROOF_EXCERPT_CHARS)
                    valid_proof_records.append((anon_rec, anon_ex))
                    valid_receipts_only.append(anon_rec)
                    seen_rids.add(anon_rid)
                if anon_rid and anon_rid not in proof_ids and anon_rid not in control_ids:
                    proof_ids.append(anon_rid)
                if evidence_value and not _receipt_contains_value(anon_rec, evidence_value):
                    promoted_anon_ev, _ = _select_stronger_evidence_from_receipts(
                        "auth_bypass",
                        "",
                        [anon_rec],
                        control_receipts,
                    )
                    if promoted_anon_ev:
                        evidence_value = promoted_anon_ev
        elif canonical_class == "auth_bypass":
            resolved_cls = _resolve_route_auth_bypass_vs_bfla(
                route_template,
                valid_receipts_only,
                control_receipts,
                actor_meta_map=actor_meta,
                receipt_store=self.receipts,
                exact_path=effective_norm_path,
                method=method,
            )
            if resolved_cls == "bfla":
                return json.dumps({
                    "rejected": True,
                    "reason": (
                        f"route {route_template} denied 'anon' (401/403) in observed receipts while allowing authenticated non-admin access; "
                        "record this finding as 'bfla' with the non-admin authenticated actor"
                    ),
                })
            canonical_class = resolved_cls

        excerpt_by_rid = {r["receipt_id"]: ex for r, ex in valid_proof_records}

        # Deduplicate & merge by route_template for auth_bypass/bfla overlap or identical canonical_class.
        with self._findings_lock:
            merged_resp = self._try_merge_existing_finding_locked(
                canonical_class=canonical_class,
                route_template=route_template,
                raw_url=raw_url,
                method=method,
                effective_actor=effective_actor,
                effective_norm_path=effective_norm_path,
                evidence_value=evidence_value,
                proof_ids=proof_ids,
                control_ids=control_ids,
                actor_meta=actor_meta,
            )
            if merged_resp is not None:
                return json.dumps(merged_resp)

        best_primary, ordered_actors = select_primary_proof(
            canonical_class,
            valid_receipts_only,
            control_receipts,
            actor_meta_map=actor_meta,
            receipt_store=self.receipts,
            route_template=route_template,
            evidence_value=evidence_value,
        )
        best_actor = str(best_primary.get("actor") or actor_alias or "anon").strip() or "anon"

        if canonical_class == "bola" and self.oracle is None:
            bola_fp = check_bola_false_positive(
                primary_proof=best_primary,
                proof_receipts=valid_receipts_only,
                control_receipts=control_receipts,
                actor_meta_map=actor_meta,
                receipt_store=self.receipts,
                surface_tracker=self.surface_tracker,
                inferred_owner=inferred_bola_owner,
            )
            if bola_fp is not None:
                return json.dumps({"rejected": True, "reason": bola_fp[1]})

        self._step_claim_submitted = True
        oracle_verdict_str = "verified"
        clean_replay_rid = ""
        if self.oracle is not None:
            ep_node_id = f"ep:{route_template}"
            hyp_id = ""
            if self.bsag is not None:
                ep_n, ep_dv = self.bsag.ensure_endpoint(best_primary["url"] or raw_url, method=best_primary["method"])
                ep_node_id = ep_n.node_id
                self._step_delta_v += ep_dv
                hyp_node, h_dv, h_de = self.bsag.register_hypothesis(
                    endpoint_node_id=ep_node_id,
                    category=self.active_category or canonical_class,
                    vuln_class=canonical_class,
                    actor=best_actor,
                    summary=summary,
                    status="CLAIMED",
                    proof_receipt_ids=proof_ids,
                    control_receipt_ids=control_ids,
                    evidence_value=evidence_value,
                )
                hyp_id = hyp_node.node_id
                self._step_delta_v += h_dv
                self._step_delta_e += h_de
            verdict = self.oracle.verify(
                canonical_class=canonical_class,
                primary_proof=best_primary,
                proof_receipts=valid_receipts_only,
                control_receipts=control_receipts,
                evidence_value=evidence_value,
                actor_meta_map=actor_meta,
                surface_tracker=self.surface_tracker,
                inferred_owner=inferred_bola_owner,
                oob_server=self._oob_server,
                oob_hits=matching_oob_hits,
            )
            if self.bsag is not None and hyp_id:
                self.bsag.apply_oracle_verdict(
                    hypothesis_id=hyp_id,
                    endpoint_node_id=ep_node_id,
                    verdict=verdict.verdict,
                    reason=verdict.reason,
                    deception_detected=verdict.deception_detected,
                )
            if self.telemetry is not None:
                self.telemetry.emit(
                    "oracle_verdict",
                    worker_id=self.active_worker_id,
                    hypothesis_id=hyp_id,
                    node_id=ep_node_id,
                    class_type=canonical_class,
                    verdict=verdict.verdict,
                    deception_detected=verdict.deception_detected,
                    mode=verdict.mode,
                    stages=verdict.stages,
                    clean_replay_receipt_id=verdict.clean_replay_receipt_id,
                )
            if not verdict.verified:
                return json.dumps({
                    "rejected": True,
                    "oracle_verdict": verdict.verdict,
                    "deception_detected": verdict.deception_detected,
                    "reason": verdict.reason,
                    "stages": verdict.stages,
                })
            oracle_verdict_str = verdict.verdict
            clean_replay_rid = verdict.clean_replay_receipt_id

        best_evidence = compose_finding_evidence(
            best_primary,
            valid_receipts_only,
            control_receipts,
            evidence_value,
            max_proof_chars=MAX_PROOF_EXCERPT_CHARS,
            max_control_chars=MAX_CONTROL_EXCERPT_CHARS,
        )
        if matching_oob_hits:
            hit0 = matching_oob_hits[0]
            oob_note = (
                f"---[oob_callback:token={hit0.get('token')} hits={len(matching_oob_hits)}]---\n"
                f"{hit0.get('method')} {hit0.get('path')} query={hit0.get('query') or ''} "
                f"remote={hit0.get('remote_addr')} body={hit0.get('body_preview') or ''}"
            )
            best_evidence = f"{best_evidence}\n{oob_note}" if best_evidence else oob_note
        resolved_url, clean_path, _ = self.http.resolve_in_scope(best_primary["url"] or raw_url)
        with self._findings_lock:
            merged_resp = self._try_merge_existing_finding_locked(
                canonical_class=canonical_class,
                route_template=route_template,
                raw_url=raw_url,
                method=method,
                effective_actor=effective_actor,
                effective_norm_path=effective_norm_path,
                evidence_value=evidence_value,
                proof_ids=proof_ids,
                control_ids=control_ids,
                actor_meta=actor_meta,
            )
            if merged_resp is not None:
                return json.dumps(merged_resp)

            finding_id = f"F-{len(self.findings) + 1:03d}"
            finding = {
                "finding_id": finding_id,
                "title": title,
                "class_type": canonical_class,
                "route_template": route_template,
                "method": best_primary["method"],
                "url": resolved_url,
                "path": clean_path,
                "actor": best_actor,
                "actor_alias": best_actor,
                "observed_status": best_primary["status"],
                "status": "verified",
                "oracle_verdict": oracle_verdict_str,
                "clean_replay_receipt_id": clean_replay_rid,
                "severity": severity if severity in {"critical", "high", "medium", "low"} else "high",
                "evidence_value": evidence_value,
                "marker": evidence_value,
                "evidence": best_evidence or excerpt_by_rid.get(best_primary["receipt_id"], excerpt),
                "summary": summary,
                "proof_receipt_ids": proof_ids,
                "control_receipt_ids": control_ids,
                "supporting_actors": ordered_actors,
                "evidence_excerpts": [
                    {
                        "receipt_id": r["receipt_id"],
                        "actor": r["actor"],
                        "method": r["method"],
                        "url": r["url"],
                        "status": r["status"],
                        "excerpt": ex[:MAX_PROOF_EXCERPT_CHARS],
                    }
                    for r, ex in valid_proof_records
                ],
                "control_excerpts": [
                    {
                        "receipt_id": c["receipt_id"],
                        "actor": c["actor"],
                        "method": c["method"],
                        "url": c["url"],
                        "status": c["status"],
                        "excerpt": build_receipt_excerpt(c, "", max_chars=MAX_CONTROL_EXCERPT_CHARS),
                    }
                    for c in control_receipts
                ],
            }
            self.findings.append(finding)
            self._save_findings()
            total_findings = len(self.findings)
        return json.dumps({
            "accepted": True,
            "finding_id": finding_id,
            "class_type": canonical_class,
            "primary_actor": best_actor,
            "total_findings": total_findings,
        })

    def _tool_finish(self, args: dict[str, Any]) -> str:
        http_rem = self.http.budget.limit - self.http.budget.used
        rem_ratio = http_rem / max(1, self.http.budget.limit)
        if (
            self.coverage_gate_enabled
            and rem_ratio > 0.30
            and self.finish_rejections < self.max_finish_rejections
            and self.surface_tracker.has_high_value_frontier()
        ):
            self.finish_rejections += 1
            frontier = self.surface_tracker.high_value_frontier()
            return json.dumps({
                "finished": False,
                "rejected": True,
                "nudge_count": self.finish_rejections,
                "max_nudges": self.max_finish_rejections,
                "http_budget_remaining": http_rem,
                "http_budget_limit": self.http.budget.limit,
                "http_budget_remaining_pct": round(rem_ratio * 100, 1),
                "reason": (
                    f"Premature finish rejected ({self.finish_rejections}/{self.max_finish_rejections}): "
                    f"{round(rem_ratio * 100, 1)}% HTTP budget remaining ({http_rem}/{self.http.budget.limit}) "
                    "and high-value attack-surface frontier items remain untested. "
                    "Test the remaining_frontier items before calling finish."
                ),
                "remaining_frontier": frontier,
            })
        elif (
            self.discovery_finish_gate
            and rem_ratio > 0.20
            and self.finish_rejections < self.max_finish_rejections
        ):
            non_anon_actors = [a for a in self.surface_tracker.actors if a != "anon"]
            if self._auth_barrier_or_write_seen and (len(non_anon_actors) == 0 or self._non_anon_2xx_reads == 0):
                self.finish_rejections += 1
                return json.dumps({
                    "finished": False,
                    "rejected": True,
                    "nudge_count": self.finish_rejections,
                    "max_nudges": self.max_finish_rejections,
                    "http_budget_remaining": http_rem,
                    "http_budget_limit": self.http.budget.limit,
                    "http_budget_remaining_pct": round(rem_ratio * 100, 1),
                    "reason": (
                        f"Premature finish rejected ({self.finish_rejections}/{self.max_finish_rejections}): "
                        f"{round(rem_ratio * 100, 1)}% HTTP budget remaining ({http_rem}/{self.http.budget.limit}). "
                        "Auth barriers, redirects, or write/form endpoints were observed without an authenticated "
                        "post-auth GET 2xx crawl yet; register/sign in an actor via "
                        "http_request(method='POST', ..., save_session_as=...) and fetch post-auth pages before calling finish."
                    ),
                })

        self.finished = True
        self.finish_summary = str(args.get("summary") or "").strip()
        raw_untested = args.get("untested_areas")
        self.untested_areas = [str(x) for x in raw_untested] if isinstance(raw_untested, list) else []
        with self._findings_lock:
            total_findings = len(self.findings)
        return json.dumps({
            "finished": True,
            "total_findings": total_findings,
            "untested_areas": self.untested_areas,
        })
