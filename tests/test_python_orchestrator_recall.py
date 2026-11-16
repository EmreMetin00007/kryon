"""Start-URL-only end-to-end recall & orchestration acceptance tests.

Every test uses real local loopback HTTP servers, real HostToolExecutor /
LocalMCPExecutor MCP subprocesses (Hunter, Validator, Kali-tools), real HTTP
wire accounting, and real signed evidence/closure verification.

Scripted providers receive ONLY the publicly projected runtime context from
PythonBroker.project_runtime_context() / PythonSolver.context(), and preflight
explicitly configures E6 ceilings: 250 HTTP requests, 150,000 tokens, 900s.
"""
from __future__ import annotations

import hashlib
import html as html_lib
import json
import secrets
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

import jinja2
import pytest

import full_agent_holdout as holdout
import full_agent_launcher as launcher
import full_agent_preflight as preflight
from full_agent_budget import provider_json
from full_agent_provider import dump
from full_agent_python_broker import PHASE_CALL_LIMITS, READ_TOOL, SUMMARY_TOOL
from full_agent_python_solver import PythonSolver
from test_http_chromium_acceptance import evidence as acceptance_evidence

pytestmark = pytest.mark.integration

E6_HTTP_BUDGET = 250
E6_TOKEN_BUDGET = 150_000
E6_SECONDS_BUDGET = 900
HOST_API_KEY = "host-only-recall-key"


@pytest.fixture
def recall_baseline(acceptance_evidence):
    junit, directory, _ = acceptance_evidence
    for path in directory.glob("*/automatic-campaign-controls.json"):
        row = json.loads(path.read_text())
        row["lab_version"] = "blind-lab/3"
        row["score"]["proven"] = 8
        path.write_text(json.dumps(row))
    assessed = preflight.assess_results(junit, directory)
    (directory.parent / "acceptance.json").write_text(
        json.dumps({"status": "passed", "pytest_exit_code": 0, **assessed})
    )
    return directory.parent


def _assert_public_projection_only(body: dict[str, Any]) -> dict[str, Any]:
    """Assert the provider HTTP payload contains only public projected context."""
    assert body["stream"] is False
    assert len(body["messages"]) == 3
    assert all(row["role"] != "tool" for row in body["messages"])
    serialized = json.dumps(body)
    assert HOST_API_KEY not in serialized
    for hidden_marker in (
        "missing-owner-check",
        "negative_behavior",
        "lab_version",
        "expected_counts",
    ):
        assert hidden_marker not in serialized
    names = {tool["function"]["name"] for tool in body["tools"]}
    assert SUMMARY_TOOL in names
    assert not names & {"bash", "write", "edit", "task"}
    return json.loads(body["messages"][1]["content"])


def _run_e6_loopback_campaign(
    tmp_path: Path,
    baseline_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    decide,
    *,
    seed: int = 20261116,
    holdout_family: str = "",
    holdout_seed: int | None = None,
    target_factory=None,
    timeout_seconds: int | None = None,
    tag: str = "run",
) -> dict[str, Any]:
    """Run preflight + launch_seed under explicit 250/150000/900 E6 ceilings."""
    contexts_seen: list[dict[str, Any]] = []
    decisions: list[str] = []
    captured_solvers: list[PythonSolver] = []
    state: dict[str, Any] = {"turns": 0}

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            context = _assert_public_projection_only(body)
            spec = context["task_spec"]
            decisions.append(spec["id"])
            contexts_seen.append(context)
            state["turns"] += 1
            name, args = decide(context, body, state)
            emitted = [
                {
                    "id": f"call-{len(decisions)}",
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args)},
                }
            ]
            raw = provider_json(
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": emitted,
                            },
                            "finish_reason": "tool_calls",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 120,
                        "completion_tokens": 80,
                        "total_tokens": 200,
                    },
                }
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    provider_server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    provider_thread = threading.Thread(target=provider_server.serve_forever, daemon=True)
    provider_thread.start()

    work_root = tmp_path.parent / f"{tmp_path.name}-{tag}-e6-work"
    work_root.mkdir(parents=True, exist_ok=True)
    config = work_root / "provider.json"
    dump(
        config,
        {
            "schema": "cco-llm/1",
            "model": "owned/model",
            "providers": {
                "owned": {
                    "models": ["model"],
                    "api_key_env": "CCO_BENCHMARK_API_KEY",
                    "base_url": f"http://127.0.0.1:{provider_server.server_port}/v1",
                }
            },
        },
    )
    preflight_dir = work_root / "preflights"
    runs_dir = work_root / "runs"
    runs_dir.mkdir()

    try:
        argv = [
            "--baseline",
            str(baseline_dir),
            "--provider-config",
            str(config),
            "--http-budget",
            str(E6_HTTP_BUDGET),
            "--token-budget",
            str(E6_TOKEN_BUDGET),
            "--seconds-budget",
            str(E6_SECONDS_BUDGET),
            "--solver-mode",
            "python_loop",
            "--output-dir",
            str(preflight_dir),
        ]
        if holdout_family:
            argv.extend(["--holdout-family", holdout_family, "--holdout-seed", str(holdout_seed)])
        assert preflight.main(argv) == 0
        preflight_path = next(preflight_dir.glob("*/preflight.json"))
        prepared = launcher.prepared_run(preflight_path)
        limits = prepared["contract"]["limits"]
        assert limits["http_requests_per_seed"] == E6_HTTP_BUDGET
        assert limits["llm_tokens_per_seed"] == E6_TOKEN_BUDGET
        assert limits["seconds_per_seed"] == E6_SECONDS_BUDGET

        original_init = PythonSolver.__init__

        def capture_solver(self, broker, **kwargs):
            original_init(self, broker, **kwargs)
            captured_solvers.append(self)

        monkeypatch.setattr(PythonSolver, "__init__", capture_solver)
        if target_factory is not None:
            monkeypatch.setattr("lab.blind_lab.serve", target_factory)

        provider = launcher.provider_settings(config, prepared["contract"]["models"])
        launch_seed_val = holdout_seed if holdout_seed is not None else prepared["contract"]["baseline"]["seeds"][0]
        manifest_path, manifest = launcher.launch_seed(
            prepared,
            seed=launch_seed_val,
            output=runs_dir,
            provider=provider,
            api_key=HOST_API_KEY,
            bwrap=None,
            opencode=None,
            timeout_seconds=timeout_seconds,
        )
        return {
            "manifest_path": manifest_path,
            "manifest": manifest,
            "directory": manifest_path.parent,
            "private": manifest_path.parent / "private",
            "workdir": manifest_path.parent / "solver",
            "prepared": prepared,
            "preflight_path": preflight_path,
            "config": config,
            "runs_dir": runs_dir,
            "contexts": contexts_seen,
            "decisions": decisions,
            "solvers": captured_solvers,
            "state": state,
        }
    finally:
        provider_server.shutdown()
        provider_thread.join(timeout=5)
        provider_server.server_close()


def _done_summary_args(spec: dict[str, Any], *, status: str = "done") -> dict[str, Any]:
    return {
        "status": status,
        "next": "continue",
        "steps": [
            {"id": step["id"], "status": "done"}
            for step in spec["steps"]
            if not step.get("host_managed")
        ],
    }


def _serve_two_group_sqli_lookup_lab(seed: int, **_kwargs):
    """Loopback HTML `/` -> `/lookup/<hex>` -> `/lookup/<hex>/<uuid>?id=1` (4 pos, 4 neg)."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.set_authorizer(
        lambda action, *_: sqlite3.SQLITE_OK
        if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
        else sqlite3.SQLITE_DENY
    )
    data = (1, "alpha-" + "a" * 120, "inv", 2, "beta-" + "b" * 120, "inv", 3, "gamma-" + "c" * 120, "inv")
    relation = "WITH inventory(id,memo,category) AS (VALUES (?,?,?),(?,?,?),(?,?,?)) "
    routes: dict[str, dict[str, str]] = {}
    catalogs: dict[str, list[str]] = {}
    truth: list[dict[str, Any]] = []
    for g_idx, context in enumerate(("numeric", "single-quoted")):
        catalog = f"/lookup/{g_idx:02x}cafe"
        catalogs[catalog] = []
        for idx, mode in enumerate(("concatenated", "parameterized", "concatenated", "validated")):
            path = f"{catalog}/{seed}-{g_idx}-{idx}"
            routes[path] = {"context": context, "mode": mode}
            catalogs[catalog].append(path)
            truth.append(
                {
                    "case": f"{g_idx}-{idx}",
                    "family": "readonly-sql-injection",
                    "path": path,
                    "class": "sql_injection",
                    "param": "id",
                    "baseline": "1",
                    "context": context,
                    "expected": "positive" if mode == "concatenated" else "negative",
                    "negative_behavior": None if mode == "concatenated" else mode,
                }
            )
    lock = threading.Lock()
    state: dict[str, Any] = {
        "accounts": {"member-a": {"token": secrets.token_urlsafe(24), "role": "member"}},
        "requests": 0,
        "lock": lock,
        "db": db,
        "lab_version": "readonly-sqli/1",
        "truth": truth,
        "wire": [],
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, status: int, payload: Any, *, query: str | None = None, parameters=(), rows=None, error=None):
            raw = (
                payload.encode()
                if isinstance(payload, str)
                else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            )
            with lock:
                state["requests"] += 1
                state["wire"].append(
                    {
                        "sequence": state["requests"],
                        "method": self.command,
                        "path": urlsplit(self.path).path,
                        "request_path": self.path,
                        "status": status,
                        "response_length": len(raw),
                        "response_sha256": hashlib.sha256(raw).hexdigest(),
                        "response": payload,
                        "query": query,
                        "parameters": list(parameters),
                        "sql_rows": rows,
                        "sql_error": error,
                    }
                )
            self.send_response(status)
            self.send_header("Content-Type", "text/html" if isinstance(payload, str) else "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/" or parsed.path in catalogs:
                links = list(catalogs) if parsed.path == "/" else [route + "?id=1" for route in catalogs[parsed.path]]
                body = (
                    "<html><body>Inventory member-a "
                    + " ".join(f'<a href="{route}">Browse</a>' for route in links)
                    + "</body></html>"
                )
                return self._send(200, body)
            route = routes.get(parsed.path)
            if not route:
                return self._send(404, {"error": "missing"})
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if len(params) != 1 or params[0][0] != "id" or len(params[0][1]) > 256:
                return self._send(400, {"error": "invalid input"})
            value = params[0][1]
            mode, context = route["mode"], route["context"]
            if mode == "validated" and value not in {"1", "2", "3"}:
                return self._send(400, {"error": "invalid input"})
            if mode == "parameterized":
                query = relation + "SELECT id, memo, category FROM inventory WHERE id = CAST(? AS INTEGER)"
                bindings: tuple[Any, ...] = data + (value,)
            else:
                if context == "numeric":
                    query = relation + f"SELECT id, memo, category FROM inventory WHERE id = {value}"
                else:
                    query = relation + f"SELECT id, memo, category FROM inventory WHERE CAST(id AS TEXT) = '{value}'"
                bindings = data
            try:
                rows = db.execute(query, bindings).fetchall()
            except sqlite3.Error:
                return self._send(400, {"error": "query rejected"}, query=query, parameters=bindings, error="sqlite_error")
            return self._send(200, {"rows": rows}, query=query, parameters=bindings, rows=rows)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.blind_state = state
    return server


def _serve_api_314159_style_lab(_seed: int, **_kwargs):
    """314159-style JSON archive: anonymous `/` returns empty links; auth `/` returns actor records."""
    accounts = {
        "member-a": {"token": secrets.token_urlsafe(24), "role": "member"},
        "member-b": {"token": secrets.token_urlsafe(24), "role": "member"},
    }
    tokens = {acc["token"]: name for name, acc in accounts.items()}
    records: dict[str, dict[str, Any]] = {}
    truth: list[dict[str, Any]] = []
    for owner in ("member-a", "member-b"):
        for idx, mode in enumerate(("missing-owner-check", "missing-owner-check", "deny", "redact")):
            ident = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{owner}-{idx}"))
            path = f"/api/records/{ident}"
            body = {"id": ident, "owner_id": owner, "memo": f"secret-{ident}", "amount": 100 + idx}
            records[path] = {"owner": owner, "mode": mode, "body": body}
            truth.append(
                {
                    "case": ident,
                    "family": "readonly-api-access-control",
                    "path": path,
                    "class": "bola",
                    "owner": owner,
                    "marker": ident,
                    "denied_identities": [name for name in accounts if name != owner],
                    "expected": "positive" if mode == "missing-owner-check" else "negative",
                    "negative_behavior": None if mode == "missing-owner-check" else mode,
                }
            )
    lock = threading.Lock()
    state: dict[str, Any] = {
        "accounts": accounts,
        "requests": 0,
        "lock": lock,
        "lab_version": "readonly-api-access/1",
        "truth": truth,
        "wire": [],
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, status: int, payload: Any, actor: str | None, method: str):
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            with lock:
                state["requests"] += 1
                state["wire"].append(
                    {
                        "sequence": state["requests"],
                        "method": method,
                        "path": self.path,
                        "identity": actor or "anonymous",
                        "status": status,
                        "response_length": len(raw),
                        "response_sha256": hashlib.sha256(raw).hexdigest(),
                        "response": payload,
                    }
                )
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(raw)

        def do_GET(self):
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            actor = tokens.get(token)
            path = urlsplit(self.path).path
            if path == "/":
                payload: dict[str, Any] = {"service": "record archive", "links": []}
                if actor:
                    payload.update(
                        current_user={"id": actor},
                        records=[
                            {"id": rec["body"]["id"], "owner_id": actor, "href": route}
                            for route, rec in records.items()
                            if rec["owner"] == actor
                        ],
                    )
                return self._send(200, payload, actor, "GET")
            rec = records.get(path)
            if not rec:
                return self._send(404, {"error": "missing"}, actor, "GET")
            if not actor:
                return self._send(401, {"error": "unauthorized"}, actor, "GET")
            if actor == rec["owner"] or rec["mode"] == "missing-owner-check":
                return self._send(200, rec["body"], actor, "GET")
            if rec["mode"] == "redact":
                return self._send(200, {"access": "restricted", "record": None}, actor, "GET")
            return self._send(403, {"error": "forbidden"}, actor, "GET")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.blind_state = state
    return server


def _serve_multihop_html_json_lab(_seed: int, **_kwargs):
    """Multi-hop HTML -> HTML -> JSON pagination traversal starting strictly from `/`."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.set_authorizer(
        lambda action, *_: sqlite3.SQLITE_OK
        if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
        else sqlite3.SQLITE_DENY
    )
    data = (1, "alpha-" + "x" * 100, "item", 2, "beta-" + "y" * 100, "item")
    relation = "WITH items(id,memo,category) AS (VALUES (?,?,?),(?,?,?)) "
    lock = threading.Lock()
    state: dict[str, Any] = {
        "accounts": {},
        "requests": 0,
        "lock": lock,
        "db": db,
        "lab_version": "multihop-recall/1",
        "wire": [],
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, status: int, payload: Any, ctype: str = "application/json"):
            raw = (
                payload.encode()
                if isinstance(payload, str)
                else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            )
            with lock:
                state["requests"] += 1
                state["wire"].append(
                    {
                        "sequence": state["requests"],
                        "method": self.command,
                        "path": urlsplit(self.path).path,
                        "request_path": self.path,
                        "status": status,
                        "response_length": len(raw),
                        "response_sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if parsed.path == "/":
                # 10 benign info pages + /portal/catalog -> max_pages=12 visits /portal/catalog without exhausting /api/feed
                nav = "".join(f'<a href="/info/{i}">Info {i}</a>' for i in range(10))
                return self._send(
                    200,
                    f"<html><body>member-a Portal {nav}<a href='/portal/catalog'>Catalog</a></body></html>",
                    "text/html",
                )
            if parsed.path.startswith("/info/"):
                return self._send(200, "<html><body>Static info</body></html>", "text/html")
            if parsed.path == "/portal/catalog":
                return self._send(
                    200,
                    "<html><body><h2>API Catalog</h2><a href='/api/feed?page=1'>Feed Page 1</a></body></html>",
                    "text/html",
                )
            if parsed.path == "/api/feed":
                page = qs.get("page", "1")
                if page == "1":
                    return self._send(
                        200,
                        {
                            "items": [
                                {"href": "/items/sqli-unsafe?id=1"},
                                {"href": "/items/sqli-safe?id=1"},
                            ],
                            "next": "/api/feed?page=2",
                        },
                    )
                if page == "2":
                    return self._send(
                        200,
                        {
                            "items": [
                                {"href": "/items/ssti-unsafe?name=World"},
                                {"href": "/items/ssti-safe?name=World"},
                            ],
                            "_links": {"next": {"href": "/api/feed?page=3"}},
                        },
                    )
                return self._send(200, {"items": [], "next": None})
            if parsed.path in {"/items/sqli-unsafe", "/items/sqli-safe"}:
                val = qs.get("id", "1")
                if parsed.path.endswith("-safe"):
                    query = relation + "SELECT id, memo, category FROM items WHERE id = CAST(? AS INTEGER)"
                    bindings: tuple[Any, ...] = data + (val,)
                else:
                    query = relation + f"SELECT id, memo, category FROM items WHERE id = {val}"
                    bindings = data
                try:
                    rows = db.execute(query, bindings).fetchall()
                except sqlite3.Error:
                    return self._send(400, {"error": "query rejected"})
                return self._send(200, {"rows": rows})
            if parsed.path in {"/items/ssti-unsafe", "/items/ssti-safe"}:
                val = qs.get("name", "World")
                if parsed.path.endswith("-safe"):
                    return self._send(200, {"result": "Hello " + html_lib.escape(val)})
                try:
                    rendered = jinja2.Environment(autoescape=False).from_string(val).render()
                    return self._send(200, {"result": rendered})
                except jinja2.TemplateError:
                    return self._send(400, {"error": "template syntax error"})
            return self._send(404, {"error": "missing"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.blind_state = state
    return server


def _serve_16_endpoint_32_leaf_lab(_seed: int, **_kwargs):
    """16 endpoints across 4 groups (SQLi + SSTI) -> 32 scheduled parameter leaves (8 pos, 24 neg)."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.set_authorizer(
        lambda action, *_: sqlite3.SQLITE_OK
        if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
        else sqlite3.SQLITE_DENY
    )
    data = ("alpha", "memo-alpha-" + "a" * 80, "p1", "beta", "memo-beta-" + "b" * 80, "p2")
    relation = "WITH records(name,memo,pad) AS (VALUES (?,?,?),(?,?,?)) "
    lock = threading.Lock()
    state: dict[str, Any] = {
        "accounts": {"member-a": {"token": secrets.token_urlsafe(24), "role": "member"}},
        "requests": 0,
        "lock": lock,
        "db": db,
        "lab_version": "grouped-32-leaf/1",
        "wire": [],
    }
    groups = ("/search/g0", "/search/g1", "/render/g0", "/render/g1")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, status: int, payload: Any, ctype: str = "text/plain"):
            raw = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
            with lock:
                state["requests"] += 1
                state["wire"].append(
                    {
                        "sequence": state["requests"],
                        "method": self.command,
                        "path": urlsplit(self.path).path,
                        "status": status,
                    }
                )
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if parsed.path == "/":
                links = "".join(f'<a href="{g}">{g}</a>' for g in groups)
                return self._send(200, f"<html><body>member-a {links}</body></html>", "text/html")
            if parsed.path in groups:
                term_val = "alpha" if parsed.path.startswith("/search/") else "hello"
                links = "".join(
                    f'<a href="{parsed.path}/{idx}-{"unsafe" if idx % 2 == 0 else "safe"}?q={term_val}">Item {idx}</a>'
                    for idx in range(4)
                )
                return self._send(200, f"<html><body>{links}</body></html>", "text/html")
            value = qs.get("q", "")
            if parsed.path.startswith("/search/"):
                if "unsafe" in parsed.path:
                    query = relation + f"SELECT name, memo FROM records WHERE name = '{value}'"
                    bindings: tuple[Any, ...] = data
                else:
                    query = relation + "SELECT name, memo FROM records WHERE name = ?"
                    bindings = data + (value,)
                try:
                    rows = db.execute(query, bindings).fetchall()
                except sqlite3.Error:
                    return self._send(400, "query rejected")
                return self._send(200, json.dumps(rows))
            if parsed.path.startswith("/render/"):
                if "unsafe" in parsed.path:
                    try:
                        return self._send(200, jinja2.Environment(autoescape=False).from_string(value).render())
                    except jinja2.TemplateError:
                        return self._send(400, "template rejected")
                return self._send(200, "literal: " + html_lib.escape(value))
            return self._send(404, "missing")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.blind_state = state
    return server


def test_recall_a_forgetful_read_artifact_stall_hydrates_enum_and_preserves_reserves(
    tmp_path, recall_baseline, monkeypatch
):
    """Scenario (a): read_artifact(offset=0) stalls on HTML `/lookup/...` -> continuation + 0 FP."""
    def decide(context, _body, state):
        spec = context["task_spec"]
        results = context["recent_results"]
        if spec["phase"] == "recon":
            if not results:
                return "kali-tools_curl_request", {"url": spec["target"], "follow_redirects": False}
            return SUMMARY_TOOL, _done_summary_args(spec)
        if spec["phase"] == "enum":
            stall_count = state.setdefault("enum_stalls", 0)
            if stall_count < 4:
                state["enum_stalls"] = stall_count + 1
                assert context["discovery_frontier"]["counts"]["pending"] >= 2
                prev_path = context["previous_summary"]["content_ref"]["path"]
                return READ_TOOL, {"path": prev_path, "offset": 0, "limit": 3000}
            assert context["discovery_frontier"]["counts"]["completed"] >= 2
            return SUMMARY_TOOL, _done_summary_args(spec)
        if spec["phase"] == "access":
            return SUMMARY_TOOL, _done_summary_args(spec, status="partial")
        return SUMMARY_TOOL, _done_summary_args(spec, status="partial")

    run = _run_e6_loopback_campaign(
        tmp_path,
        recall_baseline,
        monkeypatch,
        decide,
        target_factory=_serve_two_group_sqli_lookup_lab,
    )
    manifest = run["manifest"]
    assert manifest["status"] == "python_finished_verified", json.dumps(manifest)
    assert manifest["closure_verified"] is True
    assert manifest["budget"]["used"]["http"] <= E6_HTTP_BUDGET
    assert manifest["budget"]["used"]["tokens"] <= E6_TOKEN_BUDGET

    loop_events = json.loads((run["private"] / "python-loop-events.json").read_bytes())
    assert any(
        ev["spec_id"] == "enum-2" and ev["reason_code"] == "archive_read_no_progress"
        for ev in loop_events
    )
    runtime_policy = json.loads((run["private"] / "runtime-policy.json").read_bytes())
    assert runtime_policy["tool_calls"]["enum-2"] <= PHASE_CALL_LIMITS["enum"]
    assert not runtime_policy["host_continuing"]

    enum_summary = json.loads((run["workdir"] / "summaries/enum-2.json").read_bytes())
    assert len(enum_summary["surface"]["routes"]) >= 11

    access_summary = json.loads((run["workdir"] / "summaries/access-3.json").read_bytes())
    outcomes = access_summary["validation_outcomes"]
    sqli_outcomes = [row for row in outcomes if row["vector"] == "injection-sqli"]
    assert len(sqli_outcomes) == 8
    assert sum(row["verdict"] == "CONFIRMED" for row in sqli_outcomes) == 4
    assert sum(row["verdict"] == "UNCONFIRMED" for row in sqli_outcomes) == 4
    assert sum(row["verdict"] == "CONFIRMED" for row in outcomes) == 4
    assert access_summary["leaf_validation_funnel"]["accepted"] >= 8
    assert (run["workdir"] / "handoff-access.json").is_file()


def test_recall_b_early_enum_summary_and_auth_json_entry_314159_style(
    tmp_path, recall_baseline, monkeypatch
):
    """Scenario (b): immediate early enum summary on 314159-style empty anon `/` bootstraps IDOR."""
    wire_capture: list[dict[str, Any]] = []
    truth_capture: list[dict[str, Any]] = []

    def serve_and_capture(seed, **kwargs):
        srv = _serve_api_314159_style_lab(seed, **kwargs)
        wire_capture.append(srv.blind_state["wire"])
        truth_capture.append(srv.blind_state["truth"])
        return srv

    def decide(context, _body, _state):
        spec = context["task_spec"]
        results = context["recent_results"]
        if spec["phase"] == "recon":
            if not results:
                return "kali-tools_curl_request", {"url": spec["target"], "follow_redirects": False}
            return SUMMARY_TOOL, _done_summary_args(spec)
        if spec["phase"] == "enum":
            return SUMMARY_TOOL, _done_summary_args(spec)
        if spec["phase"] == "access":
            return SUMMARY_TOOL, _done_summary_args(spec, status="partial")
        return SUMMARY_TOOL, _done_summary_args(spec, status="partial")

    run = _run_e6_loopback_campaign(
        tmp_path,
        recall_baseline,
        monkeypatch,
        decide,
        seed=314159,
        target_factory=serve_and_capture,
    )
    manifest = run["manifest"]
    assert manifest["status"] == "python_finished_verified", json.dumps(manifest)
    assert manifest["closure_verified"] is True
    assert manifest["budget"]["used"]["http"] <= E6_HTTP_BUDGET
    assert manifest["budget"]["used"]["tokens"] <= E6_TOKEN_BUDGET

    enum_summary = json.loads((run["workdir"] / "summaries/enum-2.json").read_bytes())
    assert enum_summary["surface"]["routes"] == [manifest["target"]]

    tool_results = json.loads((run["private"] / "python-tool-results.json").read_bytes())
    idor_loops = [
        row for row in tool_results
        if row["spec_id"] == "access-3" and row["tool"] == "hunter_run_web_loop"
    ]
    assert len(idor_loops) == 1
    assert idor_loops[0]["arguments"]["blind_discovery"] is True
    assert idor_loops[0]["arguments"]["target"] == manifest["target"]

    # Score with production holdout evaluator against real server wire + signed artifacts.
    from cco_validator_core.evidence import artifact_is_valid

    signed = json.loads((run["workdir"] / "attempt-ledger.json").read_bytes())
    run_ids = json.loads((run["workdir"] / "access/live-result.json").read_bytes())["run_ids"]
    artifacts = []
    for row in signed["payload"]["records"]:
        if row["verdict"] in {"CONFIRMED", "UNCONFIRMED"}:
            art_path = run["workdir"] / row["artifact"]
            artifacts.append(
                {
                    "path": str(art_path),
                    "sha256": hashlib.sha256(art_path.read_bytes()).hexdigest(),
                    "record": json.loads(art_path.read_bytes()),
                }
            )
    with launcher.host_environment(run["private"] / "state", run["workdir"], run["directory"] / "runtime"):
        metrics = holdout.evaluate(
            truth_capture[0],
            wire_capture[0],
            artifacts,
            target=manifest["target"],
            run_id=run_ids,
            verify_artifact=artifact_is_valid,
        )
    assert metrics["recall"] == {"numerator": 4, "denominator": 4, "value": 1.0}
    assert metrics["negative_coverage"] == {"numerator": 4, "denominator": 4, "value": 1.0}
    assert metrics["false_positives"] == {"numerator": 0, "denominator": 4, "value": 0.0}
    assert not metrics["rejected_evidence"] and not metrics["unexpected_artifacts"]


def test_recall_c_multihop_html_and_json_pagination_traversal_from_root(
    tmp_path, recall_baseline, monkeypatch
):
    """Scenario (c): start strictly at `/` and traverse HTML -> HTML -> JSON pagination -> endpoints."""
    def decide(context, _body, _state):
        spec = context["task_spec"]
        results = context["recent_results"]
        if spec["phase"] == "recon":
            if not results:
                return "kali-tools_curl_request", {"url": spec["target"], "follow_redirects": False}
            return SUMMARY_TOOL, _done_summary_args(spec)
        if spec["phase"] == "enum":
            return SUMMARY_TOOL, _done_summary_args(spec)
        if spec["phase"] == "access":
            return SUMMARY_TOOL, _done_summary_args(spec, status="partial")
        return SUMMARY_TOOL, _done_summary_args(spec, status="partial")

    run = _run_e6_loopback_campaign(
        tmp_path,
        recall_baseline,
        monkeypatch,
        decide,
        target_factory=_serve_multihop_html_json_lab,
    )
    manifest = run["manifest"]
    assert manifest["status"] == "python_finished_verified", json.dumps(manifest)
    assert manifest["closure_verified"] is True
    assert manifest["budget"]["used"]["http"] <= E6_HTTP_BUDGET
    assert manifest["budget"]["used"]["tokens"] <= E6_TOKEN_BUDGET

    enum_summary = json.loads((run["workdir"] / "summaries/enum-2.json").read_bytes())
    discovered_routes = set(enum_summary["surface"]["routes"])
    base = manifest["target"]
    for expected_suffix in (
        "portal/catalog",
        "api/feed?page=1",
        "api/feed?page=2",
        "api/feed?page=3",
        "items/sqli-unsafe?id=1",
        "items/sqli-safe?id=1",
        "items/ssti-unsafe?name=World",
        "items/ssti-safe?name=World",
    ):
        assert urljoin(base, expected_suffix) in discovered_routes

    access_summary = json.loads((run["workdir"] / "summaries/access-3.json").read_bytes())
    outcomes = access_summary["validation_outcomes"]
    by_path = {(urlsplit(row["url"]).path, row["vector"]): row["verdict"] for row in outcomes}
    assert by_path[("/items/sqli-unsafe", "injection-sqli")] == "CONFIRMED"
    assert by_path[("/items/sqli-safe", "injection-sqli")] == "UNCONFIRMED"
    assert by_path[("/items/ssti-unsafe", "injection-ssti")] == "CONFIRMED"
    assert by_path[("/items/ssti-safe", "injection-ssti")] == "UNCONFIRMED"
    # Zero false positives on safe controls and cross-family checks.
    assert sum(row["verdict"] == "CONFIRMED" for row in outcomes) == 2


def test_recall_d_16_endpoint_32_leaf_within_e6_ceilings_and_zero_fp(
    tmp_path, recall_baseline, monkeypatch
):
    """Scenario (d): 16 endpoints / 32 leaves positive + negative controls under 250/150000/900."""
    from contextlib import contextmanager
    import os

    orig_host_env = launcher.host_environment

    @contextmanager
    def _multi_profile_host_env(*args, **kwargs):
        with orig_host_env(*args, **kwargs):
            # Finite-corpus repeat threshold matching tests/test_full_agent_integration.py:
            # running both SQLi and SSTI profiles on the same 16 endpoints sends ~15 GETs/path.
            os.environ["CCO_STUCK_THRESHOLD"] = "32"
            yield

    monkeypatch.setattr(launcher, "host_environment", _multi_profile_host_env)

    def decide(context, _body, _state):
        spec = context["task_spec"]
        results = context["recent_results"]
        if spec["phase"] == "recon":
            if not results:
                return "kali-tools_curl_request", {"url": spec["target"], "follow_redirects": False}
            return SUMMARY_TOOL, _done_summary_args(spec)
        if spec["phase"] == "enum":
            return SUMMARY_TOOL, _done_summary_args(spec)
        if spec["phase"] == "access":
            return SUMMARY_TOOL, _done_summary_args(spec, status="partial")
        return SUMMARY_TOOL, _done_summary_args(spec, status="partial")

    run = _run_e6_loopback_campaign(
        tmp_path,
        recall_baseline,
        monkeypatch,
        decide,
        target_factory=_serve_16_endpoint_32_leaf_lab,
    )
    manifest = run["manifest"]
    assert manifest["status"] == "python_finished_verified", json.dumps(manifest)
    assert manifest["closure_verified"] is True
    assert manifest["budget"]["used"]["http"] <= E6_HTTP_BUDGET
    assert manifest["budget"]["used"]["tokens"] <= E6_TOKEN_BUDGET
    assert manifest["wall_clock_seconds"] <= E6_SECONDS_BUDGET

    access_summary = json.loads((run["workdir"] / "summaries/access-3.json").read_bytes())
    assert access_summary["validation_funnel"]["observed"] == 32
    assert access_summary["validation_funnel"]["evidence_accepted"] == 32
    assert access_summary["leaf_validation_funnel"]["observed"] == 32
    assert access_summary["leaf_validation_funnel"]["accepted"] == 32
    assert access_summary["leaf_validation_funnel"]["invalid_evidence"] == 0

    outcomes = access_summary["validation_outcomes"]
    assert len(outcomes) == 32
    confirmed = [row for row in outcomes if row["verdict"] == "CONFIRMED"]
    unconfirmed = [row for row in outcomes if row["verdict"] == "UNCONFIRMED"]
    assert len(confirmed) == 8
    assert len(unconfirmed) == 24
    # Every confirmed finding must be a true positive `-unsafe` route in its matching vector.
    for row in confirmed:
        path = urlsplit(row["url"]).path
        assert "unsafe" in path
        if row["vector"] == "injection-sqli":
            assert path.startswith("/search/")
        elif row["vector"] == "injection-ssti":
            assert path.startswith("/render/")
        else:
            pytest.fail(f"unexpected confirmed vector: {row}")
    assert not any(
        gap_row["reason_code"] == "invalid_or_missing_signed_evidence"
        for gap_row in access_summary["coverage_gaps"]
    )


def test_recall_e_partial_interrupted_dispatch_no_replay_and_snapshot_tamper_closure(
    tmp_path, recall_baseline, monkeypatch
):
    """Scenario (e): interrupted dispatch -> NOT TESTED + no replay on resume + tamper/closure gates."""
    wire_capture: list[list[dict[str, Any]]] = []

    def serve_and_capture(seed, **kwargs):
        srv = _serve_two_group_sqli_lookup_lab(seed, **kwargs)
        wire_capture.append(srv.blind_state["wire"])
        return srv

    from full_agent_budget import BudgetError

    # 1. Run until access-3 completes 1st slice and starts 2nd slice, then interrupt via BudgetError.
    from full_agent_python_broker import PythonBroker

    original_invoke = PythonBroker.invoke
    access_slices_started = {"count": 0}

    def interrupt_second_slice(self, tool, args):
        if self.tasks.active_spec and self.tasks.active_spec.id == "access-3" and tool == "hunter_run_web_loop":
            access_slices_started["count"] += 1
            if access_slices_started["count"] == 2:
                raise BudgetError("wall_clock_budget_exhausted")
        return original_invoke(self, tool, args)

    def decide_interrupt(context, _body, _state):
        spec = context["task_spec"]
        results = context["recent_results"]
        if spec["phase"] == "recon":
            if not results:
                return "kali-tools_curl_request", {"url": spec["target"], "follow_redirects": False}
            return SUMMARY_TOOL, _done_summary_args(spec)
        if spec["phase"] == "enum":
            return SUMMARY_TOOL, _done_summary_args(spec)
        if spec["phase"] == "access":
            return SUMMARY_TOOL, _done_summary_args(spec, status="partial")
        return SUMMARY_TOOL, _done_summary_args(spec, status="partial")

    provider_decisions_resume: list[str] = []

    class PersistentProvider(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            context = _assert_public_projection_only(body)
            spec = context["task_spec"]
            provider_decisions_resume.append(spec["id"])
            name, args = decide_interrupt(context, body, {})
            raw = provider_json(
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": f"call-{len(provider_decisions_resume)}",
                                        "type": "function",
                                        "function": {"name": name, "arguments": json.dumps(args)},
                                    }
                                ],
                            },
                            "finish_reason": "tool_calls",
                        }
                    ],
                    "usage": {"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200},
                }
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    prov_srv = ThreadingHTTPServer(("127.0.0.1", 0), PersistentProvider)
    prov_thread = threading.Thread(target=prov_srv.serve_forever, daemon=True)
    prov_thread.start()
    work_root = tmp_path.parent / f"{tmp_path.name}-interrupted-e6-work"
    work_root.mkdir(parents=True, exist_ok=True)
    config = work_root / "provider.json"
    dump(
        config,
        {
            "schema": "cco-llm/1",
            "model": "owned/model",
            "providers": {
                "owned": {
                    "models": ["model"],
                    "api_key_env": "CCO_BENCHMARK_API_KEY",
                    "base_url": f"http://127.0.0.1:{prov_srv.server_port}/v1",
                }
            },
        },
    )
    preflight_dir = work_root / "preflights"
    runs_dir = work_root / "runs"
    runs_dir.mkdir()
    captured_resumed: list[PythonSolver] = []
    try:
        assert (
            preflight.main(
                [
                    "--baseline",
                    str(recall_baseline),
                    "--provider-config",
                    str(config),
                    "--http-budget",
                    str(E6_HTTP_BUDGET),
                    "--token-budget",
                    str(E6_TOKEN_BUDGET),
                    "--seconds-budget",
                    str(E6_SECONDS_BUDGET),
                    "--solver-mode",
                    "python_loop",
                    "--output-dir",
                    str(preflight_dir),
                ]
            )
            == 0
        )
        preflight_path = next(preflight_dir.glob("*/preflight.json"))
        prepared = launcher.prepared_run(preflight_path)
        provider = launcher.provider_settings(config, prepared["contract"]["models"])
        seed = prepared["contract"]["baseline"]["seeds"][0]

        with monkeypatch.context() as interruption:
            interruption.setattr("lab.blind_lab.serve", serve_and_capture)
            interruption.setattr(PythonBroker, "invoke", interrupt_second_slice)
            manifest_path, manifest = launcher.launch_seed(
                prepared,
                seed=seed,
                output=runs_dir,
                provider=provider,
                api_key=HOST_API_KEY,
                bwrap=None,
                opencode=None,
            )

        assert manifest["status"] in {"python_failed", "python_inconclusive"}
        wire_before_resume = len(wire_capture[0])
        assert wire_before_resume > 0
        decisions_before_resume = len(provider_decisions_resume)

        orig_init = PythonSolver.__init__

        def capture_resumed(self, broker, **kwargs):
            orig_init(self, broker, **kwargs)
            captured_resumed.append(self)

        with monkeypatch.context() as resume_ctx:
            resume_ctx.setattr(PythonSolver, "__init__", capture_resumed)
            _, resumed_manifest = launcher.resume_python_run(
                prepared,
                directory=manifest_path.parent,
                seed=seed,
                provider=provider,
                api_key=HOST_API_KEY,
            )
        assert resumed_manifest["resumed"] is True
        assert resumed_manifest["status"] == "python_inconclusive"
        assert resumed_manifest["stop_reason"] == "unresolved_tasks_remain_NOT_TESTED"
        assert len(wire_capture[0]) == wire_before_resume
        assert len(provider_decisions_resume) == decisions_before_resume
        resumed_solver = captured_resumed[-1]
        assert resumed_solver.task_states["access-3"] == "inconclusive"
        gap_codes = {g["reason_code"] for g in resumed_solver.coverage_gaps.get("access-3", [])}
        assert "validator_execution_budget_exhausted" in gap_codes
        assert "task_incomplete_or_indeterminate_no_replay" in gap_codes
        assert all(
            not row["evidence_accepted"] and row["validation_state"] == "NOT TESTED"
            for row in resumed_solver.candidates_by_task["access-3"].values()
            if row.get("dispatch_started") and not row["executed"]
        )
        assert resumed_solver.leaf_outcomes_by_task["access-3"]
        assert any(leaf["status"] == "accepted" for leaf in resumed_solver.leaf_outcomes_by_task["access-3"])
    finally:
        prov_srv.shutdown()
        prov_thread.join(timeout=5)
        prov_srv.server_close()
    assert "scripts/python_discovery_runtime.py" in prepared["manifest"]["host_runtime"]
    assert "scripts/python_candidate_runtime.py" in prepared["manifest"]["host_runtime"]
    monkeypatch.setattr(
        preflight,
        "python_host_inventory",
        lambda: {**prepared["manifest"]["host_runtime"], "scripts/python_discovery_runtime.py": "0" * 64},
    )
    with pytest.raises(ValueError, match="host runtime changed"):
        launcher.prepared_run(preflight_path)
    monkeypatch.undo()

    tampered_runtime_file = prepared["runtime"] / "scripts/python_discovery_runtime.py"
    tampered_runtime_file.chmod(0o644)
    tampered_runtime_file.write_text("# tampered\n")
    with pytest.raises(ValueError, match="runtime file changed"):
        launcher.prepared_run(preflight_path)

    # 3. Run a partial-coverage 4-phase run and verify signed closure + tamper checks.
    def decide_clean_partial(context, _body, _state):
        spec = context["task_spec"]
        results = context["recent_results"]
        if spec["phase"] == "recon":
            if not results:
                return "kali-tools_curl_request", {"url": spec["target"], "follow_redirects": False}
            return SUMMARY_TOOL, _done_summary_args(spec)
        return SUMMARY_TOOL, _done_summary_args(spec, status="partial" if spec["phase"] in {"access", "report"} else "done")

    clean_run = _run_e6_loopback_campaign(
        tmp_path,
        recall_baseline,
        monkeypatch,
        decide_clean_partial,
        target_factory=_serve_api_314159_style_lab,
        tag="closure",
    )
    assert clean_run["manifest"]["status"] == "python_finished_verified"
    assert clean_run["manifest"]["closure_verified"] is True
    clean_work = clean_run["workdir"]
    clean_dir = clean_run["directory"]
    closure_payload = json.loads((clean_work / "closure.json").read_bytes())["payload"]
    assert len(closure_payload["not_tested"]) >= 8
    solver = clean_run["solvers"][0]
    for name in ("attempt-ledger.json", "closure.json", "summaries/enum-2.json"):
        target = clean_work / name
        original_bytes = target.read_bytes()
        data = json.loads(original_bytes)
        if name in {"attempt-ledger.json", "closure.json"}:
            data["payload"]["target"] = "changed"
        else:
            data["tampered"] = True
        dump(target, data)
        try:
            with launcher.host_environment(clean_dir / "private/state", clean_work, clean_dir / "runtime"):
                assert solver.verify_closure() is False
        except ValueError:
            pass
        target.write_bytes(original_bytes)
        with launcher.host_environment(clean_dir / "private/state", clean_work, clean_dir / "runtime"):
            assert solver.verify_closure() is True
    assert HOST_API_KEY not in "".join(
        p.read_text(errors="replace") for p in clean_work.rglob("*") if p.is_file()
    )
