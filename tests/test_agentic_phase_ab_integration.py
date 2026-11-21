"""End-to-end integration tests for Phase A decoupling and Phase B salvaged agentic capabilities."""
from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_runner  # noqa: E402
import agentic_vault  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient, ServiceDegradationError  # noqa: E402
from agentic_investigator import AgenticInvestigator  # noqa: E402
from agentic_oracle import DifferentialOracle  # noqa: E402
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from agentic_tools import TOOL_SCHEMAS, ToolDispatcher  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402


def _b64url(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode("utf-8")).decode("ascii").rstrip("=")


def _unwrap(raw: str) -> dict[str, Any]:
    prefix = "<<<UNTRUSTED_TARGET_RESPONSE>>>\n"
    suffix = "\n<<<END_UNTRUSTED_TARGET_RESPONSE>>>"
    assert raw.startswith(prefix) and raw.endswith(suffix)
    return json.loads(raw[len(prefix) : -len(suffix)])


def test_agentic_runner_decoupled_from_legacy_python_engine() -> None:
    """Importing agentic_runner must NOT pull in external_target_runner or legacy PythonSolver/Brain/Campaign."""
    code = (
        "import sys; sys.path.insert(0, 'scripts'); import agentic_runner; "
        "forbidden = ['external_target_runner', 'full_agent_python_solver', 'full_agent_python_broker', "
        "'full_agent_launcher', 'full_agent_e6_benchmark', 'brain', 'campaign_runtime', 'campaign_worker', "
        "'policy_engine']; "
        "loaded = [m for m in forbidden if m in sys.modules]; "
        "assert not loaded, f'legacy modules leaked into agentic_runner: {loaded}'; "
        "print('DECOUPLED_IMPORT_OK')"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "DECOUPLED_IMPORT_OK" in proc.stdout


def test_tool_schemas_include_phase_b_tools_and_stay_concise() -> None:
    names = [t["function"]["name"] for t in TOOL_SCHEMAS]
    assert "browser_crawl" in names
    assert "analyze_token" in names
    assert len(names) == 11
    for tool in TOOL_SCHEMAS:
        assert len(tool["function"]["description"]) <= 140


def test_dispatcher_analyze_token_and_waf_hint_and_degradation(tmp_path: Path) -> None:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/waf-blocked":
                body = b"<html><title>Attention Required! | Cloudflare</title><body>Sorry, you have been blocked</body></html>"
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.send_header("CF-Ray", "8a1b2c3d4e5f-IST")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/app-forbidden":
                body = b'{"error":"forbidden","detail":"admin role required"}'
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/degraded":
                body = b"Service Temporarily Unavailable"
                self.send_response(503)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = b"<html><body><a href='/app-forbidden'>admin</a></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}/"
        store = ReceiptStore(tmp_path)
        actors = ActorManager([])
        client = AgenticHTTPClient(
            base_url=base,
            receipt_store=store,
            actors=actors,
            allowed_methods=["GET"],
            max_requests=20,
            max_degradation_streak=2,
        )
        oracle = DifferentialOracle(http_client=client, receipt_store=store)
        disp = ToolDispatcher(http_client=client, receipt_store=store, oracle=oracle, root_dir=tmp_path)

        # 1. analyze_token (0 HTTP cost)
        jwt_tok = f"{_b64url({'alg': 'none', 'typ': 'JWT'})}.{_b64url({'sub': 'u1', 'role': 'admin'})}."
        tok_out = json.loads(disp.dispatch("analyze_token", {"value": jwt_tok}))
        assert tok_out["kind"] == "jwt"
        assert tok_out["valid_jwt"] is True
        assert "alg_none" in tok_out["findings"]
        assert "authorization_claims_present" in tok_out["findings"]
        assert client.budget.used == 0

        # 2. WAF block attached on Cloudflare 403, NOT on ordinary JSON 403
        waf_preview = _unwrap(disp.dispatch("http_request", {"method": "GET", "url": "/waf-blocked", "actor": "anon"}))
        assert waf_preview["waf_block"]["waf_blocked"] is True
        assert waf_preview["waf_block"]["vendor"] == "cloudflare"

        app_preview = _unwrap(disp.dispatch("http_request", {"method": "GET", "url": "/app-forbidden", "actor": "anon"}))
        assert "waf_block" not in app_preview

        # 3. ServiceDegradationError propagates out of ToolDispatcher.dispatch on streak=2
        disp.dispatch("http_request", {"method": "GET", "url": "/degraded", "actor": "anon", "force": True})
        with pytest.raises(ServiceDegradationError):
            disp.dispatch("http_request", {"method": "GET", "url": "/degraded", "actor": "anon", "force": True})

        client.close()
    finally:
        srv.shutdown()
        srv.server_close()


def test_investigator_stops_cleanly_on_service_degradation(tmp_path: Path) -> None:
    class _DegradedHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

        def do_GET(self) -> None:
            body = b"overloaded"
            self.send_response(503)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class _ScriptedTransport:
        calls = 0

        def complete(self, body: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            _ = body, kwargs
            self.calls += 1
            return {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": f"call_{self.calls}",
                                    "type": "function",
                                    "function": {
                                        "name": "http_request",
                                        "arguments": json.dumps({"method": "GET", "url": f"/p{self.calls}", "actor": "anon"}),
                                    },
                                }
                            ],
                        }
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 30, "total_tokens": 130},
            }

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _DegradedHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}/"
        store = ReceiptStore(tmp_path)
        client = AgenticHTTPClient(
            base_url=base,
            receipt_store=store,
            actors=ActorManager([]),
            allowed_methods=["GET"],
            max_requests=20,
            max_degradation_streak=2,
        )
        budget = SharedBudget(http=20, tokens=100_000, seconds=60)
        inv = AgenticInvestigator(
            http_client=client,
            receipt_store=store,
            transport=_ScriptedTransport(),  # type: ignore[arg-type]
            budget=budget,
            model="test-model",
            root_dir=tmp_path,
            max_turns=10,
            execution_mode="monolithic",
        )
        summary = inv.run()
        assert summary["status"] == "service_degraded"
        assert client.budget.used == 2
        client.close()
    finally:
        srv.shutdown()
        srv.server_close()


def test_surface_tracker_ingests_postman_client_logic_and_graphql() -> None:
    tracker = SurfaceFrontierTracker(base_url="http://127.0.0.1:8000/", allowed_methods=["GET", "POST"])
    tracker.ingest_surface(
        {
            "url": "http://127.0.0.1:8000/graphql",
            "graphql_ops": [{"kind": "query", "name": "viewer", "args": ["id"]}],
            "postman_ops": [{"method": "POST", "url": "/api/v1/orders", "body_keys": ["amount", "item_id"]}],
            "client_logic": {
                "endpoints": [
                    {"method": "POST", "path": "/api/v1/checkout", "query_params": ["coupon"], "body_fields": ["total"]}
                ]
            },
        },
        actor="user1",
    )
    unvisited = tracker.unvisited_routes()
    assert any("/graphql" in r for r in unvisited)
    assert any("/api/v1/orders" in r for r in unvisited)
    assert any("/api/v1/checkout" in r for r in unvisited)


def test_runner_plan_supports_scope_file_and_vault_credentials(tmp_path: Path) -> None:
    cfg = REPO_ROOT / "config" / "llm.example.json"
    # 1. Fail closed when allow_non_loopback without scope_file
    with pytest.raises(ValueError):
        agentic_runner.run_agentic_target(
            target="https://app.example.test/",
            provider_config=cfg,
            output_dir=tmp_path / "out_fail",
            allow_non_loopback=True,
            execute=False,
        )

    # 2. Valid scope_file + encrypted vault credentials in plan-only mode
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps(
            {
                "in_scope": [{"asset": "https://app.example.test"}],
                "excluded_paths": ["/logout", "/billing/delete"],
            }
        ),
        encoding="utf-8",
    )
    vault_home = tmp_path / "vault"
    agentic_vault.save_vault_credentials(
        vault_home,
        "staging_bundle",
        {
            "target_url": "https://app.example.test/",
            "test_accounts": [{"alias": "member1", "password": "synthetic-secret-value", "role": "member"}],
            "discovery": ["/dashboard"],
        },
    )
    plan_path, plan = agentic_runner.run_agentic_target(
        provider_config=cfg,
        output_dir=tmp_path / "out_ok",
        scope_file=scope_file,
        allow_non_loopback=True,
        vault_home=vault_home,
        vault_key_name="staging_bundle",
        execute=False,
    )
    assert plan_path.is_file()
    assert plan["target"] == "https://app.example.test/"
    assert plan["scope"]["loopback_only"] is False
    assert plan["scope"]["excluded_paths_count"] == 2
    assert plan["selected_accounts"][0]["alias"] == "member1"
    assert "synthetic-secret-value" not in plan_path.read_text(encoding="utf-8")
