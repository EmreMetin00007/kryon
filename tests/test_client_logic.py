"""Client Logic Map v1 (offline, deterministic, no network)."""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from kryon_core.js.client_logic import build_client_logic_map


SOURCE = r"""
//# sourceMappingURL=app.js.map
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function signRequest(payload) {
  return CryptoJS.HmacSHA256(JSON.stringify(payload), window.__KEY__);
}
async function checkout(cartId, email) {
  const signature = signRequest({cartId, email});
  return fetch(`/api/v2/checkout/${cartId}?preview=true`, {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-Signature": signature, "Authorization": "Bearer SECRET_CANARY"},
    body: JSON.stringify({cartId, email, quantity: 1})
  });
}
const load = (id) => axios.get("/api/v2/users/" + id + "/profile");
const xhr = new XMLHttpRequest();
xhr.open("DELETE", "/api/v2/sessions/current");
xhr.setRequestHeader("X-CSRF-Token", "csrf-canary");
localStorage.setItem("tenant_id", "tenant-canary");
"""


def _endpoint(out, method, path):
    for item in out["endpoints"]:
        if item["method"] == method and item["path"] == path:
            return item
    raise AssertionError(f"endpoint not found: {method} {path}: {out['endpoints']}")


def test_fetch_endpoint_schema_body_and_signer():
    out = build_client_logic_map(SOURCE)
    assert out["schema"] == "cco-client-logic-map/1"
    ep = _endpoint(out, "POST", "/api/v2/checkout/{id}")
    assert ep["query_params"] == ["preview"]
    assert ep["body_fields"] == ["cartId", "email", "quantity"]
    assert "X-Signature" in ep["headers"]
    assert ep["function_context"] == "checkout"
    assert ep["signer_functions"] == ["signRequest"]
    assert out["source_map"]["present"] is True
    assert out["source_map"]["url"] == "app.js.map"


def test_axios_and_xhr_are_normalized():
    out = build_client_logic_map(SOURCE)
    ep = _endpoint(out, "GET", "/api/v2/users/{id}/profile")
    assert ep["source_kind"] == "axios"
    xhr = _endpoint(out, "DELETE", "/api/v2/sessions/current")
    assert xhr["source_kind"] == "xhr"
    assert "X-CSRF-Token" in xhr["headers"]


def test_sensitive_values_and_storage_values_are_not_exposed():
    out = build_client_logic_map(SOURCE)
    text = repr(out)
    assert "SECRET_CANARY" not in text
    assert "csrf-canary" not in text
    assert "tenant-canary" not in text
    assert out["storage_keys"] == ["tenant_id"]


def test_signing_and_validation_indicators_are_reported():
    out = build_client_logic_map(SOURCE)
    assert "signRequest" in out["signing"]["functions"]
    assert out["signing"]["requires_runtime"] is True
    assert any(v["field"] == "email" for v in out["validation_rules"])


def test_dynamic_and_empty_sources_fail_closed():
    dynamic = build_client_logic_map("fetch(buildUrl(id), {method: 'PUT'})")
    assert dynamic["endpoints"][0]["runtime_required"] is True
    empty = build_client_logic_map("")
    assert empty["endpoints"] == []
    assert empty["schema"] == "cco-client-logic-map/1"


def test_parser_interface_reports_static_fallback():
    out = build_client_logic_map(SOURCE, parser="static")
    assert out["parser"]["requested"] == "static"
    assert out["parser"]["used"] == "static"
    assert out["parser"]["ast_available"] is False


def test_babel_parser_when_available(monkeypatch):
    import shutil

    node_modules = os.path.join(REPO_ROOT, "legacy/opencode/client", "node_modules")
    if not shutil.which("node") or not os.path.isdir(os.path.join(node_modules, "@babel", "parser")):
        return
    monkeypatch.setenv("NODE_PATH", node_modules)
    out = build_client_logic_map(SOURCE, parser="babel")
    assert out["parser"]["used"] == "babel"
    assert out["parser"]["ast_available"] is True
    assert _endpoint(out, "POST", "/api/v2/checkout/{id}")


def test_source_map_original_sources_are_mapped_without_values():
    import json

    source_map = json.dumps({
        "version": 3,
        "sources": ["src/orders.ts"],
        "sourcesContent": [
            "export const load = (id) => fetch(`/api/v2/orders/${id}`, "
            "{headers: {Authorization: 'Bearer ORDER_SECRET'}});"
        ],
        "names": [],
        "mappings": "AAAA",
    })
    out = build_client_logic_map("fetch('/api/v2/minified')", source_map=source_map)
    assert out["source_map"]["valid"] is True
    assert out["source_map"]["sources"] == ["src/orders.ts"]
    assert out["source_map"]["mappings_decoded"] >= 1
    original = out["source_map"]["original_endpoints"]
    assert any(e["path"] == "/api/v2/orders/{id}" for e in original)
    assert "ORDER_SECRET" not in repr(out)


def test_malformed_source_map_fails_closed():
    out = build_client_logic_map("fetch('/api/v2/minified')", source_map="{not-json")
    assert out["source_map"]["valid"] is False
    assert out["source_map"]["diagnostics"]
    assert _endpoint(out, "GET", "/api/v2/minified")


# ---------------------------------------------------------------------------
# E9: explicit parser diagnostics + machine-readable coverage gaps.
# Optional Babel must never silently imply complete JS coverage.
# ---------------------------------------------------------------------------

def _fake_proc(returncode=0, stdout="", stderr=""):
    class _Proc:
        pass

    proc = _Proc()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def _gaps(meta_or_out):
    """Collect coverage gaps from parser meta or top-level map."""
    gaps = []
    if isinstance(meta_or_out, dict):
        gaps.extend(meta_or_out.get("coverage_gaps") or [])
        parser = meta_or_out.get("parser")
        if isinstance(parser, dict):
            gaps.extend(parser.get("coverage_gaps") or [])
    return gaps


def _assert_not_tested_gap(meta_or_out):
    gaps = _gaps(meta_or_out)
    assert gaps, f"expected coverage_gaps, got {meta_or_out!r}"
    assert any(
        (g.get("status") == "NOT TESTED" or "NOT TESTED" in repr(g))
        for g in gaps
        if isinstance(g, dict)
    ), f"expected NOT TESTED gap, got {gaps!r}"
    return gaps


def _assert_bounded_safe_diagnostics(meta_or_out, forbidden=()):
    diags = []
    if isinstance(meta_or_out, dict):
        diags.extend(meta_or_out.get("diagnostics") or [])
        parser = meta_or_out.get("parser")
        if isinstance(parser, dict):
            diags.extend(parser.get("diagnostics") or [])
        # parse_javascript meta is itself the parser dict
        if "requested" in meta_or_out:
            diags.extend(meta_or_out.get("diagnostics") or [])
    # also accept result dict diagnostics
    for diag in diags:
        assert isinstance(diag, str)
        assert len(diag) <= 240, f"diagnostic too long: {diag!r}"
        for secret in forbidden:
            assert secret not in diag, f"diagnostic echoed secret: {diag!r}"
    return diags


def test_missing_node_emits_coverage_gap_not_tested(monkeypatch):
    import kryon_core.js.parsers as parsers

    monkeypatch.setattr(parsers.shutil, "which", lambda name: None)
    from kryon_core.js.parsers import parse_javascript

    result, meta = parse_javascript("fetch('/api/v2/x')", parser="auto")
    assert meta["used"] == "static"
    assert meta["ast_available"] is False
    assert meta["diagnostics"], "missing Node must emit explicit diagnostic"
    _assert_not_tested_gap(meta)
    _assert_not_tested_gap(result)
    assert result["functions"] is not None  # fallback still returns shape
    # Propagation through build_client_logic_map, endpoints preserved
    out = build_client_logic_map("fetch('/api/v2/x')", parser="auto")
    assert out["parser"]["used"] == "static"
    assert out["parser"]["diagnostics"]
    _assert_not_tested_gap(out)
    assert _endpoint(out, "GET", "/api/v2/x")


def test_missing_babel_despite_node_emits_gap_without_echoing_stderr(monkeypatch):
    import kryon_core.js.parsers as parsers

    secret = "SECRET_CANARY_BABEL_STDERR_9f3"
    monkeypatch.setattr(parsers.shutil, "which", lambda name: "/usr/bin/node")
    monkeypatch.setattr(
        parsers.subprocess,
        "run",
        lambda *a, **k: _fake_proc(
            returncode=1,
            stdout="",
            stderr=f"Error: Cannot find module '@babel/parser' {secret}",
        ),
    )
    from kryon_core.js.parsers import parse_javascript

    result, meta = parse_javascript("fetch('/api/v2/x')", parser="babel")
    assert meta["used"] == "static"
    assert meta["ast_available"] is False
    assert meta["diagnostics"]
    _assert_not_tested_gap(meta)
    _assert_bounded_safe_diagnostics(meta, forbidden=(secret,))
    _assert_bounded_safe_diagnostics(result, forbidden=(secret,))
    # fallback endpoints still useful via client_logic
    out = build_client_logic_map("fetch('/api/v2/x')", parser="babel")
    assert out["parser"]["used"] == "static"
    _assert_not_tested_gap(out)
    _assert_bounded_safe_diagnostics(out, forbidden=(secret,))
    assert _endpoint(out, "GET", "/api/v2/x")


def test_babel_execution_failure_emits_gap(monkeypatch):
    import subprocess as _sp

    import kryon_core.js.parsers as parsers

    monkeypatch.setattr(parsers.shutil, "which", lambda name: "/usr/bin/node")

    def _timeout(*a, **k):
        raise _sp.TimeoutExpired(cmd="node", timeout=8)

    monkeypatch.setattr(parsers.subprocess, "run", _timeout)
    from kryon_core.js.parsers import parse_javascript

    result, meta = parse_javascript("fetch('/api/v2/x')", parser="auto")
    assert meta["used"] == "static"
    assert meta["diagnostics"]
    _assert_not_tested_gap(meta)

    def _oserror(*a, **k):
        raise OSError("SECRET_CANARY_OSERROR_detail")

    monkeypatch.setattr(parsers.subprocess, "run", _oserror)
    result, meta = parse_javascript("fetch('/api/v2/x')", parser="auto")
    assert meta["used"] == "static"
    assert meta["diagnostics"]
    _assert_not_tested_gap(meta)
    _assert_bounded_safe_diagnostics(meta, forbidden=("SECRET_CANARY_OSERROR_detail",))
    _assert_bounded_safe_diagnostics(result, forbidden=("SECRET_CANARY_OSERROR_detail",))


def test_babel_parse_failure_does_not_echo_source_secret(monkeypatch):
    import kryon_core.js.parsers as parsers

    secret = "SECRET_SOURCE_SNIPPET_7a1"
    monkeypatch.setattr(parsers.shutil, "which", lambda name: "/usr/bin/node")
    monkeypatch.setattr(
        parsers.subprocess,
        "run",
        lambda *a, **k: _fake_proc(
            returncode=2,
            stdout="",
            stderr=f"SyntaxError: Unexpected token, expected \",\" {secret} fetch('/api/secret')",
        ),
    )
    from kryon_core.js.parsers import parse_javascript

    result, meta = parse_javascript(f"fetch('/api/x'); {secret}", parser="babel")
    assert meta["used"] == "static"
    assert meta["diagnostics"]
    _assert_not_tested_gap(meta)
    _assert_bounded_safe_diagnostics(meta, forbidden=(secret,))
    _assert_bounded_safe_diagnostics(result, forbidden=(secret,))
    out = build_client_logic_map("fetch('/api/v2/x')", parser="babel")
    _assert_bounded_safe_diagnostics(out, forbidden=(secret,))


def test_babel_invalid_and_nonobject_json_do_not_crash(monkeypatch):
    import kryon_core.js.parsers as parsers

    monkeypatch.setattr(parsers.shutil, "which", lambda name: "/usr/bin/node")
    from kryon_core.js.parsers import parse_javascript

    for payload in ("not-json", "[]", '"hello"', "123", "null", "true"):
        monkeypatch.setattr(
            parsers.subprocess,
            "run",
            lambda *a, _p=payload, **k: _fake_proc(returncode=0, stdout=_p, stderr=""),
        )
        result, meta = parse_javascript("fetch('/api/v2/x')", parser="babel")
        assert meta["used"] == "static", payload
        assert meta["diagnostics"], payload
        _assert_not_tested_gap(meta)
        out = build_client_logic_map("fetch('/api/v2/x')", parser="babel")
        assert _endpoint(out, "GET", "/api/v2/x")


def test_babel_nonobject_fields_do_not_crash(monkeypatch):
    import kryon_core.js.parsers as parsers

    monkeypatch.setattr(parsers.shutil, "which", lambda name: "/usr/bin/node")
    monkeypatch.setattr(
        parsers.subprocess,
        "run",
        lambda *a, **k: _fake_proc(
            returncode=0,
            stdout='{"functions": "bad", "calls": 42}',
            stderr="",
        ),
    )
    from kryon_core.js.parsers import parse_javascript

    result, meta = parse_javascript("fetch('/api/v2/x')", parser="babel")
    # malformed shape must be treated as parser failure, not crash
    assert meta["used"] == "static"
    _assert_not_tested_gap(meta)
    out = build_client_logic_map("fetch('/api/v2/x')", parser="babel")
    assert _endpoint(out, "GET", "/api/v2/x")


def test_deliberate_static_mode_emits_diagnostic_and_gap():
    from kryon_core.js.parsers import get_parser, parse_javascript

    result, meta = parse_javascript(SOURCE, parser="static")
    assert meta["requested"] == "static"
    assert meta["used"] == "static"
    assert meta["ast_available"] is False
    assert meta["diagnostics"], "deliberate static mode must not be silent"
    _assert_not_tested_gap(meta)
    _assert_not_tested_gap(result)
    _, get_meta = get_parser("static")
    assert get_meta["diagnostics"], "get_parser(static) must not be silent"
    _assert_not_tested_gap(get_meta)
    out = build_client_logic_map(SOURCE, parser="static")
    assert out["parser"]["diagnostics"]
    _assert_not_tested_gap(out)
    assert _endpoint(out, "POST", "/api/v2/checkout/{id}")


def test_source_truncation_emits_gap():
    from kryon_core.js.parsers import MAX_SOURCE, parse_javascript

    filler = "// filler line for truncation coverage\n" * 100
    # Build source just over MAX_SOURCE without a single huge token line.
    prefix = "fetch('/api/early');\n"
    repeats = (MAX_SOURCE // len(filler)) + 20
    source = prefix + (filler * repeats) + "fetch('/api/late');\n"
    assert len(source) > MAX_SOURCE
    result, meta = parse_javascript(source, parser="static")
    assert meta["diagnostics"], "truncation must emit diagnostic"
    gaps = _assert_not_tested_gap(meta)
    assert any("truncat" in repr(g).lower() for g in gaps), gaps
    assert any("truncat" in d.lower() for d in meta["diagnostics"])
    # client_logic propagation
    out = build_client_logic_map(source, parser="static")
    assert out["parser"]["diagnostics"]
    ogaps = _assert_not_tested_gap(out)
    assert any("truncat" in repr(g).lower() for g in ogaps), ogaps
    assert _endpoint(out, "GET", "/api/early")


def test_build_map_propagates_gap_and_never_claims_complete_coverage(monkeypatch):
    import kryon_core.js.parsers as parsers

    monkeypatch.setattr(parsers.shutil, "which", lambda name: None)
    out = build_client_logic_map(SOURCE, parser="auto")
    assert out["parser"]["used"] == "static"
    _assert_not_tested_gap(out)
    # top-level machine-readable gaps must be present (additive field)
    assert out.get("coverage_gaps"), f"missing top-level coverage_gaps: {list(out)}"
    assert any(g.get("status") == "NOT TESTED" for g in out["coverage_gaps"] if isinstance(g, dict))
    # unknowns must keep NOT TESTED visible, never claim complete coverage
    assert any("NOT TESTED" in str(u) for u in out.get("unknowns", [])), out.get("unknowns")
    assert not any(
        "complete js coverage" in str(u).lower() or "full security coverage" in str(u).lower() and "not" not in str(u).lower()
        for u in out.get("unknowns", [])
    )
    assert _endpoint(out, "POST", "/api/v2/checkout/{id}")


def test_source_map_originals_propagate_coverage_gap():
    import json

    source_map = json.dumps({
        "version": 3,
        "sources": ["src/orders.ts"],
        "sourcesContent": [
            "export const load = (id) => fetch(`/api/v2/orders/${id}`);"
        ],
        "names": [],
        "mappings": "AAAA",
    })
    out = build_client_logic_map("fetch('/api/v2/minified')", source_map=source_map, parser="static")
    assert out["source_map"]["valid"] is True
    original = out["source_map"]["original_endpoints"]
    assert any(e["path"] == "/api/v2/orders/{id}" for e in original)
    # originals are parsed with static fallback: their limited coverage
    # must be visible as a gap, not silently implied complete
    gaps = _gaps(out)
    # also check source_map-scoped gaps if present
    sm = out.get("source_map") or {}
    gaps = gaps + list(sm.get("coverage_gaps") or []) + list(sm.get("parser_coverage_gaps") or [])
    assert gaps, "source-map originals must propagate coverage gaps"
    assert any(
        (isinstance(g, dict) and (g.get("status") == "NOT TESTED" or "NOT TESTED" in repr(g)))
        for g in gaps
    ), gaps


def test_babel_success_does_not_claim_full_security_coverage():
    import shutil

    if not shutil.which("node"):
        return
    out = build_client_logic_map(SOURCE, parser="babel")
    if out["parser"]["used"] != "babel":
        return  # babel not resolvable in this env; fallback case covered elsewhere
    assert out["parser"]["ast_available"] is True
    # AST success alone must not be reported as complete security coverage
    blob = repr(out.get("unknowns", [])) + repr(out.get("notes", []))
    assert "full security coverage" not in blob.lower() or "not" in blob.lower()
    # no coverage gap should claim TESTED for overall JS/security coverage
    for gap in _gaps(out):
        assert gap.get("status") != "TESTED" or "security" not in repr(gap).lower()


def test_parser_candidates_use_explicit_env_not_repo_local(monkeypatch, tmp_path):
    import kryon_core.js.parsers as parsers

    monkeypatch.delenv("CCO_JS_PARSER_PATH", raising=False)
    monkeypatch.delenv("NODE_PATH", raising=False)
    monkeypatch.chdir(tmp_path)
    # Even when a cwd-local node_modules exists, it must not be auto-discovered;
    # only explicit env or standard external dirs may locate the parser.
    local_nm = tmp_path / "node_modules"
    local_nm.mkdir()
    candidates = parsers._node_path_candidates()
    assert str(local_nm) not in candidates
    # explicit env is honoured
    custom = str(tmp_path / "custom_modules")
    monkeypatch.setenv("CCO_JS_PARSER_PATH", custom)
    candidates = parsers._node_path_candidates()
    assert custom in candidates or str(parsers.Path(custom) / "node_modules") in candidates
