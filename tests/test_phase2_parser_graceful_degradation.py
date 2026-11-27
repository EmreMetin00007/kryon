"""Tests for Faz 2: Graceful Degradation in Parser Layer (JS opacity + WASM + frontier)."""
from __future__ import annotations

import os
import sys
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
for _p in (REPO_ROOT, SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import agentic_preview  # noqa: E402
from agentic_preview import _extract_js_client_logic, _extract_surface_summary  # noqa: E402
from agentic_surface import SurfaceFrontierTracker  # noqa: E402
from kryon_core.js import assess_js_opacity, build_client_logic_map  # noqa: E402


def test_vendor_bundle_skips_opacity_by_url_and_header() -> None:
    noisy_body = (
        "var _0x1a2b=1,_0x2b3c=2,_0x3c4d=3,_0x4d5e=4,_0x5e6f=5;\n"
        "WebAssembly.instantiate(buf); fetch('/ignored');"
    )
    for vendor_url in (
        "https://app.test/assets/vendor.js",
        "https://app.test/js/chunk-vendors.9a8b7c.js",
        "https://app.test/static/react-dom.production.min.js",
        "https://app.test/libs/lodash.min.js",
        "https://app.test/libs/jquery-3.7.1.min.js",
        "https://app.test/vs/monaco-editor/loader.js",
        "https://app.test/lib/moment.min.js",
    ):
        res = assess_js_opacity(noisy_body, url=vendor_url)
        assert res["status"] == "vendor_skip", vendor_url
        assert res["vendor_filtered"] is True
        assert res["opacity_score"] == 0.0
        assert res["signals"] == []
        assert res["wasm_refs"] == []
        assert res["opaque_regions"] == []
        assert res["coverage_gaps"] == []

    for header in (
        "/*! React v18.2.0 production */\n",
        "/** @license Lodash <https://lodash.com/> */\n",
        "/*! jQuery JavaScript Library v3.7.1 */\n",
        "/** @license @angular/core v17.0.0 */\n",
    ):
        res = assess_js_opacity(header + noisy_body, url="https://app.test/assets/bundle.js")
        assert res["status"] == "vendor_skip", header
        assert res["vendor_filtered"] is True
        assert res["opaque_regions"] == []


def test_obfuscator_0x_table_always_includes_decoder_preamble_and_bounded_slices() -> None:
    preamble = (
        "var _0x4a12=['YWRtaW4=','c2lnbmF0dXJl','L2FwaS92MS9zaWdu','WC1TaWduYXR1cmU='];"
        "(function(_0x1b2c,_0x3d4e){var _0x5f6a=function(_0x7b8c){while(--_0x7b8c){"
        "_0x1b2c['push'](_0x1b2c['shift']());}};_0x5f6a(++_0x3d4e);}(_0x4a12,0x1a3));\n"
    )
    pad1 = "/* spacer */\n" * 200  # ~2600 chars to separate windows cleanly
    crypto_chunk = (
        "async function _0x9a0b(msg){const enc=new TextEncoder().encode(msg);"
        "return crypto.subtle.digest('SHA-256',enc);}\n"
    )
    pad2 = "/* more spacer */\n" * 200  # ~3600 chars
    sink_chunk = (
        "function _0xc1d2(url,sig){const x=new XMLHttpRequest();"
        "x.open('POST',url);x.setRequestHeader('X-Signature',sig);return x;}\n"
    )
    js_src = preamble + pad1 + crypto_chunk + pad2 + sink_chunk

    res = assess_js_opacity(js_src, url="https://app.test/static/app.js", max_regions=5, slice_chars=1500)
    assert res["vendor_filtered"] is False
    assert res["status"] == "opaque_escalation_candidate"
    assert "obfuscator_0x_table" in res["signals"]
    assert "custom_transport_or_crypto" in res["signals"]
    assert 0.0 < res["opacity_score"] <= 1.0

    regions = res["opaque_regions"]
    assert 1 <= len(regions) <= 5
    preamble_reg = regions[0]
    assert preamble_reg["anchor"] == "decoder_preamble"
    assert preamble_reg["char_start"] == 0
    assert preamble_reg["char_end"] == 1500
    assert preamble_reg["reason"] == "obfuscator_string_array_decoder"
    assert preamble_reg["recommended_action"] == "llm_reverse_engineer_slice"

    anchors = {r["anchor"] for r in regions}
    assert any("crypto.subtle" in a for a in anchors)
    assert any(a in {"setRequestHeader", "XMLHttpRequest"} for a in anchors)

    # All slices bounded <= 1500 chars and non-overlapping
    sorted_regs = sorted(regions, key=lambda r: (r["char_start"], r["char_end"]))
    for idx, reg in enumerate(sorted_regs):
        assert 0 <= reg["char_start"] < reg["char_end"] <= len(js_src)
        assert (reg["char_end"] - reg["char_start"]) <= 1500
        if idx > 0:
            assert reg["char_start"] >= sorted_regs[idx - 1]["char_end"]

    # Machine-readable NOT TESTED gap emitted
    assert any(
        g.get("status") == "NOT TESTED" and g.get("code") == "opaque_js_bundle"
        for g in res["coverage_gaps"]
    )


def test_wasm_loader_extracts_bounded_refs_and_not_tested_gaps() -> None:
    refs_code = "\n".join(
        f'const wasmPath{i} = "/static/mod_{i}.wasm?v=1";' for i in range(14)
    )
    js_src = (
        refs_code
        + "\n"
        + "async function initSigner() {\n"
        + '  const resp = fetch("/static/signer.wasm");\n'
        + "  return WebAssembly.instantiateStreaming(resp, {});\n"
        + "}\n"
    )
    cl_map = build_client_logic_map(js_src, parser="static", source_url="https://app.test/static/wasm_boot.js")
    op = cl_map["opacity_assessment"]
    assert op["status"] == "opaque_escalation_candidate"
    assert "wasm_loader" in op["signals"]
    assert len(op["wasm_refs"]) == 10  # bounded at 10
    assert "/static/mod_0.wasm?v=1" in op["wasm_refs"]
    assert any(r["reason"] == "wasm_loader" for r in op["opaque_regions"])

    gap_codes = {g.get("code") for g in cl_map["coverage_gaps"] if g.get("status") == "NOT TESTED"}
    assert "opaque_js_bundle" in gap_codes
    assert "wasm_module_not_executed" in gap_codes


def test_eval_packer_hex_escapes_and_high_entropy_signals() -> None:
    hex_payload = "".join(f"\\x{(0x41 + (i % 26)):02x}" for i in range(40))
    high_ent_1 = "X9kL2mP8qR4vW7zN1bC5dF0gH3jK6lM9nP2qR5tV8wX1yZ4aBcDeFg"
    high_ent_2 = "7pQ2rS9tU4vW1xY6zA3bC8dE5fG0hI2jK4lM6nO8pQ1rS3tU5vW7xY"
    high_ent_3 = "mN3oP6qR9sT2uV5wX8yZ1aB4cD7eF0gH2iJ4kL6mN8oP0qR2sT4uV6w"
    js_src = (
        f'const t1 = "{high_ent_1}";\n'
        f'const t2 = "{high_ent_2}";\n'
        f'const t3 = "{high_ent_3}";\n'
        f'const h = "{hex_payload}";\n'
        'eval(atob("YWxlcnQoMSk="));\n'
    )
    res = assess_js_opacity(js_src, url="https://app.test/packed.js")
    assert "high_string_entropy" in res["signals"]
    assert "hex_escape_density" in res["signals"]
    assert "dynamic_eval_packer" in res["signals"]
    assert res["status"] == "opaque_escalation_candidate"
    assert res["opacity_score"] >= 0.55
    assert res["opaque_regions"]


def test_zero_routes_large_bundle_preserved_by_extract_js_client_logic(monkeypatch: Any) -> None:
    filler = "var noop = function(a, b) { return a + b; };\n" * 400  # > 15,000 chars
    js_src = (
        filler
        + "\nasync function signAndSend(key, payload) {\n"
        + "  const buf = new Uint8Array(16);\n"
        + "  const digest = await crypto.subtle.digest('SHA-256', buf);\n"
        + "  const xhr = new XMLHttpRequest();\n"
        + "  xhr.setRequestHeader('X-Custom-Auth', String(digest));\n"
        + "  return fetch;\n"
        + "}\n"
    )
    assert len(js_src) >= 15_000

    cl_calls, cl_links, cl = _extract_js_client_logic(js_src, "https://app.test/static/engine.js")
    assert cl_calls == []
    assert cl_links == []
    assert cl != {}, "zero-route opaque bundle must not be silently dropped"
    op = cl["opacity_assessment"]
    assert op["status"] == "opaque_escalation_candidate"
    assert "zero_routes_with_transport_sink" in op["signals"]
    assert "custom_transport_or_crypto" in op["signals"]
    assert op["opaque_regions"]
    assert any("opaque_js_bundle" in gap for gap in cl["coverage_gaps"])

    # Also verify _supported_kwargs compatibility if a mock build_fn lacks source_url
    def legacy_build_fn(source: str, parser: str = "auto") -> dict[str, Any]:
        return {
            "endpoints": [],
            "coverage_gaps": [],
            "opacity_assessment": {
                "status": "opaque_escalation_candidate",
                "opacity_score": 0.65,
                "signals": ["zero_routes_with_transport_sink"],
                "wasm_refs": [],
                "opaque_regions": [
                    {
                        "region_id": "region_0",
                        "anchor": "crypto.subtle",
                        "char_start": 100,
                        "char_end": 600,
                        "reason": "custom_crypto_or_rpc",
                        "recommended_action": "llm_reverse_engineer_slice",
                    }
                ],
                "coverage_gaps": [
                    {
                        "code": "opaque_js_bundle",
                        "status": "NOT TESTED",
                        "detail": "opaque bundle",
                    }
                ],
            },
        }

    monkeypatch.setattr(agentic_preview, "_load_build_client_logic_map", lambda: legacy_build_fn)
    _, _, legacy_cl = _extract_js_client_logic(js_src, "https://app.test/static/legacy.js")
    assert legacy_cl.get("opacity_assessment", {}).get("status") == "opaque_escalation_candidate"
    assert any("opaque_js_bundle" in g for g in legacy_cl.get("coverage_gaps", []))


def test_inline_script_and_cjs_offsets_in_extract_surface_summary() -> None:
    # 1. HTML with inline <script> > 1000 chars that is obfuscated
    prefix_html = "<!doctype html><html><body><h1>Portal</h1><script>"
    obf_inline = (
        "var _0x1111=['a','b'],_0x2222=1,_0x3333=2,_0x4444=3,_0x5555=4;\n"
        + ("/* inline padding */\n" * 60)
        + "WebAssembly.instantiateStreaming(fetch('/static/inline_signer.wasm'));\n"
    )
    assert len(obf_inline) > 1000
    full_html = prefix_html + obf_inline + "</script></body></html>"

    html_receipt = {
        "receipt_id": "req-html-1",
        "url": "https://app.test/portal",
        "content_type": "text/html; charset=utf-8",
        "response_headers": {"Content-Type": "text/html"},
        "body": full_html,
    }
    html_summary = _extract_surface_summary(html_receipt, "https://app.test")
    html_op = html_summary["client_logic"]["opacity_assessment"]
    assert html_op["status"] == "opaque_escalation_candidate"
    assert "/static/inline_signer.wasm" in html_op["wasm_refs"]
    first_reg = html_op["opaque_regions"][0]
    assert first_reg["receipt_id"] == "req-html-1"
    assert first_reg["url"] == "https://app.test/portal"
    assert first_reg.get("source_type") == "inline_script"
    # Byte-accurate offset inside the HTML body
    extracted_slice = full_html[first_reg["char_start"] : first_reg["char_end"]]
    assert extracted_slice.startswith("var _0x1111=")

    # 2. HTML with benign large inline <script> (> 1000 chars) should NOT emit opacity_assessment
    benign_inline = "const items = [\n" + ("  'item',\n" * 120) + "];\n"
    assert len(benign_inline) > 1000
    benign_html = "<!doctype html><html><body><script>" + benign_inline + "</script></body></html>"
    benign_summary = _extract_surface_summary(
        {
            "receipt_id": "req-html-2",
            "url": "https://app.test/clean",
            "content_type": "text/html",
            "response_headers": {},
            "body": benign_html,
        },
        "https://app.test",
    )
    assert "client_logic" not in benign_summary

    # 3. Standalone .cjs receipt preserves exact 0..slice_chars offsets
    cjs_body = (
        "var _0xaa11=1,_0xbb22=2,_0xcc33=3,_0xdd44=4,_0xee55=5;\n"
        + ("/* cjs pad */\n" * 140)
        + "const w = WebAssembly.compile(bytes);\n"
    )
    cjs_summary = _extract_surface_summary(
        {
            "receipt_id": "req-cjs-1",
            "url": "https://app.test/assets/worker.cjs",
            "content_type": "application/octet-stream",
            "response_headers": {},
            "body": cjs_body,
        },
        "https://app.test",
    )
    cjs_reg = cjs_summary["client_logic"]["opacity_assessment"]["opaque_regions"][0]
    assert cjs_reg["receipt_id"] == "req-cjs-1"
    assert cjs_reg["url"] == "https://app.test/assets/worker.cjs"
    assert cjs_reg["char_start"] == 0
    assert cjs_reg["char_end"] == 1500
    assert "source_type" not in cjs_reg


def test_end_to_end_surface_tracker_checkpoint_and_frontier_banner() -> None:
    js_body = (
        "var _0x1a2b=['x'],_0x2b3c=1,_0x3c4d=2,_0x4d5e=3,_0x5e6f=4;\n"
        + ("/* block */\n" * 180)
        + 'fetch("/static/crypto.wasm");\n'
        + "WebAssembly.instantiateStreaming(fetch('/static/crypto.wasm'));\n"
    )
    receipt = {
        "receipt_id": "req-0042",
        "url": "https://app.test/static/opaque.js",
        "content_type": "application/javascript",
        "response_headers": {"Content-Type": "application/javascript"},
        "body": js_body,
    }
    summary = _extract_surface_summary(receipt, "https://app.test")

    tracker = SurfaceFrontierTracker(
        base_url="https://app.test/",
        allowed_methods=["GET", "POST"],
    )
    tracker.ingest_surface(summary, actor="anon")
    # Re-ingesting identical summary deduplicates slices cleanly
    tracker.ingest_surface(summary, actor="anon")
    assert len(tracker.opaque_js_slices) == len(
        summary["client_logic"]["opacity_assessment"]["opaque_regions"]
    )
    assert "/static/crypto.wasm" in tracker.opaque_wasm_refs
    # WASM refs must never pollute endpoint frontier routes
    assert all(".wasm" not in route for route in tracker.unvisited_routes())

    # Cap enforcement at 15 slices
    for idx in range(25):
        tracker.ingest_surface(
            {
                "receipt_id": f"req-cap-{idx}",
                "url": f"https://app.test/static/chunk-{idx}.js",
                "client_logic": {
                    "opacity_assessment": {
                        "status": "opaque_escalation_candidate",
                        "opaque_regions": [
                            {
                                "region_id": "decoder_preamble",
                                "anchor": "decoder_preamble",
                                "char_start": 0,
                                "char_end": 1500,
                                "reason": "obfuscator_string_array_decoder",
                                "recommended_action": "llm_reverse_engineer_slice",
                            }
                        ],
                    }
                },
            }
        )
    assert len(tracker.opaque_js_slices) == 15

    # Round-trip serialization via to_dict / from_dict / load_dict
    saved = tracker.to_dict()
    restored = SurfaceFrontierTracker.from_dict(saved)
    assert restored.opaque_js_slices == tracker.opaque_js_slices
    assert restored.opaque_wasm_refs == tracker.opaque_wasm_refs

    # Legacy checkpoint missing new keys restores cleanly
    legacy = {
        k: v
        for k, v in saved.items()
        if k not in {"opaque_js_slices", "opaque_wasm_refs"}
    }
    legacy_restored = SurfaceFrontierTracker.from_dict(legacy)
    assert legacy_restored.opaque_js_slices == []
    assert legacy_restored.opaque_wasm_refs == []

    # Banner surfaces read_receipt guidance and strictly respects max_chars without crowding primary routes
    restored.ingest_surface(
        {
            "url": "https://app.test/",
            "links": [{"method": "GET", "url": "https://app.test/api/v1/orders"}],
        }
    )
    banner = restored.format_frontier_banner(max_chars=1000)
    assert "/api/v1/orders" in banner
    assert "opaque_js:" in banner
    assert "read_receipt" in banner
    for budget in (1000, 300, 150, 40, 0):
        tight = restored.format_frontier_banner(max_chars=budget)
        assert len(tight) <= budget

    # Tight budget that only fits primary routes keeps primary route and drops/skips opaque_js rather than crowding it out
    tight_primary = restored.format_frontier_banner(max_chars=120)
    assert "/api/v1/orders" in tight_primary
    assert len(tight_primary) <= 120
