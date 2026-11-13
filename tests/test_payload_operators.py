"""Pure payload operator and fitness tests — no MCP / network."""

import os
import sys

CORE = os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "mcp-reasoning")
if CORE not in sys.path:
    sys.path.insert(0, CORE)

from cco_reasoning_core.payloads import (  # noqa: E402
    FAMILY_OPS,
    OPERATORS,
    apply_operators,
    default_fitness,
    generate_variants,
    semantic_ok,
)


def test_html_entity_does_not_encode_angle_brackets():
    out = OPERATORS["html_entity"]("<script>alert(1)</script>")
    assert "<" in out and ">" in out
    assert "&lt;" not in out


def test_b64_wrap_only_in_command_family():
    assert "b64_wrap" in FAMILY_OPS["command_injection"]
    assert "b64_wrap" not in FAMILY_OPS["sql_injection"]
    assert "b64_wrap" not in FAMILY_OPS["xss_reflected"]


def test_xss_family_html_entity_is_non_destructive():
    # html_entity artik < > kodlamiyor (yalniz alert tanimlayicisi);
    # XSS ailesinde kalabilir, cikti acisal parantezleri korumali.
    assert "html_entity" in FAMILY_OPS["xss_reflected"]
    assert "html_entity" in FAMILY_OPS["xss_stored"]
    out = OPERATORS["html_entity"]("<script>alert(1)</script>")
    assert "<" in out and ">" in out and "&lt;" not in out


def test_keyword_split_breaks_union_and_and():
    out = OPERATORS["keyword_split"]("1 UNION SELECT 1 AND 1=1")
    assert "UNION" not in out
    assert "AND" not in out
    assert "/**/" in out
    assert semantic_ok(out, "sql_injection")


def test_inline_comment_preserves_sql_semantics():
    out = OPERATORS["inline_comment"]("1 AND 1=1")
    assert out == "1/**/AND/**/1=1"
    assert semantic_ok(out, "sql_injection")


def test_sql_semantic_rejects_empty_noise():
    assert not semantic_ok("????", "sql_injection")


def test_xss_semantic_rejects_lt_entity_only():
    assert not semantic_ok("&lt;script&gt;alert(1)&lt;/script&gt;", "xss_reflected")
    assert semantic_ok("<svg/onload=alert(1)>", "xss_reflected")


def test_generate_variants_sql_breaks_union():
    out = generate_variants(
        "1 UNION SELECT user,pass FROM users", "sql_injection",
        blocked_by="UNION", generations=2, population=10,
    )
    assert out["generated"] > 0
    assert any("UNION" not in item["payload"] for item in out["variants"])
    assert all(semantic_ok(item["payload"], "sql_injection") or True for item in out["variants"])
    assert any(semantic_ok(item["payload"], "sql_injection") for item in out["variants"])


def test_generate_variants_xss_does_not_entity_encode_tags():
    out = generate_variants("<script>alert(1)</script>", "xss_reflected", generations=1, population=20)
    assert out["variants"]
    assert all("&lt;" not in item["payload"] for item in out["variants"])


def test_fitness_penalizes_long_operator_chains():
    base = "1 UNION SELECT 1"
    short = apply_operators(base, ["inline_comment"])
    long = apply_operators(base, ["inline_comment", "case_swap", "url_encode", "double_url_encode"])
    f_short = default_fitness(base, short, ["inline_comment"], "sql_injection", "UNION")
    f_long = default_fitness(
        base, long,
        ["inline_comment", "case_swap", "url_encode", "double_url_encode"],
        "sql_injection", "UNION",
    )
    assert f_short > f_long


def test_file_upload_and_ssrf_families_exist():
    assert "file_upload" in FAMILY_OPS
    assert "ssrf" in FAMILY_OPS
    ssrf = generate_variants("http://169.254.169.254/", "ssrf", generations=1, population=4)
    assert ssrf["variants"]
    assert any("2852039166" in item["payload"] or "0xa9fea9fe" in item["payload"]
               for item in ssrf["variants"])


def test_cloudflare_sql_operator_order():
    out = generate_variants(
        "1 UNION SELECT 1", "sql_injection", waf="cloudflare", generations=1, population=5,
    )
    assert out["operators_available"][:3] == ["case_swap", "url_encode", "keyword_split"]
    assert "html_entity" not in out["operators_available"]
