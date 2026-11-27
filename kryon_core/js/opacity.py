"""Pure-stdlib JavaScript opacity and WASM assessment (Stage 0, 0-token).

Classifies fetched JS source as vendor-skipped, clear, partial opacity, or an
opaque escalation candidate, extracting bounded character-offset slices for
targeted LLM reverse-engineering via ``read_receipt`` without exposing secrets.
"""

from __future__ import annotations

import math
import re
from typing import Any
from urllib.parse import urlsplit

_MAX_SCAN_CHARS = 400_000
_MAX_ENTROPY_SCAN_CHARS = 200_000
_MIN_HIGH_ENTROPY = 4.6
_MIN_ENTROPY_LITERAL_LEN = 16
_ZERO_ROUTES_MIN_CHARS = 15_000
_MAX_WASM_REFS = 10

_VENDOR_URL_RE = re.compile(
    r"(?:^|[/._@-])("
    r"vendors?|chunk-vendors|polyfills?|react-dom|react\.production|"
    r"lodash|jquery|angular|vue\.runtime|monaco|three\.min|"
    r"core-js|chart\.min|d3\.min|moment\.min"
    r")(?:[/._~?-]|$|\b)",
    re.I,
)
_VENDOR_HEADER_RE = re.compile(
    r"(?:"
    r"/\*!\s*(?:React|jQuery|lodash|core-js|moment\.js|Chart\.js|three\.js|Vue\.js)\b"
    r"|@license\s+(?:React|Lodash|jQuery|Angular|Vue)\b"
    r"|jQuery\s+JavaScript\s+Library"
    r"|@angular/"
    r"|monaco-editor"
    r"|https?://lodash\.com/license"
    r"|https?://jquery\.org/license"
    r")",
    re.I,
)

_STRING_LITERAL_RE = re.compile(
    r'"((?:[^"\\\n]|\\.){16,2048})"|\'((?:[^\'\\\n]|\\.){16,2048})\''
)
_HEX_ESCAPE_RE = re.compile(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})")
_OBF_0X_RE = re.compile(r"\b_0x[0-9a-fA-F]{3,}\b")
_ROTATION_LOOP_RE = re.compile(r"\bwhile\s*\(|\(\s*function\s*\(")
_HEX_LITERAL_RE = re.compile(r"\b0x[0-9a-fA-F]+\b|\bparseInt\s*\(")
_EVAL_OR_FUNC_RE = re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\()")
_DECODE_OR_PACKED_RE = re.compile(
    r"\batob\s*\(|String\.fromCharCode\s*\(|function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\b"
)
_WASM_API_RE = re.compile(
    r"\bWebAssembly\.(?:instantiateStreaming|instantiate|compileStreaming|compile)\b"
)
_WASM_REF_RE = re.compile(
    r"""["'`]([^"'`\s\\]{1,200}\.wasm(?:\?[^"'`\s\\]{0,80})?)["'`]""",
    re.I,
)
_CUSTOM_TRANSPORT_CRYPTO_RE = re.compile(
    r"\bcrypto\.subtle\b|\bSubtleCrypto\b|\bcreateHmac\b|"
    r"(?i:grpc-web|application/grpc|\bprotobuf\b)|"
    r"\bUint8Array\b|\bDataView\b|\.setRequestHeader\s*\("
)
_TRANSPORT_SINK_RE = re.compile(
    r"\bfetch\s*\(|\bXMLHttpRequest\b|\baxios\b|\bWebSocket\b|"
    r"\bSubtleCrypto\b|\bcrypto\.subtle\b|\bWebAssembly\b|\.setRequestHeader\s*\("
)

_SIGNAL_WEIGHTS: dict[str, float] = {
    "obfuscator_0x_table": 0.45,
    "wasm_loader": 0.40,
    "zero_routes_with_transport_sink": 0.40,
    "dynamic_eval_packer": 0.35,
    "hex_escape_density": 0.30,
    "high_string_entropy": 0.30,
    "custom_transport_or_crypto": 0.25,
}
_ESCALATION_SIGNALS = frozenset({
    "wasm_loader",
    "obfuscator_0x_table",
    "zero_routes_with_transport_sink",
})

_ANCHOR_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(
            r"\bWebAssembly\.(?:instantiateStreaming|instantiate|compileStreaming|compile)\b"
            r"""|["'`]([^"'`\s\\]{1,200}\.wasm(?:\?[^"'`\s\\]{0,80})?)["'`]""",
            re.I,
        ),
        "WebAssembly.instantiate",
        "wasm_loader",
    ),
    (
        re.compile(
            r"\bcrypto\.subtle\b|\bSubtleCrypto\b|\bcreateHmac\b|(?i:grpc-web|application/grpc|\bprotobuf\b)"
        ),
        "crypto.subtle",
        "custom_crypto_or_rpc",
    ),
    (
        re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\()"),
        "eval",
        "dynamic_eval_packer",
    ),
    (
        re.compile(r"\.setRequestHeader\s*\(|\bfetch\s*\(|\bXMLHttpRequest\b|\baxios\b|\bWebSocket\b"),
        "transport_sink",
        "transport_sink",
    ),
    (
        re.compile(r"\b_0x[0-9a-fA-F]{3,}\s*\("),
        "_0x_call_cluster",
        "obfuscated_call_cluster",
    ),
)


def _shannon_entropy(text: str) -> float:
    """Return Shannon entropy in bits per character for ``text``."""
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _is_vendor_bundle(source: str, url: str) -> bool:
    """Return True if URL path or leading license banner identifies a third-party vendor library."""
    path = (urlsplit(url or "").path or url or "").strip()
    if path and _VENDOR_URL_RE.search(path):
        return True
    head = (source or "")[:1024]
    return bool(head and _VENDOR_HEADER_RE.search(head))


def _has_string_array_rotation(sample: str) -> bool:
    """Detect obfuscator string-array rotation loops (shift + push near _0x or hex lookup)."""
    if ".shift(" not in sample or ".push(" not in sample:
        return False
    for match in _ROTATION_LOOP_RE.finditer(sample):
        win = sample[max(0, match.start() - 250) : match.start() + 1000]
        if (
            ".shift(" in win
            and ".push(" in win
            and ("_0x" in win or _HEX_LITERAL_RE.search(win))
        ):
            return True
    return False


def _collect_signals(
    sample: str,
    *,
    full_len: int,
    endpoints_found: int,
) -> tuple[list[str], list[str]]:
    """Evaluate deterministic JS opacity signals and bounded WASM references."""
    signals: list[str] = []
    entropy_sample = sample[:_MAX_ENTROPY_SCAN_CHARS]

    high_count = 0
    high_chars = 0
    for match in _STRING_LITERAL_RE.finditer(entropy_sample):
        lit = match.group(1) if match.group(1) is not None else (match.group(2) or "")
        if len(lit) < _MIN_ENTROPY_LITERAL_LEN or lit.startswith("data:"):
            continue
        if _shannon_entropy(lit) >= _MIN_HIGH_ENTROPY:
            high_count += 1
            high_chars += len(lit)
            if high_count >= 3:
                break
    if high_count >= 3 or (high_count >= 2 and high_chars >= 64):
        signals.append("high_string_entropy")

    esc_matches = list(_HEX_ESCAPE_RE.finditer(entropy_sample))
    esc_count = len(esc_matches)
    if esc_count >= 25:
        esc_chars = sum(m.end() - m.start() for m in esc_matches)
        esc_ratio = esc_chars / max(1, len(entropy_sample))
        if esc_ratio >= 0.01 or esc_count >= 120:
            signals.append("hex_escape_density")

    obf_hits = 0
    for _ in _OBF_0X_RE.finditer(sample):
        obf_hits += 1
        if obf_hits >= 5:
            break
    if obf_hits >= 5 or _has_string_array_rotation(sample):
        signals.append("obfuscator_0x_table")

    if _EVAL_OR_FUNC_RE.search(sample) and _DECODE_OR_PACKED_RE.search(sample):
        signals.append("dynamic_eval_packer")

    wasm_refs: list[str] = []
    seen_refs: set[str] = set()
    for match in _WASM_REF_RE.finditer(sample):
        ref = match.group(1).strip()
        if ref and ref not in seen_refs:
            seen_refs.add(ref)
            wasm_refs.append(ref)
            if len(wasm_refs) >= _MAX_WASM_REFS:
                break
    if wasm_refs or _WASM_API_RE.search(sample):
        signals.append("wasm_loader")

    if _CUSTOM_TRANSPORT_CRYPTO_RE.search(sample):
        signals.append("custom_transport_or_crypto")

    if (
        full_len >= _ZERO_ROUTES_MIN_CHARS
        and int(endpoints_found) == 0
        and _TRANSPORT_SINK_RE.search(sample)
    ):
        signals.append("zero_routes_with_transport_sink")

    return signals, wasm_refs


def _anchor_label(match: re.Match[str], default_label: str) -> str:
    """Derive a concise anchor name from a regex match."""
    raw = match.group(0).strip()
    if default_label == "WebAssembly.instantiate":
        if ".wasm" in raw.lower():
            return "wasm_ref"
        return raw.split("(", 1)[0]
    if default_label == "crypto.subtle":
        return raw
    if default_label == "eval":
        return "new Function" if raw.startswith("new") else "eval"
    if default_label == "transport_sink":
        if "setRequestHeader" in raw:
            return "setRequestHeader"
        if "XMLHttpRequest" in raw:
            return "XMLHttpRequest"
        return raw.split("(", 1)[0].lstrip(".")
    return default_label


def _extract_opaque_regions(
    source: str,
    signals: list[str],
    *,
    max_regions: int,
    slice_chars: int,
) -> list[dict[str, Any]]:
    """Extract non-overlapping bounded offset windows around decoder and sink anchors."""
    source_len = len(source)
    if source_len == 0 or max_regions <= 0 or slice_chars <= 0:
        return []

    regions: list[dict[str, Any]] = []
    used_ranges: list[tuple[int, int]] = []

    def _add_region(
        region_id: str,
        anchor: str,
        start: int,
        end: int,
        reason: str,
    ) -> None:
        regions.append({
            "region_id": region_id,
            "anchor": anchor,
            "char_start": start,
            "char_end": end,
            "reason": reason,
            "recommended_action": "llm_reverse_engineer_slice",
        })
        used_ranges.append((start, end))

    if "obfuscator_0x_table" in signals:
        _add_region(
            "decoder_preamble",
            "decoder_preamble",
            0,
            min(source_len, slice_chars),
            "obfuscator_string_array_decoder",
        )

    scan_text = source[:_MAX_SCAN_CHARS]
    candidates: list[tuple[int, int, str, str]] = []
    for tier, (pattern, default_label, reason) in enumerate(_ANCHOR_PATTERNS):
        hits = 0
        for match in pattern.finditer(scan_text):
            candidates.append((tier, match.start(), _anchor_label(match, default_label), reason))
            hits += 1
            if hits >= 20:
                break

    half = slice_chars // 2
    for _tier, pos, anchor, reason in candidates:
        if len(regions) >= max_regions:
            break
        if any(es <= pos < ee for es, ee in used_ranges):
            continue
        start = max(0, pos - half)
        end = min(source_len, start + slice_chars)
        if end - start < slice_chars and start > 0:
            start = max(0, end - slice_chars)

        for es, ee in used_ranges:
            if start < ee and end > es:
                if pos >= ee:
                    start = max(start, ee)
                    end = min(source_len, start + slice_chars)
                elif pos < es:
                    end = min(end, es)
                    start = max(0, end - slice_chars)
        for es, ee in used_ranges:
            if start < ee and end > es:
                if pos >= ee:
                    start = max(start, ee)
                elif pos < es:
                    end = min(end, es)
                else:
                    start = end
                    break

        if not (start <= pos < end):
            continue
        if end - start > slice_chars:
            end = start + slice_chars
        min_keep = min(80, source_len - start)
        if end - start < max(40, min_keep) and source_len >= 40:
            continue
        if any(start < ee and end > es for es, ee in used_ranges):
            continue

        _add_region(f"region_{len(regions)}", anchor, start, end, reason)

    if not regions:
        _add_region(
            "region_0",
            "bundle_head",
            0,
            min(source_len, slice_chars),
            "opaque_bundle_sample",
        )

    return regions[:max_regions]


def _opacity_gap(code: str, detail: str) -> dict[str, Any]:
    """Build a machine-readable NOT TESTED coverage gap matching parsers._coverage_gap."""
    clean_detail = detail[:240]
    return {
        "code": code,
        "reason_code": code,
        "id": code,
        "status": "NOT TESTED",
        "detail": clean_detail,
        "message": clean_detail,
        "parser": "opacity",
        "ast_available": False,
    }


def assess_js_opacity(
    source: str,
    *,
    url: str = "",
    endpoints_found: int = 0,
    max_regions: int = 5,
    slice_chars: int = 1500,
) -> dict[str, Any]:
    """Assess JavaScript opacity and extract bounded reverse-engineering slices (0-token)."""
    text = source or ""
    if not text.strip():
        return {
            "status": "clear",
            "vendor_filtered": False,
            "opacity_score": 0.0,
            "signals": [],
            "wasm_refs": [],
            "opaque_regions": [],
            "coverage_gaps": [],
        }

    if _is_vendor_bundle(text, url):
        return {
            "status": "vendor_skip",
            "vendor_filtered": True,
            "opacity_score": 0.0,
            "signals": [],
            "wasm_refs": [],
            "opaque_regions": [],
            "coverage_gaps": [],
        }

    sample = text[:_MAX_SCAN_CHARS]
    signals, wasm_refs = _collect_signals(
        sample,
        full_len=len(text),
        endpoints_found=int(endpoints_found),
    )

    raw_score = sum(_SIGNAL_WEIGHTS.get(sig, 0.2) for sig in signals)
    opacity_score = round(min(1.0, raw_score), 2)

    is_escalation = bool(_ESCALATION_SIGNALS.intersection(signals)) or (
        opacity_score >= 0.55 and len(signals) >= 2
    )
    if is_escalation:
        status = "opaque_escalation_candidate"
    elif signals:
        status = "partial_opacity"
    else:
        status = "clear"

    opaque_regions: list[dict[str, Any]] = []
    if is_escalation:
        opaque_regions = _extract_opaque_regions(
            text,
            signals,
            max_regions=max(0, int(max_regions)),
            slice_chars=max(1, int(slice_chars)),
        )

    coverage_gaps: list[dict[str, Any]] = []
    if is_escalation:
        coverage_gaps.append(
            _opacity_gap(
                "opaque_js_bundle",
                f"Opaque JS bundle (score={opacity_score:.2f}, signals={','.join(signals)}): static extraction incomplete",
            )
        )
    if wasm_refs or "wasm_loader" in signals:
        coverage_gaps.append(
            _opacity_gap(
                "wasm_module_not_executed",
                f"WebAssembly loader/module referenced ({len(wasm_refs)} ref(s)); WASM binary logic not executed",
            )
        )

    return {
        "status": status,
        "vendor_filtered": False,
        "opacity_score": opacity_score,
        "signals": signals,
        "wasm_refs": wasm_refs,
        "opaque_regions": opaque_regions,
        "coverage_gaps": coverage_gaps,
    }
