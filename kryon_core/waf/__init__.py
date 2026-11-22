"""Offline HTTP WAF/CDN signatures, fingerprinting, and classification."""
from __future__ import annotations

from .waf_profiles import (
    CDN_IP_PREFIXES,
    CDN_NETWORKS,
    WAF_ALIASES,
    WAF_EVASION_OPS,
    WAF_SIGNATURES,
    classify_http,
    fingerprint,
    fingerprint_channels,
    ip_is_cdn,
    known_waf_vendor,
    normalize_waf,
    waf_pref_bonus,
)

__all__ = [
    "CDN_IP_PREFIXES",
    "CDN_NETWORKS",
    "WAF_ALIASES",
    "WAF_EVASION_OPS",
    "WAF_SIGNATURES",
    "classify_http",
    "fingerprint",
    "fingerprint_channels",
    "ip_is_cdn",
    "known_waf_vendor",
    "normalize_waf",
    "waf_pref_bonus",
]
