"""Reasoning technique priors, impact, tool routing, and normalization."""

import re


TECHNIQUE_SUCCESS_PROBS = {
    "sql_injection": 0.85, "sql_injection_blind": 0.65, "xss_stored": 0.90,
    "xss_reflected": 0.80, "xss_dom": 0.70, "rce": 0.95, "command_injection": 0.90,
    "ssrf": 0.70, "ssrf_blind": 0.50, "idor": 0.80, "lfi": 0.75, "rfi": 0.60,
    "file_upload": 0.65, "ssti": 0.75, "xxe": 0.70, "deserialization": 0.60,
    "buffer_overflow": 0.55, "authentication_bypass": 0.70, "privilege_escalation": 0.65,
    "default_credentials": 0.90, "weak_credentials": 0.80, "credential_reuse": 0.75,
    "subdomain_takeover": 0.85, "cors_misconfiguration": 0.60, "open_redirect": 0.50,
    "csrf": 0.55, "jwt_attack": 0.65, "path_traversal": 0.70,
}

TECH_IMPACT = {
    "rce": 1.0, "command_injection": 1.0, "deserialization": 0.95, "ssti": 0.95,
    "sql_injection": 0.9, "default_credentials": 0.9, "authentication_bypass": 0.85,
    "file_upload": 0.85, "lfi": 0.75, "path_traversal": 0.75, "ssrf": 0.7, "xxe": 0.7,
    "idor": 0.7, "jwt_attack": 0.7, "xss_stored": 0.7, "subdomain_takeover": 0.6,
    "privilege_escalation": 0.8, "xss_reflected": 0.5, "cors_misconfiguration": 0.4,
    "csrf": 0.4, "open_redirect": 0.3,
}

TECH_EFFORT = {
    "default_credentials": 0.1, "open_redirect": 0.15, "idor": 0.25, "sql_injection": 0.3,
    "xss_reflected": 0.3, "ssti": 0.35, "lfi": 0.35, "path_traversal": 0.35,
    "command_injection": 0.4, "ssrf": 0.45, "xxe": 0.45, "authentication_bypass": 0.4,
    "rce": 0.5, "file_upload": 0.5, "jwt_attack": 0.5, "deserialization": 0.75,
    "buffer_overflow": 0.85,
}

RECOMMENDED_TOOL = {
    "sql_injection": "mcp__kali-tools__sqlmap_test_structured",
    "command_injection": "mcp__kali-tools__generate_exploit_poc",
    "rce": "mcp__kali-tools__generate_exploit_poc",
    "ssti": "mcp__kali-tools__generate_exploit_poc",
    "ssrf": "mcp__kali-tools__interactsh_start (OOB)",
    "xxe": "mcp__kali-tools__interactsh_start (OOB)",
    "idor": "mcp__web-advanced__api_idor_matrix",
    "lfi": "mcp__kali-tools__ffuf_fuzz + manuel payload",
    "path_traversal": "mcp__kali-tools__ffuf_fuzz",
    "jwt_attack": "mcp__web-advanced__jwt_analyze",
    "default_credentials": "mcp__kali-tools__hydra_brute",
    "open_redirect": "manuel curl",
    "authentication_bypass": "mcp__web-advanced__*",
}

VALIDATE_WITH = {
    "sql_injection": "mcp__validator__validate_sqli",
    "sql_injection_blind": "mcp__validator__validate_sqli",
    "ssti": "mcp__validator__validate_ssti",
    "command_injection": "mcp__validator__validate_command_injection",
    "rce": "mcp__validator__validate_command_injection",
    "lfi": "mcp__validator__validate_path_traversal",
    "path_traversal": "mcp__validator__validate_path_traversal",
    "xss_reflected": "mcp__validator__validate_xss_reflection",
    "xss_stored": "mcp__validator__validate_xss_reflection",
    "open_redirect": "mcp__validator__validate_open_redirect",
    "ssrf": "mcp__validator__validate_ssrf_oob",
    "ssrf_blind": "mcp__validator__validate_ssrf_oob",
    "xxe": "mcp__validator__validate_xxe",
    "idor": "mcp__validator__validate_idor",
    "authentication_bypass": "mcp__validator__validate_auth_bypass",
}

SEVERITY_IMPACT = {
    "critical": 1.0, "high": 0.8, "medium": 0.5,
    "low": 0.3, "info": 0.1,
}

_SYN = [
    ("sql injection", "sql_injection"), ("sqli", "sql_injection"),
    ("blind sql", "sql_injection_blind"), ("os command", "command_injection"),
    ("command injection", "command_injection"), ("remote code", "rce"),
    ("server-side template", "ssti"), ("template injection", "ssti"),
    ("path traversal", "path_traversal"), ("directory traversal", "path_traversal"),
    ("file inclusion", "lfi"), ("local file", "lfi"), ("cross-site scripting", "xss_reflected"),
    ("reflected xss", "xss_reflected"), ("stored xss", "xss_stored"), ("dom xss", "xss_dom"),
    ("insecure direct object", "idor"), ("server-side request", "ssrf"),
    ("xml external", "xxe"), ("open redirect", "open_redirect"),
    ("auth bypass", "authentication_bypass"), ("authentication bypass", "authentication_bypass"),
    ("default cred", "default_credentials"), ("weak cred", "weak_credentials"),
    ("jwt", "jwt_attack"), ("deserial", "deserialization"), ("file upload", "file_upload"),
    ("subdomain takeover", "subdomain_takeover"), ("cors", "cors_misconfiguration"),
    ("privilege escal", "privilege_escalation"), ("priv esc", "privilege_escalation"),
]


def normalize_tech(value: str) -> str:
    low = (value or "").strip().lower()
    for needle, key in _SYN:
        if needle in low:
            return key
    norm = re.sub(r"[^a-z0-9]+", "_", low).strip("_")
    return norm or "unknown"
