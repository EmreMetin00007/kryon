"""Hunter vulnerability metadata and class normalization."""

import re


VULN_IMPACT = {
    "rce": 1.0, "command_injection": 1.0, "deserialization": 0.95, "ssti": 0.95,
    "sql_injection": 0.9, "bola": 0.85, "idor": 0.8, "bfla": 0.85, "mass_assignment": 0.85,
    "authentication_bypass": 0.85, "privilege_escalation": 0.85, "business_logic": 0.8,
    "price_manipulation": 0.85, "race_condition": 0.8, "file_upload": 0.85,
    "lfi": 0.75, "path_traversal": 0.75, "ssrf": 0.75, "xxe": 0.7, "jwt_attack": 0.7,
    "xss_stored": 0.7, "broken_access_control": 0.85, "workflow_bypass": 0.7,
    "xss_reflected": 0.5, "cors_misconfiguration": 0.5, "open_redirect": 0.35,
    "csrf": 0.45, "subdomain_takeover": 0.6, "info_disclosure": 0.4,
}

VULN_LIKELIHOOD = {
    "info_disclosure": 0.6, "idor": 0.55, "bola": 0.55, "open_redirect": 0.5,
    "xss_reflected": 0.5, "business_logic": 0.5, "mass_assignment": 0.45, "bfla": 0.45,
    "sql_injection": 0.45, "ssti": 0.4, "cors_misconfiguration": 0.45, "jwt_attack": 0.4,
    "price_manipulation": 0.5, "race_condition": 0.35, "ssrf": 0.4, "lfi": 0.4,
    "path_traversal": 0.4, "file_upload": 0.4, "xxe": 0.35, "deserialization": 0.3,
    "rce": 0.3, "command_injection": 0.35, "authentication_bypass": 0.4,
    "workflow_bypass": 0.45, "broken_access_control": 0.55, "subdomain_takeover": 0.4,
}

VALIDATE_WITH = {
    "sql_injection": "mcp__validator__validate_sqli", "ssti": "mcp__validator__validate_ssti",
    "command_injection": "mcp__validator__validate_command_injection",
    "rce": "mcp__validator__validate_command_injection",
    "lfi": "mcp__validator__validate_path_traversal",
    "path_traversal": "mcp__validator__validate_path_traversal",
    "xss_reflected": "mcp__validator__validate_xss_reflection",
    "xss_stored": "mcp__validator__validate_xss_reflection",
    "open_redirect": "mcp__validator__validate_open_redirect",
    "ssrf": "mcp__validator__validate_ssrf_oob", "xxe": "mcp__validator__validate_xxe",
    "idor": "mcp__validator__validate_idor", "bola": "mcp__validator__validate_idor",
    "bfla": "mcp__validator__validate_auth_bypass",
    "authentication_bypass": "mcp__validator__validate_auth_bypass",
    "broken_access_control": "mcp__hunter__analyze_authz_result",
    "business_logic": "manuel diferansiyel doğrulama (beklenen vs gözlenen)",
    "price_manipulation": "manuel: sipariş toplamını/ödemeyi doğrula",
    "race_condition": "manuel: eşzamanlı istek + tekil-kaynak sayacı",
    "mass_assignment": "manuel: yanıtta enjekte edilen ayrıcalıklı alanı doğrula",
}

SKILL_FOR = {
    "sql_injection": "/web-exploit", "ssti": "/web-exploit", "lfi": "/web-exploit",
    "path_traversal": "/web-exploit", "command_injection": "/web-exploit", "rce": "/web-exploit",
    "file_upload": "/web-exploit", "xss_reflected": "/web-exploit", "xss_stored": "/web-exploit",
    "idor": "/access-control-hunting", "bola": "/access-control-hunting",
    "bfla": "/access-control-hunting", "broken_access_control": "/access-control-hunting",
    "mass_assignment": "/access-control-hunting", "business_logic": "/access-control-hunting",
    "price_manipulation": "/access-control-hunting", "race_condition": "/access-control-hunting",
    "workflow_bypass": "/access-control-hunting", "privilege_escalation": "/access-control-hunting",
    "jwt_attack": "/web-advanced", "cors_misconfiguration": "/web-advanced",
    "xxe": "/web-advanced", "open_redirect": "/web-advanced", "deserialization": "/web-advanced",
    "authentication_bypass": "/web-advanced", "ssrf": "/cloud-exploitation",
    "subdomain_takeover": "/attack-surface-mapping", "info_disclosure": "/attack-surface-mapping",
}

CLASS_SYNONYMS = [
    ("sql", "sql_injection"), ("sqli", "sql_injection"), ("bola", "bola"),
    ("broken object", "bola"), ("broken function", "bfla"), ("bfla", "bfla"),
    ("idor", "idor"), ("insecure direct", "idor"), ("mass assign", "mass_assignment"),
    ("business logic", "business_logic"), ("price", "price_manipulation"),
    ("race", "race_condition"), ("workflow", "workflow_bypass"),
    ("privilege", "privilege_escalation"), ("priv esc", "privilege_escalation"),
    ("access control", "broken_access_control"), ("ssti", "ssti"),
    ("template injection", "ssti"), ("command inj", "command_injection"),
    ("os command", "command_injection"), ("remote code", "rce"), ("ssrf", "ssrf"),
    ("xxe", "xxe"), ("path traversal", "path_traversal"), ("directory traversal", "path_traversal"),
    ("lfi", "lfi"), ("file inclusion", "lfi"), ("file upload", "file_upload"),
    ("stored xss", "xss_stored"), ("reflected xss", "xss_reflected"), ("xss", "xss_reflected"),
    ("open redirect", "open_redirect"), ("cors", "cors_misconfiguration"),
    ("jwt", "jwt_attack"), ("deserial", "deserialization"), ("auth bypass", "authentication_bypass"),
    ("authentication bypass", "authentication_bypass"), ("subdomain takeover", "subdomain_takeover"),
    ("disclosure", "info_disclosure"), ("leak", "info_disclosure"),
]


def impact(vulnerability):
    return VULN_IMPACT.get(vulnerability, 0.5)


def expected_value(vulnerability):
    return round(VULN_LIKELIHOOD.get(vulnerability, 0.4) * impact(vulnerability), 4)


def validator_hook(vulnerability):
    return VALIDATE_WITH.get(vulnerability, "mcp__validator__validate_finding")


def normalize_class(value):
    low = (value or "").strip().lower()
    for needle, key in CLASS_SYNONYMS:
        if needle in low:
            return key
    return re.sub(r"[^a-z0-9]+", "_", low).strip("_")
