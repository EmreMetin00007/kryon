"""Endpoint-to-vulnerability coverage policy."""

import re


ENDPOINT_CLASS_HINTS = [
    (r"(login|signin|auth|session|password|reset|register|sso|oauth)",
     ["authentication_bypass", "business_logic", "sql_injection", "open_redirect"]),
    (r"(admin|manage|internal|console|dashboard|config|settings)",
     ["bfla", "broken_access_control", "privilege_escalation", "idor"]),
    (r"(/api/|/v\d+/|graphql|\.json)",
     ["bola", "bfla", "mass_assignment", "idor", "info_disclosure"]),
    (r"[?&](id|uid|user_id|account|order|invoice|doc|file|pid|oid|ref)=|/\d+(/|$)",
     ["idor", "bola", "sql_injection"]),
    (r"(search|query|q=|filter|sort|category)",
     ["sql_injection", "xss_reflected", "ssti"]),
    (r"(upload|import|file|attachment|avatar|image)",
     ["file_upload", "path_traversal", "xxe"]),
    (r"(redirect|return|next|url=|callback|continue|dest)",
     ["open_redirect", "ssrf"]),
    (r"(cart|checkout|order|payment|pay|invoice|coupon|price|product|subscribe|plan)",
     ["price_manipulation", "business_logic", "race_condition", "workflow_bypass", "idor"]),
    (r"(fetch|proxy|webhook|import|preview|render|pdf|image_url)",
     ["ssrf", "xxe"]),
]

CORE_CLASS_GROUPS = {
    "access_control": ["idor", "bola", "bfla", "broken_access_control", "privilege_escalation"],
    "business_logic": ["business_logic", "price_manipulation", "race_condition", "workflow_bypass", "mass_assignment"],
    "injection": ["sql_injection", "command_injection", "ssti", "xxe", "lfi", "path_traversal"],
    "client_side": ["xss_reflected", "xss_stored", "cors_misconfiguration", "open_redirect"],
    "server_side": ["ssrf", "rce", "deserialization", "file_upload"],
}


def relevant_classes(url):
    classes = set()
    for pattern, candidates in ENDPOINT_CLASS_HINTS:
        if re.search(pattern, url, re.I):
            classes.update(candidates)
    if not classes:
        classes.update(["xss_reflected", "idor", "info_disclosure"])
    return classes
