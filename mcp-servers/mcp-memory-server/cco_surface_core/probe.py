"""httpx-style response fingerprint: title, tech, body hash."""

from __future__ import annotations

import hashlib
import re

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
TECH_HINTS = (
    "wordpress", "wp-json", "php", "nginx", "apache", "express", "flask",
    "django", "laravel", "graphql", "jwt", "tomcat", "iis", "next.js",
    "react", "vue", "spring", "asp.net", "cloudflare",
)
HEADER_TECH = {
    "server": None,
    "x-powered-by": None,
    "x-aspnet-version": "asp.net",
    "x-generator": None,
}


def fingerprint_response(url: str = "", status=None, headers=None, body=b"") -> dict:
    """Build a compact probe record from one HTTP response."""
    headers = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    if isinstance(body, str):
        raw = body.encode("utf-8", "replace")
        text = body
    else:
        raw = body or b""
        text = raw.decode("utf-8", "replace")
    title_m = TITLE_RE.search(text or "")
    title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:180] if title_m else ""
    tech = []
    blob = " ".join([
        headers.get("server", ""),
        headers.get("x-powered-by", ""),
        headers.get("content-type", ""),
        url or "",
        text[:4000],
    ]).lower()
    for header, mapped in HEADER_TECH.items():
        value = headers.get(header) or ""
        if not value:
            continue
        token = mapped or re.split(r"[/\s]", value, maxsplit=1)[0]
        token = token.strip().lower()
        if token and token not in tech:
            tech.append(token[:40])
    for name in TECH_HINTS:
        label = "wordpress" if name == "wp-json" else name
        if name in blob and label not in tech:
            tech.append(label)
    status_i = None
    try:
        status_i = int(status) if status not in (None, "") else None
    except (TypeError, ValueError):
        status_i = None
    auth = None
    if status_i in (401, 403):
        auth = 1
    elif headers.get("www-authenticate") or headers.get("set-cookie"):
        auth = 1
    return {
        "url": url,
        "status": status_i,
        "content_type": (headers.get("content-type") or "")[:160],
        "title": title,
        "body_len": len(raw),
        "body_hash": hashlib.sha256(raw[:65536]).hexdigest()[:16],
        "tech": tech[:12],
        "auth_required": auth,
    }
