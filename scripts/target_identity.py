"""Canonical target identity: one key for plan, summaries, findings, ledger.

The same lab target was recorded as both ``192.168.2.1:8080`` and
``192.168.2.1`` and the finding store split on the mismatch. Every layer
must derive its key here instead of inventing its own spelling.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse, urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def finding_context(scope_revision: str) -> dict[str, str]:
    scope_file = os.environ.get("CCO_SCOPE_FILE", "")
    workdir = os.environ.get("CCO_WORKDIR", "")
    return {"engagement": os.environ.get("CCO_ENGAGEMENT_ID", "").strip(),
            "scope_file": str(Path(scope_file).expanduser().resolve()) if scope_file else "",
            "scope_revision": str(scope_revision or "scope:unknown"),
            "workdir": str(Path(workdir).expanduser().resolve()) if workdir else ""}


def finding_context_key(scope_revision: str) -> str:
    data = json.dumps(finding_context(scope_revision), ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()


def resource_identity(raw: str) -> str:
    """Conservative identity for a URL or bare host, retaining path and query.

    Equivalent explicit default ports collapse; schemes, non-default ports,
    case-sensitive paths and the exact query remain distinct. An invalid or
    ambiguous target has no deduplication identity.
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        if "://" in text:
            part = urlsplit(text)
            scheme = part.scheme.lower()
            if scheme not in {"http", "https"} or not part.hostname or part.username is not None:
                return ""
            host = part.hostname.lower()
            host = f"[{host}]" if ":" in host else host
            port = part.port
            authority = host + (f":{port}" if port and port != _DEFAULT_PORTS[scheme] else "")
            path = part.path or "/"
            return f"{scheme}://{authority}{path}" + (f"?{part.query}" if part.query else "")
        part = urlsplit("//" + text)
        if not part.hostname or part.username is not None or part.path or part.query or part.fragment:
            return ""
        host = part.hostname.lower()
        host = f"[{host}]" if ":" in host else host
        return "bare:" + host + (f":{part.port}" if part.port else "")
    except ValueError:
        return ""


def target_query_matches(query: str, stored: str) -> bool:
    """A bare-host lookup is broad; a URL lookup keeps origin and path limits."""
    if str(query or "").strip() and str(query).strip() == str(stored or "").strip():
        return True  # Historical opaque target labels remain retrievable.
    query_key, stored_key = resource_identity(query), resource_identity(stored)
    if not query_key or not stored_key:
        return False
    if query_key == stored_key:
        return True
    try:
        if query_key.startswith("bare:"):
            q = urlsplit("//" + query_key[5:])
            s = urlsplit("//" + stored_key[5:]) if stored_key.startswith("bare:") else urlsplit(stored_key)
            if q.hostname != s.hostname:
                return False
            if q.port is None:
                return True
            return q.port == (s.port or _DEFAULT_PORTS.get(s.scheme))
        if stored_key.startswith("bare:"):
            return False
        q, s = urlsplit(query_key), urlsplit(stored_key)
        if (q.scheme, q.netloc) != (s.scheme, s.netloc):
            return False
        if q.path in ("", "/") and not q.query:
            return True
        return q.path == s.path and (not q.query or q.query == s.query)
    except ValueError:
        return False


def canonical_target(raw: str) -> str:
    """Display form: scheme/host lowercased, path dropped, explicit port kept.

    Bare hosts (``10.0.0.5``, ``host:8443``) pass through with the host
    lowercased; no default port is invented for the display form.
    """
    text = (raw or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if not host:
            return text
        port = f":{parsed.port}" if parsed.port else ""
        return f"{scheme}://{host}{port}"
    host_part = text.split("/", 1)[0]
    if ":" in host_part and not host_part.startswith("["):
        host, _, port = host_part.rpartition(":")
        return f"{host.lower()}:{port}" if port.isdigit() else host_part.lower()
    return host_part.lower()


def target_key(raw: str) -> str:
    """Identity key: ``host:port`` with the scheme default port filled in.

    ``http://h`` and ``h`` spelled with the matching default port collapse
    to one key; a bare host with no scheme/port stays ``host`` so callers
    notice the missing port instead of guessing one.
    """
    text = (raw or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        host = (parsed.hostname or "").lower()
        if not host:
            return text.lower()
        port = parsed.port or _DEFAULT_PORTS.get(parsed.scheme.lower())
        return f"{host}:{port}" if port else host
    host_part = text.split("/", 1)[0]
    if ":" in host_part and not host_part.startswith("["):
        host, _, port_text = host_part.rpartition(":")
        if port_text.isdigit():
            return f"{host.lower()}:{port_text}"
    return host_part.lower()
