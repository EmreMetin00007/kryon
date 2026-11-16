"""Bounded declarations and controls for synthetic application file reads.

This module does not open files or make requests. An endpoint declaration is
not evidence: baseline, direct-name, missing-file and repeat controls are still
required by the validator.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

_SEGMENT = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_SECRET_DIRS = {".ssh", ".aws", ".gnupg", ".cco", ".kube", ".docker"}
_SECRET_FILES = {"passwd", "shadow", "credential_vault.db"}


def endpoint_key(url):
    try:
        if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 32 for c in url):
            raise ValueError("invalid traversal endpoint")
        parsed = urlsplit(url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None or parsed.fragment):
            raise ValueError("invalid traversal endpoint")
        return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80), parsed.path or "/"
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid traversal endpoint") from exc


def _validate_application_files_rule(rule, permits):
    if (not isinstance(rule, dict) or set(rule) != {"mode", "files"}
            or rule.get("mode") != "application_files" or not isinstance(rule.get("files"), list)
            or not 1 <= len(rule["files"]) <= 32):
        raise ValueError("declared traversal test files unavailable")
    seen = set()
    entries = []
    for row in rule["files"]:
        if (not isinstance(row, dict) or set(row) != {"url", "param", "carrier", "path", "marker", "test_data_only", "outside_root"}
                or row.get("test_data_only") is not True or row.get("outside_root") is not True
                or row.get("carrier") not in {"query", "path"}
                or not isinstance(row.get("param"), str) or not _SEGMENT.fullmatch(row["param"])):
            raise ValueError("declared traversal test files unavailable")
        declared_url = row["url"]
        declared = endpoint_key(declared_url)
        if urlsplit(declared_url).query or not permits(declared_url):
            raise ValueError("declared traversal test files unavailable")
        path, marker = row["path"], row["marker"]
        if (not isinstance(path, str) or len(path) > 256
                or not isinstance(marker, str) or not 16 <= len(marker) <= 512
                or any(ord(c) < 32 for c in marker) or marker in path):
            raise ValueError("declared traversal test files unavailable")
        parts = path.split("/")
        parents = 0
        while parents < len(parts) and parts[parents] == "..":
            parents += 1
        tail = parts[parents:]
        if (not 1 <= parents <= 8 or not 1 <= len(tail) <= 8
                or any(not _SEGMENT.fullmatch(p) or p in {".", ".."} for p in tail)
                or any(p.lower().startswith(".env") or p.lower() in _SECRET_DIRS | _SECRET_FILES
                       or p.lower().endswith((".pem", ".key", ".p12", ".pfx")) for p in tail)):
            raise ValueError("declared traversal test files unavailable")
        key = declared, row["param"], row["carrier"], path
        if key in seen:
            raise ValueError("declared traversal test files unavailable")
        seen.add(key)
        entries.append((declared, row["param"], row["carrier"], path, marker))
    return entries


def application_files(rule, url, param, carrier, permits):
    if not permits(url):
        raise ValueError("declared traversal test files unavailable")
    entries = _validate_application_files_rule(rule, permits)
    expected = endpoint_key(url)
    selected = [
        {"path": path, "marker": marker}
        for declared, row_param, row_carrier, path, marker in entries
        if (declared, row_param, row_carrier) == (expected, param, carrier)
    ]
    if not 1 <= len(selected) <= 2:
        raise ValueError("declared traversal test files unavailable")
    return selected


def check_traversal_policy_eligibility(rule, url, param, carrier, permits):
    """Return opaque eligibility boolean and controlled reason code; never expose paths or markers."""
    if rule is None or rule == {}:
        return {"eligible": False, "reason_code": "traversal_policy_not_declared"}
    try:
        entries = _validate_application_files_rule(rule, permits)
        if not permits(url):
            return {"eligible": False, "reason_code": "traversal_policy_invalid"}
        expected = endpoint_key(url)
    except (ValueError, TypeError, KeyError):
        return {"eligible": False, "reason_code": "traversal_policy_invalid"}
    matches = [
        1 for declared, row_param, row_carrier, _path, _marker in entries
        if (declared, row_param, row_carrier) == (expected, param, carrier)
    ]
    if not 1 <= len(matches) <= 2:
        return {"eligible": False, "reason_code": "traversal_policy_not_declared"}
    return {"eligible": True, "reason_code": ""}


def baseline_sample(url, param, carrier, supplied=""):
    values = [v for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True) if k == param]
    if (carrier == "query" and len(values) > 1) or (carrier == "path" and url.count("{" + param + "}") != 1):
        raise ValueError("observed traversal baseline value unavailable")
    if supplied:
        value = supplied
    elif carrier == "query" and param:
        if len(values) != 1:
            raise ValueError("observed traversal baseline value unavailable")
        value = values[0]
    else:
        raise ValueError("observed traversal baseline value unavailable")
    if (not isinstance(value, str) or not value or len(value) > 2048
            or any(c in value for c in "\r\n\x00") or value in {"<redacted>", "<unavailable>"}):
        raise ValueError("observed traversal baseline value unavailable")
    return value


def usable_response(response, *, baseline=False):
    statuses = {200, 206} if baseline else {200, 206, 400, 403, 404}
    return bool(response.get("ok") and response.get("status") in statuses)


def missing_file_path(path, token):
    directory, name = path.rsplit("/", 1)
    suffix = "." + name.rsplit(".", 1)[1] if "." in name else ""
    return f"{directory}/cco-missing-{token}{suffix}"
