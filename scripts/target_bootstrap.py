"""Stdlib-only target origin bootstrap, credentials loading, and scope guard."""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch, fnmatchcase
import ipaddress
import json
import os
from pathlib import Path
import posixpath
import re
import socket
import stat
from typing import Any, Callable, Sequence
from urllib.parse import unquote, urljoin, urlsplit

_ADMIN_ROLES = frozenset({"platform_admin", "tenant_admin", "admin", "superadmin"})
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HOST_GLOB_LABEL_RE = re.compile(r"^[a-z0-9*?](?:[a-z0-9-*?]{0,61}[a-z0-9*?])?$")
_GLOB_CHARS = frozenset("*?[")
_HOST_GLOB_CHARS = frozenset("*?")
_CGNAT_NETWORK = ipaddress.IPv4Network((0x64400000, 10))

# Executable/handler endpoint extensions stripped from the final path segment when
# classifying operational lifecycle and logout routes (deliberately excluding static
# asset extensions such as .css/.js/.png so assets like reboot.css never false-positive).
_ROUTE_ENDPOINT_EXTENSIONS: frozenset[str] = frozenset({
    ".html",
    ".htm",
    ".php",
    ".json",
    ".asp",
    ".aspx",
    ".jsp",
    ".do",
    ".action",
    ".cgi",
    ".shtml",
    ".cfm",
    ".xml",
    ".ashx",
    ".asmx",
})

# Exact normalized path segments (underscores normalized to hyphens) identifying
# destructive service/database lifecycle endpoints blocked fail-closed by default.
DESTRUCTIVE_LIFECYCLE_SEGMENTS: frozenset[str] = frozenset({
    "reboot",
    "restart",
    "shutdown",
    "shut-down",
    "poweroff",
    "power-off",
    "halt",
    "kill",
    "terminate",
    "stop-server",
    "stopserver",
    "restart-server",
    "restartserver",
    "reboot-server",
    "rebootserver",
    "factory-reset",
    "factoryreset",
    "reset-db",
    "resetdb",
    "db-reset",
    "reset-database",
    "drop-db",
    "dropdb",
    "db-drop",
    "drop-database",
    "wipe",
    "wipe-db",
    "wipedb",
    "db-wipe",
    "wipe-database",
})

# Exact final path segments (after optional endpoint-extension stripping) identifying
# session-teardown endpoints guarded for shared authenticated actors.
LOGOUT_ROUTE_SEGMENTS: frozenset[str] = frozenset({
    "logout",
    "signout",
    "sign-out",
    "log-out",
    "sign_out",
    "log_out",
})


def normalize_loopback_origin(raw_url: str) -> str:
    """Validate and normalize an explicit owned loopback origin URL."""
    raw = str(raw_url or "").strip()
    if not raw:
        raise ValueError("target URL is required")
    parsed = urlsplit(raw)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
        raise ValueError("external target must be an explicit http://127.0.0.1:<port>/ origin")
    if parsed.path not in {"", "/"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("external target must be a clean origin without path, credentials, query, or fragment")
    return f"http://127.0.0.1:{parsed.port}/"


def load_credentials_bundle(path: Path | None) -> dict[str, Any]:
    """Load public target metadata and synthetic test accounts from an operator bundle."""
    if path is None:
        return {}
    data = json.loads(Path(path).expanduser().resolve(strict=True).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("credentials file must be a JSON object")
    return data


def _has_account_auth(row: dict[str, Any]) -> bool:
    """Return True when an account has a password or pre-authenticated session material."""
    if row.get("password"):
        return True
    for str_key in ("access_token", "bearer_token", "session_token", "auth_header", "cookie"):
        val = row.get(str_key)
        if isinstance(val, str) and val.strip():
            return True
    for map_key in ("headers", "cookies", "local_storage"):
        val = row.get(map_key)
        if isinstance(val, dict) and any(
            str(k or "").strip() and v is not None and str(v) != ""
            for k, v in val.items()
        ):
            return True
    return False


def select_representative_accounts(
    accounts: Sequence[dict[str, Any]],
    *,
    max_members: int = 4,
    max_admins: int = 1,
) -> list[dict[str, Any]]:
    """Select bounded synthetic accounts spanning tenants, roles, and peer comparisons."""
    cleaned = [
        dict(row)
        for row in accounts
        if isinstance(row, dict) and str(row.get("alias") or "").strip() and _has_account_auth(row)
    ]
    if max_members < 0 or max_admins < 0:
        raise ValueError("account limits must be non-negative")
    admins = [row for row in cleaned if str(row.get("role") or "").lower() in _ADMIN_ROLES]
    members = [row for row in cleaned if str(row.get("role") or "").lower() not in _ADMIN_ROLES]

    selected_members: list[dict[str, Any]] = []
    seen_tenants: set[str] = set()
    seen_roles: set[str] = set()
    # First pass: maximize role and tenant diversity; second pass: keep same-tenant peers for BOLA.
    for row in members:
        if len(selected_members) >= max_members:
            break
        tenant = str(row.get("tenant") or "")
        role = str(row.get("role") or "")
        if tenant not in seen_tenants or role not in seen_roles:
            selected_members.append(row)
            seen_tenants.add(tenant)
            seen_roles.add(role)
    for row in members:
        if len(selected_members) >= max_members:
            break
        if row not in selected_members:
            selected_members.append(row)

    selected_admins = admins[:max_admins]
    return [*selected_members, *selected_admins]


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _canonicalize_host(host: str) -> str:
    """Normalize a validated host or IPv6 literal to canonical lowercase/compressed form."""
    clean = host.strip().lower().rstrip(".")
    if clean.startswith("[") and clean.endswith("]") and ":" in clean:
        clean = clean[1:-1]
    if ":" in clean and "%" not in clean:
        try:
            addr = ipaddress.ip_address(clean)
            return addr.compressed
        except ValueError:
            return clean
    return clean


def _is_valid_host(host: str) -> bool:
    clean = host.strip().lower().rstrip(".")
    if not clean or any(ch.isspace() or ord(ch) < 32 for ch in clean):
        return False
    if ":" in clean:
        if "%" in clean:
            return False
        try:
            return isinstance(ipaddress.ip_address(clean), ipaddress.IPv6Address)
        except ValueError:
            return False
    labels = clean.split(".")
    return all(bool(_HOST_LABEL_RE.match(label)) for label in labels)


def _is_valid_host_pattern(pattern: str) -> bool:
    """Return True if ``pattern`` is a valid exact host, IPv6 literal, or safe DNS glob pattern."""
    clean = pattern.strip().lower().rstrip(".")
    if not clean or any(ch.isspace() or ord(ch) < 32 for ch in clean):
        return False
    if "[" in clean or "]" in clean:
        return False
    if ":" in clean:
        if any(ch in _HOST_GLOB_CHARS for ch in clean):
            return False
        return _is_valid_host(clean)
    if not any(ch in _HOST_GLOB_CHARS for ch in clean):
        return _is_valid_host(clean)
    labels = clean.split(".")
    if len(labels) < 2 or not all(bool(_HOST_GLOB_LABEL_RE.match(lbl)) for lbl in labels):
        return False
    # Require at least two wildcard-free tail labels so patterns like *.com or *target.com are rejected.
    concrete_tail = 0
    for lbl in reversed(labels):
        if any(ch in _HOST_GLOB_CHARS for ch in lbl):
            break
        if not _HOST_LABEL_RE.match(lbl):
            return False
        concrete_tail += 1
    return concrete_tail >= 2


def _host_matches(target_host: str, pattern: str) -> bool:
    target = _canonicalize_host(target_host)
    pat = _canonicalize_host(pattern)
    if not _is_valid_host(target) or not _is_valid_host_pattern(pat):
        return False
    if ":" in pat or not any(ch in _HOST_GLOB_CHARS for ch in pat):
        return target == pat
    if pat.startswith("*.") and not any(ch in _HOST_GLOB_CHARS for ch in pat[2:]):
        base = pat[2:]
        return target.endswith("." + base) and len(target) > len(base) + 1
    return fnmatchcase(target, pat)


def _is_loopback_host(host: str) -> bool:
    clean = _canonicalize_host(host)
    if not clean:
        return False
    if clean in {"127.0.0.1", "localhost", "::1"} or clean.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(clean)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    eff = mapped if mapped is not None else ip
    return bool(eff.is_loopback)


def _check_ip_forbidden_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a non-empty reason if ``ip`` (or its IPv4-mapped address) is non-public/SSRF-unsafe."""
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [ip]
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        candidates.append(mapped)
    for addr in candidates:
        if addr.is_loopback:
            return "loopback"
        if addr.is_link_local:
            return "link-local"
        if addr.is_private:
            return "private"
        if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NETWORK:
            return "cgnat"
        if addr.is_multicast:
            return "multicast"
        if addr.is_unspecified:
            return "unspecified"
    return None


def check_dns_safety(
    host: str,
    port: int,
    *,
    resolver: Callable[..., Any] | None = None,
) -> None:
    """Reject IP literals and DNS resolutions pointing to loopback, private, IMDS, CGNAT, multicast, or unspecified IPs."""
    clean_host = _canonicalize_host(str(host or ""))
    if not clean_host:
        raise ValueError("DNS resolution blocked: empty host")
    try:
        ip_lit = ipaddress.ip_address(clean_host)
    except ValueError:
        ip_lit = None
    if ip_lit is not None:
        reason = _check_ip_forbidden_reason(ip_lit)
        if reason is not None:
            raise ValueError(f"DNS resolution blocked: {clean_host!r} is a {reason} IP address")
        return

    eff_resolver = resolver or socket.getaddrinfo
    try:
        resolved_entries = eff_resolver(clean_host, port)
    except socket.gaierror:
        if resolver is None and (clean_host == "localhost" or clean_host.endswith(".localhost")):
            raise ValueError(f"DNS resolution blocked: {clean_host!r} is a loopback hostname") from None
        raise

    for entry in resolved_entries or ():
        raw_ip = ""
        if isinstance(entry, (tuple, list)) and len(entry) >= 5 and isinstance(entry[4], (tuple, list)) and entry[4]:
            raw_ip = str(entry[4][0])
        elif isinstance(entry, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
            raw_ip = str(entry)
        if not raw_ip:
            continue
        clean_ip = raw_ip.split("%", 1)[0].strip()
        try:
            addr = ipaddress.ip_address(clean_ip)
        except ValueError:
            continue
        reason = _check_ip_forbidden_reason(addr)
        if reason is not None:
            raise ValueError(
                f"DNS resolution blocked: {clean_host!r} resolved to {reason} address {addr.compressed}"
            )


def _normalize_explicit_origin(raw_url: str) -> tuple[str, str, str, int]:
    """Validate and normalize an explicit http:// or https:// origin URL."""
    raw = str(raw_url or "").strip()
    if not raw:
        raise ValueError("target URL is required")
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise ValueError(f"target URL contains invalid whitespace or control characters: {raw_url!r}")
    try:
        parsed = urlsplit(raw)
        explicit_port = parsed.port
    except ValueError as exc:
        raise ValueError(f"target URL is invalid: {raw_url!r}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"target URL must use http:// or https:// scheme: {raw_url!r}")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("target URL must not embed credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("target URL must be a clean origin without path, credentials, query, or fragment")
    raw_hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not raw_hostname or not _is_valid_host(raw_hostname):
        raise ValueError(f"target URL has invalid hostname: {raw_url!r}")
    hostname = _canonicalize_host(raw_hostname)
    if explicit_port is not None and explicit_port <= 0:
        raise ValueError(f"target URL has invalid port: {raw_url!r}")
    default_port = _default_port(scheme)
    effective_port = explicit_port if explicit_port is not None else default_port
    host_netloc = f"[{hostname}]" if ":" in hostname else hostname
    if effective_port == default_port:
        origin = f"{scheme}://{host_netloc}/"
    else:
        origin = f"{scheme}://{host_netloc}:{effective_port}/"
    return origin, scheme, hostname, effective_port


def normalize_path(raw_path: str) -> str:
    """Decode percent-encoding safely and normalize a URL path to canonical POSIX form."""
    path = str(raw_path or "")
    for _ in range(3):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if "\x00" in path:
        raise ValueError("URL path contains NUL byte")
    collapsed = re.sub(r"/+", "/", "/" + path.replace("\\", "/"))
    normalized = posixpath.normpath(collapsed)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def _normalize_excluded_pattern(pattern: str) -> str:
    raw = str(pattern or "").strip()
    if not raw or any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise ValueError(f"invalid excluded path pattern: {pattern!r}")
    collapsed = re.sub(r"/+", "/", "/" + raw.replace("\\", "/"))
    if any(ch in _GLOB_CHARS for ch in collapsed):
        clean = collapsed.rstrip("/") or "/"
        return clean.lower()
    norm = posixpath.normpath(collapsed)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return (norm.rstrip("/") or "/").lower()


def _path_matches_excluded(norm_path_lower: str, pattern_lower: str) -> bool:
    if pattern_lower == "/":
        return True
    if any(ch in _GLOB_CHARS for ch in pattern_lower):
        if fnmatch(norm_path_lower, pattern_lower):
            return True
        if not pattern_lower.endswith("*"):
            return fnmatch(norm_path_lower, f"{pattern_lower}/*")
        return False
    return norm_path_lower == pattern_lower or norm_path_lower.startswith(f"{pattern_lower}/")


def _strip_route_extension(segment: str) -> str:
    """Strip a single known endpoint extension (e.g. .html, .php, .json) from a path segment."""
    clean = segment.rstrip(".")
    dot_idx = clean.rfind(".")
    if dot_idx > 0 and clean[dot_idx:] in _ROUTE_ENDPOINT_EXTENSIONS:
        return clean[:dot_idx]
    return clean


def _match_destructive_segments(norm_path_lower: str) -> str | None:
    """Return the matched canonical destructive lifecycle segment for a normalized lowercase path."""
    segments = [seg for seg in norm_path_lower.split("/") if seg]
    if not segments:
        return None
    last_idx = len(segments) - 1
    for idx, raw_seg in enumerate(segments):
        seg = raw_seg.split(";", 1)[0]
        if idx == last_idx:
            candidate = _strip_route_extension(seg)
        elif seg.endswith(".php"):
            candidate = seg[:-4]
        else:
            candidate = seg
        canonical = candidate.replace("_", "-")
        if canonical in DESTRUCTIVE_LIFECYCLE_SEGMENTS:
            return canonical
    return None


def _match_logout_segment(norm_path_lower: str) -> str | None:
    """Return the matched logout segment if the final normalized path segment is a logout route."""
    segments = [seg for seg in norm_path_lower.split("/") if seg]
    if not segments:
        return None
    final_seg = _strip_route_extension(segments[-1].split(";", 1)[0])
    if final_seg in LOGOUT_ROUTE_SEGMENTS:
        return final_seg
    return None


def match_destructive_lifecycle_route(path_or_url: str) -> str | None:
    """Match normalized path segments against destructive service/DB lifecycle routes."""
    raw = str(path_or_url or "").strip()
    if not raw:
        return None
    parsed = urlsplit(raw)
    norm_path_lower = normalize_path(parsed.path or "/").lower()
    return _match_destructive_segments(norm_path_lower)


def is_destructive_lifecycle_route(path_or_url: str) -> bool:
    """Return True when ``path_or_url`` targets a destructive service/DB lifecycle endpoint."""
    return match_destructive_lifecycle_route(path_or_url) is not None


def match_logout_route(path_or_url: str) -> str | None:
    """Match the final normalized path segment against session-logout endpoints."""
    raw = str(path_or_url or "").strip()
    if not raw:
        return None
    parsed = urlsplit(raw)
    norm_path_lower = normalize_path(parsed.path or "/").lower()
    return _match_logout_segment(norm_path_lower)


def is_logout_route(path_or_url: str) -> bool:
    """Return True when ``path_or_url`` ends in a session-logout endpoint segment."""
    return match_logout_route(path_or_url) is not None


@dataclass(frozen=True)
class _AssetRule:
    raw: str
    scheme: str | None
    host_pattern: str
    port: int | None
    path: str

    def matches_origin(self, scheme: str, host: str, port: int) -> bool:
        if self.scheme is not None and self.scheme != scheme:
            return False
        if self.port is not None and self.port != port:
            return False
        return _host_matches(host, self.host_pattern)


def _extract_entry_text(entry: Any) -> tuple[str, bool]:
    """Return (text, is_explicit_path_field) for a scope entry."""
    if isinstance(entry, str):
        return entry.strip(), False
    if isinstance(entry, dict):
        for key in ("asset", "target", "url", "host", "domain"):
            val = entry.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip(), False
        path_val = entry.get("path")
        if isinstance(path_val, str) and path_val.strip():
            return path_val.strip(), True
    return "", False


def _parse_scope_asset(entry: Any) -> _AssetRule | None:
    """Parse a host/origin scope entry; return None for path-only or prose entries."""
    raw, is_path_field = _extract_entry_text(entry)
    if not raw or is_path_field:
        return None
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        return None
    if raw.startswith("/"):
        return None

    lower = raw.lower()
    if "://" in raw:
        if not lower.startswith(("http://", "https://")):
            return None
        try:
            parsed = urlsplit(raw)
            explicit_port = parsed.port
        except ValueError:
            return None
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            return None
        scheme = parsed.scheme.lower()
        raw_host_pat = (parsed.hostname or "").strip().lower().rstrip(".")
        if not raw_host_pat or not _is_valid_host_pattern(raw_host_pat):
            return None
        host_pat = _canonicalize_host(raw_host_pat)
        if explicit_port is not None and explicit_port <= 0:
            return None
        eff_port = explicit_port if explicit_port is not None else _default_port(scheme)
        return _AssetRule(
            raw=raw,
            scheme=scheme,
            host_pattern=host_pat,
            port=eff_port,
            path=parsed.path or "",
        )

    # Support unbracketed IPv6 literals (e.g. "::1" or "0:0:0:0:0:0:0:1").
    if "/" not in raw and "[" not in raw and "]" not in raw and ":" in raw and "%" not in raw:
        try:
            ipv6_addr = ipaddress.ip_address(raw.lower().rstrip("."))
        except ValueError:
            ipv6_addr = None
        if isinstance(ipv6_addr, ipaddress.IPv6Address):
            return _AssetRule(
                raw=raw,
                scheme=None,
                host_pattern=ipv6_addr.compressed,
                port=None,
                path="",
            )

    try:
        parsed = urlsplit(f"http://{raw}")
        explicit_port = parsed.port
    except ValueError:
        return None
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return None
    raw_host_pat = (parsed.hostname or "").strip().lower().rstrip(".")
    if not raw_host_pat or not _is_valid_host_pattern(raw_host_pat):
        return None
    host_pat = _canonicalize_host(raw_host_pat)
    if explicit_port is not None and explicit_port <= 0:
        return None
    return _AssetRule(
        raw=raw,
        scheme=None,
        host_pattern=host_pat,
        port=explicit_port,
        path=parsed.path or "",
    )


def _is_empty_scope_entry(entry: Any) -> bool:
    if entry is None:
        return True
    if isinstance(entry, str):
        return not entry.strip()
    if isinstance(entry, dict):
        return len(entry) == 0
    return False


def _is_prose_out_of_scope_entry(entry: Any) -> bool:
    """Return True only for plain-English policy prose strings (e.g. 'DoS / load testing')."""
    if not isinstance(entry, str):
        return False
    raw = entry.strip()
    if not raw or " " not in raw or raw.startswith("/"):
        return False
    if any(ord(ch) < 32 or ch == "\x7f" or ch in "\t\n\r" for ch in raw):
        return False
    if any(tok in raw for tok in ("://", "*", "?", "[", "]", "@", ":", ".")):
        return False
    return True


def _parse_out_of_scope_entry(
    entry: Any,
    *,
    allow_prose: bool,
    allow_path: bool,
    label: str,
) -> tuple[str, _AssetRule | None, str | None]:
    """Classify and strictly validate an out_of_scope / excluded_assets entry (fail-closed)."""
    if _is_empty_scope_entry(entry):
        return "empty", None, None
    raw, is_path_field = _extract_entry_text(entry)
    if not raw:
        raise ValueError(f"invalid {label} entry: {entry!r}")
    if allow_prose and _is_prose_out_of_scope_entry(entry):
        return "prose", None, None
    if allow_path and (is_path_field or raw.startswith("/")):
        norm_path = _normalize_excluded_pattern(raw)
        return "path", None, norm_path
    rule = _parse_scope_asset(entry)
    if rule is None:
        raise ValueError(f"unparseable {label} entry: {entry!r}")
    return "asset", rule, None


def _extract_excluded_paths(
    scope_doc: dict[str, Any],
    *,
    target_scheme: str | None = None,
    target_host: str | None = None,
    target_port: int | None = None,
) -> list[str]:
    collected: list[str] = []
    seen: set[str] = set()

    def _add(raw_pattern: str) -> None:
        norm = _normalize_excluded_pattern(raw_pattern)
        if norm not in seen:
            seen.add(norm)
            collected.append(norm)

    for item in scope_doc.get("excluded_paths") or []:
        if isinstance(item, str) and item.strip():
            _add(item.strip())

    for entry in scope_doc.get("out_of_scope") or []:
        kind, rule, norm_path = _parse_out_of_scope_entry(
            entry,
            allow_prose=True,
            allow_path=True,
            label="out_of_scope",
        )
        if kind == "path" and norm_path is not None:
            if norm_path not in seen:
                seen.add(norm_path)
                collected.append(norm_path)
            continue
        if (
            kind == "asset"
            and rule is not None
            and target_scheme is not None
            and target_host is not None
            and target_port is not None
            and rule.path not in {"", "/"}
            and rule.matches_origin(target_scheme, target_host, target_port)
        ):
            _add(rule.path)

    return collected


def _parse_scope_header_collection(raw: Any, field_name: str) -> dict[str, str]:
    """Validate and parse optional scope-file custom headers (dict or list of 'Name: Value')."""
    if raw is None:
        return {}
    parsed: dict[str, str] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if not isinstance(k, str) or not k.strip() or not isinstance(v, str) or not v.strip():
                raise ValueError(
                    f"scope file '{field_name}' entries must map non-empty header names to non-empty strings"
                )
            name = k.strip()
            val = v.strip()
            for existing in [ek for ek in parsed if ek.lower() == name.lower()]:
                parsed.pop(existing, None)
            parsed[name] = val
        return parsed
    if isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(f"scope file '{field_name}' entries must be non-empty 'Name: Value' strings")
            name, sep, value = entry.strip().partition(":")
            clean_name = name.strip()
            clean_value = value.strip()
            if not sep or not clean_name or not clean_value:
                raise ValueError(f"scope file '{field_name}' entries must use 'Name: Value' format")
            for existing in [ek for ek in parsed if ek.lower() == clean_name.lower()]:
                parsed.pop(existing, None)
            parsed[clean_name] = clean_value
        return parsed
    raise ValueError(f"scope file '{field_name}' must be a JSON object or array of 'Name: Value' strings")


def _extract_scope_custom_headers(scope_doc: dict[str, Any]) -> dict[str, str]:
    """Extract optional operator custom headers from a validated scope.json document."""
    merged: dict[str, str] = {}
    for key in ("request_headers", "custom_headers"):
        if key not in scope_doc or scope_doc.get(key) is None:
            continue
        for hk, hv in _parse_scope_header_collection(scope_doc.get(key), key).items():
            for existing in [ek for ek in merged if ek.lower() == hk.lower()]:
                merged.pop(existing, None)
            merged[hk] = hv
    return merged


def _extract_scope_asset_lists(scope_doc: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Extract normalized (in_scope_assets, out_of_scope_assets) host/origin rule strings."""
    in_assets: list[str] = []
    seen_in: set[str] = set()
    for entry in scope_doc.get("in_scope") or []:
        rule = _parse_scope_asset(entry)
        if rule is not None and rule.raw not in seen_in:
            seen_in.add(rule.raw)
            in_assets.append(rule.raw)

    out_assets: list[str] = []
    seen_out: set[str] = set()
    for list_key in ("out_of_scope", "excluded_assets"):
        is_excluded_assets = list_key == "excluded_assets"
        for entry in scope_doc.get(list_key) or []:
            kind, rule, _ = _parse_out_of_scope_entry(
                entry,
                allow_prose=not is_excluded_assets,
                allow_path=not is_excluded_assets,
                label=list_key,
            )
            if kind == "asset" and rule is not None and rule.raw not in seen_out:
                seen_out.add(rule.raw)
                out_assets.append(rule.raw)
    return in_assets, out_assets


def load_scope_file(path: Path) -> dict[str, Any]:
    """Load and strictly validate a .codex/scope.json style authorization document."""
    if path is None:
        raise ValueError("scope file path is required")
    raw_path = Path(path).expanduser()
    try:
        st = raw_path.lstat()
    except OSError as exc:
        raise ValueError(f"scope file is missing or unreadable: {raw_path}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"scope file must not be a symlink: {raw_path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"scope file must be a regular file: {raw_path}")

    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(raw_path, open_flags)
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            raw_text = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"failed to read scope file {raw_path}: {exc}") from exc

    try:
        data = json.loads(raw_text)
    except ValueError as exc:
        raise ValueError(f"scope file is not valid JSON: {raw_path}") from exc

    if not isinstance(data, dict):
        raise ValueError("scope file must be a JSON object")

    for list_key in ("in_scope", "out_of_scope", "excluded_paths", "excluded_assets"):
        if list_key in data and not isinstance(data[list_key], list):
            raise ValueError(f"scope file '{list_key}' must be a JSON array")
    if "allow_loopback" in data and not isinstance(data["allow_loopback"], bool):
        raise ValueError("scope file 'allow_loopback' must be a boolean")

    for entry in data.get("in_scope") or []:
        if isinstance(entry, str):
            continue
        if isinstance(entry, dict):
            asset = entry.get("asset")
            if asset is not None and not isinstance(asset, str):
                raise ValueError("scope file 'in_scope' asset must be a string")
            continue
        raise ValueError("scope file 'in_scope' entries must be strings or objects")

    for entry in data.get("out_of_scope") or []:
        if not isinstance(entry, (str, dict)):
            raise ValueError("scope file 'out_of_scope' entries must be strings or objects")
        _parse_out_of_scope_entry(entry, allow_prose=True, allow_path=True, label="out_of_scope")

    for entry in data.get("excluded_paths") or []:
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError("scope file 'excluded_paths' entries must be non-empty strings")

    for entry in data.get("excluded_assets") or []:
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError("scope file 'excluded_assets' entries must be non-empty strings")
        _parse_out_of_scope_entry(entry, allow_prose=False, allow_path=False, label="excluded_assets")

    for hdr_key in ("request_headers", "custom_headers"):
        if hdr_key in data and data[hdr_key] is not None:
            _parse_scope_header_collection(data[hdr_key], hdr_key)

    return data


def resolve_target_origin(
    raw_url: str,
    *,
    scope_file: Path | None = None,
    allow_non_loopback: bool = False,
) -> tuple[str, dict[str, Any]]:
    """Resolve and authorize a target origin under loopback-only or explicit scope-file policy."""
    if not allow_non_loopback:
        origin = normalize_loopback_origin(raw_url)
        if scope_file is None:
            return origin, {"loopback_only": True, "excluded_paths": [], "scope_file": None}
        scope_path = Path(scope_file).expanduser()
        scope_doc = load_scope_file(scope_path)
        parsed = urlsplit(origin)
        excluded_paths = _extract_excluded_paths(
            scope_doc,
            target_scheme=parsed.scheme.lower(),
            target_host=(parsed.hostname or "").lower(),
            target_port=parsed.port or _default_port(parsed.scheme.lower()),
        )
        return origin, {
            "loopback_only": True,
            "excluded_paths": excluded_paths,
            "scope_file": str(scope_path.resolve()),
            "custom_headers": _extract_scope_custom_headers(scope_doc),
        }

    if scope_file is None or (isinstance(scope_file, str) and not scope_file.strip()):
        raise ValueError("allow_non_loopback=True requires an explicit scope_file")

    scope_path = Path(scope_file).expanduser()
    scope_doc = load_scope_file(scope_path)
    origin, scheme, host, port = _normalize_explicit_origin(raw_url)

    matched_in_scope = ""
    for entry in scope_doc.get("in_scope") or []:
        rule = _parse_scope_asset(entry)
        if rule is not None and rule.matches_origin(scheme, host, port):
            matched_in_scope = rule.raw
            break
    if not matched_in_scope:
        raise ValueError(f"target origin {origin} is not authorized by in_scope in {scope_path}")

    for list_key in ("out_of_scope", "excluded_assets"):
        is_excluded_assets = list_key == "excluded_assets"
        for entry in scope_doc.get(list_key) or []:
            kind, rule, _ = _parse_out_of_scope_entry(
                entry,
                allow_prose=not is_excluded_assets,
                allow_path=not is_excluded_assets,
                label=list_key,
            )
            if kind == "asset" and rule is not None and rule.path in {"", "/"} and rule.matches_origin(scheme, host, port):
                raise ValueError(f"target origin {origin} is excluded by {list_key} entry {rule.raw!r}")

    excluded_paths = _extract_excluded_paths(
        scope_doc,
        target_scheme=scheme,
        target_host=host,
        target_port=port,
    )
    in_scope_assets, out_of_scope_assets = _extract_scope_asset_lists(scope_doc)
    return origin, {
        "loopback_only": False,
        "excluded_paths": excluded_paths,
        "scope_file": str(scope_path.resolve()),
        "matched_in_scope": matched_in_scope,
        "in_scope_assets": in_scope_assets,
        "out_of_scope_assets": out_of_scope_assets,
        "custom_headers": _extract_scope_custom_headers(scope_doc),
    }


@dataclass
class ScopeGuard:
    """Enforce target origin lock (single or authorized multi-origin), excluded path rules, and lifecycle guard."""

    base_origin: str
    excluded_paths: tuple[str, ...] = ()
    allow_lifecycle_routes: bool = False
    in_scope_assets: tuple[str, ...] = ()
    out_of_scope_assets: tuple[str, ...] = ()
    loopback_only: bool | None = None
    _origin_key: tuple[str, str, int] = field(init=False, repr=False)
    _in_scope_rules: tuple[_AssetRule, ...] = field(init=False, repr=False)
    _out_of_scope_origin_rules: tuple[_AssetRule, ...] = field(init=False, repr=False)
    _out_of_scope_path_rules: tuple[tuple[_AssetRule, str], ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        origin, scheme, host, port = _normalize_explicit_origin(self.base_origin)
        self.base_origin = origin
        self._origin_key = (scheme, host, port)
        self.allow_lifecycle_routes = bool(self.allow_lifecycle_routes)
        normalized: list[str] = []
        seen: set[str] = set()
        for pat in self.excluded_paths or ():
            if not str(pat or "").strip():
                continue
            norm = _normalize_excluded_pattern(str(pat))
            if norm not in seen:
                seen.add(norm)
                normalized.append(norm)

        in_rules: list[_AssetRule] = []
        in_raws: list[str] = []
        seen_in: set[str] = set()
        for entry in self.in_scope_assets or ():
            rule = _parse_scope_asset(entry)
            if rule is None or rule.raw in seen_in:
                continue
            seen_in.add(rule.raw)
            in_rules.append(rule)
            in_raws.append(rule.raw)

        out_origin_rules: list[_AssetRule] = []
        out_path_rules: list[tuple[_AssetRule, str]] = []
        out_raws: list[str] = []
        seen_out: set[str] = set()
        for entry in self.out_of_scope_assets or ():
            kind, rule, norm_path_pat = _parse_out_of_scope_entry(
                entry,
                allow_prose=True,
                allow_path=True,
                label="out_of_scope_assets",
            )
            if kind in {"empty", "prose"}:
                continue
            if kind == "path" and norm_path_pat is not None:
                if norm_path_pat not in seen:
                    seen.add(norm_path_pat)
                    normalized.append(norm_path_pat)
                continue
            assert rule is not None
            if rule.raw not in seen_out:
                seen_out.add(rule.raw)
                out_raws.append(rule.raw)
            if rule.path in {"", "/"}:
                out_origin_rules.append(rule)
            else:
                out_path_rules.append((rule, _normalize_excluded_pattern(rule.path)))

        self.excluded_paths = tuple(normalized)
        self.in_scope_assets = tuple(in_raws)
        self.out_of_scope_assets = tuple(out_raws)
        self._in_scope_rules = tuple(in_rules)
        self._out_of_scope_origin_rules = tuple(out_origin_rules)
        self._out_of_scope_path_rules = tuple(out_path_rules)
        if self.loopback_only is None:
            base_is_lb = _is_loopback_host(host)
            rules_are_lb = all(
                not any(ch in r.host_pattern for ch in _HOST_GLOB_CHARS)
                and _is_loopback_host(r.host_pattern)
                for r in in_rules
            )
            self.loopback_only = bool(base_is_lb and rules_are_lb)
        else:
            self.loopback_only = bool(self.loopback_only)

    @property
    def is_multi_origin(self) -> bool:
        """Return True when in_scope_assets authorizes at least one origin beyond base_origin."""
        return any(
            rule.scheme is None
            or rule.port is None
            or any(ch in rule.host_pattern for ch in _HOST_GLOB_CHARS)
            or (rule.scheme, rule.host_pattern, rule.port) != self._origin_key
            for rule in self._in_scope_rules
        )

    def check_dns_safety(
        self,
        host: str,
        port: int,
        *,
        resolver: Callable[..., Any] | None = None,
    ) -> None:
        """Enforce non-loopback DNS / private-IP SSRF guard when ``not self.loopback_only``."""
        if self.loopback_only:
            return
        check_dns_safety(host, port, resolver=resolver)

    def check_origin(self, scheme: str, host: str, port: int) -> bool:
        """Return True if ``(scheme, host, port)`` is authorized and not excluded by origin rules."""
        norm_scheme = str(scheme or "").strip().lower()
        raw_host = str(host or "").strip().lower().rstrip(".")
        if raw_host.startswith("[") and raw_host.endswith("]") and ":" in raw_host:
            raw_host = raw_host[1:-1]
        if norm_scheme not in {"http", "https"} or not raw_host or not _is_valid_host(raw_host):
            return False
        norm_host = _canonicalize_host(raw_host)
        if isinstance(port, bool) or not isinstance(port, int) or port <= 0:
            return False
        for rule in self._out_of_scope_origin_rules:
            if rule.matches_origin(norm_scheme, norm_host, port):
                return False
        if (norm_scheme, norm_host, port) == self._origin_key:
            return True
        return any(rule.matches_origin(norm_scheme, norm_host, port) for rule in self._in_scope_rules)

    def check_url(self, url: str, *, allow_lifecycle_routes: bool | None = None) -> None:
        """Raise ValueError if URL leaves authorized origins, hits excluded paths, or hits a lifecycle route."""
        raw = str(url or "").strip()
        if not raw:
            raise ValueError("URL is required")
        if raw.startswith("//"):
            raise ValueError(f"scheme-relative cross-origin URL blocked: {raw!r}")
        if any(ch in raw for ch in ("\x00", "\r", "\n")):
            raise ValueError(f"URL contains control characters: {raw!r}")
        resolved = urljoin(self.base_origin, raw)
        parsed = urlsplit(resolved)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError(f"out-of-scope URL scheme in {resolved!r}; allowed origin is {self.base_origin}")
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise ValueError(f"URL must not embed credentials: {resolved!r}")
        hostname = _canonicalize_host(parsed.hostname or "")
        port = parsed.port if parsed.port is not None else _default_port(scheme)
        if not self.check_origin(scheme, hostname, port):
            raise ValueError(f"out-of-scope URL {resolved!r}; allowed origin is {self.base_origin}")
        norm_path_lower = normalize_path(parsed.path or "/").lower()
        for pattern in self.excluded_paths:
            if _path_matches_excluded(norm_path_lower, pattern):
                raise ValueError(
                    f"URL path {parsed.path or '/'!r} is excluded by scope pattern {pattern!r}"
                )
        for rule, path_pattern in self._out_of_scope_path_rules:
            if rule.matches_origin(scheme, hostname, port) and _path_matches_excluded(norm_path_lower, path_pattern):
                raise ValueError(
                    f"URL path {parsed.path or '/'!r} is excluded by out-of-scope rule {rule.raw!r}"
                )
        effective_allow_lifecycle = (
            self.allow_lifecycle_routes
            if allow_lifecycle_routes is None
            else bool(allow_lifecycle_routes)
        )
        if not effective_allow_lifecycle:
            matched_segment = _match_destructive_segments(norm_path_lower)
            if matched_segment is not None:
                raise ValueError(
                    f"destructive service-lifecycle route blocked: {parsed.path or '/'!r} "
                    f"(matched segment {matched_segment!r}); endpoints that reboot, restart, "
                    "shutdown, or wipe the target service/database are blocked by default to "
                    "avoid crashing or disrupting the target"
                )
