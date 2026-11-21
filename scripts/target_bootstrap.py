"""Stdlib-only target origin bootstrap, credentials loading, and scope guard."""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
import json
import os
from pathlib import Path
import posixpath
import re
import stat
from typing import Any, Sequence
from urllib.parse import unquote, urljoin, urlsplit

_ADMIN_ROLES = frozenset({"platform_admin", "tenant_admin", "admin", "superadmin"})
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_GLOB_CHARS = frozenset("*?[")


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


def select_representative_accounts(
    accounts: Sequence[dict[str, Any]],
    *,
    max_members: int = 4,
    max_admins: int = 1,
) -> list[dict[str, Any]]:
    """Select bounded synthetic accounts spanning tenants, roles, and peer comparisons."""
    cleaned = [dict(row) for row in accounts if isinstance(row, dict) and row.get("alias") and row.get("password")]
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


def _is_valid_host(host: str) -> bool:
    clean = host.strip().lower().rstrip(".")
    if not clean or any(ch.isspace() for ch in clean):
        return False
    if ":" in clean:
        return all(ch in "0123456789abcdef:." for ch in clean)
    labels = clean.split(".")
    return all(bool(_HOST_LABEL_RE.match(label)) for label in labels)


def _host_matches(target_host: str, pattern: str) -> bool:
    target = target_host.strip().lower().rstrip(".")
    pat = pattern.strip().lower().rstrip(".")
    if not target or not pat:
        return False
    if pat.startswith("*."):
        base = pat[2:]
        if not base or "*" in base or not _is_valid_host(base):
            return False
        return target.endswith("." + base) and len(target) > len(base) + 1
    if "*" in pat:
        return False
    if not _is_valid_host(pat):
        return False
    return target == pat


def _normalize_explicit_origin(raw_url: str) -> tuple[str, str, str, int]:
    """Validate and normalize an explicit http:// or https:// origin URL."""
    raw = str(raw_url or "").strip()
    if not raw:
        raise ValueError("target URL is required")
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise ValueError(f"target URL contains invalid whitespace or control characters: {raw_url!r}")
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"target URL must use http:// or https:// scheme: {raw_url!r}")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("target URL must not embed credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("target URL must be a clean origin without path, credentials, query, or fragment")
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname or not _is_valid_host(hostname):
        raise ValueError(f"target URL has invalid hostname: {raw_url!r}")
    explicit_port = parsed.port
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
        host_pat = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host_pat:
            return None
        if not (host_pat.startswith("*.") or _is_valid_host(host_pat)):
            return None
        if host_pat.startswith("*.") and not _is_valid_host(host_pat[2:]):
            return None
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

    try:
        parsed = urlsplit(f"http://{raw}")
        explicit_port = parsed.port
    except ValueError:
        return None
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return None
    host_pat = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host_pat:
        return None
    if host_pat.startswith("*."):
        if not _is_valid_host(host_pat[2:]):
            return None
    elif not _is_valid_host(host_pat):
        return None
    if explicit_port is not None and explicit_port <= 0:
        return None
    return _AssetRule(
        raw=raw,
        scheme=None,
        host_pattern=host_pat,
        port=explicit_port,
        path=parsed.path or "",
    )


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
        raw, is_path_field = _extract_entry_text(entry)
        if not raw or any(ch.isspace() or ord(ch) < 32 for ch in raw):
            continue
        if is_path_field or raw.startswith("/"):
            _add(raw)
            continue
        if target_scheme is not None and target_host is not None and target_port is not None:
            rule = _parse_scope_asset(entry)
            if rule is not None and rule.path not in {"", "/"} and rule.matches_origin(target_scheme, target_host, target_port):
                _add(rule.path)

    return collected


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

    for entry in data.get("excluded_paths") or []:
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError("scope file 'excluded_paths' entries must be non-empty strings")

    for entry in data.get("excluded_assets") or []:
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError("scope file 'excluded_assets' entries must be non-empty strings")

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
        for entry in scope_doc.get(list_key) or []:
            rule = _parse_scope_asset(entry)
            if rule is not None and rule.path in {"", "/"} and rule.matches_origin(scheme, host, port):
                raise ValueError(f"target origin {origin} is excluded by {list_key} entry {rule.raw!r}")

    excluded_paths = _extract_excluded_paths(
        scope_doc,
        target_scheme=scheme,
        target_host=host,
        target_port=port,
    )
    return origin, {
        "loopback_only": False,
        "excluded_paths": excluded_paths,
        "scope_file": str(scope_path.resolve()),
        "matched_in_scope": matched_in_scope,
    }


@dataclass
class ScopeGuard:
    """Enforce exact target origin lock and normalized case-insensitive excluded path rules."""

    base_origin: str
    excluded_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        origin, scheme, host, port = _normalize_explicit_origin(self.base_origin)
        self.base_origin = origin
        self._origin_key: tuple[str, str, int] = (scheme, host, port)
        normalized: list[str] = []
        seen: set[str] = set()
        for pat in self.excluded_paths:
            if not str(pat or "").strip():
                continue
            norm = _normalize_excluded_pattern(str(pat))
            if norm not in seen:
                seen.add(norm)
                normalized.append(norm)
        self.excluded_paths = tuple(normalized)

    def check_url(self, url: str) -> None:
        """Raise ValueError if URL leaves base_origin or hits any excluded_paths rule."""
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
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        port = parsed.port if parsed.port is not None else _default_port(scheme)
        if (scheme, hostname, port) != self._origin_key:
            raise ValueError(f"out-of-scope URL {resolved!r}; allowed origin is {self.base_origin}")
        norm_path_lower = normalize_path(parsed.path or "/").lower()
        for pattern in self.excluded_paths:
            if _path_matches_excluded(norm_path_lower, pattern):
                raise ValueError(
                    f"URL path {parsed.path or '/'!r} is excluded by scope pattern {pattern!r}"
                )
