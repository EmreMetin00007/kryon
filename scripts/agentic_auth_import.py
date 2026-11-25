"""Zero-runtime-overhead Playwright storage_state importer and encrypted vault helper.

Pure stdlib + local ``agentic_vault`` only. Performs zero network calls, zero
Playwright imports, and never logs or echoes raw cookie or token values in
exceptions or return summaries.
"""
from __future__ import annotations

import errno
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Sequence
from urllib.parse import urlsplit

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import agentic_vault  # noqa: E402
from target_bootstrap import ScopeGuard  # noqa: E402

MAX_STORAGE_STATE_BYTES = 5 * 1024 * 1024
MAX_LOCAL_STORAGE_KEYS = 64
MAX_LOCAL_STORAGE_BYTES = 64 * 1024
VAULT_STORAGE_STATE_SCHEMA = "agentic-vault-storage-state/1"

_DEFAULT_ALIAS = "browser-user"
_DEFAULT_ROLE = "member"

_BEARER_PREFIX_RE = re.compile(r"^\s*bearer\s+", re.IGNORECASE)
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

_TOKEN_KEY_PRIORITY: tuple[str, ...] = (
    "access_token",
    "accesstoken",
    "bearer_token",
    "auth_token",
    "authtoken",
    "jwt",
    "id_token",
    "idtoken",
    "token",
)
_TOKEN_KEY_RANK: dict[str, int] = {key: idx for idx, key in enumerate(_TOKEN_KEY_PRIORITY)}

_LOCALSTORAGE_CSRF_PRIORITY: tuple[str, ...] = (
    "csrf_token",
    "csrftoken",
    "xsrf_token",
    "xsrftoken",
    "x-csrf-token",
    "x-xsrf-token",
)
_LOCALSTORAGE_CSRF_RANK: dict[str, int] = {
    key: idx for idx, key in enumerate(_LOCALSTORAGE_CSRF_PRIORITY)
}

_COOKIE_CSRF_PRIORITY: tuple[str, ...] = (
    "csrftoken",
    "csrf_token",
    "xsrf-token",
    "xsrf_token",
    "_csrf",
)


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ch == "\x7f" for ch in value)


def _validate_alias(alias: str) -> str:
    clean = str(alias or "").strip()
    if (
        not clean
        or clean.lower() == "anon"
        or any(ch.isspace() or ord(ch) < 32 or ch == "\x7f" for ch in clean)
    ):
        raise ValueError("actor alias must be non-empty, non-whitespace, and not 'anon'")
    return clean


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_trustworthy_origin(scheme: str, host: str) -> bool:
    if scheme == "https":
        return True
    return host in _LOOPBACK_HOSTS or host.endswith(".localhost")


def _parse_origin_tuple(raw_url: str, *, label: str = "base_url") -> tuple[str, str, int]:
    """Parse an http(s) URL into (scheme, normalized_host, effective_port)."""
    text = str(raw_url or "").strip()
    if not text or any(ch.isspace() or ord(ch) < 32 for ch in text):
        raise ValueError(f"{label} must be a valid http(s) URL")
    try:
        parsed = urlsplit(text)
        explicit_port = parsed.port
    except ValueError:
        raise ValueError(f"{label} must be a valid http(s) URL") from None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"{label} must use http:// or https:// scheme")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError(f"{label} must not embed credentials")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError(f"{label} must include a hostname")
    if explicit_port is not None and explicit_port <= 0:
        raise ValueError(f"{label} has an invalid port")
    effective_port = explicit_port if explicit_port is not None else _default_port(scheme)
    return scheme, host, effective_port


def _read_regular_file_text(
    path: Path | str,
    *,
    max_bytes: int = MAX_STORAGE_STATE_BYTES,
) -> str:
    """Safely read a regular UTF-8 file, rejecting symlinks, special files, and oversized files."""
    if isinstance(path, str) and not path.strip():
        raise ValueError("storage state file path is required")
    raw_path = Path(path).expanduser()
    try:
        st = raw_path.lstat()
    except OSError:
        raise ValueError(f"storage state file is missing or unreadable: {raw_path}") from None
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"storage state file must not be a symlink: {raw_path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"storage state file must be a regular file: {raw_path}")
    if st.st_size > max_bytes:
        raise ValueError(
            f"storage state file exceeds maximum allowed size ({max_bytes} bytes): {raw_path}"
        )

    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(raw_path, open_flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"storage state file must not be a symlink: {raw_path}") from None
        raise ValueError(f"failed to read storage state file: {raw_path}") from None

    try:
        fd_stat = os.fstat(fd)
        if not stat.S_ISREG(fd_stat.st_mode):
            os.close(fd)
            raise ValueError(f"storage state file must be a regular file: {raw_path}")
        if fd_stat.st_size > max_bytes:
            os.close(fd)
            raise ValueError(
                f"storage state file exceeds maximum allowed size ({max_bytes} bytes): {raw_path}"
            )
    except ValueError:
        raise
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        raise ValueError(f"failed to read storage state file: {raw_path}") from None

    try:
        with os.fdopen(fd, "rb") as handle:
            raw_bytes = handle.read(max_bytes + 1)
    except OSError:
        raise ValueError(f"failed to read storage state file: {raw_path}") from None

    if len(raw_bytes) > max_bytes:
        raise ValueError(
            f"storage state file exceeds maximum allowed size ({max_bytes} bytes): {raw_path}"
        )
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"storage state file is not valid UTF-8: {raw_path}") from None


def _validate_storage_state_dict(data: Any) -> dict[str, Any]:
    """Validate Playwright storage_state object structure without echoing any values."""
    if not isinstance(data, dict):
        raise ValueError("storage state must be a JSON object")
    if data and "cookies" not in data and "origins" not in data:
        raise ValueError("storage state must contain 'cookies' or 'origins'")
    if "cookies" in data:
        raw_cookies = data["cookies"]
        if not isinstance(raw_cookies, list):
            raise ValueError("storage state 'cookies' must be a JSON array")
        for item in raw_cookies:
            if not isinstance(item, dict):
                raise ValueError("storage state 'cookies' entries must be JSON objects")
    if "origins" in data:
        raw_origins = data["origins"]
        if not isinstance(raw_origins, list):
            raise ValueError("storage state 'origins' must be a JSON array")
        for item in raw_origins:
            if not isinstance(item, dict):
                raise ValueError("storage state 'origins' entries must be JSON objects")
            if "localStorage" in item and not isinstance(item["localStorage"], list):
                raise ValueError("storage state origin 'localStorage' must be a JSON array")
    return data


def _read_storage_state_file(path: Path | str) -> dict[str, Any]:
    raw_text = _read_regular_file_text(path)
    parsed: Any = None
    parse_failed = False
    try:
        parsed = json.loads(raw_text)
    except ValueError:
        parse_failed = True
    if parse_failed:
        raise ValueError("storage state file is not valid JSON")
    return _validate_storage_state_dict(parsed)


def _cookie_matches_host(raw_domain: Any, target_host: str) -> tuple[bool, bool, str]:
    """Return (matched, is_exact_host, normalized_domain) under strict cookie host scoping."""
    if not isinstance(raw_domain, str):
        return False, False, ""
    raw = raw_domain.strip().lower()
    if not raw or any(ch.isspace() or ord(ch) < 32 for ch in raw):
        return False, False, ""
    cookie_domain = raw.lstrip(".").rstrip(".")
    if not cookie_domain:
        return False, False, ""
    if cookie_domain == target_host:
        return True, True, cookie_domain
    if _is_ip_address(target_host) or _is_ip_address(cookie_domain):
        return False, False, ""
    if "." in cookie_domain and target_host.endswith("." + cookie_domain):
        return True, False, cookie_domain
    return False, False, ""


def _match_cookie_scope(
    raw_domain: Any,
    *,
    target_scheme: str,
    target_host: str,
    target_port: int,
    guard: ScopeGuard | None,
) -> tuple[bool, bool, bool, str, bool]:
    """Match a cookie domain against base_url and optional multi-origin ScopeGuard.

    Returns ``(matched, is_base_match, is_exact_host, norm_domain, trustworthy_origin)``.
    """
    if guard is None:
        matched, is_exact_host, norm_domain = _cookie_matches_host(raw_domain, target_host)
        if not matched:
            return False, False, False, "", False
        return True, True, is_exact_host, norm_domain, _is_trustworthy_origin(target_scheme, target_host)

    if not isinstance(raw_domain, str):
        return False, False, False, "", False
    raw = raw_domain.strip().lower()
    if not raw or any(ch.isspace() or ord(ch) < 32 for ch in raw):
        return False, False, False, "", False
    cookie_domain = raw.lstrip(".").rstrip(".")
    if not cookie_domain:
        return False, False, False, "", False

    base_matched, base_exact, base_norm = _cookie_matches_host(raw, target_host)
    if base_matched and guard.check_origin(target_scheme, target_host, target_port):
        return (
            True,
            True,
            base_exact,
            base_norm,
            _is_trustworthy_origin(target_scheme, target_host),
        )

    best_match: tuple[bool, bool, bool, str, bool] | None = None
    for rule in guard._in_scope_rules:
        rule_scheme = rule.scheme or target_scheme
        rule_port = rule.port if rule.port is not None else _default_port(rule_scheme)
        cand: tuple[bool, bool, bool, str, bool] | None = None
        if not rule.host_pattern.startswith("*."):
            rule_host = rule.host_pattern
            if guard.check_origin(rule_scheme, rule_host, rule_port):
                matched, is_exact_host, norm_domain = _cookie_matches_host(raw, rule_host)
                if matched:
                    cand = (
                        True,
                        False,
                        is_exact_host,
                        norm_domain,
                        _is_trustworthy_origin(rule_scheme, rule_host),
                    )
        else:
            wildcard_base = rule.host_pattern[2:]
            if cookie_domain.endswith("." + wildcard_base) and not _is_ip_address(cookie_domain):
                if guard.check_origin(rule_scheme, cookie_domain, rule_port):
                    is_exact = not raw.startswith(".")
                    cand = (
                        True,
                        False,
                        is_exact,
                        cookie_domain,
                        _is_trustworthy_origin(rule_scheme, cookie_domain),
                    )
            elif (
                cookie_domain == wildcard_base
                and "." in cookie_domain
                and not _is_ip_address(cookie_domain)
                and not any(
                    out_rule.host_pattern in {cookie_domain, f"*.{cookie_domain}"}
                    for out_rule in guard._out_of_scope_origin_rules
                )
            ):
                cand = (
                    True,
                    False,
                    False,
                    cookie_domain,
                    _is_trustworthy_origin(rule_scheme, cookie_domain),
                )

        if cand is not None:
            if cand[4]:
                return cand
            if best_match is None:
                best_match = cand

    if best_match is not None:
        return best_match
    return False, False, False, "", False


def _is_cookie_expired(expires: Any, current_time: float) -> bool:
    if isinstance(expires, bool) or not isinstance(expires, (int, float)):
        return False
    exp_val = float(expires)
    if not math.isfinite(exp_val):
        return False
    return exp_val > 0.0 and exp_val < current_time


def _clean_secret_value(raw_value: Any) -> str:
    if not isinstance(raw_value, str):
        return ""
    text = raw_value.strip()
    if not text:
        return ""
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        try:
            unwrapped = json.loads(text)
        except ValueError:
            unwrapped = None
        if isinstance(unwrapped, str):
            text = unwrapped.strip()
    if not text or _has_control_chars(text):
        return ""
    return text


def _normalize_bearer_value(raw_value: Any) -> str:
    cleaned = _clean_secret_value(raw_value)
    if not cleaned or cleaned.lower() == "bearer":
        return ""
    stripped = _BEARER_PREFIX_RE.sub("", cleaned).strip()
    if not stripped or _has_control_chars(stripped):
        return ""
    return stripped


def parse_storage_state_spec(raw: str) -> tuple[str, str, str, Path]:
    """Parse a CLI storage_state specification into (alias, role, tenant, path).

    Supported forms:
      - ``alias=/path/to/state.json`` -> ``(alias, "member", "", Path(...))``
      - ``alias:role=/path/to/state.json`` -> ``(alias, role, "", Path(...))``
      - ``alias:role:tenant=/path/to/state.json`` -> ``(alias, role, tenant, Path(...))``
      - ``/path/to/state.json`` -> ``("browser-user", "member", "", Path(...))``
    """
    text = str(raw or "").strip()
    if not text:
        raise ValueError("storage state spec is required")
    if _has_control_chars(text):
        raise ValueError("storage state spec must not contain control characters")

    if "=" not in text:
        return _DEFAULT_ALIAS, _DEFAULT_ROLE, "", Path(text).expanduser()

    prefix, raw_path = text.split("=", 1)
    prefix = prefix.strip()
    raw_path = raw_path.strip()
    if not prefix:
        raise ValueError("storage state alias must not be empty")
    if not raw_path:
        raise ValueError("storage state file path must not be empty")

    parts = prefix.split(":")
    if len(parts) > 3:
        raise ValueError("storage state spec prefix must be alias, alias:role, or alias:role:tenant")

    alias = _validate_alias(parts[0])
    role = (parts[1].strip() if len(parts) >= 2 else "") or _DEFAULT_ROLE
    if any(ch.isspace() or ord(ch) < 32 for ch in role):
        raise ValueError("storage state role must not contain whitespace or control characters")
    tenant = parts[2].strip() if len(parts) == 3 else ""
    if any(ch.isspace() or ord(ch) < 32 for ch in tenant):
        raise ValueError("storage state tenant must not contain whitespace or control characters")

    return alias, role, tenant, Path(raw_path).expanduser()


def load_storage_state_actor(
    source: Path | str | dict[str, Any],
    *,
    base_url: str,
    alias: str = _DEFAULT_ALIAS,
    role: str = _DEFAULT_ROLE,
    tenant: str = "",
    now: float | None = None,
    in_scope_assets: Sequence[str] = (),
    out_of_scope_assets: Sequence[str] = (),
) -> dict[str, Any]:
    """Load and origin-scope a Playwright storage_state into an ActorManager account dict."""
    clean_alias = _validate_alias(alias)
    clean_role = str(role or _DEFAULT_ROLE).strip() or _DEFAULT_ROLE
    clean_tenant = str(tenant or "").strip()
    target_scheme, target_host, target_port = _parse_origin_tuple(base_url, label="base_url")
    clean_in_scope = tuple(str(a).strip() for a in (in_scope_assets or ()) if str(a or "").strip())
    clean_out_of_scope = tuple(str(a).strip() for a in (out_of_scope_assets or ()) if str(a or "").strip())
    guard: ScopeGuard | None = (
        ScopeGuard(
            base_origin=base_url,
            in_scope_assets=clean_in_scope,
            out_of_scope_assets=clean_out_of_scope,
        )
        if clean_in_scope
        else None
    )

    if now is None:
        current_time = time.time()
    elif isinstance(now, bool):
        raise ValueError("now must be a numeric timestamp")
    else:
        current_time = float(now)

    if isinstance(source, dict):
        state = _validate_storage_state_dict(source)
    elif isinstance(source, (Path, str)):
        state = _read_storage_state_file(source)
    else:
        raise ValueError("storage state source must be a file path or dict")

    # 1. Strictly scope cookies to authorized origin(s), secure policy, and expiry.
    cookie_candidates: list[tuple[tuple[int, int, int, int], str, str]] = []
    for entry in state.get("cookies") or []:
        if not isinstance(entry, dict):
            continue
        raw_name = entry.get("name")
        raw_value = entry.get("value")
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            continue
        name = raw_name.strip()
        if not name or _has_control_chars(name) or ";" in name or "=" in name:
            continue
        if not raw_value or _has_control_chars(raw_value):
            continue
        matched, is_base_match, is_exact_host, norm_domain, trustworthy_match = _match_cookie_scope(
            entry.get("domain"),
            target_scheme=target_scheme,
            target_host=target_host,
            target_port=target_port,
            guard=guard,
        )
        if not matched:
            continue
        is_secure = entry.get("secure") is True
        if is_secure and not trustworthy_match:
            continue
        if _is_cookie_expired(entry.get("expires"), current_time):
            continue
        raw_path = entry.get("path")
        cookie_path = raw_path.strip() if isinstance(raw_path, str) and raw_path.strip() else "/"
        # Broader domain / narrower path sorted first so base origin & exact host & root path win on duplicates.
        priority_key = (
            1 if is_base_match else 0,
            1 if is_exact_host else 0,
            len(norm_domain),
            -len(cookie_path),
        )
        cookie_candidates.append((priority_key, name, raw_value))

    cookie_candidates.sort(key=lambda item: item[0])
    cookies_dict: dict[str, str] = {}
    for _, name, value in cookie_candidates:
        cookies_dict[name] = value

    # 2. Extract bearer & CSRF tokens and preserve authorized-origin localStorage entries.
    best_token_rank: int | None = None
    access_token_str = ""
    best_csrf_rank: int | None = None
    csrf_token_str = ""
    local_storage_dict: dict[str, str] = {}
    local_storage_bytes = 0

    target_origin = (target_scheme, target_host, target_port)
    scoped_origin_entries: list[tuple[bool, list[Any]]] = []
    for origin_entry in state.get("origins") or []:
        if not isinstance(origin_entry, dict):
            continue
        raw_origin = origin_entry.get("origin")
        if not isinstance(raw_origin, str) or not raw_origin.strip():
            continue
        try:
            origin_tuple = _parse_origin_tuple(raw_origin, label="origin")
        except ValueError:
            continue
        is_base_origin = origin_tuple == target_origin
        if guard is None:
            if not is_base_origin:
                continue
        elif not guard.check_origin(*origin_tuple):
            continue

        local_storage = origin_entry.get("localStorage")
        if not isinstance(local_storage, list):
            continue
        scoped_origin_entries.append((is_base_origin, local_storage))

    # Process base_origin entries first so base_origin wins on equal-rank tokens & key collisions.
    scoped_origin_entries.sort(key=lambda item: 0 if item[0] else 1)
    for is_base_origin, local_storage in scoped_origin_entries:
        for item in local_storage:
            if not isinstance(item, dict):
                continue
            raw_key = item.get("name")
            if not isinstance(raw_key, str):
                continue
            ls_key = raw_key.strip()
            raw_val = item.get("value")
            if ls_key and not _has_control_chars(raw_key) and isinstance(raw_val, str):
                entry_bytes = len(ls_key.encode("utf-8")) + len(raw_val.encode("utf-8"))
                if ls_key in local_storage_dict:
                    if is_base_origin:
                        prev_bytes = len(ls_key.encode("utf-8")) + len(local_storage_dict[ls_key].encode("utf-8"))
                        new_total = local_storage_bytes - prev_bytes + entry_bytes
                        if new_total <= MAX_LOCAL_STORAGE_BYTES:
                            local_storage_dict[ls_key] = raw_val
                            local_storage_bytes = new_total
                elif (
                    len(local_storage_dict) < MAX_LOCAL_STORAGE_KEYS
                    and local_storage_bytes + entry_bytes <= MAX_LOCAL_STORAGE_BYTES
                ):
                    local_storage_dict[ls_key] = raw_val
                    local_storage_bytes += entry_bytes

            key_lower = ls_key.lower()
            if not key_lower:
                continue

            token_rank = _TOKEN_KEY_RANK.get(key_lower)
            if token_rank is None:
                token_rank = _TOKEN_KEY_RANK.get(key_lower.replace("-", "_"))
            if token_rank is not None:
                candidate = _normalize_bearer_value(raw_val)
                if candidate and (best_token_rank is None or token_rank < best_token_rank):
                    best_token_rank = token_rank
                    access_token_str = candidate

            csrf_rank = _LOCALSTORAGE_CSRF_RANK.get(key_lower)
            if csrf_rank is not None:
                csrf_candidate = _clean_secret_value(raw_val)
                if csrf_candidate and (best_csrf_rank is None or csrf_rank < best_csrf_rank):
                    best_csrf_rank = csrf_rank
                    csrf_token_str = csrf_candidate

    # 3. Fallback CSRF extraction from scoped cookies.
    if not csrf_token_str and cookies_dict:
        lower_cookies = {k.lower(): v for k, v in cookies_dict.items()}
        for cookie_key in _COOKIE_CSRF_PRIORITY:
            cookie_val = lower_cookies.get(cookie_key)
            if cookie_val:
                cleaned_csrf = _clean_secret_value(cookie_val)
                if cleaned_csrf:
                    csrf_token_str = cleaned_csrf
                    break

    auth_header_str = f"Bearer {access_token_str}" if access_token_str else ""
    extra_headers: dict[str, str] = {}
    if auth_header_str:
        extra_headers["Authorization"] = auth_header_str

    return {
        "alias": clean_alias,
        "role": clean_role,
        "tenant": clean_tenant,
        "cookies": cookies_dict,
        "headers": extra_headers,
        "local_storage": local_storage_dict,
        "auth_header": auth_header_str,
        "access_token": access_token_str,
        "csrf_token": csrf_token_str,
        "authenticated": bool(cookies_dict or auth_header_str),
        "source": "storage_state",
    }


def save_storage_state_to_vault(
    cco_home: Path | str,
    key_name: str,
    storage_state_path: Path | str,
    *,
    alias: str = _DEFAULT_ALIAS,
    role: str = _DEFAULT_ROLE,
    tenant: str = "",
    target_url: str = "",
) -> dict[str, Any]:
    """Validate a Playwright storage_state file and store it encrypted in CredentialVault."""
    clean_alias = _validate_alias(alias)
    clean_role = str(role or _DEFAULT_ROLE).strip() or _DEFAULT_ROLE
    clean_tenant = str(tenant or "").strip()
    clean_target_url = str(target_url or "").strip()
    if clean_target_url:
        _parse_origin_tuple(clean_target_url, label="target_url")

    clean_key_name = str(key_name or "").strip()
    state_dict = _read_storage_state_file(storage_state_path)
    raw_cookies = state_dict.get("cookies")
    raw_origins = state_dict.get("origins")
    cookies_list: list[Any] = raw_cookies if isinstance(raw_cookies, list) else []
    origins_list: list[Any] = raw_origins if isinstance(raw_origins, list) else []

    payload: dict[str, Any] = {
        "schema": VAULT_STORAGE_STATE_SCHEMA,
        "target_url": clean_target_url,
        "alias": clean_alias,
        "role": clean_role,
        "tenant": clean_tenant,
        "storage_state": state_dict,
    }
    agentic_vault.save_vault_credentials(cco_home, clean_key_name, payload)

    return {
        "saved": True,
        "key_name": clean_key_name,
        "alias": clean_alias,
        "cookie_count": len(cookies_list),
        "origin_count": len(origins_list),
    }


def load_storage_state_actor_from_vault(
    cco_home: Path | str,
    key_name: str,
    *,
    base_url: str,
    alias: str = "",
    role: str = "",
    tenant: str = "",
    now: float | None = None,
    in_scope_assets: Sequence[str] = (),
    out_of_scope_assets: Sequence[str] = (),
) -> dict[str, Any]:
    """Load an encrypted storage_state payload fail-closed and return a scoped actor dict."""
    payload = agentic_vault.load_vault_credentials(cco_home, key_name)
    if (
        payload.get("schema") != VAULT_STORAGE_STATE_SCHEMA
        or not isinstance(payload.get("storage_state"), dict)
    ):
        raise ValueError("vault entry is not a valid storage_state payload")

    eff_alias = str(alias or "").strip() or str(payload.get("alias") or "").strip() or _DEFAULT_ALIAS
    eff_role = str(role or "").strip() or str(payload.get("role") or "").strip() or _DEFAULT_ROLE
    eff_tenant = str(tenant or "").strip() or str(payload.get("tenant") or "").strip()

    return load_storage_state_actor(
        payload["storage_state"],
        base_url=base_url,
        alias=eff_alias,
        role=eff_role,
        tenant=eff_tenant,
        now=now,
        in_scope_assets=in_scope_assets,
        out_of_scope_assets=out_of_scope_assets,
    )
