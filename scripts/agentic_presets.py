"""Opinionated engagement presets and fail-closed ``cco-run/1`` config loader."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
from typing import Any, Sequence

RUN_CONFIG_SCHEMA = "cco-run/1"

# Security boundary: live execution and authorization switches MUST always be
# passed explicitly on the CLI so a static JSON file cannot silently authorize
# live network traffic or remote LLM spend.
FORBIDDEN_CONFIG_KEYS: frozenset[str] = frozenset({
    "execute",
    "allow_non_loopback",
    "authorize_live_provider",
    "live_authorization_reason",
})

PRESETS: dict[str, dict[str, Any]] = {
    "quick": {
        "description": "Fast single-pass triage with tight HTTP/token/time budgets.",
        "options": {
            "execution_mode": "monolithic",
            "max_turns": 25,
            "http_budget": 120,
            "token_budget": 250_000,
            "seconds_budget": 300,
            "auto_crawl": False,
            "auto_crawl_forms": False,
            "prescan": False,
            "max_rps": 0.0,
            "max_degradation_streak": 5,
        },
    },
    "standard": {
        "description": "Balanced sharded assessment with Stage 0 Playwright surface discovery.",
        "options": {
            "execution_mode": "sharded",
            "max_shards": 3,
            "bootstrap_turns": 12,
            "shard_turns": 25,
            "max_turns": 75,
            "http_budget": 300,
            "token_budget": 1_000_000,
            "seconds_budget": 900,
            "auto_crawl": True,
            "auto_crawl_forms": False,
            "auto_crawl_max_pages": 12,
            "auto_crawl_max_actions": 24,
            "prescan": True,
            "prescan_max_requests": 20,
            "max_rps": 0.0,
            "max_degradation_streak": 5,
        },
    },
    "bounty-safe": {
        "description": "Conservative bug-bounty profile: paced RPS, read-only default methods, strict degradation stop.",
        "options": {
            "execution_mode": "sharded",
            "max_shards": 2,
            "bootstrap_turns": 10,
            "shard_turns": 20,
            "max_turns": 60,
            "http_budget": 200,
            "token_budget": 750_000,
            "seconds_budget": 900,
            "allowed_methods": ["GET", "HEAD"],
            "auto_crawl": True,
            "auto_crawl_forms": False,
            "auto_crawl_max_pages": 8,
            "auto_crawl_max_actions": 16,
            "prescan": True,
            "prescan_max_requests": 16,
            "max_rps": 2.0,
            "max_degradation_streak": 3,
        },
    },
    "deep": {
        "description": "Thorough multi-shard assessment with expanded budgets and Stage 0 crawl.",
        "options": {
            "execution_mode": "sharded",
            "max_shards": 5,
            "bootstrap_turns": 16,
            "shard_turns": 35,
            "max_turns": 120,
            "http_budget": 600,
            "token_budget": 2_000_000,
            "seconds_budget": 1800,
            "auto_crawl": True,
            "auto_crawl_forms": False,
            "auto_crawl_max_pages": 20,
            "auto_crawl_max_actions": 40,
            "prescan": True,
            "prescan_max_requests": 24,
            "max_rps": 0.0,
            "max_degradation_streak": 5,
        },
    },
}

_PATH_FIELDS: frozenset[str] = frozenset({
    "credentials_file",
    "provider_config",
    "output_dir",
    "scope_file",
    "vault_home",
    "asset_graph_file",
})
_PATH_LIST_FIELDS: frozenset[str] = frozenset({"seed_surface_files"})
_STRING_FIELDS: frozenset[str] = frozenset({
    "preset",
    "target",
    "model",
    "worker_model",
    "scout_model",
    "bootstrap_model",
    "api_key_env",
    "login_path",
    "session_check_path",
    "refresh_path",
    "reasoning_effort",
    "run_id",
    "scheduler",
    "verification_gate",
    "intervention",
    "execution_mode",
    "vault_key_name",
    "oob_bind_host",
    "oob_advertise_host",
})
_INT_FIELDS: frozenset[str] = frozenset({
    "http_budget",
    "token_budget",
    "seconds_budget",
    "scout_turns",
    "max_member_accounts",
    "max_admin_accounts",
    "max_turns",
    "max_shards",
    "bootstrap_turns",
    "shard_turns",
    "shard_token_quota",
    "epoch_char_limit",
    "max_degradation_streak",
    "auto_crawl_max_pages",
    "auto_crawl_max_actions",
    "prescan_max_requests",
})
_FLOAT_FIELDS: frozenset[str] = frozenset({
    "scout_token_share",
    "cache_token_weight",
    "max_rps",
})
_BOOL_FIELDS: frozenset[str] = frozenset({
    "resume",
    "use_bsag",
    "auto_crawl",
    "auto_crawl_forms",
    "prescan",
})
_STR_LIST_FIELDS: frozenset[str] = frozenset({
    "allowed_methods",
    "discovery_hints",
    "storage_states",
    "tech_hints",
})
_APPENDABLE_LIST_FIELDS: frozenset[str] = frozenset({
    "custom_headers",
    "discovery_hints",
    "storage_states",
    "seed_surface_files",
    "tech_hints",
})

ALLOWED_CONFIG_KEYS: frozenset[str] = (
    frozenset({"schema", "custom_headers"})
    | _PATH_FIELDS
    | _PATH_LIST_FIELDS
    | _STRING_FIELDS
    | _INT_FIELDS
    | _FLOAT_FIELDS
    | _BOOL_FIELDS
    | _STR_LIST_FIELDS
)


def preset_names() -> tuple[str, ...]:
    """Return sorted built-in preset identifiers."""
    return tuple(PRESETS.keys())


def get_preset_options(name: str) -> dict[str, Any]:
    """Return a deep copy of the option defaults for ``name``."""
    clean = str(name or "").strip().lower()
    if not clean:
        return {}
    entry = PRESETS.get(clean)
    if entry is None:
        valid = ", ".join(PRESETS.keys())
        raise ValueError(f"unknown preset {name!r}; valid presets: {valid}")
    return copy.deepcopy(entry["options"])


def describe_presets() -> dict[str, Any]:
    """Return a JSON-serializable catalog of built-in presets and config schema metadata."""
    return {
        "schema": RUN_CONFIG_SCHEMA,
        "presets": {
            name: {
                "description": info["description"],
                "options": copy.deepcopy(info["options"]),
            }
            for name, info in PRESETS.items()
        },
        "cli_only_safety_flags": sorted(FORBIDDEN_CONFIG_KEYS),
    }


def _coerce_header_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, dict):
        out: list[str] = []
        for k, v in raw.items():
            if not isinstance(k, str) or not k.strip() or not isinstance(v, str) or not v.strip():
                raise ValueError("config 'custom_headers' object must map non-empty strings to non-empty strings")
            out.append(f"{k.strip()}: {v.strip()}")
        return out
    if isinstance(raw, list):
        out_list: list[str] = []
        for item in raw:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("config 'custom_headers' list entries must be non-empty 'Name: Value' strings")
            out_list.append(item.strip())
        return out_list
    raise ValueError("config 'custom_headers' must be a JSON object or array of 'Name: Value' strings")


def load_run_config(path: Path) -> dict[str, Any]:
    """Load and strictly validate a ``cco-run/1`` engagement config file (fail-closed)."""
    raw_path = Path(path).expanduser()
    try:
        st = raw_path.lstat()
    except OSError as exc:
        raise ValueError(f"run config file is missing or unreadable: {raw_path}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"run config file must not be a symlink: {raw_path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"run config file must be a regular file: {raw_path}")

    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(raw_path, open_flags)
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            raw_text = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"failed to read run config {raw_path}: {exc}") from exc

    try:
        data = json.loads(raw_text)
    except ValueError as exc:
        raise ValueError(f"run config is not valid JSON: {raw_path}") from exc

    if not isinstance(data, dict):
        raise ValueError("run config must be a JSON object")

    schema = data.get("schema")
    if schema is not None and schema != RUN_CONFIG_SCHEMA:
        raise ValueError(f"unsupported run config schema {schema!r}; expected {RUN_CONFIG_SCHEMA!r}")

    forbidden_found = sorted(FORBIDDEN_CONFIG_KEYS.intersection(data.keys()))
    if forbidden_found:
        raise ValueError(
            "authorization/execution flags must be passed explicitly on the CLI, not in --config: "
            + ", ".join(forbidden_found)
        )

    unknown = sorted(set(data.keys()) - ALLOWED_CONFIG_KEYS)
    if unknown:
        raise ValueError(f"unknown key(s) in run config: {', '.join(unknown)}")

    normalized: dict[str, Any] = {}
    for key, val in data.items():
        if key == "schema" or val is None:
            continue
        if key == "custom_headers":
            normalized[key] = _coerce_header_list(val)
        elif key in _PATH_FIELDS:
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"run config {key!r} must be a non-empty path string")
            normalized[key] = Path(val.strip()).expanduser()
        elif key in _PATH_LIST_FIELDS:
            if not isinstance(val, list) or not all(isinstance(x, str) and x.strip() for x in val):
                raise ValueError(f"run config {key!r} must be an array of non-empty path strings")
            normalized[key] = [Path(x.strip()).expanduser() for x in val]
        elif key in _STRING_FIELDS:
            if not isinstance(val, str):
                raise ValueError(f"run config {key!r} must be a string")
            clean_str = val.strip()
            if key == "preset" and clean_str:
                get_preset_options(clean_str)
                normalized[key] = clean_str.lower()
            else:
                normalized[key] = clean_str
        elif key in _INT_FIELDS:
            if isinstance(val, bool) or not isinstance(val, int):
                raise ValueError(f"run config {key!r} must be an integer")
            normalized[key] = int(val)
        elif key in _FLOAT_FIELDS:
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise ValueError(f"run config {key!r} must be a number")
            normalized[key] = float(val)
        elif key in _BOOL_FIELDS:
            if not isinstance(val, bool):
                raise ValueError(f"run config {key!r} must be a boolean")
            normalized[key] = val
        elif key in _STR_LIST_FIELDS:
            if not isinstance(val, list) or not all(isinstance(x, str) and x.strip() for x in val):
                raise ValueError(f"run config {key!r} must be an array of non-empty strings")
            normalized[key] = [x.strip() for x in val]

    return normalized


def merge_run_options(
    *,
    defaults: dict[str, Any],
    preset: str = "",
    config_options: dict[str, Any] | None = None,
    explicit_overrides: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    """Merge options with precedence: ``defaults < preset < config < explicit_overrides``."""
    cfg = dict(config_options or {})
    overrides = dict(explicit_overrides or {})

    eff_preset = str(overrides.get("preset") or preset or cfg.get("preset") or "").strip().lower()
    preset_opts = get_preset_options(eff_preset) if eff_preset else {}

    merged = copy.deepcopy(defaults)
    for layer in (preset_opts, cfg, overrides):
        for key, val in layer.items():
            if key in {"preset", "config_file"}:
                continue
            if key in _APPENDABLE_LIST_FIELDS:
                if val is None:
                    continue
                prev = list(merged.get(key) or [])
                incoming: Sequence[Any] = val if isinstance(val, (list, tuple)) else [val]
                merged[key] = [*prev, *incoming]
            else:
                merged[key] = val

    return merged, eff_preset
