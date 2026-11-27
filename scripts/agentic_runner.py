#!/usr/bin/env python3
"""Launch the general-purpose AgenticInvestigator against an owned loopback target."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from typing import Any, Sequence
import uuid

SCRIPTS = Path(__file__).resolve().parent
_REPO_ROOT = SCRIPTS.parent
for _p in (str(_REPO_ROOT), str(SCRIPTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import agentic_auth_import  # noqa: E402
import agentic_har_flow  # noqa: E402
import agentic_prescan  # noqa: E402
import agentic_recon  # noqa: E402
import agentic_report  # noqa: E402
import agentic_seed  # noqa: E402
import agentic_vault  # noqa: E402
import llm_config  # noqa: E402
import target_bootstrap  # noqa: E402
from provider_auth import authorize_provider  # noqa: E402
from agentic_http import (  # noqa: E402
    ActorManager,
    AgenticHTTPClient,
    ServiceDegradationError,
    normalize_global_headers,
    parse_custom_headers,
)
from agentic_investigator import (  # noqa: E402
    _EPOCH_HARD_CHAR_LIMIT,
    _PROMPT_HARD_CHAR_LIMIT,
    AgenticInvestigator,
)
from agentic_oob import LoopbackCallbackServer  # noqa: E402
from agentic_presets import (  # noqa: E402
    load_run_config,
    merge_run_options,
    preset_names,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import canonicalize_and_deduplicate_findings  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import MeteredProviderTransport, SessionGate, dump  # noqa: E402

SCHEMA = "agentic-target-run/1"
DEFAULT_LOGIN_PATH = "/api/v1/access/sign-in"
DEFAULT_SESSION_CHECK_PATH = "/api/v1/access/session"


def _runner_defaults() -> dict[str, Any]:
    return {
        "target": "",
        "credentials_file": None,
        "provider_config": llm_config.default_config(),
        "model": "",
        "worker_model": "",
        "scout_model": "",
        "scout_turns": 22,
        "scout_token_share": 0.40,
        "api_key_env": None,
        "output_dir": None,
        "http_budget": None,
        "token_budget": 1_000_000,
        "seconds_budget": 900,
        "allowed_methods": None,
        "discovery_hints": None,
        "login_path": DEFAULT_LOGIN_PATH,
        "session_check_path": DEFAULT_SESSION_CHECK_PATH,
        "refresh_path": "",
        "max_member_accounts": 6,
        "max_admin_accounts": 2,
        "max_turns": 75,
        "reasoning_effort": "max",
        "resume": False,
        "run_id": "",
        "execute": False,
        "authorize_live_provider": False,
        "live_authorization_reason": "",
        "use_bsag": False,
        "scheduler": "prompt_only",
        "verification_gate": "differential",
        "intervention": "off",
        "execution_mode": "monolithic",
        "max_shards": 3,
        "bootstrap_turns": 12,
        "shard_turns": 25,
        "shard_token_quota": 0,
        "bootstrap_model": "",
        "max_shard_retries": 1,
        "retry_model": "",
        "retry_budget_ratio": 0.15,
        "max_retry_shards": 2,
        "epoch_char_limit": 0,
        "cache_token_weight": 0.10,
        "scope_file": None,
        "allow_non_loopback": False,
        "max_degradation_streak": 5,
        "max_rps": 0.0,
        "vault_home": None,
        "vault_key_name": "",
        "storage_states": None,
        "custom_headers": None,
        "seed_surface_files": None,
        "asset_graph_file": None,
        "tech_hints": None,
        "auto_crawl": False,
        "auto_crawl_forms": False,
        "auto_crawl_max_pages": 12,
        "auto_crawl_max_actions": 24,
        "prescan": False,
        "prescan_max_requests": 24,
        "apply_har_headers": False,
        "oob_bind_host": "",
        "oob_advertise_host": "",
    }


def _extract_bundle_auth_path(bundle: dict[str, Any], key: str) -> str:
    """Extract an optional non-empty auth path from top-level or nested ``auth`` in credentials bundle."""
    top = bundle.get(key)
    if isinstance(top, str) and top.strip():
        return top.strip()
    nested = bundle.get("auth")
    if isinstance(nested, dict):
        sub = nested.get(key)
        if isinstance(sub, str) and sub.strip():
            return sub.strip()
    return ""


def _resolve_auth_paths(
    *,
    login_path: str,
    session_check_path: str,
    bundle: dict[str, Any],
) -> tuple[str, str, str]:
    """Resolve effective (login_path, session_check_path, login_path_source).

    Explicit non-default CLI/caller arguments take precedence over credentials.json,
    which in turn overrides the built-in defaults.
    """
    clean_login = str(login_path or "").strip() or DEFAULT_LOGIN_PATH
    bundle_login = _extract_bundle_auth_path(bundle, "login_path")
    if clean_login != DEFAULT_LOGIN_PATH:
        eff_login_path = clean_login
        login_path_source = "cli"
    elif bundle_login:
        eff_login_path = bundle_login
        login_path_source = "credentials_file"
    else:
        eff_login_path = DEFAULT_LOGIN_PATH
        login_path_source = "default"

    clean_session = str(session_check_path or "").strip() or DEFAULT_SESSION_CHECK_PATH
    bundle_session = _extract_bundle_auth_path(bundle, "session_check_path")
    if clean_session != DEFAULT_SESSION_CHECK_PATH:
        eff_session_check_path = clean_session
    elif bundle_session:
        eff_session_check_path = bundle_session
    else:
        eff_session_check_path = DEFAULT_SESSION_CHECK_PATH

    return eff_login_path, eff_session_check_path, login_path_source


def _extract_stage0_login_candidates(stage0_result: dict[str, Any]) -> list[str]:
    """Extract candidate login endpoints from Stage 0 output, prioritizing POST forms and POST links."""
    post_forms: list[str] = []
    post_links: list[str] = []
    other_routes: list[str] = []
    seen: set[str] = set()

    def _add(bucket: list[str], raw_url: Any) -> None:
        val = str(raw_url or "").strip()
        if val and val not in seen:
            seen.add(val)
            bucket.append(val)

    for entry in stage0_result.get("forms") or ():
        if isinstance(entry, dict):
            method = str(entry.get("method") or "POST").strip().upper()
            raw_url = entry.get("url") or entry.get("action") or entry.get("path") or ""
            if method == "POST":
                _add(post_forms, raw_url)
            else:
                _add(other_routes, raw_url)
        elif isinstance(entry, str):
            _add(post_forms, entry)

    for entry in stage0_result.get("links") or ():
        if isinstance(entry, dict):
            method = str(entry.get("method") or "").strip().upper()
            raw_url = entry.get("url") or entry.get("path") or ""
            if method == "POST":
                _add(post_links, raw_url)
            else:
                _add(other_routes, raw_url)
        elif isinstance(entry, str):
            _add(other_routes, entry)

    return [*post_forms, *post_links, *other_routes]


def _build_auth_metadata(
    actors: ActorManager,
    *,
    login_path_source: str,
) -> dict[str, Any]:
    """Build strictly non-secret operational auth metadata for manifest/plan artifacts."""
    return {
        "login_path": str(actors.login_path),
        "session_check_path": str(actors.session_check_path),
        "login_path_source": str(login_path_source),
        "authenticated_actors": actors.authenticated_non_anon_aliases(),
        "unauthenticated_credentialed_actors": actors.unauthenticated_credentialed_aliases(),
    }


def _parse_bool_flag(raw: Any) -> bool:
    val = str(raw).strip().lower()
    if val in {"1", "true", "yes", "on"}:
        return True
    if val in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"invalid boolean flag value: {raw!r}; expected true|false")


def _parse_custom_headers(raw_values: Sequence[str] | dict[str, Any] | None) -> dict[str, str]:
    """Parse repeatable ``Name: Value`` operator headers or a dict into a validated mapping."""
    return parse_custom_headers(raw_values)


def _merge_header_maps(*maps: dict[str, str] | None) -> dict[str, str]:
    """Merge header mappings left-to-right with case-insensitive replacement."""
    merged: dict[str, str] = {}
    for mapping in maps:
        for hk, hv in (mapping or {}).items():
            for existing in [ek for ek in merged if ek.lower() == hk.lower()]:
                merged.pop(existing, None)
            merged[hk] = hv
    return normalize_global_headers(merged)


_HAR_GLOBAL_SKIP_HEADERS: frozenset[str] = frozenset({"content-type", "accept"})
_RUNNER_SECRET_HEADER_PREFIXES: tuple[str, ...] = ("sec-", "x-b3-", "x-amz-", ":")
_RUNNER_SECRET_HEADER_TOKENS: frozenset[str] = frozenset({
    "auth",
    "authorization",
    "token",
    "secret",
    "password",
    "passwd",
    "cookie",
    "jwt",
    "bearer",
    "apikey",
    "credential",
    "credentials",
    "private",
    "key",
    "signature",
    "sig",
    "hmac",
    "session",
    "sessionid",
    "sid",
    "csrf",
    "xsrf",
    "otp",
    "pin",
})
_RUNNER_SECRET_HEADER_SUBSTRINGS: tuple[str, ...] = (
    "auth",
    "jwt",
    "bearer",
    "signature",
    "credential",
    "hmac",
    "session",
    "csrf",
    "xsrf",
    "private_key",
    "secret",
    "token",
    "password",
    "passwd",
    "cookie",
    "apikey",
    "api_key",
)


def _is_blocked_har_header(name: str, value: str) -> bool:
    """Defense-in-depth secret header name/value blocklist for HAR/seed app headers."""
    if agentic_har_flow._is_secret_header_name(name) or agentic_har_flow._is_secret_header_value(value):
        return True
    low_name = name.strip().lower()
    if not low_name or any(low_name.startswith(prefix) for prefix in _RUNNER_SECRET_HEADER_PREFIXES):
        return True
    snake, tokens = agentic_har_flow._to_snake_tokens(low_name)
    if snake in _RUNNER_SECRET_HEADER_TOKENS or any(tok in _RUNNER_SECRET_HEADER_TOKENS for tok in tokens):
        return True
    if any(sub in snake for sub in _RUNNER_SECRET_HEADER_SUBSTRINGS):
        return True
    stripped_val = value.strip()
    if not stripped_val or agentic_har_flow._has_secret_value_pattern(stripped_val):
        return True
    return False


def _supported_kwargs(fn: Any, candidate_kwargs: dict[str, Any]) -> dict[str, Any]:
    """Filter optional kwargs against `fn`'s signature for safe cross-module compatibility."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return {}
    params = sig.parameters
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return dict(candidate_kwargs)
    return {k: v for k, v in candidate_kwargs.items() if k in params}


def _filter_safe_har_app_headers(*raw_maps: Any) -> dict[str, str]:
    """Extract strictly non-secret, non-auth/cookie/CSRF application headers from HAR/seed sources."""
    merged: dict[str, str] = {}
    for raw in raw_maps:
        if not isinstance(raw, dict) or not raw:
            continue
        sanitized = agentic_har_flow._sanitize_app_headers(raw)
        for hk, hv in sanitized.items():
            if hk.strip().lower() in _HAR_GLOBAL_SKIP_HEADERS:
                continue
            if _is_blocked_har_header(hk, hv):
                continue
            try:
                validated = normalize_global_headers({hk: hv})
            except ValueError:
                continue
            for vk, vv in validated.items():
                for existing in [ek for ek in merged if ek.lower() == vk.lower()]:
                    merged.pop(existing, None)
                merged[vk] = vv
    return merged


def _extract_bundle_custom_headers(bundle: dict[str, Any], scope_rules: dict[str, Any]) -> dict[str, str]:
    """Extract optional operator custom headers from a credentials bundle or its scope_rules."""
    sources: list[dict[str, str]] = []
    for container, keys in (
        (scope_rules, ("headers", "request_headers", "custom_headers")),
        (bundle, ("request_headers", "custom_headers")),
    ):
        for key in keys:
            raw = container.get(key)
            if raw is not None:
                sources.append(_parse_custom_headers(raw))
    return _merge_header_maps(*sources)


def _custom_header_arg(raw: str) -> str:
    try:
        _parse_custom_headers([raw])
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return raw


def _extract_har_flow_summary(
    seed_surface_files: Sequence[Path],
    *,
    base_url: str,
    excluded_paths: Sequence[str],
    in_scope_assets: Sequence[str],
    out_of_scope_assets: Sequence[str],
) -> tuple[dict[str, Any] | None, str]:
    """Extract and merge scope-filtered HAR multi-step workflows from any `.har` seed files."""
    har_files = [Path(p) for p in seed_surface_files if Path(p).suffix.lower() == ".har"]
    if not har_files:
        return None, ""
    merged_flows: list[dict[str, Any]] = []
    merged_headers: dict[str, str] = {}
    entries_total = 0
    entries_accepted = 0
    entries_dropped_scope = 0
    entries_dropped_static = 0
    entries_dropped_noise = 0
    chained_steps_count = 0
    for har_path in har_files:
        try:
            doc = agentic_har_flow.extract_har_flows(
                har_path,
                base_url=base_url,
                excluded_paths=excluded_paths,
                in_scope_assets=in_scope_assets,
                out_of_scope_assets=out_of_scope_assets,
            )
        except (OSError, ValueError):
            continue
        stats = doc.get("stats") or {}
        entries_total += int(stats.get("entries_total") or 0)
        entries_accepted += int(stats.get("entries_accepted") or 0)
        entries_dropped_scope += int(stats.get("entries_dropped_scope") or 0)
        entries_dropped_static += int(stats.get("entries_dropped_static") or 0)
        entries_dropped_noise += int(stats.get("entries_dropped_noise") or 0)
        chained_steps_count += int(stats.get("chained_steps_count") or 0)
        for hk, hv in (doc.get("recommended_app_headers") or {}).items():
            merged_headers.setdefault(str(hk), str(hv))
        for flow in doc.get("flows") or []:
            if len(merged_flows) >= agentic_har_flow.MAX_HAR_FLOWS:
                break
            if isinstance(flow, dict):
                copied = dict(flow)
                copied["flow_id"] = f"flow_{len(merged_flows) + 1}"
                merged_flows.append(copied)
    if not merged_flows and entries_total == 0:
        return None, ""
    mutation_cases = agentic_har_flow.build_flow_mutation_cases(merged_flows)
    combined_doc: dict[str, Any] = {
        "schema": agentic_har_flow.HAR_FLOW_SCHEMA,
        "base_url": base_url,
        "flows": merged_flows,
        "recommended_app_headers": merged_headers,
        "mutation_cases": mutation_cases,
        "stats": {
            "har_files_count": len(har_files),
            "entries_total": entries_total,
            "entries_accepted": entries_accepted,
            "entries_dropped_scope": entries_dropped_scope,
            "entries_dropped_static": entries_dropped_static,
            "entries_dropped_noise": entries_dropped_noise,
            "flows_count": len(merged_flows),
            "steps_count": sum(len(f.get("steps") or []) for f in merged_flows),
            "chained_steps_count": chained_steps_count,
            "mutation_cases_count": len(mutation_cases),
        },
    }
    handoff = (
        agentic_har_flow.format_har_flows_handoff(combined_doc, max_chars=2400)
        if merged_flows
        else ""
    )
    return combined_doc, handoff


def _parse_allowed_methods(
    cli_methods: Sequence[str] | None,
    scope_rules: dict[str, Any],
) -> list[str]:
    if cli_methods:
        parsed: list[str] = []
        for item in cli_methods:
            for part in str(item).split(","):
                clean = part.strip().upper()
                if clean and clean not in parsed:
                    parsed.append(clean)
        if parsed:
            return parsed
    raw = scope_rules.get("allowed_methods")
    if isinstance(raw, list) and raw:
        cleaned = [str(m).strip().upper() for m in raw if isinstance(m, str) and m.strip()]
        if cleaned:
            return cleaned
    return ["GET"]


def run_agentic_target(
    *,
    target: str = "",
    credentials_file: Path | None = None,
    provider_config: Path = llm_config.default_config(),
    model: str = "",
    worker_model: str = "",
    scout_model: str = "",
    scout_turns: int = 22,
    scout_token_share: float = 0.40,
    api_key_env: str | None = None,
    output_dir: Path | None = None,
    http_budget: int | None = None,
    token_budget: int = 1_000_000,
    seconds_budget: int = 900,
    allowed_methods: Sequence[str] | None = None,
    discovery_hints: Sequence[str] | None = None,
    login_path: str = DEFAULT_LOGIN_PATH,
    session_check_path: str = DEFAULT_SESSION_CHECK_PATH,
    refresh_path: str = "",
    max_member_accounts: int = 6,
    max_admin_accounts: int = 2,
    max_turns: int = 75,
    reasoning_effort: str = "max",
    resume: bool = False,
    run_id: str = "",
    execute: bool = False,
    authorize_live_provider: bool = False,
    live_authorization_reason: str = "",
    use_bsag: bool = False,
    scheduler: str = "prompt_only",
    verification_gate: str = "differential",
    intervention: str = "off",
    execution_mode: str = "monolithic",
    max_shards: int = 3,
    bootstrap_turns: int = 12,
    shard_turns: int = 25,
    shard_token_quota: int = 0,
    bootstrap_model: str = "",
    max_shard_retries: int = 1,
    retry_model: str = "",
    retry_budget_ratio: float = 0.15,
    max_retry_shards: int = 2,
    epoch_char_limit: int = 0,
    cache_token_weight: float = 0.10,
    scope_file: Path | None = None,
    allow_non_loopback: bool = False,
    max_degradation_streak: int = 5,
    max_rps: float = 0.0,
    vault_home: Path | None = None,
    vault_key_name: str = "",
    storage_states: Sequence[str] | None = None,
    custom_headers: Sequence[str] | None = None,
    seed_surface_files: Sequence[Path] | None = None,
    asset_graph_file: Path | None = None,
    tech_hints: Sequence[str] | None = None,
    auto_crawl: bool = False,
    auto_crawl_forms: bool = False,
    auto_crawl_max_pages: int = 12,
    auto_crawl_max_actions: int = 24,
    prescan: bool = False,
    prescan_max_requests: int = 24,
    apply_har_headers: bool = False,
    oob_bind_host: str = "",
    oob_advertise_host: str = "",
    preset: str = "",
    config_file: Path | None = None,
    cancel_event: threading.Event | None = None,
    _options_resolved: bool = False,
) -> tuple[Path, dict[str, Any]]:
    """Run (or plan when execute=False) AgenticInvestigator against an authorized target."""
    eff_preset = str(preset or "").strip().lower()
    eff_config_path: Path | None = Path(config_file).expanduser().resolve() if config_file is not None else None
    if not _options_resolved and (eff_preset or config_file is not None):
        defaults = _runner_defaults()
        local_vals: dict[str, Any] = {
            "target": target,
            "credentials_file": credentials_file,
            "provider_config": provider_config,
            "model": model,
            "worker_model": worker_model,
            "scout_model": scout_model,
            "scout_turns": scout_turns,
            "scout_token_share": scout_token_share,
            "api_key_env": api_key_env,
            "output_dir": output_dir,
            "http_budget": http_budget,
            "token_budget": token_budget,
            "seconds_budget": seconds_budget,
            "allowed_methods": allowed_methods,
            "discovery_hints": discovery_hints,
            "login_path": login_path,
            "session_check_path": session_check_path,
            "refresh_path": refresh_path,
            "max_member_accounts": max_member_accounts,
            "max_admin_accounts": max_admin_accounts,
            "max_turns": max_turns,
            "reasoning_effort": reasoning_effort,
            "resume": resume,
            "run_id": run_id,
            "execute": execute,
            "authorize_live_provider": authorize_live_provider,
            "live_authorization_reason": live_authorization_reason,
            "use_bsag": use_bsag,
            "scheduler": scheduler,
            "verification_gate": verification_gate,
            "intervention": intervention,
            "execution_mode": execution_mode,
            "max_shards": max_shards,
            "bootstrap_turns": bootstrap_turns,
            "shard_turns": shard_turns,
            "shard_token_quota": shard_token_quota,
            "bootstrap_model": bootstrap_model,
            "max_shard_retries": max_shard_retries,
            "retry_model": retry_model,
            "retry_budget_ratio": retry_budget_ratio,
            "max_retry_shards": max_retry_shards,
            "epoch_char_limit": epoch_char_limit,
            "cache_token_weight": cache_token_weight,
            "scope_file": scope_file,
            "allow_non_loopback": allow_non_loopback,
            "max_degradation_streak": max_degradation_streak,
            "max_rps": max_rps,
            "vault_home": vault_home,
            "vault_key_name": vault_key_name,
            "storage_states": storage_states,
            "custom_headers": custom_headers,
            "seed_surface_files": seed_surface_files,
            "asset_graph_file": asset_graph_file,
            "tech_hints": tech_hints,
            "auto_crawl": auto_crawl,
            "auto_crawl_forms": auto_crawl_forms,
            "auto_crawl_max_pages": auto_crawl_max_pages,
            "auto_crawl_max_actions": auto_crawl_max_actions,
            "prescan": prescan,
            "prescan_max_requests": prescan_max_requests,
            "apply_har_headers": apply_har_headers,
            "oob_bind_host": oob_bind_host,
            "oob_advertise_host": oob_advertise_host,
        }
        explicit_overrides = {
            k: v for k, v in local_vals.items() if v != defaults[k]
        }
        cfg_opts = load_run_config(config_file) if config_file is not None else None
        merged, resolved_preset = merge_run_options(
            defaults=defaults,
            preset=eff_preset,
            config_options=cfg_opts,
            explicit_overrides=explicit_overrides,
        )
        return run_agentic_target(
            **merged,
            preset=resolved_preset,
            config_file=config_file,
            cancel_event=cancel_event,
            _options_resolved=True,
        )
    if output_dir is None:
        raise ValueError("output_dir is required (via --output-dir or --config)")
    if isinstance(cache_token_weight, bool):
        raise ValueError("cache_token_weight must be between 0.0 and 1.0")
    eff_cache_weight = float(cache_token_weight)
    if not (0.0 <= eff_cache_weight <= 1.0):
        raise ValueError(f"cache_token_weight must be between 0.0 and 1.0, got {cache_token_weight!r}")
    if isinstance(retry_budget_ratio, bool):
        raise ValueError("retry_budget_ratio must be a finite number between 0.0 and 0.35")
    raw_retry_ratio = float(retry_budget_ratio)
    if not math.isfinite(raw_retry_ratio):
        raise ValueError(f"retry_budget_ratio must be a finite number, got {retry_budget_ratio!r}")
    eff_retry_budget_ratio = min(0.35, max(0.0, raw_retry_ratio))
    eff_max_shard_retries = max(0, int(max_shard_retries))
    eff_max_retry_shards = max(1, int(max_retry_shards))
    if isinstance(max_rps, bool):
        raise ValueError("max_rps must be a finite number >= 0.0")
    eff_max_rps = float(max_rps)
    if not math.isfinite(eff_max_rps) or eff_max_rps < 0.0:
        raise ValueError(f"max_rps must be a finite number >= 0.0, got {max_rps!r}")
    cli_global_headers = _parse_custom_headers(custom_headers)
    vault_storage_payload: dict[str, Any] | None = None
    if credentials_file is not None:
        bundle = target_bootstrap.load_credentials_bundle(credentials_file)
    elif vault_home is not None and str(vault_key_name or "").strip():
        loaded_vault = agentic_vault.load_vault_credentials(vault_home, str(vault_key_name).strip())
        if loaded_vault.get("schema") == "agentic-vault-storage-state/1":
            vault_storage_payload = loaded_vault
            bundle = {"target_url": loaded_vault.get("target_url") or ""}
        else:
            bundle = loaded_vault
    else:
        bundle = {}
    eff_login_path, eff_session_check_path, login_path_source = _resolve_auth_paths(
        login_path=login_path,
        session_check_path=session_check_path,
        bundle=bundle,
    )
    eff_refresh_path = str(refresh_path or "").strip() or _extract_bundle_auth_path(bundle, "refresh_path")
    base, scope_meta = target_bootstrap.resolve_target_origin(
        target or str(bundle.get("target_url") or ""),
        scope_file=scope_file,
        allow_non_loopback=bool(allow_non_loopback),
    )
    eff_excluded_paths = list(scope_meta.get("excluded_paths") or [])
    eff_in_scope_assets = tuple(scope_meta.get("in_scope_assets") or ())
    eff_out_of_scope_assets = tuple(scope_meta.get("out_of_scope_assets") or ())
    eff_loopback_only = bool(scope_meta.get("loopback_only", True))
    eff_run_id = str(run_id or bundle.get("run_id") or "").strip() or uuid.uuid4().hex
    raw_scope = bundle.get("scope_rules")
    scope_rules: dict[str, Any] = raw_scope if isinstance(raw_scope, dict) else {}
    scope_file_headers = _parse_custom_headers(scope_meta.get("custom_headers"))
    bundle_headers = _extract_bundle_custom_headers(bundle, scope_rules)
    eff_methods = _parse_allowed_methods(allowed_methods, scope_rules)
    bundle_max_req = scope_rules.get("max_requests")
    eff_http_budget = int(
        http_budget
        if http_budget is not None
        else (bundle_max_req if isinstance(bundle_max_req, int) and bundle_max_req > 0 else 300)
    )
    eff_discovery_hints = [
        str(item).strip()
        for item in (discovery_hints if discovery_hints else (bundle.get("discovery") or []))
        if isinstance(item, str) and str(item).strip()
    ] or ["/"]
    seed_data: dict[str, Any] | None = None
    har_flows_doc: dict[str, Any] | None = None
    har_flows_handoff: str = ""
    asset_graph_doc: dict[str, Any] | None = None
    asset_graph_raw: dict[str, Any] | None = None
    asset_graph_handoff: str = ""
    if asset_graph_file is not None:
        asset_graph_doc = agentic_recon.load_asset_graph_for_run(
            asset_graph_file,
            base_url=base,
            excluded_paths=eff_excluded_paths,
            in_scope_assets=eff_in_scope_assets,
            out_of_scope_assets=eff_out_of_scope_assets,
        )
        try:
            loaded_ag = json.loads(agentic_recon._read_regular_file(asset_graph_file))
            asset_graph_raw = loaded_ag if isinstance(loaded_ag, dict) else asset_graph_doc
        except (OSError, ValueError):
            asset_graph_raw = asset_graph_doc
        for hint in asset_graph_doc.get("discovery_hints") or []:
            if hint not in eff_discovery_hints:
                eff_discovery_hints.append(hint)
        asset_graph_handoff = str(asset_graph_doc.get("handoff") or "")
    if seed_surface_files:
        seed_data = agentic_seed.load_seed_surface_files(
            seed_surface_files,
            base_url=base,
            excluded_paths=eff_excluded_paths,
            in_scope_assets=eff_in_scope_assets,
            out_of_scope_assets=eff_out_of_scope_assets,
        )
        for hint in seed_data.get("discovery_hints") or []:
            if hint not in eff_discovery_hints:
                eff_discovery_hints.append(hint)
        har_flows_doc, har_flows_handoff = _extract_har_flow_summary(
            seed_surface_files,
            base_url=base,
            excluded_paths=eff_excluded_paths,
            in_scope_assets=eff_in_scope_assets,
            out_of_scope_assets=eff_out_of_scope_assets,
        )
    har_app_headers = _filter_safe_har_app_headers(
        seed_data.get("app_headers") if isinstance(seed_data, dict) else None,
        har_flows_doc.get("recommended_app_headers") if isinstance(har_flows_doc, dict) else None,
    )
    operator_headers = _merge_header_maps(
        scope_file_headers,
        bundle_headers,
        cli_global_headers,
    )
    if apply_har_headers and har_app_headers:
        global_headers = _merge_header_maps(
            har_app_headers,
            operator_headers,
        )
    else:
        global_headers = dict(operator_headers)
    if tech_hints:
        eff_discovery_hints = agentic_seed.enrich_tech_discovery_hints(
            tech_hints,
            existing_hints=eff_discovery_hints,
        )
    accounts = target_bootstrap.select_representative_accounts(
        bundle.get("test_accounts") or [],
        max_members=max_member_accounts,
        max_admins=max_admin_accounts,
    )
    if vault_storage_payload is not None:
        accounts.append(
            agentic_auth_import.load_storage_state_actor(
                vault_storage_payload.get("storage_state") or {},
                base_url=base,
                alias=str(vault_storage_payload.get("alias") or "browser-user"),
                role=str(vault_storage_payload.get("role") or "member"),
                tenant=str(vault_storage_payload.get("tenant") or ""),
                in_scope_assets=eff_in_scope_assets,
                out_of_scope_assets=eff_out_of_scope_assets,
                refresh_path=eff_refresh_path,
            )
        )
    for raw_spec in storage_states or ():
        s_alias, s_role, s_tenant, s_path = agentic_auth_import.parse_storage_state_spec(str(raw_spec))
        accounts.append(
            agentic_auth_import.load_storage_state_actor(
                s_path,
                base_url=base,
                alias=s_alias,
                role=s_role,
                tenant=s_tenant,
                in_scope_assets=eff_in_scope_assets,
                out_of_scope_assets=eff_out_of_scope_assets,
                refresh_path=eff_refresh_path,
            )
        )

    auth = authorize_provider(
        provider_config,
        model=model,
        worker_model=worker_model,
        execute=execute,
        authorize_live_provider=authorize_live_provider,
        live_authorization_reason=live_authorization_reason,
        api_key_env=api_key_env,
    )
    models = auth["models"]
    provider = llm_config.provider_settings(provider_config, models)
    eff_scout_model = str(scout_model or "").strip()
    scout_model_id = ""
    if eff_scout_model:
        scout_sel = llm_config.model_selection(provider_config, model=models["worker"], worker_model=eff_scout_model)
        scout_provider = llm_config.provider_settings(provider_config, scout_sel)
        provider["models"] = set(provider["models"]) | set(scout_provider["models"])
        models = {**models, "scout": scout_sel["worker"]}
        scout_model_id = scout_sel["worker"].split("/", 1)[1]
    eff_bootstrap_model = str(bootstrap_model or "").strip()
    bootstrap_model_id = ""
    if eff_bootstrap_model:
        boot_sel = llm_config.model_selection(provider_config, model=models["worker"], worker_model=eff_bootstrap_model)
        boot_provider = llm_config.provider_settings(provider_config, boot_sel)
        provider["models"] = set(provider["models"]) | set(boot_provider["models"])
        models = {**models, "bootstrap": boot_sel["worker"]}
        bootstrap_model_id = boot_sel["worker"].split("/", 1)[1]
    eff_retry_model = str(retry_model or "").strip()
    retry_model_id = ""
    if eff_retry_model:
        retry_sel = llm_config.model_selection(provider_config, model=models["worker"], worker_model=eff_retry_model)
        retry_provider = llm_config.provider_settings(provider_config, retry_sel)
        provider["models"] = set(provider["models"]) | set(retry_provider["models"])
        models = {**models, "retry": retry_sel["worker"]}
        retry_model_id = retry_sel["worker"].split("/", 1)[1]
    eff_reasoning_effort = llm_config.normalize_reasoning_effort(reasoning_effort)
    effective_provider_options, provider_routing = llm_config.adapt_provider_options_for_effort(
        provider.get("provider_options"),
        models=list(models.values()),
        provider_name=str(provider.get("name") or ""),
        provider_url=str(provider.get("url") or ""),
        reasoning_effort=eff_reasoning_effort,
    )

    raw_epoch_limit = int(epoch_char_limit)
    eff_epoch_char_limit = max(
        _PROMPT_HARD_CHAR_LIMIT,
        _EPOCH_HARD_CHAR_LIMIT if raw_epoch_limit <= 0 else raw_epoch_limit,
    )

    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    limits = {
        "http_requests": eff_http_budget,
        "llm_tokens": int(token_budget),
        "seconds": int(seconds_budget),
        "max_turns": int(max_turns),
        "epoch_char_limit": eff_epoch_char_limit,
        "cache_token_weight": eff_cache_weight,
        "max_rps": eff_max_rps,
    }

    ablation_cfg = {
        "use_bsag": bool(use_bsag),
        "scheduler": str(scheduler or "ucb").strip().lower(),
        "verification_gate": str(verification_gate or "differential").strip().lower(),
        "intervention": str(intervention or "lazy").strip().lower(),
        "execution_mode": str(execution_mode or "ephemeral").strip().lower(),
    }
    sharding_cfg: dict[str, Any] = {
        "max_shards": max(1, int(max_shards)),
        "bootstrap_turns": max(1, int(bootstrap_turns)),
        "shard_turns": max(1, int(shard_turns)),
    }
    if eff_max_shard_retries != 1:
        sharding_cfg["max_shard_retries"] = eff_max_shard_retries
    if abs(eff_retry_budget_ratio - 0.15) > 1e-9:
        sharding_cfg["retry_budget_ratio"] = eff_retry_budget_ratio
    if eff_max_retry_shards != 2:
        sharding_cfg["max_retry_shards"] = eff_max_retry_shards
    eff_shard_token_quota = max(0, int(shard_token_quota))
    if eff_shard_token_quota > 0:
        sharding_cfg["shard_token_quota"] = eff_shard_token_quota
    if eff_bootstrap_model:
        sharding_cfg["bootstrap_model"] = models["bootstrap"]
    if eff_retry_model:
        sharding_cfg["retry_model"] = models["retry"]

    eff_auto_crawl = bool(auto_crawl or auto_crawl_forms)
    eff_auto_crawl_forms = bool(auto_crawl_forms and "POST" in eff_methods)
    stage0_cfg: dict[str, Any] = {
        "enabled": eff_auto_crawl,
        "forms_requested": bool(auto_crawl_forms),
        "forms_allowed": eff_auto_crawl_forms,
        "max_pages": max(1, int(auto_crawl_max_pages)),
        "max_actions": max(0, int(auto_crawl_max_actions)),
    }
    eff_prescan = bool(prescan)
    eff_prescan_max_requests = max(1, int(prescan_max_requests))
    prescan_cfg: dict[str, Any] = {
        "enabled": eff_prescan,
        "max_requests": eff_prescan_max_requests,
    }

    eff_oob_bind = str(oob_bind_host or os.environ.get("CCO_OOB_BIND_HOST") or "").strip()
    eff_oob_adv = str(oob_advertise_host or os.environ.get("CCO_OOB_ADVERTISE_HOST") or "").strip()
    configured_oob: LoopbackCallbackServer | None = None
    if eff_oob_bind or eff_oob_adv:
        configured_oob = LoopbackCallbackServer.from_config(
            bind_host=eff_oob_bind,
            advertise_host=eff_oob_adv,
        )
    oob_summary: dict[str, Any] = {
        "bind_host": configured_oob.host if configured_oob is not None else "127.0.0.1",
        "advertise_host": configured_oob.advertise_host if configured_oob is not None else "",
        "bind_scope": (
            "bridge"
            if (configured_oob is not None and (configured_oob.allow_private_bridge or configured_oob.advertise_host))
            else "loopback"
        ),
    }

    asset_graph_manifest: dict[str, Any] | None = None
    if asset_graph_doc is not None:
        asset_graph_manifest = dict(asset_graph_doc.get("stats") or {})
        if asset_graph_file is not None:
            asset_graph_manifest["file"] = str(Path(asset_graph_file).expanduser().resolve())

    if not execute:
        plan_path = output / "agentic-plan.json"
        plan_actors = ActorManager(
            accounts,
            login_path=eff_login_path,
            session_check_path=eff_session_check_path,
            global_headers=global_headers,
        )
        plan = {
            "schema": SCHEMA,
            "mode": "plan_only",
            "target": base,
            "scope": {
                "loopback_only": eff_loopback_only,
                "scope_file": scope_meta.get("scope_file"),
                "excluded_paths_count": len(eff_excluded_paths),
                "multi_origin": bool(len(eff_in_scope_assets) > 0 and not eff_loopback_only),
                "in_scope_assets_count": len(eff_in_scope_assets),
                "max_degradation_streak": max(0, int(max_degradation_streak)),
            },
            "run_id": eff_run_id,
            "models": models,
            "reasoning_effort": eff_reasoning_effort or None,
            "provider_routing": provider_routing,
            "provider_kind": auth["provider_kind"],
            "provider_host": auth["provider_host"],
            "allowed_methods": eff_methods,
            "request_headers": sorted(global_headers),
            "discovery_hints": eff_discovery_hints,
            "seed_surface": dict(seed_data.get("stats") or {}) if seed_data is not None else None,
            "har_flows": dict(har_flows_doc.get("stats") or {}) if har_flows_doc is not None else None,
            "asset_graph": dict(asset_graph_manifest) if asset_graph_manifest is not None else None,
            "stage0_crawl": dict(stage0_cfg),
            "prescan": dict(prescan_cfg),
            "oob_listener": dict(oob_summary),
            "auth": _build_auth_metadata(plan_actors, login_path_source=login_path_source),
            "ablation": ablation_cfg,
            "sharding": sharding_cfg,
            "selected_accounts": [
                {"alias": row["alias"], "tenant": row.get("tenant", ""), "role": row.get("role", "")}
                for row in accounts
            ],
            "limits": limits,
            "llm_calls": 0,
            "target_requests": 0,
        }
        if eff_preset:
            plan["preset"] = eff_preset
        if eff_config_path is not None:
            plan["config_file"] = str(eff_config_path)
        dump(plan_path, plan)
        return plan_path, plan

    env_name = api_key_env or provider.get("api_key_env", "")
    api_key = os.environ.get(env_name, "")
    if not api_key and auth["provider_kind"] == "remote":
        raise PermissionError("provider credentials are missing in environment")

    started = time.monotonic()
    private_dir = output / "private"
    private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    budget = SharedBudget(
        http=eff_http_budget,
        tokens=int(token_budget),
        seconds=int(seconds_budget),
    )
    session_gate = SessionGate()
    transport = MeteredProviderTransport(
        budget=budget,
        private=private_dir,
        provider=provider["url"],
        models=provider["models"],
        api_key=api_key,
        api_key_header=provider.get("api_key_header", "Authorization"),
        session_gate=session_gate,
        provider_options=effective_provider_options,
        cache_token_weight=eff_cache_weight,
    )
    receipt_store = ReceiptStore(output)
    actor_mgr_kwargs: dict[str, Any] = {
        "login_path": eff_login_path,
        "session_check_path": eff_session_check_path,
        "global_headers": global_headers,
    }
    resolved_auth_hdr = ""
    if eff_refresh_path:
        actor_mgr_kwargs["refresh_path"] = eff_refresh_path
    actors = ActorManager(accounts, **actor_mgr_kwargs)

    def _host_session_cache_path() -> Path:
        raw_home = (os.environ.get("CCO_HOME") or "").strip()
        cco_home = Path(raw_home).expanduser() if raw_home else (Path.home() / ".cco")
        key = hashlib.sha256(str(output.resolve()).encode("utf-8")).hexdigest()[:24]
        return cco_home / "run-state" / f"sessions-{key}.json"

    def _save_private_actor_sessions() -> None:
        snap = actors.export_private_sessions()
        cache_path = _host_session_cache_path()
        cache_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".sessions-", suffix=".tmp", dir=str(cache_path.parent))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(snap, fh, separators=(",", ":"))
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, cache_path)
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _load_private_actor_sessions() -> None:
        cache_path = _host_session_cache_path()
        if not cache_path.is_file():
            return
        try:
            loaded = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(loaded, dict) and loaded:
            actors.import_private_sessions(loaded)

    if resume:
        _load_private_actor_sessions()
    else:
        try:
            _host_session_cache_path().unlink(missing_ok=True)
        except OSError:
            pass

    http_client = AgenticHTTPClient(
        base_url=base,
        receipt_store=receipt_store,
        actors=actors,
        allowed_methods=eff_methods,
        max_requests=eff_http_budget,
        excluded_paths=eff_excluded_paths,
        in_scope_assets=eff_in_scope_assets,
        out_of_scope_assets=eff_out_of_scope_assets,
        max_degradation_streak=max(0, int(max_degradation_streak)),
        max_rps=eff_max_rps,
        on_session_mutated=_save_private_actor_sessions,
    )
    del resolved_auth_hdr

    scope_summary = {
        "loopback_only": eff_loopback_only,
        "scope_file": scope_meta.get("scope_file"),
        "excluded_paths_count": len(eff_excluded_paths),
        "multi_origin": bool(len(eff_in_scope_assets) > 0 and not eff_loopback_only),
        "in_scope_assets_count": len(eff_in_scope_assets),
        "max_degradation_streak": max(0, int(max_degradation_streak)),
    }
    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "mode": "agentic",
        "status": "starting",
        "run_id": eff_run_id,
        "target": base,
        "scope": scope_summary,
        "models": models,
        "reasoning_effort": eff_reasoning_effort or None,
        "provider_routing": provider_routing,
        "provider_kind": auth["provider_kind"],
        "allowed_methods": eff_methods,
        "request_headers": sorted(global_headers),
        "discovery_hints": list(eff_discovery_hints),
        "seed_surface": dict(seed_data.get("stats") or {}) if seed_data is not None else None,
        "har_flows": dict(har_flows_doc.get("stats") or {}) if har_flows_doc is not None else None,
        "asset_graph": dict(asset_graph_manifest) if asset_graph_manifest is not None else None,
        "stage0_crawl": dict(stage0_cfg),
        "prescan": dict(prescan_cfg),
        "oob_listener": dict(oob_summary),
        "auth": _build_auth_metadata(actors, login_path_source=login_path_source),
        "ablation": ablation_cfg,
        "sharding": sharding_cfg,
        "limits": limits,
    }
    if eff_preset:
        manifest["preset"] = eff_preset
    if eff_config_path is not None:
        manifest["config_file"] = str(eff_config_path)
    manifest_path = output / "manifest.json"
    if har_flows_doc is not None:
        har_flows_path = output / "har-flows.json"
        dump(har_flows_path, har_flows_doc)
        if isinstance(manifest.get("har_flows"), dict):
            manifest["har_flows"]["file"] = str(har_flows_path)
    dump(manifest_path, manifest)

    investigator: AgenticInvestigator | None = None
    prescan_doc_final: dict[str, Any] | None = None
    stage0_result_final: dict[str, Any] | None = None
    raw_seed_data: dict[str, Any] | None = seed_data
    try:
        has_resume_checkpoint = (
            (output / "checkpoint.json").is_file()
            or ((output / "shards").is_dir() and any((output / "shards").glob("*/checkpoint.json")))
        )
        if (not resume or has_resume_checkpoint) and any(
            alias != "anon" and bool(sess.login_payload) and not sess.authenticated
            for alias, sess in actors.actors.items()
        ):
            http_client.authenticate_all_actors()
            manifest["auth"] = _build_auth_metadata(actors, login_path_source=login_path_source)

        if not resume:
            if eff_auto_crawl:
                import agentic_stage0_crawl  # type: ignore[import-not-found]

                stage0_result = agentic_stage0_crawl.run_stage0_crawl(
                    http_client,
                    output_dir=output,
                    start_paths=list(eff_discovery_hints),
                    max_pages=stage0_cfg["max_pages"],
                    max_actions=stage0_cfg["max_actions"],
                    allow_forms=eff_auto_crawl_forms,
                )
                if isinstance(stage0_result, dict):
                    stage0_result_final = stage0_result
                    stage0_stats = dict(stage0_result.get("stats") or {})
                    if stage0_result.get("status") is not None and "status" not in stage0_stats:
                        stage0_stats["status"] = str(stage0_result.get("status"))
                    manifest["stage0_crawl"] = {
                        **stage0_cfg,
                        **stage0_stats,
                        "seed_file": str(stage0_result.get("seed_file") or ""),
                    }
                    if stage0_result.get("discovered_api_hosts"):
                        manifest["stage0_crawl"]["discovered_api_hosts"] = list(
                            stage0_result["discovered_api_hosts"]
                        )
                    merged_seed = agentic_seed.merge_seed_surfaces(
                        [seed_data, stage0_result],
                        base_url=base,
                        excluded_paths=eff_excluded_paths,
                        in_scope_assets=eff_in_scope_assets,
                        out_of_scope_assets=eff_out_of_scope_assets,
                    )
                    if merged_seed is not None:
                        seed_data = merged_seed
                        for hint in seed_data.get("discovery_hints") or []:
                            if hint not in eff_discovery_hints:
                                eff_discovery_hints.append(hint)
                        manifest["discovery_hints"] = list(eff_discovery_hints)
                        manifest["seed_surface"] = dict(seed_data.get("stats") or {})
                    if actors.actors_failed_with_missing_login_route():
                        fallback_candidates = _extract_stage0_login_candidates(stage0_result)
                        if fallback_candidates:
                            fallback_results = http_client.retry_unauthenticated_actors_with_discovered_login_paths(
                                fallback_candidates
                            )
                            if any(fallback_results.values()):
                                login_path_source = "stage0_fallback"
                    manifest["auth"] = _build_auth_metadata(actors, login_path_source=login_path_source)
                    dump(manifest_path, manifest)

        prescan_handoff = ""
        initial_waf_vendors: list[str] = []
        if eff_prescan and not resume:
            try:
                operator_keys_low = {k.lower() for k in operator_headers}
                if apply_har_headers:
                    raw_prescan_har_headers = _filter_safe_har_app_headers(
                        seed_data.get("app_headers") if isinstance(seed_data, dict) else None,
                        har_flows_doc.get("recommended_app_headers") if isinstance(har_flows_doc, dict) else None,
                    )
                    prescan_har_headers = {
                        hk: hv
                        for hk, hv in raw_prescan_har_headers.items()
                        if hk.lower() not in operator_keys_low
                    }
                    if isinstance(har_flows_doc, dict):
                        safe_rec = _filter_safe_har_app_headers(har_flows_doc.get("recommended_app_headers"))
                        prescan_har_flows: dict[str, Any] | None = {
                            **har_flows_doc,
                            "recommended_app_headers": {
                                hk: hv for hk, hv in safe_rec.items() if hk.lower() not in operator_keys_low
                            },
                        }
                    else:
                        prescan_har_flows = None
                else:
                    prescan_har_headers = {}
                    prescan_har_flows = (
                        {**har_flows_doc, "recommended_app_headers": {}}
                        if isinstance(har_flows_doc, dict)
                        else None
                    )
                prescan_extra = _supported_kwargs(
                    agentic_prescan.run_deterministic_prescan,
                    {
                        "har_flows": prescan_har_flows,
                        "extra_headers": prescan_har_headers or None,
                    },
                )
                prescan_doc = agentic_prescan.run_deterministic_prescan(
                    http_client,
                    output_dir=output,
                    seed_surface=seed_data,
                    candidate_urls=eff_discovery_hints,
                    max_requests=eff_prescan_max_requests,
                    **prescan_extra,
                )
                prescan_doc_final = prescan_doc
                prescan_stats = dict(prescan_doc.get("stats") or {})
                initial_waf_vendors = [
                    str(v).strip()
                    for v in (prescan_doc.get("waf_vendors_seen") or [])
                    if str(v).strip()
                ]
                manifest["prescan"] = {
                    **prescan_cfg,
                    **prescan_stats,
                    "status": str(prescan_doc.get("status") or "ok"),
                    "leads_count": len(prescan_doc.get("leads") or []),
                    "waf_vendors_seen": list(initial_waf_vendors),
                    "summary_file": str(prescan_doc.get("summary_file") or ""),
                }
                prescan_handoff = agentic_prescan.format_prescan_handoff(prescan_doc, max_chars=2400)
                dump(manifest_path, manifest)
            except ServiceDegradationError:
                raise
            except Exception as exc:
                manifest["prescan"] = {
                    **prescan_cfg,
                    "status": "error",
                    "error": type(exc).__name__,
                }
                dump(manifest_path, manifest)
        elif resume and (output / "prescan-summary.json").is_file():
            try:
                prior_prescan = json.loads((output / "prescan-summary.json").read_text(encoding="utf-8"))
                if isinstance(prior_prescan, dict):
                    prescan_doc_final = prior_prescan
                    prescan_handoff = agentic_prescan.format_prescan_handoff(prior_prescan, max_chars=2400)
                    initial_waf_vendors = [
                        str(v).strip()
                        for v in (prior_prescan.get("waf_vendors_seen") or [])
                        if str(v).strip()
                    ]
            except (OSError, ValueError):
                pass

        worker_model_id = models["worker"].split("/", 1)[1]
        investigator = AgenticInvestigator(
            http_client=http_client,
            receipt_store=receipt_store,
            transport=transport,
            budget=budget,
            model=worker_model_id,
            root_dir=output,
            discovery_hints=eff_discovery_hints,
            max_turns=max_turns,
            reasoning_effort=eff_reasoning_effort,
            use_bsag=ablation_cfg["use_bsag"],
            scheduler_mode=ablation_cfg["scheduler"],
            verification_gate=ablation_cfg["verification_gate"],
            intervention_mode=ablation_cfg["intervention"],
            execution_mode=ablation_cfg["execution_mode"],
            enable_telemetry=True,
            scout_model=scout_model_id or None,
            scout_max_turns=scout_turns,
            scout_token_share=scout_token_share,
            max_shards=sharding_cfg["max_shards"],
            bootstrap_turns=sharding_cfg["bootstrap_turns"],
            shard_turns=sharding_cfg["shard_turns"],
            shard_token_quota=eff_shard_token_quota,
            bootstrap_model=bootstrap_model_id or None,
            max_shard_retries=eff_max_shard_retries,
            retry_model=retry_model_id or None,
            retry_budget_ratio=eff_retry_budget_ratio,
            max_retry_shards=eff_max_retry_shards,
            epoch_char_limit=eff_epoch_char_limit,
            cache_token_weight=eff_cache_weight,
            seed_surface=seed_data,
            oob_server=configured_oob,
            stage0_post_auth_enabled=eff_auto_crawl,
            stage0_allow_forms=eff_auto_crawl_forms,
            prescan_handoff=prescan_handoff,
            har_flows_handoff=har_flows_handoff,
            asset_graph_handoff=asset_graph_handoff,
            initial_waf_vendors=initial_waf_vendors,
            cancel_event=cancel_event,
        )
        run_info = investigator.run(resume=resume)
        manifest.update(run_info)
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
    except ServiceDegradationError as exc:
        manifest.update(status="service_degraded", error=type(exc).__name__, error_detail=str(exc)[:300])
    except Exception as exc:
        manifest.update(status="failed", error=type(exc).__name__, error_detail=str(exc)[:300])
    finally:
        if configured_oob is not None:
            configured_oob.close()
        _save_private_actor_sessions()
        http_client.close()
        transport.close_upstream()
        findings_file = output / "findings.json"
        if not findings_file.is_file():
            dump(findings_file, [])
        try:
            findings_list = json.loads(findings_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            findings_list = []
        if not isinstance(findings_list, list):
            findings_list = []
        else:
            findings_list = [item for item in findings_list if isinstance(item, dict)]
        shards_dir = output / "shards"
        if shards_dir.is_dir():
            for shard_findings_path in sorted(shards_dir.glob("*/findings.json")):
                try:
                    shard_items = json.loads(shard_findings_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if isinstance(shard_items, list):
                    findings_list.extend(item for item in shard_items if isinstance(item, dict))
        if findings_list:
            actor_meta_map = {
                row["alias"]: {
                    "alias": row["alias"],
                    "role": str(row.get("role") or "").lower(),
                    "tenant": str(row.get("tenant") or "").lower(),
                }
                for row in actors.summaries()
            }
            findings_list = canonicalize_and_deduplicate_findings(
                findings_list,
                actor_meta_map=actor_meta_map,
                receipt_store=receipt_store,
            )
            dump(findings_file, findings_list)
        snap = budget.snapshot()
        manifest.update(
            auth=_build_auth_metadata(actors, login_path_source=login_path_source),
            budget=snap,
            llm_calls=transport.calls,
            target_requests=http_client.budget.used,
            findings_count=len(findings_list) if isinstance(findings_list, list) else 0,
            findings_artifact=str(findings_file),
            receipts_dir=str(receipt_store.receipts_dir),
            wall_clock_seconds=round(time.monotonic() - started, 2),
        )
        if investigator is not None:
            if isinstance(findings_list, list):
                investigator.dispatcher.findings = findings_list
            waf_pivot_tracker = getattr(investigator.dispatcher, "waf_pivot", None)
            if waf_pivot_tracker is not None and callable(getattr(waf_pivot_tracker, "summary", None)):
                manifest["waf_pivot"] = waf_pivot_tracker.summary()
            try:
                m_json, m_md, metrics_doc = investigator.write_metrics(manifest=manifest)
            except TypeError:
                m_json, m_md, metrics_doc = investigator.write_metrics()
            manifest["process_metrics_json"] = str(m_json)
            manifest["process_metrics_md"] = str(m_md)
            manifest["process_metrics"] = metrics_doc
        dump(private_dir / "budget.json", snap)
        try:
            surface_map_mod: Any = importlib.import_module("agentic_surface_map")
        except ImportError:
            surface_map_mod = None
        if surface_map_mod is not None:
            try:
                all_receipts: list[dict[str, Any]] = []
                for rid in receipt_store.list_ids():
                    try:
                        all_receipts.append(receipt_store.get(rid))
                    except (KeyError, ValueError, OSError):
                        continue
                stage0_docs_for_map: list[dict[str, Any]] = []
                if isinstance(stage0_result_final, dict):
                    stage0_docs_for_map.append(stage0_result_final)
                elif (output / "stage0-seed.json").is_file():
                    try:
                        disk_s0 = json.loads((output / "stage0-seed.json").read_text(encoding="utf-8"))
                        if isinstance(disk_s0, dict):
                            stage0_docs_for_map.append(disk_s0)
                    except (OSError, ValueError):
                        pass
                post_auth_s0_path = output / "stage0-post-auth-seed.json"
                if post_auth_s0_path.is_file():
                    try:
                        disk_post_s0 = json.loads(post_auth_s0_path.read_text(encoding="utf-8"))
                        if isinstance(disk_post_s0, dict):
                            stage0_docs_for_map.append(disk_post_s0)
                    except (OSError, ValueError):
                        pass
                stage0_for_map: dict[str, Any] | None = None
                if len(stage0_docs_for_map) == 1:
                    stage0_for_map = stage0_docs_for_map[0]
                elif len(stage0_docs_for_map) > 1:
                    merge_s0_fn = getattr(surface_map_mod, "_merge_stage0_docs", None)
                    stage0_for_map = (
                        merge_s0_fn(stage0_docs_for_map)
                        if callable(merge_s0_fn)
                        else stage0_docs_for_map[0]
                    )
                sm_kwargs = _supported_kwargs(
                    surface_map_mod.build_surface_map,
                    {
                        "base_url": base,
                        "receipts": all_receipts,
                        "seed_surface": raw_seed_data,
                        "stage0_result": stage0_for_map,
                        "har_flows": har_flows_doc,
                        "asset_graph": asset_graph_raw,
                        "prescan_doc": prescan_doc_final,
                        "surface_tracker": investigator.dispatcher.surface_tracker if investigator is not None else None,
                        "in_scope_assets": eff_in_scope_assets,
                        "out_of_scope_assets": eff_out_of_scope_assets,
                        "excluded_paths": eff_excluded_paths,
                    },
                )
                surface_map = surface_map_mod.build_surface_map(**sm_kwargs)
                sm_json, sm_md = surface_map_mod.write_surface_map_artifacts(output, surface_map)
                sm_stats = surface_map.get("stats") if isinstance(surface_map, dict) else {}
                manifest["surface_map"] = {
                    "json": str(sm_json),
                    "md": str(sm_md),
                    **(sm_stats if isinstance(sm_stats, dict) else {}),
                }
            except Exception as sm_exc:
                manifest["surface_map_error"] = type(sm_exc).__name__
        dump(manifest_path, manifest)
        dump(output / "launch.json", manifest)
        report_md_text: str | None = None
        try:
            rep = agentic_report.generate_run_reports(output)
            if rep.get("markdown_path"):
                manifest["report_md"] = rep["markdown_path"]
                try:
                    report_md_text = Path(str(rep["markdown_path"])).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    report_md_text = None
            if rep.get("sarif_path"):
                manifest["report_sarif"] = rep["sarif_path"]
        except Exception as report_exc:
            manifest["report_error"] = type(report_exc).__name__
        if investigator is not None and report_md_text is not None:
            try:
                m_json, m_md, metrics_doc = investigator.write_metrics(
                    manifest=manifest,
                    report_text=report_md_text,
                )
            except TypeError:
                m_json, m_md, metrics_doc = investigator.write_metrics()
            manifest["process_metrics_json"] = str(m_json)
            manifest["process_metrics_md"] = str(m_md)
            manifest["process_metrics"] = metrics_doc
        dump(manifest_path, manifest)
        dump(output / "launch.json", manifest)
    return manifest_path, manifest


def main(argv: list[str] | None = None, *, force_plan_only: bool = False) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--preset",
        choices=list(preset_names()),
        default=argparse.SUPPRESS,
        help=f"Named engagement preset ({', '.join(preset_names())}); simplifies budgets and crawl defaults",
    )
    parser.add_argument(
        "--config",
        dest="config_file",
        type=Path,
        default=argparse.SUPPRESS,
        help="Optional cco-run/1 JSON engagement config file (CLI flags override config values)",
    )
    parser.add_argument("--target", default=argparse.SUPPRESS, help="Owned loopback target origin http://127.0.0.1:<port>/")
    parser.add_argument("--credentials-file", "--credentials", dest="credentials_file", type=Path, default=argparse.SUPPRESS)
    parser.add_argument("--provider-config", type=Path, default=argparse.SUPPRESS)
    parser.add_argument("--model", default=argparse.SUPPRESS)
    parser.add_argument("--worker-model", default=argparse.SUPPRESS)
    parser.add_argument("--scout-model", default=argparse.SUPPRESS, help="Optional Phase 1 scout model (same provider) for 2-phase handoff")
    parser.add_argument("--scout-turns", type=int, default=argparse.SUPPRESS, help="Max Phase 1 scout turns before handoff")
    parser.add_argument("--scout-token-share", type=float, default=argparse.SUPPRESS, help="Max token budget fraction for Phase 1 scout")
    parser.add_argument("--api-key-env", default=argparse.SUPPRESS)
    parser.add_argument("--output-dir", "--output", dest="output_dir", type=Path, default=argparse.SUPPRESS, help="Output directory for plan/manifest/receipts/reports (required via CLI or --config)")
    parser.add_argument("--http-budget", "--max-requests", dest="http_budget", type=int, default=argparse.SUPPRESS)
    parser.add_argument("--token-budget", type=int, default=argparse.SUPPRESS)
    parser.add_argument("--seconds-budget", type=int, default=argparse.SUPPRESS)
    parser.add_argument("--allowed-methods", action="append", default=argparse.SUPPRESS, help="Allowed HTTP methods (e.g. GET,POST,PUT)")
    parser.add_argument("--discovery-hint", action="append", dest="discovery_hints", default=argparse.SUPPRESS, help="Initial discovery entry path(s)")
    parser.add_argument("--login-path", default=argparse.SUPPRESS)
    parser.add_argument("--session-check-path", default=argparse.SUPPRESS)
    parser.add_argument("--refresh-path", default=argparse.SUPPRESS, help="Optional token refresh endpoint path for automatic mid-run 401 session renewal")
    parser.add_argument("--max-member-accounts", type=int, default=argparse.SUPPRESS)
    parser.add_argument("--max-admin-accounts", type=int, default=argparse.SUPPRESS)
    parser.add_argument("--max-turns", type=int, default=argparse.SUPPRESS)
    parser.add_argument("--reasoning-effort", default=argparse.SUPPRESS)
    parser.add_argument("--resume", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("--run-id", default=argparse.SUPPRESS)
    parser.add_argument("--execute", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("--authorize-live-provider", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("--live-authorization-reason", default=argparse.SUPPRESS)
    parser.add_argument("--use-bsag", type=_parse_bool_flag, default=argparse.SUPPRESS, help="Enable external BSAG (true|false)")
    parser.add_argument("--scheduler", choices=["ucb", "prompt_only", "round_robin"], default=argparse.SUPPRESS)
    parser.add_argument("--verification-gate", choices=["differential", "llm_self_judge"], default=argparse.SUPPRESS)
    parser.add_argument("--intervention", choices=["lazy", "always_on", "off"], default=argparse.SUPPRESS)
    parser.add_argument("--execution-mode", choices=["ephemeral", "monolithic", "sharded"], default=argparse.SUPPRESS)
    parser.add_argument("--max-shards", type=int, default=argparse.SUPPRESS, help="Max subsystem shards for sharded mode")
    parser.add_argument("--bootstrap-turns", type=int, default=argparse.SUPPRESS, help="Stage 1 bootstrap turns for sharded mode")
    parser.add_argument("--shard-turns", type=int, default=argparse.SUPPRESS, help="Stage 2 per-shard turn budget for sharded mode")
    parser.add_argument(
        "--shard-token-quota",
        type=int,
        default=argparse.SUPPRESS,
        help="Optional per-shard soft token quota for sharded mode (0 = auto-balanced from remaining tokens)",
    )
    parser.add_argument(
        "--bootstrap-model",
        default=argparse.SUPPRESS,
        help="Optional Stage 1 discovery-only bootstrap model (same provider) for sharded mode",
    )
    parser.add_argument(
        "--max-shard-retries",
        type=int,
        default=argparse.SUPPRESS,
        help="Max Stage 2.5 selective fresh-context retries per shard (0 disables, default: 1)",
    )
    parser.add_argument(
        "--retry-model",
        default=argparse.SUPPRESS,
        help="Optional Stage 2.5 selective retry model (same provider) for sharded mode",
    )
    parser.add_argument(
        "--retry-budget-ratio",
        type=float,
        default=argparse.SUPPRESS,
        help="Stage 2.5 retry budget reservation ratio in [0.0, 0.35] (default: 0.15)",
    )
    parser.add_argument(
        "--max-retry-shards",
        type=int,
        default=argparse.SUPPRESS,
        help="Maximum Stage 2.5 shards retried per run (default: 2)",
    )
    parser.add_argument(
        "--epoch-char-limit",
        type=int,
        default=argparse.SUPPRESS,
        help="Optional per-epoch serialized byte limit before advancing epoch (0 = default 80000)",
    )
    parser.add_argument(
        "--cache-token-weight",
        type=float,
        default=argparse.SUPPRESS,
        help="Effective token weight in [0.0, 1.0] for cached prompt tokens (default: 0.10)",
    )
    parser.add_argument(
        "--scope-file",
        type=Path,
        default=argparse.SUPPRESS,
        help="Optional explicit scope.json file (required when --allow-non-loopback is set)",
    )
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Allow non-loopback http(s) target origin explicitly verified by --scope-file",
    )
    parser.add_argument(
        "--max-degradation-streak",
        type=int,
        default=argparse.SUPPRESS,
        help="Stop gracefully after N consecutive 429/502/503/504 or connection-error responses (0 disables, default: 5)",
    )
    parser.add_argument(
        "--max-rps",
        type=float,
        default=argparse.SUPPRESS,
        help="Optional maximum HTTP/WS requests per second rate limit (0 disables, default: 0.0)",
    )
    parser.add_argument(
        "--vault-home",
        type=Path,
        default=argparse.SUPPRESS,
        help="Optional CredentialVault directory for encrypted credential bundle lookup",
    )
    parser.add_argument(
        "--vault-key-name",
        default=argparse.SUPPRESS,
        help="Credential bundle key name inside --vault-home",
    )
    parser.add_argument(
        "--storage-state",
        action="append",
        dest="storage_states",
        default=argparse.SUPPRESS,
        help="Playwright storage_state.json spec (alias=/path or alias:role:tenant=/path); repeatable",
    )
    parser.add_argument(
        "-H",
        "--header",
        "--custom-header",
        action="append",
        dest="custom_headers",
        type=_custom_header_arg,
        default=argparse.SUPPRESS,
        metavar="NAME: VALUE",
        help="Operator header sent on every HTTP/browser request (repeatable; e.g. -H 'Pentest: Cyberbounty')",
    )
    parser.add_argument(
        "--seed-surface",
        action="append",
        dest="seed_surface_files",
        type=Path,
        default=argparse.SUPPRESS,
        help="Offline discovery seed file (HAR/mitm_scope/ZAP/ffuf/nuclei/URL list); repeatable",
    )
    parser.add_argument(
        "--asset-graph",
        dest="asset_graph_file",
        type=Path,
        default=argparse.SUPPRESS,
        help="Optional cco-asset-graph/1 JSON file produced by 'cco-agent recon' to seed prioritized in-scope hosts/paths",
    )
    parser.add_argument(
        "--tech-hint",
        action="append",
        dest="tech_hints",
        default=argparse.SUPPRESS,
        help="Optional technology stack hint (e.g. nextjs, django, spring) to enrich initial discovery paths",
    )
    parser.add_argument(
        "--auto-crawl",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Run Stage 0 deterministic Playwright crawler before LLM discovery",
    )
    parser.add_argument(
        "--no-auto-crawl",
        action="store_false",
        dest="auto_crawl",
        default=argparse.SUPPRESS,
        help="Disable Stage 0 deterministic Playwright crawler (overrides preset/config)",
    )
    parser.add_argument(
        "--auto-crawl-forms",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Opt-in non-destructive form/upload submission during Stage 0 crawl (requires POST in --allowed-methods; implies --auto-crawl)",
    )
    parser.add_argument(
        "--auto-crawl-max-pages",
        type=int,
        default=argparse.SUPPRESS,
        help="Maximum pages to visit during Stage 0 crawl (default: 12)",
    )
    parser.add_argument(
        "--auto-crawl-max-actions",
        type=int,
        default=argparse.SUPPRESS,
        help="Maximum interactive UI actions during Stage 0 crawl (default: 24)",
    )
    parser.add_argument(
        "--prescan",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Run deterministic 0-LLM-token prescan (secrets/CORS/redirect/GraphQL + 2-actor BOLA/BFLA matrix) before Turn 1",
    )
    parser.add_argument(
        "--no-prescan",
        action="store_false",
        dest="prescan",
        default=argparse.SUPPRESS,
        help="Disable deterministic 0-LLM-token prescan (overrides preset/config)",
    )
    parser.add_argument(
        "--prescan-max-requests",
        type=int,
        default=argparse.SUPPRESS,
        help="Maximum HTTP requests budgeted for deterministic prescan (default: 24)",
    )
    parser.add_argument(
        "--apply-har-headers",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Merge strictly non-secret HAR/seed application headers at lowest precedence into global headers",
    )
    parser.add_argument(
        "--no-apply-har-headers",
        action="store_false",
        dest="apply_har_headers",
        default=argparse.SUPPRESS,
        help="Disable merging non-secret HAR/seed application headers into global headers (overrides config)",
    )
    parser.add_argument(
        "--oob-bind-host",
        default=argparse.SUPPRESS,
        help="Optional OOB callback bind IP (default 127.0.0.1; private Docker bridge IP permitted)",
    )
    parser.add_argument(
        "--oob-advertise-host",
        default=argparse.SUPPRESS,
        help="Optional OOB callback advertised hostname/IP (e.g. host.docker.internal for Dockerized targets)",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Display the read-only live TUI dashboard while running (or a snapshot in plan mode)",
    )
    explicit = vars(parser.parse_args(argv))
    use_tui = bool(explicit.pop("tui", False))
    if force_plan_only and explicit.get("execute"):
        parser.error("--execute is not allowed with 'cco-agent plan'; use 'cco-agent run --execute' after reviewing the plan")

    config_path: Path | None = explicit.pop("config_file", None)
    cli_preset = str(explicit.pop("preset", "") or "")
    try:
        config_options = load_run_config(config_path) if config_path is not None else None
        effective, eff_preset = merge_run_options(
            defaults=_runner_defaults(),
            preset=cli_preset,
            config_options=config_options,
            explicit_overrides=explicit,
        )
    except ValueError as exc:
        parser.error(str(exc))

    if force_plan_only:
        effective["execute"] = False

    if effective.get("output_dir") is None:
        parser.error("--output-dir is required (via CLI or --config)")
    if not (0.0 <= float(effective["cache_token_weight"]) <= 1.0):
        parser.error("--cache-token-weight must be between 0.0 and 1.0")
    if isinstance(effective["retry_budget_ratio"], bool) or not math.isfinite(float(effective["retry_budget_ratio"])):
        parser.error("--retry-budget-ratio must be a finite number in [0.0, 0.35]")
    if not math.isfinite(float(effective["max_rps"])) or float(effective["max_rps"]) < 0.0:
        parser.error("--max-rps must be a finite number >= 0.0")

    if use_tui and bool(effective.get("execute")):
        import agentic_tui

        done_event = threading.Event()
        cancel_event = threading.Event()
        result_box: dict[str, Any] = {}

        def _worker() -> None:
            try:
                r_path, r_doc = run_agentic_target(
                    **effective,
                    preset=eff_preset,
                    config_file=config_path,
                    cancel_event=cancel_event,
                    _options_resolved=True,
                )
                result_box["result"] = (r_path, r_doc)
            except BaseException as exc:
                result_box["error"] = exc
            finally:
                done_event.set()

        thread = threading.Thread(target=_worker, name="kryon-runner", daemon=True)
        thread.start()
        try:
            agentic_tui.watch_run_dir(
                effective["output_dir"],
                refresh_seconds=0.75,
                stop_event=done_event,
            )
        finally:
            if not done_event.is_set():
                cancel_event.set()
            thread.join(timeout=5.0)
        if "error" in result_box:
            raise result_box["error"]
        if "result" in result_box:
            path, doc = result_box["result"]
        else:
            out_dir_resolved = Path(effective["output_dir"]).expanduser().resolve()
            path = out_dir_resolved / "manifest.json"
            doc = {}
            if path.is_file():
                try:
                    loaded_doc = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(loaded_doc, dict):
                        doc = loaded_doc
                except (OSError, ValueError):
                    doc = {}
            if str(doc.get("status") or "").strip().lower() in {"", "starting", "running"}:
                doc["status"] = "interrupted"
            doc.setdefault("mode", "agentic")
            doc.setdefault("target", str(effective.get("target") or ""))
            doc.setdefault("llm_calls", 0)
            doc.setdefault("target_requests", 0)
            doc.setdefault("findings_count", 0)
    else:
        path, doc = run_agentic_target(
            **effective,
            preset=eff_preset,
            config_file=config_path,
            _options_resolved=True,
        )
        if use_tui:
            import agentic_tui

            agentic_tui.watch_run_dir(effective["output_dir"], once=True)
    summary: dict[str, Any] = {
        "artifact": str(path),
        "mode": doc.get("mode"),
        "status": doc.get("status"),
        "target": doc.get("target"),
        "llm_calls": doc.get("llm_calls"),
        "target_requests": doc.get("target_requests"),
        "findings_count": doc.get("findings_count"),
        "findings_artifact": doc.get("findings_artifact"),
    }
    if doc.get("preset"):
        summary["preset"] = doc["preset"]
    print(json.dumps(summary))
    status_str = str(doc.get("status") or "").strip().lower()
    if status_str == "interrupted":
        return 130
    if status_str == "failed" or status_str.startswith("error:"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
