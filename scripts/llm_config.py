"""Provider configuration for the Python engine; no client or credential store.

Only environment variable *names* belong in this file. Credentials are resolved
by the operator at execution time and never enter snapshots or model context.
"""
from __future__ import annotations

from collections.abc import Sequence
import copy
import json
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from runtime_paths import runtime_root

SCHEMA = "cco-llm/1"
REASONING_EFFORT_LEVELS: frozenset[str] = frozenset(
    {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
)
MAX_REASONING_EFFORT_LEVELS: frozenset[str] = frozenset({"xhigh", "max"})
DEEPSEEK_MAX_INCOMPATIBLE_GATEWAY_PROVIDERS: frozenset[str] = frozenset({"deepinfra"})
DEEPSEEK_MAX_PREFERRED_GATEWAY_PROVIDERS: tuple[str, ...] = ("deepseek", "fireworks", "baseten")


def normalize_reasoning_effort(value: str | None) -> str:
    """Normalize and validate an optional OpenAI/gateway reasoning_effort string."""
    if value is None:
        return ""
    clean = str(value).strip().lower()
    if not clean:
        return ""
    if clean not in REASONING_EFFORT_LEVELS:
        allowed = ", ".join(sorted(REASONING_EFFORT_LEVELS))
        raise ValueError(f"unsupported reasoning_effort {value!r}; expected one of: {allowed}")
    return clean


def adapt_provider_options_for_effort(
    provider_options: dict[str, Any] | None,
    *,
    models: Sequence[str] = (),
    provider_name: str = "",
    provider_url: str = "",
    reasoning_effort: str = "",
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Avoid max-incompatible gateway backends (e.g. deepinfra) when DeepSeek runs at max/xhigh effort."""
    effort = normalize_reasoning_effort(reasoning_effort)
    opts: dict[str, Any] | None = (
        copy.deepcopy(provider_options)
        if isinstance(provider_options, dict) and provider_options
        else None
    )
    gw_raw = opts.get("gateway") if isinstance(opts, dict) else None
    has_gateway_opts = isinstance(gw_raw, dict)
    is_deepseek = any("deepseek" in str(m or "").lower() for m in models if str(m or "").strip())
    is_vercel_gateway = (
        str(provider_name or "").strip().lower() == "vercel"
        or "ai-gateway.vercel" in str(provider_url or "").lower()
        or "vercel.sh" in str(provider_url or "").lower()
    )
    meta: dict[str, Any] = {
        "provider": str(provider_name or "").strip() or None,
        "reasoning_effort": effort or None,
        "adapted": False,
        "reason": None,
        "excluded_providers": [],
    }
    if effort in MAX_REASONING_EFFORT_LEVELS and is_deepseek and (is_vercel_gateway or has_gateway_opts):
        gw: dict[str, Any] = dict(gw_raw) if isinstance(gw_raw, dict) else {}
        only_raw = gw.get("only")
        order_raw = gw.get("order")
        if isinstance(only_raw, list):
            clean_only = [str(p).strip() for p in only_raw if str(p).strip()]
            removed = [p for p in clean_only if p.lower() in DEEPSEEK_MAX_INCOMPATIBLE_GATEWAY_PROVIDERS]
            kept = [p for p in clean_only if p.lower() not in DEEPSEEK_MAX_INCOMPATIBLE_GATEWAY_PROVIDERS]
            if removed and not kept:
                raise ValueError(
                    f"provider_options.gateway.only={clean_only!r} does not support reasoning_effort={effort!r} "
                    "for DeepSeek models; use --reasoning-effort high or include deepseek/fireworks/baseten"
                )
            if removed:
                gw["only"] = kept
                opts = {**(opts or {}), "gateway": gw}
                meta.update(
                    adapted=True,
                    reason="effort_max_excluded_incompatible_gateway_providers",
                    excluded_providers=removed,
                )
        elif isinstance(order_raw, list) and any(str(p).strip() for p in order_raw):
            clean_order = [str(p).strip() for p in order_raw if str(p).strip()]
            removed = [p for p in clean_order if p.lower() in DEEPSEEK_MAX_INCOMPATIBLE_GATEWAY_PROVIDERS]
            kept = [p for p in clean_order if p.lower() not in DEEPSEEK_MAX_INCOMPATIBLE_GATEWAY_PROVIDERS]
            if removed:
                kept_low = {p.lower() for p in kept}
                next_order = [*kept, *(p for p in DEEPSEEK_MAX_PREFERRED_GATEWAY_PROVIDERS if p not in kept_low)]
                gw["order"] = next_order
                opts = {**(opts or {}), "gateway": gw}
                meta.update(
                    adapted=True,
                    reason="effort_max_excluded_deepinfra_fallback_order",
                    excluded_providers=removed,
                )
        elif is_vercel_gateway:
            gw["order"] = list(DEEPSEEK_MAX_PREFERRED_GATEWAY_PROVIDERS)
            opts = {**(opts or {}), "gateway": gw}
            meta.update(
                adapted=True,
                reason="effort_max_pinned_max_capable_gateway_order",
            )
    final_gw = opts.get("gateway") if isinstance(opts, dict) else None
    if isinstance(final_gw, dict):
        if isinstance(final_gw.get("order"), list):
            meta["gateway_order"] = [str(p) for p in final_gw["order"]]
        if isinstance(final_gw.get("only"), list):
            meta["gateway_only"] = [str(p) for p in final_gw["only"]]
    return opts, meta


def default_config() -> Path:
    configured = os.environ.get("CCO_LLM_CONFIG")
    return Path(configured).expanduser() if configured else runtime_root() / "config/llm.json"


def load_config(path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError("expected cco-llm/1 provider configuration")
    if set(data) - {"schema", "model", "providers"}:
        raise ValueError("unsupported provider configuration fields")
    providers = data.get("providers")
    if not isinstance(providers, dict) or not providers:
        raise ValueError("at least one provider is required")
    for name, provider in providers.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError("invalid provider name")
        if not isinstance(provider, dict) or set(provider) - {
            "base_url", "models", "api_key_env", "api_key_header", "provider_options"
        }:
            raise ValueError("provider fields must contain configuration, never credentials")
        if "provider_options" in provider:
            opts = provider["provider_options"]
            if not isinstance(opts, dict):
                raise ValueError("provider_options must be an object")
            opts_text = json.dumps(opts, ensure_ascii=False).lower()
            if any(bad in opts_text for bad in ('"api_key"', '"apikey"', '"authorization"', '"secret"', '"password"', '"token"')):
                raise ValueError("provider_options must not contain credentials")
        endpoint = provider.get("base_url", "")
        if not isinstance(endpoint, str) or any(c.isspace() for c in endpoint):
            raise ValueError("invalid provider base_url")
        url = urlsplit(endpoint)
        if (not url.hostname or url.username or url.password or url.query or url.fragment
                or url.scheme not in {"http", "https"}
                or (url.scheme != "https" and url.hostname not in {"127.0.0.1", "::1", "localhost"})):
            raise ValueError("provider base_url must use HTTPS or owned loopback, without URL credentials")
        # Accessing port also rejects malformed numeric ports before execution.
        if url.port == 0:
            raise ValueError("invalid provider port")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", provider.get("api_key_env", "")):
            raise ValueError("provider api_key_env must name an environment variable")
        if provider.get("api_key_header", "Authorization") not in {"Authorization", "X-API-Key"}:
            raise ValueError("invalid provider api_key_header")
        models = provider.get("models")
        if (not isinstance(models, list) or not models
                or any(not isinstance(m, str) or not m or any(c.isspace() for c in m) for m in models)
                or len(models) != len(set(models))):
            raise ValueError("provider models must be a nonempty unique list of model IDs")
    _selected(data, data.get("model"))
    return data


def _selected(data, value):
    if not isinstance(value, str) or "/" not in value:
        raise ValueError("model must be a provider/model identifier")
    provider, model = value.split("/", 1)
    if provider not in data["providers"] or model not in data["providers"][provider]["models"]:
        raise ValueError("selected model is not configured")
    return provider, model


def model_selection(path, model="", worker_model=""):
    data = load_config(path)
    selected = model or data["model"]
    worker = worker_model or selected
    primary, _ = _selected(data, selected)
    secondary, _ = _selected(data, worker)
    if primary != secondary:
        raise ValueError("a run requires one provider")
    return {"planner": selected, "worker": worker,
            "worker_selection": "explicit" if worker_model else "same_as_planner",
            "credentials": "environment only; never stored in run artifacts"}


def provider_settings(path, models):
    data = load_config(path)
    selected = [_selected(data, models[key]) for key in ("planner", "worker")]
    if len({name for name, _ in selected}) != 1:
        raise ValueError("a run requires one provider")
    name = selected[0][0]
    source = data["providers"][name]
    result = {"name": name, "url": source["base_url"].rstrip("/"),
              "models": {model for _, model in selected}, "api_key_env": source["api_key_env"],
              "api_key_header": source.get("api_key_header", "Authorization")}
    if "provider_options" in source:
        result["provider_options"] = source["provider_options"]
    return result


def snapshot(path, models):
    """Freeze selected routing metadata without reading any credential value."""
    settings = provider_settings(path, models)
    provider_snap = {"base_url": settings["url"], "models": sorted(settings["models"]),
                     "api_key_env": settings["api_key_env"],
                     "api_key_header": settings["api_key_header"]}
    if "provider_options" in settings:
        provider_snap["provider_options"] = settings["provider_options"]
    return {"schema": SCHEMA, "model": models["worker"], "providers": {
        settings["name"]: provider_snap}}
