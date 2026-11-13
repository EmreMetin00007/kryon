"""Provider configuration for the Python engine; no client or credential store.

Only environment variable *names* belong in this file. Credentials are resolved
by the operator at execution time and never enter snapshots or model context.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from runtime_paths import runtime_root

SCHEMA = "cco-llm/1"


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
            "base_url", "models", "api_key_env", "api_key_header"
        }:
            raise ValueError("provider fields must contain configuration, never credentials")
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
    return {"name": name, "url": source["base_url"].rstrip("/"),
            "models": {model for _, model in selected}, "api_key_env": source["api_key_env"],
            "api_key_header": source.get("api_key_header", "Authorization")}


def snapshot(path, models):
    """Freeze selected routing metadata without reading any credential value."""
    settings = provider_settings(path, models)
    return {"schema": SCHEMA, "model": models["worker"], "providers": {
        settings["name"]: {"base_url": settings["url"], "models": sorted(settings["models"]),
                           "api_key_env": settings["api_key_env"],
                           "api_key_header": settings["api_key_header"]}}}
