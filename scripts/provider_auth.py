"""Provider routing validation and fail-closed live remote authorization gate."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import llm_config

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def authorize_provider(
    provider_config: str | Path,
    *,
    model: str = "",
    worker_model: str = "",
    execute: bool = False,
    authorize_live_provider: bool = False,
    live_authorization_reason: str = "",
    api_key_env: str | None = None,
) -> dict[str, Any]:
    """Validate provider routing and fail-closed live remote authorization gate.

    Never reads or embeds credential secrets into return values or artifacts.
    """
    models = llm_config.model_selection(provider_config, model, worker_model)
    settings = llm_config.provider_settings(provider_config, models)
    host = urlsplit(settings["url"]).hostname or ""
    provider_kind = "loopback" if host in LOOPBACK_HOSTS else "remote"
    reason = live_authorization_reason.strip() if isinstance(live_authorization_reason, str) else ""
    env_name = api_key_env or settings["api_key_env"]
    if execute and provider_kind == "remote":
        if authorize_live_provider is not True or not reason:
            raise PermissionError(
                "live remote provider usage requires explicit operator authorization "
                "(--authorize-live-provider and non-empty --live-authorization-reason)")
    if execute and not os.environ.get(env_name, ""):
        raise ValueError(f"provider credential environment variable is empty: {env_name}")
    return {
        "models": models,
        "provider_name": settings["name"],
        "provider_host": host,
        "provider_kind": provider_kind,
        "api_key_env": env_name,
        "live_provider_authorized": bool(authorize_live_provider and reason) if provider_kind == "remote" else False,
        "live_authorization_reason": reason if (provider_kind == "remote" and authorize_live_provider and reason) else None,
    }
