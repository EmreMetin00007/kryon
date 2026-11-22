"""Read-only browser runtime hooks and request-level interception policy."""
from __future__ import annotations

from .hooks import (
    MAX_EVENTS,
    SCHEMA,
    build_runtime_hook_script,
    merge_runtime_into_client_map,
    normalize_runtime_events,
)
from .policy import install_readonly_request_gate

__all__ = [
    "MAX_EVENTS",
    "SCHEMA",
    "build_runtime_hook_script",
    "install_readonly_request_gate",
    "merge_runtime_into_client_map",
    "normalize_runtime_events",
]
