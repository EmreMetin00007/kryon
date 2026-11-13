"""Compatibility facade preserving historical full_agent_broker exports.

Shared provider, executor, and budget primitives now live in full_agent_provider
and full_agent_executor; native bridge/gate/SSE behavior lives in
full_agent_native_compat. Python-engine modules do not import this facade.
"""
from __future__ import annotations

from socketserver import UnixStreamServer

from full_agent_executor import CATALOG
from full_agent_native_compat import (
    LOCAL_TOOLS,
    NATIVE_DESCRIPTION_LIMIT,
    NativeBrokerCompat as Broker,
    make_server as _compat_make_server,
    runtime_request,
)
from full_agent_provider import (
    MAX_BODY,
    dump,
    provider_failure,
    provider_failure_reason,
    provider_usage_diagnostics,
)

NativeBrokerCompat = Broker


def make_server(path, broker):
    return _compat_make_server(path, broker, server_base=UnixStreamServer)


__all__ = [
    "Broker",
    "CATALOG",
    "LOCAL_TOOLS",
    "MAX_BODY",
    "NATIVE_DESCRIPTION_LIMIT",
    "UnixStreamServer",
    "dump",
    "make_server",
    "provider_failure",
    "provider_failure_reason",
    "provider_usage_diagnostics",
    "runtime_request",
]
