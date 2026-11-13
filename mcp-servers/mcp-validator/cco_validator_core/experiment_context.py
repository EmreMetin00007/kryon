"""Transient request builder shared by a validator's control and probe rounds."""
from contextlib import contextmanager
from contextvars import ContextVar

_PAYLOADS = ContextVar("validator_experiment_payloads", default=None)


@contextmanager
def scoped_payloads(builder, baseline, *, baseline_check=None):
    token = _PAYLOADS.set((builder, baseline, baseline_check))
    try:
        yield
    finally:
        _PAYLOADS.reset(token)


def payload_request(payload):
    context = _PAYLOADS.get()
    return context[0](payload) if context is not None else None


def observed_baseline(fallback):
    context = _PAYLOADS.get()
    return context[1] if context is not None else fallback


def has_experiment():
    return _PAYLOADS.get() is not None


def baseline_control_ok(response):
    context = _PAYLOADS.get()
    return context is None or context[2] is None or bool(context[2](response))
