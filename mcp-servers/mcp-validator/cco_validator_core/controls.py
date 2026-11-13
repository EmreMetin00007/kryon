"""Request metadata for completed negative controls; no response bodies retained."""
from __future__ import annotations

from .evidence import response_evidence
from .waf_retry import response_is_waf_block


def usable_control(response, *, baseline=False, redirects=False):
    from .experiment_context import baseline_control_ok
    if baseline and not baseline_control_ok(response):
        return False
    status = response.get("status")
    if not response.get("ok") or not isinstance(status, int) or isinstance(status, bool):
        return False
    allowed = 200 <= status < 300
    if not baseline:
        allowed = allowed or status in {400, 422}
    if redirects:
        allowed = allowed or status in {301, 302, 303, 307, 308}
    return allowed and not response_is_waf_block(response)


class ControlTrace:
    """Keep every attempted control and refuse clean credit after a failed one."""

    def __init__(self):
        self.evidence = []
        self.complete = True

    def observe(self, response, role, **requirements):
        self.evidence.append(response_evidence(response, role, 0))
        self.complete = self.complete and usable_control(response, **requirements)
        return response
