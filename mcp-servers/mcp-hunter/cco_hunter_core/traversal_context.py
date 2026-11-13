"""Select declared application canaries without changing observed baselines."""
from __future__ import annotations


def bind_file_probes(record, probes, rule, scope, revision):
    if rule is None:
        return probes
    from cco_surface_core.fuzz import apply_canary
    from cco_validator_core.traversal import application_files
    for probe in probes:
        if probe.get("vuln_class") not in {"lfi", "path_traversal"} or probe.get("skip"):
            continue
        try:
            if str(probe.get("baseline_method") or "GET").upper() != "GET":
                raise ValueError("application canaries require GET")
            files = application_files(rule, probe["baseline_url"], probe["param"],
                                      probe["location"], scope.permits_url)
            file = files[0]  # The validator tests both declared files, if present.
            applied = apply_canary(record, probe["param"], probe["location"], file["path"])
            probe.update(applied, payload=file["path"],
                         _declared_file={"marker": file["marker"], "revision": revision})
        except (ValueError, KeyError, TypeError):
            probe.update(skip="missing_context", reason="declared application file unavailable")
    return probes
