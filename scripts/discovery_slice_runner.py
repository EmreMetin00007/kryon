"""Reproducible owned-lab trials with exact scope files and live audit logs.

Credentials are inherited from DISCOVERY_API_KEY/AR_KEY or entered with
getpass. They are never written to trial records or command arguments.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime
import getpass
import json
import os
from pathlib import Path
import re
import threading
import urllib.error

import discovery_experiment as experiment
from discovery_executor import LabExecutor
from discovery_loop import responses_transport


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-root", type=Path, required=True)
    parser.add_argument("--prefix", default="slice5")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--concurrency", type=int, choices=(1, 2), default=2)
    parser.add_argument("--brake-mode", choices=("novelty", "hypothesis"), default="novelty")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.prefix) or args.repeats <= 0:
        parser.error("use a simple prefix and positive repeat count")
    root = args.out_root.expanduser().resolve()
    if root.is_relative_to(Path(__file__).resolve().parents[1]):
        parser.error("experiment data must be outside the Git worktree")
    for variant in ("concat", "unspecified"):
        if any((root / f"{args.prefix}-{variant}").glob("run-llm-*.json")):
            parser.error("existing trials found; choose a new prefix")
    key = os.environ.get("DISCOVERY_API_KEY") or os.environ.get("AR_KEY") or getpass.getpass("API key: ")
    lock = threading.RLock()
    audit = Path.home() / ".codex/logs/scan_history.json"
    audit.parent.mkdir(parents=True, exist_ok=True)
    owned, counters = {}, {"concat": 0, "unspecified": 0}
    original_lab, original_fetch = experiment.DiscoveryLab, LabExecutor.fetch

    def event(action, **details):
        entry = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 "action": action, "experiment": args.prefix, **details}
        with lock, audit.open("a") as handle:
            handle.write(json.dumps(entry) + "\n")

    def progress(**details):
        with lock:
            print(json.dumps(details, ensure_ascii=False), flush=True)

    class ScopedLab(original_lab):
        def __init__(self, *lab_args, **kwargs):
            super().__init__(*lab_args, **kwargs)
            variant = self.js_variant
            with lock:
                counters[variant] += 1
                repeat = counters[variant]
            scope_dir = root / f"{args.prefix}-{variant}" / ".codex"
            scope_dir.mkdir(parents=True, exist_ok=True)
            path = scope_dir / f"scope-run-{repeat}.json"
            scope = {"authorization": "User-approved process-owned discovery experiment",
                     "in_scope": [{"asset": self.base, "type": "process-owned-synthetic-lab"}],
                     "out_of_scope": ["all other assessment targets", "destructive testing", "real user data"]}
            path.write_text(json.dumps(scope, indent=2) + "\n")
            (scope_dir / "scope.json").write_text(json.dumps(scope, indent=2) + "\n")
            assert json.loads(path.read_text())["in_scope"][0]["asset"] == self.base
            with lock:
                owned[self.base] = {"scope": path, "variant": variant, "repeat": repeat, "lab": self}
            event("scope_verified", target=self.base, variant=variant, repeat=repeat, scope_file=str(path))
            progress(event="scope_verified", variant=variant, repeat=repeat, target=self.base)

    def scoped_fetch(executor, method, path, body=None, session=None):
        with lock:
            info = owned.get(executor.base)
        if info is None:
            raise RuntimeError("unowned target refused")
        assert json.loads(info["scope"].read_text())["in_scope"][0]["asset"] == executor.base
        result = original_fetch(executor, method, path, body=body, session=session)
        log = info["lab"].log
        event("http_request", variant=info["variant"], repeat=info["repeat"], target=executor.base,
              method=method, path=path, status=result["status"], user=log[-1].get("user") if log else None)
        return result

    experiment.DiscoveryLab, LabExecutor.fetch = ScopedLab, scoped_fetch

    def run_variant(variant):
        out = root / f"{args.prefix}-{variant}"
        out.mkdir(parents=True, exist_ok=True)
        rows = []
        for repeat in range(1, args.repeats + 1):
            provider = responses_transport(key, "gpt-6.1-sol")
            call = 0

            def transport(body):
                nonlocal call
                call += 1
                phase = "closure" if body.get("tool_choice") == "required" else "discovery"
                progress(event="provider_call", variant=variant, repeat=repeat, call=call,
                         phase=phase, request_bytes=len(json.dumps(body).encode()))
                event("provider_call", variant=variant, repeat=repeat, call=call, phase=phase)
                try:
                    response = provider(body)
                except urllib.error.HTTPError as exc:
                    diagnostic = {"variant": variant, "repeat": repeat, "call": call, "phase": phase,
                                  "http_status": exc.code,
                                  "provider_error": exc.read().decode(errors="replace").replace(key, "[REDACTED]")[:1500]}
                    (out / f"provider-error-{repeat}-{call}.json").write_text(json.dumps(diagnostic, indent=2) + "\n")
                    progress(event="provider_error", **diagnostic)
                    event("provider_error", variant=variant, repeat=repeat, call=call, http_status=exc.code)
                    raise
                tools = dict(collections.Counter(c["name"] for c in response.get("function_calls", [])))
                tokens = (response.get("usage") or {}).get("total_tokens")
                progress(event="provider_result", variant=variant, repeat=repeat, call=call,
                         phase=phase, tokens=tokens, tools=tools, response_status=response.get("response_status"))
                event("provider_response", variant=variant, repeat=repeat, call=call,
                      phase=phase, reported_tokens=tokens, tools=tools)
                return response

            run = experiment.one_run("llm", repeat, transport, js_variant=variant, brake_mode=args.brake_mode)
            scope = out / ".codex" / f"scope-run-{repeat}.json"
            run.update(target=json.loads(scope.read_text())["in_scope"][0]["asset"],
                       scope_file=str(scope), experiment_concurrency=args.concurrency)
            path = out / f"run-llm-{repeat}.json"
            with path.open("x") as handle:
                handle.write(json.dumps(run, indent=1, ensure_ascii=False) + "\n")
            row = {k: run[k] for k in ("repeat", "js_variant", "elapsed_s", "http_requests", "llm_tokens",
                   "turns", "stop_reason", "submitted", "report_completed", "score", "closure_trigger", "phase_turns")}
            rows.append(row)
            progress(event="trial_completed", **row)
            event("trial_completed", variant=variant, repeat=repeat, path=str(path),
                  submitted=run["submitted"], report_completed=run["report_completed"],
                  detections=run["score"]["positives_found"])
        (out / "summary.json").write_text(json.dumps(rows, indent=1, ensure_ascii=False) + "\n")
        return rows

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = [pool.submit(run_variant, variant) for variant in ("concat", "unspecified")]
            for future in futures:
                future.result()
    finally:
        experiment.DiscoveryLab, LabExecutor.fetch = original_lab, original_fetch
    progress(event="all_trials_completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
