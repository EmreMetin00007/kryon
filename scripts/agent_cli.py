"""Independent Python engine entry point. Planning never authorizes traffic."""
from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
import sys

# Existing operator modules support direct execution from this directory.
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

COMMANDS = {
    "plan": ("brain", ["plan"]),
    "operations": ("brain", ["operations"]),
    "preflight": ("full_agent_preflight", []),
    "run": ("full_agent_launcher", []),
    "audit": ("full_agent_holdout", ["audit"]),
    "benchmark": ("full_agent_e6_benchmark", []),
    "campaign": ("campaign_runtime", []),
    "worker": ("campaign_worker", []),
    "security": ("policy_gate_cli", []),
    "status": ("operator_cli", ["dashboard"]),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "preflight/run currently execute the bounded four-phase owned-lab workflow. "
        "plan/operations are offline; run requires --execute and a verified preflight."))
    parser.add_argument("command", choices=[*COMMANDS, "check-config"])
    args, remainder = parser.parse_known_args(argv)
    if args.command == "check-config":
        from llm_config import default_config, load_config, model_selection
        check = argparse.ArgumentParser(prog="cco-agent check-config")
        check.add_argument("--provider-config", type=Path, default=default_config())
        options = check.parse_args(remainder)
        try:
            data = load_config(options.provider_config)
            models = model_selection(options.provider_config)
        except (ValueError, OSError, TypeError) as exc:
            # Do not echo parsed config values or provider credentials.
            check.error("configuration unavailable or invalid: " + type(exc).__name__)
        print(json.dumps({"status": "valid", "schema": data["schema"], "model": models["worker"],
                          "credential_read": False, "network_requests": 0}))
        return 0
    module, prefix = COMMANDS[args.command]
    if args.command in {"preflight", "run"}:
        # This entry point has one engine. Native compatibility is never selected
        # by a model, environment variable or an omitted solver flag.
        if any(value == "--solver-mode" or value.startswith("--solver-mode=") for value in remainder):
            parser.error("cco-agent always uses python_loop; omit --solver-mode")
        remainder = [*remainder, "--solver-mode", "python_loop"]
    return importlib.import_module(module).main([*prefix, *remainder])


if __name__ == "__main__":
    raise SystemExit(main())
