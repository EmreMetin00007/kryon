"""Kryon autonomous security operator CLI entry point."""
from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent
_REPO_ROOT = SCRIPTS.parent
for _p in (str(_REPO_ROOT), str(SCRIPTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

COMMANDS: dict[str, tuple[str, list[str]]] = {
    "agentic": ("agentic_runner", []),
    "report": ("agentic_report", []),
    "save-auth": ("save_browser_auth", []),
    "governance": ("governance_audit", []),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Available commands: agentic (autonomous assessment runner), "
            "report (evidence-backed report renderer), save-auth (browser session capture), "
            "governance (secret/PII static audit), and check-config (offline LLM config check)."
        ),
    )
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
        print(
            json.dumps(
                {
                    "status": "valid",
                    "schema": data["schema"],
                    "model": models["worker"],
                    "credential_read": False,
                    "network_requests": 0,
                }
            )
        )
        return 0
    module, prefix = COMMANDS[args.command]
    return int(importlib.import_module(module).main([*prefix, *remainder]))


if __name__ == "__main__":
    raise SystemExit(main())
