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
    "start": ("agentic_wizard", []),
    "recon": ("agentic_recon", []),
    "map": ("agentic_surface_map", []),
    "agentic": ("agentic_runner", []),
    "run": ("agentic_runner", []),
    "watch": ("agentic_tui", []),
    "report": ("agentic_report", []),
    "save-auth": ("save_browser_auth", []),
    "governance": ("governance_audit", []),
}


def _cmd_presets(remainder: list[str]) -> int:
    from agentic_presets import describe_presets

    sub = argparse.ArgumentParser(prog="cco-agent presets")
    sub.add_argument("--format", choices=["json", "text"], default="json")
    opts = sub.parse_args(remainder)
    catalog = describe_presets()
    if opts.format == "text":
        for name, info in catalog["presets"].items():
            o = info["options"]
            print(
                f"{name}: {info['description']} "
                f"[mode={o.get('execution_mode')}, http={o.get('http_budget')}, "
                f"tokens={o.get('token_budget')}, seconds={o.get('seconds_budget')}, "
                f"max_rps={o.get('max_rps')}]"
            )
        return 0
    print(json.dumps(catalog, indent=2))
    return 0


def _cmd_status(remainder: list[str]) -> int:
    sub = argparse.ArgumentParser(prog="cco-agent status")
    sub.add_argument("run_dir", type=Path, help="Assessment output directory containing manifest.json or agentic-plan.json")
    opts = sub.parse_args(remainder)
    run_dir = opts.run_dir.expanduser().resolve()
    manifest_path = run_dir / "manifest.json"
    plan_path = run_dir / "agentic-plan.json"
    artifact = manifest_path if manifest_path.is_file() else (plan_path if plan_path.is_file() else None)
    if artifact is None:
        sub.error(f"no manifest.json or agentic-plan.json found in {run_dir}")
    try:
        doc = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        sub.error(f"failed to read {artifact.name}: {type(exc).__name__}")
    if not isinstance(doc, dict):
        sub.error(f"invalid JSON object in {artifact.name}")
    summary = {
        "run_dir": str(run_dir),
        "artifact": str(artifact),
        "mode": doc.get("mode"),
        "status": doc.get("status") or ("planned" if doc.get("mode") == "plan_only" else None),
        "target": doc.get("target"),
        "preset": doc.get("preset"),
        "allowed_methods": doc.get("allowed_methods"),
        "request_headers": doc.get("request_headers"),
        "findings_count": doc.get("findings_count", 0),
        "target_requests": doc.get("target_requests", 0),
        "llm_calls": doc.get("llm_calls", 0),
        "wall_clock_seconds": doc.get("wall_clock_seconds"),
        "prescan": doc.get("prescan"),
        "har_flows": doc.get("har_flows"),
        "asset_graph": doc.get("asset_graph"),
        "surface_map": doc.get("surface_map"),
        "waf_pivot": doc.get("waf_pivot"),
        "report_md": doc.get("report_md"),
        "report_sarif": doc.get("report_sarif"),
        "error": doc.get("error"),
    }
    print(json.dumps(summary, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Available commands: start (interactive zero-flag launcher), recon (scope-locked asset discovery & graph builder), "
            "map (canonical multi-origin site map builder), "
            "plan (zero-traffic dry-run planner), run / agentic (autonomous assessment runner with --preset/--config/--prescan/--tui), "
            "watch (read-only live TUI monitor), presets (list built-in presets), status (compact JSON run summary), "
            "report (evidence-backed report renderer), save-auth (browser session capture), "
            "governance (secret/PII static audit), and check-config (offline LLM config check)."
        ),
    )
    parser.add_argument("command", choices=[*COMMANDS, "plan", "presets", "status", "check-config"])
    args, remainder = parser.parse_known_args(argv)
    if args.command == "plan":
        import agentic_runner

        return int(agentic_runner.main(remainder, force_plan_only=True))
    if args.command == "presets":
        return _cmd_presets(remainder)
    if args.command == "status":
        return _cmd_status(remainder)
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
