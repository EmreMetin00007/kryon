#!/usr/bin/env python3
"""CLI wrapper for the central policy engine."""

from __future__ import annotations

import argparse
import json
import os
import sys

try:
    from .policy_engine import PolicyEngine
except ImportError:
    from policy_engine import PolicyEngine  # type: ignore[no-redef]


def _engine() -> PolicyEngine:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return PolicyEngine(
        cco_home=os.environ.get("CCO_HOME", os.path.join(repo_root, ".cco")),
        repo_root=repo_root,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCO policy gate CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("--tool", required=True)
    validate.add_argument("--args-json", default="{}")
    validate.add_argument("--action-type", default="execute")
    validate.add_argument("--metadata-json", default="{}")

    approve = sub.add_parser("approve")
    approve.add_argument("--tool-pattern", default="*")
    approve.add_argument("--target-pattern", default="*")
    approve.add_argument("--ttl", type=int, default=3600)
    approve.add_argument("--reason", default="ACTIVE_OK")

    revoke = sub.add_parser("revoke")
    revoke.add_argument("approval_id", type=int)

    sub.add_parser("approvals")
    scope = sub.add_parser("scope")
    scope.add_argument("--json", action="store_true")
    policy = sub.add_parser("policy")
    policy.add_argument("--json", action="store_true")
    audit = sub.add_parser("audit")
    audit.add_argument("--limit", type=int, default=100)

    path_close = sub.add_parser("path-close")
    path_close.add_argument("--url", required=True)
    path_close.add_argument("--host", default="")
    path_close.add_argument("--min-probes", type=int, default=5)
    path_close.add_argument("--min-methods", type=int, default=2)
    path_close.add_argument("--min-ua", type=int, default=2)
    path_close.add_argument("--min-headers", type=int, default=2)

    args = parser.parse_args(argv)
    if args.command in ("approve", "revoke") and os.environ.get("CCO_BASH_SANDBOXED") == "1":
        print(json.dumps({"error": (
            "operator-only: approve/revoke inside the bash sandbox writes to a "
            "throwaway store; run it from an operator shell outside the sandbox"
        )}), file=sys.stderr)
        return 2
    engine = _engine()

    if args.command == "validate":
        try:
            parsed_args = json.loads(args.args_json)
            metadata = json.loads(args.metadata_json)
            if not isinstance(parsed_args, dict):
                parsed_args = {}
            if not isinstance(metadata, dict):
                metadata = {}
        except Exception:
            parsed_args, metadata = {}, {}
        result = engine.validate_tool_invocation(args.tool, parsed_args, args.action_type, metadata)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["allowed"] else 2

    if args.command == "approve":
        grant = engine.grant_approval(args.tool_pattern, args.target_pattern, args.ttl, args.reason)
        print(json.dumps(grant.__dict__, indent=2, ensure_ascii=False))
        return 0

    if args.command == "revoke":
        ok = engine.revoke_approval(args.approval_id)
        print(json.dumps({"revoked": ok, "approval_id": args.approval_id}, indent=2))
        return 0 if ok else 1

    if args.command == "approvals":
        print(json.dumps(engine.list_approvals(), indent=2, ensure_ascii=False))
        return 0

    if args.command == "scope":
        scope_data = engine.scope.get("raw", {}) or {
            "targets": sorted(engine.scope["targets"]),
            "domains": sorted(engine.scope["domains"]),
            "cidr_ranges": sorted(engine.scope["cidr_ranges"]),
            "url_prefixes": sorted(engine.scope["url_prefixes"]),
        }
        print(json.dumps(scope_data, indent=2, ensure_ascii=False))
        return 0

    if args.command == "policy":
        print(json.dumps(engine.program_policy, indent=2, ensure_ascii=False))
        return 0

    if args.command == "audit":
        print(json.dumps(engine.audit(limit=args.limit), indent=2, ensure_ascii=False))
        return 0

    if args.command == "path-close":
        result = engine.check_path_close(
            args.url,
            host=args.host,
            min_probes=args.min_probes,
            min_methods=args.min_methods,
            min_ua=args.min_ua,
            min_headers=args.min_headers,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["allowed"] else 2

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
