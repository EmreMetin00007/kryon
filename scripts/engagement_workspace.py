"""Launch an engagement with isolated state and working-data directories."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys


def engagement_environment(engagement_id: str, scope: str, home_root: str, work_root: str,
                           policy: str = "") -> dict[str, str]:
    """Resolve paths without creating or reading any engagement data."""
    identity = str(engagement_id or "").strip()
    if not identity or len(identity) > 128 or re.search(r"[\x00-\x1f\x7f]", identity):
        raise ValueError("engagement ID must contain 1–128 printable characters")
    scope_path = Path(scope).expanduser().resolve()
    if not scope_path.is_file():
        raise ValueError("scope file does not exist")
    policy_path = Path(policy).expanduser().resolve() if policy else None
    if policy_path is not None and not policy_path.is_file():
        raise ValueError("program policy file does not exist")
    homes, works = Path(home_root).expanduser().resolve(), Path(work_root).expanduser().resolve()
    if homes == works or homes in works.parents or works in homes.parents:
        raise ValueError("state and work roots must not overlap")
    material = json.dumps(["cco-engagement/1", identity, str(scope_path),
                           str(policy_path) if policy_path else ""], ensure_ascii=False)
    namespace = hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
    result = {"CCO_ENGAGEMENT_ID": identity, "CCO_SCOPE_FILE": str(scope_path),
              "CCO_HOME": str(homes / namespace), "CCO_WORKDIR": str(works / namespace)}
    if policy_path:
        result["CCO_PROGRAM_POLICY_FILE"] = str(policy_path)
    return result


def mcp_config_overlay(project_config: Path | None, isolated: dict[str, str], existing: str = "") -> str:
    """Bind local MCP server settings to the selected engagement."""
    try:
        inline = json.loads(existing) if existing else {}
        project = json.loads(project_config.read_text(encoding="utf-8")) if project_config else {}
    except (OSError, ValueError) as exc:
        raise ValueError("MCP configuration could not be read or parsed") from exc
    if not isinstance(inline, dict) or not isinstance(project, dict):
        raise ValueError("MCP configuration must be a JSON object")
    base_mcp = project.get("mcp", {})
    inline_mcp = inline.get("mcp", {})
    if not isinstance(base_mcp, dict) or not isinstance(inline_mcp, dict):
        raise ValueError("MCP servers must be an object")

    def merge(base, overlay):
        result = copy.deepcopy(base)
        for key, value in overlay.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = merge(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        return result

    servers = merge(base_mcp, inline_mcp)
    for server in servers.values():
        if not isinstance(server, dict) or server.get("type") != "local":
            continue
        server_env = server.setdefault("environment", {})
        if not isinstance(server_env, dict):
            raise ValueError("MCP server environment must be an object")
        server_env.update({"CCO_HOME": isolated["CCO_HOME"], "CCO_WORKDIR": isolated["CCO_WORKDIR"],
                           "CCO_SCOPE_FILE": isolated["CCO_SCOPE_FILE"],
                           "CCO_ENGAGEMENT_ID": isolated["CCO_ENGAGEMENT_ID"],
                           "CCO_PROGRAM_POLICY_FILE": isolated.get("CCO_PROGRAM_POLICY_FILE", "")})
    inline["mcp"] = servers
    return json.dumps(inline, ensure_ascii=False, separators=(",", ":"))


def _find_mcp_config() -> Path | None:
    current = Path.cwd().resolve()
    return next((directory / "config/mcp-servers.json" for directory in (current, *current.parents)
                 if (directory / "config/mcp-servers.json").is_file()), None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True, help="Unique program/run identifier")
    parser.add_argument("--scope", required=True, help="Existing scope JSON file")
    parser.add_argument("--policy", default="", help="Existing program policy JSON file")
    parser.add_argument("--home-root", default="~/.cco/engagements")
    parser.add_argument("--work-root", default="~/cco-work/engagements")
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="Optional command after --; no command prints the isolation plan")
    args = parser.parse_args(argv)
    try:
        isolated = engagement_environment(args.id, args.scope, args.home_root, args.work_root, args.policy)
        command = args.command[1:] if args.command and args.command[0] == "--" else args.command
        if not command:
            print(json.dumps({"created": False, "environment": isolated}, indent=2, ensure_ascii=False))
            return 0
        for key in ("CCO_HOME", "CCO_WORKDIR"):
            directory = Path(isolated[key])
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not directory.is_dir():
                raise ValueError(f"{key} is not a directory")
            if directory.stat().st_mode & 0o077:
                raise ValueError(f"{key} must not be accessible to group or others")
        env = os.environ.copy()
        env.update(isolated)
        if not args.policy:
            # Do not inherit a different engagement's explicit policy.
            env.pop("CCO_PROGRAM_POLICY_FILE", None)
        project_config = _find_mcp_config()
        if project_config or env.get("CCO_MCP_CONFIG_CONTENT"):
            env["CCO_MCP_CONFIG_CONTENT"] = mcp_config_overlay(
                project_config, isolated, env.get("CCO_MCP_CONFIG_CONTENT", ""))
        os.execvpe(command[0], command, env)
    except (OSError, ValueError) as exc:
        print(f"engagement isolation: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
