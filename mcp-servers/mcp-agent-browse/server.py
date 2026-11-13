#!/usr/bin/env python3
"""MCP agent-browse server — guardrailed agentic browser (self-hosted browser-use).

Two tools:
  agent_browse        full agent loop (needs explicit --model / $CCO_AGENT_MODEL)
  agent_browse_check  no-LLM verification: browser + proxy + research header proof

The wrapper (scripts/agent_browse.py) enforces allowlist/scope, research
header, scope proxy and secret handling; this server only passes arguments
through (argv list, no shell) and returns the run summary. Secrets are never
read here — --creds is a local path consumed by the wrapper into
browser-use `sensitive_data` (kept out of the LLM prompt).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

REPO = Path(__file__).resolve().parent.parent.parent
WRAPPER = REPO / "scripts" / "agent_browse.py"
VENV_PY = REPO / ".venv" / "bin" / "python"

EXIT_OK, EXIT_ERROR, EXIT_HUMAN = 0, 2, 10

mcp = FastMCP(
    "agent-browse",
    instructions=(
        "Guardrailed agentic browser. allowlist defaults to the active program scope; "
        "off-scope start URLs are refused. Every request carries the research header "
        "through the scope proxy. Secrets: pass a local 0600 --creds path and use "
        "<placeholders> in the task, never raw values. CAPTCHA/anti-bot walls stop "
        "the run with HUMAN_NEEDED and a screenshot (no third-party solvers)."
    ),
)


def _resolve_out(out_dir: str) -> Path | None:
    """Resolve evidence dir; refuse anything outside the repo."""
    if not out_dir:
        return None
    p = (REPO / out_dir).resolve() if not Path(out_dir).is_absolute() else Path(out_dir).resolve()
    if not p.is_relative_to(REPO):
        return None
    return p


def _run_wrapper(args: list[str], run_timeout_seconds: int) -> dict:
    if not VENV_PY.exists():
        return {"ok": False, "exit_code": 2,
                "error": f"project venv missing: {VENV_PY} (run: uv venv && uv pip install browser-use)"}
    if not WRAPPER.exists():
        return {"ok": False, "exit_code": 2, "error": f"wrapper missing: {WRAPPER}"}
    try:
        proc = subprocess.run(
            [str(VENV_PY), str(WRAPPER), *args],
            capture_output=True, text=True, timeout=run_timeout_seconds, cwd=str(REPO),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "timeout": True,
                "error": f"run exceeded {run_timeout_seconds}s and was killed"}
    out = {"exit_code": proc.returncode, "stdout_tail": proc.stdout[-2000:], "stderr_tail": proc.stderr[-2000:]}
    if proc.returncode == EXIT_HUMAN:
        out["human_needed"] = True
    # Attach run summary when the wrapper wrote one.
    for line in proc.stdout.splitlines():
        if line.startswith("evidence: "):
            run_json = Path(line.split("evidence: ", 1)[1].strip()) / "run.json"
            if run_json.exists():
                try:
                    out["run"] = json.loads(run_json.read_text())
                    out["evidence"] = str(run_json.parent)
                except Exception:
                    pass
            break
    out["ok"] = proc.returncode == EXIT_OK
    return out


@mcp.tool()
def agent_browse(
    task: str,
    start_url: str,
    model: str = "",
    allowlist: str = "",
    extra_domains: str = "",
    max_steps: int = 25,
    max_actions_per_step: int = 3,
    storage_state: str = "",
    creds: str = "",
    headed: bool = False,
    out_dir: str = "",
    extra_headers: str = "",
    run_timeout_seconds: int = 900,
) -> str:
    """Run the guardrailed agentic browser on a scope URL.

    Args:
        task: Agent task. Use <placeholders> for secrets, never raw values.
        start_url: Entry URL. Must be in allowlist (default: active scope) or loopback.
        model: LiteLLM id, e.g. "openrouter/<m>" (or $CCO_AGENT_MODEL). Empty = refuse.
        allowlist: Comma domains or @file. Empty = .codex/scope.json in_scope assets.
        extra_domains: Explicit non-scope domains (e.g. OAuth hosts). Operator approval required.
        max_steps: Agent step budget (default 25).
        max_actions_per_step: Action budget per step (default 3).
        storage_state: Saved login session path (0600 recommended).
        creds: JSON {placeholder: value} path (0600 required). Values never reach the LLM.
        headed: Headed browser (needs display). Default headless.
        out_dir: Evidence dir, must stay inside the repo. Empty = auto.
        extra_headers: JSON dict of extra request headers, e.g. '{"X-HackerOne": "letmet4y"}'.
        run_timeout_seconds: Hard kill deadline for the whole run (default 900).

    Returns: JSON with ok/exit_code/evidence/run summary. exit 10 (human_needed)
        means a CAPTCHA/login wall stopped the run — see the screenshot, do NOT retry blindly.
    """
    args = ["--task", task, "--start-url", start_url]
    if model:
        args += ["--model", model]
    if allowlist:
        args += ["--allowlist", allowlist]
    if extra_domains:
        args += ["--extra-domains", extra_domains]
    args += ["--max-steps", str(max_steps), "--max-actions-per-step", str(max_actions_per_step)]
    for flag, val in (("--storage-state", storage_state), ("--creds", creds)):
        if val:
            if not Path(val).exists():
                return json.dumps({"ok": False, "error": f"refusing: file missing: {val}"})
            args += [flag, val]
    if extra_headers:
        try:
            hdrs = json.loads(extra_headers)
        except Exception:
            return json.dumps({"ok": False, "error": "refusing: extra_headers is not valid JSON"})
        if not isinstance(hdrs, dict):
            return json.dumps({"ok": False, "error": "refusing: extra_headers must be a JSON object"})
        for k, v in hdrs.items():
            args += ["--header", f"{k}: {v}"]
    if headed:
        args += ["--headed"]
    if out_dir:
        resolved = _resolve_out(out_dir)
        if resolved is None:
            return json.dumps({"ok": False, "error": f"refusing: out_dir outside repo: {out_dir}"})
        args += ["--out", str(resolved)]
    return json.dumps(_run_wrapper(args, run_timeout_seconds))


@mcp.tool()
def agent_browse_check(start_url: str, out_dir: str = "", run_timeout_seconds: int = 180) -> str:
    """No-LLM verification: launch browser, load a loopback URL, prove proxy+header.

    Args:
        start_url: Loopback lab URL only (live URLs refused in check mode).
        out_dir: Evidence dir, must stay inside the repo. Empty = auto.
        run_timeout_seconds: Hard kill deadline (default 180).

    Returns: JSON with research_header_seen / screenshot / exit_code. Zero LLM cost.
    """
    args = ["--task", "check", "--start-url", start_url, "--check"]
    if out_dir:
        resolved = _resolve_out(out_dir)
        if resolved is None:
            return json.dumps({"ok": False, "error": f"refusing: out_dir outside repo: {out_dir}"})
        args += ["--out", str(resolved)]
    return json.dumps(_run_wrapper(args, run_timeout_seconds))


if __name__ == "__main__":
    mcp.run()
