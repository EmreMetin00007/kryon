#!/usr/bin/env python3
"""Agentic browser runner (self-hosted browser-use) with scope guardrails.

Guards:
  - start URL and observed steps use central scope rules, including path and
    port; browser-use's domain allowlist provides an additional host filter.
    The step callback runs after navigation and is not a per-request gate.
  - secrets: `--creds` JSON values go ONLY into browser-use `sensitive_data`
    (placeholder substitution at action time, kept out of the LLM prompt).
    The task text must use <placeholders>; if a raw secret value appears in
    the task it is refused. Values are never printed or written to evidence.
  - captcha/anti-bot: no third-party solver services (PII/ToS). On detection
    the run stops, a screenshot is saved, exit code 10 (HUMAN_NEEDED).
  - audit: browser traffic normally goes through the configured proxy; the
    logging proxy itself does not enforce a policy gate on every request.

Exit codes: 0 ok, 2 error/policy violation, 10 human needed (captcha/wall).

Live agent-browser execution is currently disabled: the browser-use adapter
does not provide an enforceable per-request gate. Use the gated browser MCP
session until that adapter can be validated end to end.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import socket
import stat
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
EXIT_OK, EXIT_ERROR, EXIT_HUMAN = 0, 2, 10

CAPTCHA_PAT = re.compile(
    r"captcha|turnstile|recaptcha|hcaptcha|verify you are human|are you a robot|"
    r"unusual traffic|datadome|perimeterx|kasada|just a moment|attention required",
    re.IGNORECASE,
)
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
PLACEHOLDER = re.compile(r"<([A-Za-z0-9_]+)>")


def _agent_wire_policy_available() -> bool:
    # A logging proxy and a post-navigation callback cannot enforce every
    # browser request. Do not provide an environment-variable bypass.
    return False


def _wire_policy_unavailable() -> int:
    print("refusing: agent-browser request-level policy is unavailable; "
          "use the gated browser session tools", file=sys.stderr)
    return EXIT_ERROR


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def central_scope_permits(url: str) -> bool:
    """Read-only prefilter; a live request still needs the full policy gate."""
    try:
        script_dir = str(REPO / "scripts")
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        from policy_engine import ScopeResolver
        return ScopeResolver(repo_root=REPO).permits_url(url)
    except (ImportError, OSError, RuntimeError, ValueError):
        return False


def in_allowlist(host: str, allow: set[str]) -> bool:
    if host in LOOPBACK:
        return True
    return any(host == d or host.endswith("." + d) for d in allow)


def load_scope_allowlist() -> set[str]:
    """Default allowlist from the active program scope file."""
    p = Path(os.environ.get("CCO_SCOPE_FILE") or REPO / ".codex" / "scope.json")
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text())
    except Exception:
        return set()
    out: set[str] = set()
    items = data.get("in_scope", []) if isinstance(data, dict) else []
    for it in items:
        asset = it.get("asset", "") if isinstance(it, dict) else str(it)
        asset = asset.strip().lower()
        if "://" in asset:
            asset = host_of(asset)
        asset = asset.split("/")[0].split(":")[0]
        if asset and asset != "*":
            out.add(asset.removeprefix("*.").lstrip("."))
    return out


def parse_allowlist(spec: str | None) -> set[str]:
    if not spec:
        return load_scope_allowlist()
    if spec.startswith("@"):
        lines = Path(spec[1:].replace("@", "", 1) if spec.startswith("@@") else spec[1:]).read_text().splitlines()
        parts = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    else:
        parts = [d.strip().lower().lstrip(".") for d in spec.split(",")]
    return {d for d in parts if d}


def check_perms(path: Path, label: str, strict: bool) -> None:
    st = path.stat()
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        msg = f"{label} {path} is group/other accessible (mode {oct(st.st_mode & 0o777)}); run: chmod 600 {path}"
        if strict:
            print(f"refusing: {msg}", file=sys.stderr)
            raise SystemExit(EXIT_ERROR)
        print(f"warning: {msg}", file=sys.stderr)


def proxy_reachable(proxy_url: str) -> bool:
    u = urlparse(proxy_url)
    try:
        with socket.create_connection((u.hostname or "127.0.0.1", u.port or 8080), timeout=5):
            return True
    except OSError:
        return False


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Guardrailed agentic browser (browser-use, self-hosted).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--task", help="Agent task. Use <placeholders> for secrets, never raw values.")
    g.add_argument("--task-file", type=Path, help="File with the agent task.")
    ap.add_argument("--start-url", required=True)
    ap.add_argument("--allowlist", default=None,
                    help="Comma domains or @file. Default: .codex/scope.json in_scope assets.")
    ap.add_argument("--extra-domains", default="",
                    help="Explicit non-scope domains (e.g. github.com for OAuth). Operator approval required.")
    ap.add_argument("--max-steps", type=int, default=25)
    ap.add_argument("--max-actions-per-step", type=int, default=3)
    ap.add_argument("--model", default=os.environ.get("CCO_AGENT_MODEL", ""),
                    help="LiteLLM model id, e.g. openrouter/google/gemini-2.0-flash-001 (or $CCO_AGENT_MODEL).")
    ap.add_argument("--proxy", default="http://127.0.0.1:8080")
    ap.add_argument("--no-proxy", action="store_true", help="Bypass scope proxy (lab only).")
    ap.add_argument("--handle", default=os.environ.get("HACKERONE_HANDLE", ""),
                    help="Research handle for X-HackerOne-Research (or $HACKERONE_HANDLE).")
    ap.add_argument("--header", action="append", default=[],
                    help='Extra request header "Name: value" (repeatable, wins over --handle).')
    ap.add_argument("--storage-state", type=Path, default=None)
    ap.add_argument("--creds", type=Path, default=None,
                    help="JSON {placeholder: value}. 0600 required. Values never reach the LLM prompt.")
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--check", action="store_true",
                    help="No-LLM verification: launch browser, load start URL, prove header+proxy, exit.")
    return ap


def resolve_task(args) -> str:
    if args.task_file:
        return args.task_file.read_text(encoding="utf-8").strip()
    return args.task.strip()


def load_creds(path: Path | None, task: str) -> dict[str, str]:
    if path is None:
        return {}
    check_perms(path, "creds file", strict=True)
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        print("creds file must be a JSON object {placeholder: value}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)
    creds = {str(k): str(v) for k, v in data.items()}
    # Fail closed: raw secret values must not appear in the LLM-bound task text.
    for name, val in creds.items():
        if len(val) >= 4 and val in task:
            print(f"refusing: cred value for <{name}> appears literally in --task; use the placeholder",
                  file=sys.stderr)
            raise SystemExit(EXIT_ERROR)
    missing = sorted(set(PLACEHOLDER.findall(task)) - set(creds))
    if missing:
        print(f"warning: task placeholders without creds (agent will stall on them): {missing}", file=sys.stderr)
    return creds


def launch_hardening() -> dict:
    """Root/container environments need the chromium sandbox off (lab-only box)."""
    if os.geteuid() == 0:
        return {"chromium_sandbox": False,
                "args": ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]}
    return {}


async def arm_header_injection(session, headers: dict[str, str]) -> bool:
    """Inject research headers into every page request (CDP, per focus target).

    Notes (verified against browser-use 0.13.10 source):
    - `BrowserSession(headers=...)` only covers the CDP handshake, NOT page
      traffic. Real injection is `set_extra_headers` (Network.setExtraHTTPHeaders).
    - Headers are per target: call again after navigation / new tabs.
    """
    if not headers:
        return True
    try:
        await session.set_extra_headers(headers)
        return True
    except Exception as e:
        print(f"header injection arming failed: {e}", file=sys.stderr)
        return False


def build_llm(model: str):
    from browser_use.llm.litellm import ChatLiteLLM

    if model.startswith("openrouter/"):
        from browser_use.llm.openrouter.chat import ChatOpenRouter

        return ChatOpenRouter(model=model.removeprefix("openrouter/"))
    return ChatLiteLLM(model=model)


def make_out_dir(base: Path | None) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = base or (REPO / "evidence" / "agent-browse" / ts)
    out.mkdir(parents=True, exist_ok=True)
    return out


def _traffic_log_path() -> Path:
    cco_home = Path(os.environ.get("CCO_HOME", "~/.cco")).expanduser()
    return cco_home / "scope-traffic.jsonl"


async def _extract_session_cookies(session) -> list[dict]:
    for attr in ("cookies", "get_cookies"):
        fn = getattr(session, attr, None)
        if callable(fn):
            try:
                res = fn()
                if asyncio.iscoroutine(res):
                    res = await res
                if isinstance(res, list):
                    return res
            except Exception:
                pass
    try:
        get_page = getattr(session, "get_current_page", None)
        if callable(get_page):
            page = await get_page()
            if page is not None and hasattr(page, "context"):
                res = page.context.cookies()
                if asyncio.iscoroutine(res):
                    res = await res
                if isinstance(res, list):
                    return res
    except Exception:
        pass
    return []


def _harvest_allowed(url: str, allow: set[str] | None) -> bool:
    """Hasat filtresi: allow=None ise her şey geç; loopback her zaman izinli."""
    if allow is None:
        return True
    return in_allowlist(host_of(url or ""), allow)


def harvest_agent_run(
    cookies: list[dict],
    start_url: str,
    steps: list[dict],
    headers: dict[str, str],
    out: Path,
    traffic_offset: int = 0,
    cco_home: str | None = None,
    allow: set[str] | None = None,
) -> dict:
    """Sync cookies to session vault/jar, ingest MITM+step routes to attack_surface, and compile chains.

    allow verilirse kapsam dışı host'lar kasaya, yüzeye ve zincire girmez;
    denetim izi (violations/visited_hosts) run.json'da korunur.
    """
    script_dir = str(REPO / "scripts")
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    from workflow_compiler import (
        compile_workflow_manifests,
        ingest_captured_requests,
        sync_browser_cookies_to_vault,
    )

    session_summary = sync_browser_cookies_to_vault(
        cookies,
        default_url=start_url,
        headers=headers,
        identity="agent_browse",
        source="agent_browse",
        cco_home=cco_home,
        allow=allow,
    )

    captured: list[dict] = []
    allow_filtered = 0
    tpath = Path(cco_home) / "scope-traffic.jsonl" if cco_home else _traffic_log_path()
    if tpath.is_file():
        try:
            with tpath.open("rb") as f:
                f.seek(max(0, traffic_offset))
                raw_lines = f.read().decode("utf-8", errors="replace").splitlines()
            for ln in raw_lines:
                ln = ln.strip()
                if ln.startswith("{"):
                    try:
                        entry = json.loads(ln)
                        u = str(entry.get("url") or "")
                        if u and not _harvest_allowed(u, allow):
                            allow_filtered += 1
                            continue
                        captured.append(entry)
                    except Exception:
                        pass
        except Exception:
            pass

    for s in steps or []:
        u = str(s.get("url") or "").strip()
        if u.startswith(("http://", "https://")):
            if not _harvest_allowed(u, allow):
                allow_filtered += 1
                continue
            captured.append({"method": "GET", "url": u, "status": 200})

    ingested = ingest_captured_requests(
        captured,
        target_hint=start_url,
        source="agent_browse",
        cco_home=cco_home,
        allow=allow,
    )
    workflow_gaps = []
    manifests = compile_workflow_manifests(captured, target_ref=host_of(start_url) or "target",
                                           allow=allow, diagnostics=workflow_gaps)
    manifest_file = out / "workflow_manifests.json"
    if manifests:
        try:
            manifest_file.write_text(json.dumps(manifests, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    return {
        "session_synced": session_summary,
        "surface_ingested": {
            "inserted": ingested.get("inserted", 0),
            "updated": ingested.get("updated", 0),
            "total_touched": ingested.get("total_touched", 0),
        },
        "allow_filtered": allow_filtered,
        "workflow_manifests_count": len(manifests),
        "workflow_missing_prerequisites": workflow_gaps,
        "workflow_manifests_path": str(manifest_file) if manifests else "",
    }


# ---------------------------------------------------------------- check mode

class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = json.dumps({"headers": dict(self.headers), "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


async def run_check(args, allow: set[str], headers: dict[str, str]) -> int:
    """Prove browser + header (+proxy) path with zero LLM calls and zero live targets."""
    if not _agent_wire_policy_available():
        return _wire_policy_unavailable()
    from browser_use import BrowserSession
    from browser_use.browser.profile import ProxySettings

    if host_of(args.start_url) not in LOOPBACK:
        print("--check only targets loopback (lab). Refusing live URL.", file=sys.stderr)
        return EXIT_ERROR
    srv = HTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    echo_url = f"http://127.0.0.1:{srv.server_port}/echo"
    proxy = None if args.no_proxy else ProxySettings(server=args.proxy)
    session = BrowserSession(
        headless=not args.headed,
        proxy=proxy,
        headers=headers,
        allowed_domains=sorted(allow | LOOPBACK),
        storage_state=str(args.storage_state) if args.storage_state else None,
        minimum_wait_page_load_time=0.5,
        **launch_hardening(),
    )
    try:
        try:
            await session.start()
        except Exception as e:
            print(f"browser start failed: {type(e).__name__}: {str(e)[:300]}", file=sys.stderr)
            return EXIT_ERROR
        await session.navigate_to(args.start_url)
        # Re-arm after navigation: headers are per focus target and the focus
        # target only exists once a page is open.
        if not await arm_header_injection(session, headers):
            print("refusing: could not arm header injection; no headerless traffic allowed.",
                  file=sys.stderr)
            return EXIT_ERROR
        await session.navigate_to(echo_url)
        page = await session.get_current_page()
        assert page is not None, "no current page after navigation"
        seen = json.loads(await page.evaluate("() => document.body.innerText"))
        got = seen.get("headers", {})
        # mitmproxy normalises to Title-Case; compare case-insensitively
        lowered = {k.lower(): v for k, v in got.items()}
        missing = [k for k in headers if k.lower() not in lowered]
        shot = make_out_dir(args.out) / "check.png"
        await session.take_screenshot(path=str(shot))
        print(json.dumps({
            "start_url_ok": True, "echo_url": echo_url,
            "research_header_seen": not missing, "missing": missing,
            "via_proxy": not args.no_proxy, "screenshot": str(shot),
        }, indent=1))
        return EXIT_OK if not missing else EXIT_ERROR
    finally:
        try:
            await session.stop()
        finally:
            srv.shutdown()


# ---------------------------------------------------------------- agent mode

async def run_agent(args, task: str, allow: set[str], headers: dict[str, str],
                   creds: dict[str, str], out: Path) -> int:
    if not _agent_wire_policy_available():
        return _wire_policy_unavailable()
    from browser_use import Agent, BrowserSession
    from browser_use.browser.profile import ProxySettings

    if not args.model:
        print("refusing: --model or $CCO_AGENT_MODEL is required (no spend without explicit choice).",
              file=sys.stderr)
        return EXIT_ERROR

    state = {"stop": False, "reason": "", "steps": []}
    steps_log = (out / "steps.jsonl").open("w", encoding="utf-8")

    async def new_step(state_summary, _agent_output, step: int) -> None:
        # Fires after the LLM call, before actions run. Re-arm every step:
        # headers are per focus target, so this also covers new tabs.
        if headers and not await arm_header_injection(session, headers):
            state.update(stop=True, reason="header injection not armed; refusing headerless traffic")
            return
        url = getattr(state_summary, "url", "") or ""
        title = getattr(state_summary, "title", "") or ""
        host = host_of(url)
        rec = {"step": step, "url": url, "title": title[:160]}
        state["steps"].append(rec)
        steps_log.write(json.dumps(rec) + "\n")
        steps_log.flush()
        print(f"[step {step}] {host} :: {title[:100]}", flush=True)
        if host and (not in_allowlist(host, allow) or not central_scope_permits(url)):
            state.update(stop=True, reason=f"off-allowlist navigation: {host}")
            return
        if CAPTCHA_PAT.search(url) or CAPTCHA_PAT.search(title):
            state.update(stop=True, reason=f"captcha/wall suspected: {title[:120]}")

    async def should_stop() -> bool:
        return state["stop"]

    proxy = None if args.no_proxy else ProxySettings(server=args.proxy)
    session = BrowserSession(
        headless=not args.headed,
        proxy=proxy,
        headers=headers,
        # LOOPBACK: lab runs + OAuth redirect callbacks (127.0.0.1:port).
        # Every visited host is still logged in steps.jsonl/run.json.
        allowed_domains=sorted(allow | LOOPBACK),
        storage_state=str(args.storage_state) if args.storage_state else None,
        minimum_wait_page_load_time=0.5,
        wait_between_actions=0.4,
        **launch_hardening(),
    )
    agent = Agent(
        task=f"Start at {args.start_url}.\n\n{task}",
        llm=build_llm(args.model),
        browser_session=session,
        sensitive_data=creds or None,
        register_new_step_callback=new_step,
        register_should_stop_callback=should_stop,
        max_actions_per_step=args.max_actions_per_step,
        use_vision=True,
        save_conversation_path=str(out / "conversation.json"),
    )
    history = None
    session_cookies: list[dict] = []
    tpath = _traffic_log_path()
    traffic_offset = tpath.stat().st_size if tpath.is_file() else 0
    try:
        history = await agent.run(max_steps=args.max_steps)
    except Exception as e:  # browser-use raises on blocked domains etc; audit anyway
        state["reason"] = state["reason"] or f"agent exception: {type(e).__name__}: {e}"
        print(f"agent stopped: {e}", file=sys.stderr)
    finally:
        steps_log.close()
        try:
            session_cookies = await _extract_session_cookies(session)
        except Exception:
            session_cookies = []
        try:
            if state["reason"]:
                await session.take_screenshot(path=str(out / "stop.png"))
            if history is not None:
                (out / "history.json").write_text(history.json(indent=1))
        except Exception as e:
            print(f"evidence save failed: {e}", file=sys.stderr)
        try:
            await session.stop()
        except Exception:
            pass

    harvest = {}
    try:
        harvest = harvest_agent_run(
            session_cookies,
            args.start_url,
            state["steps"],
            headers,
            out,
            traffic_offset=traffic_offset,
            allow=allow,
        )
    except Exception as e:
        print(f"post-run harvest warning: {e}", file=sys.stderr)

    violations = [s for s in state["steps"]
                  if (h := host_of(s["url"])) and
                  (not in_allowlist(h, allow) or not central_scope_permits(s["url"]))]
    run = {
        "task_hint": task[:200], "start_url": args.start_url,
        "allowlist": sorted(allow), "max_steps": args.max_steps,
        "model": args.model, "steps_taken": len(state["steps"]),
        "visited_hosts": sorted({host_of(s["url"]) for s in state["steps"] if host_of(s["url"])}),
        "stop_reason": state["reason"], "violations": violations,
        "final_result": (history.final_result() if history else None),
        **harvest,
    }
    (out / "run.json").write_text(json.dumps(run, indent=1))
    print(json.dumps({k: run[k] for k in ("steps_taken", "visited_hosts", "stop_reason")}, indent=1))

    if violations:
        print(f"POLICY VIOLATION: {violations}", file=sys.stderr)
        return EXIT_ERROR
    if not state["steps"] or (history is not None and history.final_result() is None
                              and not state["reason"]):
        print("agent produced no usable result (LLM error or zero steps); see evidence dir.",
              file=sys.stderr)
        return EXIT_ERROR
    if state["reason"] and ("captcha" in state["reason"].lower() or "wall" in state["reason"].lower()):
        print(f"HUMAN_NEEDED: {state['reason']} (see {out / 'stop.png'})")
        return EXIT_HUMAN
    if state["reason"]:
        print(f"stopped: {state['reason']}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def main() -> int:
    args = build_parser().parse_args()
    allow = parse_allowlist(args.allowlist)
    extra = {d.strip().lower().lstrip(".") for d in args.extra_domains.split(",") if d.strip()}
    if extra:
        print(f"note: extra (non-scope) domains explicitly allowed by operator: {sorted(extra)}")
    allow |= extra

    start_host = host_of(args.start_url)
    if not start_host:
        print("refusing: bad --start-url", file=sys.stderr)
        return EXIT_ERROR
    if start_host not in LOOPBACK and not allow:
        print("refusing: empty allowlist and no scope file; pass --allowlist.", file=sys.stderr)
        return EXIT_ERROR
    if not in_allowlist(start_host, allow):
        print(f"refusing: start host {start_host} not in allowlist {sorted(allow)}", file=sys.stderr)
        return EXIT_ERROR
    if not central_scope_permits(args.start_url):
        print("refusing: start URL is outside the active central scope", file=sys.stderr)
        return EXIT_ERROR
    if not _agent_wire_policy_available():
        return _wire_policy_unavailable()
    if args.no_proxy and start_host not in LOOPBACK:
        print("refusing: --no-proxy is restricted to an explicitly scoped loopback lab", file=sys.stderr)
        return EXIT_ERROR

    if args.storage_state:
        if not args.storage_state.exists():
            print(f"refusing: storage file missing: {args.storage_state}", file=sys.stderr)
            return EXIT_ERROR
        check_perms(args.storage_state, "storage file", strict=False)
    if args.creds and not args.creds.exists():
        print(f"refusing: creds file missing: {args.creds}", file=sys.stderr)
        return EXIT_ERROR

    if not args.no_proxy and not proxy_reachable(args.proxy):
        print(f"refusing: scope proxy unreachable: {args.proxy} (start mitmdump or pass --no-proxy for lab)",
              file=sys.stderr)
        return EXIT_ERROR

    headers: dict[str, str] = {}
    if args.handle:
        headers["X-HackerOne-Research"] = args.handle
    for h in args.header:
        if ":" not in h:
            print(f"refusing: bad --header (want 'Name: value'): {h}", file=sys.stderr)
            return EXIT_ERROR
        name, val = h.split(":", 1)
        headers[name.strip()] = val.strip()
    if start_host not in LOOPBACK and not headers:
        print("refusing: research identity required for non-loopback targets (--handle / --header).",
              file=sys.stderr)
        return EXIT_ERROR

    task = resolve_task(args)
    if not task:
        print("refusing: empty task", file=sys.stderr)
        return EXIT_ERROR
    creds = load_creds(args.creds, task)

    if args.check:
        return asyncio.run(run_check(args, allow, headers))
    out = make_out_dir(args.out)
    print(f"evidence: {out}")
    return asyncio.run(run_agent(args, task, allow, headers, creds, out))


if __name__ == "__main__":
    raise SystemExit(main())
