#!/usr/bin/env python3
"""SPA kapsama doğrulaması: izole keşif koşusu + operatör tarafında puanlama.

Keşif süreci doğruluk listesini görmez; puanlama yalnız bu dosyada yapılır.
Kullanım: python3 scripts/spa-validate.py [--report dosya.json]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "lab"))
import spa_lab  # noqa: E402


def _isolated_env(home: str) -> dict:
    env = dict(os.environ)
    env["CCO_HOME"] = home
    env["CCO_GRAPH_BACKEND"] = "networkx"
    scope_p = os.path.join(home, "lab-scope.json")
    policy_p = os.path.join(home, "lab-policy.json")
    with open(scope_p, "w", encoding="utf-8") as fh:
        json.dump({"allow_loopback": True, "allow_public_labs": True,
                   "rules": {}}, fh)
    try:
        with open(os.path.join(REPO, "config", "program-profiles",
                               "lab.json"), encoding="utf-8") as fh:
            policy = json.load(fh)
    except (OSError, ValueError):
        policy = {}
    policy["rate_limits"] = {
        "default": {"window_seconds": 60, "max_calls": 600},
        "conservative": {"window_seconds": 60, "max_calls": 600}}
    with open(policy_p, "w", encoding="utf-8") as fh:
        json.dump(policy, fh)
    env["CCO_SCOPE_FILE"] = scope_p
    env["CCO_PROGRAM_POLICY_FILE"] = policy_p
    env["CCO_STUCK_THRESHOLD"] = "10000"
    for key in ("OPENROUTER_API_KEY", "ANTHROPIC_AUTH_TOKEN", "DEEPSEEK_API_KEY"):
        env.pop(key, None)
    return env


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="")
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()
    server = spa_lab.serve(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    home = tempfile.mkdtemp(prefix="cco_spa_")
    out_path = os.path.join(home, "discover-out.json")
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, "scripts", "lab",
                                          "spa_discover_run.py"),
             "--base", base, "--out", out_path],
            env=_isolated_env(home), capture_output=True, text=True,
            timeout=args.timeout)
        if proc.returncode != 0:
            print(json.dumps({"error": "discover runner failed",
                              "stderr": proc.stderr[-2000:]}))
            return 1
        with open(out_path, encoding="utf-8") as fh:
            payload = json.load(fh)
    finally:
        server.shutdown()
    result = spa_lab.score_surface(spa_lab.build_truth(), payload["rows"])
    result["discover"] = {
        "ingested": payload["report"].get("ingested"),
        "sources": payload["report"].get("sources"),
        "stop_reason": payload["report"].get("stop_reason", ""),
        "errors": payload["report"].get("errors", [])[:5],
    }
    print(json.dumps(result, indent=1, ensure_ascii=False))
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=1, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
