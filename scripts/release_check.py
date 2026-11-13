#!/usr/bin/env python3
"""Run the repository release quality gate."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path
try:
    from .runtime_paths import runtime_root
except ImportError:
    from runtime_paths import runtime_root


REPO_ROOT = runtime_root()


def _quality_gate() -> list[str]:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return list(data.get("tool", {}).get("cco", {}).get("quality_gate", []))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run CCO release quality gates")
    parser.add_argument("--list", action="store_true", help="print configured gates and exit")
    args = parser.parse_args(argv)
    gates = _quality_gate()
    if args.list:
        for gate in gates:
            print(gate)
        return 0
    for gate in gates:
        print(f"[release-check] {gate}")
        result = subprocess.run(gate, cwd=REPO_ROOT, shell=True, text=True)
        if result.returncode != 0:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
