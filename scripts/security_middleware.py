#!/usr/bin/env python3
"""Backward-compatible wrapper around the central policy gate CLI."""

from policy_gate_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
