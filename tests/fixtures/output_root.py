"""Fixture artifacts honor caller-owned workflow roots, never a fixed /tmp path."""
import os
from pathlib import Path
import tempfile


def output_root(name: str) -> Path:
    base = os.environ.get("CCO_WORKDIR") or os.environ.get("TMPDIR") or tempfile.gettempdir()
    return Path(base).expanduser().resolve() / name
