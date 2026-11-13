"""Locate runtime assets in a source checkout or an installed wheel."""
from pathlib import Path
import sys


def runtime_root() -> Path:
    source = Path(__file__).resolve().parents[1]
    if (source / "pyproject.toml").is_file() and (source / "mcp-servers").is_dir():
        return source
    installed = Path(sys.prefix) / "share" / "hackagent"
    if (installed / "pyproject.toml").is_file() and (installed / "mcp-servers").is_dir():
        return installed
    return source
