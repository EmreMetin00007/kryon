"""Test-only archived loader for historical native compatibility assets."""
from __future__ import annotations

from pathlib import Path
import re
import shutil
from typing import Callable

ARCHIVE_ROOT = Path(__file__).resolve().parent
NATIVE_AGENT_FILES = (
    ".opencode/agents/kalibounty.md",
    ".opencode/agents/worker.md",
)


def _validated_archive_file(root: Path, relative: str) -> Path:
    """Resolve one archived compat file strictly inside root without symlinks."""
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"invalid archived fixture path: {relative}")
    candidate = root / rel
    if not candidate.exists() and not candidate.is_symlink():
        raise FileNotFoundError(f"archived native compat fixture missing: {relative}")
    if candidate.is_symlink():
        raise ValueError(f"archived native compat fixture must not be a symlink: {relative}")
    for parent in candidate.parents:
        if parent == root:
            break
        if root not in parent.parents:
            break
        if parent.is_symlink():
            raise ValueError(f"archived native compat directory must not be a symlink: {parent}")
    resolved = candidate.resolve(strict=True)
    if root.resolve(strict=True) not in resolved.parents:
        raise ValueError(f"archived native compat fixture escapes archive root: {relative}")
    if not candidate.is_file():
        raise ValueError(f"archived native compat fixture must be a regular file: {relative}")
    return candidate


def _validate_agent_frontmatter(path: Path, relative: str) -> None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"invalid native agent frontmatter: {relative}")
    front, sep, _rest = text.removeprefix("---\n").partition("\n---\n")
    if not sep or not re.search(r"(?m)^model:\s*\S+", front):
        raise ValueError(f"invalid native agent frontmatter: {relative}")


def stage_native_compat_assets(
    destination: Path,
    *,
    runtime_file: Callable[[Path], bool] | None = None,
    archive_root: Path = ARCHIVE_ROOT,
) -> list[str]:
    """Copy archived historical native compat agents into a test staging source."""
    destination = Path(destination)
    root = Path(archive_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"invalid native compat archive root: {archive_root}")
    staged: list[str] = []
    for relative in NATIVE_AGENT_FILES:
        source = _validated_archive_file(root, relative)
        _validate_agent_frontmatter(source, relative)
        rel_path = Path(relative)
        if runtime_file is not None and not runtime_file(rel_path):
            raise ValueError(f"archived fixture disallowed by runtime_file: {relative}")
        target = destination / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        staged.append(relative)
    return staged
