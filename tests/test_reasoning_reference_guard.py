"""Drift guard: reasoning/hunter core'daki her sembolik referans canlı karşılığa
çözülmelidir. Kırık bir `mcp__sunucu__alet` adı ya da diskte olmayan bir skill,
modeli ölü bir yola sokar (kör turda sessiz ıskalama).

Kapsar:
  1. `mcp__<server>__<tool>` literalleri -> mcp-servers/mcp-<server>/server.py içinde
     `def <tool>` olarak mevcut olmalı.
  2. SKILL_SIGNALS anahtarları + FINDING_SKILL değerleri ->
     .claude/skills/<ad>/SKILL.md diskte olmalı.
  3. Önerilen trigger `/<ad>` aynı dizine çözülmeli.
"""
from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
CORE_DIRS = [
    REPO / "mcp-servers" / "mcp-reasoning" / "cco_reasoning_core",
    REPO / "mcp-servers" / "mcp-hunter" / "cco_hunter_core",
]
SKILLS_DIR = REPO / ".claude" / "skills"

sys.path.insert(0, str(REPO / "mcp-servers" / "mcp-reasoning"))

TOOL_REF_RE = re.compile(r"mcp__([a-z][a-z0-9-]*)__([a-z_0-9]+)")


def _live_tools(server: str) -> set[str]:
    srv = REPO / "mcp-servers" / f"mcp-{server}" / "server.py"
    assert srv.exists(), f"bilinmeyen sunucu dizini: mcp-{server}"
    names = set(re.findall(r"^def ([a-z_0-9]+)\(", srv.read_text(), re.M))
    assert names, f"{srv} içinde hiç tool tanımı yok"
    return names


def _core_texts() -> str:
    chunks = []
    for d in CORE_DIRS:
        assert d.is_dir(), f"core dizin yok: {d}"
        for py in sorted(d.glob("*.py")):
            chunks.append(py.read_text())
    return "\n".join(chunks)


def test_mcp_tool_references_resolve_live():
    text = _core_texts()
    refs = sorted(set(TOOL_REF_RE.findall(text)))
    assert refs, "core içinde hiç mcp__ referansı yok — regex mi eskidi?"
    broken = []
    cache: dict[str, set[str]] = {}
    for server, tool in refs:
        live = cache.setdefault(server, _live_tools(server))
        if tool not in live:
            broken.append(f"mcp__{server}__{tool}")
    assert not broken, f"ölü tool referansları: {broken}"


def test_skill_references_exist_on_disk():
    from cco_reasoning_core.router_data import FINDING_SKILL, SKILL_SIGNALS

    names = set(SKILL_SIGNALS) | set(FINDING_SKILL.values())
    assert names, "router tabloları boş"
    missing = [n for n in sorted(names) if not (SKILLS_DIR / n / "SKILL.md").exists()]
    assert not missing, f"diskte SKILL.md olmayan skill referansları: {missing}"


def test_skill_triggers_resolve_to_disk():
    from cco_reasoning_core.router_data import SKILL_SIGNALS

    broken = []
    for skill, (_signals, trigger) in SKILL_SIGNALS.items():
        slug = (trigger or "").strip().lstrip("/").split()[0]
        if not slug or not (SKILLS_DIR / slug / "SKILL.md").exists():
            broken.append(f"{skill} -> {trigger!r}")
    assert not broken, f"ölü skill trigger'ları: {broken}"
