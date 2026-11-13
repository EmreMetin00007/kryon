#!/usr/bin/env python3
"""Worker görev şeması: eksik prompt fail-fast ile reddedilir.

Brainstorm (veya swarm) bir worker'a iş vermeden önce görevi bu şemayla kurar;
`validate_task_spec` eksik alanı çalışmadan raporlar. Amaç: kör prompt yüzünden
boşa yanan batch ve uydurma sonuçların önüne geçmek.
"""

from __future__ import annotations


REQUIRED_FIELDS = ("target", "objective", "commands", "evidence_dir", "scope_ref", "output_format")

OPTIONAL_FIELDS = ("identities", "budget_requests", "kinds", "notes")


def validate_task_spec(spec: dict) -> dict:
    """Görev şemasını doğrula. Dönüş: {"valid", "missing", "errors"}."""
    if not isinstance(spec, dict):
        return {"valid": False, "missing": list(REQUIRED_FIELDS),
                "errors": ["spec dict olmalı"]}
    missing = [f for f in REQUIRED_FIELDS if not str(spec.get(f) or "").strip()]
    errors = []
    if missing:
        errors.append(f"eksik alanlar: {', '.join(missing)}")
    commands = spec.get("commands")
    if commands is not None and (not isinstance(commands, list) or not commands
                                 or any(not isinstance(c, str) or not c.strip() for c in commands)):
        errors.append("commands boş olmayan string listesi olmalı")
    budget = spec.get("budget_requests")
    if budget is not None:
        try:
            if int(budget) < 1:
                errors.append("budget_requests >= 1 olmalı")
        except (TypeError, ValueError):
            errors.append("budget_requests tamsayı olmalı")
    kinds = spec.get("kinds")
    if kinds is not None and (not isinstance(kinds, list) or
                              any(not isinstance(k, str) or not k.strip() for k in kinds)):
        errors.append("kinds string listesi olmalı")
    return {"valid": not missing and not errors, "missing": missing, "errors": errors}


def build_worker_prompt(spec: dict) -> str:
    """Şemadan eksiksiz worker promptu üret (geçersizse ValueError)."""
    check = validate_task_spec(spec)
    if not check["valid"]:
        raise ValueError(f"geçersiz task_spec: {'; '.join(check['errors'])}")
    lines = [
        f"HEDEF: {spec['target']}",
        f"KAPSAM: {spec['scope_ref']}",
        f"AMAÇ: {spec['objective']}",
        "KOMUTLAR (sırayla, aynen çalıştır; yeni fikir üretme):",
        *[f"  - {c}" for c in spec["commands"]],
        f"KANIT DİZİNİ: {spec['evidence_dir']} (ham çıktı buraya, sohbete değil)",
    ]
    if spec.get("identities"):
        lines.append(f"KİMLİKLER: {spec['identities']}")
    if spec.get("budget_requests"):
        lines.append(f"İSTEK BÜTÇESİ: en fazla {spec['budget_requests']} istek")
    if spec.get("notes"):
        lines.append(f"NOTLAR: {spec['notes']}")
    lines.append(f"ÇIKTI FORMATI: {spec['output_format']}")
    return "\n".join(lines)


def partition_kinds(kinds: list[str], workers: int) -> list[list[str]]:
    """Kind listesini worker'lara round-robin böl (çakışmasız paralel iddia)."""
    n = max(1, int(workers))
    parts: list[list[str]] = [[] for _ in range(n)]
    for i, kind in enumerate(kinds or []):
        parts[i % n].append(kind)
    return parts
