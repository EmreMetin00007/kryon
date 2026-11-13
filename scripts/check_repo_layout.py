#!/usr/bin/env python3
"""Kök dizinde çalışma verisi birikmesini engelleyen düzen denetimi.

Kod bu repoda yaşar; engagement çalışma verisi CCO_WORKDIR (varsayılan
~/cco-work) altında tutulur. Bu denetim, yasak desenlerden biri repo
kökünde belirirse kalite kapısını kırmızıya çevirir.

Kullanım: python3 scripts/check_repo_layout.py [--root .]
Çıkış kodu: 0 temiz, 1 ihlal var.
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path

FORBIDDEN = [
    "recon",
    "evidence",
    "reports",
    "targets",
    "labs",
    "lab-*",
    "lab2-*",
    "faz*",
    "anduril",
    "shop.tw.coupang.com",
    "anf-*.md",
    "*-bb",
    "codex-session-*.md",
    ".worker",
    ".tmp_*",
    "skills~*",
]


def violations(root: Path) -> list[str]:
    found = []
    for entry in sorted(root.iterdir()):
        if entry.name == ".git":
            continue
        for pattern in FORBIDDEN:
            if fnmatch.fnmatch(entry.name, pattern):
                found.append(entry.name)
                break
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="denetlenecek repo kökü")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    found = violations(root)
    if found:
        print("Repo kökünde çalışma verisi bulundu (CCO_WORKDIR altına taşıyın):")
        for name in found:
            print(f"  - {name}")
        return 1
    print("Repo düzeni temiz: kökte çalışma verisi yok.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
