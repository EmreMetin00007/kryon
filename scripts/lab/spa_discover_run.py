#!/usr/bin/env python3
"""SPA keşif koşucusu: discover_web_surface çalıştırır, yüzey satırlarını yazar.

Doğruluk listesi bu sürece verilmez; yalnız hedef adres ve çıktı dosyası alır.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for rel in ("mcp-servers/mcp-memory-server", "mcp-servers/mcp-kali-tools",
            "mcp-servers/mcp-validator", "mcp-servers/mcp-hunter"):
    path = os.path.join(REPO, rel)
    if path not in sys.path:
        sys.path.insert(0, path)
sys.path.insert(0, os.path.join(REPO, "tests"))
os.chdir(REPO)

from conftest import load_server  # noqa: E402
from cco_surface_core.store import memory_db_path, query_surface  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    kali = load_server("kali-tools")
    report = json.loads(kali.discover_web_surface(
        args.base, mode="active", probe_limit=32))
    rows = query_surface(args.base, limit=200, db_path=memory_db_path())
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"report": report, "rows": rows}, fh)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
