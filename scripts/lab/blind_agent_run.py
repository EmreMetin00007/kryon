#!/usr/bin/env python3
"""Kör koşu ajan tarafı: yalnızca base URL + hesap başlıkları alır.

Cevap anahtarı bu sürece hiç verilmez. Çıktı: run_web_loop raporu (JSON).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def benchmark_payload(hunter, loop: dict, target: str, *, surface_inventory: dict | None = None) -> dict:
    """Export current signed coverage while the run's policy context is active.

    Use Hunter's artifact verifier, not loop claims or an unsigned tested flag.
    The scorer receives metadata/evidence references only, never account secrets.
    """
    run_id = loop.get("run_id")
    events = hunter._verified_coverage_events(target) if run_id else []
    payload = {"loop": loop, "verified_coverage": [event for event in events
                                                   if event.get("run_id") == run_id]}
    if surface_inventory is not None and surface_inventory.get("run_id") == run_id:
        payload["surface_inventory"] = surface_inventory
    return payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--identities", required=True,
                    help='JSON {label: {headers}} — yalnız test hesapları')
    ap.add_argument("--out", required=True)
    ap.add_argument("--blind-differential", action="store_true",
                    help="WS4 küme farkı keşfi (operatör beyanlı test kimlikleri)")
    args = ap.parse_args()
    sys.path.insert(0, os.path.join(REPO, "mcp-servers", "mcp-memory-server"))
    hunter = _load("hunter_blind", os.path.join(
        REPO, "mcp-servers", "mcp-hunter", "server.py"))
    from cco_surface_core.store import next_work
    # The parent creates a fresh CCO_HOME. Refuse stale surface state rather
    # than attributing a prior run's inventory to the current discovery.
    if next_work(args.base, limit=1, untested_only=False, db_path=hunter.MEM_DB)["total_surface"]:
        raise ValueError("blind benchmark requires an empty isolated surface inventory")
    # Birincil oturum (member-a) keşif/fuzz başlığı olur; diğer kimlikler
    # yalnız authz karşılaştırması içindir. Kimlikler keşfe taşınmazsa
    # karışık-yetki yüzeyde ilk 401 tüm koşuyu keser.
    try:
        ident_map = json.loads(args.identities)
    except ValueError:
        ident_map = {}
    primary = (ident_map.get("member-a") or {}).get("headers") or {}
    identities_arg = args.identities
    if args.blind_differential:
        # Operatör beyanı: lab hesapları sentetik test kimlikleridir.
        declared = {}
        for label, identity in ident_map.items():
            entry = dict(identity) if isinstance(identity, dict) else {}
            entry.setdefault("role", "member")
            entry["test_data_only"] = True
            declared[label] = entry
        identities_arg = json.dumps(declared)
    loop = json.loads(hunter.run_web_loop(
        args.base, live=True, crawl=False, zap=False,
        headers=json.dumps(primary), identities=identities_arg,
        blind_discovery=bool(args.blind_differential),
        blind_differential=bool(args.blind_differential),
        blind_max_requests=40,
        fuzz_limit=12, max_validations=10, sleep_s=0))
    snapshot = next_work(args.base, limit=10000, untested_only=False, db_path=hunter.MEM_DB)
    inventory = {"run_id": loop.get("run_id"), "source": "isolated_run_surface_snapshot",
                 "complete": snapshot["count"] == snapshot["total_surface"],
                 "records": [{"url": row["url"], "method": row["method"],
                              "operation_id": row.get("operation_id"),
                              "fingerprint": row["fingerprint"], "sources": row["sources"],
                              "params": [{"name": p["name"], "in": p["in"]} for p in row["params"]]}
                             for row in snapshot["queue"]]}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(benchmark_payload(hunter, loop, args.base, surface_inventory=inventory), fh)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
