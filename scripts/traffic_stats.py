#!/usr/bin/env python3
"""Trafik ozet API: ham scope-traffic.jsonl OKUNMADAN host sayaclarini sorgular.

Kaynak: /root/.cco/scope-host-stats.json (proxy akarken artirimli yazar).
Kullanim:
  traffic_stats.py summary            # toplam host/istek + kod dagilimi
  traffic_stats.py top [N]            # en cok istek alan N host (varsayilan 20)
  traffic_stats.py host <name>        # tek host detayi
  traffic_stats.py host <name> --routes  # + o hostun gozlenen yollari (routes dosyasindan)
"""
import json
import sys
from collections import Counter
from pathlib import Path

CCO = Path("/root/.cco")
HOSTSTATS = CCO / "scope-host-stats.json"
ROUTES = CCO / "scope-routes-live.json"


def load(p):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def main(argv):
    stats = load(HOSTSTATS)
    cmd = argv[0] if argv else "summary"
    if cmd == "summary":
        codes: Counter = Counter()
        total = 0
        for v in stats.values():
            total += v.get("n", 0)
            codes.update(v.get("codes", {}))
        print(json.dumps({"hosts": len(stats), "requests": total,
                          "codes": dict(codes.most_common())}, indent=1))
    elif cmd == "top":
        n = int(argv[1]) if len(argv) > 1 else 20
        rows = sorted(stats.items(), key=lambda kv: -kv[1].get("n", 0))[:n]
        for h, v in rows:
            print(f"{v.get('n', 0):6d} {h} {v.get('codes', {})} last={v.get('last', '')}")
    elif cmd == "host":
        if len(argv) < 2:
            print("kullanim: traffic_stats.py host <name>", file=sys.stderr)
            return 2
        h = argv[1].strip().lower()
        v = stats.get(h)
        if v is None:
            print(json.dumps({"host": h, "requests": 0, "note": "sayac yok (istek gormedi ya da scope disi)"}))
            return 0
        out = {"host": h, **v}
        if "--routes" in argv:
            routes = load(ROUTES)
            out["note_routes_global"] = "routes dosyasi host bazinda degil, tum scope'un birlesik envanteri"
            out["routes_observed"] = len(routes)
        print(json.dumps(out, indent=1))
    else:
        print("kullanim: traffic_stats.py {summary|top [N]|host <name> [--routes]}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
