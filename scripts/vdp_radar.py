#!/usr/bin/env python3
"""VDP radari + scope madenci (tamamen pasif, hedefe temas yok).

Kaynak: bounty-targets-data (tum platformlar, saatlik guncel).
- scan: repo'yu gunceller, YENI program / YENI scope diff'ler, aday listeler.
- mine: adayi normalize scope TASLAGI yapar (ASLA aktive etmez — Kapi 1 operatorde).

Ciktilar (repo disi): /root/.cco/radar/{state.json,candidates.json}
Taslak: .codex/scope.<handle>.json (DRAFT, gozden gecmeden kullanilmaz)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path("/root/.cco/bounty-targets-data/data")
DATA_REPO = "https://github.com/arkadiyt/bounty-targets-data"
RADAR_DIR = Path("/root/.cco/radar")
STATE_FILE = RADAR_DIR / "state.json"
CANDIDATES_FILE = RADAR_DIR / "candidates.json"
PLATFORM_FILES = {
    "hackerone": "hackerone_data.json",
    "bugcrowd": "bugcrowd_data.json",
    "intigriti": "intigriti_data.json",
    "yeswehack": "yeswehack_data.json",
    "federacy": "federacy_data.json",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except ValueError:
            pass
    return {"programs": {}}


def _save_state(state: dict) -> None:
    RADAR_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=1, sort_keys=True))


def _scope_hash(assets: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(assets)).encode()).hexdigest()[:16]


def _in_scope_assets(prog: dict) -> tuple[list[dict], list[str]]:
    items = ((prog.get("targets") or {}).get("in_scope") or [])
    eligible = [i for i in items if i.get("eligible_for_submission", True)]
    return eligible, sorted({str(i.get("asset_identifier", "")).strip() for i in eligible if i.get("asset_identifier")})


def _out_of_scope(prog: dict) -> list[str]:
    items = ((prog.get("targets") or {}).get("out_of_scope") or [])
    return sorted({str(i.get("asset_identifier", "")).strip() for i in items if i.get("asset_identifier")})


def _score(prog: dict, assets: list[str]) -> float:
    eff = prog.get("response_efficiency_percentage") or 0
    avg = prog.get("average_time_to_first_program_response")
    wild = sum(1 for a in assets if "*" in a)
    s = float(eff) + min(wild, 10) * 2.0
    if isinstance(avg, (int, float)) and avg > 7:
        s -= 20.0
    if prog.get("submission_state") != "open":
        s -= 100.0
    return s


def cmd_scan(a) -> int:
    if not a.no_pull:
        # URL acik yazilir: gate hedef cikarsin (origin kirak kalirdi).
        r = subprocess.run(["git", "-C", str(DATA_DIR.parent), "pull", "--ff-only", "-q",
                            a.repo],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[radar] git pull hatasi: {r.stderr.strip()[:200]}", flush=True)
            return 1
    state = _load_state()
    known = state.get("programs", {})
    first_run = not known
    candidates: list[dict] = []
    indexed = 0
    for platform, fname in PLATFORM_FILES.items():
        if a.platforms and platform not in a.platforms:
            continue
        f = DATA_DIR / fname
        if not f.exists():
            continue
        try:
            programs = json.loads(f.read_text())
        except ValueError:
            continue
        for prog in programs:
            handle = str(prog.get("handle") or prog.get("name") or "?")
            key = f"{platform}:{handle}"
            _, assets = _in_scope_assets(prog)
            h = _scope_hash(assets)
            indexed += 1
            prev = known.get(key)
            new_assets: list[str] = []
            is_new_prog = prev is None
            if not is_new_prog and prev.get("scope_hash") != h:
                old = set(prev.get("assets", []))
                new_assets = [x for x in assets if x not in old]
            known[key] = {"scope_hash": h, "assets": assets,
                          "first_seen": prev.get("first_seen", _now()) if prev else _now(),
                          "name": str(prog.get("name", ""))}
            if first_run:
                continue
            if not is_new_prog and not new_assets:
                continue
            if a.vdp_only and prog.get("offers_bounties"):
                continue
            candidates.append({
                "key": key, "platform": platform, "handle": handle,
                "name": str(prog.get("name", "")), "url": str(prog.get("url", "")),
                "is_new_program": is_new_prog, "new_assets": new_assets,
                "asset_count": len(assets),
                "offers_bounties": bool(prog.get("offers_bounties")),
                "submission_state": str(prog.get("submission_state", "")),
                "response_efficiency": prog.get("response_efficiency_percentage"),
                "avg_first_response_days": prog.get("average_time_to_first_program_response"),
                "out_of_scope_count": len(_out_of_scope(prog)),
                "score": _score(prog, assets),
            })
    state["programs"] = known
    state["last_scan"] = _now()
    _save_state(state)
    candidates.sort(key=lambda c: (not c["is_new_program"], -c["score"]))
    RADAR_DIR.mkdir(parents=True, exist_ok=True)
    CANDIDATES_FILE.write_text(json.dumps(candidates, indent=1))
    if first_run:
        print(f"[radar] baseline: {indexed} program indekslendi, alarm yok.", flush=True)
        _print_top_vdp()
        return 0
    print(f"[radar] {indexed} program tarandi, {len(candidates)} aday.", flush=True)
    for c in candidates[:20]:
        tag = "YENI-PROGRAM" if c["is_new_program"] else f"+{len(c['new_assets'])} scope"
        vdp = "VDP" if not c["offers_bounties"] else "odullu"
        print(f"[radar] {tag} [{vdp}] {c['key']} ({c['asset_count']} asset) {c['url']}", flush=True)
    return 0


def _print_top_vdp() -> None:
    rows = []
    for platform, fname in PLATFORM_FILES.items():
        f = DATA_DIR / fname
        if not f.exists():
            continue
        try:
            programs = json.loads(f.read_text())
        except ValueError:
            continue
        for prog in programs:
            if prog.get("offers_bounties") or prog.get("submission_state") != "open":
                continue
            _, assets = _in_scope_assets(prog)
            if not assets:
                continue
            rows.append((_score(prog, assets), platform, prog, assets))
    rows.sort(key=lambda r: r[0], reverse=True)
    print("[radar] mevcut en iyi 10 VDP adayi (baslangic secenegi):", flush=True)
    for s, platform, prog, assets in rows[:10]:
        wild = sum(1 for x in assets if "*" in x)
        print(f"[radar]   {platform}:{prog.get('handle')} skor={s:.0f} "
              f"asset={len(assets)} wildcard={wild} {prog.get('url')}", flush=True)


def cmd_mine(a) -> int:
    try:
        platform, handle = a.key.split(":", 1)
    except ValueError:
        print("HATA: key formati platform:handle", flush=True)
        return 2
    fname = PLATFORM_FILES.get(platform)
    if not fname:
        print(f"HATA: platform bilinmiyor: {platform}", flush=True)
        return 2
    f = DATA_DIR / fname
    if not f.exists():
        print("HATA: veri yok, once scan", flush=True)
        return 2
    prog = next((p for p in json.loads(f.read_text())
                 if str(p.get("handle")) == handle), None)
    if not prog:
        print(f"HATA: program yok: {a.key}", flush=True)
        return 2
    eligible, assets = _in_scope_assets(prog)
    oos = _out_of_scope(prog)
    in_scope = [{"asset": x, "type": "web"} for x in assets[:500]]
    draft = {
        "engagement": f"{prog.get('name')} ({platform}, radar taslak {datetime.now(timezone.utc).date()})",
        "declared_by": "vdp_radar (OTOMATIK TASLAK - operator onayi YOK)",
        "status": "DRAFT-NEEDS-OPERATOR-REVIEW",
        "program_url": prog.get("url"),
        "offers_bounties": bool(prog.get("offers_bounties")),
        "submission_state": prog.get("submission_state"),
        "in_scope": in_scope,
        "targets": assets[:500],
        "out_of_scope": oos[:200],
        "rules": {
            "passive_first": True,
            "max_rps": 1,
            "pii_exfiltration": False,
            "dos_testing": False,
            "social_engineering": False,
            "test_identity_only": True,
            "human_verification_before_report": True,
            "destructive_prohibited": ["DELETE", "DROP", "TRUNCATE", "DoS",
                                       "brute_force_unbounded", "real_user_data_exfil"],
            "notes": [
                "RADAR TASLAGI: program politika sayfasi operator tarafindan okunmali.",
                "Rate limit / yasak testler program sayfasindan teyit edilmeli.",
                "Aktive etmek icin: icerigi gozden gecir, scope.<handle>.json yap, grant ver.",
            ],
        },
    }
    out = Path(f".codex/scope.{handle}.json.DRAFT")
    out.write_text(json.dumps(draft, indent=1))
    print(f"[radar] taslak yazildi: {out} (AKTIVE DEGIL)", flush=True)
    avg = prog.get("average_time_to_first_program_response")
    avg_txt = f"{avg}gun" if isinstance(avg, (int, float)) else "bilinmiyor"
    print(f"[radar] KAPI-1 ozet: {prog.get('name')} | asset={len(assets)} "
          f"oos={len(oos)} | odul={'evet' if prog.get('offers_bounties') else 'VDP'} | "
          f"yanit-hizi={avg_txt}", flush=True)
    print(f"[radar] program sayfasi: {prog.get('url')}", flush=True)
    print("[radar] siradaki: sayfayi oku -> .DRAFT'i onayla scope.<handle>.json yap -> grant ver", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--no-pull", action="store_true")
    s.add_argument("--platforms", nargs="*", default=[])
    s.add_argument("--vdp-only", action="store_true")
    s.add_argument("--repo", default=DATA_REPO,
                   help="Veri repo URL'si (gate gorunurlugu icin acik yazilir)")
    m = sub.add_parser("mine")
    m.add_argument("key", help="platform:handle (ornek hackerone:ornek_vdp)")
    a = ap.parse_args()
    if a.cmd == "scan":
        return cmd_scan(a)
    return cmd_mine(a)


if __name__ == "__main__":
    raise SystemExit(main())
