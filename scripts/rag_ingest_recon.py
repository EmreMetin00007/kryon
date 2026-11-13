#!/usr/bin/env python3
"""Recon JSON ciktiyi RAG'e tasi: ham dosya okuma yerine rag_search.

Kullanim:
  python3 scripts/rag_ingest_recon.py [recon/vdp-fiserv] [--ingest|--no-ingest]

Ne yapar:
  1. recon/<prog>/*.json dos Requirementslarini kompakt .txt ozetlere cevirir
     (staging: /root/.cco/rag_staging/<prog>/, repo disi).
  2. --ingest ile rag_bulk_ingest(source='directory') cagirir (varsayilan acik).
     Embedding lokal (chromadb-default/all-MiniLM-L6-v2, ONNX) -> sifir API maliyeti.

Sonrasi: worker `rag_search` ile "hangi hostta keycloak var" diye sorar,
14 MB JSON'u context'e gommez. Idempotent: ayni source_key uzerine yazar.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
STAGING_ROOT = Path(os.environ.get("CCO_RAG_STAGING", "/root/.cco/rag_staging"))
MAX_TXT_BYTES = 200_000  # ingest limiti 250KB altinda tut
MAX_ITEMS_PER_FILE = 6000  # satir basi 1 kayit dosyalari icin

# Tek satirlik ozette tutulacak alanlar (sirali dene)
URL_KEYS = ("url", "input", "host", "hostname", "target", "domain")
STATUS_KEYS = ("status-code", "status_code", "status", "code")
TITLE_KEYS = ("title", "page_title")
EXTRA_KEYS = ("technologies", "tech", "webserver", "ip", "port", "scheme",
              "content-length", "content_length", "final-url", "redirectlocation")


def flatten_item(item):
    """Bir kaydi tek satirlik metne indir."""
    if isinstance(item, str):
        return item[:300]
    if not isinstance(item, dict):
        return json.dumps(item, ensure_ascii=False)[:300]
    parts = []
    for keys, label in ((URL_KEYS, ""), (STATUS_KEYS, "status"),
                        (TITLE_KEYS, "title")):
        for k in keys:
            if item.get(k) not in (None, "", []):
                v = item[k]
                parts.append(f"{v}" if not label else f"{label}={v}")
                break
    for k in EXTRA_KEYS:
        v = item.get(k)
        if v in (None, "", []):
            continue
        if isinstance(v, list):
            v = ",".join(str(x) for x in v[:8])
        parts.append(f"{k}={v}")
    # Bilinmeyen ama kisa skalar alanlari da ekle (kesif sinyali kaybolmasin)
    known = set(URL_KEYS) | set(STATUS_KEYS) | set(TITLE_KEYS) | set(EXTRA_KEYS)
    for k, v in item.items():
        if k in known or v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            continue
        parts.append(f"{k}={str(v)[:80]}")
    return " | ".join(parts)[:500]


def convert_json(path: Path) -> str:
    """JSON dosyayi kompakt txt'ye cevir."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"KAYNAK: {path.name}\nOKUMA HATASI: {exc}\n"
    lines = [f"KAYNAK: {path.name}",
             f"PROGRAM-DIZIN: {path.parent.name}",
             ""]
    items = data if isinstance(data, list) else data.get("results", data.get("items", [data])) \
        if isinstance(data, dict) else [data]
    if not isinstance(items, list):
        items = [items]
    total = len(items)
    lines.append(f"KAYIT SAYISI: {total}" + (f" (ilk {MAX_ITEMS_PER_FILE} alindi)" if total > MAX_ITEMS_PER_FILE else ""))
    lines.append("")
    for item in items[:MAX_ITEMS_PER_FILE]:
        lines.append(flatten_item(item))
    text = "\n".join(lines) + "\n"
    if len(text.encode("utf-8")) > MAX_TXT_BYTES:
        raw = text.encode("utf-8")[:MAX_TXT_BYTES].decode("utf-8", errors="ignore")
        text = raw + "\n...[BOYUT BUDCESI: dosya kesildi]...\n"
    return text


def stage(prog_dir: Path, staging: Path) -> int:
    staging.mkdir(parents=True, exist_ok=True)
    count = 0
    for src in sorted(prog_dir.glob("*.json")):
        txt = convert_json(src)
        (staging / (src.stem + ".txt")).write_text(txt, encoding="utf-8")
        count += 1
    (staging / "_MANIFEST.txt").write_text(
        f"program-dir: {prog_dir}\nstaged: {datetime.now(timezone.utc).isoformat()}\n"
        f"files: {count}\nKullanim: rag_search ile sorgula, ham JSON okuma.\n",
        encoding="utf-8",
    )
    return count


def ingest(staging: Path) -> str:
    sys.path.insert(0, str(REPO / "mcp-servers" / "mcp-rag-engine"))
    import server  # noqa: E402
    out = server.rag_bulk_ingest(source="directory", path=str(staging))
    try:
        out += "\n" + server.rag_stats()
    except Exception:
        pass
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Recon JSON -> RAG staging + ingest")
    ap.add_argument("prog_dir", nargs="?", default="recon/vdp-fiserv")
    ap.add_argument("--staging", default="")
    ap.add_argument("--ingest", dest="ingest", action="store_true", default=True)
    ap.add_argument("--no-ingest", dest="ingest", action="store_false")
    args = ap.parse_args()
    prog_dir = (REPO / args.prog_dir).resolve()
    if not prog_dir.is_dir():
        print(f"HATA: dizin yok: {prog_dir}")
        return 2
    staging = Path(args.staging) if args.staging else STAGING_ROOT / prog_dir.name
    n = stage(prog_dir, staging)
    print(f"staging: {n} dosya -> {staging}")
    if args.ingest:
        print(ingest(staging))
    else:
        print("ingest atlandi (--no-ingest). Worker sunu kosabilir:")
        print(f"  rag_bulk_ingest(source='directory', path='{staging}')")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
