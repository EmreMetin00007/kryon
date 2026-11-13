#!/usr/bin/env python3
"""Paralel kampanya worker havuzu (süreç başına izole kanıt dizini).

Her worker ayrı süreçte `campaign_worker.py drain` koşar:
  - Kuyruk, bütçe ve oran limiti aynı SQLite DB'de paylaşılır
    (BEGIN IMMEDIATE + lease ile çakışmasız iddia).
  - Kanıt dizini süreç başına ayrılır: CCO_WORKDIR/pool/w<i>.
  - Kind listesi verilirse worker'lara round-robin bölünür; verilmezse
    hepsi aynı kuyruktan iddia eder (kanıt yolu çakışabilir, önerilmez).

Kullanım:
  python3 scripts/worker_pool.py --campaign-id 28 --workers 4 \\
      --kinds recon,fuzz,chain,validate --max-tasks 10 --mode dry-run
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from task_spec import partition_kinds


def build_worker_env(base_env: dict, workdir: str, index: int) -> dict:
    """Worker sürecinin ortamı: izole kanıt dizini, paylaşılan DB yolu korunur."""
    env = dict(base_env)
    pool_dir = str((Path(workdir).expanduser() / "pool" / f"w{index}").resolve())
    os.makedirs(pool_dir, exist_ok=True)
    env["CCO_WORKDIR"] = pool_dir
    return env


def run_pool(campaign_id: int | None, workers: int, kinds: list[str],
             max_tasks: int, extra_args: list[str],
             base_env: dict | None = None,
             workdir: str | None = None) -> dict:
    """Havuzu koştur, özet döndür. {"workers": [...], "exit_codes": [...] }."""
    requested = max(1, min(int(workers), 8))
    # kinds verildiyse boş filtre = tüm kind'lar demektir; kind sayısından
    # fazla worker spawn'ı bölünmeyi bozar (üst seviye worker'lar her şeyi
    # kapar). Efektif sayıyı kind sayısıyla sınırla.
    n = min(requested, len(kinds)) if kinds else requested
    parts = partition_kinds(kinds, n) if kinds else [[] for _ in range(n)]
    env_base = dict(base_env if base_env is not None else os.environ)
    cco_workdir = workdir or env_base.get("CCO_WORKDIR", "~/cco-work")
    procs = []
    for i in range(n):
        cmd = [sys.executable, str(SCRIPT_DIR / "campaign_worker.py"), "drain",
               "--worker-id", f"pool-w{i}",
               "--max-tasks", str(max_tasks), *extra_args]
        if campaign_id is not None:
            cmd += ["--campaign-id", str(campaign_id)]
        if parts[i]:
            cmd += ["--kinds", ",".join(parts[i])]
        env = build_worker_env(env_base, cco_workdir, i)
        procs.append(subprocess.Popen(cmd, env=env))
    codes = [p.wait() for p in procs]
    return {"workers": n,
            "workers_requested": requested,
            "kinds_per_worker": parts,
            "exit_codes": codes,
            "all_ok": all(c == 0 for c in codes)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Paralel campaign worker havuzu")
    ap.add_argument("--campaign-id", type=int, default=None)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--kinds", default="",
                    help="Virgülle ayrılmış kind listesi (round-robin bölünür)")
    ap.add_argument("--max-tasks", type=int, default=10)
    ap.add_argument("--workdir", default=None,
                    help="CCO_WORKDIR kökü (varsayılan: ortamdaki)")
    ap.add_argument("extra", nargs=argparse.REMAINDER,
                    help="campaign_worker.py drain'e aktarılan ek bayraklar")
    args = ap.parse_args(argv)
    kinds = [k.strip() for k in (args.kinds or "").split(",") if k.strip()]
    extra = [a for a in (args.extra or []) if a != "--"]
    summary = run_pool(args.campaign_id, args.workers, kinds,
                       args.max_tasks, extra, workdir=args.workdir)
    print(f"workers={summary['workers']} exit={summary['exit_codes']} "
          f"kinds={summary['kinds_per_worker']}")
    return 0 if summary["all_ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
