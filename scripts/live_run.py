#!/usr/bin/env python3
"""Canlı lab koşularının TEK giriş kapısı (ad-hoc /tmp betiği yasak).

Akış: kapsam kapısı (fail-closed) -> kampanya + görev kuyruğu ->
worker_pool ile paralel çalıştırma -> özet.

Kullanım:
  python3 scripts/live_run.py --target https://<lab-host>/ --objective "..." \\
      --kinds recon,fuzz --workers 2 --max-tasks 5 [--campaign-id 7] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from campaign_runtime import CampaignRuntime  # noqa: E402
from policy_engine import ScopeResolver  # noqa: E402
from worker_pool import run_pool  # noqa: E402


def _scope_file() -> Path:
    return Path(os.environ.get("CCO_SCOPE_FILE",
                               str(REPO_ROOT / ".codex" / "scope.json")))


def load_scope_hosts(scope_path: str | Path | None = None) -> set[str]:
    """Kapsamdaki host kümesi (in_scope asset'leri + targets)."""
    p = Path(scope_path or _scope_file())
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"kapsam dosyası okunamadı: {p} ({exc})")
    hosts: set[str] = set()
    items = data.get("in_scope", []) if isinstance(data, dict) else []
    for entry in items:
        asset = entry.get("asset") if isinstance(entry, dict) else entry
        host = (urlparse(str(asset or "")).hostname or "").lower().lstrip(".")
        if host:
            hosts.add(host)
    for t in (data.get("targets") or [] if isinstance(data, dict) else []):
        host = str(t or "").lower().lstrip(".")
        if host and "." in host:
            hosts.add(host)
    return hosts


def gate_target(target: str, scope_path: str | Path | None = None) -> str:
    """Hedef kapsamdaysa host'u döndür, değilse fail-closed reddet."""
    host = (urlparse(target).hostname or "").lower()
    if not host:
        raise SystemExit(f"geçersiz hedef: {target}")
    try:
        allowed = ScopeResolver(scope_file=scope_path or _scope_file(), repo_root=REPO_ROOT).permits_url(target)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(f"kapsam dosyası okunamadı: {type(exc).__name__}") from exc
    if not allowed:
        raise SystemExit(f"KAPSAM DISI — koşu reddedildi: {host}")
    return host


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Kapsam kapılı canlı lab koşusu")
    ap.add_argument("--target", required=True, help="Tam lab URL'si")
    ap.add_argument("--objective", required=True, help="Lab hedefi (tek cümle)")
    ap.add_argument("--kinds", default="recon",
                    help="Virgülle ayrılmış görev kind listesi")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--max-tasks", type=int, default=5)
    ap.add_argument("--campaign-id", type=int, default=None)
    ap.add_argument("--campaign-name", default="live-run")
    ap.add_argument("--dry-run", action="store_true",
                    help="Worker'lar gerçek istek atmaz (yol doğrulama)")
    ap.add_argument("--scope", default=None, help="Kapsam dosyası (varsayılan repo)")
    ap.add_argument("--manifest-file", default=None,
                    help="Zincir manifestosu JSON dosyası (chain_runner_execute görevi kurar)")
    ap.add_argument("--identities-json", default=None,
                    help="Chain identities JSON dosyası (araştırmacı başlıkları vb.)")
    ap.add_argument("extra", nargs=argparse.REMAINDER,
                    help="worker_pool'a aktarılan ek bayraklar (-- sonrası)")
    args = ap.parse_args(argv)

    host = gate_target(args.target, args.scope)
    kinds = [k.strip() for k in (args.kinds or "").split(",") if k.strip()]
    if not kinds:
        raise SystemExit("en az bir kind gerekli (--kinds)")

    manifest = None
    if args.manifest_file:
        try:
            manifest = json.loads(Path(args.manifest_file).read_text(encoding="utf-8"))
        except Exception as exc:
            raise SystemExit(f"manifesto okunamadı: {exc}")
        from action_manifest import validate_manifest
        check = validate_manifest(manifest)
        if not check["valid"]:
            raise SystemExit(f"manifesto geçersiz: {'; '.join(check['errors'][:5])}")
        manifest_hash = str(check.get("manifest_hash") or "m")
    identities = None
    if args.identities_json:
        try:
            identities = json.loads(Path(args.identities_json).read_text(encoding="utf-8"))
        except Exception as exc:
            raise SystemExit(f"identities okunamadı: {exc}")
        if not isinstance(identities, dict):
            raise SystemExit("identities dict olmalı")

    rt = CampaignRuntime()
    cid = args.campaign_id
    if cid is None:
        cid = rt.create_campaign(f"{args.campaign_name}-{host}",
                                 scope_file=str(args.scope or _scope_file()),
                                 budget_requests=0,
                                 notes=args.objective)
    if manifest is not None:
        chain_args: dict = {"manifest": manifest}
        if identities is not None:
            chain_args["identities"] = identities
        ref = str(manifest.get("target_ref") or "").strip()
        if ref:
            chain_args["target_bases"] = {ref: f"{args.target.rstrip('/')}"}
        rt.enqueue_task(cid, "chain", tool_name="chain_runner_execute",
                        args=chain_args,
                        idempotency_key=f"live-{cid}-chain-{manifest_hash}")
        if "chain" not in kinds:
            kinds.append("chain")
    manifest_kinds = {"chain"} if manifest is not None else set()
    for i, kind in enumerate(kinds):
        if kind in manifest_kinds:
            continue  # manifesto görevi zaten kuyrukta; boş yinelenen ekleme
        rt.enqueue_task(cid, kind, tool_name="",
                        args={"target": args.target, "objective": args.objective},
                        idempotency_key=f"live-{cid}-{kind}-{i}")

    extra = ["--mode", "dry-run"] if args.dry_run else []
    extra += [a for a in (args.extra or []) if a != "--"]
    summary = run_pool(cid, args.workers, kinds, args.max_tasks, extra)
    print(f"campaign={cid} host={host} "
          f"workers={summary['workers']}/{summary.get('workers_requested', summary['workers'])} "
          f"exit={summary['exit_codes']} ok={summary['all_ok']}")
    return 0 if summary["all_ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
