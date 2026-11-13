#!/usr/bin/env python3
"""Negatif-kontrol benchmark (Faz 7): sertlestirilmis yuzeyde FP olcumu.

vuln_lab'in /safe/* ikizlerine validator + authz oracle bataryasi kosar;
CONFIRMED = false-positive. Cikis: fp_rate. Pozitif kontrol (48/48 lab)
yaninda bu, iskeletin yanlis alarm oranini olcer.

Kullanim: python3 scripts/negative-control.py [--rounds 2] [--json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(alias: str, path: str):
    spec = importlib.util.spec_from_file_location(alias, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    return mod


def _verdict(raw) -> str:
    try:
        data = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception:
        return "ERROR"
    if not isinstance(data, dict):
        return "ERROR"
    return str(data.get("verdict") or "ERROR").strip().upper()


def summarize_checks(checks: list[dict]) -> dict:
    """Only a nonempty set of definitive safe verdicts passes the battery."""
    verdicts = [str(item.get("verdict") or "ERROR").strip().upper() for item in checks]
    false_positives = sum(verdict == "CONFIRMED" for verdict in verdicts)
    unresolved = sum(verdict not in {"CONFIRMED", "UNCONFIRMED"} for verdict in verdicts)
    return {
        "total": len(checks),
        "false_positives": false_positives,
        "unresolved": unresolved,
        "fp_rate": round(false_positives / len(checks), 4) if checks else 0.0,
        "passed": bool(checks) and false_positives == 0 and unresolved == 0,
    }


def run_battery(rounds: int = 2) -> dict:
    os.environ.setdefault("CCO_HOME", tempfile.mkdtemp(prefix="cco_neg_"))
    lab = _load("neg_vuln_lab", os.path.join(REPO, "scripts", "lab", "vuln_lab.py"))
    sys.path.insert(0, os.path.join(REPO, "mcp-servers", "mcp-validator"))
    sys.path.insert(0, os.path.join(REPO, "mcp-servers", "mcp-hunter"))
    validator = _load("neg_validator", os.path.join(REPO, "mcp-servers", "mcp-validator", "server.py"))
    hunter = _load("neg_hunter", os.path.join(REPO, "mcp-servers", "mcp-hunter", "server.py"))

    server = lab.serve(0)
    import threading
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    hdr = lambda tok: json.dumps({"Authorization": f"Bearer {tok}"})  # noqa: E731

    def bola_oracle() -> str:
        import requests
        owner = requests.get(f"{base}/safe/api/orders/1001",
                             headers={"Authorization": "Bearer userA"}, timeout=10)
        attacker = requests.get(f"{base}/safe/api/orders/1001",
                                headers={"Authorization": "Bearer userB"}, timeout=10)
        return _verdict(hunter.analyze_authz_result(json.dumps({
            "test_type": "bola",
            "authorized": {"identity": "userA", "status": owner.status_code, "body": owner.text},
            "attacker": {"identity": "userB", "status": attacker.status_code, "body": attacker.text},
        })))

    checks_spec = [
        ("sqli_safe_item", lambda: _verdict(validator.validate_sqli(f"{base}/safe/item", param="id"))),
        ("xss_safe_search", lambda: _verdict(validator.validate_xss_reflection(f"{base}/safe/search", param="q"))),
        ("idor_safe_orders", lambda: _verdict(validator.validate_idor(
            object_url=f"{base}/safe/api/orders/1001",
            owner_headers_json=hdr("userA"), attacker_headers_json=hdr("userB")))),
        ("auth_bypass_safe_export", lambda: _verdict(validator.validate_auth_bypass(
            protected_url=f"{base}/safe/admin/export", authorized_headers_json=hdr("admin"),
            protected_marker="all-customer-pii"))),
        ("open_redirect_safe_go", lambda: _verdict(validator.validate_open_redirect(
            f"{base}/safe/go", param="next"))),
        ("bola_oracle_safe_orders", bola_oracle),
    ]

    checks: list[dict] = []
    try:
        for rnd in range(max(1, rounds)):
            for name, fn in checks_spec:
                try:
                    verdict = fn()
                except Exception as exc:  # noqa: BLE001
                    verdict = f"ERROR:{type(exc).__name__}"
                checks.append({"round": rnd + 1, "name": name, "verdict": verdict,
                               "false_positive": verdict == "CONFIRMED"})
    finally:
        server.shutdown()
        server.server_close()

    return {
        "battery": "negative-control/safe-twins",
        "checks": checks,
        **summarize_checks(checks),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    out = run_battery(rounds=args.rounds)
    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        for c in out["checks"]:
            mark = "FP!" if c["false_positive"] else "ok" if c["verdict"] == "UNCONFIRMED" else "unresolved"
            print(f"[{mark}] r{c['round']} {c['name']}: {c['verdict']}")
        print(f"fp_rate={out['fp_rate']} ({out['false_positives']}/{out['total']})")
    return 0 if out["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
