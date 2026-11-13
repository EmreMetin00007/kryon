#!/usr/bin/env python3
"""Rapyd dashboard session keeper v2 (tarayıcısız keep-alive).

Mantık: localStorage token'ı `token`+`fingerprint` header'larıyla API'de
kullanıldıkça session canlı kalır. Yeni giriş eski token'ı öldürebilir,
o yüzden keeper tek aktif session olarak tutulur.

Kullanım:
  python3 scripts/rapyd_session_keeper.py set <TOKEN> <FP>  # taze değerleri kaydet
  python3 scripts/rapyd_session_keeper.py check              # tek seferlik canlılık testi
  python3 scripts/rapyd_session_keeper.py daemon             # her 10 dk keep-alive (arka plan)
"""
import json
import sys
import time
import urllib.request
from pathlib import Path

CCO = Path("/root/.cco")
VAULT = CCO / "rapyd-sandbox-keys.json"
CURL_FILE = CCO / "rapyd-dashboard-curl.txt"
TOKEN_URL = "https://dashboard.rapyd.net/v1/merchants-portal/users/login/token"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")


def load() -> tuple[str | None, str | None]:
    if not VAULT.exists():
        return None, None
    v = json.loads(VAULT.read_text())
    return v.get("dashboard_token_iceland"), v.get("dashboard_fp_iceland")


def save(token: str, fp: str) -> None:
    v = json.loads(VAULT.read_text()) if VAULT.exists() else {}
    v["dashboard_token_iceland"] = token
    v["dashboard_fp_iceland"] = fp
    VAULT.write_text(json.dumps(v, indent=1))
    CURL_FILE.write_text(
        f"""curl --url '{TOKEN_URL}' \\
  -H 'content-type: application/json' \\
  -H 'fingerprint: {fp}' \\
  -H 'origin: https://dashboard.rapyd.net' \\
  -H 'referer: https://dashboard.rapyd.net/' \\
  -H 'token: {token}' \\
  -H 'user-agent: {UA}' \\
  --data-raw '{{"plugin_registration_params":null}}'
""")
    print(f"[keeper] kaydedildi (token={token[:8]}…)")


def check(token: str, fp: str) -> bool:
    req = urllib.request.Request(
        TOKEN_URL, data=b'{"plugin_registration_params":null}',
        headers={"content-type": "application/json", "token": token,
                 "fingerprint": fp, "X-Bugcrowd": "letmet4y",
                 "user-agent": UA}, method="POST")
    try:
        body = urllib.request.urlopen(req, timeout=30).read().decode()
        return '"status":"SUCCESS"' in body
    except Exception as e:  # noqa: BLE001
        print(f"[keeper] check hata: {e}")
        return False


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == "set" and len(sys.argv) == 4:
        save(sys.argv[2], sys.argv[3])
        t, f = sys.argv[2], sys.argv[3]
        print("[keeper] CANLI" if check(t, f) else "[keeper] ÖLÜ — değerler geçersiz")
        return 0
    if cmd == "check":
        t, f = load()
        if not (t and f):
            print("[keeper] vault'ta token yok")
            return 2
        ok = check(t, f)
        print("[keeper] CANLI" if ok else "[keeper] ÖLÜ — taze token gerekli")
        return 0 if ok else 2
    if cmd == "daemon":
        print("[keeper] daemon: her 10 dk keep-alive (log: /tmp/rapyd-keeper.log)")
        while True:
            t, f = load()
            stamp = time.strftime("%H:%M:%S")
            if t and f and check(t, f):
                print(f"[keeper] {stamp} CANLI", flush=True)
            else:
                print(f"[keeper] {stamp} ÖLÜ — taze token gerekli, daemon durdu",
                      flush=True)
                return 2
            time.sleep(10 * 60)
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
