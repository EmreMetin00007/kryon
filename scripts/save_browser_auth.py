#!/usr/bin/env python3
"""Test hesabi login + OTP autofill + storage_state kaydetme.

Operator bir kez calistirir; cikti ~/.cco/auth/<program>-storage.json (0600).
Kimlik bilgileri ~/.cco/auth/<program>-login.json (operator yazar, 0600):
  {"username": "...", "password": "..."}
Email OTP kimligi ~/.cco/auth/email.json (ayri dosya).

Secret'lar ASLA stdout'a basilmez (kodun kendisi dahil).

Ornek:
  python3 scripts/save_browser_auth.py --program hepsiburada \\
      --login-url https://giris.hepsiburada.com/ \\
      --user-selector '#username' --pass-selector '#password' \\
      --submit-selector 'button[type=submit]' --otp-sender hepsiburada
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp-servers" / "mcp-otp"))
from otp_core import OtpError, fetch_latest_otp  # noqa: E402

AUTH_DIR = Path(os.environ.get("CCO_AUTH_DIR", "~/.cco/auth")).expanduser()
PROXY = os.environ.get("CCO_PROXY", "http://127.0.0.1:8080").strip()

OTP_CANDIDATES = [
    "input[name*=otp i]", "input[name*=code i]", "input[name*=sms i]",
    "input[name*=verify i]", "input[name*=dogrulama i]", "input[id*=otp i]",
    "input[inputmode=numeric]", "input[autocomplete=one-time-code]",
]


def _proxy_args() -> dict:
    if not PROXY:
        return {}
    try:
        import socket
        from urllib.parse import urlparse
        u = urlparse(PROXY)
        with socket.create_connection((u.hostname or "127.0.0.1", u.port or 8080), timeout=1.0):
            return {"proxy": {"server": PROXY}}
    except OSError:
        print("[auth] proxy erisilemiyor, direkt baglaniliyor", flush=True)
        return {}


def _load_login(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"HATA: login dosyasi yok: {path} (operator olusturmali)")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        print(f"[auth] UYARI: {path} izinleri gevsek ({oct(mode)}), 0600 yapiliyor", flush=True)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    try:
        data = json.loads(path.read_text())
    except ValueError:
        sys.exit("HATA: login dosyasi bozuk JSON")
    if not data.get("username") or not data.get("password"):
        sys.exit("HATA: login dosyasinda username/password eksik")
    return data


def _find_otp_field(page, explicit: str):
    if explicit:
        try:
            page.wait_for_selector(explicit, state="visible", timeout=8000)
            return explicit
        except Exception:
            return None
    for sel in OTP_CANDIDATES:
        try:
            if page.is_visible(sel, timeout=1500):
                return sel
        except Exception:
            continue
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--program", required=True)
    ap.add_argument("--login-url", required=True)
    ap.add_argument("--user-selector", required=True)
    ap.add_argument("--pass-selector", required=True)
    ap.add_argument("--submit-selector", required=True)
    ap.add_argument("--otp-selector", default="")
    ap.add_argument("--otp-sender", default="")
    ap.add_argument("--otp-retries", type=int, default=4)
    ap.add_argument("--otp-wait", type=int, default=15)
    ap.add_argument("--login-file", default="")
    ap.add_argument("--storage", default="")
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--timeout", type=int, default=30000)
    a = ap.parse_args()

    login_file = Path(a.login_file or AUTH_DIR / f"{a.program}-login.json").expanduser()
    storage = Path(a.storage or AUTH_DIR / f"{a.program}-storage.json").expanduser()
    creds = _load_login(login_file)
    AUTH_DIR.mkdir(parents=True, exist_ok=True)

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not a.headed, args=["--no-sandbox"])
        ctx = browser.new_context(
            viewport={"width": 1366, "height": 800},
            locale="tr-TR", timezone_id="Europe/Istanbul",
            user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
            ignore_https_errors=True, **_proxy_args())
        page = ctx.new_page()
        page.set_default_timeout(a.timeout)
        print(f"[auth] login sayfasi aciliyor: {a.login_url}", flush=True)
        resp = page.goto(a.login_url, wait_until="domcontentloaded")
        page.wait_for_timeout(2000)
        if (resp and resp.status == 403) or "güvenlik" in page.title().lower():
            browser.close()
            print("[auth] HATA: WAF headless'i yakaladi (403/Güvenlik). "
                  "--headed ile tekrar dene.", flush=True)
            return 3
        page.fill(a.user_selector, creds["username"])
        page.fill(a.pass_selector, creds["password"])
        print("[auth] kullanici/sifre dolduruldu, gonderiliyor", flush=True)
        page.click(a.submit_selector)
        page.wait_for_timeout(4000)

        otp_sel = _find_otp_field(page, a.otp_selector)
        if otp_sel:
            print(f"[auth] OTP alani bulundu ({otp_sel}), kod bekleniyor", flush=True)
            code = None
            for i in range(max(1, a.otp_retries)):
                try:
                    res = fetch_latest_otp(sender=a.otp_sender, max_age_minutes=5)
                    code, age = res["code"], res["age_seconds"]
                    print(f"[auth] OTP kodu alindi (yas: {age}sn)", flush=True)
                    break
                except OtpError as e:
                    print(f"[auth] OTP deneme {i + 1}/{a.otp_retries}: {e}", flush=True)
                    time.sleep(a.otp_wait)
            if not code:
                browser.close()
                print("[auth] HATA: OTP kodu alinamadi", flush=True)
                return 2
            page.fill(otp_sel, code)
            page.wait_for_timeout(1000)
            try:
                page.click(a.submit_selector, timeout=5000)
            except Exception:
                page.keyboard.press("Enter")
            page.wait_for_timeout(4000)
        else:
            print("[auth] OTP alani gorunmedi, direkt login varsayiliyor", flush=True)

        page.wait_for_timeout(3000)
        storage.parent.mkdir(parents=True, exist_ok=True)
        ctx.storage_state(path=str(storage))
        try:
            storage.chmod(0o600)
        except OSError:
            pass
        cookies = ctx.cookies()
        print(f"[auth] storage kaydedildi: {storage} ({len(cookies)} cookie)", flush=True)
        print(f"[auth] son URL: {page.url[:120]} | baslik: {page.title()[:80]}", flush=True)
        ctx.close()
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
