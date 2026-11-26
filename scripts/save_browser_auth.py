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
from typing import Sequence

_SCRIPTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPTS_DIR.parent
for _p in (str(_REPO_ROOT), str(_SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from agentic_http import parse_custom_headers  # noqa: E402
from kryon_core.vault.otp_core import OtpError, fetch_latest_otp  # noqa: E402

AUTH_DIR = Path(os.environ.get("CCO_AUTH_DIR", "~/.cco/auth")).expanduser()
PROXY = os.environ.get("CCO_PROXY", "http://127.0.0.1:8080").strip()
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

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


def _custom_header_arg(raw: str) -> str:
    try:
        parse_custom_headers([raw])
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return raw


def _build_context_headers(raw_headers: Sequence[str] | None) -> tuple[str, dict[str, str]]:
    """Return ``(user_agent, extra_http_headers)`` from validated operator header args."""
    parsed = parse_custom_headers(raw_headers)
    user_agent = DEFAULT_USER_AGENT
    extra_http_headers: dict[str, str] = {}
    for key, value in parsed.items():
        if key.lower() == "user-agent":
            user_agent = value
        else:
            extra_http_headers[key] = value
    return user_agent, extra_http_headers


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--program", required=True)
    ap.add_argument("--login-url", required=True)
    ap.add_argument("--user-selector", default="")
    ap.add_argument("--pass-selector", default="")
    ap.add_argument("--submit-selector", default="")
    ap.add_argument("--otp-selector", default="")
    ap.add_argument("--otp-sender", default="")
    ap.add_argument("--otp-retries", type=int, default=4)
    ap.add_argument("--otp-wait", type=int, default=15)
    ap.add_argument("--login-file", default="")
    ap.add_argument("--storage", default="")
    ap.add_argument(
        "--record-har",
        default="",
        help="Optional HAR output path captured during the auth/browse context (saved with 0600 permissions)",
    )
    ap.add_argument(
        "--manual",
        action="store_true",
        help="Open headed browser for interactive login/browsing without login-file or selectors",
    )
    ap.add_argument(
        "--browse-seconds",
        type=int,
        default=0,
        help="Extra seconds to wait after login (non-manual) to enrich recorded HAR in headed mode",
    )
    ap.add_argument(
        "-H",
        "--header",
        "--custom-header",
        action="append",
        dest="custom_headers",
        type=_custom_header_arg,
        default=None,
        metavar="NAME: VALUE",
        help="Operator header sent on every browser request (repeatable; e.g. -H 'Pentest: Cyberbounty')",
    )
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--timeout", type=int, default=30000)
    a = ap.parse_args(argv)

    if not a.manual:
        missing = [
            flag
            for flag, val in (
                ("--user-selector", a.user_selector),
                ("--pass-selector", a.pass_selector),
                ("--submit-selector", a.submit_selector),
            )
            if not str(val or "").strip()
        ]
        if missing:
            ap.error(f"the following arguments are required unless --manual is set: {', '.join(missing)}")
    if a.browse_seconds < 0:
        ap.error("--browse-seconds must be >= 0")

    storage = Path(a.storage or AUTH_DIR / f"{a.program}-storage.json").expanduser()
    har_raw = str(a.record_har or "").strip()
    har_path = Path(har_raw).expanduser() if har_raw else None
    creds: dict = {}
    if not a.manual:
        login_file = Path(a.login_file or AUTH_DIR / f"{a.program}-login.json").expanduser()
        creds = _load_login(login_file)
    eff_user_agent, extra_http_headers = _build_context_headers(a.custom_headers)
    if a.custom_headers:
        header_names = sorted(parse_custom_headers(a.custom_headers))
        print(f"[auth] ozel basliklar aktif: {', '.join(header_names)}", flush=True)
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    if har_path is not None:
        har_path.parent.mkdir(parents=True, exist_ok=True)

    eff_headed = bool(a.headed or a.manual)

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not eff_headed, args=["--no-sandbox"])
        context_kwargs: dict = {
            "viewport": {"width": 1366, "height": 800},
            "locale": "tr-TR",
            "timezone_id": "Europe/Istanbul",
            "user_agent": eff_user_agent,
            "ignore_https_errors": True,
            **_proxy_args(),
        }
        if extra_http_headers:
            context_kwargs["extra_http_headers"] = extra_http_headers
        if har_path is not None:
            context_kwargs["record_har_path"] = str(har_path)
            context_kwargs["record_har_mode"] = "minimal"
            context_kwargs["record_har_content"] = "embed"
        ctx = browser.new_context(**context_kwargs)
        page = ctx.new_page()
        page.set_default_timeout(a.timeout)
        print(f"[auth] login sayfasi aciliyor: {a.login_url}", flush=True)
        resp = page.goto(a.login_url, wait_until="domcontentloaded")
        page.wait_for_timeout(2000)
        if a.manual:
            try:
                input("[auth] Tarayicida giris yapip akislari gezdikten sonra Enter'a basin...")
            except EOFError:
                pass
        else:
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
            if a.browse_seconds > 0:
                print(
                    f"[auth] HAR zenginlestirme icin {a.browse_seconds}sn bekleniyor...",
                    flush=True,
                )
                page.wait_for_timeout(a.browse_seconds * 1000)
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
        if har_path is not None:
            try:
                har_path.chmod(0o600)
            except OSError:
                pass
            try:
                har_size = har_path.stat().st_size
            except OSError:
                har_size = 0
            print(f"[auth] HAR kaydedildi: {har_path} ({har_size} byte)", flush=True)
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
