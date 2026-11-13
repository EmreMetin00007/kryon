"""Dar OTP cekirdegi — IMAP'tan son OTP kodunu okur, SADECE kodu dondurur.

Guvenlik modeli:
- Kimlik bilgileri ~/.cco/auth/email.json (0600, operator yazar) — model asla gormez.
- Cikti yalnizca {"code", "age_seconds"} — konu/icerik/gonderen detayi YOK.
- Hata mesajlarinda secret yok.
"""
from __future__ import annotations

import imaplib
import html as html_lib
import json
import os
import re
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import decode_header
from pathlib import Path

DEFAULT_AUTH_FILE = "~/.cco/auth/email.json"
DEFAULT_PATTERN = r"(?<!\d)(\d{4,8})(?!\d)"
# Anchored to the phrasing providers actually use; supports ALPHANUMERIC codes
# (e.g. Nebius "verification code: I7DVXF") which the digit-only pattern misses
# and which otherwise falsely matches HTML noise such as xmlns=".../1999/xhtml".
CODE_ANCHORED_PATTERN = re.compile(
    r"(?:verification\s*code|one[\s-]*time\s*code|login\s*code|\bcode\b)"
    r"\s*(?:is|:)?\s*([A-Za-z0-9]{4,8})",
    re.I,
)
FETCH_LAST_N = 15
AUTH_TEMPLATE = '{"imap": "imap.gmail.com", "user": "test@mail.com", "app_password": "..."}'


class OtpError(Exception):
    pass


def auth_path() -> Path:
    return Path(os.environ.get("CCO_EMAIL_AUTH", DEFAULT_AUTH_FILE)).expanduser()


def _load_auth() -> dict:
    p = auth_path()
    if not p.exists():
        raise OtpError(f"email auth dosyasi yok: {p} (operator kurmali)")
    try:
        data = json.loads(p.read_text())
    except ValueError:
        raise OtpError("email auth dosyasi bozuk JSON")
    for k in ("imap", "user", "app_password"):
        if not data.get(k):
            raise OtpError(f"email auth dosyasinda eksik alan: {k}")
    return data


def _decode_header(h) -> str:
    if not h:
        return ""
    parts = []
    for blob, enc in decode_header(h):
        if isinstance(blob, bytes):
            try:
                parts.append(blob.decode(enc or "utf-8", "replace"))
            except LookupError:
                parts.append(blob.decode("utf-8", "replace"))
        else:
            parts.append(blob)
    return "".join(parts)


def _text_parts(msg) -> str:
    out = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() != "text":
                continue
            if "attachment" in (part.get("Content-Disposition") or "").lower():
                continue
            try:
                payload = part.get_payload(decode=True)
                out.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
            except Exception:
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            out.append(payload.decode(msg.get_content_charset() or "utf-8", "replace")
                       if isinstance(payload, bytes) else str(payload))
        except Exception:
            pass
    return "\n".join(out)


def fetch_latest_otp(sender: str = "", max_age_minutes: int = 5,
                     pattern: str = DEFAULT_PATTERN) -> dict:
    """Son OTP kodunu dondur. Cikti disi asla mail icerigi sizdirmaz."""
    auth = _load_auth()
    rx = re.compile(pattern)
    now = datetime.now(timezone.utc)
    try:
        box = imaplib.IMAP4_SSL(auth["imap"])
        box.login(auth["user"], auth["app_password"])
    except (imaplib.IMAP4.error, OSError) as e:
        raise OtpError(f"IMAP baglanti hatasi ({auth['imap']})") from e
    try:
        box.select("INBOX", readonly=True)
        status, data = box.search(None, "ALL")
        if status != "OK":
            raise OtpError("INBOX aramasi basarisiz")
        uids = data[0].split()[-FETCH_LAST_N:]
        for uid in reversed(uids):
            st, msg_data = box.fetch(uid, "(RFC822)")
            if st != "OK" or not msg_data or not msg_data[0]:
                continue
            msg = message_from_bytes(msg_data[0][1])
            try:
                from email.utils import parsedate_to_datetime
                date = parsedate_to_datetime(msg.get("Date"))
                if date and date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                continue
            if not date:
                continue
            age = (now - date).total_seconds()
            if age < 0 or age > max_age_minutes * 60:
                continue
            if sender and sender.lower() not in _decode_header(msg.get("From", "")).lower():
                continue
            blob = _decode_header(msg.get("Subject", "")) + "\n" + _text_parts(msg)
            # Strip HTML tags/entities first: provider codes are often separated
            # from the "verification code:" label by markup, and digits inside
            # tag attributes (xmlns=".../1999/xhtml") are noise.
            plain = html_lib.unescape(re.sub(r"<[^>]+>", " ", blob))
            plain = re.sub(r"\s+", " ", plain)
            # Prefer a code anchored to its provider phrasing (handles
            # alphanumeric codes like Nebius "I7DVXF" and pure digits).
            anchored = CODE_ANCHORED_PATTERN.search(plain)
            if anchored and any(ch.isdigit() for ch in anchored.group(1)):
                return {"code": anchored.group(1), "age_seconds": int(age)}
            m = rx.search(plain)
            if m:
                return {"code": m.group(1), "age_seconds": int(age)}
    finally:
        try:
            box.logout()
        except Exception:
            pass
    raise OtpError("son maillerde OTP kodu bulunamadi")
