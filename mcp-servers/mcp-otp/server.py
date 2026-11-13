#!/usr/bin/env python3
"""MCP OTP Server — dar yetkili OTP okuyucu.

Tek tool: get_latest_otp — IMAP'taki son OTP kodunu dondurur.
Mailbox icerigi, konu, gonderen detayi ASLA disari cikmaz.
Kimlik bilgileri ~/.cco/auth/email.json (operator yazar, 0600).
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

from otp_core import OtpError, fetch_latest_otp

mcp = FastMCP(
    "otp",
    instructions="Dar OTP okuyucu — yalnizca son OTP kodunu dondurur, mail icerigi vermez.",
)


@mcp.tool()
def get_latest_otp(sender: str = "", max_age_minutes: int = 5) -> str:
    """Test mailbox'undaki son OTP kodunu dondurur.

    Args:
        sender: Gonderen filtresi (ornek: "hepsiburada"). Bos = filtresiz.
        max_age_minutes: Bu yas araligindaki maillere bak.

    Returns: JSON {"code": "482913", "age_seconds": 47} ya da HATA metni.
    Mail konusu/icerigi asla dondurulmez.
    """
    try:
        return json.dumps(fetch_latest_otp(sender=sender, max_age_minutes=max_age_minutes))
    except OtpError as e:
        return f"HATA: {e}"


if __name__ == "__main__":
    mcp.run()
