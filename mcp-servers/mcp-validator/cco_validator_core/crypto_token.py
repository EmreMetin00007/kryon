"""Sifreli token (opaque cookie/param) analizi ve CBC IV-dovme (Faz G).

Ham token degerleri ASLA saklanmaz/raporlanmaz; yalnizca uzunluk, blok
hizasi ve sha256 ozeti doner. Tum kripto islemleri yerel hesaptir (ag yok).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from urllib.parse import quote, unquote


def decode_token_sample(value: str) -> bytes:
    """Cookie/param degeri -> ham baytlar (URL/std Base64, hex veya duz metin)."""
    text = unquote(str(value or "").strip())
    if not text:
        return b""
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(text + "=" * (-len(text) % 4))
        except (binascii.Error, ValueError):
            continue
    try:
        return bytes.fromhex(text)
    except ValueError:
        return text.encode("utf-8", "ignore")


def is_wellformed_token_text(text: str) -> bool:
    """Sozdizimsel iyi-yapililik: Base64 alfabesi + dogru dolgu (ag yok).

    Decode-hatasi 500'leri ile dolgu-hatasi sinyallerini ayirmak icin
    kontrol probu olarak kullanilir: yalnizca True donen varyantlar
    oracle kumesi sayilir.
    """
    t = unquote(str(text or "").strip())
    if not t or len(t) % 4 != 0:
        return False
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    if any(c not in alphabet for c in t):
        return False
    try:
        base64.b64decode(t, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def token_structure(raw: bytes) -> dict:
    """Ham tokenin olculebilir yapisi (deger icermez)."""
    n = len(raw)
    return {
        "length_bytes": n,
        "block16_aligned": n > 0 and n % 16 == 0,
        "block8_aligned": n > 0 and n % 8 == 0,
        "sha256": hashlib.sha256(raw).hexdigest() if raw else "",
    }


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    """PKCS#7 dolgu (bilinen-duz-metin varyantlari icin)."""
    pad_len = block - (len(data) % block)
    return data + bytes([pad_len]) * pad_len


def forge_cbc_iv(iv: bytes, known_plaintext: bytes, target_plaintext: bytes) -> bytes:
    """CBC IV-oynanabilirligi: ayni C blogu, hedef duz-metin icin yeni IV.

    P' = Dec(C) XOR IV' esitliginden: IV' = IV XOR P_bilinen XOR P_hedef.
    Dolguya dokunulmaz; girdiler ayni uzunlukta olmali (tek blok).
    """
    if not (len(iv) == len(known_plaintext) == len(target_plaintext)):
        raise ValueError(
            "iv, known_plaintext ve target_plaintext ayni uzunlukta olmali")
    return bytes(a ^ b ^ c for a, b, c in zip(iv, known_plaintext, target_plaintext))


def encode_token_value(raw: bytes, url_safe: bool = True) -> str:
    """Ham token -> tasiyici metni (URL kodlu Base64)."""
    text = base64.b64encode(raw).decode("ascii")
    return quote(text, safe="") if url_safe else text


def cut_leading_bytes(raw: bytes, drop_bytes: int, block: int = 16) -> bytes:
    """Ham sifreli metnin basindan blok-hizali kesit at (CBC blok birlestirme).

    Cozum-oracle'i one ek iceriyorsa (orn hata one eki), girdiyi one-uzunlugu
    blok katina tamamlayacak kadar doldurup sifrelet, sonra buradan o bloklari
    at: kalan bloklar hedef duz-metni verir. drop_bytes blok kati olmali.
    """
    if drop_bytes <= 0 or drop_bytes >= len(raw):
        raise ValueError("drop_bytes (0, len) araliginda olmali")
    if drop_bytes % block != 0:
        raise ValueError("drop_bytes blok kati olmali "
                         f"(blok={block}, drop={drop_bytes})")
    return raw[drop_bytes:]
