"""Serileştirilmiş akış tanıma (Faz 1): biçim + Java sınıf adı çıkarımı.

Değerler saklanmaz/raporlanmaz; yalnızca biçim, sınıf adı ve uzunluk döner.
"""
from __future__ import annotations

import base64
import binascii
from urllib.parse import unquote

_JAVA_MAGIC = b"\xac\xed\x00\x05"
_DOTNET_MAGIC = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"


def decode_sample(value: str) -> bytes:
    """Cookie/param değeri -> ham baytlar (URL/std Base64, hex veya düz metin)."""
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


def detect_format(raw: bytes) -> str:
    if raw.startswith(_JAVA_MAGIC):
        return "java"
    if raw.startswith(b"O:") or raw.startswith(b"a:"):
        return "php"
    if raw.startswith(b"\x80\x04") or raw.startswith(b"\x80\x05") or raw.startswith(b"\x80\x03"):
        return "python_pickle"
    if raw.startswith(_DOTNET_MAGIC):
        return "dotnet"
    return "unknown"


def java_class_name(raw: bytes) -> str:
    """Java akışındaki ilk TC_CLASSDESC sınıf adı (yoksa boş)."""
    try:
        if not raw.startswith(_JAVA_MAGIC):
            return ""
        pos = 4
        if raw[pos:pos + 1] == b"\x73":  # TC_OBJECT
            pos += 1
        if raw[pos:pos + 1] != b"\x72":  # TC_CLASSDESC
            return ""
        pos += 1
        name_len = int.from_bytes(raw[pos:pos + 2], "big")
        pos += 2
        return raw[pos:pos + name_len].decode("utf-8", "ignore")
    except Exception:
        return ""


def looks_serialized(value: str) -> bool:
    return detect_format(decode_sample(value)) != "unknown"
