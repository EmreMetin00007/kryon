"""Pure-stdlib gRPC-Web binary and base64-text frame encoder/decoder."""
from __future__ import annotations

import base64
import binascii
import struct
from typing import Any
from urllib.parse import unquote

_TRAILER_FLAG = 0x80
_COMPRESSED_FLAG = 0x01
_MAX_PREVIEW_CHARS = 512


def is_grpc_web_content_type(content_type: str) -> bool:
    """Return True if the HTTP Content-Type indicates a gRPC-Web payload."""
    ct = str(content_type or "").split(";", 1)[0].strip().lower()
    return (
        ct == "application/grpc-web"
        or ct.startswith("application/grpc-web+")
        or ct == "application/grpc-web-text"
        or ct.startswith("application/grpc-web-text+")
    )


def encode_grpc_web_frame(
    payload: bytes,
    *,
    text_mode: bool = False,
    flags: int = 0x00,
) -> bytes:
    """Encode a single gRPC-Web frame (1-byte flags + 4-byte BE length + payload).

    When ``text_mode=True``, returns the ASCII base64 encoding suitable for
    ``application/grpc-web-text``.
    """
    if not (0 <= int(flags) <= 0xFF):
        raise ValueError(f"gRPC-Web flags byte must be in 0..255, got {flags!r}")
    data = bytes(payload)
    frame = struct.pack("!BI", int(flags), len(data)) + data
    if text_mode:
        return base64.b64encode(frame)
    return frame


def encode_grpc_web_trailers(
    trailers: dict[str, str],
    *,
    text_mode: bool = False,
) -> bytes:
    """Encode a gRPC-Web trailer frame (flags=0x80) from header key/value pairs."""
    lines = [f"{str(k).strip().lower()}: {str(v).strip()}\r\n" for k, v in (trailers or {}).items()]
    payload = "".join(lines).encode("utf-8")
    return encode_grpc_web_frame(payload, text_mode=text_mode, flags=_TRAILER_FLAG)


def _decode_grpc_web_text_base64(raw_bytes: bytes) -> bytes:
    """Decode one or more concatenated padded base64 segments from grpc-web-text."""
    compact = b"".join(raw_bytes.split())
    if not compact:
        return b""
    parts: list[bytes] = []
    idx = 0
    total = len(compact)
    while idx < total:
        eq_pos = compact.find(b"=", idx)
        if eq_pos == -1:
            segment = compact[idx:]
            idx = total
        else:
            end = eq_pos
            while end < total and compact[end : end + 1] == b"=":
                end += 1
            segment = compact[idx:end]
            idx = end
        if segment:
            parts.append(base64.b64decode(segment, validate=True))
    return b"".join(parts)


def _printable_preview(payload: bytes) -> str:
    """Build a compact readable preview of a binary protobuf/JSON data frame."""
    if not payload:
        return ""
    decoded = payload[: _MAX_PREVIEW_CHARS * 2].decode("utf-8", errors="replace")
    cleaned = "".join(
        ch if (ch.isprintable() or ch in ("\n", "\t")) else "."
        for ch in decoded
    )
    return cleaned[:_MAX_PREVIEW_CHARS]


def decode_grpc_web_frames(
    raw_bytes: bytes,
    *,
    content_type: str = "",
) -> dict[str, Any]:
    """Decode binary ``application/grpc-web`` or base64 ``application/grpc-web-text`` frames.

    Separates data frames (``flag & 0x80 == 0``) and trailer frames (``flag & 0x80 != 0``),
    parsing ``grpc-status``, ``grpc-message``, and trailer header pairs cleanly.
    """
    ct_low = str(content_type or "").split(";", 1)[0].strip().lower()
    is_text_mode = ct_low == "application/grpc-web-text" or ct_low.startswith("application/grpc-web-text+")

    wire = bytes(raw_bytes or b"")
    data_frames: list[dict[str, Any]] = []
    trailers: dict[str, str] = {}
    trailer_frame_count = 0
    truncated = False
    error = ""

    if is_text_mode and wire:
        try:
            wire = _decode_grpc_web_text_base64(wire)
        except (binascii.Error, ValueError) as exc:
            return {
                "protocol": "grpc-web",
                "text_mode": True,
                "data_frames": [],
                "trailers": {},
                "grpc_status": None,
                "grpc_message": "",
                "frame_count": 0,
                "truncated": True,
                "error": f"invalid grpc-web-text base64: {exc}",
            }

    offset = 0
    total_len = len(wire)
    while offset < total_len:
        if total_len - offset < 5:
            truncated = True
            break
        flag, length = struct.unpack("!BI", wire[offset : offset + 5])
        payload_start = offset + 5
        payload_end = payload_start + length
        if payload_end > total_len:
            truncated = True
            break
        payload = wire[payload_start:payload_end]
        offset = payload_end

        if flag & _TRAILER_FLAG:
            trailer_frame_count += 1
            trailer_text = payload.decode("utf-8", errors="replace")
            for raw_line in trailer_text.replace("\r\n", "\n").split("\n"):
                line = raw_line.strip()
                if not line or ":" not in line:
                    continue
                k, v = line.split(":", 1)
                key = k.strip().lower()
                val = v.strip()
                if key:
                    trailers[key] = val
        else:
            data_frames.append({
                "flags": flag,
                "compressed": bool(flag & _COMPRESSED_FLAG),
                "length": length,
                "payload_base64": base64.b64encode(payload).decode("ascii"),
                "text_preview": _printable_preview(payload),
            })

    raw_status = trailers.get("grpc-status")
    grpc_status: int | str | None = None
    if raw_status is not None and raw_status != "":
        grpc_status = int(raw_status) if raw_status.lstrip("-").isdigit() else raw_status
    raw_msg = trailers.get("grpc-message", "")
    grpc_message = unquote(raw_msg) if raw_msg else ""

    return {
        "protocol": "grpc-web",
        "text_mode": is_text_mode,
        "data_frames": data_frames,
        "trailers": trailers,
        "grpc_status": grpc_status,
        "grpc_message": grpc_message,
        "frame_count": len(data_frames) + trailer_frame_count,
        "truncated": truncated,
        "error": error,
    }


__all__ = [
    "decode_grpc_web_frames",
    "encode_grpc_web_frame",
    "encode_grpc_web_trailers",
    "is_grpc_web_content_type",
]
