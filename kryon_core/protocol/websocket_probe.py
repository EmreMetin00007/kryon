"""Pure-stdlib RFC-6455 WebSocket probe client for security testing.

Performs bounded, scope-caller-controlled WebSocket handshakes and frame
exchanges over ``ws://`` and ``wss://`` using only the Python standard library.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import socket
import ssl
import struct
import time
from typing import Any, Sequence
from urllib.parse import urlsplit

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_MAX_HTTP_HEADER_BYTES = 64 * 1024
_RESERVED_HANDSHAKE_HEADERS = frozenset({
    "host",
    "upgrade",
    "connection",
    "sec-websocket-key",
    "sec-websocket-version",
})


def _validate_wire_text(value: str, *, label: str) -> str:
    """Reject CR, LF, and NUL bytes to prevent HTTP request splitting."""
    text = str(value)
    if any(ch in text for ch in ("\r", "\n", "\x00")):
        raise ValueError(f"invalid control characters in WebSocket {label}")
    return text


def encode_client_frame(
    opcode: int,
    payload: bytes = b"",
    *,
    fin: bool = True,
    mask_key: bytes | None = None,
) -> bytes:
    """Encode a client-to-server RFC-6455 masked WebSocket frame."""
    if not (0 <= opcode <= 0x0F):
        raise ValueError(f"invalid WebSocket opcode: {opcode!r}")
    data = bytes(payload)
    length = len(data)
    first_byte = (0x80 if fin else 0x00) | (opcode & 0x0F)

    if length < 126:
        header = struct.pack("!BB", first_byte, 0x80 | length)
    elif length < 65536:
        header = struct.pack("!BBH", first_byte, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", first_byte, 0x80 | 127, length)

    if mask_key is not None:
        if len(mask_key) != 4:
            raise ValueError("WebSocket mask_key must be exactly 4 bytes")
        mask = bytes(mask_key)
    else:
        mask = os.urandom(4)

    masked = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
    return header + mask + masked


class _BufferedSocketReader:
    """Bounded deadline-aware exact-byte reader over a TCP/TLS socket."""

    def __init__(self, sock: socket.socket, initial_buf: bytes, deadline: float) -> None:
        self._sock = sock
        self._buf = bytearray(initial_buf)
        self._deadline = deadline

    def read_exact(self, count: int, *, read_timeout: float | None = None) -> bytes:
        if count <= 0:
            return b""
        while len(self._buf) < count:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0.0:
                raise TimeoutError("WebSocket read deadline exceeded")
            eff_timeout = min(remaining, read_timeout) if read_timeout is not None else remaining
            if eff_timeout <= 0.0:
                raise TimeoutError("WebSocket idle read timeout")
            self._sock.settimeout(max(0.01, eff_timeout))
            chunk = self._sock.recv(max(4096, count - len(self._buf)))
            if not chunk:
                raise EOFError("WebSocket peer closed connection")
            self._buf.extend(chunk)
        out = bytes(self._buf[:count])
        del self._buf[:count]
        return out


def _read_http_upgrade_response(
    sock: socket.socket,
    deadline: float,
) -> tuple[int, dict[str, str], bytes]:
    """Read HTTP/1.1 handshake response headers and preserve trailing frame bytes."""
    buf = bytearray()
    while True:
        sep = buf.find(b"\r\n\r\n")
        if sep != -1:
            head_bytes = bytes(buf[:sep])
            trailing = bytes(buf[sep + 4 :])
            break
        if len(buf) >= _MAX_HTTP_HEADER_BYTES:
            raise ValueError("WebSocket handshake response headers exceed 64 KiB")
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            raise TimeoutError("WebSocket handshake response timed out")
        sock.settimeout(max(0.01, remaining))
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("WebSocket connection closed during handshake")
        buf.extend(chunk)

    lines = head_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
    if not lines or not lines[0].upper().startswith("HTTP/"):
        raise ValueError("malformed HTTP status line in WebSocket handshake")
    status_parts = lines[0].split(None, 2)
    if len(status_parts) < 2 or not status_parts[1].isdigit():
        raise ValueError(f"invalid HTTP status line: {lines[0]!r}")
    status_code = int(status_parts[1])

    resp_headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip()
        val = v.strip()
        if not key:
            continue
        existing_key = next((ek for ek in resp_headers if ek.lower() == key.lower()), None)
        if existing_key is not None:
            resp_headers[existing_key] = f"{resp_headers[existing_key]}, {val}"
        else:
            resp_headers[key] = val

    return status_code, resp_headers, trailing


def _record_data_frame(
    frames_received: list[dict[str, Any]],
    *,
    opcode: int,
    payload: bytes,
    remaining_bytes: int,
) -> int:
    """Append a structured text or binary frame record and return bytes accounted."""
    clipped = payload[:remaining_bytes] if len(payload) > remaining_bytes else payload
    if opcode == 0x1:
        frames_received.append({
            "opcode": 1,
            "type": "text",
            "data": clipped.decode("utf-8", errors="replace"),
            "length": len(payload),
        })
    else:
        frames_received.append({
            "opcode": 2,
            "type": "binary",
            "data_base64": base64.b64encode(clipped[:1024]).decode("ascii"),
            "length": len(payload),
        })
    return len(clipped)


def probe_websocket(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    send_messages: Sequence[str | bytes] | None = None,
    timeout_s: float = 5.0,
    max_frames: int = 8,
    max_bytes: int = 65536,
) -> dict[str, Any]:
    """Perform a bounded RFC-6455 WebSocket handshake and frame exchange.

    Returns a JSON-serializable summary dict with keys:
    ``status``, ``response_headers``, ``upgraded``, ``frames_received``,
    ``close_code``, and ``error``.
    """
    raw_url = str(url or "").strip()
    if not raw_url:
        raise ValueError("WebSocket URL is required")
    parsed = urlsplit(raw_url)
    scheme = parsed.scheme.lower()
    if scheme not in {"ws", "wss"}:
        raise ValueError(f"WebSocket URL must use ws:// or wss:// scheme: {url!r}")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("WebSocket URL must not embed credentials")
    host = (parsed.hostname or "").strip()
    if not host:
        raise ValueError(f"WebSocket URL missing host: {url!r}")
    default_port = 443 if scheme == "wss" else 80
    port = parsed.port if parsed.port is not None else default_port
    if port <= 0 or port > 65535:
        raise ValueError(f"invalid WebSocket port: {port}")

    path = _validate_wire_text(parsed.path or "/", label="path")
    query = _validate_wire_text(parsed.query, label="query")
    request_target = f"{path}?{query}" if query else path

    host_bracketed = f"[{host}]" if ":" in host else host
    host_header = host_bracketed if port == default_port else f"{host_bracketed}:{port}"

    eff_timeout = max(0.05, float(timeout_s))
    eff_max_frames = max(0, int(max_frames))
    eff_max_bytes = max(0, int(max_bytes))

    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    # RFC 6455 Section 1.3 mandates SHA-1 for Sec-WebSocket-Accept derivation.
    expected_accept = base64.b64encode(
        hashlib.sha1((ws_key + _WS_GUID).encode("ascii")).digest()
    ).decode("ascii")

    req_lines = [
        f"GET {request_target} HTTP/1.1",
        f"Host: {host_header}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Version: 13",
    ]
    for raw_k, raw_v in (headers or {}).items():
        k = _validate_wire_text(str(raw_k).strip(), label="header name")
        v = _validate_wire_text(str(raw_v).strip(), label="header value")
        if not k or k.lower() in _RESERVED_HANDSHAKE_HEADERS:
            continue
        req_lines.append(f"{k}: {v}")
    handshake_bytes = ("\r\n".join(req_lines) + "\r\n\r\n").encode("iso-8859-1", errors="replace")

    deadline = time.monotonic() + eff_timeout
    sock: socket.socket | None = None
    status = 0
    response_headers: dict[str, str] = {}
    upgraded = False
    frames_received: list[dict[str, Any]] = []
    close_code: int | None = None
    error = ""

    try:
        raw_sock = socket.create_connection((host, port), timeout=eff_timeout)
        if scheme == "wss":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            raise TimeoutError("WebSocket handshake send timed out")
        sock.settimeout(max(0.01, remaining))
        sock.sendall(handshake_bytes)

        status, response_headers, trailing = _read_http_upgrade_response(sock, deadline)
        if status != 101:
            return {
                "status": status,
                "response_headers": response_headers,
                "upgraded": False,
                "frames_received": [],
                "close_code": None,
                "error": "",
            }

        actual_accept = ""
        for hk, hv in response_headers.items():
            if hk.lower() == "sec-websocket-accept":
                actual_accept = hv.strip()
                break
        if not actual_accept or not hmac.compare_digest(actual_accept, expected_accept):
            return {
                "status": 101,
                "response_headers": response_headers,
                "upgraded": False,
                "frames_received": [],
                "close_code": None,
                "error": "invalid Sec-WebSocket-Accept header",
            }

        upgraded = True

        for msg in send_messages or ():
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                break
            sock.settimeout(max(0.01, remaining))
            if isinstance(msg, (bytes, bytearray)):
                frame = encode_client_frame(0x2, bytes(msg))
            else:
                frame = encode_client_frame(0x1, str(msg).encode("utf-8"))
            sock.sendall(frame)

        reader = _BufferedSocketReader(sock, trailing, deadline)
        bytes_read = 0
        frag_opcode: int | None = None
        frag_buf = bytearray()

        while len(frames_received) < eff_max_frames and bytes_read < eff_max_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                break
            idle_cap = min(remaining, 0.25) if frames_received else remaining
            try:
                head2 = reader.read_exact(2, read_timeout=idle_cap)
            except (TimeoutError, socket.timeout, EOFError, OSError):
                break

            b0, b1 = head2[0], head2[1]
            fin = bool(b0 & 0x80)
            opcode = b0 & 0x0F
            is_masked = bool(b1 & 0x80)
            payload_len = b1 & 0x7F

            try:
                if payload_len == 126:
                    payload_len = struct.unpack("!H", reader.read_exact(2))[0]
                elif payload_len == 127:
                    payload_len = struct.unpack("!Q", reader.read_exact(8))[0]

                if opcode >= 0x8 and payload_len > 125:
                    error = f"invalid control frame payload length: {payload_len}"
                    break
                if opcode < 0x8 and payload_len > max(eff_max_bytes, 1024):
                    error = f"frame payload {payload_len} exceeds max_bytes {eff_max_bytes}"
                    break

                mask_bytes = reader.read_exact(4) if is_masked else b""
                payload = reader.read_exact(payload_len) if payload_len > 0 else b""
                if is_masked and payload:
                    payload = bytes(b ^ mask_bytes[i & 3] for i, b in enumerate(payload))
            except (TimeoutError, socket.timeout, EOFError, OSError):
                break

            if opcode == 0x9:
                # Ping -> immediately respond with masked Pong echoing payload.
                try:
                    sock.sendall(encode_client_frame(0xA, payload[:125]))
                except OSError:
                    pass
                continue
            if opcode == 0xA:
                # Pong -> ignore and keep reading data frames.
                continue
            if opcode == 0x8:
                # Close frame: optional 2-byte big-endian status code + UTF-8 reason.
                reason = ""
                if len(payload) >= 2:
                    close_code = struct.unpack("!H", payload[:2])[0]
                    reason = payload[2:].decode("utf-8", errors="replace")[:256]
                frames_received.append({
                    "opcode": 8,
                    "type": "close",
                    "code": close_code,
                    "reason": reason,
                })
                try:
                    sock.sendall(encode_client_frame(0x8, payload[:2]))
                except OSError:
                    pass
                break

            if opcode in (0x1, 0x2):
                if fin:
                    bytes_read += _record_data_frame(
                        frames_received,
                        opcode=opcode,
                        payload=payload,
                        remaining_bytes=max(0, eff_max_bytes - bytes_read),
                    )
                else:
                    frag_opcode = opcode
                    frag_buf = bytearray(payload[: max(0, eff_max_bytes - bytes_read)])
            elif opcode == 0x0 and frag_opcode is not None:
                budget_left = max(0, eff_max_bytes - bytes_read - len(frag_buf))
                if budget_left > 0:
                    frag_buf.extend(payload[:budget_left])
                if fin or len(frag_buf) >= max(0, eff_max_bytes - bytes_read):
                    bytes_read += _record_data_frame(
                        frames_received,
                        opcode=frag_opcode,
                        payload=bytes(frag_buf),
                        remaining_bytes=max(0, eff_max_bytes - bytes_read),
                    )
                    frag_opcode = None
                    frag_buf.clear()

        return {
            "status": status,
            "response_headers": response_headers,
            "upgraded": True,
            "frames_received": frames_received,
            "close_code": close_code,
            "error": error,
        }
    except Exception as exc:
        return {
            "status": status,
            "response_headers": response_headers,
            "upgraded": upgraded,
            "frames_received": frames_received,
            "close_code": close_code,
            "error": f"{type(exc).__name__}: {str(exc)[:200]}",
        }
    finally:
        if sock is not None:
            if upgraded and close_code is None:
                try:
                    sock.settimeout(0.1)
                    sock.sendall(encode_client_frame(0x8, struct.pack("!H", 1000)))
                except OSError:
                    pass
            try:
                sock.close()
            except OSError:
                pass


__all__ = ["encode_client_frame", "probe_websocket"]
