"""Source Map v3 decoding for Client Logic Map.

Only metadata and decoded segment counts leave this module. Original source
content is returned separately to the caller for local analysis and is never
embedded in the Client Logic Map output.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

_B64 = {ch: i for i, ch in enumerate(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)}
_INLINE_MAP_RE = re.compile(r"sourceMappingURL=data:application/json;base64,([A-Za-z0-9+/=]+)")
_EXTERNAL_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")


def _decode_vlq(text: str, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(text):
        digit = _B64.get(text[pos])
        pos += 1
        if digit is None:
            raise ValueError("invalid base64 VLQ digit")
        result |= (digit & 31) << shift
        if not digit & 32:
            break
        shift += 5
    sign = result & 1
    value = result >> 1
    return (-value if sign else value), pos


def decode_mappings(mappings: str) -> list[dict[str, int]]:
    """Decode Source Map v3 mappings into generated/original segments."""
    segments: list[dict[str, int]] = []
    source_index = 0
    source_line = 0
    source_column = 0
    name_index = 0
    for generated_line, line in enumerate((mappings or "").split(";"), start=1):
        generated_column = 0
        if not line:
            continue
        for segment in line.split(","):
            if not segment:
                continue
            values: list[int] = []
            pos = 0
            while pos < len(segment):
                value, pos = _decode_vlq(segment, pos)
                values.append(value)
            if not values:
                continue
            generated_column += values[0]
            item = {
                "generated_line": generated_line,
                "generated_column": generated_column,
            }
            if len(values) >= 4:
                source_index += values[1]
                source_line += values[2]
                source_column += values[3]
                item.update({
                    "source_index": source_index,
                    "source_line": source_line + 1,
                    "source_column": source_column,
                })
                if len(values) >= 5:
                    name_index += values[4]
                    item["name_index"] = name_index
            segments.append(item)
    return segments


def _coerce_map(raw: Any, generated_source: str) -> tuple[Any, str | None, list[str]]:
    diagnostics: list[str] = []
    if raw is None:
        inline = _INLINE_MAP_RE.search(generated_source or "")
        if inline:
            try:
                return base64.b64decode(inline.group(1)).decode("utf-8"), None, diagnostics
            except Exception:
                return None, None, ["inline source map could not be decoded"]
        external = _EXTERNAL_MAP_RE.search(generated_source or "")
        if external:
            return None, external.group(1), ["external source map is not fetched"]
        return None, None, diagnostics
    if isinstance(raw, dict):
        return raw, None, diagnostics
    text = str(raw).strip()
    if text.startswith("data:application/json;base64,"):
        try:
            return base64.b64decode(text.split(",", 1)[1]).decode("utf-8"), None, diagnostics
        except Exception:
            return None, None, ["source map data URI could not be decoded"]
    return text, None, diagnostics


def parse_source_map(raw: Any, generated_source: str = "") -> tuple[dict[str, Any], list[str]]:
    """Return (metadata, sourcesContent). Metadata contains no source code."""
    value, external_url, diagnostics = _coerce_map(raw, generated_source)
    metadata: dict[str, Any] = {
        "present": bool(raw is not None or external_url or value),
        "valid": False,
        "url": external_url,
        "sources": [],
        "sources_content_present": 0,
        "mappings_decoded": 0,
        "segments": [],
        "original_endpoints": [],
        "diagnostics": diagnostics,
    }
    if value is None:
        return metadata, []
    try:
        data = json.loads(value) if isinstance(value, str) else value
    except Exception:
        metadata["diagnostics"].append("source map JSON could not be parsed")
        return metadata, []
    if not isinstance(data, dict) or data.get("version") != 3:
        metadata["diagnostics"].append("source map version must be 3")
        return metadata, []
    sources = [str(s)[:300] for s in (data.get("sources") or []) if s]
    contents = data.get("sourcesContent") or []
    contents = [str(c) if isinstance(c, str) else "" for c in contents]
    try:
        segments = decode_mappings(str(data.get("mappings") or ""))
    except Exception as exc:
        metadata["diagnostics"].append(f"source map mappings could not be decoded: {type(exc).__name__}")
        return metadata, []
    metadata.update({
        "valid": True,
        "sources": sources,
        "sources_content_present": sum(1 for c in contents if c),
        "mappings_decoded": len(segments),
        "segments": segments[:200],
    })
    return metadata, contents


def original_position_for(segments: list[dict[str, int]], line: int, column: int = 0) -> dict[str, int] | None:
    candidates = [
        s for s in segments
        if s.get("generated_line") == line and s.get("generated_column", 0) <= column
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda s: s.get("generated_column", 0))
