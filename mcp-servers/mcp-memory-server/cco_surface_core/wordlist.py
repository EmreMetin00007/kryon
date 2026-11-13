"""Compile a target-specific content/param wordlist from surface + JS + OpenAPI."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from .extract import extract_js
from .normalize import params_from_url

STOP = {
    "http", "https", "www", "com", "org", "net", "html", "htm", "php", "asp",
    "aspx", "jsp", "index", "home", "the", "and", "for", "from", "this", "that",
    "null", "true", "false", "undefined", "function", "return", "var", "let",
    "const", "window", "document",
}
QUERY_KEY_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_-]{0,40})=")
IDENT_RE = re.compile(r"/([A-Za-z][A-Za-z0-9_-]{1,40})(?:/|$|\?|#)")


def _add(token: str, out: list[str], seen: set[str]) -> None:
    value = (token or "").strip().strip("/")
    if not value or len(value) > 64:
        return
    key = value.lower()
    if key in STOP or key in seen or not re.fullmatch(r"[A-Za-z0-9._~-]+", value):
        return
    seen.add(key)
    out.append(value)


def tokens_from_url(url: str, out: list[str], seen: set[str]) -> None:
    parsed = urlparse(url or "")
    for part in (parsed.path or "").split("/"):
        _add(part, out, seen)
    for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
        _add(name, out, seen)
    for param in params_from_url(url or ""):
        _add(param.get("name") or "", out, seen)


def tokens_from_js(text: str, base: str, out: list[str], seen: set[str], limit: int = 80) -> None:
    for rec in extract_js(text or "", base or "http://wordlist.local", limit=limit):
        tokens_from_url(rec.get("url") or "", out, seen)
        for param in rec.get("params") or []:
            if isinstance(param, dict):
                _add(param.get("name") or "", out, seen)
    for key in QUERY_KEY_RE.findall(text or ""):
        _add(key, out, seen)
    for part in IDENT_RE.findall(text or ""):
        _add(part, out, seen)


def tokens_from_records(records, out: list[str], seen: set[str]) -> None:
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        tokens_from_url(rec.get("url") or "", out, seen)
        path = rec.get("path") or ""
        if path:
            for part in str(path).split("/"):
                _add(part, out, seen)
        for param in rec.get("params") or []:
            if isinstance(param, dict):
                _add(param.get("name") or "", out, seen)
            else:
                _add(str(param), out, seen)


def compile_wordlist(records=None, extra_texts=None, base: str = "", limit: int = 400) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    tokens_from_records(records, out, seen)
    for text in extra_texts or []:
        tokens_from_js(text, base, out, seen)
    return out[: max(1, int(limit))]


def write_wordlist(tokens, path: str) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    lines = [str(item) for item in tokens if item]
    Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return path
