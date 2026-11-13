#!/usr/bin/env python3
"""Egress disiplini: kabuk-ici ag trafigi icin policy yardimcilari (pure).

Gozlem (ApexCore session, 2026-09-16): agent MCP rate-limit'ini `bash` icinden
kendi yazdigi `nohup` fuzz scriptleriyle deldi (~200 req/s, ~1M istek).
Gate komut metnini ZATEN goruyor — bu modul iki kural uretir:

1. background_network_jobs: `nohup`/`&` + ag araci/URL iceren komutlar
   gozetimsiz calisamaz (varsayilan: onay gerekir).
2. fuzz_budget: komuttaki wordlist satir sayisi x hedef sayisi tahmini
   butceyi asarsa blok (kontrol-dosya disiplini mesajiyla).

Agirlikli olarak heuristic'tir; supheli durumda fail-open degil,
supheli-arka-plan durumunda onaya duser (guvenli taraf).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse

URL_RE = re.compile(r"(?P<url>(?:https?|wss?)://[^\s'\"<>]+)", re.I)

BACKGROUND_TOKENS_RE = re.compile(r"\b(?:nohup|setsid|disown)\b", re.I)

NETWORK_TOOL_RE = re.compile(
    r"\b(?:curl|wget|aria2c|python3?|ffuf|gobuster|feroxbuster|dirsearch|"
    r"nuclei|masscan|rustscan|nmap|nikto|sqlmap|ghauri|hydra|medusa|"
    r"wpscan|amass|subfinder|dnsenum|requests|urllib|httpx|aiohttp)\b",
    re.I,
)

# Dinleyici komutlar egress degildir (yerel test sunucusu vb.).
LISTENER_RE = re.compile(
    r"http\.server|php\s+-S|\bnc\b[^-]*-[a-z]*l|ncat[^-]*-[a-z]*l|"
    r"\bsocat\b|listener|BurpSuite|mitmproxy|wiremock",
    re.I,
)

WORDLIST_NAME_RE = re.compile(
    r"(?i)(?:seclists|SecLists|wordlists?)/\S*\.txt\b|"
    r"\b(?:raft-[a-z-]*|common|big|medium|small|directory-list-[\w.-]*|"
    r"LinuxFileList[\w.]*|rockyou[\w.]*|all\.txt|api-endpoints[\w.]*)\.txt\b"
)

SCRIPT_REF_RE = re.compile(r"(?P<path>[^\s'\";|&<>]+\.(?:py|sh|pl|rb))\b")

# URL taramasi icin script basligi (asiri okumayi engelle).
SCRIPT_HEAD_BYTES = 65536
# Satir sayimi icin tek dosya ust siniri.
WORDLIST_READ_CAP_BYTES = 200 * 1024 * 1024

DEFAULT_FUZZ_BUDGET = 5000


def _strip_quoted_spans(command: str) -> str:
    """Tirnakli alanlari koruyarak `&` tespitini sadelestir (kaba ama yeterli)."""
    out: list[str] = []
    quote: str | None = None
    escaped = False
    for ch in command:
        if escaped:
            escaped = False
            out.append(" ")
            continue
        if ch == "\\":
            escaped = True
            out.append(" ")
            continue
        if quote:
            out.append(" ")
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(" ")
            continue
        out.append(ch)
    return "".join(out)


def is_backgrounded(command: str) -> bool:
    """Komut arka-plana atiliyor mu (`nohup`/`setsid`/`&`)?"""
    if BACKGROUND_TOKENS_RE.search(command or ""):
        return True
    bare = _strip_quoted_spans(command or "")
    # `&&`, `2>&1`, `>&file` arka-plan degildir.
    bare = bare.replace("&&", "  ")
    bare = re.sub(r"\d*>&\S*", " ", bare)
    return "&" in bare


def _script_urls(command: str) -> list[str]:
    """Komutta referans verilen .py/.sh dosyalarinin basliginda URL ara."""
    urls: list[str] = []
    for match in SCRIPT_REF_RE.finditer(command or ""):
        candidate = Path(match.group("path"))
        paths = [candidate]
        if not candidate.is_absolute():
            paths.append(Path.cwd() / candidate)
            paths.append(Path(os.environ.get("CCO_WORKDIR", "~/cco-work")).expanduser() / candidate.name)
        for path in paths:
            try:
                if path.is_file() and path.stat().st_size <= 10 * 1024 * 1024:
                    head = path.read_bytes()[:SCRIPT_HEAD_BYTES].decode(
                        "utf-8", errors="ignore")
                    urls.extend(m.group("url") for m in URL_RE.finditer(head))
                    break
            except OSError:
                continue
    return urls


def is_background_network_job(command: str, urls: list[str] | None = None) -> bool:
    """Gozetimsiz ag isi mi? `nohup python fuzz.py &` + (URL|ag araci)."""
    command = command or ""
    if not is_backgrounded(command):
        return False
    if LISTENER_RE.search(command):
        return False
    if urls:
        return True
    if NETWORK_TOOL_RE.search(command):
        # Ag araci var ama hedef yoksa: script icinde URL olabilir.
        if _script_urls(command):
            return True
        # `curl URL &` gibi acik hedef zaten urls'te olurdu; burada
        # hedefsiz ag araci (or. `nmap ... &` IP ile) da sayilir.
        return True
    return bool(_script_urls(command))


def find_wordlists(command: str) -> list[str]:
    """Komuttaki wordlist referanslarini dosya yoluna coz (varsa)."""
    found: list[str] = []
    command = command or ""
    for match in WORDLIST_NAME_RE.finditer(command):
        start, end = match.span()
        # Eslesme yolun parcasi olabilir (`/tmp/x/big.txt` -> `big.txt`);
        # tam whitespace-token'a genislet.
        while start > 0 and command[start - 1] not in " \t\n'\";|&<>":
            start -= 1
        while end < len(command) and command[end] not in " \t\n'\";|&<>":
            end += 1
        token = command[start:end]
        candidates = [Path(token)]
        if not Path(token).is_absolute():
            candidates.append(Path.cwd() / token)
            candidates.append(Path("/usr/share/seclists") / token)
            candidates.append(Path("/usr/share/wordlists") / token)
            # `raft-large-files.txt` gibi ciplak adlar icin yaygin alt dizinler.
            for sub in ("Discovery/Web-Content", "Discovery/DNS",
                        "Passwords", "Fuzzing", "Discovery/Web-Content"):
                candidates.append(Path("/usr/share/seclists") / sub / token)
        for path in candidates:
            try:
                if path.is_file():
                    found.append(str(path))
                    break
            except OSError:
                continue
    # Tekrarsiz, sirayi koru.
    return list(dict.fromkeys(found))


def _count_lines(path: str) -> int:
    try:
        size = os.path.getsize(path)
        if size > WORDLIST_READ_CAP_BYTES:
            return -1
        count = 0
        with open(path, "rb") as handle:
            while chunk := handle.read(1024 * 1024):
                count += chunk.count(b"\n")
        return count
    except OSError:
        return -1


_PROXY_FLAG_RE = re.compile(
    r"(?:^|[\s;|&])(?:-x|--proxy|-http-proxy|--http-proxy|-proxy)\s*=?\s*"
    r"(?P<proxy>'[^']*'|\"[^\"]*\"|\S+)"
)
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _loopback_proxy_urls(command: str) -> set[str]:
    """`-x` loopback proxy URL'leri: tasiyici, fuzz hedefi degil (carpima katilmaz)."""
    out: set[str] = set()
    for match in _PROXY_FLAG_RE.finditer(command or ""):
        val = match.group("proxy").strip().strip("'\"").rstrip("/")
        try:
            host = urlparse(val).hostname
        except ValueError:
            continue
        if host and host.lower() in _LOOPBACK_HOSTS:
            out.add(val)
    return out


def estimate_fuzz_requests(command: str, urls: list[str] | None = None) -> tuple[int, list[str]]:
    """Tahmini istek sayisi = wordlist satirlari x hedef sayisi.

    Hedef yoksa (yerel `wc -l` vb.) 0 doner — yalnizca uzak fuzz sayilir.
    Dosya okunamazsa tahmine katilmaz (fail-open).
    Loopback proxy (`-x 127.0.0.1`) carpima katilmaz; uzak proxy sayilir.
    """
    loopbacks = _loopback_proxy_urls(command)
    urls = [u for u in (urls or []) if u.rstrip("/") not in loopbacks]
    targets = max(1, len(urls))
    if not (urls or []):
        # Hedefsiz komut: script icinde URL olabilir (nohup fuzz.py).
        if not _script_urls(command):
            return 0, []
        targets = 1
    total = 0
    details: list[str] = []
    for path in find_wordlists(command):
        lines = _count_lines(path)
        if lines < 0:
            continue
        total += lines * targets
        details.append(f"{Path(path).name}: {lines} satir x {targets} hedef")
    return total, details


def fuzz_budget(program_policy: dict | None = None) -> int:
    """Tek cagri fuzz butcesi: env override > program policy > varsayilan."""
    override = (os.environ.get("CCO_FUZZ_BUDGET") or "").strip()
    if override:
        try:
            return max(1, int(override))
        except ValueError:
            pass
    try:
        return max(1, int((program_policy or {}).get(
            "fuzz_max_requests_per_call", DEFAULT_FUZZ_BUDGET)))
    except (TypeError, ValueError):
        return DEFAULT_FUZZ_BUDGET


def background_jobs_mode(program_policy: dict | None = None) -> str:
    """'allow' | 'approval' (varsayilan) | 'deny'."""
    override = (os.environ.get("CCO_BACKGROUND_NET_JOBS") or "").strip().lower()
    if override in {"allow", "approval", "deny"}:
        return override
    raw = str((program_policy or {}).get("background_network_jobs", "approval"))
    raw = raw.strip().lower()
    return raw if raw in {"allow", "approval", "deny"} else "approval"
