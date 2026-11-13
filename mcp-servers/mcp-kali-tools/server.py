#!/usr/bin/env python3
"""
MCP Kali Tools Server — Kali Linux güvenlik araçlarını HackerAgent orkestratörüne expose eder.
FastMCP kullanarak nmap, gobuster, ffuf, sqlmap, nikto, hydra ve daha fazlasını
MCP tool'ları olarak sunar. Herhangi bir MCP-uyumlu istemciyle çalışır.

Kullanım:
    python server.py                          # stdio transport (varsayılan)
    python server.py --transport streamable-http --port 8080  # HTTP transport
"""

import subprocess
import select
import shlex
import os
import json
import sqlite3
import tempfile
import time
import re
import uuid
import asyncio
import base64
import fnmatch
import hashlib
import importlib.util
import sys
import requests  # Used for Hybrid Orchestration (Phase C)
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from mcp.server.fastmcp import FastMCP

# CCO veri dizini — CCO_HOME env variable veya ~/.cco
CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
os.makedirs(CCO_HOME, exist_ok=True)

_SURFACE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp-memory-server"))
if _SURFACE_DIR not in sys.path:
    sys.path.insert(0, _SURFACE_DIR)
try:
    from cco_surface_core.crawl import HAS_PLAYWRIGHT, crawl_site, playwright_missing_msg
    from cco_surface_core.extract import extract_html, extract_js, extract_js_calls, extract_robots, extract_sitemap, find_spec_urls, is_sitemap_index
    from cco_surface_core.normalize import discovery_link_skip_reason, normalize_url, params_from_url, same_host
    from cco_surface_core.parsers import (
        parse_browser_crawl, parse_ffuf, parse_gau, parse_nuclei, parse_openapi, parse_sqlmap, parse_xhr, parse_zap,
    )
    from cco_surface_core.probe import fingerprint_response
    from cco_surface_core.wire import SurfaceBlocked, current_surface_guard, guarded_get
    from cco_surface_core.store import artifact_dir, ingest_records, memory_db_path, next_work, query_surface, write_artifact
    from cco_surface_core.wordlist import compile_wordlist, write_wordlist
    from cco_surface_core.zap import run_zap_map, zap_missing_msg
    from cco_surface_core.zap_snapshot import import_zap_snapshot
    HAS_SURFACE = True
except Exception:
    HAS_SURFACE = False
    HAS_PLAYWRIGHT = False
    class SurfaceBlocked(RuntimeError):
        pass

    def current_surface_guard():
        return None

    crawl_site = playwright_missing_msg = is_sitemap_index = None
    extract_html = extract_js = extract_js_calls = extract_robots = extract_sitemap = find_spec_urls = None
    discovery_link_skip_reason = normalize_url = params_from_url = same_host = None
    parse_browser_crawl = parse_xhr = parse_zap = None
    parse_ffuf = parse_gau = parse_nuclei = parse_openapi = parse_sqlmap = None
    fingerprint_response = None
    artifact_dir = ingest_records = memory_db_path = next_work = query_surface = write_artifact = None
    compile_wordlist = write_wordlist = None
    run_zap_map = zap_missing_msg = import_zap_snapshot = None

_POSTEX_DIR = os.path.abspath(os.path.dirname(__file__))
if _POSTEX_DIR not in sys.path:
    sys.path.insert(0, _POSTEX_DIR)
try:
    from cco_postex_core.parsers import parse_linpeas, parse_winpeas
    HAS_POSTEX = True
except Exception:
    HAS_POSTEX = False
    parse_linpeas = parse_winpeas = None

try:
    from cco_js_core.compose import compose_js_routes as compose_js_routes_core
    HAS_JS_CORE = True
except Exception:
    HAS_JS_CORE = False
    compose_js_routes_core = None

# Arkaplan daemon PIDs kaydı
daemon_processes = {}

# Server oluştur
mcp = FastMCP(
    "kali-tools",
    instructions="Kali Linux güvenlik araçlarına MCP erişimi — pentest, CTF ve bug bounty operasyonları için"
)

# ============================================================
# GÜVENLİK KATMANI — Command Validation & API Key Security
# ============================================================

# Kesinlikle engellenen komutlar/kalıplar
BLOCKED_COMMANDS = [
    "rm -rf /",
    "rm -rf /*",
    "dd if=/dev/zero",
    "dd if=/dev/random",
    "mkfs.",
    ":(){:|:&};:",     # Fork bomb
    "shutdown",
    "reboot",
    "poweroff",
    "init 0",
    "init 6",
    "chmod -R 777 /",
    "chown -R",
    "> /dev/sda",
    "mv / ",
    "wget -O- | sh",
    "wget -O- | bash",
    "curl | sh",
    "curl | bash",
]

# Regex ile tespit edilen tehlikeli patternler
DANGEROUS_PATTERNS = [
    r">/dev/sd[a-z]",                          # Disk overwrite
    r"\|\s*base64\s+-d\s*\|\s*(sh|bash)",     # Encoded shell execution
    r"python[23]?\s+-c\s*['\"].*__import__.*os.*system",  # Python reverse shell via import
    r"echo\s+.*\|\s*xxd\s+-r\s*\|\s*(sh|bash)",  # Hex encoded shell
    r"rm\s+-[rf]+\s+/[a-z]",                   # Recursive delete on system dirs
    r">(\s*)/etc/(passwd|shadow|sudoers)",      # System file overwrite
    r"crontab\s+-r",                            # Delete all crontabs
    r"iptables\s+-F",                            # Flush all firewall rules  
]

def validate_command(cmd: str) -> tuple:
    """Komutu güvenlik kontrolünden geçir.
    Returns: (is_safe: bool, reason: str)
    """
    cmd_lower = cmd.lower().strip()
    
    # Bloke edilen komut kontrolü
    for blocked in BLOCKED_COMMANDS:
        if blocked.lower() in cmd_lower:
            return False, f"🚫 ENGELLENDİ: '{blocked}' destructive komut yasak. Bu komut sisteme kalıcı hasar verebilir."
    
    # Regex pattern kontrolü
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return False, f"🚫 ENGELLENDİ: Tehlikeli pattern tespit edildi ({pattern}). Komut güvenlik gerekçesiyle reddedildi."
    
    return True, "OK"


def get_api_key_secure() -> str:
    """OpenRouter API key'i güvenli hiyerarşiyle al:
    1. Environment variable (en güvenli)
    2. Python keyring (OS keychain)
    3. settings.json (fallback)
    """
    # 1. Environment variable (önce OPENROUTER_API_KEY, sonra ANTHROPIC_AUTH_TOKEN)
    key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
    if key:
        return key
    
    # 2. Keyring (OS keychain entegrasyonu)
    try:
        import keyring
        key = keyring.get_password("cco", "openrouter")
        if key:
            return key
    except (ImportError, Exception):
        pass
    
    # 3. config.yaml / settings.json (fallback — en az güvenli)
    #    Önce yeni konum (~/.cco/config.yaml), sonra eski (~/.claude/settings.json)
    settings_candidates = [
        os.path.join(CCO_HOME, "config.yaml"),
        os.path.join(CCO_HOME, "settings.json"),
        os.path.expanduser("~/.claude/settings.json"),  # legacy
    ]
    for settings_path in settings_candidates:
        try:
            if os.path.exists(settings_path):
                if settings_path.endswith(".yaml") or settings_path.endswith(".yml"):
                    try:
                        import yaml
                        with open(settings_path, "r") as f:
                            data = yaml.safe_load(f) or {}
                        key = (
                            data.get("llm", {}).get("openrouter_api_key")
                            or data.get("openrouter_api_key", "")
                        )
                        if key:
                            return key
                    except ImportError:
                        continue
                else:
                    with open(settings_path, 'r') as f:
                        settings = json.load(f)
                        key = settings.get("openrouter_api_key", "")
                        if key:
                            return key
        except Exception:
            pass

    return ""


# ============================================================
# HUMAN-IN-THE-LOOP APPROVAL SİSTEMİ
# ============================================================

APPROVAL_DIR = os.path.join(CCO_HOME, "approvals")

def _ensure_approval_dir():
    os.makedirs(APPROVAL_DIR, exist_ok=True)

# ============================================================
# YARDIMCI FONKSİYONLAR
# ============================================================

def _quote_extra_args(extra_args: str) -> str:
    """Quote each extra-args token so shell metacharacters stay literal.

    Defence in depth behind the policy gate: even a token the gate let
    through cannot become shell syntax in the composed command string.
    Unparseable input degrades to one literal argument, never raw shell.
    """
    try:
        tokens = shlex.split(extra_args or "")
    except ValueError:
        return shlex.quote(extra_args or "")
    return " ".join(shlex.quote(token) for token in tokens)


def run_command(cmd: str, timeout: int = 300, cwd: str = None, retries: int = 1) -> dict:
    """Shell komutu çalıştır ve sonucu döndür. Ağ hatalarına karşı retry mekanizması içerir."""
    attempt = 0
    last_exception = ""
    
    while attempt <= retries:
        if attempt > 0:
            time.sleep(2) # Hata sonrası kısa bekleme

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd
            )
            
            # Syntax hatalarında anlık geri bildirim için (Tool başarısız olursa orkestratör hatayı görsün)
            success = result.returncode == 0
            if not success and "usage" in result.stderr.lower():
                return {
                    "stdout": result.stdout,
                    "stderr": f"SÖZDİZİMİ HATASI (Syntax/Usage): Lütfen argümanları düzeltin.\nDetay: {result.stderr}",
                    "returncode": result.returncode,
                    "success": False
                }
                
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": success
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"TIMEOUT: Komut {timeout} saniye içinde tamamlanmadı. Daha yüksek timeout verin.",
                "returncode": -1,
                "success": False
            }
        except Exception as e:
            last_exception = str(e)
            attempt += 1

    return {
        "stdout": "",
        "stderr": f"HATA: Komut {retries+1} denemede de başarısız oldu. Son hata: {last_exception}",
        "returncode": -1,
        "success": False
    }

def format_output(result: dict) -> str:
    """Komut çıktısını formatlı döndür."""
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        if output:
            output += "\n\n--- STDERR ---\n"
        output += result["stderr"]
    if not output:
        output = f"Komut tamamlandı (return code: {result['returncode']})"
    return output


# ============================================================
# FUZZ GUARDRAILS (F1/F2/F3) — MCP fuzz yolu bash bütçesini
# bypass etmesin diye tahmin + erken durdurma burada da var.
# ============================================================

_FUZZ_BUDGET_DEFAULT = 5000
_FUZZ_EARLY_STOP_DEFAULT = 1000
_FUZZ_COMMON_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
_ARJUN_DEFAULT_WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config", "param-top80.txt")


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _program_fuzz_budget() -> int | None:
    """Aktif program profilindeki fuzz_max_requests_per_call (yoksa None)."""
    candidates = []
    env_path = (os.environ.get("CCO_PROGRAM_POLICY_FILE") or "").strip()
    if env_path:
        # Explicit policy file is authoritative (PolicyEngine discovery ile ayni kural);
        # repo program-policy.json'a dusulmez.
        candidates.append(os.path.expanduser(env_path))
    else:
        candidates.append(os.path.join(_repo_root(), ".codex", "program-policy.json"))
    for path in candidates:
        try:
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            continue
        value = raw.get("fuzz_max_requests_per_call")
        if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
            return value
    return None


def _fuzz_budget() -> int:
    """Tek cagri fuzz butcesi: env override > program profili > varsayilan."""
    try:
        override = (os.environ.get("CCO_FUZZ_BUDGET", "") or "").strip()
        if override:
            return max(1, int(override))
    except ValueError:
        pass
    profile = _program_fuzz_budget()
    if profile is not None:
        return profile
    return _FUZZ_BUDGET_DEFAULT


def _count_file_lines(path: str) -> int:
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return -1


def _extra_wordlists(extra_args: str) -> list[str]:
    return re.findall(r"(?:^|\s)-w\s+(\S+)", extra_args or "")


def _fuzz_request_estimate(wordlist: str, extensions: str = "", extra_args: str = "") -> tuple[int, int]:
    """(satir, tahmini-istek) doner; okunamazsa (-1, -1)."""
    lines = _count_file_lines(wordlist)
    if lines < 0:
        return -1, -1
    for extra in _extra_wordlists(extra_args):
        extra_lines = _count_file_lines(extra.strip("'\""))
        if extra_lines > 0:
            lines += extra_lines
    mult = 1
    if extensions:
        mult += len([e for e in str(extensions).split(",") if e.strip()])
    return lines, lines * mult


def _fuzz_budget_refusal(wordlist: str, lines: int, total: int, budget: int) -> str:
    return (
        f"REFUSED (fuzz-budget): estimated ~{total} requests "
        f"({os.path.basename(wordlist)}: {lines} lines) exceeds the per-call fuzz budget ({budget}). "
        "First validate the vector against a KNOWN control file, then chunk small->medium with evidence, "
        "e.g. `head -1000 <wordlist> > chunk1.txt` or `split -n l/10 <wordlist> chunk_` and call ffuf_fuzz per chunk."
    )


_FFUF_PROGRESS_RE = re.compile(r"Progress: \[(\d+)/(\d+)\]")
_FFUF_MATCH_RE = re.compile(r"\[Status: \d+")


def _run_ffuf_supervised(cmd: str, timeout: int, early_stop: int) -> dict:
    """ffuf'u akis izleyerek calistir; early_stop istekte 0 eslesme varsa oldur."""
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
    except Exception as exc:
        return {"stdout": "", "stderr": f"HATA: ffuf başlatılamadı: {exc}",
                "returncode": -1, "success": False, "stopped_early": False}
    for stream in (proc.stdout, proc.stderr):
        try:
            os.set_blocking(stream.fileno(), False)
        except OSError:
            pass
    out_chunks: list[str] = []
    err_chunks: list[str] = []
    stopped_early = False
    timed_out = False
    done = 0
    matches = 0

    def drain(wait: float) -> None:
        try:
            ready, _, _ = select.select([proc.stdout, proc.stderr], [], [], wait)
        except (OSError, ValueError):
            return
        for stream in ready:
            try:
                data = os.read(stream.fileno(), 65536).decode("utf-8", "replace")
            except OSError:
                continue
            if not data:
                continue
            if stream is proc.stdout:
                out_chunks.append(data)
            else:
                err_chunks.append(data)

    def parse() -> None:
        nonlocal done, matches
        for match in _FFUF_PROGRESS_RE.finditer("".join(err_chunks)[-2000:]):
            done = max(done, int(match.group(1)))
        matches = len(_FFUF_MATCH_RE.findall("".join(out_chunks)))

    while proc.poll() is None:
        if time.monotonic() - start >= timeout:
            timed_out = True
            break
        drain(0.5)
        parse()
        if early_stop > 0 and done >= early_stop and matches == 0:
            # Yaris korumasi: eslesme satiri yoldayken oldurme, bir kez daha dene.
            drain(2.0)
            parse()
            if matches == 0:
                stopped_early = True
                break
    try:
        if stopped_early or timed_out:
            proc.kill()
        rest_out, rest_err = proc.communicate(timeout=10)
    except Exception:
        try:
            proc.kill()
        except OSError:
            pass
        rest_out, rest_err = "", ""
    stdout = "".join(out_chunks) + (rest_out or "")
    stderr = "".join(err_chunks) + (rest_err or "")
    matches = len(_FFUF_MATCH_RE.findall(stdout))
    if stopped_early:
        stderr += (
            f"\nEARLY-STOP: killed after {done} requests with 0 matches (all filtered). "
            "Hypothesis looks dead — do NOT re-run a bigger wordlist. Pivot (architecture review, "
            "JS analysis, auth flow) or justify the retry in one line."
        )
        return {"stdout": stdout, "stderr": stderr, "returncode": proc.returncode,
                "success": False, "stopped_early": True}
    if timed_out:
        stderr += f"\nTIMEOUT: ffuf {timeout} saniye içinde tamamlanmadı ({done} istek, {matches} eşleşme)."
        return {"stdout": stdout, "stderr": stderr, "returncode": -1,
                "success": False, "stopped_early": False}
    return {"stdout": stdout, "stderr": stderr, "returncode": proc.returncode,
            "success": proc.returncode == 0, "stopped_early": False}


def _surface_auto_ingest_enabled() -> bool:
    return os.environ.get("CCO_SURFACE_AUTO_INGEST", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def _target_from_url(url: str) -> str:
    cleaned = (url or "").replace("FUZZ", "x")
    parsed = urlparse(cleaned if "://" in cleaned else f"http://{cleaned}")
    return parsed.hostname or cleaned


def _ingest_surface_records(records, target: str):
    if not HAS_SURFACE or not _surface_auto_ingest_enabled() or not records:
        return None
    try:
        return ingest_records(records, target=target, db_path=memory_db_path())
    except Exception as exc:
        return {"error": str(exc)}


def _surface_summary(ingest, artifact: str = "", extra=None) -> str:
    payload = {"surface_artifact": artifact}
    if ingest:
        payload["surface_ingest"] = ingest
    if extra:
        payload.update(extra)
    return "\n[surface] " + json.dumps(payload, ensure_ascii=False)


def _parse_extra_headers(headers=None, cookie: str = "") -> dict[str, str]:
    merged: dict[str, str] = {"User-Agent": "CCO/2.0 SurfaceDiscovery"}
    if isinstance(headers, dict):
        for k, v in headers.items():
            if k:
                merged[str(k).strip()] = str(v).strip()
    elif isinstance(headers, str) and headers.strip():
        raw = headers.strip()
        if raw.startswith("{"):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    for k, v in parsed.items():
                        if k:
                            merged[str(k).strip()] = str(v).strip()
            except Exception:
                pass
        else:
            for chunk in re.split(r"[\r\n;]+", raw):
                if ":" in chunk:
                    k, v = chunk.split(":", 1)
                    if k.strip():
                        merged[k.strip()] = v.strip()
    if cookie and str(cookie).strip():
        existing_cookie_key = next((k for k in merged if k.lower() == "cookie"), None)
        if not existing_cookie_key:
            merged["Cookie"] = str(cookie).strip()
    return merged


def _http_get(url: str, timeout: int = 12, headers=None, cookie: str = ""):
    req_headers = _parse_extra_headers(headers=headers, cookie=cookie)
    proxies = None
    if globals().get("_rate_limit_config", {}).get("configured"):
        delay = float(_rate_limit_config.get("current_delay") or 0.0)
        if delay > 0:
            time.sleep(min(delay, 2.0))
        proxy = str(_rate_limit_config.get("proxy") or "").strip()
        if proxy:
            proxies = {"http": proxy, "https": proxy}
    if current_surface_guard():
        return guarded_get(url, headers=req_headers, timeout=timeout,
                           proxies=proxies, sender=requests.get)
    response = requests.get(
        url, timeout=timeout, verify=False, allow_redirects=True, headers=req_headers, proxies=proxies
    )
    return response


# ============================================================
# ASİNKRON EXECUTION ENGİNE (v2.0 — Phase 3)
# ============================================================

async def run_command_async(cmd: str, timeout: int = 300, cwd: str = None) -> dict:
    """Asenkron shell komutu çalıştır."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "stdout": stdout.decode('utf-8', errors='replace'),
                "stderr": stderr.decode('utf-8', errors='replace'),
                "returncode": proc.returncode,
                "success": proc.returncode == 0
            }
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {"stdout": "", "stderr": f"TIMEOUT: {timeout}s", "returncode": -1, "success": False}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "success": False}


def _run_parallel(coroutines):
    """Async coroutine'leri senkron kontekste çalıştır."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, asyncio.gather(*coroutines)).result()
        else:
            return loop.run_until_complete(asyncio.gather(*coroutines))
    except RuntimeError:
        return asyncio.run(asyncio.gather(*coroutines))


@mcp.tool()
def parallel_recon(
    target: str,
    scan_types: str = "nmap,ffuf,whatweb,nuclei",
    timeout: int = 300
) -> str:
    """
    Birden fazla keşif aracını PARALEL çalıştır (4x hızlanma!).
    
    Args:
        target: Hedef IP/domain/URL
        scan_types: Virgülle ayrılmış araç listesi
                    Desteklenen: nmap, ffuf, whatweb, nuclei, subfinder, wafw00f, nikto, dirb
        timeout: Her araç için zaman aşımı (saniye)
    """
    task_map = {
        "nmap": f"nmap -sC -sV -T4 --top-ports 1000 {shlex.quote(target)}",
        "ffuf": f"ffuf -u http://{shlex.quote(target)}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -c -t 50 2>/dev/null",
        "whatweb": f"whatweb -a 3 http://{shlex.quote(target)} 2>/dev/null",
        "nuclei": f"nuclei -u http://{shlex.quote(target)} -severity critical,high -silent 2>/dev/null",
        "subfinder": f"subfinder -d {shlex.quote(target)} -silent 2>/dev/null",
        "wafw00f": f"wafw00f http://{shlex.quote(target)} 2>/dev/null",
        "nikto": f"nikto -h http://{shlex.quote(target)} -maxtime 120s 2>/dev/null",
        "dirb": f"dirb http://{shlex.quote(target)} /usr/share/dirb/wordlists/common.txt -S 2>/dev/null",
    }
    
    tools = [t.strip() for t in scan_types.split(",") if t.strip() in task_map]
    if not tools:
        return f"HATA: Geçerli araç bulunamadı. Desteklenen: {', '.join(task_map.keys())}"
    
    import time as _time
    start = _time.time()
    
    coroutines = [run_command_async(task_map[tool], timeout=timeout) for tool in tools]
    results = _run_parallel(coroutines)
    
    elapsed = _time.time() - start
    
    output = f"⚡ PARALEL RECON TAMAMLANDI ({len(tools)} araç, {elapsed:.1f}s)\n{'='*60}\n"
    for tool, result in zip(tools, results):
        status = "✓" if result["success"] else "✗"
        output += f"\n{'─'*50}\n[{status}] {tool.upper()}\n{'─'*50}\n"
        if result["stdout"]:
            # Çıktıyı makul uzunlukta tut
            lines = result["stdout"].strip().split("\n")
            if len(lines) > 50:
                output += "\n".join(lines[:50]) + f"\n... ({len(lines)-50} satır daha)\n"
            else:
                output += result["stdout"].strip() + "\n"
        if result["stderr"] and not result["success"]:
            output += f"STDERR: {result['stderr'][:200]}\n"
    
    output += f"\n{'='*60}\n⏱️ Toplam süre: {elapsed:.1f}s (sıralı tahmini: ~{elapsed * len(tools):.0f}s)\n"
    return output

# ============================================================
# NETWORK TARAMA ARAÇLARI
# ============================================================

@mcp.tool()
def nmap_scan(
    target: str,
    scan_type: str = "default",
    ports: str = "",
    scripts: str = "",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    Nmap ile port ve servis taraması yap.
    
    Args:
        target: Hedef IP/domain/CIDR
        scan_type: 'default' (-sC -sV), 'quick' (-T4 --top-ports 100), 
                   'full' (-p- -T4), 'udp' (-sU --top-ports 50),
                   'vuln' (--script=vuln), 'aggressive' (-A -T4),
                   'stealth' (-sS -T2)
        ports: Özel port belirtimi (ör: '80,443,8080' veya '1-1000')
        scripts: NSE scriptleri (ör: 'http-enum,http-headers')
        extra_args: Ek nmap argümanları
        timeout: Zaman aşımı (saniye)
    """
    scan_flags = {
        "default": "-sC -sV",
        "quick": "-T4 --top-ports 100 -sV",
        "full": "-p- -T4 --min-rate=1000",
        "udp": "-sU --top-ports 50 -T4",
        "vuln": "--script=vuln",
        "aggressive": "-A -T4",
        "stealth": "-sS -T2 -Pn"
    }
    
    flags = scan_flags.get(scan_type, scan_flags["default"])
    cmd = f"nmap {flags}"
    
    if ports:
        cmd += f" -p {ports}"
    if scripts:
        cmd += f" --script={scripts}"
    if extra_args:
        cmd += f" {extra_args}"
    
    cmd += f" {target}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def masscan_scan(
    target: str,
    ports: str = "1-65535",
    rate: int = 1000,
    extra_args: str = ""
) -> str:
    """
    Masscan ile ultra hızlı port taraması yap.
    
    Args:
        target: Hedef IP/CIDR
        ports: Port aralığı
        rate: Paket gönderme hızı (pps)
        extra_args: Ek argümanlar
    """
    cmd = f"masscan -p{ports} --rate={rate} {extra_args} {target}"
    result = run_command(cmd, timeout=300)
    return format_output(result)

# ============================================================
# WEB KEŞİF ARAÇLARI
# ============================================================

@mcp.tool()
def arjun_param_discover(
    url: str,
    method: str = "GET",
    headers: str = "",
    wordlist: str = "",
    timeout: int = 120,
) -> str:
    """Arjun ile gizli HTTP parametre kesfi (OpenAPI'si olmayan uclar icin).

    Yansima/yanit yoksa parametre ADINI tahmin etme — kesfet. Varsayilan
    top-80 liste (~80 istek, butce dostu). Bulunan her parametreyi XSS/SQLi/
    redirect/IDOR probuyla test et; 403 veren filtrede evolve varyanti dene.
    Hafif yerlesik alternatif: web-advanced.api_param_discover (binary yok).

    Args:
        url: Hedef URL (or: http://hedef/bankportal/notice)
        method: GET veya POST
        headers: Ek headerlar ('H: v' formatinda, ';' ile ayir)
        wordlist: Ozel wordlist yolu (bos: config/param-top80.txt)
        timeout: Zaman asimi sn (varsayilan 120)
    """
    wl = wordlist or _ARJUN_DEFAULT_WORDLIST
    try:
        with open(wl, "r", encoding="utf-8", errors="replace") as fh:
            lines = sum(1 for ln in fh if ln.strip())
    except OSError:
        return f"ERROR: wordlist unreadable: {wl}."
    budget = _fuzz_budget()
    if lines > budget:
        return _fuzz_budget_refusal(wl, lines, lines, budget)
    if run_command("which arjun 2>/dev/null", timeout=5).get("returncode") != 0:
        return "ERROR: arjun kurulu degil."
    out_path = os.path.join(tempfile.gettempdir(), f"arjun-{uuid.uuid4().hex}.json")
    cmd = (f"arjun -u {shlex.quote(url)} -w {shlex.quote(wl)} "
           f"-m {shlex.quote(method or 'GET')} -oJ {shlex.quote(out_path)} "
           f"-t 5 -T 10 -q")
    if headers:
        cmd += f" --headers {shlex.quote(headers)}"
    res = run_command(cmd, timeout=timeout)
    found = []
    try:
        if os.path.exists(out_path):
            data = json.load(open(out_path, "r", encoding="utf-8"))
            params = data.get("params", data) if isinstance(data, dict) else data
            if isinstance(params, dict):
                found = sorted(params.keys())
            elif isinstance(params, list):
                found = sorted(str(p) for p in params)
    except (OSError, ValueError):
        found = []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
    if not found and not res.get("success"):
        return f"arjun calisamadi (rc={res.get('returncode')}): {(res.get('stderr') or '')[:400]}"
    return json.dumps({
        "url": url, "method": method, "wordlist_lines": lines,
        "found_params": found,
        "next": ("Bulunan parametrelere XSS/SQLi/redirect problari at; yansima yoksa "
                 "evolve_payload ile encode zinciri dene. Hicbirsey yoksa POST+JSON "
                 "varyantini ve header/cookie konumlarini dene."),
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def ffuf_fuzz(
    url: str,
    wordlist: str = _FUZZ_COMMON_WORDLIST,
    method: str = "GET",
    extensions: str = "",
    headers: str = "",
    data: str = "",
    filter_code: str = "",
    match_code: str = "200,301,302,403",
    filter_size: str = "",
    extra_args: str = "",
    timeout: int = 180,
    calibrate: bool = True,
    early_stop: int = _FUZZ_EARLY_STOP_DEFAULT,
) -> str:
    """
    ffuf ile web fuzzing yap (dizin, parametre, vhost keşfi).

    Args:
        url: Hedef URL (FUZZ keyword'ünü kullan, ör: http://target.com/FUZZ)
        wordlist: Wordlist dosya yolu (varsayılan common.txt; büyük liste chunk'la)
        method: HTTP metodu (GET, POST, PUT)
        extensions: Dosya uzantıları (ör: 'php,html,txt,js')
        headers: Özel headerler (ör: 'Host: FUZZ.target.com')
        data: POST data (ör: 'user=admin&pass=FUZZ')
        filter_code: Filtrelenecek HTTP kodları (ör: '404,403')
        match_code: Eşleşecek HTTP kodları
        filter_size: Filtrelenecek response boyutu
        extra_args: Ek ffuf argümanları
        timeout: Zaman aşımı (MCP yanıt sınırının altında tutmak için en fazla 50 sn)
        calibrate: True iken özel filtre yoksa ffuf -ac (otomatik 404 kalibrasyonu)
        early_stop: Bu kadar istekte 0 eşleşme varsa öldür (0 = kapalı)
    """
    timeout = max(5, min(int(timeout or 0), 50))
    lines, total = _fuzz_request_estimate(wordlist, extensions, extra_args)
    budget = _fuzz_budget()
    if lines < 0:
        return f"ERROR: wordlist unreadable: {wordlist}. Provide an existing readable wordlist path."
    if total > budget:
        return _fuzz_budget_refusal(wordlist, lines, total, budget)
    cmd = f"ffuf -u {shlex.quote(url)} -w {shlex.quote(wordlist)}"
    
    if extensions:
        cmd += f" -e .{extensions.replace(',', ',.')}"
    if headers:
        cmd += f" -H {shlex.quote(headers)}"
    if method != "GET":
        cmd += f" -X {method}"
    if data:
        cmd += f" -d {shlex.quote(data)}"
    extra = extra_args or ""
    user_filter = bool(filter_code or filter_size) or bool(
        re.search(r"(^|\s)-(mc|fc|fs|fw|ac)\b", extra)
    )
    default_mc = "200,301,302,403"
    match_customized = bool(match_code) and match_code != default_mc
    if calibrate and not user_filter and not match_customized:
        cmd += " -ac"
    else:
        if filter_code:
            cmd += f" -fc {filter_code}"
        elif match_code:
            cmd += f" -mc {match_code}"
        if filter_size:
            cmd += f" -fs {filter_size}"
    if extra_args:
        cmd += f" {extra_args}"
    
    cmd += " -c"  # Renkli çıktı
    artifact = ""
    if HAS_SURFACE:
        artifact = os.path.join(artifact_dir(), f"ffuf-{uuid.uuid4().hex[:8]}.json")
        cmd += f" -of json -o {shlex.quote(artifact)}"

    if early_stop and early_stop > 0:
        result = _run_ffuf_supervised(cmd, timeout=timeout, early_stop=early_stop)
    else:
        result = run_command(cmd, timeout=timeout)
    output = format_output(result)
    if HAS_SURFACE and artifact and os.path.isfile(artifact):
        try:
            records = parse_ffuf(artifact, target=_target_from_url(url))
            ingest = _ingest_surface_records(records, _target_from_url(url))
            output += _surface_summary(ingest, artifact, extra={"hits": len(records)})
        except Exception as exc:
            output += _surface_summary({"error": str(exc)}, artifact)
    return output


@mcp.tool()
def gobuster_scan(
    url: str,
    mode: str = "dir",
    wordlist: str = _FUZZ_COMMON_WORDLIST,
    extensions: str = "",
    extra_args: str = "",
    timeout: int = 180
) -> str:
    """
    Gobuster ile dizin/DNS/VHost keşfi yap.

    Args:
        url: Hedef URL veya domain
        mode: 'dir' (dizin), 'dns' (subdomain), 'vhost' (virtual host)
        wordlist: Wordlist dosya yolu (varsayılan common.txt; büyük liste chunk'la)
        extensions: Dosya uzantıları (ör: 'php,html,txt')
        extra_args: Ek argümanlar
        timeout: Zaman aşımı (varsayılan 180 sn)
    """
    lines, total = _fuzz_request_estimate(wordlist, extensions, extra_args)
    budget = _fuzz_budget()
    if lines < 0:
        return f"ERROR: wordlist unreadable: {wordlist}. Provide an existing readable wordlist path."
    if total > budget:
        return _fuzz_budget_refusal(wordlist, lines, total, budget)
    cmd = f"gobuster {mode} -u {shlex.quote(url)} -w {wordlist}"
    
    if extensions and mode == "dir":
        cmd += f" -x {extensions}"
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def nikto_scan(
    target: str,
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    Nikto ile web server zafiyet taraması yap.
    
    Args:
        target: Hedef URL/IP
        extra_args: Ek nikto argümanları
        timeout: Zaman aşımı
    """
    cmd = f"nikto -h {shlex.quote(target)} {extra_args}"
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def whatweb_fingerprint(
    target: str,
    aggression: int = 3,
    extra_args: str = ""
) -> str:
    """
    WhatWeb ile web teknoloji fingerprinting yap.
    
    Args:
        target: Hedef URL
        aggression: Agresiflik seviyesi (1-4)
        extra_args: Ek argümanlar
    """
    cmd = f"whatweb -a {aggression} {shlex.quote(target)} {extra_args}"
    result = run_command(cmd)
    return format_output(result)


@mcp.tool()
def nuclei_scan(
    target: str,
    severity: str = "critical,high,medium",
    templates: str = "",
    tags: str = "",
    extra_args: str = "",
    timeout: int = 900
) -> str:
    """
    Nuclei ile template tabanlı zafiyet taraması yap.
    
    Args:
        target: Hedef URL
        severity: Severity filtresi (critical, high, medium, low, info)
        templates: Özel template yolu
        tags: Tag filtresi (ör: 'cve,sqli,xss')
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
    """
    cmd = f"nuclei -u {shlex.quote(target)} -severity {severity}"
    
    if templates:
        cmd += f" -t {templates}"
    if tags:
        cmd += f" -tags {tags}"
    if extra_args:
        cmd += f" {extra_args}"
    artifact = ""
    if HAS_SURFACE:
        artifact = os.path.join(artifact_dir(), f"nuclei-{uuid.uuid4().hex[:8]}.jsonl")
        cmd += f" -jsonl -o {shlex.quote(artifact)}"

    result = run_command(cmd, timeout=timeout)
    output = format_output(result)
    if HAS_SURFACE and artifact and os.path.isfile(artifact):
        try:
            records = parse_nuclei(artifact, target=_target_from_url(target))
            ingest = _ingest_surface_records(records, _target_from_url(target))
            output += _surface_summary(ingest, artifact, extra={"hits": len(records)})
        except Exception as exc:
            output += _surface_summary({"error": str(exc)}, artifact)
    return output

# ============================================================
# EXPLOITATION ARAÇLARI
# ============================================================

@mcp.tool()
def sqlmap_test(
    url: str = "",
    request_file: str = "",
    data: str = "",
    parameter: str = "",
    cookie: str = "",
    headers: str = "",
    level: int = 1,
    risk: int = 1,
    technique: str = "",
    tamper: str = "",
    action: str = "dbs",
    database: str = "",
    table: str = "",
    extra_args: str = "",
    timeout: int = 600,
    validation_id: str = "",
    allow_deepen: bool = False,
) -> str:
    """
    SQLMap ile SQL injection testi yap.
    
    Args:
        url: Hedef URL (parametre ile, ör: http://target.com/page?id=1)
        request_file: Burp/ZAP'tan kaydedilmiş request dosyası
        data: POST verisi (ör: 'user=admin&pass=test')
        parameter: Test edilecek parametre
        cookie: Cookie string
        headers: Ek headerler
        level: Test seviyesi (1-5)
        risk: Risk seviyesi (1-3)
        technique: Teknik (B:boolean, E:error, U:union, S:stacked, T:time, Q:inline)
        tamper: Tamper script'leri (ör: 'space2comment,between')
        action: 'dbs', 'tables', 'dump', 'os-shell', 'file-read'
        database: Veritabanı adı (tables/dump için)
        table: Tablo adı (dump için)
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
        validation_id: CONFIRMED SQLi validator id (zorunlu)
        allow_deepen: dump/os-shell/file-read için True (request_approval sonrası)
    """
    gate = _sqlmap_confirmed_gate(validation_id, allow_deepen=allow_deepen,
                                  action=action, options=extra_args, target=url)
    if not gate.get("ok"):
        return json.dumps({"ok": False, **gate, "tool": "sqlmap_test"}, ensure_ascii=False)

    cmd = "sqlmap --batch"
    
    if request_file:
        cmd += f" -r {request_file}"
    elif url:
        cmd += f" -u {shlex.quote(url)}"
    
    if data:
        cmd += f" --data={shlex.quote(data)}"
    if parameter:
        cmd += f" -p {parameter}"
    if cookie:
        cmd += f" --cookie={shlex.quote(cookie)}"
    if headers:
        cmd += f" --headers={shlex.quote(headers)}"
    if level > 1:
        cmd += f" --level={level}"
    if risk > 1:
        cmd += f" --risk={risk}"
    if technique:
        cmd += f" --technique={technique}"
    if tamper:
        cmd += f" --tamper={tamper}"
    
    # Action
    if action == "dbs":
        cmd += " --dbs"
    elif action == "tables":
        cmd += f" -D {database} --tables"
    elif action == "dump":
        cmd += f" -D {database} -T {table} --dump"
    elif action == "os-shell":
        cmd += " --os-shell"
    elif action == "file-read":
        cmd += f" --file-read={extra_args.split('=', 1)[1] if '=' in extra_args else '/etc/passwd'}"
    
    if extra_args and action != "file-read":
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def hydra_brute(
    target: str,
    service: str,
    username: str = "",
    username_list: str = "",
    password_list: str = "/usr/share/wordlists/rockyou.txt",
    port: int = 0,
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    Hydra ile brute-force saldırısı yap.
    
    Args:
        target: Hedef IP/domain
        service: Servis (ssh, ftp, http-post-form, mysql, rdp, smb, vnc, telnet)
        username: Tek kullanıcı adı
        username_list: Kullanıcı adı wordlist'i
        password_list: Şifre wordlist'i
        port: Özel port numarası
        extra_args: Ek argümanlar (http-post-form için form parametreleri)
        timeout: Zaman aşımı
    """
    cmd = "hydra"
    
    if username:
        cmd += f" -l {username}"
    elif username_list:
        cmd += f" -L {username_list}"
    
    cmd += f" -P {password_list}"
    
    if port:
        cmd += f" -s {port}"
    
    cmd += f" {target} {service}"
    
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)

# ============================================================
# SUBDOMAIN VE DNS ARAÇLARI
# ============================================================

@mcp.tool()
def subfinder_enum(
    domain: str,
    extra_args: str = ""
) -> str:
    """
    Subfinder ile subdomain enumeration yap.
    
    Args:
        domain: Hedef domain
        extra_args: Ek argümanlar
    """
    cmd = f"subfinder -d {domain} -silent {extra_args}"
    result = run_command(cmd, timeout=300)
    return format_output(result)


@mcp.tool()
def katana_crawl(
    url: str,
    depth: int = 2,
    headers: str = "",
    timeout: int = 300
) -> str:
    """
    Katana ile JS-aware crawl — endpoint envanteri çıkarır.

    Kimlikli crawl için headers verin ('Authorization: Bearer [REDACTED]; Cookie: a=b').
    Çıktı tekilleştirilmiş URL listesi; hunter/mcp envanterine elle işlenebilir.

    Args:
        url: Başlangıç URL'si (http/https)
        depth: Crawl derinliği (1-5 arası sınırlanır)
        headers: ';' ile ayrılmış ek header'lar
        timeout: Saniye
    """
    if not (url.startswith("http://") or url.startswith("https://")):
        return "HATA: url http/https olmalı"
    depth = max(1, min(int(depth), 5))
    parts = ["katana", "-u", shlex.quote(url), "-d", str(depth),
             "-silent", "-nc", "-c", "10", "-rl", "50", "-timeout", "10",
             "-retry", "1", "-jc"]
    for item in (headers or "").split(";"):
        item = item.strip()
        if ":" in item:
            parts += ["-H", shlex.quote(item)]
    result = run_command(" ".join(parts), timeout=timeout)
    raw = (result or {}).get("stdout") or (result or {}).get("output") or ""
    urls = sorted({line.strip() for line in str(raw).splitlines()
                   if line.strip().startswith(("http://", "https://"))})
    if not urls:
        return format_output(result)
    lines = [f"Katana crawl: {len(urls)} benzersiz URL ({url}, depth={depth})"]
    lines += urls[:500]
    if len(urls) > 500:
        lines.append(f"... (+{len(urls) - 500} daha, çıktı kırpıldı)")
    return "\n".join(lines)


@mcp.tool()
def dig_dns(
    domain: str,
    record_type: str = "ANY",
    nameserver: str = "",
    extra_args: str = ""
) -> str:
    """
    dig ile DNS sorgusu yap.
    
    Args:
        domain: Hedef domain
        record_type: Kayıt tipi (A, AAAA, MX, TXT, NS, CNAME, SOA, ANY, AXFR)
        nameserver: DNS server (ör: 8.8.8.8)
        extra_args: Ek argümanlar
    """
    cmd = f"dig {record_type} {domain}"
    if nameserver:
        cmd += f" @{nameserver}"
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd)
    return format_output(result)

# ============================================================
# PASSWORD CRACKING
# ============================================================

@mcp.tool()
def hashcat_crack(
    hash_value: str = "",
    hash_file: str = "",
    hash_mode: int = 0,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    rules: str = "",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    Hashcat ile hash kırma.
    
    Args:
        hash_value: Tek hash değeri
        hash_file: Hash dosyası yolu
        hash_mode: Hash modu (0:MD5, 100:SHA1, 1400:SHA256, 1700:SHA512, 
                   1000:NTLM, 3200:bcrypt, 1800:sha512crypt, 16500:JWT)
        wordlist: Wordlist yolu
        rules: Rule dosyası
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
    """
    if hash_value and not hash_file:
        # Hash'i geçici dosyaya yaz
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False)
        tmp.write(hash_value)
        tmp.close()
        hash_file = tmp.name
    
    cmd = f"hashcat -m {hash_mode} {hash_file} {wordlist} --force"
    
    if rules:
        cmd += f" -r {rules}"
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def john_crack(
    hash_file: str,
    format: str = "",
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    John the Ripper ile hash kırma.
    
    Args:
        hash_file: Hash dosyası yolu
        format: Hash formatı (ör: raw-md5, raw-sha256, bcrypt, nt)
        wordlist: Wordlist yolu
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
    """
    cmd = f"john --wordlist={wordlist}"
    if format:
        cmd += f" --format={format}"
    if extra_args:
        cmd += f" {extra_args}"
    cmd += f" {hash_file}"
    
    result = run_command(cmd, timeout=timeout)
    
    # Kırılmış hash'leri göster
    show_result = run_command(f"john --show {hash_file}")
    output = format_output(result)
    if show_result["stdout"]:
        output += f"\n\n--- KIRILAN HASH'LER ---\n{show_result['stdout']}"
    
    return output

# ============================================================
# CMS TARAMA
# ============================================================

@mcp.tool()
def wpscan_scan(
    url: str,
    enumerate: str = "u,p,t,vp",
    api_token: str = "",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    WPScan ile WordPress zafiyet taraması yap.
    
    Args:
        url: WordPress site URL'si
        enumerate: Numaralandırma seçenekleri (u:users, p:plugins, t:themes, vp:vulnerable plugins)
        api_token: WPScan API token
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
    """
    cmd = f"wpscan --url {shlex.quote(url)} --enumerate {enumerate}"
    if api_token:
        cmd += f" --api-token {api_token}"
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)

# ============================================================
# SMB/NETWORK ENUMERATION
# ============================================================

@mcp.tool()
def enum4linux_scan(
    target: str,
    extra_args: str = "-a"
) -> str:
    """
    enum4linux ile SMB/NetBIOS enumeration yap.
    
    Args:
        target: Hedef IP
        extra_args: Ek argümanlar (-a: tüm enumeration)
    """
    cmd = f"enum4linux {extra_args} {target}"
    result = run_command(cmd, timeout=120)
    return format_output(result)

# ============================================================
# GENEL ARAÇLAR
# ============================================================

_MULTIPART_KEY_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_MULTIPART_VALUE_MAX = 8192


def _multipart_flags(multipart: str) -> tuple[list[str], str]:
    """Build -F flags; @paths must stay inside CCO_WORKDIR or tmp."""
    try:
        roots = [os.path.realpath(os.environ.get("CCO_WORKDIR", "")),
                 os.path.realpath(tempfile.gettempdir())]
    except (OSError, ValueError):
        return [], "HATA: multipart: workdir cozumu basarisiz"
    roots = [root for root in roots if root]
    flags: list[str] = []
    for field in (multipart or "").split(";"):
        field = field.strip()
        if not field:
            continue
        key, sep, value = field.partition("=")
        if not sep or not _MULTIPART_KEY_RE.fullmatch(key):
            return [], f"HATA: multipart: bozuk alan: {field[:80]}"
        if len(value) > _MULTIPART_VALUE_MAX:
            return [], f"HATA: multipart: deger cok uzun: {key}"
        if value.startswith("@"):
            candidate = value[1:]
            base = candidate if os.path.isabs(candidate) else os.path.join(
                roots[0] if roots else os.getcwd(), candidate)
            try:
                resolved = os.path.realpath(base)
            except (OSError, ValueError):
                return [], f"HATA: multipart: yol cozumu basarisiz: {key}"
            if not any(resolved == root or resolved.startswith(root + os.sep)
                       for root in roots):
                return [], f"HATA: multipart: workdir disi dosya: {key}"
            if not os.path.isfile(resolved):
                return [], f"HATA: multipart: dosya yok: {key}"
            flags.append(f"-F {shlex.quote(key + '=@' + resolved)}")
        else:
            flags.append(f"-F {shlex.quote(field)}")
    if not flags:
        return [], "HATA: multipart: bos alan listesi"
    return flags, ""


@mcp.tool()
def curl_request(
    url: str,
    method: str = "GET",
    headers: str = "",
    data: str = "",
    cookie: str = "",
    follow_redirects: bool = True,
    show_headers: bool = False,
    extra_args: str = "",
    multipart: str = "",
    insecure_tls: bool = False
) -> str:
    """
    curl ile HTTP request gönder.
    
    Args:
        url: Hedef URL
        method: HTTP metodu (GET, POST, PUT, DELETE, PATCH)
        headers: Özel headerler (';' ile ayır, ör: 'Content-Type: application/json;Authorization: Bearer xxx')
        data: Request body
        cookie: Cookie string
        follow_redirects: Redirect'leri takip et
        show_headers: Response header'larını göster
        extra_args: Ek curl argümanları
        multipart: Multipart alanlar (';' ile ayır, 'k=v'; dosya için 'k=@yol', yol CCO_WORKDIR/tmp içinde olmalı)
        insecure_tls: Self-signed TLS için -k (yalnızca kapsam-içi lab hedefleri)
    """
    from wire_budget import current_budget, UnsupportedWireAccounting
    if current_budget() is not None:
        if extra_args or multipart:
            raise UnsupportedWireAccounting("campaign HTTP adapter does not support extra_args or multipart")
        validator_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp-validator"))
        if validator_dir not in sys.path:
            sys.path.insert(0, validator_dir)
        from cco_validator_core.egress import egress_request, scoped_wire_gate
        from policy_engine import PolicyEngine
        engine = PolicyEngine()
        request_headers = _parse_extra_headers(headers, cookie)
        effective_method = "POST" if data and method.upper() == "GET" else method.upper()

        def gate(request_method, request_url, wire_headers):
            decision = engine.validate_wire_invocation("kali-tools_curl_request", {
                "target": request_url, "url": request_url, "method": request_method, "headers": wire_headers})
            return decision["allowed"], decision["reason"]

        def send(request_method, request_url, *, params, data, headers, timeout):
            proxy = str(globals().get("_rate_limit_config", {}).get("proxy") or "").strip()
            proxies = {"http": proxy, "https": proxy} if proxy else None
            return requests.request(request_method, request_url, params=params, data=data, headers=headers,
                                    timeout=timeout, allow_redirects=False, verify=not insecure_tls, proxies=proxies)

        with scoped_wire_gate(gate):
            response = egress_request(effective_method, url, data=data or None, headers=request_headers,
                                      allow_redirects=follow_redirects, timeout=15, transport=send)
        return json.dumps(response, ensure_ascii=False)

    cmd = "curl -s"

    if insecure_tls:
        cmd += " -k"
    if multipart:
        flags, error = _multipart_flags(multipart)
        if error:
            return error
        cmd += " " + " ".join(flags)
    
    if show_headers:
        cmd += " -v"
    if method != "GET":
        cmd += f" -X {method}"
    if headers:
        for h in headers.split(';'):
            cmd += f" -H {shlex.quote(h.strip())}"
    if data:
        cmd += f" -d {shlex.quote(data)}"
    if cookie:
        cmd += f" -b {shlex.quote(cookie)}"
    if follow_redirects:
        cmd += " -L"
    if globals().get("_rate_limit_config", {}).get("configured"):
        delay = float(_rate_limit_config.get("current_delay") or 0.0)
        if delay > 0:
            time.sleep(min(delay, 2.0))
        proxy = str(_rate_limit_config.get("proxy") or "").strip()
        if proxy and "-x " not in extra_args and "--proxy" not in extra_args:
            cmd += f" -x {shlex.quote(proxy)}"
    if extra_args:
        cmd += f" {_quote_extra_args(extra_args)}"

    cmd += f" {shlex.quote(url)}"

    result = run_command(cmd)
    return format_output(result)


@mcp.tool()
def netcat_connect(
    target: str,
    port: int,
    data: str = "",
    listen: bool = False,
    udp: bool = False,
    timeout_secs: int = 10
) -> str:
    """
    Netcat ile TCP/UDP bağlantısı kur.
    
    Args:
        target: Hedef IP/domain
        port: Port numarası
        data: Gönderilecek veri
        listen: Dinleme modu
        udp: UDP kullan
        timeout_secs: Bağlantı timeout'u
    """
    if listen:
        cmd = f"timeout {timeout_secs} nc -nlvp {port}"
    else:
        cmd = f"timeout {timeout_secs} nc -nv"
        if udp:
            cmd += " -u"
        cmd += f" {target} {port}"
    
    if data:
        cmd = f"echo {shlex.quote(data)} | {cmd}"
    
    result = run_command(cmd, timeout=timeout_secs + 5)
    return format_output(result)


@mcp.tool()
def python_exec(
    code: str = "",
    script_file: str = "",
    args: str = "",
    timeout: int = 120
) -> str:
    """
    Python3 kodu veya script çalıştır.
    
    Args:
        code: Çalıştırılacak Python kodu
        script_file: Çalıştırılacak Python dosyası
        args: Script argümanları
        timeout: Zaman aşımı
    """
    if code:
        cmd = f"python3 -c {shlex.quote(code)}"
    elif script_file:
        cmd = f"python3 {script_file} {args}"
    else:
        return "HATA: code veya script_file parametresi gerekli"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def shell_exec(
    command: str,
    cwd: str = None,
    timeout: int = 120
) -> str:
    """
    Genel shell komutu çalıştır. GÜVENLİK KATMANI AKTİF — destructive komutlar engellenir.
    
    Args:
        command: Çalıştırılacak shell komutu
        cwd: Çalışma dizini
        timeout: Zaman aşımı
    """
    # Güvenlik kontrolü
    is_safe, reason = validate_command(command)
    if not is_safe:
        return reason
    
    result = run_command(command, timeout=timeout, cwd=cwd)
    return format_output(result)


@mcp.tool()
def file_analyze(
    filepath: str
) -> str:
    """
    Dosya analizi yap (file, strings, checksec, exiftool, binwalk).
    
    Args:
        filepath: Analiz edilecek dosya yolu
    """
    outputs = []
    
    # file komutu
    r = run_command(f"file {shlex.quote(filepath)}")
    outputs.append(f"=== FILE ===\n{r['stdout']}")
    
    # strings (ilk 50 satır)
    r = run_command(f"strings {shlex.quote(filepath)} | head -50")
    outputs.append(f"\n=== STRINGS (ilk 50) ===\n{r['stdout']}")
    
    # xxd (ilk 100 byte)
    r = run_command(f"xxd {shlex.quote(filepath)} | head -10")
    outputs.append(f"\n=== HEX DUMP (ilk 160 byte) ===\n{r['stdout']}")
    
    # checksec (ELF ise)
    r = run_command(f"checksec --file={shlex.quote(filepath)} 2>/dev/null")
    if r['stdout']:
        outputs.append(f"\n=== CHECKSEC ===\n{r['stdout']}")
    
    # exiftool
    r = run_command(f"exiftool {shlex.quote(filepath)} 2>/dev/null")
    if r['stdout']:
        outputs.append(f"\n=== EXIFTOOL (Metadata) ===\n{r['stdout']}")
    
    # binwalk
    r = run_command(f"binwalk {shlex.quote(filepath)} 2>/dev/null")
    if r['stdout']:
        outputs.append(f"\n=== BINWALK ===\n{r['stdout']}")
    
    return "\n".join(outputs)


@mcp.tool()
def searchsploit_search(
    query: str,
    extra_args: str = ""
) -> str:
    """
    SearchSploit ile exploit-db'de zafiyet ara.
    
    Args:
        query: Arama sorgusu (ör: 'apache 2.4.49', 'wordpress 5.0')
        extra_args: Ek argümanlar
    """
    cmd = f"searchsploit {shlex.quote(query)} {extra_args}"
    result = run_command(cmd)
    return format_output(result)

# ============================================================
# SUPERVISOR DAEMON & HYBRID ORCHESTRATION (Phase C)
# ============================================================

@mcp.tool()
def qwen_analyze(
    target: str,
    data: str,
    analysis_type: str = "vulnerability",
    openrouter_api_key: str = None
) -> str:
    """
    Qwen 3.6 Plus ile derinlemesine zafiyet analizi, trafik analizi veya kod güvenlik incelemesi yap.
    Orkestratör (HackerAgent) karar verdikten sonra, analiz derinliği gerektiren durumlarda
    bu tool'u çağırarak Qwen'in analitik gücünden faydalanır.
    
    Args:
        target: Hedef bilgisi (IP, domain, URL veya bağlam)
        data: Analiz edilecek veri (PCAP özeti, kaynak kod, HTTP response, log, nmap çıktısı vb.)
        analysis_type: Analiz tipi:
            - 'vulnerability': Zafiyet analizi ve exploit yolu önerisi
            - 'traffic': Ağ trafiği / PCAP analizi
            - 'code_review': Kaynak kod güvenlik incelemesi
            - 'log_analysis': Log dosyası analizi ve anomali tespiti
            - 'pattern': Veri içinde pattern/flag/gizli bilgi arama
            - 'reverse': Decompile edilmiş kod analizi
            - 'crypto': Kriptografik analiz (şifre tipi tespiti, zayıflık analizi)
        openrouter_api_key: OpenRouter API anahtarı (None ise settings.json'dan okunur)
    """
    # API key kontrolü (güvenli hiyerarşi: env > keyring > settings.json)
    api_key = openrouter_api_key or get_api_key_secure()

    if not api_key:
        return "HATA: OpenRouter API key bulunamadı. Şu yöntemlerden birini kullanın:\n1. OPENROUTER_API_KEY env var\n2. keyring: python3 -c \"import keyring; keyring.set_password('cco','openrouter','YOUR_KEY')\"\n3. ~/.cco/config.yaml → llm.openrouter_api_key alanı"

    analysis_prompts = {
        "vulnerability": "You are an expert penetration tester and vulnerability analyst. Analyze the following data from the target system. Identify all potential vulnerabilities, rank them by severity (Critical/High/Medium/Low), suggest specific exploit techniques, and provide exact commands or payloads to verify each finding.",
        "traffic": "You are a network forensics expert. Analyze the following network traffic data. Identify suspicious patterns, potential attacks, data exfiltration, credential leaks, C2 communication, unusual protocols, and any hidden information.",
        "code_review": "You are a senior application security engineer. Perform a thorough security code review of the following source code. Identify all security vulnerabilities including injection flaws, authentication issues, authorization bypasses, cryptographic weaknesses, sensitive data exposure, and provide specific line references and fix recommendations.",
        "log_analysis": "You are a SOC analyst and incident responder. Analyze the following log data. Identify indicators of compromise (IoCs), suspicious activities, failed/successful attacks, lateral movement, privilege escalation attempts, and provide a timeline of events.",
        "pattern": "You are a CTF expert and data analyst. Examine the following data carefully. Look for hidden flags (flag{}, CTF{}, or custom formats), encoded data (base64, hex, binary, morse), steganographic patterns, unusual strings, and any concealed information.",
        "reverse": "You are a reverse engineering expert. Analyze the following decompiled/disassembled code. Identify the program logic, find security-critical functions, locate hardcoded secrets, understand the control flow, and identify exploitable vulnerabilities.",
        "crypto": "You are a cryptography expert. Analyze the following cryptographic data. Identify the cipher/hash type, assess key strength, find implementation weaknesses, suggest attack vectors (factorization, padding oracle, ECB patterns, etc.), and provide decryption strategies."
    }

    system_prompt = analysis_prompts.get(analysis_type, analysis_prompts["vulnerability"])
    user_prompt = f"Target: {target}\n\nData to analyze:\n{data}\n\nProvide a detailed, structured analysis with actionable findings."

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cco.local",
        "X-Title": "HackerAgent Qwen Analyzer"
    }

    payload = {
        "model": os.environ.get("CCO_ANALYZE_MODEL", "qwen/qwen3.6-plus"),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    }

    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=90)
        response.raise_for_status()
        result = response.json()
        content = result['choices'][0]['message']['content']
        return f"\n[📊] QWEN 3.6 PLUS ANALİZ SONUCU ({analysis_type.upper()}):\n{'='*60}\n{content}\n{'='*60}\n"
    except requests.exceptions.Timeout:
        return "HATA (Qwen API): İstek zaman aşımına uğradı. Daha küçük veri ile tekrar deneyin."
    except Exception as e:
        return f"HATA (Qwen API): İstek başarısız oldu. {e}"


@mcp.tool()
def generate_exploit_poc(
    vulnerability: str,
    target: str,
    context: str = "",
    openrouter_api_key: str = None
) -> str:
    """
    Tespit edilen zafiyet için proof-of-concept exploit payload'u üretir.
    Önce lokal payload veritabanında arar, bulamazsa OpenRouter üzerinden
    Hermes 405B modeliyle teknik PoC kodu oluşturur.
    
    Args:
        vulnerability: Zafiyetin tipi (örn: 'Apache Struts OGNL RCE', 'SQL Injection')
        target: Hedef sistem bilgileri
        context: Varsa tespit edilen detaylar, parametreler veya WAF bypass gereksinimleri
        openrouter_api_key: OpenRouter API anahtarı (Eğer None ise, ~/.cco/config.yaml içinden okunmaya çalışılır)
    """
    # --- STEP 1: Lokal payload veritabanı araması ---
    local_payload = _search_local_payloads(vulnerability)
    if local_payload:
        return f"\n[📦] LOKAL PAYLOAD DB SONUCU:\n{'='*50}\n{local_payload}\n{'='*50}\n💡 Kaynak: payloads.md (LLM çağrısı gerekmedi)\n"

    # --- STEP 2: Hermes 405B ile PoC üretimi ---
    api_key = openrouter_api_key or get_api_key_secure()
            
    if not api_key:
        return "HATA: OpenRouter API key bulunamadı. Şu yöntemlerden birini kullanın:\n1. OPENROUTER_API_KEY env var\n2. keyring: python3 -c \"import keyring; keyring.set_password('cco','openrouter','YOUR_KEY')\"\n3. ~/.cco/config.yaml → llm.openrouter_api_key alanı"

    system_prompt = ("You are a certified OSEP/OSCP penetration testing consultant performing "
                     "authorized security validation in a controlled lab environment. Generate "
                     "a technically precise proof-of-concept for the described vulnerability. "
                     "Output format: executable payload with deployment notes and expected outcome. "
                     "Focus on accuracy and reproducibility.")
    
    user_prompt = f"Target: {target}\nVulnerability: {vulnerability}\nContext: {context}\n\nGenerate a working proof-of-concept payload for this vulnerability in a controlled test environment."

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cco.local", 
        "X-Title": "HackerAgent Security Validation"
    }
    
    data = {
        "model": os.environ.get("CCO_EXPLOIT_MODEL", "nousresearch/hermes-4-405b"),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    }
    
    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=data, timeout=60)
        response.raise_for_status()
        result = response.json()
        return f"\n[🔬] HERMES 405B — PoC ÇIKTISI:\n{result['choices'][0]['message']['content']}\n"
    except Exception as e:
         return f"HATA (Hermes API): İstek başarısız oldu. {e}"


def _search_local_payloads(vulnerability: str) -> str:
    """Lokal payload veritabanında (payloads.md) zafiyet tipine göre arama yap."""
    vuln_lower = vulnerability.lower()
    payload_paths = [
        os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'web-exploit', 'references', 'payloads.md'),
        os.path.join(CCO_HOME, 'skills', 'web-exploit', 'references', 'payloads.md'),
        os.path.expanduser('~/.gemini/antigravity/skills/web-exploit/references/payloads.md'),  # legacy
    ]
    
    # Zafiyet tipini anahtar kelimelerle eşleştir
    keyword_map = {
        'sqli': ['sql injection', 'sqli', 'union select', 'sqlmap'],
        'xss': ['xss', 'cross-site scripting', 'script', 'alert('],
        'ssrf': ['ssrf', 'server-side request', 'localhost bypass'],
        'ssti': ['ssti', 'template injection', 'jinja', 'twig'],
        'lfi': ['lfi', 'local file inclusion', 'path traversal', 'directory traversal'],
        'rfi': ['rfi', 'remote file inclusion'],
        'cmdi': ['command injection', 'os command', 'cmdi', 'rce'],
        'xxe': ['xxe', 'xml external entity', 'xml injection'],
        'upload': ['file upload', 'upload bypass', 'webshell'],
        'auth': ['authentication bypass', 'auth bypass', 'jwt', 'session'],
        'idor': ['idor', 'insecure direct object', 'broken access'],
        'deserialization': ['deserialization', 'unserialize', 'pickle', 'java serial'],
    }
    
    matched_section = None
    for category, keywords in keyword_map.items():
        if any(kw in vuln_lower for kw in keywords):
            matched_section = category
            break
    
    if not matched_section:
        return ""
    
    for path in payload_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            try:
                with open(abs_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # İlgili bölümü bul (## veya ### heading ile)
                lines = content.split('\n')
                capturing = False
                captured = []
                depth = 0
                
                for line in lines:
                    if line.startswith('#') and any(kw in line.lower() for kw in keyword_map.get(matched_section, [])):
                        capturing = True
                        depth = len(line) - len(line.lstrip('#'))
                        captured.append(line)
                        continue
                    
                    if capturing:
                        if line.startswith('#') and len(line) - len(line.lstrip('#')) <= depth:
                            break
                        captured.append(line)
                
                if captured:
                    return '\n'.join(captured[:80])  # Max 80 satır
            except Exception:
                pass
    
    return ""


@mcp.tool()
def parallel_llm_analyze(
    target: str,
    data: str,
    analysis_type: str = "vulnerability",
    also_generate_payload: bool = True,
    vulnerability_hint: str = "",
    openrouter_api_key: str = None
) -> str:
    """Qwen ANALİZ + Hermes EXPLOIT üretimini PARALEL çalıştır — tek çağrıda iki model.
    MCP tool'ları sıralı çağrıldığı için bu tool her iki modeli
    ThreadPoolExecutor ile aynı anda çağırır. Sonuç: ~30sn yerine ~15sn.

    Args:
        target: Hedef bilgisi (IP, domain, URL)
        data: Analiz edilecek veri (nmap çıktısı, kaynak kod, HTTP response vb.)
        analysis_type: Qwen analiz tipi ('vulnerability', 'traffic', 'code_review', 
                       'log_analysis', 'pattern', 'reverse', 'crypto')
        also_generate_payload: True ise Hermes 405B'den exploit payload da iste
        vulnerability_hint: Hermes'e verilecek zafiyet ipucu (boş: Qwen sonucundan çıkarılır)
        openrouter_api_key: OpenRouter API anahtarı
    """
    from concurrent.futures import ThreadPoolExecutor

    api_key = openrouter_api_key or get_api_key_secure()
    if not api_key:
        return "HATA: OpenRouter API key bulunamadı."

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cco.local",
        "X-Title": "HackerAgent Parallel LLM"
    }

    # Qwen analiz promptları
    analysis_prompts = {
        "vulnerability": "You are an expert penetration tester. Analyze the data, identify all vulnerabilities ranked by severity, suggest exploit techniques, and provide exact commands/payloads to verify each finding.",
        "traffic": "You are a network forensics expert. Identify suspicious patterns, attacks, data exfiltration, credential leaks, and C2 communication.",
        "code_review": "You are a senior appsec engineer. Find injection flaws, auth issues, crypto weaknesses, sensitive data exposure. Provide line references and fixes.",
        "log_analysis": "You are a SOC analyst. Identify IoCs, suspicious activities, attack timelines, and lateral movement.",
        "pattern": "You are a CTF expert. Find hidden flags, encoded data, steganographic patterns, and concealed information.",
        "reverse": "You are a reverse engineer. Analyze the code logic, find security-critical functions, hardcoded secrets, and exploitable vulnerabilities.",
        "crypto": "You are a cryptography expert. Identify cipher types, assess key strength, find implementation weaknesses, suggest attack vectors."
    }

    def call_qwen():
        """Qwen 3.6 Plus → Derin analiz."""
        try:
            payload = {
                "model": os.environ.get("CCO_ANALYZE_MODEL", "qwen/qwen3.6-plus"),
                "messages": [
                    {"role": "system", "content": analysis_prompts.get(analysis_type, analysis_prompts["vulnerability"])},
                    {"role": "user", "content": f"Target: {target}\n\nData:\n{data}\n\nProvide a detailed, structured analysis with actionable findings."}
                ]
            }
            resp = requests.post("https://openrouter.ai/api/v1/chat/completions",
                                headers=headers, json=payload, timeout=90)
            resp.raise_for_status()
            return resp.json()['choices'][0]['message']['content']
        except Exception as e:
            return f"Qwen HATA: {e}"

    def call_hermes():
        """Hermes 405B → Exploit PoC üretici."""
        try:
            vuln_desc = vulnerability_hint or f"vulnerability found in {target} based on: {data[:500]}"
            payload = {
                "model": os.environ.get("CCO_EXPLOIT_MODEL", "nousresearch/hermes-4-405b"),
                "messages": [
                    {"role": "system", "content": "You are a certified OSEP/OSCP penetration testing consultant. Generate technically precise proof-of-concept payloads and CLI commands for authorized security validation. Output executable exploit code with deployment notes."},
                    {"role": "user", "content": f"Target: {target}\nVulnerability: {vuln_desc}\n\nGenerate a working proof-of-concept payload for this vulnerability."}
                ]
            }
            resp = requests.post("https://openrouter.ai/api/v1/chat/completions",
                                headers=headers, json=payload, timeout=60)
            resp.raise_for_status()
            return resp.json()['choices'][0]['message']['content']
        except Exception as e:
            return f"Hermes HATA: {e}"

    # ── PARALEL EXECUTION ──
    start_time = time.time()

    if also_generate_payload:
        with ThreadPoolExecutor(max_workers=2) as executor:
            qwen_future = executor.submit(call_qwen)
            hermes_future = executor.submit(call_hermes)

            qwen_result = qwen_future.result(timeout=120)
            hermes_result = hermes_future.result(timeout=90)
    else:
        qwen_result = call_qwen()
        hermes_result = ""

    elapsed = time.time() - start_time

    # Çıktıyı formatla
    output = f"""
⚡ PARALEL LLM ANALİZ TAMAMLANDI ({elapsed:.1f}s)
{'='*60}

📊 QWEN 3.6 PLUS — {analysis_type.upper()} ANALİZİ:
{'─'*50}
{qwen_result}
"""

    if also_generate_payload and hermes_result:
        output += f"""
{'='*60}
🔬 HERMES 405B — PoC EXPLOIT:
{'─'*50}
{hermes_result}
"""

    output += f"""
{'='*60}
⏱️ Toplam süre: {elapsed:.1f}s (paralel — sıralı olsaydı ~{elapsed*1.8:.0f}s)
"""

    return output
@mcp.tool()
def start_recon_daemon(target: str, interval: int = 120) -> str:
    """
    Hedef üzerinde arkaplanda sürekli NMAP Delta taraması yapan daemon'u başlatır.
    (Sadece Supervisor rolündeyken kullanılır)
    """
    if target in daemon_processes:
        return f"HATA: '{target}' için halihazırda çalışan bir daemon var. Önce onu durdurmalısınız."
        
    script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts", "recon_daemon.py")
    if not os.path.exists(script_path):
         return f"HATA: Daemon script bulunamadı: {script_path}"
         
    try:
        proc = subprocess.Popen(
            ["python3", script_path, "--target", target, "--interval", str(interval)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        daemon_processes[target] = proc
        return f"Recon Daemon BAŞLATILDI. Hedef: {target}, Periyot: her {interval} saniyede. Process ID: {proc.pid}\nYeni portlar otomatik olarak memory-server'a kaydedilecektir."
    except Exception as e:
        return f"HATA: Daemon başlatılamadı: {e}"

@mcp.tool()
def stop_recon_daemon(target: str) -> str:
    """
    Belirtilen hedef için arkaplanda çalışan recon daemon'ı durdurur. 
    """
    proc = daemon_processes.get(target)
    if not proc:
         return f"HATA: '{target}' hedefi için kayıtlı çalışan bir daemon bulunamadı."
         
    try:
        proc.terminate()
        proc.wait(timeout=5)
        del daemon_processes[target]
        return f"Recon Daemon DURDURULDU. Hedef: {target}"
    except Exception:
        try:
            proc.kill()
            del daemon_processes[target]
            return f"Recon Daemon zorla (kill) durduruldu. Hedef: {target}"
        except Exception as kill_err:
             return f"HATA: Daemon durdurulamadı: {kill_err}"


@mcp.tool()
def metasploit_search(
    query: str,
    module_type: str = ""
) -> str:
    """
    Metasploit'te modül ara.
    
    Args:
        query: Arama sorgusu
        module_type: Modül tipi (exploit, auxiliary, post, payload)
    """
    search_q = query
    if module_type:
        search_q = f"type:{module_type} {query}"
    
    cmd = f"msfconsole -q -x 'search {search_q}; exit'"
    result = run_command(cmd, timeout=120)
    return format_output(result)


@mcp.tool()
def wafw00f_detect(target: str) -> str:
    """
    WAF tespiti yap.
    
    Args:
        target: Hedef URL
    """
    cmd = f"wafw00f {shlex.quote(target)}"
    result = run_command(cmd)
    return format_output(result)


@mcp.tool()
def steghide_extract(
    filepath: str,
    passphrase: str = "",
    extra_args: str = ""
) -> str:
    """
    Steghide ile steganografi verisi çıkar.
    
    Args:
        filepath: Dosya yolu
        passphrase: Şifre (boş: şifresiz deneme)
        extra_args: Ek argümanlar
    """
    if passphrase:
        cmd = f"steghide extract -sf {shlex.quote(filepath)} -p {shlex.quote(passphrase)} -f"
    else:
        cmd = f"steghide info {shlex.quote(filepath)} 2>&1; steghide extract -sf {shlex.quote(filepath)} -p '' -f 2>&1"
    
    result = run_command(cmd)
    return format_output(result)


@mcp.tool()
def volatility_analyze(
    dump_file: str,
    plugin: str = "windows.info",
    extra_args: str = ""
) -> str:
    """
    Volatility ile memory dump analizi yap.
    
    Args:
        dump_file: Memory dump dosya yolu
        plugin: Volatility plugini (windows.info, windows.pslist, windows.pstree, 
                windows.cmdline, windows.filescan, windows.hashdump, windows.netscan,
                linux.pslist, linux.bash)
        extra_args: Ek argümanlar
    """
    # Volatility 3 dene
    cmd = f"vol3 -f {shlex.quote(dump_file)} {plugin} {extra_args}"
    result = run_command(cmd, timeout=300)
    
    if result['returncode'] != 0:
        # Volatility 2 dene
        cmd = f"volatility -f {shlex.quote(dump_file)} {plugin} {extra_args}"
        result = run_command(cmd, timeout=300)
    
    return format_output(result)


# ============================================================
# EKSİK KRİTİK ARAÇLAR (v2.0 — Phase 3)
# ============================================================

# --- GIT / SECRET SCANNING ---

@mcp.tool()
def trufflehog_scan(
    target: str,
    scan_type: str = "git",
    extra_args: str = ""
) -> str:
    """
    TruffleHog ile secret/leak hunting. Git repo, dosya sistemi veya S3 bucket tarar.
    
    Args:
        target: Git repo URL veya dizin yolu
        scan_type: 'git' (repo), 'filesystem' (dizin), 's3' (bucket)
        extra_args: Ek argümanlar
    """
    cmd = f"trufflehog {scan_type} {shlex.quote(target)} --json {extra_args}"
    result = run_command(cmd, timeout=300)
    return format_output(result)


@mcp.tool()
def gitleaks_scan(
    target: str,
    extra_args: str = ""
) -> str:
    """
    Gitleaks ile kaynak kodda secret taraması.
    
    Args:
        target: Git repo yolu veya URL
        extra_args: Ek argümanlar (ör: '--report-format json')
    """
    cmd = f"gitleaks detect --source {shlex.quote(target)} -v {extra_args}"
    result = run_command(cmd, timeout=300)
    return format_output(result)


# --- API ENDPOINT DISCOVERY ---

@mcp.tool()
def kiterunner_scan(
    target: str,
    wordlist: str = "",
    extra_args: str = ""
) -> str:
    """
    Kiterunner ile API endpoint brute force. REST/GraphQL endpoint keşfi.
    
    Args:
        target: Hedef URL (ör: http://target.com)
        wordlist: Wordlist yolu (boş: varsayılan kiterunner data)
        extra_args: Ek argümanlar
    """
    wl = f"-w {shlex.quote(wordlist)}" if wordlist else ""
    cmd = f"kr scan {shlex.quote(target)} {wl} {extra_args}"
    result = run_command(cmd, timeout=300)
    return format_output(result)


# --- HISTORIC ENDPOINT DISCOVERY ---

@mcp.tool()
def gau_urls(
    domain: str,
    extra_args: str = ""
) -> str:
    """
    gau ile historic URL discovery (Wayback Machine, Common Crawl, OTX, URLScan).
    
    Args:
        domain: Hedef domain (ör: example.com)
        extra_args: Ek argümanlar (ör: '--threads 5 --subs')
    """
    cmd = f"gau {shlex.quote(domain)} {extra_args}"
    result = run_command(cmd, timeout=120)
    raw = format_output(result)
    urls = [ln.strip() for ln in raw.splitlines() if ln.strip().startswith("http")]
    footer = ""
    if HAS_SURFACE and urls:
        artifact = write_artifact(urls, prefix="gau")
        ingest = _ingest_surface_records(parse_gau(urls, target=domain), domain)
        footer = _surface_summary(ingest, artifact, extra={"urls": len(urls)})
    lines = raw.strip().split("\n")
    body = "\n".join(lines[:200])
    if len(lines) > 200:
        body += f"\n... (toplam {len(lines)} URL bulundu)"
    return body + footer


@mcp.tool()
def waybackurls_fetch(
    domain: str,
    extra_args: str = ""
) -> str:
    """
    waybackurls ile Wayback Machine'den historik URL çekme.
    
    Args:
        domain: Hedef domain
        extra_args: Ek argümanlar
    """
    cmd = f"echo {shlex.quote(domain)} | waybackurls {extra_args}"
    result = run_command(cmd, timeout=120)
    raw = format_output(result)
    urls = [ln.strip() for ln in raw.splitlines() if ln.strip().startswith("http")]
    footer = ""
    if HAS_SURFACE and urls:
        artifact = write_artifact(urls, prefix="wayback")
        records = parse_gau(urls, target=domain)
        for rec in records:
            rec["sources"] = ["wayback"]
        ingest = _ingest_surface_records(records, domain)
        footer = _surface_summary(ingest, artifact, extra={"urls": len(urls), "source": "wayback"})
    lines = raw.strip().split("\n")
    body = "\n".join(lines[:200])
    if len(lines) > 200:
        body += f"\n... (toplam {len(lines)} URL)"
    return body + footer


@mcp.tool()
def discover_web_surface(
    target: str,
    mode: str = "active",
    include_historic: bool = False,
    include_browser: bool = False,
    max_urls: int = 400,
    probe_limit: int = 32,
    timeout: int = 12,
    allow_subdomains: bool = False,
    cookie: str = "",
    headers: str = "",
) -> str:
    """Tek girişli web yüzey derleyici. Probe + robots/sitemap/HTML/JS (+ isteğe
    historic gau/wayback, isteğe Playwright crawl) → attack_surface DB + kuyruk.

    LLM'in gau/ffuf metnini parse etmesine gerek yok; sonuç JSON kuyruktur.

    Args:
        target: Domain veya URL (scheme yoksa https sonra http denenir)
        mode: 'passive' (base+robots+sitemap+historic) veya 'active' (+link probe)
        include_historic: gau/wayback çalıştır (yavaş; varsayılan kapalı)
        include_browser: Playwright BFS+XHR (varsayılan kapalı; crawl_web_surface tercih)
        max_urls: ingest tavanı
        probe_limit: active modda status almak için GET edilecek extra URL
        timeout: HTTP timeout
        allow_subdomains: HTML/JS'ten alt alan adı kabul et
        cookie: isteğe bağlı Cookie header (browser crawl için)
        headers: ekstra HTTP header'ları (JSON veya 'Name: value' satırları)
    """
    if not HAS_SURFACE:
        return json.dumps({"error": "surface core yüklenemedi"}, ensure_ascii=False)
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    errors = []
    pages = {}
    records = []
    probe = {}
    stop_reason = ""
    skipped_links = {}
    skipped_urls = set()
    fetched = {}
    browser_snapshot = {}

    def _skip(url, reason):
        key = (url, reason)
        if key not in skipped_urls:
            skipped_urls.add(key)
            skipped_links[reason] = skipped_links.get(reason, 0) + 1

    def _fetch(url, limit=timeout):
        nonlocal stop_reason
        if stop_reason:
            return None
        if url in fetched:
            return fetched[url]
        reason = discovery_link_skip_reason(url)
        if reason:
            _skip(url, reason)
            return None
        if current_surface_guard():
            try:
                scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
                if scripts_dir not in sys.path:
                    sys.path.insert(0, scripts_dir)
                from policy_engine import ScopeResolver
                if not ScopeResolver().permits_url(url):
                    return None
            except (ImportError, OSError, RuntimeError, ValueError):
                stop_reason = "discovery stopped: scope policy unavailable"
                return None
        try:
            try:
                result = _http_get(url, timeout=limit, headers=headers, cookie=cookie)
            except TypeError:
                if current_surface_guard():
                    raise
                result = _http_get(url, timeout=limit)
            if current_surface_guard() and result is not None and result.status_code in {401, 429}:
                stop_reason = f"discovery stopped: HTTP {result.status_code}"
                errors.append(stop_reason)
                return None
            fetched[url] = result
            return result
        except SurfaceBlocked as exc:
            message = str(exc)
            errors.append(message)
            if current_surface_guard() or "stopped:" in message or "different origin" in message:
                stop_reason = message
            return None
        except Exception as exc:
            if current_surface_guard():
                stop_reason = f"discovery transport error: {type(exc).__name__}"
                errors.append(stop_reason)
            else:
                errors.append(f"{url}: {exc}")
            return None

    raw = (target or "").strip()
    if not raw:
        return json.dumps({"error": "target gerekli"}, ensure_ascii=False)

    candidates = [raw] if "://" in raw else [f"https://{raw}", f"http://{raw}"]
    response = None
    base = candidates[0]
    for candidate in candidates:
        response = _fetch(candidate)
        if response is not None:
            # A trailing slash changes relative script/link resolution.
            base = str(response.url) or candidate
            break
    if response is None:
        return json.dumps({"error": "hedefe erişilemedi", "tried": candidates, "errors": errors,
                           **({"stop_reason": stop_reason or "discovery target unavailable"}
                              if current_surface_guard() else {})},
                          ensure_ascii=False)

    probe = fingerprint_response(
        base, response.status_code, response.headers, response.content or b""
    )
    # Set-Cookie değerleri de saldırı yüzeyidir (ör. TrackingId blind SQLi):
    # cookie parametre kaydı olarak işle, yoksa fuzz/validator göremez.
    cookie_params = []
    try:
        for c in response.cookies:
            cookie_params.append({"name": c.name, "in": "cookie",
                                  "sample": (c.value or "")[:80]})
    except Exception:
        cookie_params = []
    title = probe.get("title") or ""
    tech = list(probe.get("tech") or [])
    pages[base] = response.text or ""
    js_texts = []
    surface_target = raw.rstrip("/")
    records.append({
        "target": surface_target,
        "url": base,
        "method": "GET",
        "status": probe["status"],
        "content_type": probe["content_type"],
        "title": title,
        "body_len": probe["body_len"],
        "body_hash": probe["body_hash"],
        "tech": tech,
        "auth_required": probe["auth_required"],
        "sources": ["probe"],
        "params": params_from_url(base) + cookie_params,
    })

    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    robots = _fetch(urljoin(origin + "/", "robots.txt"))
    if robots is not None and robots.status_code == 200:
        records.extend(extract_robots(robots.text or "", origin))
    sitemap = _fetch(urljoin(origin + "/", "sitemap.xml"))
    if sitemap is not None and sitemap.status_code == 200:
        body = sitemap.text or ""
        records.extend(extract_sitemap(body, origin, allow_subdomains=allow_subdomains))
        if is_sitemap_index(body):
            for rec in extract_sitemap(body, origin, allow_subdomains=allow_subdomains):
                child_url = rec.get("url") or ""
                if not child_url:
                    continue
                child = _fetch(child_url)
                if child is None or child.status_code >= 400:
                    continue
                records.extend(extract_sitemap(child.text or "", origin, allow_subdomains=allow_subdomains))

    for well_known in ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json"):
        spec_resp = _fetch(urljoin(origin + "/", well_known.lstrip("/")))
        if spec_resp is None or spec_resp.status_code >= 400:
            continue
        ctype = (spec_resp.headers.get("Content-Type") or "").lower()
        body = spec_resp.text or ""
        if "json" in ctype or body.lstrip().startswith("{") or well_known.endswith(".json"):
            records.extend(parse_openapi(body, target=surface_target, base=origin))
            break

    html_records = extract_html(pages.get(base, ""), base, allow_subdomains=allow_subdomains)
    records.extend(html_records)
    scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    from feature_frontier import UnifiedFrontier
    from policy_engine import ScopeResolver
    frontier = UnifiedFrontier(base, ScopeResolver().permits_url if current_surface_guard() else lambda _: True,
                               "authenticated" if cookie or headers else "anonymous")
    frontier.add_html(pages.get(base, ""), base)
    frontier.add_records(records)

    def sync_frontier():
        frontier.add_records(records)
        for item in frontier.items.values():
            if item['status'] in {'pending', 'running'} and item['url'] in fetched:
                frontier.finish(item)

    sync_frontier()
    # Budgets bound wire work, not inventory. Every unspent source remains
    # visible, including imports discovered while processing other bundles.
    source_budget = max(0, int(probe_limit))
    while frontier.pending('bundle') and source_budget and not stop_reason:
        work = frontier.take('bundle')
        js_url = work['url']
        source_budget -= 1
        js_resp = _fetch(js_url)
        if js_resp is None or js_resp.status_code >= 400:
            frontier.finish(work, 'source_unavailable')
            continue
        js_texts.append(js_resp.text or "")
        records.extend(extract_js(js_resp.text or "", base, allow_subdomains=allow_subdomains))
        # WS2 şema hasadı: metot + gövde anahtarları + GraphQL değişkenleri.
        records.extend(extract_js_calls(js_resp.text or "", base,
                                        allow_subdomains=allow_subdomains))
        frontier.add_js_imports(js_resp.text or '', js_url)
        frontier.finish(work)
        sync_frontier()

    # JS/HTML içinde anılan spec adresleri (sabit well-known listesine ek).
    spec_candidates = []
    for text in js_texts + [pages.get(base, "")]:
        for spec_url in find_spec_urls(text, base, allow_subdomains=allow_subdomains):
            if spec_url not in spec_candidates:
                spec_candidates.append(spec_url)
    for spec_url in spec_candidates:
        frontier.add(spec_url, source='schema-reference', kind='schema')
    sync_frontier()
    while frontier.pending('schema') and source_budget and not stop_reason:
        work = frontier.take('schema')
        spec_url = work['url']
        source_budget -= 1
        spec_resp = _fetch(spec_url)
        if spec_resp is None or spec_resp.status_code >= 400:
            frontier.finish(work, 'source_unavailable')
            continue
        body = spec_resp.text or ""
        if body.lstrip().startswith("{"):
            records.extend(parse_openapi(body, target=surface_target, base=origin))
        frontier.finish(work)
        sync_frontier()

    historic = {"gau": 0, "wayback": 0}
    if include_historic and not stop_reason:
        domain = parsed.hostname or surface_target
        gau = run_command(f"gau {shlex.quote(domain)}", timeout=45)
        gau_urls = [ln.strip() for ln in (gau.get("stdout") or "").splitlines() if ln.strip().startswith("http")]
        historic["gau"] = len(gau_urls)
        for url in gau_urls:
            frontier.add(url, source='gau', kind='operation')
            if same_host(url, base, allow_subdomains=allow_subdomains):
                records.append({"url": url, "method": "GET", "sources": ["gau"],
                                "params": params_from_url(url), "target": surface_target})
        wayback = run_command(f"echo {shlex.quote(domain)} | waybackurls", timeout=45)
        wb_urls = [ln.strip() for ln in (wayback.get("stdout") or "").splitlines() if ln.strip().startswith("http")]
        historic["wayback"] = len(wb_urls)
        for url in wb_urls:
            frontier.add(url, source='wayback', kind='operation')
            if same_host(url, base, allow_subdomains=allow_subdomains):
                records.append({"url": url, "method": "GET", "sources": ["wayback"],
                                "params": params_from_url(url), "target": surface_target})

    if (mode or "active").lower() == "active":
        sync_frontier()
        seen = {base}
        extras = []
        for rec in records:
            url = rec.get("url")
            if str(rec.get("method") or "GET").upper() != "GET":
                _skip(url, "non_get_discovery_record")
                continue
            reason = discovery_link_skip_reason(url) if url else ""
            if reason:
                _skip(url, reason)
                continue
            if url and url not in seen and same_host(url, base, allow_subdomains=allow_subdomains):
                extras.append(url)
                seen.add(url)
        for url in extras[:max(0, int(probe_limit))]:
            extra = _fetch(url)
            if extra is None:
                continue
            extra_url = normalize_url(str(extra.url) or url, base=base) or url
            fp = fingerprint_response(extra_url, extra.status_code, extra.headers, extra.content or b"")
            for item in records:
                current = normalize_url(item.get("url") or "", base=base)
                if current == extra_url or item.get("url") == url:
                    item["status"] = fp.get("status")
                    item["content_type"] = fp.get("content_type") or ""
                    item["body_len"] = fp.get("body_len")
                    item["body_hash"] = fp.get("body_hash") or ""
                    item["title"] = fp.get("title") or item.get("title") or ""
                    if fp.get("tech"):
                        item["tech"] = list(dict.fromkeys(list(item.get("tech") or []) + list(fp.get("tech") or [])))
                    if fp.get("auth_required") is not None:
                        item["auth_required"] = fp.get("auth_required")
                    break

    if include_browser and not stop_reason:
        if crawl_site is None:
            errors.append("crawl core yüklenemedi")
        else:
            crawled = crawl_site(
                base,
                max_pages=min(40, max(8, int(probe_limit) * 2)),
                cookie=cookie,
                headers=headers,
                allow_subdomains=allow_subdomains,
                wire_gate=(current_surface_guard() or (None,))[0],
                tool_name="kali-tools_discover_web_surface",
                source_records=records,
            )
            browser_snapshot = {key: crawled.get(key, []) for key in
                                ('frontier', 'continuation_queue', 'external_sources', 'visited_states', 'feature_map')}
            if crawled.get("ok"):
                records.extend(crawled.get("records") or [])
            else:
                errors.append(crawled.get("error") or "browser crawl başarısız")

    sync_frontier()
    snapshot = frontier.snapshot()
    for key, items in browser_snapshot.items():
        seen = {json.dumps(item, sort_keys=True) for item in snapshot[key]}
        for item in items:
            encoded = json.dumps(item, sort_keys=True)
            if encoded not in seen:
                snapshot[key].append(item)
                seen.add(encoded)
    ingest = ingest_records(
        records, target=surface_target, base=base, db_path=memory_db_path(), max_records=max_urls
    )
    tokens = compile_wordlist(records, extra_texts=js_texts, base=base, limit=400)
    host_slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", parsed.hostname or surface_target).strip("_") or "target"
    wordlist_path = os.path.join(artifact_dir(), f"wordlist-{host_slug}.txt")
    write_wordlist(tokens, wordlist_path)
    queue = next_work(surface_target, limit=15, db_path=memory_db_path())
    artifact = write_artifact({
        "target": surface_target,
        "base_url": base,
        "probe": probe,
        "record_count": len(records),
        "ingest": ingest,
        "wordlist_path": wordlist_path,
        "wordlist_size": len(tokens),
        "skipped_links": skipped_links,
        **snapshot,
    }, prefix="discover")
    return json.dumps({
        "target": surface_target,
        "base_url": base,
        "mode": mode,
        "probe": probe,
        "ingested": ingest.get("total_touched", 0),
        "inserted": ingest.get("inserted", 0),
        "updated": ingest.get("updated", 0),
        "sources": ingest.get("sources", {}),
        "historic": historic,
        "wordlist_path": wordlist_path,
        "wordlist_size": len(tokens),
        "wordlist_sample": tokens[:20],
        "skipped_links": skipped_links,
        **snapshot,
        "errors": errors[:12],
        **({"stop_reason": stop_reason} if stop_reason else {}),
        "artifact": artifact,
        "work_queue": queue.get("queue", []),
        "total_surface": queue.get("total_surface", 0),
        "untested": queue.get("untested", 0),
    }, indent=2, ensure_ascii=False, default=str)


@mcp.tool()
def compile_target_wordlist(target: str, js_text: str = "", openapi_json: str = "",
                            limit: int = 400) -> str:
    """Hedefe özel ffuf/param wordlist: attack_surface + JS + OpenAPI token'ları.

    SecLists yerine JS path, query key ve OpenAPI param adlarını yazar.
    """
    if not HAS_SURFACE:
        return json.dumps({"error": "surface core yüklenemedi"}, ensure_ascii=False)
    if not (target or "").strip():
        return json.dumps({"error": "target gerekli"}, ensure_ascii=False)
    records = query_surface(target, limit=500, db_path=memory_db_path())
    extra_texts = [js_text] if js_text else []
    if openapi_json:
        records = list(records) + parse_openapi(openapi_json, target=target)
    tokens = compile_wordlist(records, extra_texts=extra_texts, limit=limit)
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", target).strip("_")[:80] or "target"
    path = os.path.join(artifact_dir(), f"wordlist-{slug}.txt")
    write_wordlist(tokens, path)
    return json.dumps({
        "target": target,
        "path": path,
        "size": len(tokens),
        "sample": tokens[:24],
        "surface_records": len(records),
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def crawl_web_surface(
    target: str,
    max_pages: int = 40,
    cookie: str = "",
    headers: str = "",
    allow_subdomains: bool = False,
    timeout: int = 120,
    session_target: str = "",
    identity: str = "",
) -> str:
    """Playwright BFS crawl + XHR/fetch yakala → attack_surface ingest.

    Discover tek hop; bu tool aynı host'ta link takip eder, form/hidden input
    ve SPA XHR endpoint'lerini JSON kuyruğa yazar. Playwright yoksa net hata.

    Args:
        target: Başlangıç URL
        max_pages: BFS tavanı (varsayılan 40)
        cookie: Cookie header (auth ikinci tur, ör: session=userA)
        headers: JSON object veya 'Name: value' satırları
        allow_subdomains: Eski çağrılar için korunur; crawl ayrı origin'e çıkmaz
        timeout: toplam zaman aşımı (saniye; sayfa başına 15s)
        session_target: Doğrulanmış oturumun tam kayıt hedefi; gizli veri içermez
        identity: Kayıtlı hesap etiketi; oturum araç içinde çözülür
    """
    if not HAS_SURFACE:
        return json.dumps({"error": "surface core yüklenemedi"}, ensure_ascii=False)
    raw = (target or "").strip()
    if not raw:
        return json.dumps({"error": "target gerekli"}, ensure_ascii=False)
    extra = headers
    if headers and str(headers).strip().startswith("{"):
        try:
            extra = json.loads(headers)
        except json.JSONDecodeError:
            extra = headers
    crawled = crawl_site(
        raw if "://" in raw else f"https://{raw}",
        max_pages=max(1, int(max_pages or 40)),
        cookie=cookie,
        headers=extra,
        timeout_ms=min(20000, max(5000, int(timeout) * 100)),
        allow_subdomains=allow_subdomains,
        session_target=session_target,
        identity=identity,
    )
    if not crawled.get("ok"):
        return json.dumps({
            "ok": False,
            "error": crawled.get("error") or playwright_missing_msg(),
            "playwright": bool(HAS_PLAYWRIGHT),
        }, ensure_ascii=False)
    from cco_surface_core.normalize import canonical_target
    # Preserve the port in the inventory key so scoped coverage and access
    # consume the same surface; hostname-only storage loses loopback identity.
    surface_target = canonical_target(crawled.get("url") or raw)
    records = crawled.get("records") or parse_browser_crawl(crawled, target=surface_target)
    ingest = ingest_records(records, target=surface_target, db_path=memory_db_path(), max_records=800)
    artifact = write_artifact({
        "target": surface_target,
        "url": crawled.get("url"),
        "pages": len(crawled.get("pages") or []),
        "xhr": len(crawled.get("xhr") or []),
        "forms": len(crawled.get("forms") or []),
        "ingest": ingest,
    }, prefix="crawl")
    queue = next_work(surface_target, limit=15, db_path=memory_db_path())
    urls = [item.get("url") for item in records if item.get("url")]
    return json.dumps({
        "ok": True,
        "target": surface_target,
        "base_url": crawled.get("url"),
        "pages": crawled.get("pages") or [],
        "page_count": len(crawled.get("pages") or []),
        "form_count": len(crawled.get("forms") or []),
        "xhr_count": len(crawled.get("xhr") or []),
        "xhr": crawled.get("xhr") or [],
        "urls_sample": urls[:40],
        "records": records,
        "ingested": ingest.get("total_touched", 0),
        "inserted": ingest.get("inserted", 0),
        "updated": ingest.get("updated", 0),
        "artifact": artifact,
        "work_queue": queue.get("queue", []),
        "errors": crawled.get("errors") or [],
    }, indent=2, ensure_ascii=False, default=str)


@mcp.tool()
def zap_map_surface(
    target: str,
    ajax: bool = False,
    allow_ascan: bool = False,
    timeout: int = 180,
    snapshot_json: str = "",
) -> str:
    """Import a scope-filtered ZAP snapshot; live ZAP mapping is unavailable.

    Snapshot'taki alert'ler hipotezdir, doğrulanmış bulgu değildir. Kapsam ve
    origin dışı kayıtlar, yazma metotları ve sorgu değerleri içeri alınmaz.

    Args:
        target: Hedef URL
        ajax: Eski çağrılar için korunur; canlı tarama başlatmaz
        allow_ascan: Eski çağrılar için korunur; aktif tarama başlatmaz
        timeout: Eski çağrılar için korunur
        snapshot_json: Önceden toplanmış ZAP urls ve alerts JSON nesnesi
    """
    if not HAS_SURFACE:
        return json.dumps({"ok": False, "error": "surface core yüklenemedi"}, ensure_ascii=False)
    raw = (target or "").strip()
    if not raw:
        return json.dumps({"ok": False, "error": "target gerekli"}, ensure_ascii=False)
    if snapshot_json and (ajax or allow_ascan):
        return json.dumps({"ok": False, "error": "offline snapshot cannot start scans"})
    mapped = (import_zap_snapshot(raw, snapshot_json) if snapshot_json else
              run_zap_map(raw, ajax=bool(ajax), allow_ascan=bool(allow_ascan), timeout=int(timeout or 180)))
    if not mapped.get("ok"):
        return json.dumps({
            "ok": False,
            "error": mapped.get("error") or zap_missing_msg(),
            "ascan": {"skipped": True, "ran": False},
        }, ensure_ascii=False)
    records = mapped.get("records") or parse_zap(
        {"urls": mapped.get("urls") or [], "alerts": mapped.get("alerts") or []},
        target=_target_from_url(mapped.get("target") or raw),
    )
    surface_target = _target_from_url(mapped.get("target") or raw)
    ingest = ingest_records(records, target=surface_target, db_path=memory_db_path(), max_records=800)
    artifact = write_artifact({
        "target": surface_target,
        "urls": len(mapped.get("urls") or []),
        "alerts": len(mapped.get("alerts") or []),
        "ascan": mapped.get("ascan"),
        "ingest": ingest,
        "verdict": None,
    }, prefix="zap")
    queue = next_work(surface_target, limit=15, db_path=memory_db_path())
    return json.dumps({
        "ok": True,
        "target": surface_target,
        "url_count": len(mapped.get("urls") or []),
        "alert_count": len(mapped.get("alerts") or []),
        "ingested": ingest.get("total_touched", 0),
        "inserted": ingest.get("inserted", 0),
        "updated": ingest.get("updated", 0),
        "ascan": mapped.get("ascan") or {"skipped": True, "ran": False},
        "ajax": mapped.get("ajax"),
        "calls": mapped.get("calls") or [],
        "verdict": None,
        "artifact": artifact,
        "work_queue": queue.get("queue", []),
        "urls_sample": (mapped.get("urls") or [])[:30],
        "alert_titles": [
            str((item or {}).get("alert") or (item or {}).get("name") or "")[:80]
            for item in (mapped.get("alerts") or [])[:12]
            if isinstance(item, dict)
        ],
        "mode": mapped.get("mode"),
        "discarded": mapped.get("discarded", 0),
    }, indent=2, ensure_ascii=False, default=str)


# --- IMPACKET SUITE ---

@mcp.tool()
def impacket_tool(
    tool_name: str,
    target: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    hashes: str = "",
    extra_args: str = ""
) -> str:
    """
    Impacket suite araçları (AD/SMB/Kerberos operasyonları).
    
    Args:
        tool_name: Araç adı: secretsdump, psexec, wmiexec, smbexec, 
                   GetNPUsers, GetUserSPNs, smbclient, lookupsid, reg
        target: Hedef IP/hostname
        username: Kullanıcı adı
        password: Şifre
        domain: AD domain adı
        hashes: NTLM hash (LM:NT formatında)
        extra_args: Ek argümanlar
    """
    # Credential string'i oluştur
    cred = ""
    if domain and username:
        cred = f"{shlex.quote(domain)}/{shlex.quote(username)}"
    elif username:
        cred = shlex.quote(username)
    
    if password:
        cred += f":{shlex.quote(password)}"
    elif hashes:
        cred += f" -hashes {shlex.quote(hashes)}"
    
    if cred:
        cred += f"@{shlex.quote(target)}"
    else:
        cred = shlex.quote(target)
    
    cmd = f"impacket-{tool_name} {cred} {extra_args}"
    result = run_command(cmd, timeout=120)
    return format_output(result)


# --- AD ENUMERATION ---

@mcp.tool()
def bloodhound_collect(
    target: str,
    username: str,
    password: str,
    domain: str,
    collection: str = "All",
    extra_args: str = ""
) -> str:
    """
    BloodHound (bloodhound-python) ile Active Directory enumeration.
    
    Args:
        target: Domain Controller IP
        username: AD kullanıcı adı
        password: AD şifresi
        domain: AD domain adı (ör: corp.local)
        collection: Koleksiyon tipi (All, Group, LocalAdmin, Session, Trusts, ACL)
        extra_args: Ek argümanlar
    """
    cmd = (f"bloodhound-python -u {shlex.quote(username)} -p {shlex.quote(password)} "
           f"-d {shlex.quote(domain)} -ns {shlex.quote(target)} "
           f"-c {shlex.quote(collection)} --zip {extra_args}")
    result = run_command(cmd, timeout=300)
    return format_output(result)


# --- DESERIALIZATION ---

@mcp.tool()
def ysoserial_generate(
    payload_type: str,
    command: str,
    extra_args: str = ""
) -> str:
    """
    ysoserial ile Java deserialization payload üretimi.
    
    Args:
        payload_type: Payload tipi (CommonsCollections1-7, Jdk7u21, Spring, Groovy, vb.)
        command: Çalıştırılacak komut (ör: '/bin/bash -c id')
        extra_args: Ek argümanlar
    """
    cmd = f"java -jar /opt/ysoserial/ysoserial.jar {shlex.quote(payload_type)} {shlex.quote(command)} {extra_args}"
    result = run_command(cmd, timeout=30)
    if result["stdout"]:
        encoded = base64.b64encode(result["stdout"].encode()).decode()
        return f"Payload (base64):\n{encoded}\n\nRaw length: {len(result['stdout'])} bytes"
    return format_output(result)


# --- SYMBOLIC EXECUTION ---

@mcp.tool()
def angr_analyze(
    binary_path: str,
    find_addr: str = "",
    avoid_addr: str = "",
    extra_args: str = ""
) -> str:
    """
    angr ile symbolic execution (CTF pwn otomatize çözücü).
    
    Args:
        binary_path: Binary dosya yolu
        find_addr: Hedef adres (hex, ör: '0x4011a0')
        avoid_addr: Kaçınılacak adres (hex, ör: '0x401180')
        extra_args: Ek argümanlar
    """
    find_part = f"find=int('{find_addr}',16)," if find_addr else ""
    avoid_part = f"avoid=[int('{avoid_addr}',16)]," if avoid_addr else ""
    
    script = f"""
import angr, sys
p = angr.Project('{binary_path}', auto_load_libs=False)
state = p.factory.entry_state()
simgr = p.factory.simulation_manager(state)
simgr.explore({find_part} {avoid_part} timeout=120)
if simgr.found:
    s = simgr.found[0]
    print('FOUND! Input:', s.posix.dumps(0))
    print('Output:', s.posix.dumps(1))
else:
    print('No solution found')
"""
    
    script_path = tempfile.mktemp(suffix=".py")
    with open(script_path, "w") as f:
        f.write(script)
    
    result = run_command(f"python3 {script_path}", timeout=180)
    os.unlink(script_path)
    return format_output(result)


# --- HEADLESS RE ---

@mcp.tool()
def ghidra_headless(
    binary_path: str,
    script: str = "",
    project_dir: str = "/tmp/ghidra_projects",
    extra_args: str = ""
) -> str:
    """
    Ghidra headless analyzer ile otomatik reverse engineering.
    
    Args:
        binary_path: Analiz edilecek binary dosya yolu
        script: Çalıştırılacak Ghidra script (boş: varsayılan analiz)
        project_dir: Ghidra proje dizini
        extra_args: Ek argümanlar
    """
    os.makedirs(project_dir, exist_ok=True)
    proj_name = os.path.basename(binary_path).replace(".", "_")
    
    script_part = f"-postScript {shlex.quote(script)}" if script else ""
    cmd = (f"analyzeHeadless {shlex.quote(project_dir)} {proj_name} "
           f"-import {shlex.quote(binary_path)} -overwrite "
           f"{script_part} {extra_args}")
    result = run_command(cmd, timeout=300)
    return format_output(result)


# --- MOBILE TESTING ---

@mcp.tool()
def frida_hook(
    target: str,
    script_code: str = "",
    script_file: str = "",
    extra_args: str = ""
) -> str:
    """
    Frida ile runtime hooking (mobile app / thick client testing).
    
    Args:
        target: Hedef process adı veya PID
        script_code: Inline JavaScript hook kodu
        script_file: Hook script dosya yolu
        extra_args: Ek argümanlar (ör: '-U' USB device)
    """
    if script_code:
        script_path = tempfile.mktemp(suffix=".js")
        with open(script_path, "w") as f:
            f.write(script_code)
        cmd = f"frida -l {script_path} {shlex.quote(target)} {extra_args}"
    elif script_file:
        cmd = f"frida -l {shlex.quote(script_file)} {shlex.quote(target)} {extra_args}"
    else:
        cmd = f"frida {shlex.quote(target)} {extra_args}"
    
    result = run_command(cmd, timeout=60)
    return format_output(result)


# --- NETWORK INTERCEPTION ---

@mcp.tool()
def mitmproxy_dump(
    listen_port: int = 8080,
    target_url: str = "",
    script: str = "",
    timeout: int = 30,
    extra_args: str = ""
) -> str:
    """
    mitmdump ile traffic capture ve analiz.
    
    Args:
        listen_port: Dinleme portu
        target_url: URL filtresi (opsiyonel)
        script: mitmdump script yolu (opsiyonel)
        timeout: Capture süresi (saniye)
        extra_args: Ek argümanlar
    """
    flow_filter = f"~u {shlex.quote(target_url)}" if target_url else ""
    script_part = f"-s {shlex.quote(script)}" if script else ""
    dump_file = f"/tmp/mitm_capture_{int(time.time())}.flow"
    
    cmd = (f"timeout {timeout} mitmdump -p {listen_port} "
           f"-w {dump_file} {script_part} {flow_filter} {extra_args} 2>&1")
    result = run_command(cmd, timeout=timeout + 10)
    
    output = format_output(result)
    if os.path.exists(dump_file):
        output += f"\n\nCapture dosyası: {dump_file} ({os.path.getsize(dump_file)} bytes)"
    return output


# ============================================================
# VISION / MULTIMODAL KATMANI (v2.0 — Phase 3)
# ============================================================

@mcp.tool()
def screenshot_analyze(
    url: str = "",
    image_path: str = "",
    analysis_type: str = "general"
) -> str:
    """
    Web sayfası screenshot'ı al ve/veya mevcut görseli analiz et.
    
    Args:
        url: Screenshot alınacak URL
        image_path: Mevcut görsel dosyası yolu
        analysis_type: Analiz tipi:
            - 'general': Genel bilgi çıkarma (OCR + metadata)
            - 'steg': Steganografi analizi
            - 'ocr': Sadece OCR (metin çıkarma)
            - 'metadata': Sadece EXIF/metadata
    """
    outputs = []
    
    # URL'den screenshot al
    if url and not image_path:
        image_path = f"/tmp/screenshot_{int(time.time())}.png"
        # cutycapt veya wkhtmltoimage dene
        r = run_command(f"cutycapt --url={shlex.quote(url)} --out={image_path} 2>/dev/null", timeout=30)
        if r['returncode'] != 0:
            r = run_command(f"wkhtmltoimage --quality 80 {shlex.quote(url)} {image_path} 2>/dev/null", timeout=30)
        if r['returncode'] != 0:
            return "HATA: Screenshot alınamadı. cutycapt veya wkhtmltoimage kurun."
        outputs.append(f"📸 Screenshot alındı: {image_path}")
    
    if not image_path or not os.path.exists(image_path):
        return "HATA: Geçerli bir image_path veya url sağlayın."
    
    if analysis_type in ("general", "ocr"):
        r = run_command(f"tesseract {shlex.quote(image_path)} stdout 2>/dev/null", timeout=30)
        if r['stdout'].strip():
            outputs.append(f"📝 OCR Sonucu:\n{r['stdout'].strip()[:2000]}")
    
    if analysis_type in ("general", "metadata"):
        r = run_command(f"exiftool {shlex.quote(image_path)} 2>/dev/null", timeout=15)
        if r['stdout'].strip():
            outputs.append(f"📋 Metadata:\n{r['stdout'].strip()[:1000]}")
    
    if analysis_type in ("general", "steg"):
        steg_results = []
        for cmd_name, cmd in [
            ("zsteg", f"zsteg {shlex.quote(image_path)} 2>/dev/null"),
            ("strings", f"strings {shlex.quote(image_path)} | grep -iE 'flag|ctf|key|pass|secret|token' | head -20"),
            ("binwalk", f"binwalk {shlex.quote(image_path)} 2>/dev/null"),
        ]:
            r = run_command(cmd, timeout=30)
            if r['stdout'].strip():
                steg_results.append(f"[{cmd_name}]\n{r['stdout'].strip()[:500]}")
        if steg_results:
            outputs.append("🔍 Steganografi/Hidden Data:\n" + "\n".join(steg_results))
    
    return "\n\n".join(outputs) if outputs else "Analiz sonucu boş."


@mcp.tool()
def steg_deep_analyze(
    image_path: str
) -> str:
    """
    Görsel dosyada derinlemesine steganografi analizi.
    Tüm bilinen steg araçlarını otomatik çalıştırır.
    
    Args:
        image_path: Analiz edilecek görsel dosya yolu
    """
    if not os.path.exists(image_path):
        return f"HATA: Dosya bulunamadı: {image_path}"
    
    outputs = []
    commands = [
        ("file", f"file {shlex.quote(image_path)}"),
        ("exiftool", f"exiftool {shlex.quote(image_path)} 2>/dev/null"),
        ("binwalk", f"binwalk {shlex.quote(image_path)} 2>/dev/null"),
        ("zsteg", f"zsteg {shlex.quote(image_path)} 2>/dev/null"),
        ("steghide_info", f"steghide info -sf {shlex.quote(image_path)} 2>&1"),
        ("strings_flags", f"strings {shlex.quote(image_path)} | grep -iE 'flag|ctf|key|pass|secret|hack|admin' | head -30"),
        ("strings_b64", f"strings {shlex.quote(image_path)} | grep -E '^[A-Za-z0-9+/]{{20,}}=*$' | head -10"),
        ("xxd_header", f"xxd {shlex.quote(image_path)} | head -20"),
        ("foremost", f"foremost -T -i {shlex.quote(image_path)} -o /tmp/foremost_{int(time.time())} 2>/dev/null; ls -la /tmp/foremost_{int(time.time())}/*/ 2>/dev/null"),
    ]
    
    for name, cmd in commands:
        result = run_command(cmd, timeout=30)
        if result["stdout"].strip():
            outputs.append(f"=== {name.upper()} ===\n{result['stdout'].strip()[:800]}")
    
    if outputs:
        return f"🔬 Derin Steganografi Analizi: {image_path}\n{'='*50}\n\n" + "\n\n".join(outputs)
    return "Steganografi verisi bulunamadı."


# ============================================================
# OSINT ENGINE (v2.0 — Phase 6)
# ============================================================

@mcp.tool()
def osint_harvest(
    domain: str,
    sources: str = "all",
    extra_args: str = ""
) -> str:
    """theHarvester ile email, subdomain, host ve IP keşfi.

    Args:
        domain: Hedef domain (ör: example.com)
        sources: Veri kaynakları (all, google, bing, linkedin, twitter, shodan, censys, crtsh)
        extra_args: Ek argümanlar
    """
    src = sources if sources != "all" else "google,bing,crtsh,dnsdumpster,threatminer"
    cmd = f"theHarvester -d {shlex.quote(domain)} -b {src} {extra_args}"
    result = run_command(cmd, timeout=120)
    return format_output(result)


@mcp.tool()
def sherlock_lookup(
    username: str,
    extra_args: str = ""
) -> str:
    """Sherlock ile kullanıcı adını 300+ sosyal medya platformunda ara.

    Args:
        username: Aranacak kullanıcı adı
        extra_args: Ek argümanlar (ör: '--timeout 10')
    """
    cmd = f"sherlock {shlex.quote(username)} --print-found {extra_args}"
    result = run_command(cmd, timeout=120)
    output = format_output(result)
    lines = output.strip().split("\n")
    if len(lines) > 100:
        return "\n".join(lines[:100]) + f"\n... (toplam {len(lines)} platform)"
    return output


@mcp.tool()
def whois_enrichment(
    target: str
) -> str:
    """WHOIS + DNS + ASN zenginleştirme — tek komutla tüm pasif keşif.

    Args:
        target: Domain veya IP adresi
    """
    outputs = []

    # WHOIS
    r = run_command(f"whois {shlex.quote(target)} 2>/dev/null | head -50", timeout=15)
    if r["stdout"].strip():
        outputs.append(f"📋 WHOIS:\n{r['stdout'].strip()}")

    # DNS kayıtları
    for record_type in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]:
        r = run_command(f"dig +short {shlex.quote(target)} {record_type} 2>/dev/null", timeout=10)
        if r["stdout"].strip():
            outputs.append(f"🌐 DNS {record_type}: {r['stdout'].strip()}")

    # ASN
    r = run_command(f"whois -h whois.radb.net -- '-i origin {shlex.quote(target)}' 2>/dev/null | head -20", timeout=10)
    if r["stdout"].strip():
        outputs.append(f"🏢 ASN:\n{r['stdout'].strip()}")

    # SSL sertifika bilgisi
    r = run_command(f"echo | openssl s_client -connect {shlex.quote(target)}:443 -servername {shlex.quote(target)} 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null", timeout=10)
    if r["stdout"].strip():
        outputs.append(f"🔒 SSL:\n{r['stdout'].strip()}")

    return "\n\n".join(outputs) if outputs else f"'{target}' için bilgi bulunamadı."


@mcp.tool()
def spiderfoot_scan(
    target: str,
    scan_type: str = "all",
    extra_args: str = ""
) -> str:
    """SpiderFoot ile kapsamlı OSINT taraması.

    Args:
        target: Hedef domain, IP, email veya kullanıcı adı
        scan_type: Tarama tipi ('all', 'passive', 'footprint')
        extra_args: Ek argümanlar
    """
    cmd = f"spiderfoot -s {shlex.quote(target)} -t {scan_type} -q {extra_args}"
    result = run_command(cmd, timeout=300)
    return format_output(result)


# ============================================================
# CLOUD SECURITY SCANNER (v2.0 — Phase 6)
# ============================================================

@mcp.tool()
def cloud_enum(
    target: str,
    providers: str = "aws,azure,gcp",
    extra_args: str = ""
) -> str:
    """Cloud asset enumeration — S3 bucket, Azure blob, GCP bucket keşfi.

    Args:
        target: Hedef şirket/domain adı (ör: 'acmecorp', 'example.com')
        providers: Sağlayıcılar (aws, azure, gcp — virgülle ayrılmış)
        extra_args: Ek argümanlar
    """
    outputs = []
    keyword = target.replace(".com", "").replace(".", "-")

    if "aws" in providers:
        # S3 bucket enumeration
        common_patterns = [keyword, f"{keyword}-dev", f"{keyword}-backup", f"{keyword}-prod",
                          f"{keyword}-staging", f"{keyword}-data", f"{keyword}-assets",
                          f"{keyword}-logs", f"{keyword}-uploads", f"{keyword}-static"]
        s3_found = []
        for bucket in common_patterns:
            r = run_command(f"curl -s -o /dev/null -w '%{{http_code}}' https://{bucket}.s3.amazonaws.com/ 2>/dev/null", timeout=5)
            code = r["stdout"].strip()
            if code in ("200", "403"):
                status = "🟢 PUBLIC" if code == "200" else "🟡 EXISTS (403)"
                s3_found.append(f"  {status}: {bucket}.s3.amazonaws.com")
        if s3_found:
            outputs.append("☁️ AWS S3 Buckets:\n" + "\n".join(s3_found))

    if "azure" in providers:
        azure_found = []
        for name in [keyword, f"{keyword}dev", f"{keyword}prod"]:
            r = run_command(f"curl -s -o /dev/null -w '%{{http_code}}' https://{name}.blob.core.windows.net/ 2>/dev/null", timeout=5)
            code = r["stdout"].strip()
            if code != "000" and code != "404":
                azure_found.append(f"  [{code}]: {name}.blob.core.windows.net")
        if azure_found:
            outputs.append("☁️ Azure Blobs:\n" + "\n".join(azure_found))

    if "gcp" in providers:
        gcp_found = []
        for name in [keyword, f"{keyword}-dev", f"{keyword}-data"]:
            r = run_command(f"curl -s -o /dev/null -w '%{{http_code}}' https://storage.googleapis.com/{name}/ 2>/dev/null", timeout=5)
            code = r["stdout"].strip()
            if code in ("200", "403"):
                status = "🟢 PUBLIC" if code == "200" else "🟡 EXISTS"
                gcp_found.append(f"  {status}: storage.googleapis.com/{name}")
        if gcp_found:
            outputs.append("☁️ GCP Buckets:\n" + "\n".join(gcp_found))

    # cloud_enum tool varsa çalıştır
    r = run_command("which cloud_enum 2>/dev/null", timeout=3)
    if r["returncode"] == 0:
        r = run_command(f"cloud_enum -k {shlex.quote(keyword)} {extra_args}", timeout=120)
        if r["stdout"].strip():
            outputs.append(f"🔍 cloud_enum:\n{r['stdout'].strip()[:1500]}")

    return "\n\n".join(outputs) if outputs else f"'{target}' için cloud asset bulunamadı."


@mcp.tool()
def aws_security_check(
    profile: str = "default",
    service: str = "all",
    extra_args: str = ""
) -> str:
    """Prowler/ScoutSuite ile AWS güvenlik denetimi (kendi hesabınız için).

    Args:
        profile: AWS CLI profili
        service: Servis filtresi (all, s3, iam, ec2, rds, lambda)
        extra_args: Ek argümanlar
    """
    # Prowler dene
    r = run_command("which prowler 2>/dev/null", timeout=3)
    if r["returncode"] == 0:
        svc = f"-S {service}" if service != "all" else ""
        cmd = f"prowler aws -p {shlex.quote(profile)} {svc} --severity critical high {extra_args}"
        result = run_command(cmd, timeout=600)
        return format_output(result)

    # ScoutSuite dene
    r = run_command("which scout 2>/dev/null", timeout=3)
    if r["returncode"] == 0:
        cmd = f"scout aws --profile {shlex.quote(profile)} {extra_args}"
        result = run_command(cmd, timeout=600)
        return format_output(result)

    return "HATA: Prowler veya ScoutSuite kurulu değil. pip install prowler-cloud veya scoutsuite"


# ============================================================
# PROFESYONEL RAPOR ÜRETİCİ (v2.0 — Phase 6)
# ============================================================


_VALIDATOR_EVIDENCE_MODULE = "cco_validator_evidence_report"
_validator_evidence_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp-validator", "cco_validator_core", "evidence.py")
try:
    _validator_evidence_spec = importlib.util.spec_from_file_location(_VALIDATOR_EVIDENCE_MODULE, _validator_evidence_path)
    _validator_evidence_mod = importlib.util.module_from_spec(_validator_evidence_spec)
    _validator_evidence_spec.loader.exec_module(_validator_evidence_mod)
    _signed_artifact_is_valid = _validator_evidence_mod.artifact_is_valid
    _signed_artifact_is_current = _validator_evidence_mod.artifact_is_current
    _load_validation = getattr(_validator_evidence_mod, "load_validation", None)
    _normalize_finding_type = getattr(_validator_evidence_mod, "normalize_finding_type", None)
except Exception:
    _signed_artifact_is_valid = None
    _signed_artifact_is_current = None
    _load_validation = None
    _normalize_finding_type = None


_SQLMAP_DUMP_RE = re.compile(
    r"(^|\s)(--dump(?:-all)?|--os-shell|--sql-shell|--file-read|--os-pwn|--priv-esc)\b",
    re.I,
)


_deepen_engine_factory = None  # testler enjekte edebilir; varsayilan PolicyEngine


def _deepen_grant_check(target: str) -> dict:
    """Destructive deepen icin gercek onay (grant) dogrulamasi — fail-closed."""
    try:
        if _deepen_engine_factory is not None:
            engine = _deepen_engine_factory()
        else:
            import importlib.util as _ilu
            _path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))), "scripts", "policy_engine.py")
            _spec = _ilu.spec_from_file_location("cco_policy_engine_deepen", _path)
            _mod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            engine = _mod.PolicyEngine()
        decision = engine.validate_tool_invocation(
            "kali-tools_sqlmap_test", {"url": target or ""})
        if decision.get("allowed"):
            return {"ok": True}
        return {"ok": False,
                "error": f"deepen icin onay (grant) gerekli: {decision.get('reason')}",
                "requires_approval": True}
    except Exception as exc:  # noqa: BLE001 - fail-closed
        return {"ok": False, "error": f"onay dogrulanamadi: {type(exc).__name__}",
                "requires_approval": True}


def _sqlmap_confirmed_gate(validation_id: str, allow_deepen: bool = False,
                           action: str = "", options: str = "", target: str = "") -> dict:
    """sqlmap keşif değil; yalnızca CONFIRMED SQLi deepen."""
    if not (validation_id or "").strip():
        return {"ok": False, "error": "sqlmap yalnızca CONFIRMED SQLi deepen — validation_id gerekli"}
    if _load_validation is None:
        return {"ok": False, "error": "validator evidence yüklenemedi"}
    record = _load_validation(validation_id.strip())
    if not isinstance(record, dict):
        return {"ok": False, "error": "validation artifact bulunamadı"}
    if (_signed_artifact_is_current is None or not _signed_artifact_is_current(
            record, expected_target=target, expected_finding_type="sql_injection")):
        return {"ok": False, "error": "validation artifact doğrulanamadı"}
    if record.get("verdict") != "CONFIRMED":
        return {"ok": False, "error": f"verdict={record.get('verdict')} — CONFIRMED değil"}
    finding_type = ""
    if _normalize_finding_type:
        finding_type = _normalize_finding_type(
            (record.get("binding") or {}).get("finding_type") or record.get("vuln_type") or ""
        )
    if finding_type != "sql_injection":
        return {"ok": False, "error": "sqlmap yalnızca sql_injection CONFIRMED artifact kabul eder"}
    destructive = (action or "").strip().lower() in {"dump", "os-shell", "file-read"} or bool(
        _SQLMAP_DUMP_RE.search(options or "")
    )
    if destructive and not allow_deepen:
        return {
            "ok": False,
            "error": "dump/os-shell/file-read için allow_deepen=True ve request_approval gerekir",
            "destructive": True,
        }
    if destructive and allow_deepen:
        rec_target = target or (record.get("binding") or {}).get("target") \
            or record.get("target") or record.get("target_url") or ""
        grant = _deepen_grant_check(str(rec_target))
        if not grant.get("ok"):
            return {**grant, "destructive": True}
    return {"ok": True, "validation_id": record.get("validation_id"), "destructive": destructive}


def _load_validation_artifact(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _canonical_artifact_hash(record: dict) -> str:
    import copy as _copy
    candidate = _copy.deepcopy(record)
    candidate.setdefault("artifact", {})["content_sha256"] = ""
    payload = json.dumps(candidate, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    import hashlib as _hashlib
    return _hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _artifact_path_in_trusted_root(path: str) -> bool:
    if not path:
        return False
    try:
        candidate = os.path.realpath(os.path.expanduser(path))
        root = os.path.realpath(os.path.join(CCO_HOME, "validations"))
        return os.path.commonpath([root, candidate]) == root
    except (OSError, ValueError):
        return False


def _validation_artifact_current(path: str, target: str = "", finding_type: str = "") -> bool:
    artifact = _load_validation_artifact(path)
    if not artifact:
        return False
    if _signed_artifact_is_current is not None:
        return bool(_signed_artifact_is_current(
            artifact,
            expected_target=target,
            expected_finding_type=finding_type,
            expected_path=path,
        ))
    return False


def _validation_excerpt(artifact: dict, limit: int = 280) -> str:
    if not artifact:
        return ""
    parts = []
    evidence = artifact.get("evidence")
    if isinstance(evidence, list):
        parts.extend(str(item) for item in evidence[:2] if item)
    elif isinstance(evidence, dict):
        for key in list(evidence.keys())[:2]:
            value = evidence.get(key)
            if isinstance(value, (str, int, float, bool)):
                parts.append(f"{key}={value}")
    elif evidence:
        parts.append(str(evidence))

    differential = artifact.get("differential") or {}
    if isinstance(differential, dict):
        for key in ("shared_markers", "required_markers", "attacker_status", "authorized_status"):
            value = differential.get(key)
            if value:
                parts.append(f"{key}={value}")

    request_evidence = artifact.get("request_evidence") or []
    for item in request_evidence[:2]:
        if not isinstance(item, dict):
            continue
        role = item.get("role") or "probe"
        status = item.get("status")
        excerpt = item.get("excerpt") or ""
        snippet = f"{role}:{status}"
        if excerpt:
            snippet += f" {excerpt}"
        parts.append(snippet)

    notes = artifact.get("notes")
    if notes:
        parts.append(str(notes))

    compact = " | ".join(part.strip() for part in parts if str(part).strip())
    return _redact_secrets(compact[:limit])


def _campaign_close_out_gate(campaign_id: int, output_format: str) -> str | None:
    """Kampanya raporu kapanış denetimi: engel varsa mesaj döner, yoksa None."""
    scripts_dir = os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    def blocked(reason: str, hint: str = "", untested: list | None = None):
        detail = {"blocked": True, "reason": reason, "hint": hint,
                  "untested": untested or []}
        if output_format == "json":
            return json.dumps(detail, ensure_ascii=False)
        lines = ["# Rapor Engellendi: kampanya kapanışı tamamlanmamış",
                 "", f"- Sebep: `{reason}`"]
        if detail["untested"]:
            lines.append(f"- Test edilmemiş rota: {len(detail['untested'])}")
        if hint:
            lines.append(f"- Sıradaki adım: {hint}")
        return "\n".join(lines)

    try:
        from campaign_runtime import CampaignRuntime
    except ImportError:
        return blocked("runtime yok")
    try:
        check = CampaignRuntime(cco_home=CCO_HOME).check_close_out(
            int(campaign_id), require_brain_review=True)
    except Exception as exc:
        return blocked(f"denetim hatası: {type(exc).__name__}")
    if check.get("ok"):
        return None
    return blocked(check.get("reason", "bilinmiyor"), check.get("hint", ""),
                   check.get("untested", []))


_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*(?:basic|bearer)\s+)(\S+)"),
    re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9\-._~+/=]{8,})"),
    re.compile(r"(?i)((?:cookie|set-cookie|sess|session(?:id)?|password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*)([^\s;,\"'}]+)"),
)


def _redact_secrets(text: str) -> str:
    """Rapor yüzeyinde credential/secret sızıntısını engelle."""
    if not text:
        return text
    redacted = str(text)
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted

@mcp.tool()
def generate_pentest_report(
    target: str,
    report_type: str = "executive",
    output_format: str = "markdown",
    campaign_id: int = 0
) -> str:
    """Memory server'daki verilerden otomatik pentest raporu oluştur.
    Knowledge Graph + findings + credentials + endpoints → profesyonel rapor.

    Args:
        target: Hedef IP/domain
        report_type: Rapor tipi ('executive': yönetici özeti, 'full': detaylı, 'findings': sadece bulgular)
        output_format: Çıktı formatı ('markdown', 'json')
        campaign_id: Kampanya bağlı raporlarda close-out denetimi uygular
            (findings/full tipleri kapanışsız çıkmaz).
    """
    if campaign_id and report_type in ("findings", "full"):
        gate = _campaign_close_out_gate(campaign_id, output_format)
        if gate is not None:
            return gate
    import sqlite3 as _sqlite3

    db_path = os.path.join(CCO_HOME, "agent_memory.db")
    if not os.path.exists(db_path):
        return "HATA: Hafızada veri yok. Önce keşif yapın."

    conn = _sqlite3.connect(db_path)
    conn.row_factory = _sqlite3.Row
    c = conn.cursor()

    scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    try:
        from target_identity import finding_context_key, target_query_matches
    except ImportError:
        conn.close()
        return "HATA: Hedef kimliği doğrulanamadı."
    try:
        aliases = {int(r[0]) for r in c.execute("SELECT alias_id FROM finding_aliases")}
    except _sqlite3.OperationalError:
        aliases = set()  # Older databases may not have migrated alias metadata.
    allowed_finding_ids = None
    if os.environ.get("CCO_ENGAGEMENT_ID", "").strip():
        if _signed_artifact_is_current is None:
            conn.close()
            return "HATA: Çalışma bağlamı doğrulanamadı."
        context = finding_context_key(_validator_evidence_mod.current_scope_revision())
        try:
            allowed_finding_ids = {int(r[0]) for r in c.execute(
                "SELECT finding_id FROM finding_identity WHERE context_key=?", (context,))}
        except _sqlite3.OperationalError:
            allowed_finding_ids = set()
    findings = [dict(r) for r in c.execute("SELECT * FROM findings")
                if int(r["id"]) not in aliases
                and (allowed_finding_ids is None or int(r["id"]) in allowed_finding_ids)
                and target_query_matches(target, r["target"])]
    creds = [dict(r) for r in c.execute("SELECT * FROM credentials")
             if target_query_matches(target, r["target"])]
    endpoints = [dict(r) for r in c.execute("SELECT * FROM endpoints")
                 if target_query_matches(target, r["target"])]
    conn.close()

    if not any([findings, creds, endpoints]):
        return f"'{target}' için hafızada veri bulunamadı."

    reportable_findings = []
    hypothesis_findings = []
    for finding in findings:
        entry = dict(finding)
        artifact_current = _validation_artifact_current(
            entry.get("validation_artifact", ""),
            target=entry.get("target", ""),
            finding_type=entry.get("type", ""),
        )
        entry["validation_artifact_current"] = artifact_current
        if bool(entry.get("reportable")) and artifact_current:
            reportable_findings.append(entry)
        else:
            if bool(entry.get("reportable")) and not artifact_current:
                entry["validation_state"] = "stale_or_invalid_artifact"
            hypothesis_findings.append(entry)

    for finding in reportable_findings:
        artifact = _load_validation_artifact(finding.get("validation_artifact", ""))
        finding["validation_excerpt"] = _validation_excerpt(artifact)

    validation_summary = {
        "by_verdict": {},
        "by_evidence_grade": {},
    }
    for finding in reportable_findings:
        verdict = str(finding.get("validation_verdict") or "unknown")
        grade = str(finding.get("validation_evidence_grade") or finding.get("validation_oracle") or "unknown")
        validation_summary["by_verdict"][verdict] = validation_summary["by_verdict"].get(verdict, 0) + 1
        validation_summary["by_evidence_grade"][grade] = validation_summary["by_evidence_grade"].get(grade, 0) + 1

    # Severity sayımları sadece artifact-backed reportable finding'lerden üretilir.
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in reportable_findings:
        sev = f.get("severity", "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # Risk skoru hesapla
    risk_score = sev_counts["critical"] * 10 + sev_counts["high"] * 7 + sev_counts["medium"] * 4 + sev_counts["low"] * 1
    risk_level = "KRİTİK" if risk_score >= 30 else "YÜKSEK" if risk_score >= 15 else "ORTA" if risk_score >= 5 else "DÜŞÜK"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if output_format == "json":
        redacted_findings = []
        for entry in reportable_findings:
            item = dict(entry)
            item["payload"] = _redact_secrets(item.get("payload", ""))
            item["description"] = _redact_secrets(item.get("description", ""))
            redacted_findings.append(item)
        redacted_hypotheses = []
        for entry in hypothesis_findings:
            item = dict(entry)
            item["payload"] = _redact_secrets(item.get("payload", ""))
            item["description"] = _redact_secrets(item.get("description", ""))
            redacted_hypotheses.append(item)
        return json.dumps({
            "target": target, "generated_at": now,
            "risk_score": risk_score, "risk_level": risk_level,
            "severity_counts": sev_counts,
            "findings": redacted_findings,
            "reportable_findings_count": len(redacted_findings),
            "hypotheses_count": len(redacted_hypotheses),
            "hypotheses": redacted_hypotheses,
            "validation_summary": validation_summary,
            "credentials_count": len(creds),
            "endpoints_count": len(endpoints)
        }, indent=2, default=str)

    # Markdown rapor
    report = f"""# 🔴 Penetrasyon Testi Raporu

| Alan | Değer |
|------|-------|
| **Hedef** | `{target}` |
| **Tarih** | {now} |
| **Risk Düzeyi** | **{risk_level}** (Skor: {risk_score}) |
| **Agent** | HackerAgent v2.0 |

## Yönetici Özeti

{target} hedefi üzerinde yapılan otomatik penetrasyon testinde artifact-backed doğrulama ile toplam **{len(reportable_findings)} raporlanabilir bulgu** tespit edilmiştir.

Doğrulanmamış / artifact-backed olmayan hipotez sayısı: **{len(hypothesis_findings)}**

Artifact-backed validation verdict dağılımı: **{', '.join(f'{k}={v}' for k, v in sorted(validation_summary['by_verdict'].items())) or 'yok'}**

Evidence grade / oracle dağılımı: **{', '.join(f'{k}={v}' for k, v in sorted(validation_summary['by_evidence_grade'].items())) or 'yok'}**

| Severity | Sayı |
|----------|------|
| 🔴 Critical | {sev_counts['critical']} |
| 🟠 High | {sev_counts['high']} |
| 🟡 Medium | {sev_counts['medium']} |
| 🟢 Low | {sev_counts['low']} |
| ⚪ Info | {sev_counts['info']} |

Keşfedilen endpoint sayısı: **{len(endpoints)}**
Ele geçirilen credential sayısı: **{len(creds)}**
"""

    if report_type in ("full", "findings"):
        report += "\n## Detaylı Bulgular\n\n"
        if not reportable_findings:
            report += "_Artifact-backed reportable finding bulunamadı._\n\n"
        for i, f in enumerate(reportable_findings, 1):
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.get("severity", "").lower(), "⚪")
            report += f"""### {i}. {sev_emoji} {f.get('type', 'Unknown')} [{f.get('severity', '?').upper()}]

**Açıklama:** {_redact_secrets(f.get('description', 'N/A'))}

**Payload:** `{_redact_secrets(f.get('payload', 'N/A'))}`

**Validation Verdict:** `{f.get('validation_verdict', '-') or '-'}`

**Evidence Grade:** `{f.get('validation_evidence_grade', '-') or '-'}`

**Validation Artifact:** `{f.get('validation_artifact', '-') or '-'}`

**Validation Report:** `{f.get('validation_report_path', '-') or '-'}`

**Validation Excerpt:** {f.get('validation_excerpt', '-') or '-'}

**Tarih:** {f.get('timestamp', 'N/A')}

---
"""

        if hypothesis_findings:
            report += "\n## Hariç Tutulan Hipotezler\n\n"
            report += "Aşağıdaki kayıtlar hafızada mevcut, ancak artifact-backed validator kanıtı taşımadıkları için resmî bulgu listesine alınmadı.\n\n"
            for i, f in enumerate(hypothesis_findings, 1):
                report += f"""### H{i}. {f.get('type', 'Unknown')} [{str(f.get('severity', 'info')).upper()}]

**Açıklama:** {_redact_secrets(f.get('description', 'N/A'))}

**Validation State:** `{f.get('validation_state', 'unvalidated')}`

**Validation Verdict:** `{f.get('validation_verdict', '-') or '-'}`

---
"""

    if report_type == "full" and endpoints:
        report += "\n## Keşfedilen Serviser\n\n"
        report += "| Port/URL | Protokol | Durum | Teknolojiler |\n"
        report += "|----------|----------|-------|--------------|\n"
        for ep in endpoints:
            report += f"| {ep.get('url_or_port', '?')} | {ep.get('protocol', '?')} | {ep.get('state', '?')} | {ep.get('technologies', '-')} |\n"

    if report_type == "full" and creds:
        report += f"\n## Ele Geçirilen Credentials ({len(creds)})\n\n"
        report += "| Servis | Kullanıcı | Durum |\n"
        report += "|--------|-----------|-------|\n"
        for cr in creds:
            report += f"| {cr.get('service', '?')} | {cr.get('username', '?')} | ✅ Doğrulandı |\n"

    report += f"""
## Genel Öneriler

1. **Kritik zafiyetleri** derhal yamalayın (24 saat içinde)
2. **High** seviye bulguları 1 hafta içinde düzeltin
3. WAF/IDS kurallarını güncelleyin
4. Düzenli penetrasyon testi programı oluşturun
5. Güvenlik farkındalık eğitimlerini artırın

---
*Bu rapor HackerAgent v2.0 tarafından otomatik oluşturulmuştur.*
*Rapor tarihi: {now}*
"""

    # Dosyaya kaydet
    safe_target = target.replace(".", "_").replace("/", "_")
    report_path = f"/tmp/pentest_report_{safe_target}_{int(time.time())}.md"
    try:
        with open(report_path, "w") as rf:
            rf.write(report)
    except Exception:
        report_path = None

    output = f"📋 Rapor oluşturuldu: {target}\n"
    if report_path:
        output += f"📁 Dosya: {report_path}\n"
    output += f"\n{report}"
    return output


@mcp.tool()
def cvss_calculate(
    av: str = "N", ac: str = "L", pr: str = "N", ui: str = "N",
    s: str = "U", c: str = "H", i: str = "H", a: str = "N"
) -> str:
    """CVSS v3.1 skoru hesapla.

    Args:
        av: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
        ac: Attack Complexity (L=Low, H=High)
        pr: Privileges Required (N=None, L=Low, H=High)
        ui: User Interaction (N=None, R=Required)
        s: Scope (U=Unchanged, C=Changed)
        c: Confidentiality Impact (N=None, L=Low, H=High)
        i: Integrity Impact (N=None, L=Low, H=High)
        a: Availability Impact (N=None, L=Low, H=High)
    """
    # CVSS v3.1 weight tables
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_weights = {"L": 0.77, "H": 0.44}
    pr_weights_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_weights_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_weights = {"N": 0.85, "R": 0.62}
    cia_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

    pr_weights = pr_weights_changed if s == "C" else pr_weights_unchanged

    exploitability = 8.22 * av_weights.get(av, 0) * ac_weights.get(ac, 0) * pr_weights.get(pr, 0) * ui_weights.get(ui, 0)

    isc_base = 1 - ((1 - cia_weights.get(c, 0)) * (1 - cia_weights.get(i, 0)) * (1 - cia_weights.get(a, 0)))

    if s == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    if impact <= 0:
        base_score = 0.0
    elif s == "U":
        base_score = min(impact + exploitability, 10.0)
    else:
        base_score = min(1.08 * (impact + exploitability), 10.0)

    # Yukarı yuvarlama (ceil to 1 decimal)
    import math
    base_score = math.ceil(base_score * 10) / 10

    # Severity
    if base_score >= 9.0:
        severity = "CRITICAL"
    elif base_score >= 7.0:
        severity = "HIGH"
    elif base_score >= 4.0:
        severity = "MEDIUM"
    elif base_score > 0.0:
        severity = "LOW"
    else:
        severity = "NONE"

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    return f"""📊 CVSS v3.1 Hesaplama
{'='*40}
  Vektör: {vector}
  Skor:   {base_score}
  Seviye: {severity}

  Exploitability: {exploitability:.2f}
  Impact:         {impact:.2f}
"""

# ============================================================
# HUMAN-IN-THE-LOOP APPROVAL ARAÇLARI
# ============================================================

@mcp.tool()
def request_approval(
    operation_type: str,
    description: str,
    target: str,
    payload: str = "",
    risk_level: str = "high"
) -> str:
    """
    Kritik/destructive operasyonlar için human approval iste.
    Exploit çalıştırma, credential kullanma, flag submission, lateral movement gibi
    operasyonlarda MUTLAKA bu tool çağrılmalıdır.
    
    Args:
        operation_type: Operasyon tipi ('exploit', 'credential_use', 'flag_submit', 
                        'destructive', 'lateral_movement', 'persistence', 'data_exfil')
        description: Ne yapılacağının detaylı açıklaması
        target: Hedef sistem/servis
        payload: Kullanılacak payload (varsa)
        risk_level: Risk seviyesi ('low', 'medium', 'high', 'critical')
    """
    _ensure_approval_dir()
    
    approval_id = str(uuid.uuid4())[:8]
    approval_file = os.path.join(APPROVAL_DIR, f"{approval_id}.json")
    
    approval_request = {
        "id": approval_id,
        "operation_type": operation_type,
        "description": description,
        "target": target,
        "payload": payload[:500] if payload else "",  # Payload'ı truncate et
        "risk_level": risk_level,
        "status": "pending",
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "decided_at": None,
        "decision": None
    }
    
    with open(approval_file, 'w') as f:
        json.dump(approval_request, f, indent=2)
    
    risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(risk_level, "🟡")
    
    return f"""\n{risk_emoji} ONAY GEREKLİ [{approval_id}]\n{'='*50}\nOperasyon: {operation_type}\nHedef: {target}\nRisk: {risk_level.upper()}\nAçıklama: {description}\n{'Payload: ' + payload[:200] + '...' if payload else ''}\n{'='*50}\nOnaylamak için: approve_operation(\"{approval_id}\")\nReddetmek için: reject_operation(\"{approval_id}\")\n"""


@mcp.tool()
def approve_operation(approval_id: str, note: str = "") -> str:
    """
    Bekleyen bir operasyonu onayla.
    
    Args:
        approval_id: Onay ID'si (request_approval'dan dönen)
        note: Opsiyonel onay notu
    """
    if os.environ.get("CCO_BLIND_MODE", "").strip().lower() in {"1", "true", "yes"}:
        return "HATA: Kör modda (blind_mode) ajan kendi onay isteğini onaylayamaz. Operatör onayı (PolicyEngine grant) gereklidir."

    approval_file = os.path.join(APPROVAL_DIR, f"{approval_id}.json")
    
    if not os.path.exists(approval_file):
        return f"HATA: Onay isteği bulunamadı: {approval_id}"
    
    with open(approval_file, 'r') as f:
        req = json.load(f)
    
    if req["status"] != "pending":
        return f"Bu istek zaten işlenmiş: {req['status']}"
    
    req["status"] = "approved"
    req["decided_at"] = datetime.now(timezone.utc).isoformat()
    req["decision"] = f"ONAYLANDI{' — ' + note if note else ''}"
    
    with open(approval_file, 'w') as f:
        json.dump(req, f, indent=2)
    
    return (
        f"✅ Operasyon ONAYLANDI [{approval_id}]: {req['operation_type']} → {req['target']}\n"
        f"⚠️ Not: Canlı hedef araç çağrıları merkezi güvenlik kapısı (PolicyEngine audit.db) "
        f"tarafından denetlenir (`./scripts/cco.sh security approve`)."
    )


@mcp.tool()
def reject_operation(approval_id: str, reason: str = "") -> str:
    """
    Bekleyen bir operasyonu reddet.
    
    Args:
        approval_id: Onay ID'si
        reason: Red gerekçesi
    """
    approval_file = os.path.join(APPROVAL_DIR, f"{approval_id}.json")
    
    if not os.path.exists(approval_file):
        return f"HATA: Onay isteği bulunamadı: {approval_id}"
    
    with open(approval_file, 'r') as f:
        req = json.load(f)
    
    if req["status"] != "pending":
        return f"Bu istek zaten işlenmiş: {req['status']}"
    
    req["status"] = "rejected"
    req["decided_at"] = datetime.now(timezone.utc).isoformat()
    req["decision"] = f"REDDEDİLDİ{' — ' + reason if reason else ''}"
    
    with open(approval_file, 'w') as f:
        json.dump(req, f, indent=2)
    
    return f"❌ Operasyon REDDEDİLDİ [{approval_id}]: {req['operation_type']} → {req['target']}"


@mcp.tool()
def check_approval(approval_id: str) -> str:
    """
    Bir onay isteğinin durumunu kontrol et.
    
    Args:
        approval_id: Onay ID'si
    """
    approval_file = os.path.join(APPROVAL_DIR, f"{approval_id}.json")
    
    if not os.path.exists(approval_file):
        return f"HATA: Onay isteği bulunamadı: {approval_id}"
    
    with open(approval_file, 'r') as f:
        req = json.load(f)
    
    status_emoji = {"pending": "⏳", "approved": "✅", "rejected": "❌"}.get(req["status"], "❓")
    
    return f"{status_emoji} Onay [{approval_id}]: {req['status'].upper()} | {req['operation_type']} → {req['target']}"


@mcp.tool()
def list_pending_approvals() -> str:
    """Tüm bekleyen onay isteklerini listele."""
    _ensure_approval_dir()
    
    pending = []
    for fname in os.listdir(APPROVAL_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(APPROVAL_DIR, fname)
        try:
            with open(fpath, 'r') as f:
                req = json.load(f)
            if req.get("status") == "pending":
                pending.append(req)
        except Exception:
            continue
    
    if not pending:
        return "Bekleyen onay isteği bulunmuyor."
    
    output = f"⏳ Bekleyen Onaylar ({len(pending)}):\n{'='*50}\n"
    for req in sorted(pending, key=lambda x: x.get("requested_at", "")):
        risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(req.get("risk_level", ""), "🟡")
        output += f"{risk_emoji} [{req['id']}] {req['operation_type']} → {req['target']}\n"
        output += f"   {req['description'][:80]}\n"
    
    return output


# ============================================================
# SERVER BAŞLAT
# ============================================================
# SWARM ORCHESTRATOR TOOL'LARI (v2.0 — Phase 5)
# ============================================================

@mcp.tool()
def swarm_dispatch(
    task_description: str,
    roles: str = "recon",
    target: str = ""
) -> str:
    """Multi-agent swarm'a görev gönder.
    Her agent kendi context window'unda paralel çalışır.

    Args:
        task_description: Görev açıklaması
        roles: Agent rolleri (virgülle ayrılmış):
            - recon: Keşif (Qwen — ucuz, hızlı)
            - exploit: Exploit üretimi (Hermes 405B — sansürsüz)
            - validate: Doğrulama (Qwen — dikkatli)
            - report: Raporlama (Qwen — formatlı)
        target: Hedef bilgisi (opsiyonel)
    """
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
        from swarm_orchestrator import SwarmOrchestrator, AgentRole

        orch = SwarmOrchestrator()
        role_list = [AgentRole(r.strip()) for r in roles.split(",") if r.strip()]

        if not role_list:
            return "HATA: Geçerli rol belirtilmedi. Kullanın: recon, exploit, validate, report"

        context = {"target": target} if target else {}

        if len(role_list) == 1:
            tid = orch.create_task(role_list[0], task_description, context)
            result = orch.execute_task(tid)
            return f"🤖 [{role_list[0].value.upper()}] Agent tamamlandı\n{'='*50}\n{result}"
        else:
            tasks = [(role, task_description, context) for role in role_list]
            results = orch.dispatch_parallel(tasks)

            output = f"⚡ SWARM TAMAMLANDI ({len(results)} agent)\n{'='*60}\n"
            for tid, result in results.items():
                output += f"\n{'─'*50}\n🤖 [{tid}]\n{'─'*50}\n{result[:1500]}\n"
            return output
    except ImportError:
        return "HATA: swarm_orchestrator.py bulunamadı. scripts/ dizinini kontrol edin."
    except Exception as e:
        return f"HATA: Swarm çalıştırılamadı: {e}"


@mcp.tool()
def swarm_chain(
    task_description: str,
    chain: str = "recon,exploit,validate,report",
    target: str = ""
) -> str:
    """Agent zinciri çalıştır — her agent öncekinin çıktısını alır.
    recon → exploit → validate → report pipeline'ı.

    Args:
        task_description: Başlangıç görevi
        chain: Agent zinciri (virgülle ayrılmış, sıralı handoff)
        target: Hedef bilgisi
    """
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
        from swarm_orchestrator import SwarmOrchestrator, AgentRole

        orch = SwarmOrchestrator()
        chain_roles = [AgentRole(r.strip()) for r in chain.split(",") if r.strip()]
        context = {"target": target} if target else {}

        output = f"🔗 AGENT CHAIN: {' → '.join(r.value for r in chain_roles)}\n{'='*60}\n"
        prev_result = ""

        for i, role in enumerate(chain_roles):
            prompt = task_description if i == 0 else f"Önceki agent çıktısına göre görevini yap:\n{prev_result[:2000]}"
            if prev_result:
                context["previous_output"] = prev_result[:2000]

            tid = orch.create_task(role, prompt, context)
            result = orch.execute_task(tid)

            output += f"\n{'─'*50}\n#{i+1} 🤖 [{role.value.upper()}]\n{'─'*50}\n{result[:1000]}\n"
            prev_result = result

        return output
    except Exception as e:
        return f"HATA: Agent chain çalıştırılamadı: {e}"


# ============================================================
# C2 BRIDGE (v2.0 — Phase 5)
# ============================================================

@mcp.tool()
def sliver_command(
    command: str,
    session: str = "",
    extra_args: str = ""
) -> str:
    """Sliver C2 framework ile etkileşim.
    İmplant yönetimi, beacon kontrol, lateral movement.

    Args:
        command: Sliver komutu (sessions, use, execute, upload, download, 
                 pivots, portfwd, socks5, shell, screenshot)
        session: Session ID (opsiyonel)
        extra_args: Ek argümanlar
    """
    session_part = f"--session {shlex.quote(session)}" if session else ""

    if command == "sessions":
        cmd = "sliver-client sessions"
    elif command in ("beacons", "implants", "jobs"):
        cmd = f"sliver-client {command}"
    elif session and command in ("execute", "shell", "upload", "download", "screenshot", "portfwd"):
        cmd = f"sliver-client {session_part} {command} {extra_args}"
    else:
        cmd = f"sliver-client {command} {session_part} {extra_args}"

    result = run_command(cmd, timeout=30)
    return format_output(result)


@mcp.tool()
def self_improve(
    engagement_summary: str,
    findings_count: int = 0,
    success_rate: float = 0.0,
    lessons_learned: str = ""
) -> str:
    """Engagement sonrası öz-değerlendirme ve iyileştirme notu kaydet.
    Sonraki engagement'larda RAG ile benzer hedefler için kullanılır.

    Args:
        engagement_summary: Engagement özeti
        findings_count: Bulunan toplam zafiyet sayısı
        success_rate: Başarı oranı (0.0-1.0)
        lessons_learned: Öğrenilen dersler
    """
    improvement_log = os.path.join(CCO_HOME, "improvement_log.json")

    try:
        if os.path.exists(improvement_log):
            with open(improvement_log, 'r') as f:
                logs = json.load(f)
        else:
            logs = []

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": engagement_summary,
            "findings_count": findings_count,
            "success_rate": success_rate,
            "lessons_learned": lessons_learned,
            "version": "2.0"
        }
        logs.append(entry)

        os.makedirs(os.path.dirname(improvement_log), exist_ok=True)
        with open(improvement_log, 'w') as f:
            json.dump(logs, f, indent=2)

        if lessons_learned and lessons_learned.strip():
            try:
                lessons_db = os.path.join(CCO_HOME, "lessons.db")
                lconn = sqlite3.connect(lessons_db, timeout=2.0)
                lconn.execute("""CREATE TABLE IF NOT EXISTS lessons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT, context TEXT, technique TEXT, target_tech TEXT,
                    action TEXT, outcome TEXT, worked INTEGER, tags TEXT,
                    provenance TEXT DEFAULT 'unverified')""")
                lconn.execute(
                    "INSERT INTO lessons (ts, context, technique, target_tech, action, outcome, worked, tags, provenance) "
                    "VALUES (?, ?, 'engagement_retrospective', '', ?, ?, ?, 'self_improve', 'unverified')",
                    (
                        entry["timestamp"],
                        engagement_summary[:300],
                        lessons_learned[:500],
                        f"findings={findings_count}, success_rate={success_rate:.2f}",
                        1 if findings_count > 0 or success_rate > 0 else 0,
                    ),
                )
                lconn.commit()
                lconn.close()
            except Exception:
                pass

        total_engagements = len(logs)
        avg_findings = sum(log.get("findings_count", 0) for log in logs) / max(total_engagements, 1)
        avg_success = sum(log.get("success_rate", 0) for log in logs) / max(total_engagements, 1)

        return f"""📊 Self-Improvement Log Güncellendi
{'='*40}
  Toplam engagement: {total_engagements}
  Ortalama finding: {avg_findings:.1f}
  Ortalama başarı: {avg_success:.1%}
  Son ders: {lessons_learned[:200]}

  💾 Log: {improvement_log}"""
    except Exception as e:
        return f"HATA: Log kaydedilemedi: {e}"


# ============================================================
# OOB CALLBACK SERVER — Blind Vulnerability Detection (Phase 7)
# ============================================================

# Global interactsh state
_interactsh_sessions = {}

@mcp.tool()
def interactsh_start(
    session_name: str = "default"
) -> str:
    """Interactsh callback sunucusu başlat — Blind SSRF, Blind XSS, Blind XXE tespiti için.
    Bu sunucu benzersiz bir subdomain üretir. Callback metadata'sı tek başına
    kaynağı veya bir zafiyeti doğrulamaz.

    Args:
        session_name: Oturum adı (birden fazla paralel test için)
    """
    # interactsh-client kurulu mu?
    r = run_command("which interactsh-client 2>/dev/null", timeout=5)
    if r["returncode"] != 0:
        return ("HATA: interactsh-client kurulu değil.\n"
                "Kurulum: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest\n"
                "veya: apt install interactsh -y")

    # Önceki session varsa kullan
    if session_name in _interactsh_sessions:
        info = _interactsh_sessions[session_name]
        return f"⚡ Mevcut session kullanılıyor: {session_name}\n🌐 OOB Domain: {info.get('domain', '?')}\nPID: {info.get('pid', '?')}"

    log_file = f"/tmp/interactsh_{session_name}_{int(time.time())}.log"
    banner_file = log_file + ".banner"

    try:
        # Domain stderr banner'ına basılır; -o dosyası yalnız JSON etkileşim
        # kayıtları içindir. Banner ayrı dosyaya gider, domain oradan okunur.
        banner_fh = open(banner_file, "w")  # noqa: SIM115 - süreç yaşamı boyu açık
        proc = subprocess.Popen(
            ["interactsh-client", "-json", "-o", log_file, "-poll-interval", "3"],
            stdout=banner_fh,
            stderr=banner_fh,
            text=True
        )

        # Kayıt, sunucu denemeleri nedeniyle yavaş olabilir: domaini bekle
        import re as _re
        domain = ""
        for _ in range(45):
            if proc.poll() is not None:
                break
            try:
                with open(banner_file) as f:
                    content = f.read()
            except OSError:
                content = ""
            match = _re.search(r"([a-z0-9]{10,}\.(?:oast\.[a-z]+|interact\.sh))", content)
            if match:
                domain = match.group(1)
                break
            time.sleep(1)

        _interactsh_sessions[session_name] = {
            "pid": proc.pid,
            "process": proc,
            "log_file": log_file,
            "banner_file": banner_file,
            "domain": domain,
            "started_at": datetime.now(timezone.utc).isoformat()
        }

        return f"""🟢 Interactsh Callback Server BAŞLATILDI
{'='*55}
  Session: {session_name}
  🌐 OOB Domain: {domain or '(log dosyasından kontrol edin: ' + log_file + ')'}
  PID: {proc.pid}
  Log: {log_file}

📌 KULLANIM — Bu domain'i payload'lara gömün:
  Blind SSRF:  http://{domain or 'YOUR_DOMAIN'}
  Blind XSS:   <img src=http://{domain or 'YOUR_DOMAIN'}>
  Blind XXE:   <!ENTITY xxe SYSTEM "http://{domain or 'YOUR_DOMAIN'}">

Sonuçları kontrol etmek için: interactsh_poll("{session_name}")
"""
    except Exception as e:
        return f"HATA: Interactsh başlatılamadı: {e}"


@mcp.tool()
def interactsh_poll(
    session_name: str = "default"
) -> str:
    """Interactsh callback metadata'sını göster; olay tek başına bulgu değildir.

    Args:
        session_name: Oturum adı
    """
    info = _interactsh_sessions.get(session_name)
    if not info:
        return f"HATA: '{session_name}' session bulunamadı. Önce interactsh_start() çalıştırın."

    log_file = info.get("log_file", "")
    if not os.path.exists(log_file):
        return "Henüz callback alınmadı (log dosyası boş)."

    try:
        with open(log_file, 'r') as f:
            content = f.read().strip()

        if not content:
            return "⏳ Henüz callback alınmadı. Payload'ların hedefte tetiklenmesini bekleyin."

        # JSON satırlarını parse et
        interactions = []
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                interactions.append(data)
            except json.JSONDecodeError:
                continue

        if not interactions:
            return "⏳ Henüz callback alınmadı."

        output = f"🔔 CALLBACK TESPİT EDİLDİ! ({len(interactions)} etkileşim)\n{'='*55}\n"
        for i, data in enumerate(interactions[-20:], 1):  # Son 20 callback
            proto = str(data.get("protocol") or "").upper()
            proto = proto if proto in {"DNS", "HTTP", "HTTPS", "SMTP", "LDAP"} else "UNKNOWN"
            timestamp = str(data.get("timestamp") or "?")[:40]
            host = str(data.get("full-id") or "").strip().lower()
            if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
                host = "unknown"
            output += f"\n#{i} [{proto}] {host} @ {timestamp}\n"

        output += "\nCallback metadata gözlendi; kaynak ve bulgu ayrıca doğrulanmalı.\n"
        return output
    except Exception as e:
        return f"HATA: Log okunamadı: {e}"


@mcp.tool()
def interactsh_stop(
    session_name: str = "default"
) -> str:
    """Interactsh oturumunu durdur ve sonuçları özetle.

    Args:
        session_name: Oturum adı
    """
    info = _interactsh_sessions.get(session_name)
    if not info:
        return f"Session bulunamadı: {session_name}"

    proc = info.get("process")
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    # Son kez sonuçları oku
    result = interactsh_poll(session_name)

    del _interactsh_sessions[session_name]
    return f"🔴 Interactsh session '{session_name}' DURDURULDU.\n\n{result}"


# ============================================================
# HEADLESS BROWSER — DOM XSS, Auth Flow, JS Analysis (Phase 7)
# ============================================================

@mcp.tool()
def browser_crawl(
    url: str,
    max_pages: int = 20,
    timeout: int = 60,
    extract_forms: bool = True,
    extract_links: bool = True,
    extract_js: bool = True,
) -> str:
    """Crawl an in-scope origin with per-request policy enforcement."""
    if not HAS_SURFACE or crawl_site is None:
        return json.dumps({"ok": False, "error": "policy-controlled crawler unavailable"})
    result = crawl_site(url, max_pages=min(40, max(1, int(max_pages))),
                        timeout_ms=min(20000, max(1000, int(timeout) * 1000)),
                        tool_name="kali-tools_browser_crawl")
    result.pop("records", None)
    if not extract_forms:
        result["forms"] = []
    if not extract_links:
        result["links"] = []
    if not extract_js:
        result["js_files"] = []
    return json.dumps(result, ensure_ascii=False, default=str)


@mcp.tool()
def browser_dom_xss(url: str, payloads: str = "", timeout: int = 30) -> str:
    """DOM execution remains disabled until browser requests are gated."""
    return "HATA: DOM XSS browser validation unavailable: request-level policy is not integrated"


@mcp.tool()
def browser_auth_test(
    login_url: str,
    username_field: str = "username",
    password_field: str = "password",
    username: str = "admin",
    password: str = "admin",
    success_indicator: str = "",
    timeout: int = 15,
) -> str:
    """Login automation is disabled; provide a scoped test session instead."""
    return "HATA: browser login automation is disabled; supply an existing scoped test session"


# ============================================================
# JAVASCRIPT ANALİZ SUITE (Phase 7)
# ============================================================

@mcp.tool()
def linkfinder_scan(
    url: str,
    output_format: str = "cli",
    extra_args: str = ""
) -> str:
    """LinkFinder ile JavaScript dosyalarından endpoint çıkar.
    REST API path'leri, gizli admin panelleri, internal URL'ler bulur.

    Args:
        url: JS dosyası URL'si veya web sayfası URL'si
        output_format: Çıktı formatı ('cli', 'html')
        extra_args: Ek argümanlar
    """
    # linkfinder kurulu mu?
    r = run_command("python3 -c 'import linkfinder' 2>/dev/null", timeout=5)
    if r["returncode"] != 0:
        # Inline extraction fallback
        return _extract_endpoints_manual(url)

    cmd = f"python3 -m linkfinder -i {shlex.quote(url)} -o {output_format} {extra_args}"
    result = run_command(cmd, timeout=60)
    output = format_output(result)

    if not output.strip() or result["returncode"] != 0:
        return _extract_endpoints_manual(url)

    return f"🔗 LinkFinder Sonuçları: {url}\n{'='*50}\n{output}"


def _extract_endpoints_manual(url: str) -> str:
    """LinkFinder yoksa manuel JS endpoint extraction."""
    # JS içeriğini indir
    r = run_command(f"curl -sL {shlex.quote(url)} 2>/dev/null", timeout=15)
    if not r["stdout"]:
        return f"JS içeriği alınamadı: {url}"

    content = r["stdout"]

    # Regex ile endpoint'leri çıkar
    import re as _re
    patterns = [
        r'["\']/(api|v[0-9]|graphql|admin|internal|private|hidden|secret|debug|test|staging|dev)[/\w.-]*["\']',
        r'["\'](https?://[^"\'>\s]+)["\']',
        r'["\'](/[a-zA-Z0-9._/-]{3,})["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        r'XMLHttpRequest.*open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
    ]

    endpoints = set()
    for pattern in patterns:
        matches = _re.findall(pattern, content)
        for m in matches:
            if isinstance(m, tuple):
                m = m[0]
            if len(m) > 3 and not m.endswith(('.png', '.jpg', '.gif', '.css', '.ico', '.svg', '.woff')):
                endpoints.add(m)

    # Secret pattern'leri de ara
    secret_patterns = [
        r'(?:api[_-]?key|apikey|api_secret|token|secret|password|passwd|auth)\s*[:=]\s*["\']([^"\']{8,})["\']',
        r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']',  # Base64 long strings
        r'(?:Bearer|Basic)\s+([A-Za-z0-9+/._=-]{20,})',
    ]

    secrets = set()
    for pattern in secret_patterns:
        matches = _re.findall(pattern, content, _re.IGNORECASE)
        for m in matches:
            if len(m) > 8:
                secrets.add(m[:60])

    output = f"🔗 JS Endpoint Extraction: {url}\n{'='*50}\n"

    if endpoints:
        output += f"\n📌 Bulunan Endpoint'ler ({len(endpoints)}):\n"
        # Kritik olanları üste çıkar
        critical = [e for e in endpoints if any(kw in e.lower() for kw in ['admin', 'api', 'internal', 'secret', 'debug', 'graphql', 'private'])]
        normal = [e for e in endpoints if e not in critical]

        for ep in sorted(critical):
            output += f"  🔴 {ep}\n"
        for ep in sorted(normal)[:30]:
            output += f"  {ep}\n"
        if len(normal) > 30:
            output += f"  ... (+{len(normal)-30} daha)\n"
    else:
        output += "\nEndpoint bulunamadı.\n"

    if secrets:
        output += f"\n🔑 Olası Secret'lar ({len(secrets)}):\n"
        for s in list(secrets)[:10]:
            output += f"  ⚠️ {s}\n"

    return output


@mcp.tool()
def secretfinder_scan(
    url: str,
    extra_args: str = ""
) -> str:
    """JS dosyalarında API key, token, password gibi secret'ları ara.
    LinkFinder'ın secret odaklı versiyonu.

    Args:
        url: JS dosyası veya web sayfası URL'si
        extra_args: Ek argümanlar
    """
    # SecretFinder kurulu mu dene
    r = run_command("python3 -c 'from SecretFinder import SecretFinder' 2>/dev/null", timeout=5)
    if r["returncode"] == 0:
        cmd = f"python3 -m SecretFinder -i {shlex.quote(url)} -o cli {extra_args}"
        result = run_command(cmd, timeout=60)
        if result["stdout"].strip():
            return f"🔑 SecretFinder Sonuçları: {url}\n{'='*50}\n{format_output(result)}"

    # Fallback: curl + regex
    r = run_command(f"curl -sL {shlex.quote(url)} 2>/dev/null", timeout=15)
    if not r["stdout"]:
        return f"İçerik alınamadı: {url}"

    import re as _re
    content = r["stdout"]

    patterns = {
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "AWS Secret Key": r'(?:aws_secret|secret_access_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
        "Google API Key": r'AIza[0-9A-Za-z_-]{35}',
        "Firebase": r'["\']https://[a-z0-9-]+\.firebaseio\.com["\']',
        "Slack Token": r'xox[baprs]-[0-9a-zA-Z-]{10,}',
        "GitHub Token": r'gh[pousr]_[0-9a-zA-Z]{36,}',
        "JWT Token": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        "Private Key": r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        "Heroku API Key": r'[hH]eroku[a-zA-Z0-9_-]*[kK]ey\s*[:=]\s*["\']?([0-9a-fA-F-]{36})',
        "Mailgun Key": r'key-[0-9a-zA-Z]{32}',
        "Twilio": r'SK[0-9a-fA-F]{32}',
        "Stripe Key": r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
        "Square OAuth": r'sq0[a-z]{3}-[0-9A-Za-z_-]{22,}',
        "Discord Token": r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
        "Generic Secret": r'(?:secret|password|passwd|api_key|apikey|token|auth)[\s]*[:=][\s]*["\']([^"\']{8,})["\']',
        "Internal URL": r'https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost)[:/][^\s"\']+',
    }

    findings = {}
    for name, pattern in patterns.items():
        matches = _re.findall(pattern, content)
        if matches:
            findings[name] = list(set(m if isinstance(m, str) else m[0] for m in matches))[:5]

    if not findings:
        return f"✅ {url} içinde secret bulunamadı."

    output = f"🔑 Secret Taraması: {url}\n{'='*55}\n"
    for category, values in findings.items():
        output += f"\n🔴 {category}:\n"
        for v in values:
            output += f"  → {v[:80]}{'...' if len(v) > 80 else ''}\n"

    output += f"\n⚠️ TOPLAM: {sum(len(v) for v in findings.values())} potansiyel secret bulundu!\n"
    return output


@mcp.tool()
def js_beautify(
    url: str,
    grep_pattern: str = ""
) -> str:
    """Minified JS dosyasını beautify et ve opsiyonel grep ile filtrele.
    Source map yoksa code review için kritik.

    Args:
        url: JS dosyası URL'si
        grep_pattern: Filtrelenecek pattern (ör: 'admin|api|token|secret')
    """
    r = run_command(f"curl -sL {shlex.quote(url)} 2>/dev/null", timeout=15)
    if not r["stdout"]:
        return f"JS dosyası alınamadı: {url}"

    content = r["stdout"]

    # js-beautify kuruluysa kullan
    r2 = run_command(f"echo {shlex.quote(content[:5000])} | js-beautify - 2>/dev/null", timeout=10)
    if r2["returncode"] == 0 and r2["stdout"]:
        beautified = r2["stdout"]
    else:
        # Python ile basit beautify
        beautified = content.replace(";", ";\n").replace("{", "{\n").replace("}", "\n}\n")

    if grep_pattern:
        import re as _re
        lines = beautified.split("\n")
        matched = [line.strip() for line in lines if _re.search(grep_pattern, line, _re.IGNORECASE)]
        if matched:
            return f"📜 JS Beautify + Grep ({grep_pattern}): {url}\n{'='*50}\n" + "\n".join(matched[:100])
        return f"Pattern '{grep_pattern}' bulunamadı."

    # Truncate
    if len(beautified) > 5000:
        return f"📜 JS Beautify: {url}\n{'='*50}\n{beautified[:5000]}\n\n... ({len(beautified)} karakter, truncated)"

    return f"📜 JS Beautify: {url}\n{'='*50}\n{beautified}"


@mcp.tool()
def compose_js_routes(source: str, target: str = "") -> str:
    """Compose hidden REST paths from JS source (index arrays, concat, templates).

    Local/offline: pass already-fetched JS text. Does not fetch URLs.
    LinkFinder only sees quoted literals; this expands `_k[i]`, string
    concatenation, and `/users/${id}/profile` into concrete paths plus
    `{id}` templates (IDOR/BOLA candidates). Probe `next_probes` before
    JWT, nmap, or wordlists. Pass `target` (page origin) so the policy
    gate can queue those paths.

    Args:
        source: JavaScript source text (bundle or beautified). Max ~400k chars.
        target: Optional origin, e.g. http://host:8088 — used to build next_probes.
    """
    if not HAS_JS_CORE:
        return json.dumps({"error": "cco_js_core yuklenemedi"})
    text = source or ""
    if not text.strip():
        return json.dumps({"error": "source bos"})
    result = compose_js_routes_core(text)
    origin = (target or "").rstrip("/")
    probes = []
    for path in result.get("templates") or []:
        concrete = re.sub(r"\{[^}]+\}", "1", path)
        probes.append(f"{origin}{concrete}" if origin else concrete)
    header_curl = [
        f'-H "{name}: {value}"'
        for name, value in (result.get("header_values") or {}).items()
        if value and "***" not in value and "..." not in value
    ]
    header_note = (
        f"Use these observed headers verbatim: {' '.join(header_curl)}"
        if header_curl
        else "No header name→value pairs found in source; keep default headers."
    )
    result["next_probes"] = probes[:12]
    result["header_curl"] = header_curl[:8]
    result["notes"] = list(result.get("notes") or []) + [
        "Probe next_probes with curl before JWT, nmap, or fuzz. The policy gate blocks those until the queue is empty.",
        header_note,
    ]
    return json.dumps(result, indent=2, ensure_ascii=False)


# ============================================================
# SUBDOMAIN TAKEOVER DOĞRULAMA (Phase 7)
# ============================================================

@mcp.tool()
def subdomain_takeover_check(
    domain: str,
    wordlist: str = "",
    extra_args: str = ""
) -> str:
    """Subdomain takeover açıklarını kontrol et.
    Dangling CNAME'ler, expired services, unclaimed resources tespit eder.

    Args:
        domain: Hedef domain (ör: example.com)
        wordlist: Subdomain wordlist (boş: subfinder çıktısı)
        extra_args: Ek argümanlar
    """
    # Önce subdomain'leri bul
    subs_file = f"/tmp/subs_{domain.replace('.', '_')}_{int(time.time())}.txt"

    if wordlist and os.path.exists(wordlist):
        subs_file = wordlist
    else:
        r = run_command(f"subfinder -d {shlex.quote(domain)} -silent 2>/dev/null | head -200", timeout=60)
        if r["stdout"].strip():
            with open(subs_file, "w") as f:
                f.write(r["stdout"])
        else:
            return f"'{domain}' için subdomain bulunamadı. Önce keşif yapın."

    outputs = []

    # subjack dene
    r = run_command("which subjack 2>/dev/null", timeout=3)
    if r["returncode"] == 0:
        r = run_command(f"subjack -w {subs_file} -t 50 -timeout 10 -ssl -v {extra_args}", timeout=120)
        if r["stdout"].strip():
            outputs.append(f"[subjack]\n{r['stdout'].strip()}")

    # Manuel CNAME kontrol
    try:
        with open(subs_file, 'r') as f:
            subdomains = [s.strip() for s in f.readlines() if s.strip()]
    except Exception:
        subdomains = []

    vulnerable_services = [
        "github.io", "herokuapp.com", "s3.amazonaws.com", "cloudfront.net",
        "azurewebsites.net", "blob.core.windows.net", "cloudapp.net",
        "trafficmanager.net", "pantheon.io", "readme.io", "surge.sh",
        "bitbucket.io", "ghost.io", "helpscoutdocs.com", "feedpress.me",
        "freshdesk.com", "zendesk.com", "statuspage.io", "tumblr.com",
        "wordpress.com", "shopify.com", "unbounce.com", "helpjuice.com",
        "teamwork.com", "cargocollective.com", "uservoice.com",
        "smartling.com", "getfly.com", "aftership.com", "tictail.com",
    ]

    dangling = []
    for sub in subdomains[:100]:
        r = run_command(f"dig +short CNAME {shlex.quote(sub)} 2>/dev/null", timeout=5)
        cname = r["stdout"].strip()
        if cname:
            # Vulnerable service'e point ediyor mu?
            for service in vulnerable_services:
                if service in cname.lower():
                    # NXDOMAIN kontrolü
                    r2 = run_command(f"dig +short {shlex.quote(cname.rstrip('.'))} 2>/dev/null", timeout=5)
                    if not r2["stdout"].strip():
                        dangling.append({
                            "subdomain": sub,
                            "cname": cname,
                            "service": service,
                            "status": "TAKEOVER POSSIBLE"
                        })
                    break

    if dangling:
        outputs.append(f"\n🔴 SUBDOMAIN TAKEOVER TESPİT EDİLDİ ({len(dangling)}):")
        for d in dangling:
            outputs.append(f"  🎯 {d['subdomain']} → {d['cname']} ({d['service']})")

    if outputs:
        return f"🌐 Subdomain Takeover Check: {domain}\n{'='*55}\n" + "\n".join(outputs)

    return f"✅ {domain} üzerinde subdomain takeover açığı bulunamadı ({len(subdomains)} subdomain kontrol edildi)."


# ============================================================
# ADAPTIVE RATE LIMITER (Phase 7)
# ============================================================

# Global rate limit ayarları
_rate_limit_config = {
    "requests_per_second": 10,
    "backoff_on_429": True,
    "backoff_multiplier": 2.0,
    "max_backoff_seconds": 60,
    "proxy": "",
    "rotate_user_agent": True,
    "current_delay": 0.1,
}

@mcp.tool()
def set_rate_limit(
    requests_per_second: int = 10,
    backoff_on_429: bool = True,
    proxy: str = "",
    rotate_user_agent: bool = True
) -> str:
    """Adaptive rate limiter ayarla — hedef tarafından banlanmayı önle.
    Tüm HTTP tool'ları bu ayarları kullanır.

    Args:
        requests_per_second: Saniyede max istek (1-100)
        backoff_on_429: 429 (Too Many Requests) alınca otomatik yavaşla
        proxy: Proxy adresi (ör: 'socks5://127.0.0.1:9050' Tor, 'http://proxy:8080')
        rotate_user_agent: Her istekte farklı User-Agent kullan
    """
    _rate_limit_config["requests_per_second"] = max(1, min(100, requests_per_second))
    _rate_limit_config["backoff_on_429"] = backoff_on_429
    _rate_limit_config["proxy"] = proxy
    _rate_limit_config["rotate_user_agent"] = rotate_user_agent
    _rate_limit_config["current_delay"] = 1.0 / _rate_limit_config["requests_per_second"]
    _rate_limit_config["configured"] = True

    proxy_info = f"Proxy: {proxy}" if proxy else "Proxy: Yok (direkt bağlantı)"

    return f"""⚙️ Rate Limiter Ayarlandı
{'='*40}
  Rate: {requests_per_second} req/s (delay: {_rate_limit_config['current_delay']:.2f}s)
  429 Backoff: {'Aktif' if backoff_on_429 else 'Pasif'}
  {proxy_info}
  UA Rotation: {'Aktif' if rotate_user_agent else 'Pasif'}

💡 İpuçları:
  - Bug bounty: 5-10 req/s önerilir
  - Agresif tarama: 50+ req/s (ban riski!)
  - Tor proxy: set_rate_limit(proxy='socks5://127.0.0.1:9050')
"""


@mcp.tool()
def get_rate_limit_status() -> str:
    """Mevcut rate limiting durumunu göster."""
    return json.dumps(_rate_limit_config, indent=2)


# ============================================================
# STRUCTURED PARSERS (Phase A) — Nmap XML + sqlmap JSON → JSON
# ============================================================

@mcp.tool()
def nmap_scan_structured(
    target: str,
    options: str = "-sV -T4 --top-ports 1000",
    timeout_sec: int = 600,
) -> str:
    """Nmap taraması yap ve sonucu JSON olarak döndür (LLM için daha doğru).
    Ham nmap çıktısı yerine host/port/service/script dict'leri döner.

    Args:
        target: Hedef IP/domain/CIDR
        options: nmap argümanları (varsayılan: -sV -T4 --top-ports 1000)
        timeout_sec: Max tarama süresi (default 600s)
    """
    import xml.etree.ElementTree as _ET

    # Güvenlik kontrolü
    full_cmd = f"nmap {options} {target}"
    ok, reason = validate_command(full_cmd)
    if not ok:
        return reason

    # -oX - ile XML çıktı al
    xml_cmd = f"nmap {options} -oX - {shlex.quote(target)}"
    result = run_command(xml_cmd, timeout=timeout_sec)
    if not result["success"] and not result["stdout"]:
        return json.dumps({
            "error": "nmap başarısız",
            "stderr": result["stderr"][:500],
            "target": target,
        })

    try:
        root = _ET.fromstring(result["stdout"])
    except _ET.ParseError as e:
        return json.dumps({"error": f"XML parse başarısız: {e}", "raw": result["stdout"][:800]})

    hosts: list[dict] = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        ip = addr_el.get("addr") if addr_el is not None else ""
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"
        hostnames = [h.get("name") for h in host_el.findall("hostnames/hostname") if h.get("name")]

        ports: list[dict] = []
        for p in host_el.findall("ports/port"):
            port_num = int(p.get("portid", 0))
            proto = p.get("protocol", "")
            state_el = p.find("state")
            port_state = state_el.get("state") if state_el is not None else ""
            svc = p.find("service")
            service = {
                "name": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                "cpe": [c.text for c in (svc.findall("cpe") if svc is not None else []) if c.text],
            }
            scripts = [
                {"id": s.get("id", ""), "output": (s.get("output") or "")[:800]}
                for s in p.findall("script")
            ]
            ports.append({
                "port": port_num, "protocol": proto, "state": port_state,
                "service": service, "scripts": scripts,
            })

        os_el = host_el.find("os/osmatch")
        os_guess = {
            "name": os_el.get("name", "") if os_el is not None else "",
            "accuracy": os_el.get("accuracy", "") if os_el is not None else "",
        }

        hosts.append({
            "ip": ip, "state": state, "hostnames": hostnames,
            "os": os_guess, "ports": ports,
            "open_port_count": sum(1 for p in ports if p["state"] == "open"),
        })

    runstats_el = root.find("runstats/finished")
    summary = {
        "target": target,
        "options": options,
        "hosts_scanned": len(hosts),
        "total_open_ports": sum(h["open_port_count"] for h in hosts),
        "elapsed_sec": runstats_el.get("elapsed") if runstats_el is not None else "",
        "hosts": hosts,
    }
    return json.dumps(summary, indent=2, ensure_ascii=False)


@mcp.tool()
def sqlmap_test_structured(
    target_url: str,
    options: str = "--batch --level=2 --risk=1",
    timeout_sec: int = 900,
    validation_id: str = "",
    allow_deepen: bool = False,
) -> str:
    """sqlmap taramasını JSON çıktısıyla çalıştır; önemli bulgulara ait yapılandırılmış özet döndürür.

    Keşif aracı değildir — yalnızca CONFIRMED SQLi deepen.

    Args:
        target_url: Hedef URL (parametreleriyle birlikte)
        options: sqlmap argümanları (varsayılan: --batch --level=2 --risk=1)
        timeout_sec: Max çalışma süresi (default 900s)
        validation_id: CONFIRMED SQLi validator id (zorunlu)
        allow_deepen: --dump / os-shell için True
    """
    gate = _sqlmap_confirmed_gate(validation_id, allow_deepen=allow_deepen, options=options,
                                  target=target_url)
    if not gate.get("ok"):
        return json.dumps({"ok": False, **gate, "tool": "sqlmap_test_structured"}, ensure_ascii=False)

    # Geçici output dir
    out_dir = tempfile.mkdtemp(prefix="sqlmap_", dir="/tmp")
    cmd = f"sqlmap -u {shlex.quote(target_url)} {options} --batch --output-dir={shlex.quote(out_dir)}"
    ok, reason = validate_command(cmd)
    if not ok:
        return reason
    result = run_command(cmd, timeout=timeout_sec)

    # sqlmap output-dir'i altında target klasörü ve log dosyaları oluşur
    summary = {
        "target": target_url,
        "returncode": result["returncode"],
        "vulnerable": False,
        "dbms": "",
        "techniques": [],
        "injectable_params": [],
        "log_excerpt": "",
    }

    stdout = result.get("stdout", "")
    # Temel pattern'ler
    if "is vulnerable" in stdout or "are vulnerable" in stdout:
        summary["vulnerable"] = True
    m_dbms = re.search(r"back-end DBMS:\s*(.+)", stdout)
    if m_dbms:
        summary["dbms"] = m_dbms.group(1).strip().splitlines()[0][:120]
    # Teknikler
    for tech in ["boolean-based blind", "time-based blind", "error-based", "UNION query", "stacked queries"]:
        if tech.lower() in stdout.lower():
            summary["techniques"].append(tech)
    # Parametre(ler)
    for m in re.finditer(r"Parameter:\s*(\S+)\s*\(([^)]+)\)", stdout):
        summary["injectable_params"].append({"param": m.group(1), "place": m.group(2)})

    # Log'un son 2000 karakteri (LLM için)
    summary["log_excerpt"] = stdout[-2000:]
    if HAS_SURFACE:
        try:
            records = parse_sqlmap(summary, target=_target_from_url(target_url))
            ingest = _ingest_surface_records(records, _target_from_url(target_url))
            summary["surface_ingest"] = ingest
        except Exception as exc:
            summary["surface_ingest"] = {"error": str(exc)}

    return json.dumps(summary, indent=2, ensure_ascii=False)



# ============================================================
# POST-EXPLOITATION — PrivEsc enum + parser + memory aine kayit
# ============================================================
# Kural: bu tool'lar salt-okunur numaralandirma + parse yapar; exploit
# CALISTIRMAZ, persistence KURMAZ, secret'lari log'a YAZMAZ.
# Bulunan credential adaylari memory vault'a refs olarak gecer.

LINPEAS_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
_PEER_CACHE: dict = {}


def _postex_peer(name: str, folder: str):
    cached = _PEER_CACHE.get(name)
    if cached is not None:
        return cached
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", folder, "server.py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    _PEER_CACHE[name] = module
    return module


def _postex_tools_dir() -> str:
    tools_dir = os.path.join(CCO_HOME, "tools")
    os.makedirs(tools_dir, exist_ok=True)
    return tools_dir


@mcp.tool()
def linpeas_fetch(
    force: bool = False
) -> str:
    """linpeas.sh'i PEASS-ng releases'tan indir ve sha256 ile dogrula.

    Args:
        force: True ise mevcut kopyayi yeniden indir
    """
    dest = os.path.join(_postex_tools_dir(), "linpeas.sh")
    if os.path.exists(dest) and not force:
        digest = hashlib.sha256(open(dest, "rb").read()).hexdigest()
        return json.dumps({"path": dest, "sha256": digest, "cached": True}, indent=2)
    dl = run_command(
        f"wget -q -O {shlex.quote(dest)} {LINPEAS_URL} || "
        f"curl -sSL -o {shlex.quote(dest)} {LINPEAS_URL}",
        timeout=180,
    )
    if dl.get("returncode") != 0 or not os.path.exists(dest):
        return json.dumps({"error": f"linpeas indirilemedi: {(dl.get('stderr') or '')[:300]}"})
    os.chmod(dest, 0o755)
    digest = hashlib.sha256(open(dest, "rb").read()).hexdigest()
    return json.dumps({"path": dest, "sha256": digest, "cached": False}, indent=2)


@mcp.tool()
def parse_privesc_report(
    report_text: str,
    platform: str = "linux"
) -> str:
    """Bir linpeas/winPEAS ciktisini yapisal bulgulara cevir (saf parse, calistirma yok).

    Uzak hedefte calistirilmis peas ciktisini yapistir; SUID, sudo, cron,
    token yetkisi, servis yanlis-yapilandirma ve kimlik kalintilari
    siniflandirilmis JSON olarak doner. Secret degerleri maskelenir.

    Args:
        report_text: peas stdout metni (en fazla ~2MB)
        platform: 'linux' (linpeas) veya 'windows' (winPEAS)
    """
    if not HAS_POSTEX:
        return json.dumps({"error": "cco_postex_core yuklenemedi"})
    text = (report_text or "")[:2_000_000]
    if not text.strip():
        return json.dumps({"error": "report_text bos"})
    plat = (platform or "linux").strip().lower()
    if plat.startswith("win"):
        return json.dumps(parse_winpeas(text), indent=2, ensure_ascii=False)
    return json.dumps(parse_linpeas(text), indent=2, ensure_ascii=False)


@mcp.tool()
def privesc_scan_local(
    store: bool = True,
    target_label: str = "localhost",
    quick: bool = True
) -> str:
    """Yerel Kali host'unda linpeas calistir, parse et, bulgulari memory'ye yaz.

    Salt-okunur numaralandirma (lab/L4 icin). Credential sinifi bulgular
    memory vault'a refs olarak gecer; ham secret dondurulmez.

    Args:
        store: True ise bulgulari memory-server'a finding olarak kaydet
        target_label: Memory kaydi icin hedef etiketi
        quick: True ise linpeas -Q (hizli), False ise tam tarama
    """
    if not HAS_POSTEX:
        return json.dumps({"error": "cco_postex_core yuklenemedi"})
    fetched = json.loads(linpeas_fetch())
    if "error" in fetched:
        return json.dumps(fetched, ensure_ascii=False)
    # Hizli mod: sadece cabuk biten secili kontroller (~40sn). interesting_*
    # dosya taramalari buyuk dosya sistemlerinde cok uzun surer, tam moda birakilir.
    # NOT: bu linpeas derlemesi -Q/-n bayraklarini yoksayip kullanim metni basiyor;
    # yalnizca dogrulanmis bayrak kombinasyonlari kullanilir.
    QUICK_CHECKS = "system_information,users_information"
    flag = f"-o {QUICK_CHECKS} -N -q" if quick else "-s -N -q"
    res = run_command(f"bash {shlex.quote(fetched['path'])} {flag} 2>/dev/null", timeout=900)
    stdout = res.get("stdout", "")
    if len(stdout.splitlines()) < 200 or "LINPEAS" not in stdout.upper():
        return json.dumps({"error": "linpeas gecerli rapor uretmedi (bayrak/surum uyumsuzlugu olabilir)",
                           "lines": len(stdout.splitlines())}, ensure_ascii=False)
    parsed = parse_linpeas(stdout)
    stored = 0
    store_errors: list[str] = []
    if store:
        try:
            mem = _postex_peer("mem_postex", "mcp-memory-server")
            for item in parsed["findings"]:
                if item["severity"] == "info":
                    continue
                try:
                    mem.store_finding(
                        target=target_label,
                        type=f"privesc:{item['class']}",
                        severity=item["severity"],
                        description=f"{item['title']} — {item['remediation']}",
                        payload=item["evidence"] if not item["sensitive"] else "",
                        validation_result_json=json.dumps({"sensitive": item["sensitive"]}) if item["sensitive"] else "",
                    )
                    stored += 1
                except Exception as exc:
                    store_errors.append(str(exc)[:120])
        except Exception as exc:
            store_errors.append(f"memory peer: {exc}"[:150])
    parsed["stored_findings"] = stored
    if store_errors:
        parsed["store_errors"] = store_errors[:5]
    parsed["linpeas_sha256"] = fetched["sha256"]
    return json.dumps(parsed, indent=2, ensure_ascii=False)


# ============================================================
# LEDGER + RACE ONAY ARAÇLARI — sandbox-dışı custody (host-side)
# ============================================================
# brain.py CLI bash sandboxında çalışır; sandbox .cco'yu tmpfs ile
# maskeler. İmza anahtarı ve onay tablosu bu yüzden CLI'dan erişilemez.
# Bu araçlar MCP sunucusunda (sandbox-dışı) çalışır ve GERÇEK CCO_HOME'u
# görür: defter ekleme/kapsama + race onay denetimi buradan yapılır.

_ATTEMPT_LEDGER_MOD = None
_policy_engine_factory = None  # testler enjekte edebilir


def _attempt_ledger_mod():
    global _ATTEMPT_LEDGER_MOD
    if _ATTEMPT_LEDGER_MOD is None:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), "scripts", "attempt_ledger.py")
        if os.path.dirname(path) not in sys.path:
            sys.path.insert(0, os.path.dirname(path))
        spec = importlib.util.spec_from_file_location("cco_attempt_ledger", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        _ATTEMPT_LEDGER_MOD = mod
    return _ATTEMPT_LEDGER_MOD


def _ledger_policy_engine():
    if _policy_engine_factory is not None:
        return _policy_engine_factory()
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "scripts", "policy_engine.py")
    spec = importlib.util.spec_from_file_location("cco_policy_engine_ledger", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.PolicyEngine()


def _run_bare_host(workdir: str) -> str:
    try:
        with open(os.path.join(workdir, "hypotheses.json"), encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    for key in ("target_key", "target"):
        raw = str(data.get(key, "") or "").strip()
        if not raw:
            continue
        host = urlparse(raw if "://" in raw else "//" + raw).hostname or ""
        if host:
            return host
    return ""


def _confined_workdir(workdir: str) -> str:
    base = os.path.realpath(os.environ.get(
        "CCO_WORKDIR", os.path.expanduser("~/cco-work")))
    resolved = os.path.realpath(workdir)
    try:
        inside = os.path.commonpath([resolved, base]) == base
    except ValueError:
        inside = False
    if not inside:
        raise ValueError("workdir outside CCO_WORKDIR")
    return resolved


def ledger_attempt_add_impl(workdir: str, vector: str, endpoint: str,
                            identity: str, verdict: str, candidate=None,
                            control=None, status=None, size=None,
                            artifact: str = "", note: str = "") -> dict:
    workdir = _confined_workdir(workdir)
    if not os.path.isdir(workdir):
        raise ValueError("unknown run workdir")
    record = {"vector": vector, "endpoint": endpoint,
              "identity": identity, "verdict": verdict}
    for key, value in (("candidate", candidate), ("control", control),
                       ("status", status), ("size", size)):
        if value is not None:
            record[key] = value
    if artifact:
        record["artifact"] = artifact
    if note:
        record["note"] = note
    stored = _attempt_ledger_mod().append_record(
        os.path.join(workdir, "attempts.jsonl"), record)
    return {"seq": stored["seq"], "record_hash": stored["record_hash"],
            "signature": stored["signature"]}


def ledger_coverage_impl(workdir: str, vector: str, expected=()) -> dict:
    workdir = _confined_workdir(workdir)
    mod = _attempt_ledger_mod()
    records = mod.read_records(os.path.join(workdir, "attempts.jsonl"))
    return mod.coverage(records, vector, tuple(expected or ()),
                        path=os.path.join(workdir, "attempts.jsonl"))


def race_check_impl(workdir: str) -> dict:
    workdir = _confined_workdir(workdir)
    host = _run_bare_host(workdir)
    if not host:
        return {"allowed": False, "reason": "no run target"}
    try:
        engine = _ledger_policy_engine()
        rows = engine.list_approvals(active_only=True)
    except Exception as exc:
        return {"allowed": False,
                "reason": f"grant store unreadable: {exc}"[:200]}
    for row in rows:
        if not fnmatch.fnmatch("race_burst", row["tool_pattern"]):
            continue
        # Same target matcher the gate itself uses (private helper, no
        # public single-grant check exists); semantics pinned by tests.
        if not engine._approval_target_allows(row["target_pattern"], host):
            continue
        return {"allowed": True, "approval_id": row["id"],
                "expires_at": row["expires_at"]}
    return {"allowed": False, "reason": "no active race_burst grant"}


@mcp.tool()
def ledger_attempt_add(workdir: str, vector: str, endpoint: str,
                       identity: str, verdict: str,
                       candidate: int | None = None,
                       control: int | None = None,
                       status: int | None = None,
                       size: int | None = None,
                       artifact: str = "", note: str = "") -> str:
    """Attempt ledger'a imzalı kayıt ekle (sandbox-dışı custody).

    workdir: koşu dizini. vector: hipotez vektörü. endpoint: sondalanan uç.
    identity: own/peer. verdict: sonuç kararı. candidate/control: havuz
    aday ve kontrol no'ları. status/size: HTTP durum ve gövde boyu.
    artifact: workdir-içi kanıt yolu. note: kısa not.
    """
    try:
        stored = ledger_attempt_add_impl(
            workdir, vector, endpoint, identity, verdict,
            candidate=candidate, control=control, status=status,
            size=size, artifact=artifact, note=note)
    except ValueError as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)
    return json.dumps(stored, ensure_ascii=False)


def ledger_attempt_add_batch_impl(workdir: str, items: object) -> dict:
    """Append many attempt records; per-item errors continue, chain halt stops."""
    workdir = _confined_workdir(workdir)
    if not os.path.isdir(workdir):
        raise ValueError("unknown run workdir")
    if not isinstance(items, list) or not items:
        raise ValueError("items must be a non-empty list")
    mod = _attempt_ledger_mod()
    ledger_file = os.path.join(workdir, "attempts.jsonl")
    try:
        existing = mod.read_records(ledger_file)
        _, chain_errors = mod.verify_records(existing, path=ledger_file)
    except ValueError as exc:
        chain_errors = [str(exc)]
    if chain_errors:
        halted = f"chain halted: {chain_errors[0]}"[:200]
        return {"results": [{"ok": False, "error": halted} for _ in items]}
    results = []
    for item in items:
        if not isinstance(item, dict):
            results.append({"ok": False, "error": "item must be an object"})
            continue
        # Report the whole input defect in one response. Otherwise a worker
        # pays for a separate model turn for each missing inner JSON field.
        errors = []
        for key in mod.REQUIRED_STRINGS:
            value = item.get(key)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"attempt {key} must be a non-empty string")
        defaults = {"vector": "schema-check", "endpoint": "/", "identity": "unknown", "verdict": "observed"}
        for key in (*mod.OPTIONAL_INTS, *mod.OPTIONAL_IDS, "artifact", "note"):
            if key not in item:
                continue
            try:
                mod.validate_record({**defaults, key: item[key]})
            except ValueError as exc:
                errors.append(str(exc))
        if errors:
            results.append({"ok": False, "error": errors[0], "errors": errors,
                            "required_strings": list(mod.REQUIRED_STRINGS),
                            "hint": "Fix all fields together. status is an HTTP integer, artifact is an evidence path."})
            continue
        try:
            stored = ledger_attempt_add_impl(
                workdir, str(item.get("vector", "")),
                str(item.get("endpoint", "")),
                str(item.get("identity", "")),
                str(item.get("verdict", "")),
                candidate=item.get("candidate"), control=item.get("control"),
                status=item.get("status"), size=item.get("size"),
                artifact=str(item.get("artifact", "") or ""),
                note=str(item.get("note", "") or ""))
        except ValueError as exc:
            results.append({"ok": False, "error": str(exc)[:200]})
            continue
        results.append({"ok": True, "seq": stored["seq"],
                        "record_hash": stored["record_hash"]})
    return {"results": results}


@mcp.tool()
def ledger_attempt_add_batch(workdir: str, items_json: str) -> str:
    """Attempt ledger'a toplu kayıt ekle (faz-sonu tek çağrı).

    workdir: koşu dizini. items_json: kayıt dizisi (vector, endpoint,
    identity, verdict: nonempty strings). Optional candidate/control: string
    or integer IDs; status: HTTP integer 0..599 (not 'done'); size: nonnegative
    integer; artifact/note: strings. Use artifact for the evidence path.
    Öğe hataları devam eder; zincir bozuksa tamamı durur.
    """
    try:
        items = json.loads(items_json)
    except (TypeError, ValueError) as exc:
        return json.dumps({"error": f"invalid items_json: {exc}"},
                          ensure_ascii=False)
    try:
        outcome = ledger_attempt_add_batch_impl(workdir, items)
    except ValueError as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)
    return json.dumps(outcome, ensure_ascii=False)


@mcp.tool()
def ledger_coverage(workdir: str, vector: str,
                    expected: list[int] | None = None) -> str:
    """İmzalı defterden vektör kapsaması (tried/untried/controls).

    workdir: koşu dizini. vector: hipotez vektörü. expected: havuz
    aday no'ları (havuz vektörlerinde denenmemiş hesabı için).
    """
    try:
        covered = ledger_coverage_impl(workdir, vector, expected or ())
    except ValueError as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)
    return json.dumps(covered, ensure_ascii=False)


@mcp.tool()
def member_login(target: str, identity: str) -> str:
    """Use an explicitly enabled lab demo login for one existing ordinary member.

    Follow only the published selector/link for this configured account. Cookies
    stay inside the encrypted session vault. Password forms require separately
    provisioned credentials and are never guessed. A fresh session is operational
    evidence only, not a security finding. At most one login per account/run.
    """
    scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from member_login import login_member
    return json.dumps(login_member(target, identity), ensure_ascii=False)


@mcp.tool()
def ledger_prepare_handoff(target: str, workdir: str,
                           summary_file: str = "summaries/enum-2.json",
                           vector: str = "access", own_ids_json: str = "[]",
                           budget_calls: int = 25, max_chars: int = 12000,
                           session_bindings_json: str = "{}") -> str:
    """Create the bounded object pool and deterministic worker handoff locally.

    Use this instead of bash bookkeeping. summary_file must be a terminal
    enum/seed summary inside workdir. own_ids_json is an array of explicitly
    operator-owned IDs (integer, UUID, opaque, or {family,format,value});
    observed links and id_formats never supply ownership automatically.
    Empty own_ids_json keeps ownership unknown. session_bindings_json uses
    {label: {target, test_data_only: true, role?, owned_objects_private?}};
    only recently verified session references enter run-state, never cookies.
    Standard authz/pool vector handoffs are also prepared. No HTTP or sealing occurs.
    """
    try:
        return json.dumps(ledger_prepare_handoff_impl(
            target, workdir, summary_file, vector, own_ids_json, budget_calls, max_chars,
            session_bindings_json),
            ensure_ascii=False)
    except (OSError, TypeError, ValueError) as exc:
        return json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)


def ledger_prepare_handoff_impl(target: str, workdir: str,
                                summary_file: str = "summaries/enum-2.json",
                                vector: str = "access", own_ids_json: str = "[]",
                                budget_calls: int = 25, max_chars: int = 12000,
                                session_bindings_json: str = "{}") -> dict:
    from pathlib import Path

    workdir = _confined_workdir(workdir)
    root = Path(workdir)
    if not root.is_dir():
        raise ValueError("unknown run workdir")
    if not isinstance(vector, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", vector):
        raise ValueError("vector must be a short label")
    if isinstance(budget_calls, bool) or not isinstance(budget_calls, int) or not 5 <= budget_calls <= 30:
        raise ValueError("budget_calls must be 5..30")
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or not 512 <= max_chars <= 64000:
        raise ValueError("max_chars must be 512..64000")
    mod = _attempt_ledger_mod()
    import brain
    from object_identity import normalize_object_id
    from policy_engine import ScopeResolver, _secret_path_hit
    from target_identity import canonical_target
    from cco_surface_core import session_store as target_sessions

    scope = ScopeResolver()
    if not scope.permits_url(target):
        raise ValueError("target outside active scope")
    if not isinstance(summary_file, str) or not summary_file:
        raise ValueError("summary_file must name a run-local JSON file")
    supplied_path = Path(summary_file)
    supplied_path = supplied_path if supplied_path.is_absolute() else root / supplied_path
    if supplied_path.is_symlink() or _secret_path_hit(str(supplied_path)):
        raise ValueError("summary_file cannot be a secret path or symlink")
    summary_path = mod.resolve_artifact(workdir, summary_file)
    if (summary_path is None or summary_path.suffix != ".json"
            or _secret_path_hit(str(summary_path)) or summary_path.stat().st_size > 1048576):
        raise ValueError("summary_file must be a non-secret JSON file inside the run (max 1 MiB)")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    errors = brain.validate_summary(summary)
    if errors:
        raise ValueError("invalid summary: " + "; ".join(errors))
    if summary.get("phase") not in {"enum", "seed"} or summary.get("status") not in {"done", "partial"}:
        raise ValueError("summary must be a terminal enum/seed result")
    if canonical_target(summary.get("target", "")) != canonical_target(target):
        raise ValueError("summary target does not match the run target")
    if not isinstance(summary.get("surface"), dict):
        raise ValueError("summary must include an observed surface")
    raw_ids = json.loads(own_ids_json)
    if not isinstance(raw_ids, list) or len(raw_ids) > 100:
        raise ValueError("own_ids_json must be an array of at most 100 explicit owned IDs")
    own_ids = []
    for raw_id in raw_ids:
        normalized = normalize_object_id(raw_id)
        family, value = ("", normalized) if isinstance(normalized, int) else (
            normalized["family"], normalized["value"])
        if re.search(r"(?i)bearer\s|(?:cookie|password|token|session|api[-_]?key)\s*[:=]", str(value)):
            raise ValueError("credential material cannot be an object identifier")
        own_ids.append({"family": family, "id": str(value)})
    destinations = {"pool": root / "object-pool.json",
                    "handoff": root / f"handoff-{vector}.json",
                    "ledger": root / "hypotheses.json", "state": mod.state_path(workdir)}
    handoff_paths = {label: root / f"handoff-{label}.json"
                     for label in dict.fromkeys([vector, "authz", *brain.POOL_VECTORS])}
    for path in [*destinations.values(), *handoff_paths.values(), mod.ledger_path(workdir)]:
        if (path.is_symlink() or _secret_path_hit(str(path))
                or (path.exists() and not path.is_file())):
            raise ValueError("handoff output must be a non-secret regular file inside the run")
    bindings = json.loads(session_bindings_json)
    if not isinstance(bindings, dict) or len(bindings) > 8:
        raise ValueError("session_bindings_json must be an object of at most eight test account references")
    state = mod.load_state(workdir)
    checked = []
    target_origin = target_sessions._origin(target)
    for label, binding in bindings.items():
        if (not isinstance(label, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", label)
                or not isinstance(binding, dict)
                or set(binding) - {"target", "role", "test_data_only", "owned_objects_private"}
                or binding.get("test_data_only") is not True
                or ("role" in binding and (not isinstance(binding["role"], str)
                    or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", binding["role"])))
                or ("owned_objects_private" in binding and not isinstance(binding["owned_objects_private"], bool))):
            raise ValueError("invalid test session reference binding")
        bound_target = binding.get("target")
        if (not isinstance(bound_target, str) or not target_origin
                or target_sessions._origin(bound_target) != target_origin or not scope.permits_url(bound_target)):
            raise ValueError("session reference origin or scope mismatch")
        entry = target_sessions.verified_session(bound_target, label)
        if (not entry or target_sessions._origin(entry.get("check_url")) != target_origin
                or not scope.permits_url(entry.get("check_url") or "")):
            raise ValueError("session reference is unavailable or not recently verified")
        reference = hashlib.sha256(target_sessions.key_for(bound_target, label).encode()).hexdigest()
        mod.set_identity(state, label, "session-vault:" + reference)
        checked.append((bound_target, label, entry))
    new_ledger = None
    if destinations["ledger"].exists():
        ledger = brain.ledger_mod.load_ledger(workdir)
        if canonical_target(ledger.get("target", "")) != canonical_target(target):
            raise ValueError("ledger target does not match the run target")
    else:
        new_ledger = brain.ledger_mod.init_ledger(target)
    records = mod.read_records(mod.ledger_path(workdir))
    _, integrity_errors = mod.verify_records(records, path=mod.ledger_path(workdir))
    if integrity_errors:
        raise ValueError("attempt ledger integrity error: " + integrity_errors[0])
    pool = brain.build_object_pool(summary, own_ids, budget_calls=budget_calls)
    packets = {label: brain._handoff_packet(workdir, label, max_chars, pool_data=pool, state_data=state)
               for label in handoff_paths}
    if any(data.get("truncated") or data.get("untried_truncated")
           or len(json.dumps(data, ensure_ascii=False)) > max_chars for data in packets.values()):
        raise ValueError("handoff exceeds max_chars; increase the budget before dispatch")
    packet = packets[vector]
    planned = [(destinations["pool"], pool),
               *[(handoff_paths[label], data) for label, data in packets.items()]]
    if checked:
        planned.insert(0, (destinations["state"], state))
    if new_ledger is not None:
        planned.insert(0, (destinations["ledger"], new_ledger))
    # Each replacement is atomic. A crash between files is caught by the
    # existing pool/state/attempt fingerprints; incomplete JSON is never published.
    pending = []
    try:
        for destination, data in planned:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root,
                                             prefix=".handoff-", delete=False) as handle:
                pending.append((Path(handle.name), destination))
                handle.write(json.dumps(data, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        if not all(target_sessions.same_verified_session(bound_target, label, entry)
                   for bound_target, label, entry in checked):
            raise ValueError("session reference changed while preparing handoff")
        for temporary, destination in pending:
            temporary.replace(destination)
    finally:
        for temporary, _ in pending:
            temporary.unlink(missing_ok=True)
    return {"ok": True, "pool": str(destinations["pool"]),
            "handoff": str(destinations["handoff"]), "candidates": len(pool["candidates"]),
            "handoffs": {label: str(path) for label, path in handoff_paths.items()},
            "declared_own_ids": len(own_ids), "trusted_records": packet["trusted_records"],
            "pool_truncated": pool["truncated"], "dropped_candidates": pool["dropped"],
            "estimated_calls": pool["estimated_calls"],
            "session_references_bound": len(checked),
            "identities": len(packet["identities"]), "pool_sha256": packet["pool_sha256"],
            "sealed": False}


@mcp.tool()
def ledger_checkpoint(workdir: str, seal: bool = False,
                       spec_file: str = "specs.json") -> str:
    """Host custody: attest legacy evidence; optionally run the full closure gate.

    Signing keys stay outside bash. Local brain commands can verify the
    resulting public signatures. seal=True requires a valid spec file in
    the run and all existing validator/coverage/approval closure checks.
    """
    try:
        return json.dumps(ledger_checkpoint_impl(workdir, seal, spec_file), ensure_ascii=False)
    except (OSError, ValueError) as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)


def ledger_checkpoint_impl(workdir: str, seal: bool = False,
                            spec_file: str = "specs.json") -> dict:
    workdir = _confined_workdir(workdir)
    if not os.path.isdir(workdir):
        raise ValueError("unknown run workdir")
    mod = _attempt_ledger_mod()
    outcome = mod.checkpoint(os.path.join(workdir, "attempts.jsonl"))
    scripts_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    import brain
    brain._validation_context()
    from cco_validator_core.evidence import load_validation, publish_legacy_receipt

    run_ledger = brain.ledger_mod.load_ledger(workdir)
    exported = 0
    for entry in run_ledger.get("hypotheses", []):
        validation_id = entry.get("validation_id")
        if entry.get("status") != "confirmed" or not validation_id:
            continue
        artifact = load_validation(str(validation_id))
        if artifact is None:
            raise ValueError("validator artifact missing for " + str(entry.get("vector", "?")))
        exported += int(publish_legacy_receipt(artifact))
    outcome.update(legacy_artifacts=exported, sealed=False)
    if not seal:
        return outcome
    spec = mod.resolve_artifact(workdir, spec_file)
    from policy_engine import _secret_path_hit
    if spec is None or spec.suffix != ".json" or _secret_path_hit(str(spec)):
        raise ValueError("spec_file must be an existing non-secret JSON file inside the run")
    import contextlib
    import io
    from target_identity import target_key

    specs = brain.load_specs(spec.read_text())
    if not specs:
        raise ValueError("closure requires a non-empty task spec")
    if any(target_key(item.target) != target_key(run_ledger.get("target", "")) for item in specs):
        raise ValueError("spec target does not match the run target")
    with contextlib.redirect_stdout(io.StringIO()) as captured:
        code = brain.main(["check", "--spec", str(spec), "--workdir", workdir, "--closure"])
    outcome.update(check_exit=code, sealed=(code == 0), detail=captured.getvalue()[-1200:])
    if code == 0:
        outcome["closure"] = os.path.join(workdir, brain.CLOSURE_FILENAME)
    return outcome


@mcp.tool()
def race_check(workdir: str) -> str:
    """Race-burst onayı denetimi (gerçek onay tablosu, host-side).

    workdir: koşu dizini (hedef hypotheses.json'dan okunur). Operatör
    `policy_gate_cli.py approve --tool-pattern race_burst` ile TTL'li
    onay vermedikçe allowed=false döner.
    """
    try:
        decision = race_check_impl(workdir)
    except ValueError as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)
    return json.dumps(decision, ensure_ascii=False)


# ============================================================
# TOOL GRUP FİLTRELEME — Token Tasarrufu (opsiyonel)
# ============================================================
# kali-tools 89 tool ile en büyük şema maliyetine sahip (~12K token/istek).
# CCO_KALI_GROUPS env'i verilirse YALNIZCA o gruplar register kalır; geri
# kalan tool'lar kaldırılır → context'e daha az şema yüklenir.
# Profiller (scripts/cco-profile.sh) bunu görev tipine göre ayarlar.
# Env verilmezse veya "all" ise tüm 89 tool yüklenir (varsayılan davranış korunur).
#
# Her tool TAM OLARAK bir gruba aittir (toplam 89):
KALI_TOOL_GROUPS = {
    # core — temel recon/scan/enum + kontrol (her zaman gerekli)
    "nmap_scan": "core", "nmap_scan_structured": "core", "masscan_scan": "core",
    "ffuf_fuzz": "core", "gobuster_scan": "core", "nuclei_scan": "core",
    "nikto_scan": "core", "wpscan_scan": "core", "whatweb_fingerprint": "core",
    "wafw00f_detect": "core", "dig_dns": "core", "whois_enrichment": "core",
    "subfinder_enum": "core", "subdomain_takeover_check": "core", "curl_request": "core",
    "netcat_connect": "core", "parallel_recon": "core", "kiterunner_scan": "core",
    "nmap_scan_structured": "core",
    "gau_urls": "core", "waybackurls_fetch": "core", "discover_web_surface": "core",
    "compile_target_wordlist": "core", "file_analyze": "core",
    "ledger_attempt_add": "core", "ledger_coverage": "core", "race_check": "core",
    "ledger_checkpoint": "core", "ledger_prepare_handoff": "core",
    "shell_exec": "core", "python_exec": "core", "request_approval": "core",
    "check_approval": "core", "list_pending_approvals": "core", "approve_operation": "core",
    "reject_operation": "core", "set_rate_limit": "core", "get_rate_limit_status": "core",
    # osint — pasif/aktif istihbarat + cloud enum
    "osint_harvest": "osint", "spiderfoot_scan": "osint", "sherlock_lookup": "osint",
    "whois_enrichment": "osint", "subdomain_takeover_check": "osint",
    "cloud_enum": "osint", "aws_security_check": "osint",
    # web — web exploit + JS analizi + browser + OOB
    "sqlmap_test": "web", "sqlmap_test_structured": "web", "linkfinder_scan": "web",
    "secretfinder_scan": "web", "js_beautify": "web", "compose_js_routes": "web",
    "wafw00f_detect": "web", "browser_crawl": "web",
    "browser_auth_test": "web", "browser_dom_xss": "web", "mitmproxy_dump": "web",
    "interactsh_start": "web", "interactsh_poll": "web", "interactsh_stop": "web",
    "crawl_web_surface": "web", "zap_map_surface": "web",
    "member_login": "web",
    # exploit — exploit arama/üretim + brute + C2 + secret scan
    "searchsploit_search": "exploit", "metasploit_search": "exploit",
    "ysoserial_generate": "exploit", "generate_exploit_poc": "exploit",
    "hydra_brute": "exploit", "sliver_command": "exploit",
    "gitleaks_scan": "exploit", "trufflehog_scan": "exploit",
    # pwn — binary/RE/forensics/crypto-crack
    "angr_analyze": "pwn", "ghidra_headless": "pwn", "frida_hook": "pwn",
    "volatility_analyze": "pwn", "steghide_extract": "pwn", "steg_deep_analyze": "pwn",
    "hashcat_crack": "pwn", "john_crack": "pwn",
    # ad — Active Directory / internal
    "bloodhound_collect": "ad", "enum4linux_scan": "ad", "impacket_tool": "ad",
    # llm — LLM delegation + meta analiz
    "qwen_analyze": "llm", "parallel_llm_analyze": "llm", "self_improve": "llm",
    "screenshot_analyze": "llm",
    # swarm — orkestrasyon / daemon
    "swarm_dispatch": "swarm", "swarm_chain": "swarm",
    "start_recon_daemon": "swarm", "stop_recon_daemon": "swarm",
    # report — raporlama
    "generate_pentest_report": "report", "cvss_calculate": "report",
    # postex — privesc numaralandirma + parser (salt-okunur)
    "linpeas_fetch": "postex", "parse_privesc_report": "postex", "privesc_scan_local": "postex",
}

_kali_groups_env = os.environ.get("CCO_KALI_GROUPS", "").strip()
if _kali_groups_env and _kali_groups_env.lower() != "all":
    _enabled_groups = {g.strip() for g in _kali_groups_env.split(",") if g.strip()}
    for _tool_name in list(mcp._tool_manager._tools.keys()):
        if KALI_TOOL_GROUPS.get(_tool_name, "core") not in _enabled_groups:
            mcp.remove_tool(_tool_name)


if __name__ == "__main__":
    import sys
    
    transport = "stdio"
    port = 8080
    
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--transport" and i < len(sys.argv) - 1:
            transport = sys.argv[i + 1]
        elif arg == "--port" and i < len(sys.argv) - 1:
            port = int(sys.argv[i + 1])
    
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="streamable-http", port=port)
