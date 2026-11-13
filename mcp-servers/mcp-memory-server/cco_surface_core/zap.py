"""OWASP ZAP JSON API client — no zap-cli. Daemon spawn only if CCO_ZAP_AUTOSTART=1."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_ZAP_URL = "http://127.0.0.1:8080"
_SPAWNED = None


def zap_config():
    url = (os.environ.get("ZAP_API_URL") or DEFAULT_ZAP_URL).rstrip("/")
    key = os.environ.get("ZAP_API_KEY") or os.environ.get("ZAP_APIKEY") or ""
    return url, key


def zap_missing_msg() -> str:
    return (
        "HATA: ZAP API erişilemedi. Kurulu ZAP daemon gerekli:\n"
        "  zap.sh -daemon -port 8080 -config api.key=<ZAP_API_KEY>\n"
        "  export ZAP_API_URL=http://127.0.0.1:8080 ZAP_API_KEY=...\n"
        "Otomatik start (ağır): CCO_ZAP_AUTOSTART=1"
    )


def zap_request(path: str, params=None, timeout: int = 20, request_fn=None):
    if request_fn is not None:
        return request_fn(path, params or {})
    base, key = zap_config()
    query = dict(params or {})
    if key:
        query["apikey"] = key
    url = base + path
    if query:
        url += ("&" if "?" in path else "?") + urllib.parse.urlencode(query)
    req = urllib.request.Request(url, headers={"User-Agent": "CCO-ZAP/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
    return json.loads(body) if body.strip() else {}


def zap_version(request_fn=None, timeout: int = 5):
    try:
        data = zap_request("/JSON/core/view/version/", timeout=timeout, request_fn=request_fn)
        return data.get("version") or data.get("Version") or True
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return None


def _find_zap_bin() -> str:
    for name in ("zap.sh", "zaproxy"):
        found = shutil.which(name)
        if found:
            return found
    for path in (
        "/usr/share/zaproxy/zap.sh",
        "/usr/bin/zap.sh",
        "/opt/zaproxy/zap.sh",
    ):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return ""


def maybe_autostart(request_fn=None, wait_s: int = 40):
    global _SPAWNED
    if zap_version(request_fn=request_fn):
        return True, None
    flag = os.environ.get("CCO_ZAP_AUTOSTART", "").strip().lower()
    if flag not in {"1", "true", "yes", "on"}:
        return False, zap_missing_msg()
    if request_fn is not None:
        return False, zap_missing_msg()
    binary = _find_zap_bin()
    if not binary:
        return False, zap_missing_msg() + "\n(zap.sh / zaproxy bulunamadı)"
    base, key = zap_config()
    parsed = urllib.parse.urlparse(base)
    port = parsed.port or 8080
    cmd = [binary, "-daemon", "-port", str(port), "-config", "api.disablekey=" + ("false" if key else "true")]
    if key:
        cmd.extend(["-config", f"api.key={key}"])
    try:
        _SPAWNED = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True
        )
    except Exception as exc:
        return False, f"{zap_missing_msg()}\nSpawn hata: {exc}"
    deadline = time.time() + max(8, int(wait_s))
    while time.time() < deadline:
        if zap_version():
            return True, None
        time.sleep(1.5)
    return False, zap_missing_msg() + "\n(daemon ayağa kalkmadı)"


def ensure_zap(request_fn=None):
    version = zap_version(request_fn=request_fn)
    if version:
        return True, version
    return maybe_autostart(request_fn=request_fn)


def _poll_status(view_path: str, done_values, request_fn, timeout: int, extra=None):
    deadline = time.time() + max(5, int(timeout))
    last = None
    while time.time() < deadline:
        last = zap_request(view_path, extra or {}, timeout=15, request_fn=request_fn)
        status = str(last.get("status") or last.get("Status") or "")
        if status.lower() in {str(v).lower() for v in done_values}:
            return last
        if status.isdigit() and int(status) >= 100:
            return last
        time.sleep(1)
    return last or {"status": "timeout"}



def run_zap_map(
    target: str,
    ajax: bool = False,
    allow_ascan: bool = False,
    timeout: int = 180,
    request_fn=None,
) -> dict:
    """Refuse live ZAP mapping until every request is policy-enforced."""
    return {
        "ok": False,
        "error": "ZAP live mapping unavailable: request-level policy enforcement is not verified",
        "ascan": {"skipped": True, "ran": False},
    }
