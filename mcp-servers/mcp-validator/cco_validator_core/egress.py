"""Istek-seviyesi egress muhasebesi (Faz 4).

Tek cap: her gercek HTTP istegi (redirect hop'lari dahil) sayilir; her hop
yeniden dogrulanir. Kapsam disi host'a yonlendirme sessizce takip edilmez.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from urllib.parse import unquote, urlencode, urljoin, urlparse

_MAX_REDIRECTS = 5
_counter_lock = threading.Lock()
_jar_lock = threading.Lock()
_request_total = 0
_LOGIN_REDIRECT_RE = re.compile(r"/(?:login|signin|sign-in|sso|auth/login)\b", re.I)
_WIRE_GATE: ContextVar = ContextVar("validator_wire_gate", default=None)


def _login_location(value: str) -> bool:
    location = str(value or "")
    for _ in range(4):
        decoded = unquote(location)
        if decoded == location:
            break
        location = decoded
    return bool(_LOGIN_REDIRECT_RE.search(location))


def current_wire_gate():
    """Return the inherited per-request policy, if the caller supplied one."""
    return _WIRE_GATE.get()


@contextmanager
def scoped_wire_gate(gate):
    token = _WIRE_GATE.set(gate)
    try:
        yield
    finally:
        _WIRE_GATE.reset(token)


def session_jar_path(cco_home: str | None = None) -> Path:
    root = Path(cco_home or os.environ.get("CCO_HOME", "~/.cco")).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    return root / "session-jar.json"


def _read_jar(cco_home: str | None = None) -> dict:
    path = session_jar_path(cco_home)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_jar(data: dict, cco_home: str | None = None) -> None:
    path = session_jar_path(cco_home)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)


def save_shared_session(
    host: str,
    *,
    cookie: str = "",
    headers: dict | None = None,
    state: str = "active",
    source: str = "manual",
    cco_home: str | None = None,
) -> dict:
    """Persist shared session credentials and liveness state per host."""
    raw_host = (host or "").strip()
    bound_origin = list(_origin(raw_host)) if "://" in raw_host and _origin(raw_host) else None
    h = raw_host.lower()
    if "://" in h:
        h = _host(h)
    if not h:
        return {}
    now = time.time()
    with _jar_lock:
        jar = _read_jar(cco_home)
        prev = jar.get(h) if isinstance(jar.get(h), dict) else {}
        if bound_origin is not None and prev.get("origin") != bound_origin:
            # Never transplant old credentials from another or unknown origin.
            prev = {}
        clean_headers = {
            str(k): str(v)
            for k, v in (headers if headers is not None else (prev.get("headers") or {})).items()
            if k and str(k).lower() != "cookie"
        }
        entry = {
            "host": h,
            "origin": (bound_origin if bound_origin is not None else
                       None if cookie or headers is not None else prev.get("origin")),
            "cookie": cookie if cookie else (prev.get("cookie") or ""),
            "headers": clean_headers,
            "state": state,
            "source": source,
            "updated_at": now,
            "last_verified_at": now if state == "active" else prev.get("last_verified_at", 0.0),
            "consecutive_401": 0 if state == "active" else int(prev.get("consecutive_401", 0)),
        }
        jar[h] = entry
        _write_jar(jar, cco_home)
        return dict(entry)


def load_shared_session(
    host: str,
    *,
    max_age_seconds: float | None = 3600.0,
    cco_home: str | None = None,
    require_origin: bool = False,
) -> dict | None:
    """Load shared session for host; marks stale=True if older than max_age_seconds."""
    raw_host = (host or "").strip()
    expected_origin = list(_origin(raw_host)) if "://" in raw_host and _origin(raw_host) else None
    h = raw_host.lower()
    if "://" in h:
        h = _host(h)
    if not h:
        return None
    with _jar_lock:
        jar = _read_jar(cco_home)
    entry = jar.get(h)
    if not isinstance(entry, dict):
        return None
    if require_origin and (expected_origin is None or entry.get("origin") != expected_origin):
        return {"host": h, "state": "origin_mismatch", "stale": True}
    out = dict(entry)
    now = time.time()
    age = max(0.0, now - float(out.get("updated_at") or 0.0))
    out["age_seconds"] = round(age, 2)
    out["stale"] = bool(max_age_seconds is not None and age > float(max_age_seconds))
    return out


def record_session_observation(
    host: str,
    *,
    status: int | None,
    location: str = "",
    had_auth: bool = False,
    cco_home: str | None = None,
) -> dict | None:
    """Update session liveness state from an observed HTTP response."""
    h = (host or "").strip().lower()
    if "://" in h:
        h = _host(h)
    if not h or not had_auth:
        return None
    login_redirect = bool(status in (301, 302, 303, 307, 308) and _login_location(location))
    with _jar_lock:
        jar = _read_jar(cco_home)
        entry = jar.get(h)
        if not isinstance(entry, dict):
            if status == 401 or login_redirect:
                entry = {
                    "host": h, "cookie": "", "headers": {}, "state": "expired",
                    "source": "egress_observer", "updated_at": time.time(),
                    "last_verified_at": 0.0, "consecutive_401": 1,
                }
                jar[h] = entry
                _write_jar(jar, cco_home)
                return dict(entry)
            return None
        if status == 401 or login_redirect:
            c401 = int(entry.get("consecutive_401", 0)) + 1
            entry["consecutive_401"] = c401
            if login_redirect or c401 >= 2:
                entry["state"] = "expired"
                entry["expired_reason"] = "login_redirect" if login_redirect else "consecutive_401"
            entry["updated_at"] = time.time()
            jar[h] = entry
            _write_jar(jar, cco_home)
        elif status in (200, 201, 204):
            entry["consecutive_401"] = 0
            entry["state"] = "active"
            entry["last_verified_at"] = time.time()
            jar[h] = entry
            _write_jar(jar, cco_home)
        return dict(entry)



def request_count() -> int:
    with _counter_lock:
        return _request_total


def reset_request_count() -> int:
    global _request_total
    with _counter_lock:
        previous, _request_total = _request_total, 0
    return previous


def _bump() -> int:
    global _request_total
    with _counter_lock:
        _request_total += 1
        return _request_total


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _origin(url: str):
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
            return None
        port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
        return (scheme, parsed.hostname.lower(), port) if port > 0 else None
    except (TypeError, ValueError):
        return None


def _send(transport, method, url, *, params, data, headers, timeout):
    t0 = time.perf_counter()
    try:
        resp = transport(method, url, params=params, data=data, headers=headers,
                         timeout=timeout)
        return {
            "ok": True,
            "request_method": str(method or "GET").upper(),
            "status": resp.status_code,
            "len": len(resp.content or b""),
            "time": time.perf_counter() - t0,
            "text": resp.text or "",
            "headers": dict(resp.headers or {}),
            "location": (resp.headers or {}).get("Location", ""),
            "final_url": url,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - normalize edilmis hata zarfi
        return {"ok": False, "request_method": str(method or "GET").upper(), "status": None, "len": 0,
                "time": time.perf_counter() - t0, "text": "", "headers": {},
                "location": "", "final_url": url, "error": str(exc)}


def egress_request(method: str, url: str, *, params=None, data=None, headers=None,
                   allow_redirects: bool = True, timeout: int = 15,
                   extra_hosts: tuple | list = (),
                   request_budget: int | None = None,
                   use_shared_session: bool = False, observe_session: bool = True,
                   transport=None, stop_on_login_redirect: bool = False) -> dict:
    """Kapsam-dogrulamali, sayacli tek istek (redirect hop'lari tek tek).

    Hop host'u ilk host veya extra_hosts icinde degilse bloklanir:
    {ok: False, blocked: "egress", error: ...} doner, istek ATILMAZ.
    """
    if transport is None:
        import requests

        def transport(m, u, *, params, data, headers, timeout):  # noqa: ANN001
            return requests.request(m.upper(), u, params=params, data=data,
                                    headers=headers, allow_redirects=False,
                                    timeout=timeout, verify=False)

    host = _host(url)
    eff_headers = dict(headers) if isinstance(headers, dict) else None
    explicit_auth = bool(eff_headers and any(
        re.search(r"auth|cookie|token|session|credential|api[-_]?key", str(name), re.I)
        for name in eff_headers))
    shared_session_used = False
    if use_shared_session and host and not explicit_auth:
        shared = load_shared_session(url, require_origin=True)
        if shared and (shared.get("state") != "active" or shared.get("stale")):
            return {"ok": False, "blocked": "session", "status": None, "len": 0,
                    "time": 0.0, "text": "", "headers": {}, "location": "",
                    "final_url": url, "requests_sent": 0,
                    "error": "shared test session is stale, expired, or bound to another origin"}
        if shared:
            eff_headers = dict(eff_headers or {})
            for hk, hv in (shared.get("headers") or {}).items():
                if not any(k.lower() == hk.lower() for k in eff_headers):
                    eff_headers[hk] = hv
            if shared.get("cookie") and not any(k.lower() == "cookie" for k in eff_headers):
                eff_headers["Cookie"] = shared["cookie"]
            shared_session_used = bool(shared.get("cookie") or any(
                re.search(r"auth|cookie|token|session|credential|api[-_]?key", str(name), re.I)
                for name in (shared.get("headers") or {})))

    had_auth = bool(
        isinstance(eff_headers, dict)
        and any(re.search(r"auth|cookie|token|session|credential|api[-_]?key", str(k), re.I)
                for k in eff_headers)
    )
    allowed = {host} | {str(h).lower() for h in extra_hosts if h}
    current = url
    first_params, first_data = params, data
    for hop in range(_MAX_REDIRECTS + 1):
        if request_budget is not None and request_count() >= request_budget:
            return {"ok": False, "blocked": "budget", "status": None, "len": 0,
                    "time": 0.0, "text": "", "headers": {}, "location": "",
                    "final_url": current,
                    "error": f"egress request budget asildi ({request_budget})"}
        gate = _WIRE_GATE.get()
        if gate is not None:
            gate_url = current
            if first_params:
                extra = urlencode(first_params, doseq=True)
                if extra:
                    gate_url += ("&" if "?" in gate_url else "?") + extra
            try:
                allowed_request, reason = gate(method, gate_url, dict(eff_headers or {}))
            except Exception as exc:
                allowed_request, reason = False, f"policy gate error: {type(exc).__name__}"
            if not allowed_request:
                from wire_budget import note_blocked
                note_blocked("campaign request blocked by policy")
                return {"ok": False, "blocked": "policy", "status": None, "len": 0,
                        "time": 0.0, "text": "", "headers": {}, "location": "",
                        "request_method": str(method).upper(), "final_url": current,
                        "requests_sent": hop, "error": str(reason)}
        from wire_budget import consume_request
        admitted, budget_reason = consume_request(gate)
        if not admitted:
            return {"ok": False, "blocked": "budget", "status": None, "len": 0,
                    "time": 0.0, "text": "", "headers": {}, "location": "",
                    "final_url": current, "requests_sent": hop, "error": budget_reason}
        _bump()
        resp = _send(transport, method, current,
                     params=first_params, data=first_data, headers=eff_headers,
                     timeout=timeout)
        resp["requests_sent"] = hop + 1
        observer = getattr(gate, "observe", None)
        if callable(observer):
            observer(dict(eff_headers or {}), resp)
        if not resp["ok"]:
            from wire_budget import note_blocked
            note_blocked("campaign transport failed")
            return resp
        location = resp.get("location") or ""
        if observe_session and had_auth and host and shared_session_used:
            obs = record_session_observation(
                host, status=resp.get("status"), location=location, had_auth=True
            )
            if obs and obs.get("state") == "expired":
                resp["session_expired"] = True
                resp["session_state"] = "expired"
        is_redirect = resp.get("status") in (301, 302, 303, 307, 308) and location
        if not (allow_redirects and is_redirect):
            resp["final_url"] = current
            return resp
        nxt = urljoin(current, location)
        if stop_on_login_redirect and _login_location(urlparse(nxt).path):
            resp["final_url"] = current
            resp["session_expired"] = True
            resp["blocked"] = "login_redirect"
            return resp
        if _host(nxt) not in allowed:
            return {"ok": False, "blocked": "egress", "status": resp.get("status"),
                    "len": 0, "time": resp.get("time", 0.0), "text": "",
                    "headers": resp.get("headers", {}), "location": location,
                    "final_url": current,
                    "error": f"egress blocked: redirect kapsam disi hosta: {_host(nxt)}",
                    "requests_sent": hop + 1}
        next_origin = _origin(nxt)
        if (not next_origin or (next_origin != _origin(current)
                and (gate is not None or eff_headers or first_data is not None
                     or str(method).upper() not in {"GET", "HEAD"}))):
            return {"ok": False, "blocked": "egress", "status": resp.get("status"),
                    "len": 0, "time": resp.get("time", 0.0), "text": "",
                    "headers": resp.get("headers", {}), "location": location,
                    "final_url": current, "requests_sent": hop + 1,
                    "error": "egress blocked: redirect to different origin"}
        if resp["status"] in (301, 302, 303):
            method, first_data = "GET", None
        first_params = None
        current = nxt
    resp["final_url"] = current
    resp["error"] = "too many redirects"
    return resp
