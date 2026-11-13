"""Optional request guard for discovery embedded in another tool's run."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import urljoin, urlsplit


_GUARD = ContextVar("surface_request_guard", default=None)


class SurfaceBlocked(RuntimeError):
    pass


def _origin(url):
    try:
        parsed = urlsplit(url if "://" in url else "https://" + url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
            return None
        return (parsed.scheme.lower(), parsed.hostname.lower(),
                parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
    except (ValueError, TypeError):
        return None


@contextmanager
def scoped_surface_requests(gate, target):
    origin = _origin(str(target or ""))
    if not callable(gate) or not origin:
        raise SurfaceBlocked("discovery policy unavailable or invalid target")
    token = _GUARD.set((gate, origin))
    try:
        yield
    finally:
        _GUARD.reset(token)


def current_surface_guard():
    return _GUARD.get()


def guarded_get(url, *, headers, timeout, proxies, sender):
    """Check each hop and never forward the session to another origin."""
    gate, origin = _GUARD.get()
    current = url
    for _ in range(6):
        if _origin(current) != origin:
            raise SurfaceBlocked("discovery blocked: different origin")
        try:
            allowed, reason = gate("GET", current, dict(headers))
        except Exception as exc:
            raise SurfaceBlocked("discovery policy unavailable") from exc
        if not allowed:
            raise SurfaceBlocked("discovery blocked by policy: " + str(reason or "blocked"))
        from wire_budget import consume_request
        admitted, budget_reason = consume_request(gate)
        if not admitted:
            raise SurfaceBlocked("discovery blocked: " + budget_reason)
        response = sender(current, timeout=timeout, verify=False, allow_redirects=False,
                          headers=headers, proxies=proxies)
        observer = getattr(gate, "observe", None)
        if callable(observer):
            observer(headers, {"ok": True, "status": response.status_code,
                               "location": response.headers.get("Location", "")})
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("Location") or response.headers.get("location")
        if not location:
            return response
        current = urljoin(current, location)
        if urlsplit(current).path.lower().rstrip("/").endswith(("/login", "/signin", "/sign-in")):
            raise SurfaceBlocked("discovery stopped: session redirected to login")
    raise SurfaceBlocked("discovery stopped: redirect limit reached")
