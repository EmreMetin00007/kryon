"""mitmproxy eklentisi: AKTIF scope'taki hostlarin trafigini kaydet + route envanteri.

mitm_rapyd.py'den farki: host listesini sabit kodlamak yerine aktif
.codex/scope.json'daki "targets" listesinden okur. Scope degisince
mitmdump'u yeniden baslatmak yeterli, script duzenlenmez.

Calistirma (rapyd logger ile birlikte):
  mitmdump -s scripts/mitm_rapyd.py -s scripts/mitm_scope.py --listen-port 8080 -q

Ciktilar (repo DISI, secret sizmasin):
  /root/.cco/scope-traffic.jsonl      — ham istek/yanit ozeti
  /root/.cco/scope-routes-live.json   — gozlenen route envanteri
"""
import json
import os
import time
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode

CCO = Path(os.environ.get("CCO_HOME", "/root/.cco")).expanduser()
TRAFFIC = CCO / "scope-traffic.jsonl"
ROUTES = CCO / "scope-routes-live.json"
HOSTSTATS = CCO / "scope-host-stats.json"
SCOPE_FILE = Path(__file__).resolve().parent.parent / ".codex" / "scope.json"
# Disk yazma trottle: dosya-butun rewrite'i her akista degil, en cok 5sn'de bir.
SAVE_INTERVAL_SEC = 5.0
_safe_headers = {"accept", "accept-encoding", "content-type"}


def _load_scope_hosts() -> tuple:
    try:
        data = json.loads(SCOPE_FILE.read_text())
    except (OSError, ValueError):
        return ()
    targets = data.get("targets") or []
    return tuple(t for t in targets if isinstance(t, str) and t)


WATCH_HOSTS: tuple = ()
_WATCH_EXACT: frozenset = frozenset()
_WATCH_SUFFIX: tuple = ()
_SCOPE_MTIME = 0.0


def _maybe_reload_scope() -> tuple:
    """Scope dosyasi degismisse host listesini yeniden yukle (restart'siz scope switch)."""
    global _SCOPE_MTIME, WATCH_HOSTS, _WATCH_EXACT, _WATCH_SUFFIX
    try:
        mtime = SCOPE_FILE.stat().st_mtime
    except OSError:
        return WATCH_HOSTS
    if mtime != _SCOPE_MTIME:
        _SCOPE_MTIME = mtime
        WATCH_HOSTS = _load_scope_hosts()
        # O(1) uyelik + wildcard destegi: "*.ornek.com" alt hostlari da kapsar.
        # (Eskiden tuple'da literal eslesme vardi: wildcard'lar hic tutmuyordu.)
        exact = set()
        suffix = []
        for t in WATCH_HOSTS:
            tl = t.strip().lower()
            if tl.startswith("*."):
                suffix.append(tl[2:])
            else:
                exact.add(tl)
        _WATCH_EXACT = frozenset(exact)
        _WATCH_SUFFIX = tuple(suffix)
    return WATCH_HOSTS


def host_in_scope(host: str) -> bool:
    """Akis basi scope kontrolu: exact O(1) + wildcard suffix."""
    _maybe_reload_scope()
    h = (host or "").strip().lower()
    if h in _WATCH_EXACT:
        return True
    return any(h == s or h.endswith("." + s) for s in _WATCH_SUFFIX)


def url_in_scope(url: str) -> bool:
    """Filter captured traffic with the central scope, not a host approximation.

    This is a logging filter; this addon does not block requests on the wire.
    """
    try:
        script_dir = str(Path(__file__).resolve().parent)
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        from policy_engine import ScopeResolver
        scope_file = os.environ.get("CCO_SCOPE_FILE") or str(SCOPE_FILE)
        return ScopeResolver(scope_file=scope_file).permits_url(url)
    except (ImportError, OSError, RuntimeError, ValueError):
        return False


_maybe_reload_scope()


def _clean(headers) -> dict:
    return {k: (v if k.lower() in _safe_headers else "<redacted>")
            for k, v in headers.items()}


def _clean_query(path: str) -> str:
    if "?" not in path:
        return ""
    qs = path.split("?", 1)[1]
    try:
        pairs = [(k, "<redacted>")
                 for k, v in parse_qsl(qs, keep_blank_values=True)]
    except ValueError:
        return "<redacted>"
    return urlencode(pairs)[:300]


def load_routes() -> dict:
    if ROUTES.exists():
        try:
            return json.loads(ROUTES.read_text())
        except ValueError:
            pass
    return {}


def save_routes(routes: dict) -> None:
    ROUTES.write_text(json.dumps(routes, indent=1, sort_keys=True))


def load_hoststats() -> dict:
    if HOSTSTATS.exists():
        try:
            return json.loads(HOSTSTATS.read_text())
        except ValueError:
            pass
    return {}


def save_hoststats(stats: dict) -> None:
    HOSTSTATS.write_text(json.dumps(stats, indent=1, sort_keys=True))


def _extract_body_params(content_type: str, body_text: str) -> list[dict]:
    """Extract parameter names and redacted samples from JSON or form bodies."""
    if not body_text:
        return []
    ctype = (content_type or "").lower()
    raw = body_text.strip()
    out: list[dict] = []
    if "json" in ctype or raw.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                for k, v in list(data.items())[:32]:
                    name = str(k).strip()
                    if not name:
                        continue
                    out.append({"name": name, "in": "json", "sample": "<redacted>"})
                return out
        except Exception:
            pass
    if "form-urlencoded" in ctype or ("=" in raw and not raw.startswith("<")):
        try:
            for k, v in parse_qsl(raw, keep_blank_values=True)[:32]:
                name = str(k).strip()
                if not name:
                    continue
                out.append({"name": name, "in": "body", "sample": "<redacted>"})
        except Exception:
            pass
    return out


def _sync_routes_to_attack_surface(routes: dict) -> None:
    """Bridge observed MITM routes into attack_surface SQLite table."""
    try:
        import sys
        mem_dir = str(Path(__file__).resolve().parent.parent / "mcp-servers" / "mcp-memory-server")
        if mem_dir not in sys.path:
            sys.path.insert(0, mem_dir)
        from cco_surface_core.store import ingest_records
    except Exception:
        return
    by_host: dict[str, list[dict]] = {}
    for route_key, info in (routes or {}).items():
        if not isinstance(info, dict):
            continue
        url = info.get("sample_url") or ""
        host = info.get("host") or ""
        if not url or not host:
            continue
        method = route_key.split(" ", 1)[0] if " " in route_key else "GET"
        statuses = info.get("statuses") or {}
        top_status = next((int(k) for k in statuses if str(k).isdigit()), 200)
        by_host.setdefault(host, []).append({
            "target": host,
            "url": url,
            "method": method,
            "status": top_status,
            "params": info.get("params") or [],
            "sources": ["mitm"],
        })
    db_path = str(CCO / "agent_memory.db")
    for host, recs in by_host.items():
        try:
            ingest_records(recs, target=host, db_path=db_path)
        except Exception:
            pass


class ScopeLogger:
    def __init__(self) -> None:
        self.routes = load_routes()
        self.hoststats = load_hoststats()
        self._last_save = 0.0

    def _maybe_save(self) -> None:
        now = time.monotonic()
        if now - self._last_save >= SAVE_INTERVAL_SEC:
            self._last_save = now
            save_routes(self.routes)
            save_hoststats(self.hoststats)
            _sync_routes_to_attack_surface(self.routes)

    def response(self, flow) -> None:  # noqa: ANN001
        host = flow.request.host
        if not url_in_scope(flow.request.pretty_url):
            return
        st = str(flow.response.status_code)
        # Route envanteri (sema degismedi, ek alanlar geriye uyumlu).
        key = f"{flow.request.method} {flow.request.path.split('?')[0]}"
        entry = self.routes.get(key, {"count": 0, "statuses": {}})
        entry["count"] += 1
        entry["statuses"][st] = entry["statuses"].get(st, 0) + 1
        entry["host"] = host
        entry["sample_url"] = flow.request.pretty_url.split("?")[0] + (
            ("?" + _clean_query(flow.request.path)) if "?" in flow.request.path else ""
        )
        q = _clean_query(flow.request.path)
        if q:
            entry["sample_query"] = q
        ctype = flow.request.headers.get("Content-Type") or flow.request.headers.get("content-type") or ""
        body_params = _extract_body_params(ctype, flow.request.text or "")
        try:
            query_params = [{"name": name, "in": "query", "sample": "<redacted>"}
                            for name, _ in parse_qsl(flow.request.path.partition("?")[2],
                                                     keep_blank_values=True)[:32] if name]
        except ValueError:
            query_params = []
        if body_params:
            existing_params = {
                (p.get("in"), p.get("name")): p
                for p in (entry.get("params") or [])
                if isinstance(p, dict)
            }
            for bp in body_params:
                existing_params[(bp["in"], bp["name"])] = bp
            entry["params"] = list(existing_params.values())
        self.routes[key] = entry
        # Host sayaci (artirimli, O(1)): ajan ozet API'si buradan beslenir.
        hs = self.hoststats.get(host, {"n": 0, "codes": {}, "last": ""})
        hs["n"] += 1
        hs["codes"][st] = hs["codes"].get(st, 0) + 1
        hs["last"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.hoststats[host] = hs
        self._maybe_save()
        safe_url = flow.request.pretty_url.split("?", 1)[0] + (("?" + q) if q else "")
        rec = {"method": flow.request.method, "url": safe_url,
               "status": flow.response.status_code,
               "req_headers": _clean(flow.request.headers),
               "params": query_params + body_params, "capture_redacted": True,
               "req_body": "", "resp_body": "",
               "req_body_length": len(flow.request.text or ""),
               "resp_body_length": len(flow.response.text or "")}
        with TRAFFIC.open("a") as f:
            f.write(json.dumps(rec) + "\n")


addons = [ScopeLogger()]
