"""Zero-runtime-overhead offline seed surface importer and optional tech-hints helper.

Purely local offline parsing (0 network calls, zero legacy engine imports) that
converts operator-supplied proxy/HAR/scanner/URL artifacts into strictly
scope-validated, secret-stripped surface payloads ingestible by
`SurfaceFrontierTracker.ingest_surface`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from agentic_http import is_static_asset_url  # noqa: E402
from agentic_surface import SurfaceFrontierTracker, is_id_segment, route_template_of  # noqa: E402
from target_bootstrap import ScopeGuard, normalize_path  # noqa: E402

MAX_SEED_FILE_BYTES = 10 * 1024 * 1024  # 10 MB hard cap per seed file
_MAX_PARAMS_PER_ROUTE = 32
_MAX_QUERY_FIELDS = 128

_VALID_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_SAFE_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]$]{1,64}$")
_METHOD_PATH_KEY_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/\S*)$",
    re.IGNORECASE,
)
_METHOD_URL_LINE_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)$",
    re.IGNORECASE,
)
_MULTIPART_NAME_RE = re.compile(
    r'Content-Disposition\s*:[^\r\n]*?\bname\s*=\s*"([^"\r\n]{1,64})"',
    re.IGNORECASE,
)
_REQUEST_LINE_METHOD_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+",
    re.IGNORECASE,
)
_SCHEMELESS_HOST_RE = re.compile(
    r"^(?:(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})(?::\d{1,5})?$",
    re.IGNORECASE,
)
_API_PATH_RE = re.compile(
    r"^/(?:api(?:/v\d+)?|v\d+|rest|rpc|graphql)(?:/|$)|/api(?:/v\d+)?/",
    re.IGNORECASE,
)
_HIGH_SIGNAL_KEYWORDS = (
    "admin",
    "internal",
    "debug",
    "config",
    "export",
    "import",
    "upload",
    "download",
    "transfer",
    "payment",
    "billing",
    "invoice",
    "order",
    "account",
    "user",
    "profile",
    "role",
    "permission",
    "token",
    "oauth",
    "webhook",
    "search",
    "report",
    "settings",
    "graphql",
)
_LOW_SIGNAL_EXACT_PATHS = frozenset({"/", "/robots.txt", "/sitemap.xml", "/favicon.ico"})

_TECH_TAG_ALIASES: dict[str, str] = {
    "next": "nextjs",
    "nextjs": "nextjs",
    "spring": "spring",
    "springboot": "spring",
    "java": "spring",
    "tomcat": "spring",
    "django": "django",
    "fastapi": "fastapi",
    "starlette": "fastapi",
    "flask": "flask",
    "rails": "rails",
    "rubyonrails": "rails",
    "ruby": "rails",
    "graphql": "graphql",
    "apollo": "graphql",
    "express": "express",
    "expressjs": "express",
    "node": "node",
    "nodejs": "node",
    "nestjs": "express",
    "laravel": "laravel",
    "php": "php",
    "wordpress": "wordpress",
    "wp": "wordpress",
    "nginx": "nginx",
    "apache": "apache",
    "dotnet": "dotnet",
    "aspnet": "dotnet",
    "iis": "iis",
    "go": "go",
    "golang": "go",
    "swagger": "openapi",
    "openapi": "openapi",
}

_BUILTIN_TECH_HINTS: dict[str, tuple[str, ...]] = {
    "nextjs": (
        "/api/auth/session",
        "/api/auth/providers",
        "/api/health",
        "/api/trpc",
        "/_next/data",
        "/sitemap.xml",
        "/robots.txt",
    ),
    "django": (
        "/admin",
        "/api",
        "/api/schema",
        "/graphql",
        "/accounts/login",
        "/__debug__",
        "/health",
        "/sitemap.xml",
    ),
    "spring": (
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/mappings",
        "/v3/api-docs",
        "/swagger-ui.html",
        "/api",
        "/health",
    ),
    "fastapi": (
        "/openapi.json",
        "/docs",
        "/redoc",
        "/api/v1",
        "/health",
        "/metrics",
    ),
    "flask": (
        "/api",
        "/api/v1",
        "/health",
        "/status",
        "/console",
        "/debug",
        "/metrics",
    ),
    "rails": (
        "/rails/info/routes",
        "/rails/info",
        "/admin",
        "/api",
        "/api/v1",
        "/graphql",
        "/sidekiq",
        "/health",
    ),
    "graphql": (
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/graphiql",
        "/playground",
        "/altair",
    ),
    "express": (
        "/api",
        "/api/v1",
        "/api-docs",
        "/swagger.json",
        "/graphql",
        "/health",
        "/status",
        "/metrics",
    ),
    "node": (
        "/api",
        "/api/v1",
        "/graphql",
        "/health",
        "/status",
        "/metrics",
        "/debug",
        "/package.json",
    ),
    "laravel": (
        "/api",
        "/sanctum/csrf-cookie",
        "/telescope",
        "/horizon",
        "/admin",
        "/health",
        "/storage",
    ),
    "php": (
        "/api",
        "/admin",
        "/info.php",
        "/phpinfo.php",
        "/phpmyadmin",
        "/adminer.php",
        "/config.php",
    ),
    "wordpress": (
        "/wp-json",
        "/wp-json/wp/v2/users",
        "/wp-admin",
        "/wp-login.php",
        "/xmlrpc.php",
        "/readme.html",
    ),
    "nginx": (
        "/files",
        "/uploads",
        "/download",
        "/export",
        "/backup",
        "/stub_status",
        "/nginx_status",
    ),
    "apache": (
        "/server-status",
        "/server-info",
        "/cgi-bin",
        "/uploads",
        "/webdav",
        "/manual",
    ),
    "dotnet": (
        "/swagger",
        "/swagger/v1/swagger.json",
        "/api",
        "/health",
        "/elmah.axd",
        "/trace.axd",
        "/web.config",
    ),
    "iis": (
        "/trace.axd",
        "/elmah.axd",
        "/web.config",
        "/admin",
        "/api",
        "/owa",
    ),
    "go": (
        "/debug/pprof",
        "/metrics",
        "/health",
        "/healthz",
        "/api",
        "/status",
    ),
    "openapi": (
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
        "/api-docs",
        "/docs",
        "/swagger-ui.html",
    ),
}

_LOW_VALUE_TECH_HINT_SEGMENTS = frozenset({
    "/css",
    "/js",
    "/images",
    "/img",
    "/fonts",
    "/static",
    "/assets",
})


@dataclass
class _CandidateRoute:
    method: str
    url: str
    params: list[str] = field(default_factory=list)
    is_form: bool = False
    status: int | None = None


@dataclass
class _AcceptedRoute:
    method: str
    path: str
    params: list[str] = field(default_factory=list)
    is_form: bool = False
    best_status: int | None = None
    first_seen: int = 0


def _read_seed_file(path: Path | str, *, max_bytes: int = MAX_SEED_FILE_BYTES) -> str:
    """Safely read a regular non-symlink local seed file with a hard byte cap."""
    if path is None or not str(path).strip():
        raise ValueError("seed file path is required")
    raw_path = Path(path).expanduser()
    try:
        st = raw_path.lstat()
    except OSError as exc:
        raise ValueError(f"seed file is missing or unreadable: {raw_path}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"seed file must not be a symlink: {raw_path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"seed file must be a regular file: {raw_path}")
    if st.st_size > max_bytes:
        raise ValueError(f"seed file exceeds maximum size of {max_bytes} bytes: {raw_path}")

    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(raw_path, open_flags)
    except OSError as exc:
        raise ValueError(f"failed to open seed file {raw_path}: {exc}") from exc

    try:
        fd_stat = os.fstat(fd)
        if not stat.S_ISREG(fd_stat.st_mode):
            raise ValueError(f"seed file must be a regular file: {raw_path}")
        if fd_stat.st_size > max_bytes:
            raise ValueError(f"seed file exceeds maximum size of {max_bytes} bytes: {raw_path}")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            raw_bytes = fh.read(max_bytes + 1)
    except ValueError:
        if fd >= 0:
            os.close(fd)
        raise
    except OSError as exc:
        if fd >= 0:
            os.close(fd)
        raise ValueError(f"failed to read seed file {raw_path}: {exc}") from exc

    if len(raw_bytes) > max_bytes:
        raise ValueError(f"seed file exceeds maximum size of {max_bytes} bytes: {raw_path}")
    text = raw_bytes.decode("utf-8", errors="replace")
    return text.lstrip("\ufeff")


def _normalize_method(raw: Any, default: str = "GET") -> str:
    cleaned = str(raw or "").strip().upper()
    if cleaned in _VALID_HTTP_METHODS:
        return cleaned
    return default


def _coerce_status(raw: Any) -> int | None:
    if isinstance(raw, bool) or raw is None:
        return None
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return None
    return val if 100 <= val <= 599 else None


def _status_priority(status: int | None) -> int:
    if status is None:
        return 0
    if 200 <= status < 300 or status in {401, 403}:
        return 6
    if 300 <= status < 400 or status in {400, 405, 422}:
        return 3
    if status in {404, 410}:
        return -10
    return -2


def _sanitize_param_name(raw: Any) -> str:
    name = str(raw or "").strip()
    if not name or not _SAFE_PARAM_NAME_RE.fullmatch(name):
        return ""
    return name


def _extract_param_names(raw: Any) -> list[str]:
    """Extract sanitized parameter/field names only (never values)."""
    out: list[str] = []
    seen: set[str] = set()

    def _add(candidate: Any) -> None:
        clean = _sanitize_param_name(candidate)
        if clean and clean not in seen and len(out) < _MAX_PARAMS_PER_ROUTE:
            seen.add(clean)
            out.append(clean)

    if isinstance(raw, str):
        if "=" in raw or "&" in raw:
            for k, _ in parse_qsl(raw, keep_blank_values=True, max_num_fields=_MAX_QUERY_FIELDS):
                _add(k)
        else:
            _add(raw)
    elif isinstance(raw, dict):
        for k in raw:
            _add(k)
    elif isinstance(raw, (list, tuple, set)):
        for item in raw:
            if isinstance(item, str):
                _add(item)
            elif isinstance(item, dict):
                _add(item.get("name") or item.get("param") or item.get("key") or item.get("field"))
    return out


def _extract_body_field_names(body_text: str, mime_type: str = "") -> list[str]:
    """Extract JSON/form/multipart field NAMES from a request body (never values)."""
    if not isinstance(body_text, str):
        return []
    raw = body_text.strip()
    if not raw:
        return []
    ctype = str(mime_type or "").split(";", 1)[0].strip().lower()

    if "json" in ctype or raw.startswith(("{", "[")):
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            return _extract_param_names(list(parsed.keys()))
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            return _extract_param_names(list(parsed[0].keys()))
        if "json" in ctype:
            return []

    if "multipart/form-data" in ctype or "Content-Disposition:" in raw:
        names = _MULTIPART_NAME_RE.findall(raw)
        if names:
            return _extract_param_names(names)
        if "multipart/form-data" in ctype:
            return []

    if "x-www-form-urlencoded" in ctype or ("=" in raw and not raw.startswith(("<", "{", "["))):
        pairs = parse_qsl(raw, keep_blank_values=True, max_num_fields=_MAX_QUERY_FIELDS)
        return _extract_param_names([k for k, _ in pairs])

    return []


def _parse_method_path_key(key: Any) -> tuple[str, str] | None:
    if not isinstance(key, str):
        return None
    match = _METHOD_PATH_KEY_RE.fullmatch(key.strip())
    if not match:
        return None
    return match.group(1).upper(), match.group(2)


def _resolve_host_and_path(host_hint: str, path_or_url: str, guard: ScopeGuard) -> str:
    """Attach an explicit host hint to a relative path so ScopeGuard enforces exact origin."""
    raw_path = str(path_or_url or "").strip()
    if not raw_path:
        return ""
    if "://" in raw_path or raw_path.startswith("//"):
        return raw_path
    clean_host = str(host_hint or "").strip()
    if not clean_host:
        return raw_path

    base_parsed = urlsplit(guard.base_origin)
    base_scheme = base_parsed.scheme.lower()
    base_host = (base_parsed.hostname or "").lower().rstrip(".")

    if "://" in clean_host:
        return urljoin(clean_host.rstrip("/") + "/", raw_path if raw_path.startswith("/") else "/" + raw_path)

    try:
        parsed_host = urlsplit(f"{base_scheme}://{clean_host}")
        explicit_port = parsed_host.port
    except ValueError:
        return f"{base_scheme}://{clean_host}{raw_path if raw_path.startswith('/') else '/' + raw_path}"

    hint_hostname = (parsed_host.hostname or "").strip().lower().rstrip(".")
    if explicit_port is None and hint_hostname == base_host:
        return urljoin(guard.base_origin, raw_path)
    return f"{base_scheme}://{clean_host}{raw_path if raw_path.startswith('/') else '/' + raw_path}"


def _best_status_from_map(statuses: Any) -> int | None:
    if not isinstance(statuses, dict):
        return None
    best: int | None = None
    best_rank = -999
    for code_raw in statuses:
        code = _coerce_status(code_raw)
        if code is None:
            continue
        rank = _status_priority(code)
        if rank > best_rank:
            best_rank = rank
            best = code
    return best


def _parse_har(data: dict[str, Any]) -> list[_CandidateRoute]:
    log = data.get("log")
    if not isinstance(log, dict):
        return []
    entries = log.get("entries")
    if not isinstance(entries, list):
        return []

    out: list[_CandidateRoute] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request")
        if not isinstance(req, dict):
            continue
        url = str(req.get("url") or "").strip()
        if not url:
            continue
        method = _normalize_method(req.get("method"), default="GET")

        # Extract ONLY parameter/field names — never headers, cookies, or values.
        params: list[str] = []
        seen: set[str] = set()

        def _extend(names: Sequence[str]) -> None:
            for name in names:
                if name and name not in seen and len(params) < _MAX_PARAMS_PER_ROUTE:
                    seen.add(name)
                    params.append(name)

        if isinstance(req.get("queryString"), list):
            _extend(_extract_param_names(req["queryString"]))

        is_form = False
        post_data = req.get("postData")
        if isinstance(post_data, dict):
            mime = str(post_data.get("mimeType") or "").split(";", 1)[0].strip().lower()
            has_form_params = isinstance(post_data.get("params"), list) and bool(post_data["params"])
            if has_form_params:
                _extend(_extract_param_names(post_data["params"]))
            raw_text = post_data.get("text")
            if isinstance(raw_text, str) and raw_text.strip():
                _extend(_extract_body_field_names(raw_text, mime))
            if method in _WRITE_METHODS and (
                "x-www-form-urlencoded" in mime
                or "multipart/form-data" in mime
                or (has_form_params and "json" not in mime)
            ):
                is_form = True

        resp = entry.get("response")
        status = _coerce_status(resp.get("status")) if isinstance(resp, dict) else None
        out.append(_CandidateRoute(method=method, url=url, params=params, is_form=is_form, status=status))
    return out


def _is_zap_dict(data: dict[str, Any]) -> bool:
    if "site" in data and isinstance(data["site"], (list, dict)):
        sites = data["site"] if isinstance(data["site"], list) else [data["site"]]
        if not sites or any(
            isinstance(s, dict) and any(k in s for k in ("@name", "@host", "alerts", "urls"))
            for s in sites
        ):
            return True
    if "urlsInScope" in data:
        return True
    if "alerts" in data and isinstance(data["alerts"], (list, dict)):
        return True
    if "urls" in data and (
        isinstance(data["urls"], dict)
        or any(k in data for k in ("@version", "@generated", "ascan", "ajax", "mode", "spider"))
    ):
        return True
    return False


def _parse_zap(data: dict[str, Any], guard: ScopeGuard) -> list[_CandidateRoute]:
    out: list[_CandidateRoute] = []

    raw_sites = data.get("site")
    sites = raw_sites if isinstance(raw_sites, list) else ([raw_sites] if isinstance(raw_sites, dict) else [])
    for site in sites:
        if not isinstance(site, dict):
            continue
        site_origin = str(site.get("@name") or "").strip()
        if not site_origin and site.get("@host"):
            ssl_flag = str(site.get("@ssl") or "").strip().lower() in {"true", "1", "yes"}
            scheme = "https" if ssl_flag else "http"
            host = str(site.get("@host") or "").strip()
            port = str(site.get("@port") or "").strip()
            if port and not ((scheme == "https" and port == "443") or (scheme == "http" and port == "80")):
                site_origin = f"{scheme}://{host}:{port}"
            elif host:
                site_origin = f"{scheme}://{host}"

        for raw_u in site.get("urls") or []:
            u = raw_u if isinstance(raw_u, str) else (raw_u.get("url") if isinstance(raw_u, dict) else "")
            u_str = str(u or "").strip()
            if u_str:
                out.append(_CandidateRoute(method="GET", url=_resolve_host_and_path(site_origin, u_str, guard)))

        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances")
            if isinstance(instances, list) and instances:
                for inst in instances:
                    if not isinstance(inst, dict):
                        continue
                    uri = str(inst.get("uri") or inst.get("url") or "").strip()
                    if not uri:
                        continue
                    method = _normalize_method(inst.get("method") or alert.get("method"), default="GET")
                    params = _extract_param_names([inst.get("param") or inst.get("parameter") or alert.get("param")])
                    out.append(
                        _CandidateRoute(
                            method=method,
                            url=_resolve_host_and_path(site_origin, uri, guard),
                            params=params,
                        )
                    )
            else:
                uri = str(alert.get("uri") or alert.get("url") or "").strip()
                if uri:
                    method = _normalize_method(alert.get("method"), default="GET")
                    params = _extract_param_names([alert.get("param") or alert.get("parameter")])
                    out.append(
                        _CandidateRoute(
                            method=method,
                            url=_resolve_host_and_path(site_origin, uri, guard),
                            params=params,
                        )
                    )

    raw_urls = data.get("urls") or data.get("urlsInScope") or []
    if isinstance(raw_urls, dict):
        raw_urls = raw_urls.get("urls") or []
    if isinstance(raw_urls, list):
        for item in raw_urls:
            if isinstance(item, str) and item.strip():
                out.append(_CandidateRoute(method="GET", url=item.strip()))
            elif isinstance(item, dict):
                u_str = str(item.get("url") or item.get("uri") or "").strip()
                if u_str:
                    method = _normalize_method(item.get("method"), default="GET")
                    params = _extract_param_names(item.get("params"))
                    out.append(_CandidateRoute(method=method, url=u_str, params=params))

    raw_alerts = data.get("alerts") or data.get("alert") or []
    if isinstance(raw_alerts, dict):
        raw_alerts = raw_alerts.get("alerts") or raw_alerts.get("alert") or []
    if isinstance(raw_alerts, list):
        for alert in raw_alerts:
            if not isinstance(alert, dict):
                continue
            uri = str(alert.get("url") or alert.get("uri") or "").strip()
            if not uri:
                continue
            method = _normalize_method(alert.get("method"), default="GET")
            params = _extract_param_names([alert.get("param") or alert.get("parameter")])
            out.append(_CandidateRoute(method=method, url=uri, params=params))

    return out


def _is_ffuf_dict(data: dict[str, Any]) -> bool:
    results = data.get("results") if "results" in data else data.get("Results")
    if not isinstance(results, list):
        return False
    if "commandline" in data or "config" in data:
        return True
    if not results:
        return "results" in data
    return any(isinstance(item, dict) and ("url" in item or "URL" in item) for item in results[:10])


def _parse_ffuf(data: dict[str, Any]) -> list[_CandidateRoute]:
    results = data.get("results") if isinstance(data.get("results"), list) else data.get("Results")
    if not isinstance(results, list):
        return []
    raw_cfg = data.get("config")
    cfg: dict[str, Any] = raw_cfg if isinstance(raw_cfg, dict) else {}
    default_method = _normalize_method(cfg.get("method"), default="GET")

    out: list[_CandidateRoute] = []
    for item in results:
        if isinstance(item, str) and item.strip():
            out.append(_CandidateRoute(method=default_method, url=item.strip()))
        elif isinstance(item, dict):
            url = str(item.get("url") or item.get("URL") or "").strip()
            if not url:
                continue
            method = _normalize_method(item.get("method"), default=default_method)
            status = _coerce_status(item.get("status") if "status" in item else item.get("status_code"))
            out.append(_CandidateRoute(method=method, url=url, status=status))
    return out


def _is_mitm_scope_dict(data: dict[str, Any]) -> bool:
    if not data:
        return False
    for key, val in data.items():
        if _parse_method_path_key(key) is not None:
            return True
        if isinstance(val, dict) and val:
            if any(_parse_method_path_key(inner_k) is not None for inner_k in val):
                return True
    return False


def _extract_mitm_route_entry(
    route_key: str,
    info: Any,
    host_hint: str,
    guard: ScopeGuard,
) -> _CandidateRoute | None:
    parsed_key = _parse_method_path_key(route_key)
    if parsed_key is None:
        return None
    method, path = parsed_key
    params: list[str] = []
    status: int | None = None
    entry_host = host_hint
    candidate_url = ""

    if isinstance(info, dict):
        if info.get("host"):
            entry_host = str(info.get("host")).strip()
        raw_sample = str(info.get("sample_url") or info.get("url") or "").strip()
        if raw_sample:
            candidate_url = _resolve_host_and_path(entry_host, raw_sample, guard)
        else:
            candidate_url = _resolve_host_and_path(entry_host, path, guard)
        for pkey in ("params", "query_params", "body_fields", "fields"):
            params.extend(_extract_param_names(info.get(pkey)))
        if info.get("sample_query"):
            params.extend(_extract_param_names(str(info.get("sample_query"))))
        status = _best_status_from_map(info.get("statuses")) or _coerce_status(info.get("status"))
    else:
        candidate_url = _resolve_host_and_path(entry_host, path, guard)

    if not candidate_url:
        return None
    return _CandidateRoute(method=method, url=candidate_url, params=params, status=status)


def _parse_mitm_scope_dict(data: dict[str, Any], guard: ScopeGuard) -> list[_CandidateRoute]:
    out: list[_CandidateRoute] = []
    for key, val in data.items():
        if _parse_method_path_key(key) is not None:
            rec = _extract_mitm_route_entry(str(key), val, "", guard)
            if rec is not None:
                out.append(rec)
        elif isinstance(val, dict):
            host_hint = str(key).strip()
            for inner_k, inner_v in val.items():
                rec = _extract_mitm_route_entry(str(inner_k), inner_v, host_hint, guard)
                if rec is not None:
                    out.append(rec)
    return out


def _is_nuclei_item(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    return any(k in item for k in ("matched-at", "matched_at", "template-id", "template_id", "matcher-name"))


def _parse_nuclei_items(items: Sequence[Any]) -> list[_CandidateRoute]:
    out: list[_CandidateRoute] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = str(
            item.get("matched-at")
            or item.get("matched_at")
            or item.get("url")
            or item.get("host")
            or ""
        ).strip()
        if not url:
            continue
        method = _normalize_method(item.get("method"), default="")
        if not method:
            req_raw = item.get("request")
            if isinstance(req_raw, str):
                m_req = _REQUEST_LINE_METHOD_RE.match(req_raw.lstrip())
                if m_req:
                    method = m_req.group(1).upper()
        if not method:
            method = "GET"
        status = _coerce_status(item.get("status") or item.get("status-code"))
        out.append(_CandidateRoute(method=method, url=url, status=status))
    return out


def _parse_route_item(item: Any, *, default_method: str = "GET", is_form: bool = False) -> _CandidateRoute | None:
    if isinstance(item, str):
        line = item.strip()
        if not line:
            return None
        m_line = _METHOD_URL_LINE_RE.fullmatch(line)
        if m_line:
            return _CandidateRoute(method=m_line.group(1).upper(), url=m_line.group(2), is_form=is_form)
        if any(ch.isspace() for ch in line):
            return None
        return _CandidateRoute(method=default_method, url=line, is_form=is_form)

    if isinstance(item, dict):
        url = str(
            item.get("url")
            or item.get("path")
            or item.get("endpoint")
            or item.get("action")
            or item.get("href")
            or item.get("uri")
            or ""
        ).strip()
        if not url:
            return None
        method = _normalize_method(item.get("method"), default=default_method)
        params: list[str] = []
        for pkey in ("params", "query_params", "body_fields", "fields", "inputs", "body_keys"):
            params.extend(_extract_param_names(item.get(pkey)))
        status = _coerce_status(item.get("status"))
        return _CandidateRoute(method=method, url=url, params=params, is_form=is_form, status=status)
    return None


def _parse_generic_json(data: Any) -> list[_CandidateRoute]:
    out: list[_CandidateRoute] = []
    if isinstance(data, list):
        for item in data:
            rec = _parse_route_item(item)
            if rec is not None:
                out.append(rec)
        return out

    if not isinstance(data, dict):
        return out

    found_collection = False
    for list_key in ("routes", "urls", "endpoints", "links", "pages", "js_calls", "spa_routes", "api_requests"):
        arr = data.get(list_key)
        if isinstance(arr, list):
            found_collection = True
            for item in arr:
                rec = _parse_route_item(item)
                if rec is not None:
                    out.append(rec)

    forms = data.get("forms")
    if isinstance(forms, list):
        found_collection = True
        for item in forms:
            rec = _parse_route_item(item, default_method="GET", is_form=True)
            if rec is not None:
                out.append(rec)

    if not found_collection:
        single = _parse_route_item(data)
        if single is not None:
            out.append(single)
    return out


def _parse_plain_text(text: str, guard: ScopeGuard) -> list[_CandidateRoute]:
    base_scheme = urlsplit(guard.base_origin).scheme.lower()
    out: list[_CandidateRoute] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line[0] in "{[\"'":
            continue
        method = "GET"
        target_str = line
        m_line = _METHOD_URL_LINE_RE.fullmatch(line)
        if m_line:
            method = m_line.group(1).upper()
            target_str = m_line.group(2)
        elif any(ch.isspace() for ch in line):
            continue

        # Treat schemeless `host.tld/path` lines as explicit host URLs so ScopeGuard
        # rejects off-origin hosts instead of interpreting them as relative paths.
        if (
            "://" not in target_str
            and not target_str.startswith(("/", "//"))
            and "/" in target_str
        ):
            first_seg = target_str.split("/", 1)[0]
            if not first_seg.startswith(".") and _SCHEMELESS_HOST_RE.fullmatch(first_seg):
                target_str = f"{base_scheme}://{target_str}"

        out.append(_CandidateRoute(method=method, url=target_str))
    return out


def _parse_seed_text(text: str, guard: ScopeGuard) -> tuple[str, list[_CandidateRoute]]:
    """Auto-detect seed artifact format and parse candidate routes offline."""
    stripped = text.strip()
    if not stripped:
        return "text", []

    if stripped[0] in "{[":
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None

        if isinstance(parsed, dict):
            if isinstance(parsed.get("log"), dict) and isinstance(parsed["log"].get("entries"), list):
                return "har", _parse_har(parsed)
            if _is_zap_dict(parsed):
                return "zap", _parse_zap(parsed, guard)
            if _is_ffuf_dict(parsed):
                return "ffuf", _parse_ffuf(parsed)
            if _is_mitm_scope_dict(parsed):
                return "mitm_scope", _parse_mitm_scope_dict(parsed, guard)
            if _is_nuclei_item(parsed):
                return "nuclei", _parse_nuclei_items([parsed])
            return "generic_json", _parse_generic_json(parsed)

        if isinstance(parsed, list):
            if any(_is_nuclei_item(item) for item in parsed[:20]):
                return "nuclei", _parse_nuclei_items(parsed)
            if any(
                isinstance(item, dict)
                and "method" in item
                and "url" in item
                and ("params" in item or "capture_redacted" in item or "statuses" in item)
                for item in parsed[:20]
            ):
                return "mitm_scope", _parse_generic_json(parsed)
            return "generic_json", _parse_generic_json(parsed)

        # JSONL fallback (e.g., nuclei JSONL or mitm_scope traffic JSONL)
        json_items: list[dict[str, Any]] = []
        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    json_items.append(obj)
        if json_items:
            if any(_is_nuclei_item(item) for item in json_items[:20]):
                return "nuclei", _parse_nuclei_items(json_items)
            if any(
                "method" in item
                and "url" in item
                and ("params" in item or "capture_redacted" in item)
                for item in json_items[:20]
            ):
                return "mitm_scope", _parse_generic_json(json_items)
            return "generic_json", _parse_generic_json(json_items)
        return "text", []

    return "text", _parse_plain_text(stripped, guard)


def _route_priority_score(route: _AcceptedRoute) -> int:
    """Compute a deterministic signal score favoring API, write, parameterized, and deeper routes."""
    score = 0
    low = route.path.lower()

    if _API_PATH_RE.search(low):
        score += 40
    if route.method in _WRITE_METHODS:
        score += 30
    if route.params:
        score += 20 + min(len(route.params), 5)

    segments = [seg for seg in route.path.split("/") if seg]
    score += min(len(segments), 6) * 5
    if any(is_id_segment(seg) for seg in segments):
        score += 10
    if any(kw in low for kw in _HIGH_SIGNAL_KEYWORDS):
        score += 8
    if route.is_form:
        score += 5
    score += _status_priority(route.best_status)
    if low in _LOW_SIGNAL_EXACT_PATHS:
        score -= 15
    return score


def _select_discovery_hints(routes: Sequence[_AcceptedRoute], max_hints: int) -> list[str]:
    """Select up to `max_hints` diverse high-signal GET/entry `/path` discovery hints."""
    cap = max(0, int(max_hints))
    if cap == 0:
        return []

    get_routes = [r for r in routes if r.method in {"GET", "HEAD"}]
    if not get_routes:
        return []

    def _hint_sort_key(route: _AcceptedRoute) -> tuple[int, int, int, str]:
        segments = [seg for seg in route.path.split("/") if seg]
        has_id = 1 if any(is_id_segment(seg) for seg in segments) else 0
        is_get = 0 if route.method == "GET" else 1
        return (is_get, has_id, -_route_priority_score(route), route.path)

    ranked = sorted(get_routes, key=_hint_sort_key)
    selected: list[str] = []
    seen_paths: set[str] = set()
    seen_templates: set[str] = set()

    # Pass 1: maximize endpoint template diversity.
    for route in ranked:
        if len(selected) >= cap:
            return selected
        tmpl = route_template_of(route.path)
        if route.path in seen_paths or tmpl in seen_templates:
            continue
        seen_paths.add(route.path)
        seen_templates.add(tmpl)
        selected.append(route.path)

    # Pass 2: fill any remaining slots with distinct concrete GET paths.
    for route in ranked:
        if len(selected) >= cap:
            break
        if route.path in seen_paths:
            continue
        seen_paths.add(route.path)
        selected.append(route.path)

    return selected


def load_seed_surface_files(
    paths: Sequence[Path | str],
    *,
    base_url: str,
    excluded_paths: Sequence[str] = (),
    max_routes: int = 200,
    max_discovery_hints: int = 12,
) -> dict[str, Any]:
    """Load, scope-filter, secret-strip, deduplicate, and rank offline seed surface files."""
    guard = ScopeGuard(base_origin=base_url, excluded_paths=tuple(excluded_paths or ()))
    effective_max_routes = max(0, int(max_routes))
    effective_max_hints = max(0, int(max_discovery_hints))

    files_loaded = 0
    routes_dropped_scope = 0
    routes_dropped_static = 0
    formats_detected: list[str] = []
    accepted_by_key: dict[tuple[str, str], _AcceptedRoute] = {}
    seen_order = 0

    for raw_file in paths:
        text = _read_seed_file(raw_file)
        files_loaded += 1
        fmt, candidates = _parse_seed_text(text, guard)
        if fmt and fmt not in formats_detected:
            formats_detected.append(fmt)

        for cand in candidates:
            raw_url = str(cand.url or "").strip()
            if not raw_url:
                continue

            # Strict ScopeGuard enforcement BEFORE static filtering or normalization.
            try:
                guard.check_url(raw_url)
            except ValueError:
                routes_dropped_scope += 1
                continue

            resolved = urljoin(guard.base_origin, raw_url)
            parsed = urlsplit(resolved)
            try:
                norm_path = normalize_path(parsed.path or "/")
            except ValueError:
                routes_dropped_scope += 1
                continue

            if is_static_asset_url(norm_path) or is_static_asset_url(resolved):
                routes_dropped_static += 1
                continue

            method = _normalize_method(cand.method, default="GET")

            # Extract ONLY parameter names from query string + parsed body fields; discard all values.
            param_names: list[str] = []
            param_seen: set[str] = set()
            if parsed.query:
                for qk, _ in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=_MAX_QUERY_FIELDS):
                    clean_k = _sanitize_param_name(qk)
                    if clean_k and clean_k not in param_seen and len(param_names) < _MAX_PARAMS_PER_ROUTE:
                        param_seen.add(clean_k)
                        param_names.append(clean_k)
            for extra_p in cand.params:
                clean_p = _sanitize_param_name(extra_p)
                if clean_p and clean_p not in param_seen and len(param_names) < _MAX_PARAMS_PER_ROUTE:
                    param_seen.add(clean_p)
                    param_names.append(clean_p)

            key = (method, norm_path)
            existing = accepted_by_key.get(key)
            if existing is None:
                seen_order += 1
                accepted_by_key[key] = _AcceptedRoute(
                    method=method,
                    path=norm_path,
                    params=sorted(param_names),
                    is_form=bool(cand.is_form),
                    best_status=cand.status,
                    first_seen=seen_order,
                )
            else:
                if param_names:
                    merged = sorted(set(existing.params) | set(param_names))[:_MAX_PARAMS_PER_ROUTE]
                    existing.params = merged
                if cand.is_form:
                    existing.is_form = True
                if cand.status is not None and _status_priority(cand.status) > _status_priority(existing.best_status):
                    existing.best_status = cand.status

    ranked_routes = sorted(
        accepted_by_key.values(),
        key=lambda r: (-_route_priority_score(r), r.first_seen, r.path, r.method),
    )
    kept_routes = ranked_routes[:effective_max_routes]

    links: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    for route in kept_routes:
        entry: dict[str, Any] = {
            "method": route.method,
            "url": route.path,
            "params": list(route.params),
        }
        if route.is_form:
            forms.append(entry)
        else:
            links.append(entry)

    discovery_hints = _select_discovery_hints(kept_routes, effective_max_hints)

    return {
        "url": guard.base_origin,
        "links": links,
        "forms": forms,
        "discovery_hints": discovery_hints,
        "stats": {
            "files_loaded": files_loaded,
            "routes_accepted": len(links) + len(forms),
            "routes_dropped_scope": routes_dropped_scope,
            "routes_dropped_static": routes_dropped_static,
            "formats_detected": formats_detected,
        },
    }


def apply_seed_surface(
    surface_tracker: SurfaceFrontierTracker,
    seed_data: dict[str, Any],
    *,
    actor: str = "seed",
) -> int:
    """Ingest loaded seed surface data into `SurfaceFrontierTracker` and return route count."""
    if not isinstance(seed_data, dict):
        return 0
    links = [item for item in (seed_data.get("links") or []) if isinstance(item, dict) and item.get("url")]
    forms = [item for item in (seed_data.get("forms") or []) if isinstance(item, dict) and item.get("url")]
    count = len(links) + len(forms)
    if count == 0:
        return 0
    surface_tracker.ingest_surface(seed_data, actor=actor)
    return count


def _normalize_hint_path(raw: str) -> str:
    cleaned = str(raw or "").strip()
    if not cleaned:
        return ""
    parsed = urlsplit(cleaned)
    raw_path = parsed.path or "/"
    try:
        norm = normalize_path(raw_path)
    except ValueError:
        return ""
    if is_static_asset_url(norm):
        return ""
    return norm


def _canonicalize_tech_tags(tech_tags: Sequence[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in tech_tags:
        for piece in re.split(r"[,;/\s]+", str(raw or "").strip()):
            token = re.sub(r"[^a-z0-9]+", "", piece.lower())
            if not token:
                continue
            canonical = _TECH_TAG_ALIASES.get(token, token)
            if canonical not in seen:
                seen.add(canonical)
                out.append(canonical)
    return out


def enrich_tech_discovery_hints(
    tech_tags: Sequence[str],
    *,
    existing_hints: Sequence[str] = (),
    max_added: int = 16,
) -> list[str]:
    """Optionally append deduplicated normalized `/path` hints for operator-specified tech tags."""
    result: list[str] = []
    seen: set[str] = set()

    for raw_hint in existing_hints:
        norm = _normalize_hint_path(raw_hint)
        if norm and norm.lower() not in seen:
            seen.add(norm.lower())
            result.append(norm)

    cap = max(0, int(max_added))
    canonical_tags = _canonicalize_tech_tags(tech_tags)
    if cap == 0 or not canonical_tags:
        return result

    candidates: list[str] = []

    # 1. Stack-specific built-in hints first (covers modern stacks like nextjs/fastapi/graphql/express).
    for tag in canonical_tags:
        for path in _BUILTIN_TECH_HINTS.get(tag, ()):
            candidates.append(path)

    # 2. Lazily query tech_routes.build_wordlist without making any network calls.
    try:
        import tech_routes  # type: ignore[import-not-found]
    except ImportError:
        tech_routes = None

    if tech_routes is not None:
        tag_blob = " ".join(str(t) for t in tech_tags if str(t or "").strip())
        base_set = {str(w).strip().lstrip("/").lower() for w in getattr(tech_routes, "BASE_ROUTES", ())}
        tech_map = getattr(tech_routes, "TECH_ROUTES", {})
        if isinstance(tech_map, dict):
            for tag in canonical_tags:
                for route in tech_map.get(tag, ()):
                    candidates.append(str(route))
        try:
            words, _ = tech_routes.build_wordlist(
                server=tag_blob,
                powered_by=tag_blob,
                body=tag_blob,
                budget=int(getattr(tech_routes, "MAX_ROUTES", 100)),
            )
        except Exception:
            words = []
        # Append tech-specific words from build_wordlist before generic BASE_ROUTES entries.
        tech_specific = [w for w in words if str(w).strip().lstrip("/").lower() not in base_set]
        generic_words = [w for w in words if str(w).strip().lstrip("/").lower() in base_set]
        candidates.extend(tech_specific)
        candidates.extend(generic_words)

    added = 0
    for raw_cand in candidates:
        if added >= cap:
            break
        norm = _normalize_hint_path(raw_cand)
        if not norm or norm.lower() in _LOW_VALUE_TECH_HINT_SEGMENTS:
            continue
        if norm.lower() in seen:
            continue
        seen.add(norm.lower())
        result.append(norm)
        added += 1

    return result
