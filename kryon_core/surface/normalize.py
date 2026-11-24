"""URL/param normalization, fingerprinting, and EV ranking for attack surface."""

from __future__ import annotations

import hashlib
import copy
import json
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlparse, urlsplit, urlunparse

SCHEMA_VERSION = "attack-surface/1.1"
_BARE_HOSTPORT_URL_RE = re.compile(
    r"^(?:(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]|localhost|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}):\d{1,5}(?:/|[?#]|$)",
    re.I,
)
_EMBEDDED_HOSTPORT_SEG_RE = re.compile(
    r"^(?:(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]|localhost|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}):\d{1,5}$",
    re.I,
)
_PATH_KV_URL_SCHEME_SEG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}=https?:$", re.I)
_THIRD_PARTY_CLOUD_AUTH_SDK_PATH_RE = re.compile(
    r"^(?:"
    r"/v[12]/accounts(?:/mfa(?:enrollment|signin))?:"
    r"(?:signup|lookup|send(?:oobcode|verificationcode)|signinwith[a-z]+|"
    r"createauthuri|resetpassword|delete(?:account)?|update|revoketoken|"
    r"verify[a-z]+|(?:get|set)accountinfo|getoobconfirmationcode|"
    r"queryuserinfo|start|finalize|withdraw|\{[a-z_][a-z0-9_]*\}|)"
    r"|/v2/(?:recaptchaconfig|passwordpolicy|projectconfig)"
    r"|/v1/(?:recaptchaparams|getrecaptchaparam)"
    r"|/v1/projects/[^/]+/(?:accounts:[a-z0-9_{}-]*|databases/.*|installations(?:/.*)?|tenants/.*|namespaces/.*|messages:send|(?:android|ios|web)apps/.*)"
    r")$",
    re.I,
)
_GOOGLE_IDENTITY_SDK_CONTEXT_RE = re.compile(
    r"(?:identitytoolkit\.googleapis\.com|securetoken\.googleapis\.com|"
    r"/v[12]/accounts:(?:signInWithPassword|signUp|lookup|sendOobCode|revokeToken)|"
    r"/v2/(?:recaptchaConfig|passwordPolicy))",
    re.I,
)
_GOOGLE_SECURE_TOKEN_PATH_RE = re.compile(r"^/v1/token$", re.I)

_WIN_DRIVE_RAW_RE = re.compile(r"^[A-Za-z]:[/\\]")
_WIN_DRIVE_PATH_RE = re.compile(r"^/[A-Za-z]:(?:[/\\]|$)")
_UNIX_VAR_SUBDIRS = frozenset({
    "www", "log", "tmp", "run", "lib", "cache", "spool", "opt", "mail",
    "backups", "lock", "local", "snap", "empty", "db", "folders", "containers",
})
_UNIX_USR_SUBDIRS = frozenset({
    "local", "lib", "lib64", "lib32", "libexec", "share", "bin", "sbin",
    "include", "src", "games", "etc", "var", "opt",
})
_UNIX_PROC_SUBDIRS = frozenset({
    "self", "thread-self", "sys", "net", "fs", "bus", "driver", "irq", "tty",
    "acpi", "scsi", "cpuinfo", "meminfo", "version", "cmdline", "mounts",
    "stat", "uptime", "loadavg", "filesystems", "modules", "cgroups",
    "environ", "maps", "status", "fd", "cwd", "exe", "root", "limits", "sched",
})
_UNIX_SYS_SUBDIRS = frozenset({
    "class", "devices", "fs", "kernel", "module", "bus", "block",
    "firmware", "power", "hypervisor", "dev",
})
_UNIX_PRIVATE_SUBDIRS = frozenset({"var", "tmp", "etc"})
_UNIX_HOME_SUBDIRS = frozenset({
    "desktop", "documents", "downloads", "library", "applications", "pictures",
    "movies", "music", "public", "sites", "appdata", "projects", "project",
    "workspace", "workspaces", "repos", "repo", "src", "code", "dev", "app",
    "apps", "www", "web", "html", "venv", "conda", "miniconda3", "anaconda3",
    "bin", "lib", "var", "tmp", "cache", "config", "local", "share",
    "node_modules", "site-packages",
})
_OS_SERVER_CODE_EXTS = (
    ".py", ".pyc", ".pyo", ".rb", ".go", ".java", ".class", ".jar",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".so", ".dylib", ".dll",
    ".exe", ".ini", ".conf", ".cfg", ".cnf", ".log", ".sh", ".bash",
    ".pid", ".sock",
)
_SENSITIVE_NAME = re.compile(
    r"(^|[._-])(csrf|xsrf|password|passwd|secret|session|sessionid|cookie|"
    r"authorization|api[_-]?key|token|access_token|refresh_token)([._-]|$)", re.I)


_DISCOVERY_SECRET_QUERY = re.compile(r"auth|token|secret|session|password|csrf|api[-_]?key", re.I)
_DISCOVERY_MUTATING_WORD = re.compile(
    r"(?:^|[/_.-])(login|log-in|logout|log-out|signin|sign-in|signout|sign-out|"
    r"signup|sign-up|register|authorize|delete|remove|destroy|reset|"
    r"update|edit|save|submit|create|upload|unsubscribe|purchase|checkout|refresh|"
    r"revoke|disable|enable|activate|deactivate|approve|reject|cancel|send)(?:$|[/_.-])", re.I)


def _discovery_decoded(value: str) -> str | None:
    for _ in range(4):
        decoded = unquote(value)
        if decoded == value:
            return decoded
        value = decoded
    return None if re.search(r"%[0-9a-f]{2}", value, re.I) else value


def discovery_link_skip_reason(url: str) -> str:
    """Decide suitability for automatic GET selection, independently of scope.

    Observed unsafe links may remain inventory records, but must not consume
    transport calls. This filter never grants permission to fetch a URL.
    """
    if (not isinstance(url, str) or not url or len(url) > 2048
            or "\\" in url or any(ord(char) < 32 or ord(char) == 127 for char in url)):
        return "invalid_discovery_url"
    try:
        parsed = urlparse(url)
        if (parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or (parsed.port is not None and parsed.port <= 0)):
            return "invalid_discovery_url"
        path = _discovery_decoded(parsed.path)
        pairs = [(_discovery_decoded(name), _discovery_decoded(value))
                 for name, value in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=64)]
        if path is None or any(name is None or value is None for name, value in pairs):
            return "ambiguous_discovery_encoding"
        decoded_pairs: list[tuple[str, str]] = [
            (name, value) for name, value in pairs if name is not None and value is not None
        ]
        if any("\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value)
               for value in [path, *(item for pair in decoded_pairs for item in pair)]):
            return "invalid_discovery_url"
        if is_os_filesystem_path(url) or is_os_filesystem_path(path):
            return "os_filesystem_path"
        if is_js_property_dot_path(url) or is_js_property_dot_path(path):
            return "js_property_dot_path"
        if _DISCOVERY_MUTATING_WORD.search(path) or any(
                _DISCOVERY_MUTATING_WORD.search(name) or _DISCOVERY_MUTATING_WORD.search(value)
                for name, value in decoded_pairs):
            return "mutating_discovery_link"
        if any(_DISCOVERY_SECRET_QUERY.search(name) for name, _ in decoded_pairs):
            return "sensitive_discovery_query"
        return ""
    except (TypeError, ValueError):
        return "invalid_discovery_url"


def safe_sample(name: str, value):
    """Keep usable types while withholding credentials and incomplete values."""
    if _SENSITIVE_NAME.search(str(name)):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(key): safe_sample(str(key), item) for key, item in value.items()}
    if isinstance(value, list):
        return [safe_sample("", item) for item in value]
    if isinstance(value, str) and len(value) > 120:
        return "<unavailable>"
    return copy.deepcopy(value)


def json_parameters(data: dict, limit: int = 32) -> list[dict]:
    """Flatten nested object leaves while preserving JSON types and paths."""
    params: list[dict] = []
    truncated = False

    def visit(value, path: list[str]) -> None:
        nonlocal truncated
        if len(params) >= limit or len(path) > 8:
            truncated = True
            return
        if path and _SENSITIVE_NAME.search(path[-1]):
            params.append({"name": ".".join(path), "in": "json", "path": path, "sample": "<redacted>"})
        elif isinstance(value, dict) and value:
            for key, child in value.items():
                visit(child, [*path, str(key)])
        elif path:
            params.append({"name": ".".join(path), "in": "json", "path": path,
                           "sample": safe_sample(path[-1], value)})

    visit(data, [])
    if truncated:
        params.append({"name": "truncated_request", "in": "json", "sample": "<unavailable>"})
    return params

HIGH_VALUE_PARAMS = {
    "id", "uid", "user_id", "userid", "account", "account_id", "order", "order_id",
    "invoice", "doc", "doc_id", "file", "filename", "path", "page", "url", "uri",
    "redirect", "next", "return", "returnto", "callback", "dest", "goto", "continue",
    "price", "quantity", "qty", "amount", "coupon", "token", "template", "include",
    "q", "search", "query", "filter", "sort", "cmd", "host", "ip", "webhook",
}

PATH_BONUSES = [
    (re.compile(r"/api/|/graphql|/v\d+/|\.json\b", re.I), 0.18),
    (re.compile(r"/admin|/manage|/internal|/debug|/console", re.I), 0.2),
    (re.compile(r"/upload|/import|/attachment", re.I), 0.16),
    (re.compile(r"/checkout|/cart|/payment|/order", re.I), 0.18),
    (re.compile(r"/login|/oauth|/sso|/auth|/signin", re.I), 0.14),
]

CLASS_HINTS = [
    (re.compile(r"(login|signin|auth|session|password|oauth|sso)", re.I),
     ["authentication_bypass", "sql_injection", "open_redirect"]),
    (re.compile(r"(admin|manage|internal|console|debug)", re.I),
     ["bfla", "broken_access_control", "idor"]),
    (re.compile(r"(/api/|/v\d+/|graphql|\.json)", re.I),
     ["bola", "bfla", "idor", "mass_assignment"]),
    (re.compile(r"[?&](id|uid|user_id|account|order|invoice|doc|file)=|/\d+(/|$)", re.I),
     ["idor", "bola", "sql_injection"]),
    (re.compile(r"(search|query|[?&]q=|filter|sort)", re.I),
     ["sql_injection", "xss_reflected", "ssti"]),
    (re.compile(r"(upload|import|file|attachment)", re.I),
     ["file_upload", "path_traversal", "xxe"]),
    (re.compile(r"(redirect|return|next|url=|callback|continue|dest)", re.I),
     ["open_redirect", "ssrf"]),
    (re.compile(r"(cart|checkout|order|payment|coupon|price)", re.I),
     ["price_manipulation", "business_logic", "idor"]),
    (re.compile(r"(proxy|webhook|preview|render|pdf)", re.I),
     ["ssrf", "xxe"]),
]


def host_of(url: str) -> str:
    parsed = urlparse(url if "://" in (url or "") else f"http://{url or ''}")
    return (parsed.hostname or "").lower()


def same_host(url: str, base: str, allow_subdomains: bool = False) -> bool:
    left = host_of(url)
    right = host_of(base)
    if not left or not right:
        return False
    if left == right:
        return True
    if allow_subdomains and (left.endswith("." + right) or right.endswith("." + left)):
        return True
    return False


def normalize_bare_hostport_url(raw: str, base: str = "") -> str:
    """Resolve schemeless ``host:port/path`` strings using ``base`` scheme and reject malformed ``http:/`` URLs."""
    text = (raw or "").strip()
    if not text:
        return ""
    low = text.lower()
    if (low.startswith("http:/") and not low.startswith("http://")) or (
        low.startswith("https:/") and not low.startswith("https://")
    ):
        return ""
    if base and _BARE_HOSTPORT_URL_RE.match(text):
        try:
            base_scheme = urlparse(base).scheme.lower()
        except ValueError:
            base_scheme = ""
        if base_scheme in ("http", "https"):
            return f"{base_scheme}://{text}"
    return text


def is_port_in_path_artifact(
    url_or_path: str,
    *,
    origin_url: str = "",
    target_port: int | str | None = None,
) -> bool:
    """Return True if a URL/path looks like a malformed ``host:port/path`` split artifact.

    Rejects:
    - Embedded ``host:port`` segments inside a path (outside ``key=http(s)://...`` path params).
    - Paths starting with ``/{target_port}/...`` or unrooted ``{target_port}/...`` (2+ segments).
    - Paths repeating ``target_port`` across multiple segments (recursive port-in-path loops).
    - Paths containing ``/{target_port}/`` followed by a duplicated prefix segment.

    Preserves legitimate numeric resource ID paths such as ``/api/items/50759`` and
    ``/orders/8080/details``.
    """
    raw = str(url_or_path or "").strip()
    if not raw:
        return False
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False

    path = (parsed.path or "").strip()
    if not path or path == "/":
        return False

    raw_segs = [seg for seg in path.split("/") if seg]
    if not raw_segs:
        return False

    # Inspect path segments up to any valid `key=http(s):` path-embedded URL tail.
    segs: list[str] = []
    for seg in raw_segs:
        if _PATH_KV_URL_SCHEME_SEG_RE.fullmatch(seg):
            break
        if _EMBEDDED_HOSTPORT_SEG_RE.fullmatch(seg):
            return True
        segs.append(seg)

    clean_segs = [seg for seg in segs if seg not in {".", ".."}]
    if not clean_segs:
        return False

    port_str = ""
    if target_port is not None and str(target_port).strip():
        candidate_port = str(target_port).strip()
        if candidate_port.isdigit() and int(candidate_port) > 0:
            port_str = str(int(candidate_port))
    if not port_str and origin_url:
        try:
            o_port = urlsplit(str(origin_url).strip()).port
            if o_port is not None and o_port > 0:
                port_str = str(o_port)
        except ValueError:
            port_str = ""
    if not port_str and parsed.netloc:
        try:
            u_port = parsed.port
            if u_port is not None and u_port > 0:
                port_str = str(u_port)
        except ValueError:
            port_str = ""

    if not port_str:
        return False

    # 1. Path starts with `{target_port}/...` (rooted or relative) synthesized from `host:port/path`.
    if len(clean_segs) >= 2 and clean_segs[0] == port_str:
        return True

    port_indices = [idx for idx, seg in enumerate(clean_segs) if seg == port_str]
    if not port_indices:
        return False

    # 2. Target port appears in multiple path segments (recursive port-prefix loop).
    if len(port_indices) >= 2:
        return True

    # 3. `/{prefix}/{target_port}/{duplicated_prefix}/...` (e.g. `/index/index/50759/index/index/search.html`).
    idx = port_indices[0]
    if idx >= 1 and idx + 1 < len(clean_segs):
        before = [s.lower() for s in clean_segs[:idx]]
        after = [s.lower() for s in clean_segs[idx + 1 :]]
        if after[0] == before[0] and (len(before) >= 2 or len(after) >= 2):
            return True
        if len(after) >= 2 and after[0] in set(before):
            return True

    return False


def is_os_filesystem_path(url_or_path: str) -> bool:
    """Return True when the URL path itself is a local OS filesystem path (Unix or Windows).

    Inspects only the path component (never query parameters like ``/api/download?file=/etc/passwd``)
    and preserves legitimate web routes such as ``/users``, ``/users/42``, ``/home``, ``/home/feed``,
    and path-embedded parameters like ``/file=../../etc/passwd``.
    """
    raw = str(url_or_path or "").strip()
    if not raw:
        return False
    raw_no_qf = raw.split("#", 1)[0].split("?", 1)[0].strip()
    if _WIN_DRIVE_RAW_RE.match(raw_no_qf):
        return True
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    path = (parsed.path or "").strip()
    if not path:
        return False
    if _WIN_DRIVE_PATH_RE.match(path) or _WIN_DRIVE_PATH_RE.match(unquote(path)):
        return True
    if path == "/":
        return False
    check_path = path
    while check_path.startswith("./"):
        check_path = check_path[2:]
    segs = [seg for seg in check_path.split("/") if seg]
    if len(segs) < 2:
        return False
    if "=" in segs[0]:
        return False
    low_segs = [seg.lower() for seg in segs]
    first = low_segs[0]
    second = low_segs[1]
    last = low_segs[-1]

    if first == "var":
        return second in _UNIX_VAR_SUBDIRS or last.endswith(_OS_SERVER_CODE_EXTS)
    if first == "usr":
        return second in _UNIX_USR_SUBDIRS or last.endswith(_OS_SERVER_CODE_EXTS)
    if first in {"etc", "opt", "root", "tmp", "srv", "mnt"}:
        return True
    if first == "private":
        return second in _UNIX_PRIVATE_SUBDIRS
    if first == "proc":
        return second in _UNIX_PROC_SUBDIRS or second.isdigit()
    if first == "sys":
        return second in _UNIX_SYS_SUBDIRS
    if segs[0] == "System" and segs[1] == "Library":
        return True
    if segs[0] == "Users":
        return (
            len(segs) >= 3
            and not segs[1].isdigit()
            and not segs[1].startswith("{")
        )
    if first == "home":
        return (
            len(segs) >= 3
            and not second.isdigit()
            and not segs[1].startswith("{")
            and (
                low_segs[2] in _UNIX_HOME_SUBDIRS
                or low_segs[2].startswith(".")
                or last.endswith(_OS_SERVER_CODE_EXTS)
            )
        )
    return False


_KNOWN_WEB_FILE_EXTENSIONS = frozenset({
    "html", "htm", "xhtml", "shtml", "php", "php5", "php7", "phtml",
    "jsp", "jspx", "asp", "aspx", "ashx", "asmx", "axd", "svc", "cfm", "cfc",
    "do", "action", "cgi", "pl", "py", "rb", "sh",
    "json", "xml", "yaml", "yml", "toml", "txt", "md", "csv", "rss", "atom",
    "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "svelte",
    "css", "scss", "sass", "less", "styl", "map", "wasm", "webmanifest",
    "ico", "svg", "png", "jpg", "jpeg", "gif", "webp", "bmp", "avif",
    "woff", "woff2", "ttf", "otf", "eot",
    "mp4", "mp3", "webm", "wav",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "jar", "war",
    "sql", "sqlite", "db", "bak", "old", "orig",
    "env", "ini", "conf", "cfg", "config", "properties", "log",
    "pem", "crt", "key",
    "graphql", "gql", "wsdl", "wadl",
})
_JS_SCRIPT_ASSET_DIRS = frozenset({
    "js", "javascript", "scripts", "script", "assets", "static",
    "dist", "build", "chunks", "chunk", "bundles", "bundle",
})
_JS_PROP_API_PREFIX_RE = re.compile(r"(?:^|/)(?:api(?:/v\d+)?|graphql|rest|rpc)(?:/|$)", re.I)
_JS_IDENT_PART_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


def is_known_web_extension(ext: str) -> bool:
    """Return True when ``ext`` (with or without leading dot) is a known web/document/code/archive extension."""
    cleaned = str(ext or "").strip().lstrip(".").lower()
    return bool(cleaned) and cleaned in _KNOWN_WEB_FILE_EXTENSIONS


def is_js_property_dot_path(url_or_path: str) -> bool:
    """Return True when a URL path under a script/asset dir looks like a JS property-access string.

    Filters relative JS property strings resolved under script/asset directories such as
    ``/static/js/lineStyle.color``, ``/js/itemStyle.borderColor``, and ``/assets/tooltip.formatter``
    where the trailing segment is a dot-joined JS identifier chain whose final suffix is not a
    known web/document/code/archive/media extension.

    Preserves legitimate dotted endpoints such as ``/index/Article/info.html``,
    ``/api/v1/users.json``, ``/admin/config.ini``, ``/api/v2.1/orders``, and
    ``/.well-known/openid-configuration``.
    """
    raw = str(url_or_path or "").strip()
    if not raw:
        return False
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    path = (parsed.path or "").strip()
    if not path or path == "/" or "=" in path:
        return False
    check_path = path
    while check_path.startswith(("./", "../")):
        check_path = check_path[2:] if check_path.startswith("./") else check_path[3:]
    segs = [seg for seg in check_path.split("/") if seg]
    if len(segs) < 2:
        return False
    if any(seg.startswith(".") for seg in segs):
        return False
    if _JS_PROP_API_PREFIX_RE.search("/" + "/".join(segs).lower()):
        return False
    dir_segs = [seg.lower() for seg in segs[:-1]]
    if not any(seg in _JS_SCRIPT_ASSET_DIRS for seg in dir_segs):
        return False
    last = segs[-1]
    if "." not in last or last.startswith(".") or last.endswith("."):
        return False
    parts = last.split(".")
    if len(parts) < 2 or not all(_JS_IDENT_PART_RE.fullmatch(part) for part in parts):
        return False
    return parts[-1].lower() not in _KNOWN_WEB_FILE_EXTENSIONS


def has_google_identity_sdk_context(text: str) -> bool:
    """Return True when static JS text contains Google Identity Toolkit / Firebase Auth SDK markers."""
    if not text:
        return False
    return bool(_GOOGLE_IDENTITY_SDK_CONTEXT_RE.search(text))


def is_third_party_sdk_static_route(url_or_path: str, *, sdk_context: bool = False) -> bool:
    """Return True for well-known third-party cloud auth SDK path constants from static JS bundles.

    Intended strictly for static JS string/call/route extraction (e.g. embedded Firebase /
    Google Identity Toolkit `/v1/accounts:<action>`, `/v2/accounts:<action>`,
    `/v2/recaptchaConfig`, `/v2/passwordPolicy` constants), never for live observed network traffic.
    When ``sdk_context=True`` (Google Identity SDK markers present in the same JS source),
    bare ``/v1/token`` (Google Secure Token Service) is also filtered while preserving
    ``/api/v1/token`` and non-SDK OAuth ``/v1/token`` routes.
    """
    raw = str(url_or_path or "").strip()
    if not raw:
        return False
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    path = (parsed.path or "").strip()
    if not path and parsed.fragment.startswith("/"):
        path = parsed.fragment.strip().split("?", 1)[0]
    if not path:
        return False
    trimmed = path.rstrip("/")
    if _THIRD_PARTY_CLOUD_AUTH_SDK_PATH_RE.fullmatch(trimmed):
        return True
    if sdk_context and _GOOGLE_SECURE_TOKEN_PATH_RE.fullmatch(trimmed):
        return True
    return False


def normalize_url(url: str, base: str = "") -> str:
    raw = (url or "").strip()
    if not raw or raw.startswith(("#", "javascript:", "mailto:", "data:")):
        return ""
    raw = normalize_bare_hostport_url(raw, base=base)
    if not raw:
        return ""
    if base:
        raw = urljoin(base, raw)
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        return ""
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
    path = parsed.path or "/"
    netloc = parsed.netloc.lower()
    if parsed.scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    if parsed.scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    return urlunparse((parsed.scheme, netloc, path, "", query, ""))


def params_from_url(url: str) -> list[dict]:
    parsed = urlparse(url)
    out = []
    seen = set()
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if not name or name in seen:
            continue
        seen.add(name)
        out.append({"name": name, "in": "query", "sample": safe_sample(name, value)})
    return out


def _redact_sensitive_url(url: str) -> str:
    parsed = urlparse(url)
    pairs = [(name, safe_sample(name, value))
             for name, value in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))


def _param_names(params) -> list[str]:
    names = []
    for item in params or []:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
        else:
            name = str(item).strip()
        if name and name not in names:
            names.append(name)
    return names


def canonical_target(value: str) -> str:
    """Hedef anahtari kanoniklestir: host[:port], kucuk harf.

    Kaynaklar hedefi farkli yazar (discover: scheme+host, crawl: hostname,
    mitm: host). Kanonik form tek olmali ki ayni varlik tek satirda
    birlessin ve tested_classes bolunmesin. CIDR/IP araliklari oldugu gibi
    korunur (bolunmez).
    """
    import re as _re
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        hostport = urlparse(text).netloc or urlparse(text).hostname or ""
    elif _re.fullmatch(r"[\da-fA-F.:]+(/\d{1,3})?", text):
        return text.lower()
    else:
        hostport = text.split("/")[0]
    hostport = hostport.split("@")[-1].strip().lower()
    if hostport.endswith("."):
        hostport = hostport[:-1]
    return hostport


def fingerprint(target: str, method: str, url: str, params=None, *, operation_id: str = "") -> str:
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    names = ",".join(sorted(_param_names(params) or [k for k, _ in parse_qsl(parsed.query)]))
    raw = f"{(target or '').lower()}|{(method or 'GET').upper()}|{(parsed.hostname or '').lower()}|{path}|{names}"
    if operation_id:
        carriers = sorted({(str(p.get("in") or "query"), str(p.get("name") or ""),
                            () if p.get("path") == [p.get("name")] else tuple(p.get("path") or ()))
                           for p in params or [] if isinstance(p, dict)})
        raw = json.dumps(["surface/2", operation_id, carriers], separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]


def score_record(record: dict) -> float:
    ev = 0.28
    names = {name.lower() for name in _param_names(record.get("params"))}
    if names & {item.lower() for item in HIGH_VALUE_PARAMS}:
        ev += 0.22
    path = record.get("path") or urlparse(record.get("url") or "").path
    blob = f"{path} {record.get('url') or ''}"
    for pattern, bonus in PATH_BONUSES:
        if pattern.search(blob):
            ev += bonus
            break
    status = record.get("status")
    if status in (200, 201, 204, 301, 302, 401, 403):
        ev += 0.08
    if record.get("auth_required"):
        ev += 0.08
    sources = {str(item).lower() for item in (record.get("sources") or [])}
    if sources & {"openapi", "js", "sitemap"}:
        ev += 0.05
    return round(min(0.99, ev), 4)


def _looks_serialized_sample(sample: str) -> bool:
    text = str(sample or "").strip()
    return text.startswith(("rO0AB", "aced", "O:", "a:", "gASV", "AAEAAAD"))


def suggested_classes(record: dict) -> list[str]:
    blob = " ".join([
        record.get("url") or "",
        record.get("path") or "",
        " ".join(_param_names(record.get("params"))),
    ])
    found = []
    for pattern, classes in CLASS_HINTS:
        if pattern.search(blob):
            for item in classes:
                if item not in found:
                    found.append(item)
    # User-controlled text can reach a renderer without a route named search.
    # These are applicability hints; only an arithmetic validator can confirm.
    text_names = {"name", "message", "text", "template", "greeting", "content"}
    if (any(isinstance(p, dict) and str(p.get("name") or "").lower() in text_names
            and p.get("type") not in {"integer", "number", "boolean", "object", "array"}
            for p in record.get("params") or [])
            or re.search(r"(template|render|greeting)", blob, re.I)):
        if "ssti" not in found:
            found.append("ssti")
    if (record.get("auth_required") or re.search(r"/(account|profile|statement)(/|[?\s]|$)", blob, re.I)):
        if "authentication_bypass" not in found:
            found.insert(0, "authentication_bypass")
    # Tasiyici ornegi serilestirilmis akisa benziyorsa sinifi one al (Faz 1)
    for param in record.get("params") or []:
        if isinstance(param, dict) and _looks_serialized_sample(param.get("sample") or ""):
            if "deserialization" not in found:
                found.insert(0, "deserialization")
            break
    # Cookie taşıyıcıları sunucu tarafı arama anahtarıdır (TrackingId örüntüsü):
    # adı ipucu vermese de SQLi adayı say, yoksa kuyruğa hiç giremez.
    for param in record.get("params") or []:
        if isinstance(param, dict) and str(param.get("in") or "").lower() == "cookie":
            if "sql_injection" not in found:
                found.insert(0, "sql_injection")
            break
    return found[:8]


def normalize_record(record: dict, target: str = "", base: str = "") -> dict | None:
    if not isinstance(record, dict):
        return None
    url = normalize_url(str(record.get("url") or record.get("uri") or ""), base=base)
    if not url:
        return None
    method = str(record.get("method") or "GET").upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        method = "GET"
    parsed = urlparse(url)
    params = record.get("params") or params_from_url(url)
    cleaned_params = []
    seen = set()
    for item in params:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        location = str(item.get("in") or "query").lower()
        if location not in {"query", "body", "json", "header", "cookie", "path"}:
            location = "query"
        path = item.get("path")
        if not isinstance(path, list) or not path or not all(isinstance(p, str) and p for p in path):
            path = None
        marker = (location, name, tuple(path or ()))
        if not name or marker in seen:
            continue
        seen.add(marker)
        sample = safe_sample(name, item.get("sample"))
        if location != "json" and sample is None:
            sample = ""
        entry = {
            "name": name,
            "in": location,
            "sample": sample,
        }
        if item.get("sample_available") is False or (item.get("required") is True and "sample" not in item):
            entry["sample_available"] = False
        if path:
            entry["path"] = path
        if isinstance(item.get("type"), str) and item["type"] in {"string", "integer", "number", "boolean", "object", "array", "null"}:
            entry["type"] = item["type"]
        if isinstance(item.get("required"), bool):
            entry["required"] = item["required"]
        if isinstance(item.get("sample_source"), str) and item["sample_source"] in {"openapi_example", "openapi_default", "openapi_enum",
                                         "schema_generated", "schema_unresolved"}:
            entry["sample_source"] = item["sample_source"]
        if item.get("schema_unresolved") is True:
            entry["schema_unresolved"] = True
        for key in ("nullable", "repeated", "body_root", "file_part"):
            if isinstance(item.get(key), bool):
                entry[key] = item[key]
        for key in ("enum", "format", "schema_context", "schema_version", "encoding"):
            if key in item:
                entry[key] = safe_sample(name if key == "enum" else "", item[key])
        cleaned_params.append(entry)
    sources = record.get("sources") or record.get("source") or []
    if isinstance(sources, str):
        sources = [sources] if sources else []
    sources = [str(item) for item in sources if item][:12]
    tech = record.get("tech") or record.get("technologies") or []
    if isinstance(tech, str):
        tech = [part.strip() for part in tech.replace(",", " ").split() if part.strip()]
    tech = [str(item) for item in tech if item][:16]
    status = record.get("status")
    try:
        status = int(status) if status not in (None, "") else None
    except (TypeError, ValueError):
        status = None
    auth = record.get("auth_required")
    if auth in (True, 1, "1", "true", "True"):
        auth = 1
    elif auth in (False, 0, "0", "false", "False"):
        auth = 0
    else:
        auth = None
    body_len = record.get("body_len")
    try:
        body_len = int(body_len) if body_len not in (None, "") else None
    except (TypeError, ValueError):
        body_len = None
    normalized: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "target": canonical_target(target or record.get("target") or parsed.hostname or ""),
        "url": _redact_sensitive_url(url),
        "method": method,
        "host": (parsed.hostname or "").lower(),
        "path": parsed.path or "/",
        "params": cleaned_params,
        "status": status,
        "content_type": str(record.get("content_type") or "")[:160],
        "title": str(record.get("title") or "")[:180],
        "body_hash": str(record.get("body_hash") or "")[:64],
        "body_len": body_len,
        "auth_required": auth,
        "tech": tech,
        "sources": sources or ["manual"],
        "tested_classes": list(record.get("tested_classes") or []),
    }
    if not normalized["target"]:
        return None
    from .operation import operation_descriptor, operation_id
    normalized["operation"] = operation_descriptor({**record, "url": url})
    normalized["operation_id"] = operation_id(url, method, normalized["operation"])
    if normalized["operation"].get("protocol") == "graphql":
        def redact_envelope(value):
            if isinstance(value, list):
                return [redact_envelope(child) for child in value]
            if isinstance(value, dict):
                return {key: "<unavailable>" if key == "query" and '"' in str(child)
                        else redact_envelope(safe_sample(key, child)) for key, child in value.items()}
            return value
        for param in cleaned_params:
            if param["name"] == "query" and '"' in str(param["sample"]):
                param["sample"] = "<unavailable>"
            elif param["name"] in {"variables", "operations", "extensions"} and isinstance(param["sample"], str):
                try:
                    variables = json.loads(param["sample"])
                    if redact_envelope(variables) != variables:
                        param["sample"] = "<unavailable>"
                except (TypeError, ValueError):
                    param["sample"] = "<unavailable>"
            elif param.get("body_root"):
                param["sample"] = redact_envelope(param["sample"])
        # GET envelopes can embed secrets in the URL as well as in samples.
        # Preserve the descriptor computed from the original, before redaction.
        safe_envelope = {param["name"]: param["sample"] for param in cleaned_params
                         if param["in"] == "query" and param["name"] in {"query", "variables"}}
        parsed_safe = urlparse(normalized["url"])
        normalized["url"] = urlunparse(parsed_safe._replace(query=urlencode([
            (name, safe_envelope.get(name, value)) for name, value in
            parse_qsl(parsed_safe.query, keep_blank_values=True)], doseq=True)))
    for key in ("identity", "run_id", "resource_owner"):
        value = record.get(key)
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", value):
            normalized[key] = value
    binding = record.get("capture_binding")
    if isinstance(binding, dict):
        keys = ("session_target", "identity", "session_version", "scope_revision", "policy_hash", "request_mac")
        if (set(binding) == set(keys) and all(isinstance(binding[k], str) for k in keys)
                and all(re.fullmatch(r"[a-f0-9]{64}", binding[k]) for k in ("session_version", "request_mac"))
                and all(re.fullmatch(r"sha256:[a-f0-9]{64}", binding[k]) for k in ("scope_revision", "policy_hash"))
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", binding["identity"])
                and len(binding["session_target"]) <= 2048 and not any(c in binding["session_target"] for c in "?#\r\n\x00")):
            normalized["capture_binding"] = dict(binding)
    normalized["request_state"] = ("observed_request" if any(s in {"xhr", "proxy"} for s in sources)
                                   else "schema_only" if any(s in {"openapi", "js-call", "graphql"} for s in sources)
                                   else "unknown")
    normalized["fingerprint"] = fingerprint(
        normalized["target"], normalized["method"], normalized["url"], normalized["params"],
        operation_id=normalized["operation_id"]
    )
    normalized["ev_score"] = score_record(normalized)
    normalized["suggested_classes"] = suggested_classes(normalized)
    return normalized


def dumps_params(params) -> str:
    return json.dumps(params or [], ensure_ascii=False)


def dumps_list(items) -> str:
    return json.dumps(items or [], ensure_ascii=False)
