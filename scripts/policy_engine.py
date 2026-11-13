#!/usr/bin/env python3
"""Central policy engine for OpenCode and CLI security enforcement."""

from __future__ import annotations

import ipaddress
import json
import os
import posixpath
import re
import shlex
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, TypedDict
from urllib.parse import parse_qsl, urlencode, unquote, urlparse, urlsplit, urlunsplit

try:
    from .runtime_paths import runtime_root
except ImportError:
    from runtime_paths import runtime_root


def _canonical_scope_url(raw: str) -> str:
    """Canonicalize an HTTP URL before applying path-prefix scope rules."""
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
        raise ValueError("invalid wire URL")
    # Validate a malformed port even if a hostname is present.
    _ = parsed.port
    path = parsed.path or "/"
    for _ in range(3):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if re.search(r"%[0-9a-fA-F]{2}", path) or "\x00" in path:
        raise ValueError("ambiguous encoded path")
    path = posixpath.normpath("/" + path.replace("\\", "/").lstrip("/"))
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def _caller_fingerprint(args) -> str:
    """Tel isteğindeki kimlik başlıklarından koşu parmak izi (WS7)."""
    headers: dict = {}

    def scan(node):
        if isinstance(node, dict):
            for key, value in node.items():
                lowered = str(key).lower()
                if lowered == "headers" and isinstance(value, dict):
                    headers.update(value)
                elif lowered in {"authorization", "cookie"} and isinstance(value, str):
                    headers.setdefault(key, value)
                elif isinstance(value, (dict, list)):
                    scan(value)
        elif isinstance(node, list):
            for item in node:
                scan(item)

    scan(args if isinstance(args, dict) else {})
    if not headers:
        return ""
    try:
        import write_set as _write_set
        return _write_set.fingerprint_credentials(headers)
    except Exception:
        return ""


def _load_stuck_evaluator():
    """stuck_detector baglantisi (importlib ile yuklense bile calisir)."""
    try:
        from stuck_detector import evaluate_probe

        return evaluate_probe
    except ImportError:
        pass
    try:
        import importlib.util

        path = Path(__file__).with_name("stuck_detector.py")
        spec = importlib.util.spec_from_file_location("cco_stuck_detector", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.evaluate_probe
    except Exception:
        return None


_EVALUATE_PROBE = _load_stuck_evaluator()


def _load_js_queue_evaluator():
    try:
        from js_route_queue import evaluate as evaluate_js_queue

        return evaluate_js_queue
    except ImportError:
        pass
    try:
        import importlib.util

        path = Path(__file__).with_name("js_route_queue.py")
        spec = importlib.util.spec_from_file_location("cco_js_route_queue", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.evaluate
    except Exception:
        return None


_EVALUATE_JS_QUEUE = _load_js_queue_evaluator()


def _load_egress_helpers():
    """egress_policy baglantisi (importlib ile yuklense bile calisir)."""
    try:
        import egress_policy

        return egress_policy
    except ImportError:
        pass
    try:
        import importlib.util

        path = Path(__file__).with_name("egress_policy.py")
        spec = importlib.util.spec_from_file_location("cco_egress_policy", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


_EGRESS = _load_egress_helpers()


OSINT_ALLOWLIST = {
    "crt.sh",
    "shodan.io",
    "censys.io",
    "github.com",
    "archive.org",
    "wayback.archive.org",
    "hackerone.com",
    "bugcrowd.com",
}
PUBLIC_LABS = {
    "scanme.nmap.org",
    "testphp.vulnweb.com",
    "dvwa.co.uk",
    "hackthebox.com",
    "tryhackme.com",
}
LOCAL_SAFE_TOOLS = {
    "read",
    "glob",
    "grep",
    "list_mcp_resources",
    "list_mcp_resource_templates",
    "read_mcp_resource",
    "skill",
    "todowrite",
    "question",
    "task",
}
# Native OpenCode tools that are always known to the gate. Anything that is
# neither native, nor an exact entry, nor a pattern in
# config/tool-capabilities.json is denied as blocked_unknown_tool
# (fail-closed: registering a tool is an explicit operator act).
KNOWN_NATIVE_TOOLS = LOCAL_SAFE_TOOLS | {
    "list",
    "bash",
    "webfetch",
    "websearch",
    "write",
    "edit",
    "patch",
    "multiedit",
    "apply_patch",
    "notebookedit",
    "todo",
}
# Secret/credential path deny list for path-bearing tools (read/glob/grep/…)
# and for slash-bearing bash tokens. Classification is by path component or
# basename — the class of credential stores, not individual files.
SECRET_DIR_COMPONENTS = {".ssh", ".aws", ".gnupg", ".cco", ".kube", ".docker"}
SECRET_BASENAMES = {
    ".env",
    "credentials",
    "credentials.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".netrc",
    "credential_vault.db",
}
SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx")
ENV_SAFE_BASENAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.defaults",
}
_PATH_ARG_KEYS = {
    "filepath", "file", "path", "filename", "dir", "directory", "cwd",
    "workdir", "notebook_path", "target_file", "pattern", "glob",
}
# Bare filenames with these extensions are local files, never network
# targets (`cat notes.txt`, `python3 script.py`, `> out.txt`). Real TLDs
# (.com/.net/.org/…) are deliberately absent so hosts still extract.
_LOCAL_FILE_EXTENSIONS = (
    ".txt", ".json", ".jsonl", ".md", ".log", ".csv", ".tsv", ".html",
    ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".py", ".js", ".ts",
    ".sh", ".rb", ".pl", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf",
    ".zip", ".gz", ".db", ".sqlite", ".sqlite3", ".out", ".lock",
)


_LOCAL_ORCHESTRATION_RE = re.compile(
    r"^\s*(?:python3?|python)\s+scripts/(?:brain\.py|policy_gate_cli\.py)\b"
    r"|^\s*(?:python3?|python)\s+scripts/chain_executor\.py\s+plan\b"
)
_NETWORKISH_BASH_RE = re.compile(
    r"(?:https?|wss?)://|\b(?:curl|wget|aria2c|ffuf|gobuster|feroxbuster|"
    r"dirsearch|nuclei|masscan|rustscan|nmap|nikto|sqlmap|hydra|medusa|"
    r"wpscan|amass|subfinder|dnsenum|httpx|nc|ncat|telnet|ssh|scp|sftp|"
    r"ftp|ping|traceroute)\b|\bgit\s+(?:clone|pull|fetch|push|ls-remote)\b",
    re.I,
)
_SHELL_CHAIN_RE = re.compile(r"[;|`]|\$\(|\|\|")
_WORKDIR_LOCAL_VERBS = frozenset({
    "mkdir", "ls", "cat", "head", "tail", "wc", "stat", "file", "du",
    "touch", "pwd", "dirname", "basename", "test", "[", "true", "false",
})
_READ_ONLY_LOCAL_VERBS = frozenset({
    "ls", "cat", "head", "tail", "wc", "stat", "file", "du",
})


def _workdir_roots() -> tuple[Path, Path]:
    try:
        workdir = Path(os.environ.get("CCO_WORKDIR", "~/cco-work")).expanduser().resolve()
    except Exception:
        workdir = Path.home() / "cco-work"
    return workdir, Path("/tmp")


def _path_under_roots(candidate: str, roots: tuple[Path, ...]) -> bool:
    text = candidate.strip().strip("'\"")
    if not text or text.startswith("-") or text in {">", ">>", "<", "|"}:
        return True
    if "://" in text or text.startswith(("http:", "https:", "ws:", "wss:")):
        return False
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        resolved = str(path.resolve())
    except Exception:
        return False
    return any(os.path.commonpath([resolved, str(base)]) == str(base) for base in roots
               if str(base) not in ("", "/"))


def _single_segment_is_local(segment: str, roots: tuple[Path, Path]) -> bool:
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return False
    if not tokens or tokens[0] not in _WORKDIR_LOCAL_VERBS:
        return False
    if _NETWORKISH_BASH_RE.search(segment):
        return False
    use_roots = roots + (Path.cwd().resolve(),) if tokens[0] in _READ_ONLY_LOCAL_VERBS else roots
    return all(_path_under_roots(token, use_roots) for token in tokens[1:])


def _bash_is_local(command: str, urls: list, targets: list | None = None) -> bool:
    """True for bash that cannot touch the network by construction.

    Repo-local orchestration CLIs (brain planner, gate CLI, chain plan)
    only read/write local state even though their arguments name a
    target. Workdir-scoped file commands (mkdir/ls/cat/...) joined
    by && also qualify. Anything with an extracted URL or target and
    anything outside the workdir/tmp roots stays gated.
    """
    if not isinstance(command, str) or not command.strip():
        return False
    if _SHELL_CHAIN_RE.search(command):
        return False
    if _LOCAL_ORCHESTRATION_RE.search(command):
        return True
    if urls or targets:
        return False
    roots = _workdir_roots()
    if "&&" in command:
        segments = [seg.strip() for seg in command.split("&&")]
        return bool(segments) and all(_single_segment_is_local(seg, roots) for seg in segments)
    try:
        first = shlex.split(command)[0]
    except (ValueError, IndexError):
        return False
    if first in _WORKDIR_LOCAL_VERBS:
        return _single_segment_is_local(command, roots)
    return _NETWORKISH_BASH_RE.search(command) is None


def _is_local_filename(candidate: str) -> bool:
    if "/" in candidate or "\\" in candidate or ":" in candidate:
        return False
    return candidate.lower().endswith(_LOCAL_FILE_EXTENSIONS)


_SANDBOX_INNER_RE = re.compile(r"/bin/bash'?\s+'?-c'?\s+'((?:[^']|'\\'')*)'")


def _sandbox_inner_command(command: str) -> str | None:
    """Plugin'in bwrap zarfini ac; ajan zarfi kopyalayip yeniden gonderebilir."""
    if "bwrap" not in command:
        return None
    inner = command
    for _ in range(3):
        match = _SANDBOX_INNER_RE.search(inner)
        if not match:
            return inner if inner != command else None
        inner = match.group(1).replace("'\\''", "'")
        if "bwrap" not in inner:
            return inner
    return inner


def _secret_path_hit(raw: Any) -> str | None:
    """Return the matched secret class for a path-like string, else None."""
    if not isinstance(raw, str):
        return None
    text = raw.strip().strip("'\"")
    if not text or text.startswith(("http://", "https://", "ws://", "wss://")):
        return None
    parts = [
        part for part in re.split(r"[/\\]+", text)
        if part not in ("", ".", "..", "**", "*")
    ]
    if not parts:
        return None
    lower = [part.lower() for part in parts]
    basename = lower[-1]
    if basename in ENV_SAFE_BASENAMES:
        return None
    # The session vault is the sanctioned boot file the brain is required
    # to read first; it holds pointers, not secrets. Allow exactly it.
    if basename == "session-vault.json" and ".cco" in lower:
        return None
    for component in lower:
        if component in SECRET_DIR_COMPONENTS:
            return f"secret directory ({component})"
    if ".config" in lower and "opencode" in lower:
        return "opencode credential store"
    if basename == ".env" or basename.startswith(".env."):
        return ".env file"
    if basename in SECRET_BASENAMES:
        return f"credential file ({basename})"
    if basename.endswith(SECRET_SUFFIXES):
        return f"key material ({basename})"
    return None
ACTIVE_TOOL_PREFIXES = (
    "kali-tools_",
    "web-advanced_",
    "validator_",
    "hunter_",
    "browser_",
    "llm-security_",
    "webfetch",
    "bash",
)
UNTRUSTED_OUTPUT_PREFIXES = (
    "browser_",
    "webfetch",
    "kali-tools_curl_request",
    "kali-tools_browser_",
)
URL_RE = re.compile(r"(?P<url>(?:https?|wss?)://[^\s'\"<>]+)", re.I)
HOST_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
HTTP_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b", re.I)
# curl/wget benzeri bayraklar: sonraki token hedef değil seçenek değeridir (UA/header/data).
_BASH_OPTION_VALUE_FLAGS = frozenset({
    "-A", "--user-agent", "-H", "--header", "-b", "--cookie",
    "-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
    "-u", "--user", "-e", "--referer", "-X", "--request",
})
_BASH_OPTION_VALUE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<flag>-A|--user-agent|-H|--header|-b|--cookie"
    r"|-d|--data(?:-raw|-binary|-ascii)?|-u|--user|-e|--referer|-X|--request"
    r"|-w|--wordlist|-o|--output)"
    r"(?P<eq>=?)\s*(?P<val>'[^']*'|\"[^\"]*\"|\S+)"
)
# Bu flag'larin URL-sekilli degerleri hedeftir (ffuf -u/-w uzak URL);
# semasiz degerler dosya/kimlik sayilip maskelenir.
_URL_OR_FILE_FLAGS = ("-u", "--user", "-w", "--wordlist", "-o", "--output")


def _mask_bash_option_values(text: str) -> str:
    def repl(match: re.Match) -> str:
        # URL-sekilli deger hedeftir (ffuf `-u <URL>`), maskeleme ki scope denetlensin.
        # Semasiz deger dosya/kimliktir (`-w liste.txt`, `curl -u user:pass`), maskele.
        val = (match.group("val") or "").strip().strip("'\"")
        if match.group("flag") in _URL_OR_FILE_FLAGS and val.lower().startswith(
            ("http://", "https://", "ws://", "wss://")
        ):
            return match.group(0)
        return match.group("flag") + match.group("eq") + " "

    return _BASH_OPTION_VALUE_RE.sub(repl, text)


_AUTH_ATTEST_RE = re.compile(r"auth:(?:recovered|not-required:)", re.IGNORECASE)


def _mask_auth_attestation(text: str) -> str:
    """Hide closure attestation markers from target extraction.

    `auth:recovered` / `auth:not-required:` are protocol constants the
    closure gate requires inside ledger notes; the host:port splitter
    would otherwise flag them as invalid targets and block commands
    (e.g. chained `brain.py hypotheses mark`) that carry them.
    """
    return _AUTH_ATTEST_RE.sub("auth_attested", text)


IPV4_TEXT = r"(?:\d{1,3}\.){3}\d{1,3}"
IPV4_CIDR_CANDIDATE_RE = re.compile(
    rf"(?<![\w.])(?P<network>{IPV4_TEXT}/[^\s,;'\"<>\[\](){{}}]+)"
)
IPV4_RANGE_CANDIDATE_RE = re.compile(
    rf"(?<![\w.])(?P<range>{IPV4_TEXT}\s*-\s*(?:{IPV4_TEXT}|\d{{1,3}}))(?![\w./])"
)
OPAQUE_ARGUMENT_FIELDS = {
    "command_args",
    "curl_args",
    "extra_args",
    "nmap_args",
    "options",
    "sqlmap_args",
}
# Safe extra-args allowlists: opaque fields fail closed by default, but
# these exact per-tool tokens carry no target/scope escape. Anything
# else in the field keeps the blocked_unsafe_arguments verdict.
SAFE_EXTRA_ARGS = {
    "kali-tools_nmap_scan": frozenset({"-sV", "-sC", "-T4", "-Pn", "-sT"}),
    "kali-tools_nmap_scan_structured": frozenset({"-sV", "-T4", "--top-ports"}),
}
_SAFE_TOP_PORTS_RE = re.compile(r"^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$")
# curl evidence flags: valueless display flags, bounded timeouts, output
# paths confined to the workdir/tmp roots, and a write-out format limited
# to known placeholders plus a safe literal charset. Everything else
# (user-agent spoofing, proxy/resolve rewiring, file-reading --data/--config
# forms) keeps the blocked_unsafe_arguments verdict.
_CURL_VALUELESS_FLAGS = frozenset({"-s", "-S", "-i", "-L", "--compressed"})
_CURL_NUMBER_FLAGS = frozenset({"-m", "--max-time", "--connect-timeout"})
_CURL_PATH_FLAGS = frozenset({"-o", "-D"})
_CURL_NUMBER_RE = re.compile(r"^\d+(?:\.\d+)?$")
_CURL_NUMBER_MAX = 300.0
_CURL_WRITEOUT_PLACEHOLDERS = frozenset({
    "http_code", "response_code", "size_download", "size_header",
    "size_request", "time_total", "time_connect", "time_starttransfer",
    "time_appconnect", "speed_download", "speed_upload", "url_effective",
    "remote_ip", "remote_port", "local_ip", "local_port", "content_type",
    "scheme", "http_version", "method", "num_connects", "num_redirects",
    "redirect_url", "filename_effective", "errormsg", "exitcode",
})
_CURL_WRITEOUT_PLACEHOLDER_RE = re.compile(r"%\{([A-Za-z0-9_]+)\}")
_CURL_WRITEOUT_REST_RE = re.compile(r"[A-Za-z0-9 \t.,:_\-+=/()\[\]\\]*")
_CURL_SHELL_META = frozenset(";&|$`<>(){}\n\r")
_CURL_GUIDANCE = (
    "curl extra_args allowlist: -s -S -i -L --compressed; "
    "-m/--max-time/--connect-timeout <0 < seconds <= 300>; "
    "-o/-D <path under workdir or /tmp>; -w/--write-out '<%{...} format>'."
)


def _curl_path_ok(value: str, roots: tuple[Path, Path]) -> bool:
    if value == "-":
        return True  # curl writes to stdout
    if any(char in _CURL_SHELL_META for char in value):
        return False
    candidate = value
    if not Path(value).expanduser().is_absolute():
        candidate = str(roots[0] / value)
    return _path_under_roots(candidate, roots)


def _curl_number_ok(value: str) -> bool:
    if not _CURL_NUMBER_RE.match(value):
        return False
    try:
        return 0 < float(value) <= _CURL_NUMBER_MAX
    except ValueError:
        return False


def _curl_writeout_ok(value: str) -> bool:
    if not value or len(value) > 256:
        return False
    text = value.replace("%%", " ")  # %% is a literal percent in curl formats
    names = _CURL_WRITEOUT_PLACEHOLDER_RE.findall(text)
    rest = _CURL_WRITEOUT_PLACEHOLDER_RE.sub("", text)
    if "%" in rest or any(char in _CURL_SHELL_META for char in rest):
        return False
    if any(name not in _CURL_WRITEOUT_PLACEHOLDERS for name in names):
        return False
    return _CURL_WRITEOUT_REST_RE.fullmatch(rest) is not None


def _split_long_flag(token: str) -> tuple[str, str | None]:
    if token.startswith("--") and "=" in token:
        name, _, inline = token.partition("=")
        return name, inline
    return token, None
REDACTED = "[REDACTED]"


class InvocationData(TypedDict):
    targets: list[str]
    url_targets: list[str]
    standalone_targets: list[str]
    network_targets: list[str]
    range_targets: list[str]
    invalid_targets: list[str]
    urls: list[str]
    methods: list[str]
    unsafe_arguments: list[str]
    unsafe_argument_detail: str


@dataclass
class ApprovalGrant:
    id: int
    tool_pattern: str
    target_pattern: str
    reason: str
    expires_at: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _json_load(path: Path, description: str) -> dict[str, Any]:
    try:
        raw = path.read_text()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{description} file is missing: {path}") from exc
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"unable to read {description} file {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"malformed {description} file {path}: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(f"malformed {description} file {path}: top-level value must be an object")
    return data


def _parse_ip_range(expression: str):
    compact = re.sub(r"\s+", "", expression)
    if compact.count("-") != 1:
        return None
    start_text, end_text = compact.split("-", 1)
    try:
        start = ipaddress.ip_address(start_text)
        if start.version == 4 and end_text.isdigit():
            octet = int(end_text)
            if not 0 <= octet <= 255:
                return None
            end_text = f"{start_text.rsplit('.', 1)[0]}.{octet}"
        end = ipaddress.ip_address(end_text)
    except ValueError:
        return None
    if start.version != end.version or int(start) > int(end):
        return None
    return start, end, f"{start}-{end}"


def _ip_expression_networks(expression: str) -> list[Any] | None:
    parsed_range = _parse_ip_range(expression)
    if parsed_range:
        start, end, _ = parsed_range
        return list(ipaddress.summarize_address_range(start, end))
    try:
        return [ipaddress.ip_network(expression.strip(), strict=False)]
    except ValueError:
        return None


def _network_is_within(candidate: Any, container: Any) -> bool:
    return candidate.version == container.version and candidate.subnet_of(container)


def _credential_key(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    exact = {
        "accesstoken",
        "apikey",
        "auth",
        "authorization",
        "authtoken",
        "bearer",
        "clientsecret",
        "code",
        "credential",
        "jwt",
        "key",
        "pass",
        "password",
        "passwd",
        "pwd",
        "refreshtoken",
        "secret",
        "session",
        "sessionid",
        "sig",
        "signature",
        "token",
    }
    return normalized in exact or normalized.endswith(
        (
            "accesstoken",
            "apikey",
            "authtoken",
            "clientsecret",
            "credential",
            "password",
            "secret",
            "sessionid",
            "token",
        )
    )


def _redact_parameter_string(value: str) -> str:
    pairs = parse_qsl(value, keep_blank_values=True)
    if not pairs:
        return value
    return urlencode([(key, REDACTED if _credential_key(key) else item) for key, item in pairs], doseq=True)


def _redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.netloc:
            return value
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = f"{REDACTED}@{netloc.rsplit('@', 1)[1]}"
        query = _redact_parameter_string(parsed.query)
        fragment = _redact_parameter_string(parsed.fragment) if "=" in parsed.fragment else parsed.fragment
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))
    except (TypeError, ValueError):
        return REDACTED


def _redact_urls_in_text(value: str) -> str:
    return URL_RE.sub(lambda match: _redact_url(match.group("url")), value)


def _redact_audit_value(value: Any, key: str = "") -> Any:
    if key and _credential_key(key):
        return REDACTED
    if isinstance(value, str):
        return _redact_urls_in_text(value)
    if isinstance(value, dict):
        return {str(child_key): _redact_audit_value(child, str(child_key)) for child_key, child in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_redact_audit_value(child) for child in value]
    return value


def _looks_like_loopback(host: str) -> bool:
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _parse_scope_url_prefix(asset: str) -> str:
    asset = asset.rstrip("/")
    if asset.startswith(("http://", "https://", "ws://", "wss://")):
        return asset
    return f"//{asset}"


class PolicyEngine:
    def __init__(self, cco_home: str | None = None, repo_root: str | None = None,
                 scope_file: str | None = None, program_policy_file: str | None = None,
                 *, scope_only: bool = False):
        self.cco_home = Path(cco_home or os.environ.get("CCO_HOME", "~/.cco")).expanduser()
        self.repo_root = Path(repo_root or runtime_root())
        if scope_only:
            self.scope_file = Path(scope_file).expanduser() if scope_file else self._discover_scope_file()
            self.program_policy_file = (Path(program_policy_file).expanduser() if program_policy_file
                                        else self._discover_program_policy_file())
            if self.scope_file is None:
                raise ValueError("scope file is required")
            self.scope = self._load_scope()
            self.program_policy = self._load_program_policy()
            return
        self.cco_home.mkdir(parents=True, exist_ok=True)
        self.audit_db = self.cco_home / "audit.db"
        self.sqlite_timeout_seconds = max(1.0, float(os.environ.get("CCO_SQLITE_TIMEOUT_SECONDS", "30")))
        self.permissions_file = self.cco_home / "permissions.json"
        capability_candidates = (
            self.repo_root / "config" / "tool-capabilities.json",
            Path(__file__).resolve().parents[1] / "config" / "tool-capabilities.json",
            Path(sys.prefix) / "share" / "hackagent" / "tool-capabilities.json",
        )
        self.tool_capabilities_file = next((path for path in capability_candidates if path.exists()), None)
        if self.tool_capabilities_file is None:
            raise FileNotFoundError("tool capability policy is missing")
        self.scope_file = Path(scope_file).expanduser() if scope_file else self._discover_scope_file()
        self.program_policy_file = (
            Path(program_policy_file).expanduser() if program_policy_file else self._discover_program_policy_file()
        )
        self._init_db()
        self.reload()

    def _connect(self, row_factory: bool = False):
        conn = sqlite3.connect(self.audit_db, timeout=self.sqlite_timeout_seconds)
        conn.execute(f"PRAGMA busy_timeout={int(self.sqlite_timeout_seconds * 1000)}")
        if row_factory:
            conn.row_factory = sqlite3.Row
        return conn

    def _config_signatures(self) -> tuple:
        def signature(path: Path | None):
            if path is None:
                return None
            try:
                stat = Path(path).stat()
                return (str(path), stat.st_mtime_ns, stat.st_size)
            except OSError:
                return (str(path), None, None)

        return (
            signature(self.scope_file),
            signature(self.program_policy_file),
            signature(self.permissions_file),
            signature(self.tool_capabilities_file),
        )

    def reload(self, force: bool = False):
        # validate_tool_invocation calls this on every invocation. Re-parsing
        # four JSON files per call dominated gate latency, so unchanged files
        # (mtime+size signature) reuse the parsed state. Any edit is picked
        # up on the next call; force=True bypasses the cache.
        signatures = self._config_signatures()
        if not force and signatures == getattr(self, "_reload_signatures", None) \
                and hasattr(self, "tool_capabilities"):
            return
        self.scope = self._load_scope()
        self.permissions = self._load_permissions()
        self.program_policy = self._load_program_policy()
        self.tool_capabilities = self._load_tool_capabilities()
        self._reload_signatures = signatures

    def _discover_scope_file(self) -> Path | None:
        if os.environ.get("CCO_SCOPE_FILE"):
            return Path(os.environ["CCO_SCOPE_FILE"]).expanduser()
        candidates = [
            self.repo_root / ".codex" / "scope.json",
            self.repo_root / ".codex" / "scope-xbow-labs.json",
            self.cco_home / "scope.json",
        ]
        for path in candidates:
            if path.exists():
                return path
        return None

    def _discover_program_policy_file(self) -> Path | None:
        if os.environ.get("CCO_PROGRAM_POLICY_FILE"):
            return Path(os.environ["CCO_PROGRAM_POLICY_FILE"]).expanduser()
        candidates = [
            self.repo_root / ".codex" / "program-policy.json",
            self.cco_home / "program_policy.json",
        ]
        for path in candidates:
            if path.exists():
                return path
        return None

    def _init_db(self):
        conn = self._connect()
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                targets_json TEXT DEFAULT '[]',
                scope_valid BOOLEAN,
                permission TEXT,
                result TEXT,
                metadata TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_pattern TEXT NOT NULL,
                target_pattern TEXT NOT NULL,
                reason TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_limit_reservations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                weight INTEGER NOT NULL CHECK(weight > 0)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS path_probes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                ua_variant TEXT NOT NULL,
                header_variant TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                effective INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        for column, definition in (
            ("targets_json", "TEXT DEFAULT '[]'"),
            ("metadata", "TEXT DEFAULT '{}'"),
        ):
            try:
                conn.execute(f"ALTER TABLE audit_log ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_tool_time ON audit_log(tool_name, timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_approval_active ON approval_grants(expires_at, revoked_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rate_reservation_tool_time ON rate_limit_reservations(tool_name, timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_path_probes_host_path ON path_probes(host, path)"
        )
        conn.commit()
        conn.close()

    def _load_permissions(self) -> dict[str, Any]:
        permissions = {"default": "ask", "tools": {}, "rate_limits": {}}
        if self.permissions_file.exists():
            try:
                permissions.update(_json_load(self.permissions_file, "permissions"))
            except (OSError, RuntimeError, ValueError):
                # Permissions are a legacy optional overlay. Core policy files below
                # are strict and remain the security boundary if this file is bad.
                pass
        return permissions

    def _load_scope(self) -> dict[str, Any]:
        scope: dict[str, Any] = {
            "raw": {},
            "targets": set(),
            "domains": set(),
            "cidr_ranges": set(),
            "url_prefixes": set(),
            "excluded": set(),
            "explicit_only": False,
            "allow_osint": True,
            "allow_public_labs": True,
            "allow_loopback": True,
        }
        if not self.scope_file:
            return scope
        data = _json_load(self.scope_file, "scope")
        for key in ("targets", "domains", "cidr_ranges", "in_scope", "excluded_assets"):
            if key in data and not isinstance(data[key], list):
                raise ValueError(f"malformed scope file {self.scope_file}: {key} must be an array")
        if "rules" in data and not isinstance(data["rules"], dict):
            raise ValueError(f"malformed scope file {self.scope_file}: rules must be an object")
        for key in ("allow_osint", "allow_public_labs", "allow_loopback", "blind_mode"):
            if key in data and not isinstance(data[key], bool):
                raise ValueError(f"malformed scope file {self.scope_file}: {key} must be a boolean")
        scope["raw"] = data
        scope["allow_osint"] = data.get("allow_osint", True)
        scope["allow_public_labs"] = data.get("allow_public_labs", True)
        scope["allow_loopback"] = data.get("allow_loopback", True)
        scope["explicit_only"] = data.get("scope_policy") == "explicit_only"

        for key in ("targets", "domains", "cidr_ranges"):
            for item in data.get(key, []):
                if not isinstance(item, str):
                    raise ValueError(f"malformed scope file {self.scope_file}: {key} entries must be strings")
                scope[key].add(str(item))

        for item in data.get("excluded_assets", []):
            if not isinstance(item, str) or not item.strip():
                raise ValueError(
                    f"malformed scope file {self.scope_file}: excluded_assets entries must be non-empty strings"
                )
            scope["excluded"].add(item.strip().lower().lstrip("*."))

        for entry in data.get("in_scope", []):
            if not isinstance(entry, dict) or not isinstance(entry.get("asset"), str):
                raise ValueError(
                    f"malformed scope file {self.scope_file}: in_scope entries require a string asset"
                )
            asset = entry["asset"].strip()
            if not asset:
                continue
            if asset.startswith(("http://", "https://", "ws://", "wss://")):
                scope["url_prefixes"].add(asset.rstrip("/"))
            elif asset.startswith("*."):
                scope["domains"].add(asset[2:])
            else:
                try:
                    ipaddress.ip_network(asset, strict=False)
                    scope["cidr_ranges"].add(asset)
                    continue
                except ValueError:
                    pass
                if "/" in asset:
                    scope["url_prefixes"].add(asset.rstrip("/"))
                else:
                    scope["targets"].add(asset)
        return scope

    def _load_program_policy(self) -> dict[str, Any]:
        rules = {
            "profile": "default",
            "approval_required_tools": [],
            "denied_tools": [],
            "blocked_http_methods": [],
            "blocked_paths": [],
            "member_login": {},
            "rate_limits": {
                "default": {"window_seconds": 60, "max_calls": 60},
                "conservative": {"window_seconds": 60, "max_calls": 20},
                "aggressive": {"window_seconds": 60, "max_calls": 120},
                "overrides": {},
            },
            "active_requires": "",
            "background_network_jobs": "approval",
            "fuzz_max_requests_per_call": 5000,
            "bash_budget_max_calls": 50,
            "bash_budget_window_seconds": 3600,
            "time_budget_max_seconds": 3600,
            "time_budget_idle_reset_seconds": 900,
            "required_request_headers": {},
            "allow_loopback": self.scope.get("allow_loopback", True),
            "allow_osint": self.scope.get("allow_osint", True),
            "allow_public_labs": self.scope.get("allow_public_labs", True),
            "untrusted_output_prefixes": list(UNTRUSTED_OUTPUT_PREFIXES),
        }
        if self.program_policy_file:
            raw = _json_load(self.program_policy_file, "program policy")
            for key in (
                "approval_required_tools",
                "denied_tools",
                "blocked_http_methods",
                "blocked_paths",
                "untrusted_output_prefixes",
            ):
                if key in raw and (
                    not isinstance(raw[key], list) or not all(isinstance(item, str) for item in raw[key])
                ):
                    raise ValueError(
                        f"malformed program policy file {self.program_policy_file}: {key} must be an array of strings"
                    )
            for key in ("allow_loopback", "allow_osint", "allow_public_labs"):
                if key in raw and not isinstance(raw[key], bool):
                    raise ValueError(
                        f"malformed program policy file {self.program_policy_file}: {key} must be a boolean"
                    )
            if "blind_discovery" in raw:
                blind_rule = raw["blind_discovery"]
                if (not isinstance(blind_rule, dict)
                        or set(blind_rule) - {"synthetic_accounts_only", "owned_objects_private",
                                              "differential_ownership"}
                        or any(not isinstance(value, bool) for value in blind_rule.values())):
                    raise ValueError(
                        f"malformed program policy file {self.program_policy_file}: "
                        "blind_discovery must contain only boolean synthetic_accounts_only/"
                        "owned_objects_private/differential_ownership"
                    )
            if "write_set" in raw:
                write_rule = raw["write_set"]
                create_list = write_rule.get("create_allowlist") if isinstance(write_rule, dict) else None
                if (not isinstance(write_rule, dict)
                        or set(write_rule) - {"enabled", "create_allowlist",
                                              "max_objects_per_task", "ttl_seconds"}
                        or not isinstance(write_rule.get("enabled", False), bool)
                        or not isinstance(create_list, list)
                        or any(not isinstance(item, dict)
                               or set(item) - {"method", "path"}
                               or not isinstance(item.get("method"), str)
                               or not isinstance(item.get("path"), str)
                               for item in create_list)
                        or not isinstance(write_rule.get("max_objects_per_task", 3), int)
                        or not isinstance(write_rule.get("ttl_seconds", 600), int)):
                    raise ValueError(
                        f"malformed program policy file {self.program_policy_file}: "
                        "write_set must contain enabled/create_allowlist/"
                        "max_objects_per_task/ttl_seconds"
                    )
            if "rate_limits" in raw:
                table = raw["rate_limits"]
                if not isinstance(table, dict) or "default" not in table:
                    raise ValueError(
                        f"malformed program policy file {self.program_policy_file}: "
                        "rate_limits must be an object containing default"
                    )
                overrides = table.get("overrides", {})
                if not isinstance(overrides, dict):
                    raise ValueError(
                        f"malformed program policy file {self.program_policy_file}: rate_limits.overrides must be an object"
                    )
                for name, value in {key: value for key, value in table.items() if key != "overrides"}.items():
                    if not isinstance(value, dict):
                        raise ValueError(
                            f"malformed program policy file {self.program_policy_file}: rate limit {name} must be an object"
                        )
                    window = value.get("window_seconds")
                    maximum = value.get("max_calls")
                    if (
                        isinstance(window, bool)
                        or not isinstance(window, int)
                        or window < 1
                        or isinstance(maximum, bool)
                        or not isinstance(maximum, int)
                        or maximum < 0
                    ):
                        raise ValueError(
                            f"malformed program policy file {self.program_policy_file}: rate limit {name} "
                            "requires positive integer window_seconds and non-negative integer max_calls"
                        )
                for name, value in overrides.items():
                    if not isinstance(value, dict) or not value:
                        raise ValueError(
                            f"malformed program policy file {self.program_policy_file}: rate limit {name} must be an object"
                        )
                    window = value.get("window_seconds", 1)
                    maximum = value.get("max_calls", 0)
                    if (
                        isinstance(window, bool)
                        or not isinstance(window, int)
                        or window < 1
                        or isinstance(maximum, bool)
                        or not isinstance(maximum, int)
                        or maximum < 0
                    ):
                        raise ValueError(
                            f"malformed program policy file {self.program_policy_file}: rate limit {name} "
                            "contains an invalid window_seconds or max_calls"
                        )
            if "background_network_jobs" in raw and str(
                    raw["background_network_jobs"]).strip().lower() not in {
                        "allow", "approval", "deny"}:
                raise ValueError(
                    f"malformed program policy file {self.program_policy_file}: "
                    "background_network_jobs must be one of allow, approval, deny"
                )
            for _budget_key, _budget_min in (
                ("bash_budget_max_calls", 0),
                ("bash_budget_window_seconds", 1),
                ("time_budget_max_seconds", 0),
                ("time_budget_idle_reset_seconds", 1),
            ):
                if _budget_key in raw and (
                        isinstance(raw[_budget_key], bool)
                        or not isinstance(raw[_budget_key], int)
                        or raw[_budget_key] < _budget_min):
                    raise ValueError(
                        f"malformed program policy file {self.program_policy_file}: "
                        f"{_budget_key} must be an integer >= {_budget_min} (0 disables the budget)"
                    )
            if "fuzz_max_requests_per_call" in raw and (
                    isinstance(raw["fuzz_max_requests_per_call"], bool)
                    or not isinstance(raw["fuzz_max_requests_per_call"], int)
                    or raw["fuzz_max_requests_per_call"] < 1):
                raise ValueError(
                    f"malformed program policy file {self.program_policy_file}: "
                    "fuzz_max_requests_per_call must be a positive integer"
                )
            if "required_request_headers" in raw and (
                    not isinstance(raw["required_request_headers"], dict)
                    or not all(isinstance(k, str) and isinstance(v, str)
                               for k, v in raw["required_request_headers"].items())):
                raise ValueError(
                    f"malformed program policy file {self.program_policy_file}: "
                    "required_request_headers must be an object of string to string"
                )
            if "member_login" in raw:
                login = raw["member_login"]
                if (not isinstance(login, dict) or (login and (
                        set(login) != {"login_url", "accounts", "test_data_only"}
                        or login.get("test_data_only") is not True
                        or not isinstance(login.get("accounts"), list)
                        or not 1 <= len(login["accounts"]) <= 8
                        or not all(isinstance(account, str) and re.fullmatch(
                            r"[A-Za-z][A-Za-z0-9_.-]{0,63}", account)
                            for account in login["accounts"])
                        or len(set(login["accounts"])) != len(login["accounts"])
                        or not isinstance(login.get("login_url"), str)))):
                    raise ValueError("malformed member_login policy")
                if login:
                    parsed_login = urlparse(login["login_url"])
                    if (parsed_login.scheme not in {"http", "https"}
                            or not parsed_login.hostname or parsed_login.username is not None
                            or parsed_login.query or parsed_login.fragment
                            or re.search(r"[%\\\s]", login["login_url"])
                            or not re.search(r"/(?:quick-)?login$", parsed_login.path, re.I)):
                        raise ValueError("member_login.login_url must be an exact login URL")
            rules.update(raw)
        scope_rules = self.scope.get("raw", {}).get("rules", {})
        if scope_rules:
            rules["active_requires"] = rules.get("active_requires") or scope_rules.get("active_requires", "")
            blocked = list(rules.get("blocked_http_methods", []))
            blocked.extend(x for x in scope_rules.get("destructive_prohibited", []) if x in {"DELETE", "PUT", "PATCH"})
            rules["blocked_http_methods"] = sorted(set(blocked))
            if not rules.get("rate_limit_profile") and scope_rules.get("rate_limit"):
                rules["rate_limit_profile"] = scope_rules["rate_limit"]
        return rules

    def _load_tool_capabilities(self) -> dict[str, Any]:
        defaults = {
            "network": False,
            "requires_scope": False,
            "requires_approval": False,
            "mutates_local_state": False,
            "mutates_remote_state": False,
            "destructive": False,
            "sensitive_output": False,
            "untrusted_output": False,
            "request_multiplier": 1,
            "target_fields": [],
        }
        if self.tool_capabilities_file is None:
            raise FileNotFoundError("tool capability policy is missing")
        data = _json_load(self.tool_capabilities_file, "tool capability policy")
        if "defaults" in data and not isinstance(data["defaults"], dict):
            raise ValueError(
                f"malformed tool capability policy file {self.tool_capabilities_file}: defaults must be an object"
            )
        if "tools" in data and not isinstance(data["tools"], dict):
            raise ValueError(
                f"malformed tool capability policy file {self.tool_capabilities_file}: tools must be an object"
            )
        if "patterns" in data and not isinstance(data["patterns"], list):
            raise ValueError(
                f"malformed tool capability policy file {self.tool_capabilities_file}: patterns must be an array"
            )
        data.setdefault("defaults", defaults)
        data.setdefault("tools", {})
        data.setdefault("patterns", [])
        for key, value in defaults.items():
            data["defaults"].setdefault(key, value)
        for rule in [data["defaults"], *data["tools"].values(), *data["patterns"]]:
            if not isinstance(rule, dict):
                raise ValueError(
                    f"malformed tool capability policy file {self.tool_capabilities_file}: capability rules must be objects"
                )
            weight = rule.get("request_multiplier", 1)
            if isinstance(weight, bool) or not isinstance(weight, int) or weight < 1:
                raise ValueError(
                    f"malformed tool capability policy file {self.tool_capabilities_file}: "
                    "request_multiplier must be a positive integer"
                )
            for key in (
                "network",
                "requires_scope",
                "requires_approval",
                "mutates_local_state",
                "mutates_remote_state",
                "destructive",
                "sensitive_output",
                "untrusted_output",
            ):
                if key in rule and not isinstance(rule[key], bool):
                    raise ValueError(
                        f"malformed tool capability policy file {self.tool_capabilities_file}: {key} must be a boolean"
                    )
            if "target_fields" in rule and (
                not isinstance(rule["target_fields"], list)
                or not all(isinstance(field, str) for field in rule["target_fields"])
            ):
                raise ValueError(
                    f"malformed tool capability policy file {self.tool_capabilities_file}: "
                    "target_fields must be an array of strings"
                )
            if "pattern" in rule and not isinstance(rule["pattern"], str):
                raise ValueError(
                    f"malformed tool capability policy file {self.tool_capabilities_file}: pattern must be a string"
                )
        return data

    def tool_capability(self, tool_name: str) -> dict[str, Any]:
        base = dict(self.tool_capabilities.get("defaults", {}))
        exact = self.tool_capabilities.get("tools", {}).get(tool_name)
        if isinstance(exact, dict):
            base.update(exact)
            if "target_fields" not in exact:
                # Kesin kayit bayraklari ezer ama desenin alan eslemesini
                # silmez; aksi halde target argumani kapiya hic gorunmez.
                for rule in self.tool_capabilities.get("patterns", []):
                    pattern = rule.get("pattern")
                    if pattern and fnmatch(tool_name, pattern) and rule.get("target_fields"):
                        base["target_fields"] = rule["target_fields"]
                        break
            return base
        for rule in self.tool_capabilities.get("patterns", []):
            pattern = rule.get("pattern")
            if pattern and fnmatch(tool_name, pattern):
                base.update({k: v for k, v in rule.items() if k != "pattern"})
                return base
        # Compatibility fallback until every caller is migrated to the registry.
        active = tool_name.startswith(ACTIVE_TOOL_PREFIXES)
        base.update({
            "network": active,
            "requires_scope": active,
            "requires_approval": active,
            "sensitive_output": active,
        })
        return base

    def _is_known_tool(self, tool_name: str) -> bool:
        if tool_name in KNOWN_NATIVE_TOOLS:
            return True
        capabilities = self.tool_capabilities
        if tool_name in capabilities.get("tools", {}):
            return True
        return any(
            rule.get("pattern") and fnmatch(tool_name, rule["pattern"])
            for rule in capabilities.get("patterns", [])
        )

    def _secret_path_violation(self, tool_name: str, args: dict[str, Any]) -> str | None:
        if tool_name == "bash":
            command = args.get("command", "")
            if isinstance(command, str):
                # Sandbox zarfiyla yeniden gonderilen komutta zarfin kendi
                # .cco/.env belirtecleri degil, ic komut yargilanir.
                command = _sandbox_inner_command(command) or command
                for token in re.split(r"[\s;|&<>]+", command):
                    # Only slash-bearing tokens are path-like; a bare word
                    # (e.g. a grep pattern) is not a file access. Bare secret
                    # filenames are additionally masked inside the sandbox.
                    if "/" not in token:
                        continue
                    hit = _secret_path_hit(token)
                    if hit:
                        return hit
            return None
        values: list[str] = []

        def walk(value: Any, key: str = ""):
            if isinstance(value, str):
                lowered = key.lower()
                if lowered in _PATH_ARG_KEYS or lowered.endswith(
                    ("_path", "_file", "_dir", "_directory")
                ):
                    # grep's pattern is a search regex, not a path; glob's
                    # pattern is a path expression and stays checked.
                    if not (lowered == "pattern" and tool_name != "glob"):
                        values.append(value)
            elif isinstance(value, dict):
                for child_key, child in value.items():
                    walk(child, str(child_key))
            elif isinstance(value, (list, tuple, set)):
                for child in value:
                    walk(child, key)

        walk(args)
        for value in values:
            hit = _secret_path_hit(value)
            if hit:
                return hit
        return None

    def _match_tool_rule(self, tool_name: str, action: str) -> str:
        if tool_name in self.permissions["tools"]:
            tool_perms = self.permissions["tools"][tool_name]
            if isinstance(tool_perms, str):
                return tool_perms
            if action in tool_perms:
                return tool_perms[action]
            return tool_perms.get("default", self.permissions["default"])
        for pattern, perms in self.permissions["tools"].items():
            if fnmatch(tool_name, pattern.replace("*", "*")):
                if isinstance(perms, str):
                    return perms
                if action in perms:
                    return perms[action]
                return perms.get("default", self.permissions["default"])
        return self.permissions["default"]

    def _flatten_strings(self, data: Any) -> list[str]:
        strings = []
        if isinstance(data, str):
            strings.append(data)
        elif isinstance(data, dict):
            for key, value in data.items():
                if key.lower() in {"headers_json", "data", "body_template"} and isinstance(value, str):
                    strings.append(value)
                strings.extend(self._flatten_strings(value))
        elif isinstance(data, (list, tuple, set)):
            for item in data:
                strings.extend(self._flatten_strings(item))
        return strings

    def _target_field_strings(self, data: Any, target_fields: set[str]) -> list[str]:
        strings: list[str] = []

        def walk(value: Any):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in target_fields:
                        strings.extend(self._flatten_strings(child))
                    elif key == "params_json" and isinstance(child, str):
                        try:
                            walk(json.loads(child))
                        except Exception:
                            pass
                    elif isinstance(child, (dict, list, tuple, set)):
                        walk(child)
            elif isinstance(value, (list, tuple, set)):
                for child in value:
                    walk(child)

        walk(data)
        return strings

    def _extra_args_is_safe(self, tool_name: str, value: Any) -> bool:
        return self._extra_args_violation(tool_name, value) is None

    def _extra_args_violation(self, tool_name: str, value: Any) -> str | None:
        """First offending token in an opaque extra-args value, None if safe.

        A violation of "" means field-level (no single token to name):
        the verdict keeps the legacy bare reason shape.
        """
        if not isinstance(value, str):
            if SAFE_EXTRA_ARGS.get(tool_name) is not None:
                return None  # legacy: allowlist tools only inspect strings
            return ""
        text = value.strip()
        if not text:
            return None
        if tool_name == "kali-tools_curl_request":
            return self._curl_extra_args_violation(text)
        allowlist = SAFE_EXTRA_ARGS.get(tool_name)
        if allowlist is None:
            try:
                tokens = shlex.split(text)
            except ValueError:
                return ""
            return tokens[0] if tokens else ""
        return self._allowlist_violation(allowlist, text)

    @staticmethod
    def _allowlist_violation(allowlist: frozenset[str], text: str) -> str | None:
        try:
            tokens = shlex.split(text)
        except ValueError:
            return ""
        skip_value = False
        for index, token in enumerate(tokens):
            if skip_value:
                if not _SAFE_TOP_PORTS_RE.match(token):
                    return token
                skip_value = False
                continue
            if token == "--top-ports":
                if token not in allowlist:
                    return token
                skip_value = True
                continue
            if token not in allowlist:
                return token
            if index > 0 and tokens[index - 1] == "--top-ports":
                return token
        return "--top-ports" if skip_value else None

    def _curl_extra_args_violation(self, text: str) -> str | None:
        try:
            tokens = shlex.split(text)
        except ValueError:
            return ""
        roots: tuple[Path, Path] | None = None
        index = 0
        while index < len(tokens):
            token = tokens[index]
            name, inline = _split_long_flag(token)
            if inline is None and token.startswith("-") and not token.startswith("--") \
                    and len(token) > 2:
                head, rest = token[:2], token[2:]
                if all(char in "sSiL" for char in token[1:]):
                    index += 1
                    continue  # bundled valueless flags, e.g. -sS
                if head in ("-m", "-o", "-D", "-w"):
                    name, inline = head, rest  # joined form, e.g. -m10, -o/tmp/x
            if name in _CURL_VALUELESS_FLAGS and inline is None:
                index += 1
                continue
            kind = None
            if name in _CURL_NUMBER_FLAGS:
                kind = "number"
            elif name in _CURL_PATH_FLAGS or name == "--output":
                kind = "path"
            elif name in ("-w", "--write-out"):
                kind = "writeout"
            if kind is not None:
                if inline is not None:
                    value: str | None = inline
                    step = 1
                elif index + 1 < len(tokens):
                    value = tokens[index + 1]
                    step = 2
                else:
                    return token
                if not value or (value.startswith("-") and value != "-"):
                    return token
                if kind == "number":
                    if not _curl_number_ok(value):
                        return value
                elif kind == "path":
                    if roots is None:
                        roots = _workdir_roots()
                    if not _curl_path_ok(value, roots):
                        return value
                elif not _curl_writeout_ok(value):
                    return value
                index += step
                continue
            return token
        return None

    def _opaque_argument_findings(self, tool_name: str, data: Any) -> list[tuple[str, str | None]]:
        """(field path, offending token) pairs for opaque argument fields."""
        findings: list[tuple[str, str | None]] = []

        def meaningful(value: Any) -> bool:
            if value is None:
                return False
            if isinstance(value, str):
                return bool(value.strip())
            if isinstance(value, (dict, list, tuple, set)):
                return bool(value)
            return True

        def walk(value: Any, prefix: str = ""):
            if isinstance(value, dict):
                for key, child in value.items():
                    name = str(key)
                    path = f"{prefix}.{name}" if prefix else name
                    if name.lower() in OPAQUE_ARGUMENT_FIELDS and meaningful(child):
                        if name.lower() in ("extra_args", "nmap_args", "options"):
                            bad = self._extra_args_violation(tool_name, child)
                            if bad is None:
                                continue
                            findings.append((path, bad or None))
                            continue
                        findings.append((path, None))
                    elif name == "params_json" and isinstance(child, str):
                        try:
                            walk(json.loads(child), path)
                        except (TypeError, ValueError):
                            pass
                    elif isinstance(child, (dict, list, tuple, set)):
                        walk(child, path)
            elif isinstance(value, (list, tuple, set)):
                for index, child in enumerate(value):
                    walk(child, f"{prefix}[{index}]")

        walk(data)
        seen: set[tuple[str, str | None]] = set()
        ordered: list[tuple[str, str | None]] = []
        for finding in findings:
            if finding not in seen:
                seen.add(finding)
                ordered.append(finding)
        return ordered

    def _opaque_argument_fields(self, tool_name: str, data: Any) -> list[str]:
        return sorted({path for path, _ in self._opaque_argument_findings(tool_name, data)})

    def _opaque_argument_detail(self, tool_name: str, data: Any) -> str:
        for path, token in self._opaque_argument_findings(tool_name, data):
            if token:
                return f"{path} '{token}'"
        return ""

    def extract_invocation_data(self, tool_name: str, args: dict[str, Any], *, wire_request: bool = False) -> InvocationData:
        capability = self.tool_capability(tool_name)
        # A transport supplies its final URL independently of the parent
        # tool's public argument names (e.g. protected_url vs target_url).
        target_fields = {"target", "endpoint", "url"} if wire_request else set(capability.get("target_fields") or [])
        strings = self._target_field_strings(args, target_fields)
        if tool_name == "bash":
            strings = [_mask_bash_option_values(value) for value in strings]
        urls: list[str] = []
        url_targets: list[str] = []
        standalone_targets: list[str] = []
        network_targets: list[str] = []
        range_targets: list[str] = []
        invalid_targets: list[str] = []
        methods: list[str] = []

        def add_target(candidate: str, strict_ip_expression: bool = False):
            candidate = candidate.strip().strip("'\"(){}")
            if not candidate:
                return
            if "$" in candidate:
                # Shell variables cannot be resolved statically. The literal
                # value (e.g. an H=10.0.0.1 assignment) is extracted on its
                # own; a command with no literal target still fails closed
                # via blocked_missing_target.
                return
            if candidate.lower().startswith(("http://", "https://", "ws://", "wss://")):
                try:
                    parsed = urlparse(candidate)
                    hostname = parsed.hostname
                    _ = parsed.port
                except ValueError:
                    invalid_targets.append(candidate)
                    return
                urls.append(candidate.rstrip("/"))
                if hostname:
                    url_targets.append(hostname)
                else:
                    invalid_targets.append(candidate)
                return

            parsed_range = _parse_ip_range(candidate)
            if parsed_range:
                _, _, normalized = parsed_range
                range_targets.append(normalized)
                standalone_targets.append(normalized)
                return

            if "/" in candidate and candidate.count("/") != 1:
                # Multi-segment paths (`/srv/10.0.0.1/recon/x`) are files,
                # not network expressions; a CIDR has exactly one slash.
                return
            if "/" in candidate and (":" in candidate or re.search(r"\d+\.\d+\.\d+\.\d+", candidate)):
                networks = _ip_expression_networks(candidate)
                if networks is None:
                    invalid_targets.append(candidate)
                    return
                network_targets.append(candidate)
                standalone_targets.append(candidate)
                return

            host = candidate
            if host.startswith("[") and "]" in host:
                host = host[1:host.index("]")]
            elif host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
                host = host.rsplit(":", 1)[0]
            try:
                standalone_targets.append(str(ipaddress.ip_address(host)))
                return
            except ValueError:
                pass
            if HOST_RE.fullmatch(host):
                if re.fullmatch(IPV4_TEXT, host):
                    invalid_targets.append(candidate)
                else:
                    standalone_targets.append(host)
            elif strict_ip_expression:
                invalid_targets.append(candidate)

        for value in strings:
            masked = list(value)

            def mask(start: int, end: int):
                masked[start:end] = " " * (end - start)

            for match in URL_RE.finditer(value):
                add_target(match.group("url"))
                mask(*match.span())

            residual = "".join(masked)
            for match in IPV4_RANGE_CANDIDATE_RE.finditer(residual):
                add_target(match.group("range"), strict_ip_expression=True)
                mask(*match.span())

            residual = "".join(masked)
            for match in IPV4_CIDR_CANDIDATE_RE.finditer(residual):
                network = match.group("network")
                # `10.0.0.1/recon/file.py` is a filesystem path whose segment
                # looks like an IP, not a CIDR expression. Only a single
                # slash with a numeric prefix length is a network candidate.
                if network.count("/") == 1 and network.rsplit("/", 1)[1].isdigit():
                    add_target(network, strict_ip_expression=True)
                mask(*match.span())

            residual = "".join(masked)
            for match in re.finditer(r"[^\s,;]+", residual):
                token = match.group(0).strip("'\"(){}")
                if ":" not in token:
                    continue
                if "/" in token or "-" in token:
                    add_target(token, strict_ip_expression=True)
                else:
                    try:
                        ipaddress.ip_address(token.strip("[]"))
                    except ValueError:
                        continue
                    add_target(token)
                mask(*match.span())

            residual = "".join(masked)
            for match in HOST_RE.finditer(residual):
                candidate = match.group(0)
                # Yol parcasi veya mevcut dosya (`/tmp/x/big.txt`, `./a.txt`)
                # hostname degildir — aksi halde wordlist'li komutlar
                # yanlis `blocked_scope` yer.
                prev = residual[match.start() - 1] if match.start() > 0 else ""
                if prev in ("/", "\\"):
                    continue
                if tool_name == "bash" and _is_local_filename(candidate):
                    continue
                if tool_name == "bash" and residual[: match.start()].rstrip().endswith(">"):
                    continue
                try:
                    if Path(candidate).is_file():
                        continue
                except OSError:
                    pass
                add_target(candidate)
        for key in ("method", "http_method"):
            if key in args and isinstance(args[key], str):
                methods.append(args[key].upper())

        if tool_name == "bash" and isinstance(args.get("command"), str):
            command = args["command"]
            methods.extend(m.upper() for m in HTTP_METHOD_RE.findall(command))
            try:
                tokens = shlex.split(command)
            except ValueError:
                invalid_targets.append("malformed bash command")
                tokens = []
            skip_next = False
            for token in tokens:
                if skip_next:
                    skip_next = False
                    continue
                if re.fullmatch(r"\d*>>?|&>>?", token):
                    skip_next = True
                    continue
                if re.match(r"^\d*>>?", token):
                    continue
                if _is_local_filename(token):
                    continue
                if token in _BASH_OPTION_VALUE_FLAGS or token.startswith("--header=") \
                        or token.startswith("--user-agent=") or token.startswith("--cookie="):
                    if token in _BASH_OPTION_VALUE_FLAGS:
                        skip_next = True
                    continue
                add_target(token)

        return {
            "targets": sorted(set(url_targets) | set(standalone_targets)),
            "url_targets": sorted(set(url_targets)),
            "standalone_targets": sorted(set(standalone_targets)),
            "network_targets": sorted(set(network_targets)),
            "range_targets": sorted(set(range_targets)),
            "invalid_targets": sorted(set(invalid_targets)),
            "urls": sorted(set(urls)),
            "methods": sorted(set(methods)),
            "unsafe_arguments": self._opaque_argument_fields(tool_name, args),
            "unsafe_argument_detail": self._opaque_argument_detail(tool_name, args),
        }

    def _is_osint_target(self, target: str) -> bool:
        return any(target == domain or target.endswith(f".{domain}") for domain in OSINT_ALLOWLIST)

    def _is_public_lab(self, target: str) -> bool:
        return any(target == domain or target.endswith(f".{domain}") for domain in PUBLIC_LABS)

    def _is_excluded_host(self, host: str) -> bool:
        host = (host or "").strip().lower()
        if not host:
            return False
        for excluded in self.scope["excluded"]:
            if host == excluded or host.endswith(f".{excluded}"):
                return True
        return False

    def _scope_allows(self, target: str, url: str = "", allow_public_exemptions: bool = True) -> bool:
        if not target and not url:
            return True
        try:
            url_host = urlparse(url).hostname or "" if url else ""
        except ValueError:
            url_host = ""
        if self._is_excluded_host(target) or self._is_excluded_host(url_host):
            return False
        target = target.strip()
        url = url.rstrip("/")
        if self.program_policy.get("allow_loopback", True) and _looks_like_loopback(target):
            return True
        if allow_public_exemptions and self.program_policy.get("allow_osint", True) and self._is_osint_target(target):
            return True
        if allow_public_exemptions and self.program_policy.get("allow_public_labs", True) and self._is_public_lab(target):
            return True

        if url and any(self._url_matches_prefix(url, prefix) for prefix in self.scope["url_prefixes"]):
            return True
        if target in self.scope["targets"]:
            return True
        if target in self.scope["domains"]:
            return True
        for domain in self.scope["domains"]:
            if target.endswith(f".{domain}"):
                return not self.scope["explicit_only"]

        requested_networks = _ip_expression_networks(target)
        if requested_networks is not None:
            allowed_networks = []
            for scoped_target in set(self.scope["cidr_ranges"]) | set(self.scope["targets"]):
                networks = _ip_expression_networks(scoped_target)
                if networks:
                    allowed_networks.extend(networks)
            return bool(allowed_networks) and all(
                any(_network_is_within(requested, allowed) for allowed in allowed_networks)
                for requested in requested_networks
            )
        return False

    def _url_matches_prefix(self, candidate_url: str, scope_prefix: str) -> bool:
        try:
            candidate = urlparse(candidate_url)
            scope = urlparse(_parse_scope_url_prefix(scope_prefix))
            candidate_port = candidate.port
            scope_port = scope.port
        except ValueError:
            return False
        if scope.scheme and candidate.scheme and scope.scheme != candidate.scheme:
            return False
        if scope.hostname and candidate.hostname != scope.hostname:
            return False
        defaults = {"http": 80, "https": 443, "ws": 80, "wss": 443}
        candidate_effective_port = candidate_port if candidate_port is not None else defaults.get(candidate.scheme)
        scope_effective_port = scope_port if scope_port is not None else defaults.get(scope.scheme)
        if scope_effective_port is not None and candidate_effective_port != scope_effective_port:
            return False
        scope_path = (scope.path or "").rstrip("/")
        candidate_path = (candidate.path or "").rstrip("/")
        if not scope_path:
            return True
        return candidate_path == scope_path or candidate_path.startswith(scope_path + "/")

    def _rate_limit_for(self, tool_name: str) -> tuple[int, int]:
        profile = self.program_policy.get("rate_limit_profile") or self.scope.get("raw", {}).get("rules", {}).get("rate_limit")
        table = self.program_policy["rate_limits"]
        selected = table.get(profile or "default", table["default"])
        for pattern, override in table.get("overrides", {}).items():
            if fnmatch(tool_name, pattern):
                return int(override.get("window_seconds", selected["window_seconds"])), int(override.get("max_calls", selected["max_calls"]))
        return int(selected["window_seconds"]), int(selected["max_calls"])

    def _stuck_probe(self, tool_name: str, urls: list[str], targets: list[str]) -> str | None:
        """Stuck-detector karari. Engelliyorsa gerekce detayi, yoksa None.

        Cagri zincirinde bu noktaya yalnizca onceki kontrolleri gecen
        cagrilar ulasir; sayaca yalnizca onlar islenir.
        """
        if _EVALUATE_PROBE is None:
            return None
        conn = self._connect()
        try:
            allowed, detail = _EVALUATE_PROBE(conn, tool_name, urls, targets)
        finally:
            conn.close()
        return None if allowed else detail

    def _js_route_queue(self, tool_name: str, args: dict[str, Any],
                        urls: list[str], targets: list[str]) -> str | None:
        """Composed JS templates probed edilmeden jwt/nmap/fuzz kacisini kes."""
        if _EVALUATE_JS_QUEUE is None:
            return None
        conn = self._connect()
        try:
            allowed, detail = _EVALUATE_JS_QUEUE(conn, tool_name, args, urls, targets)
        finally:
            conn.close()
        return None if allowed else detail

    def _reserve_rate_limit(self, tool_name: str, weight: int) -> bool:
        window_seconds, max_calls = self._rate_limit_for(tool_name)
        now = _utc_now()
        cutoff = (now - timedelta(seconds=window_seconds)).isoformat()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "DELETE FROM rate_limit_reservations WHERE tool_name=? AND timestamp<=?",
                (tool_name, cutoff),
            )
            used = conn.execute(
                "SELECT COALESCE(SUM(weight), 0) FROM rate_limit_reservations "
                "WHERE tool_name=? AND timestamp>?",
                (tool_name, cutoff),
            ).fetchone()[0]
            if used + weight > max_calls:
                conn.commit()
                return False
            conn.execute(
                "INSERT INTO rate_limit_reservations (timestamp, tool_name, weight) VALUES (?, ?, ?)",
                (now.isoformat(), tool_name, weight),
            )
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    _MCP_TOOL_TOKEN_RE = re.compile(
        r"(?:kali-tools|hunter|validator|web-advanced|llm-security|browser|"
        r"memory-server|rag-engine|reasoning|osint-tools|chain_runner|"
        r"agent-browse|ctf-platform|ad-tools|container-tools|telemetry|otp)"
        r"_[a-z0-9_]+"
    )

    def _task_spec_violation(self, tool_name: str, args: dict[str, Any]) -> str | None:
        """Check worker delegation with the same contract as TaskSpec rendering."""
        if tool_name != "task":
            return None
        subagent = ""
        prompts = []
        for key, value in args.items():
            lowered = str(key).lower()
            if lowered in ("subagent_type", "subagenttype", "subagent", "agent"):
                subagent = str(value or "")
            elif lowered in ("prompt", "description", "task", "message"):
                prompts.append(str(value or ""))
        if "worker" not in subagent.lower():
            return None
        try:
            try:
                from .orchestration_spec import validate_worker_prompt
            except ImportError:
                from orchestration_spec import validate_worker_prompt
            errors = validate_worker_prompt("\n".join(prompts))
        except Exception:
            return "worker TaskSpec validator unavailable"
        return "; ".join(errors) if errors else None

    _FUTILITY_REASONS = frozenset({
        "blocked_task_spec",
        "blocked_secret_path",
        "blocked_missing_target",
        "blocked_invalid_target",
        "blocked_unknown_tool",
        "blocked_unsafe_arguments",
    })

    def _bash_budget_exceeded(self) -> bool:
        try:
            max_calls = int(self.program_policy.get("bash_budget_max_calls", 50))
            window = int(self.program_policy.get("bash_budget_window_seconds", 3600))
        except (TypeError, ValueError):
            return False
        if max_calls <= 0:
            return False
        cutoff = (_utc_now() - timedelta(seconds=max(1, window))).isoformat()
        conn = self._connect()
        try:
            used = conn.execute(
                "SELECT COUNT(*) FROM audit_log "
                "WHERE tool_name='bash' AND result='allowed' AND timestamp>?",
                (cutoff,),
            ).fetchone()[0]
        finally:
            conn.close()
        return int(used) >= max_calls

    def _time_budget_exceeded(self, targets: list[str]) -> str | None:
        """Wall-clock budget per target host; detail string when exceeded.

        The clock is sessionized: it starts at the first allowed targeted
        call of the current activity cluster for the host. A gap longer
        than time_budget_idle_reset_seconds ends the cluster, so a finished
        run never eats the next run's budget. This is policy state, not an
        agent error, so the marker stays out of _FUTILITY_REASONS (no
        repeat brake): hitting the budget ends the run, it is not retried.
        """
        try:
            max_seconds = int(self.program_policy.get("time_budget_max_seconds", 3600))
            idle_reset = int(self.program_policy.get("time_budget_idle_reset_seconds", 900))
        except (TypeError, ValueError):
            return None
        if max_seconds <= 0:
            return None
        idle_reset = max(1, idle_reset)
        hosts: list[str] = []
        for target in targets:
            host = str(target).strip().lower()
            if host and host not in hosts:
                hosts.append(host)
        if not hosts:
            return None
        now = _utc_now()
        conn = self._connect()
        try:
            for host in hosts:
                rows = conn.execute(
                    "SELECT timestamp FROM audit_log WHERE result='allowed' "
                    "AND (target=? OR targets_json LIKE ?) "
                    "ORDER BY timestamp DESC LIMIT 500",
                    (host, f'%"{host}"%'),
                ).fetchall()
                stamps: list[datetime] = []
                for row in rows:
                    try:
                        stamps.append(datetime.fromisoformat(str(row[0])))
                    except (TypeError, ValueError):
                        continue
                if not stamps:
                    continue
                if (now - stamps[0]).total_seconds() > idle_reset:
                    continue  # last activity is stale: fresh clock
                cluster_start = stamps[0]
                for newer, older in zip(stamps, stamps[1:]):
                    if (newer - older).total_seconds() > idle_reset:
                        break
                    cluster_start = older
                elapsed = (now - cluster_start).total_seconds()
                if elapsed >= max_seconds:
                    return f"{host}: {int(elapsed)}s elapsed >= {max_seconds}s time budget"
        finally:
            conn.close()
        return None

    def _repeat_brake(self, tool_name: str, reason: str) -> bool:
        """Third consecutive identical agent-error block becomes a hard stop.

        Policy-state blocks (scope, approval, rate limit) are excluded: they
        may legitimately repeat. Agent-error blocks repeating means the
        caller is looping, not progressing.
        """
        if reason not in self._FUTILITY_REASONS:
            return False
        conn = self._connect(row_factory=True)
        try:
            rows = conn.execute(
                "SELECT result, metadata FROM audit_log WHERE tool_name=? "
                "ORDER BY id DESC LIMIT 8",
                (tool_name,),
            ).fetchall()
        finally:
            conn.close()
        trailing = 0
        for row in rows:
            stored = row["result"]
            if stored == reason:
                trailing += 1
                continue
            if stored == "blocked_repeat_brake":
                try:
                    meta = json.loads(row["metadata"] or "{}")
                except (TypeError, ValueError):
                    meta = {}
                if meta.get("blocked_reason") == reason:
                    trailing += 1
                    continue
            break
        return trailing >= 2

    def grant_approval(self, tool_pattern: str = "*", target_pattern: str = "*",
                       ttl_seconds: int = 3600, reason: str = "") -> ApprovalGrant:
        created_at = _utc_now()
        expires_at = created_at + timedelta(seconds=max(60, ttl_seconds))
        conn = self._connect()
        cur = conn.execute(
            "INSERT INTO approval_grants (tool_pattern, target_pattern, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (tool_pattern, target_pattern, reason, created_at.isoformat(), expires_at.isoformat()),
        )
        grant_id = cur.lastrowid
        conn.commit()
        conn.close()
        return ApprovalGrant(grant_id, tool_pattern, target_pattern, reason, expires_at.isoformat())

    def revoke_approval(self, approval_id: int) -> bool:
        conn = self._connect()
        cur = conn.execute(
            "UPDATE approval_grants SET revoked_at=? WHERE id=? AND revoked_at=''",
            (_utc_now().isoformat(), approval_id),
        )
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    def list_approvals(self, active_only: bool = True) -> list[dict[str, Any]]:
        conn = self._connect(row_factory=True)
        if active_only:
            rows = conn.execute(
                "SELECT * FROM approval_grants WHERE revoked_at='' AND expires_at>? ORDER BY id DESC",
                (_utc_now().isoformat(),),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM approval_grants ORDER BY id DESC").fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def _approval_target_allows(self, pattern: str, target: str) -> bool:
        if pattern == "*":
            return True
        requested_networks = _ip_expression_networks(target)
        if requested_networks is not None:
            approved_networks = _ip_expression_networks(pattern)
            if approved_networks is not None:
                return all(
                    any(_network_is_within(requested, approved) for approved in approved_networks)
                    for requested in requested_networks
                )
            try:
                ipaddress.ip_address(target)
            except ValueError:
                return False
        return fnmatch(target, pattern)

    def _has_approval(self, tool_name: str, targets: list[str]) -> bool:
        now = _utc_now().isoformat()
        conn = self._connect(row_factory=True)
        rows = conn.execute(
            "SELECT * FROM approval_grants WHERE revoked_at='' AND expires_at>? ORDER BY id DESC",
            (now,),
        ).fetchall()
        conn.close()
        matching = [row for row in rows if fnmatch(tool_name, row["tool_pattern"])]
        if not targets:
            return any(row["target_pattern"] == "*" for row in matching)
        if any(row["target_pattern"] == "*" for row in matching):
            return True
        for target in targets:
            if not any(self._approval_target_allows(row["target_pattern"], target) for row in matching):
                return False
        return True

    def _program_requires_approval(self, tool_name: str) -> bool:
        explicit = self.program_policy.get("approval_required_tools", [])
        if any(fnmatch(tool_name, pattern) for pattern in explicit):
            return True
        capability = self.tool_capability(tool_name)
        active = bool(
            capability.get("network")
            or capability.get("requires_scope")
            or capability.get("mutates_remote_state")
        )
        return bool(self.program_policy.get("active_requires")) and active and tool_name.startswith(ACTIVE_TOOL_PREFIXES)

    def _approval_policy_applies(self, tool_name: str) -> bool:
        return bool(self.tool_capability(tool_name).get("requires_approval")) or self._program_requires_approval(tool_name)

    def _requires_approval(self, tool_name: str, targets: list[str]) -> bool:
        capability = self.tool_capability(tool_name)
        if targets and all(_looks_like_loopback(target) for target in targets):
            return False
        if self._program_requires_approval(tool_name):
            return True
        if capability.get("requires_approval"):
            return True
        return False

    def _missing_required_headers(self, tool_name: str, args: dict[str, Any],
                                    urls: list[str], *, wire_request: bool = False) -> list[str]:
        """Program profili header sart kosmus ve URL'li istekte header yoksa eksikleri doner."""
        required = self.program_policy.get("required_request_headers") or {}
        if not required or not urls:
            return []
        in_program = False
        for url in urls:
            try:
                host = urlparse(url).hostname or ""
            except ValueError:
                continue
            if not host or _looks_like_loopback(host):
                continue
            if self._is_osint_target(host) or self._is_public_lab(host):
                continue
            if self._scope_allows(host, url, allow_public_exemptions=False):
                in_program = True
                break
        if not in_program:
            return []
        if tool_name == "bash":
            haystack = str(args.get("command", "") or "")
        elif tool_name == "kali-tools_curl_request":
            haystack = " ".join(str(args.get(k, "") or "") for k in ("headers", "extra_args"))
        elif wire_request or tool_name in {"chain_runner_http_get", "chain_runner_http_post",
                           "chain_runner_mailbox_poll", "chain_runner_batch_probe",
                           "chain_runner_race_burst"}:
            # The chain transport supplies the final headers after session
            # cookies/tokens and per-item overrides have been applied.
            actual = args.get("headers") or {}
            actual = {str(k).lower(): str(v) for k, v in actual.items()} if isinstance(actual, dict) else {}
            handle = (os.environ.get("HACKERONE_HANDLE") or "").strip()
            return [name for name, template in required.items()
                    if ("{handle}" in template and not handle)
                    or actual.get(name.lower()) != template.replace("{handle}", handle)]
        else:
            return []
        handle = (os.environ.get("HACKERONE_HANDLE") or "").strip()
        missing = []
        for name, template in required.items():
            if "{handle}" in template and not handle:
                missing.append(f"{name} (set HACKERONE_HANDLE)")
                continue
            if template.replace("{handle}", handle) not in haystack:
                missing.append(name)
        return missing

    def _bash_destructive_denied(self, args: dict[str, Any]) -> bool:
        command = str(args.get("command", ""))
        bad = [" rm ", " rm-", "mkfs", "shutdown", "reboot", "git reset", "git clean"]
        lower = f" {command.lower()} "
        return any(token in lower for token in bad)

    def _log(self, tool_name: str, action: str, targets: list[str], permission: str,
             scope_valid: bool, result: str, metadata: dict[str, Any]):
        safe_targets = [_redact_urls_in_text(str(target)) for target in targets]
        safe_metadata = _redact_audit_value(metadata)
        conn = self._connect()
        conn.execute(
            "INSERT INTO audit_log (timestamp, tool_name, action, target, targets_json, scope_valid, permission, result, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _utc_now().isoformat(),
                tool_name,
                action,
                safe_targets[0] if safe_targets else "",
                json.dumps(safe_targets),
                scope_valid,
                permission,
                result,
                json.dumps(safe_metadata, ensure_ascii=False),
            ),
        )
        conn.commit()
        conn.close()

    _WRITE_TOOLS = frozenset({
        "edit", "write", "patch", "multiedit", "apply_patch", "notebookedit",
    })
    _INLINE_WRITE_RE = re.compile(
        r"(?:\.write_text\s*\(|\.write_bytes\s*\(|open\s*\([^)]*,\s*['\"][wax+]|"
        r"shutil\.(?:copy|copy2|copyfile|move)\s*\(|os\.(?:replace|rename)\s*\(|"
        r"fs\.(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\()",
        re.I,
    )
    _STRING_LITERAL_PATH_RE = re.compile(
        r"""['"]((?:\.?\.?/)?[A-Za-z0-9_./-]{2,256})['"]"""
    )

    def _extract_write_candidates(self, tool_name: str, args: dict[str, Any]) -> tuple[list[str], bool]:
        """Extract candidate target file paths from write-capable tools or bash commands.

        Returns (candidates, has_unscoped_inline_write).
        """
        candidates: list[str] = []
        has_unscoped_inline_write = False
        if tool_name in self._WRITE_TOOLS:
            lowered = {str(k).lower(): v for k, v in args.items()}
            for key in ("filepath", "file", "path", "filename", "target_file", "notebook_path"):
                for variant in {key, key.replace("_", "")}:
                    value = lowered.get(variant)
                    if isinstance(value, str) and value.strip():
                        candidates.append(value)
                for prefix in ("new_", "old_", "dest_", "target_"):
                    value = lowered.get(prefix + key)
                    if isinstance(value, str) and value.strip():
                        candidates.append(value)
            for list_key in ("edits", "files", "changes"):
                items = lowered.get(list_key)
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            sub, _ = self._extract_write_candidates("edit", item)
                            candidates.extend(sub)
            for patch_key in ("patch", "patchtext", "diff", "content"):
                patch_val = lowered.get(patch_key)
                if isinstance(patch_val, str) and tool_name in ("patch", "apply_patch"):
                    for m in re.finditer(r"^\+\+\+\s+(?:b/)?([^\s\t\r\n]+)", patch_val, re.M):
                        if m.group(1) != "/dev/null":
                            candidates.append(m.group(1))
                    for m in re.finditer(r"^\*\*\*\s+(?:Update|Add|Delete)\s+File:\s*([^\r\n]+)", patch_val, re.M):
                        candidates.append(m.group(1).strip())
        elif tool_name == "bash":
            command = args.get("command", "")
            if isinstance(command, str) and command.strip():
                # 1. Shell redirections > and >> (ignore >&2, 2>&1)
                for match in re.finditer(r"(?<![0-9>&])>{1,2}(?!&)\s*([^\s;|&<>]+)", command):
                    target = match.group(1).strip("'\"")
                    if target and not target.startswith("&"):
                        candidates.append(target)
                # 2. tee [-a] <file>
                for match in re.finditer(r"\btee\b(?:\s+-[a-zA-Z]+)*\s+([^\s;|&<>]+)", command):
                    candidates.append(match.group(1))
                # 3. sed -i / perl -i in-place edits
                for match in re.finditer(r"\b(?:sed|perl)\b[^\n;|]*?\s-[a-zA-Z]*i[a-zA-Z]*(?:\s+'[^']*'|\s+\"[^\"]*\")*\s+([^\s;|&<>'\"]+)", command):
                    candidates.append(match.group(1))
                # 4. dd of=<file>
                for match in re.finditer(r"\bof=([^\s;|&<>]+)", command):
                    candidates.append(match.group(1))
                # 5. curl -o/--output, wget -O/--output-document
                for match in re.finditer(r"(?<![A-Za-z0-9_-])(?:-o|--output|-O|--output-document)(?:=|\s+)('[^']*'|\"[^\"]*\"|[^\s;|&<>]+)", command):
                    candidates.append(match.group(1))
                # 6. cp / mv / install destination (last argument before separator)
                for seg in re.split(r"[;&|]+|\n", command):
                    seg_s = seg.strip()
                    m_cp = re.match(r"^(?:sudo\s+)?(?:cp|mv|install)\b\s+(.+)$", seg_s)
                    if m_cp:
                        tokens = [t.strip("'\"") for t in re.findall(r"'[^']*'|\"[^\"]*\"|\S+", m_cp.group(1))]
                        non_flags = [t for t in tokens if not t.startswith("-")]
                        if len(non_flags) >= 2:
                            candidates.append(non_flags[-1])
                # 7. Inline python/node/ruby/perl file writes
                if self._INLINE_WRITE_RE.search(command):
                    lit_paths = [
                        m.group(1) for m in self._STRING_LITERAL_PATH_RE.finditer(command)
                        if "/" in m.group(1) or m.group(1).endswith((".json", ".py", ".js", ".md", ".db", ".sh", ".yaml", ".yml", ".txt"))
                    ]
                    if lit_paths:
                        candidates.extend(lit_paths)
                    else:
                        has_unscoped_inline_write = True
        return candidates, has_unscoped_inline_write

    def _is_Protected_governance_path(self, resolved: str, scope_path: str, policy_path: str) -> bool:
        """Governance, scope, policy, and audit DB files are always read-only to agent tools."""
        name = os.path.basename(resolved)
        if resolved.endswith("/scope.json") or (name.startswith("scope.") and name.endswith(".json")):
            return True
        if resolved.endswith("/program-policy.json") or (name.startswith("program-policy.") and name.endswith(".json")):
            return True
        if resolved.endswith("/audit.db"):
            return True
        if scope_path and resolved == scope_path:
            return True
        if policy_path and resolved == policy_path:
            return True
        return False

    def _blind_write_violation(self, tool_name: str, args: dict[str, Any]) -> str | None:
        """Kor tur izolasyonu ve yonetisim dosyasi korumasi.

        - .codex/scope*.json, .codex/program-policy*.json ve audit.db her zaman salt-okunurdur.
        - blind_mode acikken (scope.json, program-policy.json veya CCO_BLIND_MODE=1)
          proje agacina (repo_root) yazim tamamen yasaktir; yalnizca CCO_WORKDIR
          (varsayilan ~/cco-work), /tmp ve /dev/null yazilabilir.
        Donus: ihlal nedeni ya da None.
        """
        raw = self.scope.get("raw", {}) or {}
        env_blind = os.environ.get("CCO_BLIND_MODE", "").strip().lower() in {"1", "true", "yes", "on"}
        policy_blind = bool((self.program_policy or {}).get("blind_mode", False))
        blind_mode = bool(raw.get("blind_mode", False)) or env_blind or policy_blind

        candidates, has_unscoped_inline_write = self._extract_write_candidates(tool_name, args)
        if not candidates and not has_unscoped_inline_write:
            return None
        if blind_mode and has_unscoped_inline_write and not candidates:
            return "blind mode: inline script file writes without explicit workdir path are denied"

        try:
            workdir = Path(os.environ.get("CCO_WORKDIR", "~/cco-work")).expanduser().resolve()
        except Exception:
            workdir = Path.home() / "cco-work"
        try:
            tmpdir = Path(os.environ.get("TMPDIR", "/tmp")).resolve()
        except Exception:
            tmpdir = Path("/tmp")
        repo = self.repo_root.resolve()
        scope_path = str(self.scope_file.resolve()) if self.scope_file else ""
        policy_path = str(self.program_policy_file.resolve()) if self.program_policy_file else ""

        for text in candidates:
            token = text.strip().strip("'\"")
            if not token or len(token) > 1024:
                continue
            if token in ("/dev/null", "nul"):
                continue
            path = Path(token).expanduser()
            if not path.is_absolute():
                path = repo / token
            try:
                resolved = str(path.resolve())
            except Exception:
                continue
            if self._is_Protected_governance_path(resolved, scope_path, policy_path):
                return "scope/policy file is read-only"
            if not blind_mode:
                continue
            allowed = False
            for base in (workdir, tmpdir):
                try:
                    if os.path.commonpath([resolved, str(base)]) == str(base):
                        allowed = True
                        break
                except ValueError:
                    continue
            if not allowed:
                return f"blind mode: writes outside workdir are denied ({token})"
        return None

    @staticmethod
    def _unwrap_sandbox_command(command: str) -> str | None:
        """Inner command of a gate-wrapped bwrap call, else None.

        The plugin validates the original command, rewrites it into a
        bwrap invocation (whose mask list names .cco/.ssh), and the
        wrapped text can re-enter validation. Validating the wrapper
        scans the gate's own mask paths and self-blocks
        (blocked_secret_path). Validate the payload instead; the secret
        scan still applies to it in full.
        """
        if "CCO_BASH_SANDBOXED" not in command:
            return None
        try:
            tokens = shlex.split(command)
        except ValueError:
            return None
        if "/bin/bash" not in tokens:
            return None
        dash_c = [i for i, tok in enumerate(tokens) if tok == "-c"]
        if not dash_c or dash_c[-1] + 1 >= len(tokens):
            return None
        return tokens[dash_c[-1] + 1]

    def validate_tool_invocation(self, tool_name: str, args: dict[str, Any] | None = None,
                                 action: str = "execute", extra_metadata: dict[str, Any] | None = None,
                                 *, _wire_request: bool = False, _policy_preflight: bool = False) -> dict[str, Any]:
        """Check current policy; trusted previews do not debit request counters.

        A caller using _policy_preflight must arrange a full check at actual
        transport time. Tool arguments cannot select this internal mode.
        """
        self.reload()
        args = args or {}
        if tool_name == "bash" and isinstance(args.get("command"), str):
            inner = self._unwrap_sandbox_command(str(args["command"]))
            if inner is not None:
                args = {**args, "command": inner}
            args = {**args, "command": _mask_auth_attestation(args["command"])}
        metadata = extra_metadata or {}
        invocation = self.extract_invocation_data(tool_name, args, wire_request=_wire_request)
        targets = invocation["targets"]
        url_targets = invocation.get("url_targets", [])
        standalone_targets = invocation.get("standalone_targets", [])
        network_targets = invocation.get("network_targets", [])
        range_targets = invocation.get("range_targets", [])
        invalid_targets = invocation.get("invalid_targets", [])
        unsafe_arguments = invocation.get("unsafe_arguments", [])
        unsafe_detail = invocation.get("unsafe_argument_detail", "")
        urls = invocation["urls"]
        methods = invocation["methods"]
        # Local bash (orchestration CLIs, read-only file work) carries no
        # network target: keep it out of scope/approval/time accounting.
        local_bash = tool_name == "bash" and _bash_is_local(
            str(args.get("command", "")), urls, targets)
        if local_bash:
            targets, url_targets, standalone_targets = [], [], []
            network_targets, urls, methods = [], [], []
        permission = self._match_tool_rule(tool_name, action)
        capability = self.tool_capability(tool_name)
        request_weight = 1 if _wire_request else int(capability.get("request_multiplier", 1))
        requires_approval = self._requires_approval(tool_name, targets)
        allow_public_exemptions = not self._approval_policy_applies(tool_name)

        scope_valid = True
        missing_required_target = (
            bool(capability.get("requires_scope"))
            and tool_name not in LOCAL_SAFE_TOOLS
            and not targets
            and not urls
        )
        if missing_required_target or invalid_targets:
            scope_valid = False
        for url in urls:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname
            except ValueError:
                hostname = None
            if not hostname or not self._scope_allows(
                hostname, url, allow_public_exemptions=allow_public_exemptions
            ):
                scope_valid = False
                break
        if scope_valid:
            for target in standalone_targets:
                if not self._scope_allows(target, "", allow_public_exemptions=allow_public_exemptions):
                    scope_valid = False
                    break
        # If a URL was parsed, its hostname is checked with the URL above. Do not
        # re-check that hostname as a host-only target, otherwise URL-prefix
        # scopes would be widened or falsely rejected.
        if scope_valid:
            url_target_set = set(url_targets)
            for target in targets:
                if target in url_target_set or target in set(standalone_targets):
                    continue
                if not self._scope_allows(target, "", allow_public_exemptions=allow_public_exemptions):
                    scope_valid = False
                    break

        # WS7 mühürlü mutasyon: write_set etkinken PUT/PATCH/DELETE yalnız
        # mühürlü nesne + koşu kimliği ile geçer (metot yasağını da aşar).
        sealed_mutation_ok = False
        write_rule = self.program_policy.get("write_set") or {}
        if (_wire_request and isinstance(write_rule, dict)
                and write_rule.get("enabled") is True
                and any(method in {"PUT", "PATCH", "DELETE"} for method in methods) and urls):
            try:
                import write_set as _write_set
                now_env = os.environ.get("CCO_WRITE_SET_NOW", "")
                now = float(now_env) if now_env else None
                fingerprint = _caller_fingerprint(args)
                db_path = _write_set.default_db_path(self.cco_home)
                sealed_mutation_ok = all(
                    _write_set.mutation_permitted(
                        db_path, url, fingerprint, now=now,
                        run_id=os.environ.get('CCO_RUN_ID'),
                        session_id=os.environ.get('CCO_SESSION_ID'))[0]
                    for url in urls)
            except Exception:
                sealed_mutation_ok = False

        guidance = ""
        bg_job = False
        bg_mode = "approval"
        fuzz_estimate, fuzz_details = 0, []
        if tool_name == "bash" and _EGRESS is not None:
            command_text = args.get("command", "")
            if not isinstance(command_text, str):
                command_text = ""
            try:
                bg_job = _EGRESS.is_background_network_job(command_text, urls)
                bg_mode = _EGRESS.background_jobs_mode(self.program_policy)
                fuzz_estimate, fuzz_details = _EGRESS.estimate_fuzz_requests(
                    command_text, urls)
            except Exception:
                bg_job, fuzz_estimate, fuzz_details = False, 0, []
        fuzz_budget = _EGRESS.fuzz_budget(self.program_policy) if _EGRESS else 5000

        result = "allowed"
        reason = "allowed"
        secret_violation = self._secret_path_violation(tool_name, args)
        task_spec_violation = self._task_spec_violation(tool_name, args)
        known_tool = self._is_known_tool(tool_name)
        blind_violation = self._blind_write_violation(tool_name, args)
        if blind_violation and permission != "deny":
            result = "blocked_blind_write"
            reason = f"blocked_blind_write: {blind_violation}"
            guidance = (
                "Blind engagement: project tree is read-only. Write run "
                "artefacts under the workdir (~/cco-work) or /tmp instead."
            )
        if tool_name in LOCAL_SAFE_TOOLS and not targets and tool_name != "bash":
            scope_valid = True
        # The decision chain must also run for local-safe tools: secret-path
        # and unknown-tool denies would otherwise be skipped entirely.
        if result == "blocked_blind_write":
            pass
        elif secret_violation:
            result = reason = "blocked_secret_path"
            guidance = (
                f"Secret/credential paths are denied to agent tools ({secret_violation}). "
                "Use the credential vault APIs instead of reading secret files directly."
            )
        elif task_spec_violation:
            result = reason = "blocked_task_spec"
            guidance = (
                f"Worker delegation rejected: {task_spec_violation}. Add a "
                "`Tools:` line with exact MCP tool names (e.g. "
                "kali-tools_curl_request), or `Tools: bash (no MCP equivalent: <why>)`."
            )
        elif not known_tool:
            result = reason = "blocked_unknown_tool"
            guidance = (
                "Tool is not registered in config/tool-capabilities.json and is "
                "not a native tool. Register it explicitly (fail-closed) before use."
            )
        elif permission == "deny":
            result = reason = "blocked_permission"
        elif tool_name == "bash" and self._bash_destructive_denied(args):
            result = reason = "blocked_destructive_bash"
        elif unsafe_arguments:
            result = "blocked_unsafe_arguments"
            reason = "blocked_unsafe_arguments" + (f": {unsafe_detail}" if unsafe_detail else "")
            if tool_name == "kali-tools_curl_request":
                guidance = _CURL_GUIDANCE
        elif local_bash:
            pass  # local-only bash: allowed, no target accounting
        elif invalid_targets:
            result = reason = "blocked_invalid_target"
        elif missing_required_target:
            result = reason = "blocked_missing_target"
        elif not scope_valid:
            result = reason = "blocked_scope"
        elif (any(method in {m.upper() for m in self.program_policy.get("blocked_http_methods", [])}
                  for method in methods)
              and not sealed_mutation_ok
              and not (_wire_request and tool_name == "kali-tools_member_login"
                       and methods == ["POST"] and len(urls) == 1
                       and self.program_policy.get("member_login", {}).get("test_data_only") is True
                       and urls[0] == self.program_policy["member_login"].get("login_url"))):
            result = reason = "blocked_http_method"
        elif (_wire_request and isinstance(write_rule, dict)
              and write_rule.get("enabled") is True
              and any(method in {"PUT", "PATCH", "DELETE"} for method in methods)
              and not sealed_mutation_ok):
            result = reason = "blocked_unsealed_mutation"
            guidance = (
                "Mutation requires a sealed test object (WS7 write_set): create "
                "it with a test identity, seal it, then mutate it with a run "
                "identity before the seal expires."
            )
        elif any(
            any(path_fragment in parsed.path for path_fragment in self.program_policy.get("blocked_paths", []))
            for parsed in (urlparse(url) for url in urls)
        ):
            result = reason = "blocked_path"
        elif (missing_headers := self._missing_required_headers(tool_name, args, urls, wire_request=_wire_request)):
            result = reason = "blocked_missing_headers"
            guidance = (
                "Program policy requires these request headers: "
                + ", ".join(missing_headers)
                + ". Add -H 'User-Agent: HackerOne/<handle>' -H 'X-HackerOne: <handle>' "
                "(curl) or the headers= argument (curl_request tool)."
            )
        elif any(fnmatch(tool_name, pattern) for pattern in self.program_policy.get("denied_tools", [])):
            result = reason = "blocked_program_policy"
        elif bg_job and bg_mode == "deny":
            result = reason = "blocked_background_job"
            guidance = (
                "Unsupervised background network jobs are denied by program "
                "policy. Run the probe in the foreground with a bounded wordlist, "
                "or ask the operator to set background_network_jobs=approval and "
                "issue an explicit grant."
            )
        elif fuzz_estimate > fuzz_budget:
            result = reason = "blocked_fuzz_budget"
            detail = "; ".join(fuzz_details) if fuzz_details else "wordlist sweep"
            guidance = (
                f"Estimated ~{fuzz_estimate} requests ({detail}) exceeds the "
                f"per-call fuzz budget ({fuzz_budget}). First validate the bypass "
                "against a KNOWN control file, then sweep small->medium with "
                "evidence; chunk large sweeps into budgeted calls."
            )
        elif requires_approval and not self._has_approval(tool_name, targets):
            result = reason = "blocked_approval_required"
        elif (queue_detail := self._js_route_queue(tool_name, args, urls, targets)) is not None:
            result = "blocked_js_route_queue"
            reason = f"blocked_js_route_queue: {queue_detail}"
            guidance = queue_detail
        elif not _policy_preflight and (stuck_detail := self._stuck_probe(tool_name, urls, targets)) is not None:
            result = "blocked_stuck_detected"
            reason = f"blocked_stuck_detected: {stuck_detail}"
        elif tool_name == "bash" and self._bash_budget_exceeded():
            result = reason = "blocked_bash_budget"
            guidance = (
                "Bash call budget for this window is exhausted. Stop hand-rolling "
                "shell probes: use the registered MCP tools (kali-tools_*, hunter_*, "
                "validator_*, web-advanced_*, llm-security_*) for this phase, or end "
                "the phase and report back."
            )
        elif (time_detail := self._time_budget_exceeded(targets)) is not None:
            result = "blocked_time_budget"
            reason = f"blocked_time_budget: {time_detail}"
            guidance = (
                "Wall-clock time budget for this target is exhausted. End the "
                "phase now and report what was covered and what was NOT tested; "
                "do not start new probes against this target."
            )
        elif not _policy_preflight and tool_name not in LOCAL_SAFE_TOOLS and not self._reserve_rate_limit(tool_name, request_weight):
            result = reason = "blocked_rate_limit"

        if result == "blocked_approval_required" and bg_job and bg_mode == "approval":
            guidance = (
                "Background network job: run it in the foreground, or request an "
                "explicit grant covering this host "
                "(policy_gate_cli.py approve --tool-pattern 'bash' "
                "--target-pattern '<host>'). Unleased background jobs are "
                "terminated by the egress watchdog."
            )

        blocked_reason = ""
        if result != "allowed" and self._repeat_brake(tool_name, result):
            blocked_reason = result
            result = "blocked_repeat_brake"
            reason = (f"blocked_repeat_brake: {reason} (3x consecutive; "
                      "exit: allowed-shape resend or brain.py synthesize)")
            if blocked_reason == "blocked_missing_target":
                exit_hint = "Include the missing target. "
            elif tool_name == "bash":
                exit_hint = "Use pipe-less workdir-local verbs. "
            else:
                exit_hint = "Fix the cited argument. "
            guidance = (
                "Same gate block three times in a row. This brake is not a "
                "lockout: an allowed-shape call still passes. " + exit_hint +
                "For read-only synthesis use 'python3 scripts/brain.py "
                "synthesize --workdir <run> --kind "
                "<ledger-summary|coverage-count>'. Do not repeat the "
                "blocked shape."
            )

        payload = {
            "tool_name": tool_name,
            "blocked_reason": blocked_reason,
            "known_tool": known_tool,
            "secret_violation": secret_violation or "",
            "background_job": bg_job,
            "fuzz_estimate": fuzz_estimate,
            "targets": targets,
            "url_targets": url_targets,
            "standalone_targets": standalone_targets,
            "network_targets": network_targets,
            "range_targets": range_targets,
            "invalid_targets": invalid_targets,
            "unsafe_arguments": unsafe_arguments,
            "unsafe_argument_detail": unsafe_detail,
            "urls": urls,
            "methods": methods,
            "capability": capability,
            "request_weight": request_weight,
            "policy_preflight": _policy_preflight,
            **metadata,
        }
        self._log(tool_name, action, targets, permission, scope_valid, result, payload)
        ua_variant, header_variant = self._probe_variants(tool_name, args)
        if not _policy_preflight:
            self._record_probes(tool_name, urls, methods, ua_variant, header_variant, result == "allowed")
        return {
            "allowed": result == "allowed",
            "reason": reason,
            "guidance": guidance,
            "background_job": bg_job,
            "fuzz_estimate": fuzz_estimate,
            "tool_name": tool_name,
            "targets": targets,
            "url_targets": url_targets,
            "standalone_targets": standalone_targets,
            "network_targets": network_targets,
            "range_targets": range_targets,
            "invalid_targets": invalid_targets,
            "unsafe_arguments": unsafe_arguments,
            "unsafe_argument_detail": unsafe_detail,
            "urls": urls,
            "methods": methods,
            "scope_valid": scope_valid,
            "permission": permission,
            "requires_approval": requires_approval,
        }

    def validate_wire_invocation(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Apply the parent tool's scope and grant to one actual HTTP request."""
        scoped_args = dict(args)
        for key in ("target", "endpoint", "url"):
            raw = scoped_args.get(key)
            if not isinstance(raw, str) or "://" not in raw:
                continue
            try:
                scoped_args[key] = _canonical_scope_url(raw)
            except ValueError:
                scoped_args[key] = "invalid://invalid"
        return self.validate_tool_invocation(tool_name, scoped_args, _wire_request=True)

    def audit(self, limit: int = 100) -> list[dict[str, Any]]:
        conn = self._connect(row_factory=True)
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_untrusted_prefixes(self) -> list[str]:
        return list(self.program_policy.get("untrusted_output_prefixes", UNTRUSTED_OUTPUT_PREFIXES))

    @staticmethod
    def _normalize_probe_path(path: str) -> str:
        return path.rstrip("/") or "/"

    def _probe_variants(self, tool_name: str, args: dict[str, Any]) -> tuple[str, str]:
        ua = "ua:default"
        headers: set[str] = set()

        def scan(obj: Any):
            nonlocal ua
            if isinstance(obj, dict):
                for key, value in obj.items():
                    normalized = str(key).lower().replace("-", "_")
                    if normalized in ("user_agent", "useragent") and isinstance(value, str) and value.strip():
                        ua = "ua:custom"
                    elif normalized in ("headers", "header", "extra_headers", "custom_headers"):
                        if isinstance(value, dict):
                            for header_key in value:
                                headers.add("hdr:" + str(header_key).lower())
                        elif isinstance(value, str) and value.strip():
                            headers.add("hdr:custom")
                    elif normalized in ("cookie", "cookies", "authorization", "auth_token", "token") and value:
                        headers.add("hdr:" + normalized)
                    scan(value)
            elif isinstance(obj, (list, tuple)):
                for value in obj:
                    scan(value)

        scan(args)
        if tool_name == "bash" and isinstance(args.get("command"), str):
            try:
                tokens = shlex.split(args["command"])
            except ValueError:
                tokens = []
            index = 0
            while index < len(tokens):
                token = tokens[index]
                if token in ("-A", "--user-agent"):
                    ua = "ua:custom"
                    index += 2
                    continue
                if token in ("-H", "--header") and index + 1 < len(tokens):
                    name = tokens[index + 1].split(":", 1)[0].strip().lower()
                    headers.add("hdr:" + (name or "custom"))
                    index += 2
                    continue
                if token in ("-b", "--cookie"):
                    headers.add("hdr:cookie")
                    index += 2
                    continue
                index += 1
        return ua, "|".join(sorted(headers)) if headers else "hdr:none"

    def _record_probes(self, tool_name: str, urls: list[str], methods: list[str],
                       ua_variant: str, header_variant: str, effective: bool) -> None:
        if not urls:
            return
        method = methods[0] if methods else "GET"
        rows = []
        for url in urls:
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            rows.append((
                _utc_now().isoformat(),
                url,
                (parsed.hostname or "").lower(),
                self._normalize_probe_path(parsed.path or "/"),
                method,
                ua_variant,
                header_variant,
                tool_name,
                1 if effective else 0,
            ))
        if not rows:
            return
        conn = self._connect()
        conn.executemany(
            "INSERT INTO path_probes (timestamp, url, host, path, method, ua_variant, header_variant, tool_name, effective)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        conn.close()

    def check_path_close(self, url_or_path: str, host: str = "", min_probes: int = 5,
                         min_methods: int = 2, min_ua: int = 2, min_headers: int = 2) -> dict[str, Any]:
        target = (url_or_path or "").strip()
        query_host = (host or "").strip().lower()
        if target.lower().startswith(("http://", "https://", "ws://", "wss://")):
            parsed = urlparse(target)
            query_host = query_host or (parsed.hostname or "").lower()
            query_path = self._normalize_probe_path(parsed.path or "/")
        else:
            query_path = self._normalize_probe_path(target if target.startswith("/") else "/" + target)
        conn = self._connect(row_factory=True)
        if query_host:
            rows = conn.execute(
                "SELECT method, ua_variant, header_variant FROM path_probes"
                " WHERE host=? AND path=? AND effective=1",
                (query_host, query_path),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT method, ua_variant, header_variant FROM path_probes"
                " WHERE path=? AND effective=1",
                (query_path,),
            ).fetchall()
        conn.close()
        observed: dict[str, Any] = {
            "probes": len(rows),
            "methods": sorted({str(row["method"]) for row in rows}),
            "ua_variants": sorted({str(row["ua_variant"]) for row in rows}),
            "header_variants": sorted({str(row["header_variant"]) for row in rows}),
        }
        missing = []
        if observed["probes"] < min_probes:
            missing.append(f"en az {min_probes} deneme gerekli (şu an {observed['probes']})")
        if len(observed["methods"]) < min_methods:
            missing.append(
                f"en az {min_methods} farklı metod gerekli (şu an {observed['methods']});"
                " HEAD/OPTIONS gibi güvenli metodları dene"
            )
        if len(observed["ua_variants"]) < min_ua:
            missing.append(
                f"en az {min_ua} farklı User-Agent gerekli (şu an {observed['ua_variants']});"
                " özel UA ile dene (curl -A ...)"
            )
        if len(observed["header_variants"]) < min_headers:
            missing.append(
                f"en az {min_headers} farklı header varyasyonu gerekli (şu an {observed['header_variants']});"
                " özel header ile dene (curl -H ...)"
            )
        return {
            "allowed": not missing,
            "host": query_host,
            "path": query_path,
            "observed": observed,
            "missing": missing,
        }


class ScopeResolver:
    """Read-only view of the central scope logic; it never creates an audit DB.

    This is a prefilter, not authorization to send a request: the full policy
    gate still checks grants, methods, headers, and limits at execution time.
    """

    def __init__(self, scope_file: str | Path | None = None,
                 program_policy_file: str | Path | None = None,
                 repo_root: str | Path | None = None):
        self._engine = PolicyEngine(
            scope_file=str(scope_file) if scope_file else None,
            program_policy_file=str(program_policy_file) if program_policy_file else None,
            repo_root=str(repo_root) if repo_root else None, scope_only=True)

    def permits_url(self, url: str) -> bool:
        try:
            normalized = _canonical_scope_url(str(url or ""))
            host = urlsplit(normalized).hostname or ""
            return bool(host and self._engine._scope_allows(
                host, normalized, allow_public_exemptions=False))
        except (TypeError, ValueError):
            return False

    def blind_discovery_rules(self) -> dict:
        """Return the configured read-only blind discovery declarations."""
        value = self._engine.program_policy.get("blind_discovery")
        return dict(value) if isinstance(value, dict) else {}
