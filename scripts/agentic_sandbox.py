"""Air-gapped pure-Python compute sandbox (`python_pure`) for payload encoding and decoding."""
from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Sequence

from agentic_receipts import redact_secrets

MAX_CODE_CHARS = 8000
MIN_TIMEOUT_MS = 100
MAX_TIMEOUT_MS = 3000
DEFAULT_TIMEOUT_MS = 1500
DEFAULT_MAX_OUTPUT_BYTES = 65536
MAX_OUTPUT_BYTES_CAP = 262144
MAX_DECODED_BODY_BYTES = 256 * 1024
_MAX_STDOUT_PREVIEW_CHARS = 4096

ALLOWED_STDLIB_MODULES: frozenset[str] = frozenset({
    "hashlib",
    "hmac",
    "struct",
    "base64",
    "binascii",
    "zlib",
    "gzip",
    "json",
    "math",
    "time",
    "datetime",
    "re",
    "itertools",
    "functools",
    "collections",
    "urllib.parse",
    "decimal",
    "uuid",
    "copy",
    "string",
})

FORBIDDEN_IDENTIFIERS: frozenset[str] = frozenset({
    "__import__",
    "eval",
    "exec",
    "compile",
    "open",
    "breakpoint",
    "input",
    "vars",
    "globals",
    "locals",
    "dir",
    "getattr",
    "setattr",
    "delattr",
})

_FORBIDDEN_INTROSPECT_ATTRS: frozenset[str] = frozenset({
    "gi_frame",
    "gi_code",
    "cr_frame",
    "cr_code",
    "ag_frame",
    "ag_code",
    "f_globals",
    "f_locals",
    "f_builtins",
    "f_back",
    "func_globals",
    "func_code",
})

_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$")

# Child bootstrap executed under `python3 -I` with `env={}` and an isolated tempdir cwd.
# Pre-imports the allowlisted pure-compute modules BEFORE registering `sys.addaudithook`
# because Python's importlib calls `open()` when loading module bytecode from disk.
_BOOTSTRAP = r'''
import base64
import binascii
import builtins
import collections
import copy
import datetime
import decimal
import functools
import gzip
import hashlib
import hmac
import io
import itertools
import json
import math
import re
import resource
import string
import struct
import sys
import time
import types
import urllib.parse
import uuid
import zlib
try:
    import _strptime  # noqa: PLC0415
except Exception:
    _strptime = None  # type: ignore[assignment]

# Pre-warm lazy stdlib helpers before locking down `open` in the audit hook.
try:
    datetime.datetime.strptime("2026/01/01", "%Y/%m/%d")
except Exception:
    pass
try:
    _ = "".encode("utf-8").decode("latin-1")
except Exception:
    pass

_ALLOWED_MODULES = {
    "hashlib": hashlib,
    "hmac": hmac,
    "struct": struct,
    "base64": base64,
    "binascii": binascii,
    "zlib": zlib,
    "gzip": gzip,
    "json": json,
    "math": math,
    "time": time,
    "datetime": datetime,
    "re": re,
    "itertools": itertools,
    "functools": functools,
    "collections": collections,
    "urllib.parse": urllib.parse,
    "decimal": decimal,
    "uuid": uuid,
    "copy": copy,
    "string": string,
}
_INTERNAL_HELPER_MODULES = {"_strptime": _strptime} if _strptime is not None else {}
_URLLIB_STUB = types.SimpleNamespace(parse=urllib.parse)


def _restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level == 0 and name in _INTERNAL_HELPER_MODULES:
        return _INTERNAL_HELPER_MODULES[name]
    if level != 0 or name not in _ALLOWED_MODULES:
        raise ImportError(f"module {name!r} is not allowed in python_pure sandbox")
    if name == "urllib.parse" and not fromlist:
        return _URLLIB_STUB
    return _ALLOWED_MODULES[name]


class _BoundedTextIO(io.TextIOBase):
    def __init__(self, limit_chars: int):
        self._limit = max(64, int(limit_chars))
        self._chunks = []
        self._size = 0
        self.truncated = False

    def writable(self) -> bool:
        return True

    def write(self, s: str) -> int:
        text = str(s)
        if self._size >= self._limit:
            if text:
                self.truncated = True
            return len(text)
        remaining = self._limit - self._size
        if len(text) > remaining:
            self._chunks.append(text[:remaining])
            self._size += remaining
            self.truncated = True
        else:
            self._chunks.append(text)
            self._size += len(text)
        return len(text)

    def getvalue(self) -> str:
        return "".join(self._chunks)


def _clamp_rlimit(res_id: int, target: int) -> None:
    soft, hard = resource.getrlimit(res_id)
    lim = target if hard == resource.RLIM_INFINITY else min(target, hard)
    resource.setrlimit(res_id, (lim, lim))


def _audit_hook(event, args):
    if (
        event.startswith(("socket.", "urllib.", "http.client.", "subprocess.", "ctypes.", "shutil.", "os.exec"))
        or event in {
            "os.system",
            "os.popen",
            "os.posix_spawn",
            "open",
            "os.fork",
            "os.spawn",
            "os.kill",
            "os.remove",
            "os.unlink",
            "os.rename",
            "os.replace",
            "os.mkdir",
            "os.rmdir",
            "os.chmod",
            "os.chown",
            "os.symlink",
            "os.link",
            "pty.spawn",
            "webbrowser.open",
            "sqlite3.connect",
        }
    ):
        raise PermissionError(f"blocked audit event: {event}")


def _main() -> None:
    raw_in = sys.stdin.read()
    payload = json.loads(raw_in)
    user_code = payload["code"]
    inputs = payload.get("inputs") or {}
    max_output_bytes = int(payload.get("max_output_bytes") or 65536)

    _clamp_rlimit(resource.RLIMIT_CPU, 2)
    _clamp_rlimit(resource.RLIMIT_FSIZE, 0)
    _clamp_rlimit(resource.RLIMIT_NOFILE, 32)
    _clamp_rlimit(resource.RLIMIT_AS, 256 * 1024 * 1024)
    sys.addaudithook(_audit_hook)

    safe_builtin_names = (
        "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes",
        "callable", "chr", "complex", "dict", "divmod", "enumerate", "filter",
        "float", "format", "frozenset", "hash", "hex", "int", "isinstance",
        "issubclass", "iter", "len", "list", "map", "max", "min", "next",
        "oct", "ord", "pow", "print", "range", "repr", "reversed", "round",
        "set", "slice", "sorted", "str", "sum", "tuple", "zip",
        "Exception", "ValueError", "TypeError", "KeyError", "IndexError",
        "RuntimeError", "ArithmeticError", "ZeroDivisionError", "LookupError",
        "AttributeError", "AssertionError", "StopIteration", "ImportError",
        "PermissionError",
    )
    safe_builtins = {name: getattr(builtins, name) for name in safe_builtin_names}
    safe_builtins["__import__"] = _restricted_import

    exec_ns = {
        "__builtins__": safe_builtins,
        "inputs": copy.deepcopy(inputs),
    }

    real_stdout = sys.stdout
    real_stderr = sys.stderr
    cap_out = _BoundedTextIO(min(max_output_bytes, 4096))
    cap_err = _BoundedTextIO(1024)
    sys.stdout = cap_out
    sys.stderr = cap_err

    out_doc = None
    try:
        compiled = builtins.compile(user_code, "<python_pure>", "exec")
        builtins.exec(compiled, exec_ns, exec_ns)
        fn = exec_ns.get("transform")
        if callable(fn):
            raw_result = fn(copy.deepcopy(inputs))
        elif "RESULT" in exec_ns:
            raw_result = exec_ns["RESULT"]
        elif "result" in exec_ns:
            raw_result = exec_ns["result"]
        else:
            raw_result = None
        out_doc = {
            "ok": True,
            "result": raw_result,
            "stdout": cap_out.getvalue(),
            "stdout_truncated": cap_out.truncated,
        }
    except BaseException as exc:
        out_doc = {
            "ok": False,
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
            "stdout": cap_out.getvalue(),
        }
    finally:
        sys.stdout = real_stdout
        sys.stderr = real_stderr

    try:
        encoded = json.dumps(out_doc, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        encoded = json.dumps(
            {
                "ok": False,
                "error": f"sandbox result must be JSON-serializable: {exc}",
                "stdout": cap_out.getvalue(),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    real_stdout.write(encoded)
    real_stdout.flush()


if __name__ == "__main__":
    _main()
'''


def _is_dunder(name: str) -> bool:
    return name.startswith("__") or name.endswith("__")


def validate_python_pure_ast(code: str) -> str | None:
    """Validate `code` against the Layer 1 pure-compute AST policy; return error or None."""
    if not isinstance(code, str):
        return "code must be a string"
    if not code.strip():
        return "code must not be empty"
    if len(code) > MAX_CODE_CHARS:
        return f"code length {len(code)} exceeds limit of {MAX_CODE_CHARS} chars"

    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as exc:
        return f"SyntaxError: {exc.msg} (line {exc.lineno})"

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in ALLOWED_STDLIB_MODULES:
                    return f"disallowed import module: {alias.name!r}"
                if alias.asname and (_is_dunder(alias.asname) or alias.asname in FORBIDDEN_IDENTIFIERS):
                    return f"disallowed import alias: {alias.asname!r}"
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                return "relative imports are disallowed"
            mod = str(node.module or "")
            if mod not in ALLOWED_STDLIB_MODULES:
                return f"disallowed import-from module: {mod!r}"
            for alias in node.names:
                if alias.name == "*":
                    return "wildcard imports are disallowed"
                if _is_dunder(alias.name) or alias.name in FORBIDDEN_IDENTIFIERS:
                    return f"disallowed imported symbol: {alias.name!r}"
                if alias.asname and (_is_dunder(alias.asname) or alias.asname in FORBIDDEN_IDENTIFIERS):
                    return f"disallowed import alias: {alias.asname!r}"
        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_IDENTIFIERS or _is_dunder(node.id):
                return f"forbidden identifier: {node.id!r}"
        elif isinstance(node, ast.Attribute):
            if (
                _is_dunder(node.attr)
                or node.attr in FORBIDDEN_IDENTIFIERS
                or node.attr in _FORBIDDEN_INTROSPECT_ATTRS
            ):
                return f"forbidden attribute access: {node.attr!r}"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if _is_dunder(node.name) or node.name in FORBIDDEN_IDENTIFIERS:
                return f"forbidden definition name: {node.name!r}"
        elif isinstance(node, ast.arg):
            if _is_dunder(node.arg) or node.arg in FORBIDDEN_IDENTIFIERS:
                return f"forbidden parameter name: {node.arg!r}"
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for target_name in node.names:
                if _is_dunder(target_name) or target_name in FORBIDDEN_IDENTIFIERS:
                    return f"forbidden variable scope name: {target_name!r}"
    return None


def _redact_json_value(value: Any, secret_values: Sequence[str]) -> Any:
    if isinstance(value, str):
        return redact_secrets(value, secret_values)
    if isinstance(value, list):
        return [_redact_json_value(item, secret_values) for item in value]
    if isinstance(value, dict):
        return {
            redact_secrets(str(k), secret_values): _redact_json_value(v, secret_values)
            for k, v in value.items()
        }
    return value


def _validate_and_normalize_headers(raw_headers: Any, secret_values: Sequence[str]) -> dict[str, str]:
    if raw_headers is None:
        return {}
    if not isinstance(raw_headers, dict):
        raise ValueError("sandbox result 'headers' must be a dict")
    clean: dict[str, str] = {}
    for raw_k, raw_v in raw_headers.items():
        if not isinstance(raw_k, str):
            raise ValueError("sandbox header names must be strings")
        key = raw_k.strip()
        if any(ch in raw_k for ch in ("\r", "\n", "\x00")) or not _HEADER_NAME_RE.fullmatch(key):
            raise ValueError(f"invalid or unsafe sandbox header name: {raw_k!r}")
        val = "" if raw_v is None else str(raw_v)
        if any(ch in val for ch in ("\r", "\n", "\x00")):
            raise ValueError(f"sandbox header {key!r} value contains CR/LF/NUL injection characters")
        clean[key] = redact_secrets(val, secret_values)
    return clean


def _validate_and_normalize_query(raw_query: Any, secret_values: Sequence[str]) -> dict[str, str]:
    if raw_query is None:
        return {}
    if not isinstance(raw_query, dict):
        raise ValueError("sandbox result 'query' must be a dict")
    clean: dict[str, str] = {}
    for raw_k, raw_v in raw_query.items():
        key = str(raw_k).strip()
        if not key or any(ch in str(raw_k) for ch in ("\r", "\n", "\x00")):
            raise ValueError(f"invalid sandbox query parameter name: {raw_k!r}")
        val = "" if raw_v is None else str(raw_v)
        if any(ch in val for ch in ("\r", "\n", "\x00")):
            raise ValueError(f"sandbox query parameter {key!r} contains control characters")
        clean[key] = redact_secrets(val, secret_values)
    return clean


def _validate_body_base64(raw_b64: Any) -> str:
    if raw_b64 is None or raw_b64 == "":
        return ""
    if not isinstance(raw_b64, str):
        raise ValueError("sandbox result 'body_base64' must be a string")
    compact = "".join(raw_b64.split())
    max_b64_chars = ((MAX_DECODED_BODY_BYTES + 3) * 4 // 3) + 4
    if len(compact) > max_b64_chars:
        raise ValueError(f"sandbox body_base64 exceeds max {MAX_DECODED_BODY_BYTES} decoded bytes")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid sandbox body_base64: {exc}") from exc
    if len(decoded) > MAX_DECODED_BODY_BYTES:
        raise ValueError(
            f"sandbox body_base64 decoded size {len(decoded)} exceeds limit of {MAX_DECODED_BODY_BYTES} bytes"
        )
    return base64.b64encode(decoded).decode("ascii")


def _truncate_utf8_text(text: str, max_bytes: int) -> str:
    if max_bytes <= 0 or not text:
        return ""
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return text
    return raw[:max_bytes].decode("utf-8", errors="ignore")


def _error_response(error: str, started: float) -> dict[str, Any]:
    return {
        "ok": False,
        "runtime": "python_pure",
        "error": error,
        "elapsed_ms": round(max(0.0, (time.monotonic() - started) * 1000.0), 2),
    }


def run_python_pure_sandbox(
    code: str,
    *,
    inputs: dict[str, Any] | None = None,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    secret_values: Sequence[str] = (),
) -> dict[str, Any]:
    """Execute pure-Python payload compute code inside a 3-layer air-gapped sandbox."""
    started = time.monotonic()

    if isinstance(timeout_ms, bool):
        return _error_response("timeout_ms must be an integer", started)
    try:
        eff_timeout_ms = min(max(MIN_TIMEOUT_MS, int(timeout_ms)), MAX_TIMEOUT_MS)
    except (TypeError, ValueError):
        return _error_response(f"invalid timeout_ms: {timeout_ms!r}", started)

    if isinstance(max_output_bytes, bool):
        return _error_response("max_output_bytes must be an integer", started)
    try:
        eff_max_output = min(max(64, int(max_output_bytes)), MAX_OUTPUT_BYTES_CAP)
    except (TypeError, ValueError):
        return _error_response(f"invalid max_output_bytes: {max_output_bytes!r}", started)

    if inputs is None:
        safe_inputs: dict[str, Any] = {}
    elif isinstance(inputs, dict):
        safe_inputs = inputs
    else:
        return _error_response("inputs must be a JSON object", started)

    ast_err = validate_python_pure_ast(code)
    if ast_err is not None:
        return _error_response(ast_err, started)

    try:
        stdin_payload = json.dumps(
            {
                "code": code,
                "inputs": safe_inputs,
                "max_output_bytes": eff_max_output,
            },
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        return _error_response(f"inputs must be JSON-serializable: {exc}", started)

    timeout_s = eff_timeout_ms / 1000.0
    try:
        with tempfile.TemporaryDirectory(prefix="kryon-sbx-") as tmpdir:
            proc = subprocess.run(
                [sys.executable, "-I", "-c", _BOOTSTRAP],
                input=stdin_payload,
                capture_output=True,
                cwd=Path(tmpdir),
                env={},
                timeout=timeout_s,
                check=False,
            )
    except subprocess.TimeoutExpired:
        return _error_response(f"sandbox execution timed out after {eff_timeout_ms}ms", started)
    except OSError as exc:
        return _error_response(f"sandbox launch error: {exc}", started)

    if proc.returncode != 0:
        stderr_msg = _truncate_utf8_text(proc.stderr.decode("utf-8", errors="replace").strip(), 300)
        detail = f": {stderr_msg}" if stderr_msg else ""
        return _error_response(f"sandbox process failed (rc={proc.returncode}){detail}", started)

    raw_stdout = proc.stdout.decode("utf-8", errors="replace")
    if not raw_stdout:
        return _error_response("sandbox returned empty output", started)
    try:
        envelope = json.loads(raw_stdout)
    except ValueError as exc:
        return _error_response(f"invalid sandbox output JSON: {exc}", started)
    if not isinstance(envelope, dict):
        return _error_response("invalid sandbox envelope type", started)

    raw_child_stdout = str(envelope.get("stdout") or "")
    redacted_stdout = redact_secrets(raw_child_stdout, secret_values)
    stdout_cap = min(eff_max_output, _MAX_STDOUT_PREVIEW_CHARS)
    stdout_preview = _truncate_utf8_text(redacted_stdout, stdout_cap)

    if not envelope.get("ok"):
        err_msg = redact_secrets(str(envelope.get("error") or "sandbox error"), secret_values)
        resp = _error_response(err_msg, started)
        if stdout_preview:
            resp["stdout_preview"] = stdout_preview
        return resp

    raw_result = envelope.get("result")
    body_b64 = ""
    headers: dict[str, str] = {}
    query: dict[str, str] = {}
    decoded_val: Any = None

    try:
        if isinstance(raw_result, dict):
            body_b64 = _validate_body_base64(raw_result.get("body_base64"))
            headers = _validate_and_normalize_headers(raw_result.get("headers"), secret_values)
            query = _validate_and_normalize_query(raw_result.get("query"), secret_values)
            if "decoded" in raw_result:
                decoded_val = raw_result["decoded"]
            elif "decoded_json" in raw_result:
                decoded_val = raw_result["decoded_json"]
            else:
                extra_keys = {
                    k: v
                    for k, v in raw_result.items()
                    if k not in {"body_base64", "headers", "query", "decoded", "decoded_json"}
                }
                if extra_keys:
                    decoded_val = extra_keys
        else:
            decoded_val = raw_result
    except ValueError as exc:
        return _error_response(str(exc), started)

    redacted_decoded = _redact_json_value(decoded_val, secret_values)
    if redacted_decoded is not None:
        try:
            decoded_bytes = json.dumps(
                redacted_decoded,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            return _error_response(f"decoded result serialization failed: {exc}", started)
        if len(decoded_bytes) > eff_max_output:
            return _error_response(
                f"sandbox decoded output ({len(decoded_bytes)} bytes) exceeds max_output_bytes ({eff_max_output})",
                started,
            )

    tx_seed = json.dumps(
        {
            "code_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest()[:16],
            "body_base64": body_b64,
            "headers": headers,
            "query": query,
            "decoded": redacted_decoded,
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    tx_id = f"tx_{hashlib.sha256(tx_seed).hexdigest()[:12]}"

    return {
        "ok": True,
        "runtime": "python_pure",
        "transform_id": tx_id,
        "body_base64": body_b64,
        "headers": headers,
        "query": query,
        "decoded": redacted_decoded,
        "stdout_preview": stdout_preview,
        "elapsed_ms": round(max(0.0, (time.monotonic() - started) * 1000.0), 2),
    }


__all__ = [
    "ALLOWED_STDLIB_MODULES",
    "FORBIDDEN_IDENTIFIERS",
    "MAX_CODE_CHARS",
    "MAX_DECODED_BODY_BYTES",
    "run_python_pure_sandbox",
    "validate_python_pure_ast",
]
