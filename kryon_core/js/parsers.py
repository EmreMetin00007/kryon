"""JavaScript parser interface for Client Logic Map.

Backends share one result shape. ``static`` is the dependency-free fallback;
``babel`` is an optional Node adapter used only when @babel/parser resolves.
No JavaScript from the target is executed: Babel only parses source text.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Protocol

MAX_SOURCE = 400_000
MAX_DIAGNOSTIC_CHARS = 240
MAX_DIAGNOSTICS = 8

STATIC_DIAGNOSTIC = "static parser used: AST coverage not available"
NODE_DIAGNOSTIC = "node executable not found"
BABEL_MODULE_DIAGNOSTIC = "babel parser unavailable: @babel/parser not found"
BABEL_PARSE_DIAGNOSTIC = "babel parser failed: parse error"
BABEL_INVALID_JSON_DIAGNOSTIC = "babel parser returned invalid JSON"
BABEL_NONOBJECT_DIAGNOSTIC = "babel parser returned non-object JSON"
BABEL_SHAPE_DIAGNOSTIC = "babel parser returned invalid result shape"
FALLBACK_DIAGNOSTIC = "fell back to static parser"

FUNCTION_RE = re.compile(
    r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
    r"|([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{",
)
REQUEST_RE = re.compile(
    r"\bfetch\s*\(|\baxios\.(get|post|put|patch|delete|head|options|request)\s*\("
    r"|\baxios\s*\(|\.open\s*\(",
    re.I,
)


class JavaScriptParser(Protocol):
    name: str

    def parse(self, source: str) -> dict[str, Any]:
        """Return functions, calls and diagnostics for source text."""
        ...


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _truncation_diagnostic() -> str:
    return f"source truncated at {MAX_SOURCE} characters: remaining JS not parsed"


def _coverage_gap(
    code: str, detail: str, parser_name: str, *, truncated: bool = False
) -> dict[str, Any]:
    gap: dict[str, Any] = {
        "code": code,
        "reason_code": code,
        "id": code,
        "status": "NOT TESTED",
        "detail": detail[:MAX_DIAGNOSTIC_CHARS],
        "message": detail[:MAX_DIAGNOSTIC_CHARS],
        "parser": parser_name,
        "ast_available": False,
    }
    if truncated:
        gap["truncated"] = True
    return gap


def _bounded_diagnostics(values: Any) -> list[str]:
    out: list[str] = []
    if not isinstance(values, (list, tuple)):
        values = [values] if values else []
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.strip()[:MAX_DIAGNOSTIC_CHARS]
        if text and text not in out:
            out.append(text)
        if len(out) >= MAX_DIAGNOSTICS:
            break
    return out


def _dedupe_gaps(gaps: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(gaps, (list, tuple)):
        return out
    for gap in gaps:
        if not isinstance(gap, dict):
            continue
        # One gap per code per original source; the same truncation
        # reported by both the failed backend and the fallback collapses.
        key = (
            str(gap.get("code") or gap.get("reason_code") or ""),
            str(gap.get("original_source") or ""),
        )
        if key in seen and key[0]:
            continue
        seen.add(key)
        out.append(gap)
    return out


def _callee_from_match(text: str) -> str:
    low = text.lower()
    if low.startswith("fetch"):
        return "fetch"
    if "axios." in low:
        return "axios." + low.rsplit("axios.", 1)[1].split("(", 1)[0]
    if low.startswith("axios"):
        return "axios"
    return "xhr.open"


class StaticParser:
    name = "static"

    def parse(self, source: str) -> dict[str, Any]:
        original = source or ""
        truncated = len(original) > MAX_SOURCE
        text = original[:MAX_SOURCE]
        functions = []
        for match in FUNCTION_RE.finditer(text):
            name = next((g for g in match.groups() if g), "")
            if name and name not in {"if", "for", "while", "switch", "catch"}:
                functions.append({
                    "name": name,
                    "start": match.start(),
                    "line": _line(text, match.start()),
                })
        calls = [{
            "callee": _callee_from_match(match.group(0)),
            "start": match.start(),
            "line": _line(text, match.start()),
        } for match in REQUEST_RE.finditer(text)]
        diagnostics = [STATIC_DIAGNOSTIC]
        gaps = [_coverage_gap("static_parser_no_ast", STATIC_DIAGNOSTIC, self.name)]
        if truncated:
            diagnostics.append(_truncation_diagnostic())
            gaps.append(_coverage_gap(
                "source_truncated", _truncation_diagnostic(), self.name, truncated=True,
            ))
        return {
            "name": self.name,
            "available": True,
            "ast_available": False,
            "functions": functions,
            "calls": calls,
            "diagnostics": _bounded_diagnostics(diagnostics),
            "coverage_gaps": _dedupe_gaps(gaps),
            "coverage_status": "NOT TESTED",
            "truncated": truncated,
        }


_NODE_SCRIPT = r"""
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { input += chunk; });
process.stdin.on("end", () => {
  try {
    const parser = require("@babel/parser");
    const ast = parser.parse(input, {
      sourceType: "unambiguous",
      allowReturnOutsideFunction: true,
      plugins: ["jsx", "typescript"],
    });
    const functions = [];
    const calls = [];
    const lineOf = (node) => node.loc ? node.loc.start.line : 0;
    function calleeName(node) {
      if (!node) return "";
      if (node.type === "Identifier") return node.name;
      if (node.type === "MemberExpression") {
        const obj = calleeName(node.object);
        const prop = node.property && (node.property.name || node.property.value || "");
        return obj ? `${obj}.${prop}` : String(prop || "");
      }
      return node.type || "";
    }
    function visit(node, parentName) {
      if (!node || typeof node.type !== "string") return;
      let currentName = parentName || "";
      if (node.type === "FunctionDeclaration" && node.id) {
        currentName = node.id.name;
        functions.push({name: currentName, start: node.start, line: lineOf(node)});
      }
      if (node.type === "VariableDeclarator" && node.id && node.id.type === "Identifier" &&
          node.init && (node.init.type === "ArrowFunctionExpression" || node.init.type === "FunctionExpression")) {
        currentName = node.id.name;
        functions.push({name: currentName, start: node.start, line: lineOf(node)});
      }
      if ((node.type === "ObjectMethod" || node.type === "ClassMethod") && node.key) {
        currentName = node.key.name || node.key.value || currentName;
        functions.push({name: currentName, start: node.start, line: lineOf(node)});
      }
      if (node.type === "CallExpression") {
        calls.push({callee: calleeName(node.callee), start: node.start, line: lineOf(node)});
      }
      for (const key of Object.keys(node)) {
        if (["loc", "start", "end", "__clone"].includes(key)) continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach((item) => visit(item, currentName));
        else if (child && typeof child === "object") visit(child, currentName);
      }
    }
    visit(ast.program, "");
    process.stdout.write(JSON.stringify({functions, calls}));
  } catch (error) {
    process.stderr.write(String(error && error.message || error));
    process.exit(2);
  }
});
"""


def _node_path_candidates() -> list[str]:
    """Explicit env plus standard external Node dirs only.

    Repository-local ``node_modules`` (cwd or repo root) is never
    auto-discovered: a checkout must not gain a runtime parser install.
    ``CCO_JS_PARSER_PATH`` / ``NODE_PATH`` entries are honoured verbatim,
    and an entry pointing at a project root also contributes its
    ``node_modules`` child when present.
    """
    out: list[str] = []
    for value in (
        os.environ.get("CCO_JS_PARSER_PATH", ""),
        os.environ.get("NODE_PATH", ""),
    ):
        for part in value.split(os.pathsep):
            part = part.strip()
            if not part:
                continue
            out.append(part)
            try:
                p = Path(part)
                child = p / "node_modules"
                if child.is_dir():
                    out.append(str(child))
                # Tolerate pointing directly at .../@babel/parser or .../@babel
                if p.name == "parser" and p.parent.name == "@babel":
                    out.append(str(p.parent.parent))
                elif p.name == "@babel":
                    out.append(str(p.parent))
            except OSError:
                continue
    standard: list[Path] = [
        Path("/usr/local/lib/node_modules"),
        Path("/usr/lib/node_modules"),
        Path("/usr/share/nodejs"),
        Path("/usr/lib/x86_64-linux-gnu/nodejs"),
        Path.home() / ".npm-global" / "lib" / "node_modules",
        Path.home() / ".node_modules",
    ]
    node = shutil.which("node")
    if node:
        try:
            standard.append(Path(node).resolve().parent.parent / "lib" / "node_modules")
        except (OSError, RuntimeError):
            pass
    for candidate in standard:
        try:
            if candidate.is_dir():
                out.append(str(candidate))
        except OSError:
            continue
    return list(dict.fromkeys(out))


def _babel_locatable(candidates: list[str] | None = None) -> bool:
    for base in candidates if candidates is not None else _node_path_candidates():
        try:
            root = Path(base)
            if (root / "@babel" / "parser").is_dir():
                return True
            if (root / "node_modules" / "@babel" / "parser").is_dir():
                return True
        except OSError:
            continue
    return False


def _classify_babel_stderr(stderr: str) -> tuple[str, str]:
    """Map untrusted stderr to a stable code; never echo its text."""
    low = (stderr or "").lower()
    if "cannot find module" in low or "module not found" in low:
        return "babel_module_not_found", BABEL_MODULE_DIAGNOSTIC
    if "@babel/parser" in low and ("not found" in low or "cannot find" in low):
        return "babel_module_not_found", BABEL_MODULE_DIAGNOSTIC
    return "babel_parse_failed", BABEL_PARSE_DIAGNOSTIC


class BabelParser:
    name = "babel"

    def _failure(
        self, diagnostic: str, code: str, truncated: bool
    ) -> dict[str, Any]:
        diagnostics = [diagnostic]
        gaps = [_coverage_gap(code, diagnostic, self.name)]
        if truncated:
            diagnostics.append(_truncation_diagnostic())
            gaps.append(_coverage_gap(
                "source_truncated", _truncation_diagnostic(), self.name, truncated=True,
            ))
        return {
            "name": self.name, "available": False, "ast_available": False,
            "functions": [], "calls": [],
            "diagnostics": _bounded_diagnostics(diagnostics),
            "coverage_gaps": _dedupe_gaps(gaps),
            "coverage_status": "NOT TESTED",
            "truncated": truncated,
        }

    def parse(self, source: str) -> dict[str, Any]:
        original = source or ""
        truncated = len(original) > MAX_SOURCE
        node = shutil.which("node")
        if not node:
            return self._failure(NODE_DIAGNOSTIC, "node_executable_not_found", truncated)
        env = dict(os.environ)
        candidates = _node_path_candidates()
        if candidates:
            env["NODE_PATH"] = os.pathsep.join(candidates)
        try:
            proc = subprocess.run(
                [node, "-e", _NODE_SCRIPT],
                input=original[:MAX_SOURCE],
                capture_output=True,
                text=True,
                timeout=8,
                env=env,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            # Only the exception type is stable/safe; str(exc) may embed
            # command or source fragments and is never echoed.
            diagnostic = f"babel parser failed: {type(exc).__name__}"
            return self._failure(diagnostic, "babel_execution_failed", truncated)
        if proc.returncode != 0:
            code, diagnostic = _classify_babel_stderr(proc.stderr or "")
            return self._failure(diagnostic, code, truncated)
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return self._failure(
                BABEL_INVALID_JSON_DIAGNOSTIC, "babel_invalid_response", truncated,
            )
        if not isinstance(data, dict):
            return self._failure(
                BABEL_NONOBJECT_DIAGNOSTIC, "babel_invalid_response", truncated,
            )
        functions = data.get("functions", [])
        calls = data.get("calls", [])
        if not isinstance(functions, list) or not isinstance(calls, list):
            return self._failure(
                BABEL_SHAPE_DIAGNOSTIC, "babel_invalid_response", truncated,
            )
        if any(not isinstance(item, dict) for item in functions) or any(
            not isinstance(item, dict) for item in calls
        ):
            return self._failure(
                BABEL_SHAPE_DIAGNOSTIC, "babel_invalid_response", truncated,
            )
        diagnostics: list[str] = []
        gaps: list[dict[str, Any]] = []
        if truncated:
            diagnostics.append(_truncation_diagnostic())
            gaps.append(_coverage_gap(
                "source_truncated", _truncation_diagnostic(), self.name, truncated=True,
            ))
        return {
            "name": self.name,
            "available": True,
            "ast_available": True,
            "functions": functions,
            "calls": calls,
            "diagnostics": _bounded_diagnostics(diagnostics),
            "coverage_gaps": _dedupe_gaps(gaps),
            "coverage_status": "NOT TESTED" if gaps else "ast_parsed",
            "truncated": truncated,
        }


def get_parser(name: str = "auto") -> tuple[JavaScriptParser, dict[str, Any]]:
    requested = (name or "auto").lower()
    if requested not in {"auto", "static", "babel"}:
        requested = "auto"
    if requested == "static":
        gap = _coverage_gap("static_parser_no_ast", STATIC_DIAGNOSTIC, "static")
        return StaticParser(), {
            "requested": "static", "used": "static", "ast_available": False,
            "diagnostics": [STATIC_DIAGNOSTIC], "coverage_gaps": [gap],
            "coverage_status": "NOT TESTED", "truncated": False,
        }
    node = shutil.which("node")
    if not node:
        gap = _coverage_gap("node_executable_not_found", NODE_DIAGNOSTIC, "babel")
        return BabelParser(), {
            "requested": requested, "used": "babel", "ast_available": False,
            "diagnostics": [NODE_DIAGNOSTIC], "coverage_gaps": [gap],
            "coverage_status": "NOT TESTED", "truncated": False,
        }
    if not _babel_locatable():
        gap = _coverage_gap("babel_module_not_found", BABEL_MODULE_DIAGNOSTIC, "babel")
        return BabelParser(), {
            "requested": requested, "used": "babel", "ast_available": False,
            "diagnostics": [BABEL_MODULE_DIAGNOSTIC], "coverage_gaps": [gap],
            "coverage_status": "NOT TESTED", "truncated": False,
        }
    return BabelParser(), {
        "requested": requested, "used": "babel", "ast_available": True,
        "diagnostics": [], "coverage_gaps": [],
        "coverage_status": "ast_parsed", "truncated": False,
    }


def parse_javascript(source: str, parser: str = "auto") -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse with the requested backend, falling back to static on failure."""
    requested = (parser or "auto").lower()
    original = source or ""
    truncated = len(original) > MAX_SOURCE
    if requested == "static":
        result = StaticParser().parse(original)
        return result, {
            "requested": "static", "used": "static",
            "ast_available": False,
            "diagnostics": _bounded_diagnostics(result.get("diagnostics") or []),
            "coverage_gaps": _dedupe_gaps(result.get("coverage_gaps") or []),
            "coverage_status": "NOT TESTED",
            "truncated": truncated,
        }
    result = BabelParser().parse(original)
    if result.get("available"):
        return result, {
            "requested": requested, "used": "babel",
            "ast_available": True,
            "diagnostics": _bounded_diagnostics(result.get("diagnostics") or []),
            "coverage_gaps": _dedupe_gaps(result.get("coverage_gaps") or []),
            "coverage_status": result.get("coverage_status") or "ast_parsed",
            "truncated": truncated,
        }
    fallback = StaticParser().parse(original)
    diagnostics = _bounded_diagnostics(
        list(result.get("diagnostics") or [])
        + list(fallback.get("diagnostics") or [])
        + [FALLBACK_DIAGNOSTIC]
    )
    gaps = _dedupe_gaps(
        list(result.get("coverage_gaps") or [])
        + list(fallback.get("coverage_gaps") or [])
    )
    fallback_result = dict(fallback)
    fallback_result["diagnostics"] = diagnostics
    fallback_result["coverage_gaps"] = gaps
    fallback_result["coverage_status"] = "NOT TESTED"
    fallback_result["truncated"] = truncated
    return fallback_result, {
        "requested": requested, "used": "static",
        "ast_available": False, "diagnostics": diagnostics,
        "coverage_gaps": gaps,
        "coverage_status": "NOT TESTED",
        "truncated": truncated,
    }
