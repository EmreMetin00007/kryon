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
        text = (source or "")[:MAX_SOURCE]
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
        return {
            "name": self.name,
            "available": True,
            "ast_available": False,
            "functions": functions,
            "calls": calls,
            "diagnostics": [],
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
    out: list[str] = []
    for value in (
        os.environ.get("CCO_JS_PARSER_PATH", ""),
        os.environ.get("NODE_PATH", ""),
    ):
        out.extend(p for p in value.split(os.pathsep) if p)
    cwd = Path.cwd()
    for candidate in (
        cwd / "node_modules",
        Path(__file__).resolve().parents[3] / "node_modules",
    ):
        if candidate.is_dir():
            out.append(str(candidate))
    return list(dict.fromkeys(out))


class BabelParser:
    name = "babel"

    def parse(self, source: str) -> dict[str, Any]:
        node = shutil.which("node")
        if not node:
            return {
                "name": self.name, "available": False, "ast_available": False,
                "functions": [], "calls": [], "diagnostics": ["node executable not found"],
            }
        env = dict(os.environ)
        candidates = _node_path_candidates()
        if candidates:
            env["NODE_PATH"] = os.pathsep.join(candidates)
        try:
            proc = subprocess.run(
                [node, "-e", _NODE_SCRIPT],
                input=(source or "")[:MAX_SOURCE],
                capture_output=True,
                text=True,
                timeout=8,
                env=env,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "name": self.name, "available": False, "ast_available": False,
                "functions": [], "calls": [],
                "diagnostics": [f"babel parser failed: {type(exc).__name__}"],
            }
        if proc.returncode != 0:
            detail = (proc.stderr or "unknown babel parser error").strip()[:240]
            return {
                "name": self.name, "available": False, "ast_available": False,
                "functions": [], "calls": [],
                "diagnostics": [f"babel parser unavailable: {detail}"],
            }
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return {
                "name": self.name, "available": False, "ast_available": False,
                "functions": [], "calls": [],
                "diagnostics": ["babel parser returned invalid JSON"],
            }
        return {
            "name": self.name,
            "available": True,
            "ast_available": True,
            "functions": data.get("functions") or [],
            "calls": data.get("calls") or [],
            "diagnostics": [],
        }


def get_parser(name: str = "auto") -> tuple[JavaScriptParser, dict[str, Any]]:
    requested = (name or "auto").lower()
    if requested not in {"auto", "static", "babel"}:
        requested = "auto"
    if requested == "static":
        return StaticParser(), {"requested": "static", "used": "static", "ast_available": False, "diagnostics": []}
    if requested == "babel":
        return BabelParser(), {"requested": "babel", "used": "babel", "ast_available": True, "diagnostics": []}
    return BabelParser(), {"requested": "auto", "used": "babel", "ast_available": True, "diagnostics": []}


def parse_javascript(source: str, parser: str = "auto") -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse with the requested backend, falling back to static on failure."""
    requested = (parser or "auto").lower()
    if requested == "static":
        result = StaticParser().parse(source)
        return result, {
            "requested": "static", "used": "static",
            "ast_available": False, "diagnostics": [],
        }
    result = BabelParser().parse(source)
    if result.get("available"):
        return result, {
            "requested": requested, "used": "babel",
            "ast_available": True, "diagnostics": result.get("diagnostics") or [],
        }
    fallback = StaticParser().parse(source)
    diagnostics = list(result.get("diagnostics") or []) + ["fell back to static parser"]
    return fallback, {
        "requested": requested, "used": "static",
        "ast_available": False, "diagnostics": diagnostics,
    }
