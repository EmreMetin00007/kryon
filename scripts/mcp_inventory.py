"""Side-effect-free inventory of first-party MCP server tool declarations."""
from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path
try:
    from .runtime_paths import runtime_root
except ImportError:
    from runtime_paths import runtime_root

ROOT = runtime_root() / "mcp-servers"


@lru_cache(maxsize=1)
def first_party_servers() -> frozenset[str]:
    return frozenset(path.parent.name.removeprefix("mcp-") for path in ROOT.glob("mcp-*/server.py"))


@lru_cache(maxsize=1)
def registered_mcp_tools() -> frozenset[str]:
    names = set()
    for path in ROOT.glob("mcp-*/server.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        server = path.parent.name.removeprefix("mcp-")
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                func = decorator.func if isinstance(decorator, ast.Call) else decorator
                is_direct_tool = (isinstance(func, ast.Attribute) and func.attr == "tool"
                                  and isinstance(func.value, ast.Name) and func.value.id == "mcp")
                is_lazy_memory_tool = (server == "memory-server" and isinstance(func, ast.Name)
                                       and func.id == "memory_tool")
                if is_direct_tool or is_lazy_memory_tool:
                    tool_name = node.name
                    if isinstance(decorator, ast.Call):
                        for keyword in decorator.keywords:
                            if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                                tool_name = str(keyword.value.value)
                    names.add(f"{server}_{tool_name}")
    return frozenset(names)
