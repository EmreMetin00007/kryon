"""Pytest collection must not initialize a caller's real workspace state."""
import os
import subprocess
import sys
from pathlib import Path


def test_collection_isolated_before_module_import(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sentinel = tmp_path / "caller-home"
    env = dict(os.environ, CCO_HOME=str(sentinel), CCO_GRAPH_BACKEND="networkx",
               PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/test_memory_summary.py"],
        cwd=root, env=env, capture_output=True, text=True, timeout=45,
    )
    assert result.returncode == 0, result.stdout[-1500:] + result.stderr[-1500:]
    assert not sentinel.exists()


def test_memory_import_and_tool_listing_do_not_initialize_caller_state(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sentinel = tmp_path / "caller-home"
    env = dict(os.environ, CCO_HOME=str(sentinel), CCO_GRAPH_BACKEND="networkx")
    code = '''
import asyncio, importlib.util, sys
path = sys.argv[1]
spec = importlib.util.spec_from_file_location("isolated_memory_import", path)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)
assert len(asyncio.run(mod.mcp.list_tools())) == 15
'''
    result = subprocess.run([sys.executable, "-c", code, str(root / "mcp-servers/mcp-memory-server/server.py")],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr[-1500:]
    assert not sentinel.exists()
