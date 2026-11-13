"""Faz B: loop, Authorization'daki JWT'yi görünce jwt_kid_jku kancasını ateşler."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "mcp-servers" / "mcp-hunter"))

from cco_hunter_core.loop import execute_web_loop  # noqa: E402

TOK = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig-nature_1"


def test_loop_fires_jwt_hook_when_bearer_present():
    seen = {}

    def hook(url, token):
        seen["url"], seen["token"] = url, token
        return "CONFIRMED kid/jku (fake)"

    out = execute_web_loop(
        "https://t.local/api", live=True,
        headers=f"Authorization: Bearer {TOK}",
        fuzz=lambda target, **kw: {"probes": 0, "likely_hits": [], "validator_queue": []},
        surface_hooks={"jwt_kid_jku": hook},
    )
    assert seen == {"url": "https://t.local/api", "token": TOK}
    assert any(p["hook"] == "jwt_kid_jku" for p in out["surface_probes"])
    assert "jwt_kid_jku" in out["steps"]


def test_loop_skips_jwt_hook_without_token():
    out = execute_web_loop(
        "https://t.local/api", live=True, headers="Cookie: a=b",
        fuzz=lambda target, **kw: {"probes": 0, "likely_hits": [], "validator_queue": []},
        surface_hooks={"jwt_kid_jku": lambda u, t: "x"},
    )
    assert not any(p["hook"] == "jwt_kid_jku" for p in out["surface_probes"])
