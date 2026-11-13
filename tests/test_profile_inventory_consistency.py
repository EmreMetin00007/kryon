"""First-party profile and count reports must reflect the real inventory."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from profile_manager import ProfileManager  # noqa: E402
from tool_counts import actual_counts  # noqa: E402


def test_profile_disables_all_first_party_and_counts_custom(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "profiles.json").write_text((ROOT / "config" / "profiles.json").read_text())
    servers = {path.parent.name.removeprefix("mcp-"): {"enabled": True}
               for path in (ROOT / "mcp-servers").glob("mcp-*/server.py")}
    servers["custom-remote"] = {"enabled": True, "url": "https://custom.invalid"}
    config_path = config_dir / "mcp-servers.json"
    config_path.write_text(json.dumps({"mcp": servers}))
    manager = ProfileManager(config_dir)
    result = manager.apply_profile("min")
    output = json.loads(config_path.read_text())["mcp"]
    assert not output["agent-browse"]["enabled"] and not output["otp"]["enabled"]
    assert output["custom-remote"]["enabled"]
    assert result["enabled_servers"] == sum(bool(entry.get("enabled")) for entry in output.values()) == 5
    assert manager.get_current_profile() == "min"


def test_full_profile_and_tool_count_follow_real_server_decorators():
    profiles = json.loads((ROOT / "config" / "profiles.json").read_text())["profiles"]
    servers = {path.parent.name.removeprefix("mcp-")
               for path in (ROOT / "mcp-servers").glob("mcp-*/server.py")}
    assert set(profiles["full"]["servers"]) == servers
    counts = actual_counts()
    assert set(counts) == servers and counts["hunter"] >= 16
