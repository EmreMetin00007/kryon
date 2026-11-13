#!/usr/bin/env python3
"""
MCP inventory profile manager
Dynamically manages MCP server profiles based on task type
"""
import json
import os
import re
import sys
from pathlib import Path
try:
    from .mcp_inventory import first_party_servers
    from .runtime_paths import runtime_root
except ImportError:
    from mcp_inventory import first_party_servers
    from runtime_paths import runtime_root

class ProfileManager:
    def __init__(self, config_dir=None):
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            # Runtime assets are independent of an agent client
            self.config_dir = runtime_root() / "config"

        self.profiles_file = self.config_dir / "profiles.json"
        self.servers_file = self.config_dir / "mcp-servers.json"
        self.profiles = self._load_profiles()

    def _load_profiles(self):
        """Load profile configurations"""
        if not self.profiles_file.exists():
            raise FileNotFoundError(f"Profiles file not found: {self.profiles_file}")

        with open(self.profiles_file) as f:
            return json.load(f)

    def detect_profile(self, task_description):
        """Auto-detect profile based on task description"""
        if not self.profiles.get("auto_detect", {}).get("enabled", False):
            return "web"

        rules = self.profiles["auto_detect"].get("rules", [])
        for rule in rules:
            pattern = rule["pattern"]
            if re.search(pattern, task_description):
                return rule["profile"]

        return "web"

    def apply_profile(self, profile_name):
        """Apply a profile to mcp-servers.json"""
        if profile_name not in self.profiles["profiles"]:
            raise ValueError(f"Unknown profile: {profile_name}")

        profile = self.profiles["profiles"][profile_name]

        # Load current mcp-servers.json
        with open(self.servers_file) as f:
            config = json.load(f)

        # Update MCP servers
        mcp_config = {}
        for server_name in profile["servers"]:
            if server_name in config["mcp"]:
                server_config = config["mcp"][server_name].copy()
                server_config["enabled"] = True

                # Add kali groups if specified
                if server_name == "kali-tools" and profile.get("kali_groups"):
                    if "environment" not in server_config:
                        server_config["environment"] = {}
                    server_config["environment"]["CCO_KALI_GROUPS"] = profile["kali_groups"]

                mcp_config[server_name] = server_config

        # Disable known servers not in profile; leave custom/unknown servers
        # (e.g. user-added remote MCPs like burp) untouched.
        known_servers = set(first_party_servers()) | set(self.profiles["profiles"]["full"]["servers"])
        for server_name, server_config in config["mcp"].items():
            if server_name not in profile["servers"] and server_name in known_servers:
                server_config["enabled"] = False
                mcp_config[server_name] = server_config
            elif server_name not in profile["servers"]:
                mcp_config[server_name] = server_config

        config["mcp"] = mcp_config

        # Save updated config
        with open(self.servers_file, "w") as f:
            json.dump(config, f, indent=2)

        return {
            "profile": profile_name,
            "description": profile["description"],
            "enabled_servers": sum(bool(entry.get("enabled", False)) for entry in mcp_config.values()),
            "missing_servers": [name for name in profile["servers"] if name not in config["mcp"]],
            "estimated_tokens": profile["estimated_tokens"]
        }

    def list_profiles(self):
        """List all available profiles"""
        profiles = []
        for name, profile in self.profiles["profiles"].items():
            profiles.append({
                "name": name,
                "description": profile["description"],
                "servers": len(profile["servers"]),
                "estimated_tokens": profile["estimated_tokens"]
            })
        return profiles

    def get_current_profile(self):
        """Detect current active profile"""
        with open(self.servers_file) as f:
            config = json.load(f)

        enabled_servers = [
            name for name, cfg in config["mcp"].items()
            if cfg.get("enabled", False)
        ]

        # Ignore custom/unknown servers (not in full profile) when matching.
        known_servers = set(first_party_servers()) | set(self.profiles["profiles"]["full"]["servers"])
        enabled_servers = [name for name in enabled_servers if name in known_servers]

        # Match against profiles
        for name, profile in self.profiles["profiles"].items():
            if set(enabled_servers) == set(profile["servers"]):
                return name

        return "custom"

def main():
    import argparse

    parser = argparse.ArgumentParser(description="CCO Profile Manager")
    parser.add_argument("action", choices=["list", "apply", "detect", "current"],
                       help="Action to perform")
    parser.add_argument("profile", nargs="?", help="Profile name (for apply)")
    parser.add_argument("--task", help="Task description (for detect)")
    parser.add_argument("--config-dir", help="Config directory path")

    args = parser.parse_args()

    try:
        manager = ProfileManager(args.config_dir)

        if args.action == "list":
            profiles = manager.list_profiles()
            print("Available Profiles:")
            print("-" * 60)
            for p in profiles:
                print(f"  {p['name']:10} | {p['description']:40} | ~{p['estimated_tokens']:,} tokens")
            print("-" * 60)

        elif args.action == "apply":
            if not args.profile:
                print("Error: profile name required for apply")
                sys.exit(1)
            result = manager.apply_profile(args.profile)
            print(f"✓ Profile '{result['profile']}' applied")
            print(f"  Description: {result['description']}")
            print(f"  Enabled servers: {result['enabled_servers']}")
            print(f"  Estimated tokens: ~{result['estimated_tokens']:,}")
            print("\n→ Profile applies to MCP inventory; the Python solver retains its bounded tool catalog")

        elif args.action == "detect":
            if not args.task:
                print("Error: --task required for detect")
                sys.exit(1)
            profile = manager.detect_profile(args.task)
            print(f"Detected profile: {profile}")
            print(f"Apply with: python3 {__file__} apply {profile}")

        elif args.action == "current":
            profile = manager.get_current_profile()
            print(f"Current profile: {profile}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
