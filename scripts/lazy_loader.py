#!/usr/bin/env python3
"""
Lazy MCP Server Loader
Delays server startup until first use to reduce initial token load
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

class LazyServerLoader:
    def __init__(self, config_file=None):
        self.config_file = config_file or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "config", "mcp-servers.json"
        )
        self.servers = {}
        self.processes = {}
        self._load_config()

    def _load_config(self):
        """Load server configurations"""
        with open(self.config_file) as f:
            config = json.load(f)

        for name, cfg in config.get("mcp", {}).items():
            if cfg.get("enabled", False):
                self.servers[name] = cfg

    def start_server(self, server_name):
        """Start a server on demand"""
        if server_name not in self.servers:
            raise ValueError(f"Unknown server: {server_name}")

        if server_name in self.processes:
            # Check if process is still running
            proc = self.processes[server_name]
            if proc.poll() is None:
                return {"status": "already_running", "pid": proc.pid}
            else:
                # Process died, restart it
                del self.processes[server_name]

        cfg = self.servers[server_name]
        cmd = cfg["command"]
        cwd = cfg.get("cwd", ".")
        env = os.environ.copy()
        env.update(cfg.get("environment", {}))

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.processes[server_name] = proc

            return {
                "status": "started",
                "pid": proc.pid,
                "server": server_name
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "server": server_name
            }

    def stop_server(self, server_name):
        """Stop a running server"""
        if server_name not in self.processes:
            return {"status": "not_running", "server": server_name}

        proc = self.processes[server_name]
        proc.terminate()

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        del self.processes[server_name]

        return {"status": "stopped", "server": server_name}

    def get_server_status(self, server_name=None):
        """Get status of one or all servers"""
        if server_name:
            if server_name in self.processes:
                proc = self.processes[server_name]
                return {
                    "server": server_name,
                    "status": "running" if proc.poll() is None else "stopped",
                    "pid": proc.pid
                }
            return {"server": server_name, "status": "not_started"}

        # Return all servers
        status = {}
        for name in self.servers:
            status[name] = self.get_server_status(name)
        return status

    def start_all(self):
        """Start all enabled servers"""
        results = {}
        for name in self.servers:
            results[name] = self.start_server(name)
        return results

    def stop_all(self):
        """Stop all running servers"""
        results = {}
        for name in list(self.processes.keys()):
            results[name] = self.stop_server(name)
        return results

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Lazy MCP Server Loader")
    parser.add_argument("action", choices=["start", "stop", "status", "start-all", "stop-all"],
                       help="Action to perform")
    parser.add_argument("server", nargs="?", help="Server name")
    parser.add_argument("--config", help="Config file path")

    args = parser.parse_args()

    try:
        loader = LazyServerLoader(args.config)

        if args.action == "start":
            if not args.server:
                print("Error: server name required")
                sys.exit(1)
            result = loader.start_server(args.server)
            print(json.dumps(result, indent=2))

        elif args.action == "stop":
            if not args.server:
                print("Error: server name required")
                sys.exit(1)
            result = loader.stop_server(args.server)
            print(json.dumps(result, indent=2))

        elif args.action == "status":
            result = loader.get_server_status(args.server)
            print(json.dumps(result, indent=2))

        elif args.action == "start-all":
            results = loader.start_all()
            print(json.dumps(results, indent=2))

        elif args.action == "stop-all":
            results = loader.stop_all()
            print(json.dumps(results, indent=2))

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()