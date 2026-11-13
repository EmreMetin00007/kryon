#!/usr/bin/env python3
"""MCP server/tool sayilarinin tek kaynagi.

Gerçek MCP dekoratörleri AST ile okunur; sunucular import edilmez.
Dokumanlardaki toplamlar buradan uretilir:

    python3 scripts/tool_counts.py            # markdown tablo
    python3 scripts/tool_counts.py --json     # makine ciktisi
"""
import argparse
import json
try:
    from .mcp_inventory import first_party_servers, registered_mcp_tools
except ImportError:
    from mcp_inventory import first_party_servers, registered_mcp_tools


def actual_counts() -> dict[str, int]:
    counts = {server: 0 for server in sorted(first_party_servers())}
    for tool in registered_mcp_tools():
        server, _, _ = tool.partition("_")
        if server in counts:
            counts[server] += 1
    return counts


def expected_counts() -> dict[str, int]:
    """Compatibility alias; return the live inventory, not test constants."""
    return actual_counts()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    counts = actual_counts()
    total = sum(counts.values())
    if args.json:
        print(json.dumps({"servers": len(counts), "tools": total, "per_server": counts}, indent=2))
        return 0
    print(f"{len(counts)} MCP server, {total} tool\n")
    print("| Server | Tool |")
    print("|---|---|")
    for name in sorted(counts):
        print(f"| mcp-{name} | {counts[name]} |")
    print(f"| **Toplam** | **{total}** |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
