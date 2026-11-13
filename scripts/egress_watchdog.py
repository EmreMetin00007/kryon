#!/usr/bin/env python3
"""Egress watchdog: gozetimsiz ag konusmalarini tespit et, raporla, durdur.

Gate (policy) komut aninda karar verir; bu script calisma aninda denetler:
`ss` ile ESTABLISHED baglantilari sureclere baglar, her uzak host icin
scope + grant (lease) kontrolu yapar.

Hedef: ApexCore session'indaki gibi saatlerce calisan `nohup` fuzz'lar.
Varsayilan kip salt rapor; `--enforce` yalnizca BOTH kosullari saglayan
surecleri oldurur:

- saldirgan-arac profili (python/curl/ffuf/...) + kendi soy agacimiz disinda,
- kalici + agir (yas >= `--min-age`, baglanti >= `--min-connections`),
- out-of-scope VEYA leasesiz (canli grant yok).

Tek seferlik `curl`'ler ve runtime baglantilari (node/opencode) asla
oldurulmez. Kullanim: `./scripts/cco.sh ...` yerine dogrudan veya
cron/systemd-timer ile periyodik.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from policy_engine import PolicyEngine
except ImportError:  # pragma: no cover
    PolicyEngine = None  # type: ignore

# oldurme karari icin arac profili (kendi runtime'imiz haric).
TOOL_PROFILE_RE = re.compile(
    r"(?i)(?:^|/)(?:python3?(?:\.\d+)?|curl|wget|aria2c|ffuf|gobuster|"
    r"feroxbuster|dirsearch|nuclei|masscan|rustscan|nmap|nikto|sqlmap|"
    r"ghauri|hydra|medusa|wpscan|amass|subfinder|ruby|perl|php(?:\d+)?|"
    r"perl5|sh|bash|dash)\b"
)

# Asla dokunulmayacaklar.
PROTECTED_RE = re.compile(
    r"(?i)(?:^|/)(?:sshd?|systemd|dbus|node|deno|bun|opencode|docker|"
    r"containerd|firefox|chrome|chromium|java|postgres|mysql|redis|"
    r"ss$|egress_watchdog)"
)

SS_LINE_RE = re.compile(
    r"^(?P<state>\S+)\s+\S+\s+\S+\s+(?P<local>\S+)\s+(?P<peer>\S+)"
    r"(?:\s+users:\(\(\"(?P<proc>[^\"]+)\",pid=(?P<pid>\d+),fd=\d+\)\))?"
)

MAX_CMDLINE = 300


def parse_ss(output: str) -> list[dict]:
    """`ss -tnp` ciktisini baglanti listesine cevir (pure)."""
    conns: list[dict] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.startswith("State"):
            continue
        match = SS_LINE_RE.match(line)
        if not match:
            continue
        peer = match.group("peer")
        host, _, port = peer.rpartition(":")
        host = host.strip("[]")
        if not host or host == "*":
            continue
        pid = match.group("pid")
        conns.append({
            "state": match.group("state"),
            "peer_host": host,
            "peer_port": port,
            "proc": match.group("proc") or "",
            "pid": int(pid) if pid else 0,
        })
    return conns


def _own_ancestry() -> set[int]:
    """Kendimiz + ebeveyn zinciri (koruma)."""
    pids = {os.getpid()}
    try:
        pid = os.getpid()
        for _ in range(64):
            with open(f"/proc/{pid}/stat") as handle:
                ppid = int(handle.read().rsplit(")", 1)[1].split()[1])
            if ppid <= 1 or ppid in pids:
                break
            pids.add(ppid)
            pid = ppid
    except (OSError, ValueError, IndexError):
        pass
    return pids


def read_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return raw.replace(b"\0", b" ").decode("utf-8", errors="replace").strip()[:MAX_CMDLINE]
    except OSError:
        return ""


def process_age(pid: int) -> float:
    """Surec yasi (saniye); bilinmiyorsa -1."""
    try:
        out = subprocess.run(["ps", "-p", str(pid), "-o", "etimes="],
                             capture_output=True, text=True, timeout=5)
        return float(out.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return -1.0


def group_by_process(conns: list[dict], include_loopback: bool = False) -> list[dict]:
    procs: dict[int, dict] = {}
    for conn in conns:
        if conn["state"] != "ESTAB" or not conn["pid"]:
            continue
        host = conn["peer_host"]
        if not include_loopback and host in {"127.0.0.1", "::1"}:
            continue
        entry = procs.setdefault(conn["pid"], {
            "pid": conn["pid"], "proc": conn["proc"], "conns": 0,
            "peers": set(), "cmdline": "", "age": -1.0,
        })
        entry["conns"] += 1
        entry["peers"].add(f"{host}:{conn['peer_port']}")
    result = []
    for entry in procs.values():
        entry["cmdline"] = read_cmdline(entry["pid"])
        entry["age"] = process_age(entry["pid"])
        entry["peers"] = sorted(entry["peers"])
        result.append(entry)
    result.sort(key=lambda e: e["conns"], reverse=True)
    return result


def _live_grants(engine) -> list[dict]:
    now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    conn = engine._connect()
    try:
        rows = conn.execute(
            "SELECT tool_pattern, target_pattern FROM approval_grants "
            "WHERE revoked_at='' AND expires_at>?", (now,)).fetchall()
        return [{"tool_pattern": r[0], "target_pattern": r[1]} for r in rows]
    finally:
        conn.close()


def host_in_scope(engine, host: str) -> bool:
    try:
        return bool(engine._scope_allows(host, ""))
    except Exception:
        return False


def host_leased(engine, host: str, grants: list[dict]) -> bool:
    """Herhangi bir canli grant bu host'u kapsiyor mu (arac-bagimsiz lease)?"""
    from fnmatch import fnmatch

    for grant in grants:
        pattern = grant.get("target_pattern", "")
        if pattern == "*" or fnmatch(host, pattern) or host == pattern:
            return True
        try:
            if engine._approval_target_allows(pattern, host):
                return True
        except Exception:
            continue
    return False


def assess(proc: dict, engine, grants: list[dict]) -> dict:
    """Verdict: ok | unleased | out_of_scope (+ heavy bayragi)."""
    hosts = sorted({peer.rsplit(":", 1)[0].strip("[]") for peer in proc["peers"]})
    out_of_scope = [h for h in hosts if not host_in_scope(engine, h)]
    unleased = [h for h in hosts
                if h not in out_of_scope and not host_leased(engine, h, grants)]
    if out_of_scope:
        verdict = "out_of_scope"
    elif unleased:
        verdict = "unleased"
    else:
        verdict = "ok"
    return {"verdict": verdict, "hosts": hosts,
            "out_of_scope": out_of_scope, "unleased": unleased}


def killable(proc: dict, verdict: dict, ancestry: set[int],
             min_connections: int, min_age: float) -> tuple[bool, str]:
    """Oldurme karari + gerekce. Suphede oldurme."""
    pid = proc["pid"]
    if pid in ancestry or pid <= 1:
        return False, "protected: own ancestry"
    blob = f"{proc['proc']} {proc['cmdline']}"
    if PROTECTED_RE.search(blob):
        return False, "protected: system/runtime process"
    if not TOOL_PROFILE_RE.search(blob):
        return False, "not an agent-tool profile"
    if proc["conns"] < min_connections:
        return False, f"below connection floor ({proc['conns']})"
    if proc["age"] >= 0 and proc["age"] < min_age:
        return False, f"too young ({proc['age']:.0f}s)"
    if verdict["verdict"] == "ok":
        return False, "leased and in-scope"
    return True, verdict["verdict"]


def terminate_process(pid: int, grace_seconds: float = 3.0) -> bool:
    try:
        os.kill(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        return False
    deadline = time.time() + grace_seconds
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except (OSError, ProcessLookupError):
            return True
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except (OSError, ProcessLookupError):
        return True


def run_ss() -> str:
    try:
        out = subprocess.run(["ss", "-tnp"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"ss calistirilamadi: {exc}")
    if out.returncode != 0:
        raise RuntimeError(f"ss hata verdi: {out.stderr.strip()[:200]}")
    return out.stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCO egress watchdog")
    parser.add_argument("--json", action="store_true", help="JSON rapor")
    parser.add_argument("--enforce", action="store_true",
                        help="leasesiz agir konusmacilari oldur")
    parser.add_argument("--min-connections", type=int, default=5)
    parser.add_argument("--min-age", type=float, default=120.0)
    parser.add_argument("--include-loopback", action="store_true")
    parser.add_argument("--ss-file", default="",
                        help="Canli ss yerine dosya (test/cevrimdisi)")
    parser.add_argument("--cco-home", default=None)
    args = parser.parse_args(argv)

    if PolicyEngine is None:
        print("policy_engine yuklenemedi", file=sys.stderr)
        return 1
    try:
        raw = Path(args.ss_file).read_text() if args.ss_file else run_ss()
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    engine = PolicyEngine(cco_home=args.cco_home) if args.cco_home else PolicyEngine()
    grants = _live_grants(engine)
    ancestry = _own_ancestry()
    report: list[dict] = []
    killed: list[int] = []
    for proc in group_by_process(parse_ss(raw), args.include_loopback):
        verdict = assess(proc, engine, grants)
        can_kill, why = killable(proc, verdict, ancestry,
                                 args.min_connections, args.min_age)
        action = "none"
        if args.enforce and can_kill and terminate_process(proc["pid"]):
            action = "killed"
            killed.append(proc["pid"])
        report.append({**proc, **verdict, "killable": can_kill,
                       "kill_reason": why, "action": action})

    if args.json:
        print(json.dumps({"processes": report, "killed": killed,
                          "enforce": args.enforce}, indent=2, ensure_ascii=False))
        return 0
    if not report:
        print("Egress temiz: ESTABLISHED agent baglantisi yok.")
        return 0
    print(f"{'PID':>7} {'CONN':>5} {'AGE':>7} {'VERDICT':<12} CMD")
    for entry in report:
        age = f"{entry['age']:.0f}s" if entry["age"] >= 0 else "?"
        cmd = (entry["cmdline"] or entry["proc"])[:100]
        mark = " [KILLED]" if entry["action"] == "killed" else (
            " [KILLABLE]" if entry["killable"] else "")
        print(f"{entry['pid']:>7} {entry['conns']:>5} {age:>7} "
              f"{entry['verdict']:<12} {cmd}{mark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
