#!/usr/bin/env python3
"""Run owned HTTP/Chromium acceptance and retain an explicit result manifest."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SEEDS = [20261104, 20261105, 20261106, 20261107, 20261108]
EXPECTED_TESTS = 37  # 32 wire guardrails + five Chromium-to-campaign seeds.


def preflight():
    checks = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
        checks.append({"name": "loopback_socket", "ok": True})
    except OSError as exc:
        checks.append({"name": "loopback_socket", "ok": False,
                       "error": type(exc).__name__, "errno": exc.errno, "detail": str(exc)})
        return checks  # Chromium also needs sockets; avoid a redundant launch.
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                checks.append({"name": "chromium", "ok": True, "version": browser.version})
            finally:
                browser.close()
    except Exception as exc:
        checks.append({"name": "chromium", "ok": False, "error": type(exc).__name__,
                       "detail": str(exc)[:500]})
    return checks


def assess_results(junit_path, test_directory):
    """Reject skipped/incomplete runs and require each seed's measured evidence."""
    root = ET.parse(junit_path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    counts = {key: sum(int(suite.get(key, 0)) for suite in suites)
              for key in ("tests", "errors", "failures", "skipped")}
    if counts != {"tests": EXPECTED_TESTS, "errors": 0, "failures": 0, "skipped": 0}:
        raise ValueError(f"incomplete or failing acceptance: {counts}")
    runs = {}
    paths = {path.resolve() for path in Path(test_directory).glob(
        "test_real_chromium_surface_to_*/automatic-campaign-controls.json")}
    for path in sorted(paths):
        row = json.loads(path.read_text())
        seed, score = row["seed"], row["score"]
        if seed in runs:
            raise ValueError("duplicate seed evidence")
        if (row["mode"] != "real_http_chromium" or score["proven"] < 6 or score["positives"] != 8
                or score["negatives_clean"] != 8 or score["negatives_evaluated"] != 8
                or score["fp_rate"] != 0 or score["negative_coverage"] != 1):
            raise ValueError("seed does not meet acceptance criteria")
        phases = [row[key] for key in (
            "preparation_requests", "browser_requests", "discovery_requests", "campaign_requests")]
        if any(type(value) is not int or value < 0 for value in phases):
            raise ValueError("invalid phase request accounting")
        if (type(row["requests"]) is not int or not 0 < row["requests"] <= 300
                or row["requests"] != sum(phases) or row["browser_requests"] < 1):
            raise ValueError("request ceiling or phase accounting failed")
        wire = json.loads((path.parent / "received-wire.json").read_text())
        browser = json.loads((path.parent / "chromium-discovery.json").read_text())
        origin = urlsplit(wire["base"])
        if (origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.port is None
                or origin.path != "/" or origin.query or origin.fragment or origin.username is not None):
            raise ValueError("wire evidence must belong to an exact test-owned loopback origin")
        requests = wire["requests"]
        if (wire["mode"] != row["mode"] or wire["seed"] != seed
                or wire["received_requests"] != row["requests"] or len(requests) != row["requests"]
                or not all(r["method"] == "GET" and r["program_header_present"]
                           and r["url"].startswith(wire["base"]) for r in requests)
                or browser["fallback"] is not False or browser["requests"] != row["browser_requests"]
                or not browser["parameterized_links"] or not browser["ingest"] or browser["ingest"].get("error")):
            raise ValueError("server/browser evidence does not match the campaign")
        runs[seed] = row
    if sorted(runs) != SEEDS:
        raise ValueError("five distinct seed artifacts required")
    return {"tests": counts, "runs": [runs[seed] for seed in SEEDS]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        default=Path(os.environ.get("CCO_WORKDIR", "~/cco-work")).expanduser() / "http-chromium-acceptance")
    parser.add_argument("--check-only", action="store_true", help="check socket and Chromium availability")
    args = parser.parse_args(argv)
    output = args.output_dir.expanduser().resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error("acceptance data must live outside the code repository")
    output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    manifest = {"schema": "http-chromium-acceptance/1", "mode": "real_http_chromium",
                "started_at": datetime.now(timezone.utc).isoformat(), "status": "environment_unavailable",
                "scope": "test-owned ephemeral loopback origins; per-test scope and approvals",
                "checks": preflight(), "directory": str(directory)}
    code = 2
    if all(check["ok"] for check in manifest["checks"]):
        if args.check_only:
            manifest["status"] = "ready"
            code = 0
        else:
            command = [sys.executable, "-m", "pytest", "tests/test_http_chromium_lab.py",
                       "tests/test_http_chromium_campaign.py::test_real_chromium_surface_to_observed_campaign",
                       "-q", "--tb=short",
                       f"--basetemp={directory / 'tests'}", f"--junitxml={directory / 'junit.xml'}"]
            manifest["command"] = command
            environment = dict(os.environ, CCO_RUN_WIRE_LAB="1", CCO_WORKDIR=str(directory / "work"))
            # Parent sessions must not provide credentials to acceptance.
            for key in ("CCO_BROWSER_CDP", "CCO_VAULT_KEY", "CCO_WORKER_ALLOWED_TOOLS"):
                environment.pop(key, None)
            try:
                with (directory / "pytest.log").open("w") as log:
                    result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log,
                                            stderr=subprocess.STDOUT, timeout=1800, check=False)
                manifest["pytest_exit_code"] = result.returncode
                if result.returncode:
                    raise ValueError("pytest acceptance failed; see pytest.log and junit.xml")
                manifest.update(assess_results(directory / "junit.xml", directory / "tests"))
                manifest["status"], code = "passed", 0
            except (ValueError, OSError, KeyError, TypeError, ET.ParseError, subprocess.TimeoutExpired) as exc:
                manifest["status"], code = "failed", 1
                manifest["error"] = f"{type(exc).__name__}: {exc}"
    manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
    path = directory / "acceptance.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": manifest["status"], "artifact": str(path)}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
