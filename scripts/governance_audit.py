#!/usr/bin/env python3
"""Secret and PII governance audit with redacted findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path


SKIP_DIRS = {
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
}
RUNTIME_DIRS = {".cco", ".hackeragent", "loot", "screenshots"}
SENSITIVE_FILENAMES = {".env", ".env.local", "credentials.json", ".credentials"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
TEXT_SUFFIXES = {
    ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".md", ".txt", ".sh",
    ".html", ".css", ".xml", ".ini", ".cfg", ".conf", ".env.example",
}


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    pattern: re.Pattern


SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)['\"]?\b(api[_-]?key|secret|token|password)\b['\"]?\s*[:=]\s*"
    r"(?:'[^'\r\n]{12,}'|\"[^\"\r\n]{12,}\"|[A-Za-z0-9_+/=-]{16,})"
)
ENV_SECRET_REFERENCE_RE = re.compile(
    r"(?i)['\"]?\b(api[_-]?key|secret|token|password)\b['\"]?\s*[:=]\s*"
    r"(?P<quote>['\"])\{env:[A-Za-z_][A-Za-z0-9_]*\}(?P=quote)"
)


RULES = [
    Rule("aws_access_key", "high", re.compile(r"AKIA[0-9A-Z]{16}")),
    Rule("private_key_block", "high", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    Rule("bearer_token", "high", re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{20,}")),
    Rule("jwt", "high", re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")),
    Rule("secret_assignment", "high", SECRET_ASSIGNMENT_RE),
    Rule("email_pii", "medium", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Rule("phone_pii", "medium", re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{8,}\d)(?!\d)")),
]


def _is_sensitive_file(path: Path) -> bool:
    name = path.name.lower()
    if name in SENSITIVE_FILENAMES or name.startswith(".env."):
        return True
    return path.suffix.lower() in SENSITIVE_SUFFIXES


def _is_text_candidate(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    return path.name in {"Dockerfile", "Makefile", "AGENTS.md", "CLAUDE.md", "README.md"}


def _redacted_excerpt(line: str, match: re.Match) -> str:
    start, end = match.span()
    prefix = line[max(0, start - 24):start]
    suffix = line[end:min(len(line), end + 24)]
    return f"{prefix}<redacted>{suffix}".strip()


def _fingerprint(path: str, rule: str, excerpt: str) -> str:
    payload = json.dumps({"path": path, "rule": rule, "excerpt": excerpt}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _load_filter_file(path: str | Path | None) -> dict:
    if not path:
        return {"fingerprints": set(), "path_rules": set()}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {"fingerprints": set(), "path_rules": set()}
    fingerprints = set()
    path_rules = set()
    for item in data.get("findings", []) if isinstance(data, dict) else []:
        if isinstance(item, dict) and item.get("fingerprint"):
            fingerprints.add(str(item["fingerprint"]))
    for item in data.get("allow", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        if item.get("fingerprint"):
            fingerprints.add(str(item["fingerprint"]))
        if item.get("path") and item.get("rule"):
            path_rules.add((str(item["path"]), str(item["rule"])))
    return {"fingerprints": fingerprints, "path_rules": path_rules}


def _iter_files(root: Path, include_runtime: bool):
    for current, dirs, files in os.walk(root):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS and (include_runtime or d not in RUNTIME_DIRS)
        ]
        for filename in files:
            path = Path(current) / filename
            rel = path.relative_to(root)
            if any(part in SKIP_DIRS for part in rel.parts):
                continue
            if not include_runtime and any(part in RUNTIME_DIRS for part in rel.parts):
                continue
            yield path


def run_audit(root: str | Path, include_runtime: bool = False, max_file_bytes: int = 512_000,
              baseline_file: str | Path | None = None, allowlist_file: str | Path | None = None) -> dict:
    root = Path(root).expanduser().resolve()
    findings = []
    suppressed = []
    skipped_sensitive = []
    skipped_large = []
    baseline = _load_filter_file(baseline_file)
    allowlist = _load_filter_file(allowlist_file)
    for path in _iter_files(root, include_runtime):
        rel = str(path.relative_to(root))
        if _is_sensitive_file(path):
            skipped_sensitive.append(rel)
            continue
        if not _is_text_candidate(path):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_file_bytes:
            skipped_large.append(rel)
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for rule in RULES:
                matches = list(rule.pattern.finditer(line))
                if rule.name == "secret_assignment":
                    # A runtime environment lookup contains no secret value.
                    # Keep scanning the line for other literal assignments.
                    matches = [match for match in matches
                               if not ENV_SECRET_REFERENCE_RE.fullmatch(match.group(0))]
                if not matches:
                    continue
                match = matches[0]
                excerpt = _redacted_excerpt(line, match)
                finding = {
                    "path": rel,
                    "line": line_no,
                    "rule": rule.name,
                    "severity": rule.severity,
                    "excerpt": excerpt,
                    "fingerprint": _fingerprint(rel, rule.name, excerpt),
                }
                if finding["fingerprint"] in baseline["fingerprints"]:
                    suppressed.append({**finding, "suppressed_by": "baseline"})
                    continue
                if finding["fingerprint"] in allowlist["fingerprints"] or (finding["path"], finding["rule"]) in allowlist["path_rules"]:
                    suppressed.append({**finding, "suppressed_by": "allowlist"})
                    continue
                findings.append(finding)
    summary = {"high": 0, "medium": 0, "low": 0, "total": len(findings)}
    for finding in findings:
        summary[finding["severity"]] = summary.get(finding["severity"], 0) + 1
    return {
        "root": str(root),
        "summary": summary,
        "findings": findings,
        "suppressed_findings": suppressed,
        "skipped_sensitive_files": sorted(skipped_sensitive),
        "skipped_large_files": sorted(skipped_large),
    }


def write_baseline(result: dict, output_path: str | Path) -> str:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    baseline = {
        "version": 1,
        "generated_by": "governance_audit",
        "findings": [
            {
                "fingerprint": item["fingerprint"],
                "path": item["path"],
                "rule": item["rule"],
                "severity": item["severity"],
            }
            for item in result.get("findings", [])
        ],
    }
    output.write_text(json.dumps(baseline, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return str(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCO secret/PII governance audit")
    parser.add_argument("--root", default=".")
    parser.add_argument("--include-runtime", action="store_true")
    parser.add_argument("--max-file-bytes", type=int, default=512_000)
    parser.add_argument("--format", choices=["json", "text"], default="json")
    parser.add_argument("--fail-on", choices=["none", "medium", "high"], default="none")
    parser.add_argument("--baseline", default="")
    parser.add_argument("--allowlist", default="")
    parser.add_argument("--write-baseline", default="")
    args = parser.parse_args(argv)
    result = run_audit(args.root, args.include_runtime, args.max_file_bytes, args.baseline or None, args.allowlist or None)
    if args.write_baseline:
        result["baseline_written"] = write_baseline(result, args.write_baseline)
    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        summary = result["summary"]
        print(f"Governance findings: high={summary['high']} medium={summary['medium']} low={summary['low']} total={summary['total']}")
        print(f"Suppressed findings: {len(result['suppressed_findings'])}")
        for finding in result["findings"][:50]:
            print(f"{finding['severity']} {finding['rule']} {finding['path']}:{finding['line']} {finding['excerpt']}")
    if args.fail_on == "high" and result["summary"]["high"]:
        return 2
    if args.fail_on == "medium" and (result["summary"]["high"] or result["summary"]["medium"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
