"""Versioned re-evaluation of existing experiment runs.

Reads run-*.json records, applies the current scorer to the preserved
lab log and claims, and writes run-*-v2.json files plus a summary.
Original files are never modified; their sha256 is recorded in the
re-evaluated output for provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "lab"))

from discovery_experiment import SCORER_VERSION, score  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True, help="directory containing run-*.json")
    args = ap.parse_args()
    runs_dir = Path(args.runs).expanduser()
    summary = []
    for path in sorted(runs_dir.glob("run-*.json")):
        if path.stem.endswith("-v2"):
            continue
        original_bytes = path.read_bytes()
        record = json.loads(original_bytes)
        claims = (record.get("final_report") or {}).get("detected_differences", [])
        if record.get("final_report") is None and record.get("partial_report"):
            claims = record["partial_report"].get("submitted_findings", [])
        new_score = score(record.get("lab_log", []), claims)
        out = {"source_file": path.name,
               "source_sha256": hashlib.sha256(original_bytes).hexdigest(),
               "scorer": SCORER_VERSION,
               "kind": record.get("kind"), "repeat": record.get("repeat"),
               "js_variant": record.get("js_variant", "misleading"),
               "old_score": record.get("score"),
               "new_score": new_score}
        target = runs_dir / f"{path.stem}-v2.json"
        target.write_text(json.dumps(out, indent=1, ensure_ascii=False))
        summary.append(out)
        print(f"{path.name}: FP { (record.get('score') or {}).get('false_positive_claims') } -> "
              f"{new_score['false_positive_claims']}, positives {new_score['positives_found']}/2")
    (runs_dir / "reevaluation-v2-summary.json").write_text(
        json.dumps(summary, indent=1, ensure_ascii=False))
    print(f"wrote {len(summary)} re-evaluations to {runs_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
