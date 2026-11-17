"""Host-rendered task registry and native worker contracts."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import re
from typing import Any

from brain import next_spec
from orchestration_spec import (TaskSpec, render_task_prompt, skeleton_summary,
                                validate_chain, validate_summary, validate_worker_prompt)


# Bounded summary limit: host-compiled validation_funnel and leaf_outcomes exceed 128 KiB on 80+ candidate leaves.
MAX_SUMMARY_BYTES = 1024 * 1024


class TaskRegistry:
    """Bounded, workspace-confined frozen TaskSpec and summary registry."""

    def __init__(self, specs, workdir, bindings, *, setup_checks_passed=False):
        if type(setup_checks_passed) is not bool:
            raise ValueError("setup_checks_passed must be boolean")
        self.workdir = Path(workdir).resolve()
        self.specs = [TaskSpec.from_dict(spec.to_dict()) for spec in specs]
        self.bindings = json.loads(json.dumps(bindings))
        self.setup_checks_passed = setup_checks_passed
        self.active_spec: TaskSpec | None = None
        self.normalizations = []
        errors = validate_chain(self.specs)
        if errors or any(spec.tool_profile != "broker" for spec in self.specs):
            raise ValueError("task registry requires a valid broker plan")
        for spec in self.specs:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", spec.id):
                raise ValueError("invalid task ID")
            self.confine(Path(spec.evidence_dir))

    def confine(self, path):
        path = Path(path).resolve()
        if path != self.workdir and self.workdir not in path.parents:
            raise ValueError("task path escapes workspace")
        return path

    def summary_path(self, spec):
        return self.confine(self.workdir / "summaries" / (spec.id + ".json"))

    def read_summary(self, spec):
        path = self.summary_path(spec)
        with path.open("rb") as handle:
            raw = handle.read(MAX_SUMMARY_BYTES + 1)
        if len(raw) > MAX_SUMMARY_BYTES:
            raise ValueError("native summary too large")
        summary = json.loads(raw)
        if not isinstance(summary, dict):
            raise ValueError("native summary must be an object")
        if summary.get("phase") != spec.phase or summary.get("target") != spec.target:
            raise ValueError("native summary phase/target mismatch")
        formats = (summary.get("surface") or {}).get("id_formats", []) if isinstance(summary.get("surface"), dict) else []
        changes = []
        aliases = {"integer": "int", "filename": "string", "email-like marker": "string"}
        if isinstance(formats, list):
            for index, entry in enumerate(formats):
                if not isinstance(entry, dict):
                    continue
                original = entry.get("format")
                if isinstance(original, str) and original in aliases:
                    entry["format"] = aliases[original]
                    changes.append({"field": f"surface.id_formats[{index}].format",
                                    "from": original, "to": entry["format"]})
                # Copy a supplied textual example only; never infer an ID,
                # ownership, status, evidence or a missing probe result.
                if "example" not in entry and isinstance(entry.get("value"), str) and entry["value"].strip():
                    entry["example"] = entry["value"]
                    changes.append({"field": f"surface.id_formats[{index}].example",
                                    "from": "value", "to": "example"})
        if changes:
            from full_agent_provider import dump
            dump(path, summary)
            self.normalizations.append({"spec_id": spec.id, "fields": [change["field"] for change in changes],
                "changes": changes, "from": changes[0]["from"], "to": changes[0]["to"],
                "before_sha256": hashlib.sha256(raw).hexdigest(),
                "after_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        return summary

    def normalize_summary_file(self, path):
        path = self.confine(self.workdir / path)
        for spec in self.specs:
            if self.summary_path(spec) == path:
                return self.read_summary(spec)
        raise ValueError("summary is outside the frozen task registry")

    def finalize_active(self, reason, evidence, private):
        """Preserve draft bytes and actual tool receipts after execution stops.

        This records interruption, never successful discovery or validation.
        Terminal valid summaries stay byte-for-byte unchanged. Bad drafts are
        retained in host-private storage rather than repaired into assertions.
        """
        from full_agent_provider import dump
        spec = self.active_spec
        if spec is None:
            raise ValueError("no active task spec")
        path = self.workdir / "summaries" / (spec.id + ".json")
        receipt = Path(spec.evidence_dir) / ("host-stop-" + spec.id + ".json")
        for candidate in (path, receipt):
            if any(p.is_symlink() for p in (candidate, *candidate.parents) if p != self.workdir):
                raise ValueError("host finalization refuses symlink paths")
            self.confine(candidate)
        raw = None
        summary: Any = None
        if path.exists():
            with path.open("rb") as handle:
                raw = handle.read(MAX_SUMMARY_BYTES + 1)
            if len(raw) > MAX_SUMMARY_BYTES:
                raise ValueError("native summary too large")
            try:
                summary = json.loads(raw)
            except (ValueError, UnicodeError):
                pass
        summary_dict: dict[str, Any] | None = (
            summary
            if isinstance(summary, dict) and summary.get("phase") == spec.phase and summary.get("target") == spec.target
            else None
        )
        record = {"spec_id": spec.id, "reason": reason, "summary": str(path),
                  "before_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None}
        if summary_dict is not None and not validate_summary(summary_dict):
            return {**record, "action": "terminal_summary_preserved", "status": summary_dict["status"]}
        if raw is not None:
            archive = Path(private) / ("summary-before-stop-" + spec.id + ".json")
            with archive.open("xb") as handle:
                handle.write(raw)
            record["preserved_draft"] = str(archive)
        # Keep all assertions and step states in a well-formed draft. Malformed
        # or wrong-target drafts remain solely in the unmodified archive.
        blocked = {**summary_dict, "status": "blocked"} if summary_dict is not None else None
        if blocked is None or validate_summary(blocked):
            blocked = {**skeleton_summary(spec), "status": "blocked"}
        receipt.parent.mkdir(parents=True, exist_ok=True)
        dump(receipt, {"schema": "native-task-interruption/1", **record,
                       "tool_artifacts": evidence, "artifacts_visibility": "host_private",
                       "security_validation_claimed": False, "acceptance_claimed": False})
        blocked["evidence"] = [*blocked["evidence"], {"kind": "host_interruption_receipt", "artifact": str(receipt)}]
        blocked["host_interruption"] = {"reason": reason, "receipt": str(receipt)}
        path.parent.mkdir(parents=True, exist_ok=True)
        dump(path, blocked)
        return {**record, "action": "blocked_summary_written", "status": "blocked",
                "receipt": str(receipt), "tool_artifact_count": len(evidence),
                "after_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


class NativeTasks(TaskRegistry):
    """Host-rendered native worker contracts; the planner sends task IDs only."""

    def __init__(self, specs, workdir, bindings, *, setup_checks_passed=False):
        super().__init__(specs, workdir, bindings, setup_checks_passed=setup_checks_passed)
        self.active_prompt = None

    def resolve(self, args):
        # Accept the canonical pointer or the ID in an older rendered prompt.
        # All model-authored commands, tool lists, targets and task_id resumes
        # are replaced; only the frozen host spec determines execution.
        match = re.search(r"(?m)^Task(?:Spec)?: ([a-z0-9][a-z0-9-]*)(?:\s|$)", str(args.get("prompt", "")))
        if not match:
            raise ValueError("send prompt='TaskSpec: <task-id>'")
        ident = match.group(1)
        summaries = {}
        for spec in self.specs:
            path = self.summary_path(spec)
            if path.exists():
                summaries[spec.id] = self.read_summary(spec)
        expected, reason = next_spec(self.specs, summaries)
        if expected is None:
            raise ValueError(reason)
        if expected.id != ident:
            raise ValueError("next task is " + expected.id)
        prompt = render_task_prompt(expected, scaffolded=True, compact=True)
        evidence_relative = Path(expected.evidence_dir).relative_to(self.workdir).as_posix()
        prompt = prompt.replace(f"Evidence dir: {expected.evidence_dir}\n",
                                f"Evidence dir: {evidence_relative} (under Workdir)\n", 1)
        try:
            scope_relative = Path(expected.scope_ref).relative_to(self.workdir.parent).as_posix()
        except ValueError:
            pass
        else:
            prompt = prompt.replace(f"Scope: {expected.scope_ref}\n",
                                    f"Scope: ../{scope_relative} (from Workdir)\n", 1)
        prompt += (f"\nWorkdir: {self.workdir}\n"
                   f"Synthetic session references (host-owned): {json.dumps(self.bindings, separators=(',', ':'))}\n")
        if expected.phase == "enum" and self.setup_checks_passed:
            # This says what the host actually checked, not that future checks
            # can be skipped unconditionally. Handoff freshness is still gated.
            prompt += ("Host setup checks passed; refresh if stale. Do not reread spec/scaffold; "
                       "read needed prior evidence/handoffs.")
        else:
            prompt += ("Complete TaskSpec. Commands first. Do not reread the current spec/scaffold. "
                       "Cited prior evidence/handoffs as needed.")
        if expected.depends_on:
            prompt += "\nPrevious summaries: " + ", ".join(
                "summaries/" + dep + ".json" for dep in expected.depends_on)
        errors = validate_worker_prompt(prompt)
        if errors:
            raise ValueError("invalid canonical task: " + "; ".join(errors))
        return expected, {"description": "Run " + ident, "subagent_type": "worker", "prompt": prompt}

    def scaffold(self, spec, *, prompt=None):
        self.confine(spec.evidence_dir).mkdir(parents=True, exist_ok=True)
        path = self.summary_path(spec)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Caller serializes resolution and admission under the broker lock.
        # Never overwrite an existing worker heartbeat or terminal summary.
        with path.open("x") as handle:
            json.dump(skeleton_summary(spec), handle, ensure_ascii=False)
            handle.write("\n")
        if prompt is not None:
            with (Path(spec.evidence_dir) / 'task-context.txt').open('x', encoding='utf-8') as handle:
                handle.write(prompt)
        self.active_spec = spec
        self.active_prompt = prompt
