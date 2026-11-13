"""Task-spec engine: the thin orchestration contract replacing free-form
brain->worker prompts.

Every worker delegation is a TaskSpec: exact target, exact MCP tool names
(the `Tools:` line the policy gate enforces), bounded call budget, fixed
summary schema. Specs are validated before dispatch; summaries are validated
on return. No spec, no run — hand-rolled improvisation is a spec error, not
a style choice.
"""

from __future__ import annotations

import fnmatch
import json
import re
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
try:
    from .mcp_inventory import registered_mcp_tools
    from .runtime_paths import runtime_root
except ImportError:
    from mcp_inventory import registered_mcp_tools
    from runtime_paths import runtime_root  # type: ignore[no-redef]

# Proven core inventory (~29 tools). Other tools are
# opt-in and must be justified per task; the gate still checks registration.
CORE_TOOLS = frozenset({
    "kali-tools_nmap_scan",
    "kali-tools_curl_request",
    "kali-tools_ffuf_fuzz",
    "kali-tools_nuclei_scan",
    "kali-tools_sqlmap_test",
    "kali-tools_compose_js_routes",
    "kali-tools_linkfinder_scan",
    "kali-tools_interactsh_start",
    "validator_validate_sqli",
    "validator_validate_ssti",
    "validator_validate_command_injection",
    "validator_validate_path_traversal",
    "validator_validate_xss_reflection",
    "validator_validate_finding",
    "validator_generate_validation_report",
    "web-advanced_graphql_introspect",
    "web-advanced_jwt_analyze",
    "web-advanced_api_route_fuzz",
    "browser_browser_extract_links",
    "browser_browser_capture_requests",
    "browser_browser_security_headers",
    "memory-server_store_finding",
    "memory-server_store_endpoint",
    "reasoning_deep_think",
    "reasoning_next_best_action",
    "reasoning_record_lesson",
    "reasoning_reason_reflexion",
    "llm-security_llm_prompt_injection_probe",
    "llm-security_llm_system_prompt_leak",
})

BASH_EXCEPTION = "bash"
PROTOCOL_TOOLS = (
    "kali-tools_ledger_attempt_add_batch",
    "memory-server_store_finding",
    "memory-server_update_finding_validation",
)
BROKER_PROTOCOL_TOOLS = ("kali-tools_ledger_attempt_add_batch",)
COMPILED_WORKFLOW_TOOL = "workflow_execute_compiled"


def broker_tools() -> frozenset[str]:
    """Use the host catalog, or its launcher-frozen projection in the solver."""
    path = runtime_root() / ".codex" / "broker-catalog.json"
    if path.is_file():
        return frozenset(json.loads(path.read_text()))
    try:
        from .full_agent_executor import CATALOG
    except ImportError:
        from full_agent_executor import CATALOG  # type: ignore[no-redef]
    return frozenset(group + "_" + name for group, names in CATALOG.items() for name in names)


def protocol_tools(profile: str, phase: str | None = None) -> tuple[str, ...]:
    # Discovery evidence is not a security attempt. Keep the signed attempt
    # ledger available to validation/reporting, without a recon repair loop.
    if profile == "broker":
        return () if phase in {"recon", "enum", "seed"} else BROKER_PROTOCOL_TOOLS
    return PROTOCOL_TOOLS


MAX_CALLS_PER_TASK = 30
MAX_MINUTES_PER_TASK = 180

SUMMARY_KEYS = ("phase", "target", "status", "evidence", "findings", "next")
SUMMARY_STATUSES = ("done", "blocked", "failed", "partial")
SKELETON_STATUS = "in-progress"
STEP_STATUSES = ("done", "blocked", "not_tested")


def is_skeleton_summary(summary: object) -> bool:
    """A live worker heartbeat, not a verdict: complete it, never ingest it."""
    return (
        isinstance(summary, dict)
        and summary.get("status") == SKELETON_STATUS
        and isinstance(summary.get("phase"), str)
        and isinstance(summary.get("target"), str)
    )


def skeleton_summary(spec: "TaskSpec") -> dict:
    """Deterministic skeleton for `spec`: phase/target/steps come from the
    spec itself, never from the worker's freehand JSON. The worker only
    flips step statuses and fills evidence/findings/next."""
    summary: dict = {
        "phase": spec.phase,
        "target": spec.target,
        "status": SKELETON_STATUS,
        "evidence": [],
        "findings": [],
        "next": "",
        "steps": [{"id": step.id, "status": "not_tested"} for step in spec.steps],
    }
    if spec.vector:
        summary["vector"] = spec.vector
    if spec_expects_surface(spec):
        summary["surface"] = {"routes": [], "params": []}
    return summary


@dataclass
class Step:
    """One phase step. `fallback` is the ONLY sanctioned retry: a
    pre-written gate-friendly variant. `optional` steps that still fail
    after the fallback are marked NOT TESTED and the phase goes partial
    instead of killing the chain."""

    id: str
    command: str
    optional: bool = False
    fallback: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "command": self.command,
            "optional": self.optional,
            "fallback": self.fallback,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Step":
        return cls(
            id=str(data.get("id", "")),
            command=str(data.get("command", "")),
            optional=bool(data.get("optional", False)),
            fallback=str(data.get("fallback", "")),
        )

_TOOL_TOKEN_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*_[a-z0-9_]+$")


def _capability_registry() -> dict:
    path = runtime_root() / "config" / "tool-capabilities.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _capability_known(tool: str) -> bool:
    """Require an exact registration or a real tool covered by a pattern."""
    registry = _capability_registry()
    if tool in registry.get("tools", {}):
        return True
    return tool in registered_mcp_tools() and any(
        rule.get("pattern") and fnmatch.fnmatch(tool, rule["pattern"])
        for rule in registry.get("patterns", [])
        if isinstance(rule, dict))


def _scope_ref() -> str:
    return os.environ.get("CCO_SCOPE_FILE") or ".codex/scope.json"


@dataclass
class TaskSpec:
    id: str
    phase: str
    target: str
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    custom_commands: list[str] = field(default_factory=list)
    evidence_dir: str = ""
    max_calls: int = 20
    bash_justification: str = ""
    tool_justification: str = ""
    max_minutes: int = 0
    depends_on: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    vector: str = ""
    scope_ref: str = field(default_factory=_scope_ref)
    tool_profile: str = "core"
    references: dict = field(default_factory=dict)
    compiled_workflows: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "phase": self.phase,
            "target": self.target,
            "tools": list(self.tools),
            "tool_profile": self.tool_profile,
            "commands": list(self.commands),
            "custom_commands": list(self.custom_commands),
            "evidence_dir": self.evidence_dir,
            "max_calls": self.max_calls,
            "bash_justification": self.bash_justification,
            "tool_justification": self.tool_justification,
            "max_minutes": self.max_minutes,
            "depends_on": list(self.depends_on),
            "steps": [s.to_dict() for s in self.steps],
            "vector": self.vector,
            "scope_ref": self.scope_ref,
            **({"references": self.references} if self.references else {}),
            **({"compiled_workflows": self.compiled_workflows} if self.compiled_workflows else {}),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TaskSpec":
        return cls(
            references=data.get("references", {}),
            compiled_workflows=data.get("compiled_workflows", {}),
            id=str(data.get("id", "")),
            phase=str(data.get("phase", "")),
            target=str(data.get("target", "")),
            tools=[str(t) for t in data.get("tools", [])],
            tool_profile=str(data.get("tool_profile", "core")),
            commands=[str(c) for c in data.get("commands", [])],
            custom_commands=[str(c) for c in data.get("custom_commands", [])],
            evidence_dir=str(data.get("evidence_dir", "")),
            max_calls=int(data.get("max_calls", 20)),
            bash_justification=str(data.get("bash_justification", "")),
            tool_justification=str(data.get("tool_justification", "")),
            max_minutes=int(data.get("max_minutes", 0)),
            depends_on=[str(d) for d in data.get("depends_on", [])],
            steps=[Step.from_dict(s) for s in data.get("steps", [])],
            vector=str(data.get("vector", "")),
            scope_ref=str(data.get("scope_ref") or _scope_ref()),
        )


def validate_spec(spec: TaskSpec) -> list[str]:
    """Return spec errors; empty list means dispatchable."""
    from agent_integration import validate_references
    errors: list[str] = validate_references(spec.references)
    if not isinstance(spec.compiled_workflows, dict):
        errors.append("compiled_workflows must be a host reference map")
    elif spec.compiled_workflows and (spec.phase != 'access' or COMPILED_WORKFLOW_TOOL not in spec.tools):
        errors.append("compiled workflows require the access workflow tool")
    if spec.tool_profile not in {"core", "broker"}:
        errors.append("unknown tool profile: " + spec.tool_profile)
    allowed = broker_tools() if spec.tool_profile == "broker" else None
    if not spec.id:
        errors.append("id is required")
    if not spec.phase:
        errors.append("phase is required")
    if not spec.target:
        errors.append("target is required")
    if not spec.evidence_dir:
        errors.append("evidence_dir is required")
    if not spec.scope_ref:
        errors.append("scope_ref is required")
    if not spec.tools:
        errors.append("tools is required (name exact MCP tools)")
    checked_tools = list(dict.fromkeys([*spec.tools, *protocol_tools(spec.tool_profile)])) if allowed is not None else spec.tools
    for tool in checked_tools:
        if tool == COMPILED_WORKFLOW_TOOL:
            if spec.tool_profile != 'broker' or spec.phase != 'access':
                errors.append("compiled workflow tool requires Python access tasks")
            continue
        if tool == BASH_EXCEPTION:
            if not spec.bash_justification:
                errors.append("bash requires bash_justification (no MCP equivalent: <why>)")
            continue
        if not _TOOL_TOKEN_RE.match(tool):
            errors.append(f"malformed tool name: {tool}")
        elif allowed is not None:
            if tool not in allowed:
                errors.append(f"tool outside broker catalog: {tool}")
        elif tool not in CORE_TOOLS and tool not in PROTOCOL_TOOLS:
            if not spec.tool_justification.strip():
                errors.append(f"tool not in core inventory (opt-in needs "
                              f"tool_justification): {tool}")
            elif not _capability_known(tool):
                errors.append(f"tool not registered in tool-capabilities: {tool}")
    if spec.max_calls < 1 or spec.max_calls > MAX_CALLS_PER_TASK:
        errors.append(f"max_calls must be 1..{MAX_CALLS_PER_TASK}")
    if spec.max_minutes < 0 or spec.max_minutes > MAX_MINUTES_PER_TASK:
        errors.append(f"max_minutes must be 0..{MAX_MINUTES_PER_TASK} (0 = unset)")
    if spec.id and spec.id in spec.depends_on:
        errors.append("spec cannot depend on itself")
    step_ids: set[str] = set()
    for step in spec.steps:
        if not step.id or not step.command:
            errors.append("every step needs id and command")
        elif step.id in step_ids:
            errors.append(f"duplicate step id: {step.id}")
        step_ids.add(step.id)
    return errors


def validate_chain(specs: list[TaskSpec]) -> list[str]:
    """List-level spec errors: duplicate ids, dangling or forward deps."""
    errors: list[str] = []
    seen: set[str] = set()
    for spec in specs:
        errors.extend(validate_spec(spec))
        if spec.id in seen:
            errors.append(f"duplicate spec id: {spec.id}")
        for dep in spec.depends_on:
            if dep not in seen:
                errors.append(f"{spec.id}: dependency not dispatched earlier: {dep}")
        seen.add(spec.id)
    return errors


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in text) or "run"


def _handoff_lines(spec: TaskSpec) -> list[str]:
    if spec.phase not in ("authz", "access"):
        return []
    label = spec.vector or (spec.phase if spec.phase == "authz" else "access")
    path = str(Path(spec.evidence_dir).parent / f"handoff-{_slug(label)}.json")
    return [
        f"Handoff packet: {path} (read before probing; if the file is missing, "
        "report INCOMPLETE_SPEC naming it)",
    ]


def _pool_lines(spec: TaskSpec) -> list[str]:
    if spec.phase not in ("authz", "access"):
        return []
    pool_path = str(Path(spec.evidence_dir).parent / "object-pool.json")
    return [
        f"Object pool: {pool_path} (candidate object ids from observed evidence)",
        "Only probe candidates verified to belong to authorized test accounts; "
        "record \"pool_probed\": <count probed>. Unowned or unverified "
        "candidates remain untested and prevent tested-clean closure.",
    ]


def render_task_prompt(spec: TaskSpec, *, scaffolded: bool = False, compact: bool = False) -> str:
    """Render the worker prompt. The `Tools:` line is gate-enforced."""
    errors = validate_spec(spec)
    if errors:
        raise ValueError("invalid task spec: " + "; ".join(errors))
    if compact and (not scaffolded or spec.tool_profile != "broker"):
        raise ValueError("compact prompts require a host-scaffolded broker task")
    effective_tools = list(dict.fromkeys([*spec.tools, *protocol_tools(spec.tool_profile, spec.phase)]))
    ledger_rules = ([
        'Ledger items: call kali-tools_ledger_attempt_add_batch once at phase end. '
        'workdir=Workdir; items_json is a JSON array of objects. Required nonempty strings: '
        'vector,endpoint,identity,verdict. Optional: candidate/control (string or integer IDs), '
        'status (HTTP integer 0..599, never "done"), size (nonnegative integer), artifact/note (strings). '
        'Use artifact for the evidence path. Omit unobserved values; never infer ownership or validation. '
        'On schema error fix all supplied fields together; at most one corrected retry.'
    ] if "kali-tools_ledger_attempt_add_batch" in effective_tools else [])
    if BASH_EXCEPTION in effective_tools and spec.bash_justification.strip():
        reason = spec.bash_justification.strip()
        if not re.match(r"^(?:no MCP equivalent|helper-compute):", reason, re.I):
            reason = f"no MCP equivalent: {reason}"
        rendered = [f"bash ({reason})"
                    if tool == BASH_EXCEPTION else tool
                    for tool in effective_tools]
        tools_line = "Tools: " + ", ".join(rendered)
    else:
        tools_line = "Tools: " + ", ".join(effective_tools)
    skeleton_path = str(Path(spec.evidence_dir).parent / "summaries" / f"{spec.id}.json")
    if compact:
        tools_line = tools_line.replace(", ", ",")
        lines = [
            f"Task: {spec.id} (phase: {spec.phase})",
            f"Target: {spec.target}",
            f"Scope: {spec.scope_ref}",
            f"Tool profile: {spec.tool_profile}",
            *(["Operation/hypothesis references: " + json.dumps(spec.references, sort_keys=True)] if spec.references else []),
            *([f"Vector: {spec.vector} (test ONLY this vector)"] if spec.vector else []),
            tools_line,
            *ledger_rules,
            *([f"Tool justification: {spec.tool_justification.strip()}"]
              if spec.tool_justification.strip() else []),
            f"Evidence dir: {spec.evidence_dir}",
            *_pool_lines(spec),
            *_handoff_lines(spec),
            f"Summary path: summaries/{spec.id}.json; already created; compact JSON; host validates.",
            f"Budget: at most {spec.max_calls} tool calls; stop.",
            *([f"Deadline: {spec.max_minutes} minutes (host)."]
              if spec.max_minutes > 0 else []),
            "Commands:",
            *[f"- {command}" for command in spec.commands],
            *([f"After terminal observed routes/docs: vector={spec.vector or ('authz' if spec.phase == 'seed' else 'access')} "
               "handoff via Target/Workdir/Summary path. own_ids_json=verified own IDs|[]; "
               "session_bindings_json=supplied refs (recent checks). "
               "Returned paths/exact custom labels only; no wrappers/replacements."]
              if "kali-tools_ledger_prepare_handoff" in effective_tools
              and spec.phase in {"enum", "seed"} else []),
            *(_step_lines(spec) if spec.steps else []),
            "Return exactly one JSON summary: " + ",".join(SUMMARY_KEYS)
            + ". status: " + "|".join(SUMMARY_STATUSES) + "."
            + (f" vector={spec.vector}; vector_result: confirmed|blocked|not_applicable|tested_clean. "
               "confirmed requires a finding with persisted validator artifact validation_id."
               if spec.vector else ""),
            "steps [{id,status}]: done|blocked|not_tested for partial/all declared steps; optional NOT TESTED: partial.",
            "Session checks: evidence/session_checks; no security/ownership proof.",
            *(["Enum summary MUST embed surface.routes and surface.params lists in the summary JSON; "
               "surface.json/evidence paths alone are insufficient. Include observed surface.docs, "
               "surface.id_formats and surface.docs_probes; never invent missing observations."]
              if spec.phase == "enum" else []),
            *(["surface.id_formats: {family:nonempty string,format:uuid|int|string|other,example:nonempty string}; "
               "integers use int. surface.docs_probes: {url:nonempty string,status:HTTP integer 100..599}."]
              if spec.phase == "enum" else []),
        ]
        return "\n".join(lines)
    summary_instruction = (
        f"Summary path: {skeleton_path}. The host gate already created its deterministic in-progress skeleton. "
        "Do not run scaffold/validate shell commands; finish this file with native write/edit. "
        "The host validates the terminal summary before admitting the next phase."
        if scaffolded else
        f"First action: create the skeleton summary deterministically with "
        f"`python3 scripts/brain.py summary scaffold --spec {Path(spec.evidence_dir).parent / 'specs.json'} --id {spec.id}` "
        f"(writes {skeleton_path} with status \"{SKELETON_STATUS}\"); do not hand-write it. "
        "Before any probe, then update the same file into a terminal summary when done and check it with "
        f"`python3 scripts/brain.py summary validate --spec {Path(spec.evidence_dir).parent / 'specs.json'} --id {spec.id}` before returning."
    )
    lines = [
        f"Task: {spec.id} (phase: {spec.phase})",
        f"Target: {spec.target}",
        f"Scope: {spec.scope_ref}",
        f"Tool profile: {spec.tool_profile}",
            *(["Operation/hypothesis references: " + json.dumps(spec.references, sort_keys=True)] if spec.references else []),
        *([f"Vector: {spec.vector} (hypothesis ledger; test ONLY this vector)"]
          if spec.vector else []),
        tools_line,
        *ledger_rules,
        *([f"Tool justification: {spec.tool_justification.strip()}"]
          if spec.tool_justification.strip() else []),
        f"Evidence dir: {spec.evidence_dir}",
        *_pool_lines(spec),
        *_handoff_lines(spec),
        summary_instruction,
        f"Budget: at most {spec.max_calls} tool calls; then stop and report.",
        *([f"Deadline: about {spec.max_minutes} minutes of wall clock for this "
           "task; the policy gate enforces the per-target time budget."]
          if spec.max_minutes > 0 else []),
        "Commands:",
        *[f"- {command}" for command in spec.commands],
        *(["After saving the terminal enum/seed summary with observed surface.routes and surface.docs arrays, "
           "call kali-tools_ledger_prepare_handoff "
           f"with target={spec.target}, workdir={Path(spec.evidence_dir).parent}, "
           f"summary_file={skeleton_path}, vector={spec.vector or ('authz' if spec.phase == 'seed' else 'access')}. "
           "Pass own_ids_json only for explicitly verified operator-owned IDs; otherwise use []. "
           "Pass the existing synthetic account reference map in session_bindings_json; "
           "the tool verifies recent checks and stores only references. "
           "It also returns standard authz/authz-idor/file-access handoff paths; "
           "refresh a custom vector by passing that exact label before dispatch. "
           "Use the returned pool/handoff paths; no bash wrappers or hand-written replacement files."]
          if "kali-tools_ledger_prepare_handoff" in effective_tools and spec.phase in {"enum", "seed"} else []),
        *(_step_lines(spec) if spec.steps else []),
        "Return exactly one JSON summary with keys: "
        + ", ".join(SUMMARY_KEYS)
        + f". status must be one of {SUMMARY_STATUSES}."
        + (" Also include \"vector\" (this vector) and \"vector_result\": "
           "confirmed|blocked|not_applicable|tested_clean. A confirmed result "
           "requires a finding with the persisted validator artifact's "
           "\"validation_id\"."
           if spec.vector else "")
        + (" Record every step in a `steps` list ({id, status}); "
           "status=partial when an optional step is NOT TESTED."
           if spec.steps else ""),
        "A partial summary always needs a steps list of {id, status} objects, "
        "even when the task did not enumerate steps. Allowed step statuses: done, blocked, not_tested.",
        "Session-health CONFIRMED checks belong in evidence/session_checks; "
        "they are operational results. Security findings and ownership claims need their own observed evidence.",
        *(["Enum summary MUST embed surface.routes and surface.params lists in the summary JSON; "
           "surface.json/evidence paths alone are insufficient. Include observed surface.docs, "
           "surface.id_formats and surface.docs_probes; never invent missing observations."]
          if spec.phase == "enum" else []),
        *(["Enum surface.id_formats entries must be {family: nonempty string, format: uuid|int|string|other, "
           "example: nonempty string}. Use int for integer IDs. surface.docs_probes entries must be "
           "{url: nonempty string, status: integer HTTP status 100..599}."]
          if spec.phase == "enum" else []),
    ]
    return "\n".join(lines)


def validate_worker_prompt(prompt: str) -> list[str]:
    """Validate the same dispatch contract used by the generated TaskSpec."""
    errors = []
    text = str(prompt or "")
    profiles = re.findall(r"(?im)^\s*Tool profile:\s*(\S+)\s*$", text)
    profile = profiles[0] if len(profiles) == 1 else "core"
    if len(profiles) > 1 or profile not in {"core", "broker"}:
        errors.append("invalid worker tool profile")
    allowed = broker_tools() if profile == "broker" else None
    for label in ("Target", "Scope", "Evidence dir"):
        if not re.search(rf"(?im)^\s*{re.escape(label)}:\s*\S", text):
            errors.append(f"worker task lacks {label}: value")
    if not re.search(r"(?im)^[ \t]*Commands:[ \t]*\r?\n[ \t]*-[ \t]*\S", text):
        errors.append("worker task lacks exact commands")
    if not re.search(r"(?i)return exactly one JSON summary", text):
        errors.append("worker task lacks JSON summary format")
    match = re.search(r"(?im)^\s*Tools:\s*([^\r\n]+)", text)
    if not match:
        return [*errors, "worker task lacks a Tools: line naming exact MCP tools"]
    values = [part.strip() for part in re.split(r",\s*(?![^()]*\))", match.group(1))]
    found = set()
    phase_match = re.search(r"(?im)^\s*Task:.*\(phase: ([a-z0-9-]+)\)", text)
    phase = phase_match.group(1) if phase_match else None
    for value in values:
        if value == COMPILED_WORKFLOW_TOOL and profile == 'broker' and phase == 'access':
            found.add(value)
            continue
        if value.startswith("bash"):
            if not re.fullmatch(r"bash\s*\((?:no MCP equivalent|helper-compute):\s*[^()\s][^()]*\)",
                                value, re.I):
                errors.append("bash requires an explicit non-empty exception reason")
            continue
        if not _TOOL_TOKEN_RE.fullmatch(value) or (
                value not in allowed if allowed is not None else not _capability_known(value)):
            errors.append(f"tool not registered: {value}")
        else:
            found.add(value)
    phase_match = re.search(r"(?im)^\s*Task:.*\(phase: ([a-z0-9-]+)\)", text)
    phase = phase_match.group(1) if phase_match else None
    required_protocol = set(protocol_tools(profile, phase))
    missing = required_protocol - found
    if missing:
        errors.append("worker task lacks protocol tools: " + ", ".join(sorted(missing)))
    extras = found - (allowed if allowed is not None else CORE_TOOLS) - required_protocol - {COMPILED_WORKFLOW_TOOL}
    if extras and not re.search(r"(?im)^\s*Tool justification:\s*\S", text):
        errors.append("non-core tools require Tool justification")
    return errors


def _step_lines(spec: TaskSpec) -> list[str]:
    lines = ["Steps (execute in order):"]
    for step in spec.steps:
        line = f"- {step.id}: {step.command}"
        if step.fallback:
            line += (f" [if the gate blocks this step, run the fallback ONCE: "
                     f"{step.fallback}]")
        if step.optional:
            line += (" [optional: if still blocked, mark this step NOT TESTED "
                     "in the summary and continue the phase]")
        lines.append(line)
    return lines


def _route_has_object_shape(route: object) -> bool:
    """True when a route visibly carries an object id.

    Authority (ports) and version labels (`v2`) are not object ids;
    `:id` placeholders and digit-bearing segments are.
    """
    text = str(route)
    if "://" in text:
        try:
            text = urlsplit(text).path or text
        except ValueError:
            pass
    segments = [seg for seg in text.split("/")
                if seg and not re.fullmatch(r"v\d+", seg, re.IGNORECASE)]
    return any(":id" in seg or re.search(r"\d", seg) for seg in segments)


def surface_errors(summary: object) -> list[str]:
    """Enum surface gate: evidence without inventory stops the chain.

    Only enum summaries with recorded evidence owe a surface inventory
    (`surface.routes`/`surface.params`). Vacuous summaries (no evidence)
    keep validating so host/llm presets and legacy chains without
    surface tracking still advance.
    """
    if not isinstance(summary, dict):
        return []
    if summary.get("phase") != "enum":
        return []
    if summary.get("status") not in ("done", "partial"):
        return []
    evidence = summary.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return []
    if "surface" not in summary:
        return ["enum summary with evidence must include a surface inventory (routes/params)"]
    surface = summary.get("surface")
    if not isinstance(surface, dict):
        return ["enum surface must be an object with routes/params lists"]
    routes = surface.get("routes")
    params = surface.get("params")
    if not isinstance(routes, list) or not isinstance(params, list):
        return ["enum surface.routes and surface.params must be lists"]
    if not routes and not params:
        return ["enum surface is empty (routes and params both empty) despite recorded evidence"]
    if any(_route_has_object_shape(route) for route in routes):
        formats = surface.get("id_formats")
        if not isinstance(formats, list) or not formats:
            return ["enum surface with routes must include an id_formats inventory "
                    "({family, format, example} per observed object family)"]
        for entry in formats:
            if not isinstance(entry, dict):
                return ["enum surface.id_formats entries must be objects"]
            family = entry.get("family")
            format_name = entry.get("format")
            example = entry.get("example")
            if not isinstance(family, str) or not family.strip():
                return ["enum surface.id_formats entry needs a non-empty family"]
            if format_name not in ("uuid", "int", "string", "other"):
                return ["enum surface.id_formats.format must be one of "
                        "uuid/int/string/other"]
            if not isinstance(example, str) or not example.strip():
                return ["enum surface.id_formats entry needs a non-empty example"]
    if routes:
        wanted: dict[str, str] = {}
        for route in routes:
            text = str(route)
            for token, pattern in DOC_PATH_RES:
                if pattern.search(text):
                    wanted.setdefault(token, text)
        if wanted:
            probes = surface.get("docs_probes")
            if not isinstance(probes, list) or not probes:
                missing = sorted(wanted.values())
                return ["enum surface lists doc path(s) "
                        f"{missing} without a docs_probes fetch record"]
            covered: set[str] = set()
            for probe in probes:
                if not isinstance(probe, dict):
                    return ["enum surface.docs_probes entries must be objects"]
                url = probe.get("url")
                status = probe.get("status")
                if not isinstance(url, str) or not url.strip():
                    return ["enum surface.docs_probes entry needs a non-empty url"]
                if not isinstance(status, int) or isinstance(status, bool) \
                        or not 100 <= status <= 599:
                    return ["enum surface.docs_probes.status must be an HTTP "
                            "status int"]
                for token, pattern in DOC_PATH_RES:
                    if pattern.search(url):
                        covered.add(token)
            missing = sorted(text for token, text in wanted.items()
                             if token not in covered)
            if missing:
                return ["enum surface lists doc path(s) "
                        f"{missing} without a docs_probes fetch record"]
    return []


def validate_summary(summary: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(summary, dict):
        return ["summary must be a JSON object"]
    for key in SUMMARY_KEYS:
        if key not in summary:
            errors.append(f"summary missing key: {key}")
    if summary.get("status") not in SUMMARY_STATUSES:
        errors.append(f"summary status must be one of {SUMMARY_STATUSES}")
    if "evidence" in summary and not isinstance(summary["evidence"], list):
        errors.append("summary evidence must be a list")
    if "findings" in summary and not isinstance(summary["findings"], list):
        errors.append("summary findings must be a list")
    errors.extend(_summary_step_errors(summary))
    errors.extend(surface_errors(summary))
    return errors


def _summary_step_errors(summary: dict) -> list[str]:
    """Step honesty: skips are visible, never hidden inside `done`."""
    steps = summary.get("steps")
    if steps is None:
        if summary.get("status") == "partial":
            return ["partial summary must record its steps"]
        return []
    if not isinstance(steps, list) or not all(isinstance(s, dict) for s in steps):
        return ["summary steps must be a list of {id, status} objects"]
    errors: list[str] = []
    skipped = False
    for step in steps:
        if step.get("status") not in STEP_STATUSES:
            errors.append(f"step {step.get('id')!r}: status must be one of {STEP_STATUSES}")
        if step.get("status") in ("blocked", "not_tested"):
            skipped = True
    if summary.get("status") == "done" and skipped:
        errors.append("status=done contradicts a blocked/not_tested step (use partial)")
    if summary.get("status") == "partial" and not skipped:
        errors.append("status=partial but no step is blocked/not_tested")
    return errors


WEB_SURFACE_TOOLS = frozenset({
    "browser_browser_extract_links",
    "browser_browser_capture_requests",
    "kali-tools_compose_js_routes",
    "kali-tools_ffuf_fuzz",
})

# Conventional documentation paths (industry-wide, never target-specific).
DOC_PATH_RES = (
    ("docs", re.compile(r"(^|/)docs([/.]|$)", re.IGNORECASE)),
    ("openapi", re.compile(r"openapi", re.IGNORECASE)),
    ("swagger", re.compile(r"swagger", re.IGNORECASE)),
)


def spec_expects_surface(spec: TaskSpec) -> bool:
    """Only web-surface enum specs owe a routes/params inventory.

    Host enum (nmap/nuclei) has no routes to inventory; forcing the web
    surface schema there would stop the chain on a category error.
    """
    return spec.phase == "enum" and bool(WEB_SURFACE_TOOLS.intersection(spec.tools))


def classify_finding(validator_confirmed: bool, validator_confidence: float = 0.0) -> str:
    """Reflexion gate: no CONFIRMED band without a deterministic validator.

    Mirrors the exploitability-score rule: an LLM/reflexion opinion alone
    caps at LIKELY; CONFIRMED requires validator evidence.
    """
    if validator_confirmed and validator_confidence >= 0.75:
        return "CONFIRMED"
    if validator_confirmed:
        return "LIKELY"
    return "POSSIBLE"


def dump_specs(specs: list[TaskSpec]) -> str:
    return json.dumps([spec.to_dict() for spec in specs], indent=1, ensure_ascii=False)


def load_specs(text: str) -> list[TaskSpec]:
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("spec file must be a JSON list")
    return [TaskSpec.from_dict(item) for item in data]
