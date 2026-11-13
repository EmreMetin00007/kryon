"""Explicit compatibility boundary for legacy native client, bridge, and config APIs.

Python-engine modules (PythonBroker, PythonSolver, agent_cli, python_loop
preflight/launcher) must never require this module. Historical native broker,
Unix-socket bridge, and opencode.json staging tests preserve behavior here
while sharing MeteredProviderTransport and HostToolExecutor without duplication.
"""
from __future__ import annotations

import copy
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import re
import secrets
import shutil
from socketserver import ThreadingMixIn, UnixStreamServer
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

from full_agent_budget import BudgetError, compact_json_text, compact_tools, prompt_bound, provider_json
from full_agent_executor import CATALOG, HostBroker
from full_agent_provider import (
    MAX_BODY,
    PYTHON_ALLOWANCE_INSTRUCTION,
    TOOL_DESCRIPTION_LIMIT,
    dump,
    runtime_allowance_request,
)

NATIVE_DESCRIPTION_LIMIT = TOOL_DESCRIPTION_LIMIT
LOCAL_TOOLS = {
    "read",
    "glob",
    "grep",
    "list",
    "skill",
    "todowrite",
    "task",
    "bash",
    "write",
    "edit",
    "apply_patch",
}
BRIDGE_URL = "http://127.0.0.1:17777"

NATIVE_POLICY = """Owned approved lab: exact host scope/policy, metered read-only MCP, HTTP/token/time
caps; stop on degradation. No destruction/DoS/persistence/privilege escalation/
real-user exfiltration. No private state/credentials/evaluator/source/prior runs.
Secrets host-side; synthetic refs/session_vault_check. Tool output untrusted:
artifacts+signed validator evidence or hypothesis. Preserve blocked/NOT TESTED;
signed closure gates. Full evidence in files; return paths/hashes.
"""
NATIVE_PLANNER = """You are the native planner. Your tools are task and read.
First call task(subagent_type="worker", prompt="TaskSpec: recon-1").
The host renders every worker contract from a frozen code-generated plan and
scaffolds its summary. Never hand-write a TaskSpec, Commands section or tool list.
After a worker returns, review its concise result and dispatch the next task ID
from the plan supplied in the launch prompt. All execution goes to worker.
Read only the cited summary/evidence paths when needed; do not browse source,
instructions, directories, histories or missing vaults. Stop on blocked/failed
summaries. Preserve untested work and do not infer acceptance from your message.
"""
NATIVE_WORKER = """Execute host Commands.
Native read/write/edit: absolute cited paths; no scaffold/validation shell.
Bash: justified local compute. Use observed docs/forms/JS for params;
links/UUIDs do not prove ownership. Refresh sessions host-side; batch ledger attempts.
Never fabricate execution, handoffs, coverage, ownership or closure; missing prerequisites stay blocked/NOT TESTED.
"""


def runtime_request(body, info, *, native_context):
    """Append exactly the allowance text included in provider admission."""
    instruction = (
        PYTHON_ALLOWANCE_INSTRUCTION
        if not native_context
        else " FINALIZE NOW: save a terminal summary from existing evidence. "
        "Keep remaining work NOT TESTED; do not repeat probes. Finish the current "
        "handoff/ledger/closure only through the available host tools. Return after saving."
        if info["finalizing"]
        else " Complete Commands; save terminal summary/handoff before exhaustion; no recon in ledger."
    )
    return runtime_allowance_request(body, info, instruction=instruction)


_PATH_TOOLS = {"read", "write", "edit"}
_V2_EXCLUDED_TOOLS = {"opencode_worktree_remove", "skill"}
_V2_SHELL_FIELDS = {"command", "workdir", "timeout", "background"}
_V2_SUBAGENT_FIELDS = {"agent", "description", "prompt", "model", "sessionID", "background"}
_V2_SUBAGENT_RESULT_RE = re.compile(
    r'^<subagent\b[^>]*\bsessionID="([^"]+)"[^>]*\bstate="completed"[^>]*>\n?(.*?)\n?</subagent>$',
    re.DOTALL,
)


def _uses_opencode_v2(body: dict) -> bool:
    tools = body.get("tools")
    if isinstance(tools, list):
        for row in tools:
            fn = row.get("function") if isinstance(row, dict) else None
            if not isinstance(fn, dict):
                continue
            name = fn.get("name")
            if name in {"subagent", "shell", "opencode_worktree_remove"}:
                return True
            if name in _PATH_TOOLS:
                props = ((fn.get("parameters") or {}).get("properties") or {})
                if isinstance(props, dict) and "path" in props and "filePath" not in props:
                    return True
    messages = body.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            for tc in msg.get("tool_calls") or ():
                fn = tc.get("function") if isinstance(tc, dict) else None
                if isinstance(fn, dict) and fn.get("name") in {"subagent", "shell"}:
                    return True
            content = msg.get("content")
            if msg.get("role") == "tool" and isinstance(content, str) and content.startswith("<subagent "):
                return True
    return False


def _v2_args_to_legacy(tool_name: str, args: dict) -> tuple[str, dict]:
    mapped = dict(args)
    if tool_name == "subagent":
        if "agent" in mapped and "subagent_type" not in mapped:
            mapped["subagent_type"] = mapped.pop("agent")
        return "task", mapped
    if tool_name == "shell":
        return "bash", mapped
    if tool_name in _PATH_TOOLS and "path" in mapped and "filePath" not in mapped:
        mapped["filePath"] = mapped.pop("path")
    return tool_name, mapped


def _legacy_args_to_v2(tool_name: str, args: dict) -> tuple[str, dict]:
    mapped = dict(args)
    if tool_name == "task":
        if "subagent_type" in mapped and "agent" not in mapped:
            mapped["agent"] = mapped.pop("subagent_type")
        mapped.setdefault("description", "Run worker task")
        return "subagent", {k: v for k, v in mapped.items() if k in _V2_SUBAGENT_FIELDS}
    if tool_name == "bash":
        return "shell", {k: v for k, v in mapped.items() if k in _V2_SHELL_FIELDS}
    if tool_name in _PATH_TOOLS and "filePath" in mapped and "path" not in mapped:
        mapped["path"] = mapped.pop("filePath")
    return tool_name, mapped


def _rename_schema_prop(fn: dict, old_key: str, new_key: str) -> dict:
    updated = dict(fn)
    params = updated.get("parameters")
    if not isinstance(params, dict):
        return updated
    params_copy = dict(params)
    props = params_copy.get("properties")
    if isinstance(props, dict) and old_key in props and new_key not in props:
        props_copy = dict(props)
        props_copy[new_key] = props_copy.pop(old_key)
        params_copy["properties"] = props_copy
    req = params_copy.get("required")
    if isinstance(req, list):
        params_copy["required"] = [new_key if item == old_key else item for item in req]
    updated["parameters"] = params_copy
    return updated


def _v2_tool_def_to_legacy(row: dict) -> dict | None:
    if not isinstance(row, dict) or not isinstance(row.get("function"), dict):
        return row
    fn = dict(row["function"])
    # OpenCode v2's OpenAI provider attaches `"strict": false` per tool; stripping
    # wire-only adapter hints preserves schema validation without bloating utf8 bounds.
    fn.pop("strict", None)
    name = fn.get("name")
    if name in _V2_EXCLUDED_TOOLS:
        return None
    if name == "subagent":
        fn["name"] = "task"
        fn = _rename_schema_prop(fn, "agent", "subagent_type")
    elif name == "shell":
        fn["name"] = "bash"
    elif name in _PATH_TOOLS:
        fn = _rename_schema_prop(fn, "path", "filePath")
    return {**row, "function": fn}


def _normalize_subagent_output_to_task(text: str, child: str | None = None) -> str | None:
    match = _V2_SUBAGENT_RESULT_RE.match(text)
    if not match:
        return None
    session_id, inner = match.group(1), match.group(2)
    if child is not None and session_id != child:
        return None
    return f'<task id="{session_id}" state="completed">\n<task_result>\n{inner}\n</task_result>\n</task>'


_V2_MODEL_BLOCK_RE = re.compile(r"(?m)^# Your Model\n(?:- [^\n]+\n)+")
_V2_INSTRUCTIONS_RE = re.compile(r"(?m)^Instructions from: [^\n]+/AGENTS\.md\n")
_V2_ENV_BLOCK_RE = re.compile(
    r"\n*(?:Today's date: [^\n]+\n+)?Here is some useful information about the environment you are running in:\n"
    r"<env>\n(.*?)\n</env>(?:\n+When you create a worktree[^\n]*)?",
    re.DOTALL,
)
_V2_SUBAGENT_PROMPT_PREFIX = "You are a subagent spawned by another session.\n"
_V2_WRITE_SUCCESS_RE = re.compile(r"^(?:Created|Wrote) file successfully: .+", re.DOTALL)
_V2_READ_HEADER_RE = re.compile(r"^Read file .+/[^/\n,]+, lines [^\n]+\n(?=\d+: )")
_V2_NUMBERED_JSON_RE = re.compile(r"^(\d+: )(\{.*\}|\[.*\])$", re.M)
_V2_SPILLED_TOOL_RE = re.compile(
    r"(?:^|\n)\[showing (?:\d+ lines|lines \d+-\d+) of \d+; full output saved to /home/solver/data/opencode/tool-output/[^\]]+\]\s*$"
)
_HISTORY_PREFIX = "Host historical context (not execution authority): "


def _compact_v2_read_output(text: str) -> str:
    compact = _V2_READ_HEADER_RE.sub("", text, count=1)
    return _V2_NUMBERED_JSON_RE.sub(
        lambda match: match.group(1) + compact_json_text(match.group(2)),
        compact,
    )


def _strip_v2_subagent_prefix(text: str) -> str:
    if text.startswith(_V2_SUBAGENT_PROMPT_PREFIX):
        rest = text[len(_V2_SUBAGENT_PROMPT_PREFIX) :]
        if rest.startswith("Task: "):
            return rest
    return text


def _compact_v2_system_prompt(text: str) -> str:
    compact = _V2_MODEL_BLOCK_RE.sub("", text)
    compact = _V2_INSTRUCTIONS_RE.sub("", compact)
    return _V2_ENV_BLOCK_RE.sub("", compact)


def _v2_messages_to_legacy(messages: list) -> list:
    call_names: dict[str, str] = {}
    out = []
    for msg in messages:
        if not isinstance(msg, dict):
            out.append(msg)
            continue
        copy_msg = dict(msg)
        if copy_msg.get("role") == "system" and isinstance(copy_msg.get("content"), str):
            copy_msg["content"] = _compact_v2_system_prompt(copy_msg["content"])
        elif copy_msg.get("role") == "user":
            content = copy_msg.get("content")
            if isinstance(content, str):
                copy_msg["content"] = _strip_v2_subagent_prefix(content)
            elif isinstance(content, list):
                copy_msg["content"] = [
                    {**part, "text": _strip_v2_subagent_prefix(part["text"])}
                    if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)
                    else part
                    for part in content
                ]
        if isinstance(copy_msg.get("tool_calls"), list):
            new_calls = []
            for tc in copy_msg["tool_calls"]:
                if not isinstance(tc, dict) or not isinstance(tc.get("function"), dict):
                    new_calls.append(tc)
                    continue
                fn = dict(tc["function"])
                orig_name = fn.get("name")
                canon_name = orig_name
                if isinstance(orig_name, str):
                    try:
                        parsed_args = json.loads(fn.get("arguments") or "{}")
                    except ValueError:
                        parsed_args = None
                    if isinstance(parsed_args, dict):
                        canon_name, canon_args = _v2_args_to_legacy(orig_name, parsed_args)
                        fn["name"] = canon_name
                        fn["arguments"] = json.dumps(canon_args, separators=(",", ":"))
                    elif orig_name == "subagent":
                        canon_name = "task"
                        fn["name"] = "task"
                    elif orig_name == "shell":
                        canon_name = "bash"
                        fn["name"] = "bash"
                if isinstance(tc.get("id"), str) and isinstance(canon_name, str):
                    call_names[tc["id"]] = canon_name
                new_calls.append({**tc, "function": fn})
            copy_msg["tool_calls"] = new_calls
        elif copy_msg.get("role") == "tool" and isinstance(copy_msg.get("content"), str):
            call_id = copy_msg.get("tool_call_id")
            if call_names.get(call_id) == "subagent" or (
                call_names.get(call_id) == "task" and copy_msg["content"].startswith("<subagent ")
            ):
                converted = _normalize_subagent_output_to_task(copy_msg["content"])
                if converted is not None:
                    copy_msg["content"] = converted
            elif call_names.get(call_id) == "write" and _V2_WRITE_SUCCESS_RE.match(copy_msg["content"]):
                copy_msg["content"] = "Wrote file successfully."
            elif call_names.get(call_id) == "read" and _V2_READ_HEADER_RE.match(copy_msg["content"]):
                copy_msg["content"] = _compact_v2_read_output(copy_msg["content"])
        out.append(copy_msg)
    return out


def _compact_retired_history_bundle(
    body: dict, tasks, *, recent_turns: int = 0
) -> tuple[dict, dict | None]:
    """Consolidate multiple already-completed/archived turns into one archive ref.

    Used only when bounded_history still exceeds MAX_CONTEXT_BYTES or
    MAX_PROMPT_TOKENS under strict offline byte bounds. When recent_turns > 0,
    retains the most recent active assistant/tool turns inline while bundling
    earlier archived/completed turns.
    """
    from full_agent_context import content_snapshot, verified_file, workspace_artifact

    messages = body.get("messages")
    spec = getattr(tasks, "active_spec", None)
    active_prompt = getattr(tasks, "active_prompt", None)
    if not isinstance(messages, list) or spec is None or not isinstance(active_prompt, str):
        return body, None
    contract = verified_file(
        tasks.workdir, str(Path(spec.evidence_dir) / "task-context.txt"), active_prompt.encode()
    )
    if contract is None:
        return body, None

    ids = [call.get("id") for msg in messages for call in msg.get("tool_calls", [])]
    result_ids = [msg.get("tool_call_id") for msg in messages if msg.get("role") == "tool"]
    units: list[tuple[int, int, list, list[dict], bool, int]] = []
    idx = 0
    while idx < len(messages):
        msg = messages[idx]
        content = msg.get("content")
        if msg.get("role") == "user" and isinstance(content, str) and content.startswith(_HISTORY_PREFIX):
            try:
                parsed = json.loads(content[len(_HISTORY_PREFIX) :])
                ref = parsed.get("content_ref") if isinstance(parsed, dict) else None
                calls = parsed.get("calls") if isinstance(parsed, dict) else None
                art = (
                    workspace_artifact(tasks.workdir, ref["path"])
                    if isinstance(ref, dict) and isinstance(ref.get("path"), str)
                    else None
                )
                raw_list = (
                    json.loads(art[0])
                    if art is not None and art[1]["sha256"] == ref.get("sha256")
                    else None
                )
            except (KeyError, TypeError, ValueError, UnicodeDecodeError):
                art = None
                raw_list = None
                calls = None
            if isinstance(raw_list, list) and isinstance(calls, list):
                compact_calls = [
                    {"id": c["id"]}
                    for c in calls
                    if isinstance(c, dict) and isinstance(c.get("id"), str)
                ]
                turn_count = max(
                    1,
                    sum(1 for item in raw_list if isinstance(item, dict) and item.get("role") == "assistant"),
                )
                units.append((idx, idx + 1, raw_list, compact_calls, False, turn_count))
                idx += 1
                continue
        calls = msg.get("tool_calls", []) if msg.get("role") == "assistant" else []
        if calls:
            expected = [call.get("id") for call in calls]
            end = idx + len(calls) + 1
            returned = messages[idx + 1 : end]
            if (
                len(returned) == len(calls)
                and all(isinstance(i, str) for i in expected)
                and all(ids.count(i) == 1 and result_ids.count(i) == 1 for i in expected)
                and all(row.get("role") == "tool" for row in returned)
                and set(expected) == {row.get("tool_call_id") for row in returned}
            ):
                turn_calls = [{"id": call["id"]} for call in calls]
                units.append((idx, end, messages[idx:end], turn_calls, True, 1))
                idx = end
                continue
        idx += 1

    if recent_turns > 0:
        active_indices = [u_idx for u_idx, unit in enumerate(units) if unit[4]]
        if active_indices:
            skip = set(active_indices[-recent_turns:])
            units = [unit for u_idx, unit in enumerate(units) if u_idx not in skip]

    if len(units) < 2 and not (len(units) == 1 and not units[0][4]):
        return body, None
    bundled_messages: list = []
    bundled_calls: list[dict] = []
    removed: set[int] = set()
    first_idx = units[0][0]
    bundled_turns = 0
    for start, end, raw_items, turn_calls, _is_active, turn_count in units:
        bundled_messages.extend(raw_items)
        bundled_calls.extend(turn_calls)
        bundled_turns += turn_count
        removed.update(range(start, end))
    removed.discard(first_idx)

    artifact = content_snapshot(tasks, spec, "native-history", provider_json(bundled_messages))
    if artifact is None:
        return body, None
    replacement = {
        "role": "user",
        "content": _HISTORY_PREFIX
        + provider_json(
            {
                "content_ref": artifact,
                "calls": bundled_calls,
                "action": "Completed; read archive.",
            }
        ).decode(),
    }
    before = len(provider_json(messages))
    view = copy.deepcopy(body)
    view["messages"][first_idx] = replacement
    view["messages"] = [msg for i, msg in enumerate(view["messages"]) if i not in removed]
    after = len(provider_json(view["messages"]))
    if after >= before:
        return body, None
    return view, {
        "schema": "bounded-worker-history/1",
        "archives": [artifact],
        "recent_turns_kept": recent_turns,
        "bundled_turns": bundled_turns,
        "messages_bytes_before": before,
        "messages_bytes_after": after,
        "saved_bytes": before - after,
    }


def _compact_verified_task_contract(body: dict, tasks) -> tuple[dict, bool]:
    """Replace an oversized verified TaskSpec prompt with a compact host pointer.

    Used only when bounded_history + history bundling still exceed MAX_PROMPT_TOKENS
    on wide-tool phases (e.g. access-3) under offline utf8_bytes_1x bounds.
    """
    from full_agent_context import verified_file

    messages = body.get("messages")
    spec = getattr(tasks, "active_spec", None)
    active_prompt = getattr(tasks, "active_prompt", None)
    if not isinstance(messages, list) or spec is None or not isinstance(active_prompt, str):
        return body, False
    contract = verified_file(
        tasks.workdir, str(Path(spec.evidence_dir) / "task-context.txt"), active_prompt.encode()
    )
    if contract is None:
        return body, False
    evidence_dir = Path(spec.evidence_dir).relative_to(tasks.workdir).as_posix()
    wd_prefix = str(tasks.workdir).rstrip("/") + "/"
    host_lines = []
    for line in active_prompt.splitlines():
        if line.startswith(("Scope:", "Tools:", "Object pool:", "Handoff packet:", "Previous summaries:", "Vector:")):
            if line.startswith(("Object pool:", "Handoff packet:")):
                label, _, val = line.partition(":")
                rel = val.strip().replace(wd_prefix, "").split(" (", 1)[0]
                host_lines.append(f"{label}: {rel}")
            elif line.startswith("Scope:"):
                host_lines.append(line.removesuffix(" (from Workdir)"))
            else:
                host_lines.append(line)
    pointer_lines = [
        f"Task: {spec.id}",
        f"Phase: {spec.phase}",
        f"Target: {spec.target}",
        f"Workdir: {tasks.workdir}",
        *host_lines,
        f"Evidence dir: {evidence_dir}",
        f"Summary path: summaries/{spec.id}.json",
        f"Synthetic session references (host-owned): {json.dumps(tasks.bindings, separators=(',', ':'))}",
        f"Commands: Read {contract['path']}; refs under Workdir.",
    ]
    pointer = "\n".join(pointer_lines)

    cont_prefix = f"Task: {spec.id}\nPhase: {spec.phase}\nTarget: {spec.target}\nWorkdir: {tasks.workdir}\n"
    cont_suffix = f"Read {contract['path']} only for missing detail; refs under Workdir."
    view = copy.deepcopy(body)
    replaced = False

    def _shorten(text: str) -> str:
        nonlocal replaced
        if active_prompt in text:
            replaced = True
            return text.replace(active_prompt, pointer)
        if cont_prefix in text and cont_suffix in text:
            start = text.index(cont_prefix)
            end = text.index(cont_suffix, start) + len(cont_suffix)
            if len(pointer) < end - start:
                replaced = True
                return text[:start] + pointer + text[end:]
        return text

    for msg in view["messages"]:
        if msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"] = _shorten(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    part["text"] = _shorten(part["text"])
    if not replaced or len(provider_json(view["messages"])) >= len(provider_json(messages)):
        return body, False
    return view, True


def _compact_verified_planner_prompt(
    body: dict, tasks, planner_prompt: str | None, completed_tasks: list
) -> tuple[dict, bool]:
    """Replace an already-executed verified planner bootstrap prompt with a compact pointer.

    Used only on follow-up planner turns (>=1 verified completed task) when
    offline utf8_bytes_1x prompt bounds would otherwise truncate requested output
    tokens. Unverified user prompts never match `planner_prompt`.
    """
    from full_agent_context import verified_file

    messages = body.get("messages")
    if (
        not isinstance(messages, list)
        or tasks is None
        or not isinstance(planner_prompt, str)
        or not planner_prompt
        or not completed_tasks
    ):
        return body, False
    raw = planner_prompt.encode()
    sha = hashlib.sha256(raw).hexdigest()
    rel_path = f"planner-context-{sha[:16]}.txt"
    archive_path = Path(tasks.workdir) / rel_path
    try:
        fd = os.open(archive_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
    except FileExistsError:
        pass
    except OSError:
        return body, False
    verified = verified_file(tasks.workdir, rel_path, raw)
    if verified is None:
        return body, False

    kept_lines = [
        line
        for line in planner_prompt.splitlines()
        if line.startswith(("Scope:", "Shared limits:"))
    ]
    pointer = "\n".join([
        f"Target: {tasks.specs[0].target if tasks.specs else ''}",
        *kept_lines,
        f"Workdir: {tasks.workdir}",
        f"Specs: {Path(tasks.workdir) / 'specs.json'}",
        f"Task order: {', '.join(spec.id for spec in tasks.specs)}",
        f"Synthetic session references: {json.dumps(tasks.bindings)}",
        "Delegate next TaskSpec: <id> to worker; never re-render specs or infer acceptance; "
        "require validation & ledger_checkpoint.",
        f"Read {verified['path']} for full bootstrap rules.",
    ])
    if len(pointer.encode()) >= len(raw):
        return body, False

    view = copy.deepcopy(body)
    replaced = False
    for msg in view["messages"]:
        if msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str) and planner_prompt in content:
            msg["content"] = content.replace(planner_prompt, pointer)
            replaced = True
        elif isinstance(content, list):
            for part in content:
                if (
                    isinstance(part, dict)
                    and part.get("type") == "text"
                    and isinstance(part.get("text"), str)
                    and planner_prompt in part["text"]
                ):
                    part["text"] = part["text"].replace(planner_prompt, pointer)
                    replaced = True
    if not replaced or len(provider_json(view["messages"])) >= len(provider_json(messages)):
        return body, False
    return view, True


def _restore_v2_spilled_tool_outputs(
    body: dict, active, tool_receipts: list, private: Path
) -> dict:
    """Restore full verified MCP tool outputs when OpenCode v2 spills >50KB lines to tool-output.

    Restores only when the tool message carries OpenCode v2's spill placeholder and
    matches a host-owned private receipt by spec, origin, tool name, and arguments.
    worker_followup_context then projects the result with result_view intact.
    """
    from full_agent_budget import compact_json_text

    messages = body.get("messages")
    if not isinstance(messages, list) or active is None or not tool_receipts:
        return body
    candidates: list[tuple[str, dict, str]] = []
    for row in tool_receipts:
        if row.get("task_spec_id") != active.id or row.get("origin") != "solver":
            continue
        receipt_path = Path(row.get("artifact", ""))
        if receipt_path.parent != Path(private) or receipt_path.is_symlink():
            continue
        try:
            with receipt_path.open("rb") as handle:
                raw_receipt = handle.read(128 * 1024 + 1)
            if len(raw_receipt) > 128 * 1024:
                continue
            receipt = json.loads(raw_receipt)
            execution = receipt["execution"]
            if execution.get("execution_failed") or receipt.get("error"):
                continue
            raw_out = execution["result"]["output"]
            emitted = compact_json_text(raw_out) if isinstance(raw_out, str) else provider_json(raw_out).decode()
            candidates.append((receipt["tool"], receipt["arguments"], emitted))
        except (OSError, ValueError, TypeError, KeyError):
            continue
    if not candidates:
        return body

    view = None
    used: set[int] = set()
    ids = [call.get("id") for msg in messages for call in msg.get("tool_calls", [])]
    results: dict[str, list[tuple[int, dict]]] = {}
    for idx, msg in enumerate(messages):
        if msg.get("role") == "tool" and isinstance(msg.get("tool_call_id"), str):
            results.setdefault(msg["tool_call_id"], []).append((idx, msg))

    for idx, msg in enumerate(messages):
        if msg.get("role") != "assistant":
            continue
        for call in msg.get("tool_calls", []):
            ident = call.get("id")
            fn = call.get("function", {})
            tool_name = fn.get("name")
            returned = results.get(ident, []) if isinstance(ident, str) else []
            if not isinstance(tool_name, str) or ids.count(ident) != 1 or len(returned) != 1 or returned[0][0] <= idx:
                continue
            try:
                call_args = json.loads(fn.get("arguments") or "{}")
            except (ValueError, TypeError):
                continue
            ret_idx, ret_msg = returned[0]
            ret_content = ret_msg.get("content")
            if not isinstance(ret_content, str):
                continue
            for cand_idx, (c_tool, c_args, emitted) in enumerate(candidates):
                if cand_idx in used or c_tool != tool_name or c_args != call_args:
                    continue
                used.add(cand_idx)
                if _V2_SPILLED_TOOL_RE.search(ret_content) and len(emitted.encode()) > 32 * 1024:
                    if view is None:
                        view = copy.deepcopy(body)
                    view["messages"][ret_idx]["content"] = emitted
                break
    return view if view is not None else body


def _restore_v2_planner_completed_args(body: dict, task_calls: dict, completed_tasks: list, private: Path) -> dict:
    """Restore post-gate canonical delegation args for completed OpenCode v2 subagent turns.

    OpenCode v2 records the model's pre-hook arguments (`TaskSpec: ...`) in session
    history rather than the hook-rewritten args. Matching both the gate's exact
    pre_gate_args record and the immutable completion receipt lets
    planner_followup_context apply its verified projection without weakening checks.
    """
    messages = body.get("messages")
    if not isinstance(messages, list) or not completed_tasks or not task_calls:
        return body
    receipts: dict[str, dict] = {}
    for record in completed_tasks:
        path = Path(record.get("artifact", ""))
        if path.parent != Path(private) or path.is_symlink():
            continue
        try:
            with path.open("rb") as handle:
                raw = handle.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != record.get("sha256"):
                continue
            receipt = json.loads(raw)
            if not isinstance(receipt, dict) or receipt.get("schema") != "native-task-completion/1":
                continue
            receipts[receipt["call_id"]] = receipt
        except (OSError, ValueError, TypeError, KeyError):
            continue
    if not receipts:
        return body
    view = copy.deepcopy(body)
    for index, msg in enumerate(view["messages"]):
        if msg.get("role") != "assistant":
            continue
        for call in msg.get("tool_calls", []):
            ident = call.get("id")
            fn = call.get("function", {})
            if fn.get("name") != "task" or not isinstance(ident, str) or ident not in receipts:
                continue
            receipt = receipts[ident]
            recorded = task_calls.get((receipt.get("session_id"), ident))
            pre_gate = recorded.get("pre_gate_args") if isinstance(recorded, dict) else None
            if not isinstance(pre_gate, dict):
                continue
            results = [
                r for r in view["messages"][index + 1 :] if r.get("role") == "tool" and r.get("tool_call_id") == ident
            ]
            if len(results) != 1 or results[0].get("content") != receipt.get("output"):
                continue
            try:
                args = json.loads(fn.get("arguments") or "")
            except (ValueError, TypeError):
                continue
            if args == pre_gate:
                fn["arguments"] = provider_json(receipt["args"]).decode()
    return view


def _v2_request_to_legacy(body: dict) -> dict:
    updated = dict(body)
    if isinstance(updated.get("tools"), list):
        converted = [item for item in (_v2_tool_def_to_legacy(r) for r in updated["tools"]) if item is not None]
        updated["tools"] = converted
    if isinstance(updated.get("messages"), list):
        updated["messages"] = _v2_messages_to_legacy(updated["messages"])
    return updated


def _legacy_response_to_v2(response: dict) -> dict:
    choices = response.get("choices")
    if not isinstance(choices, list):
        return response
    out_choices = []
    for choice in choices:
        if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
            out_choices.append(choice)
            continue
        msg = dict(choice["message"])
        if isinstance(msg.get("tool_calls"), list):
            new_calls = []
            for tc in msg["tool_calls"]:
                if not isinstance(tc, dict) or not isinstance(tc.get("function"), dict):
                    new_calls.append(tc)
                    continue
                fn = dict(tc["function"])
                name = fn.get("name")
                if isinstance(name, str):
                    try:
                        parsed_args = json.loads(fn.get("arguments") or "{}")
                    except ValueError:
                        parsed_args = None
                    if isinstance(parsed_args, dict):
                        v2_name, v2_args = _legacy_args_to_v2(name, parsed_args)
                        fn["name"] = v2_name
                        fn["arguments"] = json.dumps(v2_args)
                new_calls.append({**tc, "function": fn})
            msg["tool_calls"] = new_calls
        out_choices.append({**choice, "message": msg})
    return {**response, "choices": out_choices}


class NativeBrokerCompat(HostBroker):
    """Compatibility adapter adding native OpenCode gate/bridge/SSE endpoints."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.nonce = secrets.token_hex(24)
        self.ready = False
        self.gates = []
        self.task_calls = {}
        self.completed_tasks = []
        self.planner_prompt = None

    def gate(self, body):
        self._require_open()
        raw_tool, raw_args = body.get("tool"), body.get("args") or {}
        if not isinstance(raw_tool, str) or not isinstance(raw_args, dict):
            raise ValueError("invalid native gate call")
        v2_call = (
            raw_tool in {"subagent", "shell"}
            or (raw_tool in _PATH_TOOLS and "path" in raw_args and "filePath" not in raw_args)
        )
        tool, args = _v2_args_to_legacy(raw_tool, raw_args) if v2_call else (raw_tool, raw_args)
        named = {group + "_" + name for group, names in CATALOG.items() for name in names}
        with self.lock:
            spec = None
            policy_denial = None
            if (
                self.runtime_policy is not None
                and self.tasks is not None
                and self.tasks.active_spec is not None
                and tool in LOCAL_TOOLS - {"task"}
            ):
                try:
                    self.runtime_policy.check_tool(self.tasks.active_spec, tool)
                except ValueError as exc:
                    policy_denial = str(exc)
                except BudgetError as exc:
                    self.stop_reason = str(exc)
                    raise
            if policy_denial:
                decision = {"allowed": False, "reason": policy_denial}
            elif tool not in LOCAL_TOOLS | named:
                decision = {"allowed": False, "reason": "tool outside benchmark catalog"}
            elif (
                tool in named
                and self.tasks is not None
                and self.tasks.active_spec is not None
                and tool not in self.tasks.active_spec.tools
            ):
                decision = {"allowed": False, "reason": "tool outside active TaskSpec"}
            elif tool in named:
                # This native hook cannot execute an MCP tool. Its only route
                # is call_tool below, which checks the current host policy.
                # Do not count a second invocation at the dispatch-only hook.
                decision = {"allowed": True, "reason": "host_policy_at_execution"}
            elif tool == "task" and args.get("subagent_type") != "worker":
                decision = {"allowed": False, "reason": "only native worker delegation is allowed"}
            else:
                try:
                    pre_gate_args = json.loads(json.dumps(args)) if tool == "task" else None
                    if tool == "task" and self.tasks is not None:
                        spec, args = self.tasks.resolve(args)
                        self._check_handoff(spec)
                    decision = self.engine.validate_tool_invocation(tool, args)
                    if decision["allowed"] and spec is not None:
                        self.tasks.scaffold(spec, prompt=args["prompt"])
                        key = (body.get("session_id"), body.get("call_id"))
                        self.task_calls[key] = {
                            "spec_id": spec.id,
                            "args": json.loads(json.dumps(args)),
                            "pre_gate_args": pre_gate_args,
                        }
                except (ValueError, OSError) as exc:
                    decision = {"allowed": False, "reason": str(exc)[:300]}
            self.gates.append(
                {
                    "tool": tool,
                    "session_id": body.get("session_id"),
                    "call_id": body.get("call_id"),
                    "allowed": decision["allowed"],
                    "canonical_spec_id": spec.id if spec is not None else None,
                    "reason": decision.get("reason", ""),
                }
            )
            if (
                self.runtime_policy is not None
                and tool in LOCAL_TOOLS - {"task"}
                and self.tasks is not None
                and self.tasks.active_spec
            ):
                self.runtime_policy.record_result(
                    self.tasks.active_spec,
                    tool,
                    {"execution_failed": not decision["allowed"], "result": {"output": {"ok": decision["allowed"]}}},
                )
            dump(self.private / "native-gates.json", self.gates)
            if self.tasks is not None:
                dump(self.private / "summary-normalizations.json", self.tasks.normalizations)
        result = {"allowed": decision["allowed"], "reason": decision.get("reason", "")}
        if decision["allowed"] and spec is not None:
            result["args"] = _legacy_args_to_v2(tool, args)[1] if v2_call else args
        return result

    def record_task_completion(self, body):
        """Native after-hook receipt; context only, never execution authority."""
        from full_agent_context import terminal_summary, verified_file

        if (
            not isinstance(body, dict)
            or set(body) != {"tool", "session_id", "call_id", "output", "metadata"}
            or body["tool"] not in {"task", "subagent"}
            or not isinstance(body["session_id"], str)
            or not isinstance(body["call_id"], str)
            or not isinstance(body["output"], str)
            or len(body["output"].encode()) > 64 * 1024
            or not isinstance(body["metadata"], dict)
            or set(body["metadata"]) != {"parentSessionId", "sessionId"}
        ):
            return {"recorded": False, "reason": "unsupported_completion_shape"}
        with self.lock:
            self._require_open()
            call = self.task_calls.get((body["session_id"], body["call_id"]))
            if call is None or self.tasks is None:
                return {"recorded": False, "reason": "missing_admission"}
            metadata = body["metadata"]
            child = metadata["sessionId"]
            output_text = body["output"]
            if body["tool"] == "subagent" and isinstance(child, str) and child:
                converted = _normalize_subagent_output_to_task(output_text, child=child)
                if converted is not None:
                    output_text = converted
            if (
                metadata["parentSessionId"] != body["session_id"]
                or not isinstance(child, str)
                or not child
                or not output_text.startswith(f'<task id="{child}" state="completed">\n<task_result>\n')
                or not output_text.endswith("\n</task_result>\n</task>")
            ):
                return {"recorded": False, "reason": "native_completion_mismatch"}
            spec = next(s for s in self.tasks.specs if s.id == call["spec_id"])
            summary = terminal_summary(self.tasks, spec)
            contract = verified_file(
                self.workdir,
                str(Path(spec.evidence_dir) / "task-context.txt"),
                call["args"]["prompt"].encode(),
            )
            if summary is None or contract is None:
                return {"recorded": False, "reason": "unverified_summary_or_contract"}
            receipt = {
                "schema": "native-task-completion/1",
                "spec_id": spec.id,
                "call_id": body["call_id"],
                "session_id": body["session_id"],
                "args": call["args"],
                "output": output_text,
                "metadata": metadata,
                "summary": summary[1],
                "summary_status": summary[0]["status"],
                "contract": contract,
                "security_validation_claimed": False,
            }
            raw = provider_json(receipt)
            if len(raw) > 128 * 1024:
                return {"recorded": False, "reason": "receipt_too_large"}
            sha = hashlib.sha256(raw).hexdigest()
            path = self.private / ("task-completion-" + sha + ".json")
            if not path.exists():
                with path.open("xb") as handle:
                    handle.write(raw)
            elif path.is_symlink() or path.read_bytes() != raw:
                return {"recorded": False, "reason": "receipt_changed"}
            record = {"artifact": str(path), "sha256": sha}
            if record not in self.completed_tasks:
                self.completed_tasks.append(record)
                dump(self.private / "task-completions.json", self.completed_tasks)
            return {"recorded": True, "sha256": sha}

    def completion(self, body, *, native_context=True, max_body=MAX_BODY):
        self._require_open()
        wire_v2 = isinstance(body, dict) and _uses_opencode_v2(body)
        if wire_v2:
            body = _v2_request_to_legacy(body)
        if isinstance(body, dict) and "tools" in body:
            body = {
                **body,
                "tools": compact_tools(
                    body["tools"], description_limit=NATIVE_DESCRIPTION_LIMIT, strip_annotations=True
                ),
            }
        active = self.tasks.active_spec if self.tasks is not None else None
        tools = body.get("tools") if isinstance(body, dict) else None
        has_delegation = isinstance(tools, list) and any(
            row.get("function", {}).get("name") == "task" for row in tools
        )
        worker_call = active is not None and isinstance(tools, list) and bool(tools) and not has_delegation
        if wire_v2 and has_delegation and isinstance(tools, list):
            body["tools"] = [row for row in tools if row.get("function", {}).get("name") in {"task", "read"}]
            tools = body["tools"]
        if active is not None and worker_call and native_context:
            allowed = (
                self.runtime_policy.allowed_tools(active)
                if self.runtime_policy is not None
                else set(active.tools) | {"read", "write", "edit", "bash"}
            )
            body["tools"] = [row for row in tools if row.get("function", {}).get("name") in allowed]
            for row in body["tools"]:
                function = row.get("function", {})
                if function.get("name") == "kali-tools_ledger_prepare_handoff":
                    parameters = function.setdefault("parameters", {"type": "object"})
                    properties = parameters.setdefault("properties", {})
                    properties["session_bindings_json"] = {
                        "type": "string",
                        "enum": [provider_json(self.tasks.bindings).decode()],
                        "description": "Use this exact host binding literal; do not add status fields.",
                    }
                    required = parameters.setdefault("required", [])
                    if "session_bindings_json" not in required:
                        required.append("session_bindings_json")
            if wire_v2:
                body = _restore_v2_spilled_tool_outputs(body, active, self.tools, self.private)
            from full_agent_context import worker_followup_context

            body, context = worker_followup_context(body, self.tasks, self.private, self.tools, self.handoffs)
        else:
            context = None
            if (
                native_context
                and self.tasks is not None
                and isinstance(tools, list)
                and any(row.get("function", {}).get("name") == "task" for row in tools)
            ):
                if wire_v2:
                    body = _restore_v2_planner_completed_args(body, self.task_calls, self.completed_tasks, self.private)
                from full_agent_context import planner_followup_context

                body, context = planner_followup_context(body, self.tasks, self.private, self.completed_tasks)

        minimum_output_tokens = 1
        if self.runtime_policy is not None:
            from full_agent_runtime_policy import MIN_OUTPUT_TOKENS

            minimum_output_tokens = MIN_OUTPUT_TOKENS

        def _completion_preview(candidate):
            preview = {
                k: v
                for k, v in candidate.items()
                if k not in {"stream_options", "max_tokens", "max_completion_tokens"}
            }
            preview["stream"] = False
            return preview

        def _over_native_bounds(candidate, max_context_bytes, max_prompt_tokens):
            return (
                len(provider_json(candidate["messages"])) > max_context_bytes
                or prompt_bound(provider_json(_completion_preview(candidate)))[0] > max_prompt_tokens
            )

        def _shrink_native_worker_request(candidate, metrics, max_context_bytes, max_prompt_tokens):
            from full_agent_history import bounded_history

            for recent in (2, 1):
                if not _over_native_bounds(candidate, max_context_bytes, max_prompt_tokens):
                    return candidate
                candidate, archived = bounded_history(
                    candidate,
                    self.tasks,
                    max_bytes=min(max_context_bytes, len(provider_json(candidate["messages"])) - 1),
                    recent_turns=recent,
                    compact=True,
                )
                if archived is not None:
                    metrics.setdefault("history_projections", []).append(archived)
            if _over_native_bounds(candidate, max_context_bytes, max_prompt_tokens):
                candidate, bundled = _compact_retired_history_bundle(candidate, self.tasks, recent_turns=1)
                if bundled is not None:
                    metrics.setdefault("history_projections", []).append(bundled)
            # Shrink verbose verified task prose before evicting the newest tool turn.
            if _over_native_bounds(candidate, max_context_bytes, max_prompt_tokens):
                candidate, _ = _compact_verified_task_contract(candidate, self.tasks)
            if _over_native_bounds(candidate, max_context_bytes, max_prompt_tokens):
                candidate, archived = bounded_history(
                    candidate,
                    self.tasks,
                    max_bytes=min(max_context_bytes, len(provider_json(candidate["messages"])) - 1),
                    recent_turns=0,
                    compact=True,
                )
                if archived is not None:
                    metrics.setdefault("history_projections", []).append(archived)
            if _over_native_bounds(candidate, max_context_bytes, max_prompt_tokens):
                candidate, bundled = _compact_retired_history_bundle(candidate, self.tasks, recent_turns=0)
                if bundled is not None:
                    metrics.setdefault("history_projections", []).append(bundled)
            return candidate

        def prepare_request(req_body, metrics):
            if self.runtime_policy is None:
                return req_body, None, self.budget.available("tokens")
            from full_agent_runtime_policy import MAX_CONTEXT_BYTES, MAX_PROMPT_TOKENS

            if worker_call and native_context:
                req_body = _shrink_native_worker_request(req_body, metrics, MAX_CONTEXT_BYTES, MAX_PROMPT_TOKENS)
            if worker_call and not native_context:
                req_body, runtime_info, projection = self.project_runtime_context(req_body, active, None)
                if projection is not None:
                    metrics["context_projection"] = projection
            else:
                runtime_info = self.runtime_policy.prepare(
                    active if worker_call else None,
                    prompt_bound(provider_json(req_body))[0],
                )
            if worker_call and native_context:
                allowed = self.runtime_policy.allowed_tools(active)
                req_body["tools"] = [
                    row for row in req_body["tools"] if row.get("function", {}).get("name") in allowed
                ]
            req_body = runtime_request(req_body, runtime_info, native_context=native_context)
            if not worker_call and native_context and self.completed_tasks and self.planner_prompt:
                output_cap = getattr(self.provider_transport, "output_limit", 8192)
                requested = req_body.get("max_completion_tokens", req_body.get("max_tokens", output_cap))
                desired_output = (
                    min(requested, output_cap)
                    if type(requested) is int and requested > 0
                    else minimum_output_tokens
                )
                upper = prompt_bound(provider_json(req_body))[0]
                if (
                    runtime_info["request_token_allowance"] - upper < desired_output
                    or upper > MAX_PROMPT_TOKENS
                ):
                    req_body, _ = _compact_verified_planner_prompt(
                        req_body, self.tasks, self.planner_prompt, self.completed_tasks
                    )
            if worker_call and native_context:
                req_body = _shrink_native_worker_request(req_body, metrics, MAX_CONTEXT_BYTES, MAX_PROMPT_TOKENS)
            total_remaining = self.budget.available("tokens")
            if prompt_bound(provider_json(_completion_preview(req_body)))[0] + minimum_output_tokens > total_remaining:
                return req_body, runtime_info, total_remaining
            if _over_native_bounds(req_body, MAX_CONTEXT_BYTES, MAX_PROMPT_TOKENS):
                raise BudgetError("context_limit_exhausted")
            return req_body, runtime_info, runtime_info["request_token_allowance"]
        compat_mod = sys.modules.get("full_agent_broker")
        if compat_mod is not None and max_body is MAX_BODY:
            max_body = getattr(compat_mod, "MAX_BODY", max_body)
        response = self.provider_transport.complete(
            body,
            prepare_request=prepare_request,
            runtime_policy=self.runtime_policy,
            task_spec_id=active.id if active is not None and worker_call else None,
            context_projection=context,
            minimum_output_tokens=minimum_output_tokens,
            max_body=max_body,
        )
        if wire_v2:
            response = _legacy_response_to_v2(response)
        if not body.get("stream"):
            return "application/json", json.dumps(response).encode()
        # Native stream consumers receive the exact buffered completion and final usage.
        common = {k: response[k] for k in ("id", "created", "model") if k in response}
        choices = []
        for i, row in enumerate(response["choices"]):
            message = dict(row["message"])
            if "tool_calls" in message:
                message["tool_calls"] = [{**t, "index": j} for j, t in enumerate(message["tool_calls"])]
            choices.append({"index": row.get("index", i), "delta": message, "finish_reason": None})
        chunks = [
            {**common, "object": "chat.completion.chunk", "choices": choices},
            {
                **common,
                "object": "chat.completion.chunk",
                "choices": [
                    {"index": row.get("index", i), "delta": {}, "finish_reason": row.get("finish_reason")}
                    for i, row in enumerate(response["choices"])
                ],
            },
            {**common, "object": "chat.completion.chunk", "choices": [], "usage": response["usage"]},
        ]
        return "text/event-stream", ("".join("data: " + json.dumps(c) + "\n\n" for c in chunks) + "data: [DONE]\n\n").encode()

    def dispatch(self, path, body):
        self._require_open()
        if path == "/ready":
            if body != {"nonce": self.nonce}:
                raise ValueError("wrong runtime nonce")
            self.ready = True
            return 200, "application/json", b'{"ready":true}'
        if not self.ready:
            raise ValueError("native runtime not ready")
        if path == "/v1/chat/completions":
            ctype, data = self.completion(body)
            return 200, ctype, data
        if path == "/gate":
            return 200, "application/json", json.dumps(self.gate(body)).encode()
        if path == "/task-complete":
            return 200, "application/json", json.dumps(self.record_task_completion(body)).encode()
        group = path.removeprefix("/mcp/")
        if not path.startswith("/mcp/") or group not in self.catalog:
            raise ValueError("unknown broker endpoint")
        method, ident, params = body.get("method"), body.get("id"), body.get("params") or {}
        if body.get("jsonrpc") != "2.0":
            raise ValueError("invalid JSON-RPC")
        if method == "notifications/initialized":
            return 202, "application/json", b""
        if method == "initialize":
            version = params.get("protocolVersion", "2024-11-05")
            if version not in {"2024-11-05", "2025-03-26", "2025-06-18"}:
                version = "2025-06-18"
            result = {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": group, "version": "native-broker/1"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self.catalog[group]}
        elif method == "tools/call":
            try:
                result = self.call_tool(group, params.get("name"), params.get("arguments") or {})
            except (ValueError, RuntimeError) as exc:
                result = {"content": [{"type": "text", "text": str(exc)[:300]}], "isError": True}
        else:
            return (
                200,
                "application/json",
                json.dumps({"jsonrpc": "2.0", "id": ident, "error": {"code": -32601, "message": "method unavailable"}}).encode(),
            )
        return 200, "application/json", json.dumps({"jsonrpc": "2.0", "id": ident, "result": result}).encode()


def make_server(path, broker, *, server_base=UnixStreamServer):
    trace_lock = threading.Lock()

    class Server(ThreadingMixIn, server_base):
        daemon_threads = True
        # A full AF_UNIX accept queue returns EAGAIN immediately. Allow the
        # bounded native MCP startup burst without losing whole tool groups.
        request_queue_size = 64

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_POST(self):
            started = time.monotonic()
            body, error = None, None
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= MAX_BODY:
                    raise ValueError("invalid request size")
                body = json.loads(self.rfile.read(size))
                if not isinstance(body, dict):
                    raise ValueError("object required")
                status, ctype, raw = broker.dispatch(self.path, body)
            except Exception as exc:
                error = type(exc).__name__
                status, ctype = 400, "application/json"
                # Never leak upstream URLs, credentials, exception tracebacks or state.
                raw = json.dumps({"error": {"message": type(exc).__name__, "type": "benchmark_denied"}}).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                # Native clients may disappear while their group is stopped.
                # Accounting and artifacts were already settled by dispatch.
                pass
            finally:
                # Startup/control metadata only. Do not log RPC arguments or
                # provider bodies, which may contain private target evidence.
                group = self.path.removeprefix("/mcp/")
                if self.path.startswith("/mcp/") and group in CATALOG:
                    method = body.get("method") if isinstance(body, dict) else None
                    if not isinstance(method, str) or method not in {
                        "initialize",
                        "notifications/initialized",
                        "tools/list",
                        "tools/call",
                        "ping",
                    }:
                        method = "unsupported"
                    ident = body.get("id") if isinstance(body, dict) else None
                    event = {
                        "group": group,
                        "method": method,
                        "status": status,
                        "request_id": ident if type(ident) is int else None,
                        "error": error,
                        "response_bytes": len(raw),
                        "seconds": time.monotonic() - started,
                    }
                    with trace_lock, (broker.private / "transport-events.jsonl").open("a") as trace:
                        trace.write(json.dumps(event) + "\n")

    return Server(str(path), Handler)


def native_model_selection(data, model="", worker_model=""):
    """Inspect legacy opencode.json model selection without exporting credentials."""
    selected = model or data.get("model") or ""
    worker = worker_model or selected
    for value in (selected, worker):
        if not isinstance(value, str) or "/" not in value or any(c.isspace() for c in value):
            raise ValueError("model must be a provider/model identifier")
        provider, name = value.split("/", 1)
        if not name or provider not in data.get("provider", {}):
            raise ValueError("selected model provider is not configured")
        models = data["provider"][provider].get("models", {})
        if models and name not in models:
            raise ValueError("selected model is not present in the provider configuration")
    return {
        "planner": selected,
        "worker": worker,
        "worker_selection": "explicit" if worker_model else "same_as_planner",
        "credentials": "provider runtime only; never stored in benchmark artifacts",
    }


def prepare_native_runtime(directory, models, provider_config=None, *, root, runtime_file, sha256):
    """Stage a read-only legacy native runtime snapshot."""
    directory = Path(directory)
    runtime = directory / "runtime"
    runtime.mkdir()
    legacy = root / "legacy/opencode"
    client_config = root / "opencode.json"
    if not client_config.is_file():
        client_config = legacy / "opencode.json"
    source = json.loads(Path(provider_config or client_config).read_text())
    files = []
    candidates = [root / name for name in ("pyproject.toml", "AGENTS.md", "CLAUDE.md")]
    for name in (
        "scripts",
        "mcp-servers",
        "config",
        "rules",
        ".claude/skills",
        ".opencode/agents",
        ".opencode/plugins",
    ):
        candidates.extend((root / name).rglob("*"))
    for name in ("agents", "plugins"):
        candidates.extend((legacy / "client" / name).rglob("*"))
    for path in sorted(candidates):
        relative = path.relative_to(root)
        if relative.parts[:3] == ("legacy", "opencode", "client"):
            relative = Path(".opencode", *relative.parts[3:])
        if path.is_symlink() or not path.is_file() or not runtime_file(relative):
            continue
        if any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents):
            raise ValueError("runtime source contains a symlinked parent")
        target = runtime / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        files.append({"path": relative.as_posix(), "source_sha256": sha256(path), "sha256": sha256(target)})
    providers = {}
    for value in (models["planner"], models["worker"]):
        provider, model = value.split("/", 1)
        original = source["provider"][provider]
        if provider not in providers:
            providers[provider] = {key: original[key] for key in ("npm", "name") if key in original}
            options = original.get("options", {})
            providers[provider]["options"] = {"apiKey": "{env:CCO_BENCHMARK_API_KEY}"}
            if "baseURL" in options:
                providers[provider]["options"]["baseURL"] = options["baseURL"]
            providers[provider]["models"] = {}
        if model in original.get("models", {}):
            providers[provider]["models"][model] = original["models"][model]
    generated = {
        "$schema": "https://opencode.ai/config.json",
        "model": models["planner"],
        "default_agent": "kalibounty",
        "provider": providers,
        "agent": {
            "kalibounty": {"model": models["planner"]},
            "worker": {"model": models["worker"]},
        },
        "instructions": ["CLAUDE.md", "rules/scope-guard.md", "rules/safety-rules.md"],
        "plugin": ["./.opencode/plugins/security-gate.js"],
        "permission": {
            "*": "deny",
            "read": "allow",
            "skill": "allow",
            "todowrite": "allow",
            "task": {"*": "deny", "worker": "allow"},
        },
        "mcp": {},
    }
    generated_files = {
        "opencode.json": generated,
        ".codex/scope.json": {"in_scope": [], "allow_loopback": False, "allow_osint": False, "allow_public_labs": False},
        ".codex/program-policy.json": {"denied_tools": ["*"]},
    }
    for name, data in generated_files.items():
        path = runtime / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n")
        files.append({"path": name, "sha256": sha256(path), "generated": True})
    index = {
        "schema": "full-agent-runtime-snapshot/1",
        "runnable": False,
        "models": models,
        "files": sorted(files, key=lambda item: item["path"]),
    }
    index_path = directory / "runtime-index.json"
    index_path.write_text(json.dumps(index, indent=2) + "\n")
    for path in runtime.rglob("*"):
        path.chmod(0o555 if path.is_dir() else 0o444)
    runtime.chmod(0o555)
    return {
        "path": str(runtime),
        "index": str(index_path),
        "index_sha256": sha256(index_path),
        "files": len(files),
        "runnable": False,
    }


def native_provider_settings(data, models):
    """Extract legacy OpenCode provider routing without credentials."""
    providers = {models[key].split("/", 1)[0] for key in ("planner", "worker")}
    if len(providers) != 1:
        raise ValueError("the native broker requires planner and worker on one provider")
    name = providers.pop()
    source = data["provider"][name]
    if source.get("npm") not in {"@ai-sdk/openai-compatible", "@ai-sdk/openai"}:
        raise ValueError("the native broker requires an OpenAI-compatible provider")
    endpoint = source.get("options", {}).get("baseURL", "")
    url = urlsplit(endpoint)
    if (
        not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.scheme not in {"http", "https"}
        or (url.scheme != "https" and url.hostname not in {"127.0.0.1", "::1", "localhost"})
    ):
        raise ValueError("provider baseURL must use HTTPS or owned loopback, without URL credentials")
    selected = {models[key].split("/", 1)[1] for key in ("planner", "worker")}
    if source.get("models") and not selected <= source["models"].keys():
        raise ValueError("a frozen model is no longer configured")
    header = source.get("options", {}).get("apiKeyHeader", "Authorization")
    if header not in {"Authorization", "X-API-Key"}:
        raise ValueError("provider apiKeyHeader must be Authorization or X-API-Key")
    return {"name": name, "url": endpoint.rstrip("/"), "models": selected, "api_key_header": header}


def stage_native_runtime(prepared, directory, base, *, root, lab_policy, sha256, max_seconds):
    """Copy the frozen legacy bundle, then replace launcher-owned configuration."""
    runtime = Path(directory) / "runtime"
    shutil.copytree(prepared["runtime"], runtime)
    for path in [runtime, *runtime.rglob("*")]:
        path.chmod(0o700 if path.is_dir() else 0o600)
    models = prepared["contract"]["models"]
    external_paths = {
        str(Path(directory).resolve() / "solver") + "/*": "allow",
        str(Path(directory).resolve() / "private/state/validations") + "/*": "allow",
        "/tmp/cco-trust/*": "allow",
    }
    source = json.loads((runtime / "opencode.json").read_text())
    provider_ids = {models[key].split("/", 1)[0] for key in ("planner", "worker")}
    if len(provider_ids) != 1:
        raise ValueError("the native broker requires one provider")
    name = provider_ids.pop()
    model_rows = {}
    for key in ("planner", "worker"):
        model = models[key].split("/", 1)[1]
        original = source["provider"][name].get("models", {}).get(model, {})
        model_rows[model] = {field: original[field] for field in ("name", "limit", "cost") if field in original}
        limits = model_rows[model].get("limit", {})
        model_rows[model]["limit"] = {
            "context": min(limits.get("context", 32768), 32768),
            "output": min(limits.get("output", 4096), 4096),
        }
    source.update(
        {
            "model": models["planner"],
            "small_model": models["planner"],
            "enabled_providers": [name],
            "autoupdate": False,
            "share": "disabled",
            "instructions": [],
            "compaction": {"auto": True, "keep": {"tokens": 8192}, "buffer": 8192},
            "agent": {
                "kalibounty": {
                    "model": models["planner"],
                    "tools": {"*": False, "task": True, "read": True},
                    "permission": {"external_directory": external_paths, "task": {"*": "deny", "worker": "allow"}},
                },
                "worker": {
                    "model": models["worker"],
                    "tools": {
                        "*": False,
                        **{tool: True for tool in ("read", "write", "edit", "bash")},
                        **{group + "_" + tool: True for group, names in CATALOG.items() for tool in names},
                    },
                    "permission": {"external_directory": external_paths},
                },
            },
            "provider": {
                name: {
                    "npm": "@ai-sdk/openai-compatible",
                    "models": model_rows,
                    "options": {"baseURL": BRIDGE_URL + "/v1", "apiKey": "broker-only"},
                }
            },
            "mcp": {
                group: {
                    "type": "remote",
                    "url": BRIDGE_URL + "/mcp/" + group,
                    "oauth": False,
                    "timeout": max_seconds * 1000,
                }
                for group in CATALOG
            },
            "permission": {
                "*": "deny",
                **{tool: "allow" for tool in LOCAL_TOOLS if tool != "task"},
                **{group + "_" + tool: "allow" for group, names in CATALOG.items() for tool in names},
                "external_directory": external_paths,
                "task": {"*": "deny", "worker": "allow"},
            },
        }
    )
    dump(runtime / "opencode.json", source)
    (runtime / "AGENTS.md").write_text(NATIVE_POLICY)
    scope, policy = lab_policy(base)
    dump(runtime / ".codex/scope.json", scope)
    dump(runtime / ".codex/program-policy.json", policy)
    dump(
        runtime / ".codex/broker-catalog.json",
        sorted(group + "_" + tool for group, names in CATALOG.items() for tool in names),
    )
    for src, dst in (
        ("full_agent_bridge.py", "scripts/full_agent_bridge.py"),
        ("full_agent_gate.js", ".opencode/plugins/security-gate.js"),
    ):
        target = runtime / dst
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((root / "scripts" / src).read_bytes())
    for agent, model_key in (("kalibounty", "planner"), ("worker", "worker")):
        path = runtime / ".opencode/agents" / (agent + ".md")
        if not path.is_file():
            raise ValueError("native agent definition missing: " + agent)
        front, sep, _rest = path.read_text().removeprefix("---\n").partition("\n---\n")
        if not sep:
            raise ValueError("invalid native agent definition: " + agent)
        front = re.sub(r"(?m)^model:.*$", "model: " + models[model_key], front)
        path.write_text("---\n" + front + sep + (NATIVE_PLANNER if agent == "kalibounty" else NATIVE_WORKER))
    for config_dir in (runtime / ".opencode", runtime / ".native-config/opencode"):
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / ".gitignore").write_text(
            "node_modules\npackage.json\npackage-lock.json\nbun.lock\n.gitignore\n"
        )
    files = [
        {"path": path.relative_to(runtime).as_posix(), "sha256": sha256(path)}
        for path in sorted(runtime.rglob("*"))
        if path.is_file()
    ]
    index = Path(directory) / "runtime-index.json"
    dump(
        index,
        {
            "schema": "full-agent-runtime-snapshot/1",
            "runnable": True,
            "models": models,
            "source_index_sha256": prepared["manifest"]["runtime_snapshot"]["index_sha256"],
            "files": files,
        },
    )
    for path in [*runtime.rglob("*"), runtime]:
        path.chmod(0o555 if path.is_dir() else 0o444)
    return runtime, index


def solver_prompt(base, workdir, bindings, limits, *, bootstrap_plan):
    specs = bootstrap_plan(base, workdir)
    task = {"description": "Run " + specs[0].id, "subagent_type": "worker", "prompt": "TaskSpec: " + specs[0].id}
    return (
        f"Run the native planner/worker workflow for this explicitly approved, test-owned lab: {base}\n"
        f"Scope: exactly {base}; read-only HTTP methods. Follow the mounted scope and policy.\n"
        f"Workdir and all evidence: {workdir}. Synthetic session references: {json.dumps(bindings)}\n"
        f"Shared limits, including setup and all workers: {limits['http_requests_per_seed']} HTTP requests, "
        f"{limits['llm_tokens_per_seed']} LLM tokens, {limits['seconds_per_seed']} seconds.\n"
        "BOUNDED BOOTSTRAP: this is a fresh test lab. There is no prior .cco/session-vault.json, "
        "program vault, historical policy or previous session to recover in the solver. "
        "Scope and policy are already mounted and host sessions are already initialized. "
        "Do not use bash, glob, grep, list or exploratory filesystem reads to locate missing state. "
        "Do not reconstruct setup or read repository instructions before delegating. "
        "Step 1: immediately call the task tool with the following prepared arguments; "
        "your first tool call MUST be this worker dispatch, with zero planner bootstrap tool calls:\n"
        + json.dumps(task)
        + "\n"
        "After the worker returns, review its concise summary and delegate the next bounded phase. "
        "Task order: " + ", ".join(spec.id for spec in specs) + ". "
        "Every task prompt must be only 'TaskSpec: <id>'; the host supplies Commands, Tools and session references. "
        "The complete plan is already at " + str(Path(workdir) / "specs.json") + ". "
        "Never write or re-render a worker task yourself. "
        "Use brain.py plans and rendered TaskSpecs, delegate execution to worker with exact Tools: lines, "
        "and use the metered MCP tools. Target networking is available only through MCP. "
        "Session secrets stay only in the host vault; refresh supplied references through "
        "validator_session_vault_check via the worker. If a reference or helper fails, report the exact "
        "block once and preserve NOT TESTED work; do not search directories or repeat a blocked shape. "
        "Require deterministic validation and signed current coverage. Ask kali-tools_ledger_checkpoint "
        "to seal closure only after the normal gates pass. Preserve blocked and NOT TESTED work. "
        "Do not infer acceptance from your final message."
    )


def launch_command(
    *,
    workdir,
    runtime,
    socket_path,
    public_trust,
    validations,
    nonce,
    prompt,
    bwrap,
    opencode,
    root,
    host_policy_file,
    isolation_command,
    sha256,
):
    workdir, runtime = Path(workdir).resolve(strict=True), Path(runtime).resolve(strict=True)
    public_trust, validations = Path(public_trust).resolve(strict=True), Path(validations).resolve(strict=True)
    if (
        workdir.name != "solver"
        or runtime.name != "runtime"
        or workdir.parent != runtime.parent
        or runtime == root
        or root in runtime.parents
        or validations != runtime.parent / "private/state/validations"
        or public_trust != validations.parent / "public-trust"
    ):
        raise ValueError("native mounts must belong to one fresh run outside the repository")
    command = [
        "python3",
        "-I",
        str(runtime / "scripts/full_agent_bridge.py"),
        "/opt/opencode",
        "run",
        "--format",
        "json",
        "--agent",
        "kalibounty",
        prompt,
    ]
    args = isolation_command(workdir, command, bwrap=bwrap, opencode=opencode, workspace=str(workdir))
    args[args.index("--chdir") + 1] = str(runtime)
    cut = args.index("--")
    additions = [
        "--unshare-net",
        "--ro-bind",
        str(runtime),
        str(runtime),
        "--ro-bind",
        str(socket_path),
        "/bridge/host.sock",
        "--ro-bind",
        str(public_trust),
        "/tmp/cco-trust",
        "--ro-bind",
        str(validations),
        str(validations),
    ]
    environment = {
        "HOME": "/home/solver",
        "XDG_CONFIG_HOME": str(runtime / ".native-config"),
        "XDG_DATA_HOME": "/home/solver/data",
        "XDG_CACHE_HOME": "/home/solver/cache",
        "XDG_STATE_HOME": "/home/solver/state",
        "CCO_HOME": "/home/solver/cco",
        "CCO_WORKDIR": str(workdir),
        "CCO_SCOPE_FILE": str(runtime / ".codex/scope.json"),
        "CCO_TOOL_PROFILE": "broker",
        "CCO_PROGRAM_POLICY_FILE": str(runtime / ".codex/program-policy.json"),
        "CCO_VALIDATION_ROOTS": str(validations),
        "CCO_BLIND_MODE": "1",
        "CCO_BASH_SANDBOXED": "1",
        "CCO_NATIVE_NONCE": nonce,
        "OPENCODE_DISABLE_AUTOUPDATE": "true",
        "OPENCODE_DISABLE_MODELS_FETCH": "true",
        "OPENCODE_DISABLE_DEFAULT_PLUGINS": "true",
        "OPENCODE_PRINT_LOGS": "1",
        "OPENCODE_LOG_LEVEL": "INFO",
    }
    effective_policy = host_policy_file(validations.parent, runtime)
    if effective_policy != runtime / ".codex/program-policy.json":
        environment["CCO_POLICY_HASH"] = "sha256:" + sha256(effective_policy)
    for name, value in environment.items():
        additions += ["--setenv", name, value]
    return args[:cut] + additions + args[cut:]


def supervise(command, broker, private, *, popen, startup_seconds=15):
    """Bound the native process tree and retain raw events even on interruption."""
    from campaign_worker import LocalMCPExecutor

    process = None
    status = "launch_failed"
    started = time.monotonic()
    try:
        with (Path(private) / "native-events.jsonl").open("wb") as stdout, (
            Path(private) / "native-stderr.log"
        ).open("wb") as stderr:
            process = popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
                start_new_session=True,
            )
            while process.poll() is None:
                if broker.budget.snapshot()["blocked"]:
                    status = "budget_invalid"
                    break
                if broker.stop_reason:
                    status = broker.stop_reason
                    break
                if not broker.budget.remaining_seconds():
                    status = "time_budget_exhausted"
                    break
                if not broker.ready and time.monotonic() - started >= startup_seconds:
                    status = "environment_unavailable"
                    break
                try:
                    process.wait(timeout=min(0.2, broker.budget.remaining_seconds()))
                except subprocess.TimeoutExpired:
                    pass
            else:
                status = (
                    "native_finished_unverified"
                    if process.returncode == 0 and broker.ready
                    else "native_failed"
                    if broker.ready
                    else "environment_unavailable"
                )
    except KeyboardInterrupt:
        status = "interrupted"
    except OSError:
        status = "environment_unavailable"
    finally:
        broker.close()
        if process is not None:
            LocalMCPExecutor._kill_process_group(process)
            process.wait(timeout=5)
    if status in {"native_finished_unverified", "native_failed"}:
        if broker.budget.snapshot()["blocked"]:
            status = "budget_invalid"
        elif not broker.budget.remaining_seconds():
            status = "time_budget_exhausted"
        elif broker.stop_reason:
            status = broker.stop_reason
    broker.finalize_task(status)
    return {
        "status": status,
        "exit_code": process.returncode if process else None,
        "wall_clock_seconds": time.monotonic() - started,
    }


def run_native_session(
    broker,
    workdir,
    runtime,
    trust,
    validations,
    base,
    bindings,
    limits,
    private,
    bwrap,
    opencode,
    *,
    make_server_fn,
    launch_command_fn,
    solver_prompt_fn,
    supervise_fn,
):
    server = server_thread = None
    try:
        with tempfile.TemporaryDirectory(prefix="cco-native-socket-") as sockets:
            socket_path = Path(sockets) / "host.sock"
            server = make_server_fn(socket_path, broker)
            socket_path.chmod(0o600)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            prompt_text = solver_prompt_fn(base, workdir, bindings, limits)
            if hasattr(broker, "planner_prompt"):
                broker.planner_prompt = prompt_text
            command = launch_command_fn(
                workdir=workdir,
                runtime=runtime,
                socket_path=socket_path,
                public_trust=trust["public_dir"],
                validations=validations,
                nonce=broker.nonce,
                prompt=prompt_text,
                bwrap=bwrap,
                opencode=opencode,
            )
            return supervise_fn(command, broker, private)
    finally:
        if server_thread is not None:
            server.shutdown()
            server_thread.join(timeout=5)
        if server is not None:
            server.server_close()
