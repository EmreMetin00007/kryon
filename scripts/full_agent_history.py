"""Bound worker history using exact workspace archives, without altering execution."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from full_agent_budget import provider_json
from full_agent_context import content_snapshot, verified_file


def bounded_history(body, tasks, *, max_bytes, recent_turns=2, compact=False):
    messages = body.get("messages")
    spec = tasks.active_spec
    if not isinstance(messages, list) or len(provider_json(messages)) <= max_bytes:
        return body, None
    if not isinstance(tasks.active_prompt, str):
        return body, None
    # Only complete, contiguous assistant/tool turns are retired. Keep every
    # system/user instruction and every unresolved/ambiguous call verbatim.
    contract = verified_file(tasks.workdir, str(Path(spec.evidence_dir) / 'task-context.txt'),
                             tasks.active_prompt.encode())
    if contract is None:
        return body, None
    ids = [call.get("id") for msg in messages for call in msg.get("tool_calls", [])]
    result_ids = [msg.get("tool_call_id") for msg in messages if msg.get("role") == "tool"]
    turns = []
    for start, msg in enumerate(messages):
        calls = msg.get("tool_calls", [])
        if msg.get("role") != "assistant" or not calls:
            continue
        expected = [call.get("id") for call in calls]
        end = start + len(calls) + 1
        returned = messages[start + 1:end]
        if (len(returned) != len(calls) or not all(isinstance(i, str) for i in expected)
                or any(ids.count(i) != 1 or result_ids.count(i) != 1 for i in expected)
                or any(row.get("role") != "tool" for row in returned)
                or set(expected) != {row.get("tool_call_id") for row in returned}):
            continue
        turns.append((start, end))
    eligible = turns[:-recent_turns] if recent_turns else turns
    if not eligible:
        return body, None
    view = copy.deepcopy(body)
    removed: set[int] = set()
    archives: list[Any] = []
    for start, end in eligible:
        raw = provider_json(messages[start:end])
        artifact = content_snapshot(tasks, spec, "native-history", raw)
        if artifact is None:
            continue
        calls = messages[start].get("tool_calls", [])
        outcomes = {row['tool_call_id']: row.get('content') for row in messages[start + 1:end]}
        index = []
        for call in calls:
            try:
                args = json.loads(call['function']['arguments'])
            except (KeyError, ValueError, TypeError):
                args = {}
            locator = {key: args[key] for key in ('filePath', 'url', 'target', 'method', 'vector')
                       if isinstance(args, dict) and key in args}
            outcome = outcomes[call['id']]
            # Error/decision excerpts are context only; the full unmodified
            # result is available by archive hash and never grants coverage.
            excerpt_limit = 64 if compact else 512
            excerpt = outcome[:excerpt_limit] if isinstance(outcome, str) else None
            entry = {'id': call['id'], 'tool': call['function']['name'], 'result_excerpt': excerpt,
                     'excerpt_truncated': isinstance(outcome, str) and len(outcome) > excerpt_limit}
            if not compact:
                entry.update(arguments_locator=locator)
            index.append(entry)
        replacement = {'role': 'user', 'content': 'Host historical context (not execution authority): '
                       + provider_json({'content_ref': artifact, 'calls': index,
                            'action': 'These calls already completed. Read the exact archive for omitted '
                                      'arguments/results; do not repeat probes or infer missing coverage.'}).decode()}
        if len(provider_json(replacement)) >= len(raw):
            continue
        view['messages'][start] = replacement
        removed.update(range(start + 1, end))
        archives.append(artifact)
    view['messages'] = [msg for i, msg in enumerate(view['messages']) if i not in removed]
    if not archives:
        return body, None
    return view, {'schema': 'bounded-worker-history/1', 'archives': archives,
                  'recent_turns_kept': recent_turns, 'messages_bytes_before': len(provider_json(messages)),
                  'messages_bytes_after': len(provider_json(view['messages'])),
                  'saved_bytes': len(provider_json(messages)) - len(provider_json(view['messages']))}
