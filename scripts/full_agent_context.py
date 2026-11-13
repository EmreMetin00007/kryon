"""Artifact-backed provider views; native execution/history stay intact."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat

from full_agent_budget import compact_json_text, provider_json

MAX_WRITE_BYTES = 128 * 1024


def result_view(tasks, spec, emitted):
    """Keep decisions/signatures; reference large inventory fields losslessly.

    Original JSON remains readable under Workdir and in the host tool receipt.
    Omitted fields are explicit, never presented as empty or tested coverage.
    """
    raw = emitted.encode()
    if len(raw) <= 4096 or len(raw) > MAX_WRITE_BYTES:
        return None
    try:
        parsed = json.loads(emitted)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict) or 'content_ref' in parsed or 'omitted_fields' in parsed:
        return None
    protected = {'validations', 'confirmed', 'errors', 'skipped', 'stop_reason', 'verdict', 'signature'}
    omitted = [key for key, value in parsed.items()
               if key not in protected and len(provider_json(value)) > 4096]
    if not omitted:
        return None
    path = Path(spec.evidence_dir) / ('tool-result-' + hashlib.sha256(raw).hexdigest() + '.json')
    try:
        path.relative_to(tasks.workdir)
        if path.parent.resolve() != path.parent or not path.parent.is_dir():
            return None
        if not path.exists():
            with path.open('xb') as handle:
                handle.write(raw)
    except (OSError, ValueError):
        return None
    artifact = verified_file(tasks.workdir, str(path), raw)
    if artifact is None:
        return None
    preview = {key: value for key, value in parsed.items() if key not in omitted}
    preview.update(content_ref=artifact, omitted_fields=omitted)
    projected = provider_json(preview).decode()
    return (projected, artifact) if len(projected.encode()) < len(raw) else None


def workspace_artifact(workdir, name):
    """Read a bounded regular workspace artifact without following symlinks."""
    path = Path(name)
    if not path.is_absolute():
        path = workdir / path
    # Check lexical parents before resolution; resolving would hide symlinks.
    if '..' in path.parts or workdir not in path.parents:
        return None
    relative = path.relative_to(workdir)
    if any(part.startswith('.env') or part in {'.cco', '.ssh', '.aws', '.gnupg', '.kube', '.docker'}
           for part in relative.parts) or path.suffix in {'.pem', '.key', '.p12', '.pfx', '.db'}:
        return None
    if any(item.is_symlink() for item in (path, *path.parents)):
        return None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return None
            raw = handle.read(MAX_WRITE_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_WRITE_BYTES:
        return None
    return raw, {'path': relative.as_posix(), 'bytes': len(raw),
                 'sha256': hashlib.sha256(raw).hexdigest()}


def verified_file(workdir, name, expected):
    """Require current file bytes to match a known write/contract exactly."""
    artifact = workspace_artifact(workdir, name)
    return artifact[1] if artifact is not None and artifact[0] == expected else None


def content_snapshot(tasks, spec, label, raw):
    """Store exact historical bytes in a bounded, immutable workspace reference."""
    if len(raw) > MAX_WRITE_BYTES:
        return None
    folder = Path(spec.evidence_dir)
    if tasks.workdir not in folder.parents or folder.resolve() != folder or not folder.is_dir():
        return None
    path = folder / (label + '-' + hashlib.sha256(raw).hexdigest() + '.txt')
    try:
        if not path.exists():
            with path.open('xb') as handle:
                handle.write(raw)
    except OSError:
        return None
    return verified_file(tasks.workdir, str(path), raw)


def summary_feedback(tasks, handoffs=None):
    """Explain invalid terminal bytes/protocol; never repair or admit a phase."""
    from orchestration_spec import validate_summary
    spec = tasks.active_spec
    artifact = workspace_artifact(tasks.workdir, f'summaries/{spec.id}.json')
    if artifact is None:
        return None
    try:
        summary = json.loads(artifact[0])
    except (ValueError, TypeError):
        summary = None
    if isinstance(summary, dict) and summary.get('status') in {'in-progress', 'blocked', 'failed'}:
        return None
    errors = validate_summary(summary) if summary is not None else ['summary must contain valid JSON']
    if isinstance(summary, dict) and (summary.get('phase') != spec.phase or summary.get('target') != spec.target):
        errors.append('summary phase/target must match the current TaskSpec')
    if not errors:
        if spec.phase == 'enum' and 'kali-tools_ledger_prepare_handoff' in getattr(spec, 'tools', ()):
            label = getattr(spec, 'vector', '') or 'access'
            record = (handoffs or {}).get(label, {})
            ready = (record.get('producer_spec_id') == spec.id and record.get('target') == spec.target
                     and record.get('summary_sha256') == artifact[1]['sha256'])
            if not ready:
                return {'schema': 'host-summary-feedback/1', 'summary': artifact[1], 'valid': True,
                        'handoff_ready': False, 'errors': ['current host handoff receipt is missing'],
                        'action': 'Call kali-tools_ledger_prepare_handoff with Target/Workdir/Summary path, '
                        f'vector={label}, supplied synthetic session refs and verified own IDs or []. '
                        'Do not rewrite the valid summary or invent handoff files.'}
        return None
    return {'schema': 'host-summary-feedback/1', 'summary': artifact[1], 'valid': False,
            'errors': errors, 'action': 'Rewrite this summary with write (filePath and content). '
            'Embed required fields from observed evidence only; do not repeat completed probes. '
            'The next phase is not admitted until the summary validates.'}


def native_json_read_view(tasks, spec, call, result):
    """Compact only a full, exact native JSON read of current workspace bytes.

    Values, including validators and signatures, remain unchanged. Partial,
    truncated, malformed and unknown native formats fail closed.
    """
    try:
        args = json.loads(call['function']['arguments'])
        if (not isinstance(args, dict) or set(args) - {'filePath', 'offset', 'limit'}
                or not isinstance(args.get('filePath'), str)):
            return None
        artifact = workspace_artifact(tasks.workdir, args['filePath'])
        if artifact is None:
            return None
        source = artifact[0].decode('utf-8')
        if not isinstance(json.loads(source), (dict, list)):
            return None
    except (ValueError, TypeError, KeyError, UnicodeError):
        return None
    lines = source.splitlines()
    prefix = f'<path>{args["filePath"]}</path>\n<type>file</type>\n<content>\n'
    numbered = '\n'.join(f'{index}: {line}' for index, line in enumerate(lines, 1))
    expected = prefix + numbered + f'\n\n(End of file - total {len(lines)} lines)\n</content>'
    emitted = result.get('content')
    if emitted != expected:
        return None
    compact = compact_json_text(source)
    if len(compact.encode()) + 512 >= len(expected.encode()):
        return None
    snapshot = content_snapshot(tasks, spec, 'native-read', expected.encode())
    if snapshot is None:
        return None
    projected = (prefix + '1: ' + compact + '\n\n[Host JSON context view; original numbered read: '
                 + provider_json(snapshot).decode() + '; projected line numbers]\n</content>')
    return (projected, snapshot) if len(projected.encode()) < len(expected.encode()) else None


def terminal_summary(tasks, spec):
    """A context receipt cannot turn an invalid/wrong-target draft terminal."""
    from orchestration_spec import validate_summary
    artifact = workspace_artifact(tasks.workdir, f'summaries/{spec.id}.json')
    if artifact is None:
        return None
    try:
        summary = json.loads(artifact[0])
    except (ValueError, TypeError):
        return None
    if (not isinstance(summary, dict) or summary.get('phase') != spec.phase
            or summary.get('target') != spec.target or validate_summary(summary)):
        return None
    return summary, artifact[1]


def planner_followup_context(body, tasks, private, completed_tasks):
    """Shorten only exact, completed native delegations with host receipts.

    The raw tool result, system/user text and native history stay intact.
    References are the same TaskSpec pointers accepted by the admission gate.
    This view never grants next-phase execution or security confirmation.
    """
    messages = body.get('messages')
    if not isinstance(messages, list) or not completed_tasks:
        return body, None
    receipts = []
    for record in completed_tasks:
        path = Path(record['artifact'])
        if path.parent != Path(private) or path.is_symlink():
            continue
        try:
            with path.open('rb') as handle:
                raw = handle.read(MAX_WRITE_BYTES + 1)
            if len(raw) > MAX_WRITE_BYTES or hashlib.sha256(raw).hexdigest() != record['sha256']:
                continue
            receipt = json.loads(raw)
            if not isinstance(receipt, dict) or receipt.get('schema') != 'native-task-completion/1':
                continue
            spec = next(s for s in tasks.specs if s.id == receipt['spec_id'])
            summary = terminal_summary(tasks, spec)
            if summary is None or summary[1] != receipt['summary']:
                continue
            if verified_file(tasks.workdir, receipt['contract']['path'],
                             receipt['args']['prompt'].encode()) != receipt['contract']:
                continue
        except (OSError, ValueError, TypeError, KeyError, StopIteration):
            continue
        receipts.append((receipt, record))
    ids = [call.get('id') for msg in messages for call in msg.get('tool_calls', [])]
    view = copy.deepcopy(body)
    records = []
    for index, msg in enumerate(messages):
        if msg.get('role') != 'assistant':
            continue
        for call_index, call in enumerate(msg.get('tool_calls', [])):
            ident, function = call.get('id'), call.get('function', {})
            if function.get('name') != 'task' or not isinstance(ident, str) or ids.count(ident) != 1:
                continue
            results = [(i, r) for i, r in enumerate(messages)
                       if r.get('role') == 'tool' and r.get('tool_call_id') == ident]
            if len(results) != 1 or results[0][0] <= index:
                continue
            try:
                args = json.loads(function['arguments'])
            except (ValueError, TypeError, KeyError):
                continue
            matched = [(receipt, record) for receipt, record in receipts
                       if receipt['call_id'] == ident and receipt['args'] == args
                       and receipt['output'] == results[0][1].get('content')]
            if len(matched) != 1:
                continue
            receipt, record = matched[0]
            pointer = {'description': 'Run ' + receipt['spec_id'], 'subagent_type': 'worker',
                       'prompt': 'TaskSpec: ' + receipt['spec_id']}
            projected = provider_json(pointer).decode()
            if len(projected.encode()) >= len(function['arguments'].encode()):
                continue
            view['messages'][index]['tool_calls'][call_index]['function']['arguments'] = projected
            records.append({'tool_call_id': ident, 'spec_id': receipt['spec_id'],
                            'summary': receipt['summary'], 'contract': receipt['contract'],
                            'receipt': record['artifact'], 'receipt_sha256': record['sha256']})
    if not records:
        return body, None
    before, after = len(provider_json(messages)), len(provider_json(view['messages']))
    return view, {'schema': 'planner-context-view/1', 'messages_bytes_before': before,
                  'messages_bytes_after': after, 'saved_bytes': before - after, 'tasks': records}


def worker_followup_context(body, tasks, private, tool_receipts=(), handoffs=None):
    """Project only successful, byte-verified writes and the exact host prompt.

    Unknown/failed/stale history stays unchanged. Full original write messages
    and results are archived host-side; the solver can read the actual files.
    Historical content_ref fields describe omitted bytes, never new tool args.
    """
    prompt = tasks.active_prompt
    if not isinstance(prompt, str):
        return body, None
    spec = tasks.active_spec
    context_path = Path(spec.evidence_dir) / 'task-context.txt'
    contract = verified_file(tasks.workdir, str(context_path), prompt.encode())
    if contract is None:
        return body, None
    messages = body.get('messages')
    if not isinstance(messages, list):
        return body, None
    # A duplicate/missing ID must never bind a write to an unrelated result.
    results = {}
    ids = []
    for index, msg in enumerate(messages):
        if msg.get('role') == 'tool':
            ident = msg.get('tool_call_id')
            results.setdefault(ident, []).append((index, msg))
        ids.extend(call.get('id') for call in msg.get('tool_calls', []))
    view = copy.deepcopy(body)
    records = []
    anchors = []
    result_views = []
    read_views = []
    # A retired write is eligible only if its earlier exact receipt exists
    # AND a later successful native write verifies the current file bytes.
    current_writes = {}
    for index, msg in enumerate(messages):
        if msg.get('role') != 'assistant':
            continue
        for call in msg.get('tool_calls', []):
            returned = results.get(call.get('id'), [])
            if (call.get('function', {}).get('name') != 'write' or ids.count(call.get('id')) != 1
                    or len(returned) != 1 or returned[0][0] <= index
                    or returned[0][1].get('content') != 'Wrote file successfully.'):
                continue
            try:
                args = json.loads(call['function']['arguments'])
                if (not isinstance(args, dict) or set(args) != {'filePath', 'content'}
                        or not isinstance(args['filePath'], str) or not isinstance(args['content'], str)):
                    continue
                if verified_file(tasks.workdir, args['filePath'], args['content'].encode()) is not None:
                    current_writes.setdefault(args['filePath'], []).append(index)
            except (ValueError, TypeError, KeyError):
                continue
    for row in tool_receipts:
        if row.get('task_spec_id') != spec.id or row.get('origin') != 'solver':
            continue
        try:
            receipt_path = Path(row['artifact'])
            if receipt_path.parent != Path(private) or receipt_path.is_symlink():
                continue
            with receipt_path.open('rb') as handle:
                raw_receipt = handle.read(MAX_WRITE_BYTES + 1)
            if len(raw_receipt) > MAX_WRITE_BYTES:
                continue
            receipt = json.loads(raw_receipt)
            execution = receipt['execution']
            raw = execution['result']['output']
            emitted = compact_json_text(raw) if isinstance(raw, str) else provider_json(raw).decode()
        except (OSError, ValueError, TypeError, KeyError):
            continue
        if execution.get('execution_failed') or receipt.get('error'):
            continue
        for index, msg in enumerate(messages):
            for call in msg.get('tool_calls', []):
                ident = call.get('id')
                returned = results.get(ident, [])
                try:
                    arguments_match = json.loads(call['function']['arguments']) == receipt['arguments']
                except (ValueError, TypeError, KeyError):
                    continue
                if (msg.get('role') == 'assistant' and isinstance(ident, str)
                        and call.get('function', {}).get('name') == row['tool'] and ids.count(ident) == 1
                        and len(returned) == 1 and returned[0][0] > index
                        and returned[0][1].get('content') == emitted
                        and arguments_match):
                    anchors.append({'tool_call_id': ident, 'receipt': str(receipt_path),
                                    'receipt_sha256': hashlib.sha256(raw_receipt).hexdigest()})
                    projection = result_view(tasks, spec, emitted)
                    if projection is not None:
                        view['messages'][returned[0][0]]['content'] = projection[0]
                        result_views.append({'tool_call_id': ident, 'artifact': projection[1]})
                    # Handoff freshness/summary/pool hashes were checked and
                    # recorded by the host, before this provider continuation.
                    trusted = any(h.get('producer_spec_id') == spec.id
                                  and h.get('producer_artifact') == str(receipt_path)
                                  and h.get('producer_artifact_sha256') == hashlib.sha256(raw_receipt).hexdigest()
                                  for h in (handoffs or {}).values())
                    if row['tool'] == 'kali-tools_ledger_prepare_handoff' and trusted:
                        parsed = json.loads(emitted)
                        if isinstance(parsed, dict) and parsed.get('ok') is True:
                            result_bytes = emitted.encode()
                            result_hash = hashlib.sha256(result_bytes).hexdigest()
                            result_path = Path(spec.evidence_dir) / ('tool-result-' + result_hash + '.json')
                            if not result_path.exists():
                                with result_path.open('xb') as handle:
                                    handle.write(result_bytes)
                            artifact = verified_file(tasks.workdir, str(result_path), result_bytes)
                            if artifact is not None:
                                paths = {label: Path(name).relative_to(tasks.workdir).as_posix()
                                         for label, name in parsed.get('handoffs', {}).items()}
                                content = provider_json({'ok': True, 'handoffs': paths,
                                    'pool': Path(parsed['pool']).relative_to(tasks.workdir).as_posix(),
                                    'content_ref': artifact}).decode()
                                if len(content.encode()) < len(result_bytes):
                                    view['messages'][returned[0][0]]['content'] = content
                                    result_views.append({'tool_call_id': ident, 'artifact': artifact})
    for index, msg in enumerate(messages):
        if msg.get('role') != 'assistant':
            continue
        for call_index, call in enumerate(msg.get('tool_calls', [])):
            function = call.get('function', {})
            ident = call.get('id')
            returned = results.get(ident, [])
            if (function.get('name') != 'write' or not isinstance(ident, str)
                    or ids.count(ident) != 1 or len(returned) != 1
                    or returned[0][0] <= index or returned[0][1].get('content') != 'Wrote file successfully.'):
                continue
            try:
                args = json.loads(function['arguments'])
                if not isinstance(args, dict) or set(args) != {'filePath', 'content'}:
                    continue
                if not isinstance(args['content'], str) or not isinstance(args['filePath'], str):
                    continue
                expected = args['content'].encode()
            except (ValueError, TypeError, KeyError):
                continue
            if len(expected) > MAX_WRITE_BYTES:
                continue
            artifact = verified_file(tasks.workdir, args['filePath'], expected)
            archive = provider_json({'assistant': msg, 'result': returned[0][1]})
            archive_hash = hashlib.sha256(archive).hexdigest()
            archive_path = Path(private) / ('native-write-' + archive_hash + '.json')
            receipt = workspace_artifact(Path(private), str(archive_path))
            retired = artifact is None
            if retired:
                if (receipt is None or receipt[0] != archive
                        or not any(later > index for later in current_writes.get(args['filePath'], []))):
                    continue
                artifact = content_snapshot(tasks, spec, 'native-written', expected)
                if artifact is None:
                    continue
            elif archive_path.exists() or archive_path.is_symlink():
                if receipt is None or receipt[0] != archive:
                    continue
            else:
                with archive_path.open('xb') as handle:
                    handle.write(archive)
            pointer = {'filePath': args['filePath'], 'content_ref': {
                'path': artifact['path'], 'sha256': artifact['sha256']}}
            if retired:
                pointer['historical_version'] = True
            projected = provider_json(pointer).decode()
            if len(projected.encode()) >= len(function['arguments'].encode()):
                continue
            view['messages'][index]['tool_calls'][call_index]['function']['arguments'] = projected
            records.append({'tool_call_id': ident, 'artifact': artifact, 'receipt': str(archive_path),
                            'receipt_sha256': archive_hash, 'historical_version': retired})
    for index, msg in enumerate(messages):
        if msg.get('role') != 'assistant':
            continue
        for call in msg.get('tool_calls', []):
            ident = call.get('id')
            returned = results.get(ident, [])
            if (call.get('function', {}).get('name') != 'read' or not isinstance(ident, str)
                    or ids.count(ident) != 1 or len(returned) != 1 or returned[0][0] <= index):
                continue
            projection = native_json_read_view(tasks, spec, call, returned[0][1])
            if projection is not None:
                view['messages'][returned[0][0]]['content'] = projection[0]
                read_views.append({'tool_call_id': ident, 'artifact': projection[1]})
    feedback = summary_feedback(tasks, handoffs)
    if feedback is not None:
        view['messages'].append({'role': 'user', 'content': 'Host summary validation: '
                                 + provider_json(feedback).decode()})
    if not records and not anchors and not read_views and feedback is None:
        return body, None
    cmds = getattr(spec, 'commands', ())
    cmd_lines = 'Commands:\n' + ''.join(f'- {command}\n' for command in cmds)
    evidence_dir = Path(spec.evidence_dir).relative_to(tasks.workdir).as_posix()
    # Output paths belong to every task, including commandless continuations.
    # Preserve phase-specific summary/step instructions from the verified host
    # contract rather than replacing them with an incomplete generic schema.
    summary_rules = ''.join(line + '\n' for line in prompt.splitlines()
                            if line.startswith(('Return exactly ', 'steps ', 'surface.',
                                                'Enum summary MUST ', 'After terminal ', 'Step ', 'Steps:')))
    step_rules = []
    in_steps = False
    for line in prompt.splitlines():
        if line == 'Steps (execute in order):':
            in_steps = True
            step_rules.append(line)
        elif in_steps and line.startswith('- '):
            step_rules.append(line)
        else:
            in_steps = False
    host_rules = ''.join(line + '\n' for line in prompt.splitlines()
                         if line.startswith(('Tools:', 'Scope:', 'Budget:', 'Deadline:',
                                             'Tool justification:', 'Object pool:', 'Handoff packet:',
                                             'Only probe candidates ', 'Previous summaries:', 'Ledger items:')))
    continuation = (f'Task: {spec.id}\nPhase: {spec.phase}\nTarget: {spec.target}\nWorkdir: {tasks.workdir}\n'
                    + (f'Vector: {spec.vector} (test ONLY this vector)\n' if getattr(spec, 'vector', '') else '')
                    + host_rules
                    + f'Evidence dir: {evidence_dir} (under Workdir)\n'
                    + f'Summary path: summaries/{spec.id}.json; write compact JSON with write '
                      '(filePath and content required).\n'
                    + cmd_lines
                    + ''.join(line + '\n' for line in step_rules)
                    + summary_rules
                    + f'Synthetic session references (host-owned): {json.dumps(tasks.bindings, separators=(",", ":"))}\n'
                    + ('Host setup checks passed; refresh if stale.\n' if tasks.setup_checks_passed else '')
                    + 'Complete remaining Commands; avoid scaffold rereads. Cited evidence/handoffs as needed.\n'
                    + f'Read {contract["path"]} only for missing detail; refs under Workdir.')
    replaced = False
    for msg in view['messages']:
        if msg.get('role') != 'user':
            continue
        content = msg.get('content')
        if isinstance(content, str) and prompt in content:
            msg['content'] = content.replace(prompt, continuation)
            replaced = True
        elif isinstance(content, list):
            for part in content:
                if part.get('type') == 'text' and isinstance(part.get('text'), str) and prompt in part['text']:
                    part['text'] = part['text'].replace(prompt, continuation)
                    replaced = True
    before, after = len(provider_json(messages)), len(provider_json(view['messages']))
    return view, {'schema': 'worker-context-view/1', 'phase': spec.phase, 'messages_bytes_before': before,
                  'messages_bytes_after': after, 'saved_bytes': before - after,
                  'contract': contract, 'contract_replaced': replaced, 'writes': records,
                  'tool_receipts': anchors, 'tool_result_views': result_views,
                  'native_read_views': read_views, 'summary_feedback': feedback}


def enum_followup_context(body, tasks, private, tool_receipts=(), handoffs=None):
    """Compatibility entry point for enum context integrity callers."""
    return worker_followup_context(body, tasks, private, tool_receipts, handoffs)
