"""Native full-chain budget probe; only provider decisions/usage are scripted.

All four native phases and signed closure must fit a single 150,000-token run
with phase allowances, bounded history and room to write terminal summaries.
Local scripted-provider closure does not establish paid-model generalization.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import re
import sys
from urllib.parse import parse_qs, urlsplit

import pytest

from full_agent_broker import Broker, NATIVE_DESCRIPTION_LIMIT, dump
from full_agent_budget import FRAMING_TOKENS, compact_tools, prompt_bound, provider_json
from orchestration_spec import validate_summary
from test_full_agent_context_window import ContextProvider
from test_full_agent_integration import (
    integration_run, kernel_support, acceptance_evidence, read_json, tool_call,
    ObservedLinks, returned_json, message_text, integration_child, completed_tool_ids,
)

pytestmark = pytest.mark.integration
PHASES = ('recon-1', 'enum-2', 'access-3', 'report-4')


class FullChainProvider(ContextProvider):
    """Direct observed recon followed by the existing real host closure pipeline.

    Skip the separate isolation stress script; it is not part of the paid
    recon window. Keep its existing regression tests and all production gates.
    Later phases consume real MCP/read results and normal signed ledger tools.
    """

    def respond(self, body):
        tools = {row['function']['name'] for row in body.get('tools', [])}
        if not tools:
            return self.record_response(body, [])
        completed = completed_tool_ids(body)
        text = json.dumps(body['messages'])
        if body['model'] == 'planner':
            calls = []
            for ident, phase in zip(('context-delegate', 'chain-enum', 'chain-access', 'chain-report'), PHASES):
                if ident not in completed:
                    calls = [tool_call(ident, 'task', {'description': 'Execute ' + phase,
                        'subagent_type': 'worker', 'prompt': 'TaskSpec: ' + phase})]
                    break
        elif 'Task: recon-1' in text:
            return super().respond(body)
        else:
            base = re.search(r'http://127\.0\.0\.1:\d+/', text).group()
            work = Path(re.search(r'(/[^\s"\\]+/native-[^/\s"\\]+/solver)', text).group(1))
            if 'Task: enum-2' in text:
                calls = self.handoff_steps(body, base, work, completed, False)
            elif 'Task: access-3' in text:
                calls = self.handoff_steps(body, base, work, completed, True)
            elif 'Task: report-4' in text:
                calls = self.report_steps(body, base, work, completed)
            else:
                raise AssertionError('unknown host-rendered phase')
        assert all(call['function']['name'] in tools for call in calls)
        return self.record_response(body, calls)

    def handoff_steps(self, body, base, work, completed, access):
        contents = '\n'.join(message_text(row.get('content', '')) for row in body['messages']
                             if row['role'] == 'user')
        if access or 'Host setup checks passed; refresh if stale.' not in contents:
            return super().handoff_steps(body, base, work, completed, access)
        # The model follows the new host instruction. The actual setup checks
        # and handoff freshness checks still execute in the unchanged host API.
        if 'it-enum-http' not in completed:
            return [tool_call('it-enum-http', 'kali-tools_curl_request', {'url': base, 'method': 'GET'})]
        observed = returned_json(body, 'it-enum-http')
        assert observed['ok'] and observed['status'] == 200
        links = ObservedLinks(observed['text']).links
        match = re.search(r'(?m)^Synthetic session references \(host-owned\): (.+)$', contents)
        bindings = json.loads(match.group(1))
        if 'it-enum-evidence' not in completed:
            proof = {'url': observed['final_url'], 'status': observed['status'], 'headers': observed['headers'],
                     'links': links, 'response_sha256': hashlib.sha256(
                         json.dumps(observed, sort_keys=True).encode()).hexdigest()}
            return [tool_call('it-enum-evidence', 'write', {
                'filePath': str(work / 'enum/entry-response.json'),
                'content': json.dumps(proof, separators=(',', ':'))})]
        if 'it-enum-summary' not in completed:
            queries = [(urlsplit(link).path, parse_qs(urlsplit(link).query)) for link in links]
            number = next(values['id'][0] for _, values in queries if 'id' in values)
            filename = next(values['name'][0] for path, values in queries if path == '/file' and 'name' in values)
            summary = {'phase': 'enum', 'target': base, 'status': 'partial', 'findings': [],
                'evidence': ['enum/entry-response.json'], 'next': 'access-3',
                'steps': [{'id': 'entry-links', 'status': 'done'}, {'id': 'ownership', 'status': 'not_tested'}],
                'surface': {'routes': links, 'params': sorted({key for _, values in queries for key in values}),
                    'docs': [], 'docs_probes': [], 'id_formats': [
                        {'family': 'item', 'format': 'int', 'example': number},
                        {'family': 'file', 'format': 'string', 'example': filename}]}}
            return [tool_call('it-enum-summary', 'write', {
                'filePath': str(work / 'summaries/enum-2.json'),
                'content': json.dumps(summary, separators=(',', ':'))})]
        if 'it-prepare-handoff' not in completed:
            return [tool_call('it-prepare-handoff', 'kali-tools_ledger_prepare_handoff', {
                'target': base, 'workdir': str(work), 'summary_file': str(work / 'summaries/enum-2.json'),
                'vector': 'access', 'own_ids_json': '[]', 'session_bindings_json': json.dumps(bindings)})]
        assert returned_json(body, 'it-prepare-handoff')['ok']
        # The host has already written the pool/packet and its immutable
        # receipt. A second model-authored copy of that result is unnecessary.
        return []


def test_native_full_chain_budget_probe(integration_run, record_testsuite_property, monkeypatch):
    # Match the child environment's default local cache; the native fixture
    # intentionally does not inherit arbitrary host environment variables.
    monkeypatch.delenv('TIKTOKEN_CACHE_DIR', raising=False)
    monkeypatch.delenv('DATA_GYM_CACHE_DIR', raising=False)
    with integration_run('handoff_closure', provider_class=FullChainProvider,
                         token_budget=150000, child_script=Path(__file__).resolve()) as run:
        record_testsuite_property('native_full_chain_budget_probe', str(run['directory']))
        run['process'].wait(timeout=run['timeout_seconds'] + 45)
        run['tree'].finish()
        native, = run['output'].glob('native-*')
        manifest = read_json(native / 'launch.json')
        private = native / 'private'
        work = native / 'solver'
        budget = read_json(private / 'budget.json')
        requests = read_json(private / 'provider-requests.json')
        gates = read_json(private / 'native-gates.json')
        scope = read_json(private / 'scope-verification.json')
        # Always preserve the measured boundary, including a failed probe.
        # A strict closure assertion below must never erase its diagnostics
        # or imply that a budget/admission block was a successful chain.
        admitted = [row['canonical_spec_id'] for row in gates if row['tool'] == 'task' and row['allowed']]
        phases = {}
        for ident in PHASES:
            path = work / 'summaries' / (ident + '.json')
            if path.exists():
                summary = read_json(path)
                assert not validate_summary(summary)
                phases[ident] = {'status': summary['status'], 'path': str(path),
                                'evidence': summary['evidence']}
            else:
                phases[ident] = {'status': 'not_tested'}
        rejection = next((row for row in requests if not row['admitted']), None)
        dump(run['directory'] / 'full-chain-budget-probe.json', {
            'probe_status': manifest['status'], 'chain_status': 'incomplete',
            'full_chain_budget_passed': False, 'native_run': str(native),
            'target': manifest['target'], 'phases': phases, 'admitted_tasks': admitted,
            'first_rejection': rejection, 'provider_requests': requests,
            'target_requests': manifest['target_requests'],
            'charged_synthetic_tokens': budget['used']['tokens'],
            'wall_clock_seconds': manifest['wall_clock_seconds'],
            'process_cleanup_verified': not run['tree'].living(),
            'limits': manifest['effective_limits'], 'provider_calls': manifest['llm_calls'],
            'paid_provider_calls': 0, 'remaining_test_tokens': 36402,
            'budget_basis': 'prior session accounting; no provider balance query',
            'prompt_admission': manifest['effective_limits']['prompt_admission'],
            'full_acceptance': False, 'paid_model_generalization': 'not_evaluated',
        })
        assert not run['provider'].errors
        assert not run['tree'].living()
        assert scope['before_traffic'] and scope['target'] == manifest['target']
        assert budget['limits'] == {'http': 300, 'tokens': 150000}
        assert budget['reserved'] == {'http': 0, 'tokens': 0}
        assert budget['used']['http'] == manifest['target_requests'] <= 300
        assert budget['used']['tokens'] <= 150000
        assert FRAMING_TOKENS == 2048
        for row, exchange in zip((r for r in requests if r['admitted']), run['provider'].requests, strict=True):
            raw = provider_json({key: value for key, value in exchange['request'].items() if key != 'max_tokens'})
            upper, profile = prompt_bound(raw)
            assert row['request_bytes'] == len(raw)
            assert row['prompt_upper_bound'] == upper
            assert all(row[key] == value for key, value in profile.items())
            assert row['bound_profile'] in {'cl100k_base_1.5x', 'utf8_bytes_1x'}
        assert all(event['measurement_valid'] for event in budget['events'])
        assert manifest['llm_calls'] == len(run['provider'].requests) == sum(row['admitted'] for row in requests)
        assert not manifest['acceptance_passed']
        first_enum = next(row for row in requests if row['task_spec_id'] == 'enum-2')
        assert first_enum['admitted']
        assert first_enum['requested_output_tokens'] == first_enum['admitted_output_tokens'] == 4096
        enum_requests = [row for row in requests if row['task_spec_id'] == 'enum-2']
        assert all(row['admitted_output_tokens'] == 4096 for row in enum_requests[:3])
        summary_turn = enum_requests[2]
        assert summary_turn['context_projection']['contract_replaced']
        assert summary_turn['context_projection']['saved_bytes'] > 0
        assert (private / 'handoff-receipts.json').is_file()
        planner_turn = next(row for row in requests if row.get('context_projection', {}).get('schema')
                            == 'planner-context-view/1' and len(row['context_projection']['tasks']) == 2)
        assert planner_turn['admitted_output_tokens'] == planner_turn['requested_output_tokens'] == 4096
        assert planner_turn['context_projection']['saved_bytes'] > 0
        assert [item['spec_id'] for item in planner_turn['context_projection']['tasks']] == ['recon-1', 'enum-2']
        assert admitted == list(PHASES[:len(admitted)])
        assert 'access-3' in admitted
        assert run['process'].returncode == 0 and manifest['status'] == 'native_finished_unverified'
        assert admitted == list(PHASES) and all(row['admitted'] for row in requests)
        integrity = read_json(work / 'report/closure-integrity.json')
        assert integrity['source'] == 'native_bash_cli_with_pinned_public_trust'
        assert integrity['baseline']['exit_code'] == integrity['restored']['exit_code'] == 0
        assert integrity['original_bytes_restored']
        assert len(integrity['tampered']) == 5
        assert all(row['exit_code'] == 2 and row['restored']['exit_code'] == 0
                   for row in integrity['tampered'].values())
        assert read_json(work / 'closure.json')['signature_alg'] == 'ed25519:v1'
        dump(run['directory'] / 'full-chain-budget-probe.json', {
            'probe_status': 'completed', 'chain_status': 'local_slice_closed',
            'full_chain_budget_passed': True, 'native_run': str(native),
            'target': manifest['target'], 'phases': phases, 'admitted_tasks': admitted,
            'first_rejection': None,
            'provider_requests': requests, 'target_requests': manifest['target_requests'],
            'charged_synthetic_tokens': budget['used']['tokens'],
            'wall_clock_seconds': manifest['wall_clock_seconds'], 'process_cleanup_verified': True,
            'limits': manifest['effective_limits'], 'provider_calls': manifest['llm_calls'],
            'paid_provider_calls': 0, 'remaining_test_tokens': 36402,
            'budget_basis': 'prior session accounting; no provider balance query',
            'prompt_admission': manifest['effective_limits']['prompt_admission'],
            'usage_basis': 'first three calls 1226/2048/3042; later calls synthetic 117, not tokenizer measurements',
            'scope': 'one native public redirect closure slice; other vectors explicitly NOT TESTED',
            'full_acceptance': False, 'paid_model_generalization': 'not_evaluated',
        })


if __name__ == '__main__':
    if sys.argv[1:2] != ['--integration-child']:
        raise SystemExit('Use pytest for this native probe')
    original_completion = Broker.completion

    def capture_tool_metadata(self, body):
        # Test-only diagnostics: retain static function schemas, never history,
        # arguments, process environments, keys or provider credentials.
        active = self.tasks.active_spec if self.tasks is not None else None
        tools = body.get('tools', [])
        path = self.private / 'native-context-sizes.json'
        sizes = read_json(path) if path.exists() else []
        entry = {'model': body['model'], 'active_task': active.id if active is not None else None,
            'messages': [{'role': msg['role'], 'bytes': len(provider_json(msg)),
                'tool_call_id': msg.get('tool_call_id'),
                'tool_calls': [{'name': call['function']['name'],
                    'argument_bytes': len(call['function']['arguments'].encode()),
                    'content_bytes': len(json.loads(call['function']['arguments']).get('content', '').encode())}
                    for call in msg.get('tool_calls', [])]} for msg in body['messages']]}
        sizes.append(entry)
        dump(path, sizes)
        if active is not None and tools and not any(
                row.get('function', {}).get('name') == 'task' for row in tools):
            allowed = set(active.tools) | {'read', 'write', 'edit', 'bash'}
            rows = [row for row in tools if row.get('function', {}).get('name') in allowed]
            dump(self.private / (active.phase + '-tool-schemas.json'), compact_tools(
                rows, description_limit=NATIVE_DESCRIPTION_LIMIT))
            path = self.private / (active.phase + '-context-sizes.json')
            sizes = read_json(path) if path.exists() else []
            sizes.append(entry)
            dump(path, sizes)
        return original_completion(self, body)

    Broker.completion = capture_tool_metadata
    # Use the same actual loopback discovery baseline as native closure
    # regressions. The original handler still supplies the real redirect
    # oracle; no validation result or signing response is fabricated.
    raise SystemExit(integration_child())
