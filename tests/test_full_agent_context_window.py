"""Native replay of the paid smoke's admission window; no paid provider calls."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys

import pytest

import full_agent_launcher as launcher
from full_agent_broker import dump
from orchestration_spec import validate_summary
from test_full_agent_integration import (
    ScriptedProvider, integration_run, kernel_support, acceptance_evidence,
    read_json, returned_json, tool_call,
)

pytestmark = pytest.mark.integration


class ContextProvider(ScriptedProvider):
    """Replay usage window with synthetic read paths or instructed direct GET."""

    def respond(self, body):
        tools = {row['function']['name'] for row in body.get('tools', [])}
        completed = {row.get('tool_call_id') for row in body['messages'] if row['role'] == 'tool'}
        calls = []
        if tools:
            text = json.dumps(body['messages'])
            base = re.search(r'http://127\.0\.0\.1:\d+/', text).group()
            work = Path(re.search(r'(/[^\s"\\]+/native-[^/\s"\\]+/solver)', text).group(1))
            if body['model'] == 'planner':
                if 'context-delegate' not in completed:
                    calls = [tool_call('context-delegate', 'task', {
                        'description': 'Native bounded recon replay', 'subagent_type': 'worker',
                        'prompt': 'TaskSpec: recon-1'})]
            elif ('Do not reread the current spec/scaffold' not in text
                    and 'context-scope' not in completed and 'context-get' not in completed):
                calls = [tool_call('context-scope', 'read', {
                    'filePath': str(work.parent / 'runtime/.codex/scope.json')}),
                    tool_call('context-summary', 'read', {'filePath': str(work / 'summaries/recon-1.json')})]
            elif 'context-get' not in completed:
                calls = [tool_call('context-get', 'kali-tools_curl_request', {'url': base, 'method': 'GET'})]
            elif 'context-save' not in completed:
                observed = returned_json(body, 'context-get')
                proof = json.dumps({
                    'url': observed['final_url'], 'status': observed['status'],
                    'headers': observed['headers'], 'request_method': observed['request_method'],
                    'requests_sent': observed['requests_sent'],
                    'links': re.findall(r'href="([^"]+)"', observed['text']),
                    'response_sha256': hashlib.sha256(json.dumps(observed, sort_keys=True).encode()).hexdigest(),
                }, sort_keys=True)
                summary = {'phase': 'recon', 'target': base, 'status': 'done',
                           'evidence': ['recon/entry.json'], 'findings': [], 'next': 'enum-2'}
                calls = [tool_call('context-evidence', 'write', {
                    'filePath': str(work / 'recon/entry.json'), 'content': proof}),
                    tool_call('context-save', 'write', {
                        'filePath': str(work / 'summaries/recon-1.json'), 'content': json.dumps(summary)})]
            assert all(call['function']['name'] in tools for call in calls)
        return self.record_response(body, calls)

    def record_response(self, body, calls):
        """Emit the recorded three-call usage window, then synthetic local usage."""
        with self.lock:
            number = len(self.requests)
            prompt, completion = ((1219, 7), (1958, 90), (2876, 166))[number] if number < 3 else (100, 17)
            message = {'role': 'assistant', 'content': None if calls else 'Local recon replay complete.'}
            if calls:
                message['tool_calls'] = calls
            response = {'id': f'context-{number}', 'object': 'chat.completion', 'created': 1,
                        'model': body['model'], 'choices': [{'index': 0, 'message': message,
                            'finish_reason': 'tool_calls' if calls else 'stop'}],
                        'usage': {'prompt_tokens': prompt, 'completion_tokens': completion,
                                  'total_tokens': prompt + completion}}
            self.requests.append({'request': body, 'response': response, 'authenticated': True})
            dump(self.directory / 'provider-transcript.json', self.requests)
            return response


def test_native_paid_context_window(integration_run, record_testsuite_property):
    control = os.environ.get('CCO_CONTEXT_CONTROL') == '1'
    with integration_run('context_window', provider_class=ContextProvider, token_budget=150000,
                         child_script=Path(__file__).resolve()) as run:
        record_testsuite_property('native_context_window', str(run['directory']))
        run['process'].wait(timeout=150)
        run['tree'].finish()
        native, = run['output'].glob('native-*')
        manifest = read_json(native / 'launch.json')
        budget = read_json(native / 'private/budget.json')
        metrics = read_json(native / 'private/provider-requests.json')
        assert not run['provider'].errors
        assert budget['limits']['tokens'] == 150000
        assert budget['reserved'] == {'http': 0, 'tokens': 0}
        assert read_json(native / 'private/scope-verification.json')['before_traffic']
        assert manifest['native_delegations'] == 1
        assert not run['tree'].living()
        assert not manifest['acceptance_passed']
        assert sum(row['charged'] for row in budget['events'] if row['kind'] == 'tokens') >= 6316
        if control:
            assert run['process'].returncode == 2
            assert manifest['status'] == 'context_limit_exhausted'
            assert metrics[-1]['rejection'] == 'context_limit_exhausted'
            assert metrics[-1]['remaining_tokens'] == 143684
            assert manifest['target_requests'] == 3
            assert len(run['provider'].requests) == 3
        else:
            assert run['process'].returncode == 0, (manifest['status'], metrics)
            assert manifest['status'] == 'native_finished_unverified'
            assert all(row['admitted'] for row in metrics)
            window = metrics[3]
            assert window['remaining_tokens'] == 143684
            assert window['prompt_upper_bound'] <= 19588
            assert window['admitted_output_tokens'] == 4096
            summary = read_json(native / 'solver/summaries/recon-1.json')
            assert summary['status'] == 'done' and not validate_summary(summary)
            proof = read_json(native / 'solver/recon/entry.json')
            get_request = next(row['request'] for row in run['provider'].requests
                               if any(m.get('tool_call_id') == 'context-get' for m in row['request']['messages']))
            observed = returned_json(get_request, 'context-get')
            assert proof['status'] == observed['status'] == 200
            assert proof['headers'] == observed['headers']
            assert proof['links'] == re.findall(r'href="([^"]+)"', observed['text'])
            assert proof['response_sha256'] == hashlib.sha256(json.dumps(observed, sort_keys=True).encode()).hexdigest()
            assert manifest['target_requests'] == budget['used']['http'] == 4
            gates = read_json(native / 'private/native-gates.json')
            assert not any(row['tool'] == 'read' for row in gates)
        dump(run['directory'] / 'context-window-acceptance.json', {
            'control': control, 'status': manifest['status'], 'metrics': metrics,
            'paid_provider_calls': 0, 'remaining_test_tokens': 36402,
            'scope': 'recon segment only; scripted model usage; exact paid read paths were not retained',
            'full_acceptance': False})


if __name__ == '__main__':
    if sys.argv[1:2] != ['--integration-child']:
        raise SystemExit('Use pytest for this native replay')
    raise SystemExit(launcher.main(sys.argv[2:]))
