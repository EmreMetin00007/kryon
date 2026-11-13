"""Native repair of a malformed terminal enum draft; zero paid model calls."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import test_full_agent_chain_budget as chain
from full_agent_broker import dump
from orchestration_spec import validate_summary
from test_full_agent_integration import (
    integration_run, kernel_support, acceptance_evidence, read_json,
)

pytestmark = pytest.mark.integration


class FeedbackProvider(chain.FullChainProvider):
    """Intentionally omit surface, then repair only after real host feedback."""

    def feedback(self, body):
        messages = [row['content'] for row in body['messages'] if row.get('role') == 'user'
                    and isinstance(row.get('content'), str)
                    and row['content'].startswith('Host summary validation: ')]
        assert len(messages) == 1, 'Worker must receive current host validation feedback'
        return json.loads(messages[0].removeprefix('Host summary validation: '))

    def handoff_steps(self, body, base, work, completed, access):
        if not access and 'it-enum-summary' in completed and 'enum-summary-repair' not in completed:
            feedback = self.feedback(body)
            assert feedback['valid'] is False
            assert any('surface inventory' in error for error in feedback['errors'])
            calls = super().handoff_steps(body, base, work, completed - {'it-enum-summary'}, access)
            assert len(calls) == 1 and calls[0]['function']['name'] == 'write'
            assert 'surface' in json.loads(json.loads(calls[0]['function']['arguments'])['content'])
            calls[0]['id'] = 'enum-summary-repair'
            return calls
        calls = super().handoff_steps(body, base, work, completed, access)
        if not access and 'it-enum-summary' not in completed:
            for call in calls:
                if call['id'] == 'it-enum-summary':
                    args = json.loads(call['function']['arguments'])
                    summary = json.loads(args['content'])
                    summary.pop('surface')
                    args['content'] = json.dumps(summary, separators=(',', ':'))
                    call['function']['arguments'] = json.dumps(args)
        if not access and 'enum-summary-repair' in completed and 'it-prepare-handoff' not in completed:
            feedback = self.feedback(body)
            assert feedback['valid'] is True and feedback['handoff_ready'] is False
        return calls


def test_native_worker_repairs_enum_and_produces_current_signed_handoff(integration_run,
                                                                       record_testsuite_property):
    with integration_run('handoff_closure', provider_class=FeedbackProvider, token_budget=150000,
                         child_script=Path(chain.__file__).resolve()) as run:
        record_testsuite_property('native_summary_feedback', str(run['directory']))
        run['process'].wait(timeout=run['timeout_seconds'] + 45)
        run['tree'].finish()
        native, = run['output'].glob('native-*')
        private = native / 'private'
        launch = read_json(native / 'launch.json')
        metrics = read_json(private / 'provider-requests.json')
        assert not run['provider'].errors
        assert run['process'].returncode == 0 and launch['status'] == 'native_finished_unverified'
        assert not run['tree'].living() and launch['native_delegations'] == 4
        assert launch['budget']['reserved'] == {'tokens': 0, 'http': 0}
        assert read_json(private / 'scope-verification.json')['before_traffic']
        feedback = [row['context_projection']['summary_feedback'] for row in metrics
                    if row.get('context_projection', {}).get('summary_feedback') is not None]
        assert any(not row['valid'] and 'surface inventory' in str(row['errors']) for row in feedback)
        assert any(row['valid'] and row.get('handoff_ready') is False for row in feedback)
        summary = read_json(native / 'solver/summaries/enum-2.json')
        assert not validate_summary(summary) and summary['surface']['routes']
        assert read_json(private / 'handoff-receipts.json')['access']['producer_spec_id'] == 'enum-2'
        closure = read_json(native / 'solver/report/closure-integrity.json')
        assert closure['baseline']['exit_code'] == closure['restored']['exit_code'] == 0
        assert all(row['exit_code'] == 2 for row in closure['tampered'].values())
        assert all(row['admitted'] for row in metrics)
        assert not launch['acceptance_passed']
        dump(run['directory'] / 'summary-feedback-acceptance.json', {
            'native_run': str(native), 'feedback': feedback, 'status': launch['status'],
            'charged_synthetic_tokens': launch['budget']['used']['tokens'],
            'paid_provider_calls': 0, 'full_acceptance': False})
