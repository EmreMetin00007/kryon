"""Independent Python holdout audit with actual local MCP, HTTP and signatures."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading

import pytest

import full_agent_holdout as holdout
import full_agent_launcher as launcher
import full_agent_preflight as preflight
from full_agent_broker import dump
from full_agent_python_broker import SUMMARY_TOOL
from test_full_agent_python_solver import baseline as baseline, acceptance_evidence as acceptance_evidence


@pytest.mark.integration
@pytest.mark.parametrize('provider_mode,seed,family,profile', [
    ('host_batches', 314159, 'readonly-api-access-control', None),
    ('first_pair', 161803, 'readonly-api-access-control', None),
    ('parameter_batches', 271828, 'readonly-sql-injection', 'readonly_sqli_boolean'),
    ('parameter_batches', 141421, 'readonly-template-injection', 'readonly_ssti_arithmetic'),
])
def test_python_independent_holdout_scores_only_current_signed_wire(baseline, record_testsuite_property, provider_mode, seed, family, profile):
    parent = Path('/tmp/cco-work/full-agent-python-holdout')
    parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='authcoverage-', dir=parent))
    decisions = []

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            context = json.loads(body['messages'][1]['content'])
            spec, results = context['task_spec'], context['recent_results']
            decisions.append(spec['phase'])
            if spec['phase'] == 'recon' and not results:
                tool, args = 'kali-tools_curl_request', {'url': spec['target']}
            elif spec['phase'] == 'enum' and not results:
                tool, args = 'kali-tools_crawl_web_surface', {'target': spec['target'], 'max_pages': 5 if profile else 1}
            elif spec['phase'] == 'access' and not results and profile:
                tool, args = 'hunter_run_web_loop', {'target': spec['target'], 'live': True,
                    'crawl': False, 'fuzz_limit': 4, 'candidate_sample_limit': 16,
                    'max_validations': 16, 'sleep_s': 0.2, 'validation_profile': profile,
                    'session_bindings': json.dumps(context['session_bindings'])}
            elif spec['phase'] == 'access' and not results and provider_mode == 'first_pair':
                bindings = dict(list(context['session_bindings'].items())[:2])
                tool, args = 'hunter_run_web_loop', {'target': spec['target'], 'live': True,
                    'crawl': False, 'blind_discovery': True, 'blind_max_requests': 24,
                    'fuzz_limit': 0, 'candidate_sample_limit': 0, 'max_validations': 16,
                    'sleep_s': 0.2, 'session_bindings': json.dumps(bindings)}
            elif spec['phase'] == 'report' and not results:
                tool, args = 'hunter_coverage_report', {'target': spec['target']}
            else:
                tool, args = SUMMARY_TOOL, {'status': 'partial' if spec['phase'] in {'access', 'report'} else 'done',
                    'next': 'Broader coverage remains NOT TESTED.', 'steps': [
                    {'id': step['id'], 'status': 'done'} for step in spec['steps'] if not step['host_managed']]}
            raw = json.dumps({'choices': [{'message': {'tool_calls': [{'function': {
                'name': tool, 'arguments': json.dumps(args)}}]}}],
                'usage': {'prompt_tokens': 100, 'completion_tokens': 100, 'total_tokens': 200}}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = directory / 'provider.json'
    dump(config, {"schema": "cco-llm/1", "model": "owned/model", "providers": {"owned": {
        "models": ["model"], "api_key_env": "CCO_BENCHMARK_API_KEY",
        "base_url": f"http://127.0.0.1:{server.server_port}/v1"}}})
    try:
        output = directory / 'preflights'
        assert preflight.main(['--baseline', str(baseline), '--provider-config', str(config),
            '--token-budget', '150000', '--solver-mode', 'python_loop',
            '--holdout-family', family, '--holdout-seed', str(seed),
            '--output-dir', str(output)]) == 0
        prepared = launcher.prepared_run(next(output.glob('*/preflight.json')))
        runs = directory / 'runs'
        runs.mkdir()
        provider = launcher.provider_settings(config, prepared['contract']['models'])
        path, manifest = launcher.launch_seed(prepared, seed=seed, output=runs,
            provider=provider, api_key='host-only-local-fixture', bwrap=None, opencode=None)
        assert manifest['status'] == 'python_finished_verified', manifest
        assert manifest['closure_verified'] and not manifest['acceptance_passed']
        metrics, aggregate = holdout.audit_run(path)
        assert metrics['closure_verified'] and metrics['accounting_matches']
        assert metrics['recall'] == {'numerator': 8, 'denominator': 8, 'value': 1.0}
        assert metrics['negative_coverage'] == {'numerator': 8, 'denominator': 8, 'value': 1.0}
        assert metrics['false_positives'] == {'numerator': 0, 'denominator': 8, 'value': 0.0}
        assert not metrics['rejected_evidence'] and metrics['paid_provider_calls'] == 0
        assert aggregate['status'] == 'incomplete' and not aggregate['full_acceptance']
        if not profile:
            # Evaluator truth is inspected only after closure, never by the provider.
            negatives = [case for case in metrics['cases'] if case['expected'] == 'negative']
            assert sum(case['negative_behavior'] == 'deny' for case in negatives) == 4
            assert sum(case['negative_behavior'] == 'redact' for case in negatives) == 4
            for case in negatives:
                assert case['outcome'] == 'true_negative' and not case['reported_confirmations']
                proof = case['evidence'][0]
                assert proof['verdict'] == 'UNCONFIRMED' and len(proof['wire_sequences']) >= 2
                record = json.loads(Path(proof['artifact']).read_bytes())
                responses = {item['role']: item for item in record['request_evidence']}
                assert responses['owner']['status'] == 200
                assert responses['attacker']['status'] == (403 if case['negative_behavior'] == 'deny' else 200)
                assert responses['owner']['response_sha256'] != responses['attacker']['response_sha256']
        assert holdout.main(['audit', '--manifest', str(path)]) == 0
        work = path.parent / 'solver'
        rows = json.loads((path.parent / 'private/python-tool-results.json').read_bytes())
        loops = [row for row in rows if row['spec_id'] == 'access-3' and row['tool'] == 'hunter_run_web_loop']
        waits = [row for row in rows if row['tool'] == 'host_access_backoff']
        if profile:
            assert len(loops) == 4
            assert all(row['arguments']['validation_profile'] == profile for row in loops)
            assert len(waits) == 3
            enum = json.loads((work / 'summaries/enum-2.json').read_bytes())
            observed = {row['url'] for row in enum['surface']['records']}
            assert all(row['arguments']['target'] in observed for row in loops[1:])
            access = json.loads((work / 'summaries/access-3.json').read_bytes())
            assert len(access['validation_outcomes']) == 16
            assert len(access['not_tested_reasons']) == 8
            assert all(row['reason_code'] and row['vector'] for row in access['not_tested_reasons'])
            closure = json.loads((work / 'closure.json').read_bytes())['payload']
            assert len(closure['not_tested']) == 8
            assert {row['vector'] for row in closure['not_tested']} == {
                row['vector'] for row in access['not_tested_reasons']}
            wire = json.loads((path.parent / 'private/evaluator/wire.json').read_bytes())
            from collections import Counter
            counts = Counter(row['path'] for row in wire)
            assert max(counts[case['path']] for case in metrics['cases']) <= 8
        else:
            pairs = [json.loads(row['arguments']['session_bindings']) for row in loops]
            distinct_pairs = {tuple(sorted(pair)) for pair in pairs}
            assert len(loops) == 6 and len(distinct_pairs) == 6
            assert len(set().union(*(set(pair) for pair in pairs))) == 4
            assert len(waits) == 5
        assert all(row['result']['elapsed_seconds'] >= row['result']['window_seconds'] for row in waits)
        assert decisions.count('access') == (2 if provider_mode == 'host_batches' else 3)
        signed = json.loads((work / 'attempt-ledger.json').read_bytes())
        validations = [row for row in signed['payload']['records'] if row['verdict'] in {'CONFIRMED', 'UNCONFIRMED'}]
        expected_validations = 16 if profile else 24
        expected_confirmed = 8 if profile else 12
        assert len(validations) == expected_validations
        assert sum(row['verdict'] == 'CONFIRMED' for row in validations) == expected_confirmed
        for name in ('attempt-ledger.json', 'specs.json', 'access/live-result.json', 'enum/session-checks.json'):
            artifact = work / name
            original = artifact.read_bytes()
            changed = json.loads(original)
            if name == 'attempt-ledger.json':
                changed['payload']['target'] = 'https://outside.invalid/'
            elif isinstance(changed, list):
                changed[0]['target'] = 'https://outside.invalid/'
            else:
                changed['tampered'] = True
            dump(artifact, changed)
            try:
                with pytest.raises(ValueError):
                    holdout.audit_run(path)
            finally:
                artifact.write_bytes(original)
        record_testsuite_property('python_independent_holdout_run', str(path.parent))
        dump(directory / 'verified-run.json', {'manifest': str(path), 'family': family,
            'metrics': metrics, 'llm_calls': manifest['llm_calls'],
            'tokens': manifest['budget']['used']['tokens'], 'seconds': manifest['wall_clock_seconds']})
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
