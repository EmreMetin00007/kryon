#!/usr/bin/env python3
"""Offline WS7 setup -> own -> pre -> experiment -> post -> verified teardown.

The in-memory lab adapter opens no sockets. This command grants no live writes.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from chain_executor import ChainExecutor  # noqa: E402
from lab.business_logic_lab import IDENTITIES, KINDS, LogicLab  # noqa: E402
from workflow_compiler import compile_workflow_manifests  # noqa: E402
import write_set  # noqa: E402


class _LabGate:
    def validate_tool_invocation(self, tool_name, args=None, **kwargs):
        from urllib.parse import urlparse
        return {'allowed': urlparse((args or {}).get('url', '')).netloc == 'p7.lab.test'}


def run_scenario(kind, *, db_path, run_id, session_id, vulnerable=False,
                 teardown='success', lab=None, executor_factory=ChainExecutor):
    lab = lab or LogicLab(vulnerable=vulnerable, teardown=teardown)
    urls, sealed, cleanup = {}, [], []
    result = {'success': False, 'terminal': 'abort', 'requests_sent': 0}
    diagnostics = []
    try:
        for role in ('control', 'probe'):
            url = lab.setup(kind, role)
            urls[role] = url
            write_set.seal_object(db_path, object_url=url, identity_label='owner',
                run_fingerprints=[write_set.fingerprint_credentials(h) for h in IDENTITIES.values()],
                task_ref=kind, run_id=run_id, session_id=session_id, test_account=True,
                ownership_evidence={'fixture_url': url, 'adapter': 'local-in-memory-lab', 'owner': 'owner'})
            sealed.append(url)
        captures = lab.capture(kind, urls, session_id=session_id)
        manifests = compile_workflow_manifests(captures, target_ref='p7.lab.test', diagnostics=diagnostics)
        if len(manifests) != 1:
            raise ValueError('expected one observation-bound scenario: ' + repr(diagnostics))
        executor = executor_factory(policy_engine=_LabGate(), sender=lab.sender, identities=IDENTITIES,
            write_context={'db_path': db_path, 'run_id': run_id, 'session_id': session_id})
        result = executor.execute(manifests[0])
        # This is a lab result; no finding or signed reporting artifact is created.
        result['validated_effect'] = bool(result['success'])
        result['contract'] = manifests[0]['business_logic']
        result['captures'] = captures
        result['manifest'] = manifests[0]
    except Exception as exc:
        result['terminal_error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        for url in urls.values():
            if url not in sealed:
                cleanup.append({'object_url': url, 'state': 'unknown', 'unsealed_fixture': True,
                                'reason': 'ownership_not_sealed; no teardown attempted'})
                continue
            try:
                closed = lab.close(url)
                phase = 'torn_down' if closed is True else 'cleanup_failed' if closed is False else 'unknown'
            except Exception:
                closed, phase = False, 'cleanup_failed'
            if url in sealed:
                row = write_set.inspect_object(db_path, url)
                # Interrupted experiments remain uncertain even if local disposal succeeds.
                if phase == 'torn_down' and row['state'] != 'post_state':
                    write_set.mark_state(db_path, url, 'unknown', run_id=run_id,
                                         session_id=session_id, evidence={'interrupted': True})
                write_set.mark_state(db_path, url, phase, run_id=run_id,
                    session_id=session_id, evidence={'fixture_close_verified': closed})
                cleanup.append(write_set.inspect_object(db_path, url))
    result.update(cleanup=cleanup, diagnostics=diagnostics,
                  unresolved_fixtures=[r['object_url'] for r in cleanup if r['state'] != 'torn_down'])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true', help='Explicit socket-free local mode (default)')
    parser.parse_args(argv)
    results = []
    with tempfile.TemporaryDirectory(prefix='p7-ws7-') as home:
        for kind in KINDS:
            for vulnerable in (False, True):
                result = run_scenario(kind, db_path=str(Path(home) / 'write_set.db'),
                    run_id=uuid.uuid4().hex, session_id=uuid.uuid4().hex, vulnerable=vulnerable)
                results.append({'kind': kind, 'vulnerable': vulnerable,
                    'validated_effect': result.get('validated_effect', False),
                    'unresolved_fixtures': result['unresolved_fixtures'],
                    'requests_sent': result['requests_sent']})
    ok = all(r['validated_effect'] == r['vulnerable'] and not r['unresolved_fixtures'] for r in results)
    print(json.dumps({'offline': True, 'network_requests': 0, 'passed': ok, 'scenarios': results}, indent=2))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
