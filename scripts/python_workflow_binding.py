"""Host-only admission of compiled P7/P8 workflows to Python TaskSpecs.

No model-supplied HTTP, credentials, permissions or manifests enter this API.
The signed envelope is a reference contract, not a grant of wire permission.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path

from action_manifest import validate_manifest
from authz_matrix import identity_fact
from evidence_chaining import CONTEXT, EvidenceError, digest, origin
from evidence_trust import attest, canonical_bytes, verify
from orchestration_spec import COMPILED_WORKFLOW_TOOL
from workflow_compiler import compile_business_logic_chain
import write_set

BINDING_PURPOSE = 'python-compiled-workflow-binding'
EVIDENCE_PURPOSE = 'python-compiled-workflow-execution'
STEP_TOOLS = frozenset({'chain_runner_http_get', 'chain_runner_http_post'})


def policy_snapshot(engine):
    return {name: {'path': str(Path(getattr(engine, name)).resolve()),
                   'sha256': hashlib.sha256(Path(getattr(engine, name)).read_bytes()).hexdigest()}
            for name in ('scope_file', 'program_policy_file', 'permissions_file', 'tool_capabilities_file')}


class WorkflowBinding:
    def __init__(self, spec, manifest, *, graph, runtime, identities,
                 authorized_tools, policy_engine, capture_hashes=(), write_context=None):
        self.graph = graph
        self.manifest = copy.deepcopy(manifest)
        self.runtime = copy.deepcopy(runtime)
        self.identities = copy.deepcopy(identities)
        self.write_context = dict(write_context or {})
        self.capture_hashes = list(capture_hashes)
        tools = set(authorized_tools)
        if (not tools or not tools <= STEP_TOOLS
                or {'chain_runner_' + s['tool'] for s in manifest.get('steps', [])} != tools):
            raise EvidenceError('workflow_tool_authorization_denied')
        check = validate_manifest(manifest)
        if not check['valid']:
            raise EvidenceError('invalid_compiled_workflow')
        if 'evidence_chain' in manifest:
            source = manifest['evidence_chain']['spec']
            self.capture_hashes = list(source['captures'].values())
            if (runtime.get('identity_hashes') != source['identity_hashes']
                    or runtime.get('permission_hash') != source['permission_hash']
                    or runtime.get('resource_hashes') != {graph.evidence(source['resource_hash'])['resource']['url']:
                                                        source['resource_hash']}):
                raise EvidenceError('workflow_reference_mismatch')
        elif 'business_logic' not in manifest:
            raise EvidenceError('unsupported_compiled_workflow')
        hashes = sorted(set([*self.capture_hashes, runtime['permission_hash'],
                             *runtime['identity_hashes'].values(), *runtime['resource_hashes'].values()]))
        if not self.capture_hashes:
            raise EvidenceError('missing_source_evidence')
        records = [graph.evidence(h, runtime) for h in hashes]
        self.envelope = attest({
            'schema': 'python-compiled-workflow-binding/1', 'task_spec_id': spec.id,
            'target': spec.target, 'scope_ref': spec.scope_ref,
            'program_id': runtime.get('program_id'),
            'policy_files': policy_snapshot(policy_engine),
            'runtime_sha256': digest(runtime), 'write_context_sha256': digest(self.write_context),
            'context': {k: runtime.get(k) for k in CONTEXT},
            'manifest_sha256': digest(manifest), 'source_hashes': hashes,
            'source_evidence_sha256': digest(hashes),
            'authorized_tools': sorted(tools),
            'identity_hashes': runtime['identity_hashes'], 'resource_hashes': runtime['resource_hashes'],
            'expires_at': min(r['expires_at'] for r in records),
        }, BINDING_PURPOSE)

    @property
    def reference(self):
        return digest(self.envelope)

    def check(self, broker, spec, *, registered=True):
        payload = self.envelope['payload']
        if not verify(canonical_bytes(payload), self.envelope, BINDING_PURPOSE):
            raise EvidenceError('invalid_workflow_signature')
        if (spec.id != payload['task_spec_id'] or spec.target != payload['target']
                or spec.scope_ref != payload['scope_ref'] or spec.phase != 'access'
                or spec.references or COMPILED_WORKFLOW_TOOL not in spec.tools
                or (registered and spec.compiled_workflows.get(self.reference) != self.envelope)):
            raise EvidenceError('workflow_task_binding_mismatch')
        if (not payload['program_id'] or broker.engine.program_policy.get('profile') != payload['program_id']
                or origin(spec.target) != payload['context']['origin']
                or str(Path(spec.scope_ref).resolve()) != payload['policy_files']['scope_file']['path']
                or policy_snapshot(broker.engine) != payload['policy_files']):
            raise EvidenceError('workflow_program_mismatch')
        if self.graph.clock() >= payload['expires_at']:
            raise EvidenceError('expired_source_evidence')
        if digest(self.manifest) != payload['manifest_sha256']:
            raise EvidenceError('edited_compiled_workflow')
        if digest(self.runtime) != payload['runtime_sha256'] or digest(self.write_context) != payload['write_context_sha256']:
            raise EvidenceError('workflow_runtime_mismatch')
        for h in payload['source_hashes']:
            self.graph.evidence(h, payload['context'])
        runtime, graph = self.runtime, self.graph
        identities = {}
        for name, h in payload['identity_hashes'].items():
            record = graph.evidence(h, runtime)
            actor = record.get('actor', {})
            registration = broker.tasks.bindings.get(name, {})
            if (record.get('kind') != 'identity' or record.get('identity_ref') != name
                    or actor.get('test_data_only') is not True
                    or identity_fact(actor, 'tenant') != runtime['tenant']
                    or not identity_fact(actor, 'principal') or not identity_fact(actor, 'authority')
                    or record.get('credential_hash') != digest(self.identities.get(name, {}))
                    or registration.get('target') != spec.target or registration.get('test_data_only') is not True):
                raise EvidenceError('workflow_identity_mismatch')
            identities[name] = record
        if set(self.manifest['identity_refs']) != set(identities):
            raise EvidenceError('workflow_identity_mismatch')
        permission = graph.evidence(runtime['permission_hash'], runtime)
        urls = sorted({step['args']['url'] for step in self.manifest['steps']})
        writing = 'business_logic' in self.manifest
        if (permission.get('kind') != 'permission' or permission.get('scope_allowed') is not True
                or permission.get('read_allowed') is not True or permission.get('urls') != urls
                or (writing and permission.get('write_allowed') is not True)):
            raise EvidenceError('workflow_permission_denied')
        for url, h in payload['resource_hashes'].items():
            record = graph.evidence(h, runtime)
            resource = record.get('resource', {})
            if (record.get('kind') != 'resource' or resource.get('url') != url
                    or resource.get('test_data_only') is not True or resource.get('tenant') != runtime['tenant']
                    or resource.get('owner_identity') not in identities):
                raise EvidenceError('workflow_object_mismatch')
            if writing:
                ctx = self.write_context
                row = write_set.inspect_object(ctx.get('db_path', ''), url)
                if (not row or not write_set.is_sealed(ctx['db_path'], url)
                        or (row['run_id'], row['session_id']) != (runtime['run_id'], runtime['session_id'])
                        or (ctx.get('run_id'), ctx.get('session_id')) != (runtime['run_id'], runtime['session_id'])
                        or row['identity_label'] != resource['owner_identity']):
                    raise EvidenceError('workflow_object_ownership_denied')
                for step in self.manifest['steps']:
                    if step.get('object_url') == url and step.get('resource_id') != resource.get('resource_id'):
                        raise EvidenceError('workflow_object_mismatch')
        if writing:
            if set(payload['resource_hashes']) != {s['object_url'] for s in self.manifest['steps']}:
                raise EvidenceError('workflow_object_mismatch')
            expected = compile_business_logic_chain(graph, self.capture_hashes, runtime,
                                                    target_ref=self.manifest['target_ref'])
            if self.manifest not in expected:
                raise EvidenceError('edited_compiled_workflow')
            for h in self.capture_hashes:
                record = graph.evidence(h, runtime)
                if record.get('credential_hash') != identities.get(record.get('identity_ref'), {}).get('credential_hash'):
                    raise EvidenceError('workflow_capture_identity_mismatch')
        else:
            graph.check_plan(self.manifest, runtime, self.identities)

    def wire_check(self, broker, spec, tool, url, method, headers):
        self.check(broker, spec)
        if broker.closed.is_set() or broker.budget.remaining_seconds() <= 0:
            raise EvidenceError('workflow_execution_closed')
        if 'chain_runner_' + tool not in self.envelope['payload']['authorized_tools']:
            raise EvidenceError('workflow_tool_authorization_denied')
        matches = [s for s in self.manifest['steps'] if s['tool'] == tool and s['args']['url'] == url
                   and s['args'].get('method', 'GET' if tool == 'http_get' else 'POST') == method]
        def same_identity(step):
            expected = {k.lower(): v for k, v in self.identities[step['identity_refs'][0]].items()}
            actual = {k.lower(): v for k, v in headers.items()
                      if k.lower() in expected or k.lower() not in {'user-agent', 'content-type'}}
            return actual == expected
        if not any(same_identity(s) for s in matches):
            raise EvidenceError('workflow_request_binding_mismatch')
        if method in {'POST', 'PUT', 'PATCH'}:
            ctx = self.write_context
            if not any(write_set.mutation_permitted(ctx['db_path'], s['object_url'],
                       write_set.fingerprint_credentials(headers), run_id=ctx['run_id'],
                       session_id=ctx['session_id'])[0] for s in matches):
                raise EvidenceError('workflow_object_ownership_denied')
