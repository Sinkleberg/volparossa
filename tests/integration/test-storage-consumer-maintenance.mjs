// SPDX-License-Identifier: GPL-3.0-only
// Inert contracts only. These do not execute GPG, a core, or application code.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, chmod, symlink, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { boundedFile, fixtureBytes, ForegroundObservation, MAX_CIPHER, PHASES, PLAIN_BYTES,
  consumerFailureReport, depositDiagnostic, parseProcStat, replacementReady, requirePublishComplete, retainedSnapshot,
  retentionAdvanced, validateCheckpoint, validateStorage } from './storage-consumer-maintenance.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const keys = [1, 2, 3].map(v => Buffer.alloc(32, v).toString('hex'));
const copy = (key, charge = 'committed') => ({ provider_key: [...Buffer.from(key, 'hex')], charge });
const repaired = () => [0, 1, 2, 3].map(i => ({ copies: i === 1 ? [copy(keys[1]), copy(keys[2])]
  : [copy(keys[0], 'uncertain'), copy(keys[1]), copy(keys[2])], ...(i === 1 ? {} : { handoff: { phase: 'delete_pending' } }) }));
function storage(kind = 'repaired') {
  return { status: 'complete', local_process_joined: true, storage: {
    operation_complete: true, logical_ciphertext_bytes: 100, fragment_count: 4, copies_per_fragment: 2,
    distinct_provider_identities: 3, owner_signature_verified: true, reserved_payload_bytes: 0,
    report_version: 2, placement_authorizations: 3, retained_copy_records: 11, pending_retirements: 3,
    replacement_overhead_included: true, desired_copies_per_fragment: 2,
    committed_payload_bytes: kind === 'deleted' ? 0 : 200,
    uncertain_payload_bytes: kind === 'repaired' ? 75 : 0,
    physical_payload_charge_upper_bound: kind === 'deleted' ? 0 : kind === 'repaired' ? 275 : 200,
    fragments_with_confirmed_unexpired_copy: 4, fully_redundant_from_retained_receipts: true,
  } };
}

function publishFailure(value, app = 'cloud', operation = 'deposit', aborted = false, profileVersion = 1) {
  try { requirePublishComplete(value, app, operation, profileVersion); assert.fail('expected rejection'); }
  catch (error) {
    assert.equal(error.code, 'publish_operation');
    return consumerFailureReport({ provision: 'a'.repeat(64), stage: `${app}_publish`, signal: { aborted } }, 'publish', error);
  }
}

const transferFailure = () => ({ fragment_index: 2, copy_index: 1, operation: 'reserve',
  stage: 'agent_terminal', category: 'io', agent_code: null });
const diagnostics = (failures = [transferFailure()]) => ({ version: 1, failures, omitted_failures: 0 });
const detailedFailure = (stage = 'route_connect', deadline_scope = 'none') => ({
  ...transferFailure(), stage: 'agent_ready', category: 'agent_rejected', agent_code: 'CONTENT_UNAVAILABLE',
  agent_detail: { stage, deadline_scope } });
const detailedDiagnostics = (failures = [detailedFailure()]) => ({ version: 2, failures, omitted_failures: 0 });
const tlsDiagnostics = (tls_failure = 'authentication') => ({ version: 3, omitted_failures: 0,
  failures: [{ ...detailedFailure('tls_handshake'), agent_detail: {
    stage: 'tls_handshake', deadline_scope: 'none', tls_failure } }] });
const outcomeDiagnostics = () => ({ version: 4, omitted_failures: 0, failures: [{
  ...transferFailure(), operation: 'finalize', stage: 'wire_receipt', agent_detail: null,
  agent_outcome: { status: 'observed', detail: { phase: 'remote_receipt_read', category: 'timeout', deadline_scope: 'remote_wire' } },
}] });

test('profile5 observes diagnostic4 in failure envelope6 without upgrading historical profiles', () => {
  for (const app of ['image', 'cloud']) {
    const diagnostic = outcomeDiagnostics(), value = { status: 'incomplete', code: 'retained_operation_incomplete',
      local_process_joined: true, storage: { operation_complete: false, deposit_diagnostics: diagnostic, raw: 'PRIVATE' } };
    const report = publishFailure(value, app, 'deposit', false, 5);
    assert.equal(report.version, 6); assert.equal(report.publish_observation.version, 5);
    assert.deepEqual(report.publish_observation.deposit_diagnostics, diagnostic);
    assert.doesNotMatch(JSON.stringify(report), /PRIVATE|raw/u);
    for (const old of [1, 2, 3]) assert.throws(() => depositDiagnostic(diagnostic, old), /deposit_diagnostics/u);
    for (const old of [2, 3, 4]) {
      assert.equal(publishFailure(value, app, 'deposit', false, old).publish_observation.deposit_diagnostics_state, 'invalid');
    }
    const complete = { status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: { version: 4, failures: [], omitted_failures: 0 } } };
    assert.doesNotThrow(() => requirePublishComplete(complete, app, 'deposit', 5));
    delete complete.storage.deposit_diagnostics;
    assert.equal(publishFailure(complete, app, 'deposit', false, 5).publish_observation.deposit_diagnostics_state, 'missing');
  }
});

test('outcome status, nullable fields and post-READY boundary are exact; unknown context never escapes', () => {
  for (const status of ['observed', 'missing', 'pending', 'expired', 'query_failed', 'query_timeout']) {
    for (const detail of [null, outcomeDiagnostics().failures[0].agent_outcome.detail]) {
      const d = outcomeDiagnostics(); d.failures[0].agent_outcome = { status, detail };
      if ((status === 'observed') === (detail !== null)) assert.deepEqual(depositDiagnostic(d, 4), d);
      else assert.throws(() => depositDiagnostic(d, 4), /deposit_diagnostics/u);
    }
  }
  const nullable = outcomeDiagnostics(); nullable.failures[0].agent_outcome = null;
  assert.deepEqual(depositDiagnostic(nullable, 4), nullable);
  const mutations = [d => { delete d.failures[0].agent_outcome; }, d => { delete d.failures[0].agent_outcome.detail; },
    d => { d.failures[0].agent_outcome.raw = 'PRIVATE'; }, d => { d.failures[0].agent_outcome.detail.original_request_id = 'PRIVATE'; },
    d => { d.failures[0].agent_outcome.status = 'PRIVATE'; }, d => { d.failures[0].agent_outcome.detail.phase = 'unobserved'; },
    ...['agent_ready', 'authorization', 'signed_request', 'accounting', 'unknown'].map(stage => d => { d.failures[0].stage = stage; }),
    d => { d.version = 3; }];
  for (const mutate of mutations) {
    const d = outcomeDiagnostics(); mutate(d); assert.throws(() => depositDiagnostic(d, 4), /deposit_diagnostics/u);
    const report = publishFailure({ status: 'incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: d } }, 'cloud', 'deposit', false, 5);
    assert.equal(report.publish_observation.deposit_diagnostics_state, 'invalid');
    assert.equal(report.publish_observation.deposit_diagnostics, null); assert.doesNotMatch(JSON.stringify(report), /PRIVATE/u);
  }
});

test('agent outcome phase/deadline matrix preserves actual timeout versus cancellation semantics', () => {
  const phases = ['ready_write', 'local_request_read', 'local_request_verify', 'local_payload_read', 'local_payload_verify',
    'admission', 'remote_request_verify', 'remote_request_write', 'remote_payload_write', 'remote_receipt_read',
    'remote_receipt_verify', 'remote_payload_read', 'remote_payload_verify', 'local_receipt_write', 'local_payload_write',
    'provider_tls_close', 'transport_tls_close', 'final_route_check', 'final_grant_check', 'final_lifetime_check', 'terminal_write'];
  for (const [index, phase] of phases.entries()) for (const category of ['io', 'auth', 'invalid', 'busy', 'store',
    'expired', 'entropy', 'timeout', 'policy', 'unavailable', 'cancelled']) for (const scope of ['none', 'operation', 'exchange', 'bridge', 'remote_wire']) {
    const d = outcomeDiagnostics(); d.failures[0].agent_outcome.detail = { phase, category, deadline_scope: scope };
    const allowed = (category === 'timeout') === (scope !== 'none')
      && (scope !== 'bridge' || (index >= 1 && index <= 14)) && (scope !== 'remote_wire' || (index >= 6 && index <= 12));
    if (allowed) assert.deepEqual(depositDiagnostic(d, 4), d);
    else assert.throws(() => depositDiagnostic(d, 4), /deposit_diagnostics/u);
  }
  const tls = tlsDiagnostics(); tls.version = 4; tls.failures[0].agent_outcome = null;
  assert.deepEqual(depositDiagnostic(tls, 4), tls, 'pre-READY TLS detail remains valid without an outcome claim');
});

test('profile4 binds TLS diagnostic3 to the actual call without changing old profiles', () => {
  for (const app of ['image', 'cloud']) {
    const diagnostic = tlsDiagnostics();
    const value = { status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: diagnostic, private_path: 'SECRET' } };
    const result = publishFailure(value, app, 'deposit', false, 4);
    assert.equal(result.version, 5); assert.equal(result.publish_observation.version, 4);
    assert.deepEqual(result.publish_observation.deposit_diagnostics, diagnostic);
    assert.doesNotMatch(JSON.stringify(result), /SECRET|private_path/u);
    for (const old of [2, 3]) {
      assert.equal(publishFailure(value, app, 'deposit', false, old).publish_observation.deposit_diagnostics_state, 'invalid');
    }
    for (const old of [1, 2]) {
      assert.throws(() => depositDiagnostic(diagnostic, old), /deposit_diagnostics/u);
      const relabeled = structuredClone(diagnostic); relabeled.version = old;
      assert.throws(() => depositDiagnostic(relabeled, old), /deposit_diagnostics/u);
    }
    const complete = { status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: { ...diagnostic, failures: [] } } };
    assert.doesNotThrow(() => requirePublishComplete(complete, app, 'deposit', 4));
    delete complete.storage.deposit_diagnostics;
    assert.equal(publishFailure(complete, app, 'deposit', false, 4).publish_observation.deposit_diagnostics_state, 'missing');
    assert.equal(publishFailure({ status: 'failed' }, app, 'create', false, 4)
      .publish_observation.deposit_diagnostics_state, 'not_applicable');
  }
});

test('TLS classes require the observed handshake with no enclosing deadline and unavailable code', () => {
  for (const tls of ['offer', 'configuration', 'handshake_deadline', 'authentication', 'tls_other', 'io']) {
    for (const stage of ['tls_handshake', 'stream_open', 'challenge', 'unobserved']) {
      for (const scope of ['none', 'operation', 'exchange']) {
        for (const code of ['CONTENT_UNAVAILABLE', 'CONTENT_INVALID', 'CONTENT_BUSY', 'CONTENT_POLICY', 'unknown']) {
          const value = tlsDiagnostics(tls), failure = value.failures[0];
          failure.agent_detail.stage = stage; failure.agent_detail.deadline_scope = scope; failure.agent_code = code;
          if (stage === 'tls_handshake' && scope === 'none' && code === 'CONTENT_UNAVAILABLE') {
            assert.deepEqual(depositDiagnostic(value, 3), value);
          } else assert.throws(() => depositDiagnostic(value, 3), /deposit_diagnostics/u);
        }
      }
    }
  }
  const absent = tlsDiagnostics(null);
  assert.deepEqual(depositDiagnostic(absent, 3), absent);
  absent.failures[0].agent_detail = null;
  assert.deepEqual(depositDiagnostic(absent, 3), absent);
});

test('profile4 rejects missing reserved malformed and raw TLS details without leaking them', () => {
  const mutations = [d => { delete d.failures[0].agent_detail.tls_failure; },
    ...['unobserved', 'PRIVATE', 0, 1, false, [], {}].map(v => d => { d.failures[0].agent_detail.tls_failure = v; }),
    d => { d.failures[0].agent_detail.raw = 'PRIVATE'; }, d => { d.failures[0].stage = 'agent_terminal'; },
    d => { d.failures[0].category = 'io'; d.failures[0].agent_code = null; },
    d => { d.failures.push(structuredClone(d.failures[0])); }, d => { d.omitted_failures = 1; },
    d => { d.failures = Array(9).fill(d.failures[0]); }, d => { d.version = 2; }];
  for (const mutate of mutations) {
    const diagnostic = tlsDiagnostics(); mutate(diagnostic);
    assert.throws(() => depositDiagnostic(diagnostic, 3), /deposit_diagnostics/u);
    const result = publishFailure({ status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: diagnostic } }, 'image', 'deposit', false, 4);
    assert.equal(result.passed, false); assert.equal(result.version, 5);
    assert.equal(result.publish_observation.deposit_diagnostics_state, 'invalid');
    assert.equal(result.publish_observation.deposit_diagnostics, null);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE/u);
  }
  const all = tlsDiagnostics();
  all.failures = Array.from({ length: 8 }, (_, i) => ({ ...all.failures[0], fragment_index: i >> 1, copy_index: i % 2 }));
  assert.equal(depositDiagnostic(all, 3).failures.length, 8);
});

test('profile 3 requires version2 detail without upgrading historical observations', () => {
  for (const app of ['image', 'cloud']) {
    const diagnostic = detailedDiagnostics();
    const value = { status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: diagnostic, raw: '/PRIVATE' } };
    const result = publishFailure(value, app, 'deposit', false, 3);
    assert.equal(result.version, 4); assert.equal(result.publish_observation.version, 3);
    assert.equal(result.publish_observation.deposit_diagnostics_state, 'observed');
    assert.deepEqual(result.publish_observation.deposit_diagnostics, diagnostic);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE|raw/u);
    assert.equal(publishFailure(value, app, 'deposit', false, 2).publish_observation.deposit_diagnostics_state, 'invalid');
    value.storage.deposit_diagnostics = diagnostics();
    assert.equal(publishFailure(value, app, 'deposit', false, 3).publish_observation.deposit_diagnostics_state, 'invalid');
    assert.equal(publishFailure(value, app, 'deposit', false, 2).version, 3);
    assert.equal(publishFailure(value, app, 'deposit', false, 1).version, 2);
    const complete = { status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: detailedDiagnostics([]) } };
    assert.doesNotThrow(() => requirePublishComplete(complete, app, 'deposit', 3));
    delete complete.storage.deposit_diagnostics;
    assert.equal(publishFailure(complete, app, 'deposit', false, 3).publish_observation.deposit_diagnostics_state, 'missing');
    const created = publishFailure({ status: 'failed' }, app, 'create', false, 3);
    assert.equal(created.publish_observation.deposit_diagnostics_state, 'not_applicable');
    assert.equal(created.publish_observation.deposit_diagnostics, null);
  }
});

test('agent details accept only the closed stage and actual deadline matrix', () => {
  const stages = ['unobserved', 'route_connect', 'control_selection', 'provider_lookup',
    'provider_cardinality', 'offer_validity', 'stream_open', 'tls_handshake', 'challenge'];
  for (const stage of stages) for (const scope of ['none', 'operation', 'exchange']) {
    const value = detailedDiagnostics([detailedFailure(stage, scope)]);
    const allowed = (stage !== 'unobserved' || scope === 'operation')
      && (scope !== 'exchange' || ['stream_open', 'tls_handshake', 'challenge'].includes(stage));
    if (allowed) assert.deepEqual(depositDiagnostic(value, 2), value);
    else assert.throws(() => depositDiagnostic(value, 2), /deposit_diagnostics/u);
  }
  for (const code of ['CONTENT_INVALID', 'CONTENT_UNAVAILABLE', 'CONTENT_BUSY', 'CONTENT_POLICY']) {
    const value = detailedDiagnostics([{ ...detailedFailure(), agent_code: code }]);
    assert.deepEqual(depositDiagnostic(value, 2), value);
    value.failures[0].agent_detail.deadline_scope = 'operation';
    if (code === 'CONTENT_UNAVAILABLE') assert.deepEqual(depositDiagnostic(value, 2), value);
    else assert.throws(() => depositDiagnostic(value, 2), /deposit_diagnostics/u);
  }
  const nullDetail = detailedDiagnostics([{ ...transferFailure(), agent_detail: null }]);
  assert.deepEqual(depositDiagnostic(nullDetail, 2), nullDetail);
  const all = Array.from({ length: 8 }, (_, i) => ({ ...detailedFailure(), fragment_index: Math.floor(i / 2), copy_index: i % 2 }));
  assert.equal(depositDiagnostic(detailedDiagnostics(all), 2).failures.length, 8);
});

test('profile3 detail mutations cannot leak raw data or be accepted as success', () => {
  const mutations = [d => { delete d.failures[0].agent_detail; },
    d => { d.failures[0].agent_detail = '/PRIVATE'; }, d => { d.failures[0].agent_detail = []; },
    d => { d.failures[0].agent_detail.raw = '/PRIVATE'; }, d => { delete d.failures[0].agent_detail.stage; },
    d => { d.failures[0].agent_detail.stage = '/PRIVATE'; }, d => { d.failures[0].agent_detail.deadline_scope = '/PRIVATE'; },
    d => { d.failures[0].stage = 'agent_terminal'; }, d => { d.failures[0].category = 'io'; d.failures[0].agent_code = null; },
    d => { d.failures[0].agent_code = 'unknown'; }, d => { d.version = 1; },
    d => { d.failures.push(structuredClone(d.failures[0])); }, d => { d.omitted_failures = 1; },
    d => { d.failures = Array(9).fill(d.failures[0]); }];
  for (const mutate of mutations) {
    const value = detailedDiagnostics(); mutate(value);
    assert.throws(() => depositDiagnostic(value, 2), /deposit_diagnostics/u);
    const result = publishFailure({ status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: value } }, 'cloud', 'deposit', false, 3);
    assert.equal(result.version, 4); assert.equal(result.publish_observation.deposit_diagnostics_state, 'invalid');
    assert.equal(result.publish_observation.deposit_diagnostics, null);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE/u);
  }
});

test('explicit profile 2 retains bounded actual-call transfer context without raw bridge output', () => {
  for (const app of ['image', 'cloud']) {
    const value = { status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: diagnostics(), private_path: 'SECRET' } };
    const result = publishFailure(value, app, 'deposit', false, 2);
    assert.equal(result.version, 3);
    assert.deepEqual(result.publish_observation, { version: 2, app, operation: 'deposit', status: 'incomplete',
      code: 'retained_operation_incomplete', local_process_joined: true, core_report_present: true,
      core_operation_complete: false, deposit_diagnostics_state: 'observed', deposit_diagnostics: diagnostics() });
    assert.doesNotMatch(JSON.stringify(result), /SECRET|private_path/u);
    assert.equal(publishFailure(value, app).version, 2);
  }
  const rejected = { ...transferFailure(), category: 'agent_rejected', agent_code: 'CONTENT_POLICY' };
  assert.deepEqual(depositDiagnostic(diagnostics([rejected])).failures, [rejected]);
  const all = Array.from({ length: 8 }, (_, i) => ({ ...transferFailure(), fragment_index: Math.floor(i / 2), copy_index: i % 2 }));
  assert.equal(depositDiagnostic(diagnostics(all)).failures.length, 8);
});

test('profile 2 does not call missing malformed or contradictory diagnostic a successful deposit', () => {
  const complete = { status: 'complete', code: 'ok', local_process_joined: true,
    storage: { operation_complete: true, deposit_diagnostics: diagnostics([]) } };
  assert.doesNotThrow(() => requirePublishComplete(complete, 'cloud', 'deposit', 2));
  assert.doesNotThrow(() => requirePublishComplete({ status: 'complete', local_process_joined: true }, 'image', 'create', 2));
  for (const [value, state] of [[{ ...complete, storage: { operation_complete: true } }, 'missing'],
    [{ ...complete, storage: { ...complete.storage, deposit_diagnostics: diagnostics() } }, 'invalid'],
    [{ ...complete, storage: { ...complete.storage, operation_complete: false } }, 'invalid']]) {
    const result = publishFailure(value, 'cloud', 'deposit', false, 2);
    assert.equal(result.publish_observation.deposit_diagnostics_state, state);
    assert.equal(result.publish_observation.deposit_diagnostics, null);
    assert.equal(result.passed, false);
  }
  const created = publishFailure({ status: 'failed', code: 'core_failed' }, 'image', 'create', false, 2);
  assert.equal(created.publish_observation.deposit_diagnostics_state, 'not_applicable');
  assert.equal(created.publish_observation.deposit_diagnostics, null);
});

test('deposit diagnostics reject oversized duplicate forged and private fields without echoing them', () => {
  const mutations = [d => { d.version = true; }, d => { d.omitted_failures = 1; },
    d => { d.failures = Array(9).fill(transferFailure()); }, d => { d.failures.push(transferFailure()); },
    d => { d.raw = 'SECRET'; }, d => { d.failures[0].raw = 'SECRET'; },
    d => { d.failures[0].fragment_index = 4; }, d => { d.failures[0].copy_index = 2; },
    d => { d.failures[0].operation = '/SECRET'; }, d => { d.failures[0].stage = '/SECRET'; },
    d => { d.failures[0].category = '/SECRET'; }, d => { d.failures[0].agent_code = 'CONTENT_POLICY'; },
    d => { d.failures[0].category = 'agent_rejected'; },
    d => { d.failures[0].category = 'agent_rejected'; d.failures[0].agent_code = 'SECRET'; }];
  for (const mutate of mutations) {
    const value = diagnostics(); mutate(value);
    assert.throws(() => depositDiagnostic(value), /deposit_diagnostics/u);
    const report = publishFailure({ status: 'incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: value } }, 'cloud', 'deposit', false, 2);
    assert.equal(report.publish_observation.deposit_diagnostics_state, 'invalid');
    assert.equal(report.publish_observation.deposit_diagnostics, null);
    assert.doesNotMatch(JSON.stringify(report), /SECRET/u);
  }
});

test('publish rejection identifies the exact app and operation with closed bridge observations', () => {
  for (const app of ['image', 'cloud']) for (const operation of ['create', 'deposit']) {
    const result = publishFailure({ status: 'incomplete', code: 'retained_operation_incomplete',
      local_process_joined: true, storage: { operation_complete: false, private_key: 'DO-NOT-EXPORT' } }, app, operation);
    assert.equal(result.version, 2);
    assert.equal(result.passed, false);
    assert.equal(result.cleanup_confirmed, false);
    assert.deepEqual(result.publish_observation, { version: 1, app, operation,
      status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      core_report_present: true, core_operation_complete: false });
    assert.ok(!JSON.stringify(result).includes('DO-NOT-EXPORT'));
  }
  assert.doesNotThrow(() => requirePublishComplete({ status: 'complete', local_process_joined: true }, 'cloud', 'create'));
  assert.throws(() => requirePublishComplete({}, '/private/path', 'deposit'), /arguments/u);
  assert.throws(() => requirePublishComplete({}, 'image', 'delete'), /arguments/u);
});

test('publish diagnostic maps unfamiliar data to unknown without treating a join as success', () => {
  const result = publishFailure({ status: '/private/status', code: 'SECRET-CODE', local_process_joined: 1,
    storage: { operation_complete: 'SECRET-COMPLETE' }, stderr: 'SECRET-STDERR' });
  assert.deepEqual(result.publish_observation, { version: 1, app: 'cloud', operation: 'deposit',
    status: 'unknown', code: 'unknown', local_process_joined: null, core_report_present: true,
    core_operation_complete: null });
  assert.doesNotMatch(JSON.stringify(result), /private|SECRET/u);
  assert.equal(publishFailure({ status: 'complete', code: 'ok', local_process_joined: false })
    .publish_observation.local_process_joined, false);
  for (const value of [null, undefined, false, 'SECRET', { storage: ['SECRET'] }]) {
    const current = publishFailure(value);
    assert.equal(current.publish_observation.core_report_present, false);
    assert.equal(current.publish_observation.core_operation_complete, null);
    assert.doesNotMatch(JSON.stringify(current), /SECRET/u);
  }
});

test('cancellation and unrelated exceptions cannot inherit or fabricate a publish observation', () => {
  const ctx = { provision: 'a'.repeat(64), stage: 'cloud_publish', signal: { aborted: false } };
  const forged = Object.assign(new Error('PRIVATE'), { code: 'publish_operation', observation: { secret: 'PRIVATE' } });
  const report = consumerFailureReport(ctx, 'publish', forged);
  assert.equal(report.version, 1);
  assert.equal(Object.hasOwn(report, 'publish_observation'), false);
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE/u);
  const cancelled = publishFailure({ status: 'cancelled', code: 'cancelled', local_process_joined: true }, 'image', 'create', true);
  assert.equal(cancelled.code, 'phase_deadline');
  assert.equal(cancelled.publish_observation.status, 'cancelled');
});

test('four explicit phases and distinct deterministic incompressible fixture identities', () => {
  assert.deepEqual(PHASES, ['prepare', 'publish', 'exercise', 'finish']);
  const image = fixtureBytes('image'), cloud = fixtureBytes('cloud');
  assert.equal(image.length, PLAIN_BYTES); assert.equal(cloud.length, PLAIN_BYTES);
  assert.ok(PLAIN_BYTES < MAX_CIPHER);
  assert.equal(hash(image), hash(fixtureBytes('image')));
  assert.notEqual(hash(image), hash(cloud));
  assert.notDeepEqual(image.subarray(0, 4096), image.subarray(4096, 8192));
  assert.throws(() => fixtureBytes('other'), /fixture_label/u);
});

test('same-fd private reads admit exact boundary and reject oversize, writable and symlink inputs', async t => {
  const root = await mkdtemp(join(tmpdir(), 'storage-consumer-inert-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'owned.json');
  await writeFile(path, 'abcd', { mode: 0o600 });
  assert.equal((await boundedFile(path, 4)).toString(), 'abcd');
  await assert.rejects(boundedFile(path, 3), /private_file/u);
  await chmod(path, 0o644); await assert.rejects(boundedFile(path, 4), /private_file/u);
  await chmod(path, 0o600); await symlink(path, join(root, 'link'));
  await assert.rejects(boundedFile(join(root, 'link'), 4));
});

test('checkpoint validates authority scope and closed stage/cursor bounds', () => {
  const cp = { version: 1, scope: 'owner-private-maintenance', stage: 'working', turns: 3, at: 1,
    core_coordinated: true, new_network_node: false, automatic_grant_refresh: false, private_key_exported: false };
  assert.deepEqual(validateCheckpoint(cp), { stage: 'working', turns: 3 });
  for (const delta of [{ turns: 4097 }, { turns: -1 }, { stage: 'arbitrary' }, { automatic_grant_refresh: true },
    { new_network_node: true }, { private_key_exported: true }, { core_coordinated: false }]) {
    assert.throws(() => validateCheckpoint({ ...cp, ...delta }), /checkpoint/u);
  }
});

test('repair readiness requires both surviving providers and preserved unavailable-source charge', () => {
  assert.equal(replacementReady(repaired(), keys), true);
  for (const mutate of [r => r.pop(), r => r[0].copies.pop(), r => { r[0].copies[0].charge = 'deleted'; },
    r => { r[0].copies[1].provider_key = [...Buffer.from(keys[0], 'hex')]; },
    r => { r[0].handoff.phase = 'copying'; }, r => { r[1].copies[0].charge = 'uncertain'; }]) {
    const value = repaired(); mutate(value); assert.equal(replacementReady(value, keys), false);
  }
});

test('public repair summary retains all eleven copies and the unavailable provider charge', () => {
  const selected = validateStorage(storage(), 100, 'repaired', 75);
  assert.equal(selected.physical_payload_charge_upper_bound, 275);
  assert.equal(selected.pending_retirements, 3);
  assert.equal(selected.retained_copy_records, 11);
  assert.ok(!Object.keys(selected).some(k => /key|archive|grant|path/u.test(k)));
  for (const field of ['pending_retirements', 'retained_copy_records', 'uncertain_payload_bytes',
    'placement_authorizations', 'committed_payload_bytes', 'fragment_count']) {
    const value = storage(); value.storage[field] = 0;
    assert.throws(() => validateStorage(value, 100, 'repaired', 75));
  }
  const noJoin = storage(); noJoin.local_process_joined = false;
  assert.throws(() => validateStorage(noJoin, 100, 'repaired', 75));
});

test('cleanup does not turn incomplete or zero-byte replacement claims into all-copy deletion', () => {
  assert.equal(validateStorage(storage('deleted'), 100, 'deleted').physical_payload_charge_upper_bound, 0);
  for (const mutate of [r => { r.status = 'incomplete'; }, r => { r.storage.operation_complete = false; },
    r => { r.storage.uncertain_payload_bytes = 1; }, r => { r.storage.retained_copy_records = 8; }]) {
    const value = storage('deleted'); mutate(value); assert.throws(() => validateStorage(value, 100, 'deleted'));
  }
  assert.throws(() => validateStorage(storage('published'), 100, 'unknown'), /storage_kind/u);
});

test('observation requires actual overlap window: paused checkpoint, active restore and absent owner', () => {
  const valid = new ForegroundObservation('10:20', 3);
  valid.sample([{ id: '11:21', kind: 'restore' }], { stage: 'paused', turns: 3 });
  const report = valid.finish({ owner: '12:22', turns: 4 });
  assert.equal(report.observed_old_owner_absent_while_foreground_active, true);
  assert.equal(report.exact_join_before_spawn_measured, false);
  assert.ok(!JSON.stringify(report).includes('10:20'));
  for (const [children, cp] of [[[], { stage: 'paused', turns: 3 }],
    [[{ id: '11:21', kind: 'restore' }, { id: '10:20', kind: 'owner' }], { stage: 'paused', turns: 3 }],
    [[{ id: '11:21', kind: 'restore' }], { stage: 'working', turns: 3 }]]) {
    const absent = new ForegroundObservation('10:20', 3); absent.sample(children, cp);
    assert.throws(() => absent.finish({ owner: '12:22', turns: 4 }), /foreground_observation_missing/u);
  }
  assert.throws(() => valid.finish({ owner: '10:20', turns: 4 }));
  assert.throws(() => valid.finish({ owner: '12:22', turns: 3 }));
});

test('retention progress needs original copy identity, committed full bytes and unexpired finite bound', () => {
  const before = Array.from({ length: 8 }, (_, i) => ({ identity: hash(String(i)), last_expiry: 100,
    last_state: 3, last_stored_bytes: 25, ciphertext_bytes: 25 }));
  assert.equal(retentionAdvanced(before, structuredClone(before), 200), 0);
  const after = structuredClone(before); after[0].last_expiry = 150;
  assert.equal(retentionAdvanced(before, after, 200), 1);
  after[0].last_state = 4; assert.equal(retentionAdvanced(before, after, 200), 0);
  after[0].last_state = 3; after[0].last_stored_bytes = 24;
  assert.equal(retentionAdvanced(before, after, 200), 0);
  after[0].last_stored_bytes = 25;
  assert.throws(() => retentionAdvanced(before, after, 149), /retention_identity/u);
  after[0].identity = hash('changed'); assert.throws(() => retentionAdvanced(before, after, 200), /retention_identity/u);
  after[0].identity = before[0].identity; after[0].last_expiry = 99;
  assert.throws(() => retentionAdvanced(before, after, 200), /retention_identity/u);
});

test('post-resume atomic journal replacement retries only inside the original budget', async () => {
  const cancel = new AbortController(), ctx = { signal: cancel.signal, deadline: performance.now() + 1000 };
  let reads = 0;
  assert.deepEqual(await retainedSnapshot(ctx, async () => {
    if (++reads === 1) throw Object.assign(new Error('changed'), { code: 'input_changed' });
    return [{ last_expiry: 100 }];
  }), [{ last_expiry: 100 }]);
  assert.equal(reads, 2);
  await assert.rejects(retainedSnapshot(ctx, async () => { throw Object.assign(new Error('bad mode'), { code: 'private_file' }); }), /bad mode/u);
  const deadline = ctx.deadline;
  cancel.abort();
  await assert.rejects(retainedSnapshot(ctx, async () => []), /phase_deadline/u);
  assert.equal(ctx.deadline, deadline);
});

test('proc identity parsing uses field22 even when process name contains spaces and parentheses', () => {
  const suffix = ['S', ...Array(18).fill('0'), '12345', '999'].join(' ');
  assert.equal(parseProcStat(`25 (name with ) parentheses) ${suffix}`), '12345');
  assert.throws(() => parseProcStat('malformed'), /proc_record/u);
  assert.throws(() => parseProcStat('25 (bad) S 1'), /proc_record/u);
});

test('entrypoint preserves actual app APIs, no runtime injection or reenrollment during exercise', async () => {
  const source = await readFile(new URL('./storage-consumer-maintenance.mjs', import.meta.url), 'utf8');
  const exercise = source.slice(source.indexOf('async function exercise('), source.indexOf('async function finish('));
  assert.match(exercise, /m\.runSnapshotStorage\(\{ operation: 'restore'/u);
  assert.match(exercise, /python\(\['restore'/u);
  assert.match(exercise, /m\.startCloudService/u);
  assert.match(exercise, /storageMaintenance: \[\{ config: join\(app, 'storage.json'\)/u);
  assert.match(exercise, /for await \(const chunk of dav\.streamFile\(selected\)\)/u);
  assert.match(exercise, /negativeAuthorization/u);
  assert.doesNotMatch(exercise, /enrollMaintenance|storePrivateFile|\.deposit\(|\.create\(|spawnProcess|openMaintenance:/u);
  assert.doesNotMatch(source, /npm|sudo|execSync|shell: true/u);
});
