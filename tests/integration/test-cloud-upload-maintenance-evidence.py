#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic closed evidence tests only; no app, GPG, core or network execution."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'cloud-upload-maintenance-evidence.py'))
APP = runpy.run_path(str(HERE / 'test-cloud-upload-maintenance-smoke.py'))
PREVIOUS = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-evidence.py'))
MAINTENANCE = runpy.run_path(str(HERE / 'test-private-storage-maintenance-smoke.py'))


def fixture(retired=(), *, changed=True):
    previous = PREVIOUS['fixture']()
    PREVIOUS['attach_transition'](previous, changed=changed)
    pins = M['PROVISIONER']['load_pins']()
    provision = dict(version=1, kind='cloud-upload-maintenance-runtime-provision', success=True,
        pins=pins, pins_sha256=hashlib.sha256(M['PROVISIONER']['PINS'].read_bytes()).hexdigest(),
        previous_consumer_provision_sha256=previous['provision_sha256'], tools=copy.deepcopy(previous['provision']['tools']),
        **dict.fromkeys(M['PROVISIONER']['TRUE_FLAGS'], True), **dict.fromkeys(M['PROVISIONER']['FALSE_FLAGS'], False))
    digest = hashlib.sha256(M['encoded'](provision)).hexdigest()
    value = dict(schema_version=2, kind='cloud-upload-maintenance-evidence', success=True,
        scope=dict(M['SCOPE']), previous_consumers=previous, provision=provision, provision_sha256=digest)
    for phase in ('prepare', *M['PHASES']):
        node = APP['report'](phase, retired)
        node['provision_sha256'] = digest
        receipt = dict(version=1, kind='cloud-upload-maintenance-orchestration', phase=phase, passed=True,
            node=node, node_report_sha256=hashlib.sha256(json.dumps(node).encode()).hexdigest(),
            provision_sha256=digest, node_joined=True, protected_flow_proven=phase != 'prepare')
        if phase == 'prepare':
            receipt['authority'] = dict(fresh_owner_created=True, owner_distinct_from_providers=True,
                grant_payload_bytes=[1048576] * 3, grant_max_leases=[4] * 3, grant_retention_seconds=7200,
                grant_lifetime_seconds=7200, reserved_credit=0, enrollment_created=False, automatic_grant_refresh=False,
                policy_expires_at=2000000000, policy_lifetime_seconds=3600, policy_maximum_charge=3145728,
                policy_max_sessions=1, service_config_sha256='1' * 64, storage_template_sha256='2' * 64)
        else:
            receipt.update(minimum_protected_completions=M['APP']['flow_minimum'](phase, APP['report']('upload', retired)), sampler_joined=True,
                remote_cleanup_independently_proven=False)
        value[phase] = receipt
    value.update({k: copy.deepcopy(previous[k]) for k in ('layout', 'isolation', 'expected_peers')})
    value['upload_isolation'] = copy.deepcopy(previous['consumer_isolation'])
    upload = value['upload']['node']
    value.update(initial_usage=copy.deepcopy(previous['deleted_usage']),
        uploaded_usage=M['custody_usage'](upload, withdrawn=False), restored_usage=M['custody_usage'](upload, withdrawn=True),
        deleted_usage=copy.deepcopy(previous['deleted_usage']),
        withdrawal=dict(first_provider_stopped_after_measured_upload_baseline=True,
            first_provider_stopped_before_new_repair_and_reads=True, first_store_retained=True,
            other_two_providers_serving=True, same_three_stores_reopened=True,
            all_usage_snapshots_with_services_stopped=True, all_three_store_inodes_preserved=True),
        private_cleanup=dict(previous['private_cleanup'], kind='cloud-upload-maintenance-cleanup'), network={})
    repair = sum(M['APP']['geometry'](upload['cipher_bytes'])[i] for i in (0, 2, 3) if i not in retired)
    for name in M['PHASES']:
        minimum = M['APP']['flow_minimum'](name, upload)
        network = copy.deepcopy(previous['network']['exercise' if name == 'exercise' else 'publish'])
        gates = network['gates']
        gates.update(exit_mptcp_tls_completed=minimum, exit_log_records=minimum + 1,
            exit_log_observed_records=minimum + 1)
        gates['exit_flow_contexts'][0]['completed'] = minimum
        if name == 'exercise':
            for provider in M['NODES'][1:]:
                network['privacy']['exit']['provider_application'][provider]['response_payload_bytes'] = repair + upload['cipher_bytes']
        value['network'][name] = network
    return value


def write_evidence(root, value):
    PREVIOUS['write_evidence'](root, value['previous_consumers'])
    def write(name, data):
        (root / name).write_bytes(M['encoded'](data))
        (root / name).chmod(0o600)
    write('storage-consumer-evidence.json', value['previous_consumers'])
    original = MAINTENANCE['fixture']()
    for name in ('expected_peers', 'layout', 'isolation'):
        original[name] = copy.deepcopy(value[name])
    PREVIOUS['attach_transition'](original,
        changed=value['previous_consumers']['control_transition']['relation'] == 'different', consumer=False)
    write('private-storage-maintenance-smoke.json', dict(MAINTENANCE['report'](original),
        schema_version=4, run_id='a' * 32, consumers=value['previous_consumers']))
    for name in ('provision', 'prepare', *M['PHASES'], 'withdrawal'):
        write(f'cloud-upload-{name}.json', value[name])
    write('cloud-upload-private-cleanup.json', value['private_cleanup'])
    write('cloud-upload-isolation.json', value['upload_isolation'])
    for name in ('uploaded', 'restored', 'deleted'):
        write(f'private-storage-fragments-cloud_upload_{name}_usage.json', value[name + '_usage'])
    for name, phase in value['network'].items():
        for field, suffix in (('layout', 'layout'), ('selected_route', 'live-selection'), ('gates', 'gates')):
            write(f'private-storage-fragments-cloud-upload-{name}-{suffix}.json', phase[field])
        write(f'content-provider-adaptive-private-storage-fragments-cloud-upload-{name}-control.json', phase['control_privacy'])
        for role, capture in phase['privacy'].items():
            write(f'private-storage-fragments-cloud-upload-{name}-privacy-{role}.json', capture)


class Evidence(unittest.TestCase):
    def reject(self, mutate, pattern='.'):
        value = fixture((0,))
        mutate(value)
        with self.assertRaisesRegex(ValueError, pattern):
            M['validate_evidence'](value)

    def test_exact_raw_builder_cli_and_export_union(self):
        value = fixture((0, 2))
        self.assertEqual(M['validate_evidence'](value), value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            self.assertEqual(M['build_evidence'](root), value)
            exports = set(M['EXPORT_NAMES']) | set(M['OLD']['EXPORT_NAMES'])
            self.assertEqual(exports - {'cloud-upload-evidence.json', 'cloud-upload-maintenance-smoke.json'}, {p.name for p in root.iterdir()})
            self.assertEqual(len(M['EXPORT_NAMES']), len(set(M['EXPORT_NAMES'])))
            output = root / 'cloud-upload-evidence.json'
            for args in (['evidence', str(root), str(output)], ['check', str(output)]):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'), *args],
                    capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_bytes()), value)
            (root / 'private-storage-fragments-cloud-upload-exercise-layout.json').unlink()
            with self.assertRaises(FileNotFoundError):
                M['build_evidence'](root)

    def test_previous_proof_and_raw_records_remain_mandatory(self):
        self.reject(lambda v: v['previous_consumers']['finish'].update(passed=False))
        self.reject(lambda v: v['provision'].update(previous_consumer_provision_sha256='0' * 64))
        self.reject(lambda v: v['provision']['pins']['sources']['cloud'].update(revision='0' * 40))
        self.reject(lambda v: v['isolation'].update(agent_uid=123))
        value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            old = root / 'storage-consumer-finish.json'
            modified = json.loads(old.read_bytes())
            modified['node_report_sha256'] = '0' * 64
            old.write_bytes(M['encoded'](modified))
            with self.assertRaisesRegex(ValueError, 'previous_raw_binding'):
                M['build_evidence'](root)

    def test_all_cloud_phases_bind_current_broker_without_rewriting_original_upload(self):
        for changed in (False, True):
            value = fixture(changed=changed)
            original = copy.deepcopy(value['layout'])
            self.assertEqual(M['validate_evidence'](value), value)
            self.assertEqual(value['layout'], original)
            transition = value['previous_consumers']['control_transition']
            self.assertEqual(value['layout']['control_relay_peer_id'], transition['previous_control_relay_peer_id'])
            digest = hashlib.sha256(M['OLD']['canonical'](transition)).hexdigest()
            for phase in M['PHASES']:
                self.assertEqual(value['network'][phase]['layout']['control_transition_sha256'], digest)
                invalid = copy.deepcopy(value)
                invalid['network'][phase]['layout']['control_transition_sha256'] = '0' * 64
                with self.assertRaisesRegex(ValueError, 'upload_phase_transition'):
                    M['validate_evidence'](invalid)
                invalid = copy.deepcopy(value)
                del invalid['network'][phase]['layout']['control_transition_sha256']
                with self.assertRaises(ValueError): M['validate_evidence'](invalid)
                if changed:
                    invalid = copy.deepcopy(value)
                    node = next(node for node in M['ROLES'][1:4]
                        if value['expected_peers'][node] == original['control_relay_peer_id'])
                    pairs = invalid['network'][phase]['control_privacy']['content_control_pairs']
                    for pair in pairs.values(): pair[0] = M['NET']['PUBLIC_IPS'][node]
                    with self.assertRaisesRegex(ValueError, 'upload_control_boundary'):
                        M['validate_evidence'](invalid)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_evidence(root, value)
                self.assertEqual(M['build_evidence'](root), value)
                maintenance = json.loads((root / 'private-storage-maintenance-smoke.json').read_bytes())
                self.assertEqual(maintenance['schema_version'], 4)
                self.assertEqual(maintenance['maintenance']['layout'], original)
                self.assertNotIn('control_transition_sha256', maintenance['maintenance']['network']['upload']['layout'])
                self.assertEqual(maintenance['consumers']['control_transition'], transition)

    def test_old_profiles_or_replaced_transition_cannot_satisfy_current_acceptance(self):
        self.reject(lambda value: value.update(schema_version=1), 'upload_evidence_identity')
        self.reject(lambda value: value['previous_consumers'].update(schema_version=1))
        self.reject(lambda value: value['layout'].update(control_relay_peer_id=
            value['previous_consumers']['control_transition']['current_control_relay_peer_id']), 'upload_previous_fixture_binding')
        value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            path = root / M['OLD']['TRANSITION_NAME']
            replacement = fixture(changed=False)['previous_consumers']['control_transition']
            path.write_bytes(M['OLD']['canonical'](replacement))
            with self.assertRaises(ValueError): M['build_evidence'](root)

    def test_absolute_shared_authority_and_source_only_ordering_claim(self):
        for mutate in (
            lambda v: v['prepare']['authority'].update(policy_expires_at=2000000001),
            lambda v: v['prepare']['authority'].update(policy_max_sessions=2),
            lambda v: v['prepare']['authority'].update(policy_maximum_charge=4000000),
            lambda v: v['prepare']['authority'].update(enrollment_created=True),
            lambda v: v['scope'].update(io_ordering_measured=True),
            lambda v: v['scope'].update(opencloud_account_server_proven=True),
            lambda v: v['upload'].update(provision_sha256='0' * 64),
            lambda v: v['upload']['node'].update(ready_observed=False)):
            self.reject(mutate)

    def test_exact_independent_baseline_and_conservative_stopped_a_charge(self):
        for retired in ((), (0,), (2,), (3,), (0, 2), (0, 3), (2, 3)):
            value = fixture(retired)
            M['validate_evidence'](value)
            self.assertEqual(value['uploaded_usage'][0]['leases'], 3 - len(retired))
            self.assertEqual(value['restored_usage'][0], value['uploaded_usage'][0])
            self.assertEqual([x['committed_bytes'] for x in value['restored_usage'][1:]], [800001] * 2)
            self.assertEqual([x['leases'] for x in value['restored_usage'][1:]], [4] * 2)
        for phase in ('initial', 'uploaded', 'restored', 'deleted'):
            for index in range(3):
                for field in ('reserved_bytes', 'committed_bytes', 'leases'):
                    self.reject(lambda v: v[phase + '_usage'][index].update(
                        {field: v[phase + '_usage'][index][field] + 1}))

    def test_new_network_scope_not_old_phase_or_tcp_or_unsampled_route(self):
        for phase in M['PHASES']:
            minimum = M['APP']['flow_minimum'](phase, APP['report']('upload', (0,)))
            self.reject(lambda v: v[phase].update(minimum_protected_completions=minimum - 1))
            self.reject(lambda v: v['network'][phase]['gates'].update(exit_mptcp_tls_completed=minimum - 1))
            self.reject(lambda v: v['network'][phase]['gates'].update(exit_log_sampler_joined=False))
            self.reject(lambda v: v['network'][phase]['selected_route'].update(transport='tcp'))
            self.reject(lambda v: v['network'][phase]['layout']['route_scope'].update(exit_peer_id='other'))

    def test_two_reads_plus_only_remaining_repair_bytes_and_honest_failed_flows(self):
        value = fixture((0, 2))
        network = value['network']['exercise']
        application = network['privacy']['exit']['provider_application']
        # Deliberately below the original full A-copy bytes: only fragment3
        # remains to repair after withdrawal. Exact two full reads remain due.
        repair = M['APP']['geometry'](800001)[3]
        self.assertEqual(application[M['NODES'][1]]['response_payload_bytes'], repair + 800001)
        gates = network['gates']
        gates.update(exit_mptcp_tls_failed=3, exit_log_observed_records=20)
        gates['exit_flow_contexts'][0]['failed'] = 3
        M['validate_evidence'](value)
        application[M['NODES'][2]]['response_payload_bytes'] -= 1
        with self.assertRaisesRegex(ValueError, 'survivor_payload'):
            M['validate_evidence'](value)
        self.reject(lambda v: v['network']['exercise']['privacy']['exit']['provider_application'][M['NODES'][0]].update(response_payload_bytes=1))
        self.reject(lambda v: v['network']['exercise']['privacy']['client'].update(direct_client_exit_packets=1))
        self.reject(lambda v: v['network']['upload']['control_privacy']['provider_application'][M['NODES'][0]].update(request_packets=1))

    def test_new_owner_mount_denial_and_actual_all_zero_delete_not_old_probe(self):
        for field in ('client_cannot_read_new_owner_root', 'agent_mount_positive_control', 'client_cannot_read_any_provider_store'):
            self.reject(lambda v: v['upload_isolation'].update({field: False}))
        self.reject(lambda v: v['withdrawal'].update(first_provider_stopped_after_measured_upload_baseline=False))
        self.reject(lambda v: v['private_cleanup'].update(remote_cleanup_confirmed=True))
        self.reject(lambda v: v['private_cleanup'].update(removed_files=512))
        self.reject(lambda v: v['finish']['node'].update(all_retained_copies_delete_acknowledged=False))

    def test_compact_terminal_report_requires_both_original_byte_bound_proofs(self):
        value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            upload = root / 'cloud-upload-evidence.json'
            upload.write_bytes(M['encoded'](value)); upload.chmod(0o600)
            output = root / 'cloud-upload-maintenance-smoke.json'
            result = M['final_report'](root, '1' * 40, 'a' * 32, 'private-storage-maintenance-complete', 0, True, 0, 'NONE')
            self.assertTrue(result['success'])
            self.assertLess(len(M['encoded'](result)), 4096)
            self.assertNotIn('previous_consumers', result)
            output.write_bytes(M['encoded'](result)); output.chmod(0o600)
            self.assertEqual(M['check_report'](output, '1' * 40), result)
            check = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                'check-report', str(output), '1' * 40], capture_output=True, timeout=15)
            self.assertEqual(check.returncode, 0, check.stderr)
            # Same semantic report with different bytes is not the original.
            upload.write_bytes(M['encoded'](value) + b'\n')
            with self.assertRaisesRegex(ValueError, 'original_report_hash'):
                M['check_report'](output, '1' * 40)
            upload.unlink()
            failed = M['final_report'](root, '1' * 40, 'a' * 32, 'cloud-upload-exercise', 1, False, 2, 'CLOUD_UPLOAD_APPLICATION_FAILED')
            self.assertFalse(failed['success'])
            self.assertEqual(failed['runner_exit_status'], 1)
            self.assertEqual(failed['observed_blocker'], 'CLOUD_UPLOAD_APPLICATION_FAILED')
            self.assertFalse(failed['cleanup']['complete'])
            self.assertIsNone(failed['upload_evidence_sha256'])


if __name__ == '__main__':
    unittest.main()
