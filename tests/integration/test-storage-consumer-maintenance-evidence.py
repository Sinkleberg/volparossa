#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert raw-evidence fixtures; no consumer, core, key, tool or network execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-consumer-maintenance-evidence.py'))
APP = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-smoke.py'))
OLD = runpy.run_path(str(HERE / 'test-private-storage-fragments-smoke.py'))


def fixture():
    """Complete *synthetic* input for parent aggregate tests, never live proof."""
    pins = M['PROVISIONER']['load_pins']()
    provision = dict(version=1, kind='storage-consumer-maintenance-runtime-provision', success=True,
        pins=pins, pins_sha256=hashlib.sha256(M['PROVISIONER']['PINS'].read_bytes()).hexdigest(),
        tools={name: dict(package=name, package_version='1.0-1', bytes=1234, sha256='a' * 64)
            for name in ('gpg', 'gpg-agent', 'gpgconf', 'tar')},
        guest_only=True, source_files_verified=True, runtime_files_verified=True, shared_adapter_verified=True,
        original_licenses_retained=True, storage_enrollment_created=False, peer_storage_proven=False,
        application_restore_proven=False, sdk_or_browser_provisioned=False, immich_or_opencloud_server_started=False)
    digest = hashlib.sha256(M['encoded'](provision)).hexdigest()
    prepared = APP['prepared']()
    prepared['provision_sha256'] = digest
    value = dict(schema_version=1, kind='storage-consumer-maintenance-evidence', success=True,
        scope=dict(M['SCOPE']), provision=provision, provision_sha256=digest)
    for phase in ('prepare', *M['PHASES']):
        node = prepared if phase == 'prepare' else APP['report'](phase)
        node['provision_sha256'] = digest
        receipt = dict(version=1, kind='storage-consumer-maintenance-orchestration', phase=phase,
            passed=True, node=node, node_report_sha256=hashlib.sha256(json.dumps(node).encode()).hexdigest(),
            provision_sha256=digest, node_joined=True, protected_flow_proven=phase != 'prepare')
        if phase == 'prepare':
            receipt['authority'] = {app: dict(fresh_owner_created=True, owner_distinct_from_providers=True,
                grant_payload_bytes=[prepared[app]['cipher_bytes']] * 3, grant_max_leases=[4] * 3,
                grant_retention_seconds=7200, grant_lifetime_seconds=7200, reserved_credit=0,
                enrollment_created=False, policy_authorization_seconds=6000, policy_lifetime_seconds=3600,
                policy_maximum_charge=3 * prepared[app]['cipher_bytes'], automatic_grant_refresh=False) for app in M['APPS']}
        else:
            receipt.update(minimum_protected_completions=M['PHASES'][phase], sampler_joined=True,
                remote_cleanup_independently_proven=False)
        value[phase] = receipt
    old = OLD['fixture']()
    value.update({k: copy.deepcopy(old[k]) for k in ('layout', 'isolation', 'expected_peers')})
    value['consumer_isolation'] = dict(user_uid=value['isolation']['user_uid'], agent_uid=value['isolation']['agent_uid'],
        agent_mount_positive_control=True, client_cannot_read_new_owner_root=True, client_cannot_read_any_provider_store=True)
    total, amounts, repair = M['geometry'](prepared)
    def usage(amounts, counts):
        return [dict(reserved_bytes=0, committed_bytes=amount, leases=count) for amount, count in zip(amounts, counts)]
    value.update(initial_usage=usage([0] * 3, [0] * 3), uploaded_usage=usage(amounts, [6, 6, 4]),
        restored_usage=usage([amounts[0], total, total], [6, 8, 8]), deleted_usage=usage([0] * 3, [0] * 3),
        withdrawal=dict(first_provider_stopped_before_repair_and_read=True, first_store_retained=True,
            other_two_providers_serving=True, same_three_stores_reopened=True,
            all_usage_snapshots_with_services_stopped=True, all_three_store_inodes_preserved=True),
        private_cleanup=dict(version=1, kind='storage-consumer-maintenance-cleanup', passed=True,
            local_fixture_removed=True, no_owned_fixture_process_observed=True, removed_files=30, removed_directories=15,
            remote_cleanup_confirmed=False, provider_usage_proven=False), network={})
    for name, minimum in M['PHASES'].items():
        phase = copy.deepcopy(old['network']['upload'])
        selected = phase['selected_route']
        selected.update(exact_selected_exit=selected['paths'][0]['exit_peer_id'],
            exact_selected_relays=[p['relay_peer_id'] for p in selected['paths']])
        for path, slot in zip(selected['paths'], selected['benchmark_slots']):
            path['state'] = 1
            slot['path_id'] = path['path_id']
        scope = M['SAMPLER']['route_scope'](selected)
        phase['layout'] = dict(route_scope=copy.deepcopy(scope))
        gates = phase['gates']
        gates.update(exit_mptcp_tls_completed=minimum, exit_log_records=minimum + 1,
            exit_log_sampling_version=2, exit_log_samples=2, exit_log_observed_records=minimum + 1,
            exit_log_overlap_verified=True, exit_log_sampler_joined=True, exit_route_scope=scope,
            observed_route_context_ids=[selected['route_context_id']],
            exit_flow_contexts=[dict(route_context_id=selected['route_context_id'], completed=minimum, failed=0)])
        app = phase['privacy']['exit']['provider_application']
        if name == 'exercise':
            app[M['NODES'][0]] = dict(request_packets=1, response_packets=0, response_payload_bytes=0)
            for n in M['NODES'][1:]:
                app[n]['response_payload_bytes'] = repair + total  # Framing/extra renew traffic is permitted.
        value['network'][name] = phase
    value['layout']['route_scope'] = copy.deepcopy(value['network']['publish']['layout']['route_scope'])
    return value


def write_evidence(root, value):
    def write(name, data):
        (root / name).write_bytes(M['encoded'](data))
        (root / name).chmod(0o600)
    for name in ('provision', 'prepare', *M['PHASES'], 'withdrawal'):
        write(f'storage-consumer-{name}.json', value[name])
    write('storage-consumer-private-cleanup.json', value['private_cleanup'])
    write('storage-consumer-isolation.json', value['consumer_isolation'])
    write('private-storage-fragments-deleted_usage.json', value['initial_usage'])
    for name in ('uploaded', 'restored', 'deleted'):
        write(f'private-storage-fragments-consumer_{name}_usage.json', value[name + '_usage'])
    for name in ('layout', 'isolation'):
        write(f'private-storage-fragments-{name}.json', value[name])
    write('a01-expected-peers.json', value['expected_peers'])
    for name, phase in value['network'].items():
        for field, suffix in (('layout', 'layout'), ('selected_route', 'live-selection'), ('gates', 'gates')):
            write(f'private-storage-fragments-consumer-{name}-{suffix}.json', phase[field])
        write(f'content-provider-adaptive-private-storage-fragments-consumer-{name}-control.json', phase['control_privacy'])
        for role, capture in phase['privacy'].items():
            write(f'private-storage-fragments-consumer-{name}-privacy-{role}.json', capture)


class ConsumerEvidence(unittest.TestCase):
    def reject(self, mutate, code=None):
        value = fixture()
        mutate(value)
        with self.assertRaisesRegex(ValueError, code or '.'):
            M['validate_evidence'](value)

    def test_complete_raw_rebuild_exact_exports_and_cli_without_runtime(self):
        value = fixture()
        self.assertEqual(M['validate_evidence'](value), value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            self.assertEqual(M['build_evidence'](root), value)
            self.assertEqual(set(M['EXPORT_NAMES']) - {'storage-consumer-evidence.json'}, {p.name for p in root.iterdir()})
            self.assertEqual(len(M['EXPORT_NAMES']), len(set(M['EXPORT_NAMES'])))
            output = root / 'storage-consumer-evidence.json'
            for args in (['evidence', str(root), str(output)], ['check', str(output)]):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'storage-consumer-maintenance-evidence.py'), *args],
                    capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_bytes()), value)
            (root / 'private-storage-fragments-consumer-exercise-layout.json').unlink()
            with self.assertRaises(FileNotFoundError):
                M['build_evidence'](root)

    def test_pinned_sources_exact_provision_hash_and_scope(self):
        for mutate in (
            lambda v: v['provision']['pins']['sources']['image'].update(revision='0' * 40),
            lambda v: v['provision']['pins']['runtime'].update(sha256='0' * 64),
            lambda v: v['provision'].update(pins_sha256='0' * 64),
            lambda v: v['provision'].update(peer_storage_proven=True),
            lambda v: v['provision'].update(version=True),
            lambda v: v['provision']['tools']['gpg'].update(package='other'),
            lambda v: v.update(provision_sha256='0' * 64),
            lambda v: v['publish'].update(provision_sha256='0' * 64),
            lambda v: v['publish']['node'].update(provision_sha256='0' * 64),
            lambda v: v['scope'].update(host_cleanup_proven=True),
            lambda v: v['scope'].update(node_report_hash_independently_reconstructed=True)):
            with self.subTest(mutate=mutate):
                self.reject(mutate)

    def test_closed_original_application_failure_never_becomes_success(self):
        for phase in ('prepare', *M['PHASES']):
            self.reject(lambda v: v[phase].update(passed=False), 'consumer_orchestration')
            self.reject(lambda v: v[phase]['node'].update(passed=False), 'consumer_orchestration')
        self.reject(lambda v: v['exercise'].update(code='node_phase_failed', cleanup_confirmed=False), 'closed_fields')
        self.reject(lambda v: v['finish'].update(node_joined=False), 'consumer_orchestration')

    def test_authority_and_cipher_geometry_are_not_caller_selected(self):
        for mutate in (
            lambda v: v['prepare']['authority']['cloud'].update(automatic_grant_refresh=True),
            lambda v: v['prepare']['authority']['image'].update(reserved_credit=True),
            lambda v: v['prepare']['authority']['image'].update(grant_max_leases=[8] * 3),
            lambda v: v['prepare']['authority']['image'].update(policy_maximum_charge=10**7),
            lambda v: v['prepare']['node']['image'].update(cipher_bytes=15),
            lambda v: v['publish']['node']['image'].update(cipher_sha256='0' * 64),
            lambda v: v['exercise']['node']['cloud'].update(fragment_count=1),
            lambda v: v['exercise']['node']['image'].update(uncertain_payload_bytes=0)):
            with self.subTest(mutate=mutate):
                self.reject(mutate)

    def test_foreground_read_lifecycle_and_delete_checks_are_all_required(self):
        for name, field, changed in (
            ('image', 'application_decryption_verified', False), ('image', 'plaintext_sha256', '0' * 64),
            ('image', 'cipher_cache_removed_before_read', False), ('image', 'cursor_after', 3),
            ('image', 'observed_old_owner_absent_while_foreground_active', False),
            ('cloud', 'authenticated_get_body_verified', False), ('cloud', 'wrong_token_status', 200),
            ('cloud', 'confirmed_copy_retentions_advanced', 0), ('cloud', 'owner_joined', False),
            ('cloud', 'completed_turn_observed', True), ('image', 'exact_join_before_spawn_measured', True)):
            with self.subTest(field=field):
                self.reject(lambda v: v['exercise']['node'][name].update({field: changed}))
        self.reject(lambda v: v['finish']['node']['image'].update(all_retained_copies_delete_acknowledged=False))
        # Pending handoff intentions persist after acknowledged deletion; usage, not that count, proves zero charge.
        self.assertEqual(fixture()['finish']['node']['image']['pending_retirements'], 3)
        self.reject(lambda v: v['finish']['node']['image'].update(pending_retirements=0))

    def test_independent_store_usage_exact_per_provider_at_each_phase(self):
        for phase in ('initial', 'uploaded', 'restored', 'deleted'):
            for index in range(3):
                for key in ('reserved_bytes', 'committed_bytes', 'leases'):
                    with self.subTest(phase=phase, index=index, key=key):
                        self.reject(lambda v: v[phase + '_usage'][index].update(
                            {key: v[phase + '_usage'][index][key] + 1}), 'consumer_exact_provider_usage')
        self.reject(lambda v: v['deleted_usage'][0].update(leases=False), 'consumer_exact_provider_usage')

    def test_new_private_owner_probe_with_positive_control_and_cleanup(self):
        for field in ('agent_mount_positive_control', 'client_cannot_read_new_owner_root', 'client_cannot_read_any_provider_store'):
            self.reject(lambda v: v['consumer_isolation'].update({field: False}), 'consumer_new_owner_isolation')
        self.reject(lambda v: v['consumer_isolation'].update(user_uid=1001), 'consumer_new_owner_isolation')
        self.reject(lambda v: v['private_cleanup'].update(local_fixture_removed=False), 'consumer_private_cleanup')
        self.reject(lambda v: v['private_cleanup'].update(removed_files=512), 'consumer_private_cleanup')
        self.reject(lambda v: v['private_cleanup'].update(remote_cleanup_confirmed=True), 'consumer_private_cleanup')
        self.reject(lambda v: v['withdrawal'].update(all_three_store_inodes_preserved=False), 'consumer_store_withdrawal')

    def test_phase_specific_minima_and_continuous_actual_exit_scope(self):
        for name, minimum in M['PHASES'].items():
            self.reject(lambda v: v[name].update(minimum_protected_completions=minimum - 1), 'consumer_flow_scope')
            self.reject(lambda v: v['network'][name]['gates'].update(exit_mptcp_tls_completed=minimum - 1))
            self.reject(lambda v: v['network'][name]['gates'].update(exit_log_sampler_joined=False))
            self.reject(lambda v: v['network'][name]['layout']['route_scope'].update(exit_peer_id='other'))
            self.reject(lambda v: v['network'][name]['selected_route'].update(transport='tcp'))
        self.reject(lambda v: v['network']['publish']['gates'].update(exit_log_sampling_version=1))

    def test_failed_a_flows_are_retained_not_mislabelled_as_bypass(self):
        value = fixture()
        gates = value['network']['exercise']['gates']
        gates.update(exit_mptcp_tls_failed=3, exit_log_observed_records=20)
        gates['exit_flow_contexts'][0]['failed'] = 3
        M['validate_evidence'](value)
        self.assertEqual(gates['exit_mptcp_tls_failed'], 3)

    def test_context_rotation_does_not_rebind_to_old_global_context(self):
        value = fixture()
        phase = value['network']['exercise']
        new = 'b' * 32
        phase['selected_route']['route_context_id'] = new
        for path in phase['selected_route']['paths']:
            path['route_context_id'] = new
        phase['gates']['observed_route_context_ids'] = [new]
        phase['gates']['exit_flow_contexts'][0]['route_context_id'] = new
        M['validate_evidence'](value)
        phase['gates']['exit_flow_contexts'][0]['completed'] = 0
        with self.assertRaises(ValueError):
            M['validate_evidence'](value)

    def test_survivor_payload_bounds_follow_actual_four_fragment_repair_not_old_restore(self):
        value = fixture()
        total, _, repair = M['geometry'](value['prepare']['node'])
        app = value['network']['exercise']['privacy']['exit']['provider_application']
        # Either survivor can supply the application reads, after both verified repairs.
        for reader in ('relay5', 'relay3'):
            for node in ('relay5', 'relay3'):
                app[node]['response_payload_bytes'] = repair + (total if node == reader else 0)
            M['validate_evidence'](value)
        for node in ('relay5', 'relay3'):
            self.reject(lambda v: v['network']['exercise']['privacy']['exit']['provider_application'][node].update(
                response_payload_bytes=repair - 1), 'consumer_survivor_payload')
        app['relay5']['response_payload_bytes'] = repair
        app['relay3']['response_payload_bytes'] = repair + total - 1
        with self.assertRaisesRegex(ValueError, 'consumer_survivor_payload'):
            M['validate_evidence'](value)
        self.reject(lambda v: v['network']['exercise']['privacy']['exit']['provider_application']['relay4'].update(
            response_payload_bytes=1), 'consumer_withdrawn_provider_responded')

    def test_privacy_controls_actual_both_legs_and_capture_drain(self):
        for mutate in (
            lambda v: v['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
            lambda v: v['network']['publish']['privacy']['relay0'].update(internet_destination_outer_packets=1),
            lambda v: v['network']['publish']['privacy']['exit'].update(client_public_packets=1),
            lambda v: v['network']['publish']['privacy']['relay1'].update(exit_leg_wireguard_data_datagrams=16),
            lambda v: v['network']['publish']['privacy']['exit'].update(packet_socket_drops=1),
            lambda v: v['network']['publish']['privacy']['exit'].update(truncated=True),
            lambda v: v['network']['exercise']['control_privacy'].update(unexpected_provider_control_packets=1),
            lambda v: v['network']['exercise']['control_privacy']['provider_application']['relay3'].update(request_packets=1),
            lambda v: v['network']['finish']['privacy']['client']['provider_application']['relay4'].update(request_packets=1),
            lambda v: v['network']['finish']['privacy']['exit']['provider_application']['relay3'].update(request_packets=0)):
            with self.subTest(mutate=mutate):
                self.reject(mutate)

    def test_closed_envelopes_reject_extra_fields_and_false_success(self):
        for mutate in (lambda v: v.update(raw_log='secret'), lambda v: v.update(schema_version=True),
            lambda v: v.update(success=False), lambda v: v['prepare'].update(private_path='/private'),
            lambda v: v['network']['exercise'].update(restore=True),
            lambda v: v['prepare']['node']['image'].update(owner_key='secret')):
            self.reject(mutate)


class EvidenceFiles(unittest.TestCase):
    def test_noncanonical_provision_file_cannot_reuse_a_different_original_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, fixture())
            path = root / 'storage-consumer-provision.json'
            path.write_text(json.dumps(json.loads(path.read_bytes())))
            with self.assertRaisesRegex(ValueError, 'consumer_provision_encoding'):
                M['build_evidence'](root)

    def test_same_fd_file_type_size_links_mode_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'receipt.json'
            path.write_bytes(b'{}')
            path.chmod(0o600)
            self.assertEqual(M['read'](path), ({}, b'{}'))
            for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'', b' ' * (M['MAX_JSON'] + 1)):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    M['read'](path)
            path.write_bytes(b'{}')
            path.chmod(0o622)
            with self.assertRaises(ValueError):
                M['read'](path)
            path.chmod(0o600)
            os.link(path, root / 'hardlink')
            with self.assertRaises(ValueError):
                M['read'](path)
            (root / 'symlink').symlink_to(path)
            with self.assertRaises(OSError):
                M['read'](root / 'symlink')
            os.mkfifo(root / 'fifo', 0o600)
            with self.assertRaises(ValueError):
                M['read'](root / 'fifo')


if __name__ == '__main__':
    unittest.main()
