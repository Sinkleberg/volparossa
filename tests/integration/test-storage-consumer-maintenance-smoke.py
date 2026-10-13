#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert receipt/authority and owned-child tests; no GPG, core, VM or network."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.request

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-consumer-maintenance-smoke.py'))
G = M['main'].__globals__
PROVISION = 'a' * 64


def base(phase):
    return dict(version=1, kind='storage-consumer-maintenance', phase=phase, passed=True,
        provision_sha256=PROVISION, scope=dict(M['SCOPE']))


def prepared():
    return dict(base('prepare'), **{name: dict(cipher_bytes=800001 + i * 2,
        cipher_sha256=str(i + 1) * 64, application_encryption='OpenPGP-AES256')
        for i, name in enumerate(('image', 'cloud'))})


def report(phase):
    value, original = base(phase), prepared()
    for name in ('image', 'cloud'):
        size = original[name]['cipher_bytes']
        committed = 0 if phase == 'finish' else 2 * size
        uncertain = M['geometry'](size)[2] if phase == 'exercise' else 0
        app = dict(logical_ciphertext_bytes=size, committed_payload_bytes=committed,
            uncertain_payload_bytes=uncertain, physical_payload_charge_upper_bound=committed + uncertain,
            fragment_count=4, copies_per_fragment=2, retained_copy_records=8 if phase == 'publish' else 11,
            pending_retirements=0 if phase == 'publish' else 3)
        if phase == 'publish':
            app.update(cipher_sha256=original[name]['cipher_sha256'], enrollment_created=True,
                maintenance_started=False, original_journals_bound=True)
        elif phase == 'exercise':
            app.update({key: True for key in M['LIFECYCLE']})
            app.update(cursor_before=3, cursor_after=4, exact_join_before_spawn_measured=False,
                completed_turn_observed=False, confirmed_copy_retentions_advanced=1,
                cipher_cache_removed_before_read=True, plaintext_sha256=M['fixture_hash'](name),
                plaintext_bytes=M['PLAIN_BYTES'], original_enrollment_and_journals_retained=True,
                owner_joined=True)
            app.update(dict(application_decryption_verified=True, quiesced_sql_dump_restored=True)
                if name == 'image' else dict(authenticated_get_body_verified=True, wrong_token_status=401))
        else:
            app.update(all_retained_copies_delete_acknowledged=True, owner_joined=True,
                provider_usage_independently_checked=False, private_fixture_removed=False)
        value[name] = app
    return value


def write(path, data=b'{}'):
    path.write_bytes(data)
    path.chmod(0o600)


class ConsumerReceipts(unittest.TestCase):
    def test_exact_phase_geometry_and_original_ciphertext_accounting(self):
        M['validate_node_report'](prepared(), 'prepare', PROVISION)
        for phase in ('publish', 'exercise', 'finish'):
            with self.subTest(phase=phase):
                value = report(phase)
                self.assertEqual(M['validate_node_report'](value, phase, PROVISION, prepared()), value)
        self.assertEqual(M['FLOW_MINIMUM'], dict(publish=56, exercise=16, finish=22))
        for size in (16, 17, 800001, M['MAX_CIPHER']):
            fragment, lengths, charge_a = M['geometry'](size)
            self.assertEqual(sum(lengths), size)
            self.assertEqual(max(lengths), fragment)
            self.assertEqual(charge_a, lengths[0] + lengths[2] + lengths[3])
        for bad in (True, 0, 15, M['MAX_CIPHER'] + 1):
            with self.assertRaises(ValueError):
                M['geometry'](bad)

    def test_closed_reports_reject_extra_fields_wrong_source_and_claim_scope(self):
        cases = [lambda v: v.update(raw_path='/private'),
            lambda v: v.update(version=True), lambda v: v.update(provision_sha256='b' * 64),
            lambda v: v['scope'].update(immich_running_proven=True),
            lambda v: v['image'].update(owner_key='secret'),
            lambda v: v['image'].update(cipher_sha256='0' * 64),
            lambda v: v['cloud'].update(maintenance_started=True)]
        for mutate in cases:
            value = report('publish')
            mutate(value)
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, prepared())

    def test_exercise_requires_real_full_read_auth_charge_and_measured_lifecycle(self):
        for name, field, changed in [('image', 'plaintext_sha256', '0' * 64),
            ('image', 'application_decryption_verified', False), ('cloud', 'wrong_token_status', 200),
            ('cloud', 'authenticated_get_body_verified', False), ('image', 'cursor_after', 3),
            ('cloud', 'confirmed_copy_retentions_advanced', 0), ('image', 'uncertain_payload_bytes', 0),
            ('cloud', 'exact_join_before_spawn_measured', True), ('image', 'completed_turn_observed', True),
            ('cloud', 'owner_joined', False), ('cloud', 'plaintext_bytes', True)]:
            with self.subTest(field=field):
                value = report('exercise')
                value[name][field] = changed
                with self.assertRaises(ValueError):
                    M['validate_node_report'](value, 'exercise', PROVISION, prepared())

    def test_delete_zero_charge_is_not_private_or_remote_cleanup_proof(self):
        value = report('finish')
        for field, changed in [('physical_payload_charge_upper_bound', 1), ('retained_copy_records', 8),
            ('all_retained_copies_delete_acknowledged', False), ('provider_usage_independently_checked', True),
            ('private_fixture_removed', True)]:
            current = copy.deepcopy(value)
            current['image'][field] = changed
            with self.assertRaises(ValueError):
                M['validate_node_report'](current, 'finish', PROVISION, prepared())

    def test_original_closed_node_failure_survives_without_private_stderr(self):
        value = dict(version=1, kind='storage-consumer-maintenance', phase='exercise', passed=False,
            provision_sha256=PROVISION, stage='image_decrypt', code='image_decrypt', cleanup_confirmed=False)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-exercise.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            with patch.dict(G, run_child=lambda *_: (1, raw, b'PRIVATE-DO-NOT-EXPORT')):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'exercise', PROVISION, time.monotonic() + 1)
            retained = caught.exception.report
            self.assertFalse(retained['passed'])
            self.assertEqual(retained['node'], value)
            self.assertEqual(retained['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('PRIVATE', json.dumps(retained))
            value['unexpected'] = 'secret'
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'exercise', PROVISION, prepared())

    def test_generic_failure_is_closed_and_does_not_repeat_arguments(self):
        value = M['failure_report'](['exercise', '/private/key'])
        self.assertEqual(set(value), {'version', 'kind', 'phase', 'passed', 'code', 'cleanup_confirmed'})
        self.assertEqual(value['phase'], 'exercise')
        self.assertNotIn('/private', json.dumps(value))
        self.assertEqual(M['failure_report'](['/private/key'])['phase'], 'invalid')

    def test_closed_publish_observation_preserves_operation_without_exporting_raw_result(self):
        value = dict(version=2, kind='storage-consumer-maintenance', phase='publish', passed=False,
            provision_sha256=PROVISION, stage='cloud_publish', code='publish_operation', cleanup_confirmed=False,
            publish_observation=dict(version=1, app='cloud', operation='deposit', status='incomplete',
                code='retained_operation_incomplete', local_process_joined=True,
                core_report_present=True, core_operation_complete=False))
        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION), value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            with patch.dict(G, run_child=lambda *_: (1, raw, b'PRIVATE-DO-NOT-EXPORT')):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            self.assertEqual(caught.exception.report['node'], value)
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))
        cases = [lambda v: v.update(version=1), lambda v: v.update(stage='image_publish'),
            lambda v: v.update(phase='exercise'), lambda v: v.update(code='application_failed'),
            lambda v: v['publish_observation'].update(app='private-path'),
            lambda v: v['publish_observation'].update(operation='restore'),
            lambda v: v['publish_observation'].update(status='PRIVATE'),
            lambda v: v['publish_observation'].update(code='PRIVATE'),
            lambda v: v['publish_observation'].update(local_process_joined=1),
            lambda v: v['publish_observation'].update(core_report_present=1),
            lambda v: v['publish_observation'].update(core_operation_complete=1),
            lambda v: v['publish_observation'].update(core_report_present=False),
            lambda v: v['publish_observation'].update(status='complete'),
            lambda v: v['publish_observation'].update(raw_storage={'path': 'PRIVATE'}),
            lambda v: v['publish_observation'].update(version=True)]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(value)
                mutate(changed)
                with self.assertRaises(ValueError):
                    M['validate_node_report'](changed, changed['phase'], PROVISION)
        changed = copy.deepcopy(value)
        changed['code'] = 'phase_deadline'
        changed['publish_observation'].update(status='cancelled', code='cancelled',
            core_report_present=False, core_operation_complete=None)
        M['validate_node_report'](changed, 'publish', PROVISION)


class ConsumerBoundaries(unittest.TestCase):
    def test_private_reader_enforces_real_size_mode_links_and_no_follow(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, path = Path(temporary), Path(temporary) / 'owned'
            write(path, b'abcd')
            self.assertEqual(M['file_bytes'](path, 4), b'abcd')
            with self.assertRaises(ValueError):
                M['file_bytes'](path, 3)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                M['file_bytes'](path, 4)
            path.chmod(0o600)
            (root / 'link').symlink_to(path)
            with self.assertRaises(OSError):
                M['file_bytes'](root / 'link', 4)
            os.link(path, root / 'hardlink')
            with self.assertRaises(ValueError):
                M['file_bytes'](path, 4)

    def test_owned_child_drains_full_buffer_and_eof_after_normal_exit(self):
        status, output, errors = M['run_child']([sys.executable, '-I', '-B', '-c',
            'import os; os.write(1,b"a"*12000); os.write(2,b"b"*6000)'], time.monotonic() + 5)
        self.assertEqual((status, len(output), len(errors)), (0, 12000, 6000))

    def test_owned_child_failure_is_retained_not_relabelled_success(self):
        status, output, errors = M['run_child']([sys.executable, '-I', '-B', '-c',
            'import os; os.write(1,b"{}"); os.write(2,b"inert failure"); raise SystemExit(1)'], time.monotonic() + 5)
        self.assertEqual((status, output, errors), (1, b'{}', b'inert failure'))

    def test_selector_constructor_failure_still_terminates_and_joins_owned_child(self):
        children, spawn = [], subprocess.Popen

        def started(*args, **kwargs):
            child = spawn(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(subprocess, 'Popen', side_effect=started), \
                patch.object(G['selectors'], 'DefaultSelector', side_effect=OSError('inert EMFILE')):
            with self.assertRaisesRegex(OSError, 'EMFILE'):
                M['run_child']([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(10)'], time.monotonic() + 5)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(children[0].stderr.closed)
        with self.assertRaises(ProcessLookupError):
            os.killpg(children[0].pid, 0)

    def test_owned_child_oversize_and_deadline_abort_are_failures(self):
        for code, deadline, limit, reason in [
            ('import os,time; os.write(1,b"x"*4096); time.sleep(10)', 5, 128, 'output_bound'),
            ('import time; time.sleep(10)', .15, 128, 'deadline')]:
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, reason):
                M['run_child']([sys.executable, '-I', '-B', '-c', code], started + deadline, limit=limit)
            self.assertLess(time.monotonic() - started, 3)

    def test_no_fixture_cleanup_while_real_owned_child_names_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'm'
            root.mkdir(mode=0o700)
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(10)', str(root)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                with self.assertRaisesRegex(ValueError, 'fixture_process_active'):
                    M['no_fixture_processes'](root)
                self.assertTrue(root.is_dir())
            finally:
                child.terminate()
                child.wait(timeout=5)
            M['no_fixture_processes'](root)

    def test_cleanup_removes_only_exact_private_tree_and_stays_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'm'
            root.mkdir(mode=0o700)
            (root / 'image').mkdir(mode=0o700)
            (root / 'image/bundle').mkdir(mode=0o700)
            (root / 'cloud').mkdir(mode=0o700)
            write(root / 'image/bundle/recovery.key')
            write(root / 'consumer-binding.json')
            result = M['cleanup'](root)
            self.assertEqual(result['removed_files'], 2)
            self.assertEqual(result['removed_directories'], 4)
            self.assertFalse(result['remote_cleanup_confirmed'])
            self.assertFalse(result['provider_usage_proven'])
            self.assertEqual(M['cleanup'](root)['removed_files'], 0)

    def test_cleanup_rejects_unknown_top_level_or_symlink_before_removing_any_file(self):
        for bad in ('unknown', 'symlink'):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'm'
                root.mkdir(mode=0o700)
                write(root / 'consumer-binding.json')
                if bad == 'unknown':
                    write(root / 'unadmitted.txt')
                else:
                    (root / 'image').mkdir(mode=0o700)
                    (root / 'image/link').symlink_to(root / 'consumer-binding.json')
                with self.assertRaises(ValueError):
                    M['cleanup_tree'](root)
                self.assertTrue((root / 'consumer-binding.json').exists())

    def test_guard_denies_host_before_provisioning_or_spawn(self):
        with patch.object(G['socket'], 'gethostname', return_value='developer-host'), \
                patch.dict(G, tools=lambda: self.fail('tools should not run')):
            with self.assertRaisesRegex(ValueError, 'guest_only'):
                M['main'](['prepare', '/private'])


class ConsumerOrchestration(unittest.TestCase):
    def test_actual_staged_import_and_pin_closure_without_download_or_execution(self):
        # The guest stages individual files, not this whole checkout. Exercise
        # the actual runpy/load_pins closure in that same sparse arrangement.
        names = ('storage-consumer-maintenance-smoke.py', 'storage-consumer-maintenance-provision.py',
            'storage-consumer-maintenance-pins.json', 'image-snapshot-provision.py',
            'agent-private-task-code.py', 'agent-private-task-code-pins.json',
            'private-storage-fragments-smoke.py', 'private-storage-replicas-smoke.py',
            'private-storage-peer-smoke.py', 'content-provider-https-smoke.py',
            'content-network-smoke.py', 'private-storage-log-sampler.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in names:
                (root / name).write_bytes((HERE / name).read_bytes())
            with patch.object(subprocess, 'Popen') as spawn, patch.object(os, 'execve') as execute, \
                    patch.object(urllib.request, 'urlopen') as download:
                loaded = runpy.run_path(str(root / names[0]))
                self.assertEqual(loaded['PROVISIONER']['load_pins'](), M['PROVISIONER']['load_pins']())
                self.assertEqual(loaded['FLOW_MINIMUM'], M['FLOW_MINIMUM'])
                for absent in ('image-snapshot-provision.py', 'agent-private-task-code.py', 'agent-private-task-code-pins.json'):
                    (root / absent).unlink()
                    with self.assertRaises(FileNotFoundError):
                        check = runpy.run_path(str(root / names[0]))
                        check['PROVISIONER']['load_pins']()
                    (root / absent).write_bytes((HERE / absent).read_bytes())
                spawn.assert_not_called()
                execute.assert_not_called()
                download.assert_not_called()

    def test_preparation_creates_only_original_finite_authority_from_exact_cipher_size(self):
        original, calls, owners = prepared(), [], iter(('4' * 64, '5' * 64))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def node(*_):
                for name in ('image', 'cloud'):
                    (root / name).mkdir(mode=0o700)
                return original, 'b' * 64

            def core(binary, control, arguments, deadline, raw=False):
                calls.append([str(v) for v in arguments])
                if arguments[0] == 'init':
                    return None
                if arguments[:2] == ['content', 'recipient-key']:
                    return dict(identity_public_key_hex=next(owners))
                self.assertEqual(arguments[:3], ['storage', 'peer', 'grant'])
                selected = dict(zip(arguments[3::2], arguments[4::2]))
                self.assertEqual(selected['--max-leases'], 4)
                self.assertEqual(selected['--max-retention-seconds'], 7200)
                self.assertEqual(selected['--lifetime-seconds'], 7200)
                write(Path(selected['--output']), b'inert signed grant fixture')
                return dict(operation='private_storage_peer_grant', grant_written=True,
                    max_payload_bytes=selected['--max-payload-bytes'], max_leases=4,
                    expires_unix_seconds=int(time.time()) + 7200, reserved_bytes=0, network_contribution_credit=False)

            with patch.dict(G, node_phase=node, core=core, validate_locations=lambda *_: (Path('/fixed/core'), Path('/fixed/client'))):
                result = M['prepare'](root, '/fixed/core', '/fixed/client', ['a', 'b', 'c'],
                    [str(i) * 64 for i in (1, 2, 3)], PROVISION, time.monotonic() + 5)
            self.assertEqual(len(calls), 10)
            self.assertFalse(result['protected_flow_proven'])
            for name in ('image', 'cloud'):
                size = original[name]['cipher_bytes']
                config = M['private_json'](root / name / 'storage.json')
                policy = M['private_json'](root / name / 'maintenance-policy.json')
                self.assertEqual(config['fragmentBytes'], (size + 3) // 4)
                self.assertEqual((config['lifetimeSeconds'], config['deadlineMs']), (1800, 1800000))
                self.assertEqual((policy['authorizationSeconds'], policy['lifetimeSeconds'], policy['renewBeforeSeconds']),
                    (6000, 3600, 7200))
                self.assertEqual(policy['maximumChargedBytes'], size * 3)
                self.assertEqual(policy['maximumTurnBytes'], 8388608)
                self.assertNotIn(policy['fromProviderKey'], [p['key'] for p in policy['providers']])
                self.assertFalse(result['authority'][name]['enrollment_created'])

    def test_phase_requires_initial_continuous_final_sampler_and_exports_exact_name(self):
        events, writes = [], []
        value = report('exercise')
        class Coverage:
            joined = True
            def report(self, *, joined):
                self.assert_joined = joined
                return dict(exit_log_sampling_version=2)
        coverage = Coverage()

        @contextmanager
        def capture(*args, **kwargs):
            self.assertEqual(args[3], 16)
            self.assertEqual(kwargs['scope']['exit_peer_id'], 'exit')
            events.append('initial')
            yield coverage
            events.append('final_join')

        def node(*_):
            events.append('node')
            return value, 'b' * 64

        root = Path('/opt/va.' + 'a' * 32 + '.abcdef/u/m')
        work = root.parents[1]
        scope = dict(exit_peer_id='exit', paths=[dict(path_id=1, relay_peer_id='a'), dict(path_id=2, relay_peer_id='b')])
        fake_sampler = dict(M['SAMPLER'], capture=capture,
            validate_summary=lambda *_: events.append('validate'))
        with patch.dict(os.environ, STORAGE_PROOF_BASELINE_MS='1', STORAGE_PROOF_ROUTE_SCOPE=json.dumps(scope)), \
                patch.dict(G, private_json=lambda *_: dict(coreBinary='/fixed/core', controlSocket='/fixed/client'),
                    validate_locations=lambda *_: (Path('/fixed/core'), Path('/fixed/client')), private_directory=lambda *_: None,
                    node_phase=node, SAMPLER=fake_sampler, write_json=lambda path, value: writes.append((path, value))):
            result = M['phase'](root, 'exercise', work / 'runtime-exit/control/agent.sock',
                work / 'client-fixtures/private-storage-user', PROVISION, time.monotonic() + 1)
        self.assertEqual(events, ['initial', 'node', 'final_join', 'validate'])
        self.assertEqual(writes[0][0].name, 'flow-consumer-exercise.json')
        self.assertTrue(result['protected_flow_proven'])
        self.assertFalse(result['remote_cleanup_independently_proven'])

    def test_flow_minimum_cli_requires_no_guest_mutation(self):
        for phase, minimum in M['FLOW_MINIMUM'].items():
            run = subprocess.run([sys.executable, '-B', str(HERE / 'storage-consumer-maintenance-smoke.py'),
                'flow-minimum', phase], capture_output=True, timeout=5, check=True)
            self.assertEqual(run.stdout, f'{minimum}\n'.encode())
            self.assertEqual(run.stderr, b'')


if __name__ == '__main__':
    unittest.main()
