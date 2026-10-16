#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert controller checks: no subprocess, systemd unit, VM, or model is run."""
import ast
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import tempfile
import types
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name('protected-resident-model-run.py')
SPEC = importlib.util.spec_from_file_location('resident_model_run', SOURCE)
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


def boot(outcome='guest_process_returned'):
    good = outcome == 'guest_process_returned'
    return dict(version=1, outcome=outcome, stage='complete' if good else 'verity_read',
                verity_verified=good, root_readonly=good, write_denied=good,
                entrypoint_invoked=good, process_exit_zero=good,
                worker_cleanup_confirmed=False, hardware_attestation=False,
                private_inputs=False, model_execution=False, worker_execution=False,
                guest_key_origin_proven=False)


def requester():
    return dict(version=1, kind='public_resident_requester', public_fixture_only=True,
                workload_sha256='a' * 64, tls_spki_sha256='b' * 64,
                turns=[dict(sequence=index, answer=answer, prompt_tokens=12, generated_tokens=1,
                            per_turn_cleanup=dict(version=2, request_files_removed=True,
                                session_closed=False, session_private_state_retained=True))
                       for index, answer in enumerate(('READY', '4'), 1)],
                final_cleanup=dict(version=1, child_reaped=True, private_state_removed=True),
                private_inputs=False, hardware_attestation=False,
                guest_key_origin_proven=False, production_approval=False)


class Inert(unittest.TestCase):
    def setUp(self):
        # Any missed mock is an immediate test failure, never a real command.
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(R.subprocess, 'Popen', side_effect=AssertionError('real_process_forbidden')).start()
        mock.patch.object(R.time, 'monotonic', return_value=100.0).start()
        mock.patch.object(R.time, 'sleep').start()
        mock.patch.object(R, 'CANCELLED', False).start()

    def scope(self):
        value = R.Scope(['synthetic-qemu'], Path('/synthetic'), 200, {}, 50, 'test')
        value.process = types.SimpleNamespace(pid=313, returncode=0, wait=mock.Mock())
        value.log = mock.Mock()
        value.started = True
        return value


class ScopeCleanup(Inert):
    def test_start_binds_same_exec_pid_and_fixed_scope_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            group = work / 'cgroup'
            group.mkdir()
            (group / 'memory.max').write_text(str(R.QEMU_BYTES))
            (group / 'memory.swap.max').write_text('0\n')
            (group / 'cgroup.procs').write_text('313\n')
            scope = R.Scope(['synthetic-qemu'], work, 200, {}, 50, 'test')
            process = types.SimpleNamespace(pid=313)
            read_text = Path.read_text
            def read(path, *args, **kwargs):
                if path == Path('/proc/meminfo'):
                    return 'MemAvailable: 16777216 kB\n'
                return read_text(path, *args, **kwargs)
            with mock.patch.object(Path, 'read_text', read), \
                    mock.patch.object(R.subprocess, 'Popen', return_value=process) as launch, \
                    mock.patch.object(scope, 'state', return_value={'ControlGroup': '/user.slice/' + scope.unit}), \
                    mock.patch.object(R, 'scope_path', return_value=group):
                try:
                    scope.start()
                finally:
                    if scope.log is not None:
                        scope.log.close()
            self.assertIs(scope.process, process)
            self.assertEqual(scope.group, group)
            self.assertIn('--scope', launch.call_args.args[0])
            self.assertIn('--property=MemoryMax=' + str(13 * R.GIB), launch.call_args.args[0])
            self.assertIn('--property=MemorySwapMax=0', launch.call_args.args[0])
            self.assertTrue(launch.call_args.kwargs['start_new_session'])

    def test_manager_query_failure_still_joins_and_closes(self):
        scope = self.scope()
        process = scope.process
        with mock.patch.object(scope, 'state', side_effect=OSError('synthetic_bus')), \
                mock.patch.object(R, 'joined') as join:
            with self.assertRaises(R.CleanupUnconfirmed):
                scope.stop()
        join.assert_called_once_with(process)
        scope.log.close.assert_called_once()
        self.assertIsNone(scope.process)
        self.assertFalse(scope.cleanup_confirmed)
        with self.assertRaises(R.CleanupUnconfirmed):
            scope.stop()

    def test_manager_stop_failure_cannot_become_cleanup_success(self):
        scope = self.scope()
        with mock.patch.object(scope, 'state', return_value={'ActiveState': 'inactive'}), \
                mock.patch.object(R, 'run', side_effect=OSError('synthetic_stop')), \
                mock.patch.object(R, 'joined') as join:
            with self.assertRaises(R.CleanupUnconfirmed):
                scope.stop()
        join.assert_called_once()
        scope.log.close.assert_called_once()
        self.assertFalse(scope.cleanup_confirmed)

    def test_nonempty_group_refused_after_child_join(self):
        scope = self.scope()
        with tempfile.TemporaryDirectory() as temporary:
            scope.group = Path(temporary)
            (scope.group / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
            with mock.patch.object(scope, 'state', return_value={'ActiveState': 'inactive'}), \
                    mock.patch.object(R, 'run', return_value=(b'', b'', 0)), \
                    mock.patch.object(R, 'joined') as join:
                with self.assertRaises(R.CleanupUnconfirmed):
                    scope.stop()
            join.assert_called_once()
        self.assertFalse(scope.cleanup_confirmed)

    def test_empty_group_and_inactive_unit_confirm_cleanup_once(self):
        scope = self.scope()
        with tempfile.TemporaryDirectory() as temporary:
            scope.group = Path(temporary)
            (scope.group / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
            with mock.patch.object(scope, 'state', return_value={'ActiveState': 'inactive'}), \
                    mock.patch.object(R, 'run', return_value=(b'', b'', 0)), \
                    mock.patch.object(R, 'joined') as join:
                expected = {'qemu_process_joined': True, 'scope_empty': True}
                self.assertEqual(scope.stop(), expected)
                self.assertEqual(scope.stop(), expected)
            join.assert_called_once()
        self.assertTrue(scope.cleanup_confirmed)

    def test_join_failure_preserves_owned_child_and_closes_log(self):
        scope = self.scope()
        process = scope.process
        with mock.patch.object(scope, 'state', return_value={'ActiveState': 'inactive'}), \
                mock.patch.object(R, 'run', return_value=(b'', b'', 0)), \
                mock.patch.object(R, 'joined', side_effect=R.CleanupUnconfirmed('synthetic_join')):
            with self.assertRaises(R.CleanupUnconfirmed):
                scope.stop()
        self.assertIs(scope.process, process)
        scope.log.close.assert_called_once()
        self.assertFalse(scope.cleanup_confirmed)

    def test_changed_group_never_confirms_cleanup(self):
        scope = self.scope()
        scope.group = Path('/synthetic/original')
        with mock.patch.object(scope, 'state', return_value={
                'ControlGroup': '/user.slice/' + scope.unit, 'ActiveState': 'inactive'}), \
                mock.patch.object(R, 'scope_path', return_value=Path('/synthetic/replacement')), \
                mock.patch.object(R, 'joined') as join:
            with self.assertRaises(R.CleanupUnconfirmed):
                scope.stop()
        join.assert_called_once()
        self.assertEqual(scope.group, Path('/synthetic/original'))

    def test_cancellation_does_not_disable_cleanup_and_is_restored(self):
        scope = self.scope()
        observed = []
        R.CANCELLED = True
        def stop_command(*_args, **_kwargs):
            observed.append(R.CANCELLED)
            return b'', b'', 0
        with mock.patch.object(scope, 'state', return_value={'ActiveState': 'inactive'}), \
                mock.patch.object(R, 'run', side_effect=stop_command), \
                mock.patch.object(R, 'joined'):
            self.assertTrue(scope.stop()['scope_empty'])
        self.assertEqual(observed, [False])
        self.assertTrue(R.CANCELLED)


class GuestUnit(Inert):
    NAME = 'vp-resident-builder'

    def run_unit(self, *, change=None, show_error=None, stop_error=None):
        guest = R.Guest(Path('/synthetic'), 200)
        calls = []
        states = [dict(Result='success', ExecMainStatus='0', ExecMainCode='0',
                       ActiveState='active', SubState='running',
                       ControlGroup='/system.slice/' + self.NAME + '.service'),
                  dict(Result='success', ExecMainStatus='0', ExecMainCode='1',
                       ActiveState='active', SubState='exited',
                       ControlGroup='/system.slice/' + self.NAME + '.service')]
        if change:
            states[-1].update(change)
        def ssh(argv, **options):
            calls.append((argv, options))
            if argv[2:4] == ['systemctl', 'show']:
                if show_error:
                    raise show_error
                self.assertTrue(states, 'unbounded_guest_unit_poll')
                raw = ''.join(key + '=' + value + '\n' for key, value in states.pop(0).items())
                return raw.encode(), b'', 0
            if argv[2:4] == ['systemctl', 'stop'] and stop_error:
                raise stop_error
            return b'', b'', 0
        guest.ssh = mock.Mock(side_effect=ssh)
        return guest, calls

    def test_async_launch_preserves_exit_status_then_stops_and_proves_empty(self):
        guest, calls = self.run_unit()
        self.assertTrue(guest.unit(self.NAME, ['python3', '/fixed.py'], 123456, user='vpci'))
        launch = calls[0][0]
        self.assertNotIn('--wait', launch)
        self.assertNotIn('--pipe', launch)
        self.assertIn('--property=RemainAfterExit=yes', launch)
        self.assertIn('--property=KillMode=control-group', launch)
        self.assertIn('--property=MemoryMax=10G', launch)
        self.assertIn('--property=MemorySwapMax=0', launch)
        self.assertEqual(launch[-2:], ['--deadline-monotonic-ns', '123456'])
        self.assertEqual(calls[-2][0][2:4], ['systemctl', 'stop'])
        self.assertEqual(calls[-1][0][2:4], ['python3', '-c'])
        self.assertIn('/system.slice/' + self.NAME + '.service', calls[-1][0][-1])
        self.assertEqual(calls[-2][1]['deadline'], calls[-1][1]['deadline'])
        self.assertEqual(calls[-2][1]['cap'], 25)
        self.assertEqual(calls[-1][1]['cap'], 10)

    def test_nonzero_original_status_rejected_but_cleanup_attempted(self):
        guest, calls = self.run_unit(change={'ExecMainStatus': '17'})
        with self.assertRaisesRegex(ValueError, 'guest_unit_failed'):
            guest.unit(self.NAME, ['python3'], 123456)
        self.assertEqual(calls[-2][0][2:4], ['systemctl', 'stop'])
        self.assertEqual(calls[-1][0][2:4], ['python3', '-c'])

    def test_signal_exit_rejected_despite_zero_status(self):
        guest, _ = self.run_unit(change={'ExecMainCode': '2'})
        with self.assertRaisesRegex(ValueError, 'guest_unit_failed'):
            guest.unit(self.NAME, ['python3'], 123456)

    def test_foreign_cgroup_rejected(self):
        guest, _ = self.run_unit(change={'ControlGroup': '/system.slice/other.service'})
        with self.assertRaisesRegex(ValueError, 'guest_unit_cgroup'):
            guest.unit(self.NAME, ['python3'], 123456)

    def test_status_query_failure_still_attempts_guest_cleanup(self):
        guest, calls = self.run_unit(show_error=OSError('synthetic_ssh'))
        with self.assertRaises(OSError):
            guest.unit(self.NAME, ['python3'], 123456)
        self.assertEqual(calls[-2][0][2:4], ['systemctl', 'stop'])
        self.assertEqual(calls[-1][0][2:4], ['python3', '-c'])

    def test_cleanup_failure_never_returns_success(self):
        guest, _ = self.run_unit(stop_error=OSError('synthetic_stop'))
        with self.assertRaises(OSError):
            guest.unit(self.NAME, ['python3'], 123456)

    def test_unapproved_unit_rejected_before_ssh(self):
        guest, _ = self.run_unit()
        with self.assertRaisesRegex(ValueError, 'guest_unit_name'):
            guest.unit('foreign', ['python3'], 123456)
        guest.ssh.assert_not_called()

    def test_polling_does_not_restart_original_absolute_deadline(self):
        guest, calls = self.run_unit()
        with mock.patch.object(R.time, 'monotonic', side_effect=[100, 100, 100, 100, 200, 200]):
            with self.assertRaisesRegex(ValueError, 'controller_deadline'):
                guest.unit(self.NAME, ['python3'], 123456)
        self.assertEqual(len([argv for argv, _ in calls if argv[2:4] == ['systemctl', 'show']]), 1)
        self.assertEqual(calls[-2][0][2:4], ['systemctl', 'stop'])
        self.assertEqual(calls[-1][0][2:4], ['python3', '-c'])


class ReceiptAndBindings(Inert):
    def test_ready_uses_actual_fixed_entrypoint_literal(self):
        source = R.ROOT / 'packaging/protected-resident-model/entrypoint'
        statements = ast.parse(source.read_bytes()).body
        value = next(ast.literal_eval(node.value) for node in statements
                     if isinstance(node, ast.Assign) and any(
                         isinstance(target, ast.Name) and target.id == 'READY' for target in node.targets))
        self.assertTrue(R.ready_record(value))
        self.assertFalse(R.ready_record(b'booting\n'))

    def test_ready_rejects_duplicates_unknowns_and_boolean_integer_aliases(self):
        value = dict(version=1, scope='public_fixture', privileges_dropped=True,
                     hardware_attestation=False, private_inputs=False,
                     model_execution=False, worker_execution=False)
        changes = [{'version': True}, {'privileges_dropped': 1}, {'hardware_attestation': 0},
                   {'scope': 'private'}, {'extra': False}, {'worker_execution': True}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                R.ready_record(R.READY + R.encoded(dict(value, **change)))
        valid = R.READY + R.encoded(value)
        for raw in (valid + valid, b'x' * (4 * 1024 ** 2 + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                R.ready_record(raw)

    def test_two_public_turns_require_original_workload_and_final_cleanup(self):
        value = requester()
        self.assertEqual(R.requester_record(R.encoded(value), 'a' * 64), value)
        with self.assertRaisesRegex(ValueError, 'requester_receipt_scope'):
            R.requester_record(R.encoded(value), 'c' * 64)
        for field in ('private_inputs', 'hardware_attestation', 'guest_key_origin_proven', 'production_approval'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                R.requester_record(R.encoded(dict(value, **{field: True})), 'a' * 64)

    def test_requester_rejects_incomplete_wrong_or_unbounded_turns(self):
        base = requester()
        values = [dict(base, turns=[]), dict(base, turns=base['turns'][:1]),
                  dict(base, turns=base['turns'] * 2), dict(base, extra=False),
                  dict(base, tls_spki_sha256='not-a-digest'), dict(base, version=True)]
        for field, item in (('sequence', True), ('sequence', 2), ('answer', 'not READY'),
                            ('prompt_tokens', True), ('prompt_tokens', 0), ('prompt_tokens', 12289),
                            ('generated_tokens', True), ('generated_tokens', 0), ('generated_tokens', 1025)):
            changed = copy.deepcopy(base)
            changed['turns'][0][field] = item
            values.append(changed)
        for index, value in enumerate(values):
            with self.subTest(index=index), self.assertRaises(ValueError):
                R.requester_record(R.encoded(value), 'a' * 64)

    def test_cleanup_rejects_boolean_integer_aliases_missing_or_extra_fields(self):
        locations = [('final_cleanup', None), ('per_turn_cleanup', 0), ('per_turn_cleanup', 1)]
        for field, index in locations:
            base = requester()
            original = base[field] if index is None else base['turns'][index][field]
            changes = [dict(original, extra=False), {}]
            for key, value in original.items():
                alias = True if key == 'version' else int(value)
                changes.append(dict(original, **{key: alias}))
                changed = dict(original)
                del changed[key]
                changes.append(changed)
            for change in changes:
                value = copy.deepcopy(base)
                if index is None:
                    value[field] = change
                else:
                    value['turns'][index][field] = change
                with self.subTest(location=(field, index), change=change), self.assertRaises(ValueError):
                    R.requester_record(R.encoded(value), 'a' * 64)

    def test_requester_json_duplicates_nonfinite_and_size_rejected(self):
        raw = R.encoded(requester())
        for value in (b'{"version":1,' + raw[1:], raw.replace(b'"prompt_tokens":12', b'"prompt_tokens":NaN'),
                      b' ' * 65537):
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                R.requester_record(value, 'a' * 64)

    def test_positive_boot_receipt_proves_boot_not_hardware_or_model(self):
        value = boot()
        result = R.boot_record(b'public boot text\n' + R.BOOT + R.encoded(value), value['outcome'])
        self.assertEqual(result, value)
        self.assertFalse(result['model_execution'])
        self.assertFalse(result['hardware_attestation'])
        self.assertFalse(result['worker_cleanup_confirmed'])

    def test_corruption_receipt_never_claims_entrypoint_execution(self):
        value = boot('integrity_failure')
        self.assertEqual(R.boot_record(R.BOOT + R.encoded(value), 'integrity_failure'), value)

    def test_boot_wrong_flags_types_fields_and_outcome_rejected(self):
        changes = [{'version': True}, {'model_execution': True}, {'worker_cleanup_confirmed': True},
                   {'entrypoint_invoked': False}, {'verity_verified': 1}, {'stage': 'other'},
                   {'outcome': 'process_exited'}, {'extra': False}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                R.boot_record(R.BOOT + R.encoded(dict(boot(), **change)), 'guest_process_returned')
        for field in boot():
            value = boot()
            del value[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                R.boot_record(R.BOOT + R.encoded(value), 'guest_process_returned')

    def test_missing_duplicate_and_overlarge_boot_receipts_rejected(self):
        raw = R.BOOT + R.encoded(boot())
        duplicate_key = R.BOOT + b'{"version":1,' + R.encoded(boot())[1:]
        for data in (b'', raw + raw, duplicate_key, b'x' * (4 * 1024 ** 2 + 1)):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                R.boot_record(data, 'guest_process_returned')

    def test_execute_failure_is_closed_and_does_not_claim_vm_or_model_success(self):
        for error, expected in [('arbitrary_private_value', 'controller_stage_failed'),
                                ('controller_deadline', 'controller_deadline')]:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as temporary:
                args = types.SimpleNamespace(work=Path(temporary), appliance_kernel=Path('/not-opened'))
                with mock.patch.object(R.os, 'umask'), \
                        mock.patch.object(R, 'hosted', return_value=(None,
                            {'commit': '1' * 40, 'tree': '2' * 40}, {'synthetic': True}, {})), \
                        mock.patch.object(R, 'ImageTools', side_effect=ValueError(error)):
                    result = R.execute(args)
                self.assertEqual(result['state'], 'failed')
                self.assertEqual(result['phase'], 'prepare')
                self.assertEqual(result['failure'], expected)
                for field in ('model_execution', 'private_inputs', 'hardware_attestation',
                              'confidential_execution', 'production_approval', 'vm_cleanup_confirmed',
                              'scratch_removed'):
                    self.assertIs(result[field], False, field)
                self.assertEqual((args.work / 'evidence/result.json').read_bytes(), R.encoded(result))
                self.assertNotIn(b'arbitrary_private_value', R.encoded(result))

    def test_source_binding_requires_exact_checkout_and_clean_tracked_files(self):
        commit, tree = '1' * 40, '2' * 40
        with mock.patch.object(R, 'run', side_effect=[(commit.encode(), b'', 0),
                (b'', b'', 0), (tree.encode(), b'', 0)]) as command:
            self.assertEqual(R.source_binding(commit, 200), {'commit': commit, 'tree': tree})
        self.assertEqual(command.call_args_list[1].args[0][-3:], ['diff', '--name-only', 'HEAD'])
        with mock.patch.object(R, 'run', side_effect=[(commit.encode(), b'', 0), (b'dirty.py', b'', 0)]):
            with self.assertRaisesRegex(ValueError, 'source_changed'):
                R.source_binding(commit, 200)

    def test_single_link_regular_file_hash_and_denials(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'public'
            path.write_bytes(b'public fixture')
            path.chmod(0o600)
            self.assertEqual(R.file_hash(path, 200),
                             {'bytes': 14, 'sha256': hashlib.sha256(b'public fixture').hexdigest()})
            with self.assertRaisesRegex(ValueError, 'controller_file'):
                R.file_hash(path, 200, maximum=1)
            link = path.with_name('symlink')
            link.symlink_to(path)
            with self.assertRaises(OSError):
                R.file_hash(link, 200)
            os.link(path, path.with_name('hardlink'))
            with self.assertRaisesRegex(ValueError, 'controller_file'):
                R.file_hash(path, 200)

    def test_guestfish_script_has_no_host_network_or_unescaped_line(self):
        raw = R.fish_script([['mkdir-p', '/fixed/space name'], ['write', '/fixed/a', 'quoted "value"']])
        self.assertTrue(raw.startswith(b'set-pgroup false\nset-network false\nrun\n'))
        self.assertIn(b'"/fixed/space name"', raw)
        self.assertIn(b'\\"value\\"', raw)
        for operation in (['!shell', 'x'], ['write', '/x', 'x\ny'], ['write', '/x', '\x00']):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                R.fish_script([operation])

    def test_model_argv_has_fixed_resources_readonly_disks_and_no_nic(self):
        with mock.patch.object(R, 'module', return_value=types.SimpleNamespace(CMDLINE='fixed')):
            argv = R.qemu_model(Path('/fixed'), {'kernel': '/fixed/kernel'}, Path('/fixed/channel'))
        for key, value in (('-smp', '2'), ('-m', '12288'), ('-nic', 'none'), ('-monitor', 'none')):
            self.assertEqual(argv[argv.index(key) + 1], value)
        disks = [argv[index + 1] for index, value in enumerate(argv) if value == '-drive']
        self.assertEqual(len(disks), 2)
        self.assertTrue(all('readonly=on' in value for value in disks))
        self.assertNotIn('-virtfs', argv)
        self.assertNotIn('-netdev', argv)


class CommandLifecycle(Inert):
    def test_final_group_signal_precedes_direct_child_reap(self):
        events = []
        process = types.SimpleNamespace(pid=313, wait=lambda **_options: events.append('wait'))
        def kill(_pid, number):
            events.append(number)
            if number == 0:
                raise ProcessLookupError
        with mock.patch.object(R.os, 'killpg', side_effect=kill):
            R.joined(process)
        self.assertEqual(events, [signal.SIGKILL, 'wait', 0])

    def test_signal_failure_never_reaps_or_claims_cleanup(self):
        process = types.SimpleNamespace(pid=313, wait=mock.Mock())
        with mock.patch.object(R.os, 'killpg', side_effect=PermissionError):
            with self.assertRaises(R.CleanupUnconfirmed):
                R.joined(process)
        process.wait.assert_not_called()

    def test_cancellation_during_output_wait_joins_and_closes(self):
        process = types.SimpleNamespace(pid=313, stdout=mock.Mock(), stderr=mock.Mock(), returncode=0)
        events = mock.MagicMock()
        events.__enter__.return_value = events
        events.get_map.return_value = {1: True}
        def cancel(_timeout):
            self.assertFalse(R.CANCELLED, 'cancellation_ignored_by_output_wait')
            R.CANCELLED = True
            return []
        events.select.side_effect = cancel
        with mock.patch.object(R.subprocess, 'Popen', return_value=process), \
                mock.patch.object(R.selectors, 'DefaultSelector', return_value=events), \
                mock.patch.object(R.os, 'set_blocking'), mock.patch.object(R, 'joined') as join:
            with self.assertRaisesRegex(ValueError, 'controller_cancelled'):
                R.run(['not-executed'], 200)
        join.assert_called_once_with(process)
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()

    def test_cancellation_after_pipe_eof_joins_and_closes(self):
        process = types.SimpleNamespace(pid=313, stdout=mock.Mock(), stderr=mock.Mock(), returncode=0)
        events = mock.MagicMock()
        events.__enter__.return_value = events
        events.get_map.return_value = {}
        def cancel(*_args):
            self.assertFalse(R.CANCELLED, 'cancellation_ignored_by_exit_wait')
            R.CANCELLED = True
            return None
        with mock.patch.object(R.subprocess, 'Popen', return_value=process), \
                mock.patch.object(R.selectors, 'DefaultSelector', return_value=events), \
                mock.patch.object(R.os, 'set_blocking'), mock.patch.object(R.os, 'waitid', side_effect=cancel), \
                mock.patch.object(R, 'joined') as join:
            with self.assertRaisesRegex(ValueError, 'controller_cancelled'):
                R.run(['not-executed'], 200)
        join.assert_called_once_with(process)
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
