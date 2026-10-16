#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert controller checks: no subprocess, systemd unit, VM, or model is run."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
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


def memory(total=16 * R.GIB, available=15 * R.GIB, dirty=1024, writeback=2048):
    return (f'MemTotal: {total // 1024} kB\nMemAvailable: {available // 1024} kB\n'
            f'Dirty: {dirty // 1024} kB\nWriteback: {writeback // 1024} kB\n').encode()


DISK_STAGES = ('inspect_roots', 'inspect_details', 'root_export', 'raw_resize',
               'runtime_uuid', 'build_overlay', 'seed')


def inspected_root(device='/dev/sda1', size=4096, disk_size=16384, partitions=((1, 4096, 4096),)):
    table = ''.join(f'[{index}] = {{\n  part_num: {number}\n  part_start: {start}\n'
                    f'  part_end: {start + length - 1}\n  part_size: {length}\n}}\n'
                    for index, (number, start, length) in enumerate(partitions))
    return f'{device}\ndebian\n13\next4\n{size}\n{disk_size}\n' + table


@contextlib.contextmanager
def fake_tool(*, join_error=None, returncode=0):
    """Exercise real run bookkeeping without a process, pipe, wait or signal."""
    process = types.SimpleNamespace(pid=313, stdout=mock.Mock(), stderr=mock.Mock(), returncode=returncode)
    events = mock.MagicMock()
    events.__enter__.return_value = events
    events.get_map.return_value = {}
    with contextlib.ExitStack() as patches:
        patches.enter_context(mock.patch.object(R.subprocess, 'Popen', return_value=process))
        patches.enter_context(mock.patch.object(R.selectors, 'DefaultSelector', return_value=events))
        patches.enter_context(mock.patch.object(R.os, 'set_blocking'))
        patches.enter_context(mock.patch.object(R.os, 'waitid', return_value=object()))
        join = patches.enter_context(mock.patch.object(R, 'joined', side_effect=join_error))
        yield process, join


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
            scope = R.Scope(['synthetic-qemu'], work, 200, {}, 50, 'build')
            process = types.SimpleNamespace(pid=313)
            original_open = Path.open
            observations = []
            def opened(path, *args, **kwargs):
                if path == Path('/proc/meminfo'):
                    return io.BytesIO(memory())
                return original_open(path, *args, **kwargs)
            def spawned(*_args, **_kwargs):
                self.assertTrue(observations[0]['admitted'], 'snapshot_not_stored_before_launch')
                return process
            with mock.patch.object(Path, 'open', opened), \
                    mock.patch.object(R.subprocess, 'Popen', side_effect=spawned) as launch, \
                    mock.patch.object(scope, 'state', return_value={'ControlGroup': '/user.slice/' + scope.unit}), \
                    mock.patch.object(R, 'scope_path', return_value=group):
                try:
                    scope.start(observations)
                finally:
                    if scope.log is not None:
                        scope.log.close()
            self.assertIs(scope.process, process)
            self.assertEqual(scope.group, group)
            self.assertIn('--scope', launch.call_args.args[0])
            self.assertIn('--property=MemoryMax=' + str(13 * R.GIB), launch.call_args.args[0])
            self.assertIn('--property=MemorySwapMax=0', launch.call_args.args[0])
            self.assertTrue(launch.call_args.kwargs['start_new_session'])
            self.assertEqual(observations[0]['mem_total_bytes'], 16 * R.GIB)
            self.assertEqual(observations[0]['mem_available_bytes'], 15 * R.GIB)
            self.assertEqual(observations[0]['dirty_bytes'], 1024)
            self.assertEqual(observations[0]['writeback_bytes'], 2048)

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


class MemoryObservation(Inert):
    def test_baseline_observes_high_or_low_values_without_admission_or_process(self):
        for available in (0, 15 * R.GIB):
            with self.subTest(available=available):
                snapshot = dict(label='baseline', phase='before_disks')
                with mock.patch.object(Path, 'open', return_value=io.BytesIO(memory(available=available))) as opened:
                    R.memory_snapshot(snapshot, 200)
                opened.assert_called_once_with('rb')
                self.assertEqual(snapshot['state'], 'observed')
                self.assertEqual(snapshot['mem_available_bytes'], available)
                self.assertEqual(snapshot['dirty_bytes'], 1024)
                self.assertEqual(snapshot['writeback_bytes'], 2048)
                self.assertIsNone(snapshot['admitted'])
                R.subprocess.Popen.assert_not_called()

    def test_baseline_read_or_parse_failure_is_explicit_unavailable_not_rejection(self):
        for raw in (OSError('private-canary'), b'not a memory snapshot', b'x' * 65537):
            with self.subTest(kind=type(raw).__name__):
                snapshot = dict(label='baseline', phase='before_disks')
                with mock.patch.object(Path, 'open', side_effect=raw if isinstance(raw, OSError) else None,
                                       return_value=io.BytesIO(raw if isinstance(raw, bytes) else b'')):
                    R.memory_snapshot(snapshot, 200)
                self.assertEqual(snapshot['state'], 'unavailable')
                for key in ('mem_total_bytes', 'mem_available_bytes', 'dirty_bytes', 'writeback_bytes', 'admitted'):
                    self.assertIsNone(snapshot[key])
                self.assertNotIn(b'private-canary', R.encoded(snapshot))
                R.subprocess.Popen.assert_not_called()

    def test_four_exact_counters_convert_kibibytes_without_exporting_other_rows(self):
        raw = memory() + b'WritebackTmp: 0 kB\nPrivateCanary: 12345 kB\n'
        self.assertEqual(R.memory_values(raw), (16 * R.GIB, 15 * R.GIB, 1024, 2048))
        with mock.patch.object(Path, 'open', return_value=io.BytesIO(raw)):
            rows = []
            self.assertEqual(R.memory_admission(rows, 'build', 200), 15 * R.GIB)
        self.assertEqual(rows[0].keys(), {'version', 'phase', 'label', 'state', 'mem_total_bytes',
            'mem_available_bytes', 'dirty_bytes', 'writeback_bytes', 'required_available_bytes',
            'guest_memory_bytes', 'qemu_memory_max_bytes', 'qemu_swap_max_bytes', 'admitted'})
        self.assertEqual((rows[0]['required_available_bytes'], rows[0]['guest_memory_bytes'],
                          rows[0]['qemu_memory_max_bytes'], rows[0]['qemu_swap_max_bytes']),
                         (14 * R.GIB, 12 * R.GIB, 13 * R.GIB, 0))
        self.assertNotIn(b'PrivateCanary', R.encoded(rows))
        self.assertNotIn(b'/proc/', R.encoded(rows))

    def test_each_required_counter_is_unique_and_present(self):
        lines = memory().splitlines(keepends=True)
        for index in range(4):
            for raw in (b''.join(lines[:index] + lines[index + 1:]), b''.join(lines + [lines[index]])):
                with self.subTest(index=index, raw=raw), self.assertRaisesRegex(ValueError, 'host_memory_snapshot'):
                    R.memory_values(raw)

    def test_bounded_ascii_exact_units_and_decimal_fields_fail_closed(self):
        original = memory()
        variants = [None, original.decode(), b'x' * 65537, original + b'\xff',
                    original.replace(b'kB', b'KB'), original.replace(b'kB', b'bytes'),
                    original.replace(b'Dirty: 1', b'Dirty: -1'), original.replace(b'Dirty: 1', b'Dirty: +1'),
                    original.replace(b'Dirty: 1', b'Dirty: 1.0'), original.replace(b'Dirty: 1', b'Dirty: True'),
                    original.replace(b'Dirty: 1', b'Dirty: ' + b'1' * 17),
                    original.replace(b'Dirty: 1 kB', b'Dirty: 1 kB trailing'),
                    original.replace(b'MemTotal:', b'MemTotalExtra:')]
        for index, raw in enumerate(variants):
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'host_memory_snapshot'):
                R.memory_values(raw)

    def test_impossible_values_rejected_but_zero_available_is_an_observation(self):
        for values in ({'total': 0}, {'total': 2 ** 63}, {'available': 17 * R.GIB},
                       {'dirty': 17 * R.GIB}, {'writeback': 17 * R.GIB}):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, 'host_memory_snapshot'):
                R.memory_values(memory(**values))
        self.assertEqual(R.memory_values(memory(available=0))[1], 0)

    def test_low_available_keeps_snapshot_and_never_creates_scope_or_process(self):
        for available in (0, 14 * R.GIB - 1024):
            with self.subTest(available=available), tempfile.TemporaryDirectory() as temporary:
                scope = R.Scope(['not-executed'], Path(temporary), 200, {}, 50, 'build')
                rows = []
                with mock.patch.object(Path, 'open', return_value=io.BytesIO(memory(available=available))), \
                        mock.patch.object(scope, 'state') as state:
                    with self.assertRaisesRegex(ValueError, 'host_memory_headroom'):
                        scope.start(rows)
                R.subprocess.Popen.assert_not_called()
                state.assert_not_called()
                self.assertEqual(rows[0]['mem_available_bytes'], available)
                self.assertFalse(rows[0]['admitted'])
                self.assertEqual(rows[0]['state'], 'observed')
                self.assertFalse(scope.started)
                self.assertIsNone(scope.process)
                self.assertIsNone(scope.log)
                self.assertIsNone(scope.group)
                self.assertFalse(scope.logpath.exists())

    def test_read_failure_and_overlarge_input_remain_unavailable_before_spawn(self):
        for raw in (OSError('private-canary-path'), b'x' * 65537, b'Dirty: 1 kB\n'):
            with self.subTest(kind=type(raw).__name__):
                rows = []
                stream = mock.MagicMock()
                stream.__enter__.return_value.read.return_value = raw
                with mock.patch.object(Path, 'open', side_effect=raw if isinstance(raw, OSError) else None,
                                       return_value=stream):
                    with self.assertRaisesRegex(ValueError, 'host_memory_snapshot'):
                        R.Scope(['not-executed'], Path('/synthetic'), 200, {}, 50, 'build').start(rows)
                if not isinstance(raw, OSError):
                    stream.__enter__.return_value.read.assert_called_once_with(65537)
                self.assertEqual(rows[0]['state'], 'unavailable')
                for key in ('mem_total_bytes', 'mem_available_bytes', 'dirty_bytes', 'writeback_bytes', 'admitted'):
                    self.assertIsNone(rows[0][key])
                self.assertNotIn(b'private-canary', R.encoded(rows))
                R.subprocess.Popen.assert_not_called()

    def test_exact_three_ordered_checks_do_not_repoll_or_accept_free_labels(self):
        rows = []
        with mock.patch.object(Path, 'open', side_effect=lambda *_a, **_k: io.BytesIO(memory(available=14 * R.GIB))) as opened:
            for label in ('build', 'model', 'corrupt'):
                self.assertEqual(R.memory_admission(rows, label, 200), 14 * R.GIB)
            for label in ('build', 'model', 'corrupt', 'private-canary'):
                with self.assertRaisesRegex(ValueError, 'host_memory_snapshot'):
                    R.memory_admission(rows, label, 200)
            self.assertEqual(opened.call_count, 3)
        self.assertEqual([row['label'] for row in rows], ['build', 'model', 'corrupt'])
        self.assertTrue(all(row['phase'] == 'before_scope_start' and row['admitted'] is True for row in rows))
        with mock.patch.object(Path, 'open') as opened:
            for label in ('model', 'corrupt', 'arbitrary'):
                with self.assertRaises(ValueError):
                    R.memory_admission([], label, 200)
            opened.assert_not_called()

    def test_snapshot_does_not_reset_original_deadline_or_ignore_cancellation(self):
        with mock.patch.object(Path, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'controller_deadline'):
                R.memory_admission([], 'build', 99)
            R.CANCELLED = True
            with self.assertRaisesRegex(ValueError, 'controller_cancelled'):
                R.memory_admission([], 'build', 200)
            opened.assert_not_called()
        R.CANCELLED = False
        rows = []
        with mock.patch.object(Path, 'open', return_value=io.BytesIO(memory())), \
                mock.patch.object(R.time, 'monotonic', side_effect=[100, 201]):
            with self.assertRaisesRegex(ValueError, 'controller_deadline'):
                R.memory_admission(rows, 'build', 200)
        self.assertIsNone(rows[0]['admitted'])
        R.subprocess.Popen.assert_not_called()

    def execute_disk_case(self, available, baseline, *, disk_sample=None, failure=None, wrong_uuid=False,
                          scope_cleanup_error=None, export_error=None):
        pins = R.json.loads((R.HERE / 'protected-resident-image-pins-v1.json').read_bytes())
        if disk_sample is None:
            disk_sample = memory(available=available)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            requester_path = work / 'target/requester'
            requester_path.parent.mkdir()
            requester_path.write_bytes(b'public inert executable placeholder, never run')
            manifest = work / pins['debian_image_manifest']
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_bytes(b'{}')
            group = work / 'cgroup'
            group.mkdir()
            for name, raw in {'memory.max': str(R.QEMU_BYTES), 'memory.swap.max': '0',
                              'cgroup.procs': '313', 'cgroup.events': 'populated 0\n'}.items():
                (group / name).write_text(raw)
            args = types.SimpleNamespace(work=work, appliance_kernel=Path('/not-opened'),
                expected_source='1' * 40, requester=requester_path)
            base = types.SimpleNamespace(fetch=mock.Mock(), root_device=lambda _raw: '/dev/sda1')
            memory_reads, operations = [], []
            def operation(label):
                self.assertEqual(len(memory_reads), 1 + len(operations),
                                 'observation_missing_or_precedes_joined_operation')
                self.assertEqual(label, DISK_STAGES[len(operations)])
                if label == failure:
                    raise ValueError('private-operation-canary')
                operations.append(label)
            def fish(_image, ops, **_options):
                if len(ops) == 1 and ops[0][0] == 'inspect-os':
                    operation('inspect_roots')
                    return '/dev/sda1\n'
                if ops[0][0] == 'inspect-os':
                    operation('inspect_details')
                    self.assertEqual(ops, [['inspect-os'], ['inspect-get-distro', '/dev/sda1'],
                        ['inspect-get-major-version', '/dev/sda1'], ['vfs-type', '/dev/sda1'],
                        ['blockdev-getsize64', '/dev/sda1'], ['blockdev-getsize64', '/dev/sda'],
                        ['part-list', '/dev/sda']])
                    return inspected_root()
                if ops[0][0] == 'set-uuid':
                    operation('runtime_uuid')
                    self.assertEqual(ops, [['set-uuid', '/dev/sda', ops[0][2]], ['vfs-uuid', '/dev/sda']],
                                     'host_must_not_resize_runtime_filesystem')
                    return 'wrong-public-uuid' if wrong_uuid else ops[0][2]
                self.fail('unexpected_guestfish_operation')
            def exported(path, geometry, _pin, deadline):
                self.assertEqual(path, work / 'payload')
                self.assertEqual(geometry, {'offset': 4096, 'size': 4096, 'disk_size': 16384})
                self.assertEqual(deadline, 100 + R.MAX_SECONDS)
                if export_error is not None:
                    raise export_error
                operation('root_export')
            def command(argv, *_args, **_options):
                if argv[:2] == ['qemu-img', 'resize']:
                    self.assertEqual(argv[2:], ['-f', 'raw', work / 'payload/runtime-root.raw', str(32 * R.GIB)])
                    operation('raw_resize')
                elif argv[:2] == ['qemu-img', 'create']:
                    operation('build_overlay')
                else:
                    self.assertEqual(argv[0], 'systemctl', 'unexpected_process_path')
                return b'', b'', 0
            original_open, original_read = Path.open, Path.read_bytes
            def opened(path, *args, **kwargs):
                if path == Path('/proc/meminfo'):
                    index = len(memory_reads)
                    raw = baseline if index == 0 else disk_sample if index <= 7 else memory(available=available)
                    memory_reads.append(True)
                    if isinstance(raw, OSError):
                        raise raw
                    return io.BytesIO(raw)
                return original_open(path, *args, **kwargs)
            def read(path):
                if str(path) in ('/proc/net/route', '/proc/net/ipv6_route', '/etc/resolv.conf'):
                    return b'public test network observation'
                return original_read(path)
            process = types.SimpleNamespace(pid=313)
            with contextlib.ExitStack() as patches:
                patches.enter_context(mock.patch.object(R, 'ROOT', work))
                patches.enter_context(mock.patch.object(R.os, 'umask'))
                patches.enter_context(mock.patch.object(R, 'hosted', return_value=(base,
                    {'commit': '1' * 40, 'tree': '2' * 40}, {}, {})))
                patches.enter_context(mock.patch.object(R, 'ImageTools', return_value=types.SimpleNamespace(fish=fish)))
                patches.enter_context(mock.patch.object(R, 'export_root', side_effect=exported))
                patches.enter_context(mock.patch.object(R, 'file_hash', return_value={'bytes': 1, 'sha256': 'a' * 64}))
                patches.enter_context(mock.patch.object(R, 'public_keys'))
                patches.enter_context(mock.patch.object(R, 'seed', side_effect=lambda *_args: operation('seed')))
                patches.enter_context(mock.patch.object(R, 'source_bundle', return_value={'sha256': 'a' * 64}))
                patches.enter_context(mock.patch.object(R, 'reserve_space', return_value={}))
                patches.enter_context(mock.patch.object(R.socket, 'socket'))
                patches.enter_context(mock.patch.object(R, 'run', side_effect=command))
                patches.enter_context(mock.patch.object(Path, 'open', opened))
                patches.enter_context(mock.patch.object(Path, 'read_bytes', read))
                launch = patches.enter_context(mock.patch.object(R.subprocess, 'Popen', return_value=process))
                patches.enter_context(mock.patch.object(R.Scope, 'state', return_value={
                    'ControlGroup': '/user.slice/test.scope', 'ActiveState': 'inactive'}))
                patches.enter_context(mock.patch.object(R, 'scope_path', return_value=group))
                patches.enter_context(mock.patch.object(R, 'joined'))
                patches.enter_context(mock.patch.object(R, 'Guest', side_effect=ValueError('after_admission')))
                if scope_cleanup_error is not None:
                    def failed_stop(scope):
                        if scope.log is not None:
                            scope.log.close()
                        raise scope_cleanup_error
                    patches.enter_context(mock.patch.object(R.Scope, 'stop', autospec=True, side_effect=failed_stop))
                result = R.execute(args)
            self.assertEqual((work / 'evidence/result.json').read_bytes(), R.encoded(result))
            self.assertNotIn(b'private-operation-canary', R.encoded(result))
            self.assertEqual((work / 'payload').exists(), scope_cleanup_error is not None)
            self.assertIs(result['scratch_removed'], scope_cleanup_error is None)
            self.assertTrue(result['tool_cleanup_confirmed'])
            return result, len(memory_reads), launch.call_count, operations

    def test_execute_persists_pass_or_failure_snapshot_without_model_claim(self):
        for available, baseline, disk_sample in (
                (14 * R.GIB - 1024, memory(), memory()),
                (14 * R.GIB, OSError('private-baseline-canary'), OSError('private-disk-canary')),
                (14 * R.GIB, memory(available=0), memory(available=0))):
            with self.subTest(available=available):
                result, reads, launches, operations = self.execute_disk_case(
                    available, baseline, disk_sample=disk_sample)
                self.assertEqual(reads, 9, 'baseline_disk_observations_or_admission_retried')
                self.assertEqual(operations, list(DISK_STAGES))
                observations = result['disk_memory_observations']
                self.assertEqual([row['label'] for row in observations], list(DISK_STAGES))
                self.assertTrue(all(row['phase'] == 'after_disk_operation' and row['admitted'] is None
                                    for row in observations))
                self.assertTrue(all(row['state'] == ('unavailable' if isinstance(disk_sample, OSError)
                                                    else 'observed') for row in observations))
                before_disks = result['memory_before_disks']
                self.assertEqual((before_disks['label'], before_disks['phase']), ('baseline', 'before_disks'))
                self.assertEqual(before_disks['state'], 'unavailable' if isinstance(baseline, OSError) else 'observed')
                self.assertIsNone(before_disks['admitted'])
                self.assertNotIn(b'private-baseline-canary', R.encoded(result))
                self.assertNotIn(b'private-disk-canary', R.encoded(result))
                self.assertEqual(len(result['memory_admissions']), 1)
                snapshot = result['memory_admissions'][0]
                admitted = available >= 14 * R.GIB
                self.assertEqual(snapshot['admitted'], admitted)
                self.assertEqual(snapshot['mem_available_bytes'], available)
                self.assertEqual(launches, int(admitted))
                self.assertEqual(result['failure'], 'controller_stage_failed' if admitted else 'host_memory_headroom')
                self.assertEqual(result['state'], 'failed')
                self.assertFalse(result['model_execution'])
                self.assertFalse(result['private_inputs'])
                self.assertFalse(result['hardware_attestation'])

    def test_failed_disk_operation_keeps_only_completed_prefix_and_never_spawns(self):
        for index, label in enumerate(DISK_STAGES):
            with self.subTest(label=label):
                result, reads, launches, operations = self.execute_disk_case(
                    15 * R.GIB, memory(), failure=label)
                self.assertEqual(operations, list(DISK_STAGES[:index]))
                self.assertEqual([row['label'] for row in result['disk_memory_observations']],
                                 list(DISK_STAGES[:index]))
                self.assertEqual(reads, 1 + index)
                self.assertEqual(launches, 0)
                self.assertEqual(result['memory_admissions'], [])
                self.assertEqual((result['state'], result['phase']), ('failed', 'prepare_disks'))
                self.assertFalse(result['model_execution'])

    def test_uuid_validation_precedes_observation_overlay_and_vm_attach(self):
        result, reads, launches, operations = self.execute_disk_case(15 * R.GIB, memory(), wrong_uuid=True)
        self.assertEqual(operations, list(DISK_STAGES[:5]))
        self.assertEqual([row['label'] for row in result['disk_memory_observations']], list(DISK_STAGES[:4]))
        self.assertEqual(reads, 5)
        self.assertEqual(launches, 0)
        self.assertEqual(result['memory_admissions'], [])
        self.assertEqual(result['failure'], 'runtime_uuid')

    def test_compare_failure_stops_before_resize_admission_and_vm(self):
        result, reads, launches, operations = self.execute_disk_case(15 * R.GIB, memory(),
            export_error=ValueError('root_export_compare'))
        self.assertEqual(operations, list(DISK_STAGES[:2]))
        self.assertEqual([row['label'] for row in result['disk_memory_observations']], list(DISK_STAGES[:2]))
        self.assertEqual((reads, launches), (3, 0))
        self.assertEqual(result['memory_admissions'], [])
        self.assertEqual((result['failure'], result['phase']), ('root_export_compare', 'prepare_disks'))
        self.assertTrue(result['scratch_removed'])
        self.assertFalse(result['model_execution'])

    def test_scope_cleanup_failure_keeps_payload_and_original_failure(self):
        result, reads, launches, _ = self.execute_disk_case(15 * R.GIB, memory(),
            scope_cleanup_error=R.CleanupUnconfirmed('private-scope-canary'))
        self.assertEqual((reads, launches), (9, 1))
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['failure'], 'controller_stage_failed')
        self.assertEqual(result['scratch_cleanup_failure'], 'process_cleanup_unconfirmed')
        self.assertFalse(result['scratch_removed'])
        self.assertFalse(result['vm_cleanup_confirmed'])
        self.assertNotIn(b'private-scope-canary', R.encoded(result))


class DiskMemoryObservation(Inert):
    def test_exact_seven_ordered_observations_have_closed_schema_and_bound(self):
        self.assertEqual(R.DISK_MEMORY_STAGES, DISK_STAGES)
        rows = []
        with mock.patch.object(Path, 'open', side_effect=lambda *_a, **_k: io.BytesIO(memory())) as opened:
            for label in DISK_STAGES:
                R.disk_memory_observation(rows, label, 200)
            for label in (*DISK_STAGES, 'private-stage-canary'):
                with self.assertRaisesRegex(ValueError, 'host_memory_snapshot'):
                    R.disk_memory_observation(rows, label, 200)
            self.assertEqual(opened.call_count, 7)
        self.assertEqual([row['label'] for row in rows], list(DISK_STAGES))
        for row in rows:
            self.assertEqual(row.keys(), {'version', 'phase', 'label', 'state', 'mem_total_bytes',
                'mem_available_bytes', 'dirty_bytes', 'writeback_bytes', 'required_available_bytes',
                'guest_memory_bytes', 'qemu_memory_max_bytes', 'qemu_swap_max_bytes', 'admitted'})
            self.assertEqual((row['phase'], row['state'], row['version']), ('after_disk_operation', 'observed', 1))
            self.assertEqual((row['mem_total_bytes'], row['mem_available_bytes'], row['dirty_bytes'],
                              row['writeback_bytes']), (16 * R.GIB, 15 * R.GIB, 1024, 2048))
            self.assertEqual((row['required_available_bytes'], row['guest_memory_bytes'],
                              row['qemu_memory_max_bytes'], row['qemu_swap_max_bytes']),
                             (14 * R.GIB, 12 * R.GIB, 13 * R.GIB, 0))
            self.assertIsNone(row['admitted'])
        R.subprocess.Popen.assert_not_called()

    def test_unknown_duplicate_and_out_of_order_labels_fail_before_read_or_append(self):
        for prefix in range(len(DISK_STAGES)):
            rows = [dict(label=label, phase='after_disk_operation') for label in DISK_STAGES[:prefix]]
            for label in (*DISK_STAGES[:prefix], *DISK_STAGES[prefix + 1:], 'private-stage-canary', None, True):
                before = copy.deepcopy(rows)
                with self.subTest(prefix=prefix, label=label), mock.patch.object(Path, 'open') as opened:
                    with self.assertRaisesRegex(ValueError, 'host_memory_snapshot'):
                        R.disk_memory_observation(rows, label, 200)
                    opened.assert_not_called()
                self.assertEqual(rows, before)
        with mock.patch.object(Path, 'open') as opened:
            for rows in (None, (), {}, 'private-list-canary'):
                with self.assertRaisesRegex(ValueError, 'host_memory_snapshot'):
                    R.disk_memory_observation(rows, 'inspect_roots', 200)
            opened.assert_not_called()

    def test_low_and_unavailable_observations_neither_admit_nor_reject(self):
        for raw in (memory(available=0), OSError('private-read-canary'), b'Dirty: 0 kB\n', b'x' * 65537):
            rows = []
            with self.subTest(kind=type(raw).__name__), mock.patch.object(R, 'memory_admission') as admission:
                with mock.patch.object(Path, 'open', side_effect=raw if isinstance(raw, OSError) else None,
                                       return_value=io.BytesIO(raw if isinstance(raw, bytes) else b'')) as opened:
                    R.disk_memory_observation(rows, 'inspect_roots', 200)
                opened.assert_called_once_with('rb')
                admission.assert_not_called()
            observed = raw == memory(available=0)
            self.assertEqual(rows[0]['state'], 'observed' if observed else 'unavailable')
            self.assertIsNone(rows[0]['admitted'])
            self.assertEqual(rows[0]['mem_available_bytes'], 0 if observed else None)
            self.assertNotIn(b'private-read-canary', R.encoded(rows))
            R.subprocess.Popen.assert_not_called()

    def test_disk_snapshot_rejects_cross_phase_free_labels_and_extra_keys(self):
        invalid = [dict(label=label, phase='before_scope_start') for label in DISK_STAGES]
        invalid += [dict(label=label, phase='after_disk_operation') for label in ('build', 'baseline', 'private-label')]
        invalid += [dict(label='inspect_roots', phase='after_disk_operation', extra=True)]
        with mock.patch.object(Path, 'open') as opened:
            for snapshot in invalid:
                with self.subTest(snapshot=snapshot), self.assertRaisesRegex(ValueError, 'host_memory_snapshot'):
                    R.memory_snapshot(snapshot, 200)
            opened.assert_not_called()

    def test_expiry_and_cancellation_before_read_do_not_restart_or_spawn(self):
        for end, cancelled, reason in ((99, False, 'controller_deadline'), (200, True, 'controller_cancelled')):
            rows = []
            with self.subTest(reason=reason), mock.patch.object(R, 'CANCELLED', cancelled), \
                    mock.patch.object(Path, 'open') as opened:
                with self.assertRaisesRegex(ValueError, reason):
                    R.disk_memory_observation(rows, 'inspect_roots', end)
                opened.assert_not_called()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['state'], 'unavailable')
            self.assertIsNone(rows[0]['admitted'])
            R.subprocess.Popen.assert_not_called()

    def test_original_deadline_is_checked_after_successful_or_failed_read(self):
        for fail in (False, True):
            rows = []
            with self.subTest(read_failure=fail), mock.patch.object(R.time, 'monotonic', side_effect=[100, 201]), \
                    mock.patch.object(Path, 'open', side_effect=OSError('private-read-canary') if fail else None,
                                      return_value=io.BytesIO(memory())) as opened:
                with self.assertRaisesRegex(ValueError, 'controller_deadline'):
                    R.disk_memory_observation(rows, 'inspect_roots', 200)
                opened.assert_called_once_with('rb')
            self.assertEqual(rows[0]['state'], 'unavailable')
            self.assertIsNone(rows[0]['admitted'])
            self.assertNotIn(b'private-read-canary', R.encoded(rows))
            R.subprocess.Popen.assert_not_called()


class RootGeometry(Inert):
    def test_selected_root_is_exact_byte_range_among_valid_partitions(self):
        raw = inspected_root('/dev/sdb3', partitions=((1, 512, 512), (3, 4096, 4096), (2, 12288, 1024)))
        self.assertEqual(R.root_geometry('/dev/sdb3', raw),
                         {'offset': 4096, 'size': 4096, 'disk_size': 16384})
        R.subprocess.Popen.assert_not_called()

    def test_wrong_root_os_or_filesystem_never_produces_geometry(self):
        raw = inspected_root()
        for device in (None, True, '/dev/sda', '/dev/sda0', '/dev/sda01', '/dev/sdaa1', '/dev/sda1,driver=host_device'):
            with self.subTest(device=device), self.assertRaises(ValueError):
                R.root_geometry(device, raw)
        for old, new in (('/dev/sda1', '/dev/sda2'), ('debian', 'other'), ('13', '12'),
                         ('ext4', 'xfs'), ('/dev/sda1\n', '/dev/sda1\n/dev/sda2\n')):
            with self.subTest(value=new), self.assertRaises(ValueError):
                R.root_geometry('/dev/sda1', raw.replace(old, new, 1))

    def test_missing_truncated_extra_or_malformed_table_is_denied(self):
        raw = inspected_root()
        invalid = (None, b'wrong type', raw[:20], raw[:-4], raw + 'private-canary\n',
                   raw.replace('part_num:', 'unknown:'), raw.replace('part_start: 4096', 'part_start: 0x1000'),
                   raw.replace('part_end: 8191', 'part_end: 8192'), raw.replace('[0]', '[1]'),
                   raw.replace('4096\n16384', '+4096\n16384'), raw + 'x' * 16384)
        for value in invalid:
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                R.root_geometry('/dev/sda1', value)

    def test_duplicate_overlapping_missing_root_or_wrong_size_is_denied(self):
        for partitions in (((1, 4096, 4096), (1, 12288, 512)),
                           ((1, 4096, 4096), (2, 7680, 512)),
                           ((2, 4096, 4096),), ((1, 4096, 8192),)):
            with self.subTest(partitions=partitions), self.assertRaises(ValueError):
                R.root_geometry('/dev/sda1', inspected_root(partitions=partitions))

    def test_geometry_bounds_alignment_and_table_count_fail_closed(self):
        invalid = [inspected_root(size=value) for value in (0, 4095, 4097, 16 * R.GIB + 4096)]
        invalid += [inspected_root(disk_size=value) for value in (0, 4096, 16385, R.RUNTIME_BYTES + 512)]
        invalid += [inspected_root(partitions=((1, start, length),))
                    for start, length in ((0, 4096), (1, 4096), (4096, 4095), (12288, 8192))]
        invalid.append(inspected_root(disk_size=65536,
            partitions=tuple((index + 1, (index + 1) * 512, 512) for index in range(65))))
        for raw in invalid:
            with self.subTest(raw=raw[:64]), self.assertRaises(ValueError):
                R.root_geometry('/dev/sda1', raw)


class SparseRootExport(Inert):
    @contextlib.contextmanager
    def fixture(self, *, header_change=None, parent_name='owned'):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / parent_name
            parent.mkdir(mode=0o700)
            work = parent / 'payload'
            work.mkdir(mode=0o700)
            header = bytearray(104)
            header[:4] = b'QFI\xfb'
            header[4:8] = (3).to_bytes(4, 'big')
            header[20:24] = (16).to_bytes(4, 'big')
            header[24:32] = (16384).to_bytes(8, 'big')
            header[100:104] = (104).to_bytes(4, 'big')
            if header_change:
                header_change(header)
            image = work / 'base.qcow2'
            image.write_bytes(header)
            image.chmod(0o600)
            pin = {'sha512': hashlib.sha512(header).hexdigest()}
            yield work, {'offset': 4096, 'size': 4096, 'disk_size': 16384}, pin

    def converter(self, work, geometry, calls, *, mismatch=0, change=None):
        def command(argv, deadline, **options):
            calls.append((argv, deadline, options))
            target = work / 'runtime-root.raw'
            if argv[1] == 'convert':
                self.assertEqual(target.stat().st_size, geometry['size'])
                target.write_bytes(b'public-fixture' + bytes(geometry['size'] - 14))
            else:
                self.assertEqual(argv[1], 'compare')
            if change:
                change(argv[1], target)
            return b'', b'', mismatch if argv[1] == 'compare' else 0
        return command

    def test_sparse_convert_exact_graph_and_compare_before_return(self):
        with self.fixture(parent_name='owned,driver=canary:json') as (work, geometry, pin):
            calls = []
            with mock.patch.object(R, 'run', side_effect=self.converter(work, geometry, calls)):
                R.export_root(work, geometry, pin, 200)
            graph = 'json:' + R.encoded(dict(driver='raw', offset=4096, size=4096,
                file=dict(driver='qcow2', file=dict(driver='file', filename=str(work / 'base.qcow2'))))).decode().strip()
            target = work / 'runtime-root.raw'
            self.assertEqual(calls, [(['qemu-img', 'convert', '-q', '-n', '-O', 'raw', '-S', '4096',
                '-m', '1', '-t', 'writeback', graph, target], 200.0, {'cap': 600, 'maximum': 4096}),
                (['qemu-img', 'compare', '-q', '-F', 'raw', graph, target], 200.0,
                 {'cap': 600, 'maximum': 4096, 'check': False})])
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(target.stat().st_nlink, 1)
            self.assertEqual(hashlib.sha512((work / 'base.qcow2').read_bytes()).hexdigest(), pin['sha512'])
        R.subprocess.Popen.assert_not_called()

    def test_export_revalidates_geometry_before_files_or_commands(self):
        invalid = [None, [], {}, dict(offset=True, size=4096, disk_size=16384)]
        for field, values in {'offset': (0, 1, -512, 16384), 'size': (0, 4095, 16 * R.GIB + 4096),
                              'disk_size': (4096, 16385, R.RUNTIME_BYTES + 512)}.items():
            for value in values:
                row = dict(offset=4096, size=4096, disk_size=16384)
                row[field] = value
                invalid.append(row)
        invalid.append(dict(offset=4096, size=4096, disk_size=16384, extra=True))
        with mock.patch.object(R, 'run') as command, mock.patch.object(R, 'directory_identity') as identity:
            for geometry in invalid:
                with self.subTest(geometry=geometry), self.assertRaisesRegex(ValueError, 'root_geometry'):
                    R.export_root(Path('/not-opened/payload'), geometry, {}, 200)
            command.assert_not_called()
            identity.assert_not_called()

    def test_backing_external_data_encryption_and_bad_header_denied_before_qemu(self):
        changes = ((0, 4, b'nope'), (4, 8, (4).to_bytes(4, 'big')),
                   (8, 16, (104).to_bytes(8, 'big')), (16, 20, (1).to_bytes(4, 'big')),
                   (24, 32, (32768).to_bytes(8, 'big')), (32, 36, (1).to_bytes(4, 'big')),
                   (72, 80, (4).to_bytes(8, 'big')), (100, 104, b''))
        for start, stop, value in changes:
            with self.subTest(field=start), self.fixture(
                    header_change=lambda header: header.__setitem__(slice(start, stop), value)) as (work, geometry, pin):
                with mock.patch.object(R, 'run') as command, self.assertRaisesRegex(ValueError, 'root_export_source'):
                    R.export_root(work, geometry, pin, 200)
                command.assert_not_called()
                self.assertFalse((work / 'runtime-root.raw').exists())

    def test_sha512_mismatch_or_malformed_pin_prevents_export(self):
        with self.fixture() as (work, geometry, _pin), mock.patch.object(R, 'run') as command:
            for pin in ({}, {'sha512': True}, {'sha512': 'z' * 128}, {'sha512': '0' * 128}, None):
                with self.subTest(pin=pin), self.assertRaisesRegex(ValueError, 'root_export_source'):
                    R.export_root(work, geometry, pin, 200)
            command.assert_not_called()
            self.assertFalse((work / 'runtime-root.raw').exists())

    def test_source_symlink_hardlink_writable_or_nonregular_denied(self):
        for kind in ('symlink', 'hardlink', 'writable', 'directory'):
            with self.subTest(kind=kind), self.fixture() as (work, geometry, pin):
                image = work / 'base.qcow2'
                if kind == 'hardlink':
                    os.link(image, work / 'other')
                elif kind == 'writable':
                    image.chmod(0o620)
                else:
                    image.rename(work / 'original')
                    image.symlink_to(work / 'original') if kind == 'symlink' else image.mkdir()
                with mock.patch.object(R, 'run') as command, self.assertRaisesRegex(ValueError, 'root_export_source'):
                    R.export_root(work, geometry, pin, 200)
                command.assert_not_called()

    def test_identity_rejects_wrong_owner_and_oversize(self):
        with self.fixture() as (work, _geometry, _pin):
            path = work / 'base.qcow2'
            meta = path.lstat()
            with mock.patch.object(R.os, 'getuid', return_value=meta.st_uid + 1):
                with self.assertRaisesRegex(ValueError, 'root_export_source'):
                    R.export_identity(path, 104)
            with self.assertRaisesRegex(ValueError, 'root_export_source'):
                R.export_identity(path, 103)

    def test_wrong_payload_name_symlink_or_writable_directory_is_denied(self):
        for kind in ('name', 'symlink', 'writable', 'relative'):
            with self.subTest(kind=kind), self.fixture() as (work, geometry, pin):
                if kind == 'name':
                    destination = work.with_name('wrong')
                    work.rename(destination)
                    work = destination
                elif kind == 'symlink':
                    work.rename(work.with_name('original'))
                    work.symlink_to(work.with_name('original'))
                elif kind == 'writable':
                    work.chmod(0o770)
                else:
                    work = Path('not-opened/payload')
                with mock.patch.object(R, 'run') as command, self.assertRaises((ValueError, OSError)):
                    R.export_root(work, geometry, pin, 200)
                command.assert_not_called()

    def test_existing_target_regular_or_symlink_is_never_overwritten(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), self.fixture() as (work, geometry, pin):
                original = work / 'public-canary'
                original.write_bytes(b'preserve this file')
                target = work / 'runtime-root.raw'
                target.symlink_to(original) if symlink else target.write_bytes(b'existing target')
                with mock.patch.object(R, 'run') as command, self.assertRaises(FileExistsError):
                    R.export_root(work, geometry, pin, 200)
                command.assert_not_called()
                self.assertEqual(original.read_bytes(), b'preserve this file')
                self.assertEqual(target.read_bytes(), b'preserve this file' if symlink else b'existing target')

    def test_conversion_output_replacement_or_wrong_size_prevents_compare(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement), self.fixture() as (work, geometry, pin):
                calls = []
                def change(_operation, target):
                    if replacement:
                        target.rename(work / 'old')
                        target.write_bytes(bytes(4096))
                    else:
                        target.write_bytes(b'short')
                with mock.patch.object(R, 'run', side_effect=self.converter(work, geometry, calls, change=change)):
                    with self.assertRaisesRegex(ValueError, 'root_export_source'):
                        R.export_root(work, geometry, pin, 200)
                self.assertEqual([call[0][1] for call in calls], ['convert'])

    def test_source_mutation_during_conversion_or_comparison_is_denied(self):
        for phase in ('convert', 'compare'):
            with self.subTest(phase=phase), self.fixture() as (work, geometry, pin):
                calls = []
                def change(operation, _target):
                    if operation == phase:
                        (work / 'base.qcow2').write_bytes(b'changed source')
                with mock.patch.object(R, 'run', side_effect=self.converter(work, geometry, calls, change=change)):
                    with self.assertRaisesRegex(ValueError, 'root_export_source'):
                        R.export_root(work, geometry, pin, 200)
                self.assertEqual([call[0][1] for call in calls], ['convert'] if phase == 'convert'
                                 else ['convert', 'compare'])

    def test_compare_mismatch_or_error_never_returns_accepted_root(self):
        for code in (1, 2, 3, 4, -9):
            with self.subTest(code=code), self.fixture() as (work, geometry, pin):
                calls = []
                with mock.patch.object(R, 'run', side_effect=self.converter(work, geometry, calls, mismatch=code)):
                    with self.assertRaisesRegex(ValueError, 'root_export_compare'):
                        R.export_root(work, geometry, pin, 200)
                self.assertEqual([call[0][1] for call in calls], ['convert', 'compare'])
                self.assertTrue((work / 'runtime-root.raw').exists(), 'outer_cleanup_owns_partial_output')

    def test_original_export_cap_covers_hash_conversion_and_comparison(self):
        with self.fixture() as (work, geometry, pin):
            calls, deadlines = [], []
            original_hash = R.file_hash
            def hashed(path, deadline, *args):
                deadlines.append(deadline)
                return original_hash(path, deadline, *args)
            with mock.patch.object(R, 'file_hash', side_effect=hashed), \
                    mock.patch.object(R, 'run', side_effect=self.converter(work, geometry, calls)):
                R.export_root(work, geometry, pin, 10000)
            self.assertEqual(deadlines, [700])
            self.assertEqual([call[1] for call in calls], [700, 700])

    def test_cancellation_and_expiry_never_restart_export_budget(self):
        for phase in ('before', 'convert', 'compare'):
            for cancelled in (False, True):
                with self.subTest(phase=phase, cancelled=cancelled), self.fixture() as (work, geometry, pin):
                    calls = []
                    def change(operation, _target):
                        if operation == phase:
                            if cancelled:
                                R.CANCELLED = True
                            else:
                                R.time.monotonic.return_value = 201
                    try:
                        if phase == 'before':
                            R.CANCELLED = cancelled
                            R.time.monotonic.return_value = 100 if cancelled else 201
                        with mock.patch.object(R, 'run', side_effect=self.converter(work, geometry, calls, change=change)):
                            with self.assertRaisesRegex(ValueError, 'controller_cancelled' if cancelled else 'controller_deadline'):
                                R.export_root(work, geometry, pin, 200)
                        expected = [] if phase == 'before' else ['convert'] if phase == 'convert' else ['convert', 'compare']
                        self.assertEqual([call[0][1] for call in calls], expected)
                    finally:
                        R.CANCELLED = False
                        R.time.monotonic.return_value = 100

    def test_export_join_failure_keeps_real_tool_pending_and_partial_target(self):
        with self.fixture() as (work, geometry, pin):
            pending = {}
            token = R.TOOL_PROCESSES.set(pending)
            error = R.CleanupUnconfirmed('private-cleanup-canary')
            try:
                with fake_tool(join_error=error) as (process, join):
                    with self.assertRaises(R.CleanupUnconfirmed) as caught:
                        R.export_root(work, geometry, pin, 200)
                    self.assertIs(caught.exception, error)
                    self.assertEqual(pending, {id(process): process})
                    join.assert_called_once_with(process)
                    self.assertTrue((work / 'runtime-root.raw').exists())
                    process.stdout.close.assert_called_once()
                    process.stderr.close.assert_called_once()
            finally:
                R.TOOL_PROCESSES.reset(token)


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
                              'confidential_execution', 'production_approval', 'vm_cleanup_confirmed'):
                    self.assertIs(result[field], False, field)
                self.assertTrue(result['scratch_removed'])
                self.assertTrue(result['tool_cleanup_confirmed'])
                self.assertIsNone(result['scratch_cleanup_failure'])
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


class ExecutionScratchCleanup(Inert):
    def early_failure(self, *, inject=None, remove_error=None, reason='controller_deadline'):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            args = types.SimpleNamespace(work=work, appliance_kernel=Path('/not-opened'))
            def failed_prepare(payload, _kernel, deadline):
                self.assertEqual(payload, work / 'payload')
                self.assertEqual(deadline, 100 + R.MAX_SECONDS)
                (payload / 'synthetic-key').write_bytes(b'private-payload-canary')
                (work / 'evidence/prior.json').write_bytes(b'public prior receipt')
                if inject is not None:
                    inject()
                raise ValueError(reason)
            with contextlib.ExitStack() as patches:
                patches.enter_context(mock.patch.object(R.os, 'umask'))
                patches.enter_context(mock.patch.object(R, 'hosted', return_value=(None,
                    {'commit': '1' * 40, 'tree': '2' * 40}, {}, {})))
                patches.enter_context(mock.patch.object(R, 'ImageTools', side_effect=failed_prepare))
                remove = patches.enter_context(mock.patch.object(R, 'remove_payload',
                    side_effect=remove_error, wraps=None if remove_error else R.remove_payload))
                result = R.execute(args)
            self.assertEqual((work / 'evidence/result.json').read_bytes(), R.encoded(result))
            self.assertEqual((work / 'evidence/prior.json').read_bytes(), b'public prior receipt')
            self.assertNotIn(b'private-', R.encoded(result))
            self.assertEqual(result['state'], 'failed')
            self.assertFalse(result['model_execution'])
            return result, (work / 'payload').exists(), remove.call_count

    def test_successful_early_failure_cleanup_preserves_evidence_and_original_reason(self):
        for reason in ('controller_deadline', 'host_memory_headroom'):
            with self.subTest(reason=reason):
                result, present, removals = self.early_failure(reason=reason)
                self.assertFalse(present)
                self.assertEqual(removals, 1)
                self.assertTrue(result['scratch_removed'])
                self.assertTrue(result['tool_cleanup_confirmed'])
                self.assertIsNone(result['scratch_cleanup_failure'])
                self.assertEqual(result['failure'], reason)
                self.assertFalse(result['vm_cleanup_confirmed'])
        R.subprocess.Popen.assert_not_called()

    def test_removal_failure_keeps_failed_state_and_original_reason(self):
        result, present, removals = self.early_failure(remove_error=OSError('private-removal-canary'))
        self.assertTrue(present)
        self.assertEqual(removals, 1)
        self.assertFalse(result['scratch_removed'])
        self.assertTrue(result['tool_cleanup_confirmed'])
        self.assertEqual(result['failure'], 'controller_deadline')
        self.assertEqual(result['scratch_cleanup_failure'], 'scratch_removal_failed')

    def test_even_masked_tool_join_failure_stickily_prevents_payload_removal(self):
        def failed_tool():
            with fake_tool(join_error=R.CleanupUnconfirmed('private-join-canary')):
                try:
                    R.run(['never-executed'], 200)
                except R.CleanupUnconfirmed:
                    raise ValueError('controller_deadline') from None
        result, present, removals = self.early_failure(inject=failed_tool)
        self.assertTrue(present)
        self.assertEqual(removals, 0)
        self.assertFalse(result['tool_cleanup_confirmed'])
        self.assertFalse(result['scratch_removed'])
        self.assertEqual(result['failure'], 'controller_deadline')
        self.assertEqual(result['scratch_cleanup_failure'], 'process_cleanup_unconfirmed')

    def test_execution_ledger_is_fresh_and_restores_outer_context_after_error(self):
        sentinel = object()
        outer = {id(sentinel): sentinel}
        token = R.TOOL_PROCESSES.set(outer)
        seen = []
        def owned(_args, pending):
            self.assertIs(R.TOOL_PROCESSES.get(), pending)
            self.assertEqual(pending, {})
            seen.append(pending)
            if len(seen) == 1:
                pending[id(sentinel)] = sentinel
                raise ValueError('private-execution-canary')
            return {'closed': True}
        try:
            with mock.patch.object(R, 'execute_owned', side_effect=owned):
                with self.assertRaisesRegex(ValueError, 'private-execution-canary'):
                    R.execute(object())
                self.assertIs(R.TOOL_PROCESSES.get(), outer)
                self.assertEqual(R.execute(object()), {'closed': True})
                self.assertIs(R.TOOL_PROCESSES.get(), outer)
            self.assertIsNot(seen[0], seen[1])
            self.assertEqual(seen[0], outer)
            self.assertEqual(seen[1], {})
        finally:
            R.TOOL_PROCESSES.reset(token)


class PayloadRemoval(Inert):
    def tree(self, root):
        parent = root / 'work'
        parent.mkdir(mode=0o700)
        payload, evidence = parent / 'payload', parent / 'evidence'
        payload.mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)
        (payload / 'key').write_bytes(b'synthetic key canary')
        (evidence / 'receipt.json').write_bytes(b'public evidence')
        return parent, payload, evidence, R.directory_identity(parent), R.directory_identity(payload)

    def test_owned_payload_removal_preserves_evidence_and_internal_symlink_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, payload, evidence, parent_id, payload_id = self.tree(root)
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'canary').write_bytes(b'untouched')
            (payload / 'external').symlink_to(outside, target_is_directory=True)
            R.remove_payload(payload, parent_id, payload_id)
            self.assertFalse(payload.exists())
            self.assertTrue(parent.is_dir())
            self.assertEqual((evidence / 'receipt.json').read_bytes(), b'public evidence')
            self.assertEqual((outside / 'canary').read_bytes(), b'untouched')

    def test_replaced_payload_directory_is_not_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, payload, evidence, parent_id, payload_id = self.tree(root)
            held = root / 'original'
            payload.rename(held)
            payload.mkdir(mode=0o700)
            (payload / 'replacement').write_bytes(b'untouched')
            with self.assertRaisesRegex(ValueError, 'scratch_directory'):
                R.remove_payload(payload, parent_id, payload_id)
            self.assertEqual((payload / 'replacement').read_bytes(), b'untouched')
            self.assertEqual((held / 'key').read_bytes(), b'synthetic key canary')
            self.assertTrue(evidence.exists())

    def test_payload_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, payload, _, parent_id, payload_id = self.tree(root)
            held = root / 'original'
            payload.rename(held)
            payload.symlink_to(held, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'scratch_directory'):
                R.remove_payload(payload, parent_id, payload_id)
            self.assertTrue(payload.is_symlink())
            self.assertEqual((held / 'key').read_bytes(), b'synthetic key canary')

    def test_parent_directory_or_symlink_replacement_is_rejected(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                parent, payload, _, parent_id, payload_id = self.tree(root)
                held = root / 'original'
                parent.rename(held)
                if symlink:
                    parent.symlink_to(held, target_is_directory=True)
                else:
                    parent.mkdir(mode=0o700)
                    payload.mkdir(mode=0o700)
                    (payload / 'replacement').write_bytes(b'untouched')
                with self.assertRaisesRegex(ValueError, 'scratch_directory'):
                    R.remove_payload(payload, parent_id, payload_id)
                self.assertEqual((held / 'payload/key').read_bytes(), b'synthetic key canary')
                self.assertEqual((held / 'evidence/receipt.json').read_bytes(), b'public evidence')
                if not symlink:
                    self.assertEqual((payload / 'replacement').read_bytes(), b'untouched')

    def test_parent_replacement_between_path_check_and_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, payload, _, parent_id, payload_id = self.tree(root)
            held = root / 'original'
            original_open = R.os.open
            def opened(path, flags, *args, **kwargs):
                if path == parent:
                    parent.rename(held)
                    parent.mkdir(mode=0o700)
                    payload.mkdir(mode=0o700)
                    (payload / 'replacement').write_bytes(b'untouched')
                return original_open(path, flags, *args, **kwargs)
            with mock.patch.object(R.os, 'open', side_effect=opened), self.assertRaisesRegex(ValueError, 'scratch_directory'):
                R.remove_payload(payload, parent_id, payload_id)
            self.assertEqual((payload / 'replacement').read_bytes(), b'untouched')
            self.assertEqual((held / 'payload/key').read_bytes(), b'synthetic key canary')

    def test_directory_mode_wrong_name_and_unavailable_safe_removal_are_rejected(self):
        for change in ('mode', 'name', 'unsafe'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                parent, payload, _, parent_id, payload_id = self.tree(Path(temporary))
                if change == 'mode':
                    payload.chmod(0o755)
                elif change == 'name':
                    replacement = parent / 'not-payload'
                    payload.rename(replacement)
                    payload = replacement
                with mock.patch.object(R.shutil.rmtree, 'avoids_symlink_attacks', change != 'unsafe'):
                    with self.assertRaisesRegex(ValueError, 'scratch_directory'):
                        R.remove_payload(payload, parent_id, payload_id)
                self.assertEqual((payload / 'key').read_bytes(), b'synthetic key canary')

    def test_replacement_during_recursive_removal_is_preserved_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, payload, evidence, parent_id, payload_id = self.tree(root)
            held = root / 'original'
            original_rmtree = R.shutil.rmtree
            def replace_then_remove(path, **options):
                self.assertEqual(path, '.')
                opened = os.fstat(options['dir_fd'])
                self.assertEqual((opened.st_dev, opened.st_ino), payload_id)
                payload.rename(held)
                payload.mkdir(mode=0o700)
                (payload / 'replacement').write_bytes(b'untouched')
                return original_rmtree(path, **options)
            with mock.patch.object(R.shutil, 'rmtree', side_effect=replace_then_remove) as remove:
                remove.avoids_symlink_attacks = True
                with self.assertRaisesRegex(ValueError, 'scratch_directory'):
                    R.remove_payload(payload, parent_id, payload_id)
            self.assertEqual((payload / 'replacement').read_bytes(), b'untouched')
            self.assertEqual(list(held.iterdir()), [])
            self.assertEqual((evidence / 'receipt.json').read_bytes(), b'public evidence')

    def test_recursive_unlink_errors_are_not_ignored_as_final_dot_removal(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, payload, evidence, parent_id, payload_id = self.tree(Path(temporary))
            original_unlink = R.os.unlink
            error = PermissionError('private-unlink-canary')
            def fail_key(path, *args, **options):
                if path == 'key':
                    raise error
                return original_unlink(path, *args, **options)
            with mock.patch.object(R.os, 'unlink', side_effect=fail_key):
                with self.assertRaises(PermissionError) as caught:
                    R.remove_payload(payload, parent_id, payload_id)
            self.assertIs(caught.exception, error)
            self.assertEqual((payload / 'key').read_bytes(), b'synthetic key canary')
            self.assertEqual((evidence / 'receipt.json').read_bytes(), b'public evidence')


class ImageToolCleanup(Inert):
    def kernel_fixture(self, root):
        work = root / 'run/payload'
        work.mkdir(parents=True, mode=0o700)
        kernel = root / 'kernel'
        release = '6.8.0-public-fixture'
        data = bytearray(1024)
        data[514:518] = b'HdrS'
        data[526:528] = (64).to_bytes(2, 'little')
        data[576:576 + len(release)] = release.encode()
        kernel.write_bytes(data)
        kernel.chmod(0o600)
        return work, kernel, release, bytes(data)

    def test_constructor_accepts_payload_layout_and_binds_original_kernel_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, kernel, release, data = self.kernel_fixture(Path(temporary))
            modules = Path('/lib/modules') / release
            original_hash = R.file_hash
            with mock.patch.object(R.os, 'uname', return_value=types.SimpleNamespace(release=release)), \
                    mock.patch.object(Path, 'is_dir', autospec=True, side_effect=lambda path: path == modules) as directory, \
                    mock.patch.object(Path, 'is_file', autospec=True,
                                      side_effect=lambda path: path == modules / 'modules.dep') as index, \
                    mock.patch.object(R, 'file_hash', wraps=original_hash) as hashed:
                value = R.ImageTools(work, kernel, 200)
            hashed.assert_called_once_with(kernel, 200, 64 * 1024 ** 2)
            directory.assert_called_once_with(modules)
            index.assert_called_once_with(modules / 'modules.dep')
            self.assertEqual(value.kernel_record, {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            self.assertEqual((value.work, value.kernel, value.deadline), (work, kernel, 200))
            self.assertEqual(value.env, dict(R.ENV, LIBGUESTFS_BACKEND='direct',
                LIBGUESTFS_BACKEND_SETTINGS='force_kvm', LIBGUESTFS_MEMSIZE='2048',
                SUPERMIN_KERNEL=str(kernel), SUPERMIN_KERNEL_VERSION=release, SUPERMIN_MODULES=str(modules),
                LIBGUESTFS_CACHEDIR=str(work), LIBGUESTFS_TMPDIR=str(work)))
            R.subprocess.Popen.assert_not_called()

    def test_constructor_rejects_wrong_parent_symlink_and_nonpayload_name_before_hash(self):
        for variant in ('parent', 'symlink', 'name'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                work, kernel, _, _ = self.kernel_fixture(Path(temporary))
                if variant == 'parent':
                    replacement = work.parent / 'kernel'
                    kernel.rename(replacement)
                    kernel = replacement
                elif variant == 'symlink':
                    link = kernel.with_name('kernel-link')
                    link.symlink_to(kernel)
                    kernel = link
                else:
                    work = work.with_name('not-payload')
                    work.mkdir(mode=0o700)
                with mock.patch.object(R, 'file_hash') as hashed, \
                        self.assertRaisesRegex(ValueError, 'appliance_kernel_path'):
                    R.ImageTools(work, kernel, 200)
                hashed.assert_not_called()
                R.subprocess.Popen.assert_not_called()

    def test_constructor_keeps_header_release_modules_and_file_size_fail_closed(self):
        for variant, reason in (('header', 'appliance_kernel_header'),
                                ('release', 'appliance_kernel_release'),
                                ('modules', 'appliance_modules'), ('size', 'controller_file')):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                work, kernel, release, data = self.kernel_fixture(Path(temporary))
                if variant == 'header':
                    kernel.write_bytes(data[:514] + b'BAD!' + data[518:])
                with contextlib.ExitStack() as patches:
                    patches.enter_context(mock.patch.object(R.os, 'uname', return_value=types.SimpleNamespace(
                        release='different-public-kernel' if variant == 'release' else release)))
                    patches.enter_context(mock.patch.object(Path, 'is_dir', return_value=variant != 'modules'))
                    patches.enter_context(mock.patch.object(Path, 'is_file', return_value=True))
                    if variant == 'size':
                        meta = kernel.stat()
                        patches.enter_context(mock.patch.object(R.os, 'fstat', return_value=types.SimpleNamespace(
                            st_mode=meta.st_mode, st_uid=meta.st_uid, st_nlink=1, st_size=64 * 1024 ** 2 + 1)))
                    with self.assertRaisesRegex(ValueError, reason):
                        R.ImageTools(work, kernel, 200)
                R.subprocess.Popen.assert_not_called()

    def image(self, work):
        value = R.ImageTools.__new__(R.ImageTools)
        value.work, value.deadline, value.env = work, 200, {}
        value.kernel, value.kernel_record = work / 'not-opened-kernel', {'bytes': 1, 'sha256': 'a' * 64}
        path = work / 'image.raw'
        path.write_bytes(b'inert image')
        return value, path

    def test_unlink_failure_never_replaces_original_tool_or_decode_exception(self):
        errors = (ValueError('command_failed'), R.CleanupUnconfirmed('private-join'), OSError('private-tool'))
        for error in errors:
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as temporary:
                image, path = self.image(Path(temporary))
                with mock.patch.object(R, 'file_hash', return_value=image.kernel_record), \
                        mock.patch.object(R, 'run', side_effect=error), \
                        mock.patch.object(Path, 'unlink', side_effect=PermissionError('private-unlink')):
                    with self.assertRaises(type(error)) as caught:
                        image.fish(path, [['inspect-os']])
                self.assertIs(caught.exception, error)
        with tempfile.TemporaryDirectory() as temporary:
            image, path = self.image(Path(temporary))
            with mock.patch.object(R, 'file_hash', return_value=image.kernel_record), \
                    mock.patch.object(R, 'run', return_value=(b'\xff', b'', 0)), \
                    mock.patch.object(Path, 'unlink', side_effect=PermissionError('private-unlink')):
                with self.assertRaises(UnicodeDecodeError):
                    image.fish(path, [['inspect-os']])

    def test_successful_tool_with_unlink_failure_still_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            image, path = self.image(Path(temporary))
            error = PermissionError('private-unlink')
            with mock.patch.object(R, 'file_hash', return_value=image.kernel_record), \
                    mock.patch.object(R, 'run', return_value=(b'public output\n', b'', 0)), \
                    mock.patch.object(Path, 'unlink', side_effect=error):
                with self.assertRaises(PermissionError) as caught:
                    image.fish(path, [['inspect-os']])
            self.assertIs(caught.exception, error)

    def test_successful_tool_removes_only_its_script_and_returns_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            image, path = self.image(work)
            with mock.patch.object(R, 'file_hash', return_value=image.kernel_record), \
                    mock.patch.object(R, 'run', return_value=(b'public output\n', b'', 0)) as command:
                self.assertEqual(image.fish(path, [['inspect-os']]), 'public output\n')
            argv = command.call_args.args[0]
            self.assertEqual(argv[:4], ['guestfish', '--ro', '--format=raw', '-a'])
            self.assertEqual(argv[4], path)
            self.assertEqual(argv[5], '-f')
            self.assertFalse(argv[6].exists())
            self.assertEqual(path.read_bytes(), b'inert image')
            self.assertEqual(list(work.iterdir()), [path])
            R.subprocess.Popen.assert_not_called()


class CommandLifecycle(Inert):
    def test_tool_ledger_removes_entry_only_after_confirmed_join(self):
        pending = {}
        token = R.TOOL_PROCESSES.set(pending)
        try:
            with fake_tool() as (process, join):
                def verified(child):
                    self.assertIs(child, process)
                    self.assertEqual(pending, {id(process): process})
                join.side_effect = verified
                self.assertEqual(R.run(['never-executed'], 200), (b'', b'', 0))
                self.assertEqual(pending, {})
                process.stdout.close.assert_called_once()
                process.stderr.close.assert_called_once()
        finally:
            R.TOOL_PROCESSES.reset(token)

    def test_tool_ledger_retains_exact_process_when_join_raises(self):
        for error in (R.CleanupUnconfirmed('private-join'), OSError('private-observation')):
            pending = {}
            token = R.TOOL_PROCESSES.set(pending)
            try:
                with self.subTest(error=type(error).__name__), fake_tool(join_error=error) as (process, join):
                    with self.assertRaises(type(error)) as caught:
                        R.run(['never-executed'], 200)
                    self.assertIs(caught.exception, error)
                    self.assertEqual(pending, {id(process): process})
                    join.assert_called_once_with(process)
                    process.stdout.close.assert_called_once()
                    process.stderr.close.assert_called_once()
            finally:
                R.TOOL_PROCESSES.reset(token)

    def test_nonzero_status_after_confirmed_join_does_not_poison_tool_ledger(self):
        pending = {}
        token = R.TOOL_PROCESSES.set(pending)
        try:
            with fake_tool(returncode=1) as (process, join):
                with self.assertRaisesRegex(ValueError, 'command_failed'):
                    R.run(['never-executed'], 200)
                self.assertEqual(pending, {})
                join.assert_called_once_with(process)
        finally:
            R.TOOL_PROCESSES.reset(token)

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
