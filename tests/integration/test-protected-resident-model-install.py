#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert offline-installer tests; no sudo, APT, namespace, disk, VM or build."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('resident_install', HERE / 'protected-resident-model-install.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def deadline():
    return time.monotonic_ns() + 60 * 10 ** 9


def put(path, raw=b'public fixture', mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def item(raw=b'public deb'):
    return dict(version='1.2-3', architecture='amd64', filename='pool/p/public/public_1.2-3_amd64.deb',
        basename='public_1.2-3_amd64.deb', url='https://deb.debian.org/debian/pool/p/public/public_1.2-3_amd64.deb',
        bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), index='trixie', depends='', pre_depends='')


def status_row(name='public', version='1.2-3', state='install ok installed', pending='', awaited=''):
    return f'{name}\t{version}\tamd64\t{state}\t{pending}\t{awaited}\n'.encode()


class FakeRunner:
    def __init__(self, deadline_value=None):
        self.deadline = deadline_value or deadline()
        self.joined = True
        self.calls = []
        self.before = status_row('base', '1')
        self.after = self.before + status_row()
        self.plan = b'Inst public (1.2-3 local-deb [amd64])\nConf public (1.2-3 local-deb [amd64])\n'
        self.failure = None
        self.queries = 0

    def run(self, argv, **options):
        argv = [str(value) for value in argv]
        self.calls.append((argv, options))
        if self.failure is not None and self.failure(argv):
            raise ValueError('PRIVATE_CANARY must never be exported')
        if '/usr/bin/dpkg-deb' in argv:
            return b'public\n1.2-3\namd64\n'
        if '/usr/bin/dpkg-query' in argv:
            self.queries += 1
            return self.before if self.queries == 1 else self.after
        if '--simulate' in argv:
            return self.plan
        if '/usr/bin/systemd-detect-virt' in argv:
            return b'kvm\n'
        if '/usr/sbin/blkid' in argv:
            return b'ext4\n'
        return b''


class GuardTests(unittest.TestCase):
    def test_original_deadline_not_restarted_and_early_uptime(self):
        with mock.patch.object(M.time, 'monotonic_ns', return_value=35 * 10 ** 9):
            self.assertEqual(M.remaining(100 * 10 ** 9), 65)
            for value in (34 * 10 ** 9, True, 8000 * 10 ** 9):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    M.remaining(value)

    def test_root_guest_guard_accepts_only_explicit_debian_kvm(self):
        args = types.SimpleNamespace(execute=True, yes=True, disposable_guest=True,
                                     deadline_monotonic_ns=deadline())
        runner = FakeRunner()
        with mock.patch.object(M.os, 'getresuid', return_value=(0, 0, 0)), \
             mock.patch.object(M.platform, 'system', return_value='Linux'), \
             mock.patch.object(M.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(M.socket, 'gethostname', return_value='volparossa-alpha'), \
             mock.patch.object(M.Path, 'resolve', return_value=Path('/usr/lib/os-release')), \
             mock.patch.object(M, 'read_file', return_value=b'VERSION_ID="13"\n'):
            M.guest_guard(args, runner)
            self.assertEqual(runner.calls[0][0], ['/usr/bin/systemd-detect-virt', '--vm'])
            for uid in ((1000, 1000, 1000), (0, 0, 1000)):
                with mock.patch.object(M.os, 'getresuid', return_value=uid), self.assertRaises(ValueError):
                    M.guest_guard(args, runner)
            args.yes = False
            with self.assertRaises(ValueError):
                M.guest_guard(args, runner)

    def test_wrong_host_arch_os_or_virt_rejected(self):
        args = types.SimpleNamespace(execute=True, yes=True, disposable_guest=True,
                                     deadline_monotonic_ns=deadline())
        for failure in ('host', 'arch', 'release', 'virt'):
            runner = FakeRunner()
            if failure == 'virt':
                runner.run = mock.Mock(return_value=b'none\n')
            with self.subTest(failure=failure), mock.patch.object(M.os, 'getresuid', return_value=(0, 0, 0)), \
                 mock.patch.object(M.platform, 'system', return_value='Linux'), \
                 mock.patch.object(M.platform, 'machine', return_value='arm64' if failure == 'arch' else 'x86_64'), \
                 mock.patch.object(M.socket, 'gethostname', return_value='host' if failure == 'host' else 'volparossa-alpha'), \
                 mock.patch.object(M.Path, 'resolve', return_value=Path('/usr/lib/os-release')), \
                 mock.patch.object(M, 'read_file', return_value=b'VERSION_ID="12"' if failure == 'release' else b'VERSION_ID="13"'), \
                 self.assertRaises(ValueError):
                M.guest_guard(args, runner)

    def test_private_namespace_requires_pid_one_and_only_down_loopback(self):
        raw = b'Inter-| Receive\n face |bytes\n lo: 0 0 0 0\n'
        sock = mock.MagicMock()
        sock.__enter__.return_value.fileno.return_value = 33
        with mock.patch.object(M.os, 'getpid', return_value=1), \
             mock.patch.object(M.os, 'getresuid', return_value=(0, 0, 0)), \
             mock.patch.object(M, 'bounded_kernel_file', return_value=raw), \
             mock.patch.object(M.socket, 'socket', return_value=sock), \
             mock.patch.object(M.fcntl, 'ioctl', return_value=bytes(32)):
            M.namespace_guard()
            with mock.patch.object(M.os, 'getpid', return_value=2), self.assertRaises(ValueError):
                M.namespace_guard()
            with mock.patch.object(M, 'bounded_kernel_file', return_value=raw + b'eth0: 0\n'), self.assertRaises(ValueError):
                M.namespace_guard()
            with mock.patch.object(M.fcntl, 'ioctl', return_value=bytes(16) + b'\x01\0' + bytes(14)), self.assertRaises(ValueError):
                M.namespace_guard()

    def test_no_privileged_cli_without_guard_and_no_exception_text(self):
        output = io.StringIO()
        with mock.patch.object(M, 'execute', side_effect=ValueError('PRIVATE_CANARY')), \
             mock.patch('sys.stdout', output):
            code = M.main(['--mode', 'build', '--execute', '--yes', '--disposable-guest',
                '--package-lock', '/public/lock', '--package-lock-sha256', M.LOCK_SHA256,
                '--packages', '/public/packages', '--deadline-monotonic-ns', str(deadline()),
                '--result', '/public/result'])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue()), {'version': 1,
            'kind': 'protected-resident-offline-package-install', 'state': 'rejected'})
        self.assertNotIn('PRIVATE_CANARY', output.getvalue())


class PackageTests(unittest.TestCase):
    def test_actual_fixed_lock_counts_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = put(Path(directory) / 'lock.json',
                       (HERE / 'protected-resident-model-debian-lock-v1.json').read_bytes())
            for mode, count in M.COUNTS.items():
                self.assertEqual(len(M.load_lock(path, M.LOCK_SHA256, mode, deadline())), count)

    def test_wrong_lock_digest_and_duplicate_json_refused(self):
        with self.assertRaises(ValueError):
            M.load_lock(HERE / 'protected-resident-model-debian-lock-v1.json', '0' * 64, 'build', deadline())
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(ValueError):
                M.parse(raw)

    def test_named_deb_copy_hash_mode_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            put(root / 'inputs/public.deb', b'public deb')
            runner = FakeRunner()
            count = M.stage_packages(root / 'inputs', root / 'staged', {'public': item()}, runner)
            copied = root / 'staged' / item()['basename']
            self.assertEqual(count, 10)
            self.assertEqual(copied.read_bytes(), b'public deb')
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o400)
            self.assertEqual(copied.stat().st_nlink, 1)
            self.assertIn(str(copied), runner.calls[0][0])

    def test_bad_hash_stops_before_any_package_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            put(root / 'inputs/public.deb', b'wrong data')
            runner = FakeRunner()
            with self.assertRaises(ValueError):
                M.stage_packages(root / 'inputs', root / 'staged', {'public': item()}, runner)
            self.assertEqual(runner.calls, [])

    def test_symlink_hardlink_writable_and_size_refused(self):
        for kind in ('symlink', 'hardlink', 'writable', 'size'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = put(root / 'inputs/public.deb', b'public deb')
                if kind == 'symlink':
                    source.unlink()
                    source.symlink_to(put(root / 'other', b'public deb'))
                elif kind == 'hardlink':
                    os.link(source, root / 'other')
                elif kind == 'writable':
                    source.chmod(0o666)
                else:
                    source.write_bytes(b'short')
                with self.assertRaises((OSError, ValueError)):
                    M.stage_packages(root / 'inputs', root / 'staged', {'public': item()}, FakeRunner())

    def test_metadata_mismatch_after_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            put(root / 'inputs/public.deb', b'public deb')
            runner = FakeRunner()
            runner.run = mock.Mock(return_value=b'wrong\n1.2-3\namd64\n')
            with self.assertRaises(ValueError):
                M.stage_packages(root / 'inputs', root / 'staged', {'public': item()}, runner)


class PlanTests(unittest.TestCase):
    def test_exact_reinstall_plan(self):
        M.validate_plan(FakeRunner().plan, {'public': item()}, {'base': ['1', 'amd64', 'install ok installed']})

    def test_plan_rejects_removal_outside_version_missing_and_duplicate(self):
        plans = (b'Remv base [1]\n', b'Inst other (1 local [amd64])\n',
                 b'Inst public (9 local [amd64])\n', b'0 upgraded\n',
                 b'Inst public (1.2-3 local [amd64])\n' * 2,
                 b'Inst public:arm64 (1.2-3 local [arm64])\n')
        for raw in plans:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                M.validate_plan(raw, {'public': item()}, {})

    def test_full_status_and_final_locked_delta(self):
        before = M.status(status_row('base', '1') + status_row('old', '2', 'deinstall ok config-files'))
        after = M.status(status_row('base', '1') + status_row('old', '2', 'deinstall ok config-files') + status_row())
        M.final_status(before, after, {'public': item()})

    def test_status_triggers_partial_duplicate_arch_rejected(self):
        rows = (status_row(pending='ldconfig'), status_row(awaited='public'),
                status_row(state='install ok unpacked'), status_row() * 2,
                status_row().replace(b'amd64', b'arm64'), b'')
        for raw in rows:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                M.status(raw)

    def test_final_status_denies_outside_changes_removals_and_unpinned_additions(self):
        before = M.status(status_row('base', '1'))
        for raw in (status_row('base', '2') + status_row(), status_row(),
                    status_row('base', '1') + status_row() + status_row('other', '1')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                M.final_status(before, M.status(raw), {'public': item()})

    def test_apt_config_has_no_sources_parts_download_or_external_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            M.apt_configuration(root, Path('/run/vp-resident-install'))
            raw = (root / 'apt.conf').read_text()
            for expected in ('Dir::Etc::main "/dev/null"', 'Dir::Etc::sourcelist "/dev/null"',
                             'APT::Get::Download "false"', 'APT::Get::AllowUnauthenticated "false"'):
                self.assertIn(expected, raw)
            self.assertNotIn('http', raw)
            self.assertNotIn('Pre-Invoke', raw)
            self.assertEqual(list((root / 'empty').iterdir()), [])

    def test_install_executes_real_sequence_with_fixed_offline_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, report = FakeRunner(), M.receipt('build')
            policy = mock.Mock()
            policy.restore.return_value = True
            with mock.patch.object(M, 'Policy', return_value=policy):
                M.install(Path('/'), Path(directory), Path('/run/vp-resident-install'),
                          {'public': item()}, runner, report)
            apt = [call for call in runner.calls if '/usr/bin/apt-get' in call[0]]
            self.assertEqual(len(apt), 2)
            self.assertIn('--simulate', apt[0][0])
            for argv, options in apt:
                self.assertEqual(argv[:3], ['/usr/sbin/chroot', '/', '/usr/bin/apt-get'])
                for flag in ('--no-download', '--no-remove', '--reinstall'):
                    self.assertIn(flag, argv)
                self.assertEqual(options['env'], {'APT_CONFIG': '/run/vp-resident-install/apt.conf'})
            self.assertTrue(report['audit_clear'] and report['triggers_clear'] and report['policy_restored'])
            self.assertEqual(report['packages_verified'], 1)
            self.assertEqual(M.ENV['SYSTEMD_OFFLINE'], '1')
            policy.restore.assert_called_once()

    def test_failed_install_always_restores_policy_without_replacing_error(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, report = FakeRunner(), M.receipt('build')
            runner.failure = lambda argv: '/usr/bin/apt-get' in argv and '--simulate' not in argv
            policy = mock.Mock()
            policy.restore.side_effect = OSError('second private error')
            with mock.patch.object(M, 'Policy', return_value=policy), self.assertRaisesRegex(ValueError, 'PRIVATE_CANARY'):
                M.install(Path('/'), Path(directory), Path('/run/vp-resident-install'),
                          {'public': item()}, runner, report)
            self.assertFalse(report['policy_restored'])
            self.assertEqual(report['phase'], 'package_install')


class PolicyTests(unittest.TestCase):
    def root_stat(self, original):
        def converted(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            result = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
            result['st_uid'] = 0
            return types.SimpleNamespace(**result)
        return converted

    def policy_case(self, existing):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / 'usr/sbin'
            parent.mkdir(parents=True)
            parent.chmod(0o755)
            path = parent / 'policy-rc.d'
            if existing:
                put(path, b'#!/bin/sh\nexit 0\n', 0o750)
            original_stat, original_lstat = M.Path.stat, M.Path.lstat
            with mock.patch.object(M.Path, 'stat', self.root_stat(original_stat)), \
                 mock.patch.object(M.Path, 'lstat', self.root_stat(original_lstat)), \
                 mock.patch.object(M.os, 'chown'):
                policy = M.Policy(root, deadline())
                policy.install()
                self.assertEqual(path.read_bytes(), M.POLICY)
                self.assertTrue(policy.restore())
            if existing:
                self.assertEqual(path.read_bytes(), b'#!/bin/sh\nexit 0\n')
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o750)
            else:
                self.assertFalse(path.exists())

    def test_original_policy_bytes_and_mode_restored(self):
        self.policy_case(True)

    def test_original_policy_absence_restored(self):
        self.policy_case(False)

    def test_replaced_policy_not_deleted_or_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'usr/sbin').mkdir(parents=True)
            (root / 'usr/sbin').chmod(0o755)
            original_stat, original_lstat = M.Path.stat, M.Path.lstat
            with mock.patch.object(M.Path, 'stat', self.root_stat(original_stat)), \
                 mock.patch.object(M.Path, 'lstat', self.root_stat(original_lstat)):
                policy = M.Policy(root, deadline())
                policy.install()
                policy.path.unlink()
                put(policy.path, b'new owner file')
                with self.assertRaises(ValueError):
                    policy.restore()
                self.assertEqual(policy.path.read_bytes(), b'new owner file')


class RuntimeDeviceTests(unittest.TestCase):
    def exercise(self, *, serial=b'vp-resident-runtime\n', size=M.DISK_BYTES,
                 root_name='vda1', mounted=False, kind=stat.S_IFBLK, owner=0):
        meta = types.SimpleNamespace(st_mode=kind | 0o660, st_uid=owner, st_gid=6, st_nlink=1,
            st_dev=5, st_ino=9, st_size=0, st_mtime_ns=0, st_ctime_ns=0, st_rdev=os.makedev(252, 32))
        root_meta = types.SimpleNamespace(st_dev=os.makedev(252, 1))
        def resolve(path, **_kwargs):
            if path == M.RUNTIME_DISK:
                return Path('/dev/vdc')
            return Path('/sys/devices/pci/block') / ('vdc' if root_name == 'vdc1' else 'vda') / root_name
        mounts = b'1 0 252:32 / /point rw - ext4 /dev/vdc rw\n' if mounted else b'1 0 252:1 / / rw - ext4 /dev/vda1 rw\n'
        with mock.patch.object(M.Path, 'is_symlink', return_value=True), \
             mock.patch.object(M.Path, 'resolve', resolve), \
             mock.patch.object(M.Path, 'lstat', return_value=meta), \
             mock.patch.object(M.Path, 'stat', return_value=root_meta), \
             mock.patch.object(M.Path, 'open', return_value=io.BytesIO(serial)), \
             mock.patch.object(M, 'bounded_kernel_file', return_value=mounts), \
             mock.patch.object(M.os, 'open', return_value=55), \
             mock.patch.object(M.os, 'fstat', return_value=meta), \
             mock.patch.object(M.os, 'close'), \
             mock.patch.object(M.fcntl, 'ioctl', return_value=struct.pack('Q', size)):
            return M.runtime_device(FakeRunner())

    def test_fixed_raw_disk_serial_size_and_not_root(self):
        self.assertEqual(self.exercise(), Path('/dev/vdc'))

    def test_wrong_serial_size_owner_type_root_or_mounted_refused(self):
        for options in ({'serial': b'other\n'}, {'size': M.DISK_BYTES - 4096}, {'owner': 1000},
                        {'kind': stat.S_IFREG}, {'root_name': 'vdc1'}, {'mounted': True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.exercise(**options)


class LifecycleTests(unittest.TestCase):
    def test_runtime_sequence_has_no_network_and_reverses_every_owned_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            (stage / 'debs').mkdir()
            runner = FakeRunner()
            real_run = runner.run
            def run(argv, **options):
                values = [str(value) for value in argv]
                if values[:3] == ['/usr/bin/mount', '-t', 'ext4']:
                    root = Path(values[-1])
                    for name in ('run', 'proc', 'dev'):
                        (root / name).mkdir()
                    put(root / 'usr/lib/os-release', b'VERSION_ID="13"\n')
                return real_run(argv, **options)
            runner.run = run
            def configured(root, directory, visible, selected, runner, report):
                self.assertEqual(root, stage / 'root')
                self.assertEqual(visible, Path('/run/vp-resident-install'))
                self.assertEqual(directory, stage / 'root/run/vp-resident-install')
                report.update(packages_verified=1, status_verified=True, triggers_clear=True, audit_clear=True)
            with mock.patch.object(M, 'namespace_guard'), mock.patch.object(M, 'guest_guard'), \
                 mock.patch.object(M, 'load_lock', return_value={'public': item()}), \
                 mock.patch.object(M, 'runtime_device', return_value=Path('/dev/vdc')), \
                 mock.patch.object(M, 'Runner', return_value=runner), \
                 mock.patch.object(M, 'install', side_effect=configured):
                report = M.worker({'mode': 'runtime', 'deadline': deadline()}, stage)
            self.assertEqual(report['state'], 'configured')
            mounts = [argv[-1] for argv, _ in runner.calls
                      if argv[0] == '/usr/bin/mount' and 'remount,bind,ro,nosuid,nodev,noexec' not in argv]
            unmounts = [argv[-1] for argv, _ in runner.calls if argv[0] == '/usr/bin/umount']
            self.assertEqual(unmounts, list(reversed(mounts)))
            self.assertIn(['/usr/sbin/e2fsck', '-f', '-p', '/dev/vdc'], [argv for argv, _ in runner.calls])
            self.assertTrue(report['runtime_unmounted'])
            self.assertFalse(report['complete_guest_cleanup'])

    def test_outer_fixed_namespace_launcher_and_original_deadline_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / 'stage'
            stage.mkdir(mode=0o700)
            source_lock = put(root / 'lock.json',
                              (HERE / 'protected-resident-model-debian-lock-v1.json').read_bytes())
            packages = root / 'packages'
            packages.mkdir()
            args = types.SimpleNamespace(mode='build', execute=True, yes=True, disposable_guest=True,
                package_lock=source_lock, package_lock_sha256=M.LOCK_SHA256, packages=packages,
                deadline_monotonic_ns=deadline(), result=root / 'result.json')
            runner = FakeRunner(args.deadline_monotonic_ns)
            def run(argv, **options):
                runner.calls.append(([str(value) for value in argv], options))
                report = M.receipt('build')
                report.update(state='configured', failure=None, phase='complete', packages_verified=198,
                              status_verified=True, triggers_clear=True, audit_clear=True)
                put(stage / 'worker-result.json', M.encoded(report))
                return b''
            runner.run = run
            original_stat, original_read = M.Path.stat, M.read_file
            def root_stat(path, *values, **options):
                value = original_stat(path, *values, **options)
                if path == root:
                    return types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700)
                return value
            def source_read(path, maximum, end):
                if path == Path(M.__file__).resolve():
                    return b'# public installer source fixture\n'
                return original_read(path, maximum, end)
            def staged(_source, target, _selected, _runner):
                target.mkdir(mode=0o700)
                return 123
            with mock.patch.object(M, 'guest_guard'), mock.patch.object(M, 'Runner', return_value=runner), \
                 mock.patch.object(M.tempfile, 'mkdtemp', return_value=str(stage)), \
                 mock.patch.object(M.Path, 'stat', root_stat), mock.patch.object(M, 'read_file', side_effect=source_read), \
                 mock.patch.object(M, 'stage_packages', side_effect=staged):
                report = M.execute(args)
            argv = runner.calls[0][0]
            self.assertEqual(argv[:8], ['/usr/bin/unshare', '--mount', '--net', '--pid', '--fork',
                                       '--kill-child=SIGKILL', '--mount-proc', '--propagation'])
            self.assertEqual(json.loads((stage / 'config.json').read_bytes()),
                             {'mode': 'build', 'deadline': args.deadline_monotonic_ns})
            self.assertTrue(report['namespace_joined'])
            self.assertEqual(report['archive_bytes'], 123)
            self.assertEqual(json.loads(args.result.read_bytes()), report)

    def test_runner_public_process_success_and_join(self):
        runner = M.Runner(deadline())
        self.assertEqual(runner.run(['/usr/bin/python3', '-c', 'print("public")']), b'public\n')
        self.assertTrue(runner.joined)

    def test_runner_output_and_deadline_are_bounded(self):
        for code, options in (('print("x" * 1000)', {'maximum': 32}),
                              ('import time; time.sleep(10)', {'cap': 0.1})):
            runner = M.Runner(deadline())
            with self.subTest(code=code), self.assertRaises(ValueError):
                runner.run(['/usr/bin/python3', '-c', code], **options)
            self.assertTrue(runner.joined)

    def test_receipt_never_claims_descendant_vm_model_or_private_success(self):
        for mode in M.COUNTS:
            report = M.receipt(mode)
            self.assertIsNone(report['descendants_joined'])
            self.assertTrue(report['controller_cgroup_cleanup_required'])
            for name in ('complete_guest_cleanup', 'model_execution', 'worker_execution',
                         'private_inputs', 'hardware_attestation'):
                self.assertIs(report[name], False)

    def test_worker_failure_is_closed_and_attempts_reverse_unmount(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            (stage / 'debs').mkdir()
            runner = FakeRunner()
            runner.failure = lambda argv: '/usr/bin/sync' in argv
            selected = {'public': item()}
            with mock.patch.object(M, 'namespace_guard'), mock.patch.object(M, 'guest_guard'), \
                 mock.patch.object(M, 'load_lock', return_value=selected), \
                 mock.patch.object(M, 'Runner', return_value=runner), \
                 mock.patch.object(M, 'install'), mock.patch.object(M.Path, 'exists', return_value=False):
                report = M.worker({'mode': 'build', 'deadline': deadline()}, stage)
            self.assertEqual(report['state'], 'failed')
            self.assertNotIn('PRIVATE_CANARY', json.dumps(report))
            self.assertTrue(any(argv[0] == '/usr/bin/umount' for argv, _ in runner.calls))
            self.assertTrue(report['runtime_unmounted'])

    def test_worker_unmount_failure_cannot_be_success(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            (stage / 'debs').mkdir()
            runner = FakeRunner()
            runner.failure = lambda argv: '/usr/bin/umount' in argv
            with mock.patch.object(M, 'namespace_guard'), mock.patch.object(M, 'guest_guard'), \
                 mock.patch.object(M, 'load_lock', return_value={'public': item()}), \
                 mock.patch.object(M, 'Runner', return_value=runner), \
                 mock.patch.object(M, 'install'), mock.patch.object(M.Path, 'exists', return_value=False):
                report = M.worker({'mode': 'build', 'deadline': deadline()}, stage)
            self.assertEqual(report['state'], 'failed')
            self.assertEqual(report['failure'], 'cleanup_unconfirmed')
            self.assertFalse(report['runtime_unmounted'])


if __name__ == '__main__':
    unittest.main()
