#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert image/boot contract tests: no image tools, downloads, models or VMs."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('protected_resident_image',
                                              HERE / 'protected-resident-image.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def receipt(outcome='boot_verified'):
    okay = outcome == 'boot_verified'
    return dict(version=1, outcome=outcome, stage='complete' if okay else 'verity_read',
                verity_verified=okay, root_readonly=okay, write_denied=okay,
                entrypoint_invoked=okay, hardware_attestation=False, private_inputs=False,
                model_execution=False, worker_execution=False)


def encoded(value):
    return M.PREFIX + json.dumps(value, sort_keys=True).encode() + b'\n'


class InputContracts(unittest.TestCase):
    def test_existing_debian_manifest_and_three_packages_are_exact(self):
        pins = M.load_pins()
        self.assertEqual(pins['kernel_release'], '6.12.105+deb13-cloud-amd64')
        self.assertEqual(set(pins['packages']), {'cryptsetup-bin', 'libcryptsetup12', 'busybox-static'})
        self.assertEqual(sum(item['bytes'] for item in pins['packages'].values()), 1713000)
        self.assertFalse(pins['independent_production_approval'])
        self.assertTrue(pins['public_test_inputs_only'])

    def test_json_duplicate_keys_and_nonfinite_are_rejected(self):
        for raw in (b'{"version":1,"version":1}', b'{"value":NaN}', b'{"value":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                M.exact_json(raw)

    def test_digest_checks_original_bytes_and_refuses_symlink_or_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data'
            path.write_bytes(b'public fixture')
            self.assertEqual(M.digest(path), {'bytes': 14,
                'sha256': hashlib.sha256(b'public fixture').hexdigest()})
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaises(OSError):
                M.digest(link)
            with self.assertRaises(ValueError):
                M.digest(path, maximum=13)

    def test_hosted_guard_refuses_local_or_root_execution_before_mkdir(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'new'
            for environment, uid in (({}, 1000), ({'GITHUB_ACTIONS': 'true',
                    'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
                    'RUNNER_TEMP': directory}, 0)):
                with mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch.object(M.os, 'geteuid', return_value=uid), \
                        self.assertRaises(ValueError):
                    M.hosted_output(target)
            self.assertFalse(target.exists())

    def test_hosted_output_must_be_new_inside_runner_temporary_root(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                           'RUNNER_OS': 'Linux', 'RUNNER_TEMP': directory}
            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(M.os, 'geteuid', return_value=1000):
                root = Path(directory)
                for path in (root, root / '..' / 'outside'):
                    with self.assertRaises(ValueError):
                        M.hosted_output(path)
                created = M.hosted_output(root / 'new')
                self.assertEqual(created.stat().st_mode & 0o777, 0o700)
                with self.assertRaises(ValueError):
                    M.hosted_output(created)

    def test_exact_single_root_device_only(self):
        self.assertEqual(M.root_device('/dev/sda1\n'), '/dev/sda1')
        for text in ('', '/dev/sda1\n/dev/sda2\n', '/dev/mapper/arbitrary\n', '/dev/sda1;bad\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                M.root_device(text)

    def test_kernel_requires_actual_verity_and_boot_drivers(self):
        names = ('BLK_DEV_INITRD', 'DEVTMPFS', 'EXT4_FS', 'BLK_DEV_DM', 'DM_VERITY',
                 'VIRTIO_PCI', 'VIRTIO_BLK', 'SERIAL_8250', 'SERIAL_8250_CONSOLE')
        good = '\n'.join('CONFIG_' + name + '=y' for name in names)
        M.kernel_config(good)
        for name in names:
            with self.subTest(name=name), self.assertRaises(ValueError):
                M.kernel_config(good.replace('CONFIG_' + name + '=y', '# disabled'))

    def test_source_binding_requires_exact_head_and_clean_source(self):
        revision = 'a' * 40
        with mock.patch.object(M, 'command', side_effect=[(revision + '\n').encode(), b'', b'tree\n']):
            self.assertEqual(M.source_binding(revision), {'revision': revision, 'tree': 'tree'})
        for values in ([b'b' * 40], [(revision + '\n').encode(), b' M source\n']):
            with mock.patch.object(M, 'command', side_effect=values), self.assertRaises(ValueError):
                M.source_binding(revision)

    def test_package_hash_is_checked_before_any_extractor_executes(self):
        pins = M.load_pins()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(M, 'digest', return_value={'bytes': 1, 'sha256': 'bad'}), \
                mock.patch.object(M, 'command') as run, mock.patch.object(M, 'guestfish') as guest:
            with self.assertRaisesRegex(ValueError, 'package_digest'):
                M.stage_root(Path(directory), {name: Path('/unread/' + name)
                             for name in pins['packages']}, pins)
            run.assert_not_called()
            guest.assert_not_called()


class ArchiveContracts(unittest.TestCase):
    def archive(self, base, entries):
        path = base / 'fixture.tar'
        with tarfile.open(path, 'w') as output:
            for name, kind, data in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.REGTYPE:
                    member.size = len(data)
                    output.addfile(member, io.BytesIO(data))
                else:
                    member.linkname = data
                    output.addfile(member)
        return path

    def test_public_regular_files_and_inert_root_absolute_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = self.archive(base, [('usr/bin/tool', tarfile.REGTYPE, b'public'),
                                          ('bin', tarfile.SYMTYPE, '/usr/bin')])
            M.safe_tree(archive, base / 'tree')
            self.assertEqual((base / 'tree/usr/bin/tool').read_bytes(), b'public')
            self.assertEqual(os.readlink(base / 'tree/bin'), '/usr/bin')

    def test_archive_traversal_symlink_parents_and_specials_are_rejected(self):
        fixtures = [[('../escape', tarfile.REGTYPE, b'x')],
                    [('/absolute', tarfile.REGTYPE, b'x')],
                    [('link', tarfile.SYMTYPE, '/tmp'), ('link/canary', tarfile.REGTYPE, b'x')],
                    [('device', tarfile.CHRTYPE, '')]]
        for entries in fixtures:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                with self.assertRaises(ValueError):
                    M.safe_tree(self.archive(base, entries), base / 'tree')

    def test_archive_hardlink_becomes_independent_bounded_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = self.archive(base, [('first', tarfile.REGTYPE, b'public'),
                                          ('second', tarfile.LNKTYPE, 'first')])
            M.safe_tree(archive, base / 'tree')
            self.assertEqual((base / 'tree/second').read_bytes(), b'public')
            self.assertNotEqual((base / 'tree/first').stat().st_ino,
                                (base / 'tree/second').stat().st_ino)


class BootContracts(unittest.TestCase):
    def test_initrd_receipt_binds_bytes_and_public_only_scope(self):
        pins = M.load_pins()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for name in ('original-initrd.img', 'initrd.img'):
                (output / name).write_bytes(name.encode())
            value = dict(version=1, kernel_version=pins['kernel_release'], root_hash='a' * 64,
                data_blocks=1, salt=M.SALT, cmdline=M.CMDLINE,
                original_initrd_sha256=M.digest(output / 'original-initrd.img')['sha256'],
                hardware_attestation=False, private_inputs=False, model_execution=False,
                worker_execution=False, closure={'/init': 'a' * 64, '/usr/bin/busybox': 'b' * 64},
                initrd_sha256=M.digest(output / 'initrd.img')['sha256'],
                initrd_bytes=(output / 'initrd.img').stat().st_size)
            self.assertEqual(M.initrd_receipt(json.dumps(value).encode(), output, pins, 'a' * 64, 1), value)
            for delta in ({'model_execution': True}, {'private_note': 'PRIVATE_CANARY'},
                          {'root_hash': 'b' * 64}, {'data_blocks': True},
                          {'initrd_sha256': 'c' * 64}, {'closure': {'/private/canary': 'a' * 64}}):
                with self.subTest(delta=delta), self.assertRaises(ValueError):
                    M.initrd_receipt(json.dumps({**value, **delta}).encode(), output, pins, 'a' * 64, 1)

    def test_boot_has_only_fixed_readonly_disks_and_no_remote_or_debug_access(self):
        argv = M.boot_command(Path('/runner/work'))
        self.assertEqual(argv[argv.index('-append') + 1], M.CMDLINE)
        self.assertEqual(argv[argv.index('-nic') + 1], 'none')
        self.assertEqual(argv[argv.index('-monitor') + 1], 'none')
        disks = [argv[i + 1] for i, word in enumerate(argv) if word == '-drive']
        self.assertEqual(len(disks), 2)
        self.assertTrue(all('readonly=on' in disk and 'format=raw' in disk for disk in disks))
        self.assertFalse(any(word in argv for word in ('-netdev', '-virtfs', '-qmp', '-gdb', '-s')))
        self.assertNotIn('vp.root_hash', M.CMDLINE)
        self.assertEqual(argv[argv.index('-m') + 1], '1024')
        self.assertEqual(argv[argv.index('-smp') + 1], '2')

    def test_qemu_option_injection_is_rejected(self):
        for path in ('/runner/file,readonly=off', '/runner/file\nother'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                M.boot_command(Path(path))

    def test_verity_fixed_parameters_have_no_integrity_bypass(self):
        options = M.verity_options(1024)
        self.assertIn('--no-superblock', options)
        self.assertIn('--salt=' + '0' * 64, options)
        self.assertFalse(any('ignore-' in item or 'check-at-most-once' in item for item in options))
        for blocks in (False, 0, -1, M.MAX_ROOT // 4096 + 1):
            with self.assertRaises(ValueError):
                M.verity_options(blocks)

    def test_success_and_explicit_corruption_are_different_closed_receipts(self):
        for outcome in ('boot_verified', 'integrity_failure'):
            value = receipt(outcome)
            self.assertEqual(M.boot_receipt(b'public kernel log\n' + encoded(value), outcome), value)
        with self.assertRaises(ValueError):
            M.boot_receipt(b'kernel timed out\n', 'integrity_failure')

    def test_private_canary_unknown_fields_duplicates_and_claims_fail_closed(self):
        good = receipt()
        for value in ({**good, 'raw_error': 'PRIVATE_CANARY'}, {**good, 'model_execution': True},
                      {**good, 'hardware_attestation': True}, {**good, 'private_inputs': True},
                      {**good, 'version': True}, {**good, 'write_denied': 1},
                      {**good, 'stage': 'verity_open'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                M.boot_receipt(encoded(value), 'boot_verified')
        for raw in (encoded(good) * 2, M.PREFIX + b'{"version":1,"version":1}\n',
                    b'x' * (M.MAX_LOG + 1)):
            with self.assertRaises(ValueError):
                M.boot_receipt(raw, 'boot_verified')

    def test_corruption_requires_exact_stage_and_does_not_claim_partial_success(self):
        value = receipt('integrity_failure')
        for key, replacement in (('stage', 'root_mount'), ('verity_verified', True),
                                  ('outcome', 'boot_rejected')):
            with self.assertRaises(ValueError):
                M.boot_receipt(encoded({**value, key: replacement}), 'integrity_failure')

    def test_boot_pair_retains_good_original_and_flips_only_one_data_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            evidence = base / 'evidence'
            evidence.mkdir()
            original = b'P' * 4096
            (base / 'root.raw').write_bytes(original)
            commands = []
            def invoke(argv, **_):
                commands.append(argv)
                if argv[0] == 'cp':
                    Path(argv[-1]).write_bytes(Path(argv[-2]).read_bytes())
                    return b''
                outcome = 'integrity_failure' if 'corrupted-root.raw' in ' '.join(argv) else 'boot_verified'
                return encoded(receipt(outcome))
            with mock.patch.object(M, 'command', side_effect=invoke):
                M.boot_pair(base, evidence)
            changed = (base / 'corrupted-root.raw').read_bytes()
            self.assertEqual([i for i, pair in enumerate(zip(original, changed)) if pair[0] != pair[1]], [1024])
            self.assertEqual((base / 'root.raw').read_bytes(), original)
            self.assertEqual(len(commands), 3)
            self.assertEqual(set(path.name for path in evidence.iterdir()),
                             {'good-boot.json', 'corrupt-boot.json'})


class OwnedChildContracts(unittest.TestCase):
    def test_bounded_public_python_child_is_joined_before_return(self):
        self.assertEqual(M.command([sys.executable, '-c', 'print("public fixture")']), b'public fixture\n')

    def test_output_overflow_terminates_and_joins_owned_child(self):
        with self.assertRaisesRegex(ValueError, 'command_output_bound'):
            M.command([sys.executable, '-c', 'print("x"*4096)'], maximum=32)

    def test_timeout_terminates_and_joins_without_reusing_pid(self):
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'command_timeout'):
            M.command([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=.1)
        self.assertLess(time.monotonic() - start, 3)

    def test_absolute_budget_rejects_before_spawning(self):
        token = M.DEADLINE.set(time.monotonic() - 1)
        try:
            with mock.patch.object(M.subprocess, 'Popen') as spawn, self.assertRaises(ValueError):
                M.command(['not-executed'])
            spawn.assert_not_called()
        finally:
            M.DEADLINE.reset(token)

    def test_normal_exit_is_not_reaped_before_last_owned_group_signal(self):
        order = []
        wait = M.subprocess.Popen.wait
        kill = M.os.killpg
        def mark_wait(process, *args, **kwargs):
            order.append('wait')
            return wait(process, *args, **kwargs)
        def mark_kill(pid, sig):
            self.assertIn(sig, (signal.SIGKILL, 0))
            order.append('signal' if sig else 'observe')
            return kill(pid, sig)
        with mock.patch.object(M.subprocess.Popen, 'wait', mark_wait), \
                mock.patch.object(M.os, 'killpg', side_effect=mark_kill):
            M.command([sys.executable, '-c', 'pass'])
        self.assertEqual(order, ['signal', 'wait', 'observe'])

    def test_uncertain_group_is_not_treated_as_joined(self):
        with mock.patch.object(M, 'group_absent', return_value=False), \
                self.assertRaisesRegex(M.CleanupUnconfirmed, 'process_group_remaining'):
            M.command([sys.executable, '-c', 'pass'])

    def test_signal_failure_still_attempts_wait_and_closes_pipes_without_cleanup_claim(self):
        calls, processes = [], []
        spawn, kill = M.subprocess.Popen, M.os.killpg
        def remember(*args, **kwargs):
            process = spawn(*args, **kwargs)
            processes.append(process)
            original_wait = process.wait
            def waited(*args, **kwargs):
                calls.append('wait')
                return original_wait(*args, **kwargs)
            process.wait = waited
            return process
        def denied(pid, sig):
            if sig == signal.SIGKILL:
                raise PermissionError('PRIVATE_CANARY')
            return kill(pid, sig)
        with mock.patch.object(M.subprocess, 'Popen', side_effect=remember), \
                mock.patch.object(M.os, 'killpg', side_effect=denied), \
                self.assertRaisesRegex(M.CleanupUnconfirmed, 'process_group_signal_failed'):
            M.command([sys.executable, '-c', 'pass'])
        self.assertEqual(calls, ['wait'])
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

    def test_guestfish_keeps_appliance_in_owned_group_and_disables_network(self):
        with mock.patch.object(M, 'command', return_value=b'') as run:
            M.guestfish(Path('/public/root.raw'), [['list-filesystems']])
        argv = run.call_args.args[0]
        self.assertEqual(argv[argv.index('set-pgroup'):],
            ['set-pgroup', 'false', ':', 'set-network', 'false', ':', 'run', ':', 'list-filesystems'])
        self.assertEqual(M.ENV['LIBGUESTFS_BACKEND_SETTINGS'], 'force_kvm')


class FailurePreservation(unittest.TestCase):
    def exercise(self, directory, cause):
        args = SimpleNamespace(yes=True, work=directory, expected_source='a' * 40)
        with mock.patch.object(M, 'hosted_output', return_value=Path(directory)), \
                mock.patch.object(M, 'source_binding', return_value={'revision': 'a' * 40}), \
                mock.patch.object(M, 'tool_inventory', side_effect=cause):
            return M.execute(args)

    def test_primary_failure_is_closed_and_evidence_survives_scratch_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            original = ValueError('PRIVATE_CANARY arbitrary secret exception')
            with self.assertRaises(ValueError) as raised:
                self.exercise(directory, original)
            self.assertIs(raised.exception, original)
            raw = (Path(directory) / 'evidence/cleanup.json').read_text()
            self.assertNotIn('PRIVATE_CANARY', raw)
            value = json.loads(raw)
            self.assertEqual(value['failure'], {'stage': 'host_tools', 'reason': 'unclassified'})
            self.assertTrue(value['owned_scratch_removed'])
            self.assertFalse(value['boot_pair_verified'])

    def test_unconfirmed_join_preserves_owned_scratch_and_original_error(self):
        with tempfile.TemporaryDirectory() as directory:
            original = M.CleanupUnconfirmed('process_group_remaining')
            with self.assertRaises(M.CleanupUnconfirmed) as raised:
                self.exercise(directory, original)
            self.assertIs(raised.exception, original)
            value = json.loads((Path(directory) / 'evidence/cleanup.json').read_text())
            self.assertFalse(value['child_leaders_reaped'])
            self.assertFalse(value['original_process_groups_absent'])
            self.assertFalse(value['owned_scratch_removed'])
            self.assertTrue((Path(directory) / 'payload').is_dir())

    def test_sigterm_cancels_owned_child_and_restores_original_signal_handler(self):
        before = signal.getsignal(signal.SIGTERM)
        def interrupt():
            M.command([sys.executable, '-c',
                'import os,signal,time; os.kill(os.getppid(),signal.SIGTERM); time.sleep(10)'])
        with tempfile.TemporaryDirectory() as directory:
            start = time.monotonic()
            with self.assertRaisesRegex(ValueError, 'cancelled'):
                self.exercise(directory, interrupt)
            self.assertLess(time.monotonic() - start, 3)
            value = json.loads((Path(directory) / 'evidence/cleanup.json').read_text())
            self.assertEqual(value['failure'], {'stage': 'host_tools', 'reason': 'cancelled'})
            self.assertTrue(value['original_process_groups_absent'])
            self.assertTrue(value['owned_scratch_removed'])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_cleanup_error_never_replaces_original_primary_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            original = ValueError('command_failed')
            with mock.patch.object(M.shutil, 'rmtree', side_effect=PermissionError('PRIVATE_CANARY')), \
                    self.assertRaises(ValueError) as raised:
                self.exercise(directory, original)
            self.assertIs(raised.exception, original)
            value = json.loads((Path(directory) / 'evidence/cleanup.json').read_text())
            self.assertEqual(value['failure']['reason'], 'command_failed')
            self.assertEqual(value['cleanup_error'], 'scratch_removal_failed')
            self.assertFalse(value['owned_scratch_removed'])


if __name__ == '__main__':
    unittest.main()
