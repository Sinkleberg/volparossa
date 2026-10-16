#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert image/boot contract tests: no image tools, downloads, models or VMs."""
import hashlib
from contextlib import nullcontext
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
    def test_redirect_allows_only_exact_mirror_resource_and_existing_origins(self):
        path = '/images/cloud/trixie/20260826-2582/debian-13-genericcloud-amd64-20260826-2582.qcow2'
        source = M.urllib.request.Request('https://cloud.debian.org' + path)
        for host in ('saimei.ftp.acc.umu.se', 'saimei.ftp.acc.umu.se:443',
                     'cloud.debian.org', 'deb.debian.org'):
            with self.subTest(host=host):
                target = 'https://' + host + path
                redirect = M.PinnedRedirect().redirect_request(source, None, 302, '', {}, target)
                self.assertEqual(redirect.full_url, target)

    def test_redirect_rejects_changed_path_query_and_fragment(self):
        source = M.urllib.request.Request('https://cloud.debian.org/images/pinned.qcow2')
        for suffix in ('/images/other.qcow2', '/images/pinned.qcow2?changed=1',
                       '/images/pinned.qcow2#fragment', '/images/../pinned.qcow2'):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, 'download_redirect'):
                M.PinnedRedirect().redirect_request(source, None, 302, '', {},
                                                    'https://saimei.ftp.acc.umu.se' + suffix)

    def test_redirect_rejects_untrusted_host_transport_credentials_and_port(self):
        source = M.urllib.request.Request('https://cloud.debian.org/images/pinned.qcow2')
        for prefix in ('http://saimei.ftp.acc.umu.se', 'https://unreviewed.ftp.acc.umu.se',
                       'https://saimei.ftp.acc.umu.se.attacker.invalid', 'https://attacker.invalid',
                       'https://user@saimei.ftp.acc.umu.se', 'https://@saimei.ftp.acc.umu.se',
                       'https://user:password@saimei.ftp.acc.umu.se',
                       'https://saimei.ftp.acc.umu.se:444'):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, 'download_redirect'):
                M.PinnedRedirect().redirect_request(source, None, 302, '', {},
                                                    prefix + '/images/pinned.qcow2')
        package = M.urllib.request.Request('https://deb.debian.org/images/pinned.qcow2')
        with self.assertRaisesRegex(ValueError, 'download_redirect'):
            M.PinnedRedirect().redirect_request(package, None, 302, '', {},
                'https://saimei.ftp.acc.umu.se/images/pinned.qcow2')

    def test_redirect_does_not_bypass_download_digest_size_or_deadline(self):
        payload = b'public pinned bytes'
        item = dict(url='https://cloud.debian.org/images/pinned.qcow2', bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest())
        def open_public(handler, *_args, **_kwargs):
            source = M.urllib.request.Request(item['url'])
            handler.redirect_request(source, None, 302, '', {},
                'https://saimei.ftp.acc.umu.se/images/pinned.qcow2')
            result = io.BytesIO(payload)
            result.status = 200
            return result
        def opener(handler):
            return SimpleNamespace(open=lambda *args, **kwargs: open_public(handler, *args, **kwargs))
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(M.urllib.request, 'build_opener', side_effect=opener):
            target = Path(directory) / 'good'
            M.fetch(item, target, 'sha256', len(payload), time.monotonic() + 5)
            self.assertEqual(target.read_bytes(), payload)
            for index, (changed, maximum, deadline, reason) in enumerate((
                    ({**item, 'sha256': '0' * 64}, len(payload), time.monotonic() + 5, 'download_digest'),
                    ({**item, 'bytes': len(payload) + 1}, len(payload), time.monotonic() + 5, 'download_digest'),
                    (item, len(payload) - 1, time.monotonic() + 5, 'download_bound'),
                    (item, len(payload), time.monotonic() - 1, 'build_deadline'))):
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                    M.fetch(changed, Path(directory) / str(index), 'sha256', maximum, deadline)

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


class InspectionContracts(unittest.TestCase):
    def extract(self, directory, *, roots='/dev/sda1', details=('debian', '13', 'ext4', '4096')):
        output = Path(directory)
        pins = M.load_pins()
        handles = []
        def fresh_handle(_image, operations, **kwargs):
            # Inspection cache exists only inside this one invocation.
            inspected, emitted = False, []
            handles.append((operations, kwargs['operation']))
            for operation in operations:
                name = operation[0]
                if name == 'inspect-os':
                    inspected = True
                    emitted.extend((roots if len(handles) == 2 else '/dev/sda1').splitlines())
                elif name.startswith('inspect-get-'):
                    self.assertTrue(inspected, 'fresh handle has no inspection cache')
                    emitted.append(details[0 if name == 'inspect-get-distro' else 1])
                elif name == 'vfs-type':
                    emitted.append(details[2])
                elif name == 'blockdev-getsize64':
                    emitted.append(details[3])
                elif name == 'download' and str(operation[1]).startswith('/boot/config-'):
                    names = ('BLK_DEV_INITRD', 'DEVTMPFS', 'EXT4_FS', 'BLK_DEV_DM', 'DM_VERITY',
                             'VIRTIO_PCI', 'VIRTIO_BLK', 'SERIAL_8250', 'SERIAL_8250_CONSOLE')
                    Path(operation[2]).write_text('\n'.join('CONFIG_' + key + '=y' for key in names))
                elif name == 'readlink':
                    emitted.append('usr/' + operation[1].removeprefix('/'))
            return '\n'.join(emitted) + '\n'
        def extracted(_archive, tree):
            (tree / 'lib/modules' / pins['kernel_release']).mkdir(parents=True)
        with mock.patch.object(M, 'digest', return_value={'sha512': pins['debian_image_sha512']}), \
                mock.patch.object(M, 'guestfish', side_effect=fresh_handle), \
                mock.patch.object(M, 'safe_tree', side_effect=extracted):
            tree, size = M.extract_boot(output / 'public.qcow2', output, pins)
        return tree, size, handles

    def test_metadata_handle_inspects_before_cached_queries_and_binds_same_root(self):
        with tempfile.TemporaryDirectory() as directory:
            tree, size, handles = self.extract(directory)
            self.assertEqual(size, 4096)
            self.assertEqual(tree, Path(directory) / 'root-tree')
            self.assertEqual(handles[1], ([['inspect-os'], ['inspect-get-distro', '/dev/sda1'],
                ['inspect-get-major-version', '/dev/sda1'], ['vfs-type', '/dev/sda1'],
                ['blockdev-getsize64', '/dev/sda1']], 'inspect_details'))
            self.assertEqual([entry[1] for entry in handles], ['inspect_roots', 'inspect_details',
                'extract_boot_files', 'readlink_bin', 'readlink_sbin', 'readlink_lib', 'readlink_lib64'])

    def test_metadata_handle_rejects_different_multiple_or_missing_roots(self):
        for roots in ('/dev/sda2', '/dev/sda1\n/dev/sda2', ''):
            with self.subTest(roots=roots), tempfile.TemporaryDirectory() as directory, \
                    self.assertRaisesRegex(ValueError, 'inspection_root_binding'):
                self.extract(directory, roots=roots)

    def test_metadata_handle_preserves_exact_distribution_filesystem_and_size_guards(self):
        for details in (('ubuntu', '13', 'ext4', '4096'), ('debian', '12', 'ext4', '4096'),
                        ('debian', '13', 'xfs', '4096'), ('debian', '13', 'ext4', '4097'),
                        ('debian', '13', 'ext4', str(M.MAX_ROOT + 4096))):
            with self.subTest(details=details), tempfile.TemporaryDirectory() as directory, \
                    self.assertRaises(ValueError):
                self.extract(directory, details=details)


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
            M.guestfish(Path('/public/root.raw'), [['inspect-os']], operation='inspect_roots')
        argv = run.call_args.args[0]
        self.assertEqual(argv[argv.index('set-pgroup'):],
            ['set-pgroup', 'false', ':', 'set-network', 'false', ':', 'run', ':', 'inspect-os'])
        self.assertEqual(run.call_args.kwargs, {'timeout': 300, 'operation': 'inspect_roots'})
        self.assertEqual(M.ENV['LIBGUESTFS_BACKEND_SETTINGS'], 'force_kvm')


class ApplianceDiagnostics(unittest.TestCase):
    def entries(self, names):
        return nullcontext(iter(SimpleNamespace(name=name) for name in names))

    def test_candidate_census_is_closed_and_never_claims_actual_selection(self):
        canary = 'PRIVATE_KERNEL_CANARY'
        def scan(path):
            return self.entries([canary] if path == Path('/lib/modules') else
                                ['vmlinuz-' + canary, 'config-ignored', 'vmlinuz-../bad',
                                 'vmlinuz-.', 'vmlinuz-..'])
        def readable(path):
            return 'missing' if str(path).startswith('/lib/modules/') and path.name == 'vmlinuz' else 'readable'
        with mock.patch.object(M.os, 'scandir', side_effect=scan), \
                mock.patch.object(M, 'readable_regular', side_effect=readable) as access, \
                mock.patch.object(M, 'kvm_observation', return_value='api_12'):
            value = M.appliance_preflight()
        self.assertEqual(value, dict(version=1, diagnostic_only=True, selected_kernel=False,
            kernel_selection='unobserved', candidates=2, incomplete=False,
            kernel=dict(readable=1, missing=1, denied=0, other=0),
            modules_index=dict(readable=2, missing=0, denied=0, other=0), kvm='api_12'))
        self.assertEqual(access.call_count, 4)
        self.assertNotIn(canary, json.dumps(value))
        self.assertNotIn('/lib/', json.dumps(value))

    def test_candidate_and_directory_scan_caps_mark_incomplete(self):
        for names, candidates, calls in (([f'6.{i}' for i in range(40)], 32, 64),
                                         (['invalid/name'] * 140, 0, 0)):
            with self.subTest(candidates=candidates), \
                    mock.patch.object(M.os, 'scandir', return_value=self.entries(names)) as scan, \
                    mock.patch.object(M, 'readable_regular', return_value='readable') as access, \
                    mock.patch.object(M, 'kvm_observation', return_value='api_12'):
                value = M.appliance_preflight()
            self.assertEqual(value['candidates'], candidates)
            self.assertTrue(value['incomplete'])
            self.assertFalse(value['selected_kernel'])
            self.assertEqual(access.call_count, calls)
            scan.assert_called_once_with(Path('/lib/modules'))

    def test_unavailable_census_is_observation_not_raw_error_or_kernel_selection(self):
        with mock.patch.object(M.os, 'scandir', side_effect=PermissionError('PRIVATE_PATH_CANARY')), \
                mock.patch.object(M, 'kvm_observation', return_value='denied'):
            value = M.appliance_preflight()
        self.assertTrue(value['incomplete'])
        self.assertEqual(value['candidates'], 0)
        self.assertEqual(value['kvm'], 'denied')
        self.assertEqual(value['kernel_selection'], 'unobserved')
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_file_access_observation_reads_no_contents_and_closes_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'kernel'
            path.write_bytes(b'PRIVATE_KERNEL_CONTENT')
            with mock.patch.object(M.os, 'read', side_effect=AssertionError('must not read')):
                self.assertEqual(M.readable_regular(path), 'readable')
                self.assertEqual(M.readable_regular(path.parent), 'other')
                self.assertEqual(M.readable_regular(path.with_name('missing')), 'missing')
        for error, expected in ((PermissionError('PRIVATE'), 'denied'), (OSError('PRIVATE'), 'other')):
            with mock.patch.object(M.os, 'open', side_effect=error):
                self.assertEqual(M.readable_regular('/unread'), expected)
        with mock.patch.object(M.os, 'open', return_value=123), \
                mock.patch.object(M.os, 'fstat', side_effect=OSError('PRIVATE')), \
                mock.patch.object(M.os, 'close') as close:
            self.assertEqual(M.readable_regular('/unread'), 'other')
        close.assert_called_once_with(123)

    def test_kvm_query_is_only_system_api_read_and_always_closes(self):
        for mode, answer, expected in ((M.stat.S_IFCHR, 12, 'api_12'),
                                      (M.stat.S_IFCHR, 11, 'api_mismatch'),
                                      (M.stat.S_IFREG, 12, 'not_character_device')):
            with self.subTest(expected=expected), mock.patch.object(M.os, 'open', return_value=123) as opened, \
                    mock.patch.object(M.os, 'fstat', return_value=SimpleNamespace(st_mode=mode)), \
                    mock.patch.object(M.fcntl, 'ioctl', return_value=answer) as ioctl, \
                    mock.patch.object(M.os, 'close') as close:
                self.assertEqual(M.kvm_observation(), expected)
            opened.assert_called_once_with('/dev/kvm', M.os.O_RDWR | M.os.O_CLOEXEC | M.os.O_NONBLOCK)
            close.assert_called_once_with(123)
            if mode == M.stat.S_IFCHR:
                ioctl.assert_called_once_with(123, 0xAE00, 0)
            else:
                ioctl.assert_not_called()
        for error, expected in ((FileNotFoundError('PRIVATE'), 'missing'),
                                (PermissionError('PRIVATE'), 'denied'), (OSError('PRIVATE'), 'io_error')):
            with mock.patch.object(M.os, 'open', side_effect=error):
                self.assertEqual(M.kvm_observation(), expected)
        with mock.patch.object(M.os, 'open', return_value=123), \
                mock.patch.object(M.os, 'fstat', return_value=SimpleNamespace(st_mode=M.stat.S_IFCHR)), \
                mock.patch.object(M.fcntl, 'ioctl', side_effect=OSError('PRIVATE')), \
                mock.patch.object(M.os, 'close') as close:
            self.assertEqual(M.kvm_observation(), 'io_error')
        close.assert_called_once_with(123)

    def test_preflight_obeys_original_absolute_deadline_before_host_queries(self):
        token = M.DEADLINE.set(time.monotonic() - 1)
        try:
            with mock.patch.object(M, 'kvm_observation') as kvm, \
                    mock.patch.object(M.os, 'scandir') as scan, \
                    self.assertRaisesRegex(ValueError, 'build_deadline'):
                M.appliance_preflight()
            kvm.assert_not_called()
            scan.assert_not_called()
        finally:
            M.DEADLINE.reset(token)

    def test_exact_upstream_stderr_patterns_survive_every_chunk_boundary(self):
        for line, label in M.STDERR_PATTERNS.items():
            with self.subTest(label=label):
                observed = M.GuestfishStderr()
                for byte in line + b'\r\n' + line:
                    observed.feed(bytes([byte]))
                self.assertEqual(observed.finish(), label)
                self.assertEqual(observed.pending, b'')

    def test_unknown_near_match_and_private_stderr_never_become_a_known_class(self):
        line = b'libguestfs: error: force_kvm supplied but kvm not available.'
        for raw in (b'PRIVATE_CANARY/path: Permission denied\n', b'canary ' + line,
                    line + b' PRIVATE_CANARY', line.upper(), b'\xff' + line):
            with self.subTest(raw=raw):
                observed = M.GuestfishStderr()
                observed.feed(raw)
                self.assertEqual(observed.finish(), 'unclassified')
        for bad in ('PRIVATE_CANARY', [], True):
            self.assertIsNone(M.command_failure(M.CommandFailed(1, 'inspect_roots', bad))['stderr_class'])

    def test_fixed_guestfish_argv_prefix_is_supported_without_arbitrary_source_paths(self):
        line = b'libguestfs: error: guestfs_launch failed.'
        for prefix, expected in ((b'*stdin*:0: ', 'appliance_launch_failed'),
                                 (b'*stdin*:1: ', 'unclassified'),
                                 (b'/PRIVATE_PATH:0: ', 'unclassified')):
            observed = M.GuestfishStderr()
            observed.feed(prefix[:4])
            observed.feed(prefix[4:] + line)
            self.assertEqual(observed.finish(), expected)

    def test_long_lines_are_bounded_and_multiple_known_classes_are_ambiguous(self):
        observed = M.GuestfishStderr()
        observed.feed(b'P' * 4097)
        self.assertEqual(observed.pending, b'')
        self.assertTrue(observed.dropping)
        first = b'libguestfs: error: guestfs_launch failed.'
        observed.feed(first + b'\n' + first + b'\n')
        observed.feed(b'libguestfs: error: appliance launch timed out.\n')
        self.assertEqual(observed.finish(), 'ambiguous')

    def test_real_child_classifies_only_stderr_not_stdout_or_unlabelled_commands(self):
        line = b'libguestfs: error: force_kvm supplied but kvm not available.'
        for descriptor, operation, expected in ((1, 'inspect_roots', 'unclassified'),
                                                (2, 'inspect_roots', 'kvm_unavailable'),
                                                (2, None, None)):
            program = f'import os,sys; os.write({descriptor}, {line!r}); sys.exit(7)'
            with self.subTest(descriptor=descriptor, operation=operation), \
                    self.assertRaises(M.CommandFailed) as raised:
                M.command([sys.executable, '-c', program], operation=operation)
            self.assertEqual(raised.exception.stderr_class, expected)
            self.assertEqual(raised.exception.args, ('command_failed',))

    def test_stderr_classifier_does_not_expand_total_output_limit_or_change_success(self):
        line = b'libguestfs: error: guestfs_launch failed.\n'
        program = f'import os; os.write(2, {line!r}); os.write(1, b"public output\\n")'
        result = M.command([sys.executable, '-c', program], operation='inspect_roots')
        self.assertEqual(sorted(result.splitlines()), sorted([line.rstrip(), b'public output']))
        with self.assertRaisesRegex(ValueError, 'command_output_bound') as raised:
            M.command([sys.executable, '-c', program], operation='inspect_roots', maximum=len(line))
        self.assertNotIsInstance(raised.exception, M.CommandFailed)
        self.assertIsNone(M.command_failure(raised.exception))

    def test_preflight_runs_before_download_without_changing_deadline_or_admission(self):
        observed = dict(version=1, diagnostic_only=True, selected_kernel=False,
                        kernel_selection='unobserved', candidates=0, incomplete=True,
                        kernel={}, modules_index={}, kvm='denied')
        order, deadlines = [], []
        original = ValueError('download_digest')
        def sample():
            order.append('observe')
            deadlines.append(M.DEADLINE.get())
            return observed
        def download(*_args):
            order.append('download')
            deadlines.append(M.DEADLINE.get())
            raise original
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(M, 'hosted_output', return_value=Path(directory)), \
                mock.patch.object(M, 'source_binding', return_value={'revision': 'a' * 40}), \
                mock.patch.object(M, 'tool_inventory', return_value={}), \
                mock.patch.object(M, 'appliance_preflight', side_effect=sample), \
                mock.patch.object(M, 'fetch', side_effect=download), \
                self.assertRaises(ValueError) as raised:
            try:
                M.execute(SimpleNamespace(yes=True, work=directory, expected_source='a' * 40))
            finally:
                evidence = Path(directory) / 'evidence'
                value = json.loads((evidence / 'cleanup.json').read_text())
                self.assertEqual(set(path.name for path in evidence.iterdir()), {'cleanup.json'})
                self.assertEqual(value['appliance_preflight'], observed)
                self.assertEqual(value['failure']['reason'], 'download_digest')
                self.assertTrue(value['owned_scratch_removed'])
        self.assertIs(raised.exception, original)
        self.assertEqual(order, ['observe', 'download'])
        self.assertIsNotNone(deadlines[0])
        self.assertEqual(deadlines[0], deadlines[1])


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
            self.assertEqual(value['failure'], {'stage': 'host_tools', 'reason': 'unclassified', 'command': None})
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
                'import os,signal,time; os.kill(os.getppid(),signal.SIGTERM); time.sleep(10)'],
                operation='inspect_roots')
        with tempfile.TemporaryDirectory() as directory:
            start = time.monotonic()
            with self.assertRaisesRegex(ValueError, 'cancelled'):
                self.exercise(directory, interrupt)
            self.assertLess(time.monotonic() - start, 3)
            value = json.loads((Path(directory) / 'evidence/cleanup.json').read_text())
            self.assertEqual(value['failure'], {'stage': 'host_tools', 'reason': 'cancelled', 'command': None})
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

    def test_command_failure_has_only_closed_operation_and_bounded_returncode(self):
        for operation in M.GUESTFISH_OPERATIONS:
            for code in (-64, -9, 1, 255):
                failure = M.CommandFailed(code, operation)
                self.assertEqual(M.failure_reason(failure), 'command_failed')
                self.assertEqual(M.command_failure(failure), {'operation': operation, 'returncode': code,
                                                             'stderr_class': None})
        for operation, code in (('PRIVATE_CANARY/path', 1), (None, 1), ('inspect_roots', 0),
                                ('inspect_roots', True), ('inspect_roots', -65),
                                ('inspect_roots', 256), ('inspect_roots', 'PRIVATE_CANARY')):
            self.assertIsNone(M.command_failure(M.CommandFailed(code, operation)))
        fabricated = ValueError('command_failed')
        fabricated.operation, fabricated.returncode = 'inspect_roots', 1
        self.assertIsNone(M.command_failure(fabricated))

    def test_real_public_child_failure_retains_no_output_or_argv(self):
        with self.assertRaises(M.CommandFailed) as raised:
            M.command([sys.executable, '-c',
                'import sys; print("PRIVATE_CANARY"); print("PRIVATE_STDERR", file=sys.stderr); sys.exit(7)'],
                operation='inspect_roots')
        self.assertEqual(raised.exception.args, ('command_failed',))
        value = M.command_failure(raised.exception)
        self.assertEqual(value, {'operation': 'inspect_roots', 'returncode': 7, 'stderr_class': 'unclassified'})
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_timeout_never_projects_its_cleanup_signal_as_program_returncode(self):
        with self.assertRaisesRegex(ValueError, 'command_timeout') as raised:
            M.command([sys.executable, '-c', 'import time; time.sleep(10)'],
                      timeout=.05, operation='inspect_roots')
        self.assertNotIsInstance(raised.exception, M.CommandFailed)
        self.assertIsNone(M.command_failure(raised.exception))

    def test_typed_failure_context_survives_scratch_cleanup_failure_without_masking_primary(self):
        with tempfile.TemporaryDirectory() as directory:
            original = M.CommandFailed(1, 'inspect_details', 'appliance_launch_failed')
            with mock.patch.object(M.shutil, 'rmtree', side_effect=PermissionError('PRIVATE_CANARY')), \
                    self.assertRaises(M.CommandFailed) as raised:
                self.exercise(directory, original)
            self.assertIs(raised.exception, original)
            raw = (Path(directory) / 'evidence/cleanup.json').read_text()
            self.assertNotIn('PRIVATE', raw)
            value = json.loads(raw)
            self.assertEqual(value['failure'], {'stage': 'host_tools', 'reason': 'command_failed',
                'command': {'operation': 'inspect_details', 'returncode': 1,
                            'stderr_class': 'appliance_launch_failed'}})
            self.assertEqual(value['cleanup_error'], 'scratch_removal_failed')
            self.assertFalse(value['owned_scratch_removed'])


if __name__ == '__main__':
    unittest.main()
