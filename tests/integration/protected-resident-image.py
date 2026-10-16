#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted-only immutable Debian boot prerequisite; never protected-task acceptance.

All image inspection/mutation happens inside libguestfs, not host loop mounts.
The input image and three additional packages are authenticated before extraction.
The resulting descriptor records a public build: it is NOT independent owner
approval, a hardware appraisal, or authorization to release private inputs.
"""
import argparse
import contextvars
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PINS = HERE / 'protected-resident-image-pins-v1.json'
BOOTSTRAP = ROOT / 'packaging/protected-resident/init'
ENTRYPOINT = ROOT / 'packaging/protected-resident/entrypoint'
ENTRYPOINT_GUEST = '/usr/lib/volparossa/protected-resident-entrypoint'
RUNTIME = '/opt/volparossa/runtime'
WORKER_UID = 985
SALT = '0' * 64
BLOCK_SIZE = 4096
MAX_IMAGE = 4 * 1024 ** 3
MAX_ROOT = 16 * 1024 ** 3
MAX_TREE = 4 * 1024 ** 3
MAX_LOG = 1024 ** 2
BOOT_SECONDS = 180
BUILD_SECONDS = 1200
CMDLINE = 'console=ttyS0 panic=-1 oops=panic quiet rdinit=/init vp.profile=public-boot-v1'
PREFIX = b'VP_PROTECTED_BOOT_V1 '
WRITE_PROBE = b'VOLPAROSSA public verity write probe\n'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
       'LIBGUESTFS_BACKEND': 'direct', 'LIBGUESTFS_BACKEND_SETTINGS': 'force_kvm',
       'LIBGUESTFS_MEMSIZE': '2048', 'PYTHONDONTWRITEBYTECODE': '1'}
DEADLINE = contextvars.ContextVar('protected_public_boot_deadline', default=None)
SCRATCH = contextvars.ContextVar('protected_public_boot_scratch', default=None)
CANCELLED = contextvars.ContextVar('protected_public_boot_cancelled', default=False)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def checkpoint():
    require(not CANCELLED.get(), 'cancelled')
    if DEADLINE.get() is not None:
        require(time.monotonic() < DEADLINE.get(), 'build_deadline')


def exact_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate_json_key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('json_constant')))


def digest(path, algorithm='sha256', maximum=MAX_ROOT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                'input_file_shape')
        value, length = hashlib.new(algorithm), 0
        while block := source.read(1024 ** 2):
            checkpoint()
            length += len(block)
            require(length <= maximum, 'input_file_bound')
            value.update(block)
        after = os.fstat(source.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        require(identity(before) == identity(after) and length == before.st_size,
                'input_file_changed')
    return {'bytes': length, algorithm: value.hexdigest()}


def load_pins():
    pins = exact_json(PINS.read_bytes())
    image = exact_json((ROOT / pins['debian_image_manifest']).read_bytes())
    require(pins['version'] == 1 and pins['kind'] == 'protected-resident-public-boot-inputs'
            and pins['public_test_inputs_only'] is True
            and pins['independent_production_approval'] is False, 'pins_scope')
    require(image['sha512'] == pins['debian_image_sha512']
            and image['release_build'] == '20260826-2582'
            and image['architecture'] == 'amd64', 'image_pin_binding')
    require(pins['kernel_release'] == '6.12.105+deb13-cloud-amd64'
            and pins['kernel_package_version'] == '6.12.105-1', 'kernel_pin')
    require(set(pins['packages']) == {'cryptsetup-bin', 'libcryptsetup12', 'busybox-static'},
            'package_pins')
    require(pins['verity'] == dict(format=1, hash='sha256', data_block_size=4096,
                                  hash_block_size=4096, salt=SALT, superblock=False),
            'verity_parameters')
    return pins


def source_binding(expected):
    require(type(expected) is str and re.fullmatch('[0-9a-f]{40}', expected), 'source_revision')
    actual = command(['git', '-C', ROOT, 'rev-parse', 'HEAD']).decode().strip()
    require(actual == expected, 'source_revision')
    require(not command(['git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=all']),
            'source_dirty')
    return {'revision': actual,
            'tree': command(['git', '-C', ROOT, 'rev-parse', 'HEAD^{tree}']).decode().strip()}


def hosted_output(path):
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('RUNNER_OS') == 'Linux' and os.geteuid() != 0, 'hosted_only')
    parent = Path(os.environ.get('RUNNER_TEMP', '')).resolve(strict=True)
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent
            and path.is_relative_to(parent) and path != parent
            and not path.exists() and not path.is_symlink(), 'new_private_output')
    path.mkdir(mode=0o700)
    return path


class CleanupUnconfirmed(RuntimeError):
    pass


def group_absent(group, seconds=2):
    deadline = time.monotonic() + seconds
    while True:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(.02)


def command(argv, *, timeout=120, maximum=MAX_LOG, stdout_path=None):
    """Bound public tool output; retain the child until the last group signal."""
    require(0 < timeout <= BUILD_SECONDS, 'command_deadline')
    checkpoint()
    if DEADLINE.get() is not None:
        timeout = min(timeout, DEADLINE.get() - time.monotonic())
        require(timeout > 0, 'build_deadline')
    output = bytearray()
    deadline = time.monotonic() + timeout
    target = None
    environment = dict(ENV)
    if SCRATCH.get() is not None:
        environment.update(LIBGUESTFS_CACHEDIR=str(SCRATCH.get()),
                           LIBGUESTFS_TMPDIR=str(SCRATCH.get()), TMPDIR=str(SCRATCH.get()))
    process = subprocess.Popen([str(item) for item in argv], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, close_fds=True,
        start_new_session=True)
    try:
        if stdout_path is not None:
            target = open(stdout_path, 'xb')
        with selectors.DefaultSelector() as selector:
            for pipe in (process.stdout, process.stderr):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            total = 0
            while selector.get_map():
                checkpoint()
                require(time.monotonic() < deadline, 'command_timeout')
                for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(block)
                    require(total <= maximum, 'command_output_bound')
                    if target is not None and key.fileobj is process.stdout:
                        target.write(block)
                    else:
                        output.extend(block)
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                checkpoint()
                require(time.monotonic() < deadline, 'command_timeout')
                time.sleep(.01)
    finally:
        # No poll()/wait() before this last signal: even an exited leader remains
        # unreaped, so its PID/process-group identity cannot have been recycled.
        signal_failed = False
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            signal_failed = True
        try:
            try:
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError) as error:
                raise CleanupUnconfirmed('child_join_unconfirmed') from error
            if not group_absent(process.pid):
                raise CleanupUnconfirmed('process_group_remaining')
            if signal_failed:
                raise CleanupUnconfirmed('process_group_signal_failed')
        finally:
            process.stdout.close()
            process.stderr.close()
            if target is not None:
                target.close()
    require(process.returncode == 0, 'command_failed')
    return bytes(output)


def fetch(item, target, algorithm, maximum, deadline):
    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, newurl):
            parsed = urllib.parse.urlsplit(newurl)
            require(parsed.scheme == 'https' and parsed.hostname in
                    ('cloud.debian.org', 'deb.debian.org') and not parsed.username
                    and not parsed.password and parsed.port in (None, 443), 'download_redirect')
            return super().redirect_request(request, fp, code, message, headers, newurl)
    require(item['url'].startswith(('https://cloud.debian.org/', 'https://deb.debian.org/')),
            'download_origin')
    opener = urllib.request.build_opener(Redirect())
    checkpoint()
    require(time.monotonic() < deadline, 'build_deadline')
    with opener.open(item['url'], timeout=min(30, deadline - time.monotonic())) as response, \
            open(target, 'xb') as output:
        require(response.status == 200, 'download_status')
        length, value = 0, hashlib.new(algorithm)
        while block := response.read(1024 ** 2):
            checkpoint()
            require(time.monotonic() < deadline, 'build_deadline')
            length += len(block)
            require(length <= maximum, 'download_bound')
            output.write(block)
            value.update(block)
    require(0 < length <= maximum and value.hexdigest() == item[algorithm]
            and ('bytes' not in item or length == item['bytes']), 'download_digest')


def guestfish(image, operations, *, readonly=True, image_format='raw', timeout=300):
    argv = ['guestfish', '--ro' if readonly else '--rw', '--format=' + image_format,
            '-a', image, 'set-pgroup', 'false', ':', 'set-network', 'false', ':', 'run']
    for operation in operations:
        argv.extend([':', *operation])
    return command(argv, timeout=timeout).decode('utf-8', errors='strict')


def root_device(output):
    lines = output.splitlines()
    require(len(lines) == 1 and re.fullmatch(r'/dev/sd[a-z][1-9][0-9]*', lines[0]),
            'one_inspected_root')
    return lines[0]


def kernel_config(raw):
    settings = dict(line.split('=', 1) for line in raw.splitlines()
                    if line.startswith('CONFIG_') and '=' in line)
    for name in ('BLK_DEV_INITRD', 'DEVTMPFS', 'EXT4_FS', 'BLK_DEV_DM', 'DM_VERITY',
                 'VIRTIO_PCI', 'VIRTIO_BLK', 'SERIAL_8250', 'SERIAL_8250_CONSOLE'):
        require(settings.get('CONFIG_' + name) in ('y', 'm'), 'kernel_feature_' + name)
    return settings


def safe_tree(archive, destination):
    """Extract authenticated public files; never follow archive symlink parents."""
    destination.mkdir(mode=0o700, exist_ok=True)
    total, count = 0, 0
    with tarfile.open(archive, mode='r:') as source:
        for member in source:
            checkpoint()
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts, 'archive_path')
            parts = tuple(part for part in path.parts if part != '.')
            if not parts:
                continue
            count += 1
            total += member.size
            require(count <= 100000 and total <= MAX_TREE, 'archive_bound')
            target = destination.joinpath(*parts)
            for parent in target.parents:
                if parent == destination:
                    break
                require(not parent.is_symlink(), 'archive_parent_symlink')
            require(not target.is_symlink(), 'archive_overwrite_symlink')
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(mode=0o755, exist_ok=True)
            elif member.issym():
                require(not target.exists(), 'archive_duplicate')
                target.symlink_to(member.linkname)
            elif member.isfile():
                require(not target.exists(), 'archive_duplicate')
                with source.extractfile(member) as incoming, open(target, 'xb') as outgoing:
                    shutil.copyfileobj(incoming, outgoing, 1024 ** 2)
                target.chmod(member.mode & 0o777)
            elif member.islnk():
                link = PurePosixPath(member.linkname)
                require(not link.is_absolute() and '..' not in link.parts, 'archive_hardlink')
                original = destination.joinpath(*link.parts)
                require(original.resolve().is_relative_to(destination.resolve())
                        and original.is_file() and not original.is_symlink(), 'archive_hardlink')
                require(not target.exists(), 'archive_duplicate')
                shutil.copyfile(original, target)
                target.chmod(member.mode & 0o777)
            else:
                raise ValueError('archive_special_file')


def extract_boot(image, output, pins):
    require(digest(image, 'sha512', MAX_IMAGE)['sha512'] == pins['debian_image_sha512'],
            'image_digest')
    device = root_device(guestfish(image, [['inspect-os']], image_format='qcow2'))
    details = guestfish(image, [['inspect-get-distro', device],
                              ['inspect-get-major-version', device],
                              ['vfs-type', device], ['blockdev-getsize64', device]],
                       image_format='qcow2').splitlines()
    require(len(details) == 4 and details[:3] == ['debian', '13', 'ext4'], 'image_os')
    size = int(details[3])
    require(0 < size <= MAX_ROOT and size % BLOCK_SIZE == 0, 'root_size')
    release = pins['kernel_release']
    guestfish(image, [['mount-ro', device, '/'],
        ['download', '/boot/vmlinuz-' + release, output / 'vmlinuz'],
        ['download', '/boot/config-' + release, output / 'kernel.config'],
        ['download', '/boot/initrd.img-' + release, output / 'original-initrd.img'],
        ['download-offset', device, output / 'root.raw', '0', str(size)],
        ['tar-out', '/usr', output / 'usr.tar']], image_format='qcow2', timeout=600)
    kernel_config((output / 'kernel.config').read_text())
    tree = output / 'root-tree'
    safe_tree(output / 'usr.tar', tree / 'usr')
    for name in ('bin', 'sbin', 'lib', 'lib64'):
        target = guestfish(image, [['mount-ro', device, '/'], ['readlink', '/' + name]],
                           image_format='qcow2').strip()
        require(target == 'usr/' + name, 'usr_merge_binding')
        (tree / name).symlink_to(target)
    require((tree / 'usr/lib/modules' / release).is_dir(), 'kernel_modules')
    return tree, size


def stage_root(output, packages, pins):
    operations = [['mount', '/dev/sda', '/']]
    for name in ('busybox-static', 'libcryptsetup12', 'cryptsetup-bin'):
        item, package = pins['packages'][name], packages[name]
        require(digest(package, maximum=1024 ** 2) ==
                {'bytes': item['bytes'], 'sha256': item['sha256']}, 'package_digest')
        metadata = command(['dpkg-deb', '--show', '--showformat=${Package}\n${Version}\n${Architecture}\n',
                            package]).decode().splitlines()
        require(metadata == [name, item['version'], 'amd64'], 'package_metadata')
        archive = output / (name + '.tar')
        command(['dpkg-deb', '--fsys-tarfile', package], stdout_path=archive,
                maximum=16 * 1024 ** 2)
        safe_tree(archive, output / 'root-tree')
        operations.append(['tar-in', archive, '/'])
    probe = output / 'write-probe'
    probe.write_bytes(WRITE_PROBE)
    operations.extend([
        ['mkdir-p', '/usr/lib/volparossa'], ['upload', ENTRYPOINT, ENTRYPOINT_GUEST],
        ['chmod', '0755', '/usr/lib/volparossa'], ['chown', '0', '0', '/usr/lib/volparossa'],
        ['chmod', '0555', ENTRYPOINT_GUEST], ['chown', '0', '0', ENTRYPOINT_GUEST],
        ['upload', probe, '/usr/lib/volparossa/verity-write-probe'],
        ['chmod', '0644', '/usr/lib/volparossa/verity-write-probe'],
        ['chown', '0', '0', '/usr/lib/volparossa/verity-write-probe'],
        ['mkdir-p', RUNTIME], ['chmod', '0700', RUNTIME],
        ['chown', str(WORKER_UID), str(WORKER_UID), RUNTIME],
        ['touch', RUNTIME + '/.volparossa-compute.lock'],
        ['chmod', '0600', RUNTIME + '/.volparossa-compute.lock'],
        ['chown', str(WORKER_UID), str(WORKER_UID), RUNTIME + '/.volparossa-compute.lock'],
        ['sync'], ['umount-all']])
    guestfish(output / 'root.raw', operations, readonly=False)


def verity_options(blocks):
    require(type(blocks) is int and 0 < blocks <= MAX_ROOT // BLOCK_SIZE, 'data_blocks')
    return ['--no-superblock', '--format=1', '--hash=sha256', '--data-block-size=4096',
            '--hash-block-size=4096', '--data-blocks=' + str(blocks), '--salt=' + SALT]


def seal_root(output, size):
    blocks = size // BLOCK_SIZE
    command(['veritysetup', *verity_options(blocks), '--root-hash-file=' + str(output / 'root.hash'),
             'format', output / 'root.raw', output / 'verity.raw'], timeout=300)
    root_hash = (output / 'root.hash').read_text().strip()
    require(re.fullmatch('[0-9a-f]{64}', root_hash), 'verity_root_hash')
    command(['veritysetup', *verity_options(blocks), 'verify', output / 'root.raw',
             output / 'verity.raw', root_hash], timeout=300)
    return root_hash, blocks


def boot_command(output, *, corrupted=False):
    output = Path(output)
    for path in (output / 'vmlinuz', output / 'initrd.img', output / 'root.raw', output / 'verity.raw'):
        require(',' not in str(path) and '\n' not in str(path), 'qemu_path')
    data = output / ('corrupted-root.raw' if corrupted else 'root.raw')
    return ['qemu-system-x86_64', '-name', 'volparossa-protected-public-boot',
            '-no-user-config', '-nodefaults', '-machine', 'q35,accel=kvm', '-cpu', 'host',
            '-smp', '2', '-m', '1024', '-kernel', str(output / 'vmlinuz'),
            '-initrd', str(output / 'initrd.img'), '-append', CMDLINE,
            '-drive', 'if=virtio,format=raw,readonly=on,file=' + str(data),
            '-drive', 'if=virtio,format=raw,readonly=on,file=' + str(output / 'verity.raw'),
            '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
            '-no-reboot', '-sandbox',
            'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


def boot_receipt(raw, expected=None):
    require(type(raw) is bytes and len(raw) <= MAX_LOG, 'boot_output_bound')
    rows = [line[len(PREFIX):] for line in raw.splitlines() if line.startswith(PREFIX)]
    require(len(rows) == 1 and len(rows[0]) <= 4096, 'one_boot_receipt')
    value = exact_json(rows[0])
    flags = ('verity_verified', 'root_readonly', 'write_denied', 'entrypoint_invoked')
    denied = ('hardware_attestation', 'private_inputs', 'model_execution', 'worker_execution')
    require(type(value) is dict and set(value) == {'version', 'outcome', 'stage', *flags, *denied}
            and type(value['version']) is int and value['version'] == 1, 'boot_receipt_shape')
    require(all(type(value[key]) is bool for key in (*flags, *denied))
            and not any(value[key] for key in denied), 'boot_scope')
    require(value['outcome'] in ('boot_verified', 'integrity_failure', 'boot_rejected'), 'boot_outcome')
    if expected is not None:
        require(expected in ('boot_verified', 'integrity_failure') and value['outcome'] == expected,
                'boot_outcome')
    if value['outcome'] == 'boot_verified':
        require(value['stage'] == 'complete' and all(value[key] for key in flags), 'boot_proof')
    elif value['outcome'] == 'integrity_failure':
        require(value['stage'] == 'verity_read' and not any(value[key] for key in flags),
                'integrity_proof')
    else:
        require(value['stage'] in ('bootstrap', 'cmdline', 'devices', 'modules', 'verity_open',
                'verity_read', 'root_mount', 'write_probe', 'entrypoint', 'complete')
                and not any(value[key] for key in flags), 'boot_rejection')
    return value


def record(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    require(len(raw) <= 1024 ** 2, 'evidence_bound')
    with open(path, 'xb') as output:
        output.write(raw)


def initrd_receipt(raw, output, pins, root_hash, blocks):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_LOG, 'initrd_receipt_bound')
    value = exact_json(raw)
    keys = {'version', 'kernel_version', 'root_hash', 'data_blocks', 'salt', 'cmdline',
            'original_initrd_sha256', 'hardware_attestation', 'private_inputs',
            'model_execution', 'worker_execution', 'closure', 'initrd_sha256', 'initrd_bytes'}
    require(type(value) is dict and set(value) == keys and type(value['version']) is int
            and value['version'] == 1 and value['kernel_version'] == pins['kernel_release']
            and value['root_hash'] == root_hash and type(value['data_blocks']) is int
            and value['data_blocks'] == blocks and value['salt'] == SALT
            and value['cmdline'] == CMDLINE, 'initrd_receipt_binding')
    require(all(value[key] is False for key in ('hardware_attestation', 'private_inputs',
                'model_execution', 'worker_execution')), 'initrd_receipt_scope')
    closure = value['closure']
    require(type(closure) is dict and 1 <= len(closure) <= 2048
            and all(type(name) is str and re.fullmatch(r'/[A-Za-z0-9_+./-]{1,256}', name)
                    and '..' not in name.split('/') and name.startswith(('/usr/', '/lib/', '/lib64/'))
                    or name == '/init' for name in closure), 'initrd_receipt_closure')
    require(all(type(item) is str and re.fullmatch('[0-9a-f]{64}', item)
                for item in closure.values()), 'initrd_receipt_closure')
    require(value['original_initrd_sha256'] == digest(output / 'original-initrd.img')['sha256']
            and type(value['initrd_bytes']) is int
            and {'bytes': value['initrd_bytes'], 'sha256': value['initrd_sha256']}
                == digest(output / 'initrd.img', maximum=256 * 1024 ** 2), 'initrd_receipt_file')
    return value


def boot_pair(output, evidence):
    good = boot_receipt(command(boot_command(output), timeout=BOOT_SECONDS))
    record(evidence / 'good-boot.json', good)
    require(good['outcome'] == 'boot_verified', 'positive_boot_failed')
    # One authenticated data byte is changed AFTER sealing. The initrd must
    # report both a mapped-read failure and verity status C, not just a timeout.
    corrupt = output / 'corrupted-root.raw'
    command(['cp', '--reflink=auto', '--sparse=always', '--', output / 'root.raw', corrupt], timeout=120)
    with open(corrupt, 'r+b') as changed:
        changed.seek(1024)
        original = changed.read(1)
        require(len(original) == 1, 'corruption_offset')
        changed.seek(1024)
        changed.write(bytes([original[0] ^ 1]))
    bad = boot_receipt(command(boot_command(output, corrupted=True), timeout=BOOT_SECONDS))
    record(evidence / 'corrupt-boot.json', bad)
    require(bad['outcome'] == 'integrity_failure', 'negative_boot_failed')
    return {'good': good, 'corrupt': bad}


def tool_inventory():
    tools = {}
    for name in ('guestfish', 'veritysetup', 'qemu-system-x86_64', 'dpkg-deb', 'readelf'):
        binary = shutil.which(name, path=ENV['PATH'])
        require(binary is not None, 'host_tool_missing')
        resolved = Path(binary).resolve(strict=True)
        tools[name] = {'binary_sha256': digest(resolved, maximum=128 * 1024 ** 2)['sha256'],
                       'version_sha256': hashlib.sha256(command([binary, '--version'])).hexdigest()}
    return {'observed_tools': tools, 'pre_pinned_host_tool_closure': False}


def failure_reason(error):
    allowed = {'cancelled', 'build_deadline', 'command_timeout', 'command_output_bound',
        'command_failed', 'child_join_unconfirmed', 'process_group_remaining', 'process_group_signal_failed',
        'source_revision', 'source_dirty', 'source_changed', 'host_tool_missing',
        'download_origin', 'download_redirect', 'download_status', 'download_bound',
        'download_digest', 'image_digest', 'one_inspected_root', 'image_os', 'root_size',
        'kernel_modules', 'usr_merge_binding', 'archive_path', 'archive_bound',
        'archive_parent_symlink', 'archive_overwrite_symlink', 'archive_duplicate',
        'archive_hardlink', 'archive_special_file', 'package_digest', 'package_metadata',
        'verity_root_hash', 'positive_boot_failed', 'negative_boot_failed',
        'one_boot_receipt', 'boot_receipt_shape', 'boot_scope', 'boot_outcome',
        'boot_proof', 'integrity_proof', 'boot_rejection', 'boot_inputs_changed',
        'initrd_receipt_binding', 'initrd_receipt_scope', 'initrd_receipt_closure',
        'initrd_receipt_file', 'initrd_receipt_bound'}
    if isinstance(error, (ValueError, CleanupUnconfirmed)) and error.args:
        reason = error.args[0]
        if type(reason) is str and reason in allowed:
            return reason
    if isinstance(error, OSError):
        return 'io_error'
    return 'unclassified'


def execute(args):
    require(args.yes, 'explicit_hosted_execution')
    pins = load_pins()
    work = hosted_output(args.work)
    evidence, output = work / 'evidence', work / 'payload'
    evidence.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    deadline, cleanup_safe, completed = time.monotonic() + BUILD_SECONDS, True, False
    stage, failure, cleanup_error, primary = 'source', None, None, None
    budget_token = DEADLINE.set(deadline)
    scratch = output / 'temporary'
    scratch.mkdir(mode=0o700)
    scratch_token = SCRATCH.set(scratch)
    cancel_token = CANCELLED.set(False)
    previous_signals = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
    for number in previous_signals:
        # Defer cancellation to a bounded checkpoint instead of raising in the
        # narrow Popen construction/registration window. Owned children are then
        # killed and joined by command() before outer scratch removal.
        signal.signal(number, lambda _number, _frame: CANCELLED.set(True))
    try:
        source = source_binding(args.expected_source)
        stage = 'host_tools'
        tools = tool_inventory()
        stage = 'input_download'
        image_pin = exact_json((ROOT / pins['debian_image_manifest']).read_bytes())
        image = output / 'debian.qcow2'
        fetch(image_pin, image, 'sha512', MAX_IMAGE, deadline)
        packages = {}
        for name, item in pins['packages'].items():
            packages[name] = output / (name + '.deb')
            fetch(item, packages[name], 'sha256', item['bytes'], deadline)
        stage = 'image_extract'
        tree, size = extract_boot(image, output, pins)
        stage = 'root_stage'
        stage_root(output, packages, pins)
        stage = 'root_seal'
        root_hash, blocks = seal_root(output, size)
        stage = 'initrd_build'
        initrd = command([sys.executable, HERE / 'protected-resident-initrd.py', tree,
            output / 'original-initrd.img', pins['kernel_release'], root_hash, str(blocks),
            output / 'initrd.img'], timeout=300)
        record(evidence / 'initrd.json', initrd_receipt(initrd, output, pins, root_hash, blocks))
        descriptor = dict(version=1, kind='protected-resident-public-boot-build',
            source=source, kernel_release=pins['kernel_release'], verity=pins['verity'],
            root_hash=root_hash, data_blocks=blocks, cmdline=CMDLINE, host_tools=tools,
            inputs={'image_sha512': pins['debian_image_sha512'], 'packages': pins['packages'],
                    'pins': digest(PINS), 'bootstrap': digest(BOOTSTRAP), 'entrypoint': digest(ENTRYPOINT)},
            files={name: digest(output / name) for name in ('vmlinuz', 'initrd.img', 'root.raw', 'verity.raw')},
            public_test_inputs_only=True, independent_production_approval=False,
            model_execution=False, worker_admission=False, private_input_release=False,
            hardware_attestation=False, confidential_execution=False)
        record(evidence / 'build.json', descriptor)
        require(time.monotonic() < deadline, 'build_deadline')
        stage = 'boot_pair'
        boot_pair(output, evidence)
        stage = 'post_boot_binding'
        require(all(digest(output / name) == expected for name, expected in descriptor['files'].items()),
                'boot_inputs_changed')
        require(source_binding(args.expected_source) == source, 'source_changed')
        completed = True
        stage = 'complete'
    except BaseException as error:
        primary = error
        failure = {'stage': stage, 'reason': failure_reason(error)}
        if isinstance(error, CleanupUnconfirmed):
            cleanup_safe = False
        raise
    finally:
        DEADLINE.reset(budget_token)
        SCRATCH.reset(scratch_token)
        try:
            if cleanup_safe:
                try:
                    shutil.rmtree(output)
                except OSError:
                    cleanup_error = 'scratch_removal_failed'
            try:
                record(evidence / 'cleanup.json', dict(version=1, kind='protected-resident-public-boot-cleanup',
                    child_leaders_reaped=cleanup_safe, original_process_groups_absent=cleanup_safe,
                    owned_scratch_removed=cleanup_safe and not output.exists(),
                    boot_pair_verified=completed, failure=failure, cleanup_error=cleanup_error,
                    hardware_attestation=False, private_inputs=False))
            except (OSError, ValueError):
                if primary is None:
                    raise
            if cleanup_error is not None and primary is None:
                raise CleanupUnconfirmed('scratch_removal_failed')
        finally:
            CANCELLED.reset(cancel_token)
            for number, handler in previous_signals.items():
                signal.signal(number, handler)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('execute',))
    parser.add_argument('--work', required=True)
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--yes', action='store_true')
    args = parser.parse_args()
    try:
        execute(args)
    except (OSError, ValueError, subprocess.SubprocessError, CleanupUnconfirmed):
        print('protected_resident_image_failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
