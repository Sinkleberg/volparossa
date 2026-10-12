#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stage exact Image/Cloud maintenance consumers only in the disposable guest.

This is a new proof profile. Historical Image/Cloud pins and receipts stay intact.
No SDK, npm package, browser, user data or storage enrollment is provisioned here.
"""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
PINS = HERE / 'storage-consumer-maintenance-pins.json'
BASE = runpy.run_path(str(HERE / 'image-snapshot-provision.py'))
require, digest, verify_files = (BASE[key] for key in ('require', 'digest', 'verify_files'))
SOURCES = {name: Path('/opt') / ('volparossa-' + name) for name in ('image', 'cloud')}
RUNTIME = Path('/opt/volparossa-node')
RECEIPT = Path('/opt/volparossa-storage-consumers')
REVISIONS = dict(image='aade424c3e96d0934edbddf31d2434757aa08564',
    cloud='9cb94fbb83e9f503ff5a66d43ed814f556d4a3af')
FILES = {
    'image': frozenset(('scripts/immich_snapshot.py', 'scripts/snapshot-storage.mjs',
        'src/core-storage.mjs', 'LICENSE')),
    'cloud': frozenset(('scripts/cloud-serve.mjs', 'scripts/private_file.py',
        'scripts/private_catalog.py', 'scripts/recovery-web-assets.mjs', 'src/private-file.mjs',
        'src/private-catalog.mjs', 'src/opencloud-dav.mjs', 'src/private-dav-server.mjs',
        'src/private-resource-id.mjs', 'src/recovery-web-metadata.mjs', 'src/owner-uploads.mjs',
        'src/storage-maintenance.mjs', 'vendor/volparossa-image/immich_snapshot.py',
        'vendor/volparossa-image/core-storage.mjs', 'vendor/volparossa-image/LICENSE',
        'third_party/volparossa-image-source.json', 'THIRD_PARTY_LICENSES.md', 'LICENSE')),
}
VENDORED = {'scripts/immich_snapshot.py': 'vendor/volparossa-image/immich_snapshot.py',
    'src/core-storage.mjs': 'vendor/volparossa-image/core-storage.mjs',
    'LICENSE': 'vendor/volparossa-image/LICENSE'}


def load_pins():
    pins = json.loads(PINS.read_text())
    require(set(pins) == {'version', 'sources', 'runtime'} and type(pins['version']) is int
        and pins['version'] == 1 and set(pins['sources']) == set(SOURCES)
        and pins['runtime'] == BASE['loader']()['load_pins']()['runtime'])
    for name, source in pins['sources'].items():
        require(set(source) == {'repository', 'revision', 'files'}
            and source['repository'] == 'https://github.com/VOLPAROSSA/volparossa-' + name
            and source['revision'] == REVISIONS[name] and set(source['files']) == FILES[name])
        for record in source['files'].values():
            require(set(record) == {'bytes', 'sha256'} and type(record['bytes']) is int
                and 0 < record['bytes'] <= 131072
                and re.fullmatch(r'[0-9a-f]{64}', record['sha256']))
    for original, vendored in VENDORED.items():
        require(pins['sources']['image']['files'][original]
            == pins['sources']['cloud']['files'][vendored])
    return pins


def guard():
    # The existing guard requires root, the exact Debian13 KVM guest identity,
    # fresh Image/Node destinations and free space before any network/mutation.
    BASE['guard']()
    for root in (SOURCES['cloud'], RECEIPT):
        require(root.resolve() == root and not root.exists() and not root.is_symlink())


def verify_vendor(pins):
    source = SOURCES['cloud'] / 'third_party/volparossa-image-source.json'
    vendor = json.loads(source.read_text())
    require(vendor['version'] == 1 and vendor['revision'] == REVISIONS['image']
        and vendor['repository'] == pins['sources']['image']['repository']
        and vendor['license'] == 'GPL-3.0-only' and vendor['local_modifications'] is False
        and set(vendor['files']) == set(VENDORED))
    for original, local in VENDORED.items():
        expected = pins['sources']['image']['files'][original]
        require(vendor['files'][original] == dict(local=local, **expected)
            and digest(SOURCES['image'] / original) == digest(SOURCES['cloud'] / local))


def provision():
    pins = load_pins()
    guard()
    os.umask(0o077)
    runtime_stage = BASE['loader']()
    tools = BASE['tool_receipts']()
    for root in (*SOURCES.values(), RUNTIME, RECEIPT):
        root.mkdir(mode=0o700)
    for name, source in pins['sources'].items():
        for path, record in source['files'].items():
            runtime_stage['fetch'](
                f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-{name}/{source['revision']}/{path}",
                SOURCES[name] / path, record)
        verify_files(SOURCES[name], source['files'])
    verify_vendor(pins)
    with tempfile.TemporaryDirectory(prefix='storage-consumer-node.', dir='/opt') as temporary:
        archive = Path(temporary) / 'node.tar.xz'
        runtime_stage['fetch'](pins['runtime']['url'], archive, pins['runtime'])
        with tarfile.open(archive, 'r:xz') as bundle:
            runtime_stage['extract_runtime'](bundle, RUNTIME, pins['runtime']['files'])
    verify_files(RUNTIME, pins['runtime']['files'])
    require(subprocess.check_output([str(RUNTIME / 'bin/node'), '--version'], text=True,
        timeout=10, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}).strip() == 'v24.19.0')
    report = dict(version=1, kind='storage-consumer-maintenance-runtime-provision', success=True,
        pins=pins, pins_sha256=digest(PINS), tools=tools, guest_only=True,
        source_files_verified=True, runtime_files_verified=True, shared_adapter_verified=True,
        original_licenses_retained=True, storage_enrollment_created=False,
        peer_storage_proven=False, application_restore_proven=False,
        sdk_or_browser_provisioned=False, immich_or_opencloud_server_started=False)
    with (RECEIPT / 'provision.json').open('x') as stream:
        stream.write(json.dumps(report, sort_keys=True, indent=2) + '\n')
    for root in (*SOURCES.values(), RUNTIME, RECEIPT):
        BASE['expose'](root)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('provision',))
    parser.add_argument('--download', action='store_true', required=True,
        help='explicit guest-only pinned Image/Cloud sources and Node runtime download')
    parser.parse_args()
    print(json.dumps(dict(plan='guest-only-pinned-storage-consumers', revisions=REVISIONS,
        sdk_or_browser_provisioned=False, storage_enrollment_created=False)), flush=True)
    provision()
    print('Pinned consumers verified; application restoration and peer maintenance are not yet tested')


if __name__ == '__main__':
    main()
