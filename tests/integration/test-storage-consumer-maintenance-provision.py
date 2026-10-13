#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert new-consumer provenance tests; no downloads, native build or guest start."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-consumer-maintenance-provision.py'))


class ConsumerProvision(unittest.TestCase):
    def test_explicit_profile_two_keeps_historical_pins_and_adds_only_required_import(self):
        old, current = M['load_pins'](), M['load_pins'](2)
        self.assertEqual(current['version'], 2)
        self.assertEqual(current['runtime'], old['runtime'])
        self.assertEqual(current['sources']['image']['revision'], 'fa0438747b79bf29e49a2fe65116cb166ebe10df')
        self.assertEqual(current['sources']['cloud']['revision'], 'f51b49b84af404cc8dd6e377e0545e2ca1ea4569')
        self.assertEqual(set(current['sources']['cloud']['files']) - set(old['sources']['cloud']['files']),
            {'src/storage-upload-maintenance.mjs'})
        self.assertEqual(set(old['sources']['cloud']['files']) - set(current['sources']['cloud']['files']), set())
        self.assertEqual(set(current['sources']['image']['files']), set(old['sources']['image']['files']))
        self.assertNotEqual(M['pins_path'](), M['pins_path'](2))
        for version in (True, 0, 4, '2'):
            with self.assertRaises(ValueError):
                M['load_pins'](version)
        for changed in (old, dict(current, version=1)):
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'pins.json'
                path.write_text(json.dumps(changed))
                with patch.dict(M['load_pins'].__globals__, PINS_V2=path), self.assertRaises(ValueError):
                    M['load_pins'](2)

    def test_profile_three_has_distinct_pins_but_no_new_runtime_or_source_scope(self):
        old, diagnostic, detailed = (M['load_pins'](version) for version in (1, 2, 3))
        self.assertEqual(detailed['version'], 3)
        self.assertEqual(old['runtime'], detailed['runtime'])
        self.assertEqual(diagnostic['runtime'], detailed['runtime'])
        self.assertEqual(len({M['pins_path'](version) for version in (1, 2, 3)}), 3)
        node = (HERE / 'storage-consumer-maintenance.mjs').read_text()
        for name in ('image', 'cloud'):
            self.assertNotEqual(detailed['sources'][name]['revision'], diagnostic['sources'][name]['revision'])
            self.assertEqual(set(detailed['sources'][name]['files']), set(diagnostic['sources'][name]['files']))
            self.assertIn(detailed['sources'][name]['revision'], node)
            self.assertEqual(detailed['sources'][name]['files']['LICENSE'], diagnostic['sources'][name]['files']['LICENSE'])
        for original, vendored in M['VENDORED'].items():
            self.assertEqual(detailed['sources']['image']['files'][original], detailed['sources']['cloud']['files'][vendored])
        cases = [diagnostic, dict(detailed, version=2)]
        changed = copy.deepcopy(detailed)
        changed['sources']['image']['revision'] = diagnostic['sources']['image']['revision']
        cases.append(changed)
        changed = copy.deepcopy(detailed)
        changed['sources']['cloud']['files']['vendor/volparossa-image/core-storage.mjs']['sha256'] = '0' * 64
        cases.append(changed)
        for changed in cases:
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'pins.json'
                path.write_text(json.dumps(changed))
                with patch.dict(M['load_pins'].__globals__, PINS_V3=path), self.assertRaises(ValueError):
                    M['load_pins'](3)

    def test_exact_sources_runtime_licenses_and_same_adapter(self):
        pins = M['load_pins']()
        self.assertEqual(set(pins['sources']), {'image', 'cloud'})
        self.assertEqual(pins['sources']['image']['revision'], 'aade424c3e96d0934edbddf31d2434757aa08564')
        self.assertEqual(pins['sources']['cloud']['revision'], '9cb94fbb83e9f503ff5a66d43ed814f556d4a3af')
        self.assertEqual(pins['runtime']['version'], '24.19.0')
        self.assertEqual(set(pins['runtime']['files']), {'bin/node', 'LICENSE'})
        for original, vendored in M['VENDORED'].items():
            self.assertEqual(pins['sources']['image']['files'][original], pins['sources']['cloud']['files'][vendored])
        self.assertNotIn('scripts/stage_web_sdk.py', pins['sources']['cloud']['files'])
        self.assertNotIn('scripts/build_web_ui.py', pins['sources']['cloud']['files'])

    def test_modified_scope_revision_and_vendor_hash_are_rejected(self):
        original = M['load_pins']()
        cases = []
        changed = copy.deepcopy(original)
        changed['version'] = True
        cases.append(changed)
        changed = copy.deepcopy(original)
        changed['sources']['cloud']['revision'] = '0' * 40
        cases.append(changed)
        changed = copy.deepcopy(original)
        changed['sources']['cloud']['files']['../unadmitted'] = dict(bytes=1, sha256='0' * 64)
        cases.append(changed)
        changed = copy.deepcopy(original)
        changed['sources']['cloud']['files']['vendor/volparossa-image/core-storage.mjs']['sha256'] = '0' * 64
        cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'pins.json'
                path.write_text(json.dumps(changed))
                with patch.dict(M['load_pins'].__globals__, PINS=path), self.assertRaises(ValueError):
                    M['load_pins']()

    def test_guard_refuses_development_host_before_any_subprocess(self):
        base = M['BASE']['guard'].__globals__
        with patch.object(base['os'], 'geteuid', return_value=0), \
                patch.object(base['socket'], 'gethostname', return_value='developer-host'), \
                patch.object(base['subprocess'], 'check_output') as command:
            with self.assertRaises(ValueError):
                M['guard']()
            command.assert_not_called()

    def test_no_download_without_explicit_flag(self):
        result = subprocess.run([sys.executable, '-B', str(HERE / 'storage-consumer-maintenance-provision.py'),
            'provision'], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--download', result.stderr)

    def test_vendor_provenance_and_bytes_are_both_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            sources = {name: Path(temporary) / name for name in ('image', 'cloud')}
            files = {}
            manifest = dict(version=1, revision=M['REVISIONS']['image'],
                repository='https://github.com/VOLPAROSSA/volparossa-image',
                license='GPL-3.0-only', local_modifications=False, files=files)
            pins = dict(sources=dict(image=dict(repository=manifest['repository'], files={})))
            for original, local in M['VENDORED'].items():
                data = ('inert source ' + original).encode()
                record = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                pins['sources']['image']['files'][original] = record
                files[original] = dict(local=local, **record)
                for path in (sources['image'] / original, sources['cloud'] / local):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
            path = sources['cloud'] / 'third_party/volparossa-image-source.json'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest))
            with patch.dict(M['verify_vendor'].__globals__, SOURCES=sources):
                M['verify_vendor'](pins)
                manifest['local_modifications'] = True
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    M['verify_vendor'](pins)
                manifest['local_modifications'] = False
                path.write_text(json.dumps(manifest))
                (sources['cloud'] / 'vendor/volparossa-image/core-storage.mjs').write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    M['verify_vendor'](pins)


if __name__ == '__main__':
    unittest.main()
