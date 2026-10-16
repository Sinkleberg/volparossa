#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert lock/parser checks; no APT, download, package install or executable load."""
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
M = types.ModuleType('model_debian')
exec(compile((HERE / 'resolve-resident-model-debian.py').read_bytes(),
             str(HERE / 'resolve-resident-model-debian.py'), 'exec'), M.__dict__)


class IsolatedConfiguration(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for suffix in ('etc/parts', 'etc/sources.list.d', 'state/lists/partial',
                       'cache/archives/partial', 'log'):
            (self.root / suffix).mkdir(parents=True)
        self.config = self.root / 'apt.conf'
        self.original = M.APT_CONFIG_TEMPLATE.format(root=self.root)
        self.config.write_text(self.original)
        (self.root / 'status').write_bytes(b'')
        (self.root / 'etc/sources.list').write_text(''.join(
            f'deb [arch=amd64 signed-by={M.KEYRING}] {base} {suite} main\n'
            for suite, base, _ in M.SOURCES))

    def tearDown(self):
        self.temporary.cleanup()

    def rejected_before_apt(self):
        with mock.patch.object(M, 'command') as command:
            with self.assertRaises((ValueError, OSError)):
                M.resolve(self.root)
            command.assert_not_called()

    def test_exact_schema_passes_without_executing_apt(self):
        self.assertEqual(M.isolated_configuration(self.root), self.config)
        class ReachedApt(Exception):
            pass
        with mock.patch.object(M, 'command', side_effect=ReachedApt) as command:
            with self.assertRaises(ReachedApt):
                M.resolve(self.root)
        self.assertEqual(command.call_args.args[0], ['/usr/bin/apt-config', 'dump'])
        self.assertEqual(command.call_args.args[1]['APT_CONFIG'], str(self.config))

    def test_absolute_subpath_overrides_reject_before_any_apt(self):
        for key in ('Dir::State::lists', 'Dir::Cache::archives', 'Dir::Etc::sourcelist',
                    'Dir::Etc::sourceparts', 'Dir::Etc::preferencesparts', 'Dir::Log::Terminal'):
            with self.subTest(key=key):
                self.config.write_text(self.original + f'{key} "/outside";\n')
                self.rejected_before_apt()

    def test_all_hooks_and_custom_methods_reject_before_any_apt(self):
        for extra in ('DPkg::Pre-Invoke { "false"; };',
                      'DPkg::Pre-Install-Pkgs { "false"; };',
                      'APT::Update::Post-Invoke { "false"; };',
                      'Dir::Bin::Methods "/outside";',
                      'Acquire::https::Proxy-Auto-Detect "/outside";'):
            with self.subTest(extra=extra):
                self.config.write_text(self.original + extra + '\n')
                self.rejected_before_apt()

    def test_includes_clear_and_alternate_config_files_reject_before_any_apt(self):
        for extra in ('#include "/outside";', '#clear Dir;',
                      'Dir::Etc::main "/outside";', 'Dir::Etc::parts "/outside";',
                      'Dir::Etc::trusted "/outside";'):
            with self.subTest(extra=extra):
                self.config.write_text(self.original + extra + '\n')
                self.rejected_before_apt()

    def test_loaded_fragment_and_source_directories_must_be_empty(self):
        for suffix in ('etc/parts/override.conf', 'etc/sources.list.d/extra.sources'):
            path = self.root / suffix
            path.write_text('untrusted')
            self.rejected_before_apt()
            path.unlink()

    def test_source_list_is_exact_and_empty_status_is_required(self):
        path = self.root / 'etc/sources.list'
        original = path.read_bytes()
        path.write_bytes(original.replace(b'signed-by=', b'trusted=yes signed-by='))
        self.rejected_before_apt()
        path.write_bytes(original)
        (self.root / 'status').write_bytes(b'Package: inherited\n')
        self.rejected_before_apt()

    def test_symlinked_files_or_state_directories_reject_before_any_apt(self):
        for suffix in ('apt.conf', 'status', 'etc/sources.list', 'state/lists', 'cache/archives'):
            path = self.root / suffix
            original = path.with_name(path.name + '.original')
            path.rename(original)
            path.symlink_to(original)
            self.rejected_before_apt()
            path.unlink()
            original.rename(path)

    def test_nonprivate_root_oversized_and_duplicate_config_reject_before_any_apt(self):
        self.root.chmod(0o755)
        self.rejected_before_apt()
        self.root.chmod(0o700)
        for text in ('x' * 16385, self.original + 'APT::Architecture "amd64";\n'):
            self.config.write_text(text)
            self.rejected_before_apt()


class DebianLock(unittest.TestCase):
    def test_continuations_preserve_dependency_and_hash_values(self):
        value = M.fields('Package: example\nDepends: a | b,\n c (>= 1)\nSHA256: abc')
        self.assertEqual(value['Depends'], 'a | b,\nc (>= 1)')
        self.assertEqual(value['SHA256'], 'abc')

    def test_duplicate_and_orphan_fields_fail(self):
        for text in ('A: one\nA: two', ' continuation', 'invalid'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                M.fields(text)

    def test_cleartext_release_parser_is_not_signature_verification(self):
        raw = (b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\n'
               b'Codename: trixie\n-----BEGIN PGP SIGNATURE-----\nnot a signature\n')
        self.assertEqual(M.release_payload(raw)['Codename'], 'trixie')
        with self.assertRaises(ValueError):
            M.release_payload(b'Origin: Debian')

    def test_index_must_match_signed_uncompressed_size_and_sha256(self):
        raw = b'Package: example\n\n'
        digest = hashlib.sha256(raw).hexdigest()
        release = {'SHA256': f'{digest} {len(raw)} main/binary-amd64/Packages'}
        self.assertEqual(M.checked_index(release, raw)['sha256'], digest)
        for altered in (raw + b'x', raw.replace(b'example', b'changed')):
            with self.assertRaises(ValueError):
                M.checked_index(release, altered)
        for hash_field in (release['SHA256'] + '\n' + release['SHA256'],
                           'invalid 1 main/binary-amd64/Packages'):
            with self.assertRaises(ValueError):
                M.checked_index({'SHA256': hash_field}, raw)

    def test_selected_uri_decodes_paths_and_does_not_use_printed_md5_as_authenticity(self):
        value = M.selected_uris("Reading package lists...\n"
            "'https://deb.debian.org/debian/pool/main/a/a/a_1%2bb1_amd64.deb' a.deb 12 MD5Sum:ignored\n")
        self.assertEqual(value, {'https://deb.debian.org/debian/pool/main/a/a/a_1+b1_amd64.deb': 12})

    def test_empty_duplicate_or_malformed_selection_fails(self):
        line = "'https://deb.debian.org/debian/pool/a.deb' a.deb 12\n"
        for text in ('', line + line, line.replace(' 12', ' invalid')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                M.selected_uris(text)

    def test_package_fields_require_sha256_and_confined_pool_path(self):
        base = {'Package': 'libexample1', 'Version': '1:2.0-1', 'Architecture': 'amd64',
                'Filename': 'pool/main/e/example/libexample1_2.0-1_amd64.deb',
                'Size': '24', 'SHA256': 'a' * 64, 'Depends': 'libc6 (>= 2.38)'}
        value = M.package_record(base, 'trixie', 'https://deb.debian.org/debian')
        self.assertEqual(value['version'], '1:2.0-1')
        self.assertEqual(value['depends'], base['Depends'])
        for field, bad in (('Filename', '../escape'), ('Filename', '/pool/absolute'),
                           ('Filename', 'pool/../escape'), ('Size', '0'),
                           ('Architecture', 'arm64'), ('SHA256', 'b' * 32), ('Package', 'bad name')):
            changed = dict(base, **{field: bad})
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                M.package_record(changed, 'trixie', 'https://deb.debian.org/debian')

    def test_committed_lock_has_complete_bound_profiles_and_no_execution_claim(self):
        lock = json.loads((HERE / 'protected-resident-model-debian-lock-v1.json').read_bytes())
        self.assertEqual((lock['version'], lock['kind'], lock['architecture']),
                         (1, 'protected-resident-debian-package-lock', 'amd64'))
        for key in ('packages_downloaded', 'host_installation', 'guest_boot', 'model_execution'):
            self.assertIs(lock[key], False)
        self.assertIs(lock['empty_status'], True)
        self.assertIs(lock['install_recommends'], False)
        self.assertEqual(lock['profiles']['runtime']['roots'], list(M.RUNTIME))
        self.assertEqual(lock['profiles']['build']['roots'], list(M.BUILD))
        self.assertEqual(len(lock['profiles']['runtime']['packages']), 65)
        self.assertEqual(len(lock['profiles']['build']['packages']), 198)
        self.assertEqual(set(lock['profiles']['build']['packages']), set(lock['packages']))
        self.assertLessEqual(set(lock['profiles']['runtime']['packages']), set(lock['packages']))
        for profile in lock['profiles'].values():
            self.assertEqual(profile['packages'], sorted(set(profile['packages'])))
            self.assertLessEqual(set(profile['roots']), set(profile['packages']))
        for name, package in lock['packages'].items():
            source = lock['sources'][package['index']]
            self.assertTrue(source['valid_signers'])
            self.assertEqual(package['url'], source['base_url'] + '/' + package['filename'])
            self.assertRegex(package['sha256'], r'^[0-9a-f]{64}$')
            self.assertIn(package['architecture'], ('all', 'amd64'))
            self.assertGreater(package['bytes'], 0)
            self.assertNotIn('..', Path(package['filename']).parts)
        # Preserve accepted early-boot packages; the new lock adds the full
        # model/build closures, not implicit replacement of the old boot inputs.
        old = json.loads((HERE / 'protected-resident-image-pins-v1.json').read_bytes())
        for name, expected in old['packages'].items():
            actual = lock['packages'][name]
            for field in ('version', 'url', 'bytes', 'sha256'):
                self.assertEqual(actual[field], expected[field])


if __name__ == '__main__':
    unittest.main()
