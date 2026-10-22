#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert local Git fixtures only: no builds, network, SDKs or publication."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/weather-demo-0-sources.py'
spec = importlib.util.spec_from_file_location('demo_sources', SCRIPT)
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


class Sources(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='demo-sources-inert-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.core, self.core_sha = self.repository('core')
        self.weather, self.weather_sha = self.repository('weather')

    def git(self, repository, *args):
        return subprocess.check_output(['git', '-C', str(repository), *args],
            env=S.git_environment(), stderr=subprocess.PIPE).decode().strip()

    def repository(self, name):
        repository = self.root / name
        repository.mkdir()
        self.git(repository, 'init', '--quiet')
        (repository / 'LICENSE').write_text('original fixture license\n')
        (repository / '.gitignore').write_text('private-key\n.pub-cache/\n')
        (repository / 'source.txt').write_text('committed fixture source\n')
        (repository / 'third_party').mkdir()
        (repository / 'third_party/pins.json').write_text('{"commit":"' + 'a' * 40 + '"}\n')
        self.git(repository, 'add', '.')
        self.git(repository, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '--quiet', '-m', 'inert fixture')
        return repository, self.git(repository, 'rev-parse', 'HEAD')

    def run_cli(self, *extra):
        argv = ['--core-revision', self.core_sha, '--weather-repository', str(self.weather),
                '--weather-revision', self.weather_sha, '--output', str(self.core / 'bundle'), *extra]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(S, '__file__', str(self.core / 'scripts/tool.py')):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = S.main(argv)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_preview_is_read_only_and_execute_manifest(self):
        result, output, error = self.run_cli()
        self.assertEqual((result, error), (0, ''))
        self.assertEqual(json.loads(output)['mode'], 'preview')
        self.assertFalse((self.core / 'bundle').exists())
        result, output, error = self.run_cli('--execute')
        self.assertEqual((result, error), (0, ''))
        manifest = json.loads(output)
        self.assertEqual(manifest['sources']['core']['commit'], self.core_sha)
        self.assertEqual(manifest['sources']['weather']['commit'], self.weather_sha)
        self.assertNotIn(str(self.root), (self.core / 'bundle/source-manifest.json').read_text())

    def test_deterministic_exact_committed_sources_and_notices(self):
        for repository in (self.core, self.weather):
            (repository / 'private-key').write_text('ignored secret')
            (repository / 'untracked-secret').write_text('untracked secret')
            (repository / '.pub-cache').mkdir()
            (repository / '.pub-cache/sdk').write_text('ignored SDK')
            (repository / 'source.txt').write_text('uncommitted modification')
        before = self.git(self.core, 'status', '--porcelain')
        outputs = [self.core / 'one', self.core / 'two']
        for output in outputs:
            S.bundle(self.core, self.core_sha, self.weather, self.weather_sha, output)
        for name in ['core-source.tar.gz', 'weather-source.tar.gz', 'source-manifest.json']:
            self.assertEqual((outputs[0] / name).read_bytes(), (outputs[1] / name).read_bytes())
        for component in ['core', 'weather']:
            path = outputs[0] / (component + '-source.tar.gz')
            self.assertEqual(path.read_bytes()[4:8], b'\0' * 4)
            with tarfile.open(path, 'r:gz') as archive:
                prefix = 'weather-demo-0.1.0-' + component + '/'
                names = archive.getnames()
                self.assertFalse(any('secret' in n or '.git/' in n or '.pub-cache' in n for n in names))
                self.assertEqual(archive.extractfile(prefix + 'LICENSE').read(), b'original fixture license\n')
                self.assertEqual(archive.extractfile(prefix + 'source.txt').read(), b'committed fixture source\n')
                self.assertIn(prefix + 'third_party/pins.json', names)
        after = self.git(self.core, 'status', '--porcelain').splitlines()
        self.assertEqual(before.splitlines(), [line for line in after if line not in {'?? one/', '?? two/'}])

    def test_revision_rejects_short_uppercase_missing_tree_and_tag(self):
        tree = self.git(self.core, 'rev-parse', 'HEAD^{tree}')
        self.git(self.core, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 'tag', '-a', 'fixture', '-m', 'tag')
        tag = self.git(self.core, 'rev-parse', 'fixture')
        for revision in ['HEAD', self.core_sha[:12], 'A' * 40, 'f' * 40, tree, tag, '--all']:
            with self.subTest(revision=revision), self.assertRaises(S.SourceError):
                S.checked_revision(self.core, revision)

    def test_unsafe_paths_and_no_overwrite(self):
        (self.core / 'link').symlink_to(self.weather, target_is_directory=True)
        for path in [Path('relative'), self.root / 'outside', self.core,
                     self.core / '.git/output', self.core / 'link/output',
                     self.core / 'missing/output', self.core / 'x/../output']:
            with self.subTest(path=path), self.assertRaises(S.SourceError):
                S.checked_output(self.core, path)
        output = self.core / 'bundle'
        output.mkdir()
        (output / 'keep').write_text('preserve')
        result, _, error = self.run_cli('--execute')
        self.assertEqual(result, 1)
        self.assertIn('overwriting is forbidden', error)
        self.assertEqual((output / 'keep').read_text(), 'preserve')
        with self.assertRaises(FileExistsError):
            S.bundle(self.core, self.core_sha, self.weather, self.weather_sha, output)
        self.assertEqual((output / 'keep').read_text(), 'preserve')

    def test_bounded_failure_removes_partial_output(self):
        output = self.core / 'failed'
        with patch.object(S, 'MAX_ARCHIVE_BYTES', 100), self.assertRaisesRegex(S.SourceError, 'size limit'):
            S.bundle(self.core, self.core_sha, self.weather, self.weather_sha, output)
        self.assertFalse(output.exists())
        self.assertEqual(self.git(self.core, 'status', '--porcelain'), '')

    def test_second_archive_failure_cleans_first_archive(self):
        output = self.core / 'failed'
        original = S.archive_tar

        def fail_weather(repository, *args):
            if repository == self.weather:
                raise S.SourceError('inert second component failure')
            return original(repository, *args)

        with patch.object(S, 'archive_tar', side_effect=fail_weather):
            with self.assertRaisesRegex(S.SourceError, 'second component'):
                S.bundle(self.core, self.core_sha, self.weather, self.weather_sha, output)
        self.assertFalse(output.exists())

    def test_timeout_cleans_output(self):
        with patch.object(S, 'CHILD_TIMEOUT', 0), self.assertRaisesRegex(S.SourceError, 'timeout'):
            S.bundle(self.core, self.core_sha, self.weather, self.weather_sha, self.core / 'failed')
        self.assertFalse((self.core / 'failed').exists())

    def test_git_environment_ignores_object_and_worktree_overrides(self):
        with patch.dict(os.environ, {'GIT_WORK_TREE': '/invalid', 'GIT_DIR': '/invalid',
                                     'GIT_CONFIG_COUNT': '1'}):
            self.assertEqual(S.checked_revision(self.core, self.core_sha), self.core_sha)

    def test_missing_license_and_committed_cache_fail_cleanly(self):
        for filename in ['LICENSE', '.pub-cache/sdk']:
            if filename == 'LICENSE':
                (self.weather / filename).unlink()
            else:
                (self.weather / 'LICENSE').write_text('original fixture license\n')
                (self.weather / '.pub-cache').mkdir()
                (self.weather / filename).write_text('SDK cache')
                self.git(self.weather, 'add', '-f', filename)
            self.git(self.weather, 'add', '-u')
            self.git(self.weather, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                     'commit', '--quiet', '-m', 'negative fixture')
            revision = self.git(self.weather, 'rev-parse', 'HEAD')
            with self.assertRaises(S.SourceError):
                S.bundle(self.core, self.core_sha, self.weather, revision, self.core / 'failed')
            self.assertFalse((self.core / 'failed').exists())


if __name__ == '__main__':
    unittest.main()
