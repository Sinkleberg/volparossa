#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert contracts: tiny Git/text fixtures and Python children, never Cargo."""
from contextlib import contextmanager
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('admission_probe', Path(__file__).with_name('protected-compute-admission.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
WORKFLOW = P.ROOT / '.github/workflows/protected-compute-admission.yml'


def package(name, version='1.0.0', dependencies=(), source=P.REGISTRY):
    value = dict(name=name, version=version, dependencies=list(dependencies))
    if source:
        value['source'] = source
        if source == P.REGISTRY:
            value['checksum'] = 'a' * 64
    return value


def fixture_packages():
    old = [package('volparossa-content', '0.1.0', ['base'], ''), package('base')]
    new = copy.deepcopy(old)
    new[0]['dependencies'] += ['sev', 'x509-cert']
    new += [package('sev', '8.0.0', ['x509-cert', 'crypto'], P.SEV_SOURCE),
        package('x509-cert', '0.2.5', ['crypto']), package('crypto')]
    return old, new


def lock(packages):
    value = 'version = 4\n'
    for item in packages:
        value += '\n[[package]]\n' + ''.join(key + ' = ' + json.dumps(val) + '\n' for key, val in item.items())
    return value.encode()


def tool_outcome(code=0, error=None):
    return dict(exit_status=code, capture_error=error, leader_joined=True,
        cleanup_scope='owned-process-group-not-a-setsid-proof-sandbox', elapsed_ms=1)


def test_log():
    return ('running 14 tests\n' + ''.join('test ' + name + ' ... ok\n' for name in P.TESTS)
        + '\ntest result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.1s\n').encode()


def metadata_fixture(packages):
    result, nodes = [], []
    for i, item in enumerate(packages):
        identity = 'fixture-id-' + str(i)
        result.append(dict(id=identity, name=item['name'], version=item['version'],
            source=item.get('source'), license='Apache-2.0 OR MIT', rust_version='1.85.0',
            manifest_path='/private/not-exported/Cargo.toml'))
        nodes.append(dict(id=identity, features=['snp', 'crypto_nossl', 'p384', 'rsa', 'sha2', 'x509-cert']
            if item['name'] == 'sev' else ['std']))
    return dict(version=1, packages=result, resolve=dict(nodes=nodes))


def git(root, *args):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
        '-c', 'user.name=Inert fixture', '-c', 'user.email=fixture@example.invalid', '-C', str(root), *args],
        timeout=10).decode().strip()


@contextmanager
def source_fixture():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / 'source'
        root.mkdir()
        (root / 'crates/volparossa-content').mkdir(parents=True)
        for name in ('Cargo.toml', 'crates/volparossa-content/Cargo.toml'):
            (root / name).write_bytes((P.ROOT / name).read_bytes())
            (root / name).chmod(0o600)
        old, new = fixture_packages()
        (root / 'Cargo.lock').write_bytes(lock(old))
        (root / 'Cargo.lock').chmod(0o600)
        (root / 'other.rs').write_text('public synthetic source\n')
        (root / '.gitignore').write_text('ignored-output\n')
        git(root, 'init', '-q')
        git(root, 'add', '--all')
        git(root, 'commit', '-qm', 'inert public source fixture')
        commit = git(root, 'rev-parse', 'HEAD')
        with patch.object(P, 'ROOT', root), patch.dict(os.environ, {'GITHUB_SHA': commit}):
            yield root, Path(tmp) / 'work', old, new


def public_trial_fixture(root, work, new):
    """Execute orchestration with synthetic public Cargo outputs, never Cargo."""
    def fake_run(argv, output, _deadline, *, stdout=None):
        if argv[2] == '--version':
            P.write(output, (argv[0] + ' 1.85.0 (inert)\nrelease: 1.85.0\n').encode())
        elif argv[2] == 'fetch':
            (root / 'Cargo.lock').write_bytes(lock(new))
            P.write(output, b'Locking synthetic inert dependencies\n')
        elif argv[2] == 'metadata':
            P.write(stdout, json.dumps(metadata_fixture(new)).encode())
            P.write(output, b'')
        elif argv[2] == 'test':
            P.write(output, test_log())
        elif argv[2] == 'clippy':
            P.write(output, b'Finished synthetic inert Clippy\n')
        else:
            raise AssertionError(argv)
        return tool_outcome()
    with patch.object(P, 'run', side_effect=fake_run):
        P.prepare(work); P.resolve(work); P.metadata(work)
        P.execute(work, 'test'); P.execute(work, 'clippy')


class ProbeContracts(unittest.TestCase):
    def test_minimal_resolver_delta_preserves_original_packages_and_edges(self):
        old, new = fixture_packages()
        value = P.lock_delta(lock(old), lock(new))
        self.assertEqual(value['original_packages'], 2)
        self.assertEqual(len(value['added_packages']), 3)
        self.assertTrue(value['original_dependency_edges_retained'])
        self.assertTrue(value['unlisted_existing_dependency_edges_unchanged'])
        self.assertEqual(value['new_direct_dependencies'], ['sev', 'x509-cert'])

    def test_exact_der_feature_edges_follow_published_x509_and_sev_manifests_only(self):
        old, new = fixture_packages()
        der = package('der', '0.7.10', ['base'])
        der['checksum'] = P.FEATURE_PROVENANCE['der_crate_sha256']
        old.append(copy.deepcopy(der)); new.append(copy.deepcopy(der))
        new[3]['dependencies'].append('der')
        new[-1]['dependencies'] += ['der_derive', 'flagset', 'pem-rfc7468']
        new += [package('der_derive', '0.7.3'), package('flagset', '0.4.7'), package('pem-rfc7468', '0.7.0')]
        result = P.lock_delta(lock(old), lock(new))
        self.assertEqual([x['name'] for x in result['added_feature_edges']], ['der_derive', 'flagset', 'pem-rfc7468'])
        self.assertEqual(result['feature_edge_provenance'], P.FEATURE_PROVENANCE)
        for kind in ('unlisted', 'missing', 'removed_old', 'other_parent', 'too_old', 'new_minor', 'prerelease', 'source', 'checksum'):
            changed = copy.deepcopy(new)
            if kind == 'unlisted': changed[5]['dependencies'].append('crypto')
            elif kind == 'missing': changed[5]['dependencies'].remove('flagset')
            elif kind == 'removed_old': changed[5]['dependencies'].remove('base')
            elif kind == 'other_parent': changed[1]['dependencies'].append('flagset')
            elif kind == 'too_old': changed[6]['version'] = '0.7.1'
            elif kind == 'new_minor': changed[6]['version'] = '0.8.0'
            elif kind == 'prerelease': changed[6]['version'] = '0.7.3-rc.1'
            elif kind == 'source': changed[6]['source'] = P.SEV_SOURCE
            else: changed[5]['checksum'] = 'f' * 64
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                P.lock_delta(lock(old), lock(changed))

    def test_semantic_disambiguation_is_not_an_existing_dependency_update(self):
        old, new = fixture_packages()
        new.append(package('base', '2.0.0'))
        new[0]['dependencies'][0] = 'base 1.0.0'
        new[-2]['dependencies'].append('base 2.0.0')
        self.assertEqual(len(P.lock_delta(lock(old), lock(new))['added_packages']), 4)

    def test_rsa_feature_edges_only_use_exact_existing_digest_and_numeric_targets(self):
        old, new = fixture_packages()
        for parent, (target, checksum) in P.RETAINED_FEATURE_EDGES.items():
            pkg = package(parent[0], parent[1], ['base']); pkg['checksum'] = checksum
            old += [pkg, package(target[0], target[1])]
            new += [copy.deepcopy(pkg), package(target[0], target[1])]
            new[-2]['dependencies'].append(target[0])
        result = P.lock_delta(lock(old), lock(new))
        self.assertEqual(len(result['retained_feature_edges']), 2)
        for kind in ('missing', 'extra', 'wrong_parent', 'changed_target', 'changed_parent'):
            changed = copy.deepcopy(new)
            if kind == 'missing': changed[5]['dependencies'].remove('const-oid')
            elif kind == 'extra': changed[5]['dependencies'].append('crypto')
            elif kind == 'wrong_parent': changed[1]['dependencies'].append('const-oid')
            elif kind == 'changed_target': changed[6]['version'] = '0.9.7'
            else: changed[5]['checksum'] = 'f' * 64
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                P.lock_delta(lock(old), lock(changed))

    def test_existing_versions_checksums_dependencies_and_removed_packages_fail(self):
        old, good = fixture_packages()
        mutations = []
        for kind in ('version', 'checksum', 'extra_edge', 'remove_edge', 'removed', 'metadata'):
            new = copy.deepcopy(good)
            if kind == 'version': new[1]['version'] = '1.0.1'
            elif kind == 'checksum': new[1]['checksum'] = 'b' * 64
            elif kind == 'extra_edge': new[1]['dependencies'] = ['crypto']
            elif kind == 'remove_edge': new[0]['dependencies'].remove('base')
            elif kind == 'removed': new.pop(1)
            else: new[1]['replacement'] = 'unchecked'
            mutations.append(new)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                P.lock_delta(lock(old), lock(value))

    def test_unrelated_unchecked_or_wrong_new_dependencies_fail(self):
        old, good = fixture_packages()
        for kind in ('extra', 'git', 'revision', 'checksum', 'path', 'x509', 'extra_direct'):
            new = copy.deepcopy(good)
            if kind == 'extra': new.append(package('unrelated'))
            elif kind == 'git': new[-1]['source'] = 'git+https://untrusted.invalid/example#' + 'f' * 40
            elif kind == 'revision': new[2]['source'] = P.SEV_SOURCE.replace(P.REV, 'f' * 40)
            elif kind == 'checksum': del new[-1]['checksum']
            elif kind == 'path': del new[-1]['source']; del new[-1]['checksum']
            elif kind == 'x509': new[3]['version'] = '0.2.6'
            else: new[0]['dependencies'].append('crypto')
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                P.lock_delta(lock(old), lock(new))

    def test_malformed_ambiguous_duplicate_and_unbounded_lock_is_rejected(self):
        old, good = fixture_packages()
        bad = []
        duplicate = copy.deepcopy(good); duplicate.append(copy.deepcopy(good[-1])); bad.append(duplicate)
        dangling = copy.deepcopy(good); dangling[-1]['dependencies'] = ['missing']; bad.append(dangling)
        repeated = copy.deepcopy(good); repeated[-1]['dependencies'] = ['base', 'base']; bad.append(repeated)
        ambiguous = copy.deepcopy(good); ambiguous.append(package('base', '2.0.0')); bad.append(ambiguous)
        for value in bad:
            with self.assertRaises(ValueError): P.lock_delta(lock(old), lock(value))
        for raw in (b'bad', b'version=3\n', b'x' * (P.MAX_LOCK + 1)):
            with self.assertRaises(ValueError): P.lock_graph(raw)

    def test_metadata_checks_actual_features_and_removes_paths(self):
        _, new = fixture_packages()
        original = metadata_fixture(new)
        projected = P.metadata_projection(json.dumps(original).encode(), lock(new))
        self.assertNotIn('/private/', json.dumps(projected))
        self.assertFalse(projected['local_paths_exported'])
        for features in (['snp'], ['snp', 'crypto_nossl', 'openssl'],
                ['snp', 'crypto_nossl', 'p384', 'rsa', 'sha2', 'x509-cert', 'sev']):
            bad = copy.deepcopy(original)
            bad['resolve']['nodes'][2]['features'] = features
            with self.assertRaisesRegex(ValueError, 'actual_sev_features'):
                P.metadata_projection(json.dumps(bad).encode(), lock(new))

    def test_exact_test_selection_and_skips_cannot_be_relabelled(self):
        raw = test_log()
        self.assertEqual(P.verify_tests(raw)['passed'], 14)
        first = ('test ' + P.TESTS[0] + ' ... ok\n').encode()
        for bad in (raw.replace(first, b''), raw + first, raw.replace(first, first.replace(b'ok', b'ignored')),
                raw.replace(first, first.replace(b'ok', b'FAILED')), raw.replace(b'14 passed', b'13 passed'),
                raw.replace(b'0 ignored', b'1 ignored'), raw.replace(b'running 14', b'running 0'), b'build passed\n'):
            with self.assertRaises(ValueError): P.verify_tests(bad)

    def test_source_allows_only_unstaged_effective_lock_with_original_head_retained(self):
        with source_fixture() as (root, _, old, new):
            value, original = P.source()
            self.assertEqual(original, lock(old))
            (root / 'Cargo.lock').write_bytes(lock(new))
            P.source(effective=True)
            with self.assertRaisesRegex(ValueError, 'source_changed'): P.source()
            git(root, 'add', '--', 'Cargo.lock')
            with self.assertRaisesRegex(ValueError, 'source_changed'): P.source(effective=True)

    def test_source_rejects_extra_changes_hidden_changes_modes_and_wrong_head(self):
        for kind in ('source', 'untracked', 'ignored', 'assume', 'mode', 'head'):
            with source_fixture() as (root, _, _, _), self.subTest(kind=kind):
                if kind == 'head':
                    with patch.dict(os.environ, {'GITHUB_SHA': 'f' * 40}), self.assertRaises(ValueError): P.source()
                    continue
                if kind == 'mode': (root / 'other.rs').chmod(0o700)
                elif kind == 'assume': git(root, 'update-index', '--assume-unchanged', 'other.rs')
                else: (root / ('ignored-output' if kind == 'ignored' else 'extra' if kind == 'untracked' else 'other.rs')).write_text('changed')
                with self.assertRaises(ValueError): P.source(effective=True)

    def test_failed_fetch_retains_original_effective_diff_and_failure_receipt(self):
        with source_fixture() as (root, work, old, new):
            (work / 'evidence').mkdir(parents=True)
            P.write(work / 'evidence/original-Cargo.lock', lock(old))
            def fake_run(argv, output, deadline):
                self.assertEqual(argv, ['cargo', '+1.85.0', 'fetch', '--manifest-path', str(root / 'Cargo.toml')])
                self.assertEqual(deadline, 300)
                (root / 'Cargo.lock').write_bytes(lock(new))
                P.write(output, b'public resolver failed\n')
                return tool_outcome(101)
            with patch.object(P, 'run', side_effect=fake_run), self.assertRaisesRegex(ValueError, 'command_failed'):
                P.resolve(work)
            self.assertEqual(P.read(work / 'evidence/effective-Cargo.lock', P.MAX_LOCK), lock(new))
            receipt = json.loads(P.read(work / 'evidence/resolution.json', P.MAX_LOCK))
            self.assertFalse(receipt['passed']); self.assertFalse(receipt['tests_executed'])
            self.assertEqual(receipt['command']['exit_status'], 101)
            self.assertTrue((work / 'evidence/Cargo.lock.diff').is_file())

    def test_rejected_resolver_upgrade_retains_evidence_and_does_not_run_tests(self):
        with source_fixture() as (root, work, old, new):
            (work / 'evidence').mkdir(parents=True)
            P.write(work / 'evidence/original-Cargo.lock', lock(old))
            new[1]['checksum'] = 'b' * 64
            def fake_run(_argv, output, _deadline):
                (root / 'Cargo.lock').write_bytes(lock(new)); P.write(output, b'Locking candidate\n')
                return tool_outcome()
            with patch.object(P, 'run', side_effect=fake_run) as runner, self.assertRaisesRegex(ValueError, 'metadata_changed'):
                P.resolve(work)
            self.assertEqual(runner.call_count, 1)
            self.assertFalse(json.loads(P.read(work / 'evidence/resolution.json', P.MAX_LOCK))['passed'])

    def test_prepare_is_new_only_and_does_not_relabel_cryptographic_success(self):
        with source_fixture() as (_, work, old, _):
            def fake_run(argv, output, _deadline):
                P.write(output, (argv[0] + ' 1.85.0 (inert)\nrelease: 1.85.0\n').encode())
                return tool_outcome()
            with patch.object(P, 'run', side_effect=fake_run): P.prepare(work)
            record = json.loads(P.read(work / 'evidence/source.json', P.MAX_LOCK))
            self.assertFalse(record['tests_executed']); self.assertNotIn('passed', record)
            self.assertEqual(P.read(work / 'evidence/original-Cargo.lock', P.MAX_LOCK), lock(old))
            with self.assertRaises(FileExistsError): P.prepare(work)

    def test_fixed_test_and_clippy_commands_remain_locked_offline_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); (work / 'evidence').mkdir()
            P.record(work / 'evidence/resolved-metadata.json', {})
            def fake_run(argv, output, deadline):
                self.assertEqual(argv[:3], ['cargo', '+1.85.0', 'test' if output.name == 'tests.log' else 'clippy'])
                self.assertIn('--locked', argv); self.assertIn('--offline', argv)
                self.assertIn('volparossa-content', argv)
                if output.name == 'tests.log':
                    self.assertEqual(argv[-3:], [P.PREFIX, '--', '--test-threads=1'])
                    self.assertEqual(deadline, 1200); P.write(output, test_log())
                else:
                    self.assertEqual(argv[-3:], ['--', '-D', 'warnings'])
                    self.assertEqual(deadline, 600); P.write(output, b'Finished\n')
                return tool_outcome()
            with patch.object(P, 'check_effective', return_value={}), patch.object(P, 'check_metadata'), \
                    patch.object(P, 'run', side_effect=fake_run):
                P.execute(work, 'test'); P.execute(work, 'clippy')

    def test_failed_test_log_cannot_pass_even_with_all_successful_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); (work / 'evidence').mkdir(); P.record(work / 'evidence/resolved-metadata.json', {})
            def fake_run(_argv, output, _deadline): P.write(output, test_log()); return tool_outcome(101)
            with patch.object(P, 'check_effective', return_value={}), patch.object(P, 'check_metadata'), \
                    patch.object(P, 'run', side_effect=fake_run), self.assertRaises(ValueError):
                P.execute(work, 'test')
            self.assertFalse(json.loads(P.read(work / 'evidence/tests.json', 32768))['passed'])

    def test_receipt_requires_every_actual_stage_not_only_preparation(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); (work / 'evidence').mkdir()
            P.record(work / 'evidence/source.json', {'source': {'commit': 'a' * 40}})
            P.record(work / 'evidence/resolution.json', {'passed': True})
            with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work)
            value = json.loads(P.read(work / 'evidence/report.json', P.MAX_LOCK))
            self.assertFalse(value['passed']); self.assertIsNone(value['stages']['tests.json'])
            self.assertEqual(value['scope'], P.SCOPE)

    def test_complete_synthetic_orchestration_reconstructs_exact_receipt(self):
        with source_fixture() as (root, work, _, new):
            public_trial_fixture(root, work, new)
            P.receipt(work)
            value = json.loads(P.read(work / 'evidence/report.json', P.MAX_LOCK))
            self.assertTrue(value['passed'])
            self.assertEqual(set(value['files']), set(P.EXPORTS) - {'report.json'})
            self.assertEqual(value['source']['commit'], git(root, 'rev-parse', 'HEAD'))
            self.assertEqual(value['stages'], {key: True for key in (
                'resolution.json', 'resolved-metadata.json', 'tests.json', 'clippy.json')})
            self.assertFalse(value['scope']['protected_execution'])

    def test_pass_flags_cannot_override_changed_logs_source_lock_metadata_or_exit(self):
        for kind in ('log', 'source', 'lock', 'metadata', 'exit', 'tool', 'diff', 'ignored', 'scope'):
            with source_fixture() as (root, work, _, new), self.subTest(kind=kind):
                public_trial_fixture(root, work, new)
                evidence = work / 'evidence'
                if kind == 'log': (evidence / 'tests.log').write_bytes(test_log() + b'changed\n')
                elif kind == 'source': (root / 'other.rs').write_text('changed')
                elif kind == 'lock': (root / 'Cargo.lock').write_bytes(lock(new) + b'\n')
                elif kind == 'metadata':
                    raw = metadata_fixture(new); raw['resolve']['nodes'][2]['features'] += ['openssl']
                    (work / 'metadata.json').write_text(json.dumps(raw))
                elif kind == 'tool': (evidence / 'cargo.txt').write_text('cargo 1.86.0\nrelease: 1.86.0\n')
                elif kind == 'diff': (evidence / 'Cargo.lock.diff').write_text('not the observed delta')
                elif kind == 'ignored': (root / 'ignored-output').write_text('unexpected build output')
                else:
                    path = evidence / 'clippy.json'; record = json.loads(path.read_bytes())
                    if kind == 'exit': record['command']['exit_status'] = 101
                    else: record['scope']['protected_execution'] = True
                    path.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, 'incomplete'):
                    P.receipt(work)
                value = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
                self.assertFalse(value['passed'])

    def test_failed_metadata_keeps_exit_and_blocks_test_execution(self):
        with source_fixture() as (root, work, old, new):
            (work / 'evidence').mkdir(parents=True)
            P.write(work / 'evidence/original-Cargo.lock', lock(old))
            P.write(work / 'evidence/effective-Cargo.lock', lock(new))
            (root / 'Cargo.lock').write_bytes(lock(new))
            def fake_run(argv, output, deadline, *, stdout):
                self.assertEqual(argv, ['cargo', '+1.85.0', 'metadata', '--locked', '--offline',
                    '--format-version', '1', '--filter-platform', 'x86_64-unknown-linux-gnu'])
                self.assertEqual(deadline, 120)
                P.write(stdout, b''); P.write(output, b'public inert metadata error\n')
                return tool_outcome(101)
            with patch.object(P, 'run', side_effect=fake_run), self.assertRaisesRegex(ValueError, 'command_failed'):
                P.metadata(work)
            value = json.loads(P.read(work / 'evidence/resolved-metadata.json', P.MAX_LOCK))
            self.assertFalse(value['passed']); self.assertEqual(value['command']['exit_status'], 101)
            with patch.object(P, 'run') as native, self.assertRaisesRegex(ValueError, 'metadata_required'):
                P.execute(work, 'test')
            native.assert_not_called()

    def test_capture_runs_only_inert_python_and_preserves_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'output'
            result = P.run([sys.executable, '-c', 'print("public inert child");raise SystemExit(7)'], log, 5)
            self.assertEqual(result['exit_status'], 7); self.assertIsNone(result['capture_error'])
            self.assertTrue(result['leader_joined']); self.assertEqual(P.read(log, 1024), b'public inert child\n')

    def test_real_inert_timeout_and_output_bound_join_owned_leader(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            result = P.run([sys.executable, '-c', 'import time;time.sleep(20)'], base / 'timeout', 0.02)
            self.assertTrue(result['leader_joined']); self.assertEqual(result['capture_error'], 'command_io_or_deadline')
            with patch.object(P, 'MAX_LOG', 16):
                result = P.run([sys.executable, '-c', 'print("X"*128)'], base / 'overflow', 5)
            self.assertTrue(result['leader_joined']); self.assertEqual(result['capture_error'], 'command_output_bound')
            self.assertEqual((base / 'overflow').stat().st_size, 16)

    def test_injected_cancellation_unwinds_inert_child_and_remains_failure(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(P.selectors.DefaultSelector, 'select', side_effect=P.RunInterrupted):
            result = P.run([sys.executable, '-c', 'import time;time.sleep(20)'], Path(tmp) / 'cancel', 5)
            self.assertEqual(result['capture_error'], 'command_interrupted'); self.assertTrue(result['leader_joined'])
            with self.assertRaises(ValueError): P.command_ok(result)

    def test_selector_setup_failure_still_joins_real_owned_python_child(self):
        children = []
        real_popen = subprocess.Popen
        def started(*args, **kwargs):
            child = real_popen(*args, **kwargs); children.append(child); return child
        with tempfile.TemporaryDirectory() as tmp, patch.object(P.subprocess, 'Popen', side_effect=started), \
                patch.object(P.selectors, 'DefaultSelector', side_effect=OSError('inert descriptor exhaustion')):
            result = P.run([sys.executable, '-c', 'import time;time.sleep(20)'], Path(tmp) / 'setup', 5)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(result['leader_joined'])
        self.assertEqual(result['capture_error'], 'command_io_or_deadline')
        with self.assertRaises(ValueError): P.command_ok(result)

    def test_no_local_or_arbitrary_command_native_entrypoint(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(P, 'run') as native:
            for args in (['resolve'], ['test'], ['clippy'], ['arbitrary']):
                with self.assertRaises(ValueError): P.main(args)
            native.assert_not_called()

    def test_same_fd_inputs_reject_symlink_fifo_writable_hardlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); regular = base / 'input'; P.write(regular, b'1234')
            link = base / 'link'; link.symlink_to(regular)
            fifo = base / 'fifo'; os.mkfifo(fifo)
            for path, maximum in ((link, 4), (fifo, 4), (regular, 3)):
                with self.assertRaises((OSError, ValueError)): P.read(path, maximum)
            regular.chmod(0o666)
            with self.assertRaises(ValueError): P.read(regular, 4)
            regular.chmod(0o600); os.link(regular, base / 'hardlink')
            with self.assertRaises(ValueError): P.read(regular, 4)

    def test_workflow_has_exact_branch_source_and_export_closure(self):
        raw = WORKFLOW.read_text()
        self.assertIn('branches: [feature/protected-compute-admission]', raw)
        self.assertIn("if: github.ref == 'refs/heads/feature/protected-compute-admission'", raw)
        self.assertIn('cancel-in-progress: false', raw)
        self.assertIn('timeout-minutes: 45', raw)
        self.assertIn('persist-credentials: false', raw)
        self.assertIn('1.85.0 --profile minimal --component clippy --no-self-update', raw)
        observed = re.findall(r'\$\{\{ runner.temp \}\}/volparossa-protected-compute-admission/evidence/(\S+)', raw)
        self.assertEqual(tuple(observed), P.EXPORTS)
        self.assertNotIn('cargo update', raw); self.assertNotIn('generate-lockfile', raw)
        self.assertNotIn('GITHUB_ENV', raw); self.assertNotIn('pull_request:', raw)
        code = Path(P.__file__).read_text()
        self.assertNotIn("'update'", code); self.assertNotIn("'generate-lockfile'", code)
        source = (P.ROOT / 'crates/volparossa-content/src/provider/compute/attestation/tests.rs').read_text()
        names = re.findall(r'#\[test\]\s+fn (\w+)\(', source)
        self.assertEqual(set(P.TESTS), {P.PREFIX + name for name in names})
        self.assertEqual(len(names), 14)


if __name__ == '__main__':
    unittest.main()
