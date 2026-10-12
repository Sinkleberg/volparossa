#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert verifier-contract tests: no Rust, SDK, hardware or network execution."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('protected-compute-verifier.py')
SPEC = importlib.util.spec_from_file_location('fixture_verifier', SOURCE)
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
WORKFLOW = V.ROOT / '.github/workflows/protected-compute-verifier.yml'


def log():
    return ('running 4 tests\n' + ''.join('test ' + name + ' ... ok\n' for name in V.EXPECTED_TESTS)
        + '\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s\n').encode()


class FixtureContracts(unittest.TestCase):
    def test_original_pinset(self):
        selected = V.pins()
        self.assertEqual(set(selected['files']), V.EXPECTED_FILES)
        license_path = V.ROOT / 'third_party/licenses/virtee-sev-8.0.0-Apache-2.0.txt'
        raw = V.bounded(license_path, 32768)
        self.assertEqual({'bytes': len(raw), 'sha256': V.sha(raw)}, selected['files']['LICENSE'])

    def test_changed_pin_contract_is_rejected(self):
        original = V.pins()
        mutations = []
        for key, value in [('schema_version', True), ('default_features', True),
                ('features', ['sev']), ('test_filter', 'nonexistent'), ('expected_tests', []),
                ('scope', {'private_task_release': True}), ('unknown', 'ignored')]:
            mutated = copy.deepcopy(original)
            mutated[key] = value
            mutations.append(mutated)
        for key in ('commit', 'tree', 'url', 'repository'):
            mutated = copy.deepcopy(original)
            mutated['upstream'][key] = 'wrong'
            mutations.append(mutated)
        for operation in ('missing', 'extra', 'escape', 'malformed'):
            mutated = copy.deepcopy(original)
            if operation == 'missing':
                del mutated['files']['LICENSE']
            elif operation == 'extra':
                mutated['files']['extra'] = mutated['files']['LICENSE']
            elif operation == 'escape':
                mutated['files']['../LICENSE'] = mutated['files'].pop('LICENSE')
            else:
                mutated['files']['LICENSE']['bytes'] = True
            mutations.append(mutated)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'pins.json'
            with patch.object(V, 'PINS', path):
                for mutated in mutations:
                    with self.subTest(mutation=mutated):
                        path.write_text(json.dumps(mutated), encoding='utf-8')
                        with self.assertRaises(ValueError):
                            V.pins()

    def test_exact_success_requires_four_executed_tests(self):
        self.assertEqual(V.verify_results(log(), 0)['passed'], 4)

    def test_exit_failure_cannot_become_success(self):
        for status in (1, 101, 124, 137, False):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'cargo_failed'):
                V.verify_results(log(), status)

    def test_missing_duplicate_extra_ignored_or_failed_test(self):
        first = b'test snp::milan_chain ... ok\n'
        for raw in (log().replace(first, b''), log() + first,
                log().replace(first, b'test snp::milan_chain ... ignored\n'),
                log().replace(first, b'test snp::milan_chain ... FAILED\n'),
                log() + b'test unrelated::other ... ok\n',
                log().replace(b'running 4 tests', b'running 0 tests'),
                log().replace(b'4 passed', b'0 passed'), log() + log(),
                b'build succeeded\n', b'\xff', b'x' * (V.MAX_LOG + 1)):
            with self.subTest(raw_prefix=raw[:100]), self.assertRaises((ValueError, UnicodeError)):
                V.verify_results(raw, 0)

    def test_toolchain_receipts_are_version_exact(self):
        rustc = b'rustc 1.85.0 (test fixture)\nrelease: 1.85.0\n'
        cargo = b'cargo 1.85.0 (test fixture)\nrelease: 1.85.0\n'
        self.assertEqual(V.toolchain(rustc, cargo)['rust'], '1.85.0')
        for wrong in (cargo.replace(b'1.85.0', b'1.85.1'), b'cargo 1.85.0\n', b'x' * 32769):
            with self.assertRaises(ValueError):
                V.toolchain(rustc, wrong)

    def test_capture_is_bounded_and_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(V, 'MAX_LOG', 16):
            path = Path(tmp) / 'log'
            V.capture(io.BytesIO(b'x' * 16), path)
            self.assertEqual(path.read_bytes(), b'x' * 16)
            with self.assertRaises(FileExistsError):
                V.capture(io.BytesIO(b'overwrite'), path)
            overflow = Path(tmp) / 'overflow'
            with self.assertRaisesRegex(ValueError, 'test_log_bound'):
                V.capture(io.BytesIO(b'y' * 17), overflow)
            self.assertEqual(overflow.read_bytes(), b'y' * 16)

    def test_bounded_rejects_symlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input'
            path.write_bytes(b'1234')
            link = Path(tmp) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                V.bounded(path, 3)
            with self.assertRaises(ValueError):
                V.bounded(link, 4)

    def test_no_local_native_entrypoint(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'explicit_disposable_hosted_only'):
                V.main(['source', '/does-not-exist'])

    def test_source_mismatch_precedes_reading_fixtures(self):
        selected = V.pins()
        for observed in (['wrong'], [selected['upstream']['commit'], 'wrong'],
                [selected['upstream']['commit'], selected['upstream']['tree'], ' M source.rs']):
            with tempfile.TemporaryDirectory() as tmp, patch.object(V, 'command', side_effect=observed):
                with self.assertRaisesRegex(ValueError, 'source_(commit|tree|changed)'):
                    V.verify_source(Path(tmp))

    def test_receipt_preserves_scope_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(V, 'hosted'), \
                patch.object(V, 'verify_source', return_value=V.pins()), \
                patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}):
            output = Path(tmp)
            (output / 'tests.log').write_bytes(log())
            for name in ('rustc', 'cargo'):
                (output / (name + '.txt')).write_text(name + ' 1.85.0 (fixture)\nrelease: 1.85.0\n')
            V.main(['receipt', 'inert-source', tmp, '0', '0'])
            result = json.loads((output / 'report.json').read_bytes())
            self.assertEqual(result['scope'], V.SCOPE)
            self.assertIs(result['scope']['private_task_release'], False)
            self.assertIs(result['scope']['protected_execution_proven'], False)
            self.assertEqual(result['evidence']['log_sha256'], V.sha(log()))
            with self.assertRaises(FileExistsError):
                V.main(['receipt', 'inert-source', tmp, '0', '0'])

    def test_failed_capture_never_writes_receipt(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(V, 'hosted'):
            with self.assertRaisesRegex(ValueError, 'capture_failed'):
                V.main(['receipt', 'inert-source', tmp, '0', '1'])
            self.assertFalse((Path(tmp) / 'report.json').exists())

    def test_workflow_keeps_failed_pipeline_exit_evidence(self):
        text = WORKFLOW.read_text()
        step = text.split('      - name: Execute only four public cryptographic fixtures\n', 1)[1]
        step = step.split('      - name:', 1)[0].split('        run: |\n', 1)[1]
        script = '\n'.join(line[10:] for line in step.splitlines())
        # Execute the real workflow shell with inert producer/collector functions.
        # bash -e matches the runner and catches accidentally inherited errexit.
        prefix = '''
timeout() { printf 'inert compiler output\\n'; return "$TEST_CARGO_EXIT"; }
python3() {
  if [[ "$3" == capture ]]; then
    cat >/dev/null
    return "$TEST_CAPTURE_EXIT"
  elif [[ "$3" == receipt ]]; then
    test "$6" = "$TEST_CARGO_EXIT" && test "$7" = "$TEST_CAPTURE_EXIT" || return 98
    test "$6" = 0 && test "$7" = 0
  else
    return 99
  fi
}
'''
        for cargo_exit, capture_exit in ((0, 0), (101, 0), (124, 0), (0, 1), (141, 1)):
            with self.subTest(cargo=cargo_exit, capture=capture_exit), tempfile.TemporaryDirectory() as tmp:
                evidence = Path(tmp) / 'build/protected-compute-verifier/evidence'
                evidence.mkdir(parents=True)
                run = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail',
                    '-c', prefix + script], cwd=tmp, capture_output=True, timeout=10,
                    env={**os.environ, 'TEST_CARGO_EXIT': str(cargo_exit), 'TEST_CAPTURE_EXIT': str(capture_exit),
                        'VERIFIER_SOURCE': str(Path(tmp) / 'inert-source')})
                self.assertEqual((evidence / 'cargo-exit.txt').read_text().strip(), str(cargo_exit))
                self.assertEqual((evidence / 'capture-exit.txt').read_text().strip(), str(capture_exit))
                self.assertEqual(run.returncode == 0, cargo_exit == capture_exit == 0)

    def test_upstream_is_outside_parent_cargo_workspace(self):
        text = WORKFLOW.read_text()
        self.assertIn('VERIFIER_SOURCE: ${{ runner.temp }}/volparossa-protected-compute-verifier-source', text)
        self.assertIn('test ! -e "$VERIFIER_SOURCE"', text)
        self.assertEqual(text.count('--manifest-path "$VERIFIER_SOURCE/Cargo.toml"'), 2)
        self.assertNotIn('build/protected-compute-verifier/source', text)
        self.assertNotIn('workspace.exclude', text)

    def test_workflow_is_source_pinned_public_and_bounded(self):
        text = WORKFLOW.read_text()
        for required in ('contents: read', 'runs-on: ubuntu-24.04', 'timeout-minutes: 25',
                'persist-credentials: false', 'CARGO_BUILD_JOBS: \'2\'',
                'cargo +1.85.0 test --locked --offline', '--no-default-features --features snp,crypto_nossl',
                "--test certs 'snp::'", '-- --test-threads=1', 'timeout --kill-after=15s 900s',
                V.pins()['upstream']['commit'], 'cancel-in-progress: false'):
            self.assertIn(required, text)
        for forbidden in ('sudo ', '/dev/sev', 'private-task', 'self-hosted', 'continue-on-error: true'):
            self.assertNotIn(forbidden, text)
        paths = text.split('          path: |\n', 1)[1].splitlines()
        self.assertEqual(len(paths), 6)
        self.assertTrue(all(line.strip().startswith('build/protected-compute-verifier/evidence/') for line in paths))


if __name__ == '__main__':
    unittest.main()
