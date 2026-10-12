#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert dispatch/export/child-lifecycle tests, never real core or network proof."""
import copy
import io
import json
import os
from pathlib import Path
import runpy
import select
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SCENARIO = 'private-storage-maintenance'
M = runpy.run_path(str(HERE / (SCENARIO + '-smoke.py')))
FIXTURE = runpy.run_path(str(HERE / ('test-' + SCENARIO + '-smoke.py')))
DIAGNOSTICS = runpy.run_path(str(HERE / 'test-private-storage-fragments-wiring.py'))['diagnostics']


class Wiring(unittest.TestCase):
    def test_preview_is_explicit_and_last_scenario_wins(self):
        for script in ('kvm-alpha-topology.sh', 'run-alpha-topology-vm.sh'):
            for first, last in ((SCENARIO, 'private-storage-peer'), ('private-storage-peer', SCENARIO)):
                result = subprocess.run(['sh', str(HERE / script), '--preview', '--scenario', first,
                    '--scenario', last], text=True, capture_output=True, check=True, timeout=5)
                self.assertIn(last, result.stdout.lower())
                self.assertNotIn(first, result.stdout.lower())
                self.assertIn('PREVIEW ONLY', result.stdout)

    def test_exact_dependency_preflight_rejects_missing_and_symlink(self):
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        start = guest.index('if [ "$private_storage_maintenance" = yes ]; then\n    for maintenance_fixture')
        block = guest[start:guest.index('\nfi', start) + 3]
        names = ('private-storage-maintenance-smoke.sh', 'private-storage-maintenance-smoke.py',
            'private-storage-log-sampler.py', 'content-provider-readiness.py',
            'storage-consumer-maintenance-smoke.sh', 'storage-consumer-maintenance-smoke.py',
            'storage-consumer-maintenance.mjs', 'storage-consumer-maintenance-pins.json',
            'storage-consumer-maintenance-evidence.py', 'storage-consumer-maintenance-provision.py',
            'image-snapshot-provision.py', 'agent-private-task-code.py', 'agent-private-task-code-pins.json')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'tests/integration'
            directory.mkdir(parents=True)
            for name in names:
                (directory / name).touch()
            def invoke():
                return subprocess.run(['sh', '-c', 'source_directory=$1; private_storage_maintenance=yes;\n' + block,
                    'test', str(root)], check=False, timeout=5).returncode
            self.assertEqual(invoke(), 0)
            for name in names:
                path = directory / name
                path.unlink()
                self.assertEqual(invoke(), 69)
                path.symlink_to(directory / names[(names.index(name) + 1) % len(names)])
                self.assertEqual(invoke(), 69)
                path.unlink()
                path.touch()

    def test_current_readiness_and_owned_guest_service_are_preserved(self):
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        smoke = (HERE / (SCENARIO + '-smoke.sh')).read_text()
        self.assertNotIn('storage-route-readiness.py', guest + smoke)
        self.assertIn('content-provider-readiness.py', smoke)
        self.assertIn('benchmark_select_route private-storage-maintenance-reconnect mptcp', smoke)
        self.assertIn('retire_unit volparossa-alpha-agent@client.service', smoke)
        self.assertIn('launch_agent client "$CLIENT"', smoke)
        self.assertIn('"/proc/$maintenance_old_pid/ns/net"', smoke)
        self.assertIn('"/proc/$maintenance_new_pid/ns/net"', smoke)
        self.assertIn('[ "$maintenance_control_peer" = "$provider_control_peer" ]', smoke)
        self.assertLess(guest.index('        private_storage_maintenance_join || original_status=1'),
            guest.index('        private_storage_fragments_cleanup || original_status=1'))
        self.assertLess(guest.index('    private_storage_maintenance_run\n'),
            guest.index('    private_storage_fragments_run\n'))
        self.assertIn('private-storage-fragments-lifecycle-privacy)', guest)

    def test_current_scenario_bounds_tests_and_source_gate(self):
        driver = (HERE / 'run-alpha-topology-vm.sh').read_text()
        self.assertIn('[ "$scenario" != private-storage-maintenance ] || driver_time_bound=7200s', driver)
        self.assertIn('cargo test --locked -p volparossa --bin volparossa storage::peer::replicas::fragments::maintenance', driver)
        self.assertIn('private-storage-maintenance-smoke.py owner-test-output', driver)
        self.assertIn('test "$(cat /home/vpci/storage-maintenance-tests.status)" = 0', driver)
        self.assertIn('cargo test --locked -p volparossa-agent --lib maintenance', driver)
        self.assertIn('cargo test --locked -p volparossa-content --lib private_storage::wire', driver)
        self.assertIn('CARGO_BUILD_JOBS=1', driver)
        workflow = (HERE.parents[1] / '.github/workflows/alpha-topology.yml').read_text()
        self.assertIn('          - private-storage-maintenance\n', workflow)
        start = workflow.index('      - name: Require actual owner-private storage maintenance')
        gate = workflow[start:workflow.index('\n      - name:', start + 1)]
        self.assertIn('test "$TOPOLOGY_EXIT_CODE" = 0', gate)
        self.assertIn('private-storage-maintenance-smoke.py report "$report" "$GITHUB_SHA"', gate)
        self.assertIn('host-state-before.json', gate)
        self.assertIn('host-state-after.json', gate)

    def test_background_budget_config_is_scoped_to_maintenance(self):
        for selected, ceiling, interface in (('yes', 10, 'cr0'), ('no', 1, 'cr2')):
            result = subprocess.run(['sh', '-eu', '-c',
                '. "$1"; scenario=content-custody; node=client; private_storage_maintenance=$2; content_custody_config',
                'test', str(HERE / 'content-custody-smoke.sh'), selected], text=True,
                capture_output=True, check=True, timeout=5)
            self.assertEqual(result.stdout, f'sharing:\n  enabled: true\n  interface: cr0\n'
                f'  total_upload_mbps: 100\n  contribution_upload_ceiling_mbps: {ceiling}\n'
                f'download_sharing:\n  enabled: true\n  interface: {interface}\n'
                f'  total_download_mbps: 100\n  contribution_download_ceiling_mbps: {ceiling}\n')

    def test_closed_export_parity_and_private_sentinels(self):
        diagnostics = DIAGNOSTICS()
        names = set(M['EXPORT_NAMES'])
        self.assertEqual(names, diagnostics['MAINTENANCE_NAMES'])
        self.assertEqual(len(names), len(M['EXPORT_NAMES']))
        self.assertLess(len(names), 128)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / 'home'
            published = home / 'alpha-output'
            published.mkdir(parents=True)
            for name in names:
                (published / name).write_text('{}')
            for name in ('maintenance-owner-lifecycle.private', 'lifecycle-result.json',
                    'identity.key', 'enrollment.json', 'checkpoint.json', 'logs-client.txt',
                    'private-storage-maintenance-route-diagnostic.json', 'ready.json'):
                (published / name).write_text('PRIVATE_MUST_NOT_EXPORT')
            archive = diagnostics['collect'](home, root / 'missing-opt', 'a' * 40, SCENARIO, 124,
                cgroups=root / 'missing-cgroups', proc=root / 'missing-proc')
            with tarfile.open(archive, 'r:gz') as bundle:
                self.assertEqual(set(bundle.getnames()), {f'published/{name}' for name in names} | {'vm-incomplete.json'})
                for entry in bundle.getmembers():
                    self.assertNotIn(b'PRIVATE_MUST_NOT_EXPORT', bundle.extractfile(entry).read())
                receipt = json.load(bundle.extractfile('vm-incomplete.json'))
                self.assertFalse(receipt['success'])
                self.assertFalse(receipt['cleanup']['verified'])
                self.assertIsNone(receipt['host_state']['unchanged'])

    def test_emergency_deduplicates_only_identical_named_receipts(self):
        diagnostics, names = DIAGNOSTICS(), set(M['EXPORT_NAMES'])
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home, opt = base / 'home', base / 'opt'
            published = home / 'alpha-output'
            work = opt / ('va.' + 'a' * 32 + '.Abc123')
            for root in (published, work):
                root.mkdir(parents=True)
                for name in names:
                    (root / name).write_text('{}\n')
                (root / 'consumer-binding.json').write_text('PRIVATE_MUST_NOT_EXPORT')
            distinct = 'storage-consumer-finish.json'
            (work / distinct).write_text('{"passed":false}\n')
            archive = diagnostics['collect'](home, opt, 'a' * 40, SCENARIO, 124,
                cgroups=base / 'missing-cgroups', proc=base / 'missing-proc')
            with tarfile.open(archive, 'r:gz') as bundle:
                self.assertEqual(set(bundle.getnames()), {f'published/{name}' for name in names}
                    | {f'work-1/{distinct}', 'vm-incomplete.json'})
                for entry in bundle.getmembers():
                    self.assertNotIn(b'PRIVATE_MUST_NOT_EXPORT', bundle.extractfile(entry).read())

    def test_emergency_keeps_terminal_receipts_first_without_raising_bounds(self):
        diagnostics = DIAGNOSTICS()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home, opt = base / 'home', base / 'opt'
            roots = [home / 'alpha-output', *(opt / ('va.' + str(i) * 32 + '.Abc123') for i in range(4))]
            names = set(M['EXPORT_NAMES'])
            for index, root in enumerate(roots):
                root.mkdir(parents=True)
                for name in names:
                    (root / name).write_text(json.dumps({'root': index}))
                (root / 'current-phase').write_text('storage-consumer-exercise\n')
                # Never export an unfinished JSON object or its truncated tail.
                (root / 'storage-consumer-prepare.json').write_text('{"partial":')
                (root / 'storage-consumer-publish.json').write_text('x' * (diagnostics['FILE_LIMIT'] + 1))
            archive = diagnostics['collect'](home, opt, 'a' * 40, SCENARIO, 124,
                cgroups=base / 'missing-cgroups', proc=base / 'missing-proc')
            with tarfile.open(archive, 'r:gz') as bundle:
                receipt = json.load(bundle.extractfile('vm-incomplete.json'))
                self.assertLessEqual(len(receipt['diagnostics']['files']), 128)
                self.assertLessEqual(receipt['diagnostics']['captured_bytes'], diagnostics['TOTAL_LIMIT'])
                self.assertTrue(all(not item['truncated'] for item in receipt['diagnostics']['files']))
                for label in ('published', *(f'work-{i}' for i in range(1, 5))):
                    for name in ('storage-consumer-finish.json', 'private-storage-maintenance-lifecycle-failure.json',
                            'private-storage-fragments-consumer_deleted_usage.json'):
                        self.assertIn(f'{label}/{name}', bundle.getnames())
                self.assertFalse(any(name.endswith(('storage-consumer-prepare.json', 'storage-consumer-publish.json'))
                    for name in bundle.getnames()))


class OwnerLifecycle(unittest.TestCase):
    def test_ready_publication_is_atomic_after_bytes_and_metadata_and_partial_cleanup(self):
        # Execute the real publisher/cleanup functions with only install replaced:
        # no root chown is attempted, but its exact arguments remain mandatory.
        # Pause its writer after partial content and before the final mode change.
        installer = '''import os,sys
from pathlib import Path
assert sys.argv[1:7] == ['-o', 'root', '-g', str(os.getgid()), '-m', '0640']
source, target = map(Path, sys.argv[7:])
data = source.read_bytes()
with target.open('xb') as stream:
    os.fchmod(stream.fileno(), 0o600)
    stream.write(data[:len(data)//2])
    stream.flush()
    print('partial', flush=True)
    assert sys.stdin.readline() == 'continue\\n'
    if os.environ['INSTALL_FAIL'] == 'yes':
        sys.exit(7)
    stream.write(data[len(data)//2:])
    stream.flush()
    os.fchmod(stream.fileno(), 0o640)
'''
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                coordinator = work / 'maintenance-coordinator'
                coordinator.mkdir(mode=0o750)
                source = work / 'maintenance-coordinator-ready.private'
                raw = b'{"baseline":123,"scope":{"synthetic":"closed fixture"}}\n'
                source.write_bytes(raw)
                script = work / 'install-fixture.py'
                script.write_text(installer)
                ready, part = coordinator / 'ready.json', coordinator / 'ready.part'
                environment = dict(PATH='/usr/bin:/bin', WORK=str(work), WORKER_GID=str(os.getgid()),
                    INSTALL_FAIL='yes' if failed else 'no')
                command = ['sh', '-eu', '-c', '. "$1"; install() { python3 -B "$WORK/install-fixture.py" "$@"; }; '
                    'private_storage_maintenance_publish_ready', 'test', str(HERE / (SCENARIO + '-smoke.sh'))]
                process = subprocess.Popen(command, env=environment, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'installer did not reach publication barrier')
                    self.assertEqual(process.stdout.readline(), 'partial\n')
                    self.assertEqual(part.read_bytes(), raw[:len(raw)//2])
                    self.assertEqual(stat.S_IMODE(part.stat().st_mode), 0o600)
                    self.assertFalse(ready.exists(), 'watcher saw unfinished bytes or metadata')
                    stdout, stderr = process.communicate('continue\n', timeout=5)
                    self.assertEqual(stdout, '')
                    self.assertEqual(stderr, '')
                    self.assertEqual(process.returncode, 1 if failed else 0)
                    if failed:
                        self.assertFalse(ready.exists())
                        self.assertTrue(part.is_file())
                    else:
                        info = ready.stat()
                        self.assertEqual(ready.read_bytes(), raw)
                        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink),
                            (os.getuid(), os.getgid(), 0o640, 1))
                        self.assertFalse(part.exists())
                finally:
                    if process.poll() is None:
                        # Release the finite fixture writer before joining the shell.
                        process.communicate('continue\n', timeout=5)
                subprocess.run(['sh', '-eu', '-c', '. "$1"; private_storage_maintenance_join',
                    'test', str(HERE / (SCENARIO + '-smoke.sh'))], env=environment,
                    check=True, capture_output=True, timeout=5)
                self.assertFalse(coordinator.exists())
                self.assertEqual(source.read_bytes(), raw)

    @staticmethod
    def owner_test_stdout():
        names = sorted(M['OWNER_REQUIRED_TESTS'])
        return ('\nrunning ' + str(len(names)) + ' tests\n' + ''.join(
            f"test {M['OWNER_TEST_PREFIX']}{name} ... ok\n" for name in names)
            + f'\ntest result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 601 filtered out; finished in 2.00s\n\n').encode()

    def test_owner_gate_requires_actual_named_passes_not_zero_listing_or_partial(self):
        valid = self.owner_test_stdout()
        self.assertEqual(M['owner_test_output'](io.BytesIO(valid))['required_passed'], 13)
        for invalid in (b'\nrunning 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 614 filtered out; finished in 0.00s\n',
                valid.replace(b' ... ok', b': test'), valid.replace(b' ... ok', b' ... ignored', 1),
                valid.replace(b' ... ok', b' ... FAILED', 1), valid.replace(b'13 passed', b'12 passed'),
                valid.replace(b'enrollment_signature_private_mode_and_restart_cursor_are_retained', b'wrong_test'),
                valid + b'x' * 65537):
            with self.subTest(invalid=invalid[:40]), self.assertRaises(ValueError):
                M['owner_test_output'](io.BytesIO(invalid))
        for invalid in (valid.replace(b' ... ok', b' ... FAILED', 1), b'x' * 65537):
            diagnostic = io.BytesIO()
            with self.assertRaises(ValueError):
                M['owner_test_output'](io.BytesIO(invalid), diagnostic)
            self.assertLessEqual(len(diagnostic.getvalue()), 65536)
            self.assertIn(b'FAILED' if len(invalid) < 65536 else b'OWNER_TEST_OUTPUT_LIMIT_EXCEEDED', diagnostic.getvalue())

    def test_actual_guest_gate_checks_cargo_exit_even_with_a_successful_output_parser(self):
        source = (HERE / 'run-alpha-topology-vm.sh').read_text()
        start = source.index('    test ! -e /home/vpci/storage-maintenance-tests.status')
        end = source.index('    CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/home/vpci/target timeout --signal=TERM --kill-after=15s 900s', start)
        block = source[start:end].replace('tests/integration/private-storage-maintenance-smoke.py',
            str(HERE / 'private-storage-maintenance-smoke.py'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / 'cargo'
            executable.write_text('#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\n'
                'assert "storage::peer::replicas::fragments::maintenance" in sys.argv\n'
                'sys.stdout.buffer.write(Path(os.environ["TEST_OUTPUT"]).read_bytes())\n'
                'sys.exit(int(os.environ["TEST_EXIT"]))\n')
            executable.chmod(0o700)
            for index, (raw, exit_code, passed) in enumerate(((self.owner_test_stdout(), 0, True),
                    (self.owner_test_stdout(), 7, False), (b'running 0 tests\n', 0, False), (b'x' * 65537, 0, False))):
                output = root / f'output-{index}'
                output.write_bytes(raw)
                actual = block.replace('/home/vpci/storage-maintenance-tests.status', str(root / f'status-{index}'))
                result = subprocess.run(['sh', '-eu', '-c', actual], capture_output=True, timeout=5,
                    env={'PATH': f'{root}:/usr/bin:/bin', 'TEST_OUTPUT': str(output), 'TEST_EXIT': str(exit_code)})
                self.assertEqual(result.returncode == 0, passed)
                if passed:
                    self.assertEqual(json.loads(result.stdout)['required_passed'], 13)

    def test_failed_lifecycle_is_exported_only_through_exact_bounded_schema(self):
        source = (HERE / 'private-storage-maintenance-smoke.sh').read_text()
        start = source.index('    if [ "$maintenance_status" -ne 0 ]')
        block = source[start:source.index('\n    optional_json_evidence', start)]
        value = dict(version=1, success=False, kind='private-storage-maintenance-lifecycle-failure',
            stage='start_sampler', code='sampler_failure', cursor_before=3, cursor_last=5,
            checkpoint_stage='waiting_for_core', owner_exit_status=0, owner_joined=True, cleanup_error=None,
            sampler=dict(phase='initial', operation='route_query', code='process', samples=0, completed=0, failed=0,
                paths_process=dict(exit_status=1, diagnostic='CLIENT_ROUTE_BUSY', stderr_state='bounded')))
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            private = work / 'maintenance-owner-lifecycle.private'
            exported = work / 'private-storage-maintenance-lifecycle-failure.json'
            current = dict(value, version=2, retained_status=M['retained_status_diagnostic']({}, 100))
            cases = (json.dumps(value), json.dumps(current), json.dumps(dict(value, private='SECRET')),
                json.dumps(dict(value, code='SECRET_PATH')), json.dumps(dict(value, cursor_last=True)),
                json.dumps(dict(value, sampler=dict(value['sampler'], raw_stderr='SECRET'))),
                json.dumps(dict(current, retained_status=dict(current['retained_status'], private='SECRET'))), 'x' * 8193)
            for index, raw in enumerate(cases):
                private.write_text(raw)
                private.chmod(0o600)
                subprocess.run(['sh', '-eu', '-c', block], check=True, capture_output=True, timeout=5,
                    env={'PATH': '/usr/bin:/bin', 'WORK': str(work), 'source_directory': str(HERE.parents[1]),
                        'maintenance_status': '1'})
                if index < 2:
                    self.assertEqual(json.loads(exported.read_text()), (value, current)[index])
                    exported.unlink()
                else:
                    self.assertFalse(exported.exists())
                self.assertFalse((work / 'maintenance-lifecycle-failure.part').exists())

    def test_retained_charge_accepts_original_v1_without_v2_history(self):
        value, _, _ = FIXTURE['OLD']['cli_fixture']('committed')
        self.assertNotIn('retained_copy_records', value)
        self.assertNotIn('placement_authorizations', value)
        M['retained_during_core_loss'](value)
        for mutate in (
                lambda v: v.update(physical_payload_charge_upper_bound=0),
                lambda v: v.update(placement_authorizations=1),
                lambda v: v['fragments'][0]['copies'].pop()):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.assertRaises(ValueError):
                M['retained_during_core_loss'](invalid)

    def test_route_comparison_is_closed_and_only_valid_for_relay_scope_failure(self):
        value = dict(version=2, success=False, kind='private-storage-maintenance-lifecycle-failure',
            stage='start_sampler', code='sampler_failure', cursor_before=3, cursor_last=5,
            checkpoint_stage='waiting_for_core', owner_exit_status=0, owner_joined=True, cleanup_error=None,
            retained_status=None, sampler=dict(phase='sampling', operation='route_scope', code='invalid',
                samples=2, completed=1, failed=0, route_mismatch='relays_changed'))
        for context in ('same', 'changed', 'unobserved'):
            for relay in ('same', 'changed'):
                value['sampler']['route_comparison'] = dict(context_relation=context, relay_set_relation=relay)
                M['validate_lifecycle_failure'](value)
        for mutate in (
            lambda v: v['sampler'].update(operation='route_query'),
            lambda v: v['sampler'].update(code='process'),
            lambda v: v['sampler'].update(route_mismatch='path_ids_changed'),
            lambda v: v['sampler'].update(route_comparison=None),
            lambda v: v['sampler']['route_comparison'].update(context_relation='SECRET'),
            lambda v: v['sampler']['route_comparison'].update(relay_set_relation='unobserved'),
            lambda v: v['sampler']['route_comparison'].update(raw_ids=['SECRET']),
            lambda v: v['sampler']['route_comparison'].pop('relay_set_relation'),
        ):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.assertRaises(ValueError):
                M['validate_lifecycle_failure'](invalid)

    def test_retained_failure_codes_distinguish_each_unchanged_predicate(self):
        value, _, _ = FIXTURE['OLD']['cli_fixture']('committed')
        mutations = (
            (lambda v: v.update(physical_payload_charge_upper_bound=0), 'lifecycle_charge_changed'),
            (lambda v: v['fragments'].pop(), 'lifecycle_fragment_count_changed'),
            (lambda v: v['fragments'][0]['copies'].append(dict(charge='unattempted', last_confirmed_expiry=0)),
                'lifecycle_copy_count_changed'),
            (lambda v: v.update(placement_authorizations=1), 'lifecycle_placement_count_changed'))
        for mutate, code in mutations:
            invalid = copy.deepcopy(value)
            mutate(invalid)
            diagnostic = {}
            with patch.dict(M['retained_during_core_loss'].__globals__, LIFECYCLE_DIAGNOSTIC=diagnostic):
                with self.assertRaises(ValueError) as error:
                    M['retained_during_core_loss'](invalid)
            self.assertEqual(M['failure_code'](error.exception), code)
            M['validate_retained_status'](diagnostic['retained_status'])
            self.assertEqual(diagnostic['retained_status']['physical_payload_charge_upper_bound'],
                invalid['physical_payload_charge_upper_bound'])
        # Uncertainty/retention changes alone do not change the original total
        # charge/geometry acceptance, nor prove live remote availability.
        value['fragments'][0]['copies'][0].update(charge='uncertain', last_confirmed_expiry=99)
        value['fragments'][0]['copies'][1]['last_confirmed_expiry'] = 101
        M['retained_during_core_loss'](value)
        diagnostic = M['retained_status_diagnostic'](value, 100)
        self.assertEqual(diagnostic['charge_states']['uncertain'], 1)
        self.assertGreaterEqual(diagnostic['retained_expiries']['expired'], 1)
        self.assertGreaterEqual(diagnostic['retained_expiries']['unexpired'], 1)

    def test_retained_status_projection_is_bounded_closed_and_missing_is_unknown(self):
        value, _, _ = FIXTURE['OLD']['cli_fixture']('committed')
        value['private_path'] = 'PRIVATE_CANARY'
        value['fragments'][0]['copies'][0].update(provider_key='PRIVATE_CANARY',
            charge=['PRIVATE_CANARY'], last_confirmed_expiry=True)
        projected = M['retained_status_diagnostic'](value, 100)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(projected))
        self.assertEqual(projected['charge_states']['unknown'], 1)
        self.assertGreaterEqual(projected['retained_expiries']['unknown'], 1)
        self.assertFalse(projected['placement_field_present'])
        self.assertEqual(projected['placement_authorizations'], 0)  # Original v1 report shape.
        for invalid in (None, {}, dict(fragments=[{}]), dict(fragments=[{}] * 65),
                dict(fragments=[dict(copies=[{}] * 65)]),
                dict(value, physical_payload_charge_upper_bound=2**64, placement_authorizations=True)):
            diagnostic = M['retained_status_diagnostic'](invalid, 100)
            M['validate_retained_status'](diagnostic)
            self.assertLess(len(json.dumps(diagnostic)), 8192)
        self.assertIsNone(M['retained_status_diagnostic'](None, 100)['placement_authorizations'])
        for mutate in (lambda v: v.update(private_path='PRIVATE_CANARY'),
                lambda v: v.update(fragment_count=True), lambda v: v['copy_counts'].append(2),
                lambda v: v['charge_states'].update(unknown=4097),
                lambda v: v['retained_expiries'].update(expired=True)):
            invalid = copy.deepcopy(projected)
            mutate(invalid)
            with self.assertRaises(ValueError):
                M['validate_retained_status'](invalid)

    def test_lifecycle_v2_exports_only_projected_status_and_keeps_v1_distinct(self):
        value, _, _ = FIXTURE['OLD']['cli_fixture']('committed')
        context = dict(stage='verify_retained', cursor_before=3, cursor_last=4,
            checkpoint_stage='core_unavailable', owner_exit_status=0, owner_joined=True,
            cleanup_error=None, retained_status=M['retained_status_diagnostic'](value, 100))
        with patch.dict(M['failure_receipt'].__globals__, LIFECYCLE_DIAGNOSTIC=context, SAMPLER_DIAGNOSTIC={}):
            receipt = M['failure_receipt'](ValueError('core loss changed copy count'))
        self.assertEqual(receipt['version'], 2)
        M['validate_lifecycle_failure'](receipt)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'failure.json'
            path.write_text(json.dumps(receipt)); path.chmod(0o600)
            result = subprocess.run([sys.executable, '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                'lifecycle-failure', str(path)], capture_output=True, check=True, timeout=5)
            self.assertEqual(json.loads(result.stdout), receipt)
        historical = dict(receipt, version=1, code='lifecycle_charge_changed')
        del historical['retained_status']
        M['validate_lifecycle_failure'](historical)
        for invalid in (dict(receipt, version=1), dict(historical, version=2),
                dict(receipt, retained_status=dict(receipt['retained_status'], private='SECRET'))):
            with self.assertRaises(ValueError):
                M['validate_lifecycle_failure'](invalid)

    def test_every_lifecycle_flag_and_cursor_is_required(self):
        value = FIXTURE['fixture']()['lifecycle']
        M['validate_lifecycle'](value)
        for key, entry in value.items():
            invalid = copy.deepcopy(value)
            invalid[key] = False if type(entry) is bool else -1
            with self.subTest(key=key), self.assertRaises(ValueError):
                M['validate_lifecycle'](invalid)
        for mutate in (
                lambda v: v.update(cursor_after_resume=v['cursor_at_pause']),
                lambda v: v.update(cursor_at_core_loss=v['cursor_after_reconnect']),
                lambda v: v.update(cursor_after_resume=True),
                lambda v: v.update(secret='forbidden')):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.assertRaises(ValueError):
                M['validate_lifecycle'](invalid)

    def test_real_owned_python_child_joins_on_sigterm_and_drains(self):
        # This executes Python only, not the core, Rust, a network or a VM.
        code = ('import signal,sys,time\n'
            'signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n'
            'print(\'{"stage":"ready","turns":1}\',flush=True)\n'
            'while True: time.sleep(.1)\n')
        child = M['OwnerProcess']([sys.executable, '-I', '-B', '-c', code])
        try:
            M['wait_owner'](child, lambda: child.reports(), seconds=3)
            child.stop()
            self.assertEqual(child.process.returncode, 0)
            self.assertTrue(all(not thread.is_alive() for thread in child.threads))
            self.assertEqual(child.reports(), [dict(stage='ready', turns=1)])
        finally:
            child.close()

    def test_output_is_bounded_and_still_drained(self):
        child = M['OwnerProcess']([sys.executable, '-I', '-B', '-c',
            'import sys; sys.stdout.buffer.write(b"x"*600000); sys.stderr.buffer.write(b"y"*600000)'])
        child.process.wait(timeout=5)
        try:
            with self.assertRaises(ValueError):
                child.join()
            self.assertTrue(all(not thread.is_alive() for thread in child.threads))
            self.assertTrue(all(len(buffer) <= child.LIMIT for buffer in child.buffers))
            self.assertTrue(all(child.overflow))
        finally:
            try:
                child.close()
            except ValueError:
                pass

    def test_regular_coordinator_turn_records_remain_count_and_byte_bounded(self):
        for count, accepted in ((34, True), (M['MAX_LIFECYCLE_CURSOR'], True),
                (M['MAX_LIFECYCLE_CURSOR'] + 1, False)):
            with self.subTest(count=count):
                child = M['OwnerProcess']([sys.executable, '-I', '-B', '-c',
                    'import json,sys\nfor index in range(int(sys.argv[1])):\n'
                    ' print(json.dumps(dict(stage="turn_completed",turns=index+1)),flush=True)\n', str(count)])
                try:
                    child.process.wait(timeout=5)
                    child.join()
                    self.assertLessEqual(len(child.buffers[0]), child.LIMIT)
                    if accepted:
                        self.assertEqual(len(child.reports()), count)
                    else:
                        with self.assertRaisesRegex(ValueError, 'bounded owner output'):
                            child.reports()
                finally:
                    child.close()


if __name__ == '__main__':
    unittest.main()
