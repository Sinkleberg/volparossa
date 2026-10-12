#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert dispatch/export/child-lifecycle tests, never real core or network proof."""
import copy
import json
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

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
            'private-storage-log-sampler.py', 'content-provider-readiness.py')
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
        self.assertIn('cargo test --locked -p volparossa --bin volparossa storage::fragments_maintenance', driver)
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


class OwnerLifecycle(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
