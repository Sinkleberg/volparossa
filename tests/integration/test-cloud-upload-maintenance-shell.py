#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert shell orchestration checks; no guest, privileges or provider execution."""
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'cloud-upload-maintenance-smoke.sh'
SOURCE = SCRIPT.read_text()
E = runpy.run_path(str(HERE / 'cloud-upload-maintenance-evidence.py'))


class Wiring(unittest.TestCase):
    def test_syntax_and_source_has_no_immediate_actions(self):
        result = subprocess.run(['sh', '-n', str(SCRIPT)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(['sh', '-c', '. "$1"', 'inert', str(SCRIPT)], capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_explicit_profile_and_existing_completed_consumer_are_required(self):
        for existing, new, joined, failure in [('no', 'yes', 'yes', 'CLOUD_UPLOAD_PROFILE_INVALID'),
                ('yes', 'no', 'yes', 'CLOUD_UPLOAD_PROFILE_INVALID'),
                ('yes', 'yes', 'no', 'CLOUD_UPLOAD_PRIOR_CONSUMER_NOT_JOINED')]:
            script = '. "$1"; fail() { echo "$1"; exit 1; }; private_storage_maintenance=$2; cloud_upload_maintenance=$3; consumer_private_cleanup_complete=$4; private_cloud_upload_run'
            result = subprocess.run(['sh', '-c', script, 'inert', str(SCRIPT), existing, new, joined],
                capture_output=True, text=True, timeout=5)
            self.assertEqual((result.returncode, result.stdout.strip()), (1, failure))

    def test_actual_phase_function_uses_new_capture_and_dynamic_owned_minimum(self):
        with tempfile.TemporaryDirectory() as temporary:
            # The only subprocess is sh with all operation functions replaced
            # by inert trace functions, not a simulated network proof.
            script = '''. "$1"
WORK=$2; upload_user=$WORK/u/a; storage_user=$WORK/client-fixtures/private-storage-user
fail() { echo "$1" >&2; exit 1; }
private_cloud_upload_private() {
  if [ "$1" = flow-minimum ]; then
    [ "$2" = finish ] && [ "$3" = "$upload_user" ] || exit 99
    echo 9
  else printf '%s\n' "$*"; fi
}
private_storage_fragments_phase_start() { echo "begin:$1"; }
private_storage_fragments_phase_finish() { echo "end:$1"; }
private_cloud_upload_phase finish
'''
            result = subprocess.run(['sh', '-c', script, 'inert', str(SCRIPT), temporary],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'begin:cloud-upload-finish\nend:9\n')
            self.assertEqual((Path(temporary) / 'cloud-upload-finish.json').read_text(),
                f'finish {temporary}/u/a {temporary}/runtime-exit/control/agent.sock {temporary}/client-fixtures/private-storage-user\n')

    def test_failure_keeps_primary_phase_and_skips_successful_capture_finish(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = '''. "$1"
WORK=$2; upload_user=$WORK/u/a; storage_user=$WORK/client-fixtures/private-storage-user
fail() { echo "$1"; exit 1; }
private_cloud_upload_private() { if [ "$1" = flow-minimum ]; then echo 24; else return 1; fi; }
private_storage_fragments_phase_start() { :; }
private_storage_fragments_phase_finish() { echo FALSE_SUCCESS; }
private_cloud_upload_phase upload
'''
            result = subprocess.run(['sh', '-c', script, 'inert', str(SCRIPT), temporary],
                capture_output=True, text=True, timeout=5)
            self.assertEqual((result.returncode, result.stdout.strip()), (1, 'CLOUD_UPLOAD_APPLICATION_FAILED'))

    def test_real_sequence_uses_same_stores_zero_gate_and_new_mount_probe(self):
        tokens = ['CLOUD_UPLOAD_INITIAL_STORE_NOT_EMPTY', 'upload_user=$WORK/u/a',
            'CLOUD_UPLOAD_POSITIVE_ISOLATION_FAILED', 'CLOUD_UPLOAD_LOCAL_SHORTCUT',
            'private_cloud_upload_private prepare', 'private_cloud_upload_phase upload',
            'private_storage_fragments_usage cloud_upload_uploaded_usage',
            'private_storage_fragments_reopen relay5 relay3', 'CLOUD_UPLOAD_SOURCE_STILL_SERVING',
            'private_cloud_upload_phase exercise', 'private_storage_fragments_usage cloud_upload_restored_usage',
            'private_cloud_upload_phase finish', 'private_storage_fragments_usage cloud_upload_deleted_usage',
            'CLOUD_UPLOAD_PROVIDER_CLEANUP_INCOMPLETE', 'private_cloud_upload_cleanup ||',
            'evidence "$WORK" "$WORK/cloud-upload-evidence.json"']
        offsets = [SOURCE.index(token) for token in tokens]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn('runtime-client/control/agent.sock', SOURCE)
        self.assertIn('--bounding-set=-all --no-new-privs', SOURCE)
        self.assertIn('--signal=TERM --kill-after=30s 2400s', SOURCE)
        self.assertNotIn('rm -rf', SOURCE)
        self.assertNotIn('storage-consumer-maintenance-provision.py', SOURCE)

    def test_cleanup_idempotent_and_preserves_unknown_sibling(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / 'u').mkdir()
            (work / 'u/sibling').mkdir()
            script = '''. "$1"
WORK=$2; upload_user=$WORK/u/a
private_cloud_upload_private() { echo '{}'; }
private_cloud_upload_cleanup
'''
            result = subprocess.run(['sh', '-c', script, 'inert', str(SCRIPT), temporary],
                capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((work / 'u/sibling').exists())
            (work / 'u/sibling').rmdir()
            result = subprocess.run(['sh', '-c', script + '\nprivate_cloud_upload_cleanup\n', 'inert', str(SCRIPT), temporary],
                capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((work / 'u').exists())

    def test_exact_static_proof_union_is_measured_before_runner_wiring(self):
        previous = runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))['EXPORT_NAMES']
        self.assertEqual(len(set(previous)), 95)
        self.assertEqual(len(set(E['EXPORT_NAMES']) - set(previous)), 40)
        self.assertEqual(len(set(E['EXPORT_NAMES']) | set(previous)), 135)
        # This deliberately excludes emergency driver/current-phase/duplicate
        # receipts; it is NOT a claim that all recovery files fit that cap.
        self.assertNotIn('guest-phase.txt', E['EXPORT_NAMES'])

    def test_kvm_opt_in_preview_and_last_scenario_wins_without_running_it(self):
        guest = HERE / 'kvm-alpha-topology.sh'
        for first, last in (('private-storage-maintenance', 'cloud-upload-maintenance'),
                ('cloud-upload-maintenance', 'private-storage-maintenance')):
            result = subprocess.run(['sh', str(guest), '--preview', '--scenario', first, '--scenario', last],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(last + ' protected network smoke plan:', result.stdout)
            self.assertNotIn(first + ' protected network smoke plan:', result.stdout)
            self.assertIn('PREVIEW ONLY', result.stdout)

    def test_exact_new_closure_preflight_and_new_capture_gate(self):
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        start = guest.index('if [ "$cloud_upload_maintenance" = yes ]; then\n    for upload_fixture')
        block = guest[start:guest.index('\nfi', start) + 3]
        names = ('cloud-upload-maintenance-smoke.sh', 'cloud-upload-maintenance-smoke.py',
            'cloud-upload-maintenance.mjs', 'cloud-upload-maintenance-pins.json',
            'cloud-upload-maintenance-evidence.py', 'cloud-upload-maintenance-provision.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / 'tests/integration'
            target.mkdir(parents=True)
            for name in names:
                (target / name).touch()
            def check():
                return subprocess.run(['sh', '-c', 'source_directory=$1; cloud_upload_maintenance=yes;\n' + block,
                    'inert', str(root)], capture_output=True, timeout=5).returncode
            self.assertEqual(check(), 0)
            for name in names:
                path = target / name
                path.unlink()
                self.assertEqual(check(), 69)
                path.symlink_to(target / names[(names.index(name) + 1) % len(names)])
                self.assertEqual(check(), 69)
                path.unlink(); path.touch()
        privacy = 'private-storage-fragments-cloud-upload-upload-privacy|private-storage-fragments-cloud-upload-exercise-privacy|private-storage-fragments-cloud-upload-finish-privacy)\n            [ "$cloud_upload_maintenance" = yes ] || return 1 ;;'
        self.assertIn(privacy, guest)

    def test_hook_follows_old_consumer_before_disconnect_and_cleanup_is_early(self):
        fragments = (HERE / 'private-storage-fragments-smoke.sh').read_text()
        self.assertIn('private_storage_consumer_run\n        if [ "${cloud_upload_maintenance:-no}" = yes ]; then\n            private_cloud_upload_run\n        fi', fragments)
        self.assertLess(fragments.index('            private_cloud_upload_run\n'), fragments.index('    benchmark_disconnect_route private-storage-fragments'))
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        self.assertLess(guest.index('        private_cloud_upload_cleanup || original_status=1'),
            guest.index('        private_storage_fragments_cleanup || original_status=1'))
        self.assertIn('private_storage_maintenance_finalize_report "$original_status" || original_status=1\n        if [ "$cloud_upload_maintenance" = yes ]; then\n            private_cloud_upload_finalize_report "$original_status" || original_status=1', guest)
        self.assertIn('cloud-upload-maintenance-smoke.sh"', guest)
        self.assertIn('cloud-upload-maintenance-pins.json"', guest)


if __name__ == '__main__':
    unittest.main()
