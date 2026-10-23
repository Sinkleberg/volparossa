#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic inert ZIP/API tests only; these archives are never demo acceptance."""
import hashlib
import importlib.util
import io
import json
import os
import signal
from pathlib import Path
import stat
import tempfile
import sys
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('demo_review', ROOT / 'scripts/weather-demo-0-review.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
CORE = 'a' * 40
REVIEW_CORE = 'b' * 40
IDENTITY = dict(core_commit=CORE, weather_commit=R.WEATHER, run_id='123', run_attempt='2')
ENV = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux',
           GITHUB_REPOSITORY=R.REPOSITORY, GITHUB_SHA=REVIEW_CORE, GITHUB_RUN_ID='456', GITHUB_RUN_ATTEMPT='1')


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def record(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class Review(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='inert-demo-review-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def metadata(self):
        run = dict(id=123, run_attempt=2, head_sha=CORE, status='completed', conclusion='success',
                   repository=dict(full_name=R.REPOSITORY), head_repository=dict(full_name=R.REPOSITORY),
                   run_started_at='2026-10-23T12:00:00Z', updated_at='2026-10-23T13:00:00Z')
        artifact = dict(id=7, name='weather-demo-review-' + CORE, expired=False, size_in_bytes=42,
                        digest='sha256:' + 'c' * 64, workflow_run=dict(id=123, head_sha=CORE),
                        created_at='2026-10-23T12:58:00Z', updated_at='2026-10-23T12:59:00Z')
        listing = dict(total_count=1, artifacts=[artifact])
        return run, artifact, listing

    def fixture(self, *, alter=None, extra=None):
        # Deliberately synthetic bytes; original verifier is mocked, never admitted as real media.
        acceptance = dict(identity=IDENTITY, passed=True, joined_core_acceptance=True,
                          vm_cleanup_pending=False, production_authority=False)
        raw = b'not a video; synthetic unit fixture only'
        video = dict(codec='h264', width=720, height=1280, duration_seconds=3.0, has_audio=False)
        media = dict(identity=IDENTITY, joined_core_acceptance=True, production_authority=False,
                     files={'screen.mp4': record(raw)}, video=video,
                     acceptance_sha256=record(encoded(acceptance))['sha256'])
        files = {name: encoded(acceptance if name == 'weather-android-hosted-acceptance.json'
                               else {'synthetic': 'not runtime evidence'}) for name in R.REPORTS}
        files.update({'demo-media/recording.json': encoded(media), 'demo-media/screen.mp4': raw,
                      'demo-media/screen-001.png': b'synthetic not actual PNG', 'README.md': b'document'})
        presentation = dict(schema=1, kind='weather-demo-unpublished-presentation', identity=IDENTITY,
            actual_app_pixels=True, external_core=True, physical_device=False, production_authority=False,
            publication_authorized=False, includes_installable_binaries=False, visual_review_required=True,
            files={name: record(data) for name, data in files.items()},
            acceptance_sha256=media['acceptance_sha256'], recording_sha256=record(raw)['sha256'],
            # Actual producer video_info() selects these four fields; has_audio
            # belongs to the separate original media verifier's contract.
            original_video={key: video[key] for key in ('codec', 'width', 'height', 'duration_seconds')})
        if alter:
            alter(presentation, files)
        archive_path = self.root / 'review.zip'
        with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(R.PREFIX + name, data)
            archive.writestr(R.PREFIX + 'presentation.json', encoded(presentation))
            archive.writestr(R.PREFIX + 'SHA256SUMS', b'not relied upon')
            archive.writestr('weather-demo-sources/core-source.tar.gz', b'not extracted')
            if extra:
                extra(archive)
        return archive_path, presentation, media

    def test_preview_readonly_and_strict_arguments(self):
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'api') as api:
            result = R.prepare('123', '2', CORE, self.root / 'output')
            self.assertFalse(result['executed'])
            self.assertFalse((self.root / 'output').exists())
            api.assert_not_called()
            for run_id, attempt, sha in [('0', '1', CORE), ('123', '-1', CORE),
                                          ('123/zip', '2', CORE), ('123', '2', 'A' * 40)]:
                with self.subTest(values=(run_id, attempt, sha)), self.assertRaises(ValueError):
                    R.prepare(run_id, attempt, sha, self.root / 'output')
            for output in [self.root, self.root.parent / 'outside', self.root / '.git/out',
                           self.root / 'missing/out', Path('relative')]:
                with self.subTest(output=output), self.assertRaises(ValueError):
                    R.prepare('123', '2', CORE, output)

    def test_execute_rejects_local_host_before_network_or_write(self):
        with patch.object(R, 'ROOT', self.root), patch.dict(os.environ, {}, clear=True), \
                patch.object(R, 'api') as api:
            with self.assertRaises(ValueError):
                R.prepare('123', '2', CORE, self.root / 'output', execute=True)
            self.assertFalse((self.root / 'output').exists())
            api.assert_not_called()

    def test_run_and_artifact_exact_latest_attempt(self):
        run, artifact, listing = self.metadata()
        with patch.object(R, 'api', side_effect=[run, run, listing]) as api:
            selected = R.selected_artifact('123', '2', CORE)
            self.assertEqual(selected['id'], 7)
            self.assertEqual([call.args[0] for call in api.call_args_list], [
                'repos/VOLPAROSSA/volparossa/actions/runs/123',
                'repos/VOLPAROSSA/volparossa/actions/runs/123/attempts/2',
                'repos/VOLPAROSSA/volparossa/actions/runs/123/artifacts?per_page=100'])
        for key, value in [('conclusion', 'failure'), ('status', 'in_progress'),
                           ('head_sha', REVIEW_CORE), ('run_attempt', 3)]:
            invalid = {**run, key: value}
            with self.subTest(key=key), patch.object(R, 'api', side_effect=[invalid, run]), \
                    self.assertRaises(ValueError):
                R.selected_artifact('123', '2', CORE)
        invalids = [dict(artifact, expired=True), dict(artifact, digest=None),
                    dict(artifact, size_in_bytes=R.MAX_ZIP + 1),
                    dict(artifact, created_at='2026-10-23T11:59:59Z'),
                    dict(artifact, workflow_run=dict(id=123, head_sha=REVIEW_CORE))]
        for invalid in invalids:
            with patch.object(R, 'api', side_effect=[run, run, dict(total_count=1, artifacts=[invalid])]), \
                    self.assertRaises(ValueError):
                R.selected_artifact('123', '2', CORE)
        with patch.object(R, 'api', side_effect=[run, run, dict(total_count=101, artifacts=[artifact])]), \
                self.assertRaises(ValueError):
            R.selected_artifact('123', '2', CORE)

    def test_download_exact_endpoint_size_and_digest(self):
        payload = b'synthetic ZIP boundary payload'
        artifact = dict(id=7, size_in_bytes=len(payload), digest='sha256:' + record(payload)['sha256'])
        def write(args, **kwargs):
            self.assertEqual(args, ['/usr/bin/gh', 'api', '--method', 'GET',
                'repos/VOLPAROSSA/volparossa/actions/artifacts/7/zip'])
            kwargs['destination'].write_bytes(payload)
        with patch.object(R, 'tool', side_effect=str), patch.object(R, 'command', side_effect=write):
            R.download(artifact, self.root / 'valid.zip')
            with self.assertRaises(ValueError):
                R.download(dict(artifact, digest='sha256:' + '0' * 64), self.root / 'bad.zip')
            with self.assertRaises(ValueError):
                R.download(dict(artifact, size_in_bytes=1), self.root / 'wrong-size.zip')

    def test_subset_extraction_and_original_identity_do_not_fake_environment(self):
        archive, presentation, media = self.fixture()
        destination = self.root / 'evidence'
        def verify(path):
            self.assertEqual(os.environ['GITHUB_SHA'], REVIEW_CORE)
            self.assertEqual(os.environ['GITHUB_RUN_ID'], '456')
            self.assertNotIn('GH_TOKEN', os.environ)
            self.assertEqual(path, destination)
            return media
        with patch.dict(os.environ, {**ENV, 'GH_TOKEN': 'private synthetic token'}, clear=True), \
                patch.object(R.runpy, 'run_path', return_value={'verify': verify}):
            result = R.evidence(archive, destination, IDENTITY)
            self.assertEqual(os.environ['GH_TOKEN'], 'private synthetic token')
        self.assertEqual(result[0], presentation)
        self.assertFalse((destination / 'README.md').exists())
        self.assertFalse((destination / 'core-source.tar.gz').exists())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual((destination / 'demo-media/screen.mp4').stat().st_mode & 0o777, 0o600)
        self.assertEqual({p.name for p in (destination / 'demo-media').iterdir()},
                         {'screen.mp4', 'screen-001.png', 'recording.json'})

    def test_hash_mismatch_unselected_member_is_also_rejected(self):
        def alter(_, files):
            files['README.md'] = b'tampered document outside extracted subset'
        archive, _, _ = self.fixture(alter=alter)
        with patch.object(R.runpy, 'run_path') as verifier, self.assertRaisesRegex(ValueError, 'hash mismatch'):
            R.evidence(archive, self.root / 'evidence', IDENTITY)
        verifier.assert_not_called()

    def test_identity_and_original_verifier_failure_stop_render(self):
        archive, _, media = self.fixture()
        with self.assertRaisesRegex(ValueError, 'identity'):
            R.evidence(archive, self.root / 'wrong', dict(IDENTITY, weather_commit='c' * 40))
        def rejected(_):
            raise ValueError('synthetic original validator rejection')
        with patch.object(R.runpy, 'run_path', return_value={'verify': rejected}), \
                self.assertRaisesRegex(ValueError, 'original validator'):
            R.evidence(archive, self.root / 'evidence', IDENTITY)

    def test_zip_rejects_traversal_duplicates_symlinks_and_unknown_roots(self):
        for name in ['../escape', '/absolute', 'weather-demo-presentation/../escape',
                     'weather-demo-presentation//file', 'weather-demo-presentation/./file',
                     'weather-demo-presentation/back\\slash', 'other/file']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                R.canonical_name(name)
        for kind in ['symlink', 'duplicate', 'oversize']:
            path = self.root / (kind + '.zip')
            with zipfile.ZipFile(path, 'w') as archive:
                if kind == 'symlink':
                    info = zipfile.ZipInfo(R.PREFIX + 'link')
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(info, '/tmp/outside')
                else:
                    archive.writestr(R.PREFIX + 'file', b'fixture')
                    if kind == 'duplicate':
                        # The canonical-key collision also covers file-vs-directory duplicates.
                        archive.writestr(R.PREFIX + 'file/', b'')
            with zipfile.ZipFile(path) as archive:
                if kind == 'oversize':
                    archive.infolist()[0].file_size = R.MAX_ZIP + 1
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    R.zip_entries(archive)

    def test_cleanup_failure_record_retains_both_source_identities(self):
        output = self.root / 'output'
        def failed_download(_, path):
            path.write_bytes(b'partial inert download')
            R.STATE['stage'] = 'artifact-download'
            raise ValueError('private synthetic exception with path and credentials')
        with patch.object(R, 'ROOT', self.root), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R.os, 'getuid', return_value=1000), patch.object(R.os, 'geteuid', return_value=1000), \
                patch.object(R, 'selected_artifact', return_value={}), \
                patch.object(R, 'download', side_effect=failed_download), self.assertRaises(ValueError):
            R.prepare('123', '2', CORE, output, execute=True)
        self.assertEqual([p.name for p in output.iterdir()], ['review-failure.json'])
        failure = json.loads((output / 'review-failure.json').read_text())
        self.assertEqual(failure['identity']['core_commit'], CORE)
        self.assertEqual(failure['review_execution']['core_commit'], REVIEW_CORE)
        self.assertTrue(failure['partial_output_removed'])
        self.assertEqual(failure['stage'], 'artifact-download')
        self.assertFalse(failure['visual_acceptance_claimed'])
        self.assertEqual(failure['category'], 'value')
        self.assertNotIn('private synthetic', (output / 'review-failure.json').read_text())
        self.assertNotIn('reason', failure)

    def test_success_separates_packaging_identity_and_no_runtime_claim(self):
        output = self.root / 'output'
        original_archive, presentation, media = self.fixture()
        def downloaded(_, path):
            path.write_bytes(original_archive.read_bytes())
        def render(_, root, __):
            (root / 'contact-00.png').write_bytes(b'synthetic renderer stub, never real pixels')
            return {'sampled_frames': 1}
        with patch.object(R, 'ROOT', self.root), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R.os, 'getuid', return_value=1000), patch.object(R.os, 'geteuid', return_value=1000), \
                patch.object(R, 'selected_artifact', return_value={'id': 7}), \
                patch.object(R, 'download', side_effect=downloaded), \
                patch.object(R, 'evidence', return_value=(presentation, media, 'c' * 64)), \
                patch.object(R, 'contact_sheets', side_effect=render):
            result = R.prepare('123', '2', CORE, output, execute=True)
        self.assertEqual(result['identity'], IDENTITY)
        self.assertEqual(result['review_execution']['core_commit'], REVIEW_CORE)
        self.assertFalse(result['new_runtime_executed'])
        self.assertNotIn('revised_presentation', result)
        self.assertFalse(result['visual_acceptance_claimed'])
        self.assertFalse((output / 'review.zip').exists())
        self.assertTrue((output / 'review.json').exists())

    def held_fixture(self):
        original = self.root / 'original'
        (original / 'demo-media').mkdir(parents=True)
        raw = b'inert original clip; not runtime media'
        png = (b'\x89PNG\r\n\x1a\n' + b'\0\0\0\rIHDR' +
               (1080).to_bytes(4, 'big') + (1920).to_bytes(4, 'big') + b'synthetic fixture')
        (original / 'demo-media/screen.mp4').write_bytes(raw)
        (original / 'demo-media/screen-003.png').write_bytes(png)
        acceptance = dict(identity=IDENTITY, passed=True,
            observations=dict(products=dict(weather=dict(cold_peer_bytes=12), air_quality=dict(cold_peer_bytes=34))))
        (original / 'weather-android-hosted-acceptance.json').write_bytes(encoded(acceptance))
        media = dict(identity=IDENTITY, acceptance_sha256=record(encoded(acceptance))['sha256'],
            files={'screen.mp4': record(raw), 'screen-003.png': record(png)},
            video=dict(codec='h264', width=720, height=1280, duration_seconds=75.0, has_audio=False))
        output = self.root / 'rendered'
        output.mkdir()
        return original, output, media

    def test_optional_hold_rejects_paths_and_only_accepts_explicit_basename(self):
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'api') as api:
            for name in ['../screen-003.png', '/screen-003.png', 'screen-3.png', 'samples/frame-003.png',
                         'screen-003.png:movie', 'screen-003.png\n']:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    R.prepare('123', '2', CORE, self.root / 'out', hold_image=name)
            preview = R.prepare('123', '2', CORE, self.root / 'out', hold_image='screen-003.png')
            self.assertEqual(preview['held_image_requested'], 'screen-003.png')
            self.assertFalse(preview['executed'])
            api.assert_not_called()

    def test_selected_genuine_image_hash_identity_and_render_contract(self):
        original, output, media = self.held_fixture()
        def lines(identity, products):
            self.assertEqual(identity, IDENTITY)
            self.assertEqual(products['weather']['cold_peer_bytes'], 12)
            return [('completed run', 20, 'ffffff')]
        def render(raw, stage, duration, raw_info, panel, *, hold_image):
            self.assertEqual(raw, original / 'demo-media/screen.mp4')
            self.assertEqual(hold_image, original / 'demo-media/screen-003.png')
            self.assertEqual(raw_info['duration_seconds'], 75.0)
            self.assertEqual(duration, 120)
            self.assertEqual(os.environ['GITHUB_SHA'], REVIEW_CORE)
            (stage / 'weather-demo-0.mp4').write_bytes(b'synthetic renderer output')
            return stage / 'weather-demo-0.mp4', dict(duration_seconds=120)
        package = dict(presentation_lines=lines, render_video=render,
                       captions=lambda *args, **kwargs: ('held captions', 'held transcript'))
        with patch.dict(os.environ, ENV, clear=True), patch.object(R, 'tool', side_effect=str), \
                patch.object(R.runpy, 'run_path', return_value=package):
            result = R.render_held_image(original, output, media, 'screen-003.png')
        self.assertEqual(result['identity'], IDENTITY)
        self.assertEqual(result['held_image'], dict(file='screen-003.png', **media['files']['screen-003.png']))
        self.assertTrue(result['edits']['full_original_clip'])
        self.assertFalse(result['edits']['raw_clip_trimmed'])
        self.assertEqual(result['edits']['held_frame_after_seconds'], 75)
        self.assertTrue(result['visual_review_required'])
        self.assertFalse(result['publication_authorized'])
        self.assertEqual((output / 'transcript.txt').read_text(), 'held transcript')

    def test_fractional_raw_duration_has_a_full_held_second_or_rejects_bound(self):
        original, output, media = self.held_fixture()
        calls = []
        def render(raw, stage, duration, raw_info, panel, *, hold_image):
            calls.append((duration, raw_info['duration_seconds']))
            (stage / 'weather-demo-0.mp4').write_bytes(b'synthetic render output')
            return stage / 'weather-demo-0.mp4', dict(duration_seconds=duration)
        package = dict(presentation_lines=lambda *_: [], render_video=render,
                       captions=lambda *args, **kwargs: ('captions', 'transcript'))
        with patch.object(R, 'tool', side_effect=str), patch.object(R.runpy, 'run_path', return_value=package):
            media['video']['duration_seconds'] = 119.999
            result = R.render_held_image(original, output, media, 'screen-003.png')
            self.assertEqual(calls, [(121, 119.999)])
            self.assertGreaterEqual(result['video']['duration_seconds'] - 119.999, 1)
            self.assertEqual(result['edits']['held_frame_after_seconds'], 119.999)
            self.assertTrue(result['edits']['full_original_clip'])
            media['video']['duration_seconds'] = 179.999
            with self.assertRaisesRegex(ValueError, 'bounded presentation duration'):
                R.render_held_image(original, output, media, 'screen-003.png')
            self.assertEqual(len(calls), 1)

    def test_held_selection_rejects_missing_hash_dimension_or_runtime_binding(self):
        original, output, media = self.held_fixture()
        with patch.object(R.runpy, 'run_path') as renderer:
            with self.assertRaises(ValueError):
                R.render_held_image(original, output, media, 'screen-004.png')
            media['files']['screen-003.png']['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                R.render_held_image(original, output, media, 'screen-003.png')
            image = original / 'demo-media/screen-003.png'
            image.write_bytes(b'wrong dimensions')
            media['files']['screen-003.png'] = record(image.read_bytes())
            with self.assertRaisesRegex(ValueError, 'dimensions'):
                R.render_held_image(original, output, media, 'screen-003.png')
            renderer.assert_not_called()

    def test_held_renderer_rejects_changed_runtime_identity_before_native_work(self):
        original, output, media = self.held_fixture()
        acceptance_path = original / 'weather-android-hosted-acceptance.json'
        acceptance = json.loads(acceptance_path.read_bytes())
        acceptance['identity'] = dict(IDENTITY, core_commit=REVIEW_CORE)
        acceptance_path.write_bytes(encoded(acceptance))
        media['acceptance_sha256'] = record(encoded(acceptance))['sha256']
        with patch.object(R.runpy, 'run_path') as renderer, patch.object(R, 'tool') as tool:
            with self.assertRaisesRegex(ValueError, 'acceptance binding'):
                R.render_held_image(original, output, media, 'screen-003.png')
            renderer.assert_not_called()
            tool.assert_not_called()

    def test_optional_renderer_is_only_called_after_original_acceptance(self):
        output = self.root / 'output'
        original_archive, presentation, media = self.fixture()
        order = []
        def accepted(*_):
            order.append('accepted')
            return presentation, media, 'c' * 64
        def revised(original, stage, selected_media, basename):
            self.assertEqual(order, ['accepted'])
            self.assertEqual(original, output / 'original')
            self.assertEqual(selected_media, media)
            self.assertEqual(basename, 'screen-003.png')
            return dict(identity=IDENTITY, held_image=dict(file=basename), visual_review_required=True)
        with patch.object(R, 'ROOT', self.root), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R.os, 'getuid', return_value=1000), patch.object(R.os, 'geteuid', return_value=1000), \
                patch.object(R, 'selected_artifact', return_value={'id': 7}), \
                patch.object(R, 'download', side_effect=lambda _, path: path.write_bytes(original_archive.read_bytes())), \
                patch.object(R, 'evidence', side_effect=accepted), \
                patch.object(R, 'contact_sheets', return_value={}), \
                patch.object(R, 'render_held_image', side_effect=revised):
            result = R.prepare('123', '2', CORE, output, execute=True, hold_image='screen-003.png')
        self.assertEqual(result['review_execution']['core_commit'], REVIEW_CORE)
        self.assertEqual(result['revised_presentation']['identity']['core_commit'], CORE)
        self.assertFalse(result['visual_acceptance_claimed'])

    def test_sampling_commands_use_only_fixed_tools_and_original_video(self):
        evidence = self.root / 'evidence'
        evidence.mkdir()
        output = self.root / 'render'
        output.mkdir()
        font = self.root / 'font-data'
        font.write_bytes(b'inert font data')
        calls = []
        def render(args, **kwargs):
            calls.append(args)
            if '-start_number' in args and str(args[-1]).endswith('frame-%03d.png'):
                for i in range(3):
                    (output / 'samples' / f'frame-{i:03d}.png').write_bytes(b'synthetic stub PNG')
            else:
                Path(args[-1]).write_bytes(b'synthetic sheet stub')
        with patch.object(R, 'tool', side_effect=str), patch.object(R, 'command', side_effect=render), \
                patch.object(R, 'FONT', font):
            result = R.contact_sheets(evidence, output, dict(video=dict(duration_seconds=3.0)))
        self.assertEqual(result['poster_source'], 'samples/frame-001.png')
        self.assertTrue(all(args[0] == '/usr/bin/ffmpeg' for args in calls))
        self.assertIn(str(evidence / 'demo-media/screen.mp4'), calls[0])
        self.assertIn('file,pipe', calls[0])
        self.assertFalse(result['synthesized_app_pixels'])
        self.assertEqual((output / 'poster.png').read_bytes(), (output / 'samples/frame-001.png').read_bytes())

    def test_child_pipe_limits_timeout_and_failure_diagnostics(self):
        output = R.command([sys.executable, '-c', "print('inert child')"], maximum=100)
        self.assertEqual(output, b'inert child\n')
        with self.assertRaisesRegex(ValueError, 'output limit'):
            R.command([sys.executable, '-c', "print('x' * 1000)"], maximum=100)
        with self.assertRaisesRegex(ValueError, 'timeout'):
            R.command([sys.executable, '-c', 'import time; time.sleep(2)'], seconds=0.01)
        with self.assertRaises(R.ChildFailure) as failure:
            R.command([sys.executable, '-c', "import sys; sys.stderr.write('synthetic stderr'); sys.exit(3)"])
        self.assertEqual(failure.exception.status, 3)
        self.assertFalse(hasattr(failure.exception, 'diagnostics'))
        self.assertNotIn('synthetic stderr', str(failure.exception))

    def test_non_api_children_do_not_receive_github_token(self):
        with patch.dict(os.environ, {'GH_TOKEN': 'private synthetic token'}):
            result = R.command([sys.executable, '-c', "import os; print(os.getenv('GH_TOKEN', 'absent'))"])
        self.assertEqual(result, b'absent\n')

    def test_cli_sigterm_becomes_cleanup_exception_and_restores_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        def interrupted_prepare(*_):
            os.kill(os.getpid(), signal.SIGTERM)
            self.fail('SIGTERM did not interrupt execution')
        argv = ['--run-id', '123', '--attempt', '2', '--core-revision', CORE,
                '--output', str(self.root / 'interrupted'), '--execute']
        with patch.object(R, 'prepare', side_effect=interrupted_prepare), patch.object(sys, 'stderr', io.StringIO()):
            self.assertEqual(R.main(argv), 1)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_duplicate_json_keys_are_not_silently_accepted(self):
        with self.assertRaises(ValueError):
            R.decode(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            R.decode(b'{"a":NaN}')


if __name__ == '__main__':
    unittest.main()
