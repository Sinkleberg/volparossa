#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert, explicitly synthetic timing/container fixtures; never real acceptance."""
from fractions import Fraction
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('native_timing', HERE / 'weather-demo-native-timing.py')
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)


def atom(kind, body, wide=False):
    return (struct.pack('>I4sQ', 1, kind, 16 + len(body)) if wide
        else struct.pack('>I4s', 8 + len(body), kind)) + body


def fixture():
    """Three opaque pretend video packets; only native boundary is mocked."""
    points = [0, 40, 80]
    legacy = T.LEGACY + struct.pack('<I3Q', 3, 10000000, 10040000, 10080000)
    v2 = T.V2 + struct.pack('<IqI3Q', 2, -123, 3, 10000000000, 10040000000, 10080000000)
    prefix = atom(b'ftyp', b'isom0000')
    video_data = b'aaaabbbbcccc'
    pos = len(prefix) + 8
    legacy_pos, v2_pos = pos + len(video_data), pos + len(video_data) + len(legacy)
    movie = atom(b'moov', atom(b'mvhd', bytes(12) + struct.pack('>II', 1000, 120)))
    raw = prefix + atom(b'mdat', video_data + legacy + v2) + movie
    streams = [dict(index=0, codec_type='video', codec_name='h264', codec_tag_string='avc1',
        width=720, height=1280, time_base='1/1000', start_pts=0, duration_ts=120, nb_frames='3')]
    streams += [dict(index=i, codec_type='data', codec_tag_string='mett', time_base='1/1000',
        start_pts=0, duration_ts=0, nb_frames='1') for i in (1, 2)]
    packets = [dict(stream_index=0, pts=point, duration=40, pos=str(pos + i * 4), size='4')
        for i, point in enumerate(points)]
    packets += [dict(stream_index=i, pts=0, pos=str(offset), size=str(len(body)))
        for i, offset, body in ((1, legacy_pos, legacy), (2, v2_pos, v2))]
    frames = [dict(stream_index=0, pts=point, best_effort_timestamp=point, pkt_duration=40,
        pkt_pos=str(pos + i * 4), pkt_size='4') for i, point in enumerate(points)]
    timeline = dict(schema=1, kind='weather-demo-source-video-frame-timeline', source_video_sha256=T.sha(raw),
        frames=[dict(frame_index=i, source_pts_seconds=point / 1000, clip_relative_pts_seconds=point / 1000,
            pts_time=point / 1000, best_effort_timestamp_time=point / 1000, pkt_duration_time=0.04)
            for i, point in enumerate(points)], timestamp_domain='synthetic', video_duration_seconds=0.12)
    return raw, dict(streams=streams, packets=packets, programs=[], format=dict(duration='0.120000')), dict(frames=frames), timeline


class Timing(unittest.TestCase):
    def check(self, values=None):
        return T.coherence(*(fixture() if values is None else values), '6.1.1-3ubuntu5')

    def rejected(self, change, code=None):
        values = list(fixture())
        change(values)
        with self.assertRaisesRegex(ValueError, 'native_timing_' + (code or '[a-z_]+')):
            self.check(values)

    def test_synthetic_coherence_separate_authority_flags(self):
        raw, packets, frames, timeline = fixture()
        report = self.check((raw, packets, frames, timeline))
        self.assertTrue(report['technical_coherence_passed'])
        for key in ('visual_acceptance_claimed', 'media_accepted', 'publication_authorized', 'production_authority',
                    'host_wall_clock_coverage_claimed', 'exact_os_action_timestamps_claimed'):
            self.assertIs(report[key], False)
        self.assertEqual(report['video_packet_count'], 3)
        self.assertEqual(report['source_video_sha256'], T.sha(raw))
        self.assertEqual(report['relative_elapsed_span_seconds'], T.rational(Fraction(2, 25)))
        self.assertEqual(report['max_relative_pts_elapsed_error_seconds'], T.rational(Fraction(0)))
        self.assertEqual(report['derived_pts_error_bound_seconds'], T.rational(Fraction(1, 1000)))
        self.assertEqual({row['kind'] for row in report['metadata_tracks']}, {'legacy', 'v2'})
        for row in report['metadata_tracks']:
            body = raw[row['packet_offset']:row['packet_offset'] + row['packet_bytes']]
            self.assertEqual(row['packet_sha256'], T.sha(body))
        self.assertNotIn('offset', json.dumps(report).replace('packet_offset', ''))
        json.dumps(report, allow_nan=False)

    def test_payload_magic_version_lengths_counts_order(self):
        valid = T.V2 + struct.pack('<IqI3Q', 2, 0, 3, 1000, 2000, 3000)
        for bad in (b'junk' + valid, valid[:20], valid + b'\x00', valid[:-1],
                T.V2 + struct.pack('<IqI3Q', 3, 0, 3, 1000, 2000, 3000),
                T.V2 + struct.pack('<IqI3Q', 2, 0, 4, 1000, 2000, 3000),
                T.V2 + struct.pack('<IqI3Q', 2, 0, 3, 1000, 1000, 3000),
                T.V2 + struct.pack('<IqI3Q', 2, 0, 3, 1000, 3000, 2000),
                T.LEGACY + struct.pack('<I', 0),
                T.LEGACY + struct.pack('<I', T.MAX_FRAMES + 1)):
            with self.subTest(length=len(bad)), self.assertRaisesRegex(ValueError, 'native_timing_'):
                T.payload(bad)
        self.assertEqual(len(T.LEGACY), 16)
        self.assertEqual(len(T.V2), 16)

    def test_magic_outside_packet_cannot_supply_metadata(self):
        def change(v):
            raw, report, _, timeline = v
            packet = report['packets'][3]
            pos = int(packet['pos'])
            v[0] = raw[:pos] + b'!' * int(packet['size']) + raw[pos + int(packet['size']):]
            timeline['source_video_sha256'] = T.sha(v[0])
        self.rejected(change, 'metadata_magic')

    def test_metadata_relative_disagreement(self):
        def change(v):
            p = v[1]['packets'][4]
            start = int(p['pos']) + 32 + 8
            v[0] = v[0][:start] + struct.pack('<Q', 10040001000) + v[0][start + 8:]
            v[3]['source_video_sha256'] = T.sha(v[0])
        self.rejected(change, 'metadata_relative_disagreement')

    def test_video_ticks_disagree_with_elapsed(self):
        def change(v):
            v[1]['packets'][1]['pts'] = 50
            v[1]['packets'][0]['duration'] = 50
            v[1]['packets'][1]['duration'] = 30
            v[2]['frames'][1].update(pts=50, best_effort_timestamp=50, pkt_duration=30)
            v[2]['frames'][0]['pkt_duration'] = 50
        self.rejected(change, 'elapsed_pts_disagreement')

    def test_90000_timescale_one_derived_tick_bound(self):
        values = list(fixture())
        report, frames, timeline = values[1:]
        report['streams'][0].update(time_base='1/90000', duration_ts=10800)
        points, durations = [0, 3601, 7200], [3601, 3599, 3600]
        for index, (point, duration) in enumerate(zip(points, durations)):
            report['packets'][index].update(pts=point, duration=duration)
            frames['frames'][index].update(pts=point, best_effort_timestamp=point, pkt_duration=duration)
            timeline['frames'][index].update(source_pts_seconds=round(point / 90000, 6),
                clip_relative_pts_seconds=round(point / 90000, 6), pts_time=round(point / 90000, 6),
                best_effort_timestamp_time=round(point / 90000, 6), pkt_duration_time=round(duration / 90000, 6))
        result = self.check(values)
        self.assertEqual(result['max_relative_pts_elapsed_error_seconds'], T.rational(Fraction(1, 90000)))
        self.assertEqual(result['derived_pts_error_bound_seconds'], T.rational(Fraction(1, 90000)))
        report['packets'][0]['duration'] += 1
        report['packets'][1].update(pts=3602, duration=3598)
        frames['frames'][0]['pkt_duration'] += 1
        frames['frames'][1].update(pts=3602, best_effort_timestamp=3602, pkt_duration=3598)
        with self.assertRaisesRegex(ValueError, 'native_timing_elapsed_pts_disagreement'):
            self.check(values)

    def test_packet_position_size_mdat_overlap(self):
        for key, value in (('pos', '0'), ('pos', '999999'), ('size', '999999'), ('size', '0')):
            self.rejected(lambda v, k=key, x=value: v[1]['packets'][3].update({k: x}))
        self.rejected(lambda v: v[1]['packets'][3].update(pos=v[1]['packets'][4]['pos']), 'packet_overlap')
        self.rejected(lambda v: v[1]['packets'][0].update(pos=str(int(v[1]['packets'][3]['pos']) + 1)), 'packet_overlap')

    def test_track_profiles_missing_duplicate_audio_unknown(self):
        self.rejected(lambda v: v[1]['streams'].pop(), 'streams')
        self.rejected(lambda v: v[1]['streams'][2].update(index=1), 'stream_duplicate')
        for changes in (dict(codec_type='audio'), dict(codec_type='subtitle'), dict(codec_tag_string='gpmd'),
                        dict(codec_name='bin_data'), dict(codec_name='unknown'), dict(width=720)):
            self.rejected(lambda v, changes=changes: v[1]['streams'][1].update(changes), 'metadata_profile')
        for changes in (dict(codec_name='hevc'), dict(codec_tag_string='other'), dict(width=1280), dict(height=720)):
            self.rejected(lambda v, changes=changes: v[1]['streams'][0].update(changes), 'video_profile')
        self.rejected(lambda v: v[1].update(programs=[{}]), 'packet_report')

    def test_packet_and_frame_count_mapping_and_order(self):
        self.rejected(lambda v: v[1]['packets'].pop(), 'packet_count')
        self.rejected(lambda v: v[1]['packets'][4].update(stream_index=1), 'metadata_packet_count')
        self.rejected(lambda v: v[1]['packets'][1].update(pts=0), 'video_packet_order_count')
        self.rejected(lambda v: v[2]['frames'].pop(), 'decoded_frame_count')
        self.rejected(lambda v: v[2]['frames'][1].update(pts=41), 'decoded_packet_mapping')
        self.rejected(lambda v: v[2]['frames'][1].update(pkt_pos='0'), 'decoded_packet_mapping')
        self.rejected(lambda v: v[1]['streams'][0].update(nb_frames=str(T.MAX_FRAMES + 1)), 'video_samples')

    def test_timebase_duration_and_container_quantization(self):
        for bad in ('0/90000', '1/0', 'nan', '1/10000000000', 90000, '2/1'):
            self.rejected(lambda v, b=bad: v[1]['streams'][0].update(time_base=b), 'timebase')
        self.rejected(lambda v: v[1]['streams'][0].update(duration_ts=125), 'track_end')
        self.rejected(lambda v: v[1]['format'].update(duration='0.130000'), 'format_end')
        # Exactly one track tick summary quantization is distinct from its packet end.
        v = list(fixture())
        v[1]['streams'][0]['duration_ts'] = 121
        report = self.check(v)
        self.assertNotEqual(report['packet_end_seconds'], report['stream_duration_seconds'])
        self.assertNotEqual(report['stream_duration_seconds'], report['movie_duration_seconds'])

    def test_timeline_identity_counts_pts_and_rounding(self):
        self.rejected(lambda v: v[3].update(source_video_sha256='0' * 64), 'timeline_identity')
        self.rejected(lambda v: v[3]['frames'].pop(), 'timeline_count')
        self.rejected(lambda v: v[3]['frames'][1].update(frame_index=2), 'timeline_index')
        self.rejected(lambda v: v[3]['frames'][1].update(source_pts_seconds=0.041), 'timeline_pts')
        self.rejected(lambda v: v[3]['frames'][1].update(clip_relative_pts_seconds=0.041), 'timeline_pts')
        self.rejected(lambda v: v[3]['frames'][1].update(source_pts_seconds=float('nan')))
        v = list(fixture())
        v[3]['frames'][1]['source_pts_seconds'] += 0.0000004
        self.check(v)

    def test_32_and_64_bit_mdat_box_bounds(self):
        body = b'opaque'
        raw = atom(b'mdat', body, wide=True) + atom(b'moov', atom(b'mvhd', bytes(12) + struct.pack('>II', 1000, 1)))
        mdats, duration, quantum = T.container(raw)
        self.assertEqual(mdats, [(16, 22)])
        self.assertEqual(duration, quantum)
        for bad in (raw[:7], struct.pack('>I4s', 7, b'mdat'), raw[:-1],
                    struct.pack('>I4sQ', 1, b'mdat', 9999)):
            with self.assertRaisesRegex(ValueError, 'native_timing_'):
                T.container(bad)

    def test_validate_boundary_hosted_and_file_binding(self):
        raw, packets, frames, timeline = fixture()
        with tempfile.TemporaryDirectory(prefix='inert-native-timing-') as temp:
            root = Path(temp).resolve()
            path = root / 'synthetic.mp4'
            path.write_bytes(raw)
            path.chmod(0o600)
            with patch.object(T, 'ROOT', root), patch.object(T, 'hosted'), \
                    patch.object(T, 'native_json', side_effect=[packets, frames, dict(program_version=dict(version='6.1.1'))]) as native:
                self.assertTrue(T.validate(path, timeline)['technical_coherence_passed'])
                self.assertEqual([call.args[1] for call in native.call_args_list], ['packets', 'frames', 'version'])
            with patch.dict(os.environ, {}, clear=True), patch.object(T, 'native_json') as native:
                with self.assertRaisesRegex(ValueError, 'native_timing_host'):
                    T.validate(path, timeline)
                native.assert_not_called()
            replies = iter((packets, frames, dict(program_version=dict(version='6.1.1'))))
            def mutate(*_):
                path.write_bytes(raw + b'changed')
                return next(replies)
            with patch.object(T, 'ROOT', root), patch.object(T, 'hosted'), \
                    patch.object(T, 'native_json', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'native_timing_video_changed'):
                    T.validate(path, timeline)

    def test_validate_rejects_symlinks_permissions_outside_and_hardlinks(self):
        raw, _, _, timeline = fixture()
        with tempfile.TemporaryDirectory(prefix='inert-native-files-') as temp:
            root = Path(temp).resolve()
            path = root / 'synthetic.mp4'
            path.write_bytes(raw)
            path.chmod(0o644)
            with patch.object(T, 'ROOT', root), patch.object(T, 'hosted'), patch.object(T, 'native_json') as native:
                with self.assertRaisesRegex(ValueError, 'native_timing_video_file'):
                    T.validate(path, timeline)
                path.chmod(0o600)
                link = root / 'link.mp4'
                link.symlink_to(path)
                with self.assertRaisesRegex(ValueError, 'native_timing_video_path'):
                    T.validate(link, timeline)
                os.link(path, root / 'hardlink.mp4')
                with self.assertRaisesRegex(ValueError, 'native_timing_video_file'):
                    T.validate(path, timeline)
                native.assert_not_called()


class FakeChild:
    """Pre-filled OS pipes only; no executable is started."""
    def __init__(self, output=b'{"frames": []}', errors=b'', status=0):
        self.stdout = self.pipe(output)
        self.stderr = self.pipe(errors)
        self.status, self.joined, self.killed = status, False, False

    @staticmethod
    def pipe(raw):
        read, write = os.pipe()
        os.write(write, raw)
        os.close(write)
        return os.fdopen(read, 'rb')

    def poll(self):
        return self.status if self.joined else None

    def wait(self, timeout=None):
        self.joined = True
        return self.status

    def kill(self):
        self.killed = True


class NativeBoundary(unittest.TestCase):
    def invoke(self, child, mode='frames'):
        with patch.object(T, 'hosted'), patch.object(T, 'tool', return_value='/usr/bin/ffprobe'), \
                patch.object(T.subprocess, 'Popen', return_value=child) as spawn:
            result = T.native_json(Path('/workspace/public.mp4'), mode)
        return result, spawn

    def test_fixed_argv_clean_environment_and_join(self):
        child = FakeChild()
        result, spawn = self.invoke(child)
        self.assertEqual(result, dict(frames=[]))
        args, kwargs = spawn.call_args.args[0], spawn.call_args.kwargs
        self.assertEqual(args[:5], ['/usr/bin/ffprobe', '-v', 'error', '-protocol_whitelist', 'file,pipe'])
        self.assertIn('frame=stream_index,pts,best_effort_timestamp,pkt_duration,pkt_pos,pkt_size', args)
        self.assertEqual(args[-1], '/workspace/public.mp4')
        self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        self.assertTrue(child.joined)
        self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_stderr_nonzero_bounds_and_json_rejections_are_closed(self):
        for child in (FakeChild(errors=b'private path secret'), FakeChild(status=1),
                FakeChild(output=b'not json private'), FakeChild(output=b'{"a":1,"a":2}'),
                FakeChild(output=b'{"value":NaN}')):
            with self.assertRaisesRegex(ValueError, r'^native_timing_[a-z_]+$') as caught:
                self.invoke(child)
            self.assertNotIn('private', str(caught.exception))
            self.assertTrue(child.joined and child.stdout.closed and child.stderr.closed)
        child = FakeChild(output=b'x' * 100)
        with patch.object(T, 'MAX_JSON', 10), self.assertRaisesRegex(ValueError, 'native_timing_native_output_bound'):
            self.invoke(child)
        self.assertTrue(child.killed and child.joined)

    def test_timeout_and_cancellation_kill_join(self):
        child = FakeChild()
        with patch.object(T.time, 'monotonic', side_effect=[0, 61]), \
                self.assertRaisesRegex(ValueError, 'native_timing_native_timeout'):
            self.invoke(child)
        self.assertTrue(child.killed and child.joined)
        child = FakeChild()
        with patch.object(T.selectors.DefaultSelector, 'select', side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.invoke(child)
        self.assertTrue(child.killed and child.joined)


if __name__ == '__main__':
    unittest.main()
