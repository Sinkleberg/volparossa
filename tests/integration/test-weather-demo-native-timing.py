#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert, explicitly synthetic timing/container fixtures; never real acceptance."""
from fractions import Fraction
import copy
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


def track(identity, handler, *, offset=0, size=0, wide=True, fixed_size=False, extra=b'', scale=1000):
    tkhd = bytearray(84)
    struct.pack_into('>I', tkhd, 12, identity)
    mdhd = bytes(12) + struct.pack('>II', scale, 0 if handler == b'meta' else 120) + bytes(4)
    hdlr = bytes(8) + handler + bytes(12)
    entry = atom(b'mett', b'application/octet-stream\0' * 2) if handler == b'meta' else atom(b'avc1', bytes(78))
    tables = atom(b'stsd', bytes(4) + struct.pack('>I', 1) + entry)
    if handler == b'meta':
        tables += atom(b'stts', bytes(4) + struct.pack('>III', 1, 1, 0))
        tables += atom(b'stsc', bytes(4) + struct.pack('>IIII', 1, 1, 1, 1))
        sizes = bytes(4) + struct.pack('>II', size if fixed_size else 0, 1)
        if not fixed_size:
            sizes += struct.pack('>I', size)
        tables += atom(b'stsz', sizes)
        tables += atom(b'co64' if wide else b'stco', bytes(4) + struct.pack('>I', 1)
            + struct.pack('>Q' if wide else '>I', offset))
    dref = atom(b'dref', bytes(4) + struct.pack('>I', 1) + atom(b'url ', struct.pack('>I', 1)))
    info = atom(b'nmhd', bytes(4)) + atom(b'dinf', dref) + atom(b'stbl', tables)
    return atom(b'trak', atom(b'tkhd', tkhd) + extra
        + atom(b'mdia', atom(b'mdhd', mdhd) + atom(b'hdlr', hdlr) + atom(b'minf', info)))


def fixture():
    """Three opaque pretend video packets; only native boundary is mocked."""
    points = [0, 40, 80]
    legacy = T.LEGACY + struct.pack('<I3Q', 3, 10000000, 10040000, 10080000)
    v2 = T.V2 + struct.pack('<IqI3Q', 2, -123, 3, 10000000000, 10040000000, 10080000000)
    prefix = atom(b'ftyp', b'isom0000')
    video_data = b'aaaabbbbcccc'
    pos = len(prefix) + 8
    legacy_pos, v2_pos = pos + len(video_data), pos + len(video_data) + len(legacy)
    movie = atom(b'moov', atom(b'mvhd', bytes(12) + struct.pack('>II', 1000, 120))
        + track(1, b'vide') + track(2, b'meta', offset=legacy_pos, size=len(legacy))
        + track(3, b'meta', offset=v2_pos, size=len(v2)))
    raw = prefix + atom(b'mdat', video_data + legacy + v2) + movie
    streams = [dict(index=0, id='0x1', codec_type='video', codec_name='h264', codec_tag_string='avc1',
        width=720, height=1280, time_base='1/1000', start_pts=0, duration_ts=120, nb_frames='3')]
    streams += [dict(index=i, id=hex(i + 1), codec_type='data', codec_tag_string='mett', time_base='1/1000',
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


def raw_scale(values, identity, scale):
    """Same-size inert edit to the exact selected fixture track's MDHD."""
    raw = values[0]
    movie = next((s, e) for k, s, e in T.atoms(raw, 0, len(raw)) if k == b'moov')
    for kind, start, stop in T.atoms(raw, *movie):
        if kind != b'trak':
            continue
        children = {k: (s, e) for k, s, e in T.atoms(raw, start, stop)}
        tkhd = children[b'tkhd'][0]
        if struct.unpack_from('>I', raw, tkhd + 12)[0] != identity:
            continue
        mdia = {k: (s, e) for k, s, e in T.atoms(raw, *children[b'mdia'])}
        pos = mdia[b'mdhd'][0] + 12
        values[0] = raw[:pos] + struct.pack('>I', scale) + raw[pos + 4:]
        values[3]['source_video_sha256'] = T.sha(values[0])
        return
    raise AssertionError('controlled fixture track missing')


def replace_fixture_box(values, kind, change):
    """Same-size mutation of one box, preserving original parent sizes."""
    raw = values[0]
    found = []
    def walk(start, stop):
        for tag, a, b in T.atoms(raw, start, stop):
            if tag == kind:
                found.append((a, b))
            if tag in (b'moov', b'trak', b'mdia', b'minf', b'dinf', b'stbl'):
                walk(a, b)
    walk(0, len(raw))
    a, b = found[0]
    mutated = change(raw[a:b])
    assert len(mutated) == b - a
    values[0] = raw[:a] + mutated + raw[b:]
    values[3]['source_video_sha256'] = T.sha(values[0])


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
        self.assertEqual(report['metadata_association_method'], 'mp4_sample_tables')
        for row in report['metadata_tracks']:
            body = raw[row['packet_offset']:row['packet_offset'] + row['packet_bytes']]
            self.assertEqual(row['packet_sha256'], T.sha(body))
        self.assertNotIn('offset', json.dumps(report).replace('packet_offset', ''))
        json.dumps(report, allow_nan=False)

    def test_zero_native_metadata_packets_still_require_exact_raw_samples(self):
        values = list(fixture())
        values[1]['packets'] = values[1]['packets'][:3]
        for stream in values[1]['streams'][1:]:
            stream['duration_ts'] = 120
        result = self.check(values)
        self.assertEqual(result['native_packet_count'], 3)
        self.assertEqual(result['native_metadata_packet_count'], 0)
        self.assertEqual([r['native_packet_count'] for r in result['metadata_tracks']], [0, 0])
        self.assertTrue(all(r['packet_pts'] is None and r['packet_duration'] is None for r in result['metadata_tracks']))
        # Damage the actual sample, not the native summary; still must reject.
        packet = fixture()[1]['packets'][3]
        pos = int(packet['pos'])
        values[0] = values[0][:pos] + b'!' + values[0][pos + 1:]
        values[3]['source_video_sha256'] = T.sha(values[0])
        with self.assertRaisesRegex(ValueError, 'native_timing_metadata_magic'):
            self.check(values)

    def test_raw_identity_joins_exact_tkhd_not_ordinal_assumption(self):
        values = list(fixture())
        raw = values[0]
        for old, new in ((1, 41), (2, 19), (3, 77)):
            header = bytearray(84)
            struct.pack_into('>I', header, 12, old)
            changed = bytearray(header)
            struct.pack_into('>I', changed, 12, new)
            raw = raw.replace(atom(b'tkhd', header), atom(b'tkhd', changed))
            values[1]['streams'][old - 1]['id'] = hex(new)
        values[0] = raw
        values[3]['source_video_sha256'] = T.sha(raw)
        result = self.check(values)
        self.assertEqual([r['track_id'] for r in result['metadata_tracks']], [19, 77])
        values[1]['streams'][1]['id'] = '0x2'
        with self.assertRaisesRegex(ValueError, 'native_timing_sample_native_identity'):
            self.check(values)

    def test_metadata_table_shapes_and_references_reject(self):
        mutations = (
            (b'stts', lambda raw: raw[:12] + struct.pack('>I', 1), 'sample_stts'),
            (b'stsc', lambda raw: raw[:12] + struct.pack('>I', 2) + raw[16:], 'sample_stsc'),
            (b'stsz', lambda raw: raw[:8] + struct.pack('>I', 2) + raw[12:], 'sample_stsz'),
            (b'co64', lambda raw: raw[:4] + struct.pack('>I', 2) + raw[8:], 'sample_offset'),
            (b'co64', lambda raw: raw[:8] + struct.pack('>Q', 0), 'sample_outside_mdat'),
            (b'dref', lambda raw: raw[:-4] + bytes(4), 'sample_external_reference'),
            (b'hdlr', lambda raw: raw[:8] + b'soun' + raw[12:], 'sample_handler'),
        )
        for kind, change, code in mutations:
            values = list(fixture())
            # dref/hdlr have a video instance first; mutations there are also
            # required to be meaningful, so select metadata-only mutation below.
            if kind == b'dref':
                old = atom(b'dref', bytes(4) + struct.pack('>I', 1) + atom(b'url ', struct.pack('>I', 1)))
                changed = old[:-4] + bytes(4)
                values[0] = values[0].replace(old, changed)
                values[3]['source_video_sha256'] = T.sha(values[0])
            else:
                replace_fixture_box(values, kind, change)
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'native_timing_' + code):
                self.check(values)

    def test_raw_sample_overlap_native_disagreement_and_duplicate_ids(self):
        for offset in (int(fixture()[1]['packets'][0]['pos']), int(fixture()[1]['packets'][4]['pos'])):
            values = list(fixture())
            values[1]['packets'] = values[1]['packets'][:3]
            replace_fixture_box(values, b'co64', lambda raw: raw[:8] + struct.pack('>Q', offset))
            with self.assertRaisesRegex(ValueError, 'native_timing_sample_overlap'):
                self.check(values)
        self.rejected(lambda v: v[1]['packets'][3].update(pts=1), 'sample_native_packet')
        self.rejected(lambda v: v[1]['packets'][3].update(size=str(int(v[1]['packets'][3]['size']) - 1)), 'sample_native_packet')
        values = list(fixture())
        tkhd = bytearray(84)
        struct.pack_into('>I', tkhd, 12, 2)
        changed = bytearray(tkhd)
        struct.pack_into('>I', changed, 12, 1)
        values[0] = values[0].replace(atom(b'tkhd', tkhd), atom(b'tkhd', changed))
        with self.assertRaisesRegex(ValueError, 'native_timing_sample_track_id'):
            self.check(values)

    def test_stco_fixed_stsz_and_rejected_edits_fragments_duplicate_boxes(self):
        values = list(fixture())
        raw = values[0]
        top = list(T.atoms(raw, 0, len(raw)))
        movie = next((s, e) for k, s, e in top if k == b'moov')
        prefix = raw[:movie[0] - 8]
        mvhd = atom(b'mvhd', bytes(12) + struct.pack('>II', 1000, 120))
        packets = values[1]['packets']
        def make(extra=b'', movie_extra=b''):
            return prefix + atom(b'moov', mvhd + track(1, b'vide', extra=extra)
                + track(2, b'meta', offset=int(packets[3]['pos']), size=int(packets[3]['size']), wide=False, fixed_size=True)
                + track(3, b'meta', offset=int(packets[4]['pos']), size=int(packets[4]['size']), wide=False, fixed_size=True)
                + movie_extra)
        values[0] = make()
        values[3]['source_video_sha256'] = T.sha(values[0])
        self.check(values)
        for raw, code in ((make(extra=atom(b'edts', b'')), 'sample_edit'),
                (make(movie_extra=atom(b'mvex', b'')), 'sample_fragment'),
                (make() + atom(b'moof', b''), 'sample_fragment'),
                (make(movie_extra=mvhd), 'movie_header')):
            values[0] = raw
            with self.assertRaisesRegex(ValueError, 'native_timing_' + code):
                self.check(values)

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

    def test_metadata_duration_source_derived_format_inference(self):
        # Source-derived FFmpeg prediction, not observed Android ffprobe JSON.
        for summary, packet in ((0, 0), (120, 0), (120, 120)):
            values = list(fixture())
            for stream in values[1]['streams'][1:]:
                stream['duration_ts'] = summary
            for sample in values[1]['packets'][3:]:
                sample['duration'] = packet
            result = self.check(values)
            for track in result['metadata_tracks']:
                self.assertEqual(track['summary_duration_ticks'], summary)
                self.assertEqual(track['packet_duration'], packet)
        self.rejected(lambda v: v[1]['streams'][1].update(duration_ts=119), 'metadata_duration')
        self.rejected(lambda v: v[1]['streams'][1].update(duration_ts=-1), 'metadata_duration')
        self.rejected(lambda v: v[1]['streams'][1].update(duration_ts=10**15), 'metadata_duration')
        self.rejected(lambda v: v[1]['packets'][3].update(duration=120), 'metadata_packet_duration')
        values = list(fixture())
        values[1]['streams'][1].update(duration_ts=120)
        values[1]['packets'][3].update(duration=119)
        with self.assertRaisesRegex(ValueError, 'native_timing_metadata_packet_duration'):
            self.check(values)

    def test_metadata_duration_uses_nearest_rescaling_not_arbitrary_margin(self):
        values = list(fixture())
        # 0.12 / (1/25) = 3 exact ticks; neighboring values remain rejected.
        values[1]['streams'][1].update(time_base='1/25', duration_ts=3)
        raw_scale(values, 2, 25)
        values[1]['packets'][3].update(duration=3)
        self.check(values)
        values[1]['streams'][1]['duration_ts'] = 4
        with self.assertRaisesRegex(ValueError, 'native_timing_metadata_duration'):
            self.check(values)
        # A different integral media timescale remains exactly bound to MDHD.
        values[1]['streams'][1].update(time_base='1/125', duration_ts=15)
        raw_scale(values, 2, 125)
        values[1]['packets'][3].update(duration=15)
        self.check(values)

    def test_observation_closed_safe_projection_and_unknown_fields(self):
        _, packets, frames, _ = fixture()
        packets['streams'][1].update(duration_ts='120', codec_name='private secret',
            codec_tag_string='private/path', width=10**40, tags={'private': 'secret'})
        value = T.observation(packets, frames)
        self.assertEqual(value['streams'][1]['duration_ts'], 120)
        self.assertEqual(value['streams'][1]['codec_name'], 'other')
        self.assertIsNone(value['streams'][1]['width'])
        self.assertEqual(value['video_packets']['count'], 3)
        self.assertEqual(value['video_packets']['last_pts'], 80)
        self.assertEqual(value['video_frames']['last_duration'], 40)
        self.assertEqual(value['format_duration_microseconds'], 120000)
        self.assertFalse(value['technical_coherence_passed'])
        self.assertNotIn('private', json.dumps(value))
        self.assertNotIn('secret', json.dumps(value))
        missing = T.observation(None, None)
        self.assertIsNone(missing['decoded_frame_count'])
        self.assertIsNone(missing['video_frames']['count'])
        self.assertIsNone(missing['packet_count'])

    def test_observation_validator_rejects_arbitrary_or_unbounded_attachments(self):
        _, packets, frames, _ = fixture()
        good = T.observation(packets, frames)
        changes = [lambda v: v.update(private='secret'), lambda v: v.update(technical_coherence_passed=True),
            lambda v: v.update(packet_count=T.MAX_FRAMES + 3), lambda v: v.update(packet_count=True),
            lambda v: v['streams'][0].update(codec_name='private secret'),
            lambda v: v['streams'][0].update(time_base='private/path'),
            lambda v: v['streams'][0].update(duration_ts=10**40),
            lambda v: v['video_packets'].update(raw='private'),
            lambda v: v['metadata_packets'][0].update(stream_index='private')]
        for change in changes:
            bad = copy.deepcopy(good)
            change(bad)
            with self.assertRaisesRegex(ValueError, '^native_timing_'):
                T.validate_observation(bad)

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
        raw_scale(values, 1, 90000)
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

    def test_extra_stream_fields_rejected_with_finite_private_diagnostics(self):
        # Source-predicted FFmpeg shapes, not retained output from the failed
        # hosted query: that failure report contains no actual extra key names.
        cases = (({'disposition': {'default': 1}}, 'disposition'),
            ({'tags': {'private path': 'secret'}}, 'tags'),
            ({'side_data_list': [{'private': 'secret'}]}, 'side_data'),
            ({'tags': {}, 'disposition': {}}, 'nested'),
            ({'unexpected private path': 'secret'}, 'unknown'))
        for extra, code in cases:
            values = list(fixture())
            values[1]['streams'][0].update(extra)
            with self.subTest(code=code), self.assertRaises(ValueError) as caught:
                self.check(values)
            self.assertEqual(str(caught.exception), 'native_timing_stream_fields_' + code)
            self.assertNotIn('private', str(caught.exception))
            self.assertNotIn('secret', str(caught.exception))

    def test_packet_and_frame_count_mapping_and_order(self):
        self.rejected(lambda v: v[1]['packets'].pop(0), 'video_packet_order_count')
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

    def test_validate_rejection_attaches_sanitized_actual_boundary_values(self):
        raw, packets, frames, timeline = fixture()
        packets['streams'][1]['duration_ts'] = 119
        with tempfile.TemporaryDirectory(prefix='inert-native-observation-') as temp:
            root = Path(temp).resolve()
            path = root / 'synthetic.mp4'
            path.write_bytes(raw)
            path.chmod(0o600)
            with patch.object(T, 'ROOT', root), patch.object(T, 'hosted'), \
                    patch.object(T, 'native_json', side_effect=[packets, frames, dict(program_version=dict(version='6.1.1'))]), \
                    self.assertRaisesRegex(ValueError, 'native_timing_metadata_duration') as caught:
                T.validate(path, timeline)
            detail = caught.exception.native_timing_observation
            self.assertEqual(detail['streams'][1]['duration_ts'], 119)
            self.assertEqual(detail['decoded_frame_count'], 3)
            self.assertFalse(detail['technical_coherence_passed'])

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

    def test_queries_select_only_required_entries_without_recursive_show_flags(self):
        expected = {
            'packets': 'stream=' + T.STREAM_ENTRIES + ':packet=stream_index,pts,duration,pos,size:format=duration',
            'frames': 'frame=stream_index,pts,best_effort_timestamp,pkt_duration,pkt_pos,pkt_size',
            'version': 'program_version=version',
        }
        for mode, entries in expected.items():
            with self.subTest(mode=mode):
                child = FakeChild()
                _, spawn = self.invoke(child, mode)
                args = spawn.call_args.args[0]
                self.assertEqual([arg for arg in args if arg.startswith('-show_')], ['-show_entries'])
                self.assertEqual(args[args.index('-show_entries') + 1], entries)
                if mode == 'packets':
                    self.assertIn('id', entries.split(':', 1)[0].split('=', 1)[1].split(','))
                if mode == 'version':
                    self.assertNotIn('/workspace/public.mp4', args)
                else:
                    self.assertEqual(args[-1], '/workspace/public.mp4')
                if mode == 'frames':
                    self.assertEqual(args[args.index('-select_streams') + 1], 'v:0')
                self.assertTrue(child.joined and child.stdout.closed and child.stderr.closed)

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
