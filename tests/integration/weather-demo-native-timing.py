#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Technical coherence of one Android screenrecord; never media/release admission.

Winscope layouts: AOSP frameworks/av 1df77b62b5f5da43cba5ba951cc77f1aada3240a,
cmds/screenrecord/screenrecord.cpp writeWinscopeMetadata{Legacy,}. Both magic
strings are 16 bytes; the v2 count is uint32 (the implementation, not its stale
8B comment). Only relative clocks are compared. Guest real/elapsed offsets
cannot calibrate the host wall clock. Native execution is hosted-only.
"""
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import stat
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
MAX_VIDEO = 100 * 1024**2
MAX_JSON = 8 * 1024**2
MAX_FRAMES = 21600
LEGACY = b'#VV1NSC0PET1ME!#'
V2 = b'#VV1NSC0PET1ME2#'
STREAM_ENTRIES = 'index,codec_type,codec_name,codec_tag_string,width,height,time_base,start_pts,duration_ts,nb_frames'
OBS_ENUMS = {'codec_type': frozenset(('video', 'data', 'audio', 'subtitle')),
    'codec_name': frozenset(('h264', 'bin_data')), 'codec_tag_string': frozenset(('avc1', 'mett'))}
OBS_NUMBERS = {'index': (0, 7), 'width': (0, 8192), 'height': (0, 8192),
    'start_pts': (-10**9, 10**9), 'duration_ts': (0, 180 * 10**9), 'nb_frames': (0, MAX_FRAMES)}
OBS_SUMMARY = {'count': (0, MAX_FRAMES + 2), 'first_pts': (-10**9, 10**9),
    'last_pts': (-10**9, 10**9), 'first_duration': (0, 180 * 10**9), 'last_duration': (0, 180 * 10**9)}


def require(condition, code):
    if not condition:
        raise ValueError('native_timing_' + code)


def integer(value, code, low=0, high=2**63 - 1):
    require(type(value) is int or type(value) is str and re.fullmatch(r'-?(?:0|[1-9][0-9]{0,19})', value), code)
    result = int(value)
    require(low <= result <= high, code)
    return result


def rational(value):
    return dict(numerator=value.numerator, denominator=value.denominator)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError):
        raise ValueError('native_timing_json_value') from None


def hosted():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
        and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
        and os.environ.get('RUNNER_OS') == 'Linux'
        and os.environ.get('GITHUB_REPOSITORY') == 'VOLPAROSSA/volparossa'
        and os.getuid() == os.geteuid() != 0, 'host')
    require(re.fullmatch('[a-f0-9]{40}', os.environ.get('GITHUB_SHA', ''))
        and all(re.fullmatch('[1-9][0-9]{0,19}', os.environ.get(k, ''))
                for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')), 'host_identity')


def tool():
    try:
        path = Path('/usr/bin/ffprobe').resolve(strict=True)
    except OSError:
        raise ValueError('native_timing_tool_missing') from None
    for item in (path, *path.parents):
        info = item.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, 'tool_owner')
    require(stat.S_ISREG(path.stat().st_mode) and os.access(path, os.X_OK), 'tool_type')
    return str(path)


def native_json(video, mode):
    """Fixed queries; bounded concurrent pipe reads; join on every exit/cancel."""
    hosted()
    require(mode in ('packets', 'frames', 'version'), 'query')
    # ffprobe n6.1.1 opt_show_* recursively selects nested sections. A later
    # scalar -show_entries only replaces its own section, leaving child tags /
    # dispositions selected (mark_section_show_entries, lines3445-3454).
    # -show_entries alone activates each requested section via SET_DO_SHOW
    # (lines3858-3879), without enabling those unwanted child fields.
    queries = {
        'packets': ['-show_entries',
            'stream=' + STREAM_ENTRIES + ':packet=stream_index,pts,duration,pos,size:format=duration'],
        'frames': ['-select_streams', 'v:0', '-show_entries',
            'frame=stream_index,pts,best_effort_timestamp,pkt_duration,pkt_pos,pkt_size'],
        'version': ['-show_entries', 'program_version=version'],
    }
    args = [tool(), '-v', 'error', '-protocol_whitelist', 'file,pipe', *queries[mode], '-of', 'json']
    if mode != 'version':
        args.append(str(video))
    try:
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, close_fds=True)
    except OSError:
        raise ValueError('native_timing_native_start') from None
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + 60
    try:
        with selectors.DefaultSelector() as selector:
            for stream, buffer, bound in ((child.stdout, output, MAX_JSON), (child.stderr, errors, 65536)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, (buffer, bound))
            while selector.get_map():
                require(time.monotonic() < deadline, 'native_timeout')
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    buffer, bound = key.data
                    part = os.read(key.fd, min(65536, bound + 1 - len(buffer)))
                    if not part:
                        selector.unregister(key.fileobj)
                    else:
                        buffer.extend(part)
                        require(len(buffer) <= bound, 'native_output_bound')
            status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        require(status == 0 and not errors, 'native_process')
    except BaseException as error:
        if child.poll() is None:
            child.kill()
        child.wait()
        if isinstance(error, (OSError, subprocess.SubprocessError)):
            raise ValueError('native_timing_native_process') from None
        raise
    finally:
        child.stdout.close()
        child.stderr.close()
    try:
        value = json.loads(output, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('native_timing_native_json') from None
    require(type(value) is dict, 'native_json')
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError('native_timing_nonfinite_json')


def atoms(raw, start, stop):
    """Bounded 32/64-bit BMFF box walk, only used at explicit shallow levels."""
    count = 0
    while start < stop:
        require(stop - start >= 8 and count < 4096, 'box_header')
        size, kind = struct.unpack_from('>I4s', raw, start)
        header = 8
        if size == 1:
            require(stop - start >= 16, 'box_header')
            size = struct.unpack_from('>Q', raw, start + 8)[0]
            header = 16
        elif size == 0:
            size = stop - start
        require(header <= size <= stop - start, 'box_size')
        yield kind, start + header, start + size
        start += size
        count += 1
    require(start == stop, 'box_end')


def container(raw):
    top = list(atoms(raw, 0, len(raw)))
    mdats = [(start, stop) for kind, start, stop in top if kind == b'mdat']
    movies = [(start, stop) for kind, start, stop in top if kind == b'moov']
    require(mdats and len(mdats) <= 16 and len(movies) == 1, 'container')
    headers = [(start, stop) for kind, start, stop in atoms(raw, *movies[0]) if kind == b'mvhd']
    require(len(headers) == 1, 'movie_header')
    start, stop = headers[0]
    require(stop - start >= 20, 'movie_header')
    version = raw[start]
    require(version in (0, 1), 'movie_header')
    if version == 0:
        scale, duration = struct.unpack_from('>II', raw, start + 12)
    else:
        require(stop - start >= 32, 'movie_header')
        scale, duration = struct.unpack_from('>IQ', raw, start + 20)
    require(1 <= scale <= 10**9 and 0 < duration <= 180 * scale, 'movie_duration')
    return mdats, Fraction(duration, scale), Fraction(1, scale)


def payload(raw):
    """Decode a single exact metadata packet; never search arbitrary MP4 bytes."""
    if raw.startswith(LEGACY):
        require(len(raw) >= 20, 'legacy_length')
        count = struct.unpack_from('<I', raw, 16)[0]
        start, unit, kind = 20, Fraction(1, 10**6), 'legacy'
    elif raw.startswith(V2):
        require(len(raw) >= 32, 'v2_length')
        version, _guest_real_to_elapsed_offset, count = struct.unpack_from('<IqI', raw, 16)
        require(version == 2, 'v2_version')
        start, unit, kind = 32, Fraction(1, 10**9), 'v2'
    else:
        raise ValueError('native_timing_metadata_magic')
    require(1 <= count <= MAX_FRAMES and len(raw) == start + count * 8, 'metadata_length_count')
    values = struct.unpack_from('<' + str(count) + 'Q', raw, start)
    require(all(a < b for a, b in zip(values, values[1:])), 'metadata_order')
    relative = [(value - values[0]) * unit for value in values]
    require(relative[-1] <= 180, 'metadata_span')
    return kind, relative


def timebase(value):
    require(type(value) is str and re.fullmatch(r'[1-9][0-9]{0,9}/[1-9][0-9]{0,9}', value), 'timebase')
    result = Fraction(value)
    require(Fraction(1, 10**9) <= result <= 1, 'timebase')
    return result


def seconds(value, code):
    require(type(value) is str and re.fullmatch(r'[0-9]{1,3}(?:\.[0-9]{1,9})?', value), code)
    result = Fraction(value)
    require(0 < result <= 180, code)
    return result


def timeline_check(timeline, digest, pts, durations, tb):
    require(type(timeline) is dict and len(canonical(timeline)) <= MAX_JSON, 'timeline')
    require(timeline.get('schema') == 1 and type(timeline.get('schema')) is int
        and timeline.get('kind') == 'weather-demo-source-video-frame-timeline'
        and timeline.get('source_video_sha256') == digest, 'timeline_identity')
    frames = timeline.get('frames')
    require(type(frames) is list and len(frames) == len(pts), 'timeline_count')
    maximum = Fraction(0)
    # Prior ffprobe emits *_time with six decimals; subtraction of the two
    # rounded endpoints costs at most 1us. Three binary64 ulps cover the prior
    # float conversion/subtraction, with magnitudes bounded here to <=180s.
    float_bound = 3 * Fraction(math.ulp(180.0))
    bound = Fraction(1, 10**6) + float_bound
    for index, (frame, point, duration) in enumerate(zip(frames, pts, durations)):
        require(type(frame) is dict and type(frame.get('frame_index')) is int
            and frame['frame_index'] == index, 'timeline_index')
        expected = {'source_pts_seconds': point * tb, 'clip_relative_pts_seconds': (point - pts[0]) * tb,
            'pts_time': point * tb, 'best_effort_timestamp_time': point * tb,
            'pkt_duration_time': duration * tb}
        require({'source_pts_seconds', 'clip_relative_pts_seconds'} <= set(frame), 'timeline_fields')
        for key, exact in expected.items():
            if key not in frame:
                continue
            value = frame[key]
            require(type(value) in (int, float) and math.isfinite(value) and abs(value) <= 180, 'timeline_number')
            deviation = abs(Fraction(value) - exact)
            require(deviation <= bound, 'timeline_pts')
            maximum = max(maximum, deviation)
    return maximum, bound


def stream_fields(stream):
    """Reject every extra field; disclose only a fixed field-class code."""
    require(type(stream) is dict, 'stream_fields')
    extra = set(stream) - set(STREAM_ENTRIES.split(','))
    if not extra:
        return
    # These are section names from ffprobe.c's stream section table. Values,
    # arbitrary keys, tags, paths and metadata bodies never enter diagnostics.
    known = {'disposition': 'disposition', 'tags': 'tags', 'side_data_list': 'side_data'}
    if not extra <= set(known):
        code = 'unknown'
    elif len(extra) == 1:
        code = known[next(iter(extra))]
    else:
        code = 'nested'
    raise ValueError('native_timing_stream_fields_' + code)


def observation(packet_report, frame_report):
    """Closed diagnostic projection, including rejected numeric summaries only."""
    def number(value, limits):
        try:
            return integer(value, 'observation_number', *limits)
        except ValueError:
            return None
    def enum(record, key):
        if key not in record:
            return 'absent'
        value = record[key]
        return value if type(value) is str and value in OBS_ENUMS[key] else 'other'
    def ratio(value):
        try:
            timebase(value)
            return value
        except ValueError:
            return None
    streams_observed = type(packet_report) is dict and type(packet_report.get('streams')) is list
    source_streams = packet_report.get('streams', []) if type(packet_report) is dict else []
    source_streams = source_streams if type(source_streams) is list else []
    streams = []
    for item in source_streams[:8]:
        item = item if type(item) is dict else {}
        streams.append({**{key: number(item.get(key), limits) for key, limits in OBS_NUMBERS.items()},
            **{key: enum(item, key) for key in OBS_ENUMS}, 'time_base': ratio(item.get('time_base'))})
    packets_observed = type(packet_report) is dict and type(packet_report.get('packets')) is list
    frames_observed = type(frame_report) is dict and type(frame_report.get('frames')) is list
    packets = packet_report.get('packets', []) if type(packet_report) is dict else []
    frames = frame_report.get('frames', []) if type(frame_report) is dict else []
    packets = packets if type(packets) is list else []
    frames = frames if type(frames) is list else []
    def summary(rows, duration_key):
        result = {'count': number(len(rows), OBS_SUMMARY['count'])}
        for prefix, item in (('first', rows[0] if rows else {}), ('last', rows[-1] if rows else {})):
            item = item if type(item) is dict else {}
            for field, source in (('pts', 'pts'), ('duration', duration_key)):
                key = prefix + '_' + field
                result[key] = number(item.get(source), OBS_SUMMARY[key])
        return result
    video_indices = {item['index'] for item in streams if item['codec_type'] == 'video' and item['index'] is not None}
    video_packets = [item for item in packets[:MAX_FRAMES + 2] if type(item) is dict
        and type(item.get('stream_index')) is int and item['stream_index'] in video_indices]
    metadata = []
    for item in streams:
        if item['codec_type'] == 'data' and item['index'] is not None:
            rows = [p for p in packets[:MAX_FRAMES + 2] if type(p) is dict
                and type(p.get('stream_index')) is int and p['stream_index'] == item['index']]
            metadata.append(dict(stream_index=item['index'], **summary(rows, 'duration')))
    format_record = packet_report.get('format') if type(packet_report) is dict else None
    format_us = None
    if type(format_record) is dict:
        try:
            exact_us = seconds(format_record.get('duration'), 'observation_format') * 10**6
            if exact_us.denominator == 1:
                format_us = exact_us.numerator
        except ValueError:
            pass
    video_packet_summary, video_frame_summary = summary(video_packets, 'duration'), summary(frames[:MAX_FRAMES], 'pkt_duration')
    if not packets_observed:
        video_packet_summary['count'] = None
    if not frames_observed:
        video_frame_summary['count'] = None
    result = dict(schema=1, kind='weather-demo-native-timing-observation', technical_coherence_passed=False,
        stream_count=number(len(source_streams), (0, 8)) if streams_observed else None, streams=streams,
        format_duration_microseconds=format_us,
        packet_count=number(len(packets), (0, MAX_FRAMES + 2)) if packets_observed else None,
        decoded_frame_count=number(len(frames), (0, MAX_FRAMES)) if frames_observed else None,
        video_packets=video_packet_summary, video_frames=video_frame_summary,
        metadata_packets=metadata)
    return validate_observation(result)


def validate_observation(value):
    """Validate an exception attachment again before any failure JSON export."""
    def numbers(record, fields):
        require(type(record) is dict and set(record) == set(fields), 'observation_fields')
        for key, (low, high) in fields.items():
            item = record[key]
            require(item is None or type(item) is int and low <= item <= high, 'observation_number')
    require(type(value) is dict and set(value) == {'schema', 'kind', 'technical_coherence_passed',
        'stream_count', 'streams', 'format_duration_microseconds', 'packet_count', 'decoded_frame_count', 'video_packets', 'video_frames',
        'metadata_packets'}, 'observation_fields')
    require(type(value['schema']) is int and value['schema'] == 1
        and value['kind'] == 'weather-demo-native-timing-observation'
        and value['technical_coherence_passed'] is False, 'observation_identity')
    numbers({key: value[key] for key in ('stream_count', 'packet_count', 'decoded_frame_count', 'format_duration_microseconds')},
        dict(stream_count=(0, 8), packet_count=(0, MAX_FRAMES + 2), decoded_frame_count=(0, MAX_FRAMES),
            format_duration_microseconds=(0, 180 * 10**6)))
    require(type(value['streams']) is list and len(value['streams']) <= 8, 'observation_streams')
    for stream in value['streams']:
        require(type(stream) is dict and set(stream) == set(OBS_NUMBERS) | set(OBS_ENUMS) | {'time_base'}, 'observation_fields')
        numbers({key: stream[key] for key in OBS_NUMBERS}, OBS_NUMBERS)
        for key, allowed in OBS_ENUMS.items():
            require(type(stream[key]) is str and stream[key] in allowed | {'absent', 'other'}, 'observation_enum')
        require(stream['time_base'] is None or type(stream['time_base']) is str, 'observation_timebase')
        if stream['time_base'] is not None:
            timebase(stream['time_base'])
    for key in ('video_packets', 'video_frames'):
        numbers(value[key], OBS_SUMMARY)
    require(type(value['metadata_packets']) is list and len(value['metadata_packets']) <= 8, 'observation_metadata')
    for item in value['metadata_packets']:
        require(type(item) is dict and set(item) == set(OBS_SUMMARY) | {'stream_index'}, 'observation_fields')
        numbers({key: item[key] for key in OBS_SUMMARY}, OBS_SUMMARY)
        require(type(item['stream_index']) is int and 0 <= item['stream_index'] <= 7, 'observation_stream_index')
    require(len(canonical(value)) <= 8192, 'observation_size')
    return value


def coherence(raw, packet_report, frame_report, timeline, version):
    """Pure bounded verification; synthetic fixtures do not supply native proof."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_VIDEO, 'video_size')
    mdats, movie_duration, movie_tick = container(raw)
    require(type(packet_report) is dict and set(packet_report) <= {'streams', 'packets', 'format', 'programs'}
        and packet_report.get('programs', []) == [], 'packet_report')
    format_record = packet_report.get('format')
    require(type(format_record) is dict and set(format_record) == {'duration'}, 'format')
    format_duration = seconds(format_record['duration'], 'format_duration')
    streams = packet_report.get('streams')
    require(type(streams) is list and len(streams) == 3, 'streams')
    videos, metadata, indexed = [], [], {}
    for stream in streams:
        stream_fields(stream)
        index = integer(stream.get('index'), 'stream_index', high=7)
        require(index not in indexed, 'stream_duplicate')
        indexed[index] = stream
        tb = timebase(stream.get('time_base'))
        integer(stream.get('start_pts'), 'stream_start', low=-10**9, high=10**9)
        if stream.get('codec_type') == 'video':
            require(stream.get('codec_name') == 'h264' and stream.get('codec_tag_string') == 'avc1'
                and type(stream.get('width')) is int and stream['width'] == 720
                and type(stream.get('height')) is int and stream['height'] == 1280, 'video_profile')
            videos.append((index, stream, tb))
        else:
            require(stream.get('codec_type') == 'data' and stream.get('codec_tag_string') == 'mett'
                and 'codec_name' not in stream and not {'width', 'height'} & set(stream), 'metadata_profile')
            require(integer(stream.get('nb_frames'), 'metadata_samples', high=MAX_FRAMES) == 1, 'metadata_samples')
            # demux.c1548-1559 may fill a DATA stream's zero/unknown timing
            # from the format duration. av_rescale_q rounds nearest, ties away
            # from zero (mathematics.c130-132). This summary is not frame timing.
            ticks = format_duration / tb
            inferred = (2 * ticks.numerator + ticks.denominator) // (2 * ticks.denominator)
            summary_duration = integer(stream.get('duration_ts', 0), 'metadata_duration', high=180 * 10**9)
            require(summary_duration in (0, inferred) and summary_duration * tb <= 180, 'metadata_duration')
            metadata.append((index, stream, tb))
    require(len(videos) == 1 and len(metadata) == 2, 'track_profile')
    video_index, stream, tb = videos[0]
    count = integer(stream.get('nb_frames'), 'video_samples', low=1, high=MAX_FRAMES)
    stream_duration = integer(stream.get('duration_ts'), 'stream_duration', low=1) * tb
    require(stream_duration <= 180, 'stream_duration')
    packets = packet_report.get('packets')
    require(type(packets) is list and len(packets) == count + 2, 'packet_count')
    grouped = {index: [] for index in indexed}
    ranges = []
    for packet in packets:
        require(type(packet) is dict and {'stream_index', 'pts', 'pos', 'size'} <= set(packet)
            and set(packet) <= {'stream_index', 'pts', 'duration', 'pos', 'size'}, 'packet_fields')
        index = integer(packet['stream_index'], 'packet_stream', high=7)
        require(index in grouped, 'packet_stream')
        point = integer(packet['pts'], 'packet_pts', low=-10**9, high=10**9)
        duration = integer(packet.get('duration', 0), 'packet_duration', high=10**9)
        pos = integer(packet['pos'], 'packet_pos', high=len(raw))
        size = integer(packet['size'], 'packet_size', low=1, high=len(raw))
        require(any(start <= pos and pos + size <= stop for start, stop in mdats), 'packet_outside_mdat')
        ranges.append((pos, pos + size))
        grouped[index].append((point, duration, pos, size))
    ranges.sort()
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), 'packet_overlap')
    video = grouped[video_index]
    require(len(video) == count and all(a[0] < b[0] for a, b in zip(video, video[1:])), 'video_packet_order_count')
    pts = [p[0] for p in video]
    durations = [p[1] for p in video]
    require(all(0 < value * tb <= 180 for value in durations)
        and pts[0] == integer(stream['start_pts'], 'video_start', low=-10**9, high=10**9), 'video_packet_duration_start')
    require(all(a[0] + a[1] == b[0] for a, b in zip(video, video[1:])), 'video_packet_contiguity')
    require(type(frame_report) is dict and set(frame_report) == {'frames'}, 'frame_report')
    frames = frame_report['frames']
    require(type(frames) is list and len(frames) == count, 'decoded_frame_count')
    for frame, (point, duration, pos, size) in zip(frames, video):
        require(type(frame) is dict and {'stream_index', 'pts', 'best_effort_timestamp', 'pkt_duration', 'pkt_pos', 'pkt_size'}
            <= set(frame) and set(frame) <= {'stream_index', 'pts', 'best_effort_timestamp', 'pkt_duration', 'pkt_pos', 'pkt_size', 'side_data_list'}, 'frame_fields')
        expected = dict(stream_index=video_index, pts=point, best_effort_timestamp=point,
            pkt_duration=duration, pkt_pos=pos, pkt_size=size)
        require(all(integer(frame[key], 'frame_integer', low=-10**9) == value for key, value in expected.items()), 'decoded_packet_mapping')
    arrays, records = {}, []
    for index, metadata_stream, track_tb in metadata:
        require(len(grouped[index]) == 1, 'metadata_packet_count')
        point, duration, pos, size = grouped[index][0]
        summary_duration = integer(metadata_stream.get('duration_ts', 0), 'metadata_duration', high=180 * 10**9)
        # mov.c8395-8400 uses stream.duration - packet.dts for the last sample.
        # A packet buffered before timing inference can still have duration0.
        require(duration * track_tb <= 180
            and (duration == 0 or summary_duration > 0 and duration == summary_duration - point),
            'metadata_packet_duration')
        require(size <= 32 + MAX_FRAMES * 8, 'metadata_packet_shape')
        body = raw[pos:pos + size]
        kind, relative = payload(body)
        require(kind not in arrays and len(relative) == count, 'metadata_kind_count')
        arrays[kind] = relative
        records.append(dict(stream_index=index, kind=kind, packet_offset=pos, packet_bytes=size,
            packet_sha256=sha(body), packet_pts=point, packet_duration=duration, time_base=rational(track_tb), frame_count=count,
            summary_duration_ticks=summary_duration,
            summary_duration_basis='format-inferred' if summary_duration else 'zero-or-absent'))
    require(set(arrays) == {'legacy', 'v2'}, 'metadata_kinds')
    # Both AOSP writers add one constant offset to the same integer-us vector.
    # Relative arrays must therefore agree exactly, not within a guessed margin.
    require(arrays['legacy'] == arrays['v2'], 'metadata_relative_disagreement')
    errors = [abs((point - pts[0]) * tb - elapsed) for point, elapsed in zip(pts, arrays['v2'])]
    # MPEG4Writer.cpp (9ce151cc..., currDurationTicks) rounds each integer-us
    # endpoint with (timestampUs * timeScale + 500000) / 1000000. Each endpoint
    # costs <=half a tick; subtracting them costs <=one tick. Timestamp fudging
    # beyond this bound is deliberately not accepted as quantization coherence.
    pts_bound = tb
    require(max(errors) <= pts_bound, 'elapsed_pts_disagreement')
    span = (pts[-1] - pts[0]) * tb
    packet_end = (pts[-1] + durations[-1] - pts[0]) * tb
    # Track-header and sample-table durations can each quantize one endpoint;
    # this check uses one video tick, not the unrelated host capture interval.
    require(abs(packet_end - stream_duration) <= tb, 'track_end')
    require(abs(stream_duration - movie_duration) <= movie_tick + tb, 'movie_end')
    # Container/movie and track summaries use different integer timescales.
    # ffprobe's decimal format summary adds a microsecond serialization step;
    # keep these quantities separate rather than asserting exact equality.
    format_bound = movie_tick + tb + Fraction(1, 10**6)
    require(abs(format_duration - stream_duration) <= format_bound
        and abs(format_duration - movie_duration) <= format_bound, 'format_end')
    timeline_error, timeline_bound = timeline_check(timeline, sha(raw), pts, durations, tb)
    require(type(version) is str and re.fullmatch(r'[0-9][0-9A-Za-z.+~:_-]{0,79}', version), 'tool_version')
    return dict(schema=1, kind='weather-demo-native-timing-coherence', technical_coherence_passed=True,
        visual_acceptance_claimed=False, media_accepted=False, publication_authorized=False, production_authority=False,
        host_wall_clock_coverage_claimed=False, exact_os_action_timestamps_claimed=False,
        source_video_sha256=sha(raw), source_video_bytes=len(raw), frame_timeline_sha256=sha(canonical(timeline)),
        ffprobe_version=version, video_stream_index=video_index, video_time_base=rational(tb),
        video_packet_count=count, decoded_frame_count=count, prior_timeline_frame_count=len(timeline['frames']),
        metadata_tracks=sorted(records, key=lambda row: row['stream_index']),
        relative_elapsed_span_seconds=rational(arrays['v2'][-1]), relative_pts_span_seconds=rational(span),
        max_relative_pts_elapsed_error_seconds=rational(max(errors)), derived_pts_error_bound_seconds=rational(pts_bound),
        pts_bound_basis='two half-tick nearest-integer endpoint quantizations',
        max_prior_timeline_error_seconds=rational(timeline_error), derived_prior_timeline_bound_seconds=rational(timeline_bound),
        prior_timeline_bound_basis='two six-decimal timestamp roundings plus three bounded binary64 ulps',
        packet_end_seconds=rational(packet_end), stream_duration_seconds=rational(stream_duration),
        movie_duration_seconds=rational(movie_duration), movie_quantum_seconds=rational(movie_tick),
        format_duration_seconds=rational(format_duration), derived_format_bound_seconds=rational(format_bound),
        metadata_relative_arrays_agree_exactly=True,
        clock_domain='relative encoded video PTS and guest elapsed clock; no host UTC calibration')


def validate(video_path, frame_timeline):
    """Hosted-only native proof. Returns JSON-safe report or fixed-code ValueError."""
    hosted()
    path = Path(video_path)
    packets, frames = None, None
    try:
        require(path.is_absolute() and path.resolve(strict=True) == path and path.is_relative_to(ROOT), 'video_path')
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
            before = os.fstat(source.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= MAX_VIDEO, 'video_file')
            raw = source.read(MAX_VIDEO + 1)
            require(len(raw) == before.st_size, 'video_read')
            packets = native_json(path, 'packets')
            frames = native_json(path, 'frames')
            version = native_json(path, 'version')
            require(type(version) is dict and set(version) == {'program_version'}
                and type(version['program_version']) is dict and set(version['program_version']) == {'version'}, 'version_shape')
            after = os.fstat(source.fileno())
            current = path.lstat()
            identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            require(identity(before) == identity(after) == identity(current), 'video_changed')
            source.seek(0)
            require(source.read(MAX_VIDEO + 1) == raw, 'video_changed')
    except OSError:
        raise ValueError('native_timing_file_io') from None
    except ValueError as error:
        if packets is not None:
            error.native_timing_observation = observation(packets, frames)
        raise
    try:
        return coherence(raw, packets, frames, frame_timeline, version['program_version']['version'])
    except ValueError as error:
        error.native_timing_observation = observation(packets, frames)
        raise
