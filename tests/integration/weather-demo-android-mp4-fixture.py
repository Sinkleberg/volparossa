#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""SOURCE-DERIVED synthetic demuxer fixture; never Android/app evidence.

On the disposable runner, generate only one H264/avc1 video with distro
ffmpeg, leaving moov after mdat. inject(raw) appends two EMPTY source-shaped
metadata tracks. This avoids a separate data-input muxer and adds no payloads.
Actual ffprobe must verify the resulting three-stream container serializer.
The video track, all earlier media bytes and their offsets remain unchanged.

AOSP MPEG4Writer writeMetadataFourCCBox writes the MIME string twice for
legacy compatibility, explicitly using the first copy in place of reserved,
data-reference-index and encoding fields (no ordinary SampleEntry prefix):
https://android.googlesource.com/platform/frameworks/av/+/9ce151cc23792a799ca2e0ce66988b9f6e5b76e8/media/libstagefright/MPEG4Writer.cpp#4133
blob8f7d4bf0d0658faa77d75bcd342e2e16c80fe0a4, lines4142-4167.
This is a source profile, not a claim that the SDK image has that exact blob.
Screenrecord1df77b62...cpp:693-698 creates two such
application/octet-stream tracks. Here the sample tables are empty: there are
no actual frame timestamps, Winscope measurements or Android recordings.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

MAX_BYTES = 8 * 1024**2
MIME = b"application/octet-stream\0"


def require(value):
    if not value: raise ValueError("synthetic_android_mp4_fixture_rejected")


def box(tag, payload):
    require(type(tag) is bytes and len(tag) == 4 and len(payload) + 8 <= MAX_BYTES)
    return struct.pack(">I", len(payload) + 8) + tag + payload


def boxes(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES)
    result, offset = [], 0
    while offset < len(raw):
        require(len(result) < 128 and len(raw) - offset >= 8)
        size = struct.unpack(">I", raw[offset:offset + 4])[0]
        # The controlled tiny ffmpeg input needs neither extended sizes nor
        # to-end boxes. Reject either rather than reconstructing unknown data.
        require(8 <= size <= len(raw) - offset)
        result.append((raw[offset + 4:offset + 8], raw[offset + 8:offset + size]))
        offset += size
    return result


def only(raw, tag):
    selected = [payload for name, payload in boxes(raw) if name == tag]
    require(len(selected) == 1)
    return selected[0]


def empty_metadata_track(track_id):
    # Version0 ISO BMFF headers, zero duration and no samples. The sole
    # purpose is to exercise ffprobe's unknown DATA/mett stream serializer.
    identity = struct.pack(">9I", 65536, 0, 0, 0, 65536, 0, 0, 0, 1 << 30)
    tkhd = box(b"tkhd", b"\0\0\0\3" + struct.pack(">5I", 0, 0, track_id, 0, 0)
        + b"\0" * 16 + identity + b"\0" * 8)
    mdhd = box(b"mdhd", b"\0" * 4 + struct.pack(">4I2H", 0, 0, 1000, 0, 0x55c4, 0))
    hdlr = box(b"hdlr", b"\0" * 8 + b"meta" + b"\0" * 12 + b"\0")
    dref = box(b"dref", b"\0" * 4 + struct.pack(">I", 1) + box(b"url ", b"\0\0\0\1"))
    stsd = box(b"stsd", b"\0" * 4 + struct.pack(">I", 1) + box(b"mett", MIME + MIME))
    stbl = box(b"stbl", stsd + box(b"stts", b"\0" * 8) + box(b"stsc", b"\0" * 8)
        + box(b"stsz", b"\0" * 12) + box(b"stco", b"\0" * 8))
    minf = box(b"minf", box(b"nmhd", b"\0" * 4) + box(b"dinf", dref) + stbl)
    return box(b"trak", tkhd + box(b"mdia", mdhd + hdlr + minf))


def inject(raw):
    top = boxes(raw); tags = [tag for tag, _ in top]
    require(tags and tags[0] == b"ftyp" and tags[-1] == b"moov" and tags.count(b"moov") == tags.count(b"mdat") == 1
        and set(tags) <= {b"ftyp", b"free", b"mdat", b"moov"})
    movie = boxes(top[-1][1]); tracks = [body for name, body in movie if name == b"trak"]
    require(len(tracks) == 1)
    video = tracks[0]
    tkhd = only(video, b"tkhd")
    require(len(tkhd) == 84 and tkhd[0] == 0)
    video_id = struct.unpack(">I", tkhd[12:16])[0]
    mdia = only(video, b"mdia"); hdlr = only(mdia, b"hdlr")
    require(len(hdlr) >= 24 and hdlr[8:12] == b"vide")
    stsd = only(only(only(mdia, b"minf"), b"stbl"), b"stsd")
    require(stsd[:8] == b"\0\0\0\0\0\0\0\1")
    entries = boxes(stsd[8:]); require(len(entries) == 1 and entries[0][0] == b"avc1")
    mvhd = only(top[-1][1], b"mvhd")
    require(len(mvhd) == 100 and mvhd[:4] == b"\0" * 4 and video_id > 0)
    metadata_id = max(video_id + 1, struct.unpack(">I", mvhd[-4:])[0])
    require(1 < metadata_id <= 0xfffffffd)
    next_id = metadata_id + 2
    updated = b"".join(box(name, mvhd[:-4] + struct.pack(">I", next_id)) if name == b"mvhd" else box(name, body)
        for name, body in movie)
    updated += empty_metadata_track(metadata_id) + empty_metadata_track(metadata_id + 1)
    before_moov = b"".join(box(tag, payload) for tag, payload in top[:-1])
    result = before_moov + box(b"moov", updated)
    require(len(result) <= MAX_BYTES and result.startswith(before_moov))
    return result


def execute(source, destination):
    source, destination = Path(source), Path(destination)
    require(source.is_absolute() and source.resolve(strict=True) == source and destination.is_absolute()
        and destination.parent.resolve(strict=True) == destination.parent and source != destination)
    parent = destination.parent.stat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700)
    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= MAX_BYTES)
        raw = stream.read(MAX_BYTES + 1)
        after, named = os.fstat(stream.fileno()), source.stat()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(raw) == info.st_size and all(getattr(info, k) == getattr(after, k) == getattr(named, k) for k in fields))
    result = inject(raw)
    with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(result)
    return dict(schema=1, kind="synthetic-android-mett-demuxer-fixture", source_sha256=hashlib.sha256(raw).hexdigest(),
        output_sha256=hashlib.sha256(result).hexdigest(), output_bytes=len(result), video_tracks=1, metadata_tracks=2, metadata_samples=0,
        android_execution=False, app_pixels=False, joined_core_acceptance=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path); parser.add_argument("destination", type=Path)
    parser.add_argument("--execute", action="store_true"); args = parser.parse_args()
    try:
        value = execute(args.source, args.destination) if args.execute else dict(execute=False, synthetic_only=True)
        print(json.dumps(value, sort_keys=True))
    except (OSError, ValueError, TypeError, struct.error):
        raise SystemExit("synthetic_android_mp4_fixture_rejected") from None
