#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""SOURCE-DERIVED synthetic demuxer fixture; never Android/app evidence.

On the disposable runner, first mux one generated H264/avc1 video and two
explicit synthetic data inputs as bin_data/gpmd using distro ffmpeg. Leave
moov after mdat (no faststart). This helper changes only the two stsd sample
entries to Android's mett/application/octet-stream layout, updating enclosing
box sizes. Earlier media bytes and every chunk offset remain unchanged.

FFmpeg n6.1.1 movenc.c:2405-2414 writes the supported gpmd input entry.
AOSP MPEG4Writer writeMetadataFourCCBox writes the MIME string twice for
legacy compatibility, explicitly using the first copy in place of reserved,
data-reference-index and encoding fields (no ordinary SampleEntry prefix):
https://android.googlesource.com/platform/frameworks/av/+/9ce151cc23792a799ca2e0ce66988b9f6e5b76e8/media/libstagefright/MPEG4Writer.cpp#4133
blob8f7d4bf0d0658faa77d75bcd342e2e16c80fe0a4, lines4142-4167.
This is a source profile, not a claim that the SDK image has that exact blob.
Screenrecord1df77b62...cpp:693-698 creates two such
application/octet-stream tracks. Payloads here remain synthetic, not Winscope
measurements. Actual ffprobe must still verify the produced serializer.
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


def convert(raw):
    top = boxes(raw); tags = [tag for tag, _ in top]
    require(tags and tags[0] == b"ftyp" and tags[-1] == b"moov" and tags.count(b"moov") == tags.count(b"mdat") == 1
        and set(tags) <= {b"ftyp", b"free", b"mdat", b"moov"})
    counts = dict(video=0, metadata=0)
    def rewrite(tag, payload, path):
        if path in ((b"moov",), (b"moov", b"trak"), (b"moov", b"trak", b"mdia"),
                (b"moov", b"trak", b"mdia", b"minf"), (b"moov", b"trak", b"mdia", b"minf", b"stbl")):
            return box(tag, b"".join(rewrite(child, body, path + (child,)) for child, body in boxes(payload)))
        if path == (b"moov", b"trak", b"mdia", b"minf", b"stbl", b"stsd"):
            require(payload[:8] == b"\0\0\0\0\0\0\0\1")
            entries = boxes(payload[8:]); require(len(entries) == 1)
            entry, body = entries[0]
            if entry == b"avc1": counts["video"] += 1
            else:
                require(entry == b"gpmd" and body == b"\0\0\0\0\0\0\0\1\0\0\0\0")
                counts["metadata"] += 1
                return box(tag, payload[:8] + box(b"mett", MIME + MIME))
        return box(tag, payload)
    before_moov = b"".join(box(tag, payload) for tag, payload in top[:-1])
    result = before_moov + rewrite(*top[-1], (b"moov",))
    require(counts == dict(video=1, metadata=2) and len(result) <= MAX_BYTES and result.startswith(before_moov))
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
    result = convert(raw)
    with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(result)
    return dict(schema=1, kind="synthetic-android-mett-demuxer-fixture", source_sha256=hashlib.sha256(raw).hexdigest(),
        output_sha256=hashlib.sha256(result).hexdigest(), output_bytes=len(result), video_tracks=1, metadata_tracks=2,
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
