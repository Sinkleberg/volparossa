#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Admit only genuine same-run Android pixels after original v6 acceptance.

Media never supplies network, displayed-value, expiry or release authority.
The original closed evidence chain supplies those precisely bounded claims.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import struct
import subprocess

HERE = Path(__file__).resolve().parent
E = runpy.run_path(str(HERE / "weather-android-evidence.py"))
O = runpy.run_path(str(HERE / "weather-android-owner.py"))
MAX_VIDEO, MAX_PNG, MAX_SHOTS = 100 * 1024**2, 4 * 1024**2, 36
PNG = b"\x89PNG\r\n\x1a\n"


def require(value):
    if not value: raise ValueError("weather_demo_media_rejected")


def directory(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
    return path


def checked(path, maximum, *, destination=None):
    """One no-follow descriptor, bounded reads and same inode rechecks."""
    target = None
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= maximum)
        digest, total, prefix = hashlib.sha256(), 0, bytearray()
        try:
            if destination is not None:
                target = os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")
            while raw := stream.read(65536):
                total += len(raw); require(total <= maximum); digest.update(raw)
                prefix.extend(raw[:max(0, 24 - len(prefix))])
                if target is not None: target.write(raw)
            after, named = os.fstat(stream.fileno()), Path(path).lstat()
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            require(total == info.st_size and all(getattr(info, k) == getattr(after, k) == getattr(named, k) for k in fields))
        finally:
            if target is not None: target.close()
    return dict(bytes=total, sha256=digest.hexdigest()), bytes(prefix)


def document(path):
    return E["decode"](E["private_bytes"](Path(path), 65536, os.getuid(), 0o600), 65536)


def file_hash(path):
    return checked(path, 65536)[0]["sha256"]


def accepted(evidence):
    """Recheck the original closed guest/owner/VM chain without re-execution."""
    directory(evidence)
    require(not os.path.lexists(evidence / O["FAILURE_NAME"]))
    acceptance = document(evidence / "weather-android-hosted-acceptance.json")
    guest_path = evidence / "weather-android-delivery-evidence.json"
    owner_path = evidence / "weather-android-owner-join.json"
    vm_path = evidence / "weather-android-vm-cleanup.json"
    guest, joined, vm = document(guest_path), document(owner_path), document(vm_path)
    E["validate_guest_export"](guest)
    identity = acceptance["identity"]
    require(type(identity) is dict and set(identity) == {"core_commit", "weather_commit", "run_id", "run_attempt"}
        and all(type(identity[k]) is str and re.fullmatch(r"[a-f0-9]{40}", identity[k]) for k in ("core_commit", "weather_commit"))
        and all(type(identity[k]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", identity[k]) for k in ("run_id", "run_attempt")))
    O["candidate"](joined, guest, identity, acceptance["manifest_sha256"])
    require(vm == dict(schema=6, kind="weather-android-vm-cleanup", **{k: identity[k] for k in ("core_commit", "weather_commit")},
        manifest_sha256=acceptance["manifest_sha256"], driver_finished=True, qemu_started=True, qemu_joined=True,
        private_guest_state_removed=True, owner_exit_status=0, joined_core_acceptance=False))
    E["hashes"](acceptance, ("kvm_cleanup_sha256",))
    expected = dict(schema=6, kind="weather-android-hosted-acceptance", profile="android-protected-core-v6", identity=identity,
        manifest_sha256=acceptance["manifest_sha256"], core_sha256=joined["core_sha256"], prepared_sha256=joined["prepared_sha256"],
        owner_join_sha256=file_hash(owner_path), guest_evidence_sha256=file_hash(guest_path), vm_cleanup_sha256=file_hash(vm_path),
        kvm_cleanup_sha256=acceptance["kvm_cleanup_sha256"], observations=joined["observations"], passed=True,
        joined_core_acceptance=True, vm_cleanup_pending=False, helper_requests=0, expiry_proven=False,
        physical_device=False, production_authority=False)
    require(acceptance == expected and joined["guest_evidence_sha256"] == expected["guest_evidence_sha256"])
    return acceptance, joined


def probe_video(path):
    # Only the root-owned distro tool on the disposable hosted runner is used.
    tool = Path("/usr/bin/ffprobe"); info = tool.stat()
    require(tool.resolve(strict=True) == tool and stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    result = subprocess.run([str(tool), "-v", "error", "-protocol_whitelist", "file,pipe", "-show_entries",
        "stream=codec_type,codec_name,width,height:format=duration", "-of", "json", str(path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True)
    require(len(result.stdout) <= 65536 and not result.stderr)
    value = E["decode"](result.stdout, 65536)
    require(set(value) == {"streams", "format"} and value["streams"] == [dict(codec_name="h264", codec_type="video", width=720, height=1280)]
        and set(value["format"]) == {"duration"} and type(value["format"]["duration"]) is str
        and re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,6}", value["format"]["duration"]))
    duration = float(value["format"]["duration"]); require(0 < duration <= 180)
    return dict(codec="h264", width=720, height=1280, duration_seconds=duration, has_audio=False)


def media_files(root, files, shots):
    require(type(files) is dict and type(shots) is list and 1 <= len(shots) <= MAX_SHOTS)
    expected = {"screen.mp4"} | {f"screen-{i:03d}.png" for i in range(1, len(shots) + 1)}
    require(set(files) == expected)
    previous = -1
    for i, shot in enumerate(shots, 1):
        require(type(shot) is dict and set(shot) == {"file", "started_elapsed_ms", "completed_elapsed_ms", "stage"}
            and shot["file"] == f"screen-{i:03d}.png" and shot["stage"] == "unclassified")
        start, end = shot["started_elapsed_ms"], shot["completed_elapsed_ms"]
        require(type(start) is int and type(end) is int and previous <= start <= end <= 185000)
        previous = end
    total = 0
    for name in sorted(expected):
        actual, prefix = checked(root / name, MAX_VIDEO if name == "screen.mp4" else MAX_PNG)
        require(files[name] == actual); total += actual["bytes"]
        if name == "screen.mp4": require(prefix[4:8] == b"ftyp")
        else:
            require(prefix[:8] == PNG and prefix[12:16] == b"IHDR" and struct.unpack(">II", prefix[16:24]) == (1080, 1920))
    require(total <= 256 * 1024**2)


def verify(evidence_root):
    evidence = directory(evidence_root); acceptance, joined = accepted(evidence)
    root = directory(evidence / "demo-media"); value = document(root / "recording.json")
    require(set(value) == {"schema", "kind", "identity", "acceptance_sha256", "installed_report_sha256", "driver_window", "capture",
        "files", "screenshots", "video", "recorder_joined", "guest_file_removed", "joined_core_acceptance", "stage_labels_verified", "production_authority", "encoding_tolerance_ms", "visual_review_required"})
    require(value["schema"] == 1 and value["kind"] == "weather-demo-accepted-media" and value["identity"] == acceptance["identity"]
        and value["acceptance_sha256"] == file_hash(evidence / "weather-android-hosted-acceptance.json")
        and value["installed_report_sha256"] == joined["original_android_report_sha256"])
    require(all(value[k] is True for k in ("recorder_joined", "guest_file_removed", "joined_core_acceptance"))
        and value["stage_labels_verified"] is False and value["production_authority"] is False
        and type(value["encoding_tolerance_ms"]) is int and value["encoding_tolerance_ms"] == 250
        and value["visual_review_required"] is True)
    capture, window = value["capture"], value["driver_window"]
    require(type(capture) is dict and set(capture) == {"started_unix_ms", "completed_unix_ms", "elapsed_ms"}
        and type(window) is dict and set(window) == {"started_unix_ms", "completed_unix_ms"})
    require(all(type(v) is int and v > 0 for v in [*capture.values(), *window.values()])
        and capture["started_unix_ms"] <= window["started_unix_ms"] < window["completed_unix_ms"] <= capture["completed_unix_ms"]
        and 0 < capture["elapsed_ms"] <= 205000
        and abs(capture["completed_unix_ms"] - capture["started_unix_ms"] - capture["elapsed_ms"]) <= 1000)
    require({p.name for p in root.iterdir()} == set(value["files"]) | {"recording.json"})
    media_files(root, value["files"], value["screenshots"])
    require(probe_video(root / "screen.mp4") == value["video"])
    # Android's first/last encoded frame can fall between clock samples. A
    # fixed 250ms tolerance admits that granularity, not a truncated stage.
    # completed_unix_ms includes pull/removal: it is never a video end marker.
    # Human visual review is still required for readable semantic stages.
    video_ms = value["video"]["duration_seconds"] * 1000
    require(video_ms + 250 >= window["completed_unix_ms"] - capture["started_unix_ms"]
        and video_ms <= capture["elapsed_ms"] + 250)
    return value


def export(evidence_root, weather_root):
    evidence, weather = directory(evidence_root), Path(weather_root)
    acceptance, joined = accepted(evidence)
    # The original launcher already verified clean Git source. Recheck that
    # exact source/identity here before admitting its dedicated output tree.
    O["git_check"](weather, acceptance["identity"]["weather_commit"])
    O["hosted"](acceptance["identity"]["core_commit"], acceptance["identity"]["weather_commit"])
    root = directory(weather / "build/overmorrow-hosted-android-live-proof/demo-media")
    raw, window = document(root / "recording.json"), document(root / "driver-window.json")
    require(set(raw) == {"schema", "kind", "started_unix_ms", "completed_unix_ms", "elapsed_ms", "source", "files", "screenshots",
        "recorder_joined", "guest_file_removed", "stage_labels_verified", "ui_values_verified", "joined_core_acceptance", "production_authority"})
    require(raw["schema"] == 1 and raw["kind"] == "weather-demo-android-recording" and raw["source"] == "android-screenrecord-and-screencap"
        and raw["recorder_joined"] is True and raw["guest_file_removed"] is True
        and all(raw[k] is False for k in ("stage_labels_verified", "ui_values_verified", "joined_core_acceptance", "production_authority")))
    require(set(window) == {"schema", "started_unix_ms", "completed_unix_ms", "installed_report_sha256"} and window["schema"] == 1
        and window["installed_report_sha256"] == joined["original_android_report_sha256"])
    require({p.name for p in root.iterdir()} == set(raw["files"]) | {"recording.json", "driver-window.json"})
    media_files(root, raw["files"], raw["screenshots"])
    value = dict(schema=1, kind="weather-demo-accepted-media", identity=acceptance["identity"],
        acceptance_sha256=file_hash(evidence / "weather-android-hosted-acceptance.json"),
        installed_report_sha256=window["installed_report_sha256"],
        driver_window={k: window[k] for k in ("started_unix_ms", "completed_unix_ms")},
        capture={k: raw[k] for k in ("started_unix_ms", "completed_unix_ms", "elapsed_ms")},
        files=raw["files"], screenshots=raw["screenshots"], video=probe_video(root / "screen.mp4"),
        recorder_joined=True, guest_file_removed=True, joined_core_acceptance=True, stage_labels_verified=False, production_authority=False,
        encoding_tolerance_ms=250, visual_review_required=True)
    destination = evidence / "demo-media"; destination.mkdir(mode=0o700)
    for name, expected in sorted(value["files"].items()):
        actual, _ = checked(root / name, MAX_VIDEO if name == "screen.mp4" else MAX_PNG, destination=destination / name)
        require(actual == expected)
    O["write"](destination / "recording.json", value)
    return verify(evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("action", choices=("export", "verify"))
    parser.add_argument("--evidence", type=Path, required=True); parser.add_argument("--weather-root", type=Path)
    args = parser.parse_args()
    require((args.action == "export") == (args.weather_root is not None))
    value = export(args.evidence, args.weather_root) if args.action == "export" else verify(args.evidence)
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        raise SystemExit("weather_demo_media_rejected") from None
