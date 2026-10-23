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
FAILURE_NAME = "weather-demo-media-failure.json"
STAGES = frozenset(("arguments", "accepted-evidence", "source-binding", "recording-records", "raw-inventory",
    "raw-media", "video-tool", "video-process", "video-json", "video-metadata", "copy-media", "verify-record",
    "verify-window", "verify-inventory", "verify-media", "verify-video", "verify-duration", "capture-window", "collect-copy", "collect-record"))
CATEGORIES = frozenset(("io", "value", "type", "key", "timeout", "process", "unknown"))
NUMBER_FACTS = frozenset(("stream_count", "width", "height", "duration_ms", "required_end_ms", "capture_elapsed_ms"))
CONTAINER_FACTS = frozenset(("programs", "stream_groups"))
CONTAINER_STATES = frozenset(("absent", "empty", "nonempty", "wrong-type"))
STREAM_FACTS = {
    "stream_types": frozenset(("video", "data", "audio", "subtitle", "attachment")),
    "stream_tags": frozenset(("avc1", "mett", "gpmd")),
    "stream_codecs": frozenset(("h264", "bin_data")),
}
STREAM_FACT_UNKNOWN = frozenset(("absent", "wrong-type", "other"))
STATE = dict(stage="arguments", facts={}, accepted_evidence_checked=False)


def stage(name, **facts):
    require(name in STAGES)
    STATE.update(stage=name, facts=facts)


def container_state(value, name):
    if name not in value: return "absent"
    if type(value[name]) is not list: return "wrong-type"
    return "nonempty" if value[name] else "empty"


def validate_failure(value):
    require(type(value) is dict and set(value) == {"schema", "kind", "action", "identity", "stage", "category", "facts",
        "accepted_evidence_checked", "joined_core_acceptance", "production_authority"})
    require(type(value["schema"]) is int and value["schema"] == 1 and value["kind"] == "weather-demo-media-failure"
        and value["action"] in ("collect", "export", "verify") and value["stage"] in STAGES and value["category"] in CATEGORIES
        and type(value["accepted_evidence_checked"]) is bool and value["joined_core_acceptance"] is False
        and value["production_authority"] is False)
    identity = value["identity"]
    require(identity is None or type(identity) is dict and set(identity) == {"core_commit", "weather_commit", "run_id", "run_attempt"}
        and all(type(identity[k]) is str and re.fullmatch(r"[a-f0-9]{40}", identity[k]) for k in ("core_commit", "weather_commit"))
        and all(type(identity[k]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", identity[k]) for k in ("run_id", "run_attempt")))
    facts = value["facts"]
    require(type(facts) is dict and set(facts) <= NUMBER_FACTS | CONTAINER_FACTS | set(STREAM_FACTS))
    for key, item in facts.items():
        if key in NUMBER_FACTS:
            require(item is None or type(item) is int and 0 <= item <= 256 * 1024**2)
        elif key in CONTAINER_FACTS:
            require(type(item) is str and item in CONTAINER_STATES)
        else:
            require(type(item) is list and len(item) <= 8 and all(type(entry) is str
                and entry in STREAM_FACTS[key] | STREAM_FACT_UNKNOWN for entry in item))
    require(len(json.dumps(value, sort_keys=True).encode()) <= 4096)
    return value


def failure(error, action):
    category = ("timeout" if isinstance(error, subprocess.TimeoutExpired) else
        "process" if isinstance(error, subprocess.SubprocessError) else "io" if isinstance(error, OSError) else
        "value" if isinstance(error, ValueError) else "type" if isinstance(error, TypeError) else
        "key" if isinstance(error, KeyError) else "unknown")
    identity = dict(core_commit=os.environ.get("GITHUB_SHA", ""), weather_commit=os.environ.get("VOLPAROSSA_WEATHER_SOURCE_SHA", ""),
        run_id=os.environ.get("GITHUB_RUN_ID", ""), run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT", ""))
    if not (all(re.fullmatch(r"[a-f0-9]{40}", identity[k]) for k in ("core_commit", "weather_commit"))
            and all(re.fullmatch(r"[1-9][0-9]{0,19}", identity[k]) for k in ("run_id", "run_attempt"))): identity = None
    return validate_failure(dict(schema=1, kind="weather-demo-media-failure", action=action, identity=identity,
        stage=STATE["stage"], category=category, facts=dict(STATE["facts"]),
        accepted_evidence_checked=STATE["accepted_evidence_checked"], joined_core_acceptance=False, production_authority=False))



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
    stage("accepted-evidence"); STATE["accepted_evidence_checked"] = False
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
    STATE["accepted_evidence_checked"] = True
    return acceptance, joined


def stream_facts(streams):
    facts = {"stream_count": min(len(streams), 1024) if type(streams) is list else None}
    if type(streams) is not list: return facts
    for fact, field in (("stream_types", "codec_type"), ("stream_tags", "codec_tag_string"), ("stream_codecs", "codec_name")):
        def classify(stream):
            if type(stream) is not dict: return "wrong-type"
            if field not in stream: return "absent"
            item = stream[field]
            if type(item) is not str: return "wrong-type"
            return item if item in STREAM_FACTS[fact] else "other"
        facts[fact] = [classify(stream) for stream in streams[:8]]
    videos = [item for item in streams if type(item) is dict and item.get("codec_type") == "video"]
    if len(videos) == 1:
        for key in ("width", "height"):
            item = videos[0].get(key)
            facts[key] = item if type(item) is int and 0 <= item <= 8192 else None
    return facts


def video_metadata(value):
    stage("video-metadata")
    if type(value) is dict:
        stage("video-metadata", **{key: container_state(value, key) for key in CONTAINER_FACTS},
            **stream_facts(value.get("streams")))
    # The optional empty programs list is observed Ubuntu6.1.1 output.
    # Android's two DATA/mett tracks below are a SOURCE-DERIVED profile, not
    # observed Android JSON: screenrecord1df77b62...cpp:693-698 adds two
    # application/octet-stream Winscope tracks alongside its AVC track.
    # FFmpeg n6.1.1 mov.c:4336 starts unknown tracks as DATA; isom.c's data
    # tags map gpmd only. An unrecognized mett codec therefore has no name.
    # Do not accept bin_data/mett without actual tool evidence supporting it.
    require(type(value) is dict and set(value) in ({"streams", "format"}, {"streams", "format", "programs"})
        and ("programs" not in value or type(value["programs"]) is list and not value["programs"])
        and type(value["streams"]) is list and len(value["streams"]) in (1, 3))
    streams = value["streams"]
    require(all(type(item) is dict for item in streams))
    video = dict(codec_name="h264", codec_type="video", codec_tag_string="avc1", width=720, height=1280)
    metadata = dict(codec_type="data", codec_tag_string="mett")
    require(sum(item == video for item in streams) == 1
        and sum(item == metadata for item in streams) == len(streams) - 1
        and type(value["format"]) is dict and set(value["format"]) == {"duration"}
        and type(value["format"]["duration"]) is str and re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,6}", value["format"]["duration"]))
    duration = float(value["format"]["duration"])
    stage("video-metadata", **STATE["facts"], duration_ms=round(duration * 1000))
    require(0 < duration <= 180)
    return dict(codec="h264", width=720, height=1280, duration_seconds=duration, has_audio=False)


def probe_video(path):
    # Only the root-owned distro tool on the disposable hosted runner is used.
    stage("video-tool")
    tool = Path("/usr/bin/ffprobe"); info = tool.stat()
    require(tool.resolve(strict=True) == tool and stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    stage("video-process")
    result = subprocess.run([str(tool), "-v", "error", "-protocol_whitelist", "file,pipe", "-show_entries",
        "stream=codec_type,codec_name,codec_tag_string,width,height:format=duration", "-of", "json", str(path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True)
    require(len(result.stdout) <= 65536 and not result.stderr)
    stage("video-json")
    value = E["decode"](result.stdout, 65536)
    return video_metadata(value)



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
        # A later file/hash failure must not inherit another image's facts.
        stage(STATE["stage"])
        actual, prefix = checked(root / name, MAX_VIDEO if name == "screen.mp4" else MAX_PNG)
        require(files[name] == actual); total += actual["bytes"]
        if name == "screen.mp4": require(prefix[4:8] == b"ftyp")
        else:
            require(len(prefix) == 24 and prefix[:8] == PNG and prefix[12:16] == b"IHDR")
            width, height = struct.unpack(">II", prefix[16:24])
            stage(STATE["stage"], width=width if width <= 8192 else None, height=height if height <= 8192 else None)
            require((width, height) == (1080, 1920))
    require(total <= 256 * 1024**2)


def window_bounds(capture, window):
    require(type(capture) is dict and set(capture) == {"started_unix_ms", "completed_unix_ms", "elapsed_ms"}
        and type(window) is dict and set(window) == {"started_unix_ms", "completed_unix_ms"})
    require(all(type(v) is int and v > 0 for v in [*capture.values(), *window.values()])
        and capture["started_unix_ms"] <= window["started_unix_ms"] < window["completed_unix_ms"] <= capture["completed_unix_ms"]
        and 0 < capture["elapsed_ms"] <= 205000
        and abs(capture["completed_unix_ms"] - capture["started_unix_ms"] - capture["elapsed_ms"]) <= 1000)


def verify(evidence_root):
    evidence = directory(evidence_root); acceptance, joined = accepted(evidence)
    stage("verify-record")
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
    stage("verify-window")
    capture, window = value["capture"], value["driver_window"]
    window_bounds(capture, window)
    stage("verify-inventory")
    require({p.name for p in root.iterdir()} == set(value["files"]) | {"recording.json"})
    stage("verify-media"); media_files(root, value["files"], value["screenshots"])
    probed = probe_video(root / "screen.mp4")
    stage("verify-video"); require(probed == value["video"])
    # Android's first/last encoded frame can fall between clock samples. A
    # fixed 250ms tolerance admits that granularity, not a truncated stage.
    # completed_unix_ms includes pull/removal: it is never a video end marker.
    # Human visual review is still required for readable semantic stages.
    video_ms = value["video"]["duration_seconds"] * 1000
    stage("verify-duration", duration_ms=round(video_ms),
        required_end_ms=window["completed_unix_ms"] - capture["started_unix_ms"], capture_elapsed_ms=capture["elapsed_ms"])
    require(video_ms + 250 >= window["completed_unix_ms"] - capture["started_unix_ms"]
        and video_ms <= capture["elapsed_ms"] + 250)
    return value


def capture_inputs(evidence_root, weather_root):
    evidence, weather = directory(evidence_root), Path(weather_root)
    acceptance, joined = accepted(evidence)
    # The original launcher already verified clean Git source. Recheck that
    # exact source/identity here before admitting its dedicated output tree.
    stage("source-binding")
    O["git_check"](weather, acceptance["identity"]["weather_commit"])
    O["hosted"](acceptance["identity"]["core_commit"], acceptance["identity"]["weather_commit"])
    stage("recording-records")
    root = directory(weather / "build/overmorrow-hosted-android-live-proof/demo-media")
    records, record_hashes = {}, {}
    for name in ("recording.json", "driver-window.json"):
        raw_bytes = E["private_bytes"](root / name, 65536, os.getuid(), 0o600)
        records[name] = E["decode"](raw_bytes, 65536)
        record_hashes[name] = dict(bytes=len(raw_bytes), sha256=hashlib.sha256(raw_bytes).hexdigest())
    raw, window = records["recording.json"], records["driver-window.json"]
    require(set(raw) == {"schema", "kind", "started_unix_ms", "completed_unix_ms", "elapsed_ms", "source", "files", "screenshots",
        "recorder_joined", "guest_file_removed", "stage_labels_verified", "ui_values_verified", "joined_core_acceptance", "production_authority"})
    require(raw["schema"] == 1 and raw["kind"] == "weather-demo-android-recording" and raw["source"] == "android-screenrecord-and-screencap"
        and raw["recorder_joined"] is True and raw["guest_file_removed"] is True
        and all(raw[k] is False for k in ("stage_labels_verified", "ui_values_verified", "joined_core_acceptance", "production_authority")))
    require(set(window) == {"schema", "started_unix_ms", "completed_unix_ms", "installed_report_sha256"} and window["schema"] == 1
        and window["installed_report_sha256"] == joined["original_android_report_sha256"])
    stage("raw-inventory")
    require({p.name for p in root.iterdir()} == set(raw["files"]) | {"recording.json", "driver-window.json"})
    stage("raw-media"); media_files(root, raw["files"], raw["screenshots"])
    stage("capture-window")
    window_bounds({k: raw[k] for k in ("started_unix_ms", "completed_unix_ms", "elapsed_ms")},
        {k: window[k] for k in ("started_unix_ms", "completed_unix_ms")})
    return evidence, root, raw, window, acceptance, joined, record_hashes


def collect(evidence_root, weather_root):
    """Retain source-bound pixels for review, without asserting video admission.

    This explicit phase runs after original Core acceptance and before ffprobe
    or the encoded-duration gate. Failure later cannot erase the original run.
    Its dedicated inventory contains no runtime directories, logs or keys.
    """
    evidence, root, raw, window, acceptance, joined, records = capture_inputs(evidence_root, weather_root)
    stage("collect-copy")
    destination = evidence / "demo-capture-quarantine"; destination.mkdir(mode=0o700)
    pixels, originals = destination / "source-capture", destination / "original-acceptance"
    pixels.mkdir(mode=0o700); originals.mkdir(mode=0o700)
    inventory = {}
    selected = {**{name: (name, item) for name, item in raw["files"].items()},
        "rawrecording.json": ("recording.json", records["recording.json"]),
        "driver-window.json": ("driver-window.json", records["driver-window.json"])}
    for output_name, (source_name, expected) in sorted(selected.items()):
        maximum = MAX_VIDEO if source_name == "screen.mp4" else MAX_PNG if source_name.endswith(".png") else 65536
        item, _ = checked(root / source_name, maximum, destination=pixels / output_name)
        require(item == expected); inventory["source-capture/" + output_name] = item
    for name in ("weather-android-hosted-acceptance.json", "weather-android-owner-join.json",
            "weather-android-delivery-evidence.json", "weather-android-vm-cleanup.json"):
        item, _ = checked(evidence / name, 65536, destination=originals / name)
        inventory["original-acceptance/" + name] = item
    copied_acceptance, copied_joined = accepted(originals)
    require(copied_acceptance == acceptance and copied_joined == joined)
    stage("collect-record")
    value = dict(schema=1, kind="weather-demo-quarantined-capture", identity=acceptance["identity"],
        original_acceptance_sha256=inventory["original-acceptance/weather-android-hosted-acceptance.json"]["sha256"],
        original_android_report_sha256=joined["original_android_report_sha256"], files=inventory,
        capture={k: raw[k] for k in ("started_unix_ms", "completed_unix_ms", "elapsed_ms")},
        driver_window={k: window[k] for k in ("started_unix_ms", "completed_unix_ms")},
        original_core_acceptance_passed=True, media_accepted=False, joined_media_acceptance=False,
        production_authority=False, review_required=True)
    O["write"](destination / "capture.json", value)
    require({p.name for p in destination.iterdir()} == {"source-capture", "original-acceptance", "capture.json"}
        and {p.name for p in pixels.iterdir()} == set(selected) and {p.name for p in originals.iterdir()} ==
        {name.split("/", 1)[1] for name in inventory if name.startswith("original-acceptance/")})
    return value


def export(evidence_root, weather_root):
    evidence, root, raw, window, acceptance, joined, _ = capture_inputs(evidence_root, weather_root)
    value = dict(schema=1, kind="weather-demo-accepted-media", identity=acceptance["identity"],
        acceptance_sha256=file_hash(evidence / "weather-android-hosted-acceptance.json"),
        installed_report_sha256=window["installed_report_sha256"],
        driver_window={k: window[k] for k in ("started_unix_ms", "completed_unix_ms")},
        capture={k: raw[k] for k in ("started_unix_ms", "completed_unix_ms", "elapsed_ms")},
        files=raw["files"], screenshots=raw["screenshots"], video=probe_video(root / "screen.mp4"),
        recorder_joined=True, guest_file_removed=True, joined_core_acceptance=True, stage_labels_verified=False, production_authority=False,
        encoding_tolerance_ms=250, visual_review_required=True)
    stage("copy-media")
    destination = evidence / "demo-media"; destination.mkdir(mode=0o700)
    for name, expected in sorted(value["files"].items()):
        actual, _ = checked(root / name, MAX_VIDEO if name == "screen.mp4" else MAX_PNG, destination=destination / name)
        require(actual == expected)
    O["write"](destination / "recording.json", value)
    return verify(evidence)


def main():
    STATE.update(stage="arguments", facts={}, accepted_evidence_checked=False)
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("action", choices=("collect", "export", "verify"))
    parser.add_argument("--evidence", type=Path, required=True); parser.add_argument("--weather-root", type=Path)
    args = parser.parse_args()
    require((args.action in ("collect", "export")) == (args.weather_root is not None))
    try:
        if args.action == "collect": value = collect(args.evidence, args.weather_root)
        elif args.action == "export": value = export(args.evidence, args.weather_root)
        else: value = verify(args.evidence)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        value = failure(error, args.action)
        # Exclusive closed diagnostics only. An unsafe/missing evidence root
        # does not grant authority to create or repair it. The original failure
        # and acceptance records are never overwritten by this observation.
        try: O["write"](directory(args.evidence) / FAILURE_NAME, value)
        except (OSError, ValueError, TypeError, KeyError): pass
        print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)
        raise SystemExit("weather_demo_media_rejected") from None
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        raise SystemExit("weather_demo_media_rejected") from None
