#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe distro ffprobe serialization; synthetic tool input, never Android proof."""
import argparse
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def serializer(video):
    result = subprocess.run(["/usr/bin/ffprobe", "-v", "error", "-protocol_whitelist", "file,pipe", "-show_entries",
        "stream=codec_type,codec_name,codec_tag_string,width,height:format=duration", "-of", "json", str(video)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        check=True, env=NATIVE_ENV)
    if len(result.stdout) > 65536 or result.stderr:
        raise SystemExit("Bounded synthetic ffprobe observation rejected")
    value = json.loads(result.stdout)
    if not set(value) <= {"programs", "stream_groups", "streams", "format"}:
        raise SystemExit("Unexpected synthetic serializer shape; no raw output exported")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--render-held-image", action="store_true",
        help="exercise optional held-image renderer using only a synthetic contact PNG")
    args = parser.parse_args()
    root = args.output
    if not (os.getuid() == os.geteuid() != 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "VOLPAROSSA/volparossa"
            and root.is_absolute() and root.is_relative_to(ROOT) and not root.exists()
            and root.parent.resolve(strict=True) == root.parent):
        raise SystemExit("Hosted media-tool probe scope rejected")
    root.mkdir(mode=0o700)
    record = dict(schema=1, kind="weather-demo-synthetic-media-tool-probe", android_executed=False,
        genuine_app_pixels=False, joined_core_acceptance=False, production_authority=False,
        source_revision=os.environ["GITHUB_SHA"], run_id=os.environ["GITHUB_RUN_ID"], probe_completed=False)
    def checkpoint(stage):
        record["stage"] = stage
        pending = root / "probe.part"
        pending.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        pending.replace(root / "probe.json")
    checkpoint("synthetic-input")
    with tempfile.TemporaryDirectory(dir=root) as temporary:
        video = Path(temporary) / "synthetic-tool-input.mp4"
        subprocess.run(["/usr/bin/ffmpeg", "-nostdin", "-v", "error", "-f", "lavfi", "-i",
            "color=c=black:s=720x1280:r=30:d=1", "-c:v", "libx264", "-threads", "2",
            "-pix_fmt", "yuv420p", "-an", str(video)], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=True, env=NATIVE_ENV)
        # Known synthetic media only: selected format fields, no user metadata.
        record["serializer"] = serializer(video)
        checkpoint("single-track-parser")
        module = runpy.run_path(str(ROOT / "tests/integration/weather-demo-media.py"))
        try:
            record["parser_under_test_result"] = module["probe_video"](video)
            record["parser_under_test_accepted"] = True
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            record["parser_under_test_result"] = None
            record["parser_under_test_accepted"] = False
        # Format-only synthetic fixture, never Android/app evidence. AOSP MP4
        # records two timing metadata tracks; exercise that container profile
        # through the actual distro demuxer before an expensive runtime trial.
        checkpoint("synthetic-metadata-fixture")
        fixture = runpy.run_path(str(ROOT / "tests/integration/weather-demo-android-mp4-fixture.py"))
        android_profile = Path(temporary) / "synthetic-three-track-mett.mp4"
        android_profile.write_bytes(fixture["inject"](video.read_bytes()))
        record["android_metadata_profile_serializer"] = serializer(android_profile)
        checkpoint("synthetic-metadata-parser")
        profile_info = module["probe_video"](android_profile)
        record["android_metadata_profile_tool_probe"] = dict(completed=True, video=profile_info,
            synthetic_container_only=True, android_executed=False, genuine_app_pixels=False,
            metadata_tracks_are_empty=True, media_retained=False)
        checkpoint("synthetic-presentation")
        presentation = runpy.run_path(str(ROOT / "scripts/weather-demo-0-package.py"))
        output = Path(temporary) / "synthetic-presentation"
        output.mkdir(mode=0o700)
        raw_info = presentation["video_info"](video)
        _, rendered = presentation["render_video"](video, output, 120, raw_info,
            [("SYNTHETIC TOOL TEST / NOT ANDROID EVIDENCE", 32, "ffffff")])
        record["presentation_tool_probe"] = dict(completed=True, video=rendered,
            synthetic_input_only=True, media_retained=False)
        checkpoint("synthetic-contact-sheets")
        review = runpy.run_path(str(ROOT / "scripts/weather-demo-0-review.py"))
        sample_evidence = Path(temporary) / "synthetic-sampling-input"
        (sample_evidence / "demo-media").mkdir(parents=True)
        shutil.copyfile(video, sample_evidence / "demo-media/screen.mp4")
        sample_output = Path(temporary) / "synthetic-sampling-output"
        sample_output.mkdir()
        sampled = review["contact_sheets"](sample_evidence, sample_output,
            dict(video=dict(duration_seconds=1.0)))
        record["contact_sheet_tool_probe"] = dict(completed=True, rendered=sampled,
            synthetic_input_only=True, media_retained=False)
        if args.render_held_image:
            checkpoint("synthetic-selected-image-render")
            held_output = Path(temporary) / "synthetic-held-presentation"
            held_output.mkdir(mode=0o700)
            _, held_info = presentation["render_video"](video, held_output, 3, raw_info,
                [("SYNTHETIC HELD IMAGE / NOT ANDROID EVIDENCE", 32, "ffffff")],
                hold_image=sample_output / "poster.png")
            record["held_image_tool_probe"] = dict(completed=True, video=held_info,
                synthetic_input_only=True, android_executed=False, genuine_app_pixels=False,
                joined_core_acceptance=False, media_retained=False)
        version = subprocess.run(["/usr/bin/ffprobe", "-version"], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=10, check=True, env=NATIVE_ENV)
        record["ffprobe_version"] = version.stdout.decode().splitlines()[0]
    record["probe_completed"] = record["parser_under_test_accepted"] is True
    checkpoint("completed" if record["probe_completed"] else "single-track-parser-rejected")
    print(json.dumps(record, sort_keys=True))
    if not record["probe_completed"]:
        raise SystemExit("Synthetic parser rejected; no Android execution claimed")


if __name__ == "__main__":
    main()
