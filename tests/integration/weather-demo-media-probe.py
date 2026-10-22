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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
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
        source_revision=os.environ["GITHUB_SHA"], run_id=os.environ["GITHUB_RUN_ID"])
    with tempfile.TemporaryDirectory(dir=root) as temporary:
        video = Path(temporary) / "synthetic-tool-input.mp4"
        subprocess.run(["/usr/bin/ffmpeg", "-nostdin", "-v", "error", "-f", "lavfi", "-i",
            "color=c=black:s=720x1280:r=30:d=1", "-c:v", "libx264", "-threads", "2",
            "-pix_fmt", "yuv420p", "-an", str(video)], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=True)
        raw = subprocess.run(["/usr/bin/ffprobe", "-v", "error", "-protocol_whitelist", "file,pipe", "-show_entries",
            "stream=codec_type,codec_name,width,height:format=duration", "-of", "json", str(video)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True)
        if len(raw.stdout) > 65536 or raw.stderr:
            raise SystemExit("Bounded ffprobe observation rejected")
        value = json.loads(raw.stdout)
        # Known synthetic media only: no URLs, paths, tags or device fields.
        if not set(value) <= {"programs", "stream_groups", "streams", "format"}:
            raise SystemExit("Unexpected serializer shape; no raw output exported")
        record["serializer"] = value
        module = runpy.run_path(str(ROOT / "tests/integration/weather-demo-media.py"))
        try:
            record["parser_under_test_result"] = module["probe_video"](video)
            record["parser_under_test_accepted"] = True
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            record["parser_under_test_result"] = None
            record["parser_under_test_accepted"] = False
        presentation = runpy.run_path(str(ROOT / "scripts/weather-demo-0-package.py"))
        output = Path(temporary) / "synthetic-presentation"
        output.mkdir(mode=0o700)
        raw_info = presentation["video_info"](video)
        _, rendered = presentation["render_video"](video, output, 120, raw_info,
            [("SYNTHETIC TOOL TEST / NOT ANDROID EVIDENCE", 32, "ffffff")])
        record["presentation_tool_probe"] = dict(completed=True, video=rendered,
            synthetic_input_only=True, media_retained=False)
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
        version = subprocess.run(["/usr/bin/ffprobe", "-version"], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=10, check=True)
        record["ffprobe_version"] = version.stdout.decode().splitlines()[0]
    (root / "probe.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
