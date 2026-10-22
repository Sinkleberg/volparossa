#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic admission negatives only; never media or runtime evidence."""
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import runpy
import struct
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / "weather-demo-media.py"))
G = M["verify"].__globals__
F = runpy.run_path(str(HERE / "test-weather-android-owner.py"))
save = F["save"]
VIDEO = dict(codec="h264", width=720, height=1280, duration_seconds=11.5, has_audio=False)
# Original synthetic hosted probe39869565948 on Ubuntu ffprobe6.1.1-3ubuntu5.
# Artifact12466015525 SHA256a3d70dcdf0792ca42129c2dd53404108d28f1079ba1901a381e9b1b24bdde3c1.
# This fixture tests the serializer contract, not Android or delivery behavior.
PROBE_JSON = b'{"format":{"duration":"1.000000"},"programs":[],"streams":[{"codec_name":"h264","codec_type":"video","height":1280,"width":720}]}'


class Probe(unittest.TestCase):
    def probe(self, raw=PROBE_JSON, stderr=b"", error=None):
        # Stub only the external tool boundary. Exercise the actual command,
        # duplicate-key decoder, metadata parser and diagnostic projection.
        tool = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        with patch.object(Path, "stat", return_value=tool), \
                patch.object(Path, "resolve", lambda path, **_: path), \
                patch.object(M["subprocess"], "run", return_value=SimpleNamespace(stdout=raw, stderr=stderr), side_effect=error) as run:
            result = M["probe_video"](Path("/inert/private/movie.mp4"))
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/bin/ffprobe", "-v", "error", "-protocol_whitelist"])
        self.assertEqual(argv[-1], "/inert/private/movie.mp4")
        self.assertEqual(run.call_args.kwargs["timeout"], 15)
        self.assertTrue(run.call_args.kwargs["check"])
        return result

    def test_exact_hosted_serializer_passes_real_parser_with_optional_empty_programs(self):
        self.assertEqual(self.probe(), dict(VIDEO, duration_seconds=1.0))
        value = json.loads(PROBE_JSON); value.pop("programs")
        self.assertEqual(self.probe(json.dumps(value).encode()), dict(VIDEO, duration_seconds=1.0))

    def test_nonempty_or_wrong_type_programs_unknown_containers_and_streams_fail(self):
        for update in ({"programs": [{"streams": []}]}, {"programs": None}, {"programs": {}},
                {"stream_groups": []}, {"PRIVATE-key": "PRIVATE-value"},
                {"streams": []}, {"streams": json.loads(PROBE_JSON)["streams"] * 2}):
            value = json.loads(PROBE_JSON); value.update(update)
            with self.subTest(update=update), self.assertRaises(ValueError): self.probe(json.dumps(value).encode())

    def test_audio_wrong_codec_dimensions_or_stream_metadata_are_rejected(self):
        for update in ({"codec_type": "audio"}, {"codec_name": "hevc"}, {"width": 1080},
                {"height": 1920}, {"width": True}, {"side_data_list": []}):
            value = json.loads(PROBE_JSON); value["streams"][0].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError): self.probe(json.dumps(value).encode())

    def test_bounds_duration_stderr_invalid_json_and_duplicate_keys_fail(self):
        for raw in (b"x" * 65537, b"PRIVATE invalid json", PROBE_JSON.replace(b'"programs":[]', b'"programs":[],"programs":[]')):
            with self.assertRaises(ValueError): self.probe(raw)
        for duration in ("0.000000", "180.000001", "NaN", "N/A", 1):
            value = json.loads(PROBE_JSON); value["format"]["duration"] = duration
            with self.assertRaises(ValueError): self.probe(json.dumps(value).encode())
        with self.assertRaises(ValueError): self.probe(stderr=b"PRIVATE diagnostic")

    def test_probe_failure_projects_only_closed_stage_category_and_container_facts(self):
        value = json.loads(PROBE_JSON); value["programs"] = [dict(PRIVATE="secret")]
        with self.assertRaises(ValueError): self.probe(json.dumps(value).encode())
        record = M["failure"](ValueError("PRIVATE /home/secret"), "export")
        self.assertEqual(record["stage"], "video-metadata")
        self.assertEqual(record["category"], "value")
        self.assertEqual(record["facts"], dict(programs="nonempty", stream_groups="absent", stream_count=1, width=720, height=1280))
        for secret in ("PRIVATE", "secret", "/home", "/inert"):
            self.assertNotIn(secret, json.dumps(record))
        for error, category in ((subprocess.TimeoutExpired("PRIVATE", 15), "timeout"),
                (subprocess.CalledProcessError(1, "PRIVATE"), "process")):
            with self.assertRaises(type(error)): self.probe(error=error)
            record = M["failure"](error, "export")
            self.assertEqual((record["stage"], record["category"], record["facts"]), ("video-process", category, {}))


class Media(F["RecordFixture"]):
    def setUp(self):
        super().setUp(); self.join(); self.accept()
        self.media = self.proof / "demo-media"; self.media.mkdir(mode=0o700)
        save(self.media / "screen.mp4", b"\0\0\0\x18ftypmp42synthetic-test-only")
        save(self.media / "screen-001.png", M["PNG"] + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", 1080, 1920))
        files = {p.name: M["checked"](p, 1024)[0] for p in self.media.iterdir()}
        self.raw = dict(schema=1, kind="weather-demo-android-recording", started_unix_ms=1000000000000,
            completed_unix_ms=1000000012000, elapsed_ms=12000, source="android-screenrecord-and-screencap", files=files,
            screenshots=[dict(file="screen-001.png", started_elapsed_ms=100, completed_elapsed_ms=200, stage="unclassified")],
            recorder_joined=True, guest_file_removed=True, stage_labels_verified=False, ui_values_verified=False,
            joined_core_acceptance=False, production_authority=False)
        save(self.media / "recording.json", self.raw)
        self.window = dict(schema=1, started_unix_ms=1000000000100, completed_unix_ms=1000000011000,
            installed_report_sha256=M["file_hash"](self.proof / "report.json"))
        save(self.media / "driver-window.json", self.window)
        self.probe = patch.dict(G, probe_video=lambda _: VIDEO); self.probe.start(); self.addCleanup(self.probe.stop)
        self.source = patch.dict(M["O"], git_check=lambda *_: None, hosted=lambda *_: None)
        self.source.start(); self.addCleanup(self.source.stop)

    def export(self):
        return M["export"](self.output, self.weather)

    def test_original_acceptance_joins_hashes_and_only_allowlisted_pixels(self):
        value = self.export()
        self.assertEqual(M["verify"](self.output), value)
        self.assertEqual(value["identity"], F["IDENTITY"])
        self.assertEqual(value["installed_report_sha256"], self.window["installed_report_sha256"])
        self.assertEqual({p.name for p in (self.output / "demo-media").iterdir()}, {"screen.mp4", "screen-001.png", "recording.json"})
        self.assertFalse(value["stage_labels_verified"] or value["production_authority"])
        self.assertNotIn(str(self.root), json.dumps(value))

    def test_missing_failed_or_changed_acceptance_never_admits_media(self):
        path = self.output / "weather-android-hosted-acceptance.json"
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(FileNotFoundError): self.export()
        save(path, original)
        value = json.loads(original); value["passed"] = False; save(path, value)
        with self.assertRaises(ValueError): self.export()
        self.assertFalse((self.output / "demo-media").exists())

    def test_failed_vm_cleanup_cannot_be_hidden_by_success_stamp(self):
        value = json.loads(self.vm.read_bytes()); value["qemu_joined"] = False; save(self.vm, value)
        with self.assertRaises(ValueError): self.export()

    def test_other_run_original_driver_cannot_supply_recording(self):
        self.window["installed_report_sha256"] = "f" * 64; save(self.media / "driver-window.json", self.window)
        with self.assertRaises(ValueError): self.export()

    def test_unknown_file_private_log_or_symlink_is_not_exported(self):
        path = self.media / "private.log"; save(path, b"PRIVATE")
        with self.assertRaises(ValueError): self.export()
        path.unlink(); path = self.media / "screen-001.png"; path.unlink(); path.symlink_to(self.proof / "report.json")
        with self.assertRaises(OSError): self.export()

    def test_bytes_and_screenshot_dimensions_are_bound(self):
        path = self.media / "screen-001.png"
        save(path, M["PNG"] + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", 1, 1))
        self.raw["files"][path.name] = M["checked"](path, 1024)[0]; save(self.media / "recording.json", self.raw)
        with self.assertRaises(ValueError): self.export()

    def test_unverified_labels_and_missing_guest_removal_remain_rejected(self):
        for key in ("guest_file_removed", "recorder_joined"):
            value = copy.deepcopy(self.raw); value[key] = False; save(self.media / "recording.json", value)
            with self.assertRaises(ValueError): self.export()
        value = copy.deepcopy(self.raw); value["screenshots"][0]["stage"] = "resumed"
        save(self.media / "recording.json", value)
        with self.assertRaises(ValueError): self.export()

    def test_capture_window_must_cover_original_driver_without_reset(self):
        self.window["started_unix_ms"] -= 1000; save(self.media / "driver-window.json", self.window)
        with self.assertRaises(ValueError): self.export()
        # Admission failure is never uploaded: the workflow's media step uses
        # success(), while original closed failure artifacts remain separate.

    def test_truncated_video_cannot_hide_behind_later_pull_cleanup_clock(self):
        with patch.dict(G, probe_video=lambda _: dict(VIDEO, duration_seconds=5.0)):
            with self.assertRaises(ValueError): self.export()

    def test_duration_equal_to_driver_but_missing_launch_offset_is_rejected(self):
        # Driver lasts10.9s, but ends11s after recorder launch.10.7s cannot
        # cover that end even though a shorter driver alone would fit.
        self.window["started_unix_ms"] = 1000000001000
        save(self.media / "driver-window.json", self.window)
        with patch.dict(G, probe_video=lambda _: dict(VIDEO, duration_seconds=10.0)):
            with self.assertRaises(ValueError): self.export()

    def test_encoding_tolerance_is_fixed_and_visual_review_stays_required(self):
        with patch.dict(G, probe_video=lambda _: dict(VIDEO, duration_seconds=10.8)):
            value = self.export()
        self.assertEqual(value["encoding_tolerance_ms"], 250)
        self.assertTrue(value["visual_review_required"])

    def test_final_hashes_rechecked_and_destination_is_exclusive(self):
        self.export()
        with self.assertRaises(FileExistsError): self.export()
        save(self.output / "demo-media/screen.mp4", b"changed")
        with self.assertRaises(ValueError): M["verify"](self.output)

    def failed_cli(self):
        output = io.StringIO()
        args = ["media", "export", "--evidence", str(self.output), "--weather-root", str(self.weather)]
        with patch.object(sys, "argv", args), redirect_stdout(output), self.assertRaises(SystemExit) as error:
            M["main"]()
        self.assertEqual(error.exception.code, "weather_demo_media_rejected")
        record = json.loads(output.getvalue())
        self.assertEqual(M["validate_failure"](record), record)
        self.assertLess(len(output.getvalue()), 4096)
        self.assertNotIn(str(self.root), output.getvalue())
        return record

    def test_cli_retains_closed_duration_failure_without_changing_original_acceptance(self):
        original = (self.output / "weather-android-hosted-acceptance.json").read_bytes()
        with patch.dict(G, probe_video=lambda _: dict(VIDEO, duration_seconds=5.0)):
            record = self.failed_cli()
        self.assertEqual((record["stage"], record["category"]), ("verify-duration", "value"))
        self.assertEqual(record["facts"], dict(duration_ms=5000, required_end_ms=11000, capture_elapsed_ms=12000))
        self.assertTrue(record["accepted_evidence_checked"])
        self.assertFalse(record["joined_core_acceptance"] or record["production_authority"])
        saved = self.output / M["FAILURE_NAME"]
        self.assertEqual(json.loads(saved.read_bytes()), record)
        self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)
        self.assertEqual((self.output / "weather-android-hosted-acceptance.json").read_bytes(), original)

    def test_existing_diagnostic_and_symlink_targets_are_never_overwritten(self):
        path = self.output / M["FAILURE_NAME"]
        save(path, b"retained original failure")
        save(self.media / "unexpected.log", b"PRIVATE contents")
        record = self.failed_cli()
        self.assertEqual(record["stage"], "raw-inventory")
        self.assertEqual(path.read_bytes(), b"retained original failure")
        target = self.output / "retained"; save(target, b"retained target")
        path.unlink(); path.symlink_to(target)
        self.failed_cli()
        self.assertEqual(target.read_bytes(), b"retained target")

    def test_early_acceptance_failure_is_distinct_from_checked_acceptance(self):
        (self.output / "weather-android-hosted-acceptance.json").unlink()
        record = self.failed_cli()
        self.assertEqual((record["stage"], record["category"], record["facts"]), ("accepted-evidence", "io", {}))
        self.assertFalse(record["accepted_evidence_checked"])

    def test_failed_png_dimensions_are_bounded_and_truncated_header_is_closed(self):
        path = self.media / "screen-001.png"
        for payload, facts in ((M["PNG"] + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", 1, 8193), dict(width=1, height=None)),
                (M["PNG"] + struct.pack(">I", 13) + b"IHDR", {})):
            save(path, payload); self.raw["files"][path.name] = M["checked"](path, 1024)[0]
            save(self.media / "recording.json", self.raw)
            record = self.failed_cli()
            self.assertEqual(record["stage"], "raw-media")
            self.assertEqual(record["facts"], facts)

    def test_failure_schema_rejects_unreviewed_fields_strings_and_unbounded_numbers(self):
        M["stage"]("arguments")
        value = M["failure"](ValueError("PRIVATE /secret"), "export")
        for facts in (dict(width="PRIVATE"), dict(width=True), dict(duration_ms=2**40), dict(secret="PRIVATE")):
            changed = dict(value, facts=facts)
            with self.assertRaises(ValueError): M["validate_failure"](changed)
        with patch.dict(os.environ, GITHUB_SHA="PRIVATE/path"):
            self.assertIsNone(M["failure"](ValueError("PRIVATE"), "export")["identity"])


if __name__ == "__main__": unittest.main()
