#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic admission negatives only; never media or runtime evidence."""
import copy
import json
import os
from pathlib import Path
import runpy
import struct
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / "weather-demo-media.py"))
G = M["verify"].__globals__
F = runpy.run_path(str(HERE / "test-weather-android-owner.py"))
save = F["save"]
VIDEO = dict(codec="h264", width=720, height=1280, duration_seconds=11.5, has_audio=False)


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


if __name__ == "__main__": unittest.main()
