#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert rejection and provenance controls; no media/runtime acceptance claims."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load("weather-demo-0-package")
U = load("weather-demo-0-usage")


class Presentation(unittest.TestCase):
    def test_explanation_distinguishes_summary_and_held_frame(self):
        vtt, text = P.captions(120, 75)
        self.assertTrue(vtt.startswith("WEBVTT\n"))
        self.assertIn("do not assert exact action timestamps", vtt)
        self.assertIn("completed run", vtt)
        self.assertIn("After 75.000 seconds", text)
        self.assertIn("No continuing runtime activity", text)

    def test_filter_paths_are_data_not_expressions(self):
        for bad in ("/tmp/file:movie=x", "/tmp/a,b", "/tmp/a'", "/tmp/a[0]", "/tmp/a\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                P.filter_path(bad)

    def test_preview_writes_nothing_and_cannot_accept_media(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as name:
            base = Path(name)
            evidence = base / "evidence"
            evidence.mkdir()
            output = base / "presentation"
            result = P.prepare(evidence, output)
            self.assertFalse(result["executed"])
            self.assertFalse(result["publication_authorized"])
            self.assertFalse(output.exists())
            with patch.dict(P.os.environ, {}, clear=True), self.assertRaises(ValueError):
                P.prepare(evidence, output, execute=True)

    def test_different_run_is_rejected_before_media_execution(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as name:
            base = Path(name)
            evidence = base / "evidence"
            evidence.mkdir()
            environment = dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                GITHUB_REPOSITORY="VOLPAROSSA/volparossa", GITHUB_SHA="a" * 40,
                GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1")
            media = dict(identity=dict(core_commit="a" * 40, run_id="124", run_attempt="1"))
            with patch.dict(P.os.environ, environment, clear=True), patch.object(P.os, "getuid", return_value=1000), \
                    patch.object(P.os, "geteuid", return_value=1000), \
                    patch.object(P.runpy, "run_path", return_value={"verify": lambda _: media}), \
                    patch.object(P, "video_info") as inspect_video:
                with self.assertRaises(ValueError):
                    P.prepare(evidence, base / "presentation", execute=True)
                inspect_video.assert_not_called()


class RecordedUsage(unittest.TestCase):
    def test_uses_deltas_and_excludes_previous_turn_and_duplicate_snapshot(self):
        selected = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        def event(kind, **kwargs):
            return dict(type="event_msg", payload=dict(type=kind, **kwargs))
        def usage(n, cached, output):
            return event("token_count", info=dict(total_token_usage=dict(input_tokens=n,
                cached_input_tokens=cached, output_tokens=output, reasoning_output_tokens=output // 2)))
        entries = [dict(type="session_meta", payload=dict(id="thread-one", source="vscode")),
            usage(100, 80, 20), event("task_started", root_turn_id=selected),
            dict(type="turn_context", payload=dict(model="gpt-6.1-sol", effort="medium")),
            usage(130, 100, 26), usage(130, 100, 26),
            event("task_complete", root_turn_id=selected), usage(140, 105, 28)]
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "session.jsonl"
            path.write_text("".join(json.dumps(x) + "\n" for x in entries))
            report = U.collect([path], selected)
            row = report["threads"][0]["models"][0]
            self.assertEqual((row["input_tokens"], row["cached_input_tokens"], row["uncached_input_tokens"], row["output_tokens"]),
                (30, 20, 10, 6))
            self.assertEqual(report["threads"][0]["nonzero_usage_events"], 1)
            self.assertFalse(report["billing_estimate"])
            with self.assertRaises(ValueError):
                U.collect([path, path], selected)


if __name__ == "__main__":
    unittest.main()
