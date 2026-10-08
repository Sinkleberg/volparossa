#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Only shell argument/syntax checks; never start a VM, browser or service."""
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
RUNNERS = ("run-alpha-topology-vm.sh", "kvm-alpha-topology.sh")


class BrowserFilterArguments(unittest.TestCase):
    def call(self, runner, *args):
        return subprocess.run(["/bin/sh", str(HERE / runner), *args],
                              capture_output=True, timeout=5)

    def test_shell_syntax(self):
        for runner in RUNNERS:
            subprocess.run(["/bin/sh", "-n", str(HERE / runner)], check=True, timeout=5)

    def test_original_provider_preview_is_inert_and_available(self):
        for runner in RUNNERS:
            result = self.call(runner, "--preview", "--scenario", "content-provider")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"PREVIEW ONLY", result.stdout)

    def test_bundle_flags_cannot_authorize_preview_execution(self):
        for runner in RUNNERS:
            for flag in ("--browser-filter-bundle", "--browser-filter-manifest-sha256"):
                for value in (None, "", "/unread-fixture"):
                    args = ["--preview", "--scenario", "content-provider", flag]
                    if value is not None:
                        args.append(value)
                    self.assertEqual(self.call(runner, *args).returncode, 64)

    def test_duplicate_flags_are_refused_before_files_or_vm(self):
        for runner in RUNNERS:
            for flag in ("--browser-filter-bundle", "--browser-filter-manifest-sha256"):
                self.assertEqual(self.call(runner, "--execute", "--scenario", "content-provider",
                                           flag, "/unread-one", flag, "/unread-two").returncode, 64)

    def test_bundle_is_not_authorized_by_environment(self):
        for runner in RUNNERS:
            source = (HERE / runner).read_text()
            self.assertIn("\nbrowser_filter_bundle=\n", source)
            self.assertIn("\nbrowser_filter_manifest_sha256=\n", source)
            self.assertIn('[ "$scenario" = content-provider ] || exit 64', source)


if __name__ == "__main__":
    unittest.main()
