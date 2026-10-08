#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert argument, scratch-path and memory-gate checks; no VM/browser/service."""
from pathlib import Path
import stat
import subprocess
import tempfile
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

    def directory_fragment(self):
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        return source.split("RUN_DIRECTORY_PARENT=/tmp\n", 1)[1].split("QEMU_PID=\n", 1)[0]

    def test_joined_browser_scratch_is_created_next_to_workspace_output_not_inside_it(self):
        # Run only the actual path-selection/mktemp/chmod fragment, not the
        # VM driver. This temporary directory itself is on the workspace disk.
        with tempfile.TemporaryDirectory(prefix="filter-runner-test-", dir=HERE) as temporary:
            parent = Path(temporary).resolve(); output = parent / "evidence"; output.mkdir()
            script = ('set -eu\nscenario=content-provider\nbrowser_filter_bundle=/selected/bundle\n'
                      'output_directory=$1\nRUN_DIRECTORY_PARENT=/tmp\n' + self.directory_fragment()
                      + 'printf "%s\\n" "$RUN_DIRECTORY"\n')
            result = subprocess.run(["/bin/sh", "-c", script, "fixture", str(output)], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            scratch = Path(result.stdout.decode().strip())
            self.assertEqual(scratch.parent, parent)
            self.assertTrue(scratch.name.startswith("browser-filter-kvm."))
            self.assertNotEqual(scratch, output)
            self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
            self.assertEqual(list(output.iterdir()), [])

    def test_joined_browser_rejects_symlink_output_and_memory_backed_parent(self):
        with tempfile.TemporaryDirectory(prefix="filter-runner-test-", dir=HERE) as temporary:
            parent = Path(temporary).resolve(); output = parent / "evidence"; output.mkdir()
            alias = parent / "alias"; alias.symlink_to(output)
            prefix = 'set -eu\nscenario=content-provider\nbrowser_filter_bundle=/selected/bundle\noutput_directory=$1\nRUN_DIRECTORY_PARENT=/tmp\n'
            for path, filesystem, expected in ((alias, None, 64), (output, "tmpfs", 69), (output, "ramfs", 69), (output, "failed", 69)):
                stub = '' if filesystem is None else ('stat() { return 1; }\n' if filesystem == "failed"
                    else 'stat() { printf "%s\\n" "' + filesystem + '"; }\n')
                result = subprocess.run(["/bin/sh", "-c", prefix + stub + self.directory_fragment(), "fixture", str(path)],
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual({entry.name for entry in parent.iterdir()}, {"evidence", "alias"})

    def test_ordinary_provider_and_existing_scratch_selection_unchanged(self):
        # Stub mktemp/chmod so an ordinary /tmp-path check creates no files.
        script = ('set -eu\nscenario=$1\nbrowser_filter_bundle=$2\noutput_directory=$3\nRUN_DIRECTORY_PARENT=/tmp\n'
                  'mktemp() { printf "%s\\n" "${2%XXXXXX}abcdef"; }\nchmod() { :; }\n'
                  + self.directory_fragment() + 'printf "%s\\n" "$RUN_DIRECTORY"\n')
        with tempfile.TemporaryDirectory(prefix="filter-runner-test-", dir=HERE) as temporary:
            output = Path(temporary).resolve() / "evidence"; output.mkdir()
            for scenario, bundle, prefix in (("content-provider", "", "/tmp/volparossa-alpha-kvm."),
                ("alpha", "", "/tmp/volparossa-alpha-kvm."),
                ("agent-native-editor", "", str(output.parent / "native-editor-kvm.")),
                ("agent-cooperative-code", "", str(output.parent / "cooperative-code-kvm."))):
                result = subprocess.run(["/bin/sh", "-c", script, "fixture", scenario, bundle, str(output)],
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.decode().strip(), prefix + "abcdef")

    def test_memory_preflight_requires_original_four_gib_guest_plus_two_gib_reserve(self):
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        memory_function = "guest_memory_for_scenario() {\n" + source.split("guest_memory_for_scenario() {\n", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        gate = "guest_memory_mib=$(guest_memory_for_scenario)\n" + source.split("guest_memory_mib=$(guest_memory_for_scenario)\n", 1)[1].split("qemu_usernet=", 1)[0]
        script = ('set -eu\nscenario=$1\nbrowser_filter_bundle=$2\nfixture_available=$3\n'
                  'awk() { printf "%s\\n" "$fixture_available"; }\n' + memory_function + gate
                  + 'printf "%s:%s\\n" "$guest_memory_mib" "$runner_reserve_mib"\n')
        cases = (("content-provider", "bundle", 6144 * 1024 - 1, 69, None),
                 ("content-provider", "bundle", 6144 * 1024, 0, "4096:2048"),
                 ("content-provider", "bundle", "unknown", 69, None),
                 ("content-provider", "", 0, 0, "4096:1024"),
                 ("alpha", "", 0, 0, "4096:1024"),
                 ("agent-native-editor", "", 9216 * 1024 - 1, 69, None),
                 ("agent-native-editor", "", 9216 * 1024, 0, "8192:1024"))
        for scenario, bundle, available, code, expected in cases:
            with self.subTest(scenario=scenario, available=available):
                result = subprocess.run(["/bin/sh", "-c", script, "fixture", scenario, bundle, str(available)],
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, code, result.stderr)
                if expected is not None: self.assertEqual(result.stdout.decode().strip(), expected)


if __name__ == "__main__":
    unittest.main()
