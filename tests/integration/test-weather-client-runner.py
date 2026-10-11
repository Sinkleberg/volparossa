#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise runner argument/path/resource contracts without a VM or network."""
import os
import json
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
RUNNERS = ("run-alpha-topology-vm.sh", "kvm-alpha-topology.sh")
BUNDLE = "--weather-client-bundle"
DIGEST = "--weather-client-manifest-sha256"
SHA = "b" * 64


class WeatherRunner(unittest.TestCase):
    def call(self, runner, *args, env=None):
        return subprocess.run(["/bin/sh", str(HERE / runner), *args],
                              capture_output=True, timeout=5, env=env)

    def required(self, runner, scenario="content-provider"):
        args = ["--execute", "--yes", "--scenario", scenario,
                "--output", "/unread/output", "--expected-commit", "a" * 40,
                "--mpquic", "/unread/native"]
        if runner.startswith("run-"):
            args += ["--image", "/unread/image"]
        else:
            args += ["--source", "/unread/source", "--bin", "/unread/bin"]
        return args

    def test_shells_and_unselected_preview_remain_inert(self):
        for runner in RUNNERS:
            subprocess.run(["/bin/sh", "-n", str(HERE / runner)], check=True, timeout=5)
            env = dict(os.environ, weather_client_bundle="/unread/bundle",
                       weather_client_manifest_sha256=SHA)
            result = self.call(runner, "--preview", "--scenario", "content-provider", env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"PREVIEW ONLY", result.stdout)
            self.assertNotIn(b"Additional proof:", result.stdout)

    def test_explicit_pair_and_no_preview_or_duplicate_authority(self):
        for runner in RUNNERS:
            for flag in (BUNDLE, DIGEST):
                for value in (None, "", "/unread"):
                    args = [flag] + ([] if value is None else [value])
                    self.assertEqual(self.call(runner, "--preview", *args).returncode, 64)
                self.assertEqual(self.call(runner, *self.required(runner),
                                          flag, "one", flag, "two").returncode, 64)
            cases = ([BUNDLE, "/unread/bundle"], [DIGEST, SHA],
                     [BUNDLE, "relative", DIGEST, SHA],
                     [BUNDLE, "/unread/../bundle", DIGEST, SHA],
                     [BUNDLE, "/unread/bundle", DIGEST, "g" * 64],
                     [BUNDLE, "/unread/bundle", DIGEST, "b" * 63],
                     [BUNDLE, "/unread/bundle", DIGEST, SHA,
                      "--browser-filter-bundle", "/unread/browser",
                      "--browser-filter-manifest-sha256", SHA])
            for args in cases:
                with self.subTest(runner=runner, args=args):
                    self.assertEqual(self.call(runner, *self.required(runner), *args).returncode, 64)
            self.assertEqual(self.call(runner, *self.required(runner, "content"),
                                      BUNDLE, "/unread/bundle", DIGEST, SHA).returncode, 64)

    def test_weather_scratch_is_private_disk_sibling_not_exported_evidence(self):
        source = (HERE / RUNNERS[0]).read_text()
        fragment = source.split("RUN_DIRECTORY_PARENT=/tmp\n", 1)[1].split("QEMU_PID=\n", 1)[0]
        prefix = ("set -eu\nscenario=content-provider\nbrowser_filter_bundle=\n"
                  "weather_client_bundle=/selected/weather\noutput_directory=$1\nRUN_DIRECTORY_PARENT=/tmp\n")
        with tempfile.TemporaryDirectory(prefix="weather-runner-test-", dir=HERE) as temporary:
            parent = Path(temporary).resolve()
            output = parent / "evidence"
            output.mkdir()
            result = subprocess.run(["/bin/sh", "-c", prefix + fragment + 'printf "%s\\n" "$RUN_DIRECTORY"\n',
                                     "fixture", str(output)], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            scratch = Path(result.stdout.decode().strip())
            self.assertEqual(scratch.parent, parent)
            self.assertTrue(scratch.name.startswith("weather-client-kvm."))
            self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
            self.assertEqual(list(output.iterdir()), [])
            for filesystem in ("tmpfs", "ramfs"):
                stub = 'stat() { printf "%s\\n" "' + filesystem + '"; }\n'
                result = subprocess.run(["/bin/sh", "-c", prefix + stub + fragment,
                                         "fixture", str(output)], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 69, result.stderr)

    def test_weather_uses_same_four_gib_guest_and_two_gib_host_reserve(self):
        source = (HERE / RUNNERS[0]).read_text()
        memory = "guest_memory_for_scenario() {\n" + source.split("guest_memory_for_scenario() {\n", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        gate = "guest_memory_mib=$(guest_memory_for_scenario)\n" + source.split("guest_memory_mib=$(guest_memory_for_scenario)\n", 1)[1].split("qemu_usernet=", 1)[0]
        script = ("set -eu\nscenario=content-provider\nbrowser_filter_bundle=\nweather_client_bundle=/selected\n"
                  'fixture_available=$1\nawk() { printf "%s\\n" "$fixture_available"; }\n' + memory + gate +
                  'printf "%s:%s\\n" "$guest_memory_mib" "$runner_reserve_mib"\n')
        for available, expected in ((6144 * 1024 - 1, 69), (6144 * 1024, 0), ("unknown", 69)):
            result = subprocess.run(["/bin/sh", "-c", script, "fixture", str(available)], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, expected, result.stderr)
            if expected == 0:
                self.assertEqual(result.stdout.decode().strip(), "4096:2048")

    def test_guest_discriminator_binds_only_weather_arguments(self):
        source = (HERE / RUNNERS[0]).read_text()
        guest = source.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)[1].split("\nGUEST_DRIVER_SCRIPT\n", 1)[0]
        fragment = guest[guest.index("expected_commit=$1"):guest.index("cd /home/vpci")]
        script = "set -eu\n" + fragment + 'printf "%s:%s:%s\\n" "$scenario" "$browser_filter_manifest_sha256" "$weather_client_manifest_sha256"\n'
        base = ["a" * 40, SHA, SHA, "none", "content-provider"]
        for suffix, expected in ((["weather-client", SHA, SHA], 0), (["unknown", SHA, SHA], 64),
                                 (["weather-client", "none", SHA], 64), (["weather-client", SHA], 64)):
            result = subprocess.run(["/bin/sh", "-c", script, "fixture", *base, *suffix], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, expected, result.stderr)
            if expected == 0:
                self.assertEqual(result.stdout.decode().strip(), "content-provider:none:" + SHA)

    def test_control_observer_accepts_only_the_one_new_weather_prefix(self):
        source = (HERE / "content-provider-smoke.sh").read_text()
        body = source.split("content_provider_start_control_observer() {\n", 1)[1].split("\n}\n", 1)[0]
        function = "content_provider_start_control_observer() {\n" + body + "\n}\n"
        with tempfile.TemporaryDirectory() as temporary:
            script = ("set -eu\nWORK=$1\nPROVIDER_CONTROL_PID=\nprovider_control_ns=fixture\n"
                      "provider_control_ips=fixture\nip() { :; }\nwait_observer() { :; }\n" + function +
                      'content_provider_start_control_observer "$2"\n')
            for name, expected in (("weather-client-delivery-control", 0),
                                   ("content-provider-control-privacy", 0),
                                   ("weather-client-other", 1),
                                   ("weather-client-delivery-control-extra", 1),
                                   ("../weather-client-delivery-control", 1)):
                result = subprocess.run(["/bin/sh", "-c", script, "fixture", temporary, name],
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)


class WeatherEmergencyExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (HERE / RUNNERS[0]).read_text()
        body = source.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
        cls.api = {"__name__": "inert_weather_collector"}
        exec(compile(body, "weather-collector", "exec"), cls.api)

    def acquisition(self):
        return dict(schema=1, success=True, origin_https=True, acquisition_outside_overlay=True,
                    upstream_signature_attested=False, synthetic_weather=False,
                    forecast_sha256=SHA, forecast_bytes=6000, decoder_sha256=SHA,
                    fields=[dict(lead_hours=step, parameter=parameter,
                                 index_sha256=SHA, field_sha256=SHA)
                            for step in (3, 9, 24) for parameter in ("2t", "10u", "10v")])

    def collect(self, raw, limit=None):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            home, opt, proc, cgroups = (base / name for name in ("home", "opt", "proc", "cgroups"))
            for directory in (home, opt, proc, cgroups):
                directory.mkdir()
            (home / "alpha-output").mkdir()
            work = opt / ("va." + "a" * 32 + ".ABC123")
            work.mkdir()
            source = work / "weather-client-delivery-acquisition.json"
            source.write_bytes(raw)
            source.chmod(0o600)
            for name in ("weather-client-delivery-cold-consumer.json", "weather-client-delivery-input.json",
                         "weather-client-delivery.err", "forecast.json", "config.json"):
                (work / name).write_text("PRIVATE CANARY")
            overrides = {"weather_client_helper": lambda root: HERE / "weather-client-delivery.py"}
            if limit is not None:
                overrides["FILE_LIMIT"] = limit
            # Bypass only root-owned staging in this unprivileged inert test.
            # Actual production JSON validation and collector still execute.
            with patch.dict(self.api, overrides):
                archive = self.api["collect"](home, opt, "a" * 40, "content-provider", 124, cgroups, proc)
            with tarfile.open(archive, "r:gz") as bundle:
                return {item.name: bundle.extractfile(item).read() for item in bundle.getmembers()}

    def test_valid_receipt_survives_exactly_but_never_claims_vm_success(self):
        raw = json.dumps(self.acquisition(), indent=2).encode() + b"\n"
        files = self.collect(raw)
        self.assertEqual(files["work-1/weather-client-delivery-acquisition.json"], raw)
        summary = json.loads(files["vm-incomplete.json"])
        self.assertFalse(summary["success"])
        self.assertEqual(summary["cleanup"], {"complete": False, "verified": False})
        self.assertFalse(any(b"PRIVATE CANARY" in data for data in files.values()))

    def test_private_unknown_duplicate_and_malformed_json_do_not_escape(self):
        valid = self.acquisition()
        bad = [b"not json", json.dumps(dict(valid, prompt="PRIVATE CANARY")).encode(),
               b'{"schema":"PRIVATE CANARY",' + json.dumps(valid).encode()[1:],
               json.dumps(dict(valid, forecast_sha256="PRIVATE CANARY")).encode()]
        for raw in bad:
            with self.subTest(raw=raw[:30]):
                files = self.collect(raw)
                self.assertNotIn("work-1/weather-client-delivery-acquisition.json", files)
                self.assertFalse(any(b"PRIVATE CANARY" in data for data in files.values()))

    def test_verified_json_is_not_exported_as_an_unverifiable_tail(self):
        files = self.collect(json.dumps(self.acquisition()).encode(), limit=64)
        self.assertFalse(any("weather-client-delivery" in name for name in files))


if __name__ == "__main__":
    unittest.main()
