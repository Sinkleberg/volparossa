#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert closed projection tests; no guest, SSH, native runtime or live proof."""
import copy
import json
import os
from pathlib import Path
import runpy
import stat
import tempfile
import unittest
from unittest.mock import patch

D = runpy.run_path(str(Path(__file__).with_name("weather-android-driver-diagnostic.py")))
IDENTITY = dict(core_commit="a" * 40, weather_commit=D["WEATHER_COMMIT"], run_id="12345", run_attempt="1")
CANARY = "PRIVATE-CANARY.example/secret-token"


def owner_fixture():
    children = {name: dict(state="not-started", status=None, stdout_open=False, stderr_open=False)
        for name in ("driver", "native", "tunnel")}
    children["driver"].update(state="exited", status=1)
    return dict(schema=8, kind="weather-android-owner-failure", identity=IDENTITY.copy(), phase="read-ready",
        statuses=dict(driver=1, native=None, tunnel=None),
        owner_stop=dict(reason="driver-exited", stage="read-ready", budgets=[], children=children, output_overflow=False),
        owner_cleanup=dict(children_joined=True, output_drained=True, forced_kill=False,
            socket_removed=True, host_netns_unchanged=True),
        tunnel_diagnostic=None, native_diagnostic=dict(state="absent", record=None),
        weather_records={name: dict(state="absent", facts=None) for name in ("result", "failure", "emulator_cleanup")},
        diagnostic_only=True, success=False, joined_core_acceptance=False, vm_cleanup_pending=True,
        expiry_proven=False, physical_device=False, production_authority=False)


def provider_fixture():
    return dict({key: False for key in D["REPORT_FLAGS"]}, schema_version=4,
        report_kind="volparossa-native-content-providers", source_revision=IDENTITY["core_commit"],
        run_id="b" * 32, phase="weather-products-delivery-publish", success=False, transfer=None,
        runner_exit_status=1, observed_blocker="WEATHER_CLIENT_AGENT_CACHE_PREPARE_FAILED",
        cleanup=dict(complete=True, remaining_owned_objects=0), host_state=None, scope="fixture")


def vm_fixture():
    return dict(schema_version=1, report_kind="volparossa-incomplete-vm-diagnostics",
        source_revision=IDENTITY["core_commit"], scenario="content-provider", success=False,
        guest_exit_status=1, observed_blocker="GUEST_OUTPUT_UNAVAILABLE", driver_phase="topology",
        topology_phase="helper-verification", cleanup=dict(complete=False, verified=False),
        host_state=dict(unchanged=None, verified=False), diagnostics=dict(available=False, partial=True))


class DriverDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="weather-driver-diagnostic-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.write("weather-android-owner-failure.json", owner_fixture())

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for parent in path.parents:
            if parent == self.root: break
            parent.chmod(0o700)
        path.write_bytes(value if type(value) is bytes else D["encoded"](value))
        path.chmod(0o600)
        return path

    def receipt(self):
        return D["receipt"](self.root, IDENTITY, D["owner_gate"](owner_fixture(), IDENTITY))

    def test_normal_failed_report_without_phase_file(self):
        self.write("content-provider-smoke.json", provider_fixture())
        result = self.receipt()
        self.assertEqual(result["provider_consistency"], "single")
        self.assertEqual(result["sources"]["normal"]["report"], dict(state="available", facts=dict(
            phase="weather-products-delivery-publish", blocker="cache-preparation", runner_exit_status=1)))
        self.assertEqual(result["sources"]["normal"]["phase"], dict(state="absent", facts=None))
        self.assertEqual(result["vm"]["state"], "absent")
        self.assertEqual(D["validate_receipt"](result), result)

    def test_absent_sources_do_not_invent_a_cause(self):
        result = self.receipt()
        self.assertEqual(result["provider_consistency"], "absent")
        self.assertTrue(all(row["report"]["state"] == row["phase"]["state"] == "absent"
            for row in result["sources"].values()))
        for key in ("success", "joined_core_acceptance", "cause_established", "cleanup_verified", "physical_device", "production_authority"):
            self.assertIs(result[key], False)

    def test_emergency_summary_and_fixed_published_work_sources(self):
        self.write("vm-incomplete.json", vm_fixture())
        for label in ("published", "work-1", "work-4"):
            self.write(f"{label}/content-provider-smoke.json", provider_fixture())
            self.write(f"{label}/current-phase", b"weather-products-delivery-publish\n")
        result = self.receipt()
        self.assertEqual(result["provider_consistency"], "consistent")
        self.assertEqual(result["vm"]["facts"]["driver_phase"], "topology")
        self.assertEqual(result["sources"]["work_4"]["report"]["state"], "available")

    def test_extended_emergency_summary_never_exports_private_diagnostics(self):
        value = vm_fixture()
        value["helper_processes"] = [dict(pid=123, private=CANARY)]
        value["diagnostics"].update(available=True, captured_bytes=8, files=[dict(file=CANARY)])
        self.write("vm-incomplete.json", value)
        result = self.receipt()
        self.assertEqual(result["vm"]["state"], "available")
        self.assertNotIn(CANARY.encode(), D["encoded"](result))

    def test_duplicate_reports_compare_private_run_binding_not_only_projected_facts(self):
        for key, change in (("run_id", "c" * 32), ("observed_blocker", "UNKNOWN_OTHER"),
                            ("phase", "not-reviewed"), ("runner_exit_status", 2)):
            with self.subTest(key=key):
                self.write("content-provider-smoke.json", provider_fixture())
                other = provider_fixture(); other[key] = change
                self.write("published/content-provider-smoke.json", other)
                result = self.receipt()
                self.assertEqual(result["provider_consistency"], "rejected")
                self.assertEqual(result["sources"]["normal"]["report"], dict(state="rejected", facts=None))
                self.assertEqual(result["sources"]["published"]["report"], dict(state="rejected", facts=None))

    def test_two_unknown_strings_are_not_considered_consistent(self):
        value = provider_fixture(); value["phase"] = "unknown-one"
        self.write("content-provider-smoke.json", value)
        value["phase"] = "unknown-two"; self.write("work-1/content-provider-smoke.json", value)
        self.assertEqual(self.receipt()["provider_consistency"], "rejected")

    def test_rejected_duplicate_invalidates_available_reports(self):
        self.write("content-provider-smoke.json", provider_fixture())
        self.write("work-2/content-provider-smoke.json", b"{}")
        result = self.receipt()
        self.assertEqual(result["provider_consistency"], "rejected")
        self.assertEqual(result["sources"]["normal"]["report"]["state"], "rejected")

    def test_unknown_text_maps_to_static_unknown_without_leak(self):
        value = provider_fixture()
        value.update(phase=CANARY, observed_blocker=CANARY, scope=CANARY, transfer=dict(secret=CANARY))
        self.write("content-provider-smoke.json", value)
        self.write("current-phase", CANARY.encode())
        summary = vm_fixture(); summary.update(driver_phase=CANARY, topology_phase=CANARY)
        self.write("vm-incomplete.json", summary)
        result = self.receipt()
        self.assertEqual(result["sources"]["normal"]["report"]["facts"]["phase"], "unknown")
        self.assertEqual(result["sources"]["normal"]["report"]["facts"]["blocker"], "unknown")
        self.assertNotIn(CANARY.encode(), D["encoded"](result))
        self.assertNotIn(("b" * 32).encode(), D["encoded"](result))

    def test_helper_code_is_exact_not_arbitrary_suffix(self):
        value = provider_fixture(); value["observed_blocker"] = "HELPER_SERVICE_UNAVAILABLE_relay3"
        self.assertEqual(D["provider"](D["encoded"](value), IDENTITY)["facts"]["blocker"], "helper")
        value["observed_blocker"] += CANARY
        self.assertEqual(D["provider"](D["encoded"](value), IDENTITY)["facts"]["blocker"], "unknown")

    def test_cache_preparation_parent_and_agent_collision_stay_distinct(self):
        for literal, category in (("WEATHER_CLIENT_AGENT_CACHE_PREPARE_FAILED", "cache-preparation"),
                                 ("WEATHER_ANDROID_CACHE_PARENT_CHANGED", "cache-parent-changed"),
                                 ("AGENT_UNIT_COLLISION", "agent-unit-collision")):
            with self.subTest(literal=literal):
                value = provider_fixture(); value["observed_blocker"] = literal
                self.assertEqual(D["provider"](D["encoded"](value), IDENTITY)["facts"]["blocker"], category)

    def test_cleanup_code_is_not_claimed_as_first_cause(self):
        value = provider_fixture(); value["observed_blocker"] = "A15_HOST_STATE_CHANGED"
        self.write("content-provider-smoke.json", value)
        result = self.receipt()
        self.assertEqual(result["sources"]["normal"]["report"]["facts"]["blocker"], "cleanup")
        self.assertFalse(result["cause_established"])
        self.assertFalse(result["cleanup_verified"])

    def test_provider_wrong_source_type_version_success_and_fields_rejected(self):
        for key, change in (("source_revision", "c" * 40), ("schema_version", True), ("schema_version", 3),
                            ("report_kind", "other"), ("success", True), ("runner_exit_status", True),
                            ("run_id", "123"), ("additional", CANARY)):
            with self.subTest(key=key, change=change):
                value = provider_fixture(); value[key] = change
                self.write("content-provider-smoke.json", value)
                self.assertEqual(self.receipt()["sources"]["normal"]["report"]["state"], "rejected")

    def test_vm_wrong_source_scenario_version_status_and_fields_rejected(self):
        for key, change in (("source_revision", "c" * 40), ("scenario", "alpha"), ("schema_version", True),
                            ("report_kind", "other"), ("success", True), ("guest_exit_status", True),
                            ("observed_blocker", "NOT_REACHED"), ("additional", CANARY)):
            with self.subTest(key=key):
                value = vm_fixture(); value[key] = change
                self.write("vm-incomplete.json", value)
                self.assertEqual(self.receipt()["vm"]["state"], "rejected")

    def test_json_duplicates_nonfinite_truncated_and_oversize_rejected(self):
        for raw in (b'{"schema_version":4,"schema_version":4}', b'{"field":NaN}', b'{', b' ' * 1048577):
            with self.subTest(size=len(raw)):
                self.write("content-provider-smoke.json", raw)
                self.assertEqual(self.receipt()["sources"]["normal"]["report"]["state"], "rejected")

    def test_phase_bounds_and_nonascii_rejected(self):
        for raw in (b'x' * 66, b'\xff', b''):
            self.write("current-phase", raw)
            self.assertEqual(self.receipt()["sources"]["normal"]["phase"]["state"], "rejected")

    def test_unsafe_symlink_hardlink_fifo_and_mode_rejected(self):
        target = self.write("secret", provider_fixture())
        path = self.root / "content-provider-smoke.json"
        for kind in ("symlink", "dangling", "hardlink", "fifo", "public"):
            with self.subTest(kind=kind):
                if kind == "symlink": path.symlink_to(target)
                elif kind == "dangling": path.symlink_to(self.root / "missing")
                elif kind == "hardlink": os.link(target, path)
                elif kind == "fifo": os.mkfifo(path, 0o600)
                else: self.write(path.name, provider_fixture()).chmod(0o644)
                try: self.assertEqual(self.receipt()["sources"]["normal"]["report"]["state"], "rejected")
                finally: path.unlink()

    def test_symlink_and_unsafe_parent_rejected(self):
        directory = self.root / "published"
        directory.symlink_to(self.root / "missing", target_is_directory=True)
        self.assertEqual(self.receipt()["sources"]["published"]["report"]["state"], "rejected")
        directory.unlink(); self.write("published/content-provider-smoke.json", provider_fixture())
        directory.chmod(0o755)
        self.assertEqual(self.receipt()["sources"]["published"]["report"]["state"], "rejected")

    def test_wrong_file_owner_rejected(self):
        self.write("content-provider-smoke.json", provider_fixture())
        real_fstat = os.fstat
        class ForeignOwner:
            def __init__(self, source): self.source = source
            def __getattr__(self, key):
                return os.getuid() + 1 if key == "st_uid" else getattr(self.source, key)
        with patch.object(D["E"]["os"], "fstat", side_effect=lambda fd: ForeignOwner(real_fstat(fd))):
            self.assertEqual(self.receipt()["sources"]["normal"]["report"]["state"], "rejected")

    def test_file_change_during_read_rejected(self):
        path = self.write("content-provider-smoke.json", provider_fixture())
        real = os.read
        def changed(fd, size):
            result = real(fd, size)
            if result: path.write_bytes(b"{}")
            return result
        with patch.object(D["E"]["os"], "read", side_effect=changed):
            self.assertEqual(self.receipt()["sources"]["normal"]["report"]["state"], "rejected")

    def test_only_fixed_paths_read_no_tail_logs_or_extra_workdirectory(self):
        self.write("content-provider-smoke.json.tail", provider_fixture())
        self.write("work-5/content-provider-smoke.json", provider_fixture())
        self.write("runner.stderr", CANARY.encode())
        self.assertEqual(self.receipt()["provider_consistency"], "absent")

    def test_export_only_current_early_failure_and_no_overwrite(self):
        original = (self.root / "weather-android-owner-failure.json").read_bytes()
        self.assertTrue(D["export"](self.root, IDENTITY))
        path = self.root / D["NAME"]
        before = path.read_bytes()
        self.assertLessEqual(len(before), 8192)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError): D["export"](self.root, IDENTITY)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual((self.root / "weather-android-owner-failure.json").read_bytes(), original)

    def test_missing_wrong_identity_success_historical_or_later_failure_no_export(self):
        cases = []
        for key, change in (("schema", 7), ("schema", True), ("phase", "native"), ("success", True),
                            ("additional", CANARY), ("identity", dict(IDENTITY, run_attempt="2"))):
            value = owner_fixture(); value[key] = change; cases.append(value)
        value = owner_fixture(); value["owner_stop"]["reason"] = "deadline"; cases.append(value)
        value = owner_fixture(); value["owner_cleanup"]["output_drained"] = False; cases.append(value)
        value = owner_fixture(); value["owner_stop"]["children"]["native"]["state"] = "running"; cases.append(value)
        for value in cases:
            self.write("weather-android-owner-failure.json", value)
            self.assertFalse(D["export"](self.root, IDENTITY))
            self.assertFalse((self.root / D["NAME"]).exists())
        (self.root / "weather-android-owner-failure.json").unlink()
        self.assertFalse(D["export"](self.root, IDENTITY))

    def test_negative_driver_status_is_preserved_without_cleanup_claim(self):
        value = owner_fixture(); value["statuses"]["driver"] = -15
        value["owner_stop"]["children"]["driver"]["status"] = -15
        self.write("weather-android-owner-failure.json", value)
        self.assertTrue(D["export"](self.root, IDENTITY))
        result = json.loads((self.root / D["NAME"]).read_bytes())
        self.assertEqual(result["owner_stop"]["driver_status"], -15)
        self.assertFalse(result["cleanup_verified"])

    def test_receipt_mutations_do_not_create_authority_or_raw_fields(self):
        result = self.receipt()
        for key, change in (("joined_core_acceptance", True), ("schema", True), ("cause_established", True),
                            ("additional", CANARY), ("provider_consistency", "consistent")):
            value = copy.deepcopy(result); value[key] = change
            with self.assertRaises(ValueError): D["validate_receipt"](value)

    def test_cli_host_binding_and_environment_identity(self):
        env = dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted", GITHUB_REPOSITORY="VOLPAROSSA/volparossa",
            GITHUB_WORKFLOW="Weather Android protected core delivery", GITHUB_SHA=IDENTITY["core_commit"],
            VOLPAROSSA_WEATHER_SOURCE_SHA=IDENTITY["weather_commit"], GITHUB_RUN_ID=IDENTITY["run_id"], GITHUB_RUN_ATTEMPT="1")
        argv = ["export", "--output", str(self.root), "--core-commit", IDENTITY["core_commit"], "--weather-commit", IDENTITY["weather_commit"]]
        with patch.dict(os.environ, env, clear=True): D["main"](argv)
        self.assertEqual(json.loads((self.root / D["NAME"]).read_bytes())["identity"], IDENTITY)
        (self.root / D["NAME"]).unlink()
        with patch.dict(os.environ, dict(env, GITHUB_WORKFLOW="other"), clear=True):
            with self.assertRaises(ValueError): D["main"](argv)
        self.assertFalse((self.root / D["NAME"]).exists())


if __name__ == "__main__":
    unittest.main()
