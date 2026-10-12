#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert archive/parser tests. No real binaries, acquisition, browser or VM."""
import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

W = runpy.run_path(str(Path(__file__).with_name("weather-client-bundle.py")))


class WeatherBundle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="weather-bundle-test-")
        self.root = Path(self.temp.name).resolve()
        self.raw = b"inert input; must not execute\n"
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.pins = patch.dict(W["manifest"].__globals__, dict(NODE_SHA=self.digest, DECODER_SHA=self.digest,
            PIN_SHA=self.digest, BUILD_SHA=self.digest))
        self.pins.start()
        self.addCleanup(self.pins.stop)
        self.addCleanup(self.temp.cleanup)
        self.files = self.profile_files()

    def profile_files(self, version=1):
        fixed = W[{1: "FIXED", 2: "FIXED_V2", 3: "FIXED_V3"}[version]]
        static = ({W["STATIC_V3"] + name for name in W["STATIC_REQUIRED_V3"]} if version == 3
                  else {W["STATIC"] + "index.html"})
        return {name: dict(bytes=len(self.raw), mode=W["mode"](name), sha256=self.digest)
            for name in fixed | static}

    def manifest(self, value=None, version=1):
        raw = W["encode"](value or dict(version=version, kind=W["KIND"], files=self.files))
        return raw, hashlib.sha256(raw).hexdigest()

    def archive(self, suffix=b"\0" * 1024, version=1):
        raw, expected = self.manifest(version=version)
        archive = self.root / "inputs.tar"
        with archive.open("wb") as target:
            for name, data, mode in [("INPUTS.json", raw, 0o400),
                    *((name, self.raw, item["mode"]) for name, item in sorted(self.files.items()))]:
                target.write(W["header"](name, len(data), mode)); target.write(data)
                target.write(b"\0" * (-len(data) % 512))
            target.write(suffix)
        archive.chmod(0o600)
        return archive, expected

    def test_exact_roundtrip_readonly_tree_no_execution(self):
        archive, expected = self.archive()
        before = archive.read_bytes()
        destination = self.root / "unpacked"
        result = W["checked_archive"](archive, expected, destination)
        self.assertEqual(result["files"], len(self.files))
        checked = W["verify_tree"](destination, expected)
        self.assertFalse(checked["runtime_executed"])
        self.assertEqual(before, archive.read_bytes())
        for name, item in self.files.items():
            self.assertEqual((destination / name).read_bytes(), self.raw)
            self.assertEqual((destination / name).stat().st_mode & 0o777, item["mode"])
        self.assertEqual(destination.stat().st_mode & 0o777, 0o500)

    def test_v1_runtime_gate_preserves_existing_archive_and_schema(self):
        archive, expected = self.archive()
        before = archive.read_bytes()
        checked = W["checked_archive"](archive, expected, runtime=True)
        self.assertEqual(checked, W["checked_archive"](archive, expected))
        self.assertEqual(before, archive.read_bytes())
        raw, digest = self.manifest()
        self.assertEqual(W["manifest"](raw, digest), dict(version=1, kind=W["KIND"], files=self.files))
        self.assertNotIn(W["WEATHER"] + "src/air-quality.mjs", self.files)
        self.assertIn(W["WEATHER"] + "integrations/drizzli/browser-smoke.json", self.files)

    def test_runtime_version_action_checks_whole_archive_without_executing_or_changing_profiles(self):
        for version in (1, 2, 3):
            self.files = self.profile_files(version)
            archive, expected = self.archive(version=version)
            before = archive.read_bytes()
            output = io.StringIO()
            with patch.object(W["sys"], "argv", ["bundle", "runtime-version", str(archive), expected]), redirect_stdout(output):
                W["main"]()
            self.assertEqual(json.loads(output.getvalue()), dict(version=1, action="runtime-version",
                bundle_version=version, runtime_executed=False,
                **W["checked_archive"](archive, expected)))
            self.assertEqual(before, archive.read_bytes())
            self.assertEqual([path.name for path in self.root.iterdir()], ["inputs.tar"])
            # A valid manifest prefix is not enough: damaged body/trailer or a
            # wrong retained digest must be rejected before reporting a version.
            damaged = bytearray(before)
            damaged[before.rfind(self.raw)] ^= 1
            for raw, digest in ((bytes(damaged), expected), (before + b"\0" * 512, expected),
                                (before, "f" * 64)):
                archive.write_bytes(raw)
                rejected = io.StringIO()
                with self.subTest(version=version), patch.object(W["sys"], "argv",
                        ["bundle", "runtime-version", str(archive), digest]), redirect_stdout(rejected):
                    with self.assertRaises(ValueError):
                        W["main"]()
                self.assertEqual(rejected.getvalue(), "")
            archive.unlink()

    def test_runtime_profile_keeps_invoking_owner_boundary(self):
        if os.geteuid() == 0:
            self.skipTest("ownership regression uses an unprivileged test-owned archive")
        for version in (1, 2):
            self.files = self.profile_files(version)
            archive, expected = self.archive(version=version)
            before = archive.read_bytes()
            owner = archive.stat().st_uid
            # VM inputs belong to vpci: reading those as root must not bypass
            # the existing parser's owner check. No real uid/chown is changed.
            with self.subTest(version=version), patch.object(W["os"], "geteuid", return_value=0):
                with self.assertRaises(ValueError):
                    W["checked_archive"](archive, expected, report_version=True)
            with patch.object(W["os"], "geteuid", return_value=owner):
                profile = W["checked_archive"](archive, expected, report_version=True)
            self.assertEqual(profile["bundle_version"], version)
            self.assertEqual(archive.read_bytes(), before)
            self.assertEqual(archive.stat().st_uid, owner)
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
            archive.unlink()

    def test_v2_roundtrip_is_readonly_and_never_executes_captured_inputs(self):
        self.files = self.profile_files(2)
        archive, expected = self.archive(version=2)
        before = archive.read_bytes()
        destination = self.root / "v2-tree"
        result = W["checked_archive"](archive, expected, destination)
        self.assertEqual(result["files"], len(self.files))
        checked = W["verify_tree"](destination, expected)
        self.assertEqual(checked, dict(manifest_sha256=expected, files=len(self.files), runtime_executed=False))
        self.assertEqual(before, archive.read_bytes())
        self.assertEqual(json.loads((destination / "INPUTS.json").read_bytes())["version"], 2)
        for name, item in self.files.items():
            self.assertEqual((destination / name).read_bytes(), self.raw)
            self.assertEqual((destination / name).stat().st_mode & 0o777, item["mode"])
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o500
            for path in (destination, *destination.rglob("*")) if path.is_dir()))

    def test_v3_roundtrip_and_runtime_gate_preserve_original_archive_and_closed_files(self):
        self.files = self.profile_files(3)
        archive, expected = self.archive(version=3)
        before = archive.read_bytes()
        destination = self.root / "v3-tree"
        checked = W["checked_archive"](archive, expected, destination, runtime=True, report_version=True)
        self.assertEqual(checked["bundle_version"], 3)
        self.assertEqual(W["verify_tree"](destination, expected)["files"], len(self.files))
        self.assertEqual(archive.read_bytes(), before)
        self.assertEqual(json.loads((destination / "INPUTS.json").read_bytes())["version"], 3)
        for name, item in self.files.items():
            self.assertEqual((destination / name).read_bytes(), self.raw)
            self.assertEqual((destination / name).stat().st_mode & 0o777, item["mode"])
        self.assertIn(W["WEATHER"] + "integrations/overmorrow/prepare_core_browser.mjs", self.files)
        self.assertIn(W["WEATHER"] + "integrations/drizzli/prepare-core-browser.mjs", self.files)
        self.assertFalse(any(name.startswith(W["UI_STAGE"]) for name in self.files))

    def test_v3_static_closure_and_limits_do_not_spill_into_legacy_profiles(self):
        for version in (1, 2, 3):
            base = self.profile_files(version)
            wrong_prefix = W["STATIC"] if version == 3 else W["STATIC_V3"]
            files = {**base, wrong_prefix + "index.html": dict(bytes=5, mode=0o400, sha256=self.digest)}
            raw, expected = self.manifest(dict(version=version, kind=W["KIND"], files=files))
            with self.subTest(version=version), self.assertRaises(ValueError): W["manifest"](raw, expected)
        for bad in ("flutter_service_worker.js", "canvaskit/skwasm.wasm", "canvaskit/canvaskit.js.symbols",
                    "assets/worker.js", "extra.html", "../escape", ".hidden"):
            files = self.profile_files(3)
            files[W["STATIC_V3"] + bad] = dict(bytes=10, mode=0o400, sha256=self.digest)
            raw, expected = self.manifest(dict(version=3, kind=W["KIND"], files=files))
            with self.subTest(bad=bad), self.assertRaises(ValueError): W["manifest"](raw, expected)
        for missing in W["FIXED_V3"] | {W["STATIC_V3"] + name for name in W["STATIC_REQUIRED_V3"]}:
            files = self.profile_files(3); del files[missing]
            raw, expected = self.manifest(dict(version=3, kind=W["KIND"], files=files))
            with self.subTest(missing=missing), self.assertRaises(ValueError): W["manifest"](raw, expected)
        files = self.profile_files(3)
        for name in ("assets/font.otf", "assets/shaders/ink_sparkle.frag", "assets/AssetManifest.bin.json"):
            files[W["STATIC_V3"] + name] = dict(bytes=32, mode=0o400, sha256=self.digest)
        raw, expected = self.manifest(dict(version=3, kind=W["KIND"], files=files))
        W["manifest"](raw, expected)
        files[W["STATIC_V3"] + "canvaskit/canvaskit.wasm"]["bytes"] = 8 * 1024**2 + 1
        raw, expected = self.manifest(dict(version=3, kind=W["KIND"], files=files))
        with self.assertRaises(ValueError): W["manifest"](raw, expected)
        files = self.profile_files(3)
        for index in range(5):
            files[W["STATIC_V3"] + f"assets/large{index}.bin"] = dict(bytes=8*1024**2, mode=0o400, sha256=self.digest)
        raw, expected = self.manifest(dict(version=3, kind=W["KIND"], files=files))
        with self.assertRaises(ValueError): W["manifest"](raw, expected)

    def v3_proof_fixture(self):
        _, records = self.proof_fixture(2)
        selected = self.profile_files(3)
        hashes = {name[len(W["STATIC_V3"]):]: item["sha256"] for name, item in selected.items()
                  if name.startswith(W["STATIC_V3"])}
        tree = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        source = dict(upstream="b" * 40, tree="c" * 40, patch_sha256=self.digest,
            overlay_sha256=dict.fromkeys(W["OVERMORROW_OVERLAY"], self.digest),
            deployed_tree_sha256=tree, deployed_files=len(hashes), deployed_bytes=len(hashes) * len(self.raw),
            bridge_modules=dict.fromkeys(W["OVERMORROW_BRIDGE"], self.digest),
            fixture_modules=dict.fromkeys(W["OVERMORROW_FIXTURE"], self.digest),
            browser_helpers=dict.fromkeys(W["PROVEN_BROWSER_HELPERS"], self.digest),
            isolation_helper_sha256=self.digest, driver_sha256=self.digest, fixture_sha256=self.digest)
        proof = dict(schema=1, passed=True, phase="complete", wrapper_outcome="completed", source=source,
            runtime=dict(sha256=dict.fromkeys(W["PROVEN_RUNTIME_FILES"], self.digest), node_sha256=self.digest),
            scope=dict(actual_overmorrow_ui=True, actual_http_bridge=True, synthetic_weather=True,
                synthetic_air_quality=True, core_executed=False, overlay_proven=False,
                upstream_origin_proven=False, native_mobile_proven=False),
            cleanup=dict.fromkeys(("browser_exited", "fixture_exited", "private_profile_removed",
                                   "normal_browser_stop", "normal_fixture_stop"), True),
            outer_cleanup=dict.fromkeys(("namespace_wrapper_exited", "private_profile_removed", "host_netns_unchanged"), True),
            checks=dict.fromkeys(("actual_canvas_and_semantics", "independent_native_timelines", "native_values_visible",
                "no_fabricated_current_or_aqi", "fixed_public_area", "source_attribution", "actual_refresh",
                "weather_failure_and_stale_preserve_air_quality", "weather_idle_expiry_without_request",
                "air_quality_failure_and_stale_preserve_weather", "air_quality_idle_expiry_without_request",
                "existing_aq_detail_without_new_request", "same_origin_loaded_resources"), True))
        proof["checks"].update(provider_requests=10, air_quality_provider_requests=10,
                               initial_semantics_sha256=self.digest, final_semantics_sha256=self.digest)
        records["browser-proof.json"] = proof
        records["upstream.json"] = dict(commit="b" * 40, tree="c" * 40, license_sha256=self.digest,
            pubspec_lock_sha256=self.digest, upstream_patch_sha256=self.digest, flutter="3.38.5", flutter_commit="d" * 40)
        records["build-verification.json"] = dict(schema=1, upstream_commit="b" * 40,
            upstream_patch_sha256=self.digest, pubspec_lock_sha256=self.digest,
            profile="VOLPAROSSA_WEATHER=true", flutter="3.38.5", flutter_commit="d" * 40,
            actual_release_web_build=True, synthetic_products=True, browser_interaction_verified=True,
            core_delivery_verified=False, native_android_ios_verified=False, forecast_accuracy_verified=False,
            deployment=dict(tree_sha256=tree, files=len(hashes), bytes=len(hashes) * len(self.raw),
                static_profile="flutter-canvaskit", main_js_sha256=self.digest, bootstrap_sha256=self.digest,
                notices_sha256=self.digest),
            browser_trial=dict(passed=True, report_sha256=self.digest),
            request_lifecycle=dict(provider_source_sha256=self.digest, cold_core_delivery_verified=False))
        # Historical origin proof intentionally predates current wrapper changes.
        records["noaa-gefs-smoke.json"]["source_modules"] = dict.fromkeys(W["NOAA_MODULES"], "e" * 64)
        return selected, records

    def check_v3_proof(self, selected, records):
        with patch.dict(W["overmorrow_source_proof"].__globals__, small_json=lambda path: records[path.name]):
            W["overmorrow_source_proof"](Path("/inert/weather"), Path("/inert/firefox"),
                                        selected, Path("/inert/browser-proof.json"))

    def test_v3_current_ui_provenance_binds_exact_tree_sources_runtime_and_licenses(self):
        self.check_v3_proof(*self.v3_proof_fixture())
        paths = {*(W["STATIC_V3"] + name for name in W["STATIC_REQUIRED_V3"]),
            *(W["WEATHER"] + name for name in W["OVERMORROW_BRIDGE"] | W["OVERMORROW_FIXTURE"]),
            *(W["BROWSER"] + name for name in W["PROVEN_BROWSER_HELPERS"]),
            *(W["STAGE"] + name for name in W["PROVEN_RUNTIME_FILES"] | {"volparossa.cfg"}),
            *(W["UI_STAGE_V3"] + name for name in W["CLIENT_FILES_V3"]),
            *(W["WEATHER"] + "integrations/overmorrow/overlay/" + name for name in W["OVERMORROW_OVERLAY"]),
            W["WEATHER"] + W["OVERMORROW_PROOF"], W["WEATHER"] + "LICENSE",
            *(W["WEATHER"] + name for name in ("integrations/overmorrow/upstream.patch",
                "integrations/overmorrow/smoke_browser.py", "integrations/overmorrow/browser-fixture.mjs",
                "integrations/drizzli/smoke_browser.py"))}
        for name in paths:
            selected, records = self.v3_proof_fixture(); selected[name]["sha256"] = "f" * 64
            with self.subTest(name=name), self.assertRaises(ValueError): self.check_v3_proof(selected, records)

    def test_v3_module_maps_cannot_be_truncated_or_expanded(self):
        for group in ("overlay_sha256", "bridge_modules", "fixture_modules", "browser_helpers"):
            for fault in ("empty", "missing", "extra", "invalid"):
                selected, records = self.v3_proof_fixture()
                target = records["browser-proof.json"]["source"][group]
                if fault == "empty": target.clear()
                elif fault == "missing": target.pop(next(iter(target)))
                elif fault == "extra": target["unreviewed"] = self.digest
                else: target[next(iter(target))] = "invalid"
                with self.subTest(group=group, fault=fault), self.assertRaises(ValueError):
                    self.check_v3_proof(selected, records)

    def test_v3_historical_origin_evidence_is_not_current_execution_authority(self):
        selected, records = self.v3_proof_fixture()
        self.check_v3_proof(selected, records)
        self.assertNotEqual(records["noaa-gefs-smoke.json"]["source_modules"]["src/noaa-gefs.mjs"],
                            selected[W["WEATHER"] + "src/noaa-gefs.mjs"]["sha256"])
        for filename, path in (("noaa-gefs-smoke.json", ("scope", "core_executed")),
                               ("noaa-gefs-smoke.json", ("scope", "overlay_proven")),
                               ("ecmwf-precipitation-smoke.json", ("core_overlay_roundtrip_proven",)),
                               ("browser-proof.json", ("scope", "upstream_origin_proven")),
                               ("build-verification.json", ("core_delivery_verified",))):
            selected, records = self.v3_proof_fixture(); parent = records[filename]
            for key in path[:-1]: parent = parent[key]
            parent[path[-1]] = True
            with self.subTest(filename=filename, path=path), self.assertRaises(ValueError):
                self.check_v3_proof(selected, records)
        # This historical exception belongs only to v3: v2 still requires current hashes.
        selected, records = self.proof_fixture(2)
        records["noaa-gefs-smoke.json"]["source_modules"]["src/noaa-gefs.mjs"] = "e" * 64
        with self.assertRaises(ValueError): self.check_proof(selected, records, 2)

    def test_v3_exact_synthetic_scope_success_checks_and_cleanup_required(self):
        _, original = self.v3_proof_fixture()
        proof = original["browser-proof.json"]
        paths = [("passed",), ("phase",), ("wrapper_outcome",), ("schema",)]
        paths += [(group, key) for group in ("scope", "checks", "cleanup", "outer_cleanup") for key in proof[group]]
        for path in paths:
            selected, records = self.v3_proof_fixture(); parent = records["browser-proof.json"]
            for key in path[:-1]: parent = parent[key]
            old = parent[path[-1]]
            parent[path[-1]] = not old if type(old) is bool else "invalid"
            with self.subTest(path=path), self.assertRaises(ValueError): self.check_v3_proof(selected, records)

    def test_v3_capture_interface_is_explicit_and_cannot_replace_legacy_capture(self):
        arguments = [str(self.root / str(index)) for index in range(8)]
        for action, args in (("capture-v3", arguments), ("capture", arguments[:6]), ("capture-v2", arguments[:6])):
            calls = []
            def record(*paths, **kwargs):
                calls.append((paths, kwargs)); return {"captured": False}
            with patch.dict(W["main"].__globals__, capture_v3=record, capture=record), \
                    patch.object(W["sys"], "argv", ["bundle", action, *args]), redirect_stdout(io.StringIO()):
                W["main"]()
            self.assertEqual(calls, [(tuple(map(Path, args)), {} if action == "capture-v3"
                                     else {"version": 2 if action == "capture-v2" else 1})])

    def test_v3_actual_inert_capture_freezes_current_bytes_without_executing_them(self):
        weather, app, static, browser, firefox = (self.root / name for name in
                                                ("weather", "app", "static", "browser", "firefox"))
        for root in (weather, app, static, browser, firefox): root.mkdir(mode=0o700)
        sources = [(weather, W["WEATHER_FILES_V3"] - {W["OVERMORROW_PROOF"]}),
                   (app, W["CLIENT_FILES_V3"]), (static, W["STATIC_REQUIRED_V3"]),
                   (browser, W["BROWSER_FILES"]), (firefox, W["RUNTIME_FILES"])]
        for root, names in sources:
            for name in names:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.write_bytes(self.raw); path.chmod(0o600)
        for name in W["EXECUTABLES"]:
            if name.startswith(W["STAGE"]): (firefox / name[len(W["STAGE"]):]).chmod(0o700)
        node = self.root / "node"; node.write_bytes(self.raw); node.chmod(0o700)
        decoder = weather / "build/eccodes/eccodes-build/bin/grib_ls"
        decoder.parent.mkdir(parents=True, mode=0o700); decoder.write_bytes(self.raw); decoder.chmod(0o700)
        proof = self.root / "retained-proof.json"; proof.write_bytes(self.raw); proof.chmod(0o600)
        for directory in self.root.rglob("*"):
            if directory.is_dir(): directory.chmod(0o700)
        archive = self.root / "captured.tar"
        proof_calls = []
        with patch.dict(W["capture_v3"].__globals__, overmorrow_source_proof=lambda *args: proof_calls.append(args)):
            result = W["capture_v3"](weather, app, static, browser, firefox, node, proof, archive)
        self.assertEqual(len(proof_calls), 1)
        self.assertEqual(proof_calls[0][:2], (weather, firefox))
        self.assertEqual(proof_calls[0][3], proof)
        self.assertTrue(result["historical_source_proofs_only"])
        self.assertFalse(result["current_origin_acquisition_proven"])
        self.assertFalse(result["joined_delivery_proven"])
        expected = result["manifest_sha256"]
        self.assertEqual(W["checked_archive"](archive, expected, runtime=True, report_version=True)["bundle_version"], 3)
        frozen = self.root / "frozen"
        W["checked_archive"](archive, expected, frozen)
        self.assertEqual((frozen / W["WEATHER"] / W["OVERMORROW_PROOF"]).read_bytes(), self.raw)
        self.assertEqual(proof.read_bytes(), self.raw, "historical original must remain untouched")
        self.assertEqual(W["verify_tree"](frozen, expected)["runtime_executed"], False)

    def test_v2_runtime_gate_checks_complete_archive_and_preserves_existing_roots(self):
        self.files = self.profile_files(2)
        archive, expected = self.archive(version=2)
        before = archive.read_bytes()
        original_open = W["open_checked"]
        opened = []
        def observed_open(*args, **kwargs):
            result = original_open(*args, **kwargs)
            opened.append(result[0])
            return result
        destination = self.root / "existing"
        destination.mkdir(mode=0o700)
        (destination / "keep").write_bytes(b"untouched")
        with patch.dict(W["checked_archive"].__globals__, open_checked=observed_open):
            checked = W["checked_archive"](archive, expected, runtime=True)
            self.assertEqual(checked, W["checked_archive"](archive, expected))
            self.assertEqual(archive.read_bytes(), before)
            with self.assertRaises(ValueError):
                W["checked_archive"](archive, expected, destination, runtime=True)
            self.assertEqual([p.name for p in destination.iterdir()], ["keep"])
            self.assertEqual((destination / "keep").read_bytes(), b"untouched")
            damaged = bytearray(before)
            damaged[before.rfind(self.raw)] ^= 1
            archive.write_bytes(damaged)
            with self.assertRaises(ValueError):
                W["checked_archive"](archive, expected, runtime=True)
            # Eligibility still requires the whole exact v2 source closure.
            del self.files[W["WEATHER"] + "src/air-quality-core.mjs"]
            archive, incomplete = self.archive(version=2)
            fresh = self.root / "must-not-create"
            with self.assertRaises(ValueError):
                W["checked_archive"](archive, incomplete, fresh, runtime=True)
            self.assertFalse(fresh.exists())
        self.assertTrue(opened and all(stream.closed for stream in opened))

    def test_version_profiles_are_exact_not_optional_or_interchangeable(self):
        old_proof = W["WEATHER"] + "integrations/drizzli/browser-smoke.json"
        new_proof = W["WEATHER"] + "integrations/drizzli/air-quality-browser-smoke.json"
        for version in (1, 2):
            for fault in ("other_profile", "missing", "cross_proof", "unknown", "version_bool", "version_zero", "version_three", "version_string"):
                files = self.profile_files(version)
                value = dict(version=version, kind=W["KIND"], files=files)
                if fault == "other_profile": value["version"] = 3 - version
                elif fault == "missing": del files[old_proof if version == 1 else new_proof]
                elif fault == "cross_proof": files[new_proof if version == 1 else old_proof] = dict(files["runtime/node"], mode=0o400)
                elif fault == "unknown": files[W["WEATHER"] + "src/unreviewed.mjs"] = dict(files["runtime/node"], mode=0o400)
                else: value["version"] = {"version_bool": True, "version_zero": 0, "version_three": 3, "version_string": str(version)}[fault]
                raw, expected = self.manifest(value)
                with self.subTest(version=version, fault=fault), self.assertRaises(ValueError):
                    W["manifest"](raw, expected)
        for name in W["FIXED_V2"] - W["FIXED"]:
            files = self.profile_files(2)
            del files[name]
            raw, expected = self.manifest(dict(version=2, kind=W["KIND"], files=files))
            with self.subTest(missing_v2=name), self.assertRaises(ValueError):
                W["manifest"](raw, expected)

    def test_manifest_rejects_missing_unknown_escape_and_mode(self):
        base = dict(version=1, kind=W["KIND"], files=self.files)
        for fault in ("missing", "unknown", "escape", "mode", "size_bool", "extra", "version_bool", "zero"):
            value = json.loads(json.dumps(base))
            if fault == "missing": del value["files"]["runtime/node"]
            elif fault == "unknown": value["files"]["runtime/extra.so"] = self.files["runtime/node"]
            elif fault == "escape": value["files"][W["STATIC"] + "../private"] = self.files["runtime/node"]
            elif fault == "mode": value["files"]["runtime/node"]["mode"] = 0o777
            elif fault == "size_bool": value["files"]["runtime/node"]["bytes"] = True
            elif fault == "extra": value["secret"] = "no"
            elif fault == "version_bool": value["version"] = True
            else: value["files"]["runtime/node"]["bytes"] = 0
            raw, expected = self.manifest(value)
            with self.subTest(fault=fault), self.assertRaises(ValueError): W["manifest"](raw, expected)

    def test_runtime_pins_and_static_budget_are_enforced(self):
        self.files["runtime/node"]["sha256"] = "f" * 64
        raw, expected = self.manifest()
        with self.assertRaises(ValueError): W["manifest"](raw, expected)
        self.files["runtime/node"]["sha256"] = self.digest
        for i in range(5): self.files[W["STATIC"] + f"large{i}.js"] = dict(bytes=8*1024**2, mode=0o400, sha256=self.digest)
        raw, expected = self.manifest()
        with self.assertRaises(ValueError): W["manifest"](raw, expected)

    def test_bad_hash_refuses_before_creation_and_existing_tree_is_preserved(self):
        archive, expected = self.archive(); destination = self.root / "target"
        with self.assertRaises(ValueError): W["checked_archive"](archive, "f"*64, destination)
        self.assertFalse(destination.exists())
        destination.mkdir(mode=0o700)
        with self.assertRaises(ValueError): W["checked_archive"](archive, expected, destination)
        self.assertEqual(list(destination.iterdir()), [])

    def test_trailing_payload_and_corruption_never_gain_accepted_marker(self):
        archive, expected = self.archive(suffix=b"\0"*1024 + b"hidden")
        with self.assertRaises(ValueError): W["checked_archive"](archive, expected)
        archive, expected = self.archive()
        raw = bytearray(archive.read_bytes()); offset = raw.index(self.raw); raw[offset] ^= 1
        archive.write_bytes(raw)
        destination = self.root / "partial"
        with self.assertRaises(ValueError): W["checked_archive"](archive, expected, destination)
        self.assertFalse((destination / "INPUTS.json").exists())

    def test_changed_or_extra_tree_inputs_rejected(self):
        archive, expected = self.archive(); destination = self.root / "tree"
        W["checked_archive"](archive, expected, destination)
        file = destination / "runtime/node"; file.chmod(0o700); file.write_bytes(b"changed")
        with self.assertRaises(ValueError): W["verify_tree"](destination, expected)
        file.write_bytes(self.raw); file.chmod(0o500)
        directory = destination / "runtime"; directory.chmod(0o700)
        (directory / "shadow.so").write_bytes(b"unexpected")
        directory.chmod(0o500)
        with self.assertRaises(ValueError): W["verify_tree"](destination, expected)

    def proof_fixture(self, version=1):
        selected = self.profile_files(version)
        modules = W["PROVEN_WEATHER_MODULES"] | (W["AQ_MODULES"] if version == 2 else set())
        module_hashes = {name: self.digest for name in modules}
        runtime = {name: self.digest for name in W["PROVEN_RUNTIME_FILES"]}
        static = {"index.html": self.digest}
        proof = dict(passed=True, scope=dict(synthetic_weather=True, core_executed=False), runtime=dict(sha256=runtime),
            source=dict(built_tree_sha256=hashlib.sha256(json.dumps(static, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                built_files=1, built_bytes=len(self.raw), upstream="b" * 40, tree="c" * 40,
                patch_sha256=self.digest, driver_sha256=self.digest,
                overlay_sha256={"src/lib/services/volparossa/client.mjs": self.digest},
                weather_modules=module_hashes,
                bridge_modules={name: self.digest for name in W["PROVEN_BRIDGE_MODULES"]},
                browser_helpers={name: self.digest for name in W["PROVEN_BROWSER_HELPERS"]}))
        upstream = dict(commit="b" * 40, tree="c" * 40, license_sha256=self.digest,
                        upstream_patch_sha256=self.digest, weather_modules=copy.deepcopy(module_hashes))
        metadata = dict(runtime_sha256=copy.deepcopy(runtime), defaults_sha256=self.digest, autoconfig_sha256=self.digest)
        build = dict(compiled=True, embedded_definitions=True, required_environment={}, source_pin_sha256=self.digest,
            build_script_sha256=self.digest, original_sources_unchanged=True, artifacts=[dict(
                path="build/eccodes/eccodes-build/bin/grib_ls", bytes=31328216, sha256=self.digest)])
        records = {"browser-smoke.json" if version == 1 else "air-quality-browser-smoke.json": proof,
                   "upstream.json": upstream, "volparossa-staging.json": metadata, "build-receipt.json": build}
        if version == 2:
            proof.update(phase="complete", scenario="precipitation", air_quality_scenario=True, wrapper_outcome="completed")
            proof["scope"].update(synthetic_air_quality=True, actual_drizzli_ui=True, actual_http_bridge=True,
                                  overlay_proven=False, upstream_origin_proven=False)
            proof["runtime"]["node_sha256"] = self.digest
            proof["source"]["bridge_modules"]["src/air-quality-core.mjs"] = self.digest
            proof["source"]["overlay_sha256"] = {name: self.digest for name in W["OVERLAY_FILES"]}
            proof["source"]["fixture_modules"] = {name: self.digest for name in W["FIXTURE_MODULES"]}
            proof["source"]["fixture_sha256"] = self.digest
            proof["cleanup"] = dict.fromkeys(("browser_exited", "fixture_exited", "private_profile_removed",
                                               "normal_browser_stop", "normal_fixture_stop"), True)
            proof["outer_cleanup"] = dict.fromkeys(("namespace_wrapper_exited", "private_profile_removed", "host_netns_unchanged"), True)
            proof["checks"] = dict.fromkeys(("precipitation_native_windows", "precipitation_missing_zero_small_amount",
                "precipitation_no_hourly_rate", "air_quality_is_separate_product", "air_quality_native_times",
                "air_quality_missing_zero_concentrations", "air_quality_not_aqi_or_observations", "actual_refresh",
                "no_external_resources", "weather_failure_preserves_air_quality", "weather_expiry_preserves_air_quality",
                "aq_unavailable_weather_preserved", "aq_stale_weather_preserved", "air_quality_expiry_preserves_weather"), True)
            proof["checks"].update(provider_requests=11, air_quality_provider_requests=11)
            for product in ("precipitation", "air_quality"):
                for phase in ("initial", "refresh"):
                    proof["checks"][f"{product}_{phase}_dom_sha256"] = self.digest
            records["noaa-gefs-smoke.json"] = dict(version=1, kind="direct-noaa-native-particulate-forecast",
                success=True, origin="https://noaa-gefs-pds.s3.amazonaws.com", node_sha256=self.digest,
                decoder_sha256=self.digest, source_modules={name: self.digest for name in W["NOAA_MODULES"]},
                scope=dict(actual_origin_acquisition=True, actual_pinned_native_decoder=True,
                    core_executed=False, overlay_proven=False, browser_executed=False, accuracy_proven=False))
            records["ecmwf-precipitation-smoke.json"] = dict(version=1,
                kind="direct-ecmwf-native-precipitation-forecast", success=True,
                source="https://data.ecmwf.int/forecasts", node_sha256=self.digest, decoder_sha256=self.digest,
                native_accumulation_windows_preserved=True, hourly_rates_inferred=False,
                core_overlay_roundtrip_proven=False, browser_execution_proven=False,
                source_modules={name: self.digest for name in W["ECMWF_MODULES"]})
        return selected, records

    def check_proof(self, selected, records, version=1):
        # No real source/binary capture or import. Only inert JSON-shaped values.
        with patch.dict(W["source_proof"].__globals__, small_json=lambda path: records[path.name]):
            return W["source_proof"](Path("/inert/weather"), Path("/inert/browser"),
                                     Path("/inert/ui"), Path("/inert/runtime"), selected, version)

    def test_v2_complete_provenance_binds_expanded_modules_and_separate_proofs(self):
        self.check_proof(*self.proof_fixture(2), version=2)
        names = {*(W["WEATHER"] + relative for relative in
                    W["AQ_MODULES"] | W["NOAA_MODULES"] | W["ECMWF_MODULES"] | W["FIXTURE_MODULES"] | {"src/air-quality-core.mjs"}),
            *(W["WEATHER"] + "integrations/drizzli/overlay/" + relative for relative in W["OVERLAY_FILES"]),
            *(W["UI_STAGE"] + relative for relative in W["OVERLAY_FILES"]),
            *(W["UI_STAGE"] + "src/lib/services/volparossa/" + Path(relative).name for relative in W["AQ_MODULES"]),
            W["WEATHER"] + "integrations/drizzli/browser-fixture.mjs", W["UI_STAGE"] + "LICENSE.VOLPAROSSA",
            W["WEATHER"] + "LICENSE"}
        for name in names:
            selected, records = self.proof_fixture(2)
            selected[name]["sha256"] = "f" * 64
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check_proof(selected, records, version=2)

    def test_v2_expanded_provenance_maps_are_exact(self):
        paths = [("air-quality-browser-smoke.json", "source", "bridge_modules"),
            ("air-quality-browser-smoke.json", "source", "weather_modules"),
            ("air-quality-browser-smoke.json", "source", "overlay_sha256"),
            ("air-quality-browser-smoke.json", "source", "fixture_modules"),
            ("upstream.json", "weather_modules"), ("noaa-gefs-smoke.json", "source_modules"),
            ("ecmwf-precipitation-smoke.json", "source_modules")]
        for path in paths:
            for fault in ("empty", "missing", "extra", "hash", "none", "list"):
                selected, records = self.proof_fixture(2)
                parent = records
                for key in path[:-1]: parent = parent[key]
                changed = dict(parent[path[-1]])
                if fault == "empty": changed = {}
                elif fault == "missing": changed.pop(next(iter(changed)))
                elif fault == "extra": changed["PRIVATE"] = self.digest
                elif fault == "hash": changed[next(iter(changed))] = "PRIVATE"
                elif fault == "none": changed = None
                else: changed = list(changed)
                parent[path[-1]] = changed
                with self.subTest(path=path, fault=fault), self.assertRaises(ValueError):
                    self.check_proof(selected, records, version=2)

    def test_v2_scenario_scope_cleanup_and_checks_cannot_be_relaxed(self):
        selected, records = self.proof_fixture(2)
        proof = records["air-quality-browser-smoke.json"]
        mutations = [(key, [False, None, "wrong"]) for key in
                     ("phase", "scenario", "air_quality_scenario", "wrapper_outcome")]
        paths = [((key,), bad) for key, bad_values in mutations for bad in bad_values]
        for group in ("scope", "cleanup", "outer_cleanup"):
            paths.extend(((group, name), bad) for name, value in proof[group].items()
                         for bad in (not value, int(value)))
        for name, value in proof["checks"].items():
            bad_values = (False, 1) if type(value) is bool else (10, 12, True, "11") if type(value) is int else ("f" * 64, "PRIVATE")
            paths.extend((("checks", name), bad) for bad in bad_values)
        paths.append((("runtime", "node_sha256"), "f" * 64))
        for path, bad in paths:
            selected, records = self.proof_fixture(2)
            parent = records["air-quality-browser-smoke.json"]
            for key in path[:-1]: parent = parent[key]
            parent[path[-1]] = bad
            with self.subTest(path=path, bad=bad), self.assertRaises(ValueError):
                self.check_proof(selected, records, version=2)

    def test_v2_noaa_proof_preserves_source_scope_and_runtime_authority(self):
        selected, records = self.proof_fixture(2)
        noaa = records["noaa-gefs-smoke.json"]
        paths = [(("version",), bad) for bad in (True, 0, 2, "1")]
        paths.extend(((name,), bad) for name, bad in (
            ("kind", "other"), ("success", False), ("success", 1), ("origin", "https://untrusted.invalid"),
            ("node_sha256", "f" * 64), ("decoder_sha256", "f" * 64)))
        paths.extend((("scope", name), bad) for name, value in noaa["scope"].items()
                     for bad in (not value, int(value)))
        for path, bad in paths:
            selected, records = self.proof_fixture(2)
            parent = records["noaa-gefs-smoke.json"]
            for key in path[:-1]: parent = parent[key]
            parent[path[-1]] = bad
            with self.subTest(path=path, bad=bad), self.assertRaises(ValueError):
                self.check_proof(selected, records, version=2)

    def test_proof_profile_version_rejects_unknown_and_boolean_values(self):
        for version in (True, False, 0, 3, "1", "2", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.check_proof(*self.proof_fixture(), version=version)

    def test_v2_ecmwf_proof_preserves_accumulation_and_separate_source_scope(self):
        faults = [("version", value) for value in (True, 0, 2, "1")]
        faults.extend((name, value) for name, value in (
            ("kind", "other"), ("success", False), ("success", 1),
            ("source", "https://untrusted.invalid"), ("node_sha256", "f" * 64), ("decoder_sha256", "f" * 64),
            ("native_accumulation_windows_preserved", False), ("native_accumulation_windows_preserved", 1),
            ("hourly_rates_inferred", True), ("hourly_rates_inferred", 0),
            ("core_overlay_roundtrip_proven", True), ("core_overlay_roundtrip_proven", 0),
            ("browser_execution_proven", True), ("browser_execution_proven", 0)))
        for name, value in faults:
            selected, records = self.proof_fixture(2)
            records["ecmwf-precipitation-smoke.json"][name] = value
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                self.check_proof(selected, records, version=2)

    def test_complete_provenance_binds_all_known_module_groups_without_source_execution(self):
        self.check_proof(*self.proof_fixture())
        for name in (W["WEATHER"] + "src/provider-http.mjs", W["BROWSER"] + "scripts/smoke_privacy.py",
                     W["STAGE"] + "firefox-esr", W["WEATHER"] + "integrations/drizzli/smoke_browser.py",
                     W["STAGE"] + "volparossa.cfg", W["WEATHER"] + "integrations/drizzli/upstream.patch"):
            selected, records = self.proof_fixture(); selected[name]["sha256"] = "f" * 64
            with self.subTest(name=name), self.assertRaises(ValueError): self.check_proof(selected, records)

    def test_empty_truncated_extra_or_malformed_provenance_maps_cannot_skip_bindings(self):
        paths = [("browser-smoke.json", "source", "bridge_modules"),
            ("browser-smoke.json", "source", "browser_helpers"), ("browser-smoke.json", "source", "weather_modules"),
            ("browser-smoke.json", "runtime", "sha256"), ("upstream.json", "weather_modules"),
            ("volparossa-staging.json", "runtime_sha256")]
        for path in paths:
            for fault in ("empty", "missing", "extra", "hash", "none", "list"):
                selected, records = self.proof_fixture(); parent = records
                for key in path[:-1]: parent = parent[key]
                original = parent[path[-1]]
                changed = dict(original)
                if fault == "empty": changed = {}
                elif fault == "missing": changed.pop(next(iter(changed)))
                elif fault == "extra": changed["PRIVATE"] = self.digest
                elif fault == "hash": changed[next(iter(changed))] = "PRIVATE"
                elif fault == "none": changed = None
                elif fault == "list": changed = list(changed)
                parent[path[-1]] = changed
                with self.subTest(path=path, fault=fault), self.assertRaises(ValueError): self.check_proof(selected, records)

    def test_missing_malformed_duplicate_or_unbounded_artifacts_are_closed_rejections(self):
        selected, records = self.proof_fixture()
        good = records["build-receipt.json"]["artifacts"][0]
        bad = [[], None, {}, [None], [{}], [dict(good, bytes=True)], [dict(good, bytes=0)],
               [dict(good, bytes=W["MAX_FILE"] + 1)], [dict(good, sha256="PRIVATE")],
               [dict(good, path="different")], [dict(good, path="x" * 257)], [dict(good, extra="PRIVATE")],
               [good, good], [dict(good, path=str(i)) for i in range(17)]]
        for artifacts in bad:
            selected, records = self.proof_fixture(); records["build-receipt.json"]["artifacts"] = artifacts
            with self.subTest(artifacts=artifacts), self.assertRaises(ValueError): self.check_proof(selected, records)

    def test_invalid_archive_length_closes_descriptor_before_rejection(self):
        source = io.BytesIO(b"x")
        with patch.dict(W["checked_archive"].__globals__, open_checked=lambda *_: (source, SimpleNamespace(st_size=1))):
            with self.assertRaises(ValueError): W["checked_archive"](Path("/inert/archive"), self.digest)
        self.assertTrue(source.closed)


if __name__ == "__main__": unittest.main()
