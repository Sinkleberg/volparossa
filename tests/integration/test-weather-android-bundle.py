#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert Android guest input tests; never run a binary, SDK, VM or origin fetch."""
import copy
import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

B = runpy.run_path(str(Path(__file__).with_name("weather-client-bundle.py")))


class AndroidInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="weather-android-inputs-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.raw = b"inert source; execution forbidden\n"
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.pins = patch.dict(B["manifest"].__globals__, NODE_SHA=self.digest,
            DECODER_SHA=self.digest, DECODER_SHA_V4=self.digest, PIN_SHA=self.digest,
            BUILD_SHA=self.digest, BUILD_SHA_V4=self.digest)
        self.pins.start(); self.addCleanup(self.pins.stop)
        self.admitted = dict(schema=1, kind="volparossa-weather-public-android-admission",
            scope="disposable-android-core-inputs-only", sources=dict(weather=dict(commit="a" * 40)),
            artifacts={name: dict(repository="VOLPAROSSA/volparossa" + ("-weather" if name == "decoder" else ""),
                run_id=index, id=index, commit="b" * 40, name=name, sha256=self.digest, bytes=42)
                for index, name in enumerate(("decoder", "abi"), 1)},
            files={name: dict(bytes=len(self.raw), sha256=self.digest) for name in B["FIXED_V6"]})
        self.admission = patch.dict(B["manifest"].__globals__, public_android_admission=lambda: self.admitted)
        self.admission.start(); self.addCleanup(self.admission.stop)

    def selected(self):
        return {name: dict(**item, mode=B["mode"](name)) for name, item in self.admitted["files"].items()}

    def manifest(self, files=None, version=6):
        raw = B["encode"](dict(version=version, kind=B["KIND"], files=self.selected() if files is None else files))
        return raw, hashlib.sha256(raw).hexdigest()

    def decoder_records(self):
        # These are inert proof fixtures, never native build or ABI evidence.
        build = dict(compiled=True, tests_passed=True, recipe_sha256=self.digest, source_pin_sha256=self.digest,
            source_helper_sha256=self.digest, tests=dict(version=True, ccsds_nonconstant_nearest_points=True),
            scope=dict(decoder_authorized=False, debian13_abi_proven=False, network_during_build=False,
                       original_sources_unchanged=True),
            artifacts=[dict(path=name, bytes=len(self.raw), sha256=self.digest)
                       for name in ("eccodes-build/bin/grib_ls", "probe.grib2")])
        abi = dict(schema_version=1, kind="weather-decoder-abi", success=True, phase="complete", blocker=None,
            source_commit=self.admitted["artifacts"]["abi"]["commit"],
            weather_commit=self.admitted["artifacts"]["decoder"]["commit"],
            scope=dict(disposable_abi_test_only=True, production_decoder_authorized=False,
                       origin_acquisition_proven=False, core_delivery_proven=False, browser_proven=False),
            checks=dict.fromkeys(("elf_inspected", "first_point", "inputs_verified", "last_point",
                                  "relocated_lone_decoder", "sandbox_isolated", "version"), True),
            cleanup=dict(process_drain_confirmed=True, scratch_removed=True),
            logs={name: dict(bytes=len(self.raw), sha256=self.digest, exit_status=0) for name in B["ABI_LOGS"]})
        return {"decoder-build.json": build, "decoder-abi.json": abi}

    def materialize_capture(self, root, records):
        roots = tuple(root / name for name in ("source", "node", "decoder", "abi"))
        sources = B["android_sources"](*roots)
        for name, path in sources.items():
            record = records.get(name.removeprefix(B["WEATHER"] + B["ANDROID_PREFIX"]))
            raw = B["encode"](record) if record is not None else self.raw
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(raw); path.chmod(0o600)
            self.admitted["files"][name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        return roots

    def test_exact_minimal_contract_has_no_browser_sdk_fixture_or_private_material(self):
        B["validate_android_admission"](self.admitted)
        self.assertEqual(len(B["FIXED_V6"]), 39)
        self.assertEqual(set(B["android_sources"](*[self.root / name for name in ("source", "node", "decoder", "abi")])),
                         B["FIXED_V6"])
        self.assertEqual({name for name in B["FIXED_V6"] if B["mode"](name) == 0o500},
                         {"runtime/node", "decoder/grib_ls"})
        self.assertIn(B["WEATHER"] + "src/android-proof-receipts.mjs", B["FIXED_V6"])
        self.assertTrue(all(not any(word in name for word in ("firefox", "fixture", "flutter", ".apk", "browser-proof"))
                            for name in B["FIXED_V6"]))
        self.assertFalse(B["static_name"](B["STATIC"] + "index.html", 6))

    def test_caller_digest_cannot_authorize_any_changed_or_extra_member(self):
        for name in self.selected():
            files = self.selected(); files[name]["sha256"] = "f" * 64
            with self.subTest(name=name), self.assertRaises(ValueError):
                B["manifest"](*self.manifest(files))
        for name in (B["STATIC"] + "index.html", B["STATIC_V3"] + "main.dart.js",
                     "runtime/firefox-copyright", B["WEATHER"] + "tests/fixtures.mjs", "private.key", "app.apk"):
            files = self.selected(); files[name] = dict(bytes=1, mode=0o400, sha256=self.digest)
            with self.subTest(extra=name), self.assertRaises(ValueError):
                B["manifest"](*self.manifest(files))
        files = self.selected(); files.pop("runtime/node.LICENSE")
        with self.assertRaises(ValueError): B["manifest"](*self.manifest(files))

    def test_closed_admission_coordinates_and_bounds(self):
        for path, replacement in ((["schema"], True), (["scope"], "release"),
                (["sources", "weather", "commit"], "main"),
                (["artifacts", "decoder", "repository"], "other/repo"),
                (["artifacts", "abi", "run_id"], True), (["artifacts", "abi", "id"], 0),
                (["artifacts", "abi", "bytes"], -1), (["artifacts", "abi", "name"], "../record"),
                (["files", "runtime/node", "bytes"], True), (["files", "runtime/node", "sha256"], "f" * 64)):
            value = copy.deepcopy(self.admitted); target = value
            for key in path[:-1]: target = target[key]
            target[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError): B["validate_android_admission"](value)
        for mutate in (lambda v: v.update(success=True), lambda v: v["sources"].update(browser=dict(commit="a" * 40)),
                       lambda v: v["artifacts"].update(proof=v["artifacts"]["decoder"]),
                       lambda v: v["files"].pop("decoder/probe.grib2")):
            value = copy.deepcopy(self.admitted); mutate(value)
            with self.assertRaises(ValueError): B["validate_android_admission"](value)

    def test_readonly_archive_roundtrip_does_not_enable_runtime(self):
        selected = self.selected(); raw, digest = self.manifest()
        source = self.root / "inert"; source.write_bytes(self.raw); source.chmod(0o600)
        sources = dict.fromkeys(selected, source)
        archive = self.root / "guest.tar"
        written = B["write_archive"](sources, selected, raw, digest, archive)
        self.assertEqual(written["files"], 39)
        frozen = self.root / "frozen"
        checked = B["checked_archive"](archive, digest, frozen, report_version=True)
        self.assertEqual(checked["bundle_version"], 6)
        self.assertFalse(B["verify_tree"](frozen, digest)["runtime_executed"])
        self.assertEqual((frozen / "runtime/node").read_bytes(), self.raw)
        self.assertEqual(frozen.stat().st_mode & 0o777, 0o500)
        # Until the joined VM/Android dispatcher is present, archive acceptance
        # must not implicitly authorize running v6 through an older UI driver.
        denied = self.root / "must-not-extract"
        with self.assertRaises(ValueError): B["checked_archive"](archive, digest, denied, runtime=True)
        self.assertFalse(denied.exists())

    def test_capture_checks_original_decoder_proof_bytes_without_execution(self):
        records = self.decoder_records()
        roots = self.materialize_capture(self.root / "capture", records)
        archive = self.root / "capture.tar"
        result = B["capture_v6"](*roots, archive)
        self.assertEqual(result["files"], 39)
        for field in ("current_origin_acquisition_proven", "native_android_proven", "joined_delivery_proven"):
            self.assertIs(result[field], False)
        frozen = self.root / "capture-frozen"
        B["checked_archive"](archive, result["manifest_sha256"], frozen)
        for name, record in records.items():
            self.assertEqual((frozen / B["WEATHER"] / B["ANDROID_PREFIX"] / name).read_bytes(), B["encode"](record))
        self.assertFalse(B["verify_tree"](frozen, result["manifest_sha256"])["runtime_executed"])

    def test_capture_rejects_broken_decoder_and_abi_bindings_even_if_bytes_are_admitted(self):
        mutations = (("decoder-build.json", ("compiled",), False),
            ("decoder-build.json", ("recipe_sha256",), "f" * 64),
            ("decoder-build.json", ("source_pin_sha256",), "f" * 64),
            ("decoder-build.json", ("source_helper_sha256",), "f" * 64),
            ("decoder-build.json", ("artifacts", 0, "sha256"), "f" * 64),
            ("decoder-build.json", ("artifacts", 1, "bytes"), len(self.raw) + 1),
            ("decoder-build.json", ("tests", "ccsds_nonconstant_nearest_points"), False),
            ("decoder-build.json", ("scope", "network_during_build"), True),
            ("decoder-abi.json", ("source_commit",), "f" * 40),
            ("decoder-abi.json", ("weather_commit",), "f" * 40),
            ("decoder-abi.json", ("checks", "relocated_lone_decoder"), False),
            ("decoder-abi.json", ("cleanup", "process_drain_confirmed"), False),
            ("decoder-abi.json", ("scope", "production_decoder_authorized"), True),
            *(("decoder-abi.json", ("logs", name, "sha256"), "f" * 64) for name in B["ABI_LOGS"]))
        for index, (record, path, replacement) in enumerate(mutations):
            records = self.decoder_records(); target = records[record]
            for key in path[:-1]: target = target[key]
            target[path[-1]] = replacement
            roots = self.materialize_capture(self.root / str(index), records)
            # Admission hashes identify bytes; semantic decoder checks remain
            # mandatory and must fail before the archive is even created.
            B["validate_android_admission"](self.admitted)
            archive = self.root / (str(index) + ".tar")
            with self.subTest(record=record, path=path), self.assertRaises(ValueError):
                B["capture_v6"](*roots, archive)
            self.assertFalse(archive.exists())

    def test_symlink_and_changed_tree_are_rejected(self):
        selected = self.selected(); raw, digest = self.manifest()
        source = self.root / "inert"; source.write_bytes(self.raw); source.chmod(0o600)
        link = self.root / "link"; link.symlink_to(source)
        with self.assertRaises(ValueError):
            B["write_archive"](dict.fromkeys(selected, link), selected, raw, digest, self.root / "bad.tar")
        archive = self.root / "guest.tar"
        B["write_archive"](dict.fromkeys(selected, source), selected, raw, digest, archive)
        frozen = self.root / "frozen"; B["checked_archive"](archive, digest, frozen)
        changed = frozen / "runtime/node"; changed.chmod(0o700); changed.write_bytes(b"changed")
        with self.assertRaises(ValueError): B["verify_tree"](frozen, digest)

    def test_missing_v6_record_does_not_change_legacy_dispatch_or_admissions(self):
        missing = self.root / "missing.json"
        with patch.dict(B["public_android_admission"].__globals__, ADMISSION_V6=missing):
            with self.assertRaises(FileNotFoundError): B["public_android_admission"]()
        for version in (1, 2, 3, 4, 5):
            with self.subTest(version=version), self.assertRaises(ValueError):
                B["manifest"](*self.manifest(version=version))
        self.assertEqual(B["build_source"](6), "scripts/prepare_hosted_decoder.py")
        self.assertEqual(B["decoder_sha"](6), self.digest)
        self.assertEqual(B["build_sha"](6), self.digest)

    def test_valid_legacy_profiles_never_consult_v6_admission(self):
        def forbidden_v6():
            self.fail("legacy profile consulted Android admission")

        for version in (1, 2, 3, 4, 5):
            fixed = B["FIXED" if version == 1 else "FIXED_V" + str(version)]
            static = ({B["STATIC_V3"] + name for name in B["STATIC_REQUIRED_V3"]} if version in (3, 5)
                      else {B["STATIC"] + "index.html"})
            files = {name: dict(bytes=len(self.raw), mode=B["mode"](name), sha256=self.digest)
                     for name in fixed | static}
            admitted = dict(files={name: {key: item[key] for key in ("bytes", "sha256")}
                                   for name, item in files.items()})
            with self.subTest(version=version), patch.dict(B["manifest"].__globals__,
                    public_android_admission=forbidden_v6, public_admission=lambda: admitted,
                    public_overmorrow_admission=lambda: admitted):
                raw, digest = self.manifest(files, version)
                self.assertEqual(B["manifest"](raw, digest)["version"], version)


if __name__ == "__main__":
    unittest.main()
