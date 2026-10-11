#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert archive/parser tests. No real binaries, acquisition, browser or VM."""
import copy
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
        self.files = {name: dict(bytes=len(self.raw), mode=W["mode"](name), sha256=self.digest)
            for name in W["FIXED"] | {W["STATIC"] + "index.html"}}

    def manifest(self, value=None):
        raw = W["encode"](value or dict(version=1, kind=W["KIND"], files=self.files))
        return raw, hashlib.sha256(raw).hexdigest()

    def archive(self, suffix=b"\0" * 1024):
        raw, expected = self.manifest()
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

    def proof_fixture(self):
        selected = copy.deepcopy(self.files)
        module_hashes = {name: self.digest for name in W["PROVEN_WEATHER_MODULES"]}
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
        return selected, {"browser-smoke.json": proof, "upstream.json": upstream,
                          "volparossa-staging.json": metadata, "build-receipt.json": build}

    def check_proof(self, selected, records):
        # No real source/binary capture or import. Only inert JSON-shaped values.
        with patch.dict(W["source_proof"].__globals__, small_json=lambda path: records[path.name]):
            return W["source_proof"](Path("/inert/weather"), Path("/inert/browser"),
                                     Path("/inert/ui"), Path("/inert/runtime"), selected)

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
