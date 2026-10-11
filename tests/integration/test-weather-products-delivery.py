#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic adversarial evidence tests, not an origin/overlay/UI proof."""
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
A = runpy.run_path(str(HERE / "weather-products-delivery.py"))
OLD = runpy.run_path(str(HERE / "test-weather-client-delivery.py"))
SHA = "a" * 64


def selected():
    result = dict(schema=2, products={})
    for key, p in A["PRODUCTS"].items():
        value = OLD["publication"]()
        value.update(name=p["name"], manifest_id=("b" if key == "weather" else "d")*64,
            sha256=("c" if key == "weather" else "e")*64, bytes=6000 if key == "weather" else 4000)
        result["products"][key] = dict(publication=value,
            query=A["fixed_query"](key, "2026-10-10T12:00:00.000Z" if key == "weather" else "2026-10-10T00:00:00.000Z"))
    return result


def acquisition():
    selection = selected()
    return dict(schema=2, success=True, origin_https=True, acquisition_outside_overlay=True,
        upstream_signature_attested=False, synthetic_weather=False, synthetic_air_quality=False,
        independent_product_runs=True, decoder_sha256=A["B"]["DECODER_SHA"], products={
            key: dict(forecast_sha256=selection["products"][key]["publication"]["sha256"],
                forecast_bytes=selection["products"][key]["publication"]["bytes"],
                fields=[dict(lead_hours=step, parameter=parameter, index_sha256=SHA, field_sha256=SHA)
                    for step in p["steps"] for parameter in p["parameters"]]) for key, p in A["PRODUCTS"].items()})


def report():
    legacy = OLD["report"](); expected = legacy["expected"]
    result = dict(schema=2, passed=True, phase="complete", source=legacy["source"],
        expected={key: expected[key] for key in ("expected_sha256", "core_sha256", "display_sha256")},
        products={}, scope=dict(legacy["scope"], synthetic_air_quality=False, separate_native_runs=True),
        checks=dict(no_external_resources=True, provider_requests_checked=2, browser_api_requests=4,
            initial_dom_display_sha256=SHA, refresh_dom_display_sha256=SHA),
        cleanup=legacy["cleanup"], outer_cleanup=legacy["outer_cleanup"])
    result["source"]["bridge_modules"] = {name: SHA for name in A["BRIDGE_MODULES"]}
    for key in A["PRODUCTS"]:
        publication = selected()["products"][key]["publication"]
        result["products"][key] = dict(expected=dict(cold_receipt_sha256=SHA, display_sha256=SHA,
            forecast_sha256=publication["sha256"], manifest_id=publication["manifest_id"]), checks=copy.deepcopy(legacy["checks"]))
    return result


def save(path, value, mode=0o600):
    A["write_new"](path, json.dumps(value).encode(), mode)


def joined_fixture(work):
    f = OLD["FILTER"]["fixture"]()
    selection = selected()
    common = {"input": selection, "acquisition": acquisition(),
        "publisher-cleanup": dict(directory_removed=True, files_removed=True),
        "input-cleanup": dict(directory_removed=True, files_removed=True),
        "prepared": dict(prepared=True, expected_sha256=SHA, display_sha256=SHA)}
    caches = {key: dict(device=1, inode=10+i, mode="0700", user_uid=1234, group_gid=os.getgid()+1)
        for i, key in enumerate(A["PRODUCTS"])}
    for key, p in A["PRODUCTS"].items():
        publication = selection["products"][key]["publication"]
        receipt = OLD["receipt"](work / "state-client" / p["cache"], work / "client-fixtures/weather-viewer" / p["filename"])
        receipt.update({k: v for k, v in publication.items() if k != "expires_unix_seconds"})
        receipt.update(peer_bytes=publication["bytes"], provider_peer_ids=f["cold"]["application"]["receipt"]["provider_peer_ids"],
            control_relay_peer_id=f["layout"]["control_relay_peer_id"])
        files = {
            "selection": f["selected_route"], "control": f["cold"]["control_privacy"],
            "cold-consumer": dict(schema=2, product=key, receipt=receipt, publication=publication,
                cold_cache_requested=True, core_sha256=SHA, cold_receipt_sha256=SHA,
                observed_unix_seconds=publication["expires_unix_seconds"]-60,
                boundary=dict(user_uid=985, primary_control_gid=os.getgid(), supplementary_groups_empty=True,
                    all_capabilities_dropped=True, no_new_privileges=True, client_namespace=True, acquisition_parent_namespace=False)),
            "publish": dict(operation="offline_content_publish", network_publication=False,
                publisher_key_hex=publication["publisher_key"], content_type="application/json", chunks=1,
                **{k: publication[k] for k in ("name", "revision", "bytes", "manifest_id", "expires_unix_seconds")}),
            "cache-before": caches[key], "cache-after": caches[key],
        }
        files.update({"privacy-" + role: captured for role, captured in f["cold"]["privacy"].items()})
        for node in f["layout"]["provider_nodes"]:
            files[node + "-import"] = dict(f["imports"][node], manifest_id=publication["manifest_id"],
                content_bytes=publication["bytes"], agent_cache=str(work / f"state-{node}" / p["cache"]))
            files[node + "-serve"] = dict(f["serves"][node], publications=4 if key == "weather" else 5)
        for suffix, value in files.items(): save(A["artifact"](work, suffix, key), value)
    B = A["B"]
    items = {name: dict(bytes=1, mode=B["mode"](name), sha256=SHA) for name in B["FIXED_V2"] | {B["STATIC"]+"index.html"}}
    for name, digest in (("runtime/node", B["NODE_SHA"]), ("decoder/grib_ls", B["DECODER_SHA"]),
            (B["WEATHER"]+"third_party/eccodes-sources.json", B["PIN_SHA"]), (B["WEATHER"]+"scripts/build_eccodes.py", B["BUILD_SHA"])):
        items[name]["sha256"] = digest
    manifest = B["encode"](dict(version=2, kind=B["KIND"], files=items)); digest = hashlib.sha256(manifest).hexdigest()
    A["write_new"](A["artifact"](work, "manifest"), manifest, 0o400)
    for phase in ("before", "after"):
        common["tree-"+phase] = dict(version=1, action="verify-tree", manifest_sha256=digest, files=len(items), runtime_executed=False)
        common["cache-"+phase] = dict(schema=2, products=caches)
    browser = report(); browser["source"]["bundle_manifest_sha256"] = digest
    browser["source"]["built_tree_sha256"] = hashlib.sha256(json.dumps({"index.html": SHA}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    common["original-report"] = browser
    save(work / "a01-expected-peers.json", f["expected_peers"]); save(work / "content-provider-layout.json", f["layout"])
    socket = work / "runtime-client/control/agent.sock"; socket.parent.mkdir(parents=True)
    A["write_new"](socket, b"inert stat-only fixture")
    for suffix, value in common.items(): save(A["artifact"](work, suffix), value)
    with patch.dict(A["cold_evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
        save(A["artifact"](work, "cold-evidence"), A["cold_evidence"](work, digest, SHA))
    return digest, caches


class Products(unittest.TestCase):
    def test_acquisition_commands_include_precipitation_and_independent_noaa_cycle_with_one_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); root = base / "weather-publisher"; root.mkdir(mode=0o700)
            source = base / "inputs"; source.mkdir(mode=0o700)
            A["initialize"](root); A["write_new"](source / "INPUTS.json", b"fixture", 0o400)
            calls = []
            def execute(command, cwd, maximum, timeout):
                calls.append((command, timeout))
                if command[-1] == "-V": return b"ecCodes Version 2.44.0\n"
                key = "weather" if command[2].endswith("/forecast.mjs") else "air_quality"
                p = A["PRODUCTS"][key]
                def field(parameter):
                    return dict(parameter=parameter, decoder_sha256=A["B"]["DECODER_SHA"], index_sha256=SHA, field_sha256=SHA)
                samples = []
                for step in p["steps"]:
                    samples.append(dict(lead_hours=step, **(dict(evidence=field("2t"),
                        wind_10m=dict(evidence=dict(eastward=field("10u"), northward=field("10v"))),
                        precipitation=dict(evidence=field("tp"))) if key == "weather" else
                        dict(evidence=dict(pm2_5=field("PMTF"), pm10=field("PMTC"))))))
                return json.dumps(dict(schema=p["schema"], source=dict(provider=p["provider"], acquisition="origin-https",
                    model=p["model"], model_run_at=command[command.index("--run")+1]),
                    area=dict(latitude=52.52, longitude=13.41, sharing="public-community"), samples=samples)).encode()
            clock = datetime.datetime(2026, 10, 11, 14, tzinfo=datetime.timezone.utc).timestamp()
            with patch.dict(A["acquisition"].__globals__, run=execute, boundary=lambda *args: None), \
                    patch.dict(A["B"], verify_tree=lambda *args: None, manifest=lambda *args: {"version": 2}), \
                    patch.object(A["time"], "time", return_value=clock), \
                    patch.object(A["time"], "monotonic", side_effect=[100, 120, 480]):
                result = A["acquisition"](source, SHA, root, "net:[1]", "net:[2]", 1000)
            A["validate_acquisition"](result)
            weather, aq = calls[1][0], calls[2][0]
            self.assertIn("--include-precipitation", weather); self.assertNotIn("--include-precipitation", aq)
            self.assertEqual(weather[weather.index("--run")+1], "2026-10-11T00:00:00.000Z")
            self.assertEqual(aq[aq.index("--run")+1], "2026-10-11T00:00:00.000Z")
            # Same cycle time is permissible when independently selected;
            # unlike their native samples, the times need not differ by force.
            self.assertEqual(weather[weather.index("--steps")+1], "3,9,24")
            self.assertEqual(aq[aq.index("--steps")+1], "3,6,12")
            self.assertEqual([call[1] for call in calls], [10, 360, 340])
            self.assertTrue((root / "forecast.json").exists()); self.assertTrue((root / "air-quality.json").exists())

    def test_preparer_uses_both_receipts_and_separate_caches(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); viewer = base / "weather-viewer"; viewer.mkdir(mode=0o700)
            selection = selected(); save(viewer / "selection.json", selection, 0o400)
            def execute(command, cwd, maximum, timeout):
                self.assertEqual(command[command.index("--air-quality")+1], str(viewer / "air-quality.json"))
                self.assertEqual(command[command.index("--air-quality-receipt")+1], str(viewer / "air-quality-cold-receipt.json"))
                config = A["read"](viewer / "config.json")
                self.assertNotEqual(config["core"]["cache"], config["airQuality"]["core"]["cache"])
                self.assertEqual(config["core"]["scratchParent"], config["airQuality"]["core"]["scratchParent"])
                self.assertTrue(config["core"]["query"]["includePrecipitation"])
                expected = dict(schema=2, core_sha256=SHA, display_sha256=SHA,
                    products={key: {"publication": value["publication"]} for key, value in selection["products"].items()})
                raw = A["B"]["encode"](expected); A["write_new"](viewer / "expected.json", raw, 0o400)
                return json.dumps(dict(prepared=True, expected_sha256=hashlib.sha256(raw).hexdigest(), display_sha256=SHA)).encode()
            with patch.dict(A["prepare"].__globals__, run=execute), patch.dict(A["B"], fingerprint=lambda *args: {"sha256": SHA}):
                result = A["prepare"](base / "source", viewer, base / "binary", base / "agent.sock",
                    base / "state-client/weather-cache", base / "state-client/air-quality-cache")
            self.assertTrue(result["prepared"])

    def test_partial_browser_report_is_retainable_but_never_success(self):
        failed = report(); failed.update(passed=False, phase="provider", checks={}, cleanup={})
        failed["scope"].update(actual_drizzli_ui=False, real_core_adapter=False, separate_native_runs=False)
        for value in failed["products"].values(): value["checks"] = {}
        A["closed_report"](failed)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); digest, caches = joined_fixture(work)
            path = A["artifact"](work, "original-report"); path.unlink(); save(path, failed)
            with patch.dict(A["evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                with self.assertRaises(ValueError): A["evidence"](work, digest, SHA)

    def test_exact_selection_keeps_separate_native_runs_and_no_cross_product_alias(self):
        value = selected(); A["validate_selection"](value)
        self.assertNotEqual(value["products"]["weather"]["query"]["run"], value["products"]["air_quality"]["query"]["run"])
        mutations = [("air_quality", "query", "steps", [3, 9, 24]), ("weather", "query", "includePrecipitation", False),
            ("air_quality", "publication", "name", A["PRODUCTS"]["weather"]["name"]),
            ("air_quality", "publication", "manifest_id", value["products"]["weather"]["publication"]["manifest_id"])]
        for key, group, field, changed in mutations:
            bad = copy.deepcopy(value); bad["products"][key][group][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError): A["validate_selection"](bad)

    def test_acquisition_requires_twelve_weather_and_six_native_particulate_fields(self):
        good = acquisition(); A["validate_acquisition"](good)
        for key in A["PRODUCTS"]:
            for field in ("missing", "duplicate", "wrong_parameter", "wrong_step"):
                value = copy.deepcopy(good); fields = value["products"][key]["fields"]
                if field == "missing": fields.pop()
                elif field == "duplicate": fields[0] = fields[1]
                elif field == "wrong_parameter": fields[0]["parameter"] = "private-source-url"
                else: fields[0]["lead_hours"] = 1
                with self.subTest(key=key, field=field), self.assertRaises(ValueError): A["validate_acquisition"](value)

    def test_full_join_rejects_product_specific_origin_privacy_and_ui_failures(self):
        mutations = [None,
            ("cold-consumer", "air_quality", ("receipt", "origin_body_bytes"), 1),
            ("cold-consumer", "air_quality", ("publication", "sha256"), "f"*64),
            ("cold-consumer", "weather", ("boundary", "no_new_privileges"), False),
            ("cold-consumer", "air_quality", ("observed_unix_seconds",), 1900000000),
            ("privacy-client", "air_quality", ("direct_client_exit_packets",), 1),
            ("privacy-exit", "air_quality", ("packet_socket_drops",), 1),
            ("control", "air_quality", ("unexpected_provider_application_packets",), 1),
            ("original-report", None, ("products", "air_quality", "checks", "browser_api_requests"), 1),
            ("original-report", None, ("products", "weather", "checks", "refresh_dom_display_sha256"), "f"*64),
            ("original-report", None, ("products", "air_quality", "expected", "cold_receipt_sha256"), "f"*64),
            ("original-report", None, ("source", "bridge_modules", "src/air-quality-provider.mjs"), "f"*64),
            ("original-report", None, ("scope", "synthetic_air_quality"), True),
            ("original-report", None, ("scope", "separate_native_runs"), False),
            ("original-report", None, ("checks", "browser_api_requests"), 6),
            ("original-report", None, ("checks", "refresh_dom_display_sha256"), "f"*64),
            ("cold-evidence", None, ("products", "air_quality", "forecast_sha256"), "f"*64),
            ("acquisition", None, ("products", "air_quality", "forecast_sha256"), "f"*64),
            ("publisher-cleanup", None, ("files_removed",), False),
            ("cache-after", "air_quality", ("inode",), 123)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); digest, caches = joined_fixture(work)
                if mutation:
                    suffix, key, keys, changed = mutation; path = A["artifact"](work, suffix, key)
                    value = json.loads(path.read_bytes()); target = value
                    for field in keys[:-1]: target = target[field]
                    target[keys[-1]] = changed; path.unlink(); save(path, value)
                with patch.dict(A["evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                    if mutation:
                        with self.assertRaises(ValueError): A["evidence"](work, digest, SHA)
                    else:
                        proof = A["evidence"](work, digest, SHA); A["validate_evidence_export"](proof)
                        self.assertTrue(proof["scope"]["end_to_end_proven"])
                        self.assertFalse(proof["scope"]["browser_triggered_cold_fetch"])
                        self.assertEqual(proof["products"]["weather"]["acquired_fields"], 12)
                        self.assertEqual(proof["products"]["air_quality"]["acquired_fields"], 6)

    def test_weather_only_capture_or_receipt_never_proves_air_quality(self):
        for suffix in ("cold-consumer", "selection", "privacy-client", "privacy-exit", "control", "cache-before"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); digest, caches = joined_fixture(work)
                A["artifact"](work, suffix, "air_quality").unlink()
                with patch.dict(A["cold_evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                    with self.assertRaises((OSError, ValueError)): A["cold_evidence"](work, digest, SHA)

    def test_cold_evidence_survives_missing_ui_without_claiming_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); digest, caches = joined_fixture(work)
            for suffix in ("original-report", "prepared", "tree-after", "input-cleanup"):
                A["artifact"](work, suffix).unlink()
            with patch.dict(A["cold_evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                result = A["cold_evidence"](work, digest, SHA)
                self.assertFalse(result["scope"]["end_to_end_proven"])
                with self.assertRaises((ValueError, OSError)): A["evidence"](work, digest, SHA)
            output = work / "output"; output.mkdir()
            A["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertTrue(A["artifact"](output, "cold-evidence").exists())
            self.assertFalse(A["artifact"](output, "evidence").exists())

    def test_closed_exports_reject_location_and_raw_receipts_before_any_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); joined_fixture(work); output = work / "output"; output.mkdir()
            path = A["artifact"](work, "acquisition"); value = json.loads(path.read_bytes())
            value["coordinates"] = [52.52, 13.41]; path.unlink(); save(path, value)
            with self.assertRaises(ValueError): A["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual(list(output.iterdir()), [])
        value = report(); value["products"]["air_quality"]["receipt"] = {"private": "raw"}
        with self.assertRaises(ValueError): A["closed_report"](value)

    def test_cleanup_validates_all_targets_before_deleting_two_product_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "weather-publisher"; root.mkdir(mode=0o700)
            for name in ("forecast.json", "air-quality.json", "identity.key"):
                A["write_new"](root / name, b"fixture")
            A["write_new"](root / "unrelated", b"keep")
            with self.assertRaises(ValueError): A["cleanup"](root, True)
            self.assertTrue((root / "forecast.json").exists()); self.assertTrue((root / "air-quality.json").exists())
            (root / "unrelated").unlink()
            self.assertEqual(A["cleanup"](root, True), dict(directory_removed=True, files_removed=True))
            self.assertFalse(root.exists())

    def test_cleanup_accepts_larger_two_product_expected_but_not_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "weather-viewer"; root.mkdir(mode=0o700)
            A["write_new"](root / "expected.json", b"x" * (300*1024), 0o400)
            (root / "air-quality.json").symlink_to(root / "expected.json")
            with self.assertRaises(ValueError): A["cleanup"](root, False)
            self.assertTrue((root / "expected.json").exists())
            (root / "air-quality.json").unlink(); A["cleanup"](root, False)

    def test_cache_metadata_is_distinct_private_and_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); state = work / "state-client"; state.mkdir()
            values = {}
            for key, p in A["PRODUCTS"].items():
                path = state / p["cache"]; path.mkdir(mode=0o700)
                values[key] = A["cache_state"](key, path, os.getuid(), os.getgid())
            self.assertNotEqual(values["weather"]["inode"], values["air_quality"]["inode"])
            A["validate_cache_export"](dict(schema=2, products=values))
            with self.assertRaises(ValueError): A["cache_state"]("air_quality", state / "weather-cache", os.getuid(), os.getgid())


if __name__ == "__main__": unittest.main()
