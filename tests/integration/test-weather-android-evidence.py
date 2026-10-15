#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert rejection tests only; synthetic records are never runtime acceptance."""
import copy
import datetime
import json
import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

E = runpy.run_path(str(Path(__file__).with_name("weather-android-evidence.py")))
WORK = Path("/opt/va." + "a" * 32 + ".ABC123")
START = 1791972000000
END = START + 800000


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def publication(key):
    index = E["PRODUCTS"].index(key)
    return dict(publisher_key="a" * 64, name=E["NAMES"][key], revision=1,
        manifest_id=str(index + 1) * 64, sha256=str(index + 3) * 64, bytes=5000 + index,
        expires_unix_seconds=END // 1000 + 100)


def receipt(key, ordinal):
    selected = publication(key)
    value = {field: selected[field] for field in ("publisher_key", "name", "revision", "manifest_id", "sha256", "bytes")}
    value.update(operation="named_content_download", chunks=1, publication_expires_unix_seconds=selected["expires_unix_seconds"],
        local_delivery=True, output_mode="0600", ownership_changed=False, origin_authenticated=False,
        globally_latest=False, cache_only=False, origin_body_bytes=0, origin_range_requests=0,
        peer_bytes=selected["bytes"] if ordinal == 1 else 0, providers_used=1 if ordinal == 1 else 0,
        provider_peer_ids=["AbC"] if ordinal == 1 else [], control_relay_peer_id="DeF" if ordinal == 1 else "",
        cache=str(WORK / "weather-android-cache" / E["CACHES"][key]),
        local_output=str(WORK / f"client-fixtures/weather-viewer/scratch/forecast-{ordinal}BC123/forecast.json"))
    return value


def observation(raw, key, ordinal):
    return dict(schema=1, kind="weather-android-core-receipt-observation", profile=E["PROFILE"], product=key, ordinal=ordinal,
        started_at_ms=START + 2000 * ordinal, completed_at_ms=START + 2000 * ordinal + 1000,
        reuse_cache=ordinal > 1, stdout_bytes=len(raw), stdout_sha256=E["digest"](raw))


def original(key, ordinal, mutate=None):
    value = receipt(key, ordinal)
    if mutate: mutate(value)
    raw = encoded(value)
    return raw, encoded(observation(raw, key, ordinal))


def http(key, ordinal):
    selected = publication(key)
    delivery = {field: selected[field] for field in E["PUBLICATION_KEYS"] - {"expires_unix_seconds"}}
    delivery.update(mode="core-cache", publication_expires_at=datetime.datetime.fromtimestamp(
        selected["expires_unix_seconds"], datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        freshness={}, upstream_origin_attested=False, manifest_media_type_checked=False)
    body = encoded(dict(forecast={"inert": True}, delivery=delivery, observation=ordinal))
    return (b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: "
        + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)


def fixture():
    transfers, responses, publications = {}, [], {}
    observations = dict(requests=dict(weather=3, air_quality=3), bindings={}, after_resume={})
    for phase in ("initial", "refresh", "before_background"):
        observations[phase] = dict(response_sha256={})
    for key in E["PRODUCTS"]:
        publications[key] = publication(key); transfers[key] = []
        route = next(route for route, product in E["ROUTES"].items() if product == key)
        for ordinal, phase in enumerate(("initial", "refresh", "before_background"), 1):
            raw, obs = original(key, ordinal)
            transfers[key].append(E["receipt_observation"](raw, obs, key, ordinal, publication(key), WORK, (START, END)))
            response = E["response_observation"](route, ordinal, http(key, ordinal)); responses.append(response)
            observations[phase][key] = dict(rows=4 if key == "weather" else 5,
                table_sha256="7" * 64, product_sha256=response["body_sha256"])
            observations[phase]["response_sha256"][key] = response["body_sha256"]
        observations["after_resume"][key] = copy.deepcopy(observations["before_background"][key])
        observations["bindings"][key] = dict(forecast_sha256=publication(key)["sha256"], immutable_product_sha256="8" * 64)
    report = dict(schema=2, kind="overmorrow-installed-android-protected-core-trial", profile="protected-core",
        joined_core_acceptance=False, passed=True, phase="complete", package="org.volparossa.weather.trial",
        scope=dict(installed_android_app=True, mounted_widget_tables=True, real_adb_interaction=True,
            pixel_visibility_proven=False, synthetic_weather=False, synthetic_air_quality=False, core_executed=False,
            overlay_proven=False, physical_device=False, production_authority=False, expiry_proven=False),
        checks=dict(initial_exact_native_rows=True, actual_tap_refresh=True, third_refresh_exact_native_rows=True,
            real_android_background_resume=True, original_products_fresh_after_resume=True, no_extra_product_requests=True),
        cleanup=dict(app_stopped=True, forward_removed=True, vm_closed=True), observations=observations)
    return report, transfers, responses, publications


class ReceiptTests(unittest.TestCase):
    def validate(self, raw, obs, key="weather", ordinal=1):
        return E["receipt_observation"](raw, obs, key, ordinal, publication(key), WORK, (START, END))

    def test_original_cold_and_warm_receipts_are_separate_and_have_no_exported_paths(self):
        for key in E["PRODUCTS"]:
            for ordinal in (1, 2, 3):
                result = self.validate(*original(key, ordinal), key, ordinal)
                self.assertEqual(result["peer_bytes"], publication(key)["bytes"] if ordinal == 1 else 0)
                self.assertNotIn(str(WORK), json.dumps(result))
                self.assertNotIn("AbC", json.dumps(result))

    def test_no_reencoding_substitution_or_extra_json_authority(self):
        raw, obs = original("weather", 1)
        for changed in (raw + b"\n", raw.replace(b'"revision":1', b'"revision":true'),
                raw.replace(b'"chunks":1', b'"chunks":1,"chunks":1'),
                raw[:-1] + b',"unexpected":"data"}', raw[:-1] + b',"extra":NaN}'):
            with self.subTest(changed=changed[-90:]), self.assertRaises(ValueError):
                self.validate(changed, obs)

    def test_rejects_wrong_source_output_counts_origin_and_cleanup_semantics(self):
        changes = dict(peer_bytes=0, providers_used=0, provider_peer_ids=[], control_relay_peer_id="AbC",
            chunks=2, bytes=True, origin_body_bytes=1, origin_range_requests=1, cache_only=True,
            cache="/tmp/foreign", local_output=str(WORK / "client-fixtures/weather-viewer/scratch/../forecast.json"),
            manifest_id="f" * 64, publication_expires_unix_seconds=1, output_mode="0644", ownership_changed=True)
        for key, value in changes.items():
            raw, obs = original("weather", 1, lambda row: row.update({key: value}))
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(raw, obs)

    def test_warm_refresh_must_not_hide_new_peer_or_origin_transfer(self):
        for ordinal in (2, 3):
            for key, value in dict(peer_bytes=1, providers_used=1, provider_peer_ids=["AbC"], origin_body_bytes=1).items():
                with self.subTest(ordinal=ordinal, key=key), self.assertRaises(ValueError):
                    self.validate(*original("weather", ordinal, lambda row: row.update({key: value})), ordinal=ordinal)

    def test_rejects_stale_window_wrong_order_wrong_profile_or_prefill(self):
        raw, encoded_obs = original("weather", 1)
        for key, value in dict(schema=True, profile="synthetic", ordinal=2, product="air_quality", reuse_cache=True,
                stdout_sha256="9" * 64, stdout_bytes=True, started_at_ms=START - 1, completed_at_ms=END + 1).items():
            obs = json.loads(encoded_obs); obs[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(raw, encoded(obs))


class ResponseTests(unittest.TestCase):
    def test_hashes_original_utf8_bytes_not_reserialized_data_and_exports_only_closed_fields(self):
        raw = http("weather", 1)
        result = E["response_observation"](next(iter(E["ROUTES"])), 1, raw)
        self.assertEqual(result["body_sha256"], E["digest"](raw.split(b"\r\n\r\n", 1)[1]))
        self.assertFalse(result["joined_core_acceptance"])
        self.assertNotIn("forecast", result)

    def test_rejects_wrong_status_encoding_duplicate_headers_length_and_body(self):
        raw = http("weather", 1)
        candidates = [raw.replace(b"200 OK", b"503 Unavailable"), raw.replace(b"application/json", b"text/html"),
            raw.replace(b"Connection: close", b"Transfer-Encoding: chunked"),
            raw.replace(b"Connection: close", b"Content-Encoding: gzip"),
            raw.replace(b"Connection: close", b"Set-Cookie: secret"),
            raw.replace(b"Connection: close", b"Content-Length: 2"), raw + b"x", raw[:-1],
            raw.replace(b'"revision":1', b'"revision":2')]
        for value in candidates:
            with self.subTest(raw=value[:100]), self.assertRaises(ValueError):
                E["response_observation"](next(iter(E["ROUTES"])), 1, value)

    def test_wrong_product_route_and_extra_requests_are_rejected(self):
        with self.assertRaises(ValueError): E["response_observation"]("/api/volparossa/air-quality", 1, http("weather", 1))
        for ordinal in (0, 4, True):
            with self.assertRaises(ValueError): E["response_observation"](next(iter(E["ROUTES"])), ordinal, http("weather", 1))


class JoinTests(unittest.TestCase):
    def test_six_original_operations_join_without_claiming_captures_or_expiry(self):
        joined = E["join_observations"](*fixture())
        self.assertTrue(joined["matched_original_receipts_and_http_and_ui"])
        self.assertFalse(joined["joined_core_acceptance"]); self.assertFalse(joined["expiry_proven"])
        for key in E["PRODUCTS"]:
            self.assertEqual(joined["products"][key]["requests"], 3)

    def test_rejects_substituted_response_receipt_source_and_duplicate_operation(self):
        for case in ("body", "ui_body", "ui_product", "source", "duplicate", "receipt", "wrong_order", "prefill", "warm_bytes"):
            report, transfers, responses, publications = fixture()
            if case == "body": responses[0]["body_sha256"] = "f" * 64
            if case == "ui_body": report["observations"]["initial"]["response_sha256"]["weather"] = "f" * 64
            if case == "ui_product": report["observations"]["initial"]["weather"]["product_sha256"] = "f" * 64
            if case == "source": responses[0]["publication"]["manifest_id"] = "f" * 64
            if case == "duplicate": responses[-1] = responses[0]
            if case == "receipt": transfers["weather"][0]["forecast_sha256"] = "f" * 64
            if case == "wrong_order": transfers["weather"].reverse()
            if case == "prefill": transfers["weather"][0]["reuse_cache"] = True
            if case == "warm_bytes": transfers["weather"][1]["peer_bytes"] = 1
            with self.subTest(case=case), self.assertRaises(ValueError):
                E["join_observations"](report, transfers, responses, publications)

    def test_rejects_synthetic_ui_claims_added_resume_fetch_and_hidden_cleanup_failure(self):
        for section, field in (("scope", "synthetic_weather"), ("scope", "expiry_proven"),
                ("scope", "overlay_proven"), ("checks", "actual_tap_refresh"), ("cleanup", "app_stopped")):
            report, *rest = fixture(); report[section][field] = not report[section][field]
            with self.subTest(field=field), self.assertRaises(ValueError): E["join_observations"](report, *rest)
        for case in ("extra_get", "resume_changes", "incomplete"):
            report, transfers, responses, publications = fixture()
            if case == "extra_get": report["observations"]["requests"]["weather"] = 4
            if case == "resume_changes": report["observations"]["after_resume"]["weather"]["table_sha256"] = "f" * 64
            if case == "incomplete": responses.pop()
            with self.subTest(case=case), self.assertRaises(ValueError):
                E["join_observations"](report, transfers, responses, publications)


def guest_summary():
    _report, transfers, _responses, publications = fixture()
    return dict(schema=6, kind="weather-android-guest-evidence", profile=E["PROFILE"],
        manifest_sha256="1" * 64, core_sha256="2" * 64, prepared_sha256="3" * 64,
        acquisition_sha256="4" * 64, api_lifecycle_sha256="5" * 64,
        publications=publications, transfers=transfers, capture_scope="common-product-window",
        captures_validated=True, source_acquisition_validated=True, cold_caches_absent_before_api_requests=True,
        publisher_originals_removed=True, helper_requests=0, api_and_sink_joined=True, scratch_outputs_removed=True,
        private_receipts_exported=False, private_viewer_retained_until_vm_destruction=True,
        native_android_proven=False, joined_core_acceptance=False, expiry_proven=False)


class PrivateProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wa-proof-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.publications = {key: publication(key) for key in E["PRODUCTS"]}
        for key in E["PRODUCTS"]:
            for ordinal in (1, 2, 3):
                for suffix, raw in zip(("receipt", "observation"), original(key, ordinal)):
                    child = self.path / f"{key}-{ordinal}.{suffix}.json"
                    child.write_bytes(raw); child.chmod(0o600)

    def verify(self):
        return E["proof_receipts"](self.path, self.publications, WORK, (START, END), os.getuid())

    def test_exact_twelve_owned_private_files_validated_without_exporting_receipts(self):
        transfers, receipts = self.verify()
        self.assertEqual(len(transfers["weather"]), 3)
        self.assertEqual(receipts["weather"][0]["local_output"], receipt("weather", 1)["local_output"])
        self.assertNotIn("local_output", json.dumps(transfers))

    def test_missing_or_extra_proof_file_cannot_be_success(self):
        extra = self.path / "unrequested.json"; extra.write_bytes(b"{}")
        with self.assertRaises(ValueError): self.verify()
        extra.unlink()
        (self.path / "weather-3.receipt.json").unlink()
        with self.assertRaises(ValueError): self.verify()

    def test_rejects_symlink_hardlink_permissions_and_oversized_receipt(self):
        path = self.path / "weather-1.receipt.json"
        path.chmod(0o644)
        with self.assertRaises(ValueError): self.verify()
        path.chmod(0o600)
        foreign = self.path.parent / (self.path.name + ".foreign")
        self.addCleanup(lambda: foreign.unlink(missing_ok=True))
        os.link(path, foreign)
        with self.assertRaises(ValueError): self.verify()
        path.unlink(); path.symlink_to(foreign)
        with self.assertRaises(ValueError): self.verify()
        path.unlink(); path.write_bytes(b"a" * (E["MAX_RECEIPT"] + 1)); path.chmod(0o600)
        with self.assertRaises(ValueError): self.verify()

    def test_duplicate_original_bytes_cannot_be_relabeled_as_another_completed_call(self):
        raw, _ = original("weather", 2)
        (self.path / "weather-3.receipt.json").write_bytes(raw)
        (self.path / "weather-3.observation.json").write_bytes(encoded(observation(raw, "weather", 3)))
        with self.assertRaises(ValueError): self.verify()


class GuestInputBytesTests(unittest.TestCase):
    """Enter the real guest join with owned inert files, never a live guest.

    Reuse the preparation fixture's explicit identity/source-pin seams. File
    modes, inode stability, bounded reads, hashes, canonical configuration and
    lifecycle validation remain real. No fixture executable or namespace runs.
    """
    def setUp(self):
        here = Path(__file__).resolve().parent
        fixture_module = runpy.run_path(str(here / "test-weather-android-delivery.py"))
        self.fixture = fixture_module["AndroidPreparation"](
            "test_only_configuration_and_private_empty_directories_are_created")
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.prepared = self.fixture.run_prepare()
        self.work, self.layout = self.fixture.work, self.fixture.layout
        self.encode = fixture_module["B"]["encode"]
        self.fixture.save(self.work / "weather-products-delivery-manifest.json",
            (self.layout["source"] / "INPUTS.json").read_bytes(), 0o400)
        self.fixture.save(self.work / "weather-products-delivery-input.json", self.fixture.selection_raw)
        self.save_prepared()
        # The first invalid lifecycle schema is intentional: reaching its real
        # validator proves both preceding raw-byte comparisons succeeded, not
        # that any API, delivery or cleanup has been accepted.
        self.lifecycle = dict(schema=True, profile=E["PROFILE"])
        self.fixture.save(self.work / "weather-android-delivery-api.jsonl",
            encoded(self.lifecycle) + b"\n{}\n")
        api = runpy.run_path(str(here / "weather-android-api.py"))
        self.validate_record = Mock(wraps=api["validate_record"])
        prepared_module = dict(fixture_module["A"])
        prepared_module.update(fixture_module["G"])
        api.update(D=prepared_module, P=prepared_module["P"], B=prepared_module["B"],
            validate_record=self.validate_record)
        original_reader = E["private_bytes"]
        def fixture_reader(path, limit, uid, mode=0o600):
            self.assertIn(uid, (0, 985))
            return original_reader(path, limit, os.getuid(), mode)
        def load_api(path):
            self.assertEqual(Path(path).resolve(), here / "weather-android-api.py")
            return api
        seams = patch.dict(E["guest"].__globals__, private_bytes=fixture_reader,
            runpy=SimpleNamespace(run_path=load_api),
            os=SimpleNamespace(**(vars(os) | {"geteuid": lambda: 0})))
        seams.start(); self.addCleanup(seams.stop)

    def save_prepared(self):
        self.prepared_raw = self.encode(self.prepared)
        self.prepared_sha = E["digest"](self.prepared_raw)
        self.fixture.save(self.work / "weather-android-delivery-prepared.json", self.prepared_raw)
        self.fixture.save(self.layout["viewer"] / "prepared.json", self.prepared_raw, 0o400)

    def invoke(self):
        return E["guest"](self.work, self.fixture.digest, self.prepared["core_sha256"], self.prepared_sha)

    def test_identical_prepared_and_config_bytes_reach_real_lifecycle_validation(self):
        with self.assertRaises(ValueError): self.invoke()
        self.validate_record.assert_called_once_with(self.lifecycle)

    def test_prepared_bytes_must_match_even_for_equivalent_json(self):
        self.fixture.save(self.layout["viewer"] / "prepared.json", self.prepared_raw + b"\n", 0o400)
        with self.assertRaises(ValueError): self.invoke()
        self.validate_record.assert_not_called()

    def test_config_bytes_must_match_canonical_encoding_even_with_matching_hash(self):
        raw = self.layout["config"].read_bytes() + b"\n"
        self.fixture.save(self.layout["config"], raw)
        self.prepared["config_sha256"] = E["digest"](raw)
        self.save_prepared()
        with self.assertRaises(ValueError): self.invoke()
        self.validate_record.assert_not_called()

    def test_config_hash_is_still_checked_before_canonical_bytes(self):
        self.fixture.save(self.layout["config"], self.layout["config"].read_bytes() + b"\n")
        with self.assertRaises(ValueError): self.invoke()
        self.validate_record.assert_not_called()

    def test_strict_json_equality_still_rejects_boolean_integer_substitution(self):
        E["same"]({"schema": 1}, {"schema": 1})
        for actual, expected in ((True, 1), (1, True), ({"schema": True}, {"schema": 1}),
                ({"counts": [False]}, {"counts": [0]})):
            with self.subTest(actual=actual), self.assertRaises(ValueError): E["same"](actual, expected)


class GuestExportTests(unittest.TestCase):
    def test_closed_guest_evidence_never_promotes_itself_to_native_or_joined_proof(self):
        value = guest_summary(); E["validate_guest_export"](value)
        self.assertNotIn(str(WORK), json.dumps(value))
        for field in ("native_android_proven", "joined_core_acceptance", "expiry_proven", "private_receipts_exported"):
            changed = copy.deepcopy(value); changed[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError): E["validate_guest_export"](changed)

    def test_rejects_unknown_fields_and_unverified_or_unjoined_cleanup(self):
        for field, replacement in dict(capture_scope="independent-products", helper_requests=1,
                api_and_sink_joined=False, captures_validated=False, source_acquisition_validated=False,
                scratch_outputs_removed=False, private_viewer_retained_until_vm_destruction=False).items():
            value = guest_summary(); value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): E["validate_guest_export"](value)
        for section in (None, "transfer"):
            value = guest_summary()
            target = value if section is None else value["transfers"]["weather"][0]
            target["private_path"] = "/private/never-export"
            with self.assertRaises(ValueError): E["validate_guest_export"](value)

    def test_original_receipts_counters_and_expiry_bind_every_operation(self):
        for field, replacement in dict(stdout_sha256="not-a-hash", peer_bytes=1, ordinal=True,
                origin_body_bytes=1, completed_at_ms=END + 999999).items():
            value = guest_summary(); value["transfers"]["weather"][1][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): E["validate_guest_export"](value)
        value = guest_summary()
        value["transfers"]["weather"][2]["stdout_sha256"] = value["transfers"]["weather"][1]["stdout_sha256"]
        with self.assertRaises(ValueError): E["validate_guest_export"](value)


class CommonCaptureTests(unittest.TestCase):
    def setUp(self):
        here = Path(__file__).resolve().parent
        self.packets = runpy.run_path(str(here / "weather-client-delivery.py"))["validate_packets"]
        data = runpy.run_path(str(here / "test-content-provider-filter-smoke.py"))["fixture"]()
        # Keep the historical inert capture fixture, but use valid base58 labels
        # so the new original-receipt validator checks the same identities too.
        text = json.dumps(data)
        for index, peer in enumerate(data["expected_peers"].values(), 1):
            text = text.replace('"' + peer + '"', '"AbC' + str(index) + '"')
        self.data = json.loads(text)

    def verify(self, key, node):
        data = self.data
        raw, observed = original(key, 1, lambda value: value.update(
            provider_peer_ids=[data["expected_peers"][node]],
            control_relay_peer_id=data["layout"]["control_relay_peer_id"]))
        E["receipt_observation"](raw, observed, key, 1, publication(key), WORK, (START, END))
        self.packets(dict(receipt=json.loads(raw)), data["expected_peers"], data["layout"],
            data["selected_route"], data["cold"]["privacy"], data["cold"]["control_privacy"])

    def test_two_original_products_can_use_one_shared_protected_capture_window(self):
        # This is parser compatibility, not two independent capture claims or
        # proof of live transfers. Each receipt still supplies its own counters.
        for key, node in zip(E["PRODUCTS"], self.data["layout"]["provider_nodes"]): self.verify(key, node)

    def test_common_window_does_not_hide_wrong_provider_direct_exit_or_capture_loss(self):
        original_data = copy.deepcopy(self.data)
        changes = (("client", "direct_client_exit_packets", 1), ("exit", "packet_socket_drops", 1))
        for role, field, value in changes:
            self.data = copy.deepcopy(original_data)
            self.data["cold"]["privacy"][role][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify("weather", "relay4")
        self.data = original_data
        with self.assertRaises(ValueError): self.verify("weather", "exit")
        self.data["cold"]["privacy"]["exit"]["provider_application"]["relay5"]["response_payload_bytes"] = 0
        with self.assertRaises(ValueError): self.verify("air_quality", "relay5")


if __name__ == "__main__": unittest.main()
