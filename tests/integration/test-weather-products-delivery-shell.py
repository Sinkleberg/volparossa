#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert two-product dispatch, timing and cleanup contracts; no network or VM."""
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "weather-products-delivery.sh"
LEGACY = HERE / "weather-client-delivery.sh"


class ProductsShell(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="weather-products-shell-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def call(self, body, source=None):
        return subprocess.run(["/bin/sh", "-s"], input="set -eu\n" +
            (SOURCE.read_text() if source is None else source) + "\n" + body,
            text=True, capture_output=True, timeout=5,
            env=dict(PATH="/usr/bin:/bin", WORK=str(self.root), site_control_gid="987"))

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_syntax_and_inert_sourcing(self):
        subprocess.run(["/bin/sh", "-n", str(SOURCE)], check=True, timeout=5)
        self.ok(self.call(":"))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_closed_independent_product_mapping(self):
        result = self.call('''
for kind in weather air_quality; do
    weather_products_select "$kind"
    printf '%s %s %s %s %s %s\n' "$weather_product" "$weather_product_file" \
        "$weather_product_manifest" "$weather_product_source_cache" "$weather_publications" "$weather_product_prefix"
done
if weather_products_select arbitrary; then exit 90; fi
''')
        self.ok(result)
        self.assertEqual(result.stdout.splitlines(), [
            "weather forecast.json manifest.bin source-cache 4 weather-products-delivery-weather",
            "air_quality air-quality.json air-quality-manifest.bin air-quality-source-cache 5 weather-products-delivery-air-quality",
        ])

    def test_single_deadline_caps_commands_and_refuses_expired_stage(self):
        self.ok(self.call('''
date() { printf '1000\n'; }
[ "$(weather_products_remaining 120)" = 120 ]
WEATHER_PRODUCTS_DEADLINE=1840
[ "$(weather_products_remaining 120)" = 120 ]
WEATHER_PRODUCTS_DEADLINE=1031
[ "$(weather_products_remaining 200)" = 31 ]
[ "$(weather_products_remaining 270)" = 31 ]
WEATHER_PRODUCTS_DEADLINE=1000
if weather_products_remaining 200; then exit 90; fi
WEATHER_PRODUCTS_DEADLINE=999
if weather_products_remaining 270; then exit 90; fi
'''))

    def test_cleanup_retains_before_all_independent_attempts(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/weather-products-delivery.py").touch()
        output = self.root / "client-fixtures/weather-viewer/browser-output"
        output.mkdir(parents=True)
        (output / "report.json").touch()
        self.ok(self.call('''
python3() { printf 'retain\n' >> "$WORK/calls"; return 1; }
weather_products_private() { printf '%s\n' "$1" >> "$WORK/calls"; return 1; }
weather_client_home_cleanup() { printf 'home\n' >> "$WORK/calls"; }
if weather_client_delivery_cleanup; then exit 90; fi
'''))
        self.assertEqual((self.root / "calls").read_text().splitlines(),
                         ["retain", "publisher-cleanup", "user-cleanup", "home"])

    def test_already_retained_report_not_replaced(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/weather-products-delivery.py").touch()
        retained = self.root / "weather-products-delivery-original-report.json"
        retained.write_bytes(b"retained")
        self.ok(self.call('''
python3() { exit 90; }
weather_products_private() { :; }
weather_client_home_cleanup() { :; }
weather_client_delivery_cleanup
'''))
        self.assertEqual(retained.read_bytes(), b"retained")

    def test_verified_closed_dispatch_before_any_v1_work(self):
        source = LEGACY.read_text()
        head = source.split("weather_client_delivery_run() {", 1)[1].split("    PHASE=weather-client-delivery-prepare", 1)[0]
        helper_root = self.root / "tests/integration"
        helper_root.mkdir(parents=True)
        (helper_root / "weather-products-delivery.sh").write_text(
            'weather_products_delivery_run() { printf "v2\\n"; }\n')
        for version in (1, 2, 3, "2"):
            with self.subTest(version=version, value_type=type(version)):
                import json
                value = json.dumps({"bundle_version": version})
                result = self.call('''
source_directory=$WORK
weather_client_bundle=inert
weather_client_manifest_sha256=inert
python3() { printf '%s\n' 'JSON'; }
fail() { exit 77; }
run_selected
'''.replace("JSON", value), source="run_selected() {\n" + head + '\nprintf "v1\\n"\n}\n')
                self.assertEqual(result.returncode, 0 if type(version) is int and version in (1, 2) else 77)
                if result.returncode == 0: self.assertEqual(result.stdout, f"v{version}\n")
        self.assertLess(head.index("runtime-version"), head.index(".bundle_version"))
        self.assertLess(head.index(".bundle_version"), head.index('            . "$source_directory'))

    def test_publication_cleanup_independent_captures_and_retained_proof_order(self):
        source = SOURCE.read_text()
        run = source.split("weather_products_delivery_run() {", 1)[1]
        self.assertLess(run.index(' acquire \\'), run.index('WEATHER_PRODUCTS_DEADLINE='))
        self.assertLess(run.index('WEATHER_PRODUCTS_DEADLINE='), run.index(' content publish'))
        self.assertLess(run.index('weather-products-delivery-manifest.json'), run.index('chown -R'))
        self.assertLess(run.index('publisher-cleanup "$weather_publisher"'), run.index('PHASE=weather-products-delivery-cold-'))
        self.assertIn('cold "$weather_product"', run)
        self.assertIn('start_privacy_observers "$weather_product_prefix-privacy"', run)
        self.assertIn('content_provider_start_control_observer "$weather_product_prefix-control"', run)
        self.assertLess(run.index('content_provider_stop_control_observer'), run.index(' cold-evidence "$WORK"'))
        self.assertLess(run.index(' copy-cold-evidence "$WORK"'), run.index(' prepare "$weather_client_directory"'))
        self.assertLess(run.index(' retain "$WORK"'), run.index('weather_client_delivery_cleanup'))
        self.assertLess(run.index('weather_client_delivery_cleanup'), run.index(' evidence "$WORK"'))
        self.assertIn('--lifetime-seconds 900', run)
        self.assertIn('WEATHER_PRODUCTS_DEADLINE=$(($(date +%s) + 840))', run)
        for maximum in (120, 200, 40, 270): self.assertIn(f'weather_products_remaining {maximum}', source)
        self.assertEqual(source.count('--kill-after=30s'), 4)
        self.assertNotIn('--kill-after=10s', source)
        self.assertNotIn('env HOME=', source)
        self.assertNotIn('--groups=', source)

    def test_observers_accept_only_exact_new_product_prefixes(self):
        control = (HERE / "content-provider-smoke.sh").read_text()
        privacy = (HERE / "kvm-alpha-topology.sh").read_text()
        for suffix in ("weather", "air-quality"):
            self.assertIn(f"weather-products-delivery-{suffix}-control", control)
            self.assertIn(f"weather-products-delivery-{suffix}-privacy", privacy)
        self.assertNotIn('weather-products-*', control)
        self.assertNotIn('weather-products-*', privacy)


if __name__ == "__main__":
    unittest.main()
