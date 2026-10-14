#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert profile-6 shell wiring. All privileged/provider commands are mocks.

The only live child is an ordinary short-lived shell waiting on a fixture file;
these tests cannot establish Android, provider or network delivery.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "weather-android-delivery.sh"
PRODUCTS = HERE / "weather-products-delivery.sh"
LEGACY = HERE / "weather-client-delivery.sh"


class AndroidShell(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="weather-android-shell-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.libexec = self.work / "libexec"; self.libexec.mkdir(mode=0o755)
        for name in ("bin", "viewer"):
            (self.work / name).mkdir(mode=0o700)
        for name in ("weather-android-control.py", "weather-android-evidence.py", "weather-products-delivery.py"):
            (self.work / "bin" / name).write_text("inert; never executed\n")
        self.source = SOURCE.read_text().replace("/usr/local/libexec", str(self.libexec)).replace("systemd-detect-virt", "test_virt")

    def call(self, body, *, source=None, extra=None, seconds=6):
        environment = dict(PATH="/usr/bin:/bin", WORK=str(self.work), WORKER_UID="985", AGENT_UID="986", AGENT_GID="986",
            site_control_gid="987", CLIENT="owned-client", site_parent_ns="net:[111]", site_client_ns="net:[222]",
            weather_profile_version="6", weather_publisher=str(self.work / "publisher"),
            weather_viewer=str(self.work / "viewer"), WEATHER_PRODUCTS_DEADLINE="1840",
            weather_core_sha256="c" * 64, weather_client_manifest_sha256="a" * 64,
            TEST_LIBEXEC=str(self.libexec), TEST_FAILURE="", TEST_REMAINING="840")
        environment.update(extra or {})
        return subprocess.run(["/bin/sh", "-s"], input="set -eu\n" + (self.source if source is None else source) + "\n" + body,
            text=True, capture_output=True, timeout=seconds, env=environment)

    def good(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_syntax_and_sourcing_have_no_effects(self):
        subprocess.run(["/bin/sh", "-n", str(SOURCE)], check=True, timeout=5)
        before = set(self.work.rglob("*"))
        self.good(self.call(":"))
        self.assertEqual(before, set(self.work.rglob("*")))

    def test_v6_dispatch_has_no_browser_or_cold_branch(self):
        source = PRODUCTS.read_text()
        branch = source[source.index('    if [ "$weather_profile_version" = 6 ]; then\n        # The installed'):]
        branch = branch[:branch.index("    for weather_kind in weather air_quality; do")]
        for version in (2, 3, 4, 5, 6):
            result = self.call('''
weather_profile_version=VERSION
weather_android_delivery_run() { printf 'android\n'; }
dispatch() {
BRANCH
printf 'legacy\n'
}
dispatch
'''.replace("VERSION", str(version)).replace("BRANCH", branch), source="")
            self.good(result)
            self.assertEqual(result.stdout, "android\n" if version == 6 else "legacy\n")
        self.assertLess(source.index(branch), source.index("PHASE=weather-products-delivery-cold-$weather_product_path"))
        self.assertGreater(source.index(branch), source.index("fail WEATHER_PRODUCTS_PUBLISHER_FILES_REMAIN"))
        self.assertIn("2|3|4|5|6)", LEGACY.read_text())

    def test_v6_only_stages_extra_closed_helpers(self):
        source = PRODUCTS.read_text()
        staging = "    for weather_script in " + source.split("    for weather_script in ", 1)[1].split(
            "    install -o root -g root -m 0600", 1)[0]
        for version in (2, 3, 4, 5, 6):
            result = self.call('''
source_directory=/verified-core
weather_profile_version=VERSION
install() { printf '%s\n' "$*"; }
fail() { exit 97; }
'''.replace("VERSION", str(version)) + staging, source="")
            self.good(result)
            for name in ("weather-public-android-v6.json", "weather-android-delivery.py", "weather-android-api.py",
                    "weather-android-control.py", "weather-android-evidence.py"):
                calls = [line for line in result.stdout.splitlines() if name in line]
                self.assertEqual(len(calls), 1 if version == 6 else 0)

    def test_normal_guest_lifecycle_orders_actual_get_window_and_required_evidence(self):
        self.good(self.call(self.mocks() + "weather_android_delivery_run\nweather_client_delivery_cleanup\n"))
        calls = (self.work / "calls").read_text().splitlines()
        self.assertLess(calls.index("prepare"), calls.index("privacy-start"))
        self.assertLess(calls.index("privacy-start"), calls.index("api-serve"))
        self.assertLess(calls.index("api-serve"), calls.index("controller-publish"))
        self.assertLess(calls.index("controller-publish"), calls.index("paths"))
        self.assertLess(calls.index("paths"), calls.index("privacy-stop"))
        self.assertLess(calls.index("privacy-stop"), calls.index("evidence-guest"))
        self.assertLess(calls.index("evidence-guest"), calls.index("controller-remove"))
        self.assertEqual(calls.count("api-serve"), 1)
        self.assertTrue((self.work / "weather-android-delivery-evidence.json").is_file())
        self.assertFalse((self.libexec / "volparossa-weather-android-control.py").exists())
        self.assertTrue((self.work / "viewer/prepared.json").exists())
        self.assertEqual(list((self.work / "weather-android-cache").iterdir()), [])

    def test_guest_evidence_failure_is_not_promoted_to_success(self):
        result = self.call(self.mocks() + "weather_android_delivery_run\n", extra=dict(TEST_FAILURE="evidence"))
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("WEATHER_ANDROID_EVIDENCE_INVALID", result.stderr)
        calls = (self.work / "calls").read_text().splitlines()
        self.assertIn("evidence-guest", calls)
        self.assertIn("controller-remove", calls)

    def test_insufficient_remaining_budget_starts_no_api_or_capture(self):
        result = self.call(self.mocks() + "weather_android_delivery_run\n", extra=dict(TEST_REMAINING="599"))
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("WEATHER_ANDROID_TRIAL_BUDGET_INSUFFICIENT", result.stderr)
        calls = (self.work / "calls").read_text().splitlines()
        self.assertNotIn("api-serve", calls); self.assertNotIn("privacy-start", calls)

    def test_existing_cache_or_controller_is_preserved(self):
        for kind in ("cache", "controller"):
            target = self.work / "weather-android-cache" if kind == "cache" else self.libexec / "volparossa-weather-android-control.py"
            if kind == "cache": target.mkdir(mode=0o700)
            else: target.write_text("preserve")
            result = self.call(self.mocks() + "weather_android_delivery_run\n")
            self.assertEqual(result.returncode, 77, result.stderr)
            self.assertTrue(target.exists())
            if kind == "cache": target.rmdir()
            else: self.assertEqual(target.read_text(), "preserve")

    def test_cleanup_attempts_independent_resources_without_browser_private_delete(self):
        result = self.call('''
weather_android_stop_api() { printf 'api\n'; return 1; }
weather_android_stop_observers() { printf 'observers\n'; return 1; }
weather_android_controller_cleanup() { printf 'controller\n'; return 1; }
weather_products_private() { printf '%s\n' "$1" >> "$WORK/calls"; return 1; }
weather_client_home_cleanup() { exit 88; }
if weather_client_delivery_cleanup; then exit 90; fi
''')
        self.good(result)
        self.assertEqual(result.stdout.splitlines(), ["api", "observers", "controller"])
        self.assertEqual((self.work / "calls").read_text(), "publisher-cleanup\n")

    def test_recycled_or_missing_pid_is_never_signalled(self):
        self.good(self.call('''
WEATHER_ANDROID_API_PID=1
WEATHER_ANDROID_API_IDENTITY=original
weather_android_process_identity() { printf 'replacement\n'; }
kill() { exit 89; }
wait() { return 1; }
if weather_android_stop_api; then exit 90; fi
[ "$WEATHER_ANDROID_API_JOINED" = yes ]
'''))

    def test_unknown_or_live_process_is_not_unboundedly_waited(self):
        for state in ("initial-identity-missing", "probe-failed", "still-alive"):
            with self.subTest(state=state):
                self.good(self.call('''
WEATHER_ANDROID_API_PID=12345
WEATHER_ANDROID_API_IDENTITY=original
case STATE in
    initial-identity-missing) WEATHER_ANDROID_API_IDENTITY= ;;
    probe-failed) weather_android_process_identity() { return 2; } ;;
    still-alive) weather_android_process_identity() { printf 'original\\n'; } ;;
esac
wait() { exit 89; }
if weather_android_join_api; then exit 90; fi
[ "$WEATHER_ANDROID_API_JOINED" = no ]
'''.replace("STATE", state)))

    def test_inconclusive_process_probe_preserves_cleanup_failure(self):
        self.good(self.call('''
WEATHER_ANDROID_API_PID=12345
WEATHER_ANDROID_API_IDENTITY=original
weather_android_process_identity() { return 2; }
kill() { exit 89; }
wait() { exit 90; }
if weather_android_stop_api; then exit 91; fi
[ "$WEATHER_ANDROID_API_JOINED" = no ]
'''))

    def test_worker_boundary_original_deadline_and_export_contract_are_fixed(self):
        source = SOURCE.read_text()
        serve = source[source.index('    ip netns exec "$CLIENT" setpriv'):source.index('    WEATHER_ANDROID_API_PID=$!')]
        for fragment in ('--reuid="$WORKER_UID"', '--regid="$site_control_gid"', '--clear-groups',
                '--inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs',
                '"$WEATHER_PRODUCTS_DEADLINE"', '"$WORK/bin/weather-android-api.py" serve'):
            self.assertIn(fragment, serve)
        for forbidden in (" curl ", " wget ", " cold ", " prewarm", "user-cleanup", "smoke_core_browser.py"):
            # Comments explain the deliberate absence; executable lines do not.
            executable = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
            self.assertNotIn(forbidden, executable)
        self.assertIn('"$WORK/bin/weather-android-evidence.py" guest "$WORK" "$weather_client_manifest_sha256"', source)
        self.assertIn('"$WORK/bin/weather-android-evidence.py" copy-artifacts "$WORK"', source)

    @staticmethod
    def mocks():
        return r'''
record() { printf '%s\n' "$1" >> "$WORK/calls"; }
id() { printf '0\n'; }
test_virt() { printf 'kvm\n'; }
date() { printf '1000\n'; }
stat() {
    if [ "$2" = '%u:%g:%a' ]; then printf '0:0:755\n';
    else /usr/bin/stat "$@"; fi
}
fail() { printf '%s\n' "$1" >&2; exit 77; }
weather_products_remaining() {
    if [ "$1" = 840 ]; then printf '%s\n' "$TEST_REMAINING"; else printf '%s\n' "$1"; fi
}
install() {
    directory=no
    for value do [ "$value" != -d ] || directory=yes; target=$value; done
    if [ "$directory" = yes ]; then /usr/bin/mkdir -m 0710 -- "$target";
    else
        previous=
        for value do source=$previous; previous=$value; done
        /usr/bin/install -m 0400 -- "$source" "$target"
    fi
}
timeout() { record prepare; printf '{"inert_prepare":true}\n'; }
start_privacy_observers() { record privacy-start; }
content_provider_start_control_observer() { record control-start; }
stop_privacy_observers() { record privacy-stop; }
content_provider_stop_control_observer() { record control-stop; }
benchmark_capture_paths() { record paths; }
weather_client_verify_tree() { record tree-after; printf '{"inert_tree":true}\n'; }
weather_products_private() { record "$1"; printf '{"inert_cleanup":true}\n'; }
ip() {
    record api-serve
    printf '{"inert_ready":true}\n'
    while [ ! -f "$WORK/inert-finalize" ]; do /usr/bin/sleep 0.01; done
    printf '{"inert_final":true}\n'
}
python3() {
    case "$2:$3" in
        */weather-android-control.py:publish)
            record controller-publish; /usr/bin/touch "$WORK/inert-finalize"; printf '{"inert_published":true}\n' ;;
        */weather-android-control.py:remove)
            record controller-remove; printf '{"inert_removed":true}\n' ;;
        */weather-android-evidence.py:guest)
            record evidence-guest; [ "$TEST_FAILURE" != evidence ] || return 1; printf '{"inert_evidence":true}\n' ;;
        *) return 98 ;;
    esac
}
trap 'weather_client_delivery_cleanup || true' EXIT
'''


if __name__ == "__main__": unittest.main()
