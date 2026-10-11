#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Freeze exact reviewed Weather/UI/runtime inputs; never execute captured files.

The separately retained manifest hash authorizes transfer, not runtime execution.
Outputs live outside this immutable tree. The enclosing VM supplies the separately
verified core binary; no mutable package install or data download occurs here.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import tarfile

B = runpy.run_path(str(Path(__file__).with_name("browser-filter-bundle.py")))
KIND = "volparossa-weather-client-inputs"
WEATHER = "volparossa-weather/"
BROWSER = "volparossa-browser/"
STAGE = BROWSER + "build/firefox-esr-smoke-v3/"
UI_STAGE = WEATHER + "build/drizzli-volparossa/"
STATIC = UI_STAGE + "build/"
NODE_SHA = "bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12"
DECODER_SHA = "3a3b64581e6922db4287445f217f993f6967dea5fcc45ff66944b0bc883408f4"
PIN_SHA = "f136020562a6ff0d2a83b948189c31f839afb8a00ea87565469f38640fb0dc86"
BUILD_SHA = "5bcb6d58b34e5b45647feae836bfd086ff0adce0e30487430f5c50941f579827"
PROVEN_BRIDGE_MODULES = frozenset(("src/provider-http.mjs", "src/provider-core.mjs", "src/core-cache.mjs"))
PROVEN_BROWSER_HELPERS = frozenset(("scripts/smoke_compute_model.py", "scripts/smoke_privacy.py", "scripts/stage_firefox.py"))
PROVEN_RUNTIME_FILES = frozenset(("firefox-esr", "libxul.so", "omni.ja", "browser/omni.ja"))
PROVEN_WEATHER_MODULES = frozenset(("src/forecast.mjs", "src/provider.mjs"))
RUNTIME_FILES = frozenset(name for name in B["RUNTIME_FILES"] if not name.startswith("distribution/"))
WEATHER_FILES = frozenset(("LICENSE", "src/forecast.mjs", "src/ecmwf.mjs", "src/core-cache.mjs",
    "src/provider.mjs", "src/provider-core.mjs", "src/provider-http.mjs", "scripts/forecast.mjs",
    "scripts/serve-provider.mjs", "scripts/build_eccodes.py", "third_party/eccodes-sources.json",
    "build/eccodes/build-receipt.json", "integrations/drizzli/upstream.json",
    "integrations/drizzli/upstream.patch", "integrations/drizzli/browser-smoke.json",
    "integrations/drizzli/smoke_browser.py", "integrations/drizzli/smoke_core_browser.py",
    "integrations/drizzli/prepare-core-browser.mjs",
    "third_party/eccodes/licenses/eccodes/LICENSE", "third_party/eccodes/licenses/eccodes/NOTICE",
    "third_party/eccodes/licenses/ecbuild/LICENSE", "third_party/eccodes/licenses/ecbuild/NOTICE",
    "third_party/eccodes/licenses/ecbuild/COPYING", "third_party/eccodes/licenses/libaec/LICENSE.txt",
    "third_party/eccodes/licenses/expected/COPYING"))
BROWSER_FILES = frozenset(("defaults/privacy.json", "scripts/smoke_compute_model.py",
    "scripts/smoke_privacy.py", "scripts/stage_firefox.py"))
CLIENT_FILES = frozenset(("LICENSE", *("src/lib/services/volparossa/" + name + ".mjs"
    for name in ("client", "provider", "forecast"))))
FIXED = frozenset({*(WEATHER + name for name in WEATHER_FILES),
    *(BROWSER + name for name in BROWSER_FILES), *(STAGE + name for name in RUNTIME_FILES),
    *(UI_STAGE + name for name in CLIENT_FILES), "runtime/node", "decoder/grib_ls"})
# Version 1 remains the exact frozen temperature/wind input contract. Version 2
# selects the separate precipitation/particulate runner. Input eligibility does
# not constitute evidence that either runtime has completed a live proof.
AQ_MODULES = frozenset(("src/air-quality.mjs", "src/air-quality-provider.mjs"))
OVERLAY_FILES = frozenset(("src/lib/services/volparossa/client.mjs",
    "src/lib/services/volparossa/client.d.mts", "src/lib/services/volparossa-mode.ts",
    "src/routes/weather/week/VolparossaForecast.svelte", "src/routes/weather/week/VolparossaWeek.svelte",
    "src/routes/weather/week/VolparossaAirQuality.svelte"))
FIXTURE_MODULES = frozenset(("tests/fixtures.mjs", "tests/air-quality-fixtures.mjs", "src/ecmwf.mjs"))
NOAA_MODULES = frozenset(("src/noaa-gefs.mjs", "src/air-quality.mjs", "src/core-cache.mjs", "scripts/air-quality.mjs"))
ECMWF_MODULES = frozenset(("src/ecmwf.mjs", "src/forecast.mjs", "src/provider.mjs", "scripts/forecast.mjs"))
WEATHER_FILES_V2 = (WEATHER_FILES - {"integrations/drizzli/browser-smoke.json"}) | AQ_MODULES | NOAA_MODULES | FIXTURE_MODULES | {
    "src/air-quality-core.mjs", "third_party/noaa-gefs.json", "third_party/noaa-gefs-smoke.json",
    "third_party/ecmwf-precipitation-smoke.json",
    "integrations/drizzli/air-quality-browser-smoke.json", "integrations/drizzli/browser-fixture.mjs",
    *("integrations/drizzli/overlay/" + name for name in OVERLAY_FILES)}
CLIENT_FILES_V2 = CLIENT_FILES | OVERLAY_FILES | {"LICENSE.VOLPAROSSA",
    *("src/lib/services/volparossa/" + Path(name).name for name in AQ_MODULES)}
FIXED_V2 = frozenset({*(WEATHER + name for name in WEATHER_FILES_V2),
    *(BROWSER + name for name in BROWSER_FILES), *(STAGE + name for name in RUNTIME_FILES),
    *(UI_STAGE + name for name in CLIENT_FILES_V2), "runtime/node", "decoder/grib_ls"})
EXECUTABLES = frozenset({"runtime/node", "decoder/grib_ls", *(STAGE + name for name in
    ("firefox-esr", "firefox-bin", "crashhelper", "crashreporter", "glxtest", "vaapitest", "pingsender"))})
MAX_FILES = 512
MAX_MANIFEST = 128 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ARCHIVE = MAX_TOTAL + 2 * 1024 * 1024
MAX_STATIC = 32 * 1024 * 1024
require, hex64, encode = B["require"], B["hex64"], B["encode"]
fingerprint, open_checked, identity = B["fingerprint"], B["open_checked"], B["identity"]
header, read_exact, new_path = B["header"], B["read_exact"], B["new_path"]


def mode(name):
    return 0o500 if name in EXECUTABLES else 0o400


def bound(name):
    if name.startswith(STAGE) or name in ("runtime/node", "decoder/grib_ls"):
        return MAX_FILE
    return 8 * 1024 * 1024 if name.startswith(STATIC) else 1024 * 1024


def static_name(name):
    return name.startswith(STATIC) and all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,254}", part)
        and part not in (".", "..") for part in name[len(STATIC):].split("/"))


def manifest(raw, expected):
    require(hex64(expected) and 0 < len(raw) <= MAX_MANIFEST and hashlib.sha256(raw).hexdigest() == expected)
    value = json.loads(raw, object_pairs_hook=B["unique_pairs"])
    require(type(value) is dict and set(value) == {"version", "kind", "files"}
        and type(value["version"]) is int and value["version"] in (1, 2) and value["kind"] == KIND
        and type(value["files"]) is dict
        and 1 <= len(value["files"]) <= MAX_FILES and encode(value) == raw)
    fixed = FIXED if value["version"] == 1 else FIXED_V2
    require(fixed <= set(value["files"]) and all(name in fixed or static_name(name) for name in value["files"])
        and STATIC + "index.html" in value["files"])
    total = static_bytes = 0
    for name, item in value["files"].items():
        require(type(item) is dict and set(item) == {"bytes", "mode", "sha256"}
            and type(item["bytes"]) is int and 0 < item["bytes"] <= bound(name)
            and type(item["mode"]) is int and item["mode"] == mode(name) and hex64(item["sha256"]))
        total += item["bytes"]
        static_bytes += item["bytes"] if name.startswith(STATIC) else 0
    require(total <= MAX_TOTAL and static_bytes <= MAX_STATIC)
    for name, expected_sha in (("runtime/node", NODE_SHA), ("decoder/grib_ls", DECODER_SHA),
            (WEATHER + "third_party/eccodes-sources.json", PIN_SHA), (WEATHER + "scripts/build_eccodes.py", BUILD_SHA)):
        require(value["files"][name]["sha256"] == expected_sha)
    return value


def inventory(root, *, exact=None, normalized=False):
    B["canonical"](root)
    files, pending, count = {}, [root], 0
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o7022)
        if normalized:
            require(stat.S_IMODE(info.st_mode) == 0o500)
        with os.scandir(directory) as children:
            for child in children:
                count += 1
                require(count <= MAX_FILES * 4)
                path = Path(child.path)
                relative = str(path.relative_to(root))
                require(len(path.relative_to(root).parts) <= 20)
                if child.is_dir(follow_symlinks=False):
                    pending.append(path)
                else:
                    require(child.is_file(follow_symlinks=False))
                    files[relative] = path
                    require(len(files) <= MAX_FILES)
    if exact is not None:
        require(set(files) == set(exact))
        require(B["directories"](files) == {str(path.relative_to(root)) for path in root.rglob("*") if path.is_dir()})
    return files


def small_json(path):
    source, info = open_checked(path, 1024 * 1024)
    with source:
        raw = source.read(1024 * 1024 + 1)
        require(len(raw) == info.st_size and identity(os.fstat(source.fileno())) == identity(info))
    return json.loads(raw, object_pairs_hook=B["unique_pairs"])


def proven_hashes(value, names):
    # A truncated retained map must not silently skip a source-binding check.
    require(type(value) is dict and set(value) == set(names) and all(hex64(digest) for digest in value.values()))
    return value


def source_proof(weather, browser, ui, stage, selected, version=1):
    """Check retained build provenance; do not run either project's validators."""
    require(type(version) is int and version in (1, 2))
    proof = small_json(weather / ("integrations/drizzli/browser-smoke.json" if version == 1
                                 else "integrations/drizzli/air-quality-browser-smoke.json"))
    upstream = small_json(weather / "integrations/drizzli/upstream.json")
    require(proof["passed"] is True and proof["scope"]["synthetic_weather"] is True
        and proof["scope"]["core_executed"] is False)
    hashes = {name[len(STATIC):]: item["sha256"] for name, item in selected.items() if name.startswith(STATIC)}
    digest = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    require(digest == proof["source"]["built_tree_sha256"] and len(hashes) == proof["source"]["built_files"]
        and sum(item["bytes"] for name, item in selected.items() if name.startswith(STATIC)) == proof["source"]["built_bytes"])
    require(proof["source"]["upstream"] == upstream["commit"] and proof["source"]["tree"] == upstream["tree"]
        and selected[UI_STAGE + "LICENSE"]["sha256"] == upstream["license_sha256"]
        and selected[WEATHER + "integrations/drizzli/upstream.patch"]["sha256"]
            == upstream["upstream_patch_sha256"] == proof["source"]["patch_sha256"]
        and selected[WEATHER + "integrations/drizzli/smoke_browser.py"]["sha256"] == proof["source"]["driver_sha256"])
    module_names = PROVEN_WEATHER_MODULES | (AQ_MODULES if version == 2 else set())
    weather_modules = proven_hashes(upstream["weather_modules"], module_names)
    require(weather_modules == proven_hashes(proof["source"]["weather_modules"], module_names))
    for module, expected_sha in weather_modules.items():
        digest = selected[WEATHER + module]["sha256"]
        require(digest == selected[UI_STAGE + "src/lib/services/volparossa/" + Path(module).name]["sha256"]
            == expected_sha)
    overlay = proof["source"]["overlay_sha256"]
    if version == 2:
        overlay = proven_hashes(overlay, OVERLAY_FILES)
    require(selected[UI_STAGE + "src/lib/services/volparossa/client.mjs"]["sha256"]
        == overlay["src/lib/services/volparossa/client.mjs"])
    bridge_names = PROVEN_BRIDGE_MODULES | ({"src/air-quality-core.mjs"} if version == 2 else set())
    for relative, digest in proven_hashes(proof["source"]["bridge_modules"], bridge_names).items():
        require(selected[WEATHER + relative]["sha256"] == digest)
    for relative, digest in proven_hashes(proof["source"]["browser_helpers"], PROVEN_BROWSER_HELPERS).items():
        require(selected[BROWSER + relative]["sha256"] == digest)
    metadata = small_json(stage / "volparossa-staging.json")
    runtime = proven_hashes(metadata["runtime_sha256"], PROVEN_RUNTIME_FILES)
    require(runtime == proven_hashes(proof["runtime"]["sha256"], PROVEN_RUNTIME_FILES)
        and metadata["defaults_sha256"] == selected[BROWSER + "defaults/privacy.json"]["sha256"]
        and metadata["autoconfig_sha256"] == selected[STAGE + "volparossa.cfg"]["sha256"])
    for relative, digest in runtime.items():
        require(selected[STAGE + relative]["sha256"] == digest)
    build = small_json(weather / "build/eccodes/build-receipt.json")
    require(build["compiled"] is True and build["embedded_definitions"] is True
        and build["required_environment"] == {} and build["source_pin_sha256"] == PIN_SHA
        and build["build_script_sha256"] == BUILD_SHA and build["original_sources_unchanged"] is True)
    require(type(build["artifacts"]) is list and 1 <= len(build["artifacts"]) <= 16)
    artifacts = {}
    for item in build["artifacts"]:
        require(type(item) is dict and set(item) == {"path", "bytes", "sha256"}
            and type(item["path"]) is str and len(item["path"]) <= 256 and item["path"] not in artifacts
            and type(item["bytes"]) is int and 0 < item["bytes"] <= MAX_FILE and hex64(item["sha256"]))
        artifacts[item["path"]] = item
    require(artifacts.get("build/eccodes/eccodes-build/bin/grib_ls")
        == dict(path="build/eccodes/eccodes-build/bin/grib_ls", bytes=31328216, sha256=DECODER_SHA))
    if version == 2:
        extended_source_proof(weather, selected, proof)


def extended_source_proof(weather, selected, proof):
    """Bind separate historical source/UI proofs, never infer joined delivery."""
    require(proof["phase"] == "complete" and proof["scenario"] == "precipitation"
        and proof["air_quality_scenario"] is True and proof["wrapper_outcome"] == "completed"
        and proof["scope"]["synthetic_air_quality"] is True
        and proof["scope"]["actual_drizzli_ui"] is True and proof["scope"]["actual_http_bridge"] is True
        and proof["scope"]["overlay_proven"] is False and proof["scope"]["upstream_origin_proven"] is False
        and proof["runtime"]["node_sha256"] == NODE_SHA)
    for group, names in (("cleanup", ("browser_exited", "fixture_exited", "private_profile_removed",
                                     "normal_browser_stop", "normal_fixture_stop")),
                         ("outer_cleanup", ("namespace_wrapper_exited", "private_profile_removed", "host_netns_unchanged"))):
        require(all(proof[group][name] is True for name in names))
    for name in ("precipitation_native_windows", "precipitation_missing_zero_small_amount", "precipitation_no_hourly_rate",
                 "air_quality_is_separate_product", "air_quality_native_times", "air_quality_missing_zero_concentrations",
                 "air_quality_not_aqi_or_observations", "actual_refresh", "no_external_resources",
                 "weather_failure_preserves_air_quality", "weather_expiry_preserves_air_quality",
                 "aq_unavailable_weather_preserved", "aq_stale_weather_preserved", "air_quality_expiry_preserves_weather"):
        require(proof["checks"][name] is True)
    for name in ("precipitation", "air_quality"):
        initial = proof["checks"][name + "_initial_dom_sha256"]
        require(hex64(initial) and initial == proof["checks"][name + "_refresh_dom_sha256"])
    for name in ("provider_requests", "air_quality_provider_requests"):
        require(type(proof["checks"][name]) is int and proof["checks"][name] == 11)
    for relative, digest in proven_hashes(proof["source"]["overlay_sha256"], OVERLAY_FILES).items():
        require(selected[WEATHER + "integrations/drizzli/overlay/" + relative]["sha256"]
            == selected[UI_STAGE + relative]["sha256"] == digest)
    for relative, digest in proven_hashes(proof["source"]["fixture_modules"], FIXTURE_MODULES).items():
        require(selected[WEATHER + relative]["sha256"] == digest)
    require(selected[WEATHER + "integrations/drizzli/browser-fixture.mjs"]["sha256"] == proof["source"]["fixture_sha256"]
        and selected[UI_STAGE + "LICENSE.VOLPAROSSA"]["sha256"] == selected[WEATHER + "LICENSE"]["sha256"])
    noaa = small_json(weather / "third_party/noaa-gefs-smoke.json")
    require(type(noaa["version"]) is int and noaa["version"] == 1
        and noaa["kind"] == "direct-noaa-native-particulate-forecast" and noaa["success"] is True
        and noaa["origin"] == "https://noaa-gefs-pds.s3.amazonaws.com"
        and noaa["node_sha256"] == NODE_SHA and noaa["decoder_sha256"] == DECODER_SHA
        and noaa["scope"]["actual_origin_acquisition"] is True
        and noaa["scope"]["actual_pinned_native_decoder"] is True
        and all(noaa["scope"][key] is False for key in ("core_executed", "overlay_proven", "browser_executed", "accuracy_proven")))
    for relative, digest in proven_hashes(noaa["source_modules"], NOAA_MODULES).items():
        require(selected[WEATHER + relative]["sha256"] == digest)
    ecmwf = small_json(weather / "third_party/ecmwf-precipitation-smoke.json")
    require(type(ecmwf["version"]) is int and ecmwf["version"] == 1
        and ecmwf["kind"] == "direct-ecmwf-native-precipitation-forecast" and ecmwf["success"] is True
        and ecmwf["source"] == "https://data.ecmwf.int/forecasts"
        and ecmwf["node_sha256"] == NODE_SHA and ecmwf["decoder_sha256"] == DECODER_SHA
        and ecmwf["native_accumulation_windows_preserved"] is True and ecmwf["hourly_rates_inferred"] is False
        and ecmwf["core_overlay_roundtrip_proven"] is False and ecmwf["browser_execution_proven"] is False)
    for relative, digest in proven_hashes(ecmwf["source_modules"], ECMWF_MODULES).items():
        require(selected[WEATHER + relative]["sha256"] == digest)


def capture(weather, ui, browser, stage, node, archive, version=1):
    require(type(version) is int and version in (1, 2))
    for root in (weather, ui, browser, stage):
        B["canonical"](root)
    inventory(stage, exact=RUNTIME_FILES)
    sources = {**{WEATHER + name: weather / name for name in (WEATHER_FILES if version == 1 else WEATHER_FILES_V2)},
        **{BROWSER + name: browser / name for name in BROWSER_FILES},
        **{STAGE + name: stage / name for name in RUNTIME_FILES},
        **{UI_STAGE + name: ui / name for name in (CLIENT_FILES if version == 1 else CLIENT_FILES_V2)},
        **{STATIC + name: path for name, path in inventory(ui / "build").items()},
        "runtime/node": node, "decoder/grib_ls": weather / "build/eccodes/eccodes-build/bin/grib_ls"}
    selected = {name: dict(**fingerprint(path, bound(name)), mode=mode(name)) for name, path in sorted(sources.items())}
    for name in EXECUTABLES:
        require(sources[name].stat().st_mode & 0o100)
    raw = encode(dict(version=version, kind=KIND, files=selected)); expected = hashlib.sha256(raw).hexdigest()
    manifest(raw, expected)
    source_proof(weather, browser, ui, stage, selected, version)
    new_path(archive)
    with os.fdopen(os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
        for name in ("INPUTS.json", *sorted(selected)):
            item = selected.get(name, dict(bytes=len(raw), mode=0o400, sha256=expected))
            output.write(header(name, item["bytes"], item["mode"]))
            source, before = (io.BytesIO(raw), None) if name == "INPUTS.json" else open_checked(sources[name], item["bytes"])
            with source:
                digest, remaining = hashlib.sha256(), item["bytes"]
                while remaining:
                    chunk = source.read(min(65536, remaining)); require(bool(chunk))
                    output.write(chunk); digest.update(chunk); remaining -= len(chunk)
                require(not source.read(1) and digest.hexdigest() == item["sha256"])
                if before is not None:
                    require(identity(os.fstat(source.fileno())) == identity(before))
            output.write(b"\0" * (-item["bytes"] % 512))
        output.write(b"\0" * 1024); output.flush(); os.fsync(output.fileno())
    return checked_archive(archive, expected)


def checked_archive(archive, expected, root=None, *, runtime=False, report_version=False):
    source, before = open_checked(archive, MAX_ARCHIVE)
    with source:
        require(before.st_size % 512 == 0)
        first = read_exact(source, 512)
        item = tarfile.TarInfo.frombuf(first, "utf-8", "strict")
        require(item.name == "INPUTS.json" and item.type == tarfile.REGTYPE and 0 < item.size <= MAX_MANIFEST
            and first == header("INPUTS.json", item.size, 0o400))
        raw = read_exact(source, item.size)
        require(read_exact(source, -item.size % 512) == b"\0" * (-item.size % 512))
        selected = manifest(raw, expected)
        # Both closed profiles have distinct joined-runtime dispatch. Preserve
        # this explicit gate when future archive-only profiles are introduced.
        require(not runtime or selected["version"] in (1, 2))
        if root is not None:
            new_path(root); root.mkdir(mode=0o700)
        for name, record in sorted(selected["files"].items()):
            require(read_exact(source, 512) == header(name, record["bytes"], record["mode"]))
            target = None
            try:
                if root is not None:
                    path = root / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    target = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")
                digest, remaining = hashlib.sha256(), record["bytes"]
                while remaining:
                    chunk = read_exact(source, min(65536, remaining)); digest.update(chunk); remaining -= len(chunk)
                    if target is not None: target.write(chunk)
                require(digest.hexdigest() == record["sha256"])
                require(read_exact(source, -record["bytes"] % 512) == b"\0" * (-record["bytes"] % 512))
                if target is not None:
                    target.flush(); os.fchmod(target.fileno(), record["mode"])
            finally:
                if target is not None: target.close()
        require(read_exact(source, 1024) == b"\0" * 1024 and not source.read(1))
        require(identity(os.fstat(source.fileno())) == identity(before))
        source.seek(0); archive_sha = hashlib.file_digest(source, "sha256").hexdigest()
        require(identity(os.fstat(source.fileno())) == identity(before))
    if root is not None:
        with os.fdopen(os.open(root / "INPUTS.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400), "wb") as output:
            output.write(raw)
        for directory in sorted([root, *(p for p in root.rglob("*") if p.is_dir())], key=lambda p: len(p.parts), reverse=True):
            directory.chmod(0o500)
    return dict(manifest_sha256=expected, archive_sha256=archive_sha, files=len(selected["files"]),
        bytes=sum(item["bytes"] for item in selected["files"].values()),
        **({"bundle_version": selected["version"]} if report_version else {}))


def verify_tree(root, expected):
    source, info = open_checked(root / "INPUTS.json", MAX_MANIFEST, normalized=0o400)
    with source:
        raw = source.read(MAX_MANIFEST + 1); require(identity(os.fstat(source.fileno())) == identity(info))
    selected = manifest(raw, expected)
    inventory(root, exact=set(selected["files"]) | {"INPUTS.json"}, normalized=True)
    for name, item in selected["files"].items():
        require(fingerprint(root / name, item["bytes"], normalized=item["mode"])
            == {key: item[key] for key in ("bytes", "sha256")})
    return dict(manifest_sha256=expected, files=len(selected["files"]), runtime_executed=False)


def main():
    action, *args = sys.argv[1:]
    if action in ("capture", "capture-v2") and len(args) == 6:
        result = capture(*map(Path, args), version=2 if action == "capture-v2" else 1)
    elif action == "verify-runtime" and len(args) == 2:
        result = checked_archive(Path(args[0]), args[1], runtime=True)
    elif action == "runtime-version" and len(args) == 2:
        # Dispatch only after checking every member and the complete archive.
        # Identifying a valid input profile does not authorize its execution.
        result = checked_archive(Path(args[0]), args[1], report_version=True)
    elif action == "unpack" and len(args) == 3:
        result = checked_archive(Path(args[0]), args[2], Path(args[1]))
    elif action in ("verify", "verify-tree") and len(args) == 2:
        result = (checked_archive if action == "verify" else verify_tree)(Path(args[0]), args[1])
    else:
        raise ValueError("weather_client_bundle_rejected")
    print(json.dumps(dict(version=1, action=action, **(result | {"runtime_executed": False})), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, tarfile.TarError, UnicodeError):
        print('{"runtime_executed":false,"failure":"weather_client_bundle_rejected"}')
        raise SystemExit(1)
