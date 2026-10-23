# VOLPAROSSA Weather Demo 0

An installed Overmorrow Android application retrieves real forecast products
through VOLPAROSSA Core and cooperating peers. **Core runs outside the Android
emulator, in the disposable Debian 13 topology.** This is a developer demonstration,
not a standalone mobile release or a production VPN distribution.

The full [VOLPAROSSA goal](https://github.com/VOLPAROSSA/volparossa/blob/main/docs/development/GOAL.md),
including DPS and Studio, remains unchanged. These historical-baseline demo branches
must not be merged wholesale into current main: current Storage, Compute, DPS,
Studio, helper and application work remains independently owned.

## What is being reproduced

Original successful [run 38717988016](https://github.com/VOLPAROSSA/volparossa/actions/runs/38717988016):

| Input | Original revision |
| --- | --- |
| Core | `aac5be7f602fae9754153cdcb5c401ecb9ee7cb6` |
| Weather | `3b90442a9d5be4db73ccf83cba2028364980c3ca` |
| Overmorrow | `97995e2e00e454389e00e35f1e65654afe3e8bed` |
| Flutter | 3.38.5, `f6ff1529fd6d8af5f706051d9251ac9231c83407` |

The recording extension is a separately recorded derivative of these sources.
It does not replace the original result. New live acquisitions necessarily have
different runs, validity windows, bytes and hashes; historical byte counts are
never used as the expected current forecast. The v6 product contracts, explicit
publisher authority, receipt/HTTP/app-table joins and cleanup remain required.

The original run proved cold peer delivery, two cache-backed refreshes per
product, actual Android taps and background/resume. It did **not** establish
visible pixels, real-product expiry recovery, physical-device/iOS support,
concurrent bulk use of multiple subflows, forecast accuracy or production authority.
New media must be admitted against the new run's own final acceptance.

## Reproduce on a disposable hosted runner

Requirements: repository Actions execution rights, the exact pushed demo source,
public availability of the pinned upstream archives, and an ordinary GitHub-hosted
Ubuntu 24.04 runner with KVM, sufficient RAM and at least 32 GiB free space.
The existing workflow owns its Debian guest, emulator, temporary AppArmor policy,
temporary runner-private KVM ACL and cleanup. Do not run it on a development host,
relax its resource checks, or replace KVM with unverified emulation.

1. Inspect the candidate commit and the workflow's fixed Weather revision.
   Inspect any existing run for that exact source before dispatching another.
2. Dispatch the existing workflow with recording explicitly enabled:

   ```sh
   gh workflow run weather-android-delivery.yml \
     --repo VOLPAROSSA/volparossa --ref demo/weather-0-20261023 \
     -f record_demo=true
   ```

3. Record the returned run ID and candidate commit. Check its existing status
   occasionally; a terminated watcher is not grounds to rerun the trial.
4. Require the original hosted acceptance plus the separate same-run media
   acceptance. A recording alone is not a passed delivery trial.
5. Inspect the actual screenshots and recording. Reject blank, illegible,
   obscured or unrelated frames. Generic timed screenshots are not automatically
   initial/refresh/resume observations.
6. Review the assembled video, captions, transcript, provenance and limitations.
   Retain the original recording separately from any edited presentation.

The workflow performs network/toolchain builds only inside the approved disposable
hosted environment. It installs nothing on the contributor's workstation.
Source/data acquisition is separate from the overlay retrieval measurement.
Refresh reuses a still-valid product; it does not imply a new forecast acquisition.

The optional recorder has a 180-second ceiling and starts before the unchanged
driver. Its conservative media-duration check can reject an otherwise valid
near-deadline driver run. This stricter demo admission does not extend or relax
the original driver budgets; its original report and failure evidence are retained.
Readable initial, refresh and resume scenes still require inspection of actual pixels.

The dedicated `weather-demo-capture-quarantine-*` Actions artifact retains the
original recording and its source/window/report hashes after the original
delivery and cleanup pass, before strict media admission. It is **unreviewed
capture evidence**, with no media acceptance or release authority. Its existence
does not make a failed demo successful. Accepted media and presentation artifacts
remain separate and require the strict checks. Do not publish quarantine files
as release assets without the missing admission and visual review.

The AOSP recorder implementation writes one H.264 video track and two Winscope
timing metadata tracks in MP4. This explains the observed count of three in the
pinned Android API 36 trial; the actual type/tag profile still requires admission.
These timing tracks are not additional pictures or audio. The
format-specific validator checks the expected track tags and still rejects other
streams; the edited presentation selects video only. The source behavior is
documented in [AOSP screenrecord](https://android.googlesource.com/platform/frameworks/av/+/297eaacfa6/cmds/screenrecord/screenrecord.cpp).
Synthetic container probes exercise the media tools, not app or network behavior.

## Data, compatibility and retention

Weather remains IFS `0p25` temperature, wind and precipitation forecasts plus
separate NOAA GEFS-Aerosols PM2.5/PM10 forecasts for an explicit public community
area. These are forecasts, not current observations or a complete AQI service.
Missing capabilities remain unavailable and native valid times/windows remain
distinct. No private location, location search or geolocation permission is needed.

[ECMWF's current catalogue](https://www.ecmwf.int/en/forecasts/datasets/open-data)
reports field-specific GRIB packing changes from 20 October 2026 and a new 0.1-degree
product. This demo retains `0p25`; it does not silently adopt the new resolution.
Successful new native decoding and original field-identity checks, not a catalogue
claim, determine compatibility with current input bytes. Failed acquisition or
decoding must remain a failed run; do not substitute synthetic products.

The unchanged v6 input manifest identifies decoder artifact `11731895956`
(Weather run `38214736539`) and ABI artifact `11732188075` (Core run `38216142236`).
Their original archives expire on 26 October 2026. The original Android acceptance
artifact `11966068479` expires on 29 October. A missing archive is an explicit
reproduction blocker, not permission to repin an arbitrary binary. Use reviewed
source builds and a newly recorded admission if inputs must be renewed.

## Acceptance and publication

- Original guards, negative controls, source verification and deadlines remain in force.
- Real peer retrieval, authenticated publication content, no unclaimed origin
  fallback, warm-cache reuse and exact app-table correspondence must pass.
- The actual emulator pixels and interactions must be recorded within that run.
- App/forward/process/VM/policy cleanup and exact KVM ACL restoration must pass.
- Sources, dependencies, original reports, media hashes and edits must be inspectable.
- The external-Core boundary remains visible throughout the presentation.
- No APK, SDK, emulator userdata, private keys, packet captures or private logs enter
  the public presentation bundle.

The proposed prerelease is `weather-demo-0.1.0`. Prepare materials locally and as
scoped Actions evidence; **do not create/publish a GitHub release, upload public
release assets or communicate results externally without the user's explicit
publication approval.** Include installable binaries only after their exact
installation/runtime acceptance, outside this source-and-evidence demo scope.

See [release notes](release-notes.md), [storyboard](storyboard.md), and
[licenses and attribution](NOTICES.md). Pending execution or review remains pending.
