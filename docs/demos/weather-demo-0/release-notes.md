# VOLPAROSSA Weather Demo 0 — release draft

Proposed prerelease: `weather-demo-0.1.0`. Publication requires explicit approval.
This document is a draft, not evidence that a new run or a release succeeded.

Overmorrow's installed Android interface consumes real weather and particulate
forecast products through the shared VOLPAROSSA Core/provider integration.
Core operates **externally to the Android emulator**, in an isolated Debian 13
test topology. The demonstration follows cold peer retrieval, cache-backed refresh
and real Android background/resume, with same-run source and cleanup evidence.

## Release gate

Only replace the pending results after inspecting the original new-run artifacts.

| Required result | State |
| --- | --- |
| Exact demo Core and Weather revisions | Pending candidate commit |
| Successful real delivery and joined cleanup | Pending new execution |
| Actual app recording and readable screenshots | Pending visual review |
| Recording/acceptance/source hash binding | Pending new execution |
| Approximately two-minute edited video and accessible captions | Pending assembly/review |
| Source bundles, manifests and notices | Pending final exact revisions |
| User publication approval | Not granted |

The historical reference remains [38717988016](https://github.com/VOLPAROSSA/volparossa/actions/runs/38717988016),
Core `aac5be7f602fae9754153cdcb5c401ecb9ee7cb6` and Weather
`3b90442a9d5be4db73ccf83cba2028364980c3ca`. Its success does not qualify new sources.

## Intended assets

- `weather-demo-0.mp4`, original `screen.mp4`, and genuine sampled PNG screenshots.
- `captions.vtt` and `transcript.txt`; captions identify held frames/editing.
- Original final delivery/media acceptance and hash-bound provenance.
- `SHA256SUMS`, build/input manifests and exact Core/Weather source archives.
- Reproduction instructions and retained license/data attribution notices.

These assets must be generated from a passed run, not manufactured to fill this list.

## Limitations

Developer demonstration only. No standalone mobile Core, physical-phone/iOS
acceptance, production release authority, guaranteed forecast accuracy, complete
Weather service, proven real expired-product recovery or demonstrated concurrent
bulk multipath is claimed. Source acquisition happens separately from measured
peer retrieval. A signed publisher authenticates its publication, not an ECMWF
or NOAA endorsement. Cache refresh may reuse the same valid forecast.

No installable binary is included by default. Existing debug APKs and toolchain
artifacts are test inputs, not supported end-user distributions.
