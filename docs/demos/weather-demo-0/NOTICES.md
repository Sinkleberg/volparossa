# Source, license and data attribution

Preserve original license text and per-component notices. This summary does not
replace them or establish final binary-distribution compliance.

| Component | Source and retained terms |
| --- | --- |
| VOLPAROSSA Core and original integration code | Original repository `LICENSE`, GPL-3.0-only; retain `THIRD_PARTY_LICENSES.md` and component notices. |
| Overmorrow | `https://github.com/bmaroti9/Overmorrow`, revision `97995e2e00e454389e00e35f1e65654afe3e8bed`; retain upstream GPL-3.0-or-later license and attribution. |
| Flutter and dependencies | Pinned Weather SDK/dependency manifests; retain upstream licenses and Flutter-generated application notices. Do not redistribute SDK or pub caches as demo assets. |
| Native decoder | Exact admitted ecCodes/ecbuild/libaec source records and notices in the v6 decoder input; retain its licenses unchanged. |
| MPQUIC | Core native source provenance, exact upstream revision, local patches and notices; do not substitute unchecked binaries. |
| Presentation tools | Executed FFmpeg/ffprobe version and actual DejaVu font-file SHA-256 are recorded in the [development provenance](../../../THIRD_PARTY_LICENSES.md#demo-media-analysis-and-presentation-tools). The font package version was not captured. These signed Ubuntu runner tools are not product runtime dependencies or released binaries. |

Data adapted from ECMWF IFS forecast data, licensed under
[CC BY 4.0 and ECMWF Terms of Use](https://www.ecmwf.int/en/forecasts/datasets/open-data).
Preserve the exact acquisition's source attribution, forecast-run identity,
time/units and transformations. VOLPAROSSA is not an official ECMWF product.

Particulate forecasts originate from NOAA GEFS-Aerosols via the official anonymous
public-data mirror. Preserve NOAA attribution and source references in Weather's
`third_party/noaa-gefs.json`. Do not imply NOAA/NWS endorsement or present modified
material as official government material; see
[NOAA/NWS use terms](https://www.weather.gov/disclaimer/).

Release source archives must correspond to the exact accepted Core/Weather
revisions and retain the scripts, patches and manifests needed to reproduce the
demo. Do not package only generated assets while omitting their covered sources.
Demo media includes only the deliberately public community-area application;
private configurations, keys, full host logs, packet captures and emulator
userdata are excluded.
