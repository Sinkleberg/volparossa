# Weather Demo 0 — effort and recorded consumption

Model usage and hosted machine time are separate measurements. Neither is a
subscription invoice, a quota conversion or a prediction of future cost.

## Scope of the measurement

`scripts/weather-demo-0-usage.py` projects recorded cumulative-counter deltas for
implementation root turn `01a165a6-a9c8-7b03-9913-a9cadefe5401`. It excludes the
earlier readiness-audit turns, counts repeated snapshots as zero and reports
uncached input as total input minus cached input. Reasoning output is already a
subset of output; adding it again would double-count tokens. Unlisted sessions,
missing records and work after the snapshot are explicitly unmeasured.

The selected thread responsibilities are:

| Thread suffix | Actual work | Recorded model / effort |
| --- | --- | --- |
| `4131036e94d9` | Coordination, integration, evidence and presentation | Sol High |
| `0f3e43fc2e9e` | Recording implementation and media correction | Sol High |
| `84b14a5aa9bf` | Artifact inventory and CI monitoring | Luna Medium |
| `794ca99cb7c2` | Deterministic source bundles and retained-media review wrapper | Sol Medium |
| `f7b3f25f485d` | Independent technical review | Sol High |

The recording implementer's installed role is named `volparossa_reviewer`; that
metadata label does not turn its implementation work into independent review.
The separate reviewer thread supplies that independence. This implementation
thread records Sol High as its coordinating model; it does not claim Astra
execution. The separate active Astra goal and its worktrees remain untouched.
No architectural redesign was required for this milestone.

## Necessary correction and infrastructure retry

- Full run `39864237681` passed original delivery and cleanup, then failed the
  additional media gate. Its exact closed reports are retained under `trials/`.
- Synthetic tool probe `39869565948` demonstrated one concrete incompatibility:
  Ubuntu ffprobe emits an empty `programs` list. The original parser rejected it.
  That observation alone did not prove the absence of other media failures.
- The narrow correction admits only the observed empty container. Negative
  controls remain, and independent review reran all 22 focused media tests.
- Synthetic probe `39870350875` then verified both corrected parsing and actual
  120-second rendering with the distro tools. Its synthetic input was deleted;
  it is not app, peer or cleanup evidence.
- Run `39870500157`, attempt 1, timed out while downloading Ubuntu packages,
  before building or executing Android. Attempt 2 uses the identical source
  revision on a fresh disposable runner. No runtime limit or acceptance guard
  was relaxed to accommodate that infrastructure failure.

- The second full delivery trial also passed original delivery/cleanup but rejected
  three MP4 streams. AOSP and FFmpeg source analysis identified the specific
  video-plus-two-timing-tracks container profile to test before another trial.
- Dedicated capture quarantine now preserves source/window/report hashes and
  unreviewed media before strict admission, without changing a failed result.
- Synthetic review probe `39874201029` exposed a font-data guard mismatch;
  `39874591752` stopped on slow mirror downloads. Probe `39875572392` passed
  parser, rendering and contact sheets after the documented corrections.

Completed CI wall time, final model-counter snapshots and the genuine-media
review outcome must be added after the corresponding execution finishes.
Building, downloading and waiting consume hosted machine time; the model tokens
used to inspect those events belong to their actual thread counters.

## Interpretation and uncertainty

The readiness estimate was a planning range, not a token budget or commitment.
Repeated long-context monitoring and review can make cached input much larger
than the uncached implementation input. A failed expensive runtime trial also
adds CI time even when the code correction is small. Report these effects rather
than attributing every token to feature implementation or hiding rework.

Further reproduction effort depends on archive retention, current source-data
compatibility and runner availability. Existing runtime acceptance must not be
replaced by cheap synthetic probes. Future mobile packaging, device support and
an on-device Core remain separate engineering work.
