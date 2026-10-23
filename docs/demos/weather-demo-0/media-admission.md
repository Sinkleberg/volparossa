# Weather Demo 0: scoped media admission

The original run [39998753810, attempt 1](https://github.com/VOLPAROSSA/volparossa/actions/runs/39998753810)
remains **failed**. Its original application/product/delivery/cleanup acceptance
passed; its additional media-duration gate rejected the recording. Neither that
result nor the quarantined capture manifest is rewritten.

The rejected comparison treated host recorder-launch time and the driver's
post-interaction end as if they bounded the encoded guest-video timeline.
Host/guest clocks were not calibrated. The clip's 65.579-second container duration
therefore cannot establish complete coverage of the 67.695-second host interval.
An encoder-startup explanation is unproven. Extending a tolerance would not
resolve this mismatch.

For this first developer demonstration, a separate contract instead requires:

1. The unchanged original four-report application, product, peer/cache and cleanup
   chain passes, with exact run/source identities and report hashes.
2. The original quarantine archive and every retained capture file match their
   GitHub artifact digest and capture manifest. The clip remains unchanged.
3. Native decoded frames and video packet timing agree with both Android
   Winscope metadata tracks. Actual MP4 track IDs/sample tables bind the metadata
   payloads and offsets; no magic-byte search is used. FFmpeg intentionally
   discards DATA tracks whose STTS sample durations are all zero. Its reported
   metadata packet count is therefore zero for this recording; a bounded raw
   sample-table parser establishes exact ownership independently. Any native
   metadata packets, if exposed, must agree with those resolved samples. Integer time bases determine quantization bounds.
   Audio, unexpected tracks, malformed metadata, inconsistent counts/order or
   timing are rejected. This proves source-media coherence, not wall-clock coverage.
4. A committed human/model visual-review record binds the real source video,
   exact native frame indices, presentation timestamps and PNG hashes. It covers
   readable temperature, PM2.5, source/validity, first-refresh completion, HOME and
   the application's return animation. An independent Sol High review and Astra
   Ultra scope decision inspected actual pixels rather than only report flags.
5. The presentation retains the entire original clip at normal speed. A selected
   genuine frame may then be held for readability, with a visible hold label and
   its source-frame identity recorded. Network/cache counters are explicitly a
   completed-run summary, never live measurements inferred from pictures.

The result is a **new, narrowly scoped admission**, not a retroactive successful
workflow conclusion, a relaxation of network requirements or a production release.
`scoped-admission.json` must identify the old failure, unchanged source recording,
quarantine artifact, committed visual review, timing report and new verifier run.
The original `review.json` remains an inspection report with media acceptance false.
No new Android/Core execution occurs during this separate admission.

The viewport does not show every wind, precipitation or PM10 column. The final
return is an animation with a spinner; no settled post-resume frame or visibly
completed second refresh is claimed. The original run's closed acceptance supplies
the two cache-backed refreshes and successful background/resume findings. Pixel
review alone supplies none of the network, content-authentication or cleanup proof.

The exact source-bound scene witnesses are in
[visual-review-39998753810.json](visual-review-39998753810.json). Their timestamps
are video PTS, not Android input-event times. The complete old failure and original
reports are under [trials/39998753810](trials/39998753810/).
