# Protected compute: public verifier fixtures

The four public cryptographic fixtures pass. This is a preparatory compatibility
test, **not protected remote execution**.
The core must eventually verify another node's execution environment before
releasing private task context. No suitable confidential-computing server is
currently available for that end-to-end test. The existing local private service
and public peer-task admission remain unchanged.

## What this trial checks

The [hosted workflow](../../.github/workflows/protected-compute-verifier.yml)
builds the upstream Rust `virtee/sev` library at exact commit
`a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5`, using Rust 1.85.0 and the
explicit lockfile correction below. It enables only `snp,crypto_nossl`, with
default features disabled.
The selected upstream test target executes four public Milan fixtures:

- Verify the supplied AMD SNP certificate chain.
- Reject a tampered chain.
- Verify the supplied signed attestation report.
- Reject a tampered report.

These are upstream public samples, not newly generated hardware reports or
VOLPAROSSA users' data. No `/dev/sev` device, private model, task input or secret is
used. This standalone upstream trial supplies no production admission backend;
the separately tested core integration is described below.

The [pinset](../../tests/integration/protected-compute-verifier-pins.json)
records the exact source tree, nine original file hashes, and the corrected
lockfile identity. The trial requires pristine upstream before applying the
correction. Subsequent checks accept only that exact unstaged lockfile change,
verify the original `HEAD:Cargo.lock` separately, and reject other tracked,
staged, untracked or ignored files and mode changes. Dependency acquisition
is separate from offline Cargo execution;
`--offline` is not an operating-system network sandbox.

## Exact lockfile correction

The pinned upstream [lockfile](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/Cargo.lock#L965)
contains one dangling dependency reference: `num-bigint-dig 0.8.6` still names
`rand 0.8.5`, although the [same commit](https://github.com/virtee/sev/commit/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5)
replaces that package with `rand 0.8.8`. The fixture changes only that reference
to the already pinned `0.8.8`; it changes no package version, checksum, manifest,
source or test. Cargo never regenerates the lockfile, and both acquisition and
test commands retain `--locked`.

Both original and effective files contain 66,223 bytes. Their SHA-256 values are:

- Upstream: `fe1511ef932c1a54d0cd70ac470b41de8357ab2efca9ed6b3a4ea22c3b7d3bd0`.
- Effective: `7b7dbf853cecf44a8d2a6b51283012b446db97600f4e19af36a1c642b8bfa7cb`.

The schema-two pinset and result receipt distinguish these identities and name
the exact one-occurrence correction. The immutable Git commit and tree continue
to identify upstream, not an unmodified effective checkout. Preparation writes
no success receipt and cannot substitute for cryptographic tests.

## Evidence and limits

Only a zero-exit run with all four named tests executed and passed can produce a
success receipt. Missing, ignored, duplicate or extra test lines are rejected.
The original bounded log, both pipeline exit statuses and compiler-version
outputs are retained separately. Log overflow fails the trial; an earlier
success receipt cannot be overwritten by a new execution.

[Hosted run 38324431627](https://github.com/VOLPAROSSA/volparossa/actions/runs/38324431627)
at exact core revision `5c4ecba25700ef75dacbddae920c8c819a496ef4` passes
source verification, locked acquisition, offline compilation and all four named
fixtures. None are failed, ignored or filtered; both pipeline exit codes are
zero. Its original six-file artifact and schema-two receipt have been
independently validated against the source and effective-lock pins. Compilation
took 12.99 seconds and the four tests took 0.21 seconds on that hosted runner;
these are not remote-task performance measurements.

Twenty-two inert harness tests also pass locally and on that runner. They use
synthetic output, small text-only Git repositories and harmless shell functions;
they do not substitute for the four actual cryptographic tests. Earlier failed
workspace, context and original-lock attempts remain recorded in the
[implementation ledger](../IMPLEMENTATION_STATUS.md#protected-compute-verifier-preparation).

This passing run establishes compatibility with the selected public fixtures,
not a trustworthy worker or confidential task.

## Core integration

The separate [core module](../../crates/volparossa-content/src/provider/compute/attestation.rs)
verifies exact received report bytes and binds a fresh, finite owner challenge
to a proposed session key. [Core trial 38439280941](https://github.com/VOLPAROSSA/volparossa/actions/runs/38439280941)
passes fourteen tests and targeted Clippy. The tests combine real public
signature fixtures with explicitly synthetic session-state checks; they do
not prove a guest possesses the proposed key or can execute a private task.

The workspace adopts that trial's exact resolved lockfile. The current
[core workflow](../../.github/workflows/protected-compute-admission.yml) fetches
with `--locked`, requires the committed source and lockfile to remain unchanged,
then checks actual resolved features and runs tests offline. Schema-two core
receipts distinguish this fixed-lock verification from historical schema-one
dependency resolution. Broader workspace integration remains a separate gate.

The public-key-only use of the RSA dependency has an explicit, mechanically
checked [advisory scope](../../THIRD_PARTY_LICENSES.md#rsa-advisory-scope);
it is not treated as a patched general-purpose private-key implementation.

## Binding endorsement claims to the report

The integrated core checks the signed VCEK's product, chip identifier and
firmware-version extensions against the exact report before returning signature
facts. It compares each component of `REPORTED_TCB`, not the current, committed
or launch TCB. The existing certificate-size bound, pinned reference chain and
cryptographic verification remain unchanged.

The parser follows [AMD KDS specification 57230 revision 1.05, section 3.1](https://docs.amd.com/api/khub/documents/U5H~LHvkigTowyppBkpyrA/content):
canonical integers and IA5 product text, a raw 64-byte hardware identifier, zero
reserved components, and the documented component ranges. The
supported leaf profile is intentionally narrower: exactly eleven known,
noncritical AMD extensions. Additional extensions and other report/product
profiles need separate review. A version-two report cannot establish a CPUID
stepping comparison.

Eight additional tests cover valid public evidence, incomplete/duplicate
extensions, encoding and range errors, identity/component mismatches and refusal
to bypass actual signatures. Synthetic certificate edits test consistency only,
not authentication. [Trial 38455979301](https://github.com/VOLPAROSSA/volparossa/actions/runs/38455979301)
on `2ebf27af` passes all 22 named Rust tests and targeted Clippy with the committed
lockfile unchanged. Quality and CodeQL also pass; PR238 is merged. Schema-three
receipts identify that set separately from the earlier 14-test schemas. All five
remaining appraisal obligations stay explicit; this check supplies neither
private-input release nor worker admission.

## Checking certificate algorithm declarations

The integrated verifier checks the fixed Milan chain's algorithm declarations after
actual cryptographic verification and before returning signature facts. Both
signature identifiers must agree and name the supported PSS profile: SHA-384,
MGF1/SHA-384, a 48-byte salt and trailer 1. The VCEK must declare a P-384 EC key
with a byte-aligned, uncompressed point. Existing cryptographic verification,
not a point-shape check, establishes the valid public key and signatures.

This follows [AMD 57230 revision 1.05, tables 7–9](https://docs.amd.com/api/khub/documents/U5H~LHvkigTowyppBkpyrA/content),
[RFC 5280's signature-identifier agreement](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2),
[RFC 4055's hash and PSS parameters](https://datatracker.ietf.org/doc/html/rfc4055#section-3)
and [RFC 5480's EC key identifiers](https://datatracker.ietf.org/doc/html/rfc5480#section-2).
Absent and NULL SHA-384 parameters are supported. Trailer 1 may be omitted or
explicit, as in the public AMD fixture; other values are rejected. Unknown,
duplicate, reordered, implicit or trailing fields do not extend this profile.

Six new tests join the existing 22. Five real API-negative cases retain the
original signed certificate bytes and signature while changing its outer
algorithm declaration. Separate synthetic structures exercise malformed
parameters and key encodings; these edited certificates authenticate nothing.
Schema-four receipts require exactly 28 named tests and preserve explicit replay
of schemas one through three. The 51 inert harness checks and ten public-RSA
scope checks pass. [Trial 38466325432](https://github.com/VOLPAROSSA/volparossa/actions/runs/38466325432)
on `bb8d49c0` compiles and passes all 28 actual Rust tests with zero failed or
ignored, but fails targeted Clippy on three similar-name warnings, duplicate
match arms and a missing statement semicolon. Its schema-four report correctly
remains failed. The correction changes names and equivalent statement style,
not profile checks or test cases. The original 15-file artifact matches SHA-256
`4a8d1b218b1a2dc0fdd5b04d4c138d40a40994b155a3cf0c473fb0aa15b8c350`.

[Trial 38467309647](https://github.com/VOLPAROSSA/volparossa/actions/runs/38467309647)
on corrected candidate `530d3c81` passes all 28 named Rust tests and targeted
Clippy. Its original 15-file artifact matches SHA-256
`971fd9f8a12979fa42ac02df48e8391189e1b22fc0c5eab6d0398749fc9431e0`;
the committed, original and effective lockfiles are byte-identical. CodeQL
`38467310454` passes all four analyses and its separate aggregate check. Quality
`38467316376` passes strict workspace Clippy and 3,595 workspace tests, with zero
failures and seven ignored tests, plus six successful child invocations. The
tested merge tree is identical to the candidate; all 28 attestation tests pass.
PR240 is merged. The internally skipped namespace probes do not prove live
datapaths.
No dependencies, features, lockfile, appraisal obligations or execution
permissions change. This is not complete certificate-path validation.

## What is still needed before private tasks can run remotely

Certificate and report signatures are necessary but insufficient. A complete
worker-admission path still needs:

- Independently authorized trust roots, certificate and revocation handling,
  approved guest measurements, security-version requirements and debug policy.
- A fresh client challenge bound to the approved guest's session key and the
  particular task, with replay rejection and finite execution authority.
- Verification of the exact received report format and signed bytes. The guest
  must also verify authorized model/runtime assets before using task keys.
- Protected input, execution and output, plus cancellation, resource limits and
  cleanup under the same core-managed task lifecycle.
- An actual two-node trial on suitable confidential-computing hardware,
  including failed attestation and refusal to release private input.

The fixture's supplied self-signed root is not independently granted production
authority. Its signature checks alone do not establish certificate validity,
current revocation status, an approved workload or freshness. Those checks must
not be replaced by a peer signature, encrypted transport or agent approval.

Source references: [upstream fixture tests](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/tests/certs.rs),
[chain verification](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/src/certs/snp/chain.rs)
and [crate configuration](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/Cargo.toml).
See [third-party provenance](../../THIRD_PARTY_LICENSES.md#public-snp-verifier-fixture-trial)
and the [implementation ledger](../IMPLEMENTATION_STATUS.md#protected-compute-verifier-preparation).
