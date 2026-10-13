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
used. This is not yet a production dependency or an attestation backend.

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
to a proposed session key. [Core trial 38432553365](https://github.com/VOLPAROSSA/volparossa/actions/runs/38432553365)
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
