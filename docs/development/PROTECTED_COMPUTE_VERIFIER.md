# Protected compute: public verifier fixtures

This is a preparatory compatibility test, **not protected remote execution**.
The core must eventually verify another node's execution environment before
releasing private task context. No suitable confidential-computing server is
currently available for that end-to-end test. The existing local private service
and public peer-task admission remain unchanged.

## What this trial checks

The [hosted workflow](../../.github/workflows/protected-compute-verifier.yml)
builds the upstream Rust `virtee/sev` library at exact commit
`a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5`, using its original lockfile and
Rust 1.85.0. It enables only `snp,crypto_nossl`, with default features disabled.
The selected upstream test target executes four public Milan fixtures:

- Verify the supplied AMD SNP certificate chain.
- Reject a tampered chain.
- Verify the supplied signed attestation report.
- Reject a tampered report.

These are upstream public samples, not newly generated hardware reports or
VOLPAROSSA users' data. No `/dev/sev` device, private model, task input or secret is
used. This is not yet a production dependency or an attestation backend.

The [pinset](../../tests/integration/protected-compute-verifier-pins.json)
records the exact source tree and nine source, lock, license and fixture hashes.
The trial verifies source identity before dependency acquisition and after test
execution. Dependency acquisition is separate from offline Cargo execution;
`--offline` is not an operating-system network sandbox.

## Evidence and limits

Only a zero-exit run with all four named tests executed and passed can produce a
success receipt. Missing, ignored, duplicate or extra test lines are rejected.
The original bounded log, both pipeline exit statuses and compiler-version
outputs are retained separately. Log overflow fails the trial; an earlier
success receipt cannot be overwritten by a new execution.

At introduction, the fourteen inert harness tests pass locally. They use
synthetic output and harmless shell functions, not a native build or hardware.
The [first hosted attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/38321426228)
at `65decfc3` passes those tests, compiler installation and exact source/fixture
verification, then fails dependency acquisition: Cargo treats the nested checkout
as an undeclared member of the core workspace. Compilation is not reached.
The correction checks out upstream in the disposable runner's separate temporary
directory, without changing either manifest or the pinned lockfile. Fifteen inert
tests now pass. The actual upstream build and cryptographic fixture result remain
pending. Passing would establish only compatibility with these public fixtures,
not a trustworthy worker or confidential task.

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
