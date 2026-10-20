# Contributing to VOLPAROSSA

VOLPAROSSA welcomes documentation improvements, reproducible bug reports and complete,
reviewable feature slices. The current priority is a functional development alpha, not
release polish. Start with the [documentation guide](docs/README.md), then read
[AGENTS.md](AGENTS.md), the [architecture](docs/architecture/ARCHITECTURE.md) and the relevant section of
[implementation status](docs/IMPLEMENTATION_STATUS.md) before changing code.

This core-specific workflow complements the organization-wide
[contribution guide](https://github.com/VOLPAROSSA/.github/blob/main/CONTRIBUTING.md),
[Code of Conduct](https://github.com/VOLPAROSSA/.github/blob/main/CODE_OF_CONDUCT.md),
[support guide](https://github.com/VOLPAROSSA/.github/blob/main/SUPPORT.md) and
[accessibility guide](https://github.com/VOLPAROSSA/.github/blob/main/ACCESSIBILITY.md).
Use [central Discussions](https://github.com/VOLPAROSSA/volparossa/discussions) for general
or cross-project questions, and core [issues](https://github.com/VOLPAROSSA/volparossa/issues)
for actionable bugs and scoped work. Follow [SECURITY.md](SECURITY.md) for vulnerabilities.

## First core contribution

1. Choose a small documentation improvement or a reproducible task with a clear outcome.
   Check the [current status](docs/IMPLEMENTATION_STATUS.md#current-integration-and-active-work)
   so you do not mistake a failed trial or an unmerged branch for accepted behavior.
2. Before building, use the [read-only prerequisite check](docs/development/OPERATIONS.md#read-only-prerequisites):
   `./scripts/check-system.sh`. It inspects the environment without installing packages,
   creating network fixtures or changing the host configuration.
3. Follow the existing [build instructions](docs/development/OPERATIONS.md#build-and-package)
   and select a [focused test](docs/development/TESTING.md#unprivileged-quality-gate) that
   matches the change. A documentation-only change needs link and claim checks, not a fresh
   runtime trial. Package installation is a separate, explicit step in the operations guide.
4. Keep any privileged networking work in the documented disposable namespace or VM
   topology. Do not test on your active host network. In the pull request, state the exact
   checks run and leave unverified behavior clearly marked.

## Ground rules

- Preserve `client -> exactly one relay -> exit` on every path. Different parallel paths require
  different relays and the same exit.
- Do not label ordinary TCP as MPTCP or single-path QUIC as Multipath QUIC.
- Keep the agent unprivileged and the helper request schema typed, bounded, and free of arbitrary
  commands, paths, interface names, sysctls, and firewall text.
- Reject ambiguous, expired, replayed, unsupported, oversized, or policy-inconsistent input.
- Never add production private keys, accounts, analytics, remote telemetry or hidden update channels.
  The explicit authorized-update design is separate: only independently authorized releases,
  verified against established trust and without expanded installation privileges, may become
  client updates. Peer content and model output are not update authority. See
  [repository maintenance](docs/services/REPOSITORY_MAINTENANCE.md); this is not permission to install
  anything on a contributor's host.
- Do not add production logging or persistence of URLs, DNS history, payloads, full browsing
  hostnames, destination-IP history, or durable node-to-browsing links.
- Do not modify a development host's routes, DNS, firewall, interfaces, namespaces, sysctls, or VPN.
  Privileged tests must use disposable namespaces, preview changes, trap interruption, and prove
  complete cleanup.
- License original VOLPAROSSA contributions as GPL-3.0-only and preserve all applicable third-party notices.

## Workflow

1. Describe the user-visible outcome, invariant and failure mode the change addresses.
2. Add focused verification for the behavior being changed. Parsers, signatures, policy,
   selection, framing and cleanup need tests of their relevant boundaries.
3. Keep every externally controlled length, allocation, peer/session count, timeout, and queue
   bounded.
4. During iteration, run the narrowest relevant formatter/compile check and functional smoke.
   Documentation-only changes need link, structure and claim checks, not a fresh network trial.
   Use the broad gate at integration checkpoints/CI and release preparation, rather than
   repeating it for every small edit:

   ```sh
   ./scripts/check-shell.sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   ./scripts/check-rust-dependencies.sh
   ```

5. For dataplane work, include a disposable network-namespace acceptance test and machine-readable
   evidence of actual data-carrying MPTCP subflows or MPQUIC paths.
6. Update documentation and check an item in `docs/IMPLEMENTATION_STATUS.md` only after its stated
   verification passes.

Do not weaken a fail-closed default to make a test pass. If a kernel or Debian limitation is real,
capture its exact version and reproducible evidence, then document the bounded alternative.

## Documentation placement

Put topic guides in the matching folder under [docs/](docs/README.md): architecture,
network, services, applications, privacy or development. Keep the top level for the
documentation index, FAQ and `IMPLEMENTATION_STATUS.md`. Link new guides from the index
and use relative links to related topics and source files.

When moving a document, update code includes, packaging inputs and fixture source paths
as well as Markdown links. Preserve installed documentation filenames and historical
evidence URLs tied to exact commits. A changed README or guide can change the input to a
future model trial; it does not rewrite the results of an earlier source-bound trial.

## Native code and dependencies

Rust is required for new control-plane and orchestration code. Keep upstream native C/C++
behind isolated, documented integration boundaries, including mqvpn/xquic and the dependencies
needed by agreed compute or application integrations. Do not duplicate the Rust control plane
in native code. Pin exact source revisions,
record origin/license/patches in `THIRD_PARTY_LICENSES.md`, build from source, and run upstream tests
plus ASan/Valgrind. New dependencies must pass `./scripts/check-rust-dependencies.sh`; unpinned Git
dependencies and prebuilt binaries are not accepted.

## Reporting test results

State the OS, architecture, kernel, Rust version, exact command, and result. Privileged integration
reports must also include pre/post digests for host routes, DNS, and nftables, cleanup results, and
the generated acceptance report. Redact keys, full hostnames, destination addresses, and payloads.
