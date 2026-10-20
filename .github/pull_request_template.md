## Change

<!-- What changes, and why is this the smallest useful slice? -->

## Invariant and failure mode

<!-- Which security, privacy, routing, or resource invariant is preserved or strengthened? -->

## Scope and non-goals

<!-- State what is deliberately not implemented or claimed. -->

## Verification

<!-- List the exact commands and results. Never attach secrets or private traffic. -->
<!-- Mark only applicable checks; write N/A when a check does not apply to this change. -->

- [ ] Documentation-only: links and technical claims were checked; no runtime behavior is implied.
- [ ] Source change: focused checks cover the changed behavior and relevant failure paths.
- [ ] Dependency or upstream change: dependency, license, and provenance checks were run as applicable.
- [ ] If privileged networking acceptance was needed, it ran only in the documented disposable topology and cleanup was verified.

Checks run:

<!-- Documentation-only pull requests do not need Rust or network checks. -->

## Safety and truthfulness

- [ ] Applicable routing and transport claims preserve `client -> exactly one relay -> exit`; ordinary TCP and single-path QUIC are not described as multipath.
- [ ] No production key, account, private browsing metadata, telemetry, or hidden network action is added.
- [ ] No test changes the development host's routes, DNS, firewall, interfaces, sysctls, or VPN.
- [ ] Source changes keep external inputs, allocations, queues, sessions, and timeouts bounded and fail closed.
- [ ] New third-party inputs are pinned and their provenance and licenses are recorded, or none were added.

## Documentation and status

- [ ] Documentation reflects implemented behavior and remaining limitations where relevant.
- [ ] `docs/IMPLEMENTATION_STATUS.md` changed only where passing evidence supports it, or did not need to change.
