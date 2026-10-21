# Complete goal preservation and resumption verification

Verification baseline: core main `2d0e08716374e75b646cc2cb4c6f81ab89d3d013`,
2026-10-21. This record concerns requirement preservation and coherence, not
runtime acceptance. The repository contains all source payloads needed for a
fresh conversation; historical attachment names are provenance only.

## Reproduce the preservation check

From the core checkout, with Python 3 and Git available:

```sh
python3 scripts/verify-goal-preservation.py
```

After committing or fetching an integrated revision, check the actual committed
blobs, substituting its full 40-character commit SHA:

```sh
python3 scripts/verify-goal-preservation.py --git-revision FULL_COMMIT_SHA
```

The second mode reads files from that Git revision, not from the working tree.
The verifier checks fixed byte lengths/hashes, unique preservation markers, the
recorded original hash, the complete pre-DPS prefix, the exact DPS join and
required durable documentation references. It needs neither an attachment nor
old Git history. Its JSON output reports the checked revision and digests.
Hashes establish preservation against the recorded baseline, not independent
proof of the identity of the original sender or semantic/runtime correctness.

| Preserved material | Bytes | SHA-256 |
| --- | ---: | --- |
| Original goal inside `BEGIN/END ORIGINAL GOAL` | 26,125 | `2bebaf9e27860115e64f5b93f50cc1e5bc17d34b22c45fe83106d200b86b54c7` |
| Entire pre-DPS `GOAL.md`, including all earlier amendments | 30,249 | `d746ce39c645a226cf85b426a2ea9991f43bba4e2bacca4c6f53865d71bfe287` |
| First received DPS payload | 10,495 | `df3ec2bab02272138e2713159959c925097780d49f73c805a11cbdc049bfc56b` |
| User's DPS continuation | 4,375 | `26cca9ea1854ddb59920457275c5e852a646f226058f26dced5564bdf9313d6d` |
| Normative joined DPS payload | 14,640 | `38449f84a75d2a8d15c87e014d7e2e70b638380b73fc3a3f54fb92913569a142` |

The original marker payload and recorded hash are unchanged. The entire
30,249-byte pre-DPS file remains an exact prefix, independently compared with
`b96dd61c^` during consolidation. Changes are after that prefix. For every marked
payload, the one newline immediately before the closing marker is a delimiter.
[DPS_REQUIREMENTS.md](DPS_REQUIREMENTS.md) contains every first-part byte before
its interrupted Map subsection, followed by the complete continuation from Map.
The [source archive](DPS_GOAL_20261021.md) retains both original payloads unchanged.
This intentionally preserves provenance without repeating an incomplete Map
requirement in the normative text.

## Full scope and amendment inventory

[GOAL.md](GOAL.md) remains authoritative for the complete objective. Its original
contains all ten applications, all five infrastructure layers, shared cache and
private storage, participation, cooperative learning, multimodal interaction,
autonomous Internet use, protected execution, governance and voting rules,
financial recovery, the values/immune system, maintenance/updates and the full
acceptance/prioritization criteria. The v1 transport baseline is not a scope ceiling.

| Later agreement retained | Authoritative location and interpretation |
| --- | --- |
| Consent-O-Matic clarification | GOAL, Later clarifications: upstream extension, opt-in upstream contributions and cooperation with uBlock Origin. |
| Weather clarification | GOAL, Later clarifications: Drizz.li and Overmorrow, required precipitation and air quality, visibly unavailable missing values. |
| Organization efficiency and quality, 2026-10-20 | GOAL, Later clarifications: all repositories, measured priorities, Astra/Sol/Luna delegation, preserved functionality/privacy/work, standard public hosted runners and no new paid services/storage. |
| Sustainable public growth, 2026-10-20 | GOAL and [public-growth record](PUBLIC_GROWTH_20261020.md): discovery, contributions, documentation, visual communication and funding readiness; scoped outreach/funding/account/hosting restrictions retained. |
| Public messaging implementation, 2026-10-21 | GOAL, Later clarifications: authorized organization/site/core/app visitor-facing changes and permitted publication; supersedes only that earlier publication hold, not unrelated approvals. |
| Complete DPS addition, 2026-10-21 | GOAL incorporates [DPS_REQUIREMENTS.md](DPS_REQUIREMENTS.md); both received parts retained with the explicit Map continuation rule. |
| Goal consolidation/resumption, 2026-10-21 | This record, GOAL's instruction boundaries and [PURSUING_GOAL.md](PURSUING_GOAL.md): verify preservation, publish reviewable documentation, preserve ongoing integrations, then continue the entire objective. |

Earlier source history (`ee901c2e`, `5157a1a4`, `cddbb412`, `942c204b`, `5778deb2`,
then DPS `b96dd61c`) records introduction of the preserved goal and amendments.
It is useful provenance, not required input for the verifier or future execution.

## DPS completeness and traceability

The exact joined requirements are the completeness reference. The following map
connects every section to design and acceptance; it does not replace the text.

| DPS requirement group | Design/integration and verification boundary |
| --- | --- |
| Original scope preservation and autonomous execution (section 1; final resumption section) | GOAL, this check, [workflow](CODEX_WORKFLOW.md), [status](../IMPLEMENTATION_STATUS.md#current-integration-and-active-work); all existing functionality, branches, blockers and amendments retained. |
| Standalone/hybrid positioning (2.1) | [DPS research and choices](../services/DPS.md#research-and-implementation-choices): GNSS, Wi-Fi RTT, UWB, BLE, peer ranging, inertial/compass/barometer, camera/VIO, trusted anchors, robust fusion and offline operation. Relative coordinates need a trustworthy reference to become absolute; camera/platform permissions remain required. |
| GNSS integrity (2.2) | DPS shared service, research and acceptance: spoofing, jamming/outage, jumps/time manipulation, malicious anchors/peers and coordinated/correlated sources; OSNMA navigation-message authentication is not position proof. Isolation/downweighting, independent alternatives, explicit uncertainty and safe unavailability remain required; no guaranteed universal detection or unauthorized OS override. |
| Privacy, anonymity and control (2.3) | [DPS privacy](../services/DPS.md#privacy-and-shared-infrastructure): local-first, separate assistance/contribution permissions, temporary identifiers, minimization, encryption, retention, explicit consent, cross-app/profile resistance and metadata/ranging threat model. No automatic private-history publication or shared training; anonymity claims need concrete evidence. |
| Reliability and quality (2.4) | [DPS acceptance](../services/DPS.md#acceptance-sequence): accuracy/uncertainty, freshness/availability, provenance/types, integrity/conflicts, relative/absolute status and limitations; compare errors, time-to-fix, outage behavior, energy/CPU/memory/network use and attack resilience against independent references. More peers do not prove improvement; no certified safety-critical claim. |
| Existing five layers (3) | [Architecture](../architecture/ARCHITECTURE.md) and DPS privacy: permitted local measurement links; authentic public cache references; authorized private Storage with uniform redundancy; protected Compute; Transaction only where useful, never a payment condition. Versioned shared core, separate platform adapters and Linux/Android/iOS limits. |
| Map and all other applications (4 and continuation) | [Applications](../applications/APPLICATIONS.md), [DPS application priorities](../services/DPS.md#application-integration-priorities): offline Organic Maps, uncertain/tunnel/indoor fixes; Weather source independence; optional private Image geotags; consent/encrypted/limited-retention Chat preserving Signal; Browser permission/precision ceilings; authorized Cloud reuse; no unnecessary location dependency or location-only financial/identity/voting authority. |
| Architecture, trials and development order (continuation) | DPS acceptance and current plan: research standards/upstream before new algorithms; document trust/fault/hardware/platform limits; bounded relative/fusion/integrity trials, independent references and controlled injection. Distinguish simulation, hardware and measured improvement. No unauthorized scans, GNSS interference or host changes; DPS is permanent but does not automatically displace critical integrations. |

The integrated stateless `DpsAssess` slice is explicitly only input-consistency
assessment. It does not satisfy sensor acquisition, fusion, independent physical
integrity, native Map navigation or measured positioning improvement. Pending or
failed daemon/consumer trials remain pending or failed in the implementation ledger.

## Consistency and fresh-conversation check

- **Requirements:** GOAL plus every amendment and the incorporated complete DPS
  addition define what must be built. The received archive is provenance.
- **Engineering rules:** [AGENTS.md](../../AGENTS.md) governs delegation, authority,
  privacy and host safety. [CODEX_WORKFLOW.md](CODEX_WORKFLOW.md) explains recovery.
- **Evidence and plan:** IMPLEMENTATION_STATUS separates accepted functionality,
  retained candidates, historical failures and the next useful integrations.
  Recheck live worktrees/PRs/runs; a dated snapshot is not current run evidence.

Independent review found no contradictory instruction after considering scope:
Browser-specific fallback does not disable other apps' protection; Storage coding
is separate from forbidden v1 transport FEC; financial simulations grant no
real-money authority; automatic updates still require independent release trust;
a local DPS slice does not satisfy the complete positioning requirement.
DPS adds no sixth infrastructure layer or permission to bypass relay/exit privacy.

A fresh conversation can read AGENTS, GOAL and DPS_REQUIREMENTS, run the verifier,
then follow the current ledger and affected application instructions. All necessary
requirement text and provenance are tracked here. [PURSUING_GOAL.md](PURSUING_GOAL.md)
contains the copyable UI text. Updating that text does not require declaring the
unfinished project complete or restarting ongoing integrations.

Publication uses a scoped documentation PR, independent review, applicable checks
and a permitted merge. Verify the fetched final commit with `--git-revision` and
report its exact SHA; local checks alone do not establish publication. This record
cannot contain its own commit hash. The active UI field is separate client state;
this repository change does not claim to have edited that field.
