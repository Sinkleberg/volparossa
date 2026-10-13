//! Public signed fixtures test cryptography. Synthetic facts below test only
//! deterministic owner/binding state; they are never available to production.

use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use super::{session::Stamp, *};

const REPORT_HEX: &[u8] = include_bytes!("../../../../tests/fixtures/snp/report_milan.hex");
const VCEK: &[u8] = include_bytes!("../../../../tests/fixtures/snp/vcek_milan.der");
const NOW: u64 = 1_800_000_000;

fn report() -> Vec<u8> {
    hex::decode(REPORT_HEX).unwrap()
}

fn limits(attempts: u16, pending: u8) -> SessionLimits {
    SessionLimits {
        expires_at: NOW + 120,
        maximum_pending: pending,
        maximum_attempts: attempts,
    }
}

fn stamp(at: Instant, seconds: u64) -> Stamp {
    Stamp {
        unix: NOW + seconds,
        monotonic: at + Duration::from_secs(seconds),
    }
}

fn owner(at: Instant, attempts: u16, pending: u8) -> SessionOwner {
    SessionOwner::new_at([1; 32], [2; 48], 1, limits(attempts, pending), stamp(at, 0)).unwrap()
}

// Test-only construction exercises binding without claiming a new signed report.
// There is no cfg(test) feature or constructor reachable from the public library.
fn synthetic_binding_facts(pending: &PendingSession<'_>, key: &[u8; 32]) -> SignatureFacts {
    SignatureFacts {
        report_sha256: [3; 32],
        vcek_sha256: [4; 32],
        measurement: [2; 48],
        report_data: session_report_data(pending.challenge_bytes(), key).unwrap(),
        guest_svn: 1,
        guest_policy: 1 << 17,
        validity: [(NOW - 10, NOW + 1000); 3],
    }
}

#[test]
fn upstream_public_fixtures_and_reference_roots_match_source_pins() {
    use sev::certs::snp::builtin::milan;
    for (bytes, expected) in [
        (
            REPORT_HEX,
            "3d956e9104969a038031a6b63dd6c4b60000619d37702065994f7da76f88ae7d",
        ),
        (
            VCEK,
            "3bbfb6ee259f75a95d13168cfdf2e034181bb93c7c016825731cbe8ea16c95e1",
        ),
        (
            milan::ARK,
            "8c109952166431ffad8cb9a3d54f3d20ffbbb58164f0d54be3457bf0ece9e0d8",
        ),
        (
            milan::ASK,
            "8da3a65af1cb7cb90a21fac78431a2431a9ee7811f48c36569c53fb80ad31fee",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(bytes)), expected);
    }
}

#[test]
fn real_public_signatures_return_only_incomplete_facts() {
    let bytes = report();
    let facts = verify_milan_v2_signature_facts(&bytes, VCEK).unwrap();
    assert_eq!(
        facts.report_sha256(),
        &<[u8; 32]>::from(Sha256::digest(&bytes))
    );
    assert_eq!(facts.vcek_sha256(), &<[u8; 32]>::from(Sha256::digest(VCEK)));
    assert_eq!(facts.measurement(), &bytes[0x90..0xc0]);
    assert_eq!(facts.outstanding_appraisal(), &OUTSTANDING);
    assert!(
        facts
            .outstanding_appraisal()
            .contains(&OutstandingAppraisal::CurrentVendorRevocation)
    );
}

#[test]
fn signed_report_or_certificate_tampering_is_rejected_by_actual_crypto() {
    for offset in [0x15, 0x50, 0x90, 0x1a0, 0x2a0] {
        let mut bytes = report();
        bytes[offset] ^= 0x80;
        assert_eq!(
            verify_milan_v2_signature_facts(&bytes, VCEK).err(),
            Some(EvidenceError::Signature)
        );
    }
    let mut cert = VCEK.to_vec();
    cert[40] ^= 0xff; // Same parseable mutation as the upstream invalid-chain test.
    assert_eq!(
        verify_milan_v2_signature_facts(&report(), &cert).err(),
        Some(EvidenceError::Signature)
    );
}

#[test]
fn exact_received_framing_version_and_reserved_bytes_are_required() {
    let original = report();
    for size in [0, 1, 1183, 1185, 8192] {
        let mut bytes = original.clone();
        bytes.resize(size, 0);
        assert_eq!(
            verify_milan_v2_signature_facts(&bytes, VCEK).err(),
            Some(EvidenceError::Encoding)
        );
    }
    for version in [0_u32, 1, 3, 4, 5, u32::MAX] {
        let mut bytes = original.clone();
        bytes[..4].copy_from_slice(&version.to_le_bytes());
        assert_eq!(
            snp::exact_report(&bytes).err(),
            Some(EvidenceError::Encoding)
        );
    }
    // Reserved report, TCB, pre-chip, version and tail bytes plus high R/S bytes.
    for offset in [
        0x3a,
        0x4c,
        0x188,
        0x1e2,
        0x1eb,
        0x1ef,
        0x1f2,
        0x1f8,
        0x2a0 + 48,
        0x2a0 + 72 + 48,
        0x2a0 + 144,
        1183,
    ] {
        let mut bytes = original.clone();
        bytes[offset] = 1;
        assert_eq!(
            snp::exact_report(&bytes).err(),
            Some(EvidenceError::Encoding),
            "offset {offset:x}"
        );
    }
}

#[test]
fn unsupported_key_policy_platform_and_certificate_shapes_fail_closed() {
    let original = report();
    for (offset, bit) in [
        (0x30, 1),
        (0x34, 2),
        (0x48, 2),
        (0x48, 4),
        (0x48, 0x20),
        (0x0a, 0x20),
        (0x40, 0x20),
    ] {
        let mut bytes = original.clone();
        bytes[offset] |= bit;
        assert_eq!(
            snp::exact_report(&bytes).err(),
            Some(EvidenceError::Encoding)
        );
    }
    let mut bytes = original;
    bytes[0x0a] &= !2; // Mandatory policy reserved bit must be one on the wire.
    assert_eq!(
        snp::exact_report(&bytes).err(),
        Some(EvidenceError::Encoding)
    );
    for cert in [
        Vec::new(),
        vec![0; MAX_VCEK_BYTES + 1],
        [VCEK, &[0]].concat(),
    ] {
        assert_eq!(
            verify_milan_v2_signature_facts(&report(), &cert).err(),
            Some(EvidenceError::Encoding)
        );
    }
}

#[test]
fn actual_public_report_cannot_bind_to_fresh_owner_even_with_matching_measurement() {
    let facts = verify_milan_v2_signature_facts(&report(), VCEK).unwrap();
    let at = Instant::now();
    let owner = SessionOwner::new_at(
        [1; 32],
        *facts.measurement(),
        facts.guest_svn(),
        limits(1, 1),
        stamp(at, 0),
    )
    .unwrap();
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    assert_eq!(
        pending.bind_at(facts, [5; 32], stamp(at, 1)).err(),
        Some(EvidenceError::Binding)
    );
    assert_eq!(
        owner.begin_at(stamp(at, 2)).err(),
        Some(EvidenceError::Budget)
    );
}

#[test]
fn synthetic_binding_positive_is_explicitly_not_full_appraisal_or_release() {
    let at = Instant::now();
    let owner = owner(at, 2, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let expected_hash: [u8; 32] = Sha256::digest(pending.challenge_bytes()).into();
    let facts = synthetic_binding_facts(&pending, &[5; 32]);
    let evidence = pending.bind_at(facts, [5; 32], stamp(at, 1)).unwrap();
    assert_eq!(evidence.challenge_sha256(), &expected_hash);
    assert_eq!(evidence.proposed_session_key(), &[5; 32]);
    assert_eq!(evidence.expires_at(), NOW + 30);
    assert_eq!(evidence.observed_at(), NOW + 1);
    assert_eq!(evidence.outstanding_appraisal(), &OUTSTANDING);
    assert_eq!(evidence.signature_facts().report_sha256(), &[3; 32]);
    let next = owner.begin_at(stamp(at, 2)).unwrap();
    assert_ne!(
        Sha256::digest(next.challenge_bytes()).as_slice(),
        &expected_hash
    );
}

#[test]
fn fresh_nonce_owner_policy_and_proposed_key_are_all_bound() {
    let at = Instant::now();
    let owner = owner(at, 4, 2);
    let first = owner.begin_at(stamp(at, 0)).unwrap();
    let second = owner.begin_at(stamp(at, 0)).unwrap();
    let facts = synthetic_binding_facts(&first, &[5; 32]);
    assert_ne!(first.challenge_bytes(), second.challenge_bytes());
    assert_eq!(
        second.bind_at(facts, [5; 32], stamp(at, 1)).err(),
        Some(EvidenceError::Binding)
    );
    let facts = synthetic_binding_facts(&first, &[5; 32]);
    assert_eq!(
        first.bind_at(facts, [6; 32], stamp(at, 1)).err(),
        Some(EvidenceError::Binding)
    );
    let first = owner.begin_at(stamp(at, 2)).unwrap();
    let facts = synthetic_binding_facts(&first, &[5; 32]);
    let other = SessionOwner::new_at([9; 32], [2; 48], 1, limits(1, 1), stamp(at, 0)).unwrap();
    let second = other.begin_at(stamp(at, 2)).unwrap();
    assert_eq!(
        second.bind_at(facts, [5; 32], stamp(at, 3)).err(),
        Some(EvidenceError::Binding)
    );
}

#[test]
fn measurement_svn_debug_migration_and_each_certificate_time_are_checked() {
    let at = Instant::now();
    let owner = owner(at, 16, 1);
    for mutation in 0..4 {
        let pending = owner.begin_at(stamp(at, 0)).unwrap();
        let mut facts = synthetic_binding_facts(&pending, &[5; 32]);
        match mutation {
            0 => facts.measurement[0] ^= 1,
            1 => facts.guest_svn = 0,
            2 => facts.guest_policy |= 1 << 18,
            _ => facts.guest_policy |= 1 << 19,
        }
        assert_eq!(
            pending.bind_at(facts, [5; 32], stamp(at, 1)).err(),
            Some(EvidenceError::Binding)
        );
    }
    for index in 0..3 {
        for validity in [(NOW + 2, NOW + 10), (NOW - 10, NOW), (NOW + 2, NOW)] {
            let pending = owner.begin_at(stamp(at, 0)).unwrap();
            let mut facts = synthetic_binding_facts(&pending, &[5; 32]);
            facts.validity[index] = validity;
            assert_eq!(
                pending.bind_at(facts, [5; 32], stamp(at, 1)).err(),
                Some(EvidenceError::CertificateTime)
            );
        }
    }
}

#[test]
fn delayed_expired_rollback_and_cancelled_bindings_cannot_succeed() {
    let at = Instant::now();
    let owner = owner(at, 8, 1);
    for now in [
        stamp(at, 30),
        stamp(at, 31),
        Stamp {
            unix: NOW - 1,
            monotonic: at + Duration::from_secs(1),
        },
        Stamp {
            unix: NOW + 1,
            monotonic: at + Duration::from_secs(31),
        },
    ] {
        let pending = owner.begin_at(stamp(at, 0)).unwrap();
        let facts = synthetic_binding_facts(&pending, &[5; 32]);
        assert_eq!(
            pending.bind_at(facts, [5; 32], now).err(),
            Some(EvidenceError::Expired)
        );
    }
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let facts = synthetic_binding_facts(&pending, &[5; 32]);
    owner.cancel();
    assert_eq!(
        pending.bind_at(facts, [5; 32], stamp(at, 1)).err(),
        Some(EvidenceError::Cancelled)
    );
    assert_eq!(
        owner.begin_at(stamp(at, 1)).err(),
        Some(EvidenceError::Cancelled)
    );
}

#[test]
fn pending_slots_release_but_attempts_never_refund_on_drop_cancel_or_failure() {
    let at = Instant::now();
    let owner = owner(at, 3, 1);
    let first = owner.begin_at(stamp(at, 0)).unwrap();
    assert_eq!(
        owner.begin_at(stamp(at, 0)).err(),
        Some(EvidenceError::Budget)
    );
    drop(first);
    owner.begin_at(stamp(at, 1)).unwrap().cancel();
    let final_attempt = owner.begin_at(stamp(at, 2)).unwrap();
    let facts = synthetic_binding_facts(&final_attempt, &[5; 32]);
    assert_eq!(
        final_attempt.bind_at(facts, [6; 32], stamp(at, 3)).err(),
        Some(EvidenceError::Binding)
    );
    assert_eq!(
        owner.begin_at(stamp(at, 4)).err(),
        Some(EvidenceError::Budget)
    );
}

#[test]
fn owner_bounds_expire_without_rebasing_challenge_or_attempt_budget() {
    let at = Instant::now();
    let owner = owner(at, 3, 1);
    let pending = owner.begin_at(stamp(at, 119)).unwrap();
    let facts = synthetic_binding_facts(&pending, &[5; 32]);
    assert_eq!(
        pending.bind_at(facts, [5; 32], stamp(at, 120)).err(),
        Some(EvidenceError::Expired)
    );
    assert_eq!(
        owner.begin_at(stamp(at, 120)).err(),
        Some(EvidenceError::Expired)
    );
    for bad in [
        SessionLimits {
            expires_at: NOW,
            ..limits(1, 1)
        },
        SessionLimits {
            expires_at: NOW + 601,
            ..limits(1, 1)
        },
        SessionLimits {
            expires_at: u64::MAX,
            ..limits(1, 1)
        },
        limits(0, 1),
        limits(65, 1),
        limits(1, 0),
        limits(1, 9),
    ] {
        assert_eq!(
            SessionOwner::new_at([1; 32], [2; 48], 1, bad, stamp(at, 0)).err(),
            Some(EvidenceError::Configuration)
        );
    }
}

#[test]
fn public_binding_codec_rejects_unknown_duplicate_noncanonical_and_oversize() {
    let at = Instant::now();
    let owner = owner(at, 1, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let original = pending.challenge_bytes();
    let mut unknown = original.to_vec();
    unknown.extend([0x40, 1]);
    let mut duplicate = original.to_vec();
    duplicate.extend([8, 1]);
    let mut bad_version = original.to_vec();
    bad_version[1] = 2;
    for bytes in [Vec::new(), vec![0; 257], unknown, duplicate, bad_version] {
        assert_eq!(
            session_report_data(&bytes, &[5; 32]).err(),
            Some(EvidenceError::Encoding)
        );
    }
    assert_eq!(
        session_report_data(original, &[0; 32]).err(),
        Some(EvidenceError::Encoding)
    );
}

#[test]
fn public_signature_binding_entrypoint_consumes_its_attempt_without_release() {
    let facts = verify_milan_v2_signature_facts(&report(), VCEK).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let owner = SessionOwner::new(
        [1; 32],
        *facts.measurement(),
        facts.guest_svn(),
        SessionLimits {
            expires_at: now + 60,
            maximum_pending: 1,
            maximum_attempts: 1,
        },
    )
    .unwrap();
    // The public fixture may itself eventually expire: neither outcome admits it.
    let failure = owner
        .begin()
        .unwrap()
        .verify_and_bind(&report(), VCEK, [5; 32])
        .err()
        .unwrap();
    assert!(matches!(
        failure,
        EvidenceError::Binding | EvidenceError::CertificateTime
    ));
    assert_eq!(owner.begin().err(), Some(EvidenceError::Budget));
}
