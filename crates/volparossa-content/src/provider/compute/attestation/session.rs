//! Owner-local finite challenges; no task input, transport or worker lease.

use std::{
    sync::atomic::{AtomicBool, AtomicU8, AtomicU16, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use prost::Message;
use sha2::{Digest as _, Sha256, Sha512};
use subtle::ConstantTimeEq as _;

use super::{EvidenceError, OutstandingAppraisal, SignatureFacts, verify_milan_v2_signature_facts};

const MAX_OWNER_SECONDS: u64 = 600;
const CHALLENGE_SECONDS: u64 = 30;
const MAX_PENDING: u8 = 8;
const MAX_ATTEMPTS: u16 = 64;
const MAX_CHALLENGE_BYTES: usize = 256;
const BINDING_DOMAIN: &[u8] = b"VOLPAROSSA/SNP-MILAN-V2/SESSION-EVIDENCE/1\0";

/// Owner limits, not worker resources or permission to run a private task.
/// All are fixed at construction and cannot be refreshed by a peer response.
#[derive(Clone, Copy)]
pub struct SessionLimits {
    /// Absolute owner deadline in Unix seconds; at most 600 seconds from creation.
    pub expires_at: u64,
    /// Simultaneous pending verifications, in 1..=8.
    pub maximum_pending: u8,
    /// Total challenges over this owner's lifetime, in 1..=64; never refunded.
    pub maximum_attempts: u16,
}

#[derive(Clone, PartialEq, Message)]
struct Challenge {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    public_policy_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    expected_measurement: Vec<u8>,
    #[prost(uint32, tag = "5")]
    minimum_guest_svn: u32,
    #[prost(uint64, tag = "6")]
    created_at: u64,
    #[prost(uint64, tag = "7")]
    expires_at: u64,
}

#[derive(Clone, PartialEq, Message)]
struct Binding {
    #[prost(bytes = "vec", tag = "1")]
    challenge: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    proposed_session_key: Vec<u8>,
}

/// Compute the exact guest REPORT_DATA convention from a canonical challenge and
/// a proposed 32-byte ephemeral key. Does not verify freshness, key possession,
/// key origin, or signatures. The key is not used to encrypt anything here.
///
/// SHA-512 is domain separated and covers the entire protobuf, including times,
/// public expectations and random nonce. There is no private-content hash field.
///
/// # Errors
/// Rejects noncanonical, oversize, unsupported, malformed or empty-key input.
pub fn session_report_data(
    challenge: &[u8],
    proposed_session_key: &[u8; 32],
) -> Result<[u8; 64], EvidenceError> {
    if challenge.is_empty()
        || challenge.len() > MAX_CHALLENGE_BYTES
        || *proposed_session_key == [0; 32]
    {
        return Err(EvidenceError::Encoding);
    }
    let parsed = Challenge::decode(challenge).map_err(|_| EvidenceError::Encoding)?;
    if parsed.encode_to_vec() != challenge
        || parsed.version != 1
        || parsed.nonce.len() != 32
        || parsed.nonce.iter().all(|byte| *byte == 0)
        || parsed.public_policy_id.len() != 32
        || parsed.public_policy_id.iter().all(|byte| *byte == 0)
        || parsed.expected_measurement.len() != 48
        || parsed.expected_measurement.iter().all(|byte| *byte == 0)
        || parsed.expires_at <= parsed.created_at
        || parsed.expires_at - parsed.created_at > CHALLENGE_SECONDS
    {
        return Err(EvidenceError::Encoding);
    }
    let binding = Binding {
        challenge: challenge.to_vec(),
        proposed_session_key: proposed_session_key.to_vec(),
    };
    let mut digest = Sha512::new();
    digest.update(BINDING_DOMAIN);
    digest.update(binding.encode_to_vec());
    Ok(digest.finalize().into())
}

pub(super) struct Stamp {
    pub(super) unix: u64,
    pub(super) monotonic: Instant,
}

impl Stamp {
    fn now() -> Result<Self, EvidenceError> {
        Ok(Self {
            unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| EvidenceError::Unavailable)?
                .as_secs(),
            monotonic: Instant::now(),
        })
    }
}

/// One local owner's finite attempt budget and public session expectations.
/// No deserialization/clone, no process-global replay state and no network I/O.
/// Supplying expectations does not authorize their roots or workload for release.
pub struct SessionOwner {
    public_policy_id: [u8; 32],
    expected_measurement: [u8; 48],
    minimum_guest_svn: u32,
    limits: SessionLimits,
    created: Stamp,
    deadline: Instant,
    pending: AtomicU8,
    remaining: AtomicU16,
    cancelled: AtomicBool,
}

impl SessionOwner {
    /// Create a finite verifier owner from local public expectations. In
    /// particular, `public_policy_id` must never be a private task/content hash.
    ///
    /// # Errors
    /// Rejects zero expectations, unavailable time, expired/overflowing limits,
    /// more than ten minutes, more than eight pending or more than 64 attempts.
    pub fn new(
        public_policy_id: [u8; 32],
        expected_measurement: [u8; 48],
        minimum_guest_svn: u32,
        limits: SessionLimits,
    ) -> Result<Self, EvidenceError> {
        Self::new_at(
            public_policy_id,
            expected_measurement,
            minimum_guest_svn,
            limits,
            Stamp::now()?,
        )
    }

    pub(super) fn new_at(
        public_policy_id: [u8; 32],
        expected_measurement: [u8; 48],
        minimum_guest_svn: u32,
        limits: SessionLimits,
        now: Stamp,
    ) -> Result<Self, EvidenceError> {
        let seconds = limits
            .expires_at
            .checked_sub(now.unix)
            .ok_or(EvidenceError::Configuration)?;
        if public_policy_id == [0; 32]
            || expected_measurement == [0; 48]
            || !(1..=MAX_OWNER_SECONDS).contains(&seconds)
            || !(1..=MAX_PENDING).contains(&limits.maximum_pending)
            || !(1..=MAX_ATTEMPTS).contains(&limits.maximum_attempts)
        {
            return Err(EvidenceError::Configuration);
        }
        let deadline = now
            .monotonic
            .checked_add(Duration::from_secs(seconds))
            .ok_or(EvidenceError::Configuration)?;
        Ok(Self {
            public_policy_id,
            expected_measurement,
            minimum_guest_svn,
            limits,
            created: now,
            deadline,
            pending: AtomicU8::new(0),
            remaining: AtomicU16::new(limits.maximum_attempts),
            cancelled: AtomicBool::new(false),
        })
    }

    /// Permanently invalidate pending and future challenges. Dropped challenges
    /// release their slots but never refund an attempt or extend the owner expiry.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Allocate one fresh challenge. A pending value is not cloneable and is
    /// consumed by a single verification attempt, including every failure path.
    ///
    /// # Errors
    /// Rejects cancellation, exhausted budget, expiry, clock rollback or entropy failure.
    pub fn begin(&self) -> Result<PendingSession<'_>, EvidenceError> {
        self.begin_at(Stamp::now()?)
    }

    pub(super) fn begin_at(&self, now: Stamp) -> Result<PendingSession<'_>, EvidenceError> {
        self.check_time(&now)?;
        self.pending
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < self.limits.maximum_pending).then_some(count + 1)
            })
            .map_err(|_| EvidenceError::Budget)?;
        let slot = Slot(self);
        self.remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_sub(1)
            })
            .map_err(|_| EvidenceError::Budget)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| EvidenceError::Unavailable)?;
        if nonce == [0; 32] {
            return Err(EvidenceError::Unavailable);
        }
        let expires_at = now
            .unix
            .checked_add(CHALLENGE_SECONDS)
            .ok_or(EvidenceError::Expired)?
            .min(self.limits.expires_at);
        let deadline = now
            .monotonic
            .checked_add(Duration::from_secs(expires_at - now.unix))
            .ok_or(EvidenceError::Expired)?
            .min(self.deadline);
        let challenge = Challenge {
            version: 1,
            nonce: nonce.to_vec(),
            public_policy_id: self.public_policy_id.to_vec(),
            expected_measurement: self.expected_measurement.to_vec(),
            minimum_guest_svn: self.minimum_guest_svn,
            created_at: now.unix,
            expires_at,
        }
        .encode_to_vec();
        Ok(PendingSession {
            slot,
            challenge,
            created: now,
            expires_at,
            deadline,
        })
    }

    fn check_time(&self, now: &Stamp) -> Result<(), EvidenceError> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(EvidenceError::Cancelled);
        }
        if now.unix < self.created.unix
            || now.unix >= self.limits.expires_at
            || now.monotonic < self.created.monotonic
            || now.monotonic >= self.deadline
        {
            return Err(EvidenceError::Expired);
        }
        Ok(())
    }
}

struct Slot<'a>(&'a SessionOwner);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::SeqCst);
    }
}

/// In-memory, owner-borrowed, one-attempt challenge. Cannot outlive its owner.
/// Dropping/cancelling never creates evidence or releases private input.
pub struct PendingSession<'a> {
    slot: Slot<'a>,
    challenge: Vec<u8>,
    created: Stamp,
    expires_at: u64,
    deadline: Instant,
}

impl PendingSession<'_> {
    /// Canonical public-only context. No task identifier or private content digest.
    pub fn challenge_bytes(&self) -> &[u8] {
        &self.challenge
    }

    /// Discard this challenge; its total attempt remains consumed.
    pub fn cancel(self) {}

    /// Verify reference signatures, certificate validity at the owner's current
    /// clock, expected measurement/SVN, no debug/migration, and exact fresh key
    /// binding. A bound result still cannot admit a worker or release any input.
    ///
    /// # Errors
    /// Consumes the challenge even on malformed data, mismatch, cancellation,
    /// certificate-time failure or expiration during synchronous verification.
    pub fn verify_and_bind(
        self,
        report: &[u8],
        vcek_der: &[u8],
        proposed_session_key: [u8; 32],
    ) -> Result<BoundSessionEvidence, EvidenceError> {
        self.check_time(&Stamp::now()?)?;
        let facts = verify_milan_v2_signature_facts(report, vcek_der)?;
        self.bind_at(facts, proposed_session_key, Stamp::now()?)
    }

    fn check_time(&self, now: &Stamp) -> Result<(), EvidenceError> {
        self.slot.0.check_time(now)?;
        if now.unix < self.created.unix
            || now.unix >= self.expires_at
            || now.monotonic < self.created.monotonic
            || now.monotonic >= self.deadline
        {
            return Err(EvidenceError::Expired);
        }
        Ok(())
    }

    pub(super) fn bind_at(
        self,
        facts: SignatureFacts,
        proposed_session_key: [u8; 32],
        now: Stamp,
    ) -> Result<BoundSessionEvidence, EvidenceError> {
        self.check_time(&now)?;
        facts.check_time(now.unix)?;
        let expected = session_report_data(&self.challenge, &proposed_session_key)?;
        if facts.measurement != self.slot.0.expected_measurement
            || facts.guest_svn < self.slot.0.minimum_guest_svn
            || facts.guest_policy & ((1 << 18) | (1 << 19)) != 0
            || !bool::from(facts.report_data.ct_eq(&expected))
        {
            return Err(EvidenceError::Binding);
        }
        Ok(BoundSessionEvidence {
            facts,
            challenge_sha256: Sha256::digest(&self.challenge).into(),
            proposed_session_key,
            expires_at: self.expires_at,
            observed_at: now.unix,
        })
    }
}

/// Historical observation of a fresh signed binding, **not** a live capability,
/// full appraisal, key-possession proof, worker permit or task admission.
/// It has no serializer, raw Debug, Clone, public constructor or release method.
/// A subsequent owner cancellation does not turn this observation into authority.
pub struct BoundSessionEvidence {
    facts: SignatureFacts,
    challenge_sha256: [u8; 32],
    proposed_session_key: [u8; 32],
    expires_at: u64,
    observed_at: u64,
}

impl BoundSessionEvidence {
    /// The original immutable cryptographic facts, still incompletely appraised.
    pub const fn signature_facts(&self) -> &SignatureFacts {
        &self.facts
    }

    /// Public-only challenge digest, not a task/content digest.
    pub const fn challenge_sha256(&self) -> &[u8; 32] {
        &self.challenge_sha256
    }

    /// Signed proposed key bytes. Ownership, origin and possession remain unproven.
    pub const fn proposed_session_key(&self) -> &[u8; 32] {
        &self.proposed_session_key
    }

    /// Original challenge deadline; reading evidence never extends it.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Local observation time, not a trusted external timestamp or task result.
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    /// Outstanding requirements cannot be cleared by constructing a boolean.
    pub const fn outstanding_appraisal(&self) -> &'static [OutstandingAppraisal] {
        self.facts.outstanding_appraisal()
    }
}
