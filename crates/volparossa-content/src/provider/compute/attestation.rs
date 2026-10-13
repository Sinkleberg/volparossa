//! Offline SNP signature facts and one-use fresh session evidence, not admission.
//!
//! The fixed upstream Milan ARK/ASK are **cryptographic reference roots**, not
//! independently authorized production trust. A valid signature alone does not
//! establish a secure platform, an approved worker, key origin, or task execution.
//! [`OutstandingAppraisal`] makes those remaining obligations explicit. Nothing
//! here opens a connection, grants a worker budget, or releases private input.
//!
//! Before attestation the session challenge contains only random freshness, a
//! public policy identifier, a public workload measurement and finite times. A
//! proposed ephemeral key is bound into `REPORT_DATA` using SHA-512 over a
//! domain-separated canonical protobuf. This proves a signed byte binding, not
//! that the key was generated or retained inside a particular guest program.
//! Never use a private prompt/code/content hash as the public policy identifier.
//!
//! A later release layer must first appraise authenticated vendor collateral and
//! independently authorized roots/workload code, then establish possession of a
//! guest-generated key in that measured code. Exact task acceptance (fresh task
//! ID, input, permissions, limits and expiry) belongs **inside** that encrypted
//! session, with an authenticated accept response before execution. This module
//! deliberately provides neither that channel nor a task/worker permit.
//!
//! Only canonical version-two, VMPL-zero, VCEK-signed Milan-format reports are
//! supported here. Other versions/platforms fail closed, not via parse-only
//! fallback. The public upstream report is useful for signature regression tests
//! but cannot satisfy a new random session challenge.

mod cert_profile;
mod endorsement;
mod session;
mod snp;

pub use session::{
    BoundSessionEvidence, PendingSession, SessionLimits, SessionOwner, session_report_data,
};
pub use snp::verify_milan_v2_signature_facts;

/// Exact supported firmware report size, including signature and reserved bytes.
pub const REPORT_BYTES: usize = 1184;
/// Maximum DER certificate size accepted before any ASN.1 or signature work.
pub const MAX_VCEK_BYTES: usize = 8192;

/// Closed errors: never contain peer certificate bytes, chip IDs or report data.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    /// Unsupported length, encoding, version, reserved bits or signing profile.
    #[error("unsupported or noncanonical attestation input")]
    Encoding,
    /// The fixed reference chain or report signature did not verify.
    #[error("attestation signature verification failed")]
    Signature,
    /// Certificate algorithms or authenticated VCEK claims do not match the profile.
    #[error("attestation endorsement binding failed")]
    Endorsement,
    /// A reference certificate is not valid at the owner's current time.
    #[error("attestation certificate validity failed")]
    CertificateTime,
    /// The caller supplied invalid finite owner limits or public expectations.
    #[error("invalid attestation session configuration")]
    Configuration,
    /// Owner or challenge expired, or wall time moved before its creation.
    #[error("attestation session expired or clock invalid")]
    Expired,
    /// Owner cancellation permanently invalidates its pending sessions.
    #[error("attestation session cancelled")]
    Cancelled,
    /// Finite owner attempts or simultaneous pending sessions were exhausted.
    #[error("attestation session budget exhausted")]
    Budget,
    /// Measurement, policy, fresh challenge or proposed key did not match.
    #[error("attestation session binding failed")]
    Binding,
    /// Operating-system entropy or clock is unavailable.
    #[error("attestation entropy or clock unavailable")]
    Unavailable,
}

/// Obligations not discharged by either signature facts or fresh binding.
/// No caller-supplied boolean or replacement root can clear these obligations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutstandingAppraisal {
    /// The reference roots are not independently authorized production policy.
    ProductionRootAuthorization,
    /// Full certificate-path profile and issuer appraisal remain outstanding.
    /// VCEK product, hardware-ID and reported-TCB extension bindings are checked;
    /// this narrower check does not discharge the entire certificate obligation.
    EndorsementProfileAndChipBinding,
    /// Current authenticated AMD CRL and its scope/time/issuer are not checked.
    CurrentVendorRevocation,
    /// Reported TCB versus current vendor advisories and owner minima is unchecked.
    VendorTcbAndLocalPolicy,
    /// Measurement/key bytes do not prove the approved workload's key provenance.
    AuthorizedWorkloadAndKeyOrigin,
}

const OUTSTANDING: [OutstandingAppraisal; 5] = [
    OutstandingAppraisal::ProductionRootAuthorization,
    OutstandingAppraisal::EndorsementProfileAndChipBinding,
    OutstandingAppraisal::CurrentVendorRevocation,
    OutstandingAppraisal::VendorTcbAndLocalPolicy,
    OutstandingAppraisal::AuthorizedWorkloadAndKeyOrigin,
];

/// Authentic signature statements rooted in the fixed upstream reference chain.
/// Fields are private; there is no deserializer, public constructor or raw Debug.
/// Certificate algorithms and VCEK product, hardware-ID and reported-TCB are checked.
/// This is not an RFC 5280 appraisal or a worker-admission decision.
pub struct SignatureFacts {
    report_sha256: [u8; 32],
    vcek_sha256: [u8; 32],
    measurement: [u8; 48],
    report_data: [u8; 64],
    guest_svn: u32,
    guest_policy: u64,
    validity: [(u64, u64); 3],
}

impl SignatureFacts {
    /// Digest of the exact received report, not a private task/content digest.
    pub const fn report_sha256(&self) -> &[u8; 32] {
        &self.report_sha256
    }

    /// Digest of the exact received canonical VCEK certificate.
    pub const fn vcek_sha256(&self) -> &[u8; 32] {
        &self.vcek_sha256
    }

    /// Signed launch measurement. Equality is not workload authorization.
    pub const fn measurement(&self) -> &[u8; 48] {
        &self.measurement
    }

    /// Signed guest security-version claim, not a vendor minimum decision.
    pub const fn guest_svn(&self) -> u32 {
        self.guest_svn
    }

    /// Remaining appraisal requirements, also present after fresh binding.
    pub const fn outstanding_appraisal(&self) -> &'static [OutstandingAppraisal] {
        &OUTSTANDING
    }

    fn check_time(&self, now: u64) -> Result<(), EvidenceError> {
        if self
            .validity
            .iter()
            .any(|&(start, end)| start > end || now < start || now > end)
        {
            return Err(EvidenceError::CertificateTime);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
