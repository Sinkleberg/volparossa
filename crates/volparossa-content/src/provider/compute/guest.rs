//! Process-owned guest quote preparation, not protected worker admission.
//!
//! An explicitly provisioned guest owner accepts one bounded public challenge,
//! generates its own ephemeral X25519 key, and requests the exact `REPORT_DATA`
//! through the fixed Linux guest device. The key never leaves this API, but is
//! process-owned, NOT hardware-nonexportable. Approved measured images, workload
//! authorization, vendor appraisal and actual protected execution remain required.
//!
//! Collection is synchronous: call it only from an already bounded blocking
//! execution context, never an async reactor. No task/thread is spawned here.
//! Cancellation erases the key without holding a mutex across the ioctl, but
//! does not pretend to interrupt firmware. The occupied slot remains held until
//! collection really returns or unwinds. Expiry is enforced and erases the key
//! on the next operation or `Drop`; there is no hidden expiry timer or cleanup claim.
//!
//! Requests/responses are small canonical payloads for an independently
//! authorized, authenticated provider stream. This module does not listen,
//! advertise, download collateral, accept task input or produce a worker permit.

mod wire;

pub use wire::{MAX_QUOTE_REQUEST_BYTES, MAX_QUOTE_RESPONSE_BYTES, QuoteRequest, QuoteResponse};

use std::{
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::private_message::RecipientKeyPair;

use super::attestation::session_report_data;

const MAX_OWNER_SECONDS: u64 = 600;
const MAX_ATTEMPTS: u16 = 64;

/// Closed guest preparation failures; no device errors or hardware IDs are logged.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum GuestError {
    /// Owner bounds are absent, expired or exceed the fixed preparation limits.
    #[error("invalid guest preparation limits")]
    Configuration,
    /// Noncanonical, unsupported or oversized request/response framing.
    #[error("invalid guest quote encoding")]
    Encoding,
    /// A slot is occupied or the nonrefundable attempt budget is exhausted.
    #[error("guest quote capacity unavailable")]
    Budget,
    /// This owner has already admitted the exact challenge.
    #[error("guest quote challenge replay")]
    Replay,
    /// Explicit cancellation, including owner cancellation.
    #[error("guest quote cancelled")]
    Cancelled,
    /// The owner/challenge expired or its observed clock moved backwards.
    #[error("guest quote expired")]
    Expired,
    /// Time, operating-system entropy or internal synchronized state failed.
    #[error("guest quote preparation unavailable")]
    Unavailable,
    /// No usable fixed Linux guest device, or this is not Linux.
    #[error("guest firmware device unavailable")]
    DeviceUnavailable,
    /// The actual firmware request returned an error; no fallback is attempted.
    #[error("guest firmware request failed")]
    Firmware,
    /// The exact collected version is not supported by the current v2 verifier.
    #[error("unsupported guest attestation report version {0}")]
    UnsupportedReport(u32),
    /// Length, VMPL or exact `REPORT_DATA` binding differs from the request.
    #[error("guest report binding failed")]
    ReportBinding,
}

/// Locally chosen owner limits, not permission granted by the remote challenge.
#[derive(Clone, Copy)]
pub struct GuestLimits {
    /// Absolute Unix deadline, at most 600 seconds after construction.
    pub expires_at: u64,
    /// Nonrefundable attempts, in 1..=64. Exactly one may occupy the owner at once.
    pub maximum_attempts: u16,
}

#[derive(Clone, Copy)]
struct Stamp {
    unix: u64,
    monotonic: Instant,
}

impl Stamp {
    fn now() -> Result<Self, GuestError> {
        Ok(Self {
            unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| GuestError::Unavailable)?
                .as_secs(),
            monotonic: Instant::now(),
        })
    }
}

// RecipientKeyPair already uses a Zeroizing secret and the pinned RFC 9180 KEM.
// Only generate() is used here: there is no guest import/private-key getter.
struct SessionKey(Mutex<Option<RecipientKeyPair>>);

impl SessionKey {
    fn erase(&self) {
        // Cleanup must still erase after a poisoned lock; ordinary use fails closed.
        drop(
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
    }

    fn check(&self) -> Result<(), GuestError> {
        if self.0.lock().map_err(|_| GuestError::Unavailable)?.is_none() {
            return Err(GuestError::Cancelled);
        }
        Ok(())
    }
}

struct OwnerState {
    cancelled: bool,
    remaining: u16,
    seen: Vec<[u8; 32]>,
    active: Option<Weak<SessionKey>>,
}

impl OwnerState {
    fn erase_active(&self) {
        if let Some(key) = self.active.as_ref().and_then(Weak::upgrade) {
            key.erase();
        }
    }
}

/// One finite guest owner. No `Clone`/deserializer, default policy or background work.
/// A session borrows this owner and retains its slot through collection and response.
pub struct GuestSessionOwner {
    limits: GuestLimits,
    created: Stamp,
    deadline: Instant,
    state: Mutex<OwnerState>,
}

impl GuestSessionOwner {
    /// Construct local bounds; no firmware access or thread starts here.
    ///
    /// # Errors
    /// Rejects unavailable time, expired/overflowing bounds or more than 64 attempts.
    pub fn new(limits: GuestLimits) -> Result<Self, GuestError> {
        Self::new_at(limits, Stamp::now()?)
    }

    fn new_at(limits: GuestLimits, now: Stamp) -> Result<Self, GuestError> {
        let seconds = limits
            .expires_at
            .checked_sub(now.unix)
            .ok_or(GuestError::Configuration)?;
        if !(1..=MAX_OWNER_SECONDS).contains(&seconds)
            || !(1..=MAX_ATTEMPTS).contains(&limits.maximum_attempts)
        {
            return Err(GuestError::Configuration);
        }
        let deadline = now
            .monotonic
            .checked_add(Duration::from_secs(seconds))
            .ok_or(GuestError::Configuration)?;
        Ok(Self {
            limits,
            created: now,
            deadline,
            state: Mutex::new(OwnerState {
                cancelled: false,
                remaining: limits.maximum_attempts,
                seen: Vec::with_capacity(usize::from(limits.maximum_attempts)),
                active: None,
            }),
        })
    }

    /// Cancel all current/future sessions and erase their process-owned key.
    /// An in-flight firmware call retains its slot until it actually returns.
    pub fn cancel(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.cancelled = true;
        state.erase_active();
    }

    fn check_time(&self, now: Stamp) -> Result<(), GuestError> {
        if now.unix < self.created.unix
            || now.unix >= self.limits.expires_at
            || now.monotonic < self.created.monotonic
            || now.monotonic >= self.deadline
        {
            return Err(GuestError::Expired);
        }
        Ok(())
    }

    /// Admit one canonical fresh challenge and generate a new process-owned key.
    /// Admission consumes a nonrefundable attempt, including entropy/firmware failure.
    /// Incoming requests are not authority to expose the device: the caller must
    /// authorize the requester before invoking this method.
    ///
    /// # Errors
    /// Rejects cancellation, expiry, replay, occupied capacity or unavailable entropy.
    pub fn begin(&self, request: QuoteRequest) -> Result<GuestSession<'_>, GuestError> {
        self.begin_at(request, Stamp::now()?)
    }

    fn begin_at(&self, request: QuoteRequest, now: Stamp) -> Result<GuestSession<'_>, GuestError> {
        let mut state = self.state.lock().map_err(|_| GuestError::Unavailable)?;
        if state.cancelled {
            return Err(GuestError::Cancelled);
        }
        if let Err(error) = self.check_time(now) {
            state.erase_active();
            return Err(error);
        }
        request.check_time(now.unix)?;
        if state.active.is_some() || state.remaining == 0 {
            return Err(GuestError::Budget);
        }
        let challenge_hash = request.sha256();
        if state.seen.contains(&challenge_hash) {
            return Err(GuestError::Replay);
        }
        let expires_at = request.expires_at.min(self.limits.expires_at);
        let deadline = now
            .monotonic
            .checked_add(Duration::from_secs(expires_at - now.unix))
            .ok_or(GuestError::Expired)?;
        state.remaining -= 1;
        state.seen.push(challenge_hash);
        let key = RecipientKeyPair::generate().map_err(|_| GuestError::Unavailable)?;
        let public_key = *key.public_key();
        let key = Arc::new(SessionKey(Mutex::new(Some(key))));
        state.active = Some(Arc::downgrade(&key));
        Ok(GuestSession {
            owner: self,
            key,
            request,
            public_key,
            created: now,
            expires_at,
            deadline,
        })
    }
}

impl Drop for GuestSessionOwner {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Cancellation authority for one session only. It cannot access or resurrect a key.
/// Clones may cancel; keeping them alive does not retain the owner's execution slot.
#[derive(Clone)]
pub struct GuestCancellation(Arc<SessionKey>);

impl GuestCancellation {
    /// Erase the session key now; does not claim the firmware ioctl has stopped.
    pub fn cancel(&self) {
        self.0.erase();
    }
}

/// Unique one-shot preparation. The key and occupied slot live through the ioctl.
pub struct GuestSession<'a> {
    owner: &'a GuestSessionOwner,
    key: Arc<SessionKey>,
    request: QuoteRequest,
    public_key: [u8; 32],
    created: Stamp,
    expires_at: u64,
    deadline: Instant,
}

impl<'a> GuestSession<'a> {
    /// Obtain cancellation authority without sharing the private key or slot.
    pub fn cancellation(&self) -> GuestCancellation {
        GuestCancellation(Arc::clone(&self.key))
    }

    /// Cancel and drop a session which is not currently owned by collection.
    pub fn cancel(self) {}

    fn check_at(&self, now: Stamp) -> Result<(), GuestError> {
        let result = (|| {
            let state = self.owner.state.lock().map_err(|_| GuestError::Unavailable)?;
            if state.cancelled {
                return Err(GuestError::Cancelled);
            }
            self.owner.check_time(now)?;
            if now.unix < self.created.unix
                || now.unix >= self.expires_at
                || now.monotonic < self.created.monotonic
                || now.monotonic >= self.deadline
            {
                return Err(GuestError::Expired);
            }
            self.key.check()
        })();
        if result.is_err() {
            self.key.erase();
        }
        result
    }

    /// Request a quote synchronously on fixed `/dev/sev-guest`, message version 1,
    /// VMPL 0. Message version 1 does NOT force firmware report version 2.
    /// No unbounded task is spawned and cancellation cannot release the occupied
    /// slot while this call still runs. Unsupported actual report versions reject.
    ///
    /// # Errors
    /// Rejects device/firmware errors, expiry/cancellation, or report binding errors.
    pub fn collect_quote(self) -> Result<GuestQuoteSession<'a>, GuestError> {
        self.collect_source(ReportSource::Firmware)
    }

    fn collect_source(self, source: ReportSource) -> Result<GuestQuoteSession<'a>, GuestError> {
        self.check_at(Stamp::now()?)?;
        let data = session_report_data(&self.request.challenge, &self.public_key)
            .map_err(|_| GuestError::Encoding)?;
        let report = source.fetch(data)?;
        self.check_at(Stamp::now()?)?;
        let response = QuoteResponse::new(&self.request, self.public_key, report)?;
        self.check_at(Stamp::now()?)?;
        Ok(GuestQuoteSession {
            session: self,
            response,
        })
    }
}

impl Drop for GuestSession<'_> {
    fn drop(&mut self) {
        self.key.erase();
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = None;
    }
}

/// Process-owned key retained with one collected quote, not an execution permit.
/// Dropping this value erases the key and releases the occupied owner slot.
pub struct GuestQuoteSession<'a> {
    session: GuestSession<'a>,
    response: QuoteResponse,
}

impl GuestQuoteSession<'_> {
    /// Check current owner/session validity before exposing public quote bytes.
    /// The returned response remains untrusted evidence, not a live capability.
    ///
    /// # Errors
    /// Rejects cancellation, expiry or clock failure; an observed expiry erases the key.
    pub fn response(&self) -> Result<&QuoteResponse, GuestError> {
        let now = match Stamp::now() {
            Ok(now) => now,
            Err(error) => {
                self.session.key.erase();
                return Err(error);
            }
        };
        self.session.check_at(now)?;
        Ok(&self.response)
    }

    /// Erase this session's key without granting access to its secret bytes.
    pub fn cancellation(&self) -> GuestCancellation {
        self.session.cancellation()
    }

    /// Cancel and discard the prepared session; no worker or task was started.
    pub fn cancel(self) {}
}

enum ReportSource {
    Firmware,
    #[cfg(test)]
    Fake(Box<dyn FnOnce([u8; 64]) -> Result<Vec<u8>, GuestError> + Send>),
}

impl ReportSource {
    fn fetch(self, data: [u8; 64]) -> Result<Vec<u8>, GuestError> {
        match self {
            Self::Firmware => firmware_report(data),
            #[cfg(test)]
            Self::Fake(source) => source(data),
        }
    }
}

#[cfg(target_os = "linux")]
fn firmware_report(data: [u8; 64]) -> Result<Vec<u8>, GuestError> {
    let mut firmware =
        sev::firmware::guest::Firmware::open().map_err(|_| GuestError::DeviceUnavailable)?;
    firmware
        .get_report(Some(1), Some(data), Some(0))
        .map_err(|_| GuestError::Firmware)
}

#[cfg(not(target_os = "linux"))]
fn firmware_report(_data: [u8; 64]) -> Result<Vec<u8>, GuestError> {
    Err(GuestError::DeviceUnavailable)
}

#[cfg(test)]
mod tests;
