//! One-use, caller-bound observations of failed local stream handoffs, not custody receipts.

use prost::Message;
use serde::{Deserialize, Serialize};

use crate::ControlProtocolError;

/// Query only the caller's original unpredictable local request identifier.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PrivateStorageOutcomeRequest {
    /// Original 16-byte request ID; no provider, archive, path or signing key.
    #[prost(bytes = "vec", tag = "1")]
    pub original_request_id: Vec<u8>,
}

impl PrivateStorageOutcomeRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.original_request_id.len() != 16 {
            return Err(ControlProtocolError::Invalid("private storage outcome ID"));
        }
        Ok(())
    }
}

/// Availability in the querying Unix UID's short-lived local namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageOutcomeStatus {
    /// Missing, omitted at capacity, consumed, successfully completed, or already purged.
    Missing = 0,
    /// The original operation has not terminated; the query consumes nothing.
    Pending = 1,
    /// One failed post-READY handoff was observed and consumed by this query.
    Observed = 2,
    /// This exact retained observation expired; it has now been removed.
    Expired = 3,
}

/// Last locally entered boundary; never evidence of a provider commit or rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageOutcomePhase {
    /// No observation, allowed only for a non-observed query result.
    Unobserved = 0,
    /// Writing the initial READY frame, possibly only partially.
    ReadyWrite = 1,
    /// Reading the owner's signed request.
    LocalRequestRead = 2,
    /// Authenticating the owner's request.
    LocalRequestVerify = 3,
    /// Reading append ciphertext.
    LocalPayloadRead = 4,
    /// Verifying append ciphertext.
    LocalPayloadVerify = 5,
    /// Waiting for the existing resource admission.
    Admission = 6,
    /// Rechecking authorization before forwarding.
    RemoteRequestVerify = 7,
    /// Writing the signed request to the protected provider stream.
    RemoteRequestWrite = 8,
    /// Writing append ciphertext to that stream.
    RemotePayloadWrite = 9,
    /// Reading the provider receipt frame.
    RemoteReceiptRead = 10,
    /// Authenticating the provider receipt.
    RemoteReceiptVerify = 11,
    /// Reading the authorized range.
    RemotePayloadRead = 12,
    /// Verifying the range and final request validity.
    RemotePayloadVerify = 13,
    /// Forwarding the verified receipt to the local owner.
    LocalReceiptWrite = 14,
    /// Forwarding the authorized ciphertext range.
    LocalPayloadWrite = 15,
    /// Closing provider application TLS.
    ProviderTlsClose = 16,
    /// Closing the protected transport TLS.
    TransportTlsClose = 17,
    /// Rechecking the carrying route and policy.
    FinalRouteCheck = 18,
    /// Rechecking grant validity.
    FinalGrantCheck = 19,
    /// Rechecking offer and challenge validity.
    FinalLifetimeCheck = 20,
    /// Writing the existing final local success frame.
    TerminalWrite = 21,
}

/// Closed local error families; no formatted nested errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageOutcomeCategory {
    /// No failure observation.
    Unobserved = 0,
    /// Stream I/O, not evidence of a remote cause.
    Io = 1,
    /// Signed metadata authentication failed.
    Auth = 2,
    /// Invalid framing, state or metadata.
    Invalid = 3,
    /// Resource admission declined.
    Busy = 4,
    /// Local store or worker unavailable.
    Store = 5,
    /// Signed authority expired.
    Expired = 6,
    /// Randomness unavailable.
    Entropy = 7,
    /// An explicitly observed local budget elapsed.
    Timeout = 8,
    /// Policy or route authority check failed.
    Policy = 9,
    /// Other bounded local unavailability, including TLS closure.
    Unavailable = 10,
    /// The owning task or maintenance turn was cancelled, not a timeout claim.
    Cancelled = 11,
}

/// Exactly which existing local timeout fired.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageOutcomeDeadline {
    /// No local timeout was observed.
    None = 0,
    /// Whole agent operation budget.
    Operation = 1,
    /// Grant/offer-bounded agent exchange budget.
    Exchange = 2,
    /// Whole local-to-provider wire bridge budget.
    Bridge = 3,
    /// Inner provider wire operation budget.
    RemoteWire = 4,
}

/// Fixed-size outcome metadata. Never grants authority or asserts successful custody.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct PrivateStorageOutcome {
    /// Availability, scoped by both original request ID and actual Unix peer UID.
    #[prost(enumeration = "PrivateStorageOutcomeStatus", tag = "1")]
    pub status: i32,
    /// Actual local boundary, only when status is Observed.
    #[prost(enumeration = "PrivateStorageOutcomePhase", tag = "2")]
    pub phase: i32,
    /// Actual closed error family, only when status is Observed.
    #[prost(enumeration = "PrivateStorageOutcomeCategory", tag = "3")]
    pub category: i32,
    /// Existing deadline that elapsed, if any.
    #[prost(enumeration = "PrivateStorageOutcomeDeadline", tag = "4")]
    pub deadline: i32,
}

impl PrivateStorageOutcome {
    /// Reject unknown values and impossible status/deadline combinations.
    ///
    /// # Errors
    /// Rejects observations on missing results and counterfeit timeout combinations.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        let invalid = || ControlProtocolError::Invalid("private storage outcome");
        let status = PrivateStorageOutcomeStatus::try_from(self.status).map_err(|_| invalid())?;
        let phase = PrivateStorageOutcomePhase::try_from(self.phase).map_err(|_| invalid())?;
        let category =
            PrivateStorageOutcomeCategory::try_from(self.category).map_err(|_| invalid())?;
        let deadline =
            PrivateStorageOutcomeDeadline::try_from(self.deadline).map_err(|_| invalid())?;
        if status != PrivateStorageOutcomeStatus::Observed {
            return if self.phase == 0 && self.category == 0 && self.deadline == 0 {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if phase == PrivateStorageOutcomePhase::Unobserved
            || category == PrivateStorageOutcomeCategory::Unobserved
            || (category == PrivateStorageOutcomeCategory::Timeout)
                != (deadline != PrivateStorageOutcomeDeadline::None)
            || (deadline == PrivateStorageOutcomeDeadline::Bridge
                && !(2..=15).contains(&self.phase))
            || (deadline == PrivateStorageOutcomeDeadline::RemoteWire
                && !(7..=13).contains(&self.phase))
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult,
        control_request::Operation, control_response::Payload, decode_request, decode_response,
        encode_request, encode_response,
    };

    #[test]
    fn outcome_tags_roundtrip_without_reusing_quote_or_maintenance_tags() {
        let request = ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![2; 16],
            operation: Some(Operation::PrivateStorageOutcome(
                PrivateStorageOutcomeRequest {
                    original_request_id: vec![1; 16],
                },
            )),
        };
        let bytes = encode_request(&request).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), request);
        assert!(bytes.windows(2).any(|key| key == [0xfa, 0x02])); // field 47
        let response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![2; 16],
            result: ControlResult::Ok as i32,
            diagnostic_code: "PRIVATE_STORAGE_OUTCOME".into(),
            private_storage_remote_detail: None,
            payload: Some(Payload::PrivateStorageOutcome(PrivateStorageOutcome {
                status: PrivateStorageOutcomeStatus::Observed as i32,
                phase: PrivateStorageOutcomePhase::RemoteReceiptRead as i32,
                category: PrivateStorageOutcomeCategory::Io as i32,
                deadline: PrivateStorageOutcomeDeadline::None as i32,
            })),
        };
        let bytes = encode_response(&response).unwrap();
        assert_eq!(decode_response(&bytes).unwrap(), response);
        assert!(bytes.windows(2).any(|key| key == [0x9a, 0x02])); // field 35
    }

    #[test]
    fn outcome_rejects_unknown_enums_bad_ids_and_counterfeit_timeout_or_status() {
        for length in [0, 15, 17, 4096] {
            assert!(
                PrivateStorageOutcomeRequest {
                    original_request_id: vec![0; length],
                }
                .validate()
                .is_err()
            );
        }
        let valid = PrivateStorageOutcome {
            status: PrivateStorageOutcomeStatus::Observed as i32,
            phase: PrivateStorageOutcomePhase::RemoteReceiptRead as i32,
            category: PrivateStorageOutcomeCategory::Io as i32,
            deadline: PrivateStorageOutcomeDeadline::None as i32,
        };
        valid.validate().unwrap();
        for bad in [
            PrivateStorageOutcome {
                status: 99,
                ..valid
            },
            PrivateStorageOutcome {
                phase: 99,
                ..valid
            },
            PrivateStorageOutcome {
                category: 99,
                ..valid
            },
            PrivateStorageOutcome {
                deadline: 99,
                ..valid
            },
            PrivateStorageOutcome {
                status: PrivateStorageOutcomeStatus::Missing as i32,
                ..valid
            },
            PrivateStorageOutcome {
                category: PrivateStorageOutcomeCategory::Timeout as i32,
                ..valid
            },
            PrivateStorageOutcome {
                deadline: PrivateStorageOutcomeDeadline::Operation as i32,
                ..valid
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }
}
