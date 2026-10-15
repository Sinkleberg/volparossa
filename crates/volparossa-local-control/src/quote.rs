//! Explicit local quote authority and same-socket readiness, never raw hardware evidence.

use prost::Message;

use crate::ControlProtocolError;

#[cfg(test)]
mod confirmation_tests;

/// Operator authorization for exactly one requester on the existing protected provider.
#[derive(Clone, PartialEq, Message)]
pub struct QuoteAttachRequest {
    /// Explicit unprivileged listener address and port.
    #[prost(string, tag = "1")]
    pub bind_address: String,
    /// Existing policy-authorized provider hostname.
    #[prost(string, tag = "2")]
    pub advertised_hostname: String,
    /// Exact requester Ed25519 key, not a wildcard or discovery-derived permission.
    #[prost(bytes = "vec", tag = "3")]
    pub requester_key: Vec<u8>,
    /// Absolute local authorization deadline; the agent additionally checks the 600-second cap.
    #[prost(uint64, tag = "4")]
    pub expires_at: u64,
    /// Nonrefundable quote attempts, independent of the single firmware slot.
    #[prost(uint32, tag = "5")]
    pub maximum_attempts: u32,
    /// Absent keeps quote-only authority; version one explicitly permits key confirmation.
    #[prost(uint32, optional, tag = "6")]
    pub confirmation_version: Option<u32>,
}

/// Select one provider, then wait for route/TLS/authenticated quote-challenge readiness.
#[derive(Clone, PartialEq, Message)]
pub struct QuoteRemoteRequest {
    /// Independently selected provider Ed25519 key.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Explicit confirmation profile, never inferred from remote support.
    #[prost(uint32, optional, tag = "2")]
    pub confirmation_version: Option<u32>,
}

/// Content-free readiness. The following bounded binary frames are not generic control payloads.
#[derive(Clone, PartialEq, Message)]
pub struct QuoteReady {
    /// Exact selected provider.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Agent identity that will sign the quote request.
    #[prost(bytes = "vec", tag = "2")]
    pub requester_key: Vec<u8>,
    /// Exact negotiated mode; an opted-in caller must reject an absent version.
    #[prost(uint32, optional, tag = "3")]
    pub confirmation_version: Option<u32>,
}

fn key(bytes: &[u8]) -> Result<(), ControlProtocolError> {
    if bytes.len() != 32 || bytes.iter().all(|byte| *byte == 0) {
        return Err(ControlProtocolError::Invalid("quote identity"));
    }
    Ok(())
}

fn confirmation(version: Option<u32>) -> Result<(), ControlProtocolError> {
    if !matches!(version, None | Some(1)) {
        return Err(ControlProtocolError::Invalid("quote confirmation version"));
    }
    Ok(())
}

impl QuoteAttachRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        key(&self.requester_key)?;
        confirmation(self.confirmation_version)?;
        if self.bind_address.is_empty()
            || self.bind_address.len() > 128
            || self.advertised_hostname.is_empty()
            || self.advertised_hostname.len() > 253
            || self.expires_at == 0
            || !(1..=64).contains(&self.maximum_attempts)
        {
            return Err(ControlProtocolError::Invalid("quote attachment"));
        }
        Ok(())
    }
}

impl QuoteRemoteRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        confirmation(self.confirmation_version)?;
        key(&self.provider_key)
    }
}

impl QuoteReady {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        confirmation(self.confirmation_version)?;
        key(&self.provider_key)?;
        key(&self.requester_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CONTROL_PROTOCOL_VERSION, ControlRequest, Empty, control_request::Operation};

    #[test]
    fn quote_local_operations_are_distinct_bounded_and_roundtrip() {
        let attach = QuoteAttachRequest {
            bind_address: "127.0.0.1:8443".into(),
            advertised_hostname: "provider.example".into(),
            requester_key: vec![1; 32],
            expires_at: 1000,
            maximum_attempts: 1,
            confirmation_version: None,
        };
        for operation in [
            Operation::QuoteAttach(attach.clone()),
            Operation::QuoteDetach(Empty {}),
            Operation::QuoteRemote(QuoteRemoteRequest {
                provider_key: vec![2; 32],
                confirmation_version: None,
            }),
        ] {
            let request = ControlRequest {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![3; 16],
                operation: Some(operation),
            };
            assert_eq!(
                crate::decode_request(&crate::encode_request(&request).unwrap()).unwrap(),
                request
            );
        }
        for attempts in [0, 65, u32::MAX] {
            assert!(
                QuoteAttachRequest {
                    maximum_attempts: attempts,
                    ..attach.clone()
                }
                .validate()
                .is_err()
            );
        }
        for bytes in [vec![], vec![0; 32], vec![1; 31], vec![1; 33]] {
            assert!(
                QuoteRemoteRequest {
                    provider_key: bytes.clone(),
                    confirmation_version: None,
                }
                .validate()
                .is_err()
            );
            assert!(
                QuoteAttachRequest {
                    requester_key: bytes,
                    ..attach.clone()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            QuoteAttachRequest {
                expires_at: 0,
                ..attach
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn quote_ready_has_only_two_public_identity_fields() {
        let ready = QuoteReady {
            provider_key: vec![1; 32],
            requester_key: vec![2; 32],
            confirmation_version: None,
        };
        assert!(ready.validate().is_ok());
        assert_eq!(ready.encoded_len(), 68);
        assert!(
            QuoteReady {
                requester_key: vec![0; 32],
                ..ready
            }
            .validate()
            .is_err()
        );
    }
}
