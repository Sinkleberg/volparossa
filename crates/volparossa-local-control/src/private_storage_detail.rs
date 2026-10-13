//! Closed pre-READY observations, not a diagnosis of a remote provider's cause.

use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{ControlProtocolError, ControlResponse, ControlResult, control_response::Payload};

/// Last polled private-storage preparation boundary; never a remote denial claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageRemoteStage {
    /// No preparation boundary was observed, for example while awaiting admission.
    Unobserved = 0,
    /// Establishing the existing protected client route.
    RouteConnect = 1,
    /// Selecting the route's current content discovery control.
    ControlSelection = 2,
    /// Looking up the independently selected provider.
    ProviderLookup = 3,
    /// Checking the returned provider count and identity.
    ProviderCardinality = 4,
    /// Checking the selected offer's remaining validity.
    OfferValidity = 5,
    /// Opening the selected provider's protected stream.
    StreamOpen = 6,
    /// Performing the provider TLS handshake.
    TlsHandshake = 7,
    /// Beginning the original signed-grant challenge exchange.
    Challenge = 8,
}

/// Which existing local deadline actually elapsed, not why the remote work stalled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum PrivateStorageDeadlineScope {
    /// Neither enclosing local timeout was observed to elapse.
    None = 0,
    /// The outer complete private-storage operation budget elapsed.
    Operation = 1,
    /// The inner grant/offer-bounded exchange budget elapsed.
    Exchange = 2,
}

/// Optional bounded detail on a failed initial private-storage control response.
/// Old peers ignore this additive field and still receive the same result/code/Ack.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct PrivateStorageRemoteDetail {
    /// Closed observed preparation boundary.
    #[prost(enumeration = "PrivateStorageRemoteStage", tag = "1")]
    pub stage: i32,
    /// Closed enclosing timeout observation.
    #[prost(enumeration = "PrivateStorageDeadlineScope", tag = "2")]
    pub deadline_scope: i32,
}

impl PrivateStorageRemoteDetail {
    /// Validate the same closed stage/deadline matrix used by wire and JSON readers.
    ///
    /// # Errors
    /// Rejects unknown enums and combinations this observer cannot produce.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        let stage = PrivateStorageRemoteStage::try_from(self.stage)
            .map_err(|_| ControlProtocolError::Invalid("private storage detail stage"))?;
        let deadline = PrivateStorageDeadlineScope::try_from(self.deadline_scope)
            .map_err(|_| ControlProtocolError::Invalid("private storage detail deadline"))?;
        let valid = match deadline {
            PrivateStorageDeadlineScope::None => stage != PrivateStorageRemoteStage::Unobserved,
            PrivateStorageDeadlineScope::Operation => true,
            PrivateStorageDeadlineScope::Exchange => matches!(
                stage,
                PrivateStorageRemoteStage::StreamOpen
                    | PrivateStorageRemoteStage::TlsHandshake
                    | PrivateStorageRemoteStage::Challenge
            ),
        };
        if !valid {
            return Err(ControlProtocolError::Invalid(
                "private storage detail combination",
            ));
        }
        Ok(())
    }

    /// Validate a closed failure code/result against this observed detail.
    ///
    /// # Errors
    /// Rejects success, other codes/results, and a timeout without the existing unavailable result.
    pub fn validate_rejection(
        &self,
        result: ControlResult,
        code: &str,
    ) -> Result<(), ControlProtocolError> {
        self.validate()?;
        let expected = match code {
            "CONTENT_INVALID" => ControlResult::InvalidRequest,
            "CONTENT_UNAVAILABLE" => ControlResult::Unavailable,
            "CONTENT_BUSY" => ControlResult::InvalidState,
            "CONTENT_POLICY" => ControlResult::Policy,
            _ => return Err(ControlProtocolError::Invalid("private storage detail code")),
        };
        if result != expected
            || (self.deadline_scope != PrivateStorageDeadlineScope::None as i32
                && result != ControlResult::Unavailable)
        {
            return Err(ControlProtocolError::Invalid(
                "private storage detail result",
            ));
        }
        Ok(())
    }
}

pub(super) fn validate(response: &ControlResponse) -> Result<(), ControlProtocolError> {
    let Some(detail) = response.private_storage_remote_detail else {
        return Ok(());
    };
    let result = ControlResult::try_from(response.result)
        .map_err(|_| ControlProtocolError::Invalid("result"))?;
    detail.validate_rejection(result, &response.diagnostic_code)?;
    if !matches!(response.payload, Some(Payload::Ack(_))) {
        return Err(ControlProtocolError::Invalid(
            "private storage detail envelope",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
