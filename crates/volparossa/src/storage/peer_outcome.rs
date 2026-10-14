//! Best-effort local observations after a failed handoff, never a storage-operation retry.

use std::{fmt, path::Path, time::Duration};

use serde::{Deserialize, Serialize};
use volparossa_local_control::{
    PrivateStorageOutcome, PrivateStorageOutcomeCategory, PrivateStorageOutcomeDeadline,
    PrivateStorageOutcomePhase, PrivateStorageOutcomeRequest, PrivateStorageOutcomeStatus,
    control_request::Operation, control_response::Payload,
};

const QUERY_BUDGET: Duration = Duration::from_secs(1);
const PENDING_INTERVAL: Duration = Duration::from_millis(25);
const MAX_QUERIES: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Observed,
    Missing,
    Pending,
    Expired,
    QueryFailed,
    QueryTimeout,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Detail {
    phase: PrivateStorageOutcomePhase,
    category: PrivateStorageOutcomeCategory,
    deadline_scope: PrivateStorageOutcomeDeadline,
}

/// Closed error context. It cannot carry the original ID, paths, keys or free-form errors.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentOutcome {
    status: Status,
    #[serde(deserialize_with = "Option::deserialize")]
    detail: Option<Detail>,
}

impl AgentOutcome {
    fn status(status: Status) -> Self {
        Self {
            status,
            detail: None,
        }
    }

    fn from_wire(outcome: PrivateStorageOutcome) -> Option<Self> {
        outcome.validate().ok()?;
        Some(
            match PrivateStorageOutcomeStatus::try_from(outcome.status).ok()? {
                PrivateStorageOutcomeStatus::Missing => Self::status(Status::Missing),
                PrivateStorageOutcomeStatus::Pending => Self::status(Status::Pending),
                PrivateStorageOutcomeStatus::Expired => Self::status(Status::Expired),
                PrivateStorageOutcomeStatus::Observed => Self {
                    status: Status::Observed,
                    detail: Some(Detail {
                        phase: PrivateStorageOutcomePhase::try_from(outcome.phase).ok()?,
                        category: PrivateStorageOutcomeCategory::try_from(outcome.category).ok()?,
                        deadline_scope: PrivateStorageOutcomeDeadline::try_from(outcome.deadline)
                            .ok()?,
                    }),
                },
            },
        )
    }

    pub(super) fn valid(self) -> bool {
        match (self.status, self.detail) {
            (Status::Observed, Some(detail)) => PrivateStorageOutcome {
                status: PrivateStorageOutcomeStatus::Observed as i32,
                phase: detail.phase as i32,
                category: detail.category as i32,
                deadline: detail.deadline_scope as i32,
            }
            .validate()
            .is_ok(),
            (Status::Observed, None) | (_, Some(_)) => false,
            (_, None) => true,
        }
    }
}

impl fmt::Display for AgentOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private storage local outcome observation")
    }
}

impl std::error::Error for AgentOutcome {}

/// Query only after dropping the original stream. Missing includes an observation omitted
/// at capacity; it proves neither provider failure nor absent custody. Older agents may reject.
pub(super) async fn query(socket: &Path, original_request_id: &[u8]) -> AgentOutcome {
    tokio::time::timeout(QUERY_BUDGET, async {
        for attempt in 0..MAX_QUERIES {
            let response = crate::control::request(
                socket,
                Operation::PrivateStorageOutcome(PrivateStorageOutcomeRequest {
                    original_request_id: original_request_id.to_vec(),
                }),
            )
            .await;
            let outcome = match response {
                Ok(response) => match response.payload {
                    Some(Payload::PrivateStorageOutcome(outcome)) => {
                        AgentOutcome::from_wire(outcome)
                    }
                    _ => None,
                },
                Err(_) => None,
            };
            let Some(outcome) = outcome else {
                return AgentOutcome::status(Status::QueryFailed);
            };
            if outcome.status != Status::Pending || attempt + 1 == MAX_QUERIES {
                return outcome;
            }
            tokio::time::sleep(PENDING_INTERVAL).await;
        }
        // MAX_QUERIES is nonzero; no unbounded polling or registry retention refresh.
        AgentOutcome::status(Status::Pending)
    })
    .await
    .unwrap_or_else(|_| AgentOutcome::status(Status::QueryTimeout))
}

#[cfg(test)]
#[path = "peer_outcome_tests.rs"]
mod tests;
