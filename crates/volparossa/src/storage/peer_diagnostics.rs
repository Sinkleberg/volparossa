//! Bounded owner-side transfer observations, never provider denial or custody proof.

use std::{fmt, io};

use anyhow::Error;
use serde::{Deserialize, Serialize};
use volparossa_content::private_storage::{
    protocol::{ProtocolError, StorageOperation},
    wire::WireError,
};

const MAX_FAILURES: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Operation {
    Prepare,
    Reserve,
    Progress,
    Append,
    Finalize,
    Renew,
    ReadRange,
    Delete,
}

impl From<StorageOperation> for Operation {
    fn from(operation: StorageOperation) -> Self {
        match operation {
            StorageOperation::Reserve { .. } => Self::Reserve,
            StorageOperation::Progress => Self::Progress,
            StorageOperation::Append { .. } => Self::Append,
            StorageOperation::Finalize => Self::Finalize,
            StorageOperation::Renew { .. } => Self::Renew,
            StorageOperation::ReadRange { .. } => Self::ReadRange,
            StorageOperation::Delete => Self::Delete,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stage {
    JournalOpen,
    Authorization,
    AgentReady,
    Challenge,
    SignedRequest,
    WireReceipt,
    AgentTerminal,
    Accounting,
    LocalInput,
    ReceiptValidation,
    JournalSave,
    Deadline,
    Unknown,
}

/// This context contains no runtime strings, keys, archive IDs, paths or payload.
#[derive(Clone, Copy, Debug)]
pub(super) struct Boundary {
    pub(super) operation: Operation,
    pub(super) stage: Stage,
}

impl Boundary {
    pub(super) fn new(operation: StorageOperation, stage: Stage) -> Self {
        Self {
            operation: operation.into(),
            stage,
        }
    }
}

impl fmt::Display for Boundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private storage transfer boundary failed")
    }
}

impl std::error::Error for Boundary {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Category {
    Io,
    Timeout,
    Protocol,
    AgentRejected,
    Invalid,
    Busy,
    Store,
    Unknown,
}

#[derive(Debug, Deserialize, Serialize)]
enum AgentCode {
    #[serde(rename = "CONTENT_INVALID")]
    Invalid,
    #[serde(rename = "CONTENT_UNAVAILABLE")]
    Unavailable,
    #[serde(rename = "CONTENT_BUSY")]
    Busy,
    #[serde(rename = "CONTENT_POLICY")]
    Policy,
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    fragment_index: Option<usize>,
    copy_index: usize,
    operation: Operation,
    stage: Stage,
    category: Category,
    agent_code: Option<AgentCode>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Diagnostics {
    version: u8,
    failures: Vec<Failure>,
    omitted_failures: usize,
}

impl Default for Diagnostics {
    fn default() -> Self {
        Self {
            version: 1,
            failures: Vec::new(),
            omitted_failures: 0,
        }
    }
}

impl Diagnostics {
    pub(super) fn push(&mut self, copy_index: usize, error: &Error, fallback: Boundary) {
        if self.failures.len() == MAX_FAILURES {
            self.omitted_failures += 1;
            return;
        }
        let boundary = error
            .downcast_ref::<Boundary>()
            .copied()
            .unwrap_or(fallback);
        let (category, agent_code) = classify(error);
        self.failures.push(Failure {
            fragment_index: None,
            copy_index,
            operation: boundary.operation,
            stage: boundary.stage,
            category,
            agent_code,
        });
    }

    /// Only merges this executable's own bounded replica report, never peer JSON.
    pub(super) fn append_fragment(
        &mut self,
        fragment_index: usize,
        report: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let child: Self = serde_json::from_value(report["deposit_diagnostics"].clone())?;
        self.omitted_failures += child.omitted_failures;
        for mut failure in child.failures {
            if self.failures.len() == MAX_FAILURES {
                self.omitted_failures += 1;
            } else {
                failure.fragment_index = Some(fragment_index);
                self.failures.push(failure);
            }
        }
        Ok(())
    }
}

fn classify(error: &Error) -> (Category, Option<AgentCode>) {
    if let Some(rejected) = error.downcast_ref::<crate::control::AgentRejected>() {
        let code = match rejected.diagnostic_code.as_str() {
            "CONTENT_INVALID" => AgentCode::Invalid,
            "CONTENT_UNAVAILABLE" => AgentCode::Unavailable,
            "CONTENT_BUSY" => AgentCode::Busy,
            "CONTENT_POLICY" => AgentCode::Policy,
            _ => AgentCode::Unknown,
        };
        return (Category::AgentRejected, Some(code));
    }
    if error
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some()
    {
        return (Category::Timeout, None);
    }
    if let Some(wire) = error.downcast_ref::<WireError>() {
        return (
            match wire {
                WireError::Io(_) => Category::Io,
                WireError::Protocol(_) => Category::Protocol,
                WireError::Invalid => Category::Invalid,
                WireError::Busy => Category::Busy,
                WireError::Store => Category::Store,
                WireError::Timeout => Category::Timeout,
            },
            None,
        );
    }
    if error.downcast_ref::<ProtocolError>().is_some() {
        return (Category::Protocol, None);
    }
    if let Some(control) = error.downcast_ref::<volparossa_local_control::ControlProtocolError>() {
        return (
            match control {
                volparossa_local_control::ControlProtocolError::Io(_) => Category::Io,
                volparossa_local_control::ControlProtocolError::Decode(_)
                | volparossa_local_control::ControlProtocolError::TooLarge
                | volparossa_local_control::ControlProtocolError::Invalid(_) => Category::Invalid,
            },
            None,
        );
    }
    if error.downcast_ref::<io::Error>().is_some() {
        return (Category::Io, None);
    }
    (Category::Unknown, None)
}

#[cfg(test)]
#[path = "peer_diagnostics_tests.rs"]
mod tests;
