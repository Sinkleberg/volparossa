//! Request-local pre-READY boundaries; no strings or inferred remote causes.

use std::{
    future::Future,
    sync::atomic::{AtomicI32, Ordering},
    time::Duration,
};

use tokio::{net::UnixStream, time::timeout};
use volparossa_local_control::{
    PrivateStorageDeadlineScope as Deadline, PrivateStorageRemoteDetail,
    PrivateStorageRemoteStage as Stage,
};

use super::{ContentError, until_requester_closed};

#[derive(Default)]
pub(super) struct Observation {
    // Shared references remain Send across the existing asynchronous control task.
    // All access belongs to that one task; no observer task or runtime identifiers.
    stage: AtomicI32,
    deadline: AtomicI32,
}

impl Observation {
    pub(super) fn reset(&self) {
        self.stage
            .store(Stage::Unobserved as i32, Ordering::Relaxed);
        self.deadline
            .store(Deadline::None as i32, Ordering::Relaxed);
    }

    pub(super) fn detail(&self) -> Option<PrivateStorageRemoteDetail> {
        let stage = self.stage.load(Ordering::Relaxed);
        let deadline_scope = self.deadline.load(Ordering::Relaxed);
        let detail = PrivateStorageRemoteDetail {
            stage,
            deadline_scope,
        };
        // No observation for policy/resource/cancel, or an inner deadline while
        // awaiting an uninstrumented policy recheck. Never invent that boundary.
        detail.validate().is_ok().then_some(detail)
    }

    pub(super) async fn boundary<T>(
        &self,
        stage: Stage,
        preparation: impl Future<Output = Result<T, ContentError>>,
    ) -> Result<T, ContentError> {
        self.reset();
        self.stage.store(stage as i32, Ordering::Relaxed);
        let result = preparation.await;
        if result.is_ok() {
            self.reset();
        }
        result
    }

    pub(super) async fn requester_boundary<T>(
        &self,
        stage: Stage,
        local: &mut UnixStream,
        preparation: impl Future<Output = Result<T, ContentError>>,
    ) -> Result<T, ContentError> {
        self.reset();
        let mut completed = false;
        let result = until_requester_closed(local, async {
            // Set the stage only if the existing biased cancellation gate actually
            // polls this future. An already closed requester starts no boundary.
            let result = self.boundary(stage, preparation).await;
            completed = true;
            result
        })
        .await;
        if !completed {
            self.reset();
        }
        result
    }

    pub(super) fn budget<T>(
        &self,
        scope: Deadline,
        duration: Duration,
        operation: impl Future<Output = Result<T, ContentError>>,
    ) -> impl Future<Output = Result<T, ContentError>> {
        // Construct the original timeout now, not lazily on our first poll: the
        // diagnostic wrapper must not shift the existing absolute deadline.
        let operation = timeout(duration, operation);
        async move {
            match operation.await {
                Ok(result) => result,
                Err(_) => {
                    self.deadline.store(scope as i32, Ordering::Relaxed);
                    Err(ContentError::Unavailable)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
