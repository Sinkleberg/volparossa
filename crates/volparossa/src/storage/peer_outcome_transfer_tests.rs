//! Production CLI error path with signed IPC framing; not a remote-custody proof.

use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use volparossa_content::private_storage::{
    LeaseId,
    protocol::{MAX_REQUEST_BYTES, SignedStorageRequest, StorageChallenge},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlResponse, PrivateStorageOutcome,
    PrivateStorageOutcomeCategory, PrivateStorageOutcomeDeadline, PrivateStorageOutcomePhase,
    PrivateStorageOutcomeStatus, PrivateStorageReady, control_request::Operation,
    control_response::Payload, read_request, write_response,
};

use super::super::diagnostics::{Boundary, Diagnostics, Stage};

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One signed request, lost receipt and caller-bound query must share the exact IPC ID."
)]
async fn wire_failure_drops_original_stream_and_queries_exact_id_without_retrying_finalize() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let (provider, owner, grant) = fixture_grant();
    let server_grant = grant.clone();
    let server = tokio::spawn(async move {
        let (mut local, _) = listener.accept().await.unwrap();
        let uid = local.peer_cred().unwrap().uid();
        let original = read_request(&mut local).await.unwrap();
        assert!(matches!(
            original.operation,
            Some(Operation::PrivateStorageRemote(_))
        ));
        let now = crate::storage::now().unwrap();
        let challenge = StorageChallenge::issue(
            &provider,
            &server_grant,
            Validity {
                created: now,
                expires: now + 120,
            },
        )
        .unwrap();
        write_response(
            &mut local,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: original.request_id.clone(),
                result: 0,
                diagnostic_code: "PRIVATE_STORAGE_READY".into(),
                private_storage_remote_detail: None,
                payload: Some(Payload::PrivateStorageReady(PrivateStorageReady {
                    provider_key: provider.verifying_key().to_bytes().to_vec(),
                    challenge: challenge.encode(),
                })),
            },
        )
        .await
        .unwrap();
        let length = local.read_u32().await.unwrap() as usize;
        assert!((1..=MAX_REQUEST_BYTES).contains(&length));
        let mut frame = vec![0; length];
        local.read_exact(&mut frame).await.unwrap();
        let signed = SignedStorageRequest::decode_and_verify(
            &frame,
            &server_grant,
            &challenge,
            crate::storage::now().unwrap(),
        )
        .unwrap();
        assert!(matches!(signed.operation(), StorageOperation::Finalize));
        // A receipt-side EOF must drop the owner's entire original stream before query.
        local.shutdown().await.unwrap();
        assert_eq!(local.read(&mut [0]).await.unwrap(), 0);
        let (mut query_stream, _) = listener.accept().await.unwrap();
        assert_eq!(query_stream.peer_cred().unwrap().uid(), uid);
        let query = read_request(&mut query_stream).await.unwrap();
        let Some(Operation::PrivateStorageOutcome(outcome_request)) = query.operation else {
            panic!("a diagnostic query must not retry Finalize");
        };
        assert_eq!(outcome_request.original_request_id, original.request_id);
        write_response(
            &mut query_stream,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: query.request_id,
                result: 0,
                diagnostic_code: "PRIVATE_STORAGE_OUTCOME".into(),
                private_storage_remote_detail: None,
                payload: Some(Payload::PrivateStorageOutcome(PrivateStorageOutcome {
                    status: PrivateStorageOutcomeStatus::Observed as i32,
                    phase: PrivateStorageOutcomePhase::RemoteReceiptRead as i32,
                    category: PrivateStorageOutcomeCategory::Io as i32,
                    deadline: PrivateStorageOutcomeDeadline::None as i32,
                })),
            },
        )
        .await
        .unwrap();
    });
    let target = StorageTarget {
        archive_id: [5; 32],
        lease_id: Some(LeaseId::from_bytes([6; 16])),
        ciphertext_bytes: 32,
        sha256: [7; 32],
    };
    let operation = StorageOperation::Finalize;
    let error = transfer::remote(&socket, &grant, &owner, target, operation, &[])
        .await
        .err()
        .unwrap();
    server.await.unwrap();
    assert!(matches!(
        error.downcast_ref::<wire::WireError>(),
        Some(wire::WireError::Io(_))
    ));
    assert!(matches!(
        error.downcast_ref::<Boundary>().unwrap().stage,
        Stage::WireReceipt
    ));
    let mut diagnostics = Diagnostics::default();
    diagnostics.push(0, &error, Boundary::new(operation, Stage::Unknown));
    let report = serde_json::to_value(diagnostics).unwrap();
    assert_eq!(report["version"], 5);
    assert_eq!(report["failures"][0]["operation"], "finalize");
    assert_eq!(report["failures"][0]["category"], "io");
    assert_eq!(report["failures"][0]["agent_outcome"]["status"], "observed");
    assert_eq!(
        report["failures"][0]["agent_outcome"]["detail"]["phase"],
        "remote_receipt_read"
    );
    for private in [
        "request_id",
        "provider_key",
        "archive_id",
        "lease_id",
        "sha256",
    ] {
        assert!(!report.to_string().contains(private));
    }
}
