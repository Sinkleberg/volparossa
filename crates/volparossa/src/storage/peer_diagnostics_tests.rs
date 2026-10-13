//! Synthetic boundary/error tests; none proves a protected route or remote denial.

use super::*;

fn value(error: &Error) -> serde_json::Value {
    let mut diagnostics = Diagnostics::default();
    diagnostics.push(
        1,
        error,
        Boundary {
            operation: Operation::Prepare,
            stage: Stage::Unknown,
        },
    );
    serde_json::to_value(diagnostics).unwrap()
}

#[test]
fn closed_diagnostic_preserves_typed_boundary_without_private_error_text() {
    let error = Error::new(io::Error::other(
        "/private/owner.key secret-key provider-id",
    ))
    .context(Boundary::new(
        StorageOperation::Finalize,
        Stage::JournalSave,
    ));
    let report = value(&error);
    assert_eq!(
        report["failures"][0],
        serde_json::json!({
            "fragment_index": null, "copy_index": 1, "operation": "finalize",
            "stage": "journal_save", "category": "io", "agent_code": null
        })
    );
    let encoded = report.to_string();
    for secret in ["private", "owner.key", "secret-key", "provider-id"] {
        assert!(!encoded.contains(secret));
    }
    let unknown = value(&anyhow::anyhow!("CONTENT_BUSY provider quota /secret"));
    assert_eq!(unknown["failures"][0]["category"], "unknown");
    assert!(unknown["failures"][0]["agent_code"].is_null());
    // The real terminal reader wraps EOF in the typed local-control error.
    let closed = value(
        &Error::new(volparossa_local_control::ControlProtocolError::Io(
            io::Error::from(io::ErrorKind::UnexpectedEof),
        ))
        .context(Boundary::new(
            StorageOperation::Reserve { expires_at: 123 },
            Stage::AgentTerminal,
        )),
    );
    assert_eq!(closed["failures"][0]["category"], "io");
    assert_eq!(closed["failures"][0]["stage"], "agent_terminal");
}

#[test]
fn all_wire_error_families_remain_observations_not_invented_provider_denials() {
    let cases = [
        (
            WireError::Io(io::Error::from(io::ErrorKind::UnexpectedEof)),
            "io",
        ),
        (WireError::Protocol(ProtocolError::Expired), "protocol"),
        (WireError::Invalid, "invalid"),
        (WireError::Busy, "busy"),
        (WireError::Store, "store"),
        (WireError::Timeout, "timeout"),
    ];
    for (error, expected) in cases {
        let report = value(&Error::new(error).context(Boundary::new(
            StorageOperation::Reserve { expires_at: 123 },
            Stage::WireReceipt,
        )));
        assert_eq!(report["failures"][0]["category"], expected);
        assert_eq!(report["failures"][0]["stage"], "wire_receipt");
        assert!(report["failures"][0]["agent_code"].is_null());
    }
}

#[tokio::test]
async fn agent_code_requires_actual_correlated_rejection_and_is_closed() {
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, Empty, control_response::Payload,
        write_response,
    };
    for (code, expected) in [
        ("CONTENT_INVALID", "CONTENT_INVALID"),
        ("CONTENT_UNAVAILABLE", "CONTENT_UNAVAILABLE"),
        ("CONTENT_BUSY", "CONTENT_BUSY"),
        ("CONTENT_POLICY", "CONTENT_POLICY"),
        ("PRIVATE_UNLISTED_CODE", "unknown"),
    ] {
        let (mut owner, mut agent) = tokio::net::UnixStream::pair().unwrap();
        write_response(
            &mut agent,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: vec![1; 16],
                result: ControlResult::Unavailable as i32,
                diagnostic_code: code.into(),
                payload: Some(Payload::Ack(Empty {})),
            },
        )
        .await
        .unwrap();
        let error = crate::control::finish_request(&mut owner, &[1; 16])
            .await
            .unwrap_err();
        let report =
            value(&error.context(Boundary::new(StorageOperation::Progress, Stage::AgentReady)));
        assert_eq!(report["failures"][0]["category"], "agent_rejected");
        assert_eq!(report["failures"][0]["agent_code"], expected);
        assert!(!report.to_string().contains("private"));
        assert!(!report.to_string().contains("secret"));
        assert!(!report.to_string().contains("PRIVATE_UNLISTED_CODE"));
    }
}

#[tokio::test]
async fn actual_timeout_error_is_typed_without_exporting_context_text() {
    let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
        .await
        .unwrap_err();
    let report = value(
        &Error::new(elapsed).context(Boundary::new(StorageOperation::Finalize, Stage::Deadline)),
    );
    assert_eq!(report["failures"][0]["category"], "timeout");
    assert_eq!(report["failures"][0]["stage"], "deadline");
    assert!(report["failures"][0]["agent_code"].is_null());
}

#[test]
fn fragment_aggregation_retains_first_eight_failures_and_exact_omission_count() {
    let mut parent = Diagnostics::default();
    for fragment in 0..256 {
        let mut child = Diagnostics::default();
        for copy in 0..8 {
            child.push(
                copy,
                &anyhow::anyhow!("synthetic"),
                Boundary {
                    operation: Operation::Prepare,
                    stage: Stage::JournalOpen,
                },
            );
        }
        parent
            .append_fragment(fragment, &serde_json::json!({"deposit_diagnostics": child}))
            .unwrap();
    }
    let report = serde_json::to_value(parent).unwrap();
    assert_eq!(report["omitted_failures"], 2040);
    let failures = report["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 8);
    for (copy, failure) in failures.iter().enumerate() {
        assert_eq!(failure["fragment_index"], 0);
        assert_eq!(failure["copy_index"], copy);
    }
    assert!(report.to_string().len() < 2048);
}

#[test]
fn diagnostic_enum_decoding_rejects_uncontrolled_fields_and_categories() {
    let report = value(&anyhow::anyhow!("synthetic"));
    for field in ["operation", "stage", "category", "agent_code"] {
        let mut changed = report.clone();
        changed["failures"][0][field] = "private-arbitrary-text".into();
        assert!(serde_json::from_value::<Diagnostics>(changed).is_err());
    }
    let mut changed = report;
    changed["failures"][0]["raw_error"] = "private-arbitrary-text".into();
    assert!(serde_json::from_value::<Diagnostics>(changed).is_err());
}
