use super::*;

#[test]
fn tuple_codes_are_static_bounded_and_preserve_whole_tuple_identity() {
    let operations = [
        None,
        Some(Operation::Reserve),
        Some(Operation::Append),
        Some(Operation::Progress),
        Some(Operation::Finalize),
        Some(Operation::ReadRange),
        Some(Operation::Renew),
        Some(Operation::Delete),
    ];
    let phases = [
        Phase::Grant,
        Phase::Challenge,
        Phase::Request,
        Phase::Payload,
        Phase::DiskAdmission,
        Phase::Backend,
        Phase::Receipt,
        Phase::ResponsePayload,
    ];
    let categories = [
        Category::Io,
        Category::Auth,
        Category::Invalid,
        Category::Busy,
        Category::Store,
        Category::Timeout,
        Category::Database,
        Category::Integrity,
        Category::Expired,
        Category::Ownership,
        Category::Conflict,
        Category::Deleted,
        Category::Quota,
        Category::NotFound,
        Category::NotCommitted,
        Category::Entropy,
    ];
    let mut codes = std::collections::BTreeSet::new();
    for operation in operations {
        for phase in phases {
            for category in categories {
                let code: &'static str = Failure {
                    operation,
                    phase,
                    category,
                }
                .event_code();
                assert!(
                    code.len() <= 96
                        && code
                            .bytes()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                );
                assert_eq!(code.split("__").count(), 3);
                assert!(codes.insert(code));
            }
        }
    }
    assert_eq!(
        codes.len(),
        operations.len() * phases.len() * categories.len()
    );
}

#[test]
fn caller_owned_timeout_uses_active_phase_without_inventing_commit_outcome() {
    let mut observation = Observation::default();
    assert!(observation.failure(true).is_none());
    observation.begin();
    assert_eq!(
        observation.failure(true).unwrap().event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_UNKNOWN__GRANT__TIMEOUT"
    );
    observation.verified(StorageOperation::Finalize);
    observation.phase = Phase::Backend;
    assert_eq!(
        observation.failure(true).unwrap().event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_FINALIZE__BACKEND__TIMEOUT"
    );
    // A successful apply moves to Receipt before any subsequent authorization/write work.
    observation.phase = Phase::Receipt;
    observation.finish(&Err(WireError::Protocol(ProtocolError::Expired)));
    assert_eq!(
        observation.failure(false).unwrap().event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_FINALIZE__RECEIPT__EXPIRED"
    );
    observation.begin();
    observation.finish(&Ok(()));
    assert!(observation.failure(false).is_none());
    assert!(observation.failure(true).is_none());
}

#[test]
fn nested_error_payloads_never_enter_closed_backend_categories() {
    let secret = "/private/database/owner-key-and-ciphertext";
    let cases = [
        (
            ProviderError::Storage(StorageError::Io(std::io::Error::other(secret))),
            Category::Io,
        ),
        (
            ProviderError::Storage(StorageError::Database(
                rusqlite::Error::InvalidParameterName(secret.into()),
            )),
            Category::Database,
        ),
        (
            ProviderError::Storage(StorageError::Integrity),
            Category::Integrity,
        ),
        (
            ProviderError::Storage(StorageError::Expired),
            Category::Expired,
        ),
        (ProviderError::Unauthorized, Category::Ownership),
    ];
    for (error, expected) in cases {
        assert_eq!(Category::backend(&error), expected);
        let diagnostic = Failure {
            operation: Some(Operation::Finalize),
            phase: Phase::Backend,
            category: Category::backend(&error),
        };
        assert!(!diagnostic.event_code().contains(secret));
        assert!(!format!("{diagnostic:?}").contains(secret));
    }
}
