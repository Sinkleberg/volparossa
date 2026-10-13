use super::*;
use crate::{CONTROL_PROTOCOL_VERSION, Empty, decode_response, encode_response};

fn rejected() -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![7; 16],
        result: ControlResult::Unavailable as i32,
        diagnostic_code: "CONTENT_UNAVAILABLE".into(),
        private_storage_remote_detail: Some(PrivateStorageRemoteDetail {
            stage: PrivateStorageRemoteStage::ProviderLookup as i32,
            deadline_scope: PrivateStorageDeadlineScope::None as i32,
        }),
        payload: Some(Payload::Ack(Empty {})),
    }
}

#[test]
fn private_storage_detail_is_additive_to_the_original_ack_wire() {
    #[derive(Clone, PartialEq, Message)]
    struct OriginalResponse {
        #[prost(uint32, tag = "1")]
        protocol_version: u32,
        #[prost(bytes = "vec", tag = "2")]
        request_id: Vec<u8>,
        #[prost(enumeration = "ControlResult", tag = "3")]
        result: i32,
        #[prost(string, tag = "4")]
        diagnostic_code: String,
        #[prost(message, optional, tag = "10")]
        ack: Option<Empty>,
    }
    let original = OriginalResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![7; 16],
        result: ControlResult::Unavailable as i32,
        diagnostic_code: "CONTENT_UNAVAILABLE".into(),
        ack: Some(Empty {}),
    };
    let old_wire = original.encode_to_vec();
    let old = decode_response(&old_wire).unwrap();
    assert!(old.private_storage_remote_detail.is_none());
    assert_eq!(encode_response(&old).unwrap(), old_wire);
    let new = rejected();
    let new_wire = encode_response(&new).unwrap();
    assert_eq!(decode_response(&new_wire).unwrap(), new);
    // The previous schema still observes exactly the same result, code and Ack.
    assert_eq!(
        OriginalResponse::decode(new_wire.as_slice()).unwrap(),
        original
    );
}

#[test]
fn private_storage_detail_rejects_unknown_enums_success_payload_and_code_mismatch() {
    for field in ["stage", "deadline"] {
        let mut response = rejected();
        let detail = response.private_storage_remote_detail.as_mut().unwrap();
        if field == "stage" {
            detail.stage = 99;
        } else {
            detail.deadline_scope = 99;
        }
        assert!(encode_response(&response).is_err());
        assert!(decode_response(&response.encode_to_vec()).is_err());
    }
    for (result, code) in [
        (ControlResult::Ok, "CONTENT_OK"),
        (ControlResult::Unavailable, "PRIVATE_UNLISTED_CODE"),
        (ControlResult::Unavailable, "CONTENT_BUSY"),
        (ControlResult::InvalidState, "CONTENT_NAME_CONFLICT"),
    ] {
        let mut response = rejected();
        response.result = result as i32;
        response.diagnostic_code = code.into();
        assert!(encode_response(&response).is_err());
    }
    let mut response = rejected();
    response.payload = Some(Payload::Status(crate::StatusSnapshot::default()));
    assert!(encode_response(&response).is_err());
    for (result, code) in [
        (ControlResult::InvalidRequest, "CONTENT_INVALID"),
        (ControlResult::Unavailable, "CONTENT_UNAVAILABLE"),
        (ControlResult::InvalidState, "CONTENT_BUSY"),
        (ControlResult::Policy, "CONTENT_POLICY"),
    ] {
        response = rejected();
        response.result = result as i32;
        response.diagnostic_code = code.into();
        assert!(encode_response(&response).is_ok());
    }
}

#[test]
fn private_storage_detail_has_only_closed_bounded_stage_and_deadline_values() {
    for stage in 0..=8 {
        for deadline_scope in 0..=2 {
            let mut response = rejected();
            response.private_storage_remote_detail = Some(PrivateStorageRemoteDetail {
                stage,
                deadline_scope,
            });
            let allowed = match deadline_scope {
                0 => stage != 0,
                1 => true,
                2 => stage >= 6,
                _ => unreachable!(),
            };
            let wire = encode_response(&response);
            assert_eq!(wire.is_ok(), allowed);
            if let Ok(wire) = wire {
                assert!(wire.len() < 80);
                assert_eq!(decode_response(&wire).unwrap(), response);
            }
            response.diagnostic_code = "CONTENT_POLICY".into();
            response.result = ControlResult::Policy as i32;
            assert_eq!(
                encode_response(&response).is_ok(),
                allowed && deadline_scope == 0
            );
        }
    }
}
