//! Inert lifecycle/authority checks; no namespace, model or native backend.

use std::{io::Write as _, os::unix::fs::PermissionsExt as _};

use super::*;

#[test]
fn cleanup_is_explicitly_constructed_only_after_join_and_removal() {
    let ordinary = anyhow::anyhow!("not a cleanup proof");
    assert_eq!(cleanup(&ordinary), None);
    assert_eq!(cleanup(&private_task::CleanupUnconfirmed.into()), None);
    let confirmed = anyhow::Error::new(Failure::after_cleanup(
        super::super::ExecutionDeadline.into(),
    ));
    assert_eq!(cleanup(&confirmed), Some(cleanup_record()));
    assert!(execution_deadline(&confirmed));
    assert!(!execution_deadline(&ordinary));
    let different = anyhow::Error::new(Failure::after_cleanup(anyhow::anyhow!(
        "compute_owner_busy"
    )));
    assert!(!execution_deadline(&different));
}

#[test]
fn closed_failure_preserves_only_projected_diagnostic_without_opening_its_source() {
    let cause = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "PRIVATE_CANARY /private/source.rs prompt body",
    ))
    .context("compute_private_process_children");
    let before = super::super::diagnostic::describe(&cause);
    let error = anyhow::Error::new(Failure::after_cleanup(cause));
    assert_eq!(super::super::diagnostic::describe(&error), before);
    assert_eq!(error.chain().count(), 1);
    assert!(std::error::Error::source(error.downcast_ref::<Failure>().unwrap()).is_none());
    assert_eq!(error.to_string(), "compute_native_session_execution_failed");
    assert_eq!(cleanup(&error), Some(cleanup_record()));
    assert!(!execution_deadline(&error));
    let encoded = serde_json::to_string(&diagnostic(&error).unwrap()).unwrap();
    assert!(!encoded.contains("PRIVATE_CANARY") && !encoded.contains("/private/"));
}

#[test]
fn received_worker_error_cannot_construct_exit_adapter_or_cleanup_authority() {
    let value = json!({"version":1,"id":"PRIVATE_REQUEST_CANARY","kind":"result",
        "status":"error","code":"NATIVE_DECODE_FAILED"});
    let received =
        super::super::diagnostic::native_worker_failure(&value, "PRIVATE_REQUEST_CANARY").unwrap();
    assert_eq!(cleanup(&received), None);
    assert!(!execution_deadline(&received));
    assert!(super::super::adapter_violation(&received).is_none());
    let error = anyhow::Error::new(Failure::after_cleanup(received));
    let detail = serde_json::to_value(super::super::diagnostic::describe(&error)).unwrap();
    assert_eq!(detail["code"], "NATIVE_DECODE_FAILED");
    assert_eq!(detail["exit_code"], Value::Null);
    assert_eq!(detail["signal"], Value::Null);
    assert_eq!(detail["stderr_class"], Value::Null);
    assert!(!detail.to_string().contains("PRIVATE_REQUEST_CANARY"));
    assert_eq!(cleanup(&error), Some(cleanup_record()));
    assert!(!execution_deadline(&error));
    assert!(super::super::adapter_violation(&error).is_none());
    // An independent cleanup failure is never relabelled using this diagnostic.
    let unconfirmed = anyhow::Error::new(private_task::CleanupUnconfirmed);
    assert_eq!(diagnostic(&unconfirmed), None);
    assert_eq!(cleanup(&unconfirmed), None);
}

#[test]
fn closed_projected_failure_is_accepted_by_both_collector_versions() {
    // Serializer/collector contract only: no worker, native backend or cleanup
    // is executed by these deliberately fabricated private wrapper instances.
    let worker = json!({"version":1,"id":"PRIVATE_REQUEST_CANARY","kind":"result",
        "status":"error","code":"NATIVE_SAMPLE_FAILED"});
    let errors = [
        anyhow::anyhow!("PRIVATE_CANARY /private/prompt").context("compute_memory_budget"),
        super::super::diagnostic::native_worker_failure(&worker, "PRIVATE_REQUEST_CANARY").unwrap(),
        anyhow::anyhow!("PRIVATE_CANARY /private/prompt"),
    ];
    let mut log = tempfile::NamedTempFile::new().unwrap();
    for cause in errors {
        let error = anyhow::Error::new(Failure::after_cleanup(cause));
        let record = json!({"version":1,"phase":"task",
            "detail":super::super::diagnostic::describe(&error)});
        let raw = serde_json::to_string(&record).unwrap();
        assert!(!raw.contains("CANARY") && !raw.contains("/private/"));
        writeln!(log, "DEBUG private_execution_diagnostic {raw}").unwrap();
    }
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/agent-private-conversation.py");
    let output = std::process::Command::new("python3")
        .args([
            "-B",
            "-c",
            r"
import runpy, sys
from pathlib import Path
fixture = runpy.run_path(sys.argv[1])
for enabled in (False, True):
    value = fixture['service_diagnostic'](Path(sys.argv[2]), memory_enabled=enabled)
    expected = dict(version=2 if enabled else 1, truncated=False, unrecognized_record=False,
        events=[dict(version=1, phase='task', detail=dict(code=code, io_kind='none',
            exit_code=None, signal=None, stderr_class=None)) for code in
            ('compute_memory_budget', 'NATIVE_SAMPLE_FAILED', 'unclassified')])
    if enabled:
        expected['memory'] = []
    assert value == expected
",
        ])
        .arg(fixture)
        .arg(log.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "closed collector rejected projection"
    );
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}

#[test]
fn private_root_drop_preserves_uncertain_state_but_explicit_close_removes_it() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::new(parent.path()).unwrap();
    let retained = root.path().to_owned();
    fs::write(retained.join("inert-canary"), b"private").unwrap();
    assert_eq!(
        fs::metadata(&retained).unwrap().permissions().mode() & 0o777,
        0o700
    );
    drop(root);
    assert_eq!(fs::read(retained.join("inert-canary")).unwrap(), b"private");
    let root = PrivateRoot::new(parent.path()).unwrap();
    let removed = root.path().to_owned();
    root.close().unwrap();
    assert!(!removed.exists());
    assert!(retained.exists());
}

#[test]
fn staged_turn_names_and_permissions_are_core_owned_and_do_not_reuse_files() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::new(parent.path()).unwrap();
    let config = private_task::ExecutionConfig {
        runtime_root: "/runtime".into(),
        model_root: "/model".into(),
        work_parent: parent.path().to_owned(),
        model_profile: crate::compute::ModelProfile::Qwen4bInstruct2507,
        native_backend: native_cpu::Options::default(),
        threads: 2,
        max_seconds: 600,
    };
    let input = serde_json::to_vec(&json!({
        "version":1,"visibility":"private_local","generation_policy":"greedy_v1",
        "instructions":"Use all offered tools when appropriate.","tools":[],
        "history":[{"type":"message","role":"user","text":"Check this project."}]
    }))
    .unwrap();
    let one = stage(&config, root.path(), 1, &input).unwrap();
    assert_eq!(one.dataset, root.path().join("turn-1/input.json"));
    assert_eq!(one.output, root.path().join("turn-1/output"));
    assert_eq!(fs::read(&one.dataset).unwrap(), input);
    assert_eq!(
        fs::metadata(&one.dataset).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&one.output).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(stage(&config, root.path(), 1, &input).is_err());
    let two = stage(&config, root.path(), 2, &input).unwrap();
    assert_ne!(one.dataset, two.dataset);
    root.close().unwrap();
}

#[test]
fn fixed_task_and_turn_bounds_are_distinct_from_legacy_cleanup() {
    assert_eq!(
        (MAX_TASK_SECONDS, MAX_IDLE_SECONDS, MAX_REQUESTS),
        (2400, 300, 128)
    );
    let raw = json!({"conversation":{"type":"assistant","text":"ok"}});
    let legacy =
        private_conversation::summary(&raw, crate::compute::ModelProfile::Qwen4bInstruct2507);
    assert_eq!(legacy["version"], 1);
    assert_eq!(
        legacy["cleanup"],
        json!({"complete":true,"retained_input":false,"retained_report":false})
    );
    assert_ne!(legacy["cleanup"], cleanup_record());
}

#[test]
fn fixture_failure_accessor_requires_the_private_post_cleanup_wrapper() {
    for cause in [
        anyhow::anyhow!("compute_memory_budget"),
        anyhow::Error::new(private_task::CleanupUnconfirmed),
    ] {
        assert!(public_fixture_failure(&cause).is_none());
    }
    let error = public_fixture_test_failure(
        anyhow::anyhow!("PRIVATE_CANARY /private/prompt").context("compute_memory_budget"),
    );
    let value = public_fixture_failure(&error).unwrap();
    assert!(super::super::diagnostic::public_fixture_detail(&value));
    assert_eq!(value["code"], "compute_memory_budget");
    assert!(!value.to_string().contains("PRIVATE_CANARY"));
    let worker = json!({"version":1,"id":"PRIVATE_REQUEST_CANARY","kind":"result",
        "status":"error","code":"NATIVE_MODEL_LOAD_FAILED"});
    let cause =
        super::super::diagnostic::native_worker_failure(&worker, "PRIVATE_REQUEST_CANARY").unwrap();
    let error = public_fixture_test_failure(cause);
    let value = public_fixture_failure(&error).unwrap();
    assert_eq!(value["code"], "NATIVE_MODEL_LOAD_FAILED");
    assert!(value["exit_code"].is_null() && value["signal"].is_null());
    assert!(!value.to_string().contains("PRIVATE_REQUEST_CANARY"));
}

#[test]
fn fixture_detail_requires_exact_enums_and_real_startup_status_shape() {
    use super::super::diagnostic::public_fixture_detail;
    let mut value = json!({"code":"startup_missing_result","io_kind":"none",
        "exit_code":-1,"signal":9,"stderr_class":"none"});
    assert!(public_fixture_detail(&value));
    value["exit_code"] = json!(0);
    assert!(!public_fixture_detail(&value));
    value["signal"] = json!(0);
    assert!(public_fixture_detail(&value));
    value["signal"] = json!(false);
    assert!(!public_fixture_detail(&value));
    value["signal"] = json!(0);
    value["stderr_class"] = json!("none PRIVATE_CANARY");
    assert!(!public_fixture_detail(&value));
    value["stderr_class"] = json!("none");
    value["extra"] = json!("PRIVATE_CANARY");
    assert!(!public_fixture_detail(&value));
}

#[tokio::test]
async fn real_private_root_is_removed_before_failed_owner_projection_exists() {
    // Real filesystem owner cleanup, invalid input before worker spawn: no model,
    // sandbox, native process, or runtime execution is performed by this test.
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::new(parent.path()).unwrap();
    let path = root.path().to_owned();
    fs::write(path.join("private-canary"), b"PRIVATE_CANARY").unwrap();
    let config = private_task::ExecutionConfig {
        runtime_root: "/not-opened/runtime".into(),
        model_root: "/not-opened/model".into(),
        work_parent: parent.path().to_owned(),
        model_profile: crate::compute::ModelProfile::Qwen4bInstruct2507,
        native_backend: native_cpu::Options::default(),
        threads: 2,
        max_seconds: 600,
    };
    let (commands, receive) = mpsc::channel(1);
    commands
        .send(Command::Submit {
            id: "PRIVATE_REQUEST_CANARY".into(),
            input: b"invalid input".to_vec(),
        })
        .await
        .unwrap();
    let (events, mut receiving) = mpsc::channel(1);
    let (_active, activity) = watch::channel(true);
    let budget = SessionBudget::new(Instant::now() + Duration::from_secs(5), 2).unwrap();
    let error = run_owned(&config, root, receive, events, activity, &budget)
        .await
        .unwrap_err();
    assert!(matches!(receiving.recv().await, Some(Event::Opened)));
    assert!(receiving.recv().await.is_none());
    assert!(!path.exists());
    assert_eq!(cleanup(&error), Some(cleanup_record()));
    let detail = public_fixture_failure(&error).unwrap();
    assert!(super::super::diagnostic::public_fixture_detail(&detail));
    assert!(!detail.to_string().contains("PRIVATE_CANARY"));
    assert!(!detail.to_string().contains("PRIVATE_REQUEST_CANARY"));
}
