//! Inert lifecycle/authority checks; no namespace, model or native backend.

use std::os::unix::fs::PermissionsExt as _;

use super::*;

#[test]
fn cleanup_is_explicitly_constructed_only_after_join_and_removal() {
    let ordinary = anyhow::anyhow!("not a cleanup proof");
    assert_eq!(cleanup(&ordinary), None);
    assert_eq!(cleanup(&private_task::CleanupUnconfirmed.into()), None);
    let confirmed = anyhow::Error::new(Failure {
        cause: super::super::ExecutionDeadline.into(),
    });
    assert_eq!(cleanup(&confirmed), Some(cleanup_record()));
    assert!(execution_deadline(&confirmed));
    assert!(!execution_deadline(&ordinary));
    let different = anyhow::Error::new(Failure {
        cause: anyhow::anyhow!("compute_owner_busy"),
    });
    assert!(!execution_deadline(&different));
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
