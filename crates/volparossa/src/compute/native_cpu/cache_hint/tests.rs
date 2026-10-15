//! Tiny inert files and injected advice only; no model, native code, or cache syscall.

use std::{
    cell::Cell,
    os::unix::fs::{PermissionsExt as _, symlink},
    time::{Duration, SystemTime},
};

use nix::fcntl::{FcntlArg, fcntl};

use super::super::{Options, tests::fixture};
use super::*;

const PROFILE: ModelProfile = ModelProfile::Qwen4bInstruct2507;

fn bound(options: &Options) -> CacheHint {
    options
        .request(PROFILE)
        .unwrap()
        .cache_hint(options, PROFILE)
        .unwrap()
}

#[test]
fn hint_requires_known_shortage_without_changing_admission() {
    let required = 10 * 1024 * 1024 * 1024 + 512 * 1024 * 1024;
    assert_eq!(
        resources::limits(PROFILE).admission_headroom,
        Some(required)
    );
    for (available, hint, admitted) in [
        (None, false, false),
        (Some(0), true, false),
        (Some(required - 1), true, false),
        (Some(required), false, true),
        (Some(required + 1), false, true),
    ] {
        assert_eq!(needs_hint(PROFILE, available), hint);
        assert_eq!(resources::admits(PROFILE, available), admitted);
    }
    for profile in [
        ModelProfile::Default135,
        ModelProfile::Smol360,
        ModelProfile::Smol1700,
        ModelProfile::Qwen600,
    ] {
        assert!(!needs_hint(profile, Some(0)));
    }
}

#[test]
fn hint_binding_requires_the_same_owner_authorized_native_request() {
    let (_root, mut options) = fixture();
    let request = options.request(PROFILE).unwrap();
    assert!(request.cache_hint(&options, PROFILE).is_some());
    assert!(
        request
            .cache_hint(&options, ModelProfile::Qwen600)
            .is_none()
    );
    assert!(request.cache_hint(&Options::default(), PROFILE).is_none());
    options.native_backend_sha256 = Some("0".repeat(64));
    assert!(request.cache_hint(&options, PROFILE).is_none());
    assert!(options.request(PROFILE).is_err());
    assert!(
        Options::default()
            .request(PROFILE)
            .unwrap()
            .cache_hint(&options, PROFILE)
            .is_none()
    );
}

#[test]
fn bound_descriptor_is_read_only_cloexec_and_matches_exact_file() {
    let (_root, options) = fixture();
    let hint = bound(&options);
    assert!(hint.unchanged());
    assert_eq!(hint.identity.bytes, 1);
    assert_ne!(
        fcntl(&hint.file, FcntlArg::F_GETFD).unwrap() & libc::FD_CLOEXEC,
        0
    );
    assert_eq!(
        fcntl(&hint.file, FcntlArg::F_GETFL).unwrap() & libc::O_ACCMODE,
        libc::O_RDONLY
    );
}

#[test]
fn file_identity_requires_regular_private_single_link_owned_exact_size() {
    let (_root, options) = fixture();
    let identity = bound(&options).identity;
    assert!(identity.valid(1));
    assert!(!identity.valid(2));
    for changed in [
        Identity {
            mode: libc::S_IFDIR | 0o600,
            ..identity
        },
        Identity {
            mode: identity.mode | 0o004,
            ..identity
        },
        Identity {
            owner: identity.owner.wrapping_add(1),
            ..identity
        },
        Identity {
            links: 2,
            ..identity
        },
        Identity {
            bytes: 0,
            ..identity
        },
        Identity {
            bytes: 10 * 1024 * 1024 * 1024,
            ..identity
        },
    ] {
        assert!(!changed.valid(changed.bytes));
    }
    for changed in [
        Identity {
            device: identity.device.wrapping_add(1),
            ..identity
        },
        Identity {
            inode: identity.inode.wrapping_add(1),
            ..identity
        },
        Identity {
            modified: (identity.modified.0 + 1, 0),
            ..identity
        },
        Identity {
            changed: (identity.changed.0 + 1, 0),
            ..identity
        },
    ] {
        assert_ne!(changed, identity);
    }
}

#[test]
fn optional_binding_rejects_symlink_hardlink_nonregular_and_unprivate_parent() {
    let (root, _options) = fixture();
    let model = root.path().join("model.gguf");
    fs::rename(&model, root.path().join("original")).unwrap();
    symlink("original", &model).unwrap();
    assert!(CacheHint::bind(root.path(), 1).is_none());
    fs::remove_file(&model).unwrap();
    fs::hard_link(root.path().join("original"), &model).unwrap();
    assert!(CacheHint::bind(root.path(), 1).is_none());
    fs::remove_file(&model).unwrap();
    fs::create_dir(&model).unwrap();
    assert!(CacheHint::bind(root.path(), 1).is_none());
    fs::remove_dir(&model).unwrap();
    fs::rename(root.path().join("original"), &model).unwrap();
    assert!(CacheHint::bind(root.path(), 2).is_none());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(CacheHint::bind(root.path(), 1).is_none());
}

#[test]
fn replaced_same_size_file_is_never_advised() {
    let (root, options) = fixture();
    let hint = bound(&options);
    let model = root.path().join("model.gguf");
    fs::rename(&model, root.path().join("original")).unwrap();
    fs::write(&model, b"x").unwrap();
    fs::set_permissions(&model, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!hint.unchanged());
    hint.after_supervisor_with(&Ok(()), PROFILE, || Some(0), |_, _| panic!("replacement"));
}

#[test]
fn changed_metadata_and_parent_identity_are_never_advised() {
    for change in 0..4 {
        let (root, options) = fixture();
        let hint = bound(&options);
        let model = root.path().join("model.gguf");
        match change {
            0 => fs::set_permissions(&model, fs::Permissions::from_mode(0o400)).unwrap(),
            1 => fs::write(&model, b"xx").unwrap(),
            2 => hint
                .file
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
                .unwrap(),
            _ => fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap(),
        }
        assert!(!hint.unchanged());
        hint.after_supervisor_with(&Ok(()), PROFILE, || Some(0), |_, _| panic!("changed"));
    }
    let (_root, options) = fixture();
    let mut hint = bound(&options);
    hint.root_identity.1 = hint.root_identity.1.wrapping_add(1);
    assert!(!hint.unchanged());
}

#[test]
fn successful_supervisor_allows_one_exact_range_hint_without_reading_model() {
    let (_root, options) = fixture();
    let hint = bound(&options);
    let expected = hint.identity;
    let calls = Cell::new(0);
    let result = Ok("original result");
    hint.after_supervisor_with(
        &result,
        PROFILE,
        || Some(0),
        |file, bytes| {
            calls.set(calls.get() + 1);
            assert_eq!(bytes, 1);
            assert_eq!(Identity::read(&file.metadata().unwrap()), expected);
            Ok(())
        },
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(result.unwrap(), "original result");
}

#[test]
fn hint_failure_does_not_change_success_or_claim_reclaimed_memory() {
    let (_root, options) = fixture();
    let result = Ok("original result");
    bound(&options).after_supervisor_with(
        &result,
        PROFILE,
        || Some(0),
        |_, _| Err(nix::errno::Errno::EIO),
    );
    assert_eq!(result.unwrap(), "original result");
}

#[test]
fn errors_including_unconfirmed_cleanup_never_sample_or_hint() {
    let (_root, options) = fixture();
    for error in [
        anyhow::Error::new(crate::compute::private_task::CleanupUnconfirmed),
        anyhow::anyhow!("compute_cancelled"),
        anyhow::anyhow!("PRIVATE_ERROR_CANARY /private/path"),
    ] {
        let original = error.to_string();
        let uncertain_cleanup = error.is::<crate::compute::private_task::CleanupUnconfirmed>();
        let result: Result<()> = Err(error);
        bound(&options).after_supervisor_with(
            &result,
            PROFILE,
            || panic!("error sample"),
            |_, _| panic!("error hint"),
        );
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), original);
        assert_eq!(
            error.is::<crate::compute::private_task::CleanupUnconfirmed>(),
            uncertain_cleanup
        );
    }
}

#[test]
fn missing_or_sufficient_headroom_never_hints() {
    let (_root, options) = fixture();
    for available in [
        None,
        resources::limits(PROFILE).admission_headroom,
        Some(u64::MAX),
    ] {
        bound(&options).after_supervisor_with(
            &Ok(()),
            PROFILE,
            || available,
            |_, _| panic!("no measured shortage"),
        );
    }
}
