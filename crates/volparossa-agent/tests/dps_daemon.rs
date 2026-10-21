// SPDX-License-Identifier: GPL-3.0-only
//! Actual daemon/Unix-IPC lifecycle with synthetic DPS claims, hosted opt-in only.
//! The administrative socket is never delegated to a mobile application.

#[path = "dps_daemon/host_state.rs"]
mod host_state;

use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use nix::{
    sys::signal::{Signal, kill},
    unistd::{Pid, getegid, geteuid},
};
use tokio::{
    net::UnixStream,
    process::Command,
    time::{sleep, timeout},
};
use volparossa_identity::{IdentityStore, Passphrase};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult, Empty,
    control_request::Operation,
    control_response::Payload,
    dps::{
        AssessmentStatus, DPS_SERVICE_VERSION, DpsAssessRequest, FrameKind, PositionFrame,
        PositionObservation, SourceKind,
    },
    read_response, write_request,
};

const TEST: &str = "dps_daemon_startup_socket_request_and_joined_cleanup";
const MARKER: &str = "VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS";
const COMPLETE: &str = "DPS_DAEMON_CHILD_COMPLETE_V1";
const RECEIPT: &str = "DPS_DAEMON_HOST_PROOF ";

#[test]
#[ignore = "requires explicit disposable GitHub-hosted daemon proof"]
fn dps_daemon_startup_socket_request_and_joined_cleanup() {
    assert_eq!(
        std::env::var("VOLPAROSSA_REQUIRE_DPS_DAEMON_PROOF").as_deref(),
        Ok("1")
    );
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(
        std::env::var("RUNNER_ENVIRONMENT").as_deref(),
        Ok("github-hosted")
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    if let Some(parent) = std::env::var_os(MARKER) {
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
            parent
        );
        let result = runtime.block_on(daemon_scenario());
        assert!(
            result.is_ok(),
            "{}",
            result.err().unwrap_or("daemon_failure")
        );
        println!("\n{COMPLETE}");
    } else {
        runtime.block_on(hosted_scenario());
    }
}

async fn hosted_scenario() {
    let before = host_state::HostState::capture().await;
    // Even failure must reach the after-observation. No assert/panic within this span.
    let proof = if before.is_ok() {
        namespace_proof().await
    } else {
        Err("before_capture")
    };
    let after = host_state::HostState::capture().await;
    let (routes, dns, firewall, sysctls, namespace) = match (&before, &after) {
        (Ok(first), Ok(last)) => (
            first.routes == last.routes,
            first.dns == last.dns,
            first.firewall == last.firewall,
            first.sysctls == last.sysctls,
            first.namespace == last.namespace,
        ),
        _ => (false, false, false, false, false),
    };
    let success = proof.is_ok() && routes && dns && firewall && sysctls && namespace;
    let status = if before.is_err() {
        "before_capture_failed"
    } else if after.is_err() {
        "after_capture_failed"
    } else if proof.is_err() {
        "daemon_proof_failed"
    } else if !success {
        "host_configuration_changed"
    } else {
        "passed"
    };
    // Closed receipt only. No observed names, values, digests, paths, credentials or coordinates.
    let receipt = serde_json::json!({
        "version": 1, "status": status, "success": success,
        "before_captured": before.is_ok(), "after_captured": after.is_ok(),
        "routes_unchanged": routes, "dns_unchanged": dns, "firewall_unchanged": firewall,
        "sysctls_unchanged": sysctls, "parent_namespace_unchanged": namespace,
        "completed_daemon_executions": u8::from(proof.is_ok()),
        "synthetic_dps_only": true, "hardware_positioning_proven": false,
        "mobile_app_authority_proven": false,
    });
    println!("\n{RECEIPT}{receipt}");
    assert!(success, "{status}");
}

async fn namespace_proof() -> Result<(), &'static str> {
    let executable = std::env::current_exe().map_err(|_| "test_executable")?;
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let mut command = Command::new(runner);
    command.arg("--command").arg(executable).args([
        TEST,
        MARKER,
        "loopback",
        "--ignored",
        "--exact",
        TEST,
        "--nocapture",
        "--test-threads=1",
    ]);
    let (success, output) = host_state::capture_command(&mut command, 135).await?;
    let output = std::str::from_utf8(&output).map_err(|_| "child_encoding")?;
    let summaries: Vec<_> = output
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect();
    if !success
        || output.lines().filter(|line| *line == COMPLETE).count() != 1
        || summaries.len() != 1
        || !summaries[0].starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;")
        || output
            .lines()
            .filter(|line| *line == "running 1 test")
            .count()
            != 1
    {
        return Err("exact_child_execution");
    }
    Ok(())
}

struct Fixture {
    directory: tempfile::TempDir,
    socket: PathBuf,
}

impl Fixture {
    fn create() -> Result<Self, &'static str> {
        let directory = tempfile::tempdir().map_err(|_| "fixture_directory")?;
        let root = directory.path();
        for name in ["state", "control", "credentials"] {
            let path = root.join(name);
            fs::create_dir(&path).map_err(|_| "fixture_subdirectory")?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| "fixture_permissions")?;
        }
        let phrase = b"disposable synthetic DPS daemon fixture passphrase";
        let credential = root.join("credentials/identity-passphrase");
        private_file(&credential, phrase)?;
        let passphrase = Passphrase::new(phrase).map_err(|_| "fixture_passphrase")?;
        IdentityStore::new(root.join("state/identity.key"))
            .create(&passphrase)
            .map_err(|_| "fixture_identity")?;
        private_file(&root.join("config.yaml"), b"roles:\n  client: false\n  relay: false\n  exit: false\nnetwork:\n  listen_addresses: [/ip4/127.0.0.1/udp/0/quic-v1]\n  bootstrap_peers: []\nprivacy:\n  metrics_enabled: false\ncontent_contribution:\n  enabled: false\ndns_cache:\n  enabled: false\nsharing:\n  enabled: false\ndownload_sharing:\n  enabled: false\nwifi_mesh:\n  enabled: false\n")?;
        let socket = root.join("control/agent.sock");
        Ok(Self { directory, socket })
    }

    fn command(&self) -> Command {
        let root = self.directory.path();
        let mut command = Command::new(env!("CARGO_BIN_EXE_volparossa-agent"));
        command
            .env_clear()
            .env("VOLPAROSSA_CONFIG", root.join("config.yaml"))
            .env("VOLPAROSSA_STATE_DIRECTORY", root.join("state"))
            .env("VOLPAROSSA_CONTROL_SOCKET", &self.socket)
            .env(
                "VOLPAROSSA_HELPER_SOCKET",
                root.join("control/absent-helper.sock"),
            )
            .env(
                "VOLPAROSSA_MPQUIC_SOCKET",
                root.join("control/absent-mpquic.sock"),
            )
            .env("CREDENTIALS_DIRECTORY", root.join("credentials"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command
    }
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "fixture_file")?;
    file.write_all(bytes).map_err(|_| "fixture_write")
}

async fn daemon_scenario() -> Result<(), &'static str> {
    let fixture = Fixture::create()?;
    let mut child = fixture.command().spawn().map_err(|_| "daemon_spawn")?;
    let result = timeout(
        Duration::from_secs(40),
        daemon_requests(&fixture, &mut child),
    )
    .await;
    // Every request failure still kills and joins this exact child; PID namespace teardown
    // additionally removes descendants if this test itself crashes or reaches its outer bound.
    let outcome = result.unwrap_or(Err("daemon_deadline"));
    if outcome.is_err() {
        let _ = child.start_kill();
        let joined = timeout(Duration::from_secs(5), child.wait()).await;
        if !matches!(joined, Ok(Ok(_))) {
            return Err("failure_cleanup_join");
        }
    }
    outcome?;
    fixture.directory.close().map_err(|_| "fixture_cleanup")
}

async fn daemon_requests(
    fixture: &Fixture,
    child: &mut tokio::process::Child,
) -> Result<(), &'static str> {
    let pid = child.id().ok_or("daemon_pid")?;
    let mut ready = false;
    for _ in 0..100 {
        if child.try_wait().map_err(|_| "daemon_poll")?.is_some() {
            return Err("daemon_exited_before_ready");
        }
        if let Ok(mut stream) = UnixStream::connect(&fixture.socket).await {
            verify_peer(&stream, pid)?;
            let reply = exchange(&mut stream, Operation::Status(Empty {}), 7).await?;
            if reply.result != ControlResult::Ok as i32
                || !matches!(reply.payload, Some(Payload::Status(_)))
            {
                return Err("daemon_status");
            }
            ready = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    if !ready {
        return Err("daemon_not_ready");
    }
    verify_socket(&fixture.socket)?;
    verify_socket(&fixture.socket.with_extension("sock.apps"))?;
    verify_dormant_roles(fixture, pid).await?;
    let mut stream = UnixStream::connect(&fixture.socket)
        .await
        .map_err(|_| "dps_connect")?;
    verify_peer(&stream, pid)?;
    let input = synthetic_request()?;
    let expected = input.observations[0].clone();
    let reply = exchange(&mut stream, Operation::DpsAssess(input), 8).await?;
    if reply.result != ControlResult::Ok as i32 || reply.diagnostic_code != "DPS_ASSESSED" {
        return Err("dps_result");
    }
    let Some(Payload::DpsAssessment(quality)) = reply.payload else {
        return Err("dps_payload");
    };
    quality.validate().map_err(|_| "dps_quality_validation")?;
    if quality.dps_version != DPS_SERVICE_VERSION
        || quality.status != AssessmentStatus::SingleClaim as i32
        || quality.unverified_input_position != Some(expected)
        || quality.observations.len() != 1
        || quality.maximum_age_ms != 60_000
    {
        return Err("dps_quality");
    }
    drop(stream);
    let pid = i32::try_from(pid).map_err(|_| "daemon_pid_bound")?;
    kill(Pid::from_raw(pid), Signal::SIGTERM).map_err(|_| "daemon_terminate")?;
    let status = timeout(Duration::from_secs(15), child.wait())
        .await
        .map_err(|_| "daemon_shutdown_deadline")?
        .map_err(|_| "daemon_join")?;
    if !status.success() {
        return Err("daemon_shutdown_status");
    }
    for path in [&fixture.socket, &fixture.socket.with_extension("sock.apps")] {
        require_absent(path)?;
    }
    let root = fixture.directory.path();
    require_absent(&root.join("control/absent-helper.sock"))?;
    require_absent(&root.join("control/helper.cleanup-token"))?;
    Ok(())
}

async fn verify_dormant_roles(fixture: &Fixture, pid: u32) -> Result<(), &'static str> {
    let mut stream = UnixStream::connect(&fixture.socket)
        .await
        .map_err(|_| "roles_connect")?;
    verify_peer(&stream, pid)?;
    let reply = exchange(&mut stream, Operation::Roles(Empty {}), 9).await?;
    let Some(Payload::Roles(roles)) = reply.payload else {
        return Err("roles_payload");
    };
    if reply.result != ControlResult::Ok as i32 || roles.client || roles.relay || roles.exit {
        return Err("roles_not_dormant");
    }
    Ok(())
}

fn require_absent(path: &Path) -> Result<(), &'static str> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("daemon_cleanup_entry_not_absent"),
    }
}

fn verify_peer(stream: &UnixStream, pid: u32) -> Result<(), &'static str> {
    let peer = stream.peer_cred().map_err(|_| "socket_credentials")?;
    if peer.uid() != geteuid().as_raw()
        || peer.gid() != getegid().as_raw()
        || peer.pid() != i32::try_from(pid).ok()
    {
        return Err("socket_owner");
    }
    Ok(())
}

fn verify_socket(path: &Path) -> Result<(), &'static str> {
    let meta = fs::symlink_metadata(path).map_err(|_| "socket_metadata")?;
    let parent = fs::symlink_metadata(path.parent().ok_or("socket_parent")?)
        .map_err(|_| "socket_parent_metadata")?;
    if !meta.file_type().is_socket()
        || meta.mode() & 0o777 != 0o660
        || meta.uid() != geteuid().as_raw()
        || meta.gid() != parent.gid()
        || parent.uid() != geteuid().as_raw()
        || parent.mode() & 0o077 != 0
    {
        return Err("socket_permissions");
    }
    Ok(())
}

async fn exchange(
    stream: &mut UnixStream,
    operation: Operation,
    identifier: u8,
) -> Result<ControlResponse, &'static str> {
    let request = ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![identifier; 16],
        operation: Some(operation),
    };
    timeout(Duration::from_secs(5), write_request(stream, &request))
        .await
        .map_err(|_| "request_deadline")?
        .map_err(|_| "request_frame")?;
    let response = timeout(Duration::from_secs(5), read_response(stream))
        .await
        .map_err(|_| "response_deadline")?
        .map_err(|_| "response_frame")?;
    if response.protocol_version != CONTROL_PROTOCOL_VERSION
        || response.request_id != request.request_id
    {
        return Err("response_correlation");
    }
    Ok(response)
}

fn synthetic_request() -> Result<DpsAssessRequest, &'static str> {
    let frame = PositionFrame {
        kind: FrameKind::Wgs84Ecef as i32,
        local_frame_id: vec![],
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "fixture_clock")?
        .as_millis();
    Ok(DpsAssessRequest {
        dps_version: DPS_SERVICE_VERSION,
        desired_frame: Some(frame.clone()),
        maximum_age_ms: 60_000,
        observations: vec![PositionObservation {
            observation_id: vec![1; 16],
            source_id: vec![2; 16],
            declared_independence_group: vec![3; 16],
            frame: Some(frame),
            source_kind: SourceKind::Gnss as i32,
            x_metres: 6_378_137.0,
            supplied_radius_metres: 5.0,
            observed_at_unix_ms: u64::try_from(now).map_err(|_| "fixture_clock_bound")?,
            ..Default::default()
        }],
    })
}
