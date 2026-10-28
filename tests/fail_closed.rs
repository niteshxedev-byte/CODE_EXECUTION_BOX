use std::fs;
use std::time::Duration;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use CodeEditorENGINE::{
    handlers::submissions::create_submission,
    models::submission::CreateSubmissionRequest,
    services::{sandbox::SandboxConfig, seccomp::SandboxProfile},
    state::AppState,
};

#[tokio::test]
async fn test_degraded_state_rejects_submissions_with_503() {
    let mut state = AppState::new();
    // Simulate critical sandbox degradation (e.g. seccomp or userns boundary failed)
    state.sandbox.is_degraded = true;
    state.sandbox.degradation_reason = Some("Simulated host capability degradation".to_string());

    let payload = CreateSubmissionRequest {
        language_id: 71,
        source_code: "print('untrusted')".to_string(),
        stdin: None,
        expected_output: None,
        cpu_time_limit: None,
        memory_limit: None,
    };

    let response = create_submission(State(state), Json(payload)).await.into_response();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "Degraded sandbox must fail closed with 503 Service Unavailable"
    );
}

#[test]
fn test_pre_exec_fails_closed_on_cgroup_write_failure() {
    let temp = tempfile::tempdir().unwrap();
    let readonly_scope = temp.path().join("cg_readonly");
    fs::create_dir_all(&readonly_scope).unwrap();

    // Create a read-only cgroup.procs file (cannot be opened O_WRONLY)
    let procs = readonly_scope.join("cgroup.procs");
    fs::write(&procs, b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&procs, fs::Permissions::from_mode(0o400)).unwrap();
    }

    let config = SandboxConfig::init();
    let workspace = temp.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    let res = config.build_sandboxed_command(
        &workspace,
        "/bin/true",
        &[],
        SandboxProfile::Execution,
        &Some(readonly_scope.clone()),
    );

    // Opening read-only cgroup.procs with O_WRONLY must return Err fail-closed
    assert!(res.is_err(), "build_sandboxed_command must fail closed when cgroup.procs is unwritable");
    let err = res.err().unwrap();
    assert!(err.contains("fail-closed") || err.contains("Permission denied"));
}

#[test]
fn test_teardown_waits_for_populated_zero() {
    let temp = tempfile::tempdir().unwrap();
    let cg_dir = temp.path().join("test_cg_teardown");
    fs::create_dir_all(&cg_dir).unwrap();

    let events_file = cg_dir.join("cgroup.events");
    // Start with populated 1 (processes still dying)
    fs::write(&events_file, b"populated 1\n").unwrap();

    // Spawn thread that simulates asynchronous kernel reap: transition to populated 0
    let events_path_clone = events_file.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        let _ = fs::write(events_path_clone, b"populated 0\n");
    });

    let cg_opt = Some(cg_dir.clone());
    SandboxConfig::cleanup_cgroup_scope(&cg_opt);

    // cleanup_cgroup_scope must have waited for populated 0 and removed the directory cleanly
    assert!(
        !cg_dir.exists(),
        "cleanup_cgroup_scope should wait for populated 0 and remove directory"
    );
}

#[test]
fn test_anti_toctou_fd_verification_window() {
    use std::io::Read;
    let temp = tempfile::tempdir().unwrap();

    // Part A: User binary anti-TOCTOU FD verification
    let original_path = temp.path().join("main");
    let renamed_path = temp.path().join("main_renamed");
    let fake_path = temp.path().join("main");

    fs::write(&original_path, b"ORIGINAL_AUTHENTIC_USER_BINARY").unwrap();

    // 1. Open FD and hash
    let mut file = SandboxConfig::open_artifact_no_follow(temp.path(), "main").unwrap();
    let original_hash = SandboxConfig::compute_sha256_fd(&mut file).unwrap();

    // 2. Adversarial action: attacker attempts concurrent rename/replace
    fs::rename(&original_path, &renamed_path).unwrap();
    fs::write(&fake_path, b"MALICIOUS_REPLACED_USER_BINARY").unwrap();

    // 3. Confirm open FD retained by engine reads the verified original inode
    let fd_hash = SandboxConfig::compute_sha256_fd(&mut file).unwrap();
    assert_eq!(fd_hash, original_hash);

    let mut content = Vec::new();
    file.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"ORIGINAL_AUTHENTIC_USER_BINARY");

    // Part B: bwrap host binary anti-TOCTOU FD verification
    let bwrap_mock = temp.path().join("bwrap_mock");
    let bwrap_renamed = temp.path().join("bwrap_renamed");
    let bwrap_fake = temp.path().join("bwrap_mock");

    fs::write(&bwrap_mock, b"BWRAP_AUTHENTIC_ELF").unwrap();
    let mut bwrap_file = fs::File::open(&bwrap_mock).unwrap();

    // Adversarial replacement
    fs::rename(&bwrap_mock, &bwrap_renamed).unwrap();
    fs::write(&bwrap_fake, b"BWRAP_TROJANED_ELF").unwrap();

    // The open FD still reads original authentic binary
    let mut bwrap_content = Vec::new();
    bwrap_file.read_to_end(&mut bwrap_content).unwrap();
    assert_eq!(bwrap_content, b"BWRAP_AUTHENTIC_ELF");
}
