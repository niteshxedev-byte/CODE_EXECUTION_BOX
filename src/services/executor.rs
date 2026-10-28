use std::{
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};
use chrono::Utc;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use crate::{
    models::{
        language::Language,
        status::Status,
        submission::CreateSubmissionRequest,
    },
    services::{
        sandbox::{CgroupGuard, SandboxConfig},
        seccomp::SandboxProfile,
    },
    state::AppState,
};

const MAX_OUTPUT_BYTES: usize = 512 * 1024; // 512 KB output limit to avoid memory bloat
const DEFAULT_TIMEOUT_SECS: f64 = 5.0;
const MAX_TIMEOUT_SECS: f64 = 15.0;
const COMPILE_TIMEOUT_SECS: f64 = 10.0;

pub async fn execute_submission(
    state: AppState,
    token: String,
    language: Language,
    req: CreateSubmissionRequest,
) {
    // Fail-Closed Security Policy: Refuse untrusted execution if sandbox is degraded
    if state.sandbox.is_degraded {
        finish_submission(
            &state,
            &token,
            Status::internal_error(&format!(
                "Execution engine sandbox is degraded (fail-closed): {}",
                state.sandbox.degradation_reason.as_deref().unwrap_or("unknown")
            )),
            None,
            None,
            None,
            None,
            None,
        );
        return;
    }

    // 1. Transition status from "In Queue" to "Processing"
    {
        let mut subs = state.submissions.write().unwrap();
        if let Some(sub) = subs.get_mut(&token) {
            // Check if already cancelled while in queue
            if sub.status.id == 10 {
                return;
            }
            sub.status = Status::processing();
        } else {
            return;
        }
    }

    // 2. Setup temporary directory for isolated code file & compilation
    // Enforce private 0700 base directory for ephemeral workspaces to prevent cross-tenant directory inspection.
    // Uses JOBS_ROOT env var if specified, defaults to /var/lib/code_editor_engine_jobs (separate from noexec /tmp),
    // and falls back to /tmp/code_editor_engine_jobs for local unprivileged development.
    let jobs_base_path = if let Ok(custom_root) = std::env::var("JOBS_ROOT") {
        PathBuf::from(custom_root)
    } else {
        let var_lib = PathBuf::from("/var/lib/code_editor_engine_jobs");
        if var_lib.is_dir() {
            let probe = var_lib.join(".write_probe");
            if std::fs::write(&probe, b"").is_ok() {
                let _ = std::fs::remove_file(&probe);
                var_lib
            } else {
                PathBuf::from("/tmp/code_editor_engine_jobs")
            }
        } else if std::fs::create_dir_all(&var_lib).is_ok() {
            var_lib
        } else {
            PathBuf::from("/tmp/code_editor_engine_jobs")
        }
    };

    if !jobs_base_path.exists() {
        let _ = std::fs::create_dir_all(&jobs_base_path);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&jobs_base_path, std::fs::Permissions::from_mode(0o700));
    }

    let temp_dir = match tempfile::Builder::new().prefix("exec_").tempdir_in(&jobs_base_path) {
        Ok(dir) => dir,
        Err(e) => {
            finish_submission(
                &state,
                &token,
                Status::internal_error(&format!("Failed to create temporary directory: {e}")),
                None,
                None,
                None,
                None,
                None,
            );
            return;
        }
    };

    let dir_path = temp_dir.path();
    let filename = language
        .source_file
        .clone()
        .unwrap_or_else(|| "code".to_string());
    let source_path = dir_path.join(&filename);

    if let Err(e) = fs::write(&source_path, &req.source_code).await {
        finish_submission(
            &state,
            &token,
            Status::internal_error(&format!("Failed to write source code: {e}")),
            None,
            None,
            None,
            None,
            None,
        );
        return;
    }

    let mut compiled_artifact_hash: Option<String> = None;
    let mut artifact_rel_path: Option<PathBuf> = None;

    // 3. Compile if required by the language (Profile C: Compile Phase)
    if let Some(ref compile_cmd_str) = language.compile_cmd {
        let compile_parts: Vec<&str> = compile_cmd_str.split_whitespace().collect();
        if !compile_parts.is_empty() {
            let compiler_bin = compile_parts[0];
            let compiler_args = &compile_parts[1..];

            // Create dedicated Profile C cgroup v2 scope (128 pids, 1024MB memory)
            let cgroup_name = format!("cg_c_{}", &token[..8.min(token.len())]);
            let cgroup_scope = state.sandbox.create_cgroup_scope(&cgroup_name, SandboxProfile::Compile);
            let _compile_guard = CgroupGuard(cgroup_scope.clone());

            let compile_start = Instant::now();
            let mut cmd = match state.sandbox.build_sandboxed_command(
                dir_path,
                compiler_bin,
                compiler_args,
                SandboxProfile::Compile,
                &cgroup_scope,
            ) {
                Ok(c) => c,
                Err(e) => {
                    SandboxConfig::cleanup_cgroup_scope(&cgroup_scope);
                    finish_submission(
                        &state,
                        &token,
                        Status::internal_error(&format!("Sandbox creation error during compile: {e}")),
                        None,
                        None,
                        None,
                        None,
                        None,
                    );
                    return;
                }
            };

            cmd.stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);

            let child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    SandboxConfig::cleanup_cgroup_scope(&cgroup_scope);
                    finish_submission(
                        &state,
                        &token,
                        Status::compilation_error(),
                        None,
                        None,
                        Some(format!("Failed to launch compiler '{compiler_bin}' in sandbox: {e}")),
                        None,
                        None,
                    );
                    return;
                }
            };

            let compile_res = timeout(
                Duration::from_secs_f64(COMPILE_TIMEOUT_SECS),
                child.wait_with_output(),
            )
            .await;

            // Immediately destroy Profile C cgroup
            SandboxConfig::cleanup_cgroup_scope(&cgroup_scope);

            match compile_res {
                Ok(Ok(output)) => {
                    let stdout_str = String::from_utf8_lossy(&output.stdout);
                    let stderr_str = String::from_utf8_lossy(&output.stderr);
                    let full_output = format!("{}{}", stdout_str, stderr_str).trim().to_string();

                    if !output.status.success() {
                        finish_submission(
                            &state,
                            &token,
                            Status::compilation_error(),
                            None,
                            None,
                            Some(full_output),
                            output.status.code(),
                            Some(compile_start.elapsed().as_secs_f64()),
                        );
                        return;
                    }
                }
                Ok(Err(e)) => {
                    finish_submission(
                        &state,
                        &token,
                        Status::internal_error(&format!("Compiler execution failed: {e}")),
                        None,
                        None,
                        None,
                        None,
                        None,
                    );
                    return;
                }
                Err(_) => {
                    finish_submission(
                        &state,
                        &token,
                        Status::time_limit_exceeded(),
                        None,
                        None,
                        Some("Compilation timed out".to_string()),
                        None,
                        Some(COMPILE_TIMEOUT_SECS),
                    );
                    return;
                }
            }

            // Enforce aggregate workspace disk quota (512 MB) to prevent cross-tenant disk exhaustion
            if let Err(e) = SandboxConfig::check_directory_disk_usage(dir_path, 512 * 1024 * 1024) {
                finish_submission(
                    &state,
                    &token,
                    Status::internal_error("Aggregate disk quota exceeded in workspace (disk exhaustion DoS blocked)"),
                    None,
                    None,
                    Some(format!("CRITICAL RESOURCE ERROR: {e}")),
                    None,
                    None,
                );
                return;
            }

            // Anti-TOCTOU SHA-256 Hashing of generated binary artifact
            // Must use openat2 with RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS to structurally prevent symlink escapes
            let candidate_artifacts = ["main", "Main.class", &filename];
            for cand in candidate_artifacts {
                match SandboxConfig::open_artifact_no_follow(dir_path, cand) {
                    Ok(mut file) => {
                        match SandboxConfig::compute_sha256_fd(&mut file) {
                            Ok(hash) => {
                                compiled_artifact_hash = Some(hash);
                                artifact_rel_path = Some(PathBuf::from(cand));
                                break;
                            }
                            Err(e) => {
                                finish_submission(
                                    &state,
                                    &token,
                                    Status::internal_error(&format!("Failed computing artifact SHA-256: {e}")),
                                    None,
                                    None,
                                    None,
                                    None,
                                    None,
                                );
                                return;
                            }
                        }
                    }
                    Err(ref e)
                        if e.raw_os_error() == Some(libc::ELOOP)
                            || e.raw_os_error() == Some(libc::EXDEV)
                            || e.kind() == std::io::ErrorKind::PermissionDenied =>
                    {
                        // Malicious symlink or multi-link attack detected!
                        finish_submission(
                            &state,
                            &token,
                            Status::internal_error("Security violation: compilation artifact symlink/hardlink escape detected"),
                            None,
                            None,
                            Some(format!("CRITICAL SECURITY ERROR: Symlink/hardlink traversal detected in compilation output: {e}")),
                            None,
                            None,
                        );
                        return;
                    }
                    Err(_) => {
                        // Candidate not found, check next
                    }
                }
            }
        }
    }

    // 4. Anti-TOCTOU Verification: Verify binary checksum immediately before execution
    if let (Some(original_hash), Some(rel_path)) = (&compiled_artifact_hash, &artifact_rel_path) {
        let rel_str = rel_path.to_string_lossy();
        match SandboxConfig::open_artifact_no_follow(dir_path, &rel_str) {
            Ok(mut file) => {
                match SandboxConfig::compute_sha256_fd(&mut file) {
                    Ok(ref verify_hash) if verify_hash == original_hash => {
                        // Checksum verified: zero TOCTOU alteration
                    }
                    Ok(_) => {
                        finish_submission(
                            &state,
                            &token,
                            Status::internal_error("Anti-TOCTOU validation failure: artifact checksum mismatch between compile and execution phases"),
                            None,
                            None,
                            None,
                            None,
                            None,
                        );
                        return;
                    }
                    Err(e) => {
                        finish_submission(
                            &state,
                            &token,
                            Status::internal_error(&format!("Anti-TOCTOU validation error: {e}")),
                            None,
                            None,
                            None,
                            None,
                            None,
                        );
                        return;
                    }
                }
            }
            Err(ref e)
                if e.raw_os_error() == Some(libc::ELOOP)
                    || e.raw_os_error() == Some(libc::EXDEV)
                    || e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                finish_submission(
                    &state,
                    &token,
                    Status::internal_error("Security violation: compilation artifact symlink/hardlink escape detected"),
                    None,
                    None,
                    Some(format!("CRITICAL SECURITY ERROR: Symlink/hardlink traversal detected during TOCTOU verification: {e}")),
                    None,
                    None,
                );
                return;
            }
            Err(e) => {
                finish_submission(
                    &state,
                    &token,
                    Status::internal_error(&format!("Anti-TOCTOU validation failed to open artifact safely: {e}")),
                    None,
                    None,
                    None,
                    None,
                    None,
                );
                return;
            }
        }
    }

    // 5. Run execution (Profile E: Execution Phase)
    let run_cmd_str = language.run_cmd.unwrap_or_else(|| format!("./{}", filename));
    let run_parts: Vec<&str> = run_cmd_str.split_whitespace().collect();
    if run_parts.is_empty() {
        finish_submission(
            &state,
            &token,
            Status::internal_error("No run command configured for language"),
            None,
            None,
            None,
            None,
            None,
        );
        return;
    }

    let runner_bin = run_parts[0];
    let runner_args = &run_parts[1..];

    let cpu_limit = req
        .cpu_time_limit
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
        .clamp(0.1, MAX_TIMEOUT_SECS);

    // Create dedicated Profile E cgroup v2 scope (96 pids, 512MB memory)
    let cgroup_name = format!("cg_e_{}", &token[..8.min(token.len())]);
    let cgroup_scope = state.sandbox.create_cgroup_scope(&cgroup_name, SandboxProfile::Execution);
    let _exec_guard = CgroupGuard(cgroup_scope.clone());

    let mut cmd = match state.sandbox.build_sandboxed_command(
        dir_path,
        runner_bin,
        runner_args,
        SandboxProfile::Execution,
        &cgroup_scope,
    ) {
        Ok(c) => c,
        Err(e) => {
            SandboxConfig::cleanup_cgroup_scope(&cgroup_scope);
            finish_submission(
                &state,
                &token,
                Status::internal_error(&format!("Sandbox creation error during execution: {e}")),
                None,
                None,
                None,
                None,
                None,
            );
            return;
        }
    };

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            SandboxConfig::cleanup_cgroup_scope(&cgroup_scope);
            finish_submission(
                &state,
                &token,
                Status::runtime_error(&format!("Failed to start sandboxed runtime executable '{runner_bin}': {e}")),
                None,
                Some(format!("Execution launch error: {e}")),
                None,
                None,
                None,
            );
            return;
        }
    };

    // Feed stdin if provided
    if let Some(mut stdin_pipe) = child.stdin.take() {
        if let Some(ref input) = req.stdin {
            let input_bytes = input.as_bytes();
            let _ = stdin_pipe.write_all(input_bytes).await;
        }
        let _ = stdin_pipe.shutdown().await;
    }

    let start_instant = Instant::now();
    let timeout_duration = Duration::from_secs_f64(cpu_limit);

    // Read stdout & stderr asynchronously while watching process exit and timeout
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_future = async {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                if buf.len() + n <= MAX_OUTPUT_BYTES {
                    buf.extend_from_slice(&chunk[..n]);
                } else {
                    let remaining = MAX_OUTPUT_BYTES.saturating_sub(buf.len());
                    buf.extend_from_slice(&chunk[..remaining]);
                    break;
                }
            }
        }
        buf
    };

    let stderr_future = async {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr_pipe {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                if buf.len() + n <= MAX_OUTPUT_BYTES {
                    buf.extend_from_slice(&chunk[..n]);
                } else {
                    let remaining = MAX_OUTPUT_BYTES.saturating_sub(buf.len());
                    buf.extend_from_slice(&chunk[..remaining]);
                    break;
                }
            }
        }
        buf
    };

    let exec_future = async {
        let (out_res, err_res, status_res) =
            tokio::join!(stdout_future, stderr_future, child.wait());
        (out_res, err_res, status_res)
    };

    match timeout(timeout_duration, exec_future).await {
        Ok((stdout_bytes, stderr_bytes, status_res)) => {
            // Clean up cgroup scope immediately
            SandboxConfig::cleanup_cgroup_scope(&cgroup_scope);

            let elapsed_secs = start_instant.elapsed().as_secs_f64();
            let stdout_str = String::from_utf8_lossy(&stdout_bytes).to_string();
            let stderr_str = String::from_utf8_lossy(&stderr_bytes).to_string();

            let (exit_code, status) = match status_res {
                Ok(exit_status) => {
                    let code = exit_status.code();
                    if exit_status.success() {
                        // Compare with expected_output if provided
                        if let Some(ref expected) = req.expected_output {
                            if stdout_str.trim_end() == expected.trim_end() {
                                (code, Status::accepted())
                            } else {
                                (code, Status::wrong_answer())
                            }
                        } else {
                            (code, Status::accepted())
                        }
                    } else {
                        (
                            code,
                            Status::runtime_error(&format!("Exit code: {:?}", code.unwrap_or(-1))),
                        )
                    }
                }
                Err(e) => (
                    None,
                    Status::runtime_error(&format!("Failed waiting for sandboxed process: {e}")),
                ),
            };

            finish_submission(
                &state,
                &token,
                status,
                Some(stdout_str),
                if stderr_str.is_empty() {
                    None
                } else {
                    Some(stderr_str)
                },
                None,
                exit_code,
                Some(elapsed_secs),
            );
        }
        Err(_) => {
            // Timed out: child will be killed automatically via kill_on_drop and cgroup.kill
            SandboxConfig::cleanup_cgroup_scope(&cgroup_scope);

            finish_submission(
                &state,
                &token,
                Status::time_limit_exceeded(),
                None,
                Some("Time limit exceeded".to_string()),
                None,
                None,
                Some(cpu_limit),
            );
        }
    }
}

fn finish_submission(
    state: &AppState,
    token: &str,
    status: Status,
    stdout: Option<String>,
    stderr: Option<String>,
    compile_output: Option<String>,
    exit_code: Option<i32>,
    time: Option<f64>,
) {
    // Clean up abort handle
    {
        let mut handles = state.abort_handles.write().unwrap();
        handles.remove(token);
    }

    // Update submission record
    let mut subs = state.submissions.write().unwrap();
    if let Some(sub) = subs.get_mut(token) {
        // If it was already marked cancelled, don't overwrite with execution outcome
        if sub.status.id == 10 {
            return;
        }
        sub.status = status;
        sub.stdout = stdout;
        sub.stderr = stderr;
        sub.compile_output = compile_output;
        sub.exit_code = exit_code;
        sub.time = time;
        sub.finished_at = Some(Utc::now());
    }
}
