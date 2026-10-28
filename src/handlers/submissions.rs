use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::{
    models::{
        status::Status,
        submission::{
            CancelSubmissionResponse, CreateSubmissionRequest, CreateSubmissionResponse,
            SubmissionRecord,
        },
    },
    services::executor::execute_submission,
    state::AppState,
};

// POST /submissions
// Creates a code execution job (returns a tracking token)
pub async fn create_submission(
    State(state): State<AppState>,
    Json(payload): Json<CreateSubmissionRequest>,
) -> impl IntoResponse {
    // Fail-Closed Security Policy: Refuse all untrusted code if sandbox is degraded
    if state.sandbox.is_degraded {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "Execution engine sandbox is degraded and refusing untrusted execution (Fail-Closed Policy)",
                "degradation_reason": state.sandbox.degradation_reason
            })),
        );
    }

    // 1. Validate language
    let language = match state.languages.get(&payload.language_id) {
        Some(lang) => lang.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Unsupported language_id",
                    "provided_id": payload.language_id
                })),
            );
        }
    };

    // 2. Validate source code
    if payload.source_code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "source_code must not be empty"
            })),
        );
    }

    // 3. Generate tracking token
    let token = Uuid::new_v4().to_string();
    let initial_status = Status::in_queue();

    let record = SubmissionRecord {
        token: token.clone(),
        language_id: language.id,
        language_name: language.name.clone(),
        status: initial_status.clone(),
        stdout: None,
        stderr: None,
        compile_output: None,
        exit_code: None,
        time: None,
        memory: None,
        created_at: Utc::now(),
        finished_at: None,
    };

    // 4. Store initial record
    {
        let mut subs = state.submissions.write().unwrap();
        subs.insert(token.clone(), record);
    }

    // 5. Spawn background executor task & track abort handle
    let task_state = state.clone();
    let task_token = token.clone();
    let join_handle = tokio::spawn(async move {
        execute_submission(task_state, task_token, language, payload).await;
    });

    {
        let mut handles = state.abort_handles.write().unwrap();
        handles.insert(token.clone(), join_handle.abort_handle());
    }

    let response = CreateSubmissionResponse {
        token,
        status: initial_status,
    };

    (StatusCode::CREATED, Json(json!(response)))
}

// GET /submissions/{token}
// Fetches the execution output, errors, metrics, and execution status
pub async fn get_submission(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let subs = state.submissions.read().unwrap();
    if let Some(submission) = subs.get(&token) {
        (StatusCode::OK, Json(json!(submission)))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Submission not found",
                "token": token
            })),
        )
    }
}

// DELETE /submissions/{token}
// Cancels/deletes a pending or active submission in the execution queue
pub async fn delete_submission(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    // 1. Abort background task if running or in queue
    let was_running = {
        let mut handles = state.abort_handles.write().unwrap();
        if let Some(handle) = handles.remove(&token) {
            handle.abort();
            true
        } else {
            false
        }
    };

    // 2. Mark submission as Cancelled
    let mut subs = state.submissions.write().unwrap();
    if let Some(sub) = subs.get_mut(&token) {
        sub.status = Status::cancelled();
        sub.finished_at = Some(Utc::now());

        let res = CancelSubmissionResponse {
            message: if was_running {
                "Active submission was aborted and marked cancelled".to_string()
            } else {
                "Submission marked as cancelled".to_string()
            },
            token: token.clone(),
            status: Status::cancelled(),
        };

        (StatusCode::OK, Json(json!(res)))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Submission not found",
                "token": token
            })),
        )
    }
}
