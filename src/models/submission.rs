use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::status::Status;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateSubmissionRequest {
    pub language_id: u32,
    pub source_code: String,
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default)]
    pub expected_output: Option<String>,
    #[serde(default)]
    pub cpu_time_limit: Option<f64>,
    #[serde(default)]
    #[allow(dead_code)]
    pub memory_limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateSubmissionResponse {
    pub token: String,
    pub status: Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionRecord {
    pub token: String,
    pub language_id: u32,
    pub language_name: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<u64>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct CancelSubmissionResponse {
    pub message: String,
    pub token: String,
    pub status: Status,
}
