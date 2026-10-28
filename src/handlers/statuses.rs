use axum::{http::StatusCode, response::IntoResponse, Json};

use crate::models::status::get_all_statuses;

// GET /statuses
// Lists all possible execution status types (e.g., Accepted, Runtime Error)
pub async fn list_statuses() -> impl IntoResponse {
    let statuses = get_all_statuses();
    (StatusCode::OK, Json(statuses))
}
