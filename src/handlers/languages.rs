use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::{models::language::LanguageSummary, state::AppState};

// GET /languages
// Lists all supported programming languages and their unique id values
pub async fn list_languages(State(state): State<AppState>) -> impl IntoResponse {
    let mut langs: Vec<LanguageSummary> = state
        .languages
        .values()
        .map(LanguageSummary::from)
        .collect();

    // Sort by id for predictable ordering
    langs.sort_by_key(|l| l.id);

    (StatusCode::OK, Json(langs))
}

// GET /languages/{id}
// Gets details for a specific language runtime environment
pub async fn get_language_by_id(
    State(state): State<AppState>,
    Path(id): Path<u32>,
) -> impl IntoResponse {
    if let Some(language) = state.languages.get(&id) {
        (StatusCode::OK, Json(json!(language)))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Language not found",
                "requested_id": id
            })),
        )
    }
}
