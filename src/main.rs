use std::net::SocketAddr;
use axum::{
    http::Method,
    response::Html,
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use CodeEditorENGINE::{handlers, state};

use handlers::{
    languages::{get_language_by_id, list_languages},
    statuses::list_statuses,
    submissions::{create_submission, delete_submission, get_submission},
};
use state::AppState;

#[tokio::main]
async fn main() {
    // Initialize tracing / structured logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "code_editor_engine=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Shared state
    let state = AppState::new();

    // CORS configuration allowing access for web-based code editors
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    // Build the Axum router with all required API endpoints
    let app = Router::new()
        // Welcome and health routes
        .route("/", get(welcome_handler))
        .route("/health", get(health_handler))
        // Languages APIs
        .route("/languages", get(list_languages))
        .route("/languages/{id}", get(get_language_by_id))
        // Statuses API
        .route("/statuses", get(list_statuses))
        // Submissions APIs
        .route("/submissions", post(create_submission))
        .route("/submissions/{token}", get(get_submission))
        .route("/submissions/{token}", delete(delete_submission))
        .layer(cors)
        .with_state(state);

    // Bind server to port 3000
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("========================================================");
    println!("  CodeEditorENGINE API Server running on port 3000");
    println!("  Listening on http://localhost:3000 (all interfaces 0.0.0.0:3000)");
    println!("========================================================");
    println!("  GET    /languages            - List all supported languages");
    println!("  GET    /languages/{{id}}       - Get runtime details for language");
    println!("  GET    /statuses             - List all execution status types");
    println!("  POST   /submissions          - Create code execution submission");
    println!("  GET    /submissions/{{token}}  - Get submission status & output");
    println!("  DELETE /submissions/{{token}}  - Cancel pending/active submission");
    println!("========================================================");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("CRITICAL: Failed to bind to port 3000: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("CRITICAL: Server encountered error: {err}");
    }
}

async fn welcome_handler() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html>
<html>
<head><title>CodeEditorENGINE API</title></head>
<body style="font-family: system-ui, sans-serif; padding: 2rem; max-width: 800px; margin: 0 auto; line-height: 1.6;">
  <h1>CodeEditorENGINE API</h1>
  <p>Code execution engine running on Axum / Tokio (Port 3000).</p>
  <ul>
    <li><code>GET /languages</code> - List supported programming languages</li>
    <li><code>GET /languages/{id}</code> - Get details for a specific language</li>
    <li><code>GET /statuses</code> - List all execution status types</li>
    <li><code>POST /submissions</code> - Create code execution submission</li>
    <li><code>GET /submissions/{token}</code> - Fetch execution output & metrics</li>
    <li><code>DELETE /submissions/{token}</code> - Cancel/delete an active submission</li>
  </ul>
</body>
</html>"#)
}

async fn health_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": if state.sandbox.is_degraded { "degraded" } else { "healthy" },
        "service": "CodeEditorENGINE",
        "port": 3000,
        "sandbox": {
            "anti_toctou_sha256": true,
            "bwrap_containerization": state.sandbox.has_bwrap && !state.sandbox.is_degraded,
            "bwrap_version": state.sandbox.bwrap_version,
            "cgroup_v2_controller": state.sandbox.cgroup_base_dir.is_some(),
            "cgroup_subtree_control": state.sandbox.cgroup_subtree_control,
            "kernel_release": state.sandbox.kernel_release,
            "kernel_supports_cgroup_kill": state.sandbox.kernel_supports_cgroup_kill,
            "unprivileged_userns_enabled": state.sandbox.unprivileged_userns_enabled,
            "seccomp_bpf": !state.sandbox.is_degraded,
            "seccomp_probes_passed": state.sandbox.seccomp_probes_passed,
            "prlimit_backstop": state.sandbox.has_prlimit,
            "is_degraded": state.sandbox.is_degraded,
            "degradation_reason": state.sandbox.degradation_reason,
        }
    }))
}
