use std::net::SocketAddr;
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;
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

    // Strict CORS configuration allowing access ONLY to configured PUBLIC_URL origins
    let allowed_header_values: Vec<HeaderValue> = state
        .allowed_origins
        .iter()
        .filter_map(|s| s.parse::<HeaderValue>().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(allowed_header_values)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            header::ORIGIN,
            axum::http::HeaderName::from_static("x-auth-token"),
        ]);

    // Build the Axum router with URL Authorization middleware & CORS
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
        .layer(middleware::from_fn_with_state(state.clone(), url_auth_middleware))
        .layer(cors)
        .with_state(state.clone());

    // Bind server to port 3000
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("========================================================");
    println!("  CodeEditorENGINE API Server running on port 3000");
    println!("  Listening on http://localhost:3000 (0.0.0.0:3000)");
    println!("========================================================");
    println!("  [URL AUTHENTICATION ACTIVE]");
    println!("  Allowed Origins: {:?}", state.allowed_origins);
    println!("  Allowed Hosts:   {:?}", state.allowed_hosts);
    if state.auth_token.is_some() {
        println!("  Bearer/Header Token Auth: ENABLED");
    }
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

/// URL and Token Authorization Middleware
/// Enforces that only requests originating from or targeting the configured PUBLIC_URL are allowed.
async fn url_auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = req.uri().path();

    // 1. Health check is always permitted for internal Docker/Coolify container health checks
    if path == "/health" {
        return Ok(next.run(req).await);
    }

    // 2. Allow CORS preflight requests through to the CorsLayer
    if req.method() == Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    // 3. Check for Bearer token or X-Auth-Token if configured
    if let Some(ref expected_token) = state.auth_token {
        if let Some(auth_val) = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
            let token = auth_val.strip_prefix("Bearer ").unwrap_or(auth_val).trim();
            if token == expected_token {
                return Ok(next.run(req).await);
            }
        }
        if let Some(token_val) = req.headers().get("x-auth-token").and_then(|h| h.to_str().ok()) {
            if token_val.trim() == expected_token {
                return Ok(next.run(req).await);
            }
        }
    }

    // 4. Validate Origin header if present (browser requests)
    if let Some(origin_val) = req.headers().get(header::ORIGIN).and_then(|h| h.to_str().ok()) {
        let clean = origin_val.trim_end_matches('/');
        if state.allowed_origins.iter().any(|allowed| allowed == clean) {
            return Ok(next.run(req).await);
        } else {
            tracing::warn!("Forbidden: Request from unauthorized Origin '{}'", origin_val);
            let resp = (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Forbidden",
                    "message": format!("Access denied: Origin '{}' is not authorized by PUBLIC_URL policy.", origin_val)
                })),
            ).into_response();
            return Err(resp);
        }
    }

    // 5. Validate Referer header if present
    if let Some(referer_val) = req.headers().get(header::REFERER).and_then(|h| h.to_str().ok()) {
        if state.allowed_origins.iter().any(|allowed| referer_val.starts_with(allowed)) {
            return Ok(next.run(req).await);
        } else {
            tracing::warn!("Forbidden: Request from unauthorized Referer '{}'", referer_val);
            let resp = (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Forbidden",
                    "message": "Access denied: Referer is not authorized by PUBLIC_URL policy."
                })),
            ).into_response();
            return Err(resp);
        }
    }

    // 6. Direct HTTP client (no Origin/Referer): validate Host header
    if let Some(host_val) = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()) {
        let clean_host = host_val.trim();
        let matches_host = state.allowed_hosts.iter().any(|h| h == clean_host)
            || clean_host.starts_with("127.0.0.1")
            || clean_host.starts_with("localhost");

        if matches_host {
            return Ok(next.run(req).await);
        } else {
            tracing::warn!("Forbidden: Request with unauthorized Host '{}'", host_val);
            let resp = (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Forbidden",
                    "message": format!("Access denied: Host '{}' is not authorized by PUBLIC_URL policy.", host_val)
                })),
            ).into_response();
            return Err(resp);
        }
    }

    Ok(next.run(req).await)
}

async fn welcome_handler() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html>
<html>
<head><title>CodeEditorENGINE API</title></head>
<body style="font-family: system-ui, sans-serif; padding: 2rem; max-width: 800px; margin: 0 auto; line-height: 1.6;">
  <h1>CodeEditorENGINE API</h1>
  <p>Hardened Sandbox Code Execution Engine with URL Authentication.</p>
  <ul>
    <li><code>GET /health</code> - Check sandbox boundaries & health status</li>
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
        "url_auth": {
            "allowed_origins": state.allowed_origins.as_ref(),
            "token_auth_enabled": state.auth_token.is_some()
        },
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
