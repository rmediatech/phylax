//! # `phylax` Axum Edge Defense Example
//! Demonstrates full edge protection with honeypots, timing verification, and Proof-of-Work.
//!
//! Run with: `cargo run --example axum_edge_defense`

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use phylax::prelude::*;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[derive(Clone)]
struct AppState {
    phylax: Arc<PhylaxPipeline>,
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    email: String,
    username: String,
    #[allow(dead_code)]
    password: String,
    timing_token: Option<String>,
    pow_challenge: Option<String>,
    pow_nonce: Option<u64>,
    // Decoy honeypot field (bots populate this, humans leave empty)
    website_url: Option<String>,
}

#[tokio::main]
async fn main() {
    let phylax = Arc::new(
        PhylaxPipeline::builder()
            .secret_key(b"sovereign_phylax_enterprise_secret_2026")
            .with_timing(1500, 86_400_000) // minimum 1.5s human pacing
            .with_pow(14, 300_000) // 14-bit micro-PoW puzzle
            .build(),
    );

    let state = AppState { phylax };

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/shield/challenge", get(challenge_handler))
        .route("/auth/register", post(register_handler))
        .with_state(state);

    let addr = "127.0.0.1:4000";
    println!("🛡️ Phylax Edge Defense Example running on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index_handler() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html>
<head><title>Phylax Edge Defense Demo</title></head>
<body>
    <h1>Phylax Sovereign Edge Defense</h1>
    <p>Endpoints active:</p>
    <ul>
        <li><code>GET /api/shield/challenge</code> — Issue challenge token + PoW</li>
        <li><code>POST /auth/register</code> — Protected fail-fast registration</li>
    </ul>
</body>
</html>"#,
    )
}

async fn challenge_handler(State(state): State<AppState>) -> impl IntoResponse {
    let now_ms = current_timestamp_ms();
    let seed_nonce = rand_nonce();
    let ctx = state.phylax.issue_client_context(now_ms, seed_nonce);
    Json(ctx)
}

async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let now_ms = current_timestamp_ms();
    let mut submitted_fields = Vec::new();
    if let Some(ref w) = payload.website_url {
        submitted_fields.push(("website_url".to_string(), w.clone()));
    }

    let req = PhylaxRequest {
        client_ip: "127.0.0.1",
        submitted_fields: &submitted_fields,
        timing_token: payload.timing_token.as_deref(),
        pow_challenge_token: payload.pow_challenge.as_deref(),
        pow_nonce: payload.pow_nonce,
        email: Some(&payload.email),
        now_ms,
        ..Default::default()
    };

    match state.phylax.evaluate(&req) {
        PhylaxVerdict::Allow {
            canonical_email, ..
        } => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "status": "SUCCESS",
                "message": "Human operator verified. Account created.",
                "canonical_email": canonical_email,
                "username": payload.username
            })),
        ),
        PhylaxVerdict::AllowSibling { caller, .. } => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "status": "SUCCESS",
                "message": format!("Sovereign sibling [{}] verified with diplomatic immunity.", caller),
                "canonical_email": None::<String>,
                "username": payload.username
            })),
        ),
        PhylaxVerdict::Deny(reason) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "status": "BLOCKED",
                "error": reason.public_message()
            })),
        ),
    }
}

fn rand_nonce() -> u64 {
    current_timestamp_ms().wrapping_mul(6364136223846793005)
}
