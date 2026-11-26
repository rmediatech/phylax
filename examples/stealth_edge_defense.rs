//! # Phylax Stealth Deception & Active Defense Example
//!
//! Demonstrates production-grade active edge defense without tipping off automated attackers:
//! 1. **Synthetic Black Hole (Mock 201 Created)**: If a bot populates a hidden decoy honeypot field,
//!    the server returns a fake success response. The payload is silently dropped to the void,
//!    wasting the attacker's compute while keeping databases and email systems untouched.
//! 2. **Indistinguishable Auth Rejection (Generic 401)**: Honeypot-trapped login attempts return
//!    standard invalid credential errors with realistic delay rather than 403 Forbidden.
//! 3. **Perimeter Ghosting (Stealth 404)**: Requests from hostile datacenters or quarantined CIDRs
//!    receive standard plain-text 404 Not Found responses rather than security rejection banners.
//! 4. **Optional Autonomous Reporting**: Triggers background incident dossiers when abuse-reporting is active.
//!
//! Run with:
//! ```bash
//! cargo run --example stealth_edge_defense
//! ```

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use phylax::prelude::*;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    // Decoy honeypot field (hidden via CSS/DOM; bots populate this, humans leave empty)
    website_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[allow(dead_code)]
    username: String,
    #[allow(dead_code)]
    password: String,
    website_url: Option<String>,
}

#[tokio::main]
async fn main() {
    // 1. Initialize sovereign Phylax pipeline with 12-layer fail-fast defense
    let builder = PhylaxPipeline::builder()
        .secret_key(b"sovereign_stealth_defense_master_secret_2026")
        .with_honeypot_fields(["website_url", "company_fax"])
        .with_timing(1500, 600_000) // 1.5s human cadence floor, 10 min window
        .with_pow(12, 300_000) // 12-bit baseline Proof-of-Work
        .with_quarantine(QuarantineConfig::default())
        .with_adaptive_pow(AdaptivePowConfig::default());

    #[cfg(feature = "abuse-reporting")]
    let builder = builder.with_default_abuse_reporting();

    let phylax = Arc::new(builder.build());

    // 2. Spawn autonomous in-memory hygiene worker (sweeps expired bans every 60s)
    let _maintenance_handle = phylax.spawn_background_maintenance(Duration::from_secs(60));

    let state = AppState { phylax };

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/shield/challenge", get(challenge_handler))
        .route("/api/auth/register", post(register_handler))
        .route("/api/auth/login", post(login_handler))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            stealth_perimeter_middleware,
        ))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    println!("═════════════════════════════════════════════════════════════════");
    println!("🛡️  Phylax Stealth Deception Edge Defense Example");
    println!("   Listening on: http://{}", addr);
    println!("   Try testing honeypot deception:");
    println!("   curl -X POST http://{}/api/auth/register \\", addr);
    println!("        -H 'Content-Type: application/json' \\");
    println!("        -d '{{\"username\":\"bot1\",\"email\":\"bot@mail.com\",\"website_url\":\"http://spam.xyz\"}}'");
    println!("═════════════════════════════════════════════════════════════════");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

/// Perimeter middleware: Stealthily drops hostile subnets and quarantined IPs with generic 404
async fn stealth_perimeter_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let client_ip = extract_client_ip(&headers, addr);
    let now_ms = current_timestamp_ms();

    let shield_req = PhylaxRequest {
        client_ip: &client_ip,
        target_uri: Some(req.uri().path()),
        http_method: Some(req.method().as_str()),
        now_ms,
        ..Default::default()
    };

    // Evaluate perimeter (quarantine & datacenter/Tor filters)
    if let PhylaxVerdict::Deny(_) = state.phylax.evaluate_perimeter(&shield_req) {
        // Return plain 404 Not Found rather than 403 Forbidden to deny reconnaissance telemetry
        return (StatusCode::NOT_FOUND, "404 Not Found\n").into_response();
    }

    next.run(req).await
}

async fn index_handler() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html>
<head><title>Phylax Stealth Deception Server</title></head>
<body style="font-family: sans-serif; padding: 2rem; max-width: 650px; margin: auto; line-height: 1.6;">
    <h1>🛡️ Phylax Stealth Deception Defense</h1>
    <p>This server implements <strong>Stealth Neutralization</strong>. Attackers never receive <code>403 Forbidden</code> errors or security banners.</p>
    <ul>
        <li><code>GET /api/shield/challenge</code> — Issues timing tokens and micro-PoW challenges.</li>
        <li><code>POST /api/auth/register</code> — Returns synthetic <code>201 Created</code> black hole if honeypot is tripped.</li>
        <li><code>POST /api/auth/login</code> — Returns indistinguishable generic <code>401 Unauthorized</code> if honeypot is tripped.</li>
    </ul>
</body>
</html>"#,
    )
}

async fn challenge_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(&headers, addr);
    let now_ms = current_timestamp_ms();
    let seed_nonce = current_timestamp_ms().wrapping_mul(6364136223846793005);
    let ctx = state
        .phylax
        .issue_client_context_for_ip(&client_ip, now_ms, seed_nonce);
    Json(ctx)
}

/// Registration handler: Deceptive Black Hole on honeypot infractions
async fn register_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(&headers, addr);
    let now_ms = current_timestamp_ms();

    // 1. Check decoy honeypot field
    if let Some(ref decoy) = payload.website_url {
        if !decoy.trim().is_empty() {
            println!(
                "🚨 [Phylax] Honeypot decoy tripped by IP: {} (username: '{}'). Engaging Deceptive Black Hole.",
                client_ip, payload.username
            );

            // Record infraction in pipeline (quarantining IP and ratcheting PoW difficulty)
            let trapped_fields = vec![("website_url".to_string(), decoy.clone())];
            let shield_req = PhylaxRequest {
                client_ip: &client_ip,
                submitted_fields: &trapped_fields,
                target_uri: Some("/api/auth/register"),
                http_method: Some("POST"),
                now_ms,
                ..Default::default()
            };
            let _ = state.phylax.evaluate_perimeter(&shield_req);

            // Return synthetic 201 Created. The bot believes it registered and exits.
            // Nothing touches the database, no emails are dispatched.
            return (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "status": "SUCCESS",
                    "user_id": 99999,
                    "uuid": "usr_stealth_trap",
                    "username": payload.username,
                    "email": payload.email,
                    "message": "Account created successfully."
                })),
            );
        }
    }

    // 2. Normal legitimate human evaluation
    let req = PhylaxRequest {
        client_ip: &client_ip,
        timing_token: payload.timing_token.as_deref(),
        pow_challenge_token: payload.pow_challenge.as_deref(),
        pow_nonce: payload.pow_nonce,
        email: Some(&payload.email),
        target_uri: Some("/api/auth/register"),
        http_method: Some("POST"),
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
                "user_id": 1001,
                "username": payload.username,
                "email": canonical_email.unwrap_or(payload.email),
                "message": "Legitimate registration accepted."
            })),
        ),
        PhylaxVerdict::AllowSibling { caller, .. } => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "status": "SUCCESS",
                "user_id": 1001,
                "username": payload.username,
                "email": payload.email,
                "message": format!("Sovereign sibling [{}] accepted.", caller)
            })),
        ),
        PhylaxVerdict::Deny(_) => {
            // Stealth response: plain generic error without revealing Phylax rules
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "ERROR",
                    "message": "Unable to complete registration request. Please try again."
                })),
            )
        }
    }
}

/// Login handler: Deceptive generic 401 on honeypot infractions
async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(&headers, addr);
    let now_ms = current_timestamp_ms();

    // Check decoy honeypot field
    if let Some(ref decoy) = payload.website_url {
        if !decoy.trim().is_empty() {
            println!(
                "🚨 [Phylax] Honeypot decoy tripped during login by IP: {}. Returning generic 401.",
                client_ip
            );

            // Record infraction in pipeline
            let trapped_fields = vec![("website_url".to_string(), decoy.clone())];
            let shield_req = PhylaxRequest {
                client_ip: &client_ip,
                submitted_fields: &trapped_fields,
                target_uri: Some("/api/auth/login"),
                http_method: Some("POST"),
                now_ms,
                ..Default::default()
            };
            let _ = state.phylax.evaluate_perimeter(&shield_req);

            // Simulated timing delay (150ms) to mirror cryptographic hash verification
            tokio::time::sleep(Duration::from_millis(150)).await;

            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "status": "ERROR",
                    "message": "Invalid username or password. Please try again."
                })),
            );
        }
    }

    // Normal mock authentication
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "SUCCESS",
            "token": "demo_session_jwt_valid"
        })),
    )
}

fn extract_client_ip(headers: &HeaderMap, addr: SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| addr.ip().to_string())
}
