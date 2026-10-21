//! # Phylax Reverse Proxy Request Handlers
//! One-Job: Handle incoming HTTP requests, evaluate Phylax defense layers, and forward clean traffic upstream.

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::header::HeaderMap;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use phylax::pipeline::{DenialReason, PhylaxPipeline, PhylaxRequest, ShieldVerdict};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct ProxyState {
    pub pipeline: Arc<PhylaxPipeline>,
    pub http_client: reqwest::Client,
    pub upstream: String,
    pub start_time: Instant,
}

pub async fn handle_challenge(State(state): State<ProxyState>) -> impl IntoResponse {
    let now_ms = current_timestamp_ms();
    let seed_nonce = rand_nonce();
    let ctx = state.pipeline.issue_client_context(now_ms, seed_nonce);
    (StatusCode::OK, axum::Json(ctx))
}

pub async fn handle_healthz(State(state): State<ProxyState>) -> impl IntoResponse {
    let uptime_s = state.start_time.elapsed().as_secs();
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": "HEALTHY",
            "uptime_seconds": uptime_s,
            "engine": "Phylax Sovereign Edge Defense",
            "version": "0.1.0"
        })),
    )
}

pub async fn handle_status(State(state): State<ProxyState>) -> impl IntoResponse {
    let now_ms = current_timestamp_ms();
    let report = state.pipeline.run_maintenance(now_ms);
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "maintenance_report": report,
            "active_quarantined_subnets": state.pipeline.quarantine().active_bans_count(),
            "active_pow_records": state.pipeline.adaptive_pow().tracked_ips_count(),
            "uptime_seconds": state.start_time.elapsed().as_secs()
        })),
    )
}

pub async fn handle_proxy(
    State(state): State<ProxyState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now_ms = current_timestamp_ms();

    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    let mut submitted_fields = Vec::new();
    let mut timing_token = None;
    let mut pow_challenge = None;
    let mut pow_nonce = None;

    if let Some(query_str) = uri.query() {
        for pair in query_str.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "timing_token" || k == "phylax_timing" {
                    timing_token = Some(v.to_string());
                } else if k == "pow_challenge" || k == "phylax_challenge" {
                    pow_challenge = Some(v.to_string());
                } else if k == "pow_nonce" || k == "phylax_nonce" {
                    pow_nonce = v.parse::<u64>().ok();
                } else {
                    submitted_fields.push((k.to_string(), v.to_string()));
                }
            }
        }
    }

    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
        if let Some(obj) = json.as_object() {
            for (k, v) in obj {
                let v_str = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                if k == "timing_token" || k == "phylax_timing" {
                    timing_token = Some(v_str);
                } else if k == "pow_challenge" || k == "phylax_challenge" {
                    pow_challenge = Some(v_str);
                } else if k == "pow_nonce" || k == "phylax_nonce" {
                    pow_nonce = v_str.parse::<u64>().ok();
                } else {
                    submitted_fields.push((k.clone(), v_str));
                }
            }
        }
    }

    let target_uri = uri.path();
    let http_method = method.as_str();

    let req = PhylaxRequest {
        client_ip: &client_ip,
        submitted_fields: &submitted_fields,
        timing_token: timing_token.as_deref(),
        pow_challenge_token: pow_challenge.as_deref(),
        pow_nonce,
        email: None,
        target_uri: Some(target_uri),
        http_method: Some(http_method),
        user_agent: headers.get("user-agent").and_then(|v| v.to_str().ok()),
        now_ms,
    };

    let verdict = if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        state.pipeline.evaluate_perimeter(&req)
    } else {
        state.pipeline.evaluate(&req)
    };

    if let ShieldVerdict::Deny(reason) = verdict {
        println!(
            "  🛡️  [PHYLAX BLOCKED] Source: {} | Endpoint: {} {} | Reason: {}",
            client_ip,
            http_method,
            target_uri,
            reason.public_message()
        );

        let status = match &reason {
            DenialReason::DecoyUriTrapped { .. } => StatusCode::NOT_FOUND,
            _ => StatusCode::FORBIDDEN,
        };

        return (
            status,
            axum::Json(serde_json::json!({
                "status": "BLOCKED",
                "error": reason.public_message(),
                "engine": "Phylax Sovereign Edge Defense"
            })),
        )
            .into_response();
    }

    let upstream_url = format!(
        "{}{}",
        state.upstream,
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("")
    );

    let mut forward_req = state.http_client.request(method, &upstream_url);

    for (name, val) in &headers {
        let name_str = name.as_str().to_lowercase();
        if !matches!(
            name_str.as_str(),
            "host" | "connection" | "keep-alive" | "transfer-encoding"
        ) {
            forward_req = forward_req.header(name.clone(), val.clone());
        }
    }

    forward_req = forward_req.header("X-Forwarded-For", &client_ip);
    forward_req = forward_req.header("X-Shield-By", "Phylax-0.1.0");

    if !body.is_empty() {
        forward_req = forward_req.body(body);
    }

    match forward_req.send().await {
        Ok(upstream_resp) => {
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut resp_builder = Response::builder().status(status);
            for (name, val) in upstream_resp.headers() {
                resp_builder = resp_builder.header(name, val);
            }
            let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();
            resp_builder
                .body(axum::body::Body::from(resp_bytes))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(err) => {
            println!(
                "  ❌ [UPSTREAM ERROR] Failed to connect to upstream ({}): {}",
                upstream_url, err
            );
            (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "error": "Upstream service unreachable",
                    "target": upstream_url
                })),
            )
                .into_response()
        }
    }
}

pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn rand_nonce() -> u64 {
    current_timestamp_ms().wrapping_mul(6364136223846793005)
}
