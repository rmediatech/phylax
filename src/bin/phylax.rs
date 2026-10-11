//! # Phylax CLI & Autonomous WAF Reverse Proxy Daemon
//!
//! Sovereign, zero-telemetry edge defense proxy, challenge issuer, and threat inspection tool.
//! Run standalone in front of ANY backend stack (Node.js, Python, Go, PHP, Ruby, Java)
//! or execute administrative and debugging tasks.

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::header::HeaderMap;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use clap::{Args, Parser, Subcommand};
use phylax::adaptive_pow::AdaptivePowConfig;
use phylax::autonomous_quarantine::QuarantineConfig;
use phylax::pipeline::{DenialReason, PhylaxPipeline, PhylaxRequest, ShieldVerdict};
use phylax::pow::PowEngine;
use phylax::tarpit::TarpitConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(
    name = "phylax",
    author = "Rick <rick@rmediatech.com>",
    version,
    about = "Sovereign 12-layer edge defense, honeypot tarpit, and autonomous anti-bot WAF",
    long_about = "Phylax (φύλαξ) provides sub-microsecond edge security against credential stuffing, automated bots, Tor/datacenter crawlers, and Slowloris attacks with zero external telemetry."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the sovereign WAF reverse proxy daemon in front of an upstream service
    Serve(ServeArgs),
    /// Issue a fresh cryptographic challenge (timing token, PoW seed, and honeypot decoy fields)
    Challenge(ChallengeArgs),
    /// Solve a Proof-of-Work challenge puzzle client-side for testing
    Solve(SolveArgs),
    /// Inspect an IP address against known threat subnets, autonomous quarantine, or AbuseIPDB
    CheckIp(CheckIpArgs),
    /// Generate a production-ready phylax.toml configuration file
    Init(InitArgs),
    /// Execute the internal sub-microsecond microbenchmark suite
    Bench,
}

#[derive(serde::Deserialize, Debug, Default)]
struct ServerConfigToml {
    listen: Option<String>,
    upstream: Option<String>,
    secret_key: Option<String>,
}

#[derive(serde::Deserialize, Debug, Default)]
struct DefenseConfigToml {
    honeypot_fields: Option<Vec<String>>,
    timing_min_ms: Option<u64>,
    pow_difficulty: Option<u8>,
    pow_expiration_ms: Option<u64>,
    enable_tarpit: Option<bool>,
    max_concurrent_tarpits: Option<usize>,
    enable_autonomous_quarantine: Option<bool>,
    quarantine_threshold: Option<u32>,
    quarantine_duration_ms: Option<u64>,
}

#[derive(serde::Deserialize, Debug, Default)]
struct MaintenanceConfigToml {
    sweep_interval_s: Option<u64>,
}

#[derive(serde::Deserialize, Debug, Default)]
struct AbuseReportingConfigToml {
    enabled: Option<bool>,
    dry_run: Option<bool>,
    api_key: Option<String>,
    webhook_url: Option<String>,
    webhook_auth: Option<String>,
    syslog_cef: Option<bool>,
}

#[derive(serde::Deserialize, Debug, Default)]
struct PhylaxConfigFile {
    server: Option<ServerConfigToml>,
    defense: Option<DefenseConfigToml>,
    maintenance: Option<MaintenanceConfigToml>,
    abuse_reporting: Option<AbuseReportingConfigToml>,
}

#[derive(Args, Debug, Clone)]
struct ServeArgs {
    /// Optional path to configuration file (TOML format, e.g. phylax.toml)
    #[arg(short, long, env = "PHYLAX_CONFIG")]
    config: Option<std::path::PathBuf>,

    /// Upstream target service to protect (e.g. http://127.0.0.1:8080)
    #[arg(short, long)]
    upstream: Option<String>,

    /// Socket address to listen on
    #[arg(short, long)]
    listen: Option<String>,

    /// Secret HMAC key seed for tamper-proof tokens (auto-generated if omitted)
    #[arg(long)]
    secret: Option<String>,

    /// Comma-separated list of hidden decoy honeypot fields
    #[arg(long)]
    honeypot_fields: Option<String>,

    /// Minimum form interaction timing requirement in milliseconds
    #[arg(long)]
    timing_min_ms: Option<u64>,

    /// Proof-of-Work puzzle difficulty in bits (0 to disable, 12 = ~5ms, 16 = ~80ms)
    #[arg(long)]
    pow_difficulty: Option<u8>,

    /// Engage asymmetric slowloris tarpit against trapped bots
    #[arg(long, num_args(0..=1), default_missing_value = "true")]
    tarpit: Option<bool>,

    /// Autonomous CIDR quarantine for repeat offenders (/24 IPv4, /48 IPv6)
    #[arg(long, num_args(0..=1), default_missing_value = "true")]
    quarantine: Option<bool>,

    /// Enable collaborative threat reporting (AbuseIPDB, Webhooks, SIEM)
    #[arg(long, num_args(0..=1), default_missing_value = "true")]
    abuse_reporting: Option<bool>,

    /// AbuseIPDB API key (reads from ABUSEIPDB_API_KEY env if not specified)
    #[arg(long, env = "ABUSEIPDB_API_KEY")]
    abuseipdb_key: Option<String>,

    /// Enterprise Webhook destination URL for SIEM, Datadog, Slack, or internal SOC
    #[arg(long, env = "PHYLAX_WEBHOOK_URL")]
    webhook_url: Option<String>,

    /// Optional webhook authorization header (e.g. "Bearer token" or "ApiKey secret")
    #[arg(long, env = "PHYLAX_WEBHOOK_AUTH")]
    webhook_auth: Option<String>,

    /// Enable local Syslog CEF (Common Event Format) logging for threat events (zero external calls)
    #[arg(long, num_args(0..=1), default_missing_value = "true", env = "PHYLAX_SYSLOG_CEF")]
    syslog_cef: Option<bool>,

    /// Autonomous in-memory maintenance sweep interval in seconds
    #[arg(long)]
    maintenance_interval_s: Option<u64>,
}

#[derive(Args, Debug)]
struct ChallengeArgs {
    /// Secret HMAC key seed
    #[arg(long, default_value = "phylax-default-seed")]
    secret: String,

    /// PoW puzzle difficulty in bits
    #[arg(short, long, default_value_t = 12)]
    difficulty: u8,
}

#[derive(Args, Debug)]
struct SolveArgs {
    /// Challenge seed string
    #[arg(short, long)]
    seed: String,

    /// PoW puzzle difficulty in bits
    #[arg(short, long, default_value_t = 12)]
    difficulty: u8,
}

#[derive(Args, Debug)]
struct CheckIpArgs {
    /// IP address to inspect
    #[arg(short, long)]
    ip: String,

    /// Optional AbuseIPDB API key for live reputation lookup
    #[arg(long, env = "ABUSEIPDB_API_KEY")]
    api_key: Option<String>,
}

#[derive(Args, Debug)]
struct InitArgs {
    /// Output file path
    #[arg(short, long, default_value = "phylax.toml")]
    output: String,
}

#[derive(Clone)]
struct ProxyState {
    pipeline: Arc<PhylaxPipeline>,
    http_client: reqwest::Client,
    upstream: String,
    start_time: Instant,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => run_serve(args).await?,
        Commands::Challenge(args) => run_challenge(args),
        Commands::Solve(args) => run_solve(args),
        Commands::CheckIp(args) => run_check_ip(args).await?,
        Commands::Init(args) => run_init(args)?,
        Commands::Bench => run_bench(),
    }

    Ok(())
}

async fn run_serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        r#"
  ██████╗ ██╗  ██╗██╗   ██╗██╗      █████╗ ██╗  ██╗
  ██╔══██╗██║  ██║╚██╗ ██╔╝██║     ██╔══██╗╚██╗██╔╝
  ██████╔╝███████║ ╚████╔╝ ██║     ███████║ ╚███╔╝ 
  ██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██╔══██║ ██╔██╗ 
  ██║     ██║  ██║   ██║   ███████╗██║  ██║██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
  Sovereign Zero-Telemetry WAF & Edge Defense Daemon
    "#
    );

    let (
        listen,
        upstream_url,
        secret,
        decoy_fields,
        timing_min_ms,
        pow_difficulty,
        pow_expiration_ms,
        tarpit_enabled,
        tarpit_max_concurrent,
        quarantine_enabled,
        quarantine_threshold,
        quarantine_duration_ms,
        maintenance_interval_s,
        abuse_reporting_enabled,
        abuse_dry_run,
        abuseipdb_key,
        webhook_url,
        webhook_auth,
        syslog_cef,
    ) = {
        let mut config_file: Option<PhylaxConfigFile> = None;
        if let Some(path) = &args.config {
            if !path.exists() {
                return Err(format!("Configuration file not found: {}", path.display()).into());
            }
            let raw = std::fs::read_to_string(path)?;
            let parsed: PhylaxConfigFile = toml::from_str(&raw).map_err(|e| {
                format!(
                    "Failed to parse TOML configuration from {}: {}",
                    path.display(),
                    e
                )
            })?;
            println!("  📄 Loaded configuration: {}", path.display());
            config_file = Some(parsed);
        }

        let listen = args
            .listen
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.server.as_ref())
                    .and_then(|s| s.listen.clone())
            })
            .unwrap_or_else(|| "0.0.0.0:3000".to_string());

        let upstream = args
            .upstream
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.server.as_ref())
                    .and_then(|s| s.upstream.clone())
            })
            .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());

        let secret = args
            .secret
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.server.as_ref())
                    .and_then(|s| s.secret_key.clone())
            })
            .unwrap_or_else(|| "phylax-sovereign-master-key-seed-2026".to_string());

        let decoy_fields: Vec<String> = if let Some(cli_fields) = args.honeypot_fields {
            cli_fields
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else if let Some(cfg_fields) = config_file
            .as_ref()
            .and_then(|c| c.defense.as_ref())
            .and_then(|d| d.honeypot_fields.clone())
        {
            cfg_fields
        } else {
            vec!["website_url".to_string(), "company_fax".to_string()]
        };

        let timing_min_ms = args
            .timing_min_ms
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.defense.as_ref())
                    .and_then(|d| d.timing_min_ms)
            })
            .unwrap_or(2000);

        let pow_difficulty = args
            .pow_difficulty
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.defense.as_ref())
                    .and_then(|d| d.pow_difficulty)
            })
            .unwrap_or(12);

        let pow_expiration_ms = config_file
            .as_ref()
            .and_then(|c| c.defense.as_ref())
            .and_then(|d| d.pow_expiration_ms)
            .unwrap_or(300_000);

        let tarpit_enabled = args
            .tarpit
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.defense.as_ref())
                    .and_then(|d| d.enable_tarpit)
            })
            .unwrap_or(true);

        let tarpit_max_concurrent = config_file
            .as_ref()
            .and_then(|c| c.defense.as_ref())
            .and_then(|d| d.max_concurrent_tarpits)
            .unwrap_or(256);

        let quarantine_enabled = args
            .quarantine
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.defense.as_ref())
                    .and_then(|d| d.enable_autonomous_quarantine)
            })
            .unwrap_or(true);

        let quarantine_threshold = config_file
            .as_ref()
            .and_then(|c| c.defense.as_ref())
            .and_then(|d| d.quarantine_threshold)
            .unwrap_or(3);

        let quarantine_duration_ms = config_file
            .as_ref()
            .and_then(|c| c.defense.as_ref())
            .and_then(|d| d.quarantine_duration_ms)
            .unwrap_or(24 * 60 * 60 * 1000);

        let maintenance_interval_s = args
            .maintenance_interval_s
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.maintenance.as_ref())
                    .and_then(|m| m.sweep_interval_s)
            })
            .unwrap_or(60);

        let abuse_reporting_enabled = args
            .abuse_reporting
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.abuse_reporting.as_ref())
                    .and_then(|a| a.enabled)
            })
            .unwrap_or(false);

        let abuseipdb_key = args
            .abuseipdb_key
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.abuse_reporting.as_ref())
                    .and_then(|a| a.api_key.clone())
            })
            .filter(|k| !k.is_empty());

        let abuse_dry_run = config_file
            .as_ref()
            .and_then(|c| c.abuse_reporting.as_ref())
            .and_then(|a| a.dry_run)
            .unwrap_or(true);

        let webhook_url = args
            .webhook_url
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.abuse_reporting.as_ref())
                    .and_then(|a| a.webhook_url.clone())
            })
            .filter(|k| !k.is_empty());

        let webhook_auth = args
            .webhook_auth
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.abuse_reporting.as_ref())
                    .and_then(|a| a.webhook_auth.clone())
            })
            .filter(|k| !k.is_empty());

        let syslog_cef = args
            .syslog_cef
            .or_else(|| {
                config_file
                    .as_ref()
                    .and_then(|c| c.abuse_reporting.as_ref())
                    .and_then(|a| a.syslog_cef)
            })
            .unwrap_or(false);

        (
            listen,
            upstream,
            secret,
            decoy_fields,
            timing_min_ms,
            pow_difficulty,
            pow_expiration_ms,
            tarpit_enabled,
            tarpit_max_concurrent,
            quarantine_enabled,
            quarantine_threshold,
            quarantine_duration_ms,
            maintenance_interval_s,
            abuse_reporting_enabled,
            abuse_dry_run,
            abuseipdb_key,
            webhook_url,
            webhook_auth,
            syslog_cef,
        )
    };

    let mut builder = PhylaxPipeline::builder()
        .secret_key(secret.as_bytes())
        .with_honeypot_fields(decoy_fields.clone())
        .with_timing(timing_min_ms, 86_400_000)
        .with_pow(pow_difficulty, pow_expiration_ms)
        .enable_pow(pow_difficulty > 0);

    if tarpit_enabled {
        let tarpit_config = TarpitConfig {
            max_concurrent_tarpits: tarpit_max_concurrent,
            ..Default::default()
        };
        builder = builder.with_tarpit(tarpit_config);
    }

    if quarantine_enabled {
        let quarantine_config = QuarantineConfig {
            infraction_threshold: quarantine_threshold,
            quarantine_duration_ms,
            ..Default::default()
        };
        builder = builder.with_quarantine(quarantine_config);
        builder = builder.with_adaptive_pow(AdaptivePowConfig::default());
    }

    #[cfg(feature = "abuse-reporting")]
    if abuse_reporting_enabled {
        let is_dry =
            abuse_dry_run || (!syslog_cef && abuseipdb_key.is_none() && webhook_url.is_none());
        let informant_config = phylax::abuse_reporting::InformantConfig {
            enabled: true,
            dry_run: is_dry,
            api_key: abuseipdb_key.clone(),
            webhook_url: webhook_url.clone(),
            webhook_auth: webhook_auth.clone(),
            syslog_cef,
            cooldown: phylax::abuse_reporting::CooldownConfig::default(),
        };
        builder = builder.with_abuse_reporting(informant_config);
        println!(
            "  📡 Collaborative Abuse Reporting: ENABLED (Dry-Run: {})",
            is_dry
        );
        if syslog_cef {
            println!("     • Syslog / CEF Sink: Armed (Local Audit Logging)");
        }
        if let Some(ref key) = abuseipdb_key {
            println!(
                "     • AbuseIPDB Sink: Armed (Key: ...{})",
                &key[key.len().saturating_sub(6)..]
            );
        }
        if let Some(ref url) = webhook_url {
            println!("     • Generic Webhook Sink: Armed ({})", url);
        }
    }

    let pipeline = Arc::new(builder.build());

    // Spawn autonomous memory hygiene worker
    let maintenance_handle =
        pipeline.spawn_background_maintenance(Duration::from_secs(maintenance_interval_s));

    let upstream = upstream_url.trim_end_matches('/').to_string();
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let state = ProxyState {
        pipeline: pipeline.clone(),
        http_client,
        upstream: upstream.clone(),
        start_time: Instant::now(),
    };

    println!("  🛡️  Listen Socket:      {}", listen);
    println!("  🎯 Upstream Target:    {}", upstream);
    println!("  🍯 Decoy Honeypots:    {:?}", decoy_fields);
    println!("  ⏳ Min Timing Token:   {} ms", timing_min_ms);
    println!("  🧩 PoW Difficulty:     {} bits", pow_difficulty);
    println!(
        "  🕸️  Asymmetric Tarpit:  {}",
        if tarpit_enabled {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    println!(
        "  🔒 Autonomous CIDR:    {}",
        if quarantine_enabled {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    println!("  🧹 Memory Maintenance: Every {}s", maintenance_interval_s);
    println!("\n  Endpoints Active:");
    println!("    • GET  /_phylax/challenge -> Issue client tokens + PoW challenge");
    println!("    • GET  /_phylax/healthz   -> Health check & uptime");
    println!("    • GET  /_phylax/status    -> Defense metrics & maintenance report");
    println!("    • ANY  /*                 -> Protected reverse proxy to upstream\n");

    let app = Router::new()
        .route("/_phylax/challenge", get(handle_challenge))
        .route("/_phylax/healthz", get(handle_healthz))
        .route("/_phylax/status", get(handle_status))
        .fallback(any(handle_proxy))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl+c");
        println!("\n  🛑 Received shutdown signal. Cleaning up...");
        maintenance_handle.abort();
    })
    .await?;

    Ok(())
}

async fn handle_challenge(State(state): State<ProxyState>) -> impl IntoResponse {
    let now_ms = current_timestamp_ms();
    let seed_nonce = rand_nonce();
    let ctx = state.pipeline.issue_client_context(now_ms, seed_nonce);
    (StatusCode::OK, axum::Json(ctx))
}

async fn handle_healthz(State(state): State<ProxyState>) -> impl IntoResponse {
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

async fn handle_status(State(state): State<ProxyState>) -> impl IntoResponse {
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

async fn handle_proxy(
    State(state): State<ProxyState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now_ms = current_timestamp_ms();

    // Extract client IP (respecting trusted proxies like Caddy/Nginx if header present)
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    // Extract honeypot decoy fields, timing token, and PoW nonce
    let mut submitted_fields = Vec::new();
    let mut timing_token = None;
    let mut pow_challenge = None;
    let mut pow_nonce = None;

    // 1. Inspect query parameters
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

    // 2. Inspect JSON or Form body if present
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

    // For mutations (POST, PUT, DELETE), evaluate full pipeline; for GET/HEAD evaluate perimeter
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

    // Request is clean -> Proxy forward to upstream service
    let upstream_url = format!(
        "{}{}",
        state.upstream,
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("")
    );

    let mut forward_req = state.http_client.request(method, &upstream_url);

    // Forward headers except hop-by-hop
    for (name, val) in &headers {
        let name_str = name.as_str().to_lowercase();
        if name_str != "host"
            && name_str != "connection"
            && name_str != "keep-alive"
            && name_str != "transfer-encoding"
        {
            forward_req = forward_req.header(name.clone(), val.clone());
        }
    }

    // Attach client identity headers
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

fn run_challenge(args: ChallengeArgs) {
    let now_ms = current_timestamp_ms();
    let seed_nonce = rand_nonce();
    let engine = PowEngine::new(args.secret.as_bytes(), args.difficulty, 300_000);
    let (pow_seed, pow_challenge) =
        engine.issue_challenge_with_difficulty(now_ms, seed_nonce, args.difficulty);

    let output = serde_json::json!({
        "timestamp_ms": now_ms,
        "pow_challenge": pow_challenge,
        "pow_seed": pow_seed,
        "pow_difficulty": args.difficulty,
        "suggested_decoy_fields": ["website_url", "company_fax", "business_id"]
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn run_solve(args: SolveArgs) {
    println!(
        "🧩 Solving Proof-of-Work puzzle (Difficulty: {} bits)...",
        args.difficulty
    );
    let start = Instant::now();
    let (nonce, hash) = PowEngine::solve_challenge(&args.seed, args.difficulty);
    let elapsed = start.elapsed();

    println!("  • Solved Nonce: {}", nonce);
    println!("  • SHA-256 Hash: {}", hash);
    println!("  • Time Elapsed: {:.2?}", elapsed);
    println!(
        "  • Verified:     {}",
        hash.starts_with(&"0".repeat((args.difficulty as usize) / 4))
    );
}

async fn run_check_ip(args: CheckIpArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Inspecting IP address: {}\n", args.ip);

    let guard = phylax::subnet_guard::SubnetGuard::default();
    let verdict = guard.check_ip(&args.ip);
    match verdict {
        phylax::subnet_guard::SubnetVerdict::Allowed => {
            println!("  • Perimeter Subnet Check: PASS (Residential / Standard IP)");
        }
        phylax::subnet_guard::SubnetVerdict::Blocked { matched_cidr, .. } => {
            println!(
                "  • Perimeter Subnet Check: BLOCKED (Matched CIDR: {})",
                matched_cidr
            );
        }
        phylax::subnet_guard::SubnetVerdict::MalformedIp => {
            println!("  • Perimeter Subnet Check: ERROR (Invalid IP address syntax)");
        }
    }

    #[cfg(feature = "abuse-reporting")]
    if let Some(ref key) = args.api_key {
        println!("  • Querying AbuseIPDB reputation API...");
        let transport = phylax::abuse_reporting::HttpAbuseReporterTransport::new(None);
        let config = phylax::abuse_reporting::InformantConfig {
            enabled: true,
            dry_run: false,
            api_key: Some(key.clone()),
            webhook_url: None,
            webhook_auth: None,
            syslog_cef: false,
            cooldown: phylax::abuse_reporting::CooldownConfig::default(),
        };
        let engine = phylax::abuse_reporting::InformantEngine::new(config, Arc::new(transport));

        match engine.check_ip(&args.ip).await {
            Ok(rep) => {
                println!("  • Abuse Confidence:     {}%", rep.abuse_confidence_score);
                println!("  • Total Reports:        {}", rep.total_reports);
                println!(
                    "  • Country:              {}",
                    rep.country_code.as_deref().unwrap_or("N/A")
                );
                println!(
                    "  • ISP:                  {}",
                    rep.isp.as_deref().unwrap_or("N/A")
                );
                println!(
                    "  • Domain:               {}",
                    rep.domain.as_deref().unwrap_or("N/A")
                );
                println!("  • Is Tor Node:          {}", rep.is_tor);
                println!("  • Is Whitelisted:       {}", rep.is_whitelisted);
            }
            Err(e) => {
                println!("  ⚠️  AbuseIPDB query error: {}", e);
            }
        }
    }

    Ok(())
}

fn run_init(args: InitArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config_content = r#"# ==========================================================
# Phylax (φύλαξ) — Sovereign Edge Defense Configuration
# ==========================================================

[server]
# Address to bind the WAF reverse proxy listener
listen = "0.0.0.0:3000"

# Target backend service to protect
upstream = "http://127.0.0.1:8080"

# Secret HMAC master key seed (Change this in production!)
secret_key = "change-this-to-a-secure-random-hmac-master-key-seed"

[defense]
# Invisible decoy honeypot fields for bot traps
honeypot_fields = ["website_url", "company_fax", "business_id"]

# Minimum submission reaction cadence (milliseconds)
timing_min_ms = 2000

# Proof-of-Work difficulty bits (0 = disabled, 12 = ~5ms, 16 = ~80ms)
pow_difficulty = 12

# Proof-of-Work challenge expiration (milliseconds)
pow_expiration_ms = 300000

# Reverse Slowloris asymmetric connection tarpit
enable_tarpit = true

# Maximum concurrent connections held in tarpit
max_concurrent_tarpits = 256

# Autonomous CIDR quarantine for repeat offenders (/24 IPv4, /48 IPv6)
enable_autonomous_quarantine = true

# Infractions required before CIDR quarantine triggers
quarantine_threshold = 3

# Quarantine duration in milliseconds (86400000 = 24 hours)
quarantine_duration_ms = 86400000

[maintenance]
# Automatic background memory hygiene interval in seconds
sweep_interval_s = 60

[abuse_reporting]
# Opt-in collaborative reporting (AbuseIPDB, Generic Webhooks, Datadog, Slack, SIEM)
enabled = false

# Dry-run mode formats reports without external HTTP dispatch
dry_run = true

# Threat Intelligence & Incident Sinks (Completely Vendor-Agnostic / BYOK):
# 1. Generic Webhook Sink (Datadog, Splunk, Wazuh, Slack, Discord, internal SIEM)
# webhook_url = "https://siem.example.com/api/v1/incidents"
# webhook_auth = "Bearer your-token-here"

# 2. Syslog / CEF (Common Event Format) for local SIEM / syslog daemons (zero external calls)
# syslog_cef = false

# 3. AbuseIPDB Community Reporting (optional)
# api_key = "YOUR_ABUSEIPDB_API_KEY"
"#;

    std::fs::write(&args.output, config_content)?;
    println!("✅ Generated production configuration: {}", args.output);
    println!("   Run with: phylax serve --config {}", args.output);
    Ok(())
}

fn run_bench() {
    println!("⚡ Running Phylax Sub-Microsecond Microbenchmark Suite...\n");

    let iterations = 100_000;

    // 1. Honeypot check
    let hp = phylax::honeypot::HoneypotValidator::new(["website_url", "company_fax"]);
    let fields = [("username".to_string(), "alice".to_string())];
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hp.validate(&fields);
    }
    let hp_ns = (start.elapsed().as_nanos() as f64) / (iterations as f64);

    // 2. Radix Subnet check
    let subnet = phylax::subnet_guard::SubnetGuard::default();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = subnet.check_ip("198.51.100.42");
    }
    let subnet_ns = (start.elapsed().as_nanos() as f64) / (iterations as f64);

    // 3. Autonomous Quarantine check
    let aq = phylax::autonomous_quarantine::AutonomousQuarantine::new(QuarantineConfig::default());
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = aq.is_quarantined("198.51.100.42", 1000);
    }
    let aq_ns = (start.elapsed().as_nanos() as f64) / (iterations as f64);

    // 4. Timing Token validation
    let timing = phylax::timing::TimingGuard::new(b"bench_seed", 2000, 600_000);
    let token = timing.generate_token(1000);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = timing.verify_token(&token, 3500);
    }
    let timing_ns = (start.elapsed().as_nanos() as f64) / (iterations as f64);

    println!("┌────────────────────────────────────┬──────────────┐");
    println!("│ Defensive Operation                │ Mean Latency │");
    println!("├────────────────────────────────────┼──────────────┤");
    println!(
        "│ HoneypotValidator::validate        │ {:>7.2} ns   │",
        hp_ns
    );
    println!(
        "│ AutonomousQuarantine::is_banned    │ {:>7.2} ns   │",
        aq_ns
    );
    println!(
        "│ SubnetGuard::check_ip (Radix CIDR) │ {:>7.2} ns   │",
        subnet_ns
    );
    println!(
        "│ TimingGuard::verify_token (HMAC)   │ {:>7.2} ns   │",
        timing_ns
    );
    println!("└────────────────────────────────────┴──────────────┘");

    let total_ns = hp_ns + aq_ns + subnet_ns + timing_ns;
    println!(
        "\n  🚀 Total Perimeter Evaluation: {:.2} ns ({:.3} µs)",
        total_ns,
        total_ns / 1000.0
    );
    println!(
        "  ⚡ Estimated Capacity:          > {:.0} req/sec/core\n",
        1_000_000_000.0 / total_ns
    );
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn rand_nonce() -> u64 {
    current_timestamp_ms().wrapping_mul(6364136223846793005)
}
