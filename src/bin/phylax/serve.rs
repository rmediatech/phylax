//! # Phylax Reverse Proxy Server Daemon & Configuration Loader
//! One-Job: Parse CLI/TOML server configuration and launch the Axum WAF reverse proxy listener.

use crate::proxy::{handle_challenge, handle_healthz, handle_proxy, handle_status, ProxyState};
use axum::routing::{any, get};
use axum::Router;
use clap::Args;
use phylax::adaptive_pow::AdaptivePowConfig;
use phylax::autonomous_quarantine::QuarantineConfig;
use phylax::pipeline::PhylaxPipeline;
use phylax::tarpit::TarpitConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[rustfmt::skip]
#[derive(serde::Deserialize, Debug, Default)]
struct ServerConfigToml { listen: Option<String>, upstream: Option<String>, secret_key: Option<String> }

#[rustfmt::skip]
#[derive(serde::Deserialize, Debug, Default)]
struct DefenseConfigToml {
    honeypot_fields: Option<Vec<String>>, timing_min_ms: Option<u64>, pow_difficulty: Option<u8>,
    pow_expiration_ms: Option<u64>, enable_tarpit: Option<bool>, max_concurrent_tarpits: Option<usize>,
    enable_autonomous_quarantine: Option<bool>, quarantine_threshold: Option<u32>, quarantine_duration_ms: Option<u64>,
}

#[rustfmt::skip]
#[derive(serde::Deserialize, Debug, Default)]
struct MaintenanceConfigToml { sweep_interval_s: Option<u64> }

#[rustfmt::skip]
#[derive(serde::Deserialize, Debug, Default)]
struct AbuseReportingConfigToml {
    enabled: Option<bool>, dry_run: Option<bool>, api_key: Option<String>,
    webhook_url: Option<String>, webhook_auth: Option<String>, syslog_cef: Option<bool>,
}

#[rustfmt::skip]
#[derive(serde::Deserialize, Debug, Default)]
struct PhylaxConfigFile {
    server: Option<ServerConfigToml>, defense: Option<DefenseConfigToml>,
    maintenance: Option<MaintenanceConfigToml>, abuse_reporting: Option<AbuseReportingConfigToml>,
}

#[rustfmt::skip]
#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    #[arg(short, long, env = "PHYLAX_CONFIG")] pub config: Option<std::path::PathBuf>,
    #[arg(short, long)] pub upstream: Option<String>,
    #[arg(short, long)] pub listen: Option<String>,
    #[arg(long)] pub secret: Option<String>,
    #[arg(long)] pub honeypot_fields: Option<String>,
    #[arg(long)] pub timing_min_ms: Option<u64>,
    #[arg(long)] pub pow_difficulty: Option<u8>,
    #[arg(long, num_args(0..=1), default_missing_value = "true")] pub tarpit: Option<bool>,
    #[arg(long, num_args(0..=1), default_missing_value = "true")] pub quarantine: Option<bool>,
    #[arg(long, num_args(0..=1), default_missing_value = "true")] pub abuse_reporting: Option<bool>,
    #[arg(long, env = "ABUSEIPDB_API_KEY")] pub abuseipdb_key: Option<String>,
    #[arg(long, env = "PHYLAX_WEBHOOK_URL")] pub webhook_url: Option<String>,
    #[arg(long, env = "PHYLAX_WEBHOOK_AUTH")] pub webhook_auth: Option<String>,
    #[arg(long, num_args(0..=1), default_missing_value = "true", env = "PHYLAX_SYSLOG_CEF")] pub syslog_cef: Option<bool>,
    #[arg(long)] pub maintenance_interval_s: Option<u64>,
}

pub async fn run_serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
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

    let srv = config_file.as_ref().and_then(|c| c.server.as_ref());
    let def = config_file.as_ref().and_then(|c| c.defense.as_ref());
    let mnt = config_file.as_ref().and_then(|c| c.maintenance.as_ref());
    let abr = config_file
        .as_ref()
        .and_then(|c| c.abuse_reporting.as_ref());

    let listen = args
        .listen
        .or_else(|| srv.and_then(|s| s.listen.clone()))
        .unwrap_or_else(|| "0.0.0.0:3000".to_string());
    let upstream_url = args
        .upstream
        .or_else(|| srv.and_then(|s| s.upstream.clone()))
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    let secret = args
        .secret
        .or_else(|| srv.and_then(|s| s.secret_key.clone()))
        .unwrap_or_else(|| "phylax-sovereign-master-key-seed-2026".to_string());

    let decoy_fields: Vec<String> = if let Some(cli_fields) = args.honeypot_fields {
        cli_fields
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else if let Some(cfg_fields) = def.and_then(|d| d.honeypot_fields.clone()) {
        cfg_fields
    } else {
        vec!["website_url".to_string(), "company_fax".to_string()]
    };

    let timing_min_ms = args
        .timing_min_ms
        .or_else(|| def.and_then(|d| d.timing_min_ms))
        .unwrap_or(2000);
    let pow_difficulty = args
        .pow_difficulty
        .or_else(|| def.and_then(|d| d.pow_difficulty))
        .unwrap_or(12);
    let pow_expiration_ms = def.and_then(|d| d.pow_expiration_ms).unwrap_or(300_000);
    let tarpit_enabled = args
        .tarpit
        .or_else(|| def.and_then(|d| d.enable_tarpit))
        .unwrap_or(true);
    let tarpit_max_concurrent = def.and_then(|d| d.max_concurrent_tarpits).unwrap_or(256);
    let quarantine_enabled = args
        .quarantine
        .or_else(|| def.and_then(|d| d.enable_autonomous_quarantine))
        .unwrap_or(true);
    let quarantine_threshold = def.and_then(|d| d.quarantine_threshold).unwrap_or(3);
    let quarantine_duration_ms = def
        .and_then(|d| d.quarantine_duration_ms)
        .unwrap_or(24 * 60 * 60 * 1000);
    let maintenance_interval_s = args
        .maintenance_interval_s
        .or_else(|| mnt.and_then(|m| m.sweep_interval_s))
        .unwrap_or(60);

    let abuse_reporting_enabled = args
        .abuse_reporting
        .or_else(|| abr.and_then(|a| a.enabled))
        .unwrap_or(false);
    let abuseipdb_key = args
        .abuseipdb_key
        .or_else(|| abr.and_then(|a| a.api_key.clone()))
        .filter(|k| !k.is_empty());
    let abuse_dry_run = abr.and_then(|a| a.dry_run).unwrap_or(true);
    let webhook_url = args
        .webhook_url
        .or_else(|| abr.and_then(|a| a.webhook_url.clone()))
        .filter(|k| !k.is_empty());
    let webhook_auth = args
        .webhook_auth
        .or_else(|| abr.and_then(|a| a.webhook_auth.clone()))
        .filter(|k| !k.is_empty());
    let syslog_cef = args
        .syslog_cef
        .or_else(|| abr.and_then(|a| a.syslog_cef))
        .unwrap_or(false);

    let mut builder = PhylaxPipeline::builder()
        .secret_key(secret.as_bytes())
        .with_honeypot_fields(decoy_fields.clone())
        .with_timing(timing_min_ms, 86_400_000)
        .with_pow(pow_difficulty, pow_expiration_ms)
        .enable_pow(pow_difficulty > 0);

    if tarpit_enabled {
        builder = builder.with_tarpit(TarpitConfig {
            max_concurrent_tarpits: tarpit_max_concurrent,
            ..Default::default()
        });
    }

    if quarantine_enabled {
        builder = builder
            .with_quarantine(QuarantineConfig {
                infraction_threshold: quarantine_threshold,
                quarantine_duration_ms,
                ..Default::default()
            })
            .with_adaptive_pow(AdaptivePowConfig::default());
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
