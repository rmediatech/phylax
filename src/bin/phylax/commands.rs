//! # Phylax CLI Diagnostic, Challenge, Init & Benchmark Subcommands
//! One-Job: Execute offline challenge generation, PoW solving, IP checks, config init, and microbenchmarks.

use crate::proxy::{current_timestamp_ms, rand_nonce};
use clap::Args;
use phylax::autonomous_quarantine::QuarantineConfig;
use phylax::pow::PowEngine;
use std::sync::Arc;
use std::time::Instant;

#[derive(Args, Debug)]
pub struct ChallengeArgs {
    #[arg(long, default_value = "phylax-default-seed")]
    pub secret: String,
    #[arg(short, long, default_value_t = 12)]
    pub difficulty: u8,
}

#[derive(Args, Debug)]
pub struct SolveArgs {
    #[arg(short, long)]
    pub seed: String,
    #[arg(short, long, default_value_t = 12)]
    pub difficulty: u8,
}

#[derive(Args, Debug)]
pub struct CheckIpArgs {
    #[arg(short, long)]
    pub ip: String,
    #[arg(long, env = "ABUSEIPDB_API_KEY")]
    pub api_key: Option<String>,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    #[arg(short, long, default_value = "phylax.toml")]
    pub output: String,
}

pub fn run_challenge(args: ChallengeArgs) {
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

pub fn run_solve(args: SolveArgs) {
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

pub async fn run_check_ip(args: CheckIpArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Inspecting IP address: {}\n", args.ip);

    let guard = phylax::subnet_guard::SubnetGuard::default();
    match guard.check_ip(&args.ip) {
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
            Err(e) => println!("  ⚠️  AbuseIPDB query error: {}", e),
        }
    }
    Ok(())
}

pub fn run_init(args: InitArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config_content = r#"# ==========================================================
# Phylax (φύλαξ) — Sovereign Edge Defense Configuration
# ==========================================================

[server]
listen = "0.0.0.0:3000"
upstream = "http://127.0.0.1:8080"
secret_key = "change-this-to-a-secure-random-hmac-master-key-seed"

[defense]
honeypot_fields = ["website_url", "company_fax", "business_id"]
timing_min_ms = 2000
pow_difficulty = 12
pow_expiration_ms = 300000
enable_tarpit = true
max_concurrent_tarpits = 256
enable_autonomous_quarantine = true
quarantine_threshold = 3
quarantine_duration_ms = 86400000

[maintenance]
sweep_interval_s = 60

[abuse_reporting]
enabled = false
dry_run = true
"#;
    std::fs::write(&args.output, config_content)?;
    println!("✅ Generated production configuration: {}", args.output);
    println!("   Run with: phylax serve --config {}", args.output);
    Ok(())
}

pub fn run_bench() {
    println!("⚡ Running Phylax Sub-Microsecond Microbenchmark Suite...\n");
    let iterations = 100_000;

    let hp = phylax::honeypot::HoneypotValidator::new(["website_url", "company_fax"]);
    let fields = [("username".to_string(), "alice".to_string())];
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hp.validate(&fields);
    }
    let hp_ns = (start.elapsed().as_nanos() as f64) / (iterations as f64);

    let subnet = phylax::subnet_guard::SubnetGuard::default();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = subnet.check_ip("198.51.100.42");
    }
    let subnet_ns = (start.elapsed().as_nanos() as f64) / (iterations as f64);

    let aq = phylax::autonomous_quarantine::AutonomousQuarantine::new(QuarantineConfig::default());
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = aq.is_quarantined("198.51.100.42", 1000);
    }
    let aq_ns = (start.elapsed().as_nanos() as f64) / (iterations as f64);

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
