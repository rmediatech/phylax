//! # Phylax CLI & Autonomous WAF Reverse Proxy Daemon Entry Shell
//!
//! Sovereign, zero-telemetry edge defense proxy, challenge issuer, and threat inspection tool.
//! Run standalone in front of ANY backend stack (Node.js, Python, Go, PHP, Ruby, Java)
//! or execute administrative and debugging tasks.

mod audit;
mod commands;
mod proxy;
mod serve;

use audit::AuditSurfaceArgs;
use clap::{Parser, Subcommand};
use commands::{ChallengeArgs, CheckIpArgs, InitArgs, SolveArgs};
use serve::ServeArgs;

#[derive(Parser, Debug)]
#[command(
    name = "phylax",
    author = "Rick <rick@rmediatech.com>",
    version,
    about = "Sovereign 16-layer edge defense, synthetic mirage deception, and autonomous anti-bot WAF",
    long_about = "Phylax (φύλαξ) provides sub-microsecond edge security, active Mirage decoy poisoning, outside-in surface exposure auditing, and autonomous CIDR quarantine with zero external telemetry."
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
    /// Audit an edge target URL against canonical exposure vectors and Mirage deception posture
    AuditSurface(AuditSurfaceArgs),
    /// Generate a production-ready phylax.toml configuration file
    Init(InitArgs),
    /// Execute the internal sub-microsecond microbenchmark suite
    Bench,
    /// Verify sovereign cryptographic provenance seal (SOVEREIGN-SIGN-01)
    Verify,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => serve::run_serve(args).await?,
        Commands::Challenge(args) => commands::run_challenge(args),
        Commands::Solve(args) => commands::run_solve(args),
        Commands::CheckIp(args) => commands::run_check_ip(args).await?,
        Commands::AuditSurface(args) => audit::run_audit_surface(args).await?,
        Commands::Init(args) => commands::run_init(args)?,
        Commands::Bench => commands::run_bench(),
        Commands::Verify => {
            println!("🛡️  Verifying Sovereign Cryptographic Provenance...");
            if phylax::provenance::verify_sovereign_watermark() {
                println!("✓ Provenance Integrity Verified: Master Key 4E428019A109578B");
                println!("  Preimage: {}", phylax::provenance::CANARY_PREIMAGE);
                println!(
                    "  Attestation: {}",
                    phylax::provenance::format_provenance_attestation()
                );
            } else {
                eprintln!("❌ Provenance verification failed: Canary hash mismatch!");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
