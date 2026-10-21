//! # Phylax CLI & Autonomous WAF Reverse Proxy Daemon Entry Shell
//!
//! Sovereign, zero-telemetry edge defense proxy, challenge issuer, and threat inspection tool.
//! Run standalone in front of ANY backend stack (Node.js, Python, Go, PHP, Ruby, Java)
//! or execute administrative and debugging tasks.

mod commands;
mod proxy;
mod serve;

use clap::{Parser, Subcommand};
use commands::{ChallengeArgs, CheckIpArgs, InitArgs, SolveArgs};
use serve::ServeArgs;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => serve::run_serve(args).await?,
        Commands::Challenge(args) => commands::run_challenge(args),
        Commands::Solve(args) => commands::run_solve(args),
        Commands::CheckIp(args) => commands::run_check_ip(args).await?,
        Commands::Init(args) => commands::run_init(args)?,
        Commands::Bench => commands::run_bench(),
    }

    Ok(())
}
