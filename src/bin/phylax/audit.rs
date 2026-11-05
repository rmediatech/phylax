//! # Phylax Outside-In Attack Surface CLI Auditor (`audit.rs`)
//! One-Job: Execute live HTTP surface probes against an edge URL and render a posture report.

use clap::Args;
use phylax::surface_audit::{ExposureVerdict, ProbeAuditResult, SurfaceAuditEngine};

#[derive(Args, Debug)]
pub struct AuditSurfaceArgs {
    /// Target base URL to audit (e.g. https://rmediatech.com or http://127.0.0.1:3000)
    #[arg(short, long)]
    pub url: String,
    /// Emit machine-readable JSON report instead of terminal table
    #[arg(long)]
    pub json: bool,
}

pub async fn run_audit_surface(args: AuditSurfaceArgs) -> Result<(), Box<dyn std::error::Error>> {
    let base = args.url.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) Phylax-Surface-Auditor/0.3.0")
        .build()?;

    let mut root_headers = Vec::new();
    if let Ok(resp) = client.get(format!("{}/", base)).send().await {
        for (k, v) in resp.headers() {
            if let Ok(val) = v.to_str() {
                root_headers.push((k.as_str().to_string(), val.to_string()));
            }
        }
    }

    let mut results = Vec::new();
    for vec in SurfaceAuditEngine::canonical_vectors() {
        let probe_url = format!("{}{}", base, vec.path);
        match client.get(&probe_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let mut hdrs = Vec::new();
                for (k, v) in resp.headers() {
                    if let Ok(val) = v.to_str() {
                        hdrs.push((k.as_str().to_string(), val.to_string()));
                    }
                }
                let body = resp.text().await.unwrap_or_default();
                results.push(SurfaceAuditEngine::evaluate_probe_response(
                    vec, status, &hdrs, &body,
                ));
            }
            Err(_) => {
                results.push(ProbeAuditResult {
                    path: vec.path.to_string(),
                    category: vec.category,
                    status_code: 0,
                    verdict: ExposureVerdict::ProtectedByBlock { status_code: 0 },
                });
            }
        }
    }

    let report = SurfaceAuditEngine::compile_report(base, results, &root_headers);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "🛡️  Phylax Outside-In Attack Surface Audit: {}",
            report.target
        );
        println!("   Posture Grade: {}\n", report.posture_grade);
        for r in &report.results {
            let badge = match &r.verdict {
                ExposureVerdict::ProtectedByMirage { canary_hint } => {
                    format!("🎭 MIRAGE DECOY ({})", canary_hint)
                }
                ExposureVerdict::ProtectedByBlock { status_code } => {
                    format!("🛑 BLOCKED (HTTP {})", status_code)
                }
                ExposureVerdict::CleanGhost404 { status_code } => {
                    format!("👻 GHOST 404 (HTTP {})", status_code)
                }
                ExposureVerdict::Redirected { status_code } => {
                    format!("↪️  REDIRECT (HTTP {})", status_code)
                }
                ExposureVerdict::ExposedRisk { reason, .. } => format!("❌ EXPOSED: {}", reason),
            };
            println!("  • {:<26} -> {}", r.path, badge);
        }
    }
    Ok(())
}
