//! # Sovereign Outside-In Attack Surface & Exposure Auditor (`surface_audit.rs`)
//!
//! Single Job: Provide a deterministic catalog of high-risk perimeter exposure vectors
//! (`/.env`, `/.git/config`, `/.svn/wc.db`, `/wp-login.php`, `/actuator/env`, `/dump.sql`,
//! `/id_rsa`, `/terraform.tfstate`, `/swagger-ui.html`, etc.) and evaluate HTTP responses
//! to determine whether an edge target is:
//! - `ProtectedByMirage`: Actively poisoning scanners with Phylax Synthetic Mirage decoys
//! - `ProtectedByBlock`: Deflecting probes with 401/403/429 perimeter enforcement
//! - `CleanGhost404`: Stealthily dropping probes with 404 Not Found
//! - `ExposedRisk`: Leaking real sensitive artifacts or debug endpoints (200 OK without Mirage canary)

use crate::decoy_uri::DecoyCategory;
use crate::sanitize::scrub_ansi_and_control;
use serde::{Deserialize, Serialize};

/// A single outside-in attack surface probe vector
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceProbeVector {
    /// URI path to probe (e.g. `"/.env"`)
    pub path: &'static str,
    /// Associated decoy/threat category
    pub category: DecoyCategory,
    /// Human-readable description of what scanners look for on this path
    pub description: &'static str,
    /// Signature substrings that indicate a real (non-mirage) leak if status is 200 OK
    pub leak_indicators: &'static [&'static str],
}

/// Verdict for a single probed exposure vector
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExposureVerdict {
    /// Active Mirage deception detected (contains Phylax Mirage canary headers or markers)
    ProtectedByMirage { canary_hint: String },
    /// Explicitly blocked by WAF / Reverse Proxy (`401`, `403`, `429`, `444`)
    ProtectedByBlock { status_code: u16 },
    /// Stealthily ghosted with `404 Not Found` or `410 Gone`
    CleanGhost404 { status_code: u16 },
    /// Unexpected redirect (`301`, `302`, `307`, `308`)
    Redirected { status_code: u16 },
    /// CRITICAL: Endpoint returned 200 OK with sensitive content and NO Mirage canary!
    ExposedRisk { status_code: u16, reason: String },
}

impl ExposureVerdict {
    /// Returns `true` if the vector is safely contained (Mirage, Block, Ghost 404, or Redirect).
    pub fn is_safe(&self) -> bool {
        !matches!(self, Self::ExposedRisk { .. })
    }
}

/// Evaluation result for a single surface probe
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeAuditResult {
    pub path: String,
    pub category: DecoyCategory,
    pub status_code: u16,
    pub verdict: ExposureVerdict,
}

/// Overall perimeter security posture report
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceExposureReport {
    pub target: String,
    pub total_vectors_probed: usize,
    pub mirage_protected_count: usize,
    pub blocked_count: usize,
    pub ghost_404_count: usize,
    pub exposed_risk_count: usize,
    pub has_hsts: bool,
    pub has_x_content_type_options: bool,
    pub has_frame_guard: bool,
    pub posture_grade: String,
    pub results: Vec<ProbeAuditResult>,
}

/// Canonical catalog of 12 critical outside-in scanner vectors (`cscan` / `fscan` / `nuclei` parity)
pub const CANONICAL_SURFACE_VECTORS: &[SurfaceProbeVector] = &[
    SurfaceProbeVector {
        path: "/.env",
        category: DecoyCategory::EnvironmentSecret,
        description: "Production environment secrets & API keys",
        leak_indicators: &[
            "DB_PASSWORD=",
            "AWS_ACCESS_KEY_ID=",
            "SECRET_KEY=",
            "APP_KEY=",
        ],
    },
    SurfaceProbeVector {
        path: "/.git/config",
        category: DecoyCategory::VersionControl,
        description: "Git repository metadata & remote origin credentials",
        leak_indicators: &["[core]", "repositoryformatversion", "[remote "],
    },
    SurfaceProbeVector {
        path: "/.svn/wc.db",
        category: DecoyCategory::VersionControl,
        description: "Subversion working copy SQLite database",
        leak_indicators: &["SQLite format 3", "NODES", "REPOSITORY"],
    },
    SurfaceProbeVector {
        path: "/terraform.tfstate",
        category: DecoyCategory::CloudInfrastructure,
        description: "Terraform cloud infrastructure state & secrets",
        leak_indicators: &["\"terraform_version\"", "\"resources\"", "\"outputs\""],
    },
    SurfaceProbeVector {
        path: "/.aws/credentials",
        category: DecoyCategory::CloudInfrastructure,
        description: "AWS IAM CLI credential profile",
        leak_indicators: &["aws_access_key_id", "aws_secret_access_key"],
    },
    SurfaceProbeVector {
        path: "/wp-login.php",
        category: DecoyCategory::AdminCmsProbe,
        description: "WordPress authentication & brute-force surface",
        leak_indicators: &["loginform", "user_login", "wp-submit"],
    },
    SurfaceProbeVector {
        path: "/actuator/env",
        category: DecoyCategory::AdminCmsProbe,
        description: "Spring Boot Actuator environment dump",
        leak_indicators: &["propertySources", "activeProfiles", "systemEnvironment"],
    },
    SurfaceProbeVector {
        path: "/phpinfo.php",
        category: DecoyCategory::AdminCmsProbe,
        description: "PHP runtime configuration & environment table",
        leak_indicators: &["PHP Version", "System", "Configure Command"],
    },
    SurfaceProbeVector {
        path: "/dump.sql",
        category: DecoyCategory::DatabaseBackup,
        description: "Unprotected SQL database dump archive",
        leak_indicators: &[
            "CREATE TABLE",
            "INSERT INTO",
            "MySQL dump",
            "PostgreSQL database dump",
        ],
    },
    SurfaceProbeVector {
        path: "/id_rsa",
        category: DecoyCategory::PrivateKey,
        description: "Exposed SSH/TLS private key material",
        leak_indicators: &[
            "PRIVATE KEY-----",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
        ],
    },
    SurfaceProbeVector {
        path: "/_sovereign/canary_trap",
        category: DecoyCategory::Custom,
        description: "Sovereign invisible DOM crawler canary trap",
        leak_indicators: &["INTERNAL_NODE_SYNC"],
    },
    SurfaceProbeVector {
        path: "/.DS_Store",
        category: DecoyCategory::VersionControl,
        description: "macOS directory metadata index leak",
        leak_indicators: &["Bud1"],
    },
];

/// Stateless evaluator for outside-in surface exposure auditing
#[derive(Debug, Clone, Default)]
pub struct SurfaceAuditEngine;

impl SurfaceAuditEngine {
    /// Returns the canonical list of outside-in surface probe vectors.
    pub fn canonical_vectors() -> &'static [SurfaceProbeVector] {
        CANONICAL_SURFACE_VECTORS
    }

    /// Evaluates a single HTTP response `(status_code, headers, body)` against a `SurfaceProbeVector`.
    pub fn evaluate_probe_response(
        vector: &SurfaceProbeVector,
        status_code: u16,
        headers: &[(String, String)],
        body: &str,
    ) -> ProbeAuditResult {
        // 1. Check for Phylax Synthetic Mirage canary headers or body markers
        for (k, v) in headers {
            let lower = k.to_ascii_lowercase();
            if lower == "x-mirage-canary"
                || lower == "x-vcs-mirage"
                || lower == "x-key-canary"
                || lower == "x-canary-trace"
                || lower == "x-terraform-serial"
            {
                return ProbeAuditResult {
                    path: vector.path.to_string(),
                    category: vector.category,
                    status_code,
                    verdict: ExposureVerdict::ProtectedByMirage {
                        canary_hint: scrub_ansi_and_control(v),
                    },
                };
            }
        }

        if body.contains("APP_CANARY_TRACE=mirage-")
            || body.contains("canary_trace")
            || body.contains("# trace-id: ")
            || body.contains("# session_trace = ")
            || body.contains("# canary-id: ")
            || body.contains("-- Canary Trace: ")
        {
            return ProbeAuditResult {
                path: vector.path.to_string(),
                category: vector.category,
                status_code,
                verdict: ExposureVerdict::ProtectedByMirage {
                    canary_hint: "embedded-body-canary".to_string(),
                },
            };
        }

        // 2. Check status code categories
        let verdict = match status_code {
            401 | 403 | 405 | 406 | 429 | 444 | 451 => {
                ExposureVerdict::ProtectedByBlock { status_code }
            }
            404 | 410 => ExposureVerdict::CleanGhost404 { status_code },
            301 | 302 | 303 | 307 | 308 => ExposureVerdict::Redirected { status_code },
            200..=299 => {
                // Check if body matches real leak indicators (and wasn't a Mirage payload)
                let matched_indicator = vector
                    .leak_indicators
                    .iter()
                    .find(|&&ind| body.contains(ind));
                if let Some(&indicator) = matched_indicator {
                    ExposureVerdict::ExposedRisk {
                        status_code,
                        reason: format!(
                            "HTTP {} leaked unmasked indicator '{}'",
                            status_code,
                            scrub_ansi_and_control(indicator)
                        ),
                    }
                } else {
                    // Returned 200 OK (e.g. SPA fallback HTML) without sensitive indicator leak,
                    // but still suboptimal compared to 404/403/Mirage for decoy routes.
                    ExposureVerdict::CleanGhost404 { status_code }
                }
            }
            _ => ExposureVerdict::ProtectedByBlock { status_code },
        };

        ProbeAuditResult {
            path: vector.path.to_string(),
            category: vector.category,
            status_code,
            verdict,
        }
    }

    /// Aggregates individual probe results and baseline response headers into a `SurfaceExposureReport`.
    pub fn compile_report(
        target: &str,
        results: Vec<ProbeAuditResult>,
        root_headers: &[(String, String)],
    ) -> SurfaceExposureReport {
        let mut mirage_protected_count = 0;
        let mut blocked_count = 0;
        let mut ghost_404_count = 0;
        let mut exposed_risk_count = 0;

        for r in &results {
            match r.verdict {
                ExposureVerdict::ProtectedByMirage { .. } => mirage_protected_count += 1,
                ExposureVerdict::ProtectedByBlock { .. } => blocked_count += 1,
                ExposureVerdict::CleanGhost404 { .. } | ExposureVerdict::Redirected { .. } => {
                    ghost_404_count += 1
                }
                ExposureVerdict::ExposedRisk { .. } => exposed_risk_count += 1,
            }
        }

        let has_header = |name: &str| {
            root_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(name))
        };

        let has_hsts = has_header("strict-transport-security");
        let has_x_content_type_options = has_header("x-content-type-options");
        let has_frame_guard =
            has_header("x-frame-options") || has_header("content-security-policy");

        let posture_grade = if exposed_risk_count > 0 {
            "F (CRITICAL SURFACE EXPOSURE)".to_string()
        } else if mirage_protected_count > 0 && has_hsts && has_x_content_type_options {
            "A+ (Sovereign Mirage Fortress)".to_string()
        } else if (mirage_protected_count > 0 || blocked_count > 0 || ghost_404_count > 0)
            && (has_hsts || has_x_content_type_options)
        {
            "A (Hardened Perimeter)".to_string()
        } else {
            "B (Contained Surface, Missing Hardening Headers)".to_string()
        };

        SurfaceExposureReport {
            target: scrub_ansi_and_control(target),
            total_vectors_probed: results.len(),
            mirage_protected_count,
            blocked_count,
            ghost_404_count,
            exposed_risk_count,
            has_hsts,
            has_x_content_type_options,
            has_frame_guard,
            posture_grade,
            results,
        }
    }
}
