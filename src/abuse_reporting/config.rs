//! # Informant Configuration & Verdict Types
//! One-Job: Define operational configuration and outcome verdicts for the Informant Engine.

use crate::abuse_reporting::cooldown::CooldownConfig;

/// Operational configuration for the abuse informant engine
#[derive(Debug, Clone)]
pub struct InformantConfig {
    /// Master opt-in switch (defaults to false for safety)
    pub enabled: bool,
    /// Dry-run simulation mode (formats dossiers without outbound transmission)
    pub dry_run: bool,
    /// AbuseIPDB API key (if live dispatch enabled)
    pub api_key: Option<String>,
    /// Generic Webhook destination URL (for enterprise SIEM, Datadog, Slack, Splunk)
    pub webhook_url: Option<String>,
    /// Optional authorization header value for webhook (e.g. "Bearer token" or "ApiKey secret")
    pub webhook_auth: Option<String>,
    /// Enable local Syslog CEF (Common Event Format) logging for threat incidents
    pub syslog_cef: bool,
    /// Cooldown & rate limiting configuration
    pub cooldown: CooldownConfig,
}

impl Default for InformantConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            api_key: None,
            webhook_url: None,
            webhook_auth: None,
            syslog_cef: false,
            cooldown: CooldownConfig::default(),
        }
    }
}

impl InformantConfig {
    /// Discovers configuration from environment variables or standard reference paths:
    /// - Checks `ABUSEIPDB_API_KEY` environment variable or `~/Documents/reference/abuse_ip_db/api-key.txt`
    /// - Checks `PHYLAX_WEBHOOK_URL` / `RMT_WEBHOOK_URL` for generic enterprise sinks
    ///
    /// If an API key or webhook endpoint is discovered, automated reporting is armed by default.
    pub fn from_env_or_default() -> Self {
        let key = std::env::var("ABUSEIPDB_API_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let home = std::env::var("HOME").ok()?;
                let path = format!("{}/Documents/reference/abuse_ip_db/api-key.txt", home);
                std::fs::read_to_string(path)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            });

        let webhook_url = std::env::var("PHYLAX_WEBHOOK_URL")
            .or_else(|_| std::env::var("RMT_WEBHOOK_URL"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let webhook_auth = std::env::var("PHYLAX_WEBHOOK_AUTH")
            .or_else(|_| std::env::var("RMT_WEBHOOK_AUTH"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let syslog_cef = std::env::var("PHYLAX_SYSLOG_CEF")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let dry_run = std::env::var("RMT_ABUSE_REPORTING_DRY_RUN")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let enabled = (key.is_some() || webhook_url.is_some() || syslog_cef)
            && std::env::var("RMT_ABUSE_REPORTING_ENABLED")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true);

        Self {
            enabled,
            dry_run,
            api_key: key,
            webhook_url,
            webhook_auth,
            syslog_cef,
            cooldown: CooldownConfig::default(),
        }
    }
}

/// Result of evaluating an abusive incident
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InformantVerdict {
    /// Incident successfully reported to upstream threat intelligence or enterprise sink
    Reported { ip: String, confidence_score: u32 },
    /// Incident verified and formatted in dry-run mode
    DryRunReported {
        ip: String,
        categories: String,
        comment: String,
    },
    /// Report suppressed due to per-IP cooldown window or daily quota limit
    SuppressedCooldown,
    /// Engine is disabled in configuration
    Disabled,
    /// Report failed due to network or authorization error
    Error(String),
}
