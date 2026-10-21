//! # Autonomous Decoy URI Honeyroutes & Reconnaissance Traps
//! One-Job: Deterministically identify and categorize automated scanners probing known decoy endpoints.

pub mod catalog;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Category of decoy endpoint tripped by the scanner
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecoyCategory {
    /// Environment / Secrets (`/.env`, `/pip.conf`, `/.azure/credentials`)
    EnvironmentSecret,
    /// Version Control Systems (`/.git`, `/.svn`)
    VersionControl,
    /// Cloud & Infrastructure State (`/terraform.tfstate`, `/.aws`)
    CloudInfrastructure,
    /// Admin & CMS Probes (`/wp-admin`, `/wp-login.php`, `/phpmyadmin`)
    AdminCmsProbe,
    /// Database & Filesystem Dumps (`/dump.sql`, `/backup.zip`)
    DatabaseBackup,
    /// Private Keys & Tokens (`/private.key`, `/id_rsa`)
    PrivateKey,
    /// User-defined custom decoy route
    Custom,
}

impl DecoyCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::EnvironmentSecret => "Environment & Secrets Probe",
            Self::VersionControl => "Version Control Repository Probe",
            Self::CloudInfrastructure => "Cloud & Infrastructure State Probe",
            Self::AdminCmsProbe => "Administrative & CMS Panel Probe",
            Self::DatabaseBackup => "Database & Filesystem Backup Probe",
            Self::PrivateKey => "Cryptographic Private Key Probe",
            Self::Custom => "Custom Decoy Honeyroute",
        }
    }
}

/// Verdict returned from Decoy URI evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecoyUriVerdict {
    Clean,
    Trapped {
        matched_path: String,
        category: DecoyCategory,
    },
}

/// Configuration for Decoy URI Honeyroute Sentinel
#[derive(Debug, Clone)]
pub struct DecoyUriConfig {
    pub enabled: bool,
    pub custom_exact_routes: Vec<(String, DecoyCategory)>,
    pub custom_prefix_routes: Vec<(String, DecoyCategory)>,
}

impl Default for DecoyUriConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_exact_routes: Vec::new(),
            custom_prefix_routes: Vec::new(),
        }
    }
}

/// Sentinel that deterministically matches scanner reconnaissance probes in sub-microsecond time
#[derive(Debug, Clone)]
pub struct DecoyUriSentinel {
    enabled: bool,
    exact_traps: Arc<RwLock<HashMap<String, DecoyCategory>>>,
    prefix_traps: Arc<RwLock<Vec<(String, DecoyCategory)>>>,
}

impl Default for DecoyUriSentinel {
    fn default() -> Self {
        Self::new(DecoyUriConfig::default())
    }
}

impl DecoyUriSentinel {
    /// Construct a new sentinel loaded with the curated production catalog
    pub fn new(config: DecoyUriConfig) -> Self {
        let mut exact_traps = HashMap::new();
        let mut prefix_traps = Vec::new();

        for (path, category) in catalog::STANDARD_EXACT_TRAPS {
            exact_traps.insert(path.to_ascii_lowercase(), *category);
        }
        for (prefix, category) in catalog::STANDARD_PREFIX_TRAPS {
            prefix_traps.push((prefix.to_ascii_lowercase(), *category));
        }
        for (exact, category) in &config.custom_exact_routes {
            exact_traps.insert(exact.to_ascii_lowercase(), *category);
        }
        for (prefix, category) in config.custom_prefix_routes {
            prefix_traps.push((prefix.to_ascii_lowercase(), category));
        }

        Self {
            enabled: config.enabled,
            exact_traps: Arc::new(RwLock::new(exact_traps)),
            prefix_traps: Arc::new(RwLock::new(prefix_traps)),
        }
    }

    /// Dynamically registers a newly discovered honeypot / zero-day trap in real-time
    pub fn add_exact_trap(&self, path: &str) {
        let normalized = Self::normalize_path(path);
        let category = self.categorize_path(&normalized);
        self.exact_traps.write().insert(normalized, category);
    }

    /// Dynamically registers an exact trap with an explicit threat category
    pub fn add_exact_trap_with_category(&self, path: &str, category: DecoyCategory) {
        let normalized = Self::normalize_path(path);
        self.exact_traps.write().insert(normalized, category);
    }

    /// Dynamically registers a newly discovered prefix trap
    pub fn add_prefix_trap(&self, prefix: &str, category: DecoyCategory) {
        let normalized = Self::normalize_path(prefix);
        self.prefix_traps.write().push((normalized, category));
    }

    /// Checks if a normalized path is currently registered as a trap
    pub fn contains_trap(&self, raw_path: &str) -> bool {
        let normalized = Self::normalize_path(raw_path);
        self.exact_traps.read().contains_key(&normalized)
            || self
                .prefix_traps
                .read()
                .iter()
                .any(|(p, _)| normalized.starts_with(p))
    }

    /// Total count of registered active traps
    pub fn total_traps(&self) -> usize {
        self.exact_traps.read().len() + self.prefix_traps.read().len()
    }

    /// Percent-decode ASCII hexadecimal sequences e.g. "%2e" -> "."
    #[inline]
    pub fn percent_decode(s: &str) -> String {
        catalog::percent_decode(s)
    }

    /// Normalizes a URI path (decodes percent encoding, removes query/fragment, collapses multiple slashes and dot segments, converts to lowercase)
    #[inline]
    pub fn normalize_path(raw_path: &str) -> String {
        catalog::normalize_path(raw_path)
    }

    /// Evaluates a requested URI path in sub-microsecond time
    pub fn evaluate(&self, raw_path: &str) -> DecoyUriVerdict {
        if !self.enabled {
            return DecoyUriVerdict::Clean;
        }

        // Fast-path: If path is already clean lowercase with no query/multi-slash/percent, avoid all heap allocations
        let needs_normalization = raw_path
            .bytes()
            .any(|b| b.is_ascii_uppercase() || b == b'?' || b == b'#' || b == b'\\' || b == b'%')
            || raw_path.contains("//")
            || raw_path.contains("/.");

        if !needs_normalization {
            return self.match_normalized(raw_path.trim());
        }
        let normalized = Self::normalize_path(raw_path);
        self.match_normalized(&normalized)
    }

    fn match_normalized(&self, path: &str) -> DecoyUriVerdict {
        if let Some(category) = self.exact_traps.read().get(path) {
            return DecoyUriVerdict::Trapped {
                matched_path: path.to_string(),
                category: *category,
            };
        }
        for (p, category) in self.prefix_traps.read().iter() {
            if path.starts_with(p) {
                return DecoyUriVerdict::Trapped {
                    matched_path: path.to_string(),
                    category: *category,
                };
            }
        }
        if let Some(ext_idx) = path.rfind('.') {
            let ext = &path[ext_idx..];
            if matches!(ext, ".php" | ".phtml" | ".php5" | ".php7") {
                return DecoyUriVerdict::Trapped {
                    matched_path: path.to_string(),
                    category: DecoyCategory::AdminCmsProbe,
                };
            }
            if matches!(ext, ".sql" | ".dump" | ".bak" | ".old" | ".swp")
                && ["db", "data", "backup", "user", "pass", "dump"]
                    .iter()
                    .any(|kw| path.contains(kw))
            {
                return DecoyUriVerdict::Trapped {
                    matched_path: path.to_string(),
                    category: DecoyCategory::DatabaseBackup,
                };
            }
        }
        DecoyUriVerdict::Clean
    }

    /// Helper to assign appropriate category to exact matches
    pub fn categorize_path(&self, path: &str) -> DecoyCategory {
        let lower = path.to_ascii_lowercase();
        if [
            "env",
            "pip.conf",
            "credentials",
            "auth.json",
            "secrets",
            "config",
        ]
        .iter()
        .any(|k| lower.contains(k))
        {
            DecoyCategory::EnvironmentSecret
        } else if ["terraform", "aws", "k8s", "firebase"]
            .iter()
            .any(|k| lower.contains(k))
        {
            DecoyCategory::CloudInfrastructure
        } else if [
            "wp-",
            "xmlrpc",
            "phpmyadmin",
            "settings.php",
            "admin",
            "login",
            "console",
        ]
        .iter()
        .any(|k| lower.contains(k))
            || lower.ends_with(".php")
        {
            DecoyCategory::AdminCmsProbe
        } else if lower.contains("key") || lower.contains("id_rsa") {
            DecoyCategory::PrivateKey
        } else if [".zip", ".tar", ".sql"].iter().any(|k| lower.contains(k)) {
            DecoyCategory::DatabaseBackup
        } else {
            DecoyCategory::Custom
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_and_decoy_paths() {
        let sentinel = DecoyUriSentinel::default();
        for path in [
            "/",
            "/auth/login",
            "/downloads",
            "/pricing",
            "/healthz",
            "/assets/main.css",
        ] {
            assert_eq!(sentinel.evaluate(path), DecoyUriVerdict::Clean);
        }
        for (path, expected) in [
            ("/.env", DecoyCategory::EnvironmentSecret),
            ("/.azure/credentials", DecoyCategory::EnvironmentSecret),
            ("/app/terraform.tfstate", DecoyCategory::CloudInfrastructure),
            ("/wp-login.php", DecoyCategory::AdminCmsProbe),
            ("/private.key", DecoyCategory::PrivateKey),
            ("/backup.sql", DecoyCategory::DatabaseBackup),
            ("/.git/config", DecoyCategory::VersionControl),
            ("/.aws/credentials", DecoyCategory::CloudInfrastructure),
        ] {
            assert!(
                matches!(sentinel.evaluate(path), DecoyUriVerdict::Trapped { category, .. } if category == expected)
            );
        }
        assert!(matches!(
            sentinel.evaluate("//.ENV?id=1"),
            DecoyUriVerdict::Trapped { .. }
        ));
    }
}
