//! # Sovereign Bot Guard & User-Agent Interception Engine (`bot_guard`)
//!
//! Sub-microsecond, zero-allocation User-Agent classification and perimeter defense.
//! Deflects aggressive AI model scrapers, technology stack profilers, reconnaissance scanners,
//! and headless automation tools before allocating upstream server resources.

pub mod registry;
pub mod signatures;
pub use registry::{DynamicBotRecord, DynamicBotRegistry};
pub use signatures::{
    AI_SCRAPER_SIGNATURES, AUTOMATION_TOOL_SIGNATURES, LEGITIMATE_SEARCH_SIGNATURES,
    RECON_SCANNER_SIGNATURES,
};

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;

/// High-level classification of an incoming HTTP User-Agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BotCategory {
    AiScraper,
    ReconScanner,
    AutomationTool,
    LegitimateSearch,
    CliUtility,
    LegitimateBrowser,
    Unknown,
}

impl BotCategory {
    #[inline]
    pub fn is_unwanted(self) -> bool {
        matches!(
            self,
            BotCategory::AiScraper | BotCategory::ReconScanner | BotCategory::AutomationTool
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            BotCategory::AiScraper => "AI Scraper & Training Harvester",
            BotCategory::ReconScanner => "Reconnaissance Scanner & Profiler",
            BotCategory::AutomationTool => "Headless Automation & Scripting Tool",
            BotCategory::LegitimateSearch => "Legitimate Search Engine",
            BotCategory::CliUtility => "Developer CLI Utility",
            BotCategory::LegitimateBrowser => "Standard Human Browser",
            BotCategory::Unknown => "Unknown User-Agent",
        }
    }
}

/// Verdict returned when evaluating a client's User-Agent against the requested path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BotVerdict {
    Allowed {
        category: BotCategory,
    },
    Blocked {
        category: BotCategory,
        matched_token: Cow<'static, str>,
    },
}

impl BotVerdict {
    #[inline]
    pub fn matched_token(&self) -> Option<&str> {
        match self {
            BotVerdict::Blocked { matched_token, .. } => Some(matched_token.as_ref()),
            _ => None,
        }
    }

    #[inline]
    pub fn is_blocked(&self) -> bool {
        matches!(self, BotVerdict::Blocked { .. })
    }

    #[inline]
    pub fn is_allowed(&self) -> bool {
        !self.is_blocked()
    }

    pub fn public_message(&self) -> &'static str {
        match self {
            BotVerdict::Blocked { category: BotCategory::AiScraper, .. } => {
                "Access Denied: Automated AI scrapers, LLM training harvesters, and synthetic crawlers are prohibited on Sovereign infrastructure (RFC 9309)."
            }
            BotVerdict::Blocked { category: BotCategory::ReconScanner, .. } => {
                "Access Denied: Commercial stack profilers, reconnaissance scanners, and SEO harvesters are prohibited on Sovereign infrastructure (RFC 9309)."
            }
            BotVerdict::Blocked { category: BotCategory::AutomationTool, .. } => {
                "Access Denied: Headless automation, unvetted scripting engines, and vulnerability probes are blocked at perimeter."
            }
            _ => "Access Denied: Unrecognized or prohibited automated client.",
        }
    }
}

/// Sovereign Bot Guard Engine
#[derive(Debug, Clone)]
pub struct BotGuard {
    dynamic_registry: Arc<DynamicBotRegistry>,
}

impl Default for BotGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl BotGuard {
    pub fn new() -> Self {
        Self {
            dynamic_registry: Arc::new(DynamicBotRegistry::default()),
        }
    }

    pub fn with_dynamic_registry(dynamic_registry: Arc<DynamicBotRegistry>) -> Self {
        Self { dynamic_registry }
    }

    pub fn dynamic_registry(&self) -> &Arc<DynamicBotRegistry> {
        &self.dynamic_registry
    }

    pub fn harvest_canary_probe(&self, user_agent: Option<&str>, reason: &str, now_ms: u64) -> Option<String> {
        user_agent.and_then(|ua| self.dynamic_registry.harvest(ua, reason, now_ms))
    }

    #[inline]
    pub fn contains_ignore_case(haystack_bytes: &[u8], needle_lower: &[u8]) -> bool {
        if needle_lower.is_empty() {
            return true;
        }
        let needle_len = needle_lower.len();
        if haystack_bytes.len() < needle_len {
            return false;
        }
        let first = needle_lower[0];
        let max_start = haystack_bytes.len() - needle_len;
        for i in 0..=max_start {
            if haystack_bytes[i].to_ascii_lowercase() == first
                && haystack_bytes[i..i + needle_len]
                    .iter()
                    .zip(needle_lower.iter())
                    .all(|(h, n)| h.to_ascii_lowercase() == *n)
            {
                return true;
            }
        }
        false
    }

    pub fn classify(&self, user_agent: &str) -> (BotCategory, Option<Cow<'static, str>>) {
        let trimmed = user_agent.trim();
        if trimmed.is_empty() {
            return (BotCategory::Unknown, None);
        }
        if trimmed.len() > 4096 {
            return (BotCategory::AutomationTool, Some(Cow::Borrowed("Header-Exhaustion-Bomb")));
        }

        let bytes = trimmed.as_bytes();
        for &(needle, display_name) in AI_SCRAPER_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (BotCategory::AiScraper, Some(Cow::Borrowed(display_name)));
            }
        }
        for &(needle, display_name) in RECON_SCANNER_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (BotCategory::ReconScanner, Some(Cow::Borrowed(display_name)));
            }
        }
        for &(needle, display_name) in AUTOMATION_TOOL_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (BotCategory::AutomationTool, Some(Cow::Borrowed(display_name)));
            }
        }
        if let Some(matched) = self.dynamic_registry.check_ua(trimmed) {
            return (BotCategory::AutomationTool, Some(Cow::Owned(matched)));
        }
        if Self::contains_ignore_case(bytes, b"curl/")
            || Self::contains_ignore_case(bytes, b"wget/")
            || trimmed.eq_ignore_ascii_case("curl")
            || trimmed.eq_ignore_ascii_case("wget")
        {
            return (BotCategory::CliUtility, Some(Cow::Borrowed("CLI-Utility")));
        }
        for &(needle, display_name) in LEGITIMATE_SEARCH_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (BotCategory::LegitimateSearch, Some(Cow::Borrowed(display_name)));
            }
        }
        if Self::contains_ignore_case(bytes, b"python") {
            return (BotCategory::AutomationTool, Some(Cow::Borrowed("Python-Script")));
        }
        if Self::contains_ignore_case(bytes, b"mozilla/") {
            return (BotCategory::LegitimateBrowser, None);
        }
        (BotCategory::Unknown, None)
    }

    pub fn evaluate_perimeter(&self, user_agent: Option<&str>, path: &str) -> BotVerdict {
        if path == "/robots.txt" {
            return BotVerdict::Allowed { category: BotCategory::LegitimateSearch };
        }
        let ua = match user_agent {
            Some(u) if !u.trim().is_empty() => u.trim(),
            _ => return BotVerdict::Allowed { category: BotCategory::Unknown },
        };

        let (category, matched_token) = self.classify(ua);
        if category == BotCategory::CliUtility
            && (path.starts_with("/install/")
                || path.starts_with("/bin/")
                || path.starts_with("/checksums/")
                || path == "/healthz"
                || path == "/favicon.ico"
                || path == "/security.txt"
                || path.starts_with("/.well-known/")
                || path == "/SOVEREIGN_RELEASE_KEY.asc"
                || path == "/")
        {
            return BotVerdict::Allowed { category };
        }
        if category.is_unwanted() {
            return BotVerdict::Blocked {
                category,
                matched_token: matched_token.unwrap_or(Cow::Borrowed("Unwanted-Automated-Bot")),
            };
        }
        BotVerdict::Allowed { category }
    }
}
