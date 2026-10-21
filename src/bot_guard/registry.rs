//! # Dynamic Self-Healing Bot Signature Registry
//! Single Job: Autonomously harvest and LRU-bound malicious User-Agent signatures from tripped canary traps.

use super::BotGuard;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Record of an autonomously harvested bot signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicBotRecord {
    pub signature: String,
    pub original_ua_sample: String,
    pub reason: String,
    pub hits: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// Dynamic, self-healing bot registry that autonomously expands when new crawlers or scanners trip honeypots
#[derive(Debug, Clone)]
pub struct DynamicBotRegistry {
    max_capacity: usize,
    entries: Arc<RwLock<HashMap<String, DynamicBotRecord>>>,
}

impl Default for DynamicBotRegistry {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl DynamicBotRegistry {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            max_capacity,
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Autonomously harvest a malicious User-Agent from a trapped probe (e.g. Canary Trap or Honeypot).
    pub fn harvest(&self, raw_ua: &str, reason: &str, now_ms: u64) -> Option<String> {
        let trimmed = raw_ua.trim();
        if trimmed.is_empty() || trimmed.len() > 1024 {
            return None;
        }
        let token = Self::extract_signature_token(trimmed)?;
        let key = token.to_ascii_lowercase();
        if Self::is_protected_token(&key) {
            return None;
        }

        let mut lock = self.entries.write();
        if let Some(record) = lock.get_mut(&key) {
            record.hits = record.hits.saturating_add(1);
            record.last_seen_ms = now_ms;
            return Some(token);
        }

        if lock.len() >= self.max_capacity {
            if let Some(oldest_key) = lock
                .iter()
                .min_by_key(|(_, r)| r.last_seen_ms)
                .map(|(k, _)| k.clone())
            {
                lock.remove(&oldest_key);
            }
        }

        lock.insert(
            key,
            DynamicBotRecord {
                signature: token.clone(),
                original_ua_sample: trimmed.chars().take(256).collect(),
                reason: reason.to_string(),
                hits: 1,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
            },
        );
        Some(token)
    }

    /// Check if an incoming User-Agent matches any dynamically harvested signature
    pub fn check_ua(&self, user_agent: &str) -> Option<String> {
        let lock = self.entries.read();
        if lock.is_empty() {
            return None;
        }
        let ua_bytes = user_agent.as_bytes();
        for (needle_lower, record) in lock.iter() {
            if BotGuard::contains_ignore_case(ua_bytes, needle_lower.as_bytes()) {
                return Some(record.signature.clone());
            }
        }
        None
    }

    fn extract_signature_token(ua: &str) -> Option<String> {
        let first_part = ua.split(['/', ' ', ';', '(']).next()?.trim();
        if first_part.len() < 3 {
            return None;
        }
        Some(first_part.chars().take(64).collect())
    }

    fn is_protected_token(lower: &str) -> bool {
        matches!(
            lower,
            "mozilla" | "chrome" | "safari" | "webkit" | "gecko" | "applewebkit"
                | "edge" | "edg" | "curl" | "wget" | "googlebot" | "bingbot"
                | "duckduckbot" | "yandexbot" | "baiduspider"
        )
    }
}
