//! # Radical OJP: Financial Toll Fraud & Telephony Abuse Guard
//! Single Job: Intercept premium-rate routes, SMS pumping fraud, and enforce sliding financial dispatch quotas.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// High-Risk International E.164 Prefixes targeted in SMS pumping and toll fraud
pub const HIGH_RISK_PREFIXES: &[&str] = &[
    "870", "881", "882", "883", "888", // Satellite & International Premium Networks
    "247", "231", "252", "223", "232", "224", "248", "269", "290", "674", "688",
];

/// Verdict from TollGuard evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TollVerdict {
    /// Dispatch is permitted within budget quotas
    Allowed,
    /// Phone number route is high-risk premium/satellite route
    BlockedHighRiskRoute { prefix: String },
    /// Per-recipient dispatch quota exceeded for current 24-hour window
    RecipientLimitExceeded { recipient: String, limit: u32 },
    /// Global system dispatch budget exceeded for current window
    GlobalBudgetExceeded { period: String, limit: u32 },
    /// Malformed phone number syntax
    MalformedPhone,
}

impl TollVerdict {
    #[inline]
    pub fn is_allowed(&self) -> bool {
        matches!(self, TollVerdict::Allowed)
    }

    pub fn public_message(&self) -> &'static str {
        match self {
            TollVerdict::Allowed => "Dispatch permitted.",
            TollVerdict::BlockedHighRiskRoute { .. } => {
                "International carrier route restricted for security. Please use email verification."
            }
            TollVerdict::RecipientLimitExceeded { .. } => {
                "Daily dispatch limit reached for this recipient. Please try again tomorrow."
            }
            TollVerdict::GlobalBudgetExceeded { .. } => {
                "System notification capacity reached for this period. Please try again later."
            }
            TollVerdict::MalformedPhone => "Invalid phone number format.",
        }
    }
}

/// Configuration for Financial & Telephony Guard
#[derive(Debug, Clone)]
pub struct TollGuardConfig {
    pub max_per_phone_per_24h: u32,
    pub max_per_email_per_24h: u32,
    pub max_global_sms_per_hour: u32,
    pub max_global_sms_per_day: u32,
    pub blocked_prefixes: Vec<String>,
}

impl Default for TollGuardConfig {
    fn default() -> Self {
        Self {
            max_per_phone_per_24h: 3,
            max_per_email_per_24h: 5,
            max_global_sms_per_hour: 50,
            max_global_sms_per_day: 200,
            blocked_prefixes: HIGH_RISK_PREFIXES.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Debug, Default)]
struct SlidingCounter {
    events: Vec<u64>,
}

impl SlidingCounter {
    fn count_since(&mut self, cutoff_ms: u64) -> usize {
        self.events.retain(|&ts| ts >= cutoff_ms);
        self.events.len()
    }

    fn record(&mut self, now_ms: u64) {
        self.events.push(now_ms);
    }
}

/// Sovereign Toll & Financial Fraud Guard
#[derive(Debug, Clone)]
pub struct TollGuard {
    config: TollGuardConfig,
    phone_dispatches: Arc<RwLock<HashMap<String, SlidingCounter>>>,
    email_dispatches: Arc<RwLock<HashMap<String, SlidingCounter>>>,
    global_sms_dispatches: Arc<RwLock<SlidingCounter>>,
}

impl Default for TollGuard {
    fn default() -> Self {
        Self::new(TollGuardConfig::default())
    }
}

impl TollGuard {
    pub fn new(config: TollGuardConfig) -> Self {
        Self {
            config,
            phone_dispatches: Arc::new(RwLock::new(HashMap::new())),
            email_dispatches: Arc::new(RwLock::new(HashMap::new())),
            global_sms_dispatches: Arc::new(RwLock::new(SlidingCounter::default())),
        }
    }

    /// Clean phone string by stripping non-digit characters except leading '+'
    pub fn normalize_phone(phone: &str) -> String {
        let trimmed = phone.trim();
        let has_plus = trimmed.starts_with('+');
        let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
        if has_plus {
            format!("+{}", digits)
        } else {
            digits
        }
    }

    /// Inspect a candidate phone number before SMS dispatch
    pub fn check_phone(&self, phone: &str, now_ms: u64) -> TollVerdict {
        let clean = Self::normalize_phone(phone);
        let raw_digits: String = clean.chars().filter(|c| c.is_ascii_digit()).collect();

        if raw_digits.len() < 10 || raw_digits.len() > 15 {
            return TollVerdict::MalformedPhone;
        }

        // 1. Check for high-risk international prefix
        for prefix in &self.config.blocked_prefixes {
            let p_digits: String = prefix.chars().filter(|c| c.is_ascii_digit()).collect();
            if raw_digits.starts_with(&p_digits) {
                return TollVerdict::BlockedHighRiskRoute {
                    prefix: prefix.clone(),
                };
            }
        }

        // 2. Check Global Hourly and Daily Dispatch Budgets
        let hour_cutoff = now_ms.saturating_sub(3_600_000);
        let day_cutoff = now_ms.saturating_sub(86_400_000);

        {
            let mut global = self.global_sms_dispatches.write();
            let day_count = global.count_since(day_cutoff);
            if day_count >= self.config.max_global_sms_per_day as usize {
                return TollVerdict::GlobalBudgetExceeded {
                    period: "daily".to_string(),
                    limit: self.config.max_global_sms_per_day,
                };
            }

            let hour_count = global
                .events
                .iter()
                .filter(|&&ts| ts >= hour_cutoff)
                .count();
            if hour_count >= self.config.max_global_sms_per_hour as usize {
                return TollVerdict::GlobalBudgetExceeded {
                    period: "hourly".to_string(),
                    limit: self.config.max_global_sms_per_hour,
                };
            }
        }

        // 3. Check Per-Recipient 24-Hour Cap
        {
            let mut phones = self.phone_dispatches.write();
            let counter = phones.entry(raw_digits.clone()).or_default();
            if counter.count_since(day_cutoff) >= self.config.max_per_phone_per_24h as usize {
                return TollVerdict::RecipientLimitExceeded {
                    recipient: clean,
                    limit: self.config.max_per_phone_per_24h,
                };
            }
        }

        TollVerdict::Allowed
    }

    /// Record a successful phone SMS dispatch
    pub fn record_phone_dispatch(&self, phone: &str, now_ms: u64) {
        let raw_digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        {
            let mut phones = self.phone_dispatches.write();
            phones.entry(raw_digits).or_default().record(now_ms);
        }
        {
            let mut global = self.global_sms_dispatches.write();
            global.record(now_ms);
        }
    }

    /// Inspect a candidate email address before recovery dispatch
    pub fn check_email(&self, email: &str, now_ms: u64) -> TollVerdict {
        let key = email.trim().to_lowercase();
        let day_cutoff = now_ms.saturating_sub(86_400_000);

        let mut emails = self.email_dispatches.write();
        let counter = emails.entry(key.clone()).or_default();
        if counter.count_since(day_cutoff) >= self.config.max_per_email_per_24h as usize {
            return TollVerdict::RecipientLimitExceeded {
                recipient: key,
                limit: self.config.max_per_email_per_24h,
            };
        }

        TollVerdict::Allowed
    }

    /// Record a successful email dispatch
    pub fn record_email_dispatch(&self, email: &str, now_ms: u64) {
        let key = email.trim().to_lowercase();
        let mut emails = self.email_dispatches.write();
        emails.entry(key).or_default().record(now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toll_guard_blocks_satellite_and_high_risk_prefixes() {
        let guard = TollGuard::default();
        let now = 1_000_000_000;

        // Inmarsat satellite
        let res = guard.check_phone("+870773111222", now);
        assert!(matches!(res, TollVerdict::BlockedHighRiskRoute { .. }));

        // Ascension Island
        let res = guard.check_phone("+24712345678", now);
        assert!(matches!(res, TollVerdict::BlockedHighRiskRoute { .. }));

        // Valid US mobile
        let res = guard.check_phone("+12156674172", now);
        assert_eq!(res, TollVerdict::Allowed);
    }

    #[test]
    fn test_toll_guard_enforces_per_recipient_daily_cap() {
        let guard = TollGuard::default();
        let now = 1_000_000_000;
        let phone = "+12156674172";

        // First 3 dispatches allowed
        for i in 0..3 {
            assert_eq!(
                guard.check_phone(phone, now + i * 1000),
                TollVerdict::Allowed
            );
            guard.record_phone_dispatch(phone, now + i * 1000);
        }

        // 4th dispatch exceeds recipient limit
        let res = guard.check_phone(phone, now + 4000);
        assert!(matches!(res, TollVerdict::RecipientLimitExceeded { .. }));

        // After 24h window expires, dispatches are permitted again
        let next_day = now + 86_400_000 + 10_000;
        assert_eq!(guard.check_phone(phone, next_day), TollVerdict::Allowed);
    }

    #[test]
    fn test_toll_guard_enforces_global_hourly_sms_budget() {
        let config = TollGuardConfig {
            max_global_sms_per_hour: 5,
            ..Default::default()
        };
        let guard = TollGuard::new(config);
        let now = 1_000_000_000;

        for i in 0..5 {
            let phone = format!("+1555123400{}", i);
            assert_eq!(guard.check_phone(&phone, now), TollVerdict::Allowed);
            guard.record_phone_dispatch(&phone, now);
        }

        // 6th global SMS in the same hour triggers global budget cap
        let res = guard.check_phone("+15559998888", now + 100);
        assert!(matches!(res, TollVerdict::GlobalBudgetExceeded { .. }));
    }
}
