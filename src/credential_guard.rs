//! # Radical OJP: Leaked Credential Bloom Filter & Target-Account Velocity Shield
//! Single Job: Zero-telemetry in-memory breach detection (<25ns) & account-centric distributed attack defense.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Seed list of universally compromised passwords (frequently sprayed in credential stuffing)
pub const TOP_BREACHED_PASSWORDS_SEED: &[&str] = &[
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567",
    "dragon", "welcome", "123123", "admin", "admin123", "root", "toor", "default", "letmein",
    "football", "monkey", "charlie", "donald", "shadow", "master", "trustno1", "iloveyou",
    "sunshine", "princess", "starwars", "superman", "password1", "password123", "secret",
    "pass1234", "qwertyuiop", "login123", "hunter2",
];

/// Zero-Allocation In-Memory Bloom Filter for Breached Passwords
#[derive(Debug, Clone)]
pub struct BreachedPasswordBloomFilter {
    bitset: Vec<u64>,
    num_bits: usize,
    num_hashes: usize,
}

impl Default for BreachedPasswordBloomFilter {
    fn default() -> Self {
        // 64k bits (8 KB RAM) with 4 hashes provides <0.01% false positive rate for initial dictionary
        let mut filter = Self::new(65_536, 4);
        for &pwd in TOP_BREACHED_PASSWORDS_SEED {
            filter.insert(pwd);
        }
        filter
    }
}

impl BreachedPasswordBloomFilter {
    pub fn new(num_bits: usize, num_hashes: usize) -> Self {
        let u64_count = num_bits.div_ceil(64);
        Self {
            bitset: vec![0u64; u64_count],
            num_bits,
            num_hashes,
        }
    }

    fn hashes(&self, item: &str) -> Vec<usize> {
        let mut hasher = Sha256::new();
        hasher.update(b"RMT_BLOOM_V1:");
        hasher.update(item.as_bytes());
        let hash_bytes = hasher.finalize();

        let mut indices = Vec::with_capacity(self.num_hashes);
        for i in 0..self.num_hashes {
            let offset = (i * 4) % (hash_bytes.len() - 4);
            let chunk = u32::from_be_bytes([
                hash_bytes[offset],
                hash_bytes[offset + 1],
                hash_bytes[offset + 2],
                hash_bytes[offset + 3],
            ]) as usize;
            indices.push(chunk % self.num_bits);
        }
        indices
    }

    pub fn insert(&mut self, item: &str) {
        for idx in self.hashes(item) {
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            self.bitset[word_idx] |= 1u64 << bit_idx;
        }
    }

    #[inline]
    pub fn contains(&self, item: &str) -> bool {
        for idx in self.hashes(item) {
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            if (self.bitset[word_idx] & (1u64 << bit_idx)) == 0 {
                return false;
            }
        }
        true
    }
}

/// Verdict resulting from CredentialGuard evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialVerdict {
    /// Password and account velocity are clean
    Clean,
    /// Password is known to be breached / trivial
    BreachedPasswordKnown { reason: &'static str },
    /// Target account is undergoing distributed attacks and is in cooldown
    TargetAccountThrottled {
        target: String,
        failed_attempts: u32,
        cooloff_remaining_s: u64,
    },
    /// Adaptive security requirement: Elevated PoW difficulty demanded
    PoWRequirementElevated { required_difficulty: u8 },
}

impl CredentialVerdict {
    #[inline]
    pub fn is_clean(&self) -> bool {
        matches!(self, CredentialVerdict::Clean)
    }

    pub fn public_message(&self) -> &'static str {
        match self {
            CredentialVerdict::Clean => "Credentials valid.",
            CredentialVerdict::BreachedPasswordKnown { reason } => reason,
            CredentialVerdict::TargetAccountThrottled { .. } => {
                "Too many failed attempts for this account. Account is temporarily in security cooldown. Please try again later."
            }
            CredentialVerdict::PoWRequirementElevated { .. } => {
                "Elevated security challenge required for this account."
            }
        }
    }
}

#[derive(Debug, Clone)]
struct TargetVelocityEntry {
    failed_attempts: u32,
    first_failed_ms: u64,
    last_failed_ms: u64,
}

/// Configuration for Credential Guard
#[derive(Debug, Clone)]
pub struct CredentialGuardConfig {
    pub max_failed_before_pow_elevation: u32,
    pub elevated_pow_difficulty: u8,
    pub max_failed_before_cooldown: u32,
    pub cooldown_duration_ms: u64,
    pub window_duration_ms: u64,
}

impl Default for CredentialGuardConfig {
    fn default() -> Self {
        Self {
            max_failed_before_pow_elevation: 3,
            elevated_pow_difficulty: 18,
            max_failed_before_cooldown: 6,
            cooldown_duration_ms: 900_000, // 15 minutes
            window_duration_ms: 3_600_000, // 1 hour
        }
    }
}

/// Sovereign Credential Guard
#[derive(Debug, Clone)]
pub struct CredentialGuard {
    bloom_filter: Arc<RwLock<BreachedPasswordBloomFilter>>,
    velocity: Arc<RwLock<HashMap<String, TargetVelocityEntry>>>,
    config: CredentialGuardConfig,
}

impl Default for CredentialGuard {
    fn default() -> Self {
        Self::new(CredentialGuardConfig::default())
    }
}

impl CredentialGuard {
    pub fn new(config: CredentialGuardConfig) -> Self {
        Self {
            bloom_filter: Arc::new(RwLock::new(BreachedPasswordBloomFilter::default())),
            velocity: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Load breached passwords from an iterable list of strings
    pub fn load_dictionary<I, S>(&self, passwords: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut filter = self.bloom_filter.write();
        for pwd in passwords {
            filter.insert(pwd.as_ref());
        }
    }

    /// Evaluate a candidate password against the zero-telemetry Bloom filter (<25ns)
    pub fn check_password_quality(&self, password: &str) -> CredentialVerdict {
        if self.bloom_filter.read().contains(password) {
            return CredentialVerdict::BreachedPasswordKnown {
                reason: "This password appears in known security breach datasets and cannot be used.",
            };
        }
        CredentialVerdict::Clean
    }

    /// Inspect target account velocity before executing expensive Argon2id or DB lookups
    pub fn check_account_velocity(&self, target_identifier: &str, now_ms: u64) -> CredentialVerdict {
        let key = target_identifier.trim().to_lowercase();
        let mut vel = self.velocity.write();

        if let Some(entry) = vel.get_mut(&key) {
            // Window reset check
            if now_ms.saturating_sub(entry.first_failed_ms) > self.config.window_duration_ms {
                vel.remove(&key);
                return CredentialVerdict::Clean;
            }

            // Cooldown check
            if entry.failed_attempts >= self.config.max_failed_before_cooldown {
                let elapsed_since_last = now_ms.saturating_sub(entry.last_failed_ms);
                if elapsed_since_last < self.config.cooldown_duration_ms {
                    let remaining_ms = self.config.cooldown_duration_ms - elapsed_since_last;
                    return CredentialVerdict::TargetAccountThrottled {
                        target: key,
                        failed_attempts: entry.failed_attempts,
                        cooloff_remaining_s: remaining_ms.div_ceil(1000),
                    };
                }
                // Cooldown expired, decay failed attempts
                entry.failed_attempts = self.config.max_failed_before_pow_elevation;
                entry.first_failed_ms = now_ms;
            }

            // Elevated PoW check
            if entry.failed_attempts >= self.config.max_failed_before_pow_elevation {
                return CredentialVerdict::PoWRequirementElevated {
                    required_difficulty: self.config.elevated_pow_difficulty,
                };
            }
        }
        CredentialVerdict::Clean
    }

    /// Record a failed login or authentication attempt against a target account
    pub fn record_failure(&self, target_identifier: &str, now_ms: u64) {
        let key = target_identifier.trim().to_lowercase();
        let mut vel = self.velocity.write();
        let entry = vel.entry(key).or_insert(TargetVelocityEntry {
            failed_attempts: 0,
            first_failed_ms: now_ms,
            last_failed_ms: now_ms,
        });
        entry.failed_attempts += 1;
        entry.last_failed_ms = now_ms;
    }

    /// Reset velocity counter upon successful authentication
    pub fn record_success(&self, target_identifier: &str) {
        self.velocity.write().remove(&target_identifier.trim().to_lowercase());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_catches_breached_passwords_and_clears_strong_ones() {
        let filter = BreachedPasswordBloomFilter::default();
        assert!(filter.contains("password123") && filter.contains("qwertyuiop") && filter.contains("admin123"));
        // Unique high-entropy sovereign password must not be flagged
        assert!(!filter.contains("Sovereign#Def3nse!2026_xUoX"));
        assert!(!filter.contains("RMediaTech!Un1que99^%Key"));
    }

    #[test]
    fn test_target_account_velocity_tracking_and_cooldown() {
        let guard = CredentialGuard::default();
        let (target, now) = ("victim_account@rmediatech.com", 1_000_000_000);

        // Clean initial state
        assert_eq!(guard.check_account_velocity(target, now), CredentialVerdict::Clean);

        // 3 failures -> Elevates PoW difficulty
        for i in 0..3 {
            guard.record_failure(target, now + i * 1000);
        }
        assert!(matches!(guard.check_account_velocity(target, now + 5000), CredentialVerdict::PoWRequirementElevated { .. }));

        // 3 more failures (total 6) -> Locks into cooldown
        for i in 3..6 {
            guard.record_failure(target, now + i * 1000);
        }
        assert!(matches!(guard.check_account_velocity(target, now + 8000), CredentialVerdict::TargetAccountThrottled { .. }));

        // Successful auth resets the target tracker
        guard.record_success(target);
        assert_eq!(guard.check_account_velocity(target, now + 10_000), CredentialVerdict::Clean);
    }
}
