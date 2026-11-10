//! # Sovereign Asymmetric Tarpit Governor (`tarpit/governor.rs`)
//! Reverses Slowloris attacks: trickles response chunks byte-by-byte at throttled cadence.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// Configuration for the Asymmetric Tarpit Governor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TarpitConfig {
    /// Baseline delay in milliseconds between trickled chunks (e.g. 3000ms = 3s)
    pub trickle_interval_ms: u64,
    /// Baseline maximum duration in seconds to keep the bot connection stalled
    pub max_duration_s: u64,
    /// Baseline number of bytes to send per trickle tick
    pub chunk_size: usize,
    /// Maximum concurrent tarpit connections allowed before fail-safe drop
    pub max_concurrent_tarpits: usize,
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            trickle_interval_ms: 3000,
            max_duration_s: 45,
            chunk_size: 2,
            max_concurrent_tarpits: 256,
        }
    }
}

/// Dynamic per-offender velocity scaling profile computed from repeat strike history
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveTarpitProfile {
    /// Cumulative tarpit strikes recorded for this IP
    pub strike_count: u32,
    /// Scaled trickle interval in milliseconds (up to 15,000ms for Strike 3+)
    pub trickle_interval_ms: u64,
    /// Scaled bytes per tick (down to 1 byte for repeat offenders)
    pub chunk_size: usize,
    /// Scaled maximum hostage duration in seconds (up to 180s for Strike 3+)
    pub max_duration_s: u64,
}

/// RAII Slot Guard that releases the tarpit slot when the connection terminates
#[derive(Debug)]
pub struct TarpitSlotGuard {
    active_count: Arc<AtomicUsize>,
    total_wasted_ms: Arc<AtomicU64>,
    start_ms: u64,
    profile: AdaptiveTarpitProfile,
}

impl TarpitSlotGuard {
    #[inline]
    pub fn profile(&self) -> AdaptiveTarpitProfile {
        self.profile
    }
}

impl Drop for TarpitSlotGuard {
    fn drop(&mut self) {
        self.active_count.fetch_sub(1, Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(self.start_ms);
        let elapsed = now.saturating_sub(self.start_ms);
        self.total_wasted_ms.fetch_add(elapsed, Ordering::Relaxed);
    }
}

/// Tarpit allocation verdict
#[derive(Debug)]
pub enum TarpitVerdict {
    /// Tarpit engaged: worker held in slow trickle stream
    Engage { slot_guard: TarpitSlotGuard },
    /// Concurrency ceiling reached: fail-safe drop connection to conserve server FDs
    CeilingExceededDrop,
}

impl PartialEq for TarpitVerdict {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (TarpitVerdict::Engage { .. }, TarpitVerdict::Engage { .. })
                | (
                    TarpitVerdict::CeilingExceededDrop,
                    TarpitVerdict::CeilingExceededDrop
                )
        )
    }
}

/// The Tarpit Governor orchestrating connection slots, repeat-strike velocity scaling, and decoy trickling
#[derive(Debug, Clone)]
pub struct TarpitGovernor {
    config: TarpitConfig,
    active_count: Arc<AtomicUsize>,
    total_tarpitted: Arc<AtomicUsize>,
    total_wasted_ms: Arc<AtomicU64>,
    strike_ledger: Arc<Mutex<HashMap<String, u32>>>,
}

impl TarpitGovernor {
    pub fn new(config: TarpitConfig) -> Self {
        Self {
            config,
            active_count: Arc::new(AtomicUsize::new(0)),
            total_tarpitted: Arc::new(AtomicUsize::new(0)),
            total_wasted_ms: Arc::new(AtomicU64::new(0)),
            strike_ledger: Arc::new(Mutex::new(HashMap::with_capacity(256))),
        }
    }

    #[inline]
    pub fn compute_adaptive_profile(&self, strike_count: u32) -> AdaptiveTarpitProfile {
        match strike_count {
            0 | 1 => AdaptiveTarpitProfile {
                strike_count: 1,
                trickle_interval_ms: self.config.trickle_interval_ms,
                chunk_size: self.config.chunk_size,
                max_duration_s: self.config.max_duration_s,
            },
            2 => AdaptiveTarpitProfile {
                strike_count: 2,
                trickle_interval_ms: (self.config.trickle_interval_ms * 5 / 2).max(7500),
                chunk_size: 1,
                max_duration_s: (self.config.max_duration_s * 2).max(90),
            },
            s => AdaptiveTarpitProfile {
                strike_count: s,
                trickle_interval_ms: 15_000,
                chunk_size: 1,
                max_duration_s: (self.config.max_duration_s * 4).max(180),
            },
        }
    }

    pub fn acquire_slot(&self, client_ip: &str) -> TarpitVerdict {
        let current = self.active_count.load(Ordering::SeqCst);
        if current >= self.config.max_concurrent_tarpits {
            return TarpitVerdict::CeilingExceededDrop;
        }

        let strikes = if client_ip.is_empty() {
            1
        } else {
            let mut ledger = self.strike_ledger.lock();
            if ledger.len() >= 8192 && !ledger.contains_key(client_ip) {
                ledger.clear();
            }
            let entry = ledger.entry(client_ip.to_string()).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        };

        let profile = self.compute_adaptive_profile(strikes);
        self.active_count.fetch_add(1, Ordering::SeqCst);
        self.total_tarpitted.fetch_add(1, Ordering::Relaxed);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        TarpitVerdict::Engage {
            slot_guard: TarpitSlotGuard {
                active_count: Arc::clone(&self.active_count),
                total_wasted_ms: Arc::clone(&self.total_wasted_ms),
                start_ms: now_ms,
                profile,
            },
        }
    }

    pub fn strikes_for_ip(&self, client_ip: &str) -> u32 {
        self.strike_ledger
            .lock()
            .get(client_ip)
            .copied()
            .unwrap_or(0)
    }

    pub fn generate_decoy_chunk(&self, chunk_index: usize) -> Vec<u8> {
        if chunk_index == 0 {
            b"<!DOCTYPE html><html><head><title>Authentication Verification In Progress</title></head><body><!-- init -->\n".to_vec()
        } else {
            format!(
                "<!-- chunk_{:04x}: verifying security telemetry parameters... -->\n",
                chunk_index
            )
            .into_bytes()
        }
    }

    pub fn active_tarpits_count(&self) -> usize {
        self.active_count.load(Ordering::SeqCst)
    }

    pub fn total_tarpitted_count(&self) -> usize {
        self.total_tarpitted.load(Ordering::Relaxed)
    }

    pub fn total_wasted_duration_ms(&self) -> u64 {
        self.total_wasted_ms.load(Ordering::Relaxed)
    }

    pub fn config(&self) -> &TarpitConfig {
        &self.config
    }
}
