//! # Autonomous Zero-Day & Emerging Threat Harvester (Layer 13)
//!
//! One-Job: Autonomously correlate anomalous, unmapped 404 reconnaissance probes across
//! distinct network subnets, detecting coordinated zero-day vulnerability campaigns in real-time
//! and elevating confirmed threat paths into the active `DecoyUriSentinel` trap catalog without human intervention.

pub mod subnet;
pub use subnet::{categorize_candidate_heuristic, SubnetKey};

use crate::decoy_uri::{DecoyCategory, DecoyUriSentinel};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

/// Configuration for Autonomous Zero-Day Threat Harvester
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHarvesterConfig {
    /// Whether autonomous threat harvesting is active (default: true)
    pub enabled: bool,
    /// Number of distinct /24 or /48 subnets required to promote an anomalous path (default: 3)
    pub promotion_subnet_threshold: usize,
    /// Sliding time window in milliseconds during which subnets must be observed (default: 3,600,000 ms = 1 hr)
    pub window_duration_ms: u64,
    /// Maximum distinct anomalous paths tracked simultaneously to prevent memory exhaustion (default: 10,000)
    pub max_tracked_candidates: usize,
    /// Maximum distinct candidate paths a single subnet may introduce in a window (anti-fuzzing quota, default: 25)
    pub max_paths_per_subnet: usize,
}

impl Default for ThreatHarvesterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            promotion_subnet_threshold: 3,
            window_duration_ms: 3_600_000, // 1 hour
            max_tracked_candidates: 10_000,
            max_paths_per_subnet: 25,
        }
    }
}

/// In-memory forensic record for an anomalous candidate path under observation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePathRecord {
    pub path: String,
    pub category: DecoyCategory,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub hit_count: u64,
    pub participating_subnets: HashSet<SubnetKey>,
    pub promoted: bool,
}

/// Verdict returned when an anomalous path reaches threshold and is elevated to active decoy traps
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionVerdict {
    pub path: String,
    pub category: DecoyCategory,
    pub distinct_subnets: usize,
    pub total_hits: u64,
    pub first_seen_ms: u64,
    pub promoted_at_ms: u64,
}

/// Autonomous Threat Harvester Engine
#[derive(Debug, Clone)]
pub struct ThreatHarvesterEngine {
    config: ThreatHarvesterConfig,
    sentinel: DecoyUriSentinel,
    candidates: Arc<RwLock<HashMap<String, CandidatePathRecord>>>,
    subnet_path_counts: Arc<RwLock<HashMap<SubnetKey, usize>>>,
}

impl ThreatHarvesterEngine {
    /// Construct a new threat harvester bound to an existing `DecoyUriSentinel`
    pub fn new(config: ThreatHarvesterConfig, sentinel: DecoyUriSentinel) -> Self {
        Self {
            config,
            sentinel,
            candidates: Arc::new(RwLock::new(HashMap::new())),
            subnet_path_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Construct a new threat harvester with a default `DecoyUriSentinel`
    pub fn with_default_sentinel(config: ThreatHarvesterConfig) -> Self {
        Self::new(config, DecoyUriSentinel::default())
    }

    pub fn sentinel(&self) -> &DecoyUriSentinel {
        &self.sentinel
    }
    pub fn config(&self) -> &ThreatHarvesterConfig {
        &self.config
    }
    pub fn candidate_count(&self) -> usize {
        self.candidates.read().len()
    }
    pub fn is_candidate(&self, raw_path: &str) -> bool {
        let normalized = DecoyUriSentinel::normalize_path(raw_path);
        self.candidates.read().contains_key(&normalized)
    }
    pub fn get_candidate(&self, raw_path: &str) -> Option<CandidatePathRecord> {
        let normalized = DecoyUriSentinel::normalize_path(raw_path);
        self.candidates.read().get(&normalized).cloned()
    }

    /// Ingest an unmapped or anomalous URI probe from an incoming request
    pub fn ingest_anomalous_uri(
        &self,
        raw_path: &str,
        client_ip: IpAddr,
        now_ms: u64,
    ) -> Option<PromotionVerdict> {
        if !self.config.enabled {
            return None;
        }
        let normalized = DecoyUriSentinel::normalize_path(raw_path);
        if normalized == "/" || normalized.is_empty() || self.sentinel.contains_trap(&normalized) {
            return None;
        }

        let subnet = SubnetKey::from_ip(client_ip);
        let mut candidates = self.candidates.write();
        let mut subnet_counts = self.subnet_path_counts.write();

        if let Some(record) = candidates.get_mut(&normalized) {
            if now_ms.saturating_sub(record.first_seen_ms) > self.config.window_duration_ms {
                record.first_seen_ms = now_ms;
                record.last_seen_ms = now_ms;
                record.hit_count = 1;
                record.participating_subnets.clear();
                record.participating_subnets.insert(subnet);
                return None;
            }

            record.hit_count = record.hit_count.saturating_add(1);
            record.last_seen_ms = now_ms;
            record.participating_subnets.insert(subnet);

            if !record.promoted
                && record.participating_subnets.len() >= self.config.promotion_subnet_threshold
            {
                record.promoted = true;
                let category = record.category;
                let distinct_subnets = record.participating_subnets.len();
                let total_hits = record.hit_count;
                let first_seen_ms = record.first_seen_ms;

                self.sentinel.add_exact_trap_with_category(&normalized, category);
                return Some(PromotionVerdict {
                    path: normalized,
                    category,
                    distinct_subnets,
                    total_hits,
                    first_seen_ms,
                    promoted_at_ms: now_ms,
                });
            }
            None
        } else {
            let current_subnet_paths = subnet_counts.get(&subnet).copied().unwrap_or(0);
            if current_subnet_paths >= self.config.max_paths_per_subnet {
                return None;
            }

            if candidates.len() >= self.config.max_tracked_candidates {
                Self::prune_internal(
                    &mut candidates,
                    &mut subnet_counts,
                    now_ms,
                    self.config.window_duration_ms,
                );
                if candidates.len() >= self.config.max_tracked_candidates {
                    if let Some(evict_key) = candidates
                        .iter()
                        .min_by_key(|(_, rec)| (rec.participating_subnets.len(), rec.last_seen_ms))
                        .map(|(k, _)| k.clone())
                    {
                        candidates.remove(&evict_key);
                    }
                }
            }

            let entry = subnet_counts.entry(subnet).or_insert(0);
            *entry = entry.saturating_add(1);

            let category = Self::categorize_candidate_heuristic(&normalized);
            let mut subnets = HashSet::new();
            subnets.insert(subnet);
            let qualifies_immediately = self.config.promotion_subnet_threshold <= 1;

            let record = CandidatePathRecord {
                path: normalized.clone(),
                category,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                hit_count: 1,
                participating_subnets: subnets,
                promoted: qualifies_immediately,
            };
            candidates.insert(normalized.clone(), record);

            if qualifies_immediately {
                self.sentinel.add_exact_trap_with_category(&normalized, category);
                Some(PromotionVerdict {
                    path: normalized,
                    category,
                    distinct_subnets: 1,
                    total_hits: 1,
                    first_seen_ms: now_ms,
                    promoted_at_ms: now_ms,
                })
            } else {
                None
            }
        }
    }

    /// Convenience wrapper accepting an IP string
    pub fn ingest_anomalous_uri_str(
        &self,
        raw_path: &str,
        client_ip_str: &str,
        now_ms: u64,
    ) -> Option<PromotionVerdict> {
        let ip = client_ip_str.trim().parse::<IpAddr>().ok()?;
        self.ingest_anomalous_uri(raw_path, ip, now_ms)
    }

    pub fn ingest_cve_entry(&self, cve_id: &str, paths: &[&str], category: DecoyCategory) -> usize {
        let mut count = 0;
        for path in paths {
            let normalized = DecoyUriSentinel::normalize_path(path);
            if !normalized.is_empty() && normalized != "/" {
                self.sentinel.add_exact_trap_with_category(&normalized, category);
                count += 1;
            }
        }
        let _ = (cve_id, category);
        count
    }

    /// Bulk loader for CISA Known Exploited Vulnerabilities (KEV) or MITRE CVE catalogs
    pub fn ingest_bulk_cve_catalog(&self, catalog: &[(&str, DecoyCategory)]) -> usize {
        let mut activated = 0;
        for (path, category) in catalog {
            let normalized = DecoyUriSentinel::normalize_path(path);
            if !normalized.is_empty() && normalized != "/" {
                self.sentinel.add_exact_trap_with_category(&normalized, *category);
                activated += 1;
            }
        }
        activated
    }

    /// Synchronously prune expired candidate records and reset decayed subnet quotas
    pub fn prune_expired(&self, now_ms: u64) -> usize {
        let mut candidates = self.candidates.write();
        let mut subnet_counts = self.subnet_path_counts.write();
        Self::prune_internal(
            &mut candidates,
            &mut subnet_counts,
            now_ms,
            self.config.window_duration_ms,
        )
    }

    fn prune_internal(
        candidates: &mut HashMap<String, CandidatePathRecord>,
        subnet_counts: &mut HashMap<SubnetKey, usize>,
        now_ms: u64,
        window_duration_ms: u64,
    ) -> usize {
        let initial_len = candidates.len();
        candidates.retain(|_, rec| {
            !rec.promoted && now_ms.saturating_sub(rec.last_seen_ms) <= window_duration_ms
        });
        let pruned = initial_len.saturating_sub(candidates.len());

        subnet_counts.clear();
        for rec in candidates.values() {
            for subnet in &rec.participating_subnets {
                let entry = subnet_counts.entry(*subnet).or_insert(0);
                *entry = entry.saturating_add(1);
            }
        }
        pruned
    }

    /// Heuristic classifier determining threat category for newly observed probe paths
    pub fn categorize_candidate_heuristic(path: &str) -> DecoyCategory {
        subnet::categorize_candidate_heuristic(path)
    }
}
