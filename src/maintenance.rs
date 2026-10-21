//! # Autonomous Defense Maintenance & Hygiene Engine
//!
//! Radical OJP: Periodically audit and prune expired or decayed defensive in-memory state
//! (quarantined subnets, ratcheted PoW IP records) to guarantee zero memory leakage
//! and continuous sub-microsecond evaluation throughput.

use crate::adaptive_pow::AdaptivePowEngine;
use crate::autonomous_quarantine::AutonomousQuarantine;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Forensic report detailing the results of a completed hygiene cycle
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MaintenanceReport {
    pub quarantined_subnets_pruned: usize,
    pub decayed_pow_records_pruned: usize,
    pub active_quarantined_subnets: usize,
    pub active_pow_records: usize,
    #[serde(default)]
    pub threat_candidates_pruned: usize,
    #[serde(default)]
    pub active_threat_candidates: usize,
    pub timestamp_ms: u64,
}

/// Autonomous Hygiene Manager coordinating multi-engine state pruning
#[derive(Debug, Clone)]
pub struct MaintenanceManager {
    quarantine: AutonomousQuarantine,
    adaptive_pow: AdaptivePowEngine,
    threat_harvester: Option<crate::threat_harvester::ThreatHarvesterEngine>,
}

impl MaintenanceManager {
    pub fn new(quarantine: AutonomousQuarantine, adaptive_pow: AdaptivePowEngine) -> Self {
        Self {
            quarantine,
            adaptive_pow,
            threat_harvester: None,
        }
    }

    /// Attach a ThreatHarvesterEngine to coordinate candidate pruning
    pub fn with_threat_harvester(
        mut self,
        harvester: crate::threat_harvester::ThreatHarvesterEngine,
    ) -> Self {
        self.threat_harvester = Some(harvester);
        self
    }

    /// Execute a synchronous hygiene pass across all tracked defense stores
    pub fn run_maintenance(&self, now_ms: u64) -> MaintenanceReport {
        let quarantined_subnets_pruned = self.quarantine.purge_expired(now_ms);
        let decayed_pow_records_pruned = self.adaptive_pow.prune_decayed(now_ms);
        let (threat_candidates_pruned, active_threat_candidates) =
            if let Some(ref harvester) = self.threat_harvester {
                let pruned = harvester.prune_expired(now_ms);
                (pruned, harvester.candidate_count())
            } else {
                (0, 0)
            };

        MaintenanceReport {
            quarantined_subnets_pruned,
            decayed_pow_records_pruned,
            active_quarantined_subnets: self.quarantine.active_bans_count(),
            active_pow_records: self.adaptive_pow.tracked_ips_count(),
            threat_candidates_pruned,
            active_threat_candidates,
            timestamp_ms: now_ms,
        }
    }

    /// Spawn a persistent non-blocking background task running maintenance on a fixed schedule
    pub fn spawn_background_worker(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let mgr = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let report = mgr.run_maintenance(now_ms);
                if report.quarantined_subnets_pruned > 0
                    || report.decayed_pow_records_pruned > 0
                    || report.threat_candidates_pruned > 0
                {
                    #[cfg(feature = "abuse-reporting")]
                    tracing::info!(
                        "🧹 [PHYLAX MAINTENANCE] Pruned {} expired subnet bans, {} decayed PoW records, {} threat candidates. Active: {} subnets, {} PoW records, {} candidates",
                        report.quarantined_subnets_pruned,
                        report.decayed_pow_records_pruned,
                        report.threat_candidates_pruned,
                        report.active_quarantined_subnets,
                        report.active_pow_records,
                        report.active_threat_candidates
                    );
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive_pow::{AdaptivePowConfig, InfractionSeverity};
    use crate::autonomous_quarantine::QuarantineConfig;

    #[test]
    fn test_maintenance_manager_prunes_both_stores_and_reports() {
        let quarantine = AutonomousQuarantine::new(QuarantineConfig {
            infraction_threshold: 1,
            quarantine_duration_ms: 1000,
            max_tracked_subnets: 100,
        });
        let adaptive_pow = AdaptivePowEngine::new(AdaptivePowConfig {
            baseline_difficulty: 10,
            suspicious_difficulty: 12,
            hostile_difficulty: 14,
            severe_difficulty: 16,
            infraction_decay_ms: 1000,
        });

        // Set up initial state at t=1000
        quarantine.record_and_check("192.0.2.50", 1000);
        adaptive_pow.record_infraction("10.0.0.1", InfractionSeverity::Suspicious, 1000);
        adaptive_pow.record_infraction("10.0.0.2", InfractionSeverity::Severe, 1000);

        let manager = MaintenanceManager::new(quarantine.clone(), adaptive_pow.clone());

        // At t=1500 (nothing expired yet)
        let early_report = manager.run_maintenance(1500);
        assert_eq!(early_report.quarantined_subnets_pruned, 0);
        assert_eq!(early_report.decayed_pow_records_pruned, 0);
        assert_eq!(early_report.active_quarantined_subnets, 1);
        assert_eq!(early_report.active_pow_records, 2);

        // At t=2500 (both quarantine ban expired and 10.0.0.1 decayed to baseline)
        let post_report = manager.run_maintenance(2500);
        assert_eq!(post_report.quarantined_subnets_pruned, 1);
        assert_eq!(post_report.decayed_pow_records_pruned, 1);
        assert_eq!(post_report.active_quarantined_subnets, 0);
        assert_eq!(post_report.active_pow_records, 1); // 10.0.0.2 still active
    }

    #[tokio::test]
    async fn test_maintenance_manager_background_worker() {
        let quarantine = AutonomousQuarantine::new(QuarantineConfig {
            infraction_threshold: 1,
            quarantine_duration_ms: 50,
            max_tracked_subnets: 100,
        });
        let adaptive_pow = AdaptivePowEngine::new(AdaptivePowConfig {
            baseline_difficulty: 10,
            suspicious_difficulty: 12,
            hostile_difficulty: 14,
            severe_difficulty: 16,
            infraction_decay_ms: 50,
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        quarantine.record_and_check("1.2.3.4", now);
        adaptive_pow.record_infraction("5.6.7.8", InfractionSeverity::Suspicious, now);

        let manager = MaintenanceManager::new(quarantine.clone(), adaptive_pow.clone());
        let handle = manager.spawn_background_worker(Duration::from_millis(20));

        // Wait enough for expiry and background tick
        tokio::time::sleep(Duration::from_millis(120)).await;

        assert_eq!(quarantine.active_bans_count(), 0);
        assert_eq!(adaptive_pow.tracked_ips_count(), 0);

        handle.abort();
    }
}
