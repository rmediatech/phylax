//! # Sovereign Tarpit & Active Deception Engine (TDD Unit & Integration Battery)
//!
//! Tests for:
//! 1. Tarpit connection governor, socket slot management, and decoy trickle streams.
//! 2. Adaptive PoW difficulty ratcheting and algorithmic decay.
//! 3. Autonomous CIDR quarantine expanding bad-actor IPs to /24 (IPv4) or /48 (IPv6).

use phylax::adaptive_pow::{AdaptivePowConfig, AdaptivePowEngine, InfractionSeverity};
use phylax::autonomous_quarantine::{AutonomousQuarantine, QuarantineConfig};
use phylax::tarpit::{TarpitConfig, TarpitGovernor, TarpitVerdict};

#[tokio::test]
async fn test_tarpit_governor_allocates_slots_and_tracks_metrics() {
    let config = TarpitConfig {
        trickle_interval_ms: 10,
        max_duration_s: 2,
        chunk_size: 4,
        max_concurrent_tarpits: 3,
    };
    let governor = TarpitGovernor::new(config);

    // 1. Allocate up to concurrency limit of 3
    let slot1 = governor.acquire_slot("198.51.100.1");
    assert!(matches!(slot1, TarpitVerdict::Engage { .. }));

    let slot2 = governor.acquire_slot("198.51.100.2");
    assert!(matches!(slot2, TarpitVerdict::Engage { .. }));

    let slot3 = governor.acquire_slot("198.51.100.3");
    assert!(matches!(slot3, TarpitVerdict::Engage { .. }));

    assert_eq!(governor.active_tarpits_count(), 3);

    // 2. 4th attempt exceeds ceiling -> fail-safe drop to prevent FD exhaustion
    let slot4 = governor.acquire_slot("198.51.100.4");
    assert_eq!(slot4, TarpitVerdict::CeilingExceededDrop);

    // 3. Complete slot 1 and verify slot reclamation and metric updates
    if let TarpitVerdict::Engage { slot_guard } = slot1 {
        drop(slot_guard); // Simulates stream completion or client disconnect
    }

    assert_eq!(governor.active_tarpits_count(), 2);
    assert_eq!(governor.total_tarpitted_count(), 3);

    // 4. Now slot can be re-acquired
    let slot4_retry = governor.acquire_slot("198.51.100.4");
    assert!(matches!(slot4_retry, TarpitVerdict::Engage { .. }));
    assert_eq!(governor.active_tarpits_count(), 3);
}

#[tokio::test]
async fn test_tarpit_decoy_payload_stream_chunking() {
    let config = TarpitConfig {
        trickle_interval_ms: 5,
        max_duration_s: 1,
        chunk_size: 8,
        max_concurrent_tarpits: 10,
    };
    let governor = TarpitGovernor::new(config);

    // Generate stream chunks
    let chunk0 = governor.generate_decoy_chunk(0);
    assert!(chunk0.starts_with(b"<!DOCTYPE html>"));

    let chunk1 = governor.generate_decoy_chunk(1);
    assert!(!chunk1.is_empty());
    assert!(chunk1.starts_with(b"<!-- chunk_0001:"));
}

#[test]
fn test_adaptive_pow_difficulty_ratcheting_and_decay() {
    let config = AdaptivePowConfig {
        baseline_difficulty: 12,
        suspicious_difficulty: 15,
        hostile_difficulty: 18,
        severe_difficulty: 22,
        infraction_decay_ms: 60_000, // 1 minute decay
    };
    let engine = AdaptivePowEngine::new(config);
    let ip = "185.34.33.2";
    let now = 1_000_000;

    // 1. Pristine IP gets baseline difficulty
    assert_eq!(engine.get_difficulty(ip, now), 12);

    // 2. Minor infraction (e.g. failed login) ratchets to suspicious
    engine.record_infraction(ip, InfractionSeverity::Suspicious, now);
    assert_eq!(engine.get_difficulty(ip, now), 15);

    // 3. Repeated / hostile infraction ratchets to hostile
    engine.record_infraction(ip, InfractionSeverity::Hostile, now + 100);
    assert_eq!(engine.get_difficulty(ip, now + 100), 18);

    // 4. Severe infraction (tripped honeypot / bot swarm) ratchets to severe (22 bits)
    engine.record_infraction(ip, InfractionSeverity::Severe, now + 200);
    assert_eq!(engine.get_difficulty(ip, now + 200), 22);

    // 5. Verified decay: After 60s of calm, difficulty decays down
    let decayed_once = engine.get_difficulty(ip, now + 65_000);
    assert!(decayed_once < 22);
    assert!(decayed_once >= 12);

    // 6. After 180s (3 half-lives), decays fully back to baseline
    let fully_decayed = engine.get_difficulty(ip, now + 200_000);
    assert_eq!(fully_decayed, 12);
}

#[test]
fn test_autonomous_quarantine_auto_subnets_ipv4_and_ipv6() {
    let config = QuarantineConfig {
        infraction_threshold: 3,
        quarantine_duration_ms: 3_600_000, // 1 hour
        max_tracked_subnets: 1000,
    };
    let quarantine = AutonomousQuarantine::new(config);
    let now = 1_700_000_000_000;

    // 1. Subnet CIDR derivation
    assert_eq!(
        AutonomousQuarantine::derive_quarantine_cidr("185.34.33.2"),
        Some("185.34.33.0/24".to_string())
    );
    assert_eq!(
        AutonomousQuarantine::derive_quarantine_cidr("192.0.2.55"),
        Some("192.0.2.0/24".to_string())
    );
    assert_eq!(
        AutonomousQuarantine::derive_quarantine_cidr("2001:db8:85a3::8a2e:370:7334"),
        Some("2001:db8:85a3::/48".to_string())
    );

    // 2. Infractions below threshold do not quarantine
    let ip = "185.34.33.2";
    assert!(!quarantine.record_and_check(ip, now));
    assert!(!quarantine.is_quarantined(ip, now));

    assert!(!quarantine.record_and_check(ip, now + 500));
    assert!(!quarantine.is_quarantined(ip, now + 500));

    // 3. 3rd infraction triggers autonomous quarantine!
    let triggered = quarantine.record_and_check(ip, now + 1000);
    assert!(triggered);
    assert!(quarantine.is_quarantined(ip, now + 1000));

    // 4. Sister IP in the same /24 is also automatically quarantined!
    let sister_ip = "185.34.33.200";
    assert!(quarantine.is_quarantined(sister_ip, now + 1000));

    // 5. Unrelated IP in different subnet is NOT quarantined
    assert!(!quarantine.is_quarantined("198.51.100.4", now + 1000));

    // 6. TTL expiration: after 1 hour (3600s + 1.5s offset), quarantine naturally expires
    assert!(!quarantine.is_quarantined(ip, now + 3_601_500));
    assert!(!quarantine.is_quarantined(sister_ip, now + 3_601_500));
}
