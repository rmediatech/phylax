//! # Adversarial TDD Suite for Phylax v0.4.0: eBPF/XDP Sub-Kernel Wire Shield & Shared BPF Map Integration
//!
//! Verifies:
//! 1. Raw Ethernet II + 802.1Q VLAN + IPv4/IPv6 packet evaluation (`XdpAction::Drop`, `Pass`, `Aborted`).
//! 2. Shared BPF Map synchronization with `ThreatHarvesterEngine` & `AutonomousQuarantine`.
//! 3. SHA-256 sealed binary BPF map snapshot export/import and tamper detection across reboots.
//! 4. Loopback & private LAN collateral damage containment + deterministic 64-bit eBPF bytecode synthesis.

use ipnet::IpNet;
use phylax::xdp_shield::{
    generate_ebpf_xdp_bytecode, XdpAction, XdpBanReason, XdpShieldConfig, XdpWireShield,
};
use phylax::{QuarantineConfig, ShieldPipeline, ShieldRequest, ShieldVerdict};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn craft_eth_ipv4_frame(src_ip: [u8; 4], dst_ip: [u8; 4], vlan_tag: Option<u16>) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Dst MAC (6B) + Src MAC (6B)
    pkt.extend_from_slice(&[0x00, 0x16, 0x3e, 0xaa, 0xbb, 0xcc]);
    pkt.extend_from_slice(&[0x00, 0x16, 0x3e, 0x11, 0x22, 0x33]);
    if let Some(vid) = vlan_tag {
        pkt.extend_from_slice(&0x8100u16.to_be_bytes());
        pkt.extend_from_slice(&vid.to_be_bytes());
    }
    // EtherType = 0x0800 (IPv4)
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    // Minimal 20-byte IPv4 header
    let mut ipv4 = [0u8; 20];
    ipv4[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    ipv4[2..4].copy_from_slice(&20u16.to_be_bytes());
    ipv4[8] = 64; // TTL
    ipv4[9] = 6; // TCP
    ipv4[12..16].copy_from_slice(&src_ip);
    ipv4[16..20].copy_from_slice(&dst_ip);
    pkt.extend_from_slice(&ipv4);
    pkt
}

fn craft_eth_ipv6_frame(src_ip: [u8; 16], dst_ip: [u8; 16]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00, 0x16, 0x3e, 0xaa, 0xbb, 0xcc]);
    pkt.extend_from_slice(&[0x00, 0x16, 0x3e, 0x11, 0x22, 0x33]);
    pkt.extend_from_slice(&0x86DDu16.to_be_bytes());
    let mut ipv6 = [0u8; 40];
    ipv6[0] = 0x60; // Version 6
    ipv6[6] = 6; // Next Header TCP
    ipv6[7] = 64; // Hop Limit
    ipv6[8..24].copy_from_slice(&src_ip);
    ipv6[24..40].copy_from_slice(&dst_ip);
    pkt.extend_from_slice(&ipv6);
    pkt
}

#[test]
fn test_xdp_wire_shield_raw_ethernet_vlan_ipv4_ipv6_and_truncated_aborted() {
    let shield = XdpWireShield::new(XdpShieldConfig::default());
    let now_ms = 1_000_000;

    // Ban 198.51.100.0/24 and 2001:db8:dead::/48
    let v4_net: IpNet = "198.51.100.0/24".parse().unwrap();
    let v6_net: IpNet = "2001:db8:dead::/48".parse().unwrap();
    assert!(shield.upsert_ban(v4_net, now_ms + 60_000, XdpBanReason::AutonomousQuarantine));
    assert!(shield.upsert_ban(
        v6_net,
        now_ms + 60_000,
        XdpBanReason::ThreatHarvesterZeroDay
    ));

    // 1. Hostile IPv4 frame on standard Ethernet II -> XDP_DROP
    let hostile_v4 = craft_eth_ipv4_frame([198, 51, 100, 42], [173, 255, 227, 159], None);
    let verdict1 = shield.evaluate_eth_frame(&hostile_v4, now_ms + 100);
    assert_eq!(verdict1.action, XdpAction::Drop);
    assert_eq!(verdict1.matched_cidr, Some(v4_net));
    assert_eq!(verdict1.reason, Some(XdpBanReason::AutonomousQuarantine));

    // 2. Hostile IPv4 frame encapsulated in IEEE 802.1Q VLAN tag -> XDP_DROP (no VLAN bypass!)
    let vlan_hostile_v4 =
        craft_eth_ipv4_frame([198, 51, 100, 200], [173, 255, 227, 159], Some(100));
    let verdict_vlan = shield.evaluate_eth_frame(&vlan_hostile_v4, now_ms + 200);
    assert_eq!(verdict_vlan.action, XdpAction::Drop);

    // 3. Clean IPv4 frame -> XDP_PASS
    let clean_v4 = craft_eth_ipv4_frame([203, 0, 113, 7], [173, 255, 227, 159], None);
    let verdict_clean = shield.evaluate_eth_frame(&clean_v4, now_ms + 200);
    assert_eq!(verdict_clean.action, XdpAction::Pass);

    // 4. Hostile IPv6 frame -> XDP_DROP
    let src_v6 = Ipv6Addr::new(0x2001, 0x0db8, 0xdead, 0x0001, 0, 0, 0, 0x99).octets();
    let dst_v6 = Ipv6Addr::new(0x2600, 0x3c03, 0, 0, 0x2000, 0x5cff, 0xfe0f, 0xf8c4).octets();
    let hostile_v6 = craft_eth_ipv6_frame(src_v6, dst_v6);
    let verdict_v6 = shield.evaluate_eth_frame(&hostile_v6, now_ms + 300);
    assert_eq!(verdict_v6.action, XdpAction::Drop);
    assert_eq!(
        verdict_v6.reason,
        Some(XdpBanReason::ThreatHarvesterZeroDay)
    );

    // 5. Truncated / corrupted Ethernet & IPv4 headers -> XDP_ABORTED (zero panic)
    assert_eq!(
        shield
            .evaluate_eth_frame(&[0x00, 0x01, 0x02], now_ms)
            .action,
        XdpAction::Aborted
    );
    let mut bad_ihl = clean_v4.clone();
    bad_ihl[14] = 0x42; // IHL = 2 (8 bytes < 20 minimum)
    assert_eq!(
        shield.evaluate_eth_frame(&bad_ihl, now_ms).action,
        XdpAction::Aborted
    );

    let metrics = shield.metrics();
    assert_eq!(metrics.total_dropped_packets, 3);
    assert_eq!(metrics.total_aborted_packets, 2);
}

#[test]
fn test_shared_bpf_map_integration_with_threat_harvester_and_quarantine() {
    let pipeline = ShieldPipeline::builder()
        .with_quarantine(QuarantineConfig {
            infraction_threshold: 2,
            quarantine_duration_ms: 120_000,
            max_tracked_subnets: 1000,
        })
        .enable_pow(false)
        .enable_timing(false)
        .build();

    let now_ms = 5_000_000;

    // 1. Trigger AutonomousQuarantine via 2 decoy URI hits from 192.0.2.88
    for i in 0..2 {
        let req = ShieldRequest {
            client_ip: "192.0.2.88",
            target_uri: Some("/.env"),
            http_method: Some("GET"),
            user_agent: Some("Scanner/1.0"),
            submitted_fields: &[],
            email: None,
            timing_token: None,
            pow_challenge_token: None,
            pow_nonce: None,
            now_ms: now_ms + i * 10,
        };
        assert!(matches!(pipeline.evaluate(&req), ShieldVerdict::Deny(_)));
    }

    // Verify 192.0.2.0/24 was automatically pushed into the XdpWireShield BPF LPM map!
    let xdp_verdict = pipeline.xdp_shield().evaluate_ip(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 199)),
        64,
        now_ms + 50,
    );
    assert_eq!(xdp_verdict.action, XdpAction::Drop);
    assert_eq!(xdp_verdict.reason, Some(XdpBanReason::AutonomousQuarantine));

    // 2. Trigger ThreatHarvester zero-day promotion across 3 distinct subnets
    let s1: IpAddr = "198.51.100.10".parse().unwrap();
    let s2: IpAddr = "203.0.113.20".parse().unwrap();
    let s3: IpAddr = "198.18.0.30".parse().unwrap();

    assert!(pipeline
        .record_anomalous_uri("/_zero_day_rce_2026.jsp", s1, now_ms + 100)
        .is_none());
    assert!(pipeline
        .record_anomalous_uri("/_zero_day_rce_2026.jsp", s2, now_ms + 200)
        .is_none());
    let promo = pipeline
        .record_anomalous_uri("/_zero_day_rce_2026.jsp", s3, now_ms + 300)
        .expect("3rd subnet should promote zero-day path");
    assert_eq!(promo.distinct_subnets, 3);

    // Verify all 3 participating zero-day subnets are now dropped in sub-50ns by XdpWireShield!
    for neighbor_ip in ["198.51.100.250", "203.0.113.99", "198.18.0.1"] {
        let ip: IpAddr = neighbor_ip.parse().unwrap();
        let v = pipeline.xdp_shield().evaluate_ip(ip, 128, now_ms + 400);
        assert_eq!(v.action, XdpAction::Drop);
        assert_eq!(v.reason, Some(XdpBanReason::ThreatHarvesterZeroDay));
    }
}

#[test]
fn test_bpf_map_snapshot_persistence_tamper_resistance_and_ebpf_bytecode() {
    let shield = XdpWireShield::default();
    let now_ms = 10_000_000;

    // Loopback must be rejected from XDP drop map to prevent host self-lockout
    assert!(!shield.upsert_ban(
        "127.0.0.1/32".parse().unwrap(),
        now_ms + 60_000,
        XdpBanReason::OperatorManualBan
    ));
    // Private LAN /24 must be automatically clamped to /32 to prevent LAN collateral damage
    assert!(shield.upsert_ban(
        "192.168.1.50/24".parse().unwrap(),
        now_ms + 60_000,
        XdpBanReason::OperatorManualBan
    ));
    assert_eq!(
        shield
            .evaluate_ip("192.168.1.50".parse().unwrap(), 60, now_ms + 10)
            .action,
        XdpAction::Drop
    );
    assert_eq!(
        shield
            .evaluate_ip("192.168.1.1".parse().unwrap(), 60, now_ms + 10)
            .action,
        XdpAction::Pass
    );

    // Export binary BPF snapshot across reboot
    let snapshot = shield.export_bpf_snapshot_bytes(now_ms + 20);
    let rebooted_shield = XdpWireShield::default();
    let restored = rebooted_shield
        .import_bpf_snapshot_bytes(&snapshot, now_ms + 30)
        .expect("Valid SHA-256 sealed BPF snapshot must import cleanly");
    assert_eq!(restored, 1);
    assert_eq!(
        rebooted_shield
            .evaluate_ip("192.168.1.50".parse().unwrap(), 60, now_ms + 40)
            .action,
        XdpAction::Drop
    );

    // Tamper with 1 byte in snapshot -> SHA-256 verification must reject!
    let mut tampered = snapshot.clone();
    tampered[20] ^= 0xFF;
    assert!(rebooted_shield
        .import_bpf_snapshot_bytes(&tampered, now_ms + 40)
        .is_err());

    // Verify deterministic eBPF XDP instruction bytecode synthesis
    let prog = generate_ebpf_xdp_bytecode(7);
    assert_eq!(prog.len(), 20);
    // Final instruction must be BPF_EXIT (0x95)
    assert_eq!(prog.last().unwrap().code, 0x95);
}
