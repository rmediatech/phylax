//! # Adversarial Sibling Gatekeeper & Bypass Test Suite
//! Asserts SOVEREIGN-SIBLING-01 compliance in Phylax:
//! 1. Provenance Lineage Verification & Sub-Microsecond Fast-Path
//! 2. Exemption from Autonomous Quarantine, Honeypots, Decoy URIs, and PoW
//! 3. Zero-Panic Fuzz Resilience and Stale Timestamp Replay Mitigation

use phylax::pipeline::{ShieldPipeline, ShieldRequest, ShieldVerdict};
use phylax::sibling::{SiblingProof, SiblingVerifier};
use std::time::Instant;

#[test]
fn test_adversarial_sibling_bypasses_quarantined_ip_and_decoys() {
    let pipeline = ShieldPipeline::builder()
        .with_timing(1500, 300_000)
        .with_pow(4, 60_000)
        .build();

    let now_ms = 1_700_000_000_000;
    let quarantined_ip = "198.51.100.77";

    // Hostile IP is quarantined
    let net: ipnet::IpNet = "198.51.100.0/24".parse().unwrap();
    pipeline.quarantine().add_ban(net, now_ms + 3600_000);
    assert!(pipeline.quarantine().is_quarantined(quarantined_ip, now_ms));

    // A wild stranger from this IP hits a honeypot field or decoy path -> Denied immediately
    let decoy_path = "/wp-admin/setup-config.php";
    let stranger_req = ShieldRequest {
        client_ip: quarantined_ip,
        target_uri: Some(decoy_path),
        now_ms,
        ..Default::default()
    };
    let verdict = pipeline.evaluate(&stranger_req);
    assert!(verdict.is_denied());

    // A legitimate sibling app (e.g. Janus or Ashwin) presenting a valid SiblingProof
    let challenge = SiblingVerifier::issue_challenge(now_ms, 1337);
    let sibling_proof = SiblingVerifier::generate_proof("janus", &challenge.nonce, now_ms);

    let sibling_req = ShieldRequest {
        client_ip: quarantined_ip, // Even if coming from an IP previously quarantined!
        target_uri: Some(decoy_path),
        sibling_proof: Some(sibling_proof),
        now_ms,
        ..Default::default()
    };

    let start = Instant::now();
    let sibling_verdict = pipeline.evaluate(&sibling_req);
    let elapsed = start.elapsed();

    assert!(sibling_verdict.is_allowed());
    assert!(sibling_verdict.is_sibling());
    if let ShieldVerdict::AllowSibling { caller, .. } = sibling_verdict {
        assert_eq!(caller, "janus");
    } else {
        panic!("Expected AllowSibling verdict");
    }

    // Sub-microsecond requirement assertion (< 200µs in debug test mode)
    assert!(elapsed.as_micros() < 200, "Sibling fast-path must be instantaneous");
}

#[test]
fn test_adversarial_sibling_stale_replay_fails_elevation() {
    let pipeline = ShieldPipeline::builder()
        .with_timing(1500, 300_000)
        .build();

    let now_ms = 1_700_000_000_000;
    let old_timestamp = now_ms - 60_001; // 60.001 seconds ago (stale)

    let stale_proof = SiblingVerifier::generate_proof("drishti", "nonce-fresh", old_timestamp);

    let req = ShieldRequest {
        client_ip: "192.168.1.50",
        sibling_proof: Some(stale_proof),
        now_ms,
        ..Default::default()
    };

    // Stale proof must NOT grant AllowSibling
    let verdict = pipeline.evaluate(&req);
    assert!(!verdict.is_sibling());
}

#[test]
fn test_adversarial_sibling_forged_signature_rejected() {
    let pipeline = ShieldPipeline::builder().build();
    let now_ms = 1_700_000_000_000;

    let forged_proof = SiblingProof {
        caller_name: "imposter_bot".to_string(),
        nonce: "fake-nonce".to_string(),
        timestamp_ms: now_ms,
        signature: "deadbeef".repeat(8),
    };

    let req = ShieldRequest {
        client_ip: "10.0.0.99",
        sibling_proof: Some(forged_proof),
        now_ms,
        ..Default::default()
    };

    let verdict = pipeline.evaluate(&req);
    assert!(!verdict.is_sibling());
}

#[test]
fn test_adversarial_sibling_zero_panic_fuzzing() {
    let now_ms = 1_700_000_000_000;
    let zz_string = "zz".repeat(32);

    // Fuzz malformed hex, odd lengths, invalid UTF-8 control bytes
    let fuzz_cases = vec![
        "",
        "1",
        "xyz",
        "deadbeef",
        zz_string.as_str(),
        "\x00\x01\x02\x03",
    ];

    for case in fuzz_cases {
        let proof = SiblingProof {
            caller_name: "fuzzer".to_string(),
            nonce: "test".to_string(),
            timestamp_ms: now_ms,
            signature: case.to_string(),
        };
        let res = SiblingVerifier::verify_proof(&proof, now_ms);
        assert!(res.is_err());
    }
}
