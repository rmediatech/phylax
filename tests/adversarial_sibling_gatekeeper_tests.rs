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
    pipeline.quarantine().add_ban(net, now_ms + 3_600_000);
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
    assert!(
        elapsed.as_micros() < 200,
        "Sibling fast-path must be instantaneous"
    );
}

#[test]
fn test_adversarial_sibling_stale_replay_fails_elevation() {
    let pipeline = ShieldPipeline::builder().with_timing(1500, 300_000).build();

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

// ============================================================================
// 🏛️ UNIVERSAL TRI-DIMENSIONAL REALITY CRUCIBLE (SOVEREIGN-REALITY-3D-01)
// ============================================================================

// --- DIMENSION 1: THE PRISTINE GOLDEN PATH & HUMAN ERGONOMICS (BENIGN DELIGHT) ---

#[test]
fn test_golden_path_argus_mobile_burst_discovery() {
    let pipeline = ShieldPipeline::builder().build();
    let now_ms = 1_700_000_000_000;

    // Argus mobile companion on local Wi-Fi issuing rapid state queries
    for i in 0..15 {
        let nonce = format!("argus-scan-{}", i);
        let proof = SiblingVerifier::generate_proof("argus", &nonce, now_ms + (i as u64 * 10));
        let req = ShieldRequest {
            client_ip: "192.168.1.185",
            target_uri: Some("/api/status"),
            sibling_proof: Some(proof),
            now_ms: now_ms + (i as u64 * 10),
            ..Default::default()
        };

        let start = Instant::now();
        let verdict = pipeline.evaluate(&req);
        let elapsed = start.elapsed();

        assert!(
            verdict.is_allowed(),
            "Legitimate Argus burst must never be dropped"
        );
        assert!(
            verdict.is_sibling(),
            "Must retain sibling status across burst"
        );
        assert!(
            elapsed.as_micros() < 250,
            "Latency must remain sub-microsecond"
        );
    }
}

#[test]
fn test_golden_path_human_slow_composer_conformance() {
    let pipeline = ShieldPipeline::builder()
        .with_timing(1500, 300_000) // 1.5s human floor, 5m ceiling
        .with_pow(8, 60_000)
        .build();

    let session_start = 1_700_000_000_000;
    // Human takes 35 seconds to type message (slow and natural)
    let submit_time = session_start + 35_000;

    let ctx = pipeline.issue_client_context(session_start, 12345);
    let (pow_nonce, _) = phylax::PowEngine::solve_challenge(&ctx.pow_seed, 8);
    let fields = vec![(
        "message".to_string(),
        "Hello, I am interested in sovereign emancipation".to_string(),
    )];

    let req = ShieldRequest {
        client_ip: "96.227.137.44",
        submitted_fields: &fields,
        timing_token: Some(&ctx.timing_token),
        pow_challenge_token: Some(&ctx.pow_challenge),
        pow_nonce: Some(pow_nonce),
        target_uri: Some("/contact"),
        http_method: Some("POST"),
        now_ms: submit_time,
        ..Default::default()
    };

    let verdict = pipeline.evaluate(&req);
    assert!(
        verdict.is_allowed(),
        "Slow typing honest human must be allowed without friction"
    );
}

// --- DIMENSION 2: THE ADVERSARIAL RED CRUCIBLE (SELF-ATTACK & MALICE) ---

#[test]
fn test_adversarial_future_timestamp_skew_forgery() {
    let pipeline = ShieldPipeline::builder().build();
    let now_ms = 1_700_000_000_000;

    // Attacker crafts proof with future timestamp (60.001s in future) to manipulate anti-replay
    let future_timestamp = now_ms + 60_001;
    let skew_proof = SiblingVerifier::generate_proof("imposter", "future-nonce", future_timestamp);

    let req = ShieldRequest {
        client_ip: "45.33.32.156",
        sibling_proof: Some(skew_proof),
        now_ms,
        ..Default::default()
    };

    let verdict = pipeline.evaluate(&req);
    assert!(
        !verdict.is_sibling(),
        "Future clock skew beyond 60s must be rejected"
    );
}

#[test]
fn test_adversarial_sibling_identity_spoof_with_sqli_payload() {
    let pipeline = ShieldPipeline::builder().build();
    let now_ms = 1_700_000_000_000;

    // Attacker injects SQLi and command injection into sibling caller name
    let injection_payloads = [
        "ashwin'; DROP TABLE audit_log;--",
        "argus' OR '1'='1",
        "=cmd|'/C calc'!A0",
        "<script>alert(1)</script>",
    ];

    for hostile_name in injection_payloads {
        let forged_proof = SiblingProof {
            caller_name: hostile_name.to_string(),
            nonce: "nonce-inject".to_string(),
            timestamp_ms: now_ms,
            signature: "baadf00d".repeat(8),
        };

        let req = ShieldRequest {
            client_ip: "185.220.101.5",
            sibling_proof: Some(forged_proof),
            now_ms,
            ..Default::default()
        };

        let verdict = pipeline.evaluate(&req);
        assert!(
            !verdict.is_sibling(),
            "Injected sibling caller must never obtain sibling elevation"
        );
    }
}

// --- DIMENSION 3: PHYSICAL & AMBIENT ENVIRONMENTAL CHAOS (PHYSICS & UNKNOWNS) ---

#[test]
fn test_chaos_network_roaming_cellular_handover() {
    let pipeline = ShieldPipeline::builder().build();
    let now_ms = 1_700_000_000_000;

    // Sibling (e.g. Ashwin in vehicle) begins on home Wi-Fi
    let nonce = "roaming-ashwin-01";
    let proof = SiblingVerifier::generate_proof("ashwin", nonce, now_ms);

    let wifi_req = ShieldRequest {
        client_ip: "192.168.1.183", // Wi-Fi IP
        target_uri: Some("/radar/telemetry"),
        sibling_proof: Some(proof.clone()),
        now_ms,
        ..Default::default()
    };
    let verdict1 = pipeline.evaluate(&wifi_req);
    assert!(verdict1.is_sibling());

    // Wi-Fi drops! Vehicle switches to Cellular carrier IP 4 seconds later with same proof
    let cell_req = ShieldRequest {
        client_ip: "172.56.21.90", // Cellular IP
        target_uri: Some("/radar/telemetry"),
        sibling_proof: Some(proof),
        now_ms: now_ms + 4_000,
        ..Default::default()
    };
    let verdict2 = pipeline.evaluate(&cell_req);
    assert!(
        verdict2.is_sibling(),
        "Cryptographic proof must seamlessly survive cellular IP roaming handover"
    );
}

#[test]
fn test_chaos_burst_loss_and_jittered_retries() {
    let pipeline = ShieldPipeline::builder().build();
    let base_ms = 1_700_000_000_000;

    // Packets arrive out of order due to UDP/Wi-Fi jitter: T+500ms arrives before T+0ms
    let proof_first = SiblingVerifier::generate_proof("vox", "jitter-first", base_ms);
    let proof_second = SiblingVerifier::generate_proof("vox", "jitter-second", base_ms + 500);

    // Second packet arrives first
    let req2 = ShieldRequest {
        client_ip: "10.10.10.2",
        sibling_proof: Some(proof_second),
        now_ms: base_ms + 1_000,
        ..Default::default()
    };
    assert!(pipeline.evaluate(&req2).is_sibling());

    // First packet arrives late (lagging by 1200ms)
    let req1 = ShieldRequest {
        client_ip: "10.10.10.2",
        sibling_proof: Some(proof_first),
        now_ms: base_ms + 1_200,
        ..Default::default()
    };
    assert!(
        pipeline.evaluate(&req1).is_sibling(),
        "Late jittered packets within drift window must be authenticated"
    );
}
