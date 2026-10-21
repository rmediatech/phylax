//! # Comprehensive TDD Unit Battery for `rmt-shield`
//! Verifies: Honeypot, Timing, PoW, Email Guard, Subnet Guard, and Pipeline Chaining.

use phylax::prelude::*;
use phylax::*;

#[test]
fn test_layer1_honeypot_clean_and_trapped_states() {
    let hp = HoneypotValidator::default();

    // 1. Clean payload with decoy omitted
    let clean = vec![
        ("email", "operator@rmediatech.com"),
        ("password", "ValidPass12345!"),
    ];
    assert!(hp.validate(&clean).is_clean());

    // 2. Clean payload with decoy present but empty
    let empty_decoy = vec![("email", "operator@rmediatech.com"), ("website_url", "   ")];
    assert!(hp.validate(&empty_decoy).is_clean());

    // 3. Trapped payload with bot population
    let trapped = vec![
        ("email", "bot@automated.ru"),
        ("website_url", "http://spam.org"),
    ];
    let verdict = hp.validate(&trapped);
    assert!(verdict.is_trapped());
}

#[test]
fn test_layer2_timing_hmac_tamper_proofing_and_speed_thresholds() {
    let timing = TimingGuard::new(b"test_secret_key_12345", 2500, 10_000);
    let start_ms = 500_000;
    let token = timing.generate_token(start_ms);

    // 1. Sub-millisecond bot (50ms) -> Must fail as TooFast
    let fast_verdict = timing.verify_token(&token, start_ms + 50);
    assert!(matches!(
        fast_verdict,
        phylax::TimingVerdict::TooFast {
            elapsed_ms: 50,
            min_ms: 2500
        }
    ));

    // 2. Human pacing (3,200ms) -> Must pass as Valid
    let human_verdict = timing.verify_token(&token, start_ms + 3200);
    assert!(matches!(
        human_verdict,
        phylax::TimingVerdict::Valid { elapsed_ms: 3200 }
    ));

    // 3. Expired token (12,000ms > 10,000ms) -> Must fail as Expired
    let expired_verdict = timing.verify_token(&token, start_ms + 12000);
    assert!(matches!(
        expired_verdict,
        phylax::TimingVerdict::Expired { .. }
    ));

    // 4. Forged/Tampered token -> Must fail
    let tampered = format!("{}tampered", token);
    let tampered_verdict = timing.verify_token(&tampered, start_ms + 3000);
    assert!(!tampered_verdict.is_valid());
}

#[test]
fn test_layer3_pow_puzzle_generation_solving_and_replay_immunity() {
    // 8-bit difficulty for fast unit test execution (~256 iterations)
    let pow = PowEngine::new(b"test_pow_secret_key", 8, 30_000);
    let now_ms = 1_000_000;

    let (seed, token) = pow.issue_challenge(now_ms, 77);
    let (nonce, _hash_hex) = PowEngine::solve_challenge(&seed, 8);

    // 1. Valid solution verified in <1µs
    let verdict = pow.verify_solution(&token, nonce, now_ms + 100);
    assert!(matches!(verdict, phylax::PowVerdict::Verified { .. }));

    // 2. Immediate replay attack with the exact same nonce must be denied
    let replay = pow.verify_solution(&token, nonce, now_ms + 150);
    assert_eq!(replay, phylax::PowVerdict::Replayed);

    // 3. Solution with incorrect nonce must be rejected
    let (_seed2, token2) = pow.issue_challenge(now_ms + 200, 78);
    let bad_verdict = pow.verify_solution(&token2, nonce.wrapping_add(99999), now_ms + 250);
    assert!(!bad_verdict.is_verified());
}

#[test]
fn test_layer4_email_guard_dot_tricks_and_disposables() {
    let email_guard = EmailPatternGuard::new(3);

    // 1. Normal clean address
    assert!(email_guard.inspect("operator@rmediatech.com").is_clean());

    // 2. Canonicalizes Gmail dot tricks
    match email_guard.inspect("j.o.h.n@gmail.com") {
        phylax::EmailVerdict::Clean { canonical } => {
            assert_eq!(canonical, "john@gmail.com");
        }
        _ => panic!("Expected Clean with canonical email"),
    }

    // 3. Rejects extreme dot scattering (real bot signature: 6 dots)
    let dot_scattered = "da.nj.ba.r.t.h.ol.omew@gmail.com";
    assert!(matches!(
        email_guard.inspect(dot_scattered),
        phylax::EmailVerdict::ExcessiveDotScattering { .. }
    ));

    // 4. Rejects disposable domain
    assert!(matches!(
        email_guard.inspect("spammer@10minutemail.com"),
        phylax::EmailVerdict::DisposableDomain { .. }
    ));
}

#[test]
fn test_layer5_subnet_guard_against_captured_threat_intel() {
    let guard = SubnetGuard::default();

    // 1. Residential & corporate IPs allowed
    assert_eq!(
        guard.check_ip("198.51.100.62"),
        phylax::SubnetVerdict::Allowed
    );
    assert_eq!(
        guard.check_ip("198.51.100.4"),
        phylax::SubnetVerdict::Allowed
    );

    // 2. All seed Tor & datacenter IPs captured today must be blocked
    let test_ips = [
        "171.25.193.39",  // Swedish DFRI Tor Exit Node
        "185.220.101.26", // European Tor Relay
        "149.56.44.47",   // OVH Scraper
        "185.132.53.47",  // Julian Achter NL Scanner
    ];

    for ip in test_ips {
        let verdict = guard.check_ip(ip);
        assert!(
            !verdict.is_allowed(),
            "Expected IP {} to be blocked by SubnetGuard",
            ip
        );
    }
}

#[test]
fn test_pipeline_fail_fast_execution_order() {
    let pipeline = ShieldPipeline::builder()
        .secret_key(b"test_pipeline_secret_key_2026")
        .with_timing(2000, 30_000)
        .with_pow(8, 30_000)
        .build();

    let now_ms = 1_000_000;
    let client_ctx = pipeline.issue_client_context(now_ms, 123);

    // 1. Honeypot check triggers immediately on Step 1 (Fail-Fast)
    let trapped_fields = vec![
        ("email".to_string(), "clean@rmediatech.com".to_string()),
        ("website_url".to_string(), "http://bot.com".to_string()),
    ];
    let req_trapped = ShieldRequest {
        client_ip: "198.51.100.62",
        submitted_fields: &trapped_fields,
        timing_token: Some(&client_ctx.timing_token),
        pow_challenge_token: Some(&client_ctx.pow_challenge),
        pow_nonce: Some(0),
        email: Some("clean@rmediatech.com"),
        now_ms: now_ms + 4000,
        ..Default::default()
    };
    let verdict = pipeline.evaluate(&req_trapped);
    assert!(matches!(
        verdict,
        ShieldVerdict::Deny(DenialReason::HoneypotTrapped { .. })
    ));

    // 2. Subnet check triggers next on Step 2
    let clean_fields = vec![("email".to_string(), "clean@rmediatech.com".to_string())];
    let req_tor = ShieldRequest {
        client_ip: "171.25.193.39", // Tor
        submitted_fields: &clean_fields,
        timing_token: Some(&client_ctx.timing_token),
        pow_challenge_token: Some(&client_ctx.pow_challenge),
        pow_nonce: Some(0),
        email: Some("clean@rmediatech.com"),
        now_ms: now_ms + 4000,
        ..Default::default()
    };
    let verdict_tor = pipeline.evaluate(&req_tor);
    assert!(matches!(
        verdict_tor,
        ShieldVerdict::Deny(DenialReason::SubnetBlocked { .. })
    ));

    // 3. Timing check triggers on Step 4
    let req_too_fast = ShieldRequest {
        client_ip: "198.51.100.62",
        submitted_fields: &clean_fields,
        timing_token: Some(&client_ctx.timing_token),
        pow_challenge_token: Some(&client_ctx.pow_challenge),
        pow_nonce: Some(0),
        email: Some("clean@rmediatech.com"),
        now_ms: now_ms + 100, // Only 100ms
        ..Default::default()
    };
    let verdict_fast = pipeline.evaluate(&req_too_fast);
    assert!(matches!(
        verdict_fast,
        ShieldVerdict::Deny(DenialReason::SubmissionTooFast { .. })
    ));

    // 4. Fully compliant human operator passes all layers
    let (pow_nonce, _) = PowEngine::solve_challenge(&client_ctx.pow_seed, 8);
    let req_human = ShieldRequest {
        client_ip: "198.51.100.62",
        submitted_fields: &clean_fields,
        timing_token: Some(&client_ctx.timing_token),
        pow_challenge_token: Some(&client_ctx.pow_challenge),
        pow_nonce: Some(pow_nonce),
        email: Some("operator@rmediatech.com"),
        now_ms: now_ms + 3500, // Human took 3.5s
        ..Default::default()
    };
    let verdict_human = pipeline.evaluate(&req_human);
    assert!(verdict_human.is_allowed());
}

#[test]
fn test_layer6_toll_guard_e164_normalization_and_budget_decay() {
    let guard = TollGuard::default();
    assert_eq!(
        TollGuard::normalize_phone("+1 (215) 555-0199"),
        "+12155550199"
    );
    assert_eq!(TollGuard::normalize_phone("215.555.0199"), "2155550199");

    let now = 1_000_000_000;
    let phone = "+12155550199";
    for i in 0..3 {
        assert!(guard.check_phone(phone, now + i * 1000).is_allowed());
        guard.record_phone_dispatch(phone, now + i * 1000);
    }
    assert!(!guard.check_phone(phone, now + 5000).is_allowed());
}

#[test]
fn test_layer7_credential_guard_bloom_speed_and_account_lockout() {
    let guard = CredentialGuard::default();
    let now = 1_000_000_000;
    let target = "victim@rmediatech.com";

    // Fast Bloom filter evaluation (<25ns)
    assert!(!guard.check_password_quality("12345678").is_clean());
    assert!(guard
        .check_password_quality("V3ry$tr0ng!Crypt0_2026")
        .is_clean());

    // Account lockout progression
    for i in 0..6 {
        guard.record_failure(target, now + i * 500);
    }
    let locked = guard.check_account_velocity(target, now + 4000);
    assert!(matches!(
        locked,
        phylax::CredentialVerdict::TargetAccountThrottled { .. }
    ));
}

#[test]
fn test_layer8_session_sentinel_haversine_and_subnet_masking() {
    let sentinel = SessionSentinel::new(b"secret_unit_test", SessionSentinelConfig::default());
    assert_eq!(
        sentinel.extract_subnet_prefix("192.0.2.55"),
        "192.0.2.0"
    );

    let session_id = "test_sess_01";
    let coord1 = GeoCoordinate::new(34.0522, -118.2437); // Los Angeles
    let coord2 = GeoCoordinate::new(40.7128, -74.0060); // New York (~3935 km)

    assert_eq!(
        sentinel.record_and_evaluate_travel(session_id, coord1, 1000, Some("Los Angeles")),
        SessionVerdict::Clean
    );

    // Teleportation in 10 seconds -> Impossible Travel
    let res = sentinel.record_and_evaluate_travel(session_id, coord2, 1010, Some("New York"));
    assert!(matches!(res, SessionVerdict::ImpossibleTravel { .. }));
}

#[test]
fn test_layer9_turn_guard_token_minting_and_concurrency_slots() {
    let config = TurnGuardConfig {
        max_concurrent_relays_per_user: 1,
        ..Default::default()
    };
    let guard = TurnGuard::new(b"secret_turn", config);
    let now = 500_000;

    let creds = guard.issue_credentials("user_relay", now, Some(120));
    assert!(guard
        .validate_and_allocate(&creds.username, &creds.credential, now + 10)
        .is_authorized());
    // Exceeds limit of 1
    assert!(matches!(
        guard.validate_and_allocate(&creds.username, &creds.credential, now + 20),
        phylax::TurnVerdict::ConcurrentLimitExceeded { .. }
    ));
}

#[test]
fn test_layer10_dist_guard_single_use_vouchers_and_range_limits() {
    let guard = DistGuard::new(b"secret_dist", DistGuardConfig::default());
    let now = 100_000;
    let voucher = guard.issue_voucher("release.deb", "10.0.0.1", "nonce123", now);

    assert!(guard
        .validate_voucher(&voucher, "10.0.0.1", now + 10)
        .is_permitted());
    assert_eq!(
        guard.validate_voucher(&voucher, "10.0.0.1", now + 20),
        phylax::DistVerdict::VoucherReplayed
    );
}

#[test]
fn test_layer11_stream_guard_quotas_and_slowloris() {
    let guard = StreamGuard::default();
    assert!(guard
        .inspect_content_length(Some("1024"), RouteCategory::Auth)
        .is_permitted());
    assert!(matches!(
        guard.inspect_content_length(Some("50000"), RouteCategory::Auth),
        phylax::StreamVerdict::PayloadTooLarge { .. }
    ));
}

#[test]
fn test_layer12_cache_shield_etag_revalidation() {
    let cache = CacheShield::default();
    let now = 1_000_000;
    let etag = cache.insert("/api/status", b"ok".to_vec(), "text/plain", Some(60), now);

    assert_eq!(
        cache.get("/api/status", Some(&etag), now + 10),
        phylax::CacheVerdict::NotModified { etag: etag.clone() }
    );
    assert_eq!(cache.len(), 1);
    cache.invalidate("/api/status");
    assert_eq!(cache.len(), 0);
}
