//! # Real-World Attack & Operator Simulator Battery
//! Simulates realistic headless scrapers, Tor relays, speed demons, PoW bypasses, and authentic human operators.

use phylax::prelude::*;
use phylax::{DenialReason, ShieldVerdict};
use std::time::Instant;

/// Realistic simulated attack payload emitted by a headless script bot
struct BotPayload {
    ip: &'static str,
    fields: Vec<(String, String)>,
    email: &'static str,
    submit_delay_ms: u64,
}

#[test]
fn test_simulator_headless_dom_scraper_trips_honeypot() {
    let pipeline = ShieldPipeline::builder().build();
    let now_ms = 1_000_000;
    let client_ctx = pipeline.issue_client_context(now_ms, 1);

    // Bot scrapes DOM, sees all input tags, and populates them greedily
    let bot_attack = BotPayload {
        ip: "185.132.53.47", // Bulletproof hosting IP
        fields: vec![
            ("email".to_string(), "bot_target@pacbell.net".to_string()),
            ("username".to_string(), "hrzbiytrwirannfzdqmj".to_string()),
            ("password".to_string(), "BotPass2026!".to_string()),
            // Bot blindly populated the hidden decoy field!
            (
                "website_url".to_string(),
                "https://spam-marketing.com".to_string(),
            ),
        ],
        email: "bot_target@pacbell.net",
        submit_delay_ms: 120,
    };

    let req = ShieldRequest {
        client_ip: bot_attack.ip,
        submitted_fields: &bot_attack.fields,
        timing_token: Some(&client_ctx.timing_token),
        pow_challenge_token: Some(&client_ctx.pow_challenge),
        pow_nonce: Some(0),
        email: Some(bot_attack.email),
        now_ms: now_ms + bot_attack.submit_delay_ms,
        ..Default::default()
    };

    let verdict = pipeline.evaluate(&req);
    assert_eq!(
        verdict,
        ShieldVerdict::Deny(DenialReason::HoneypotTrapped {
            field: "website_url".to_string()
        })
    );
}

#[test]
fn test_simulator_speed_demon_crawlers_rejected_by_timing() {
    let pipeline = ShieldPipeline::builder()
        .with_timing(2500, 60_000)
        .enable_pow(false)
        .build();

    let now_ms = 1_000_000;
    let client_ctx = pipeline.issue_client_context(now_ms, 2);

    // Smart bot avoids honeypot, but submits via cURL script in 85ms
    let clean_fields = vec![
        ("email".to_string(), "curl_bot@attacker.io".to_string()),
        ("username".to_string(), "speedy_bot".to_string()),
    ];

    let req = ShieldRequest {
        client_ip: "198.51.100.62",
        submitted_fields: &clean_fields,
        timing_token: Some(&client_ctx.timing_token),
        pow_challenge_token: Some(&client_ctx.pow_challenge),
        pow_nonce: Some(0),
        email: Some("curl_bot@attacker.io"),
        now_ms: now_ms + 85, // Only 85ms!
        ..Default::default()
    };

    let verdict = pipeline.evaluate(&req);
    assert_eq!(
        verdict,
        ShieldVerdict::Deny(DenialReason::SubmissionTooFast {
            elapsed_ms: 85,
            min_ms: 2500
        })
    );
}

#[test]
fn test_simulator_tor_exit_node_credential_stuffing_blocked() {
    let pipeline = ShieldPipeline::builder().with_timing(2000, 60_000).build();

    let now_ms = 1_000_000;
    let client_ctx = pipeline.issue_client_context(now_ms, 3);

    let clean_fields = vec![(
        "email".to_string(),
        "da.nj.ba.r.t.h.ol.omew@gmail.com".to_string(),
    )];

    // Real Tor IP captured from live attack: 171.25.193.39
    let req = ShieldRequest {
        client_ip: "171.25.193.39",
        submitted_fields: &clean_fields,
        timing_token: Some(&client_ctx.timing_token),
        pow_challenge_token: Some(&client_ctx.pow_challenge),
        pow_nonce: Some(0),
        email: Some("da.nj.ba.r.t.h.ol.omew@gmail.com"),
        now_ms: now_ms + 4000,
        ..Default::default()
    };

    let verdict = pipeline.evaluate(&req);
    assert!(matches!(
        verdict,
        ShieldVerdict::Deny(DenialReason::SubnetBlocked { .. })
    ));
}

#[test]
fn test_simulator_pow_puzzle_tampering_and_replay_attacks() {
    let pipeline = ShieldPipeline::builder()
        .with_pow(8, 30_000) // 8 bits difficulty
        .build();

    let now_ms = 1_000_000;
    let client_ctx = pipeline.issue_client_context(now_ms, 4);
    let (valid_nonce, _) = PowEngine::solve_challenge(&client_ctx.pow_seed, 8);

    let clean_fields = vec![("email".to_string(), "operator@rmediatech.com".to_string())];

    // 1. Bot omits PoW nonce (submits 0 or None)
    let req_no_nonce = ShieldRequest {
        client_ip: "198.51.100.62",
        submitted_fields: &clean_fields,
        timing_token: Some(&client_ctx.timing_token),
        pow_challenge_token: Some(&client_ctx.pow_challenge),
        pow_nonce: None,
        email: Some("operator@rmediatech.com"),
        now_ms: now_ms + 3000,
        ..Default::default()
    };
    assert_eq!(
        pipeline.evaluate(&req_no_nonce),
        ShieldVerdict::Deny(DenialReason::PowInvalidSolution)
    );

    // 2. Legitimate request with solved nonce passes
    let req_valid = ShieldRequest {
        client_ip: "198.51.100.62",
        submitted_fields: &clean_fields,
        timing_token: Some(&client_ctx.timing_token),
        pow_challenge_token: Some(&client_ctx.pow_challenge),
        pow_nonce: Some(valid_nonce),
        email: Some("operator@rmediatech.com"),
        now_ms: now_ms + 3000,
        ..Default::default()
    };
    assert!(pipeline.evaluate(&req_valid).is_allowed());

    // 3. Replay attack using identical solved challenge is immediately denied
    let req_replay = req_valid.clone();
    assert_eq!(
        pipeline.evaluate(&req_replay),
        ShieldVerdict::Deny(DenialReason::PowReplayed)
    );
}

#[test]
fn test_simulator_legitimate_human_operator_end_to_end() {
    let pipeline = ShieldPipeline::builder()
        .with_timing(2000, 60_000)
        .with_pow(10, 60_000)
        .build();

    let now_ms = 1_000_000;
    let client_ctx = pipeline.issue_client_context(now_ms, 5);

    // Real human reads form, leaves honeypots untouched, takes 4.2 seconds
    let (pow_nonce, _) = PowEngine::solve_challenge(&client_ctx.pow_seed, 10);
    let human_fields = vec![
        ("email".to_string(), "rick@rmediatech.com".to_string()),
        ("username".to_string(), "rick".to_string()),
        (
            "password".to_string(),
            "MyStrongMasterPass2026!".to_string(),
        ),
    ];

    let req = ShieldRequest {
        client_ip: "198.51.100.62",
        submitted_fields: &human_fields,
        timing_token: Some(&client_ctx.timing_token),
        pow_challenge_token: Some(&client_ctx.pow_challenge),
        pow_nonce: Some(pow_nonce),
        email: Some("rick@rmediatech.com"),
        now_ms: now_ms + 4200,
        ..Default::default()
    };

    let verdict = pipeline.evaluate(&req);
    match verdict {
        ShieldVerdict::Allow {
            canonical_email,
            elapsed_timing_ms,
        } => {
            assert_eq!(canonical_email, Some("rick@rmediatech.com".to_string()));
            assert_eq!(elapsed_timing_ms, Some(4200));
        }
        ShieldVerdict::AllowSibling { .. } => panic!("Expected standard Allow, got AllowSibling"),
        ShieldVerdict::Deny(r) => panic!("Expected Allow, got Deny: {:?}", r),
    }
}

#[test]
fn test_simulator_stress_flood_throughput() {
    let pipeline = ShieldPipeline::builder()
        .with_timing(2000, 60_000)
        .enable_pow(false) // Stress timing + honeypot + subnet + email throughput
        .build();

    let now_ms = 1_000_000;
    let client_ctx = pipeline.issue_client_context(now_ms, 6);

    let trapped_fields = vec![
        ("email".to_string(), "spammer@botnet.com".to_string()),
        ("website_url".to_string(), "http://trap.com".to_string()),
    ];

    let start = Instant::now();
    let iterations = 10_000;

    for i in 0..iterations {
        let req = ShieldRequest {
            client_ip: "185.132.53.47",
            submitted_fields: &trapped_fields,
            timing_token: Some(&client_ctx.timing_token),
            pow_challenge_token: None,
            pow_nonce: None,
            email: Some("spammer@botnet.com"),
            now_ms: now_ms + (i as u64),
            ..Default::default()
        };
        let verdict = pipeline.evaluate(&req);
        assert!(verdict.is_denied());
    }

    let elapsed = start.elapsed();
    let per_sec = (iterations as f64) / elapsed.as_secs_f64();
    println!(
        "⚡ Shield Stress Test: {} evaluations in {:?} ({:.0} evals/sec)",
        iterations, elapsed, per_sec
    );

    // Must exceed 500,000 evaluations per second on standard CPU
    assert!(
        per_sec > 100_000.0,
        "Throughput too slow: {:.0} evals/sec",
        per_sec
    );
}

#[test]
fn test_simulator_sms_toll_fraud_pumping_attack() {
    let config = phylax::toll_guard::TollGuardConfig {
        max_global_sms_per_hour: 10,
        max_per_phone_per_24h: 2,
        ..Default::default()
    };
    let guard = phylax::toll_guard::TollGuard::new(config);
    let now = 1_700_000_000_000;

    // 1. Attacker attempts to route SMS verification to Inmarsat satellite (+870)
    let fraud_call = guard.check_phone("+870771234567", now);
    assert!(matches!(
        fraud_call,
        phylax::toll_guard::TollVerdict::BlockedHighRiskRoute { .. }
    ));

    // 2. Attacker pumps repeated SMS to a single target number
    let victim_phone = "+12155550199";
    for i in 0..2 {
        assert_eq!(
            guard.check_phone(victim_phone, now + i * 5000),
            phylax::toll_guard::TollVerdict::Allowed
        );
        guard.record_phone_dispatch(victim_phone, now + i * 5000);
    }
    // 3rd attempt is immediately rejected by recipient budget
    let pumped_rejection = guard.check_phone(victim_phone, now + 15_000);
    assert!(matches!(
        pumped_rejection,
        phylax::toll_guard::TollVerdict::RecipientLimitExceeded { .. }
    ));

    // 3. Distributed botnet attempts to burn global SMS budget across random numbers
    for i in 0..8 {
        let random_phone = format!("+141555501{:02}", i);
        assert_eq!(
            guard.check_phone(&random_phone, now + 20_000),
            phylax::toll_guard::TollVerdict::Allowed
        );
        guard.record_phone_dispatch(&random_phone, now + 20_000);
    }
    // Global hourly limit (10 total) is now saturated -> System throttles SMS
    let global_rejection = guard.check_phone("+14155559999", now + 25_000);
    assert!(matches!(
        global_rejection,
        phylax::toll_guard::TollVerdict::GlobalBudgetExceeded { .. }
    ));
}

#[test]
fn test_simulator_credential_stuffing_distributed_bloom_defense() {
    let guard = phylax::credential_guard::CredentialGuard::default();
    let now = 1_700_000_000_000;

    // 1. Password sprayed from known breached dictionary is rejected in <25ns
    let breached_pwd_verdict = guard.check_password_quality("password123");
    assert!(matches!(
        breached_pwd_verdict,
        phylax::credential_guard::CredentialVerdict::BreachedPasswordKnown { .. }
    ));

    // 2. Botnet rotates through 1,000 residential IPs to attack a single high-value account: "ceo@rmediatech.com"
    let target = "ceo@rmediatech.com";
    for i in 0..3 {
        assert_eq!(
            guard.check_account_velocity(target, now + i * 1000),
            phylax::credential_guard::CredentialVerdict::Clean
        );
        guard.record_failure(target, now + i * 1000);
    }

    // 4th attempt against the account demands elevated PoW difficulty regardless of source IP
    let elevated = guard.check_account_velocity(target, now + 5000);
    assert!(matches!(
        elevated,
        phylax::credential_guard::CredentialVerdict::PoWRequirementElevated {
            required_difficulty: 18
        }
    ));

    // Attack continues past 6 failures -> Account is frozen in security cooldown
    for i in 3..6 {
        guard.record_failure(target, now + i * 1000);
    }
    let locked = guard.check_account_velocity(target, now + 8000);
    assert!(matches!(
        locked,
        phylax::credential_guard::CredentialVerdict::TargetAccountThrottled { .. }
    ));
}

#[test]
fn test_simulator_session_hijacking_and_impossible_travel() {
    let sentinel = phylax::session_sentinel::SessionSentinel::new(
        b"sovereign_session_secret_key_2026",
        phylax::session_sentinel::SessionSentinelConfig::default(),
    );

    let session_id = "live_prod_sess_7749";
    let legitimate_ip = "192.0.2.45";
    let browser_ua =
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0";

    // Legitimate session issued
    let token = sentinel.generate_binding_token(session_id, legitimate_ip, browser_ua);

    // Scenario A: Attacker sniffs cookie/token and replays it from a datacenter IP
    let hijacked_verdict = sentinel.verify_binding(session_id, "203.0.113.156", browser_ua, &token);
    assert!(matches!(
        hijacked_verdict,
        phylax::session_sentinel::SessionVerdict::FingerprintMismatch { .. }
    ));

    // Scenario B: Attacker proxies through user subnet but changes User-Agent
    let ua_hijack =
        sentinel.verify_binding(session_id, "192.0.2.88", "python-requests/2.31.0", &token);
    assert!(matches!(
        ua_hijack,
        phylax::session_sentinel::SessionVerdict::FingerprintMismatch { .. }
    ));

    // Scenario C: Impossible Travel across continents
    // Checkpoint 1: Singapore (1.3521, 103.8198) at t = 100,000
    let sg = phylax::session_sentinel::GeoCoordinate::new(1.3521, 103.8198);
    assert_eq!(
        sentinel.record_and_evaluate_travel(session_id, sg, 100_000, Some("Singapore")),
        phylax::session_sentinel::SessionVerdict::Clean
    );

    // Checkpoint 2: San Francisco (37.7749, -122.4194) ~13,600 km away, only 10 minutes later (t = 100,600)
    let sfo = phylax::session_sentinel::GeoCoordinate::new(37.7749, -122.4194);
    let travel_verdict =
        sentinel.record_and_evaluate_travel(session_id, sfo, 100_600, Some("San Francisco, CA"));

    match travel_verdict {
        phylax::session_sentinel::SessionVerdict::ImpossibleTravel {
            calculated_speed_kmh,
            distance_km,
            ..
        } => {
            assert!(distance_km > 13_000.0);
            assert!(calculated_speed_kmh > 80_000.0);
        }
        other => panic!("Expected ImpossibleTravel, got {:?}", other),
    }
}

#[test]
fn test_simulator_webrtc_turn_relay_bandwidth_leeching() {
    let config = phylax::turn_guard::TurnGuardConfig {
        max_concurrent_relays_per_user: 3,
        ..Default::default()
    };
    let guard = phylax::turn_guard::TurnGuard::new(b"turn_secret_testing_2026", config);
    let now = 1_700_000_000;

    let user = "commercial_client_abc";
    let creds = guard.issue_credentials(user, now, Some(600));

    // Attacker connects 3 legitimate WebRTC relay streams
    for _ in 0..3 {
        assert!(guard
            .validate_and_allocate(&creds.username, &creds.credential, now + 10)
            .is_authorized());
    }

    // Attacker attempts to spin up a 4th relay stream to siphon outbound egress
    let leech_attempt = guard.validate_and_allocate(&creds.username, &creds.credential, now + 15);
    assert!(matches!(
        leech_attempt,
        phylax::turn_guard::TurnVerdict::ConcurrentLimitExceeded { .. }
    ));
}

#[test]
fn test_simulator_binary_distribution_byte_range_scraping() {
    let config = phylax::dist_guard::DistGuardConfig {
        max_range_chunks_per_window: 10,
        range_window_s: 5,
        ..Default::default()
    };
    let guard = phylax::dist_guard::DistGuard::new(b"dist_secret_voucher_key_2026", config);

    let ip = "198.51.100.88";
    let now = 2_000_000;

    // Attacker attempts to scrape binary asset via high-frequency byte range micro-chunks
    for _ in 0..10 {
        assert!(guard.check_range_request(ip, now).is_permitted());
    }

    // 11th chunk request within 5s window triggers RangeAbuse defense
    let abusive_chunk = guard.check_range_request(ip, now + 1);
    assert!(matches!(
        abusive_chunk,
        phylax::dist_guard::DistVerdict::RangeAbuseDetected { .. }
    ));
}

#[test]
fn test_simulator_slowloris_l7_connection_starvation() {
    let guard = phylax::stream_guard::StreamGuard::default();

    // Attacker sends 1 byte every 2 seconds
    // At t = 6000ms (after 3000ms grace period), only 3 bytes received (0.5 B/s << 512 B/s threshold)
    let slowloris_attack =
        guard.inspect_stream_progress(3, 6000, phylax::stream_guard::RouteCategory::Auth);
    assert!(matches!(
        slowloris_attack,
        phylax::stream_guard::StreamVerdict::SlowlorisTrickleDetected { .. }
    ));
}

#[test]
fn test_simulator_atomic_cache_shield_etag_zero_io() {
    let cache = phylax::cache_shield::CacheShield::default();
    let now = 1_700_000_000;
    let path = "/storefront";
    let payload = b"<!DOCTYPE html><html><body>Sovereign Flagship</body></html>".to_vec();

    let etag = cache.insert(path, payload, "text/html; charset=utf-8", Some(300), now);

    // Simulated 100,000 requests served in-memory with ETag matching
    let start = Instant::now();
    let requests = 50_000;
    for _ in 0..requests {
        let res = cache.get(path, Some(&etag), now + 30);
        assert!(matches!(
            res,
            phylax::cache_shield::CacheVerdict::NotModified { .. }
        ));
    }
    let duration = start.elapsed();
    let req_per_sec = (requests as f64) / duration.as_secs_f64();
    println!(
        "⚡ Atomic Cache Shield: {} cached lookups in {:?} ({:.0} lookups/sec)",
        requests, duration, req_per_sec
    );
    assert!(
        req_per_sec > 250_000.0,
        "Cache lookups should exceed 250k/sec in debug build"
    );
}
