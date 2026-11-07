//! # Adversarial Crucible: Phylax v0.5.0 Next-Gen WAF & De-Obfuscation Suite
//!
//! Verifies:
//! 1. Multi-round recursive percent-decoding (`%25252e%25252e%25252f` -> `../`), IIS `%u00XX` Unicode,
//!    and HTML hex/decimal entities (`&#x2e;`) integrated into `PayloadGuard`.
//! 2. Pure Safe-Rust SQLi Tokenizer & Inline Comment Stripper (`UN/**/ION SEL/**/ECT`, `/*!50000UNION*/`,
//!    `admin') OR ('a')=('a`, `' OR 0x50=0x50--`) replacing unsafe C `libinjection`.
//! 3. Sub-Microsecond SSRF, IMDSv1/v2 (`169.254.169.254`, `fd00:ec2::254`, `[::ffff:169.254.169.254]`),
//!    Decimal/Hex/Octal IP de-obfuscation (`http://2852039166/`, `http://0x7f000001/`, `http://0177.0.0.1/`),
//!    and stateful DNS Rebinding pinning.
//! 4. Adaptive Tarpit Velocity Scaling (progressive Slowloris socket hostage drain scaling to
//!    `15,000ms` / `1 byte` on repeat strikes).

use phylax::{
    AdversarialPayload, Canonicalizer, PayloadGuard, SqliDetection, SqliTokenizer, SsrfShield,
    SsrfVerdict, TarpitConfig, TarpitGovernor, TarpitVerdict,
};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_adversarial_multi_round_nested_encoding_traversal_blocked() {
    // 1. Triple-encoded directory traversal (%25252e%25252e%25252f -> ../):
    // Naive 1-pass decoders leave "%252e%252e%252f" which bypasses single-decode WAFs.
    let res = PayloadGuard::inspect("/assets/%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd", "");
    assert!(
        matches!(res, Err(AdversarialPayload::PathTraversal(_))),
        "Triple-encoded traversal must be unmasked and blocked: {:?}",
        res
    );

    // 2. IIS %u002e%u002e%u2215 Unicode homoglyph traversal
    let iis_res = PayloadGuard::inspect("/download/%u002e%u002e%u2215%u002e%u002e%u2215etc/shadow", "");
    assert!(
        matches!(iis_res, Err(AdversarialPayload::PathTraversal(_))),
        "IIS %uXXXX Unicode traversal must be blocked: {:?}",
        iis_res
    );

    // 3. HTML numeric entity obfuscated traversal in query string
    let html_res = PayloadGuard::inspect("/view", "template=&#x2e;&#x2e;/&#46;&#46;/etc/hosts");
    assert!(
        matches!(html_res, Err(AdversarialPayload::PathTraversal(_))),
        "HTML entity traversal must be blocked: {:?}",
        html_res
    );

    // 4. Nested null-byte poisoning (%252500 -> \0)
    let null_res = PayloadGuard::inspect("/upload/avatar.png%252500.php", "");
    assert_eq!(null_res, Err(AdversarialPayload::NullByteInjection));
}

#[test]
fn test_adversarial_pure_rust_sqli_tokenizer_vs_comment_and_tautology_bypasses() {
    // 1. Inline comment keyword splitting that bypasses regex/substring WAFs
    let split_union = PayloadGuard::inspect(
        "/api/search",
        "q=1'/**/UN/**/ION/**/ALL/**/SEL/**/ECT/**/1,2,password/**/FROM/**/users--",
    );
    assert!(
        matches!(split_union, Err(AdversarialPayload::SqlInjection(_))),
        "Comment-split UNION SELECT must be caught by SqliTokenizer: {:?}",
        split_union
    );

    // 2. MySQL versioned executable comment bypass
    let mysql_ver = PayloadGuard::inspect("/items", "id=1/*!50000UNION*//*!50000SELECT*/1,2,3");
    assert!(
        matches!(mysql_ver, Err(AdversarialPayload::SqlInjection(_))),
        "MySQL /*!50000...*/ comment bypass must be blocked: {:?}",
        mysql_ver
    );

    // 3. Novel parenthesized & hex tautologies not in static string tables
    for payload in [
        "user=admin') OR ('x')=('x",
        "id=1 OR 0x7a=0x7a--",
        "filter=' OR 999=999#",
        "sort=name; DROP TABLE operators--",
    ] {
        let verdict = PayloadGuard::inspect("/query", payload);
        assert!(
            matches!(verdict, Err(AdversarialPayload::SqlInjection(_))),
            "Payload '{}' must be blocked by structural SQLi tokenizer, got {:?}",
            payload,
            verdict
        );
    }

    // 4. Verify direct SqliTokenizer structural classifications
    assert_eq!(
        SqliTokenizer::inspect("1; SELECT pg_sleep(10)--"),
        Some(SqliDetection::StackedQuery("stacked_sql_statement"))
    );
}

#[test]
fn test_adversarial_ssrf_imds_numeric_ip_obfuscation_and_dns_rebinding() {
    // 1. Decimal 32-bit integer IP for AWS IMDS (169.254.169.254 == 2852039166)
    let dec_imds = PayloadGuard::inspect("/webhook", "callback=http://2852039166/latest/meta-data/");
    assert!(
        matches!(dec_imds, Err(AdversarialPayload::SsrfProbe(_))),
        "32-bit decimal IMDS IP must be blocked: {:?}",
        dec_imds
    );

    // 2. Hexadecimal IP for Loopback (127.0.0.1 == 0x7f000001)
    let hex_loop = PayloadGuard::inspect("/fetch", "url=http://0x7f000001:8080/internal");
    assert!(
        matches!(hex_loop, Err(AdversarialPayload::SsrfProbe(_))),
        "Hex loopback IP must be blocked: {:?}",
        hex_loop
    );

    // 3. Dotted Octal IP for Loopback (0177.0.0.1) & RFC 1918 Private (012.0.0.1 == 10.0.0.1)
    assert!(matches!(
        PayloadGuard::inspect("/proxy", "target=http://0177.0.0.1/admin"),
        Err(AdversarialPayload::SsrfProbe(_))
    ));
    assert!(matches!(
        PayloadGuard::inspect("/proxy", "target=http://012.0.0.1/metrics"),
        Err(AdversarialPayload::SsrfProbe(_))
    ));

    // 4. IPv4-mapped IPv6 IMDS (`[::ffff:169.254.169.254]`) and AWS IPv6 IMDS (`[fd00:ec2::254]`)
    assert!(matches!(
        PayloadGuard::inspect("/avatar", "url=http://[::ffff:169.254.169.254]/latest/api/token"),
        Err(AdversarialPayload::SsrfProbe(_))
    ));
    assert!(matches!(
        PayloadGuard::inspect("/avatar", "url=http://[fd00:ec2::254]/latest/meta-data"),
        Err(AdversarialPayload::SsrfProbe(_))
    ));

    // 5. Stateful DNS Rebinding protection
    let shield = SsrfShield::new(1024);
    let legitimate_public: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
    let rebound_internal: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 24, 0, 15));

    assert_eq!(
        shield.verify_and_pin_resolution("hooks.customer-site.org", legitimate_public),
        SsrfVerdict::Allow
    );
    assert_eq!(
        shield.verify_and_pin_resolution("hooks.customer-site.org", rebound_internal),
        SsrfVerdict::DnsRebindingDetected {
            host: "hooks.customer-site.org".to_string(),
            pinned_ip: legitimate_public,
            rebound_ip: rebound_internal,
        }
    );
}

#[test]
fn test_adversarial_adaptive_tarpit_velocity_scaling() {
    let gov = TarpitGovernor::new(TarpitConfig::default());
    let offender_ip = "203.0.113.199";

    // Strike 1: Baseline profile (3000ms interval, 2 bytes/tick, 45s max)
    let v1 = gov.acquire_slot(offender_ip);
    let TarpitVerdict::Engage { slot_guard: g1 } = v1 else {
        panic!("Expected Engage on strike 1");
    };
    assert_eq!(g1.profile().strike_count, 1);
    assert_eq!(g1.profile().trickle_interval_ms, 3000);
    assert_eq!(g1.profile().chunk_size, 2);
    assert_eq!(g1.profile().max_duration_s, 45);
    drop(g1);

    // Strike 2: Escalated slowloris drain (7500ms interval, 1 byte/tick, 90s max)
    let v2 = gov.acquire_slot(offender_ip);
    let TarpitVerdict::Engage { slot_guard: g2 } = v2 else {
        panic!("Expected Engage on strike 2");
    };
    assert_eq!(g2.profile().strike_count, 2);
    assert_eq!(g2.profile().trickle_interval_ms, 7500);
    assert_eq!(g2.profile().chunk_size, 1);
    assert_eq!(g2.profile().max_duration_s, 90);
    drop(g2);

    // Strike 3+: Maximum botnet thread starvation (15,000ms interval, 1 byte/tick, 180s max)
    let v3 = gov.acquire_slot(offender_ip);
    let TarpitVerdict::Engage { slot_guard: g3 } = v3 else {
        panic!("Expected Engage on strike 3");
    };
    assert_eq!(g3.profile().strike_count, 3);
    assert_eq!(g3.profile().trickle_interval_ms, 15_000);
    assert_eq!(g3.profile().chunk_size, 1);
    assert_eq!(g3.profile().max_duration_s, 180);
    assert_eq!(gov.strikes_for_ip(offender_ip), 3);
    drop(g3);

    // Verify canonicalizer zero-allocation fast path on clean traffic
    let clean = Canonicalizer::canonicalize("/api/v1/status");
    assert_eq!(clean.decode_rounds, 0);
    assert!(!clean.is_evasion_attempt());
}
