//! # Adversarial Self-Attack TDD Suite: Synthetic Mirage Deception & Surface Auditor
//!
//! Verifies Layer 16 (`MirageEngine`) and `SurfaceAuditEngine` against:
//! 1. All 7 `DecoyCategory` poison artifacts (`.env`, `.git/config`, `terraform.tfstate`,
//!    `wp-login.php`, `actuator/env`, `dump.sql`, `id_rsa`, `_sovereign/canary_trap`).
//! 2. Cryptographic canary determinism per attacker IP and cross-IP uniqueness.
//! 3. ANSI CSI/OSC escape sequence and control-byte injection neutralization.
//! 4. Quadratic tarpit drip-delay scaling and ceiling bounds.
//! 5. Outside-in `SurfaceAuditEngine` exposure detection and posture grading (`A+` vs `F`).

use phylax::decoy_uri::DecoyCategory;
use phylax::mirage::{MirageConfig, MirageEngine};
use phylax::surface_audit::{ExposureVerdict, SurfaceAuditEngine, CANONICAL_SURFACE_VECTORS};

#[test]
fn test_mirage_synthesizes_all_seven_decoy_categories_with_valid_canaries() {
    let engine = MirageEngine::new(b"sovereign-test-hmac-key-2026", MirageConfig::default());
    let attacker_ip = "198.51.100.77";

    // 1. EnvironmentSecret (/.env)
    let env_payload = engine.synthesize(DecoyCategory::EnvironmentSecret, "/.env", attacker_ip, 1);
    assert_eq!(env_payload.status_code, 200);
    assert!(env_payload.content_type.starts_with("text/plain"));
    assert!(env_payload.body.contains("AWS_ACCESS_KEY_ID=AKIA"));
    assert!(env_payload.body.contains("STRIPE_SECRET_KEY=sk_live_"));
    assert!(env_payload.body.contains(&format!(
        "APP_CANARY_TRACE=mirage-{}",
        env_payload.canary_fingerprint
    )));

    // 2. VersionControl (/.git/config & /.git/HEAD)
    let git_payload = engine.synthesize(
        DecoyCategory::VersionControl,
        "/.git/config",
        attacker_ip,
        2,
    );
    assert_eq!(git_payload.status_code, 200);
    assert!(git_payload.body.contains("[remote \"origin\"]"));
    assert!(git_payload.body.contains("ghp_"));
    assert!(git_payload.body.contains(&git_payload.canary_fingerprint));

    let head_payload =
        engine.synthesize(DecoyCategory::VersionControl, "/.git/HEAD", attacker_ip, 1);
    assert_eq!(head_payload.body, "ref: refs/heads/main\n");

    // 3. CloudInfrastructure (/terraform.tfstate & /.aws/credentials)
    let tf_payload = engine.synthesize(
        DecoyCategory::CloudInfrastructure,
        "/terraform.tfstate",
        attacker_ip,
        1,
    );
    assert_eq!(tf_payload.content_type, "application/json; charset=utf-8");
    assert!(tf_payload.body.contains("\"terraform_version\": \"1.8.2\""));
    assert!(tf_payload.body.contains(&tf_payload.canary_fingerprint));

    let aws_payload = engine.synthesize(
        DecoyCategory::CloudInfrastructure,
        "/.aws/credentials",
        attacker_ip,
        1,
    );
    assert!(aws_payload.body.contains("aws_access_key_id = AKIA"));

    // 4. AdminCmsProbe (/wp-login.php & /actuator/env)
    let wp_payload = engine.synthesize(
        DecoyCategory::AdminCmsProbe,
        "/wp-login.php",
        attacker_ip,
        1,
    );
    assert_eq!(wp_payload.content_type, "text/html; charset=utf-8");
    assert!(wp_payload.body.contains("name=\"loginform\""));
    assert!(wp_payload.body.contains("name=\"website_url\""));

    let act_payload = engine.synthesize(
        DecoyCategory::AdminCmsProbe,
        "/actuator/env",
        attacker_ip,
        1,
    );
    assert!(act_payload.content_type.contains("actuator"));
    assert!(act_payload.body.contains("SPRING_DATASOURCE_PASSWORD"));

    // 5. DatabaseBackup (/dump.sql)
    let sql_payload = engine.synthesize(DecoyCategory::DatabaseBackup, "/dump.sql", attacker_ip, 3);
    assert_eq!(sql_payload.content_type, "application/sql; charset=utf-8");
    assert!(sql_payload
        .body
        .contains("CREATE TABLE `operator_accounts`"));
    assert!(sql_payload.body.contains("tok_live_"));

    // 6. PrivateKey (/id_rsa)
    let ssh_payload = engine.synthesize(DecoyCategory::PrivateKey, "/id_rsa", attacker_ip, 1);
    assert_eq!(ssh_payload.content_type, "application/x-pem-file");
    assert!(ssh_payload
        .body
        .contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

    // 7. Custom CanaryTrap (/_sovereign/canary_trap)
    let trap_payload = engine.synthesize(
        DecoyCategory::Custom,
        "/_sovereign/canary_trap",
        attacker_ip,
        1,
    );
    assert!(trap_payload.body.contains("INTERNAL_NODE_SYNC"));
    assert!(trap_payload.body.contains("sov_canary_"));
}

#[test]
fn test_mirage_canary_attribution_is_deterministic_per_ip_and_unique_across_ips() {
    let engine = MirageEngine::new(b"attribution-secret-key", MirageConfig::default());

    let p1_a = engine.synthesize(DecoyCategory::EnvironmentSecret, "/.env", "192.0.2.10", 1);
    let p1_b = engine.synthesize(DecoyCategory::EnvironmentSecret, "/.env", "192.0.2.10", 1);
    let p2 = engine.synthesize(DecoyCategory::EnvironmentSecret, "/.env", "192.0.2.99", 1);

    // Same IP + path must produce identical canary & body for forensic correlation
    assert_eq!(p1_a.canary_fingerprint, p1_b.canary_fingerprint);
    assert_eq!(p1_a.body, p1_b.body);

    // Different attacker IP must produce a distinct canary fingerprint
    assert_ne!(p1_a.canary_fingerprint, p2.canary_fingerprint);
    assert_ne!(p1_a.body, p2.body);
}

#[test]
fn test_mirage_neutralizes_ansi_escape_and_control_injection_in_inputs() {
    let engine = MirageEngine::default();
    let hostile_ip = "198.51.100.1\x1b[31m\r\nInjected-Header: pwned";
    let hostile_path = "/.env\x1b]0;pwned\x07\0\r\n";

    let payload = engine.synthesize(
        DecoyCategory::EnvironmentSecret,
        hostile_path,
        hostile_ip,
        1,
    );

    // Verify no raw ESC or carriage returns leak into canary or headers
    assert!(!payload.canary_fingerprint.contains('\x1b'));
    assert!(!payload.canary_fingerprint.contains('\r'));
    for (_, val) in &payload.extra_headers {
        assert!(!val.contains('\x1b'));
        assert!(!val.contains('\r'));
        assert!(!val.contains('\n'));
    }
}

#[test]
fn test_mirage_progressive_drip_delay_scales_quadratically_with_cap() {
    let engine = MirageEngine::new(
        b"seed",
        MirageConfig {
            enabled: true,
            decoy_domain: "corp.local".into(),
            base_drip_delay_ms: 100,
            max_drip_delay_ms: 2_000,
        },
    );

    assert_eq!(engine.compute_drip_delay_ms(1), 100);
    assert_eq!(engine.compute_drip_delay_ms(2), 400);
    assert_eq!(engine.compute_drip_delay_ms(3), 900);
    assert_eq!(engine.compute_drip_delay_ms(4), 1600);
    assert_eq!(engine.compute_drip_delay_ms(5), 2000); // capped at max_drip_delay_ms
    assert_eq!(engine.compute_drip_delay_ms(1000), 2000); // overflow-safe cap
}

#[test]
fn test_surface_audit_engine_grades_mirage_fortress_vs_exposed_risk() {
    let mirage = MirageEngine::default();
    let mut mirage_results = Vec::new();

    for vec in CANONICAL_SURFACE_VECTORS {
        let m = mirage.synthesize(vec.category, vec.path, "192.0.2.50", 1);
        let res = SurfaceAuditEngine::evaluate_probe_response(
            vec,
            m.status_code,
            &m.extra_headers,
            &m.body,
        );
        assert!(
            matches!(res.verdict, ExposureVerdict::ProtectedByMirage { .. }),
            "Vector {} should be detected as ProtectedByMirage, got {:?}",
            vec.path,
            res.verdict
        );
        assert!(res.verdict.is_safe());
        mirage_results.push(res);
    }

    let hardened_headers = vec![
        (
            "Strict-Transport-Security".into(),
            "max-age=63072000; includeSubDomains".into(),
        ),
        ("X-Content-Type-Options".into(), "nosniff".into()),
        ("X-Frame-Options".into(), "DENY".into()),
    ];

    let report = SurfaceAuditEngine::compile_report(
        "https://rmediatech.com",
        mirage_results,
        &hardened_headers,
    );
    assert_eq!(report.exposed_risk_count, 0);
    assert_eq!(
        report.mirage_protected_count,
        CANONICAL_SURFACE_VECTORS.len()
    );
    assert_eq!(report.posture_grade, "A+ (Sovereign Mirage Fortress)");

    // Now simulate an unguarded server leaking a real /.env without a Mirage canary
    let env_vec = &CANONICAL_SURFACE_VECTORS[0];
    let leaked_res = SurfaceAuditEngine::evaluate_probe_response(
        env_vec,
        200,
        &[],
        "APP_ENV=prod\nDB_PASSWORD=real_unprotected_secret\n",
    );
    assert!(!leaked_res.verdict.is_safe());
    assert!(matches!(
        leaked_res.verdict,
        ExposureVerdict::ExposedRisk { .. }
    ));

    let fail_report =
        SurfaceAuditEngine::compile_report("http://vulnerable.example.com", vec![leaked_res], &[]);
    assert_eq!(fail_report.exposed_risk_count, 1);
    assert_eq!(fail_report.posture_grade, "F (CRITICAL SURFACE EXPOSURE)");
}
