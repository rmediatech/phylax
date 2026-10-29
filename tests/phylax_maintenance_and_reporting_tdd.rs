//! # Phylax Autonomous Maintenance & Abuse Intelligence Integration TDD
//! Radical OJP & TDD Suite for zero-lock memory hygiene and optional AbuseIPDB incident reporting.

use phylax::adaptive_pow::{AdaptivePowConfig, InfractionSeverity};
use phylax::autonomous_quarantine::QuarantineConfig;
use phylax::pipeline::{DenialReason, ShieldPipeline, ShieldRequest, ShieldVerdict};
use std::time::Duration;

#[cfg(feature = "abuse-reporting")]
use phylax::abuse_reporting::{
    AbuseCategory, AbuseIpDbSink, AbuseReportError, CooldownConfig, ForensicDossier,
    GenericWebhookSink, IncidentSink, InformantConfig, InformantEngine, MockAbuseReporterTransport,
    MockIncidentSink, MultiSink, SinkReceipt, SyslogCefSink,
};
#[cfg(feature = "abuse-reporting")]
use std::sync::Arc;

#[test]
fn test_pipeline_maintenance_manager_prunes_stores_and_returns_accurate_report() {
    let pipeline = ShieldPipeline::builder()
        .with_quarantine(QuarantineConfig {
            infraction_threshold: 1,
            quarantine_duration_ms: 1000,
            max_tracked_subnets: 100,
        })
        .with_adaptive_pow(AdaptivePowConfig {
            baseline_difficulty: 10,
            suspicious_difficulty: 12,
            hostile_difficulty: 14,
            severe_difficulty: 16,
            infraction_decay_ms: 1000,
        })
        .build();

    let now_ms = 1_000_000;

    // Simulate honeypot trap at t=1,000,000
    let trapped_fields = vec![("website_url".to_string(), "http://bot.com".to_string())];
    let req = ShieldRequest {
        client_ip: "185.34.33.2",
        submitted_fields: &trapped_fields,
        now_ms,
        ..Default::default()
    };

    let verdict = pipeline.evaluate(&req);
    assert_eq!(
        verdict,
        ShieldVerdict::Deny(DenialReason::HoneypotTrapped {
            field: "website_url".to_string()
        })
    );

    // Verify state was populated: 1 quarantined subnet, 1 adaptive PoW record
    assert_eq!(pipeline.quarantine().active_bans_count(), 1);
    assert_eq!(pipeline.adaptive_pow().tracked_ips_count(), 1);

    // Immediate maintenance pass at t+500ms (nothing pruned)
    let early_report = pipeline.run_maintenance(now_ms + 500);
    assert_eq!(early_report.quarantined_subnets_pruned, 0);
    assert_eq!(early_report.decayed_pow_records_pruned, 0);
    assert_eq!(early_report.active_quarantined_subnets, 1);
    assert_eq!(early_report.active_pow_records, 1);

    // Advance time past quarantine and decay window (t+4,000ms: 4 decay steps = score 0)
    let expired_report = pipeline.run_maintenance(now_ms + 4000);
    assert_eq!(expired_report.quarantined_subnets_pruned, 1);
    assert_eq!(expired_report.decayed_pow_records_pruned, 1);
    assert_eq!(expired_report.active_quarantined_subnets, 0);
    assert_eq!(expired_report.active_pow_records, 0);
}

#[tokio::test]
async fn test_pipeline_spawn_background_maintenance_cleans_autonomously() {
    let pipeline = ShieldPipeline::builder()
        .with_quarantine(QuarantineConfig {
            infraction_threshold: 1,
            quarantine_duration_ms: 50,
            max_tracked_subnets: 50,
        })
        .with_adaptive_pow(AdaptivePowConfig {
            baseline_difficulty: 10,
            suspicious_difficulty: 12,
            hostile_difficulty: 14,
            severe_difficulty: 16,
            infraction_decay_ms: 50,
        })
        .build();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Trigger quarantine infraction
    pipeline
        .quarantine()
        .record_and_check("192.0.2.100", now_ms);
    pipeline.adaptive_pow().record_infraction(
        "192.0.2.100",
        InfractionSeverity::Suspicious,
        now_ms,
    );

    assert_eq!(pipeline.quarantine().active_bans_count(), 1);
    assert_eq!(pipeline.adaptive_pow().tracked_ips_count(), 1);

    // Spawn background worker with 20ms interval
    let handle = pipeline.spawn_background_maintenance(Duration::from_millis(20));

    // Wait 120ms for expiration (50ms) and tick cleanup
    tokio::time::sleep(Duration::from_millis(120)).await;

    assert_eq!(pipeline.quarantine().active_bans_count(), 0);
    assert_eq!(pipeline.adaptive_pow().tracked_ips_count(), 0);

    handle.abort();
}

#[cfg(feature = "abuse-reporting")]
#[tokio::test]
async fn test_pipeline_honeypot_triggers_asynchronous_abuse_reporting() {
    let mock_transport = Arc::new(MockAbuseReporterTransport::new());
    let informant_config = InformantConfig {
        enabled: true,
        dry_run: false,
        api_key: Some("valid_key".to_string()),
        webhook_url: None,
        webhook_auth: None,
        syslog_cef: false,
        cooldown: CooldownConfig {
            cooldown_window_ms: 60_000,
            max_reports_per_day: 10,
        },
    };

    let informant = Arc::new(InformantEngine::new(
        informant_config,
        mock_transport.clone(),
    ));

    let pipeline = ShieldPipeline::builder()
        .with_informant_engine(informant.clone())
        .build();

    let now_ms = 1_000_000;

    // Clean request - should NOT trigger report
    let clean_req = ShieldRequest {
        client_ip: "198.51.100.21",
        submitted_fields: &[("username".to_string(), "alice".to_string())],
        now_ms,
        ..Default::default()
    };
    let _ = pipeline.evaluate_perimeter(&clean_req);

    // Allow async tasks a moment to run
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(mock_transport.get_recorded_reports().len(), 0);

    // Honeypot trap tripped - SHOULD trigger async report
    let trapped_req = ShieldRequest {
        client_ip: "185.34.33.2",
        submitted_fields: &[
            ("username".to_string(), "bot".to_string()),
            ("website_url".to_string(), "http://evil.com".to_string()),
        ],
        target_uri: Some("/auth/login"),
        http_method: Some("POST"),
        user_agent: Some("curl/8.5.0"),
        now_ms,
        ..Default::default()
    };

    let verdict = pipeline.evaluate_perimeter(&trapped_req);
    assert!(matches!(
        verdict,
        ShieldVerdict::Deny(DenialReason::HoneypotTrapped { .. })
    ));

    // Wait for tokio async worker to complete dispatch
    tokio::time::sleep(Duration::from_millis(50)).await;

    let reports = mock_transport.get_recorded_reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].ip, "185.34.33.2");
    assert_eq!(reports[0].categories, "10,21");
    assert!(reports[0].comment.contains("185.34.33.2"));
    assert!(reports[0].comment.contains("/auth/login"));
    assert!(reports[0].comment.contains("website_url"));

    // Subsequent duplicate trap within cooldown should be suppressed
    let duplicate_verdict = pipeline.evaluate_perimeter(&trapped_req);
    assert!(matches!(
        duplicate_verdict,
        ShieldVerdict::Deny(DenialReason::HoneypotTrapped { .. })
    ));

    tokio::time::sleep(Duration::from_millis(50)).await;
    // Count remains 1 due to cooldown governor!
    assert_eq!(mock_transport.get_recorded_reports().len(), 1);
}

#[cfg(feature = "abuse-reporting")]
#[tokio::test]
async fn test_pipeline_abuse_reporting_opt_in_disabled_by_default() {
    let pipeline = ShieldPipeline::builder().build();

    // When abuse reporting feature is enabled but no informant configured, informant() is None
    assert!(pipeline.informant().is_none());
}

#[cfg(feature = "abuse-reporting")]
#[tokio::test]
async fn test_abuseipdb_sink_translates_and_dispatches() {
    let mock_transport = Arc::new(MockAbuseReporterTransport::new());
    let sink = AbuseIpDbSink::new("test_api_key".to_string(), mock_transport.clone());
    let dossier = ForensicDossier {
        client_ip: "198.51.100.77".to_string(),
        category: AbuseCategory::WebHoneypot,
        timestamp_ms: 1_700_000_000,
        target_uri: "/auth/register".to_string(),
        http_method: "POST".to_string(),
        user_agent: Some("TestBot/1.0".to_string()),
        trapped_field: Some("website_url".to_string()),
        evidence_notes: "Trapped decoy field".to_string(),
    };

    let receipt = sink
        .dispatch(&dossier)
        .await
        .expect("AbuseIpDbSink should succeed");
    assert_eq!(receipt.sink_name, "AbuseIPDB");
    assert_eq!(mock_transport.get_recorded_reports().len(), 1);
    assert_eq!(mock_transport.get_recorded_reports()[0].ip, "198.51.100.77");
}

#[cfg(feature = "abuse-reporting")]
#[tokio::test]
async fn test_informant_engine_with_custom_pluggable_sink() {
    let mock_sink = Arc::new(MockIncidentSink::new());
    let config = InformantConfig {
        enabled: true,
        dry_run: false,
        ..Default::default()
    };
    let engine = InformantEngine::with_sink(config, mock_sink.clone());
    let dossier = ForensicDossier {
        client_ip: "192.0.2.1".to_string(),
        category: AbuseCategory::DdosVolumetric,
        timestamp_ms: 1_700_000_000,
        target_uri: "/api/submit".to_string(),
        http_method: "POST".to_string(),
        user_agent: Some("SpamBot/2.0".to_string()),
        trapped_field: None,
        evidence_notes: "High frequency connection flood".to_string(),
    };

    let verdict = engine.process_incident(&dossier).await;
    assert!(matches!(
        verdict,
        phylax::abuse_reporting::InformantVerdict::Reported { .. }
    ));
    assert_eq!(mock_sink.recorded_dossiers().len(), 1);
    assert_eq!(mock_sink.recorded_dossiers()[0].client_ip, "192.0.2.1");
}

#[cfg(feature = "abuse-reporting")]
#[tokio::test]
async fn test_syslog_cef_sink_formats_standard_cef_payload() {
    let sink = SyslogCefSink;
    let dossier = ForensicDossier {
        client_ip: "203.0.113.55".to_string(),
        category: AbuseCategory::WebHoneypot,
        timestamp_ms: 1_700_000_000,
        target_uri: "/admin".to_string(),
        http_method: "GET".to_string(),
        user_agent: Some("DirBuster".to_string()),
        trapped_field: Some("company_fax".to_string()),
        evidence_notes: "Decoy field accessed".to_string(),
    };
    let receipt = sink
        .dispatch(&dossier)
        .await
        .expect("CEF format should succeed");
    assert_eq!(receipt.sink_name, "SyslogCEF");
    let expected_prefix = format!(
        "CEF:0|Phylax|EdgeDefense|{}|Web Honeypot Trap|Web Honeypot Trap|8|src=203.0.113.55",
        env!("CARGO_PKG_VERSION")
    );
    assert!(receipt.detail.starts_with(&expected_prefix));
    assert!(receipt.detail.contains("requestMethod=GET"));
    assert!(receipt.detail.contains("request=/admin"));
    assert!(receipt.detail.contains("cs1=company_fax"));
}

#[cfg(feature = "abuse-reporting")]
struct FailingSink;

#[cfg(feature = "abuse-reporting")]
#[async_trait::async_trait]
impl IncidentSink for FailingSink {
    fn name(&self) -> &'static str {
        "FailingSink"
    }
    async fn dispatch(&self, _dossier: &ForensicDossier) -> Result<SinkReceipt, AbuseReportError> {
        Err(AbuseReportError::Network("Connection refused".to_string()))
    }
}

#[cfg(feature = "abuse-reporting")]
#[tokio::test]
async fn test_multi_sink_broadcasts_to_multiple_sinks_and_handles_partial_failures() {
    let mock_sink1 = Arc::new(MockIncidentSink::new());
    let mock_sink2 = Arc::new(MockIncidentSink::new());
    let failing_sink = Arc::new(FailingSink);

    // MultiSink with 2 working sinks and 1 failing sink
    let multi = MultiSink::new(vec![
        mock_sink1.clone(),
        failing_sink.clone(),
        mock_sink2.clone(),
    ]);

    let dossier = ForensicDossier {
        client_ip: "198.51.100.42".to_string(),
        category: AbuseCategory::WebHoneypot,
        timestamp_ms: 1_700_000_000,
        target_uri: "/auth/register".to_string(),
        http_method: "POST".to_string(),
        user_agent: Some("Bot/1.0".to_string()),
        trapped_field: Some("website_url".to_string()),
        evidence_notes: "Decoy field tripped".to_string(),
    };

    let receipt = multi
        .dispatch(&dossier)
        .await
        .expect("MultiSink should succeed if at least one sink succeeds");
    assert_eq!(receipt.sink_name, "MultiSink");
    assert_eq!(mock_sink1.recorded_dossiers().len(), 1);
    assert_eq!(mock_sink2.recorded_dossiers().len(), 1);

    // MultiSink with only failing sinks
    let all_failing = MultiSink::new(vec![failing_sink]);
    let err = all_failing.dispatch(&dossier).await.unwrap_err();
    assert!(matches!(err, AbuseReportError::MultiSinkFailure(_)));

    // Empty MultiSink
    let empty = MultiSink::new(vec![]);
    let empty_err = empty.dispatch(&dossier).await.unwrap_err();
    assert!(matches!(empty_err, AbuseReportError::Config(_)));
}

#[cfg(feature = "abuse-reporting")]
#[tokio::test]
async fn test_generic_webhook_sink_dispatches_json_payload_to_http_endpoint() {
    use axum::{http::HeaderMap, routing::post, Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let received_count = Arc::new(AtomicUsize::new(0));
    let received_count_clone = received_count.clone();

    let app = Router::new().route(
        "/webhook",
        post(
            move |headers: HeaderMap, Json(payload): Json<serde_json::Value>| {
                let count = received_count_clone.clone();
                async move {
                    if let Some(auth) = headers.get("authorization") {
                        if auth == "Bearer test-token-123"
                            && payload.get("client_ip").and_then(|v| v.as_str())
                                == Some("198.51.100.99")
                        {
                            count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    axum::http::StatusCode::OK
                }
            },
        ),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let webhook_url = format!("http://{}/webhook", addr);
    let sink = GenericWebhookSink::new(
        webhook_url,
        vec![(
            "Authorization".to_string(),
            "Bearer test-token-123".to_string(),
        )],
    );

    let dossier = ForensicDossier {
        client_ip: "198.51.100.99".to_string(),
        category: AbuseCategory::WebHoneypot,
        timestamp_ms: 1_700_000_000,
        target_uri: "/auth/login".to_string(),
        http_method: "POST".to_string(),
        user_agent: Some("EvilBot/1.0".to_string()),
        trapped_field: Some("website_url".to_string()),
        evidence_notes: "Trapped field during registration".to_string(),
    };

    let receipt = sink
        .dispatch(&dossier)
        .await
        .expect("Webhook dispatch should succeed");
    assert_eq!(receipt.sink_name, "GenericWebhook");
    assert_eq!(receipt.detail, "HTTP 200");
    assert_eq!(received_count.load(Ordering::SeqCst), 1);
}
