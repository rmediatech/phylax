//! # Pluggable Threat Intelligence & Incident Sinks
//! One-Job: Abstract and deliver forensic dossiers to diverse upstream sinks (AbuseIPDB, Generic Webhooks, Syslog/CEF, Multi-Sink).

use crate::abuse_reporting::abuseipdb::AbuseIpDbReportPayload;
use crate::abuse_reporting::dossier::{DossierFormatter, ForensicDossier};
use crate::abuse_reporting::error::AbuseReportError;
use crate::abuse_reporting::transport::{AbuseReporterTransport, HttpAbuseReporterTransport};
use async_trait::async_trait;
use std::sync::Arc;

/// Receipt returned upon successful incident dispatch
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkReceipt {
    pub sink_name: &'static str,
    pub target_identifier: String,
    pub detail: String,
}

/// Pluggable incident sink trait for enterprise flexibility
#[async_trait]
pub trait IncidentSink: Send + Sync {
    /// Human-readable identifier for diagnostics and logging
    fn name(&self) -> &'static str;

    /// Dispatches a forensic incident dossier to the upstream sink
    async fn dispatch(&self, dossier: &ForensicDossier) -> Result<SinkReceipt, AbuseReportError>;
}

/// 1. AbuseIPDB Sink (Translates to AbuseIPDB format & dispatches over transport)
pub struct AbuseIpDbSink {
    api_key: String,
    transport: Arc<dyn AbuseReporterTransport>,
}

impl AbuseIpDbSink {
    pub fn new(api_key: String, transport: Arc<dyn AbuseReporterTransport>) -> Self {
        Self { api_key, transport }
    }

    pub fn with_default_transport(api_key: String) -> Self {
        Self::new(api_key, Arc::new(HttpAbuseReporterTransport::new(None)))
    }
}

#[async_trait]
impl IncidentSink for AbuseIpDbSink {
    fn name(&self) -> &'static str {
        "AbuseIPDB"
    }

    async fn dispatch(&self, dossier: &ForensicDossier) -> Result<SinkReceipt, AbuseReportError> {
        if self.api_key.trim().is_empty() {
            return Err(AbuseReportError::MissingApiKey);
        }

        let comment = DossierFormatter::render_incident_comment(dossier);
        let categories = dossier.category.to_categories_param();
        let payload = AbuseIpDbReportPayload {
            ip: dossier.client_ip.clone(),
            categories,
            comment,
        };

        let resp = self
            .transport
            .submit_report(&payload, &self.api_key)
            .await?;
        Ok(SinkReceipt {
            sink_name: "AbuseIPDB",
            target_identifier: resp.ip_address,
            detail: format!("Confidence Score: {}", resp.abuse_confidence_score),
        })
    }
}

/// 2. Generic Webhook Sink (Posts JSON dossier to any URL with optional auth headers)
pub struct GenericWebhookSink {
    url: String,
    headers: Vec<(String, String)>,
    client: reqwest::Client,
}

impl GenericWebhookSink {
    pub fn new(url: String, headers: Vec<(String, String)>) -> Self {
        Self {
            url,
            headers,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }
}

#[async_trait]
impl IncidentSink for GenericWebhookSink {
    fn name(&self) -> &'static str {
        "GenericWebhook"
    }

    async fn dispatch(&self, dossier: &ForensicDossier) -> Result<SinkReceipt, AbuseReportError> {
        let ua = format!("Phylax-Sovereign-Defense/{}", env!("CARGO_PKG_VERSION"));
        let mut req = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("User-Agent", ua);

        for (k, v) in &self.headers {
            req = req.header(k, v);
        }

        let resp = req
            .json(dossier)
            .send()
            .await
            .map_err(|e| AbuseReportError::Network(e.to_string()))?;

        let status = resp.status();
        if status.is_success() {
            Ok(SinkReceipt {
                sink_name: "GenericWebhook",
                target_identifier: self.url.clone(),
                detail: format!("HTTP {}", status.as_u16()),
            })
        } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry = resp
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            Err(AbuseReportError::RateLimited {
                retry_after_s: retry,
            })
        } else if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            Err(AbuseReportError::Unauthorized)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(AbuseReportError::ApiError {
                status: status.as_u16(),
                body,
            })
        }
    }
}

/// 3. Syslog / CEF (Common Event Format) Sink
pub struct SyslogCefSink;

#[async_trait]
impl IncidentSink for SyslogCefSink {
    fn name(&self) -> &'static str {
        "SyslogCEF"
    }

    async fn dispatch(&self, dossier: &ForensicDossier) -> Result<SinkReceipt, AbuseReportError> {
        let safe_ip = crate::sanitize::scrub_ansi_and_control(&dossier.client_ip);
        let safe_method = crate::sanitize::scrub_ansi_and_control(&dossier.http_method);
        let safe_uri = crate::sanitize::scrub_ansi_and_control(&dossier.target_uri);
        let safe_field = dossier
            .trapped_field
            .as_deref()
            .map(crate::sanitize::scrub_ansi_and_control)
            .unwrap_or_else(|| "none".to_string());

        let cef = format!(
            "CEF:0|Phylax|EdgeDefense|{}|{}|{}|8|src={} requestMethod={} request={} cs1Label=HoneypotField cs1={}",
            env!("CARGO_PKG_VERSION"),
            dossier.category.name(),
            dossier.category.name(),
            safe_ip,
            safe_method,
            safe_uri,
            safe_field
        );
        tracing::warn!("🛡️ [CEF-AUDIT] {}", cef);
        Ok(SinkReceipt {
            sink_name: "SyslogCEF",
            target_identifier: safe_ip,
            detail: cef,
        })
    }
}

/// 4. MultiSink: Broadcasts incident to multiple sinks in parallel
pub struct MultiSink {
    sinks: Vec<Arc<dyn IncidentSink>>,
}

impl MultiSink {
    pub fn new(sinks: Vec<Arc<dyn IncidentSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl IncidentSink for MultiSink {
    fn name(&self) -> &'static str {
        "MultiSink"
    }

    async fn dispatch(&self, dossier: &ForensicDossier) -> Result<SinkReceipt, AbuseReportError> {
        if self.sinks.is_empty() {
            return Err(AbuseReportError::Config(
                "MultiSink has no registered sinks".to_string(),
            ));
        }

        let mut errors = Vec::new();
        let mut successes = Vec::new();

        for sink in &self.sinks {
            match sink.dispatch(dossier).await {
                Ok(receipt) => successes.push(format!("{}: {}", receipt.sink_name, receipt.detail)),
                Err(e) => {
                    tracing::warn!(
                        "⚠️ [INFORMANT-MULTISINK] Sink '{}' failed: {}",
                        sink.name(),
                        e
                    );
                    errors.push(format!("{}: {}", sink.name(), e));
                }
            }
        }

        if !successes.is_empty() {
            Ok(SinkReceipt {
                sink_name: "MultiSink",
                target_identifier: format!("{} sinks", successes.len()),
                detail: successes.join("; "),
            })
        } else {
            Err(AbuseReportError::MultiSinkFailure(errors.join("; ")))
        }
    }
}

/// 5. Mock Sink for deterministic testing
#[derive(Default)]
pub struct MockIncidentSink {
    recorded: parking_lot::Mutex<Vec<ForensicDossier>>,
}

impl MockIncidentSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recorded_dossiers(&self) -> Vec<ForensicDossier> {
        self.recorded.lock().clone()
    }
}

#[async_trait]
impl IncidentSink for MockIncidentSink {
    fn name(&self) -> &'static str {
        "MockSink"
    }

    async fn dispatch(&self, dossier: &ForensicDossier) -> Result<SinkReceipt, AbuseReportError> {
        self.recorded.lock().push(dossier.clone());
        Ok(SinkReceipt {
            sink_name: "MockSink",
            target_identifier: dossier.client_ip.clone(),
            detail: "Recorded in memory".to_string(),
        })
    }
}
