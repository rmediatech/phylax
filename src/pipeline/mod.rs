//! # Radical OJP: Composable Fail-Fast Shield Pipeline
//! Single Job: Chain all isolated defense layers into a unified, zero-overhead pipeline.

pub mod builder;
pub mod types;
pub use builder::ShieldPipelineBuilder;
pub use types::{DenialReason, ShieldClientContext, ShieldRequest, ShieldVerdict};

use crate::adaptive_pow::{AdaptivePowEngine, InfractionSeverity};
use crate::autonomous_quarantine::AutonomousQuarantine;
use crate::decoy_uri::{DecoyUriSentinel, DecoyUriVerdict};
use crate::email_guard::{EmailPatternGuard, EmailVerdict};
use crate::honeypot::{HoneypotValidator, HoneypotVerdict};
use crate::pow::{PowEngine, PowVerdict};
use crate::subnet_guard::{SubnetGuard, SubnetVerdict};
use crate::tarpit::TarpitGovernor;
use crate::timing::{TimingGuard, TimingVerdict};
#[cfg(feature = "abuse-reporting")]
use std::sync::Arc;

/// Composable Sovereign Shield Pipeline
#[derive(Debug, Clone)]
pub struct ShieldPipeline {
    pub(crate) honeypot: HoneypotValidator,
    pub(crate) timing: TimingGuard,
    pub(crate) pow: PowEngine,
    pub(crate) email_guard: EmailPatternGuard,
    pub(crate) subnet_guard: SubnetGuard,
    pub(crate) tarpit: TarpitGovernor,
    pub(crate) adaptive_pow: AdaptivePowEngine,
    pub(crate) quarantine: AutonomousQuarantine,
    pub(crate) decoy_uri: DecoyUriSentinel,
    pub(crate) threat_harvester: crate::threat_harvester::ThreatHarvesterEngine,
    pub(crate) enable_pow: bool,
    pub(crate) enable_timing: bool,
    pub(crate) enable_subnet: bool,
    #[cfg(feature = "abuse-reporting")]
    pub(crate) informant: Option<Arc<crate::abuse_reporting::InformantEngine>>,
}

#[rustfmt::skip]
impl ShieldPipeline {
    pub fn builder() -> ShieldPipelineBuilder { ShieldPipelineBuilder::default() }
    pub fn decoy_uri(&self) -> &DecoyUriSentinel { &self.decoy_uri }
    pub fn threat_harvester(&self) -> &crate::threat_harvester::ThreatHarvesterEngine { &self.threat_harvester }
    pub fn record_anomalous_uri(&self, raw_path: &str, client_ip: std::net::IpAddr, now_ms: u64) -> Option<crate::threat_harvester::PromotionVerdict> {
        self.threat_harvester.ingest_anomalous_uri(raw_path, client_ip, now_ms)
    }
    pub fn record_anomalous_uri_str(&self, raw_path: &str, client_ip_str: &str, now_ms: u64) -> Option<crate::threat_harvester::PromotionVerdict> {
        self.threat_harvester.ingest_anomalous_uri_str(raw_path, client_ip_str, now_ms)
    }
    pub fn tarpit(&self) -> &TarpitGovernor { &self.tarpit }
    pub fn adaptive_pow(&self) -> &AdaptivePowEngine { &self.adaptive_pow }
    pub fn quarantine(&self) -> &AutonomousQuarantine { &self.quarantine }
    pub fn maintenance_manager(&self) -> crate::maintenance::MaintenanceManager {
        crate::maintenance::MaintenanceManager::new(self.quarantine.clone(), self.adaptive_pow.clone())
            .with_threat_harvester(self.threat_harvester.clone())
    }
    pub fn run_maintenance(&self, now_ms: u64) -> crate::maintenance::MaintenanceReport {
        self.maintenance_manager().run_maintenance(now_ms)
    }
    pub fn spawn_background_maintenance(&self, interval: std::time::Duration) -> tokio::task::JoinHandle<()> {
        self.maintenance_manager().spawn_background_worker(interval)
    }
    #[cfg(feature = "abuse-reporting")]
    pub fn informant(&self) -> Option<&Arc<crate::abuse_reporting::InformantEngine>> { self.informant.as_ref() }
}

impl ShieldPipeline {
    pub fn issue_client_context(&self, now_ms: u64, seed_nonce: u64) -> ShieldClientContext {
        self.issue_client_context_for_ip("", now_ms, seed_nonce)
    }

    pub fn issue_client_context_for_ip(
        &self,
        ip: &str,
        now_ms: u64,
        seed_nonce: u64,
    ) -> ShieldClientContext {
        let timing_token = self.timing.generate_token(now_ms);
        let difficulty = if ip.is_empty() {
            self.pow.difficulty_bits()
        } else {
            self.adaptive_pow.get_difficulty(ip, now_ms) as u8
        };
        let (pow_seed, pow_challenge) = self
            .pow
            .issue_challenge_with_difficulty(now_ms, seed_nonce, difficulty);
        ShieldClientContext {
            timing_token,
            pow_challenge,
            pow_seed,
            pow_difficulty: difficulty,
            decoy_fields: self.honeypot.decoy_fields().to_vec(),
        }
    }

    pub fn evaluate(&self, req: &ShieldRequest) -> ShieldVerdict {
        self.evaluate_flexible(req, self.enable_timing, self.enable_pow)
    }

    pub fn evaluate_perimeter(&self, req: &ShieldRequest) -> ShieldVerdict {
        self.evaluate_flexible(req, false, false)
    }

    pub fn evaluate_flexible(
        &self,
        req: &ShieldRequest,
        require_timing: bool,
        require_pow: bool,
    ) -> ShieldVerdict {
        if !req.client_ip.is_empty() && self.quarantine.is_quarantined(req.client_ip, req.now_ms) {
            return ShieldVerdict::Deny(DenialReason::SubnetBlocked {
                ip: req.client_ip.to_string(),
                cidr: "autonomous_quarantine".to_string(),
            });
        }

        if let Some(target_uri) = req.target_uri {
            if let DecoyUriVerdict::Trapped {
                matched_path,
                category,
            } = self.decoy_uri.evaluate(target_uri)
            {
                if !req.client_ip.is_empty() {
                    self.quarantine.record_and_check(req.client_ip, req.now_ms);
                    self.adaptive_pow.record_infraction(
                        req.client_ip,
                        InfractionSeverity::Hostile,
                        req.now_ms,
                    );
                    #[cfg(feature = "abuse-reporting")]
                    if let Some(ref informant) = self.informant {
                        let dossier = crate::abuse_reporting::ForensicDossier {
                            client_ip: req.client_ip.to_string(),
                            timestamp_ms: req.now_ms,
                            target_uri: target_uri.to_string(),
                            http_method: req.http_method.unwrap_or("GET").to_string(),
                            category: crate::abuse_reporting::AbuseCategory::ExploitProbe,
                            trapped_field: None,
                            user_agent: req.user_agent.map(|s| s.to_string()),
                            evidence_notes: format!(
                                "Phylax autonomous decoy URI probe trapped on path '{}' ({})",
                                matched_path,
                                category.name()
                            ),
                        };
                        let informant_cloned = informant.clone();
                        tokio::spawn(async move {
                            informant_cloned.process_incident(&dossier).await;
                        });
                    }
                }
                return ShieldVerdict::Deny(DenialReason::DecoyUriTrapped {
                    path: matched_path,
                    category: category.name().to_string(),
                });
            }
        }

        if let HoneypotVerdict::Trapped { field_name, .. } =
            self.honeypot.validate(req.submitted_fields)
        {
            if !req.client_ip.is_empty() {
                self.quarantine.record_and_check(req.client_ip, req.now_ms);
                self.adaptive_pow.record_infraction(
                    req.client_ip,
                    InfractionSeverity::Severe,
                    req.now_ms,
                );
                #[cfg(feature = "abuse-reporting")]
                if let Some(ref informant) = self.informant {
                    let dossier = crate::abuse_reporting::ForensicDossier {
                        client_ip: req.client_ip.to_string(),
                        timestamp_ms: req.now_ms,
                        target_uri: req.target_uri.unwrap_or("/").to_string(),
                        http_method: req.http_method.unwrap_or("POST").to_string(),
                        category: crate::abuse_reporting::AbuseCategory::WebHoneypot,
                        trapped_field: Some(field_name.clone()),
                        user_agent: req.user_agent.map(|s| s.to_string()),
                        evidence_notes: format!(
                            "Phylax autonomous honeypot trap tripped on hidden decoy field '{}'",
                            field_name
                        ),
                    };
                    let informant_cloned = informant.clone();
                    tokio::spawn(async move {
                        informant_cloned.process_incident(&dossier).await;
                    });
                }
            }
            return ShieldVerdict::Deny(DenialReason::HoneypotTrapped { field: field_name });
        }

        if self.enable_subnet && !req.client_ip.is_empty() {
            if let SubnetVerdict::Blocked { ip, matched_cidr } =
                self.subnet_guard.check_ip(req.client_ip)
            {
                self.adaptive_pow.record_infraction(
                    req.client_ip,
                    InfractionSeverity::Hostile,
                    req.now_ms,
                );
                return ShieldVerdict::Deny(DenialReason::SubnetBlocked {
                    ip,
                    cidr: matched_cidr,
                });
            }
        }

        let mut canonical_email = None;
        if let Some(raw_email) = req.email {
            match self.email_guard.inspect(raw_email) {
                EmailVerdict::Clean { canonical } => canonical_email = Some(canonical),
                EmailVerdict::DisposableDomain { domain } => {
                    return ShieldVerdict::Deny(DenialReason::EmailPatternSuspicious {
                        reason: format!("Disposable throwaway domain '{}' is prohibited", domain),
                    });
                }
                EmailVerdict::ExcessiveDotScattering { raw_local } => {
                    return ShieldVerdict::Deny(DenialReason::EmailPatternSuspicious {
                        reason: format!("Suspicious bot dot-scattering pattern in '{}'", raw_local),
                    });
                }
                EmailVerdict::Malformed => {
                    return ShieldVerdict::Deny(DenialReason::EmailPatternSuspicious {
                        reason: "Malformed email address syntax".to_string(),
                    });
                }
            }
        }

        let mut elapsed_timing_ms = None;
        if require_timing {
            let Some(token) = req.timing_token else {
                return ShieldVerdict::Deny(DenialReason::MissingTimingToken);
            };
            match self.timing.verify_token(token, req.now_ms) {
                TimingVerdict::Valid { elapsed_ms } => elapsed_timing_ms = Some(elapsed_ms),
                TimingVerdict::TooFast { elapsed_ms, min_ms } => {
                    return ShieldVerdict::Deny(DenialReason::SubmissionTooFast {
                        elapsed_ms,
                        min_ms,
                    });
                }
                TimingVerdict::Expired { .. } => {
                    return ShieldVerdict::Deny(DenialReason::SubmissionTimingExpired)
                }
                TimingVerdict::SignatureMismatch | TimingVerdict::Malformed => {
                    return ShieldVerdict::Deny(DenialReason::TimingSignatureInvalid);
                }
            }
        }

        if require_pow {
            let Some(token) = req.pow_challenge_token else {
                return ShieldVerdict::Deny(DenialReason::MissingPowChallenge);
            };
            let Some(nonce) = req.pow_nonce else {
                return ShieldVerdict::Deny(DenialReason::PowInvalidSolution);
            };
            match self.pow.verify_solution(token, nonce, req.now_ms) {
                PowVerdict::Verified { .. } => {}
                PowVerdict::InvalidSolution { .. } => {
                    return ShieldVerdict::Deny(DenialReason::PowInvalidSolution)
                }
                PowVerdict::Expired { .. } => return ShieldVerdict::Deny(DenialReason::PowExpired),
                PowVerdict::Replayed => return ShieldVerdict::Deny(DenialReason::PowReplayed),
                PowVerdict::SignatureMismatch | PowVerdict::Malformed => {
                    return ShieldVerdict::Deny(DenialReason::PowInvalidSolution);
                }
            }
        }

        ShieldVerdict::Allow {
            canonical_email,
            elapsed_timing_ms,
        }
    }
}

impl Default for ShieldPipeline {
    fn default() -> Self {
        Self::builder().build()
    }
}

pub type PhylaxPipeline = ShieldPipeline;
pub type PhylaxPipelineBuilder = ShieldPipelineBuilder;
pub type PhylaxRequest<'a> = ShieldRequest<'a>;
pub type PhylaxVerdict = ShieldVerdict;
pub type PhylaxClientContext = ShieldClientContext;
