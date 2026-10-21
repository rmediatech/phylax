//! # Sovereign Shield Pipeline Builder
//! Single Job: Fluent builder constructing a composable `ShieldPipeline` with custom or default layer configs.

use crate::adaptive_pow::{AdaptivePowConfig, AdaptivePowEngine};
use crate::autonomous_quarantine::{AutonomousQuarantine, QuarantineConfig};
use crate::decoy_uri::{DecoyUriConfig, DecoyUriSentinel};
use crate::email_guard::EmailPatternGuard;
use crate::honeypot::HoneypotValidator;
use crate::pipeline::ShieldPipeline;
use crate::pow::PowEngine;
use crate::subnet_guard::SubnetGuard;
use crate::tarpit::{TarpitConfig, TarpitGovernor};
use crate::timing::TimingGuard;
#[cfg(feature = "abuse-reporting")]
use std::sync::Arc;

/// Builder for sovereign Shield pipeline
pub struct ShieldPipelineBuilder {
    secret_key: Vec<u8>,
    decoy_fields: Option<Vec<String>>,
    timing_min_ms: u64,
    timing_max_ms: u64,
    pow_difficulty: u8,
    pow_expiration_ms: u64,
    max_email_dots: usize,
    enable_pow: bool,
    enable_timing: bool,
    enable_subnet: bool,
    tarpit_config: TarpitConfig,
    adaptive_pow_config: AdaptivePowConfig,
    quarantine_config: QuarantineConfig,
    decoy_uri_config: DecoyUriConfig,
    threat_harvester_config: crate::threat_harvester::ThreatHarvesterConfig,
    #[cfg(feature = "abuse-reporting")]
    informant: Option<Arc<crate::abuse_reporting::InformantEngine>>,
}

impl Default for ShieldPipelineBuilder {
    fn default() -> Self {
        Self {
            secret_key: b"rmt_default_shield_secret_key_2026".to_vec(),
            decoy_fields: None,
            timing_min_ms: 2000,
            timing_max_ms: 86_400_000,
            pow_difficulty: 16,
            pow_expiration_ms: 300_000,
            max_email_dots: 3,
            enable_pow: true,
            enable_timing: true,
            enable_subnet: true,
            tarpit_config: TarpitConfig::default(),
            adaptive_pow_config: AdaptivePowConfig::default(),
            quarantine_config: QuarantineConfig::default(),
            decoy_uri_config: DecoyUriConfig::default(),
            threat_harvester_config: crate::threat_harvester::ThreatHarvesterConfig::default(),
            #[cfg(feature = "abuse-reporting")]
            informant: None,
        }
    }
}

impl ShieldPipelineBuilder {
    pub fn secret_key<K: Into<Vec<u8>>>(mut self, key: K) -> Self {
        self.secret_key = key.into();
        self
    }

    pub fn with_honeypot_fields<I, S>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.decoy_fields = Some(fields.into_iter().map(Into::into).collect());
        self
    }

    pub fn with_timing(mut self, min_ms: u64, max_ms: u64) -> Self {
        self.timing_min_ms = min_ms;
        self.timing_max_ms = max_ms;
        self.enable_timing = true;
        self
    }

    pub fn with_pow(mut self, difficulty_bits: u8, expiration_ms: u64) -> Self {
        self.pow_difficulty = difficulty_bits;
        self.pow_expiration_ms = expiration_ms;
        self.enable_pow = true;
        self
    }

    pub fn with_tarpit(mut self, config: TarpitConfig) -> Self {
        self.tarpit_config = config;
        self
    }

    pub fn with_adaptive_pow(mut self, config: AdaptivePowConfig) -> Self {
        self.adaptive_pow_config = config;
        self
    }

    pub fn with_quarantine(mut self, config: QuarantineConfig) -> Self {
        self.quarantine_config = config;
        self
    }

    /// Configure the Decoy URI Reconnaissance Sentinel
    pub fn with_decoy_uris(mut self, config: DecoyUriConfig) -> Self {
        self.decoy_uri_config = config;
        self
    }

    pub fn enable_pow(mut self, enabled: bool) -> Self {
        self.enable_pow = enabled;
        self
    }

    pub fn enable_timing(mut self, enabled: bool) -> Self {
        self.enable_timing = enabled;
        self
    }

    pub fn enable_subnet_guard(mut self, enabled: bool) -> Self {
        self.enable_subnet = enabled;
        self
    }

    #[cfg(feature = "abuse-reporting")]
    /// Configure autonomous abuse reporting with the provided InformantConfig
    pub fn with_abuse_reporting(mut self, config: crate::abuse_reporting::InformantConfig) -> Self {
        self.informant = Some(Arc::new(
            crate::abuse_reporting::InformantEngine::with_http_transport(config),
        ));
        self
    }

    #[cfg(feature = "abuse-reporting")]
    /// Automatically discovers AbuseIPDB credentials and activates live automated reporting
    pub fn with_default_abuse_reporting(mut self) -> Self {
        let conf = crate::abuse_reporting::InformantConfig::from_env_or_default();
        if conf.enabled {
            self.informant = Some(Arc::new(
                crate::abuse_reporting::InformantEngine::with_http_transport(conf),
            ));
        }
        self
    }

    #[cfg(feature = "abuse-reporting")]
    /// Attach an existing InformantEngine instance
    pub fn with_informant_engine(
        mut self,
        informant: Arc<crate::abuse_reporting::InformantEngine>,
    ) -> Self {
        self.informant = Some(informant);
        self
    }

    pub fn with_threat_harvester(
        mut self,
        config: crate::threat_harvester::ThreatHarvesterConfig,
    ) -> Self {
        self.threat_harvester_config = config;
        self
    }

    pub fn build(self) -> ShieldPipeline {
        let honeypot = match self.decoy_fields {
            Some(fields) => HoneypotValidator::new(fields),
            None => HoneypotValidator::default(),
        };

        let timing = TimingGuard::new(&*self.secret_key, self.timing_min_ms, self.timing_max_ms);
        let pow = PowEngine::new(&*self.secret_key, self.pow_difficulty, self.pow_expiration_ms);
        let email_guard = EmailPatternGuard::new(self.max_email_dots);
        let subnet_guard = SubnetGuard::default();
        let tarpit = TarpitGovernor::new(self.tarpit_config);
        let adaptive_pow = AdaptivePowEngine::new(self.adaptive_pow_config);
        let quarantine = AutonomousQuarantine::new(self.quarantine_config);
        let decoy_uri = DecoyUriSentinel::new(self.decoy_uri_config);
        let threat_harvester = crate::threat_harvester::ThreatHarvesterEngine::new(
            self.threat_harvester_config,
            decoy_uri.clone(),
        );

        ShieldPipeline {
            honeypot,
            timing,
            pow,
            email_guard,
            subnet_guard,
            tarpit,
            adaptive_pow,
            quarantine,
            decoy_uri,
            threat_harvester,
            enable_pow: self.enable_pow,
            enable_timing: self.enable_timing,
            enable_subnet: self.enable_subnet,
            #[cfg(feature = "abuse-reporting")]
            informant: self.informant,
        }
    }
}
