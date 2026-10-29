//! # Phylax (φύλαξ) — Sovereign Anti-Bot & Threat Neutralization Engine
//!
//! High-throughput, zero-telemetry, memory-safe defense suite for enterprise edge architectures.
//! Enforces a strict 15-layer cost-hierarchical fail-fast defense:
//! - Layer 0: Autonomous Radix CIDR Quarantine (`autonomous_quarantine`)
//! - Layer 0.5: Decoy URI Honeyroute Sentinel (`decoy_uri`)
//! - Layer 1: Cryptographic Honeypot Traps (`honeypot`)
//! - Layer 2: Radix CIDR Datacenter & Tor Exit Node Perimeter Filtering (`subnet_guard`)
//! - Layer 3: Bot Email Dot-Scattering & Disposable Domain Sanitization (`email_guard`)
//! - Layer 4: Tamper-Proof HMAC Submission Timing Defense (`timing`)
//! - Layer 5: Sub-microsecond SHA-256 Proof-of-Work (PoW) Verification (`pow` / `adaptive_pow`)
//! - Layer 6: Leaked Credential Bloom Filter (`credential_guard`)
//! - Layer 7: Target-Account Velocity Shield (`credential_guard`)
//! - Layer 8: Session Hijacking & Impossible Travel Sentinel (`session_sentinel`)
//! - Layer 9: WebRTC / Coturn Relay Bandwidth Leeching Guard (`turn_guard`)
//! - Layer 10: Binary Download Voucher & Byte-Range Abuse Guard (`dist_guard`)
//! - Layer 11: L7 Stream & Slowloris Protection Guard (`stream_guard`)
//! - Layer 12: Zero-Lock In-Memory Cache Shield (`cache_shield`)
//! - Layer 13: Autonomous Zero-Day & Emerging Threat Harvester (`threat_harvester`)
//! - Layer 14: Sovereign Bot Guard & User-Agent Interception (`bot_guard`)
//! - Layer 15: Adversarial Exploit & Traversal Payload Guard (`payload_guard`)

pub mod adaptive_pow;
pub mod autonomous_quarantine;
pub mod bot_guard;
pub mod cache_shield;
pub mod credential_guard;
pub mod decoy_uri;
pub mod dist_guard;
pub mod email_guard;
pub mod honeypot;
pub mod maintenance;
pub mod payload_guard;
pub mod pipeline;
pub mod pow;
pub mod sanitize;
pub mod session_sentinel;
pub mod stream_guard;
pub mod subnet_guard;
pub mod tarpit;
pub mod threat_harvester;
pub mod threat_intel;
pub mod timing;
pub mod toll_guard;
pub mod turn_guard;

#[cfg(feature = "abuse-reporting")]
pub mod abuse_reporting;

pub use adaptive_pow::{AdaptivePowConfig, AdaptivePowEngine, InfractionSeverity};
pub use autonomous_quarantine::{AutonomousQuarantine, QuarantineConfig};
pub use bot_guard::{
    BotCategory, BotGuard, BotVerdict, DynamicBotRecord, DynamicBotRegistry, AI_SCRAPER_SIGNATURES,
    AUTOMATION_TOOL_SIGNATURES, LEGITIMATE_SEARCH_SIGNATURES, RECON_SCANNER_SIGNATURES,
};
pub use cache_shield::{CacheShield, CacheShieldConfig, CacheVerdict, CachedResponse};
pub use credential_guard::{BreachedPasswordBloomFilter, CredentialGuard, CredentialVerdict};
pub use decoy_uri::{DecoyCategory, DecoyUriConfig, DecoyUriSentinel, DecoyUriVerdict};
pub use dist_guard::{DistGuard, DistGuardConfig, DistVerdict};
pub use email_guard::{EmailPatternGuard, EmailVerdict};
pub use honeypot::{HoneypotValidator, HoneypotVerdict};
pub use maintenance::{MaintenanceManager, MaintenanceReport};
pub use payload_guard::{AdversarialPayload, PayloadGuard};
pub use pipeline::{
    DenialReason, PhylaxClientContext, PhylaxPipeline, PhylaxPipelineBuilder, PhylaxRequest,
    PhylaxVerdict, ShieldClientContext, ShieldPipeline, ShieldPipelineBuilder, ShieldRequest,
    ShieldVerdict,
};
pub use pow::{PowEngine, PowVerdict};
pub use session_sentinel::{
    GeoCoordinate, SessionCheckpoint, SessionSentinel, SessionSentinelConfig, SessionVerdict,
};
pub use stream_guard::{RouteCategory, StreamGuard, StreamGuardConfig, StreamVerdict};
pub use subnet_guard::{IpRiskCategory, SubnetGuard, SubnetVerdict};
pub use tarpit::{TarpitConfig, TarpitGovernor, TarpitSlotGuard, TarpitVerdict};
pub use threat_harvester::{
    CandidatePathRecord, PromotionVerdict, SubnetKey, ThreatHarvesterConfig, ThreatHarvesterEngine,
};
pub use timing::{TimingGuard, TimingVerdict};
pub use toll_guard::{TollGuard, TollGuardConfig, TollVerdict};
pub use turn_guard::{TurnCredentials, TurnGuard, TurnGuardConfig, TurnVerdict};

#[cfg(feature = "abuse-reporting")]
pub use abuse_reporting::{
    AbuseCategory, AbuseIpDbCheckResponse, AbuseIpDbReportPayload, AbuseIpDbResponse,
    AbuseReportError, CooldownConfig, DossierFormatter, ForensicDossier, InformantConfig,
    InformantEngine, InformantVerdict, ReportCooldownGovernor,
};

/// Universal prelude for convenient drop-in integration
pub mod prelude {
    pub use crate::adaptive_pow::{AdaptivePowConfig, AdaptivePowEngine, InfractionSeverity};
    pub use crate::autonomous_quarantine::{AutonomousQuarantine, QuarantineConfig};
    pub use crate::cache_shield::CacheShield;
    pub use crate::credential_guard::{BreachedPasswordBloomFilter, CredentialGuard};
    pub use crate::dist_guard::DistGuard;
    pub use crate::email_guard::EmailPatternGuard;
    pub use crate::honeypot::HoneypotValidator;
    pub use crate::pipeline::{
        DenialReason, PhylaxClientContext, PhylaxPipeline, PhylaxPipelineBuilder, PhylaxRequest,
        PhylaxVerdict, ShieldClientContext, ShieldPipeline, ShieldRequest, ShieldVerdict,
    };
    pub use crate::pow::PowEngine;
    pub use crate::session_sentinel::{GeoCoordinate, SessionSentinel};
    pub use crate::stream_guard::{RouteCategory, StreamGuard};
    pub use crate::subnet_guard::SubnetGuard;
    pub use crate::threat_harvester::{ThreatHarvesterConfig, ThreatHarvesterEngine};
    pub use crate::timing::TimingGuard;
    pub use crate::toll_guard::TollGuard;
    pub use crate::turn_guard::TurnGuard;
}
