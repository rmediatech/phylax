//! # Collaborative Abuse Intelligence & Automated Incident Reporting
//!
//! Autonomous reporting to upstream threat intelligence platforms (AbuseIPDB, RDAP, X-ARF)
//! for honeypot intrusions, credential stuffing, scraping, and volumetric DDoS.
//! Provides opt-in controls, dry-run simulation mode, and per-IP sliding-window cooldowns.

pub mod abuseipdb;
pub mod category;
pub mod config;
pub mod cooldown;
pub mod dossier;
pub mod error;
pub mod pipeline;
pub mod rdap;
pub mod sink;
pub mod transport;

pub use abuseipdb::{AbuseIpDbCheckResponse, AbuseIpDbReportPayload, AbuseIpDbResponse};
pub use category::AbuseCategory;
pub use cooldown::{CooldownConfig, ReportCooldownGovernor};
pub use dossier::{DossierFormatter, ForensicDossier};
pub use error::{AbuseReportError, RdapError};
pub use pipeline::{InformantConfig, InformantEngine, InformantVerdict};
pub use rdap::{RdapContact, RdapParser};
pub use sink::{
    AbuseIpDbSink, GenericWebhookSink, IncidentSink, MockIncidentSink, MultiSink, SinkReceipt,
    SyslogCefSink,
};
pub use transport::{
    AbuseReporterTransport, HttpAbuseReporterTransport, MockAbuseReporterTransport,
};
