//! # Sovereign Shield Pipeline Request, Context & Verdict Types
//! Single Job: Define request payloads, client tokens, and denial/allow verdicts for `ShieldPipeline`.

use serde::{Deserialize, Serialize};

/// Request context submitted for Shield verification
#[derive(Debug, Clone, Default)]
pub struct ShieldRequest<'a> {
    pub client_ip: &'a str,
    pub submitted_fields: &'a [(String, String)],
    pub timing_token: Option<&'a str>,
    pub pow_challenge_token: Option<&'a str>,
    pub pow_nonce: Option<u64>,
    pub email: Option<&'a str>,
    pub target_uri: Option<&'a str>,
    pub http_method: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub now_ms: u64,
}

/// Client context issued to HTML/JS frontends for rendering decoy fields, timing token, and PoW puzzle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldClientContext {
    pub timing_token: String,
    pub pow_challenge: String,
    pub pow_seed: String,
    pub pow_difficulty: u8,
    pub decoy_fields: Vec<String>,
}

/// Reason for Shield denial
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenialReason {
    HoneypotTrapped { field: String },
    DecoyUriTrapped { path: String, category: String },
    SubnetBlocked { ip: String, cidr: String },
    EmailPatternSuspicious { reason: String },
    SubmissionTooFast { elapsed_ms: u64, min_ms: u64 },
    SubmissionTimingExpired,
    TimingSignatureInvalid,
    MissingTimingToken,
    PowInvalidSolution,
    PowExpired,
    PowReplayed,
    MissingPowChallenge,
}

impl DenialReason {
    pub fn public_message(&self) -> &'static str {
        match self {
            DenialReason::HoneypotTrapped { .. } => "Automated submission detected (trap tripped).",
            DenialReason::DecoyUriTrapped { .. } => {
                "Access restricted: Automated reconnaissance probe detected."
            }
            DenialReason::SubnetBlocked { .. } => {
                "Perimeter access restricted: Tor exit node or hosting datacenter."
            }
            DenialReason::EmailPatternSuspicious { .. } => "Invalid or suspicious email pattern.",
            DenialReason::SubmissionTooFast { .. } => {
                "Form submitted suspiciously fast. Please take your time."
            }
            DenialReason::SubmissionTimingExpired => {
                "Form session expired. Please refresh the page."
            }
            DenialReason::TimingSignatureInvalid => "Form verification signature mismatch.",
            DenialReason::MissingTimingToken => "Missing security timing token.",
            DenialReason::PowInvalidSolution => "Proof of work puzzle verification failed.",
            DenialReason::PowExpired => "Proof of work puzzle expired. Please reload the page.",
            DenialReason::PowReplayed => {
                "Security token has already been consumed. Please refresh."
            }
            DenialReason::MissingPowChallenge => "Missing proof of work security challenge.",
        }
    }
}

/// Verdict from Shield evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShieldVerdict {
    /// All layers passed. Genuine operator.
    Allow {
        canonical_email: Option<String>,
        elapsed_timing_ms: Option<u64>,
    },
    /// One of the defense layers failed.
    Deny(DenialReason),
}

impl ShieldVerdict {
    #[inline]
    pub fn is_allowed(&self) -> bool {
        matches!(self, ShieldVerdict::Allow { .. })
    }

    #[inline]
    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }
}
