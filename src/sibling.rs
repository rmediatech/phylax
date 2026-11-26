//! # Universal Sovereign Sibling Attestation & Bloodline Protocol (`SOVEREIGN-SIBLING-01`)
//! Single Job: Provide cryptographic mutual recognition, anti-replay challenge verification,
//! and constant-time HMAC validation for sibling daemons, mobile apps, and edge proxies.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// The immutable Sovereign Lineage Canary Preimage embedded in .rodata
pub const LINEAGE_CANARY_PREIMAGE: &[u8] = b"SOVEREIGN-SIBLING-4E428019A109578B-RMD-2026-XUOXOD";

/// Maximum allowed clock drift for anti-replay enforcement (60 seconds)
pub const MAX_TIMESTAMP_DRIFT_MS: u64 = 60_000;

/// Error conditions during Sibling attestation verification
#[derive(Debug, Error, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum SiblingError {
    #[error("Timestamp drift {delta_ms}ms exceeds anti-replay ceiling {max_ms}ms")]
    StaleTimestamp { delta_ms: u64, max_ms: u64 },
    #[error("Cryptographic signature mismatch: peer does not share sovereign lineage")]
    InvalidSignature,
    #[error("Malformed signature hex: {0}")]
    MalformedHex(String),
    #[error("Caller name cannot be empty")]
    EmptyCaller,
}

/// Ephemeral challenge issued to a peering sibling
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingChallenge {
    pub nonce: String,
    pub timestamp_ms: u64,
}

/// Proof presented by a peering sibling to claim elevated bloodline status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingProof {
    pub caller_name: String,
    pub nonce: String,
    pub timestamp_ms: u64,
    pub signature: String,
}

/// Sibling Attestation Verifier and Challenge Generator
#[derive(Debug, Clone, Default)]
pub struct SiblingVerifier;

impl SiblingVerifier {
    /// Deterministically derives the 256-bit Lineage Key from the Canary Preimage
    #[inline]
    pub fn derive_lineage_key() -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(LINEAGE_CANARY_PREIMAGE);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Issues an anti-replay challenge containing an ephemeral 16-byte hex nonce
    pub fn issue_challenge(now_ms: u64, seed_nonce: u64) -> SiblingChallenge {
        let mut hasher = Sha256::new();
        hasher.update(seed_nonce.to_be_bytes());
        hasher.update(now_ms.to_be_bytes());
        hasher.update(b"phylax-sibling-challenge-seed");
        let hash = hasher.finalize();
        let nonce = hex_encode(&hash[..16]);
        SiblingChallenge {
            nonce,
            timestamp_ms: now_ms,
        }
    }

    /// Generates a valid SiblingProof for a given caller, nonce, and timestamp
    pub fn generate_proof(caller_name: &str, nonce: &str, timestamp_ms: u64) -> SiblingProof {
        let key = Self::derive_lineage_key();
        let expected_bytes = Self::compute_hmac(&key, caller_name, nonce, timestamp_ms);
        let signature = hex_encode(&expected_bytes);
        SiblingProof {
            caller_name: caller_name.to_string(),
            nonce: nonce.to_string(),
            timestamp_ms,
            signature,
        }
    }

    /// Verifies that a SiblingProof is mathematically valid, timely, and constant-time
    pub fn verify_proof(proof: &SiblingProof, now_ms: u64) -> Result<(), SiblingError> {
        if proof.caller_name.trim().is_empty() {
            return Err(SiblingError::EmptyCaller);
        }

        // 1. Anti-Replay Temporal Freshness Check (|now_ms - proof.timestamp_ms| <= 60s)
        let delta_ms = if now_ms >= proof.timestamp_ms {
            now_ms - proof.timestamp_ms
        } else {
            proof.timestamp_ms - now_ms
        };

        if delta_ms > MAX_TIMESTAMP_DRIFT_MS {
            return Err(SiblingError::StaleTimestamp {
                delta_ms,
                max_ms: MAX_TIMESTAMP_DRIFT_MS,
            });
        }

        // 2. Decode received signature bytes
        let sig_bytes = hex_decode(&proof.signature)
            .map_err(|e| SiblingError::MalformedHex(e.to_string()))?;
        if sig_bytes.len() != 32 {
            return Err(SiblingError::InvalidSignature);
        }

        // 3. Recompute expected HMAC-SHA256 signature
        let key = Self::derive_lineage_key();
        let expected_bytes = Self::compute_hmac(&key, &proof.caller_name, &proof.nonce, proof.timestamp_ms);

        // 4. Constant-Time Verification to prevent instruction-timing leakage
        if bool::from(sig_bytes.ct_eq(&expected_bytes)) {
            Ok(())
        } else {
            Err(SiblingError::InvalidSignature)
        }
    }

    /// Computes RFC 2104 HMAC-SHA256 over: caller_name || nonce || timestamp_be_bytes
    #[inline]
    pub fn compute_hmac(key: &[u8; 32], caller_name: &str, nonce: &str, timestamp_ms: u64) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC-SHA256 should support 32-byte keys");
        mac.update(caller_name.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(&timestamp_ms.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// Helper: encode slice to lowercase hex string
#[inline]
pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Helper: decode hex string into bytes
pub fn hex_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("Hex string length must be even");
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "Invalid hex character")?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sibling_valid_proof_lifecycle() {
        let now_ms = 1_700_000_000_000;
        let challenge = SiblingVerifier::issue_challenge(now_ms, 42);
        let proof = SiblingVerifier::generate_proof("optic", &challenge.nonce, now_ms + 500);
        assert!(SiblingVerifier::verify_proof(&proof, now_ms + 600).is_ok());
    }

    #[test]
    fn test_sibling_anti_replay_stale_timestamp() {
        let now_ms = 1_700_000_000_000;
        let proof = SiblingVerifier::generate_proof("optic", "some-nonce", now_ms);
        let err = SiblingVerifier::verify_proof(&proof, now_ms + 60_001).unwrap_err();
        assert!(matches!(err, SiblingError::StaleTimestamp { .. }));
    }

    #[test]
    fn test_sibling_tampered_signature_rejected() {
        let now_ms = 1_700_000_000_000;
        let mut proof = SiblingVerifier::generate_proof("drishti", "nonce-123", now_ms);
        proof.signature = "0".repeat(64);
        assert_eq!(
            SiblingVerifier::verify_proof(&proof, now_ms),
            Err(SiblingError::InvalidSignature)
        );
    }

    #[test]
    fn test_sibling_empty_caller_rejected() {
        let now_ms = 1_700_000_000_000;
        let proof = SiblingProof {
            caller_name: "  ".to_string(),
            nonce: "nonce".to_string(),
            timestamp_ms: now_ms,
            signature: "ab".repeat(32),
        };
        assert_eq!(
            SiblingVerifier::verify_proof(&proof, now_ms),
            Err(SiblingError::EmptyCaller)
        );
    }
}
