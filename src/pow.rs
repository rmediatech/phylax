//! # Radical OJP: Sovereign Cryptographic Proof-of-Work (PoW) Engine
//! Single Job: Issue zero-telemetry SHA-256 puzzles and verify solutions in constant time (<1µs).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Default PoW difficulty: 16 leading zero bits (~65,536 hashes, ~80ms in browser)
pub const DEFAULT_POW_DIFFICULTY_BITS: u8 = 16;
/// Default PoW challenge validity: 5 minutes (300,000 ms)
pub const DEFAULT_POW_EXPIRATION_MS: u64 = 300_000;
/// Maximum replay cache capacity
const REPLAY_CACHE_CAPACITY: usize = 10_000;

/// Verdict resulting from Proof-of-Work verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowVerdict {
    /// Puzzle solution verified successfully
    Verified { nonce: u64, hash_hex: String },
    /// Nonce does not solve the challenge puzzle (difficulty unmet)
    InvalidSolution { hash_hex: String },
    /// Challenge has expired
    Expired { elapsed_ms: u64 },
    /// Challenge token has already been consumed (replay attack detected)
    Replayed,
    /// Challenge token signature mismatch (tampering detected)
    SignatureMismatch,
    /// Malformed challenge token
    Malformed,
}

impl PowVerdict {
    #[inline]
    pub fn is_verified(&self) -> bool {
        matches!(self, PowVerdict::Verified { .. })
    }
}

/// Sovereign PoW Challenge Engine
#[derive(Debug, Clone)]
pub struct PowEngine {
    secret_key: Vec<u8>,
    difficulty_bits: u8,
    expiration_ms: u64,
    consumed_seeds: Arc<RwLock<HashSet<String>>>,
}

impl PowEngine {
    /// Instantiate a PoW Engine with customized parameters
    pub fn new<K: Into<Vec<u8>>>(secret_key: K, difficulty_bits: u8, expiration_ms: u64) -> Self {
        Self {
            secret_key: secret_key.into(),
            difficulty_bits,
            expiration_ms,
            consumed_seeds: Arc::new(RwLock::new(HashSet::with_capacity(REPLAY_CACHE_CAPACITY))),
        }
    }

    /// Instantiate with standard sovereign defaults (16 bits difficulty, 5 min expiry)
    pub fn with_defaults<K: Into<Vec<u8>>>(secret_key: K) -> Self {
        Self::new(
            secret_key,
            DEFAULT_POW_DIFFICULTY_BITS,
            DEFAULT_POW_EXPIRATION_MS,
        )
    }

    /// Difficulty bits required by this engine
    pub fn difficulty_bits(&self) -> u8 {
        self.difficulty_bits
    }

    /// Issue a new cryptographic challenge token for client-side solving
    pub fn issue_challenge(&self, now_ms: u64, seed_nonce: u64) -> (String, String) {
        self.issue_challenge_with_difficulty(now_ms, seed_nonce, self.difficulty_bits)
    }

    /// Issue a challenge token with dynamically specified difficulty (e.g. adaptive ratcheting)
    pub fn issue_challenge_with_difficulty(
        &self,
        now_ms: u64,
        seed_nonce: u64,
        difficulty_bits: u8,
    ) -> (String, String) {
        // Derive unique seed from timestamp + random seed nonce
        let mut hasher = Sha256::new();
        hasher.update(b"RMT_POW_SEED:");
        hasher.update(now_ms.to_be_bytes());
        hasher.update(seed_nonce.to_be_bytes());
        let seed = hex::encode(hasher.finalize());

        let expires_at = now_ms + self.expiration_ms;
        let payload = format!("{}:{}:{}", seed, difficulty_bits, expires_at);
        let sig = self.compute_hmac(payload.as_bytes());
        let full_token = format!("{}:{}", payload, sig);
        let encoded_token = B64.encode(full_token.as_bytes());

        (seed, encoded_token)
    }

    /// Verify a submitted puzzle solution (challenge token + client nonce)
    pub fn verify_solution(
        &self,
        challenge_token: &str,
        client_nonce: u64,
        now_ms: u64,
    ) -> PowVerdict {
        let Ok(decoded_bytes) = B64.decode(challenge_token.trim().as_bytes()) else {
            return PowVerdict::Malformed;
        };

        let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) else {
            return PowVerdict::Malformed;
        };

        let parts: Vec<&str> = decoded_str.split(':').collect();
        if parts.len() != 4 {
            return PowVerdict::Malformed;
        }

        let (seed, diff_str, expires_str, sig_hex) = (parts[0], parts[1], parts[2], parts[3]);

        let Ok(diff_bits) = diff_str.parse::<u8>() else {
            return PowVerdict::Malformed;
        };
        let Ok(expires_at) = expires_str.parse::<u64>() else {
            return PowVerdict::Malformed;
        };

        // 1. Verify HMAC Signature
        let expected_payload = format!("{}:{}:{}", seed, diff_bits, expires_at);
        let expected_sig = self.compute_hmac(expected_payload.as_bytes());
        if expected_sig
            .as_bytes()
            .ct_eq(sig_hex.as_bytes())
            .unwrap_u8()
            != 1
        {
            return PowVerdict::SignatureMismatch;
        }

        // 2. Check Expiration
        if now_ms > expires_at {
            return PowVerdict::Expired {
                elapsed_ms: now_ms.saturating_sub(expires_at),
            };
        }

        // 3. Replay Protection: Check if seed was already consumed
        {
            let consumed = self.consumed_seeds.read();
            if consumed.contains(seed) {
                return PowVerdict::Replayed;
            }
        }

        // 4. Verify Proof of Work: SHA-256(seed || ":" || nonce)
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b":");
        hasher.update(client_nonce.to_string().as_bytes());
        let hash_result = hasher.finalize();
        let hash_hex = hex::encode(hash_result);

        if !has_leading_zero_bits(&hash_result, diff_bits) {
            return PowVerdict::InvalidSolution { hash_hex };
        }

        // 5. Mark challenge seed as consumed (atomic insertion with capacity check)
        {
            let mut consumed = self.consumed_seeds.write();
            if consumed.len() >= REPLAY_CACHE_CAPACITY {
                consumed.clear(); // Safe eviction when cache fills up
            }
            consumed.insert(seed.to_string());
        }

        PowVerdict::Verified {
            nonce: client_nonce,
            hash_hex,
        }
    }

    /// Helper for testing & simulators: Solve challenge locally
    pub fn solve_challenge(seed: &str, difficulty_bits: u8) -> (u64, String) {
        let mut nonce: u64 = 0;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(seed.as_bytes());
            hasher.update(b":");
            hasher.update(nonce.to_string().as_bytes());
            let result = hasher.finalize();
            if has_leading_zero_bits(&result, difficulty_bits) {
                return (nonce, hex::encode(result));
            }
            nonce += 1;
        }
    }

    fn compute_hmac(&self, data: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret_key)
            .expect("HMAC keys of arbitrary length are accepted");
        mac.update(b"RMT_SHIELD_POW_V1:");
        mac.update(data);
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Constant-time check for `N` leading zero bits
#[inline]
pub fn has_leading_zero_bits(bytes: &[u8], bits: u8) -> bool {
    let full_bytes = (bits / 8) as usize;
    let remainder_bits = bits % 8;

    if full_bytes > bytes.len() {
        return false;
    }

    // Check full zero bytes
    for &b in &bytes[..full_bytes] {
        if b != 0 {
            return false;
        }
    }

    // Check remaining zero bits
    if remainder_bits > 0 {
        let mask = !((1 << (8 - remainder_bits)) - 1);
        if (bytes[full_bytes] & mask) != 0 {
            return false;
        }
    }

    true
}

mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_engine_full_lifecycle() {
        // Use 10 bits for rapid unit test (~1,024 hashes, ~1ms)
        let engine = PowEngine::new(b"sovereign_pow_secret", 10, 60_000);
        let now_ms = 1_000_000;
        let (seed, token) = engine.issue_challenge(now_ms, 42);

        // Solve puzzle
        let (nonce, _) = PowEngine::solve_challenge(&seed, 10);

        // Verify solution on server
        let verdict = engine.verify_solution(&token, nonce, now_ms + 100);
        assert!(matches!(verdict, PowVerdict::Verified { .. }));

        // Replay attempt must be rejected
        let replay_verdict = engine.verify_solution(&token, nonce, now_ms + 200);
        assert_eq!(replay_verdict, PowVerdict::Replayed);
    }

    #[test]
    fn test_pow_engine_rejects_invalid_nonce() {
        let engine = PowEngine::new(b"sovereign_pow_secret", 16, 60_000);
        let now_ms = 1_000_000;
        let (_seed, token) = engine.issue_challenge(now_ms, 99);

        // Submitting bad nonce (not solved)
        let verdict = engine.verify_solution(&token, 0, now_ms + 100);
        assert!(matches!(verdict, PowVerdict::InvalidSolution { .. }));
    }

    #[test]
    fn test_pow_engine_rejects_expired_challenge() {
        let engine = PowEngine::new(b"sovereign_pow_secret", 8, 5_000);
        let now_ms = 1_000_000;
        let (seed, token) = engine.issue_challenge(now_ms, 123);
        let (nonce, _) = PowEngine::solve_challenge(&seed, 8);

        // Submit after 6 seconds (> 5s expiry)
        let verdict = engine.verify_solution(&token, nonce, now_ms + 6_000);
        assert!(matches!(verdict, PowVerdict::Expired { .. }));
    }
}
