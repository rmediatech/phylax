//! # Radical OJP: WebRTC / Coturn Relay Bandwidth Leeching Guard
//! Single Job: Mint and validate ephemeral time-bounded HMAC TURN credentials and enforce relay allocation quotas.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Ephemeral TURN credentials issued to authorized WebRTC peers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnCredentials {
    pub username: String,
    pub credential: String,
    pub ttl_seconds: u64,
    pub expires_at: u64,
    pub uris: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TurnVerdict {
    Authorized {
        user_id: String,
        expires_at: u64,
    },
    Expired {
        expired_at: u64,
        now_s: u64,
    },
    ExcessiveTtl {
        requested_ttl_s: u64,
        max_ttl_s: u64,
    },
    SignatureMismatch,
    MalformedCredential,
    ConcurrentLimitExceeded {
        user_id: String,
        active: u32,
        limit: u32,
    },
}

impl TurnVerdict {
    #[inline]
    pub fn is_authorized(&self) -> bool {
        matches!(self, TurnVerdict::Authorized { .. })
    }

    pub fn public_message(&self) -> &'static str {
        match self {
            TurnVerdict::Authorized { .. } => "Relay authorized.",
            TurnVerdict::Expired { .. } => "Relay credentials expired. Please re-negotiate ICE.",
            TurnVerdict::ExcessiveTtl { .. } => "Excessive relay TTL requested.",
            TurnVerdict::SignatureMismatch => "Invalid relay authentication signature.",
            TurnVerdict::MalformedCredential => "Malformed relay credential.",
            TurnVerdict::ConcurrentLimitExceeded { .. } => {
                "Maximum concurrent WebRTC relay connections exceeded for this account."
            }
        }
    }
}

/// Configuration for TURN Relay Guard
#[derive(Debug, Clone)]
pub struct TurnGuardConfig {
    pub default_ttl_s: u64,
    pub max_ttl_s: u64,
    pub max_concurrent_relays_per_user: u32,
    pub relay_server_uris: Vec<String>,
}

impl Default for TurnGuardConfig {
    fn default() -> Self {
        Self {
            default_ttl_s: 600, // 10 minutes
            max_ttl_s: 3600,    // 1 hour max
            max_concurrent_relays_per_user: 5,
            relay_server_uris: vec![
                "turn:turn.rmediatech.com:3478?transport=udp".to_string(),
                "turn:turn.rmediatech.com:3478?transport=tcp".to_string(),
                "turns:turn.rmediatech.com:5349?transport=tcp".to_string(),
            ],
        }
    }
}

/// Sovereign TURN & WebRTC Bandwidth Leeching Guard
#[derive(Debug, Clone)]
pub struct TurnGuard {
    secret_key: Vec<u8>,
    config: TurnGuardConfig,
    active_relays: Arc<RwLock<HashMap<String, u32>>>,
}

impl TurnGuard {
    pub fn new<K: Into<Vec<u8>>>(secret_key: K, config: TurnGuardConfig) -> Self {
        Self {
            secret_key: secret_key.into(),
            config,
            active_relays: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Mint ephemeral RFC-compliant Coturn / LiveKit REST credentials
    pub fn issue_credentials(
        &self,
        user_id: &str,
        now_s: u64,
        ttl_s: Option<u64>,
    ) -> TurnCredentials {
        let ttl = ttl_s
            .unwrap_or(self.config.default_ttl_s)
            .min(self.config.max_ttl_s);
        let expires_at = now_s + ttl;
        let username = format!("{}:{}", expires_at, user_id);

        let mut mac =
            HmacSha256::new_from_slice(&self.secret_key).expect("HMAC can accept key of any size");
        mac.update(username.as_bytes());
        let credential = BASE64.encode(mac.finalize().into_bytes());

        TurnCredentials {
            username,
            credential,
            ttl_seconds: ttl,
            expires_at,
            uris: self.config.relay_server_uris.clone(),
        }
    }

    /// Validate ephemeral TURN credential and check allocation quotas
    pub fn validate_and_allocate(
        &self,
        username: &str,
        provided_credential: &str,
        now_s: u64,
    ) -> TurnVerdict {
        // 1. Parse username: `<expires_at>:<user_id>`
        let parts: Vec<&str> = username.splitn(2, ':').collect();
        if parts.len() != 2 {
            return TurnVerdict::MalformedCredential;
        }

        let expires_at = match parts[0].parse::<u64>() {
            Ok(ts) => ts,
            Err(_) => return TurnVerdict::MalformedCredential,
        };
        let user_id = parts[1].to_string();

        // 2. Check expiration
        if now_s >= expires_at {
            return TurnVerdict::Expired {
                expired_at: expires_at,
                now_s,
            };
        }

        // 3. Check TTL bounds
        let requested_ttl = expires_at.saturating_sub(now_s);
        if requested_ttl > self.config.max_ttl_s {
            return TurnVerdict::ExcessiveTtl {
                requested_ttl_s: requested_ttl,
                max_ttl_s: self.config.max_ttl_s,
            };
        }

        // 4. Constant-Time HMAC Signature Verification
        let mut mac =
            HmacSha256::new_from_slice(&self.secret_key).expect("HMAC can accept key of any size");
        mac.update(username.as_bytes());
        let expected_credential = BASE64.encode(mac.finalize().into_bytes());

        if !bool::from(
            expected_credential
                .as_bytes()
                .ct_eq(provided_credential.as_bytes()),
        ) {
            return TurnVerdict::SignatureMismatch;
        }

        // 5. Enforce Concurrent Relay Quotas
        {
            let mut relays = self.active_relays.write();
            let count = relays.entry(user_id.clone()).or_insert(0);
            if *count >= self.config.max_concurrent_relays_per_user {
                return TurnVerdict::ConcurrentLimitExceeded {
                    user_id,
                    active: *count,
                    limit: self.config.max_concurrent_relays_per_user,
                };
            }
            *count += 1;
        }

        TurnVerdict::Authorized {
            user_id,
            expires_at,
        }
    }

    /// Release an active relay allocation when a WebRTC session closes
    pub fn release_relay(&self, user_id: &str) {
        let mut relays = self.active_relays.write();
        if let Some(count) = relays.get_mut(user_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                relays.remove(user_id);
            }
        }
    }

    /// Query currently active relay allocations for a user
    pub fn active_relays_for(&self, user_id: &str) -> u32 {
        let relays = self.active_relays.read();
        relays.get(user_id).copied().unwrap_or(0)
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;

    #[test]
    fn test_turn_guard_minting_and_authorization() {
        let guard = TurnGuard::new(b"turn_secret_key_testing", TurnGuardConfig::default());
        let now = 1_700_000_000;
        let creds = guard.issue_credentials("alice_operator", now, Some(300));
        assert_eq!((creds.ttl_seconds, creds.expires_at), (300, now + 300));
        let verdict = guard.validate_and_allocate(&creds.username, &creds.credential, now + 50);
        assert_eq!(verdict, TurnVerdict::Authorized { user_id: "alice_operator".to_string(), expires_at: now + 300 });
        assert_eq!(guard.active_relays_for("alice_operator"), 1);
        guard.release_relay("alice_operator");
        assert_eq!(guard.active_relays_for("alice_operator"), 0);
    }

    #[test]
    fn test_turn_guard_rejects_tampered_and_expired_tokens() {
        let guard = TurnGuard::new(b"turn_secret_key_testing", TurnGuardConfig::default());
        let now = 1_700_000_000;
        let creds = guard.issue_credentials("bob_hacker", now, Some(300));

        // Tampered signature
        let tampered_cred = format!("{}XYZ", &creds.credential[..creds.credential.len() - 3]);
        let res_tampered = guard.validate_and_allocate(&creds.username, &tampered_cred, now + 10);
        assert_eq!(res_tampered, TurnVerdict::SignatureMismatch);

        // Expired token
        let res_expired =
            guard.validate_and_allocate(&creds.username, &creds.credential, now + 301);
        assert!(matches!(res_expired, TurnVerdict::Expired { .. }));
    }

    #[test]
    fn test_turn_guard_enforces_concurrent_allocation_limits() {
        let config = TurnGuardConfig {
            max_concurrent_relays_per_user: 2,
            ..Default::default()
        };
        let guard = TurnGuard::new(b"turn_secret_key_testing", config);
        let now = 1_700_000_000;

        let creds = guard.issue_credentials("carol", now, Some(600));

        // 1st allocation -> OK
        assert!(guard
            .validate_and_allocate(&creds.username, &creds.credential, now)
            .is_authorized());
        // 2nd allocation -> OK
        assert!(guard
            .validate_and_allocate(&creds.username, &creds.credential, now)
            .is_authorized());

        // 3rd allocation -> Blocked (exceeded limit of 2)
        let verdict = guard.validate_and_allocate(&creds.username, &creds.credential, now);
        assert!(matches!(
            verdict,
            TurnVerdict::ConcurrentLimitExceeded { .. }
        ));

        // Free 1 slot -> now 3rd allocation succeeds
        guard.release_relay("carol");
        assert!(guard
            .validate_and_allocate(&creds.username, &creds.credential, now)
            .is_authorized());
    }
}
