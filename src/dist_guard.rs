//! # Radical OJP: Binary Download Voucher & Byte-Range Abuse Guard
//! Single Job: Cryptographically issue single-use download vouchers for large binary assets and prevent byte-range bandwidth scraping.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Verdict from binary download inspection
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistVerdict {
    /// Download request is authorized
    Permitted { asset_id: String, client_ip: String },
    /// Voucher lifetime has expired
    VoucherExpired { expires_at: u64, now_s: u64 },
    /// Single-use voucher has already been consumed (replay attack)
    VoucherReplayed,
    /// Cryptographic signature is invalid (tampered voucher)
    SignatureInvalid,
    /// Client IP does not match the bound voucher IP
    IpMismatch { token_ip: String, actual_ip: String },
    /// Excessive or abusive byte-range chunks requested within rolling window
    RangeAbuseDetected {
        ip: String,
        chunk_count: u32,
        window_s: u64,
    },
    /// Maximum concurrent active downloads exceeded for client IP
    ConcurrentLimitExceeded { ip: String, active: u32, limit: u32 },
    /// Voucher is malformed
    Malformed,
}

impl DistVerdict {
    #[inline]
    pub fn is_permitted(&self) -> bool {
        matches!(self, DistVerdict::Permitted { .. })
    }

    pub fn public_message(&self) -> &'static str {
        match self {
            DistVerdict::Permitted { .. } => "Download authorized.",
            DistVerdict::VoucherExpired { .. } => "Download link expired. Please regenerate.",
            DistVerdict::VoucherReplayed => "Download link has already been used.",
            DistVerdict::SignatureInvalid => "Invalid download voucher signature.",
            DistVerdict::IpMismatch { .. } => "Download voucher bound to another network address.",
            DistVerdict::RangeAbuseDetected { .. } => {
                "Excessive byte-range chunk requests. Range requests throttled."
            }
            DistVerdict::ConcurrentLimitExceeded { .. } => {
                "Maximum concurrent downloads reached for this network address."
            }
            DistVerdict::Malformed => "Malformed download voucher.",
        }
    }
}

/// Configuration for Distribution Guard
#[derive(Debug, Clone)]
pub struct DistGuardConfig {
    pub voucher_ttl_s: u64,
    pub max_concurrent_downloads_per_ip: u32,
    pub max_range_chunks_per_window: u32,
    pub range_window_s: u64,
}

impl Default for DistGuardConfig {
    fn default() -> Self {
        Self {
            voucher_ttl_s: 300,                 // 5 minutes to initiate download
            max_concurrent_downloads_per_ip: 3, // max 3 parallel multi-megabyte streams
            max_range_chunks_per_window: 25,    // max 25 byte-range chunk requests
            range_window_s: 10,                 // per 10 second window
        }
    }
}

#[derive(Debug, Default)]
struct RangeTracker {
    timestamps: Vec<u64>,
}

impl RangeTracker {
    fn record_and_count(&mut self, now_s: u64, window_s: u64) -> usize {
        let cutoff = now_s.saturating_sub(window_s);
        self.timestamps.retain(|&ts| ts >= cutoff);
        self.timestamps.push(now_s);
        self.timestamps.len()
    }
}

/// Sovereign Binary Distribution & Range-Abuse Guard
#[derive(Debug, Clone)]
pub struct DistGuard {
    secret_key: Vec<u8>,
    config: DistGuardConfig,
    consumed_nonces: Arc<RwLock<HashMap<String, u64>>>,
    active_downloads: Arc<RwLock<HashMap<String, u32>>>,
    range_trackers: Arc<RwLock<HashMap<String, RangeTracker>>>,
}

impl DistGuard {
    pub fn new<K: Into<Vec<u8>>>(secret_key: K, config: DistGuardConfig) -> Self {
        Self {
            secret_key: secret_key.into(),
            config,
            consumed_nonces: Arc::new(RwLock::new(HashMap::new())),
            active_downloads: Arc::new(RwLock::new(HashMap::new())),
            range_trackers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Issue a cryptographically signed, single-use download voucher for an asset
    pub fn issue_voucher(
        &self,
        asset_id: &str,
        client_ip: &str,
        nonce: &str,
        now_s: u64,
    ) -> String {
        let expires_at = now_s + self.config.voucher_ttl_s;
        let payload = format!("{}:{}:{}:{}", asset_id, client_ip, expires_at, nonce);
        let mut mac =
            HmacSha256::new_from_slice(&self.secret_key).expect("HMAC can accept key of any size");
        mac.update(payload.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        BASE64_URL.encode(format!("{}.{}", payload, sig).as_bytes())
    }

    /// Validate a voucher when client requests `GET /dist/...`
    pub fn validate_voucher(
        &self,
        voucher_token: &str,
        actual_ip: &str,
        now_s: u64,
    ) -> DistVerdict {
        let Ok(decoded_bytes) = BASE64_URL.decode(voucher_token.as_bytes()) else {
            return DistVerdict::Malformed;
        };
        let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) else {
            return DistVerdict::Malformed;
        };
        let Some((payload, provided_sig)) = decoded_str.rsplit_once('.') else {
            return DistVerdict::Malformed;
        };

        // 1. Verify HMAC signature in constant time
        let mut mac =
            HmacSha256::new_from_slice(&self.secret_key).expect("HMAC can accept key of any size");
        mac.update(payload.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());
        if !bool::from(expected_sig.as_bytes().ct_eq(provided_sig.as_bytes())) {
            return DistVerdict::SignatureInvalid;
        }

        // 2. Parse payload: `asset_id:token_ip:expires_at:nonce`
        let fields: Vec<&str> = payload.split(':').collect();
        if fields.len() != 4 {
            return DistVerdict::Malformed;
        }
        let (asset_id, token_ip, nonce) = (fields[0].to_string(), fields[1], fields[3]);
        let Ok(expires_at) = fields[2].parse::<u64>() else {
            return DistVerdict::Malformed;
        };

        // 3. Expiration Check
        if now_s >= expires_at {
            return DistVerdict::VoucherExpired { expires_at, now_s };
        }

        // 4. Client IP Binding Check
        if token_ip != actual_ip {
            return DistVerdict::IpMismatch {
                token_ip: token_ip.to_string(),
                actual_ip: actual_ip.to_string(),
            };
        }

        // 5. Replay Protection
        {
            let mut nonces = self.consumed_nonces.write();
            nonces.retain(|_, &mut exp| exp > now_s); // Prune expired nonces periodically
            if nonces.contains_key(nonce) {
                return DistVerdict::VoucherReplayed;
            }
            nonces.insert(nonce.to_string(), expires_at);
        }

        // 6. Concurrent Download Check
        {
            let mut active = self.active_downloads.write();
            let count = active.entry(actual_ip.to_string()).or_insert(0);
            if *count >= self.config.max_concurrent_downloads_per_ip {
                return DistVerdict::ConcurrentLimitExceeded {
                    ip: actual_ip.to_string(),
                    active: *count,
                    limit: self.config.max_concurrent_downloads_per_ip,
                };
            }
            *count += 1;
        }

        DistVerdict::Permitted {
            asset_id,
            client_ip: actual_ip.to_string(),
        }
    }

    /// Track and inspect HTTP `Range: bytes=...` requests to prevent chunk scraper abuse
    pub fn check_range_request(&self, client_ip: &str, now_s: u64) -> DistVerdict {
        let mut trackers = self.range_trackers.write();
        let tracker = trackers.entry(client_ip.to_string()).or_default();
        let count = tracker.record_and_count(now_s, self.config.range_window_s) as u32;
        if count > self.config.max_range_chunks_per_window {
            DistVerdict::RangeAbuseDetected {
                ip: client_ip.to_string(),
                chunk_count: count,
                window_s: self.config.range_window_s,
            }
        } else {
            DistVerdict::Permitted {
                asset_id: "range_chunk".to_string(),
                client_ip: client_ip.to_string(),
            }
        }
    }

    /// Mark a download finished to release the concurrent slot
    pub fn finish_download(&self, client_ip: &str) {
        let mut active = self.active_downloads.write();
        if let Some(count) = active.get_mut(client_ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(client_ip);
            }
        }
    }
}

mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;

    #[test]
    fn test_dist_voucher_issuance_and_consumption() {
        let guard = DistGuard::new(b"dist_secret_voucher_key", DistGuardConfig::default());
        let (now, ip, asset) = (1_000_000, "192.0.2.55", "rmediatech-desktop-1.0.0.AppImage");
        let voucher = guard.issue_voucher(asset, ip, "unique_nonce_abc_1", now);
        assert_eq!(guard.validate_voucher(&voucher, ip, now + 10), DistVerdict::Permitted { asset_id: asset.to_string(), client_ip: ip.to_string() });
        assert_eq!(guard.validate_voucher(&voucher, ip, now + 15), DistVerdict::VoucherReplayed);
        guard.finish_download(ip);
    }

    #[test]
    fn test_dist_guard_blocks_ip_mismatch_and_expired() {
        let guard = DistGuard::new(b"dist_secret_voucher_key", DistGuardConfig::default());
        let (now, original_ip, attacker_ip, asset) = (1_000_000, "192.0.2.55", "198.51.100.22", "rmediatech-installer.exe");
        let voucher = guard.issue_voucher(asset, original_ip, "nonce_2", now);
        assert!(matches!(guard.validate_voucher(&voucher, attacker_ip, now + 5), DistVerdict::IpMismatch { .. }));
        assert!(matches!(guard.validate_voucher(&voucher, original_ip, now + 301), DistVerdict::VoucherExpired { .. }));
    }

    #[test]
    fn test_dist_guard_detects_byte_range_chunk_scraping() {
        let config = DistGuardConfig { max_range_chunks_per_window: 5, range_window_s: 10, ..Default::default() };
        let guard = DistGuard::new(b"dist_secret_voucher_key", config);
        for _ in 0..5 {
            assert!(guard.check_range_request("203.0.113.89", 1_000_000).is_permitted());
        }
        assert!(matches!(guard.check_range_request("203.0.113.89", 1_000_001), DistVerdict::RangeAbuseDetected { .. }));
    }
}
