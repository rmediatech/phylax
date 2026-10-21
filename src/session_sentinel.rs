//! # Radical OJP: Session Hijacking & Impossible Travel Sentinel
//! Single Job: Cryptographically bind sessions to network topology and detect impossible physical travel velocities.

use hmac::{Hmac, Mac};
use ipnet::IpNet;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

const EARTH_RADIUS_KM: f64 = 6371.0;

/// Geospatial coordinates of a client request
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoCoordinate {
    pub latitude: f64,
    pub longitude: f64,
}

impl GeoCoordinate {
    pub fn new(latitude: f64, longitude: f64) -> Self {
        Self {
            latitude,
            longitude,
        }
    }

    /// Calculate great-circle distance between two points using the Haversine formula (km)
    pub fn distance_to(&self, other: &GeoCoordinate) -> f64 {
        let lat1_rad = self.latitude.to_radians();
        let lat2_rad = other.latitude.to_radians();
        let delta_lat = (other.latitude - self.latitude).to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        EARTH_RADIUS_KM * c
    }
}

/// Recorded location checkpoint for a session
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionCheckpoint {
    pub coordinate: GeoCoordinate,
    pub timestamp_s: u64,
    pub location_label: Option<String>,
}

/// Configuration for Session Sentinel
#[derive(Debug, Clone)]
pub struct SessionSentinelConfig {
    /// Maximum realistic ground speed in km/h before flagging impossible travel (e.g. 1000 km/h)
    pub max_travel_speed_kmh: f64,
    /// Minimum distance in km to enforce velocity checks (prevents jitter flags across nearby cell towers)
    pub min_distance_threshold_km: f64,
    /// Subnet mask prefix for IPv4 binding (default /24)
    pub ipv4_prefix_len: u8,
    /// Subnet mask prefix for IPv6 binding (default /48)
    pub ipv6_prefix_len: u8,
}

impl Default for SessionSentinelConfig {
    fn default() -> Self {
        Self {
            max_travel_speed_kmh: 1000.0, // Commercial aviation max cruising speed (~900 km/h)
            min_distance_threshold_km: 50.0,
            ipv4_prefix_len: 24,
            ipv6_prefix_len: 48,
        }
    }
}

/// Verdict resulting from Session Sentinel inspection
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionVerdict {
    /// Session is authentic and physics-compliant
    Clean,
    /// Cryptographic device/topology fingerprint mismatch (stolen cookie replayed from new ASN/browser)
    FingerprintMismatch { reason: &'static str },
    /// Physical impossibility detected: client teleported across geographic coordinates
    ImpossibleTravel {
        calculated_speed_kmh: f64,
        distance_km: f64,
        elapsed_s: u64,
        previous_location: Option<String>,
        current_location: Option<String>,
    },
    /// Invalid format or malformed token
    Malformed,
}

impl SessionVerdict {
    #[inline]
    pub fn is_clean(&self) -> bool {
        matches!(self, SessionVerdict::Clean)
    }

    pub fn public_message(&self) -> &'static str {
        match self {
            SessionVerdict::Clean => "Session verified.",
            SessionVerdict::FingerprintMismatch { .. } => {
                "Security session binding mismatch. Please re-authenticate."
            }
            SessionVerdict::ImpossibleTravel { .. } => {
                "Suspicious geographic relocation detected. Session locked for security."
            }
            SessionVerdict::Malformed => "Malformed session token.",
        }
    }
}

/// Sovereign Session Hijacking & Impossible Travel Sentinel
#[derive(Debug, Clone)]
pub struct SessionSentinel {
    secret_key: Vec<u8>,
    config: SessionSentinelConfig,
    checkpoints: Arc<RwLock<HashMap<String, SessionCheckpoint>>>,
}

impl SessionSentinel {
    pub fn new<K: Into<Vec<u8>>>(secret_key: K, config: SessionSentinelConfig) -> Self {
        Self {
            secret_key: secret_key.into(),
            config,
            checkpoints: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Extract normalized subnet prefix from IP address to accommodate mobile carrier IP rotation
    pub fn extract_subnet_prefix(&self, ip_str: &str) -> String {
        let trimmed = ip_str.trim();
        if let Ok(ip) = IpAddr::from_str(trimmed) {
            let prefix_len = match ip {
                IpAddr::V4(_) => self.config.ipv4_prefix_len,
                IpAddr::V6(_) => self.config.ipv6_prefix_len,
            };
            if let Ok(net) = IpNet::new(ip, prefix_len) {
                return net.network().to_string();
            }
        }
        trimmed.to_string()
    }

    /// Compute cryptographic fingerprint binding token for an authenticated session
    pub fn generate_binding_token(
        &self,
        session_id: &str,
        client_ip: &str,
        user_agent: &str,
    ) -> String {
        let subnet_prefix = self.extract_subnet_prefix(client_ip);
        let mut ua_hasher = Sha256::new();
        ua_hasher.update(user_agent.as_bytes());
        let ua_hash = format!("{:x}", ua_hasher.finalize());
        let payload = format!("{}:{}:{}", session_id, subnet_prefix, ua_hash);
        let mut mac =
            HmacSha256::new_from_slice(&self.secret_key).expect("HMAC can accept key of any size");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Verify that incoming request matches the session's cryptographic device binding
    pub fn verify_binding(
        &self,
        session_id: &str,
        client_ip: &str,
        user_agent: &str,
        provided_token: &str,
    ) -> SessionVerdict {
        let expected = self.generate_binding_token(session_id, client_ip, user_agent);
        if bool::from(expected.as_bytes().ct_eq(provided_token.as_bytes())) {
            SessionVerdict::Clean
        } else {
            SessionVerdict::FingerprintMismatch {
                reason:
                    "Client network subnet or browser fingerprint does not match session binding",
            }
        }
    }

    /// Record checkpoint and evaluate whether geographic movement violates physical laws
    pub fn record_and_evaluate_travel(
        &self,
        session_id: &str,
        coordinate: GeoCoordinate,
        timestamp_s: u64,
        location_label: Option<&str>,
    ) -> SessionVerdict {
        let mut map = self.checkpoints.write();
        if let Some(prev) = map.get(session_id) {
            let distance_km = prev.coordinate.distance_to(&coordinate);
            if distance_km > self.config.min_distance_threshold_km {
                let elapsed_s = timestamp_s.saturating_sub(prev.timestamp_s);
                // Zero or near-zero elapsed time across distant coordinates is an instant flag
                let speed_kmh = if elapsed_s == 0 {
                    f64::INFINITY
                } else {
                    distance_km / (elapsed_s as f64 / 3600.0)
                };
                if speed_kmh > self.config.max_travel_speed_kmh {
                    return SessionVerdict::ImpossibleTravel {
                        calculated_speed_kmh: (speed_kmh * 100.0).round() / 100.0,
                        distance_km: (distance_km * 100.0).round() / 100.0,
                        elapsed_s,
                        previous_location: prev.location_label.clone(),
                        current_location: location_label.map(ToString::to_string),
                    };
                }
            }
        }
        // Update checkpoint with valid current position
        map.insert(
            session_id.to_string(),
            SessionCheckpoint {
                coordinate,
                timestamp_s,
                location_label: location_label.map(ToString::to_string),
            },
        );
        SessionVerdict::Clean
    }

    /// Clear session tracking data upon logout or invalidation
    pub fn invalidate_session(&self, session_id: &str) {
        self.checkpoints.write().remove(session_id);
    }
}

// Simple hex encoder to avoid pulling in external hex crate if not present
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
    fn test_haversine_distance_accurate() {
        let (london, paris) = (GeoCoordinate::new(51.5074, -0.1278), GeoCoordinate::new(48.8566, 2.3522));
        let dist = london.distance_to(&paris);
        assert!(dist > 340.0 && dist < 350.0, "Expected ~343km, got {}", dist);
    }

    #[test]
    fn test_device_binding_detects_ip_or_ua_tampering() {
        let sentinel = SessionSentinel::new(b"test_secret_key_123", SessionSentinelConfig::default());
        let (session_id, ip, ua) = ("sess_xyz_9988", "203.0.113.45", "Mozilla/5.0 Chrome/120.0");
        let token = sentinel.generate_binding_token(session_id, ip, ua);
        assert_eq!(sentinel.verify_binding(session_id, "203.0.113.88", ua, &token), SessionVerdict::Clean);
        assert!(matches!(sentinel.verify_binding(session_id, "198.51.100.12", ua, &token), SessionVerdict::FingerprintMismatch { .. }));
        assert!(matches!(sentinel.verify_binding(session_id, ip, "curl/8.5.0", &token), SessionVerdict::FingerprintMismatch { .. }));
    }

    #[test]
    fn test_impossible_travel_catches_teleportation() {
        let sentinel = SessionSentinel::new(b"test_secret_key_123", SessionSentinelConfig::default());
        let (jfk, lhr) = (GeoCoordinate::new(40.6413, -73.7781), GeoCoordinate::new(51.4700, -0.4543));
        assert_eq!(sentinel.record_and_evaluate_travel("sess_flight_test", jfk, 10_000, Some("New York JFK")), SessionVerdict::Clean);
        match sentinel.record_and_evaluate_travel("sess_flight_test", lhr, 10_300, Some("London Heathrow")) {
            SessionVerdict::ImpossibleTravel { calculated_speed_kmh, distance_km, elapsed_s, .. } => {
                assert!(distance_km > 5000.0 && elapsed_s == 300 && calculated_speed_kmh > 1000.0);
            }
            other => panic!("Expected ImpossibleTravel, got {:?}", other),
        }
        sentinel.record_and_evaluate_travel("sess_valid_flight", jfk, 10_000, Some("New York"));
        assert_eq!(sentinel.record_and_evaluate_travel("sess_valid_flight", lhr, 38_800, Some("London")), SessionVerdict::Clean);
    }
}
