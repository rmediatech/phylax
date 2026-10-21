//! # Canonical Network Subnet Key & Heuristic Classifier for Threat Harvester
//! One-Job: Extract canonical /24 IPv4 and /48 IPv6 subnet keys and classify anomalous paths.

use crate::decoy_uri::DecoyCategory;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Canonical network subnet key used for mathematical multi-subnet correlation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SubnetKey {
    /// IPv4 /24 subnet prefix ([oct1, oct2, oct3])
    V4([u8; 3]),
    /// IPv6 /48 subnet prefix ([seg1, seg2, seg3])
    V6([u16; 3]),
}

impl SubnetKey {
    /// Extracts canonical subnet key from an `IpAddr`
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                SubnetKey::V4([o[0], o[1], o[2]])
            }
            IpAddr::V6(v6) => {
                // If it's an IPv4-mapped IPv6 address (::ffff:192.0.2.1), extract IPv4 /24
                if let Some(v4) = v6.to_ipv4_mapped() {
                    let o = v4.octets();
                    SubnetKey::V4([o[0], o[1], o[2]])
                } else {
                    let s = v6.segments();
                    SubnetKey::V6([s[0], s[1], s[2]])
                }
            }
        }
    }

    /// Parses string IP and extracts canonical subnet key
    pub fn from_ip_str(ip_str: &str) -> Option<Self> {
        let trimmed = ip_str.trim();
        // Remove port if present (e.g., "192.0.2.1:8080" or "[2001:db8::1]:8080")
        let host = if trimmed.starts_with('[') {
            if let Some(end) = trimmed.find(']') {
                &trimmed[1..end]
            } else {
                trimmed
            }
        } else if let Some(colon) = trimmed.find(':') {
            if trimmed.matches(':').count() == 1 {
                &trimmed[..colon]
            } else {
                trimmed
            }
        } else {
            trimmed
        };

        host.parse::<IpAddr>().ok().map(Self::from_ip)
    }

    /// Formats as CIDR notation
    pub fn to_cidr_string(&self) -> String {
        match self {
            SubnetKey::V4(oct) => format!("{}.{}.{}.0/24", oct[0], oct[1], oct[2]),
            SubnetKey::V6(seg) => format!("{:x}:{:x}:{:x}::/48", seg[0], seg[1], seg[2]),
        }
    }
}

/// Heuristic classifier determining threat category for newly observed probe paths
pub fn categorize_candidate_heuristic(path: &str) -> DecoyCategory {
    let lower = path.to_ascii_lowercase();

    if ["env", "secret", "credential", "token", "vault", "key", "config"]
        .iter()
        .any(|k| lower.contains(k))
    {
        DecoyCategory::EnvironmentSecret
    } else if ["admin", "login", "wp-", "cms", "actuator", "console", "php"]
        .iter()
        .any(|k| lower.contains(k))
    {
        DecoyCategory::AdminCmsProbe
    } else if ["git", "svn", "hg", "repo"].iter().any(|k| lower.contains(k)) {
        DecoyCategory::VersionControl
    } else if ["k8s", "kube", "docker", "aws", "azure", "terraform"]
        .iter()
        .any(|k| lower.contains(k))
    {
        DecoyCategory::CloudInfrastructure
    } else if ["db", "sql", "data", "backup", "dump", "tar", "zip"]
        .iter()
        .any(|k| lower.contains(k))
    {
        DecoyCategory::DatabaseBackup
    } else {
        DecoyCategory::Custom
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ThreatHarvesterConfig, ThreatHarvesterEngine};
    use super::*;
    use crate::decoy_uri::DecoyUriSentinel;

    #[test]
    fn test_subnet_key_extraction_ipv4_and_ipv6() {
        let s1 = SubnetKey::from_ip("198.51.100.55".parse().unwrap());
        let s2 = SubnetKey::from_ip("198.51.100.99".parse().unwrap());
        let s3 = SubnetKey::from_ip("198.51.101.10".parse().unwrap());
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
        assert_eq!(s1.to_cidr_string(), "198.51.100.0/24");

        let sv6_1 = SubnetKey::from_ip("2001:db8:abcd:0012::1".parse().unwrap());
        let sv6_2 = SubnetKey::from_ip("2001:db8:abcd:ffff::99".parse().unwrap());
        assert_eq!(sv6_1, sv6_2);
        assert_eq!(sv6_1.to_cidr_string(), "2001:db8:abcd::/48");

        let v6_mapped = SubnetKey::from_ip("::ffff:198.51.100.42".parse().unwrap());
        assert_eq!(v6_mapped, SubnetKey::V4([198, 51, 100]));
    }

    #[test]
    fn test_multi_subnet_promotion_and_single_ip_defense() {
        let sentinel = DecoyUriSentinel::default();
        let config = ThreatHarvesterConfig {
            promotion_subnet_threshold: 3,
            max_paths_per_subnet: 3,
            ..Default::default()
        };
        let harvester = ThreatHarvesterEngine::new(config, sentinel.clone());
        let ip1: IpAddr = "198.51.100.1".parse().unwrap();
        let ip2: IpAddr = "192.0.2.77".parse().unwrap();
        let ip3: IpAddr = "203.0.113.88".parse().unwrap();
        let now = 200_000;

        // Single IP 50 hits cannot promote
        for _ in 0..50 {
            assert!(harvester.ingest_anomalous_uri("/api/v1/zero_day", ip1, now).is_none());
        }
        assert!(!sentinel.contains_trap("/api/v1/zero_day"));

        // 2nd subnet still candidate
        assert!(harvester.ingest_anomalous_uri("/api/v1/zero_day", ip2, now + 10).is_none());
        // 3rd subnet promotes into DecoyUriSentinel!
        let verdict = harvester
            .ingest_anomalous_uri("/api/v1/zero_day", ip3, now + 20)
            .expect("Promoted on 3rd subnet");
        assert_eq!(verdict.distinct_subnets, 3);
        assert!(sentinel.contains_trap("/api/v1/zero_day"));
    }
}
