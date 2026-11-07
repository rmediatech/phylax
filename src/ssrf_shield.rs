//! # Sovereign Sub-Microsecond SSRF, IMDS & DNS Rebinding Shield (`ssrf_shield.rs`)
//!
//! Defends upstream proxies, webhooks, and URL-fetching parameters against:
//! 1. **Cloud Instance Metadata (IMDSv1/v2)**: AWS/GCP/Azure `169.254.169.254`, IPv6 `fd00:ec2::254`,
//!    Alibaba `100.100.100.200`, Oracle `192.0.0.192`, `metadata.google.internal`.
//! 2. **RFC 1918 / RFC 6598 / Loopback / Link-Local Pinning**: Blocks `127.0.0.0/8`, `10.0.0.0/8`,
//!    `172.16.0.0/12`, `192.168.0.0/16`, Carrier NAT `100.64.0.0/10`, `0.0.0.0/8`, and `::1`.
//! 3. **IPv4-Mapped IPv6 & Numeric IP Obfuscation**: Unmasks `http://[::ffff:169.254.169.254]/`,
//!    32-bit decimal IPs (`http://2852039166/` -> `169.254.169.254`), hex IPs (`http://0x7f000001/`),
//!    and octal IPs (`http://0177.0.0.1/`).
//! 4. **DNS Rebinding Guard**: Pins resolved host -> public IP mappings and rejects mid-flight
//!    rebinds where an external hostname flips to a private/loopback IP.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// Classification of an SSRF or DNS Rebinding violation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrfVerdict {
    /// Target is a safe external public endpoint
    Allow,
    /// Blocked: Cloud Instance Metadata Service (IMDS) target
    CloudMetadataTarget(&'static str),
    /// Blocked: Private / Loopback / Link-Local IPv4 or IPv6 range
    PrivateOrLoopbackIp(IpAddr, &'static str),
    /// Blocked: Obfuscated numeric IP encoding (Decimal integer, Hex, or Octal)
    ObfuscatedIpEncoding(Ipv4Addr, &'static str),
    /// Blocked: Dangerous non-HTTP scheme (`gopher://`, `dict://`, `file://`, `ldap://`)
    ForbiddenScheme(&'static str),
    /// Blocked: DNS Rebinding detected (hostname switched from public IP to private/internal IP)
    DnsRebindingDetected {
        host: String,
        pinned_ip: IpAddr,
        rebound_ip: IpAddr,
    },
}

/// Stateful DNS Rebinding Pinning Registry + Stateless Sub-Microsecond SSRF Inspector
#[derive(Debug, Clone)]
pub struct SsrfShield {
    dns_pins: Arc<RwLock<HashMap<String, IpAddr>>>,
    max_pins: usize,
}

impl Default for SsrfShield {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl SsrfShield {
    pub fn new(max_pins: usize) -> Self {
        Self {
            dns_pins: Arc::new(RwLock::new(HashMap::with_capacity(256))),
            max_pins,
        }
    }

    /// Evaluates a raw `IpAddr` (including IPv4-mapped IPv6 `::ffff:a.b.c.d`) in <5ns.
    #[inline]
    pub fn classify_ip(ip: IpAddr) -> SsrfVerdict {
        match ip {
            IpAddr::V4(v4) => Self::classify_ipv4(v4),
            IpAddr::V6(v6) => Self::classify_ipv6(v6),
        }
    }

    #[inline]
    pub fn classify_ipv4(v4: Ipv4Addr) -> SsrfVerdict {
        let octets = v4.octets();
        let u = u32::from_be_bytes(octets);

        // 1. Cloud Metadata IMDS endpoints
        if octets == [169, 254, 169, 254] {
            return SsrfVerdict::CloudMetadataTarget("AWS/GCP/Azure IMDS (169.254.169.254)");
        }
        if octets == [100, 100, 100, 200] {
            return SsrfVerdict::CloudMetadataTarget("Alibaba Cloud IMDS (100.100.100.200)");
        }
        if octets == [192, 0, 0, 192] {
            return SsrfVerdict::CloudMetadataTarget("Oracle Cloud IMDS (192.0.0.192)");
        }

        // 2. Loopback 127.0.0.0/8 and Unspecified 0.0.0.0/8
        if octets[0] == 127 {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V4(v4),
                "RFC 1122 Loopback (127.0.0.0/8)",
            );
        }
        if octets[0] == 0 {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V4(v4),
                "RFC 1122 Local Network (0.0.0.0/8)",
            );
        }

        // 3. Link-Local 169.254.0.0/16
        if octets[0] == 169 && octets[1] == 254 {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V4(v4),
                "RFC 3927 Link-Local (169.254.0.0/16)",
            );
        }

        // 4. RFC 1918 Private Internals (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        if octets[0] == 10 {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V4(v4),
                "RFC 1918 Private (10.0.0.0/8)",
            );
        }
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V4(v4),
                "RFC 1918 Private (172.16.0.0/12)",
            );
        }
        if octets[0] == 192 && octets[1] == 168 {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V4(v4),
                "RFC 1918 Private (192.168.0.0/16)",
            );
        }

        // 5. RFC 6598 Carrier-Grade NAT (100.64.0.0/10)
        if (u & 0xFFC0_0000) == 0x6440_0000 {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V4(v4),
                "RFC 6598 Carrier-Grade NAT (100.64.0.0/10)",
            );
        }

        // 6. Broadcast & Multicast (224.0.0.0/4+)
        if octets[0] >= 224 {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V4(v4),
                "Multicast / Reserved (224.0.0.0/3)",
            );
        }

        SsrfVerdict::Allow
    }

    #[inline]
    pub fn classify_ipv6(v6: Ipv6Addr) -> SsrfVerdict {
        // Unwrap IPv4-mapped IPv6 (`::ffff:169.254.169.254`)
        if let Some(mapped_v4) = v6.to_ipv4_mapped() {
            return Self::classify_ipv4(mapped_v4);
        }

        let segs = v6.segments();
        // AWS IPv6 IMDS: fd00:ec2::254
        if segs == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254] {
            return SsrfVerdict::CloudMetadataTarget("AWS IPv6 IMDS (fd00:ec2::254)");
        }

        if v6.is_loopback() || v6.is_unspecified() {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V6(v6),
                "IPv6 Loopback / Unspecified (::1 / ::)",
            );
        }

        // Unique Local (fc00::/7) or Link-Local (fe80::/10)
        if (segs[0] & 0xfe00) == 0xfc00 || (segs[0] & 0xffc0) == 0xfe80 {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V6(v6),
                "IPv6 Unique/Link-Local (fc00::/7 | fe80::/10)",
            );
        }

        SsrfVerdict::Allow
    }

    /// Inspects a URL string or query parameter value for SSRF schemes, internal hosts,
    /// and obfuscated numeric IP addresses (decimal integer, hex, octal).
    pub fn inspect_url_candidate(input: &str) -> SsrfVerdict {
        let lower = input.to_ascii_lowercase();

        // 1. Forbidden non-HTTP SSRF smuggling schemes
        const FORBIDDEN_SCHEMES: &[(&str, &str)] = &[
            ("gopher://", "gopher://"),
            ("dict://", "dict://"),
            ("file://", "file://"),
            ("ldap://", "ldap://"),
            ("ldaps://", "ldaps://"),
            ("tftp://", "tftp://"),
            ("netdoc://", "netdoc://"),
        ];
        for &(pat, label) in FORBIDDEN_SCHEMES {
            if lower.contains(pat) {
                return SsrfVerdict::ForbiddenScheme(label);
            }
        }

        // 2. Cloud metadata hostnames
        if lower.contains("metadata.google.internal") || lower.contains("metadata.goog") {
            return SsrfVerdict::CloudMetadataTarget(
                "GCP Metadata Host (metadata.google.internal)",
            );
        }
        if lower.contains("instance-data.ec2.internal") {
            return SsrfVerdict::CloudMetadataTarget("AWS EC2 Internal Metadata Host");
        }

        // 3. Extract authority/host after `http://` or `https://` or `//`
        for scheme in ["http://", "https://", "//"] {
            let mut search_slice = lower.as_str();
            while let Some(pos) = search_slice.find(scheme) {
                let after_scheme = &search_slice[pos + scheme.len()..];
                let authority = after_scheme
                    .split(['/', '?', '#', '&', ' ', '\''])
                    .next()
                    .unwrap_or("");
                // Strip optional `user:pass@` and `:port`
                let host_port = authority.rsplit('@').next().unwrap_or(authority);
                let host = if host_port.starts_with('[') {
                    host_port
                        .split(']')
                        .next()
                        .unwrap_or(host_port)
                        .trim_start_matches('[')
                } else {
                    host_port.split(':').next().unwrap_or(host_port)
                };

                let verdict = Self::inspect_host(host);
                if verdict != SsrfVerdict::Allow {
                    return verdict;
                }

                search_slice = after_scheme;
            }
        }

        SsrfVerdict::Allow
    }

    /// Inspects an extracted hostname or IP literal (standard, IPv6, decimal, hex, or octal).
    pub fn inspect_host(host: &str) -> SsrfVerdict {
        if host.is_empty() {
            return SsrfVerdict::Allow;
        }
        if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
            return SsrfVerdict::PrivateOrLoopbackIp(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "localhost hostname",
            );
        }

        // Standard IPv4 / IPv6 parse
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Self::classify_ip(ip);
        }

        // Obfuscated IPv4 encodings (32-bit decimal integer, 0x hex, or 0-prefixed octal octets)
        if let Some((v4, encoding_kind)) = Self::try_parse_obfuscated_ipv4(host) {
            let base = Self::classify_ipv4(v4);
            if base != SsrfVerdict::Allow {
                return SsrfVerdict::ObfuscatedIpEncoding(v4, encoding_kind);
            }
        }

        SsrfVerdict::Allow
    }

    /// Parses non-standard IPv4 representations used to bypass naive regex WAFs:
    /// - Single 32-bit integer: `2852039166` -> `169.254.169.254`, `2130706433` -> `127.0.0.1`
    /// - Single Hex integer: `0x7f000001` or `0xa9fea9fe`
    /// - Dotted Hex/Octal octets: `0177.0.0.1` or `0x7f.0.0.1`
    pub fn try_parse_obfuscated_ipv4(host: &str) -> Option<(Ipv4Addr, &'static str)> {
        // Case 1: Single 32-bit Hex integer `0x...`
        if let Some(hex_str) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            if !hex_str.contains('.') {
                if let Ok(val) = u32::from_str_radix(hex_str, 16) {
                    return Some((Ipv4Addr::from(val), "hex_u32_ip"));
                }
            }
        }

        // Case 2: Single 32-bit Decimal integer (e.g. `2852039166`)
        if !host.contains('.') && host.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(val) = host.parse::<u32>() {
                return Some((Ipv4Addr::from(val), "decimal_u32_ip"));
            }
        }

        // Case 3: Dotted octets with Octal (`0177.0.0.1`) or Hex (`0x7f.0.0.1`)
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4 {
            let mut octets = [0u8; 4];
            let mut used_non_decimal = false;
            for (idx, part) in parts.iter().enumerate() {
                if part.is_empty() {
                    return None;
                }
                if let Some(h) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                    octets[idx] = u8::from_str_radix(h, 16).ok()?;
                    used_non_decimal = true;
                } else if part.len() > 1
                    && part.starts_with('0')
                    && part.bytes().all(|b| (b'0'..=b'7').contains(&b))
                {
                    octets[idx] = u8::from_str_radix(part, 8).ok()?;
                    used_non_decimal = true;
                } else {
                    octets[idx] = part.parse::<u8>().ok()?;
                }
            }
            if used_non_decimal {
                return Some((Ipv4Addr::from(octets), "dotted_octal_or_hex_ip"));
            }
        }

        None
    }

    /// Verifies and pins DNS resolution for `host -> resolved_ip`.
    /// Rejects private/IMDS IPs and detects DNS Rebinding attacks where a previously
    /// verified public hostname suddenly resolves to an internal IP.
    pub fn verify_and_pin_resolution(&self, host: &str, resolved_ip: IpAddr) -> SsrfVerdict {
        let ip_verdict = Self::classify_ip(resolved_ip);
        let key = host.to_ascii_lowercase();

        let mut pins = self.dns_pins.write();
        if let Some(&pinned) = pins.get(&key) {
            if ip_verdict != SsrfVerdict::Allow {
                return SsrfVerdict::DnsRebindingDetected {
                    host: key,
                    pinned_ip: pinned,
                    rebound_ip: resolved_ip,
                };
            }
        } else {
            if ip_verdict != SsrfVerdict::Allow {
                return ip_verdict;
            }
            if pins.len() < self.max_pins {
                pins.insert(key, resolved_ip);
            }
        }

        ip_verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscated_imds_and_loopback_ips() {
        // 2852039166 == 169.254.169.254
        assert_eq!(
            SsrfShield::inspect_url_candidate("http://2852039166/latest/meta-data/"),
            SsrfVerdict::ObfuscatedIpEncoding(Ipv4Addr::new(169, 254, 169, 254), "decimal_u32_ip")
        );
        // 0x7f000001 == 127.0.0.1
        assert_eq!(
            SsrfShield::inspect_url_candidate("http://0x7f000001:8080/admin"),
            SsrfVerdict::ObfuscatedIpEncoding(Ipv4Addr::new(127, 0, 0, 1), "hex_u32_ip")
        );
        // 0177.0.0.1 == 127.0.0.1
        assert_eq!(
            SsrfShield::inspect_url_candidate("http://0177.0.0.1/status"),
            SsrfVerdict::ObfuscatedIpEncoding(
                Ipv4Addr::new(127, 0, 0, 1),
                "dotted_octal_or_hex_ip"
            )
        );
        // IPv4-mapped IPv6 IMDS
        assert_eq!(
            SsrfShield::inspect_url_candidate("http://[::ffff:169.254.169.254]/latest/meta-data"),
            SsrfVerdict::CloudMetadataTarget("AWS/GCP/Azure IMDS (169.254.169.254)")
        );
    }

    #[test]
    fn test_dns_rebinding_detection() {
        let shield = SsrfShield::default();
        let pub_ip: IpAddr = "93.184.216.34".parse().unwrap();
        let priv_ip: IpAddr = "169.254.169.254".parse().unwrap();

        assert_eq!(
            shield.verify_and_pin_resolution("webhook.attacker.com", pub_ip),
            SsrfVerdict::Allow
        );
        assert_eq!(
            shield.verify_and_pin_resolution("webhook.attacker.com", priv_ip),
            SsrfVerdict::DnsRebindingDetected {
                host: "webhook.attacker.com".to_string(),
                pinned_ip: pub_ip,
                rebound_ip: priv_ip,
            }
        );
    }
}
