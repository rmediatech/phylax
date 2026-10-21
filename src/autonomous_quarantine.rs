//! # Autonomous CIDR Quarantine Engine
//!
//! Automatically expands repeat offender IPs into their surrounding `/24` (IPv4)
//! or `/48` (IPv6) subnet boundaries, imposing an autonomous quarantine with configurable TTL.

use ipnet::IpNet;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Configuration for autonomous quarantine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantineConfig {
    /// Number of severe infractions required to trigger autonomous CIDR quarantine
    pub infraction_threshold: u32,
    /// Duration of quarantine in milliseconds (e.g. 24 hours)
    pub quarantine_duration_ms: u64,
    /// Maximum number of active quarantined subnets to track
    pub max_tracked_subnets: usize,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            infraction_threshold: 3,
            quarantine_duration_ms: 24 * 60 * 60 * 1000, // 24 hours
            max_tracked_subnets: 5000,
        }
    }
}

/// Autonomous Quarantine Manager
#[derive(Debug, Clone)]
pub struct AutonomousQuarantine {
    config: QuarantineConfig,
    active_bans: Arc<RwLock<HashMap<IpNet, u64>>>,
    ip_infractions: Arc<RwLock<HashMap<String, (u32, u64)>>>,
}

impl AutonomousQuarantine {
    pub fn new(config: QuarantineConfig) -> Self {
        Self {
            config,
            active_bans: Arc::new(RwLock::new(HashMap::new())),
            ip_infractions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Derive the /24 (IPv4) or /48 (IPv6) subnet string for a given IP
    pub fn derive_quarantine_cidr(ip_str: &str) -> Option<String> {
        let addr = IpAddr::from_str(ip_str).ok()?;
        match addr {
            IpAddr::V4(v4) => {
                let net = ipnet::Ipv4Net::new(v4, 24).ok()?.trunc();
                Some(format!("{}/24", net.network()))
            }
            IpAddr::V6(v6) => {
                let net = ipnet::Ipv6Net::new(v6, 48).ok()?.trunc();
                Some(format!("{}/48", net.network()))
            }
        }
    }

    /// Record an infraction from an IP. If threshold is met, auto-quarantine its subnet.
    /// Returns true if autonomous quarantine was activated.
    pub fn record_and_check(&self, ip: &str, now_ms: u64) -> bool {
        let mut infractions = self.ip_infractions.write();
        let entry = infractions.entry(ip.to_string()).or_insert((0, now_ms));
        entry.0 += 1;
        entry.1 = now_ms;

        if entry.0 >= self.config.infraction_threshold {
            if let Some(cidr_str) = Self::derive_quarantine_cidr(ip) {
                if let Ok(net) = IpNet::from_str(&cidr_str) {
                    let mut bans = self.active_bans.write();
                    bans.insert(net, now_ms + self.config.quarantine_duration_ms);
                    return true;
                }
            }
        }

        false
    }

    /// Check if an IP falls within any currently active quarantined CIDR block
    pub fn is_quarantined(&self, ip: &str, now_ms: u64) -> bool {
        let addr = match IpAddr::from_str(ip) {
            Ok(a) => a,
            Err(_) => return false,
        };

        let bans = self.active_bans.read();
        for (net, expires_at) in bans.iter() {
            if *expires_at > now_ms && net.contains(&addr) {
                return true;
            }
        }

        false
    }

    /// Remove expired bans and stale infractions to keep memory lean.
    /// Returns the number of expired subnet bans pruned.
    pub fn purge_expired(&self, now_ms: u64) -> usize {
        let mut bans = self.active_bans.write();
        let before_bans = bans.len();
        bans.retain(|_, expires_at| *expires_at > now_ms);
        let pruned_bans = before_bans.saturating_sub(bans.len());

        let mut infractions = self.ip_infractions.write();
        let cutoff = now_ms.saturating_sub(self.config.quarantine_duration_ms);
        infractions.retain(|_, (_, last_ts)| *last_ts > cutoff);

        pruned_bans
    }

    /// Current count of active quarantined CIDR blocks
    pub fn active_bans_count(&self) -> usize {
        self.active_bans.read().len()
    }

    /// Manually insert a quarantine ban (e.g. during startup rehydration from persistent store)
    pub fn add_ban(&self, net: IpNet, expires_at: u64) {
        let mut bans = self.active_bans.write();
        bans.insert(net, expires_at);
    }

    /// Unquarantine a specific IP or CIDR subnet.
    /// If an IP is provided, removes any quarantined subnet containing that IP.
    /// Also clears any pending infraction counter.
    /// Returns true if at least one active ban was removed.
    pub fn unban(&self, ip_or_cidr: &str) -> bool {
        let mut removed = false;

        // 1. Try exact CIDR match first
        if let Ok(target_net) = IpNet::from_str(ip_or_cidr) {
            let mut bans = self.active_bans.write();
            if bans.remove(&target_net).is_some() {
                removed = true;
            }
        }

        // 2. If not already removed, check if input is an IP and matches any containing subnet
        if !removed {
            if let Ok(target_addr) = IpAddr::from_str(ip_or_cidr) {
                let mut bans = self.active_bans.write();
                let keys_to_remove: Vec<IpNet> = bans
                    .keys()
                    .filter(|net| net.contains(&target_addr))
                    .cloned()
                    .collect();

                for key in keys_to_remove {
                    bans.remove(&key);
                    removed = true;
                }
            }
        }

        // 3. Also check if derived CIDR matches
        if !removed {
            if let Some(derived_cidr) = Self::derive_quarantine_cidr(ip_or_cidr) {
                if let Ok(derived_net) = IpNet::from_str(&derived_cidr) {
                    let mut bans = self.active_bans.write();
                    if bans.remove(&derived_net).is_some() {
                        removed = true;
                    }
                }
            }
        }

        // 4. Clear infractions for this IP or matching subnet
        let mut infractions = self.ip_infractions.write();
        if let Ok(target_net) = IpNet::from_str(ip_or_cidr) {
            infractions.retain(|ip_str, _| {
                if let Ok(addr) = IpAddr::from_str(ip_str) {
                    !target_net.contains(&addr)
                } else {
                    true
                }
            });
        } else if let Ok(target_addr) = IpAddr::from_str(ip_or_cidr) {
            infractions.remove(&target_addr.to_string());
        }

        removed
    }

    /// Unquarantine all currently active subnets and wipe infraction counters.
    /// Returns the total number of subnets unbanned.
    pub fn unban_all(&self) -> usize {
        let mut bans = self.active_bans.write();
        let count = bans.len();
        bans.clear();

        let mut infractions = self.ip_infractions.write();
        infractions.clear();

        count
    }

    /// Retrieve a snapshot of all currently active (unexpired) quarantined subnets and their expiry timestamps (ms)
    pub fn active_bans(&self, now_ms: u64) -> Vec<(IpNet, u64)> {
        let bans = self.active_bans.read();
        bans.iter()
            .filter(|(_, expires_at)| **expires_at > now_ms)
            .map(|(net, expires_at)| (*net, *expires_at))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_purge_expired_cleans_old_bans_and_infractions() {
        let aq = AutonomousQuarantine::new(QuarantineConfig {
            infraction_threshold: 1, // ban on 1st infraction
            quarantine_duration_ms: 1000,
            max_tracked_subnets: 100,
        });

        aq.record_and_check("192.0.2.50", 1000);
        assert_eq!(aq.active_bans_count(), 1);
        assert!(aq.is_quarantined("192.0.2.99", 1500));

        // At t = 2001ms, ban has expired (1000 + 1000 = 2000)
        let pruned = aq.purge_expired(2001);
        assert_eq!(pruned, 1);
        assert_eq!(aq.active_bans_count(), 0);
        assert!(!aq.is_quarantined("192.0.2.99", 2001));
    }

    #[test]
    fn test_unban_by_ip_and_cidr() {
        let aq = AutonomousQuarantine::new(QuarantineConfig {
            infraction_threshold: 1,
            quarantine_duration_ms: 100_000,
            max_tracked_subnets: 100,
        });

        // 1. Trigger ban on 192.0.2.50 (derives to 192.0.2.0/24)
        aq.record_and_check("192.0.2.50", 1000);
        assert!(aq.is_quarantined("192.0.2.99", 1500));

        // 2. Unban by exact IP
        let unbanned = aq.unban("192.0.2.50");
        assert!(unbanned);
        assert!(!aq.is_quarantined("192.0.2.99", 1500));
        assert_eq!(aq.active_bans_count(), 0);

        // 3. Trigger ban on another subnet and unban by CIDR
        aq.record_and_check("198.51.100.10", 1000);
        assert!(aq.is_quarantined("198.51.100.10", 1500));
        let unbanned_cidr = aq.unban("198.51.100.0/24");
        assert!(unbanned_cidr);
        assert!(!aq.is_quarantined("198.51.100.10", 1500));
    }

    #[test]
    fn test_unban_all_and_add_ban_rehydration() {
        let aq = AutonomousQuarantine::new(QuarantineConfig {
            infraction_threshold: 1,
            quarantine_duration_ms: 100_000,
            max_tracked_subnets: 100,
        });

        // Ban two distinct subnets
        aq.record_and_check("192.0.2.1", 1000);
        aq.record_and_check("198.51.100.1", 1000);
        assert_eq!(aq.active_bans_count(), 2);

        // Test active_bans snapshot
        let active = aq.active_bans(1500);
        assert_eq!(active.len(), 2);

        // Test unban_all
        let cleared = aq.unban_all();
        assert_eq!(cleared, 2);
        assert_eq!(aq.active_bans_count(), 0);
        assert!(!aq.is_quarantined("192.0.2.1", 1500));

        // Test add_ban for startup rehydration
        let net: IpNet = "203.0.113.0/24".parse().unwrap();
        aq.add_ban(net, 50_000);
        assert!(aq.is_quarantined("203.0.113.42", 1500));
        assert_eq!(aq.active_bans_count(), 1);
    }
}
