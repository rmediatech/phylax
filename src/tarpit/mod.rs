//! # Sovereign Asymmetric Multi-Protocol Tarpit Suite (`src/tarpit/`)
//! Reverses Slowloris, stalls SSH credential-stuffing crawlers, and exhausts botnet thread pools.

pub mod governor;
pub mod ssh_tarpit;
pub mod tcp_tarpit;

pub use governor::{
    AdaptiveTarpitProfile, TarpitConfig, TarpitGovernor, TarpitSlotGuard, TarpitVerdict,
};
pub use ssh_tarpit::{SshTarpitConfig, SshTarpitServer};
pub use tcp_tarpit::{TcpTarpitConfig, TcpTarpitServer};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tarpit_governor_strike_scaling() {
        let gov = TarpitGovernor::new(TarpitConfig {
            trickle_interval_ms: 2000,
            max_duration_s: 30,
            chunk_size: 2,
            max_concurrent_tarpits: 10,
        });

        // Strike 1
        let v1 = gov.acquire_slot("198.51.100.5");
        let g1 = match v1 {
            TarpitVerdict::Engage { slot_guard } => slot_guard,
            _ => panic!("Expected engage"),
        };
        assert_eq!(g1.profile().strike_count, 1);
        assert_eq!(g1.profile().trickle_interval_ms, 2000);

        // Strike 2
        let v2 = gov.acquire_slot("198.51.100.5");
        let g2 = match v2 {
            TarpitVerdict::Engage { slot_guard } => slot_guard,
            _ => panic!("Expected engage"),
        };
        assert_eq!(g2.profile().strike_count, 2);
        assert!(g2.profile().trickle_interval_ms >= 5000);

        // Strike 3 (Maximum penalty)
        let v3 = gov.acquire_slot("198.51.100.5");
        let g3 = match v3 {
            TarpitVerdict::Engage { slot_guard } => slot_guard,
            _ => panic!("Expected engage"),
        };
        assert_eq!(g3.profile().strike_count, 3);
        assert_eq!(g3.profile().trickle_interval_ms, 15_000);
    }
}
