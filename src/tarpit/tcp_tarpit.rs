//! # Generic Raw TCP / Decoy Port Tarpit Engine (`tarpit/tcp_tarpit.rs`)
//! Holds malicious port scanners and automated exploit scripts hostage on decoy ports.

use crate::tarpit::governor::{TarpitGovernor, TarpitVerdict};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct TcpTarpitConfig {
    pub bind_addr: String,
    pub tick_ms: u64,
    pub max_duration_s: u64,
    pub max_clients: usize,
    pub initial_greeting: Option<String>,
}

impl Default for TcpTarpitConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:2525".to_string(), // e.g. Decoy SMTP
            tick_ms: 5000,                         // 1 byte every 5 seconds
            max_duration_s: 300,                   // 5 minutes
            max_clients: 256,
            initial_greeting: Some(
                "220-sovereign-perimeter.local SMTP Service Ready\r\n".to_string(),
            ),
        }
    }
}

pub struct TcpTarpitServer {
    config: TcpTarpitConfig,
    governor: TarpitGovernor,
    active_clients: Arc<AtomicUsize>,
}

impl TcpTarpitServer {
    pub fn new(config: TcpTarpitConfig, governor: TarpitGovernor) -> Self {
        Self {
            config,
            governor,
            active_clients: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn active_clients_count(&self) -> usize {
        self.active_clients.load(Ordering::SeqCst)
    }

    pub async fn run(&self, mut shutdown_rx: watch::Receiver<bool>) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        let active = Arc::clone(&self.active_clients);
        let config = self.config.clone();
        let gov = self.governor.clone();

        loop {
            tokio::select! {
                res = listener.accept() => {
                    let (stream, peer_addr) = match res {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    if active.load(Ordering::SeqCst) >= config.max_clients {
                        drop(stream);
                        continue;
                    }

                    let client_ip = peer_addr.ip().to_string();
                    let verdict = gov.acquire_slot(&client_ip);

                    let slot_guard = match verdict {
                        TarpitVerdict::Engage { slot_guard } => slot_guard,
                        TarpitVerdict::CeilingExceededDrop => {
                            drop(stream);
                            continue;
                        }
                    };

                    active.fetch_add(1, Ordering::SeqCst);
                    let active_cloned = Arc::clone(&active);
                    let tick = Duration::from_millis(slot_guard.profile().trickle_interval_ms.max(config.tick_ms));
                    let max_dur = Duration::from_secs(config.max_duration_s);
                    let greeting = config.initial_greeting.clone();

                    tokio::spawn(async move {
                        let _guard = slot_guard;
                        Self::handle_client(stream, peer_addr, tick, max_dur, greeting).await;
                        active_cloned.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_client(
        mut stream: TcpStream,
        _peer_addr: SocketAddr,
        tick: Duration,
        max_duration: Duration,
        greeting: Option<String>,
    ) {
        if let Some(g) = greeting {
            if stream.write_all(g.as_bytes()).await.is_err() {
                return;
            }
        }

        let start = tokio::time::Instant::now();
        let mut byte_val = 0x20u8; // Start with space / newline printable character

        while start.elapsed() < max_duration {
            tokio::time::sleep(tick).await;
            if stream.write_all(&[byte_val]).await.is_err() {
                break;
            }
            if stream.flush().await.is_err() {
                break;
            }
            byte_val = if byte_val == 0x7e { 0x20 } else { byte_val + 1 };
        }
    }
}
