//! # Endless SSH Tarpit Engine (`tarpit/ssh_tarpit.rs`)
//! Holds malicious SSH brute-forcers, scanners, and botnets hostage with an endless stream of banner lines.

use crate::tarpit::governor::{TarpitGovernor, TarpitVerdict};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct SshTarpitConfig {
    pub bind_addr: String,
    pub delay_ms: u64,
    pub max_lines: usize,
    pub max_clients: usize,
}

impl Default for SshTarpitConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:2222".to_string(),
            delay_ms: 10_000, // 10 seconds per banner line
            max_lines: 3600,  // up to 10 hours per hostile scanner
            max_clients: 512,
        }
    }
}

pub struct SshTarpitServer {
    config: SshTarpitConfig,
    governor: TarpitGovernor,
    active_ssh_clients: Arc<AtomicUsize>,
}

impl SshTarpitServer {
    pub fn new(config: SshTarpitConfig, governor: TarpitGovernor) -> Self {
        Self {
            config,
            governor,
            active_ssh_clients: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn active_clients_count(&self) -> usize {
        self.active_ssh_clients.load(Ordering::SeqCst)
    }

    /// Spawns the async SSH tarpit TCP listener
    pub async fn run(&self, mut shutdown_rx: watch::Receiver<bool>) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        let active = Arc::clone(&self.active_ssh_clients);
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
                    let delay = Duration::from_millis(slot_guard.profile().trickle_interval_ms.max(config.delay_ms));
                    let max_lines = config.max_lines;

                    tokio::spawn(async move {
                        let _guard = slot_guard;
                        Self::handle_client(stream, peer_addr, delay, max_lines).await;
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

    pub async fn handle_client(
        mut stream: TcpStream,
        _peer_addr: SocketAddr,
        delay: Duration,
        max_lines: usize,
    ) {
        for line_idx in 0..max_lines {
            // RFC 4253 allows arbitrary lines of pre-banner text before the SSH-2.0 identifier
            let banner_line = format!(
                "OpenSSH-Banner-Padding_{:08x}_{:04x}\r\n",
                line_idx,
                line_idx * 31 % 65535
            );
            if stream.write_all(banner_line.as_bytes()).await.is_err() {
                break;
            }
            if stream.flush().await.is_err() {
                break;
            }
            tokio::time::sleep(delay).await;
        }
    }
}
