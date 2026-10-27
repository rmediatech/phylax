# Chapter 6: Production Deployment & Runbook

> **Namespace:** `phylax::ops`  
> **Previous:** [05: Autonomous Abuse Intelligence](05_AUTONOMOUS_ABUSE_INTELLIGENCE.md) | **Return:** [Master Index](INDEX.md)

---

## 1. Hardware Sizing & Capacity Planning

Because `phylax` executes zero-allocation bitwise comparisons and radix tree lookups in memory, its compute and RAM requirements are exceptionally minimal:

| Deployment Tier | Daily Request Volume | Recommended vCPU | RAM Allocation | Deployment Topology |
|---|---|---|---|---|
| **Starter / Edge Node** | Up to 5,000,000 req/day | 1 vCPU (AMD/Intel) | `256 MB` | Embedded inside Axum/Actix binary |
| **Enterprise SFU Cluster** | 50,000,000+ req/day | 2 – 4 vCPUs | `512 MB – 1 GB` | Embedded across application workers |
| **Standalone Proxy Gate** | 100,000,000+ req/day | 4 – 8 vCPUs | `1 GB – 2 GB` | Standalone `phylax serve` WAF daemon |

---

## 2. Reverse Proxy Integration (Caddy & Nginx)

When deploying behind a frontend TLS terminator such as **Caddy**, ensure client IP headers are correctly propagated:

### Caddyfile Configuration (`/etc/caddy/Caddyfile`)

```caddyfile
app.example.com {
    encode zstd gzip

    # Preserve real client IP for Phylax edge evaluation
    header {
        X-Real-IP {remote_host}
        X-Forwarded-For {remote_host}
    }

    # Proxy to Phylax-protected Axum backend
    reverse_proxy 127.0.0.1:3000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

---

## 3. Universal Service Management (Distro-Agnostic)

Phylax provides a universal, POSIX-compliant service lifecycle manager at [`scripts/phylax-service.sh`](../scripts/phylax-service.sh) that works across **any Linux distribution** (Ubuntu, Debian, Fedora, RHEL, CentOS, Arch, Alpine Linux, Gentoo).

It automatically detects your host's init system:
- **`systemd`** (Ubuntu, Debian, Fedora, Arch, RHEL, Rocky, openSUSE)
- **`OpenRC`** (Alpine Linux, Gentoo)
- **`SysVinit`** (Debian/CentOS legacy fallback)

### Automated Service Management Commands

#### Production (System-Wide Service with Dedicated Security User)

```bash
# 1. Install & register the service (creates user, unit files, and enables on boot)
sudo ./scripts/phylax-service.sh install

# 2. Check service health, active PID, and live journal logs
sudo ./scripts/phylax-service.sh status

# 3. Start, stop, or restart the service
sudo ./scripts/phylax-service.sh start
sudo ./scripts/phylax-service.sh stop
sudo ./scripts/phylax-service.sh restart

# 4. Reset service (flushes transient logs/state and restarts cleanly)
sudo ./scripts/phylax-service.sh reset

# 5. Cleanly uninstall & unregister service files
sudo ./scripts/phylax-service.sh uninstall
```

#### Development & Rootless (`systemd --user`)

Developers and non-root operators can install and manage Phylax without `sudo` or root privileges:

```bash
# 1. Install as user service (~/.config/systemd/user/phylax.service)
./scripts/phylax-service.sh install --user

# 2. Check service health and live logs
./scripts/phylax-service.sh status --user

# 3. Start, stop, or restart
./scripts/phylax-service.sh start --user
./scripts/phylax-service.sh stop --user
./scripts/phylax-service.sh restart --user

# 4. Reset or uninstall
./scripts/phylax-service.sh reset --user
./scripts/phylax-service.sh uninstall --user
```

> 🧪 **Rigorous Verification:** The service manager is verified by a 37-tier POSIX compliance TDD test suite ([`scripts/tests/phylax_service_tdd.sh`](../scripts/tests/phylax_service_tdd.sh)) guaranteeing zero bashisms and complete portability across `sh`, `ash` (BusyBox), `dash`, and `bash`.

---

### Manual Systemd Service Unit Template (Optional)

If you prefer to configure systemd manually without the automated script, create `/etc/systemd/system/phylax.service`:

```ini
[Unit]
Description=Phylax Sovereign Edge Defense Proxy Daemon
After=network.target network-online.target
Wants=network-online.target
Documentation=https://github.com/rmediatech/phylax

[Service]
Type=simple
User=phylax
Group=phylax
ExecStart=/usr/local/bin/phylax serve --config /etc/phylax/phylax.toml
Restart=always
RestartSec=3s
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

# Hardened Security Sandboxing
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/phylax /etc/phylax
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable and start manually:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now phylax.service
sudo systemctl status phylax.service
```

---

### Windows Production Deployment (Windows Service & IOCP)

Phylax runs natively on **Windows Server 2019/2022/2025** and **Windows 10/11**, powered by Windows I/O Completion Ports (IOCP) delivering sub-microsecond edge defense (> 990,000 req/sec/core).

#### 1. Automated Installation via PowerShell
```powershell
# Installs phylax.exe, sample phylax.toml, and analytics tools into C:\Program Files\Phylax
irm https://raw.githubusercontent.com/rmediatech/phylax/main/scripts/install.ps1 | iex
```

#### 2. Configure Windows Defender Firewall Port
```powershell
New-NetFirewallRule -DisplayName "Phylax Edge Proxy" -Direction Inbound -LocalPort 3000 -Protocol TCP -Action Allow
```

#### 3. Run as an Autonomous Windows Service (NSSM)
```powershell
choco install nssm -y

nssm install Phylax "C:\Program Files\Phylax\phylax.exe" "serve --config C:\ProgramData\Phylax\phylax.toml"
nssm set Phylax AppStdout "C:\ProgramData\Phylax\phylax.log"
nssm set Phylax AppStderr "C:\ProgramData\Phylax\phylax.err.log"
nssm set Phylax Start SERVICE_AUTO_START

Start-Service Phylax
Get-Service Phylax
```

---

### macOS Production Deployment (Launchd Daemon)

On **macOS** (Apple Silicon M1–M4 & Intel Darwin), Phylax binds directly to Apple's native `kqueue` kernel event subsystem.

#### 1. Native Build & Installation
```bash
cargo build --release
sudo cp target/release/phylax /usr/local/bin/phylax
sudo mkdir -p /etc/phylax /var/log/phylax
```

#### 2. Launchd Plist Daemon (`/Library/LaunchDaemons/com.rmediatech.phylax.plist`)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rmediatech.phylax</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/phylax</string>
        <string>serve</string>
        <string>--config</string>
        <string>/etc/phylax/phylax.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/phylax/output.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/phylax/error.log</string>
</dict>
</plist>
```

#### 3. Load & Start Service
```bash
sudo chown root:wheel /Library/LaunchDaemons/com.rmediatech.phylax.plist
sudo launchctl load -w /Library/LaunchDaemons/com.rmediatech.phylax.plist
sudo launchctl list | grep phylax
```

---

## 4. Verification & Testing Runbook

### Test 1: Verify Stealth Deception Black Hole
Send a registration request containing a non-empty decoy honeypot field (`website_url`):

```bash
$ curl -i -X POST http://127.0.0.1:3000/api/auth/register \
       -H "Content-Type: application/json" \
       -d '{"username":"bot_tester","email":"bot@test.com","website_url":"http://malicious.xyz"}'

HTTP/1.1 201 Created
Content-Type: application/json

{"status":"SUCCESS","user_id":0,"uuid":"usr_stealth_trap","message":"Account created successfully."}
```
✅ **Expected Behavior:** Returns `201 Created`. Zero database rows are inserted, and the IP is logged/quarantined in memory.

### Test 2: Verify Perimeter Ghosting (404 Drop)
Send a probe from a quarantined IP or simulated hostile subnet:

```bash
$ curl -i http://127.0.0.1:3000/api/auth/register \
       -H "X-Forwarded-For: 185.220.101.5"

HTTP/1.1 404 Not Found
Content-Type: text/plain

404 Not Found
```
✅ **Expected Behavior:** Returns generic `404 Not Found`. The attacker cannot detect firewall presence.

### Test 3: Solve PoW Challenge Client-Side
Issue a challenge and compute the valid SHA-256 nonce using the CLI:

```bash
# 1. Issue challenge
$ phylax challenge --difficulty 12
{"challenge":"...","difficulty":12,"expires_at":...}

# 2. Solve challenge
$ phylax solve --seed "<CHALLENGE_SEED>" --difficulty 12
Solved puzzle in 4.2ms. Nonce: 38291
```

---

## 5. Zero-Downtime Autonomous Self-Healing Mesh

In high-concurrency 24/7 edge environments, `phylax` and `propylea` coordinate multi-engine state pruning and memory reclamation automatically:

```mermaid
flowchart TD
    TICK["⏰ 60-Second Autonomous Timer"] --> MGR["MaintenanceManager::run_maintenance"]
    
    subgraph HygienePass["Zero-Lock State Pruning (<15µs)"]
        MGR --> PRUNE_CIDR["Purge Expired Subnet Bans"]
        MGR --> DECAY_POW["Decay PoW Infractions to Baseline"]
        MGR --> EVICT_THREAT["Evict Stale Threat Candidates (Layer 13)"]
    end
    
    HygienePass --> TRIM["libc::malloc_trim(0) Heap Deflation"]
    TRIM --> METRICS["Telemetry & Audit Reporting"]
    
    subgraph Watchdog["Autonomous Watchdog Loop"]
        WATCH["Heartbeat Probe (GET /healthz)"] --> CHECK{"Status 200 in <500µs?"}
        CHECK -- Yes (Empirical: 80µs-128µs) --> OK["Healthy Operational State"]
        CHECK -- Timeout / Crash --> RESTART["Systemd / OpenRC Auto-Restart (<1s)"]
    end
```

---

## 6. Epilogue: The Sovereign Security Manifesto

The modern web does not need heavier middleboxes, invasive cloud proxies, or external data brokers inspecting private packets.

By embedding mathematically sound, cost-hierarchical defenses directly into modern compiled systems (Rust), application authors regain complete sovereignty over:
- **Their Users' Privacy**: Zero telemetry leaks to third-party ad/tracking networks.
- **Their Application Latency**: Sub-microsecond edge evaluation preserving real-time audio, video, and WebSocket performance.
- **Their Defense Posture**: Active stealth deception that turns attackers' automation against themselves.

`phylax` stands watch.

---

[← Return to Master Index](INDEX.md)
