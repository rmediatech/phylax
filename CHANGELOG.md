# 📋 Phylax Changelog & Defense Ledger

All notable changes, defense layer releases, and architectural milestones for **Phylax** (`phylax`) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.7] - 2026-10-27 (Private Subnet Isolation & Headerless Bot Deflection)

### 🌟 Added & Fortified
* **RFC 1918, Loopback & CGNAT Subnet Isolation (`src/autonomous_quarantine.rs`)**:
  - Hardened `AutonomousQuarantine::derive_quarantine_cidr` to strictly enforce `/32` (IPv4) and `/128` (IPv6) single-host boundaries for private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and Carrier-Grade NAT (`100.64.0.0/10`).
  - Completely eliminates collateral damage and accidental quarantine of adjacent legitimate nodes or shared carrier mobile pools. Routable public IPv4 ranges remain strictly quarantined at `/24`.
* **Headerless & Missing User-Agent Interception (`src/bot_guard/mod.rs`)**:
  - Closed perimeter scanner evasion vector where raw socket scripts or custom scrapers omitted the `User-Agent` header.
  - Missing or empty User-Agents on non-infrastructure endpoints are now classified as `BotCategory::AutomationTool` (`Missing-User-Agent`) and blocked with `403 Forbidden` in $< 20\mu\text{s}$.
  - Standard operational infrastructure paths (`/healthz`, `/robots.txt`, `/security.txt`, `/favicon.ico`, `/.well-known/*`) remain permitted for automated cluster health probes.
* **Empirical Multi-OS Crucible Verification**:
  - Verified against live offensive reconnaissance suites via local virtual testing bridge with zero false positives.

---

## [0.2.6] - 2026-10-26 (Adversarial PayloadGuard: 7-Vector Zero-Allocation Defense Against OWASP & Kali Tools)

### 🌟 Added & Fortified
* **Adversarial PayloadGuard (`src/payload_guard.rs` / Layer 15)**:
  - Zero-allocation, zero-panic percent-decoding inspection engine inspecting request paths, headers, and query strings in `< 15ns`.
  - Comprehensive deflection across 7 critical vector classes:
    1. SQL Injection (`union select`, `' or 1=1`, `exec xp_cmdshell`, `sleep(`, `benchmark(`) favored by `sqlmap`.
    2. Path Traversal & LFI (`../`, `..\`, `%2e%2e%2f`, `/etc/passwd`, `/etc/shadow`, `boot.ini`).
    3. Command Injection & RCE shell meta-characters (`;`, `|`, `&&`, `` ` ``, `$(...)`, `wget `, `curl `, `/bin/sh`).
    4. Cross-Site Scripting (`<script>`, `javascript:`, `onerror=`, `onload=`, `eval(`).
    5. SSRF / Cloud Metadata reconnaissance probes (`169.254.169.254`, `metadata.google.internal`, `latest/meta-data`, `gopher://`, `dict://`).
    6. Server-Side Template Injection (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`, `__globals__`, `__builtins__`) used by `nuclei` and `tplmap`.
    7. NoSQL & Object Operator Injection (`{"$gt": ""}`, `{"$ne": null}`, `[$ne]=`, `[$gt]=`).
* **Hard Boundary Enforcement**:
  - Null-byte injection neutralization (`\0`, `%00`).
  - Hard URI length ceilings preventing allocation bombs and regex Denial of Service.

---

## [0.2.5] - 2026-10-21 (Radical OJP Modularity, ANSI/Formula Sanitization & Zero-Panic Hardening)

### 🌟 Added & Fortified
* **Radical One-Job-Principle (OJP) Modular Decomposition**:
  - Decomposed monolithic engines (`pipeline`, `bot_guard`, `threat_harvester`, `decoy_uri`, `abuse_reporting`, and the `phylax` CLI binary) into focused, single-responsibility modules ($\le 300$ lines per file) with zero breaking changes to the public library API.
* **Universal ANSI & Formula Injection Sanitization (`src/sanitize.rs`)**:
  - Added sub-microsecond ANSI CSI/OSC escape sequence scrubbing and spreadsheet formula injection neutralization across all forensic abuse dossiers, CSV/Markdown exports, and telemetry streams.
* **RFC 5737 Test Fixture Sanitization (`SOVEREIGN-SANITIZE-01`)**:
  - Standardized all test fixtures onto RFC 5737 documentation CIDR blocks (`192.0.2.0/24`).

## [0.2.4] - 2026-10-02 (Commercial Cloud, Datacenter & Mass-Scanner Threat Weighting)

### 🌟 Added & Fortified
* **Datacenter & Autonomous Scanner Threat Weighting (`src/subnet_guard.rs` & `src/threat_intel.rs`)**:
  - Ingested authoritative CIDRs for mass vulnerability scanners and cloud hosting infrastructure (`DATACENTER_AND_SCANNER_CIDR_SEEDS`): Censys, Zgrab, Tencent Cloud crawlers, Choopa/Vultr scavengers, Shadowserver, and Rapid7.
  - Introduced `IpRiskCategory`: granular classification of incoming traffic into `Residential`, `Datacenter { matched_cidr }`, or `TorExit { matched_cidr }`.
  - Zero-Tolerance Perimeter Policy: Ingress originating from commercial cloud datacenters and mass-scanners is flagged with high-risk priority, triggering instant quarantine with zero retry leeway upon tripping any honeypot or anomalous path probe.
* **Unit & Subnet TDD Expansion**:
  - Added unit test `test_subnet_guard_evaluates_datacenter_and_residential_risk` verifying accurate classification across residential, Censys, Tencent Cloud, and Tor exit IP ranges.

## [0.2.3] - 2026-10-01 (Dynamic Self-Healing BotGuard, Penetration Testing Arsenal & Canary Traps)

### 🌟 Added & Fortified
* **Autonomous Dynamic Bot Registry (`DynamicBotRegistry`)**:
  - In-memory, thread-safe, bounded auto-learning registry (`DynamicBotRegistry`) for real-time bot harvesting.
  - When an uncatalogued crawler or scanner trips an invisible honeylink or canary trap, its signature token is autonomously extracted, sanitized, and stored.
  - Subsequent incoming requests bearing that signature from **any** IP are preemptively dropped at Layer 14 with `403 Forbidden` without human intervention or server restart.
  - Memory guardrail: Bounded capacity with deterministic LRU eviction.
  - Poisoning immunity: Strictly protects common human browsers (`Mozilla`, `Chrome`, `Safari`, `WebKit`), developer CLI tools (`curl`, `wget`), and verified search indexers (`Googlebot`, `Bingbot`).
* **Kali Linux & Offensive Security Penetration Arsenal Coverage**:
  - Expanded `AUTOMATION_TOOL_SIGNATURES` with comprehensive offensive security, exploit, and forensics signatures:
    - **Fuzzers & Content Discovery**: `ffuf`, `feroxbuster`, `dirsearch`, `DirBuster`, `Gobuster`, `wfuzz`, `Nuclei`, `Arjun`, `ParamSpider`
    - **Vulnerability Scanners**: `Acunetix`, `Nessus`, `OpenVAS`, `BurpSuite`, `BurpCollaborator`, `OWASP ZAP`, `Arachni`, `WhatWeb`, `WPRecon`, `WPScan`, `Netsparker`, `QualysGuard`, `Qualys`
    - **Exploit & Injection Engines**: `sqlmap`, `SQLNinja`, `Commix`, `Havij`, `Metasploit`
    - **Password Sprayers & Bruteforcers**: `THC-Hydra`, `Medusa`, `Patator`, `Crowbar`
    - **Network Scanners & Asset Recon**: `RustScan`, `OWASP Amass`, `Sublist3r`, `assetfinder`, `Katana`, `zgrab`, `masscan`, `nmap`, `nikto`
    - **Forensics Suites**: `EnCase`, `Autopsy`, `SleuthKit`, `X-Ways`, `Magnet AXIOM`
* **Adversarial Self-Attack TDD Invariants**:
  - Added `test_adversarial_kali_and_offensive_penetration_arsenal` verifying zero bypasses across the offensive security arsenal.
  - Added `test_adversarial_dynamic_self_healing_honeylink_harvesting` verifying dynamic self-healing lifecycle and browser spoofing immunity.

## [0.2.2] - 2026-10-01 (Sovereign BotGuard, AI Harvester Interception & RFC 9309 Defense)

### 🌟 Added & Enhanced
* **Sovereign Bot Guard & User-Agent Classification Engine (`src/bot_guard.rs` - Layer 14)**:
  - Sub-microsecond, zero-allocation User-Agent classification engine (`BotGuard`) executing in `<10ns`.
  - Comprehensive canonical signature registry covering both legacy and newly rebranded search/web bots:
    - **Anthropic**: `ClaudeBot`, `anthropic-ai`, `Claude-SearchBot`, `Claude-Web`
    - **OpenAI**: `GPTBot`, `ChatGPT-User`, `OAI-SearchBot`
    - **Google AI**: `Google-Extended` (isolated from legitimate search indexing)
    - **Meta / Apple**: `Meta-ExternalAgent`, `Meta-ExternalFetcher`, `FacebookBot`, `facebookexternalhit`, `Applebot-Extended`
    - **ByteDance / TikTok**: `Bytespider`, `TikTokBot`, `BytespiderBot`
    - **Profilers & Scanners**: `BuiltWith`, `CensysInspect`, `Censys`, `Shodan`, `SemrushBot`, `AhrefsBot`, `DotBot`, `MJ12bot`
    - **Automation & Exploit Tools**: `Scrapy`, `Go-http-client`, `python-requests`, `aiohttp`, `httpx`, `sqlmap`, `nmap`, `nikto`, `masscan`
  - Invariant rules:
    - `/robots.txt` bypass is permanently guaranteed so compliant crawlers discover their exclusions.
    - Developer CLI routes (`/install/*`, `/bin/*`, `/checksums/*`, `/healthz`) permit `curl` & `wget`.
    - Legitimate search engines (`Googlebot`, `Bingbot`, `DuckDuckBot`, `Slurp`, `Baiduspider`, `YandexBot`) are permitted on public storefronts.
* **Adversarial Self-Attack TDD Suite (`tests/adversarial_bot_guard_tests.rs`)**:
  - 7/7 comprehensive red-team test batteries passing in `<0.01s`:
    - Full registry coverage asserting every old and new signature variant.
    - Mixed-case mutations and whitespace padding evasion fuzzing (`cLaUdE-sEaRcHbOt`, `bUiLtWiTh`).
    - Terminal ANSI escape code & CSI/OSC poisoning neutralization.
    - Formula injection (`=cmd|...`) and code execution payload resistance.
    - Null-byte boundary corruptions (`\0`).
    - Header allocation bomb guardrail ($>4\text{KB}$ immediately flagged as buffer exhaustion attacks).
    - Zero false-positive invariant asserting 100% pass-through for legitimate search engines and human browsers.

---

## [0.2.1] - 2026-10-01 (Vendor-Agnostic Threat Intelligence, Dynamic Versioning & Sovereign Packaging)

### 🌟 Added & Enhanced
* **Vendor-Agnostic Threat Intelligence & Incident Sinks (Non-Patching BYOK Architecture)**:
  - Added native Syslog / CEF (Common Event Format) sink (`--syslog-cef`, `syslog_cef = true`) for 100% air-gapped, local SIEM audit logging with zero third-party external HTTP calls.
  - Enhanced generic webhook sink (`--webhook-url`, `--webhook-auth`) with structured JSON dossiers for direct alerting to Datadog, Splunk, Wazuh, Slack, or Discord.
  - Retained AbuseIPDB community sink (`--abuseipdb-key`) with built-in token-bucket rate limiting and 24-hour sliding deduplication cooldown.
  - Unified multi-sink parallel broadcast (`MultiSink`) when multiple destinations are specified.
* **Dynamic Clap CLI Versioning**:
  - Replaced static string literals with dynamic `#[command(version)]` binding directly to `Cargo.toml` (`0.2.1`).
* **Sovereign Release & Cryptographic Packaging Pipeline (`scripts/release.sh`)**:
  - Implemented automated release packaging adhering to `SOVEREIGN-SIGN-01`.
  - Generates SHA-256 digests (`.sha256`, `SHA256SUMS`) and detached OpenPGP Ed25519 signatures (`.asc`, `SHA256SUMS.asc`) using the sovereign release key (`4E428019A109578B`).
* **Clean-Room Distro-Agnostic Installer (`scripts/install.sh` & `scripts/install.ps1`)**:
  - Dynamic release tag discovery resolving `v*` tag names on GitHub Releases with zero-API-rate-limit redirect inspection.
  - Automatic download and installation of analytics suite (`phylax-analyze-traffic`, `phylax-threat-recon`) even during curl-piped one-liner executions without git cloning.
* **Agnostic Threat Reconnaissance Toolkit (`phylax-threat-recon`)**:
  - Added `--webhook <URL>` support for automated incident reporting to custom endpoints.
  - Auto-discovers credentials from `.env`, `.bashrc`, and `phylax.toml`.
  - Scrubbed machine-specific paths; supports standard `/var/log` paths and sovereign project roots.
* **Adversarial Test Assertions (`POC TDD+++++`)**:
  - 114/114 core unit, integration, and active defense tests passing in `< 0.15s`.
  - Verified on Buffalo NAS KVM VM (`citadel-vm1`) clean-room environment.
* **Cross-Platform Windows IOCP Engine & PowerShell 5.1/Core Hardening**:
  - Validated native compilation for `x86_64-pc-windows-gnu` PE32+ 64-bit binaries.
  - Executed automated 7-test verification suite on Windows Server 2022 KVM VM (`citadel-win1`):
    - Sub-microsecond microbenchmark on Windows: Honeypot validation `8.74 ns`, total perimeter evaluation `1005.09 ns` (> 994,000 req/sec/core).
    - In-memory Radix IP CIDR subnet blocking validated (`193.189.100.1` blocked by `193.189.100.0/24`).
  - Hardened `phylax-analyze-traffic.ps1` and `phylax-threat-recon.ps1` for PowerShell 5.1 ANSI (Windows-1252) parser compatibility by enforcing 7-bit ASCII status tokens, explicit positional parameter bindings (`Position = 0`), and `-f` format strings, eliminating emoji byte sequence parsing exceptions on legacy Windows PowerShell engines while preserving 100% parity on PowerShell Core 7+.

---

## [0.2.0] - 2026-09-28 (Sovereign Observability & Red-Team Suite)

### 🌟 Added
* **Cross-Platform Analytics & Threat Recon Suite (`tools/analytics/`)**:
  - Implemented 100% feature-parity red-team and traffic intelligence tools across POSIX `/bin/sh` and PowerShell Core (`.ps1`).
  - Added `phylax-analyze-traffic` with Native Sovereign Context Auto-Discovery ("Royalty Mode") for auto-detecting SQLite WAL, journalctl, and application log stores across `rmediatech`, `matrix`, `propylea`, and standalone systems.
  - Added `phylax-threat-recon` for autonomous IP threat correlation, multi-subnet anomaly detection, and AbuseIPDB reputation auditing.
* **Automated Red-Team Fuzzing Battery (`tools/redteam_script_fuzzer/`)**:
  - Enforced Adversarial Self-Attack invariant validating telemetry scripts against ANSI escape sequence injection, ReDoS patterns, shell injection payloads, and symlink traversals.
* **Cryptographic Provenance Release Signing (`SOVEREIGN-SIGN-01`)**:
  - Published Ed25519 sovereign public release key (`SOVEREIGN_RELEASE_KEY.asc`, Key ID: `4E428019A109578B`).
  - Automated detached GPG signature generation (`.asc`) and SHA-256 manifests across distributed releases.
* **Closed-Loop Zero-Day Threat Harvester (Layer 13)**:
  - Added mathematical clustering over anomalous `404` probe paths across distinct IPv4 subnets.
  - Autonomous elevation from passive tracking into in-memory active decoy trie.

---

## [0.1.0] - 2026-09-16 (13-Layer Sovereign Edge Defense Engine)

### 🌟 Added
* **13-Layer In-Memory Defense Engine**:
  - **Layer 1 (CIDR Blocklist)**: Radix IP trie evaluating millions of hostile IPv4/IPv6 ranges in `< 25ns`.
  - **Layer 2 (Allowlist / Fast Path)**: Microsecond whitelist bypass for known trusted internal IPs and loopback.
  - **Layer 3 (HTTP Method Gate)**: Rejection of non-standard and dangerous HTTP verbs.
  - **Layer 4 (Protocol Strictness)**: Enforces RFC HTTP compliance and header sanitization.
  - **Layer 5 (Host Header Alignment)**: Rejection of forged Host headers and direct IP scanning.
  - **Layer 6 (Header Hygiene)**: Stripping suspicious hop-by-hop headers and proxy injection attempts.
  - **Layer 7 (User-Agent Bot Classifier)**: Sub-microsecond regex and token classifier intercepting headless scrapers, vulnerability scanners, and AI crawling bots.
  - **Layer 8 (Honeypot Decoy Fields)**: Invisible HTML traps (`website_url`, `company_fax`) that trigger immediate bot deflection upon population.
  - **Layer 9 (Decoy Path Prefix Trie)**: Nanosecond interception of scanning paths (`/.env`, `/wp-admin`, `/.git/config`) returning stealth `404 Not Found`.
  - **Layer 10 (Dynamic Latency Token Guard)**: Cryptographically enforces human cognitive interaction delays ($\ge 1.5$s) using HMAC-SHA256 tokens.
  - **Layer 11 (Quadratic Adaptive PoW)**: Progressive client-side CPU Proof-of-Work challenge scaling quadratically for repeat offenders.
  - **Layer 12 (Reverse Slowloris Tarpit)**: Asynchronous slow-trickle socket hostage mode exhausting bot connection pools with zero server CPU overhead.
  - **Layer 13 (Threat Harvester & Collaborative Abuse Reporting)**:
    - Asynchronous event dispatcher submitting forensic incident dossiers to **AbuseIPDB** v2 API under strict token-bucket rate limits.
* **Coturn WebRTC Relay Guard (`TurnGuard`)**:
  - Cryptographic session-bound ephemeral credentials preventing unauthorized WebRTC TURN relay bandwidth theft.
* **Axum & Hyper Middleware Integrations**:
  - Zero-allocation Axum middleware layers for seamless drop-in protection in Rust web services.
