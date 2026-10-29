# 🛡️ Phylax Sovereign Analytics & Observability Suite

> **Sovereign Standard:** High-Performance Zero-Dependency Infrastructure Observability  
> **Architecture:** Zero-dependency, pure POSIX `/bin/sh` + Native PowerShell Core (`.ps1`).  
> **Security Invariant:** Defensively hardened against log poisoning, ANSI escape terminal hijacking, command injection, and ReDoS buffer attacks.

---

## 🌟 Overview & Duality Architecture

The Phylax Analytics Suite operates in two seamless operational modes:

1. **Universal Agnostic Mode:** Ingests any standard access log, combined web log, or JSON stream via pipe or file argument. Runs on Linux (Musl/Glibc), macOS, FreeBSD, Solaris/illumos, and Windows.
2. **Native Sovereign Auto-Discovery ("Royalty Mode"):** When executed within a service directory without arguments, it automatically discovers local logs, databases, and telemetry stores to deliver instant forensic intelligence.

---

## 🚀 Quickstart & Usage

### 1. Ingress Traffic & Market Demand Analyzer (`phylax-analyze-traffic`)

* **POSIX:** `./tools/analytics/phylax-analyze-traffic.sh`
* **PowerShell:** `.\tools\analytics\phylax-analyze-traffic.ps1`

```bash
# Auto-discover local logs (in project root or on systemd server)
./tools/analytics/phylax-analyze-traffic.sh

# Ingest live piped stream (e.g. journalctl or log tail)
journalctl -u web-service -n 200 --no-pager | phylax-analyze-traffic.sh

# Analyze a specific access log file
./tools/analytics/phylax-analyze-traffic.sh /var/log/access.log

# Emit structured JSON for piping into jq or alerts
cat /var/log/access.log | phylax-analyze-traffic.sh --json | jq .
```

### 2. Threat Actor Reconnaissance & Abuse Reporting (`phylax-threat-recon`)

* **POSIX:** `./tools/analytics/phylax-threat-recon.sh`
* **PowerShell:** `.\tools\analytics\phylax-threat-recon.ps1`

```bash
# Auto-discover recent hostile 4xx/404 offenders on the host
./tools/analytics/phylax-threat-recon.sh

# Inspect specific IP entities with Geo, ASN, and AbuseIPDB scores
./tools/analytics/phylax-threat-recon.sh 45.138.12.14 169.40.142.74

# Autonomously dispatch formal incident dossiers to AbuseIPDB
./tools/analytics/phylax-threat-recon.sh -n 5 --report

# Emit structured JSON
./tools/analytics/phylax-threat-recon.sh -n 5 --json
```

---

## 🧠 Intelligence & Gap Discovery

The analyzer doesn't just calculate status codes; it extracts strategic insights:

* **Latency Profiling:** Upstream microsecond execution times and averages.
* **404 Market Demand Discovery:** Differentiates between hostile vulnerability scanners (WordPress, Spring Actuators, Truffle Web3 secret probes) and **🔥 Potential Market Demand / Missing APIs** where users or integrators are seeking unbuilt endpoints (e.g., `/api/v1/stream`, `/sdk`).
* **Multi-Subnet Ingress Correlation:** Groups hostile and legitimate traffic by IPv4 `/24` and IPv6 `/48` CIDR blocks.

---

## 🧪 Testing & Adversarial Verification

All scripts must pass both standard TDD verification and adversarial self-attack fuzzing:

```bash
# Run the POC TDD Test Suite (file, pipe, JSON schema, category assertions)
./tools/tests/test_analytics.sh

# Run the Adversarial Red-Team Fuzzer (command injection, ANSI escapes, quote breakouts, 100KB ReDoS)
./tools/tests/redteam_fuzzer.sh
```
