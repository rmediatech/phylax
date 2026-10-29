# Phylax Sovereign Edge Defense — Documentation & OJP Master Index

> **φύλαξ** (*phýlax* — ancient Greek for *"watcher, sentinel, guardian"*)  
> Sovereign 15-layer zero-telemetry edge defense, honeypot tarpit, and autonomous threat neutralization engine written in pure Rust.

Welcome to the **Phylax Optimal Journey Path (OJP)** documentation suite. This documentation is organized progressively—from fundamental architecture and core security paradigms to battle-tested production case studies, runnable integration guides, and operational runbooks.

---

## 🗺️ Optimal Journey Path (OJP) Sitemap

```mermaid
flowchart TD
    HOME["📖 README.md<br/>(Quickstart & Showcase)"] --> INDEX["🗺️ docs/INDEX.md<br/>(Master OJP Navigation)"]
    
    subgraph CoreFoundations["1. Core Concepts & Architecture"]
        INDEX --> ARCH["01_ARCHITECTURE_AND_COST_HIERARCHY.md<br/>• 15-Layer Cost Hierarchy<br/>• Sub-Microsecond Execution Budget<br/>• Layer 0.5 Decoy Honeyroutes & Layer 13 Harvester"]
        ARCH --> DECEPT["02_STEALTH_DECEPTION_AND_ACTIVE_DEFENSE.md<br/>• Silent Neutralization vs 403 Leakage<br/>• Synthetic 201 Black Holes<br/>• Reverse Slowloris Tarpit & PoW Ratcheting"]
    end

    subgraph ProductionBattlefield["2. Battle-Tested Showcase"]
        DECEPT --> WEBRTC_SHOWCASE["03_CASE_STUDY_WEBRTC_PRODUCTION.md<br/>• Real-World Showcase: Production WebRTC Media Mesh<br/>• Dual-Shield Edge: Propylea L7 + In-Process Phylax<br/>• Real Crawler & Exploit Spray Telemetry"]
    end

    subgraph IntegrationAndOps["3. Implementation & Operations"]
        WEBRTC_SHOWCASE --> INTEGRATE["04_INTEGRATION_AND_FRAMEWORK_GUIDE.md<br/>• Axum / Actix-web / Tower<br/>• Standalone Reverse Proxy & Propylea L7<br/>• Threat Candidate Lifecycle State Machine"]
        INTEGRATE --> ABUSE["05_AUTONOMOUS_ABUSE_INTELLIGENCE.md<br/>• Optional AbuseIPDB v2 Reporting<br/>• 15-Minute Sliding Window Rate Governor<br/>• Forensic Dossier & SIEM Webhook Dispatch"]
        ABUSE --> RUNBOOK["06_PRODUCTION_DEPLOYMENT_AND_RUNBOOK.md<br/>• Systemd & Distro-Agnostic Service Manager<br/>• Autonomous 60s Hygiene & Memory Reclamation<br/>• Hardware Sizing & Empirical Benchmarks"]
    end
```

---

## 📚 Chapters Overview

| # | Chapter | Key Topics | Target Audience |
|---|---|---|---|
| **01** | [**Architecture & Cost Hierarchy**](01_ARCHITECTURE_AND_COST_HIERARCHY.md) | 15 defensive layers (Quarantine, Decoys, Honeypots, Radix Subnets, Email Sanitizer, Timing, PoW, Credential Bloom, Velocity, Session, TurnGuard, DistGuard, StreamGuard, Cache, Threat Harvester, BotGuard, and PayloadGuard). | Architects, Security Engineers |
| **02** | [**Stealth Deception & Active Defense**](02_STEALTH_DECEPTION_AND_ACTIVE_DEFENSE.md) | Why 403 Forbidden leaks intel, Deceptive Black Holes (`201 Created`), login timing equalization, reverse Slowloris socket-hostage mode, quadratic PoW ratcheting. | Security Researchers, App Developers |
| **03** | [**Case Study: Production WebRTC Media Engine**](03_CASE_STUDY_WEBRTC_PRODUCTION.md) | Battle-tested production deployment protecting real-time WebRTC media pipelines. Dual-Shield edge topology with reverse proxy, zero-latency WebRTC `TurnGuard`, real-world crawler telemetry. | Engineering Leads, CTOs |
| **04** | [**Integration & Framework Guide**](04_INTEGRATION_AND_FRAMEWORK_GUIDE.md) | 3 deployment paths: In-process Axum/Actix middleware, Propylea L7 reverse proxy gateway, standalone WAF daemon; frontend `phylax.js` helper. | Full-Stack Developers, SREs |
| **05** | [**Autonomous Abuse Intelligence**](05_AUTONOMOUS_ABUSE_INTELLIGENCE.md) | Non-blocking AbuseIPDB v2 reporting, multi-subnet forensic dossiers, per-IP sliding window token governors, zero-config credential discovery. | SecOps, Incident Responders |
| **06** | [**Production Deployment & Runbook**](06_PRODUCTION_DEPLOYMENT_AND_RUNBOOK.md) | Systemd units, distro-agnostic service script, autonomous 60s memory hygiene pass (`malloc_trim`), live traffic tuning, production epilogue. | Sysadmins, DevOps |

---

## 🏛️ Sovereign Defense Topology: Phylax vs. Propylea vs. Cloud WAF

| Defensive Dimension | `phylax` (Native Crate) | `propylea` (L7 Gateway) | Commercial Cloud WAF |
|---|---|---|---|
| **Placement Boundary** | In-Process inside Application | Public Edge Reverse Proxy | Third-Party External Network |
| **Evaluation Latency** | **`< 950 nanoseconds`** | **`< 15 microseconds`** | 20 ms – 80 ms (RTT jitter) |
| **Data Privacy** | **Zero Telemetry** (100% Sovereign) | **Zero Telemetry** (100% Sovereign) | Plaintext TLS decrypted externally |
| **Reconnaissance Countermeasure** | Stealth Deception & Black Holes | Stealth 404 & Active Decoy Traps | Explicit 403 / 429 (fingerprintable) |
| **Zero-Day Discovery** | Multi-Subnet Correlation (Layer 13) | Upstream 404 Feedback Loop | Manual signature / CVE patch delay |
| **Hostile Compute Burn** | Reverse Slowloris + Adaptive PoW | Early Edge Socket Drop | None (attacker burns your bill) |
| **Infrastructure Cost** | **$0** (Compiled in application) | **$0** (Standalone Rust binary) | Recurring monthly / bandwidth fees |

## 🚀 Quick Navigation Links

- **Main Repository Overview:** [`README.md`](../README.md)
- **Live Runnable Examples:**
  - Standard Axum Edge Defense: [`examples/axum_edge_defense.rs`](../examples/axum_edge_defense.rs)
  - Stealth Deception & Black Hole Defense: [`examples/stealth_edge_defense.rs`](../examples/stealth_edge_defense.rs)
  - Standalone Bloom Filter Inspection: [`examples/standalone_bloom.rs`](../examples/standalone_bloom.rs)
- **Security Policy:** [`SECURITY.md`](../SECURITY.md)
- **Contribution Guidelines:** [`CONTRIBUTING.md`](../CONTRIBUTING.md)
