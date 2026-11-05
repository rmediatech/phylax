//! # Layer 16: Synthetic Mirage Active Deception & Scanner Poisoning Engine (`mirage.rs`)
//!
//! Single Job: Instead of returning an alerting `403 Forbidden` or dry `404 Not Found` when
//! automated scanners (`fscan`, `cscan`, `nuclei`, `sqlmap`, `dirsearch`, `gobuster`) probe
//! decoy honeyroutes (`/.env`, `/.git/config`, `/wp-login.php`, `/actuator/env`, `/dump.sql`,
//! `/id_rsa`, `/terraform.tfstate`), generate deterministic, cryptographically keyed
//! **Synthetic Mirage Poison Payloads** with realistic decoy headers and attacker-bound
//! HMAC canary tokens.
//!
//! ## Operational Value
//! 1. **Scanner Database Poisoning**: Automated recon pipelines ingest fake `.env` keys,
//!    fake SQL schemas, and fake Terraform states into their C2 loot databases, polluting
//!    attacker triage queues with high-confidence false positives.
//! 2. **Cryptographic Attacker Attribution**: Every generated canary token (`AKIA...`,
//!    `sk_live_...`, `ghp_...`) is deterministically derived from `HMAC-SHA256(secret, client_ip + category)`
//!    so if an attacker replays a harvested credential anywhere on the mesh, their original
//!    reconnaissance IP is mathematically unmasked.
//! 3. **Progressive Tarpit Pacing**: Calculates recommended drip delay (`recommended_drip_delay_ms`)
//!    proportional to offender infraction count to waste scanner socket concurrency.

use crate::decoy_uri::DecoyCategory;
use crate::sanitize::scrub_ansi_and_control;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Configuration for the Synthetic Mirage Deception Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirageConfig {
    /// Whether active mirage payload poisoning is enabled
    pub enabled: bool,
    /// Decoy organization domain embedded into synthetic artifacts
    pub decoy_domain: String,
    /// Base delay (ms) recommended before or during response delivery
    pub base_drip_delay_ms: u64,
    /// Maximum delay ceiling (ms) for repeat offenders
    pub max_drip_delay_ms: u64,
}

impl Default for MirageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            decoy_domain: "internal-vault.corp.local".to_string(),
            base_drip_delay_ms: 150,
            max_drip_delay_ms: 5_000,
        }
    }
}

/// A fully synthesized deceptive HTTP response payload ready for wire emission
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiragePayload {
    /// HTTP status code to return (typically 200 OK to fool scanner heuristics)
    pub status_code: u16,
    /// MIME Content-Type matching the probed artifact
    pub content_type: &'static str,
    /// Realistic decoy server header (e.g., `Apache/2.4.58 (Ubuntu)`, `nginx/1.24.0`)
    pub decoy_server_header: &'static str,
    /// Additional deceptive HTTP headers `(Header-Name, Header-Value)`
    pub extra_headers: Vec<(String, String)>,
    /// Deterministic canary fingerprint ID embedded in the payload for forensic attribution
    pub canary_fingerprint: String,
    /// Recommended tarpit drip delay in milliseconds based on infraction count
    pub recommended_drip_delay_ms: u64,
    /// Synthesized response body
    pub body: String,
}

/// Active Deception & Synthetic Mirage Generator
#[derive(Debug, Clone)]
pub struct MirageEngine {
    secret_key: Vec<u8>,
    config: MirageConfig,
}

impl Default for MirageEngine {
    fn default() -> Self {
        Self::new(
            b"phylax-sovereign-mirage-default-seed-2026",
            MirageConfig::default(),
        )
    }
}

impl MirageEngine {
    /// Creates a new `MirageEngine` keyed with a cryptographic master secret.
    pub fn new(secret_key: &[u8], config: MirageConfig) -> Self {
        let key = if secret_key.is_empty() {
            b"phylax-sovereign-mirage-fallback-key".to_vec()
        } else {
            secret_key.to_vec()
        };
        Self {
            secret_key: key,
            config,
        }
    }

    /// Returns a reference to the current `MirageConfig`.
    pub fn config(&self) -> &MirageConfig {
        &self.config
    }

    /// Deterministically derives a hex canary token from `(client_ip, label)`.
    pub fn derive_canary_hex(&self, client_ip: &str, label: &str, len: usize) -> String {
        let clean_ip = scrub_ansi_and_control(client_ip);
        let clean_label = scrub_ansi_and_control(label);
        let mut mac =
            HmacSha256::new_from_slice(&self.secret_key).expect("HMAC accepts any key size");
        mac.update(clean_ip.as_bytes());
        mac.update(b"|");
        mac.update(clean_label.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut full_hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(&mut full_hex, "{:02x}", b);
        }
        let bounded = len.clamp(4, 64);
        full_hex[..bounded.min(full_hex.len())].to_string()
    }

    /// Computes progressive tarpit delay (quadratic backoff capped at `max_drip_delay_ms`).
    pub fn compute_drip_delay_ms(&self, infraction_count: u32) -> u64 {
        let factor = (infraction_count.max(1) as u64).saturating_pow(2);
        self.config
            .base_drip_delay_ms
            .saturating_mul(factor)
            .min(self.config.max_drip_delay_ms)
    }

    /// Synthesizes a realistic decoy payload tailored to the probed `DecoyCategory` and URI.
    pub fn synthesize(
        &self,
        category: DecoyCategory,
        probed_path: &str,
        client_ip: &str,
        infraction_count: u32,
    ) -> MiragePayload {
        let safe_path = scrub_ansi_and_control(probed_path);
        let canary_id = self.derive_canary_hex(client_ip, &safe_path, 16);
        let delay_ms = self.compute_drip_delay_ms(infraction_count);

        match category {
            DecoyCategory::EnvironmentSecret => {
                self.build_env_mirage(client_ip, &canary_id, delay_ms)
            }
            DecoyCategory::VersionControl => {
                self.build_vcs_mirage(&safe_path, client_ip, &canary_id, delay_ms)
            }
            DecoyCategory::CloudInfrastructure => {
                self.build_cloud_mirage(&safe_path, client_ip, &canary_id, delay_ms)
            }
            DecoyCategory::AdminCmsProbe => {
                self.build_admin_cms_mirage(&safe_path, client_ip, &canary_id, delay_ms)
            }
            DecoyCategory::DatabaseBackup => {
                self.build_db_dump_mirage(client_ip, &canary_id, delay_ms)
            }
            DecoyCategory::PrivateKey => {
                self.build_private_key_mirage(client_ip, &canary_id, delay_ms)
            }
            DecoyCategory::Custom => self.build_canary_trap_mirage(client_ip, &canary_id, delay_ms),
        }
    }

    fn build_env_mirage(&self, client_ip: &str, canary_id: &str, delay_ms: u64) -> MiragePayload {
        let aws_suffix = self
            .derive_canary_hex(client_ip, "aws_access_key", 16)
            .to_uppercase();
        let aws_secret = self.derive_canary_hex(client_ip, "aws_secret_key", 40);
        let db_pass = self.derive_canary_hex(client_ip, "postgres_pass", 24);
        let stripe_key = self.derive_canary_hex(client_ip, "stripe_live", 32);
        let jwt_secret = self.derive_canary_hex(client_ip, "jwt_hmac", 48);

        let body = format!(
            "# Production Environment Configuration (DO NOT COMMIT)\n\
             APP_ENV=production\n\
             APP_DEBUG=false\n\
             APP_CANARY_TRACE=mirage-{canary_id}\n\
             DB_CONNECTION=pgsql\n\
             DB_HOST=db-primary.{domain}\n\
             DB_PORT=5432\n\
             DB_DATABASE=prod_ledger\n\
             DB_USERNAME=svc_fin_admin\n\
             DB_PASSWORD=vlt_{db_pass}\n\
             AWS_ACCESS_KEY_ID=AKIA{aws_suffix}\n\
             AWS_SECRET_ACCESS_KEY={aws_secret}\n\
             AWS_DEFAULT_REGION=us-east-1\n\
             STRIPE_SECRET_KEY=sk_live_{stripe_key}\n\
             JWT_SECRET={jwt_secret}\n",
            domain = self.config.decoy_domain,
        );

        MiragePayload {
            status_code: 200,
            content_type: "text/plain; charset=utf-8",
            decoy_server_header: "nginx/1.24.0 (Ubuntu)",
            extra_headers: vec![
                ("Cache-Control".into(), "no-store, max-age=0".into()),
                ("X-Mirage-Canary".into(), canary_id.to_string()),
            ],
            canary_fingerprint: canary_id.to_string(),
            recommended_drip_delay_ms: delay_ms,
            body,
        }
    }

    fn build_vcs_mirage(
        &self,
        safe_path: &str,
        client_ip: &str,
        canary_id: &str,
        delay_ms: u64,
    ) -> MiragePayload {
        let token = self.derive_canary_hex(client_ip, "git_pat", 36);
        let body = if safe_path.contains("HEAD") {
            "ref: refs/heads/main\n".to_string()
        } else {
            format!(
                "[core]\n\
                 \trepositoryformatversion = 0\n\
                 \tfilemode = true\n\
                 \tbare = false\n\
                 \tlogallrefupdates = true\n\
                 [remote \"origin\"]\n\
                 \turl = https://ci-deploy:ghp_{token}@git.{domain}/core/sovereign-backend.git\n\
                 \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
                 [branch \"main\"]\n\
                 \tremote = origin\n\
                 \tmerge = refs/heads/main\n\
                 # trace-id: {canary_id}\n",
                domain = self.config.decoy_domain,
            )
        };

        MiragePayload {
            status_code: 200,
            content_type: "text/plain; charset=utf-8",
            decoy_server_header: "Apache/2.4.58 (Debian)",
            extra_headers: vec![("X-VCS-Mirage".into(), canary_id.to_string())],
            canary_fingerprint: canary_id.to_string(),
            recommended_drip_delay_ms: delay_ms,
            body,
        }
    }

    fn build_cloud_mirage(
        &self,
        safe_path: &str,
        client_ip: &str,
        canary_id: &str,
        delay_ms: u64,
    ) -> MiragePayload {
        let akia = self
            .derive_canary_hex(client_ip, "tf_aws_key", 16)
            .to_uppercase();
        let secret = self.derive_canary_hex(client_ip, "tf_aws_secret", 40);
        if safe_path.contains("credentials") {
            let body = format!(
                "[default]\n\
                 aws_access_key_id = AKIA{akia}\n\
                 aws_secret_access_key = {secret}\n\
                 # session_trace = {canary_id}\n"
            );
            MiragePayload {
                status_code: 200,
                content_type: "text/plain; charset=utf-8",
                decoy_server_header: "AmazonS3",
                extra_headers: vec![("x-amz-request-id".into(), canary_id.to_string())],
                canary_fingerprint: canary_id.to_string(),
                recommended_drip_delay_ms: delay_ms,
                body,
            }
        } else {
            let body = format!(
                "{{\n  \"version\": 4,\n  \"terraform_version\": \"1.8.2\",\n  \"serial\": 42,\n  \
                 \"lineage\": \"{canary_id}\",\n  \"outputs\": {{\n    \"rds_master_endpoint\": {{\n      \
                 \"value\": \"prod-Aurora.{domain}:5432\",\n      \"type\": \"string\"\n    }},\n    \
                 \"iam_deploy_key\": {{\n      \"value\": \"AKIA{akia}\",\n      \"sensitive\": true\n    }}\n  }}\n}}\n",
                domain = self.config.decoy_domain,
            );
            MiragePayload {
                status_code: 200,
                content_type: "application/json; charset=utf-8",
                decoy_server_header: "nginx/1.24.0",
                extra_headers: vec![("X-Terraform-Serial".into(), canary_id.to_string())],
                canary_fingerprint: canary_id.to_string(),
                recommended_drip_delay_ms: delay_ms,
                body,
            }
        }
    }

    fn build_admin_cms_mirage(
        &self,
        safe_path: &str,
        client_ip: &str,
        canary_id: &str,
        delay_ms: u64,
    ) -> MiragePayload {
        let csrf = self.derive_canary_hex(client_ip, "cms_csrf", 24);
        if safe_path.contains("actuator") || safe_path.ends_with(".json") {
            let body = format!(
                "{{\"activeProfiles\":[\"production\"],\"canary_trace\":\"{canary_id}\",\"propertySources\":[{{\"name\":\"systemEnvironment\",\
                 \"properties\":{{\"SPRING_DATASOURCE_URL\":{{\"value\":\"jdbc:postgresql://db.{domain}:5432/core\"}},\
                 \"SPRING_DATASOURCE_PASSWORD\":{{\"value\":\"******{canary_id}\"}}}}}}]}}",
                domain = self.config.decoy_domain,
            );
            MiragePayload {
                status_code: 200,
                content_type: "application/vnd.spring-boot.actuator.v3+json",
                decoy_server_header: "Apache-Coyote/1.1",
                extra_headers: vec![(
                    "X-Application-Context".into(),
                    format!("application:{canary_id}"),
                )],
                canary_fingerprint: canary_id.to_string(),
                recommended_drip_delay_ms: delay_ms,
                body,
            }
        } else {
            let body = format!(
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Log In &lsaquo; Sovereign Admin &mdash; WordPress</title></head>\
                 <body class=\"login\"><div id=\"login\"><h1><a href=\"/\">Admin Portal</a></h1>\
                 <form name=\"loginform\" id=\"loginform\" action=\"/wp-login.php\" method=\"post\">\
                 <p><label for=\"user_login\">Username or Email Address</label><input type=\"text\" name=\"log\" id=\"user_login\" class=\"input\" size=\"20\" /></p>\
                 <p><label for=\"user_pass\">Password</label><input type=\"password\" name=\"pwd\" id=\"user_pass\" class=\"input\" size=\"20\" /></p>\
                 <input type=\"hidden\" name=\"website_url\" value=\"\" />\
                 <input type=\"hidden\" name=\"_wpnonce\" value=\"{csrf}\" />\
                 <input type=\"hidden\" name=\"canary_trace\" value=\"{canary_id}\" />\
                 <p class=\"submit\"><input type=\"submit\" name=\"wp-submit\" id=\"wp-submit\" value=\"Log In\" /></p>\
                 </form></div></body></html>"
            );
            MiragePayload {
                status_code: 200,
                content_type: "text/html; charset=utf-8",
                decoy_server_header: "Apache/2.4.58 (Ubuntu)",
                extra_headers: vec![
                    ("X-Powered-By".into(), "PHP/8.2.18".into()),
                    (
                        "Set-Cookie".into(),
                        format!(
                            "wordpress_test_cookie=WP+Cookie+check+{canary_id}; path=/; HttpOnly"
                        ),
                    ),
                ],
                canary_fingerprint: canary_id.to_string(),
                recommended_drip_delay_ms: delay_ms,
                body,
            }
        }
    }

    fn build_db_dump_mirage(
        &self,
        client_ip: &str,
        canary_id: &str,
        delay_ms: u64,
    ) -> MiragePayload {
        let admin_hash = self.derive_canary_hex(client_ip, "bcrypt_admin", 48);
        let api_token = self.derive_canary_hex(client_ip, "db_api_token", 32);
        let body = format!(
            "-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)\n\
             -- Host: db-master.{domain}    Database: sovereign_prod\n\
             -- Canary Trace: {canary_id}\n\
             SET NAMES utf8mb4;\n\
             CREATE TABLE `operator_accounts` (\n\
               `id` int NOT NULL AUTO_INCREMENT,\n\
               `username` varchar(64) NOT NULL,\n\
               `password_hash` varchar(128) NOT NULL,\n\
               `api_secret_token` varchar(64) NOT NULL,\n\
               PRIMARY KEY (`id`)\n\
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\
             INSERT INTO `operator_accounts` VALUES (1,'svc_root_admin','$2y$12${admin_hash}','tok_live_{api_token}');\n",
            domain = self.config.decoy_domain,
        );

        MiragePayload {
            status_code: 200,
            content_type: "application/sql; charset=utf-8",
            decoy_server_header: "nginx/1.24.0",
            extra_headers: vec![(
                "Content-Disposition".into(),
                format!("attachment; filename=\"backup-{canary_id}.sql\""),
            )],
            canary_fingerprint: canary_id.to_string(),
            recommended_drip_delay_ms: delay_ms,
            body,
        }
    }

    fn build_private_key_mirage(
        &self,
        client_ip: &str,
        canary_id: &str,
        delay_ms: u64,
    ) -> MiragePayload {
        let line1 = self.derive_canary_hex(client_ip, "ssh_line1", 64);
        let line2 = self.derive_canary_hex(client_ip, "ssh_line2", 64);
        let body = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n\
             b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
             {line1}\n\
             {line2}\n\
             # canary-id: {canary_id}\n\
             -----END OPENSSH PRIVATE KEY-----\n"
        );

        MiragePayload {
            status_code: 200,
            content_type: "application/x-pem-file",
            decoy_server_header: "OpenSSH_9.6p1",
            extra_headers: vec![("X-Key-Canary".into(), canary_id.to_string())],
            canary_fingerprint: canary_id.to_string(),
            recommended_drip_delay_ms: delay_ms,
            body,
        }
    }

    fn build_canary_trap_mirage(
        &self,
        client_ip: &str,
        canary_id: &str,
        delay_ms: u64,
    ) -> MiragePayload {
        let session_tok = self.derive_canary_hex(client_ip, "canary_session", 32);
        let body = format!(
            "{{\"status\":\"INTERNAL_NODE_SYNC\",\"node\":\"vault-01.{domain}\",\
             \"canary_trace\":\"{canary_id}\",\"sync_bearer_token\":\"sov_canary_{session_tok}\"}}",
            domain = self.config.decoy_domain,
        );

        MiragePayload {
            status_code: 200,
            content_type: "application/json; charset=utf-8",
            decoy_server_header: "Sovereign-Vault/1.0",
            extra_headers: vec![("X-Canary-Trace".into(), canary_id.to_string())],
            canary_fingerprint: canary_id.to_string(),
            recommended_drip_delay_ms: delay_ms,
            body,
        }
    }
}
