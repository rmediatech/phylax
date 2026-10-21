//! # Curated Decoy Honeyroute Catalog & URI Path Canonicalizer
//! One-Job: Store curated scanner reconnaissance trap tables and canonicalize URI paths.

use super::DecoyCategory;

/// Curated Exact Traps: Environment, Secrets, Cloud, CMS & Backup Probes
pub const STANDARD_EXACT_TRAPS: &[(&str, DecoyCategory)] = &[
    // Environment files
    ("/.env", DecoyCategory::EnvironmentSecret),
    ("/.env.local", DecoyCategory::EnvironmentSecret),
    ("/.env.production", DecoyCategory::EnvironmentSecret),
    ("/.env.backup", DecoyCategory::EnvironmentSecret),
    ("/.env.defaults", DecoyCategory::EnvironmentSecret),
    ("/.env_hidden", DecoyCategory::EnvironmentSecret),
    ("/fe/.env", DecoyCategory::EnvironmentSecret),
    ("/develop/.env", DecoyCategory::EnvironmentSecret),
    ("/pip.conf", DecoyCategory::EnvironmentSecret),
    ("/.azure/credentials", DecoyCategory::EnvironmentSecret),
    ("/auth.json", DecoyCategory::EnvironmentSecret),
    ("/secrets.json", DecoyCategory::EnvironmentSecret),
    ("/config.json", DecoyCategory::EnvironmentSecret),
    ("/config.properties", DecoyCategory::EnvironmentSecret),
    ("/config.codekit", DecoyCategory::EnvironmentSecret),
    ("/config/constant.js", DecoyCategory::EnvironmentSecret),
    // Cloud & Infrastructure
    ("/app/terraform.tfstate", DecoyCategory::CloudInfrastructure),
    ("/terraform.tfstate", DecoyCategory::CloudInfrastructure),
    ("/awsconfiguration.json", DecoyCategory::CloudInfrastructure),
    ("/aws.sh", DecoyCategory::CloudInfrastructure),
    ("/Procfile", DecoyCategory::CloudInfrastructure),
    ("/.firebaserc", DecoyCategory::CloudInfrastructure),
    ("/.tugboat", DecoyCategory::CloudInfrastructure),
    ("/.codeclimate.yml", DecoyCategory::CloudInfrastructure),
    ("/.zsh_history", DecoyCategory::EnvironmentSecret),
    ("/.wget-hsts", DecoyCategory::EnvironmentSecret),
    ("/errors.log", DecoyCategory::EnvironmentSecret),
    // CMS & Admin Panels
    ("/wp-login.php", DecoyCategory::AdminCmsProbe),
    ("/xmlrpc.php", DecoyCategory::AdminCmsProbe),
    ("/sites/default/settings.php.old", DecoyCategory::AdminCmsProbe),
    ("/bitrix/modules/updater_partner.log", DecoyCategory::AdminCmsProbe),
    // Private Keys & Certificates
    ("/private.key", DecoyCategory::PrivateKey),
    ("/id_rsa", DecoyCategory::PrivateKey),
    ("/storage/oauth-public.key", DecoyCategory::PrivateKey),
    // Backups
    ("/web.zip", DecoyCategory::DatabaseBackup),
    ("/site.tar.gz", DecoyCategory::DatabaseBackup),
    ("/backup.sql", DecoyCategory::DatabaseBackup),
    ("/database.sql", DecoyCategory::DatabaseBackup),
    ("/dump.sql", DecoyCategory::DatabaseBackup),
];

/// Curated Prefix Traps
pub const STANDARD_PREFIX_TRAPS: &[(&str, DecoyCategory)] = &[
    ("/.git/", DecoyCategory::VersionControl),
    ("/.git", DecoyCategory::VersionControl),
    ("/.svn/", DecoyCategory::VersionControl),
    ("/.svn", DecoyCategory::VersionControl),
    ("/.aws/", DecoyCategory::CloudInfrastructure),
    ("/wp-admin", DecoyCategory::AdminCmsProbe),
    ("/phpmyadmin", DecoyCategory::AdminCmsProbe),
    ("/pma", DecoyCategory::AdminCmsProbe),
    ("/actuator/", DecoyCategory::AdminCmsProbe),
    ("/k8s/", DecoyCategory::CloudInfrastructure),
];

/// Percent-decode ASCII hexadecimal sequences e.g. "%2e" -> "."
#[inline]
pub fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = match bytes[i + 1] {
                b'0'..=b'9' => Some(bytes[i + 1] - b'0'),
                b'a'..=b'f' => Some(bytes[i + 1] - b'a' + 10),
                b'A'..=b'F' => Some(bytes[i + 1] - b'A' + 10),
                _ => None,
            };
            let h2 = match bytes[i + 2] {
                b'0'..=b'9' => Some(bytes[i + 2] - b'0'),
                b'a'..=b'f' => Some(bytes[i + 2] - b'a' + 10),
                b'A'..=b'F' => Some(bytes[i + 2] - b'A' + 10),
                _ => None,
            };
            if let (Some(h1), Some(h2)) = (h1, h2) {
                out.push((h1 << 4) | h2);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Normalizes a URI path (decodes percent encoding, removes query/fragment, collapses multiple slashes and dot segments, converts to lowercase)
#[inline]
pub fn normalize_path(raw_path: &str) -> String {
    let decoded = percent_decode(raw_path);
    let path_without_query = match decoded.find('?') {
        Some(idx) => &decoded[..idx],
        None => &decoded,
    };
    let path_without_hash = match path_without_query.find('#') {
        Some(idx) => &path_without_query[..idx],
        None => path_without_query,
    };
    let trimmed = path_without_hash.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }

    // Segment-based canonicalization: collapses '//', '/./', and '/../'
    let mut segments: Vec<&str> = Vec::new();
    for seg in trimmed.split('/') {
        let s = seg.trim();
        if s.is_empty() || s == "." {
            continue;
        }
        if s == ".." {
            segments.pop();
        } else {
            segments.push(s);
        }
    }

    if segments.is_empty() {
        return "/".to_string();
    }

    let mut normalized = String::with_capacity(trimmed.len() + 1);
    for seg in segments {
        normalized.push('/');
        for ch in seg.chars() {
            normalized.push(ch.to_ascii_lowercase());
        }
    }
    normalized
}
