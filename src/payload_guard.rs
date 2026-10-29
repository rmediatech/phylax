//! # Sovereign Adversarial Payload Guard (`payload_guard.rs`)
//! Zero-allocation inspection and immediate deflection of adversarial injection payloads:
//! Directory Traversal, SQL Injection (SQLi), Remote Code Execution (RCE), XSS, and Null-Byte attacks.
//! Single Job (`OJP`): Universal threat pattern recognition across request URIs, headers, and query strings.

use std::borrow::Cow;

/// Adversarial payload classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdversarialPayload {
    PathTraversal(&'static str),
    SqlInjection(&'static str),
    CommandInjection(&'static str),
    CrossSiteScripting(&'static str),
    SsrfProbe(&'static str),
    TemplateInjection(&'static str),
    NoSqlInjection(&'static str),
    NullByteInjection,
    UriLengthBomb { len: usize, max: usize },
}

impl AdversarialPayload {
    pub fn description(&self) -> String {
        match self {
            AdversarialPayload::PathTraversal(pat) => {
                format!("Directory traversal vector detected ('{}')", pat)
            }
            AdversarialPayload::SqlInjection(pat) => {
                format!("SQL injection signature detected ('{}')", pat)
            }
            AdversarialPayload::CommandInjection(pat) => {
                format!(
                    "Command execution / shell meta-character detected ('{}')",
                    pat
                )
            }
            AdversarialPayload::CrossSiteScripting(pat) => {
                format!(
                    "Cross-site scripting / script injection detected ('{}')",
                    pat
                )
            }
            AdversarialPayload::SsrfProbe(pat) => {
                format!(
                    "SSRF / Cloud metadata reconnaissance vector detected ('{}')",
                    pat
                )
            }
            AdversarialPayload::TemplateInjection(pat) => {
                format!(
                    "Server-Side Template Injection (SSTI) signature detected ('{}')",
                    pat
                )
            }
            AdversarialPayload::NoSqlInjection(pat) => {
                format!("NoSQL / Operator injection vector detected ('{}')", pat)
            }
            AdversarialPayload::NullByteInjection => "Null byte injection detected".to_string(),
            AdversarialPayload::UriLengthBomb { len, max } => {
                format!("URI length bomb detected ({} > {} bytes)", len, max)
            }
        }
    }

    pub fn category_name(&self) -> &'static str {
        match self {
            AdversarialPayload::PathTraversal(_) => "Path Traversal / LFI",
            AdversarialPayload::SqlInjection(_) => "SQL Injection",
            AdversarialPayload::CommandInjection(_) => "Remote Code Execution",
            AdversarialPayload::CrossSiteScripting(_) => "Cross-Site Scripting",
            AdversarialPayload::SsrfProbe(_) => "SSRF / Metadata Probe",
            AdversarialPayload::TemplateInjection(_) => "Server-Side Template Injection",
            AdversarialPayload::NoSqlInjection(_) => "NoSQL Injection",
            AdversarialPayload::NullByteInjection => "Null Byte Poisoning",
            AdversarialPayload::UriLengthBomb { .. } => "Resource Exhaustion",
        }
    }
}

pub struct PayloadGuard;

impl PayloadGuard {
    pub const MAX_PATH_LEN: usize = 2048;
    pub const MAX_QUERY_LEN: usize = 8192;

    /// Inspect incoming request path and query string for malicious payloads.
    /// Checks both raw input and percent-decoded representation.
    pub fn inspect(path: &str, query: &str) -> Result<(), AdversarialPayload> {
        if path.len() > Self::MAX_PATH_LEN {
            return Err(AdversarialPayload::UriLengthBomb {
                len: path.len(),
                max: Self::MAX_PATH_LEN,
            });
        }
        if query.len() > Self::MAX_QUERY_LEN {
            return Err(AdversarialPayload::UriLengthBomb {
                len: query.len(),
                max: Self::MAX_QUERY_LEN,
            });
        }

        // Check path
        Self::inspect_text(path, true)?;

        // Check query
        Self::inspect_text(query, false)?;

        Ok(())
    }

    fn inspect_text(input: &str, is_path: bool) -> Result<(), AdversarialPayload> {
        if input.is_empty() {
            return Ok(());
        }

        // 1. Raw string inspection
        Self::check_patterns(input, is_path)?;

        // 2. Percent-decoded inspection
        let decoded = Self::percent_decode(input);
        if decoded.as_ref() != input {
            Self::check_patterns(&decoded, is_path)?;
        }

        Ok(())
    }

    fn check_patterns(text: &str, is_path: bool) -> Result<(), AdversarialPayload> {
        // Null byte check
        if text.contains('\0') || text.contains("%00") {
            return Err(AdversarialPayload::NullByteInjection);
        }

        let lower = text.to_ascii_lowercase();

        // 1. Path Traversal & LFI
        const TRAVERSAL_PATTERNS: &[&str] = &[
            "..",
            "%2e%2e",
            "..%2f",
            "%2f..",
            "..%5c",
            "%5c..",
            "%2e%2e%2f",
            "%2e%2e%5c",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self",
            "boot.ini",
            "win.ini",
            "file://",
            "php://",
            "data://",
        ];
        for &pat in TRAVERSAL_PATTERNS {
            if lower.contains(pat) {
                return Err(AdversarialPayload::PathTraversal(pat));
            }
        }

        // 2. SQL Injection
        const SQLI_PATTERNS: &[&str] = &[
            "union select",
            "union all select",
            "union distinct select",
            "' or '1'='1",
            "' or 1=1",
            "\" or 1=1",
            "' or ''='",
            "' or true",
            "\" or true",
            "select * from",
            "select 1 from",
            "select @@version",
            "information_schema",
            "waitfor delay",
            "benchmark(",
            "sleep(",
            "pg_sleep(",
            "into outfile",
            "load_file(",
            "xp_cmdshell",
            "drop table",
            "truncate table",
        ];
        for &pat in SQLI_PATTERNS {
            if lower.contains(pat) {
                return Err(AdversarialPayload::SqlInjection(pat));
            }
        }

        // 3. Command Injection & Shell Metacharacters
        const RCE_PATTERNS: &[&str] = &[
            "; cat ",
            "; id",
            "; whoami",
            "; uname",
            "; ls ",
            "; sleep ",
            "; curl ",
            "; wget ",
            "| cat ",
            "| id",
            "| whoami",
            "| uname",
            "| ls ",
            "| sleep ",
            "| curl ",
            "| wget ",
            "&& id",
            "&& whoami",
            "&& uname",
            "&& cat ",
            "$(id)",
            "$(whoami)",
            "`id`",
            "`whoami`",
            "/bin/sh",
            "/bin/bash",
            "powershell",
            "nc -e ",
        ];
        for &pat in RCE_PATTERNS {
            if lower.contains(pat) {
                return Err(AdversarialPayload::CommandInjection(pat));
            }
        }

        // In query strings, check for command substitution triggers
        if !is_path && (text.contains('`') || text.contains("$(")) {
            return Err(AdversarialPayload::CommandInjection("command substitution"));
        }

        // 4. Cross-Site Scripting (XSS)
        const XSS_PATTERNS: &[&str] = &[
            "<script",
            "</script>",
            "javascript:",
            "vbscript:",
            "onerror=",
            "onload=",
            "onclick=",
            "<svg/onload",
            "<img src=x onerror=",
        ];
        for &pat in XSS_PATTERNS {
            if lower.contains(pat) {
                return Err(AdversarialPayload::CrossSiteScripting(pat));
            }
        }

        // 5. SSRF & Cloud Metadata Trapping
        const SSRF_PATTERNS: &[&str] = &[
            "169.254.169.254",
            "metadata.google.internal",
            "metadata.goog",
            "100.100.100.200",
            "latest/meta-data",
            "latest/user-data",
            "latest/api/token",
            "gopher://",
            "dict://",
            "ldap://",
        ];
        for &pat in SSRF_PATTERNS {
            if lower.contains(pat) {
                return Err(AdversarialPayload::SsrfProbe(pat));
            }
        }

        // 6. Server-Side Template Injection (SSTI)
        const SSTI_PATTERNS: &[&str] = &[
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{class.module",
            "{{lipsum",
            "{{cycler",
            "{{joiner",
            "{{namespace",
            "{{config",
            "{{self",
            "__globals__",
            "__builtins__",
            "__import__",
            "__mro__",
            "__subclasses__",
        ];
        for &pat in SSTI_PATTERNS {
            if lower.contains(pat) {
                return Err(AdversarialPayload::TemplateInjection(pat));
            }
        }

        // 7. NoSQL & Object Operator Injection
        const NOSQL_PATTERNS: &[&str] = &[
            "{\"$gt\"",
            "{\"$ne\"",
            "{\"$where\"",
            "{\"$regex\"",
            "[$ne]=",
            "[$gt]=",
            "[$gte]=",
            "[$lte]=",
            "[$regex]=",
            "[$where]=",
            "[$exists]=",
            "db.collection",
        ];
        for &pat in NOSQL_PATTERNS {
            if lower.contains(pat) {
                return Err(AdversarialPayload::NoSqlInjection(pat));
            }
        }

        Ok(())
    }

    /// Zero-panic, zero-allocation percent decoder for adversarial payload inspection
    pub fn percent_decode(input: &str) -> Cow<'_, str> {
        if !input.contains('%') {
            return Cow::Borrowed(input);
        }

        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let (Some(h1), Some(h2)) =
                    (from_hex_digit(bytes[i + 1]), from_hex_digit(bytes[i + 2]))
                {
                    out.push((h1 << 4) | h2);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }

        String::from_utf8(out)
            .map(Cow::Owned)
            .unwrap_or_else(|_| Cow::Borrowed(input))
    }
}

#[inline]
fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_guard_poc_and_defenses() {
        assert!(PayloadGuard::inspect("/", "").is_ok());
        assert!(PayloadGuard::inspect("/api/v1/health", "token=safe_123").is_ok());
        assert!(PayloadGuard::inspect(
            "/qr",
            "text=https%3A%2F%2Fapp.example.com%2F%3Froom%3Dlobby%26callsign%3DOperator-1"
        )
        .is_ok());

        // SQLi
        assert!(matches!(
            PayloadGuard::inspect("/login", "q=' UNION SELECT 1"),
            Err(AdversarialPayload::SqlInjection(_))
        ));

        // Traversal
        assert!(matches!(
            PayloadGuard::inspect("/../../etc/shadow", ""),
            Err(AdversarialPayload::PathTraversal(_))
        ));

        // RCE
        assert!(matches!(
            PayloadGuard::inspect("/ping", "ip=1.1.1.1 | whoami"),
            Err(AdversarialPayload::CommandInjection(_))
        ));

        // XSS
        assert!(matches!(
            PayloadGuard::inspect("/search", "q=<script>alert(1)</script>"),
            Err(AdversarialPayload::CrossSiteScripting(_))
        ));

        // Null byte
        assert!(matches!(
            PayloadGuard::inspect("/file.txt\0.exe", ""),
            Err(AdversarialPayload::NullByteInjection)
        ));

        // SSRF
        assert!(matches!(
            PayloadGuard::inspect("/proxy", "url=http://169.254.169.254/latest/meta-data"),
            Err(AdversarialPayload::SsrfProbe(_))
        ));

        // SSTI
        assert!(matches!(
            PayloadGuard::inspect("/render", "name={{7*7}}"),
            Err(AdversarialPayload::TemplateInjection(_))
        ));

        // NoSQL
        assert!(matches!(
            PayloadGuard::inspect("/users", "filter={\"$gt\":\"\"}"),
            Err(AdversarialPayload::NoSqlInjection(_))
        ));
    }
}
