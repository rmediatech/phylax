//! # Sovereign Iterative Canonicalization & De-Obfuscation Engine (`canonicalize.rs`)
//!
//! Neutralizes multi-round encoding bypasses (`%252e%252e%252f` -> `%2e%2e%2f` -> `../`),
//! IIS Unicode `%u00XX` sequences, HTML hex/decimal entities (`&#x2e;`, `&#46;`),
//! overlong backslash normalization, and redundant path separator compaction.
//!
//! Enforces strict OJP: Single-pass borrow fast-path for clean inputs, bounded iterative
//! peeling (up to `MAX_DECODE_ROUNDS = 5`) for encoded inputs, and immediate detection
//! of deep-nested encoding evasion bombs.

use std::borrow::Cow;

/// Maximum iterative decoding rounds before flagging an encoding evasion bomb
pub const MAX_DECODE_ROUNDS: usize = 5;

/// Threshold of nested encoding layers on sensitive delimiters that triggers an evasion alert
pub const SUSPICIOUS_NESTING_THRESHOLD: usize = 2;

/// Canonicalization outcome with de-obfuscated text and encoding depth telemetry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalizedInput<'a> {
    /// Fully canonicalized, normalized string
    pub text: Cow<'a, str>,
    /// Number of iterative decoding layers peeled
    pub decode_rounds: usize,
    /// True if null bytes (`\0` or `%00`) were encountered during any decoding round
    pub contains_null_byte: bool,
    /// True if non-standard IIS `%uXXXX` Unicode encoding was used (strong WAF evasion signal)
    pub used_iis_unicode: bool,
    /// True if HTML entity encoding (`&#...;`) was used inside a URI or query parameter
    pub used_html_entities: bool,
}

impl<'a> CanonicalizedInput<'a> {
    /// Returns true if the input used excessive nested encoding to hide metacharacters
    #[inline]
    pub fn is_evasion_attempt(&self) -> bool {
        self.decode_rounds >= SUSPICIOUS_NESTING_THRESHOLD
            || self.used_iis_unicode
            || self.contains_null_byte
    }
}

pub struct Canonicalizer;

impl Canonicalizer {
    /// Iteratively canonicalizes a URI path or query string up to `MAX_DECODE_ROUNDS`.
    /// Returns `Cow::Borrowed` with 0 allocations if the input is already canonical.
    pub fn canonicalize(input: &str) -> CanonicalizedInput<'_> {
        if !Self::needs_canonicalization(input) {
            return CanonicalizedInput {
                text: Cow::Borrowed(input),
                decode_rounds: 0,
                contains_null_byte: input.as_bytes().contains(&0),
                used_iis_unicode: false,
                used_html_entities: false,
            };
        }

        let mut current = input.to_string();
        let mut rounds = 0;
        let mut contains_null = current.as_bytes().contains(&0);
        let mut used_iis_unicode = false;
        let mut used_html_entities = false;

        while rounds < MAX_DECODE_ROUNDS {
            let (next, changed, found_null, found_iis, found_html) =
                Self::decode_single_round(&current);

            if found_null {
                contains_null = true;
            }
            if found_iis {
                used_iis_unicode = true;
            }
            if found_html {
                used_html_entities = true;
            }

            if !changed {
                break;
            }

            current = next;
            rounds += 1;
        }

        let normalized = Self::normalize_separators(&current);
        if normalized.as_bytes().contains(&0) {
            contains_null = true;
        }

        CanonicalizedInput {
            text: Cow::Owned(normalized),
            decode_rounds: rounds,
            contains_null_byte: contains_null,
            used_iis_unicode,
            used_html_entities,
        }
    }

    #[inline]
    fn needs_canonicalization(input: &str) -> bool {
        let bytes = input.as_bytes();
        for i in 0..bytes.len() {
            match bytes[i] {
                b'%' | b'\\' | b'&' | b'+' => return true,
                b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => return true,
                _ => {}
            }
        }
        false
    }

    /// Performs a single pass of percent-decoding, IIS `%uXXXX` decoding, and HTML entity decoding.
    fn decode_single_round(input: &str) -> (String, bool, bool, bool, bool) {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut changed = false;
        let mut found_null = false;
        let mut found_iis = false;
        let mut found_html = false;

        while i < bytes.len() {
            // 1. Check IIS %uXXXX Unicode encoding (e.g. %u002e -> '.', %u2215 -> '/')
            if bytes[i] == b'%'
                && i + 5 < bytes.len()
                && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U')
            {
                if let (Some(d1), Some(d2), Some(d3), Some(d4)) = (
                    from_hex(bytes[i + 2]),
                    from_hex(bytes[i + 3]),
                    from_hex(bytes[i + 4]),
                    from_hex(bytes[i + 5]),
                ) {
                    let codepoint = ((d1 as u32) << 12)
                        | ((d2 as u32) << 8)
                        | ((d3 as u32) << 4)
                        | (d4 as u32);
                    changed = true;
                    found_iis = true;
                    if codepoint == 0 {
                        found_null = true;
                    }
                    // Map fullwidth/homoglyph slashes and dots to ASCII equivalents
                    let mapped = match codepoint {
                        0x2215 | 0x2044 | 0xFF0F => b'/',
                        0x2216 | 0xFF3C => b'\\',
                        0xFF0E | 0x2024 | 0x3002 => b'.',
                        0x0000..=0x007F => codepoint as u8,
                        _ => (codepoint & 0xFF) as u8,
                    };
                    out.push(mapped);
                    i += 6;
                    continue;
                }
            }

            // 2. Standard RFC 3986 %XX percent-encoding
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let (Some(h1), Some(h2)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                    let val = (h1 << 4) | h2;
                    changed = true;
                    if val == 0 {
                        found_null = true;
                    }
                    out.push(val);
                    i += 3;
                    continue;
                }
            }

            // 3. HTML Hex/Decimal numeric character references: &#x2e; or &#46;
            if bytes[i] == b'&' && i + 3 < bytes.len() && bytes[i + 1] == b'#' {
                if let Some((decoded_byte, consumed)) = Self::try_decode_html_entity(&bytes[i..]) {
                    changed = true;
                    found_html = true;
                    if decoded_byte == 0 {
                        found_null = true;
                    }
                    out.push(decoded_byte);
                    i += consumed;
                    continue;
                }
            }

            out.push(bytes[i]);
            i += 1;
        }

        // Convert to lossy UTF-8 while preserving ASCII bytes for pattern matching
        let s = String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        (s, changed, found_null, found_iis, found_html)
    }

    fn try_decode_html_entity(slice: &[u8]) -> Option<(u8, usize)> {
        // Expects slice starting with "&#"
        if slice.len() < 4 || slice[0] != b'&' || slice[1] != b'#' {
            return None;
        }
        let is_hex = slice[2] == b'x' || slice[2] == b'X';
        let start = if is_hex { 3 } else { 2 };
        let mut val: u32 = 0;
        let mut idx = start;
        let max_len = slice.len().min(10);

        while idx < max_len {
            let b = slice[idx];
            if b == b';' {
                if idx > start && val <= 0x7F {
                    return Some((val as u8, idx + 1));
                }
                return None;
            }
            if is_hex {
                let d = from_hex(b)?;
                val = (val << 4) | (d as u32);
            } else if b.is_ascii_digit() {
                val = val.saturating_mul(10).saturating_add((b - b'0') as u32);
            } else {
                return None;
            }
            idx += 1;
        }
        None
    }

    /// Normalizes backslashes to forward slashes and compacts redundant `//` into `/`
    /// (while preserving `://` scheme delimiters in URLs).
    fn normalize_separators(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;

        while i < bytes.len() {
            let b = if bytes[i] == b'\\' { b'/' } else { bytes[i] };

            if b == b'/' {
                // Preserve "://" scheme separator
                let is_scheme = i > 0 && bytes[i - 1] == b':';
                out.push(b'/');
                i += 1;
                if is_scheme && i < bytes.len() && (bytes[i] == b'/' || bytes[i] == b'\\') {
                    out.push(b'/');
                    i += 1;
                }
                // Collapse subsequent redundant slashes
                while i < bytes.len() && (bytes[i] == b'/' || bytes[i] == b'\\') {
                    i += 1;
                }
                continue;
            }

            out.push(b);
            i += 1;
        }

        String::from_utf8(out).unwrap_or_else(|_| input.to_string())
    }
}

#[inline]
fn from_hex(b: u8) -> Option<u8> {
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
    fn test_clean_fast_path_zero_alloc() {
        let res = Canonicalizer::canonicalize("/api/v1/users");
        assert!(matches!(res.text, Cow::Borrowed(_)));
        assert_eq!(res.decode_rounds, 0);
        assert!(!res.is_evasion_attempt());
    }

    #[test]
    fn test_triple_encoded_traversal_peeling() {
        // %25252e%25252e%25252f -> %252e%252e%252f -> %2e%2e%2f -> ../
        let res = Canonicalizer::canonicalize("/static/%25252e%25252e%25252fetc/passwd");
        assert_eq!(res.text, "/static/../etc/passwd");
        assert_eq!(res.decode_rounds, 3);
        assert!(res.is_evasion_attempt());
    }

    #[test]
    fn test_iis_unicode_and_backslash_normalization() {
        let res = Canonicalizer::canonicalize("/admin\\%u002e%u002e\\%u2215etc\\\\shadow");
        assert_eq!(res.text, "/admin/../etc/shadow");
        assert!(res.used_iis_unicode);
        assert!(res.is_evasion_attempt());
    }

    #[test]
    fn test_html_entity_deobfuscation() {
        let res = Canonicalizer::canonicalize("&#x2e;&#x2e;/&#46;&#46;/etc/passwd");
        assert_eq!(res.text, "../../etc/passwd");
        assert!(res.used_html_entities);
    }
}
