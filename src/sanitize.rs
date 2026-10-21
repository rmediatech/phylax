//! # Sovereign Boundary Sanitization & Injection Neutralization (`sanitize.rs`)
//!
//! Single Job: Scrub raw ANSI CSI/OSC escape sequences and unprintable control bytes from
//! untrusted network headers, banners, User-Agents, URIs, and forensic dossiers, and
//! neutralize spreadsheet/table formula injection payloads (`=`, `+`, `-`, `@`, `\t`, `\r`).

/// Maximum allowed length for a sanitized single-line header or banner field
pub const MAX_SANITIZED_FIELD_LEN: usize = 1024;

/// Scrubs raw ANSI escape sequences (CSI `\x1b[...`, OSC `\x1b]...`, two-byte escapes)
/// and unprintable ASCII/Unicode control characters from a single-line string.
/// Replaces `\r`, `\n`, and `\t` with spaces to prevent log line forging.
pub fn scrub_ansi_and_control(input: &str) -> String {
    scrub_internal(input, false, MAX_SANITIZED_FIELD_LEN)
}

/// Scrubs raw ANSI escape sequences and unprintable control characters while preserving
/// newline (`\n`) characters for structured multi-line forensic notes.
pub fn scrub_multiline_text(input: &str, max_len: usize) -> String {
    scrub_internal(input, true, max_len)
}

fn scrub_internal(input: &str, allow_newlines: bool, max_len: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_len));
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if out.len() >= max_len {
            break;
        }

        // Detect ESC (\x1b) or C1 CSI (\u{009b})
        if ch == '\x1b' || ch == '\u{009b}' {
            if ch == '\x1b' {
                match chars.peek().copied() {
                    Some('[') => {
                        chars.next(); // consume '['
                        // CSI sequence: consume parameter/intermediate bytes until final byte (0x40..=0x7E)
                        while let Some(&c) = chars.peek() {
                            chars.next();
                            if ('\x40'..='\x7e').contains(&c) {
                                break;
                            }
                        }
                    }
                    Some(']') => {
                        chars.next(); // consume ']'
                        // OSC sequence: consume until BEL (\x07) or ST (\x1b\\)
                        while let Some(c) = chars.next() {
                            if c == '\x07' {
                                break;
                            }
                            if c == '\x1b' && chars.peek() == Some(&'\\') {
                                chars.next();
                                break;
                            }
                        }
                    }
                    Some(c) if ('\x20'..='\x7e').contains(&c) => {
                        chars.next(); // consume 2-byte escape sequence
                    }
                    _ => {}
                }
            } else {
                // C1 CSI (\u{009b}): consume until final byte
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }

        if allow_newlines && ch == '\n' {
            out.push('\n');
            continue;
        }

        if ch == '\r' || ch == '\n' || ch == '\t' {
            out.push(' ');
            continue;
        }

        if ch.is_control() {
            continue;
        }

        out.push(ch);
    }

    out
}

/// Neutralizes spreadsheet and CSV formula injection payloads (`=`, `+`, `-`, `@`, `\t`, `\r`).
/// First checks the raw leading characters (before control-char conversion) as well as the
/// sanitized string, prepending a single quote (`'`) if any dangerous trigger is present.
pub fn neutralize_formula_injection(input: &str) -> String {
    let raw_trimmed = input.trim_start_matches(' ');
    let raw_starts_with_tab_or_cr = raw_trimmed.starts_with('\t') || raw_trimmed.starts_with('\r');

    let cleaned = scrub_ansi_and_control(input);
    let trimmed = cleaned.trim_start();

    let needs_prefix = raw_starts_with_tab_or_cr
        || trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@');

    if needs_prefix {
        format!("'{}", cleaned)
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_ansi_csi_and_osc_sequences() {
        let poisoned = "Mozilla/5.0 \x1b[31m\x1b[2JEvilBot\x1b]0;PwnedTitle\x07/1.0\r\nInjected: true";
        let clean = scrub_ansi_and_control(poisoned);
        assert_eq!(clean, "Mozilla/5.0 EvilBot/1.0  Injected: true");
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\r'));
        assert!(!clean.contains('\n'));
    }

    #[test]
    fn test_neutralize_formula_injection_vectors() {
        assert_eq!(
            neutralize_formula_injection("=CMD|' /C calc'!A0"),
            "'=CMD|' /C calc'!A0"
        );
        assert_eq!(neutralize_formula_injection("+1+1"), "'+1+1");
        assert_eq!(neutralize_formula_injection("-2+3"), "'-2+3");
        assert_eq!(neutralize_formula_injection("@SUM(1,2)"), "'@SUM(1,2)");
        assert_eq!(neutralize_formula_injection("\t=1+1"), "' =1+1");
        assert_eq!(neutralize_formula_injection("\r=1+1"), "' =1+1");
        assert_eq!(neutralize_formula_injection("SafeValue"), "SafeValue");
    }
}
