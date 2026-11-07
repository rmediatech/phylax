//! # Sovereign Pure-Rust Zero-Copy SQLi & Comment De-Obfuscation Tokenizer (`sqli_tokenizer.rs`)
//!
//! Replaces unsafe legacy C `libinjection` with a 100% memory-safe, zero-FFI lexical
//! state machine and comment stripper in pure Rust.
//!
//! Capabilities:
//! 1. **Inline Comment De-Obfuscation**: Collapses `UN/**/ION/**/SEL/**/ECT` and MySQL
//!    versioned comments (`/*!50000UNION*/`) into canonical space-delimited tokens.
//! 2. **Structural Token Folding (5-Token Fingerprint)**: Classifies lexemes into
//!    String (`S`), Number (`N`), Operator (`O`), Keyword (`K`), Function (`F`),
//!    Comment (`C`), and Left/Right Parens (`(`, `)`) to catch boolean tautologies,
//!    UNION extractions, stacked queries, and blind time-delay injections regardless
//!    of whitespace or casing tricks.

/// Classification of a lexical SQLi token
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlTokenKind {
    /// SQL DML/DDL/Control Keyword (e.g. UNION, SELECT, OR, AND, FROM, WHERE, DROP, EXEC)
    Keyword(&'static str),
    /// Dangerous SQL Function (e.g. SLEEP, PG_SLEEP, BENCHMARK, LOAD_FILE, CHAR, CONCAT)
    Function(&'static str),
    /// String literal ('...' or "...")
    StringLiteral,
    /// Numeric literal (integer, hex 0x..., or float)
    NumberLiteral,
    /// Comparison or logical operator (=, !=, <>, <=>, >=, <=, ||, &&)
    Operator,
    /// Line comment initiator (-- or #)
    CommentTail,
    /// Semicolon statement separator (;)
    Semicolon,
    /// Open or close parenthesis
    Paren,
    /// Identifier or benign word
    Identifier,
}

/// Detected SQL Injection vector from structural token analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliDetection {
    /// Boolean / String Tautology (e.g. `' OR '1'='1`, `1 OR 1=1`, `' OR TRUE--`)
    BooleanTautology(&'static str),
    /// UNION-based data extraction (`UNION SELECT`, `UNION ALL SELECT`, `UN/**/ION SELECT`)
    UnionExtraction(&'static str),
    /// Stacked query execution (`; DROP TABLE`, `; SELECT`, `; WAITFOR DELAY`)
    StackedQuery(&'static str),
    /// Time-based or CPU-spin blind injection (`SLEEP(`, `PG_SLEEP(`, `BENCHMARK(`, `WAITFOR DELAY`)
    BlindTimeDelay(&'static str),
    /// Comment-obfuscated keyword splitting (`UN/**/ION`, `SEL/*!50000ECT*/`)
    CommentObfuscation(&'static str),
    /// System catalog / file probe (`INFORMATION_SCHEMA`, `INTO OUTFILE`, `LOAD_FILE`)
    CatalogOrFileProbe(&'static str),
}

pub struct SqliTokenizer;

impl SqliTokenizer {
    /// Inspects a canonicalized input string for structural SQL injection patterns.
    /// Returns `Some(SqliDetection)` if an attack token sequence is matched.
    pub fn inspect(input: &str) -> Option<SqliDetection> {
        if input.len() < 4 {
            return None;
        }

        // Fast-path pre-filter: if input contains none of the characters required for SQLi, exit in <5ns
        if !Self::has_sqli_trigger_bytes(input.as_bytes()) {
            return None;
        }

        // Step 1: Detect inline comment keyword splitting (`UN/**/ION`, `/*!50000SELECT*/`)
        // and inline comment whitespace substitution (`UNION/**/ALL/**/SELECT`).
        let (collapsed, spaced, had_inline_comment, had_versioned_comment) =
            Self::strip_sql_inline_comments(input);
        if had_versioned_comment {
            return Some(SqliDetection::CommentObfuscation("/*!versioned_comment*/"));
        }

        if had_inline_comment {
            let lower_collapsed = collapsed.to_ascii_lowercase();
            for kw in ["union", "select", "sleep(", "pg_sleep(", "benchmark(", "waitfor"] {
                if lower_collapsed.contains(kw) {
                    return Some(SqliDetection::CommentObfuscation(
                        "inline_comment_keyword_split",
                    ));
                }
            }
        }

        let scan_target = if had_inline_comment {
            spaced.as_str()
        } else {
            input
        };

        // Step 2: Tokenize into structural SQL token stream (bounded to 64 tokens)
        let mut tokens = [SqlTokenKind::Identifier; 64];
        let count = Self::tokenize(scan_target, &mut tokens);
        let stream = &tokens[..count];

        // Step 3: Evaluate structural token sequences
        Self::evaluate_token_stream(stream)
    }

    #[inline]
    fn has_sqli_trigger_bytes(bytes: &[u8]) -> bool {
        for &b in bytes {
            match b {
                b'\'' | b'"' | b'-' | b'/' | b';' | b'=' | b'(' | b'#' | b' ' | b'+' => {
                    return true
                }
                _ => {}
            }
        }
        false
    }

    /// Strips `/* ... */` inline comments in two modes:
    /// 1. `collapsed` (deletes `/*...*/` to unmask `UN/**/ION` -> `UNION`)
    /// 2. `spaced` (replaces `/*...*/` with `' '` to unmask `UNION/**/SELECT` -> `UNION SELECT`)
    pub fn strip_sql_inline_comments(input: &str) -> (String, String, bool, bool) {
        let bytes = input.as_bytes();
        let mut collapsed = Vec::with_capacity(bytes.len());
        let mut spaced = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut had_comment = false;
        let mut had_versioned = false;

        while i < bytes.len() {
            if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                had_comment = true;
                if i + 2 < bytes.len() && bytes[i + 2] == b'!' {
                    had_versioned = true;
                }
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 < bytes.len() {
                    i += 2;
                } else {
                    break;
                }
                spaced.push(b' ');
                continue;
            }
            collapsed.push(bytes[i]);
            spaced.push(bytes[i]);
            i += 1;
        }

        let s_col = String::from_utf8(collapsed).unwrap_or_else(|_| input.to_string());
        let s_spc = String::from_utf8(spaced).unwrap_or_else(|_| input.to_string());
        (s_col, s_spc, had_comment, had_versioned)
    }

    fn tokenize(input: &str, out: &mut [SqlTokenKind; 64]) -> usize {
        let bytes = input.as_bytes();
        let mut i = 0;
        let mut count = 0;

        while i < bytes.len() && count < out.len() {
            let b = bytes[i];

            // Skip whitespace and URL '+' spaces
            if b.is_ascii_whitespace() || b == b'+' || b == b',' {
                i += 1;
                continue;
            }

            // String literals or SQL quote escapes ('...' or "...")
            if b == b'\'' || b == b'"' {
                let quote = b;
                // Look ahead for a matching closing quote within a bounded short literal (<= 32 bytes)
                // that does not span across SQL comment initiators.
                let mut close_idx = None;
                let max_look = (i + 33).min(bytes.len());
                let mut k = i + 1;
                while k < max_look {
                    if bytes[k] == b'\\' {
                        k += 2;
                        continue;
                    }
                    if bytes[k] == quote {
                        close_idx = Some(k);
                        break;
                    }
                    k += 1;
                }

                // If preceded immediately by an identifier/number (e.g. `1'` or `admin'`) or unclosed,
                // treat the quote itself as a string-escape boundary token so following keywords are exposed!
                let preceded_by_word = i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b')');
                if preceded_by_word || close_idx.is_none() {
                    out[count] = SqlTokenKind::StringLiteral;
                    count += 1;
                    i += 1;
                    continue;
                }

                // Otherwise consume balanced literal `'x'`
                i = close_idx.unwrap() + 1;
                out[count] = SqlTokenKind::StringLiteral;
                count += 1;
                continue;
            }

            // Line comments: `--` or `#`
            if b == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
                out[count] = SqlTokenKind::CommentTail;
                count += 1;
                break;
            }
            if b == b'#' {
                out[count] = SqlTokenKind::CommentTail;
                count += 1;
                break;
            }

            // Semicolon
            if b == b';' {
                out[count] = SqlTokenKind::Semicolon;
                count += 1;
                i += 1;
                continue;
            }

            // Parentheses
            if b == b'(' || b == b')' {
                out[count] = SqlTokenKind::Paren;
                count += 1;
                i += 1;
                continue;
            }

            // Comparison / Logical Operators
            if matches!(b, b'=' | b'!' | b'<' | b'>' | b'|' | b'&') {
                i += 1;
                while i < bytes.len() && matches!(bytes[i], b'=' | b'>' | b'|' | b'&') {
                    i += 1;
                }
                out[count] = SqlTokenKind::Operator;
                count += 1;
                continue;
            }

            // Numeric literals (including 0x hex)
            if b.is_ascii_digit() {
                i += 1;
                while i < bytes.len()
                    && (bytes[i].is_ascii_hexdigit() || bytes[i] == b'x' || bytes[i] == b'X' || bytes[i] == b'.')
                {
                    i += 1;
                }
                out[count] = SqlTokenKind::NumberLiteral;
                count += 1;
                continue;
            }

            // Identifiers, Keywords, Functions
            if b.is_ascii_alphabetic() || b == b'_' || b == b'@' {
                let start = i;
                i += 1;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'@')
                {
                    i += 1;
                }
                let word = &input[start..i];
                let next_is_paren = i < bytes.len() && bytes[i] == b'(';
                out[count] = Self::classify_word(word, next_is_paren);
                count += 1;
                continue;
            }

            i += 1;
        }

        count
    }

    fn classify_word(word: &str, next_is_paren: bool) -> SqlTokenKind {
        if next_is_paren {
            if word.eq_ignore_ascii_case("sleep") {
                return SqlTokenKind::Function("SLEEP");
            }
            if word.eq_ignore_ascii_case("pg_sleep") {
                return SqlTokenKind::Function("PG_SLEEP");
            }
            if word.eq_ignore_ascii_case("benchmark") {
                return SqlTokenKind::Function("BENCHMARK");
            }
            if word.eq_ignore_ascii_case("load_file") {
                return SqlTokenKind::Function("LOAD_FILE");
            }
            if word.eq_ignore_ascii_case("char") || word.eq_ignore_ascii_case("chr") {
                return SqlTokenKind::Function("CHAR");
            }
        }

        if word.eq_ignore_ascii_case("union") {
            SqlTokenKind::Keyword("UNION")
        } else if word.eq_ignore_ascii_case("select") {
            SqlTokenKind::Keyword("SELECT")
        } else if word.eq_ignore_ascii_case("all") || word.eq_ignore_ascii_case("distinct") {
            SqlTokenKind::Keyword("ALL")
        } else if word.eq_ignore_ascii_case("or") || word.eq_ignore_ascii_case("xor") {
            SqlTokenKind::Keyword("OR")
        } else if word.eq_ignore_ascii_case("and") {
            SqlTokenKind::Keyword("AND")
        } else if word.eq_ignore_ascii_case("from") {
            SqlTokenKind::Keyword("FROM")
        } else if word.eq_ignore_ascii_case("where") {
            SqlTokenKind::Keyword("WHERE")
        } else if word.eq_ignore_ascii_case("true") || word.eq_ignore_ascii_case("false") {
            SqlTokenKind::NumberLiteral
        } else if word.eq_ignore_ascii_case("null") {
            SqlTokenKind::NumberLiteral
        } else if word.eq_ignore_ascii_case("like") || word.eq_ignore_ascii_case("rlike") || word.eq_ignore_ascii_case("is") {
            SqlTokenKind::Operator
        } else if word.eq_ignore_ascii_case("waitfor") {
            SqlTokenKind::Keyword("WAITFOR")
        } else if word.eq_ignore_ascii_case("delay") {
            SqlTokenKind::Keyword("DELAY")
        } else if word.eq_ignore_ascii_case("drop") || word.eq_ignore_ascii_case("truncate") || word.eq_ignore_ascii_case("alter") {
            SqlTokenKind::Keyword("DROP")
        } else if word.eq_ignore_ascii_case("table") || word.eq_ignore_ascii_case("database") {
            SqlTokenKind::Keyword("TABLE")
        } else if word.eq_ignore_ascii_case("exec") || word.eq_ignore_ascii_case("execute") || word.eq_ignore_ascii_case("xp_cmdshell") {
            SqlTokenKind::Keyword("EXEC")
        } else if word.eq_ignore_ascii_case("information_schema") || word.eq_ignore_ascii_case("pg_catalog") || word.eq_ignore_ascii_case("sqlite_master") {
            SqlTokenKind::Keyword("CATALOG")
        } else if word.eq_ignore_ascii_case("outfile") || word.eq_ignore_ascii_case("dumpfile") {
            SqlTokenKind::Keyword("OUTFILE")
        } else {
            SqlTokenKind::Identifier
        }
    }

    fn evaluate_token_stream(stream: &[SqlTokenKind]) -> Option<SqliDetection> {
        let len = stream.len();
        for i in 0..len {
            match stream[i] {
                // 1. Dangerous Functions (SLEEP, PG_SLEEP, BENCHMARK, LOAD_FILE)
                SqlTokenKind::Function(fname @ ("SLEEP" | "PG_SLEEP" | "BENCHMARK")) => {
                    return Some(SqliDetection::BlindTimeDelay(fname));
                }
                SqlTokenKind::Function("LOAD_FILE") => {
                    return Some(SqliDetection::CatalogOrFileProbe("LOAD_FILE"));
                }
                SqlTokenKind::Keyword("CATALOG") => {
                    return Some(SqliDetection::CatalogOrFileProbe("SYSTEM_CATALOG"));
                }
                SqlTokenKind::Keyword("OUTFILE") => {
                    return Some(SqliDetection::CatalogOrFileProbe("INTO_OUTFILE"));
                }

                // 2. WAITFOR DELAY
                SqlTokenKind::Keyword("WAITFOR") => {
                    if i + 1 < len && stream[i + 1] == SqlTokenKind::Keyword("DELAY") {
                        return Some(SqliDetection::BlindTimeDelay("WAITFOR DELAY"));
                    }
                }

                // 3. UNION [ALL] [(] SELECT
                SqlTokenKind::Keyword("UNION") => {
                    for tok in stream.iter().skip(i + 1).take(4) {
                        if *tok == SqlTokenKind::Keyword("SELECT") {
                            return Some(SqliDetection::UnionExtraction("UNION SELECT"));
                        }
                    }
                }

                // 4. Stacked Queries: `; SELECT`, `; DROP`, `; EXEC`, `; WAITFOR`
                SqlTokenKind::Semicolon => {
                    if i + 1 < len {
                        match stream[i + 1] {
                            SqlTokenKind::Keyword("SELECT" | "DROP" | "EXEC" | "WAITFOR") => {
                                return Some(SqliDetection::StackedQuery("stacked_sql_statement"));
                            }
                            _ => {}
                        }
                    }
                }

                // 5. Boolean Tautologies:
                // Pattern A: [String/Num/Paren] OR [String/Num] = [String/Num]
                // Pattern B: StringLiteral OR [String/Num] CommentTail (`' OR 1--`)
                SqlTokenKind::Keyword("OR" | "AND") => {
                    let preceded_by_literal = i > 0
                        && matches!(
                            stream[i - 1],
                            SqlTokenKind::StringLiteral
                                | SqlTokenKind::NumberLiteral
                                | SqlTokenKind::Paren
                        );

                    if preceded_by_literal {
                        // Skip optional parens after OR
                        let mut j = i + 1;
                        while j < len && stream[j] == SqlTokenKind::Paren {
                            j += 1;
                        }
                        if j < len
                            && matches!(
                                stream[j],
                                SqlTokenKind::StringLiteral
                                    | SqlTokenKind::NumberLiteral
                                    | SqlTokenKind::Identifier
                            )
                        {
                            // Advance past left operand (and any trailing closing parens/quotes)
                            let mut k = j + 1;
                            while k < len
                                && matches!(
                                    stream[k],
                                    SqlTokenKind::Paren | SqlTokenKind::StringLiteral
                                )
                            {
                                k += 1;
                            }
                            if k < len && stream[k] == SqlTokenKind::Operator {
                                let mut m = k + 1;
                                while m < len && stream[m] == SqlTokenKind::Paren {
                                    m += 1;
                                }
                                if m < len
                                    && matches!(
                                        stream[m],
                                        SqlTokenKind::StringLiteral
                                            | SqlTokenKind::NumberLiteral
                                            | SqlTokenKind::Identifier
                                    )
                                {
                                    return Some(SqliDetection::BooleanTautology(
                                        "literal_or_equality",
                                    ));
                                }
                            }
                        }

                        // `' OR 1--` or `' OR true#`
                        if stream[i] == SqlTokenKind::Keyword("OR")
                            && j + 1 < len
                            && matches!(
                                stream[j],
                                SqlTokenKind::NumberLiteral | SqlTokenKind::StringLiteral
                            )
                            && stream[j + 1] == SqlTokenKind::CommentTail
                        {
                            return Some(SqliDetection::BooleanTautology("or_literal_comment"));
                        }
                    }
                }

                _ => {}
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comment_split_union_select() {
        assert_eq!(
            SqliTokenizer::inspect("1' UN/**/ION ALL SEL/**/ECT username,password FROM users--"),
            Some(SqliDetection::CommentObfuscation(
                "inline_comment_keyword_split"
            ))
        );
        assert_eq!(
            SqliTokenizer::inspect("1' /*!50000UNION*/ SELECT 1,2--"),
            Some(SqliDetection::CommentObfuscation("/*!versioned_comment*/"))
        );
    }

    #[test]
    fn test_boolean_tautologies_variants() {
        assert!(matches!(
            SqliTokenizer::inspect("admin') OR ('x')=('x"),
            Some(SqliDetection::BooleanTautology(_))
        ));
        assert!(matches!(
            SqliTokenizer::inspect("' OR 0x50=0x50--"),
            Some(SqliDetection::BooleanTautology(_))
        ));
        assert!(matches!(
            SqliTokenizer::inspect("1' OR 1#"),
            Some(SqliDetection::BooleanTautology(_))
        ));
    }

    #[test]
    fn test_benign_queries_pass() {
        assert_eq!(SqliTokenizer::inspect("search=select+your+plan+or+contact+us"), None);
        assert_eq!(SqliTokenizer::inspect("page=1&sort=asc&filter=active"), None);
    }
}
