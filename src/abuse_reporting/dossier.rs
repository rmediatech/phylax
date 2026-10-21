//! # Forensic Incident Dossier & X-ARF Formatter
//! One-Job: Immutable incident data structure and RFC/AbuseIPDB compliant evidence serialization.

use crate::abuse_reporting::category::AbuseCategory;
use crate::sanitize::{neutralize_formula_injection, scrub_ansi_and_control, scrub_multiline_text};
use serde::{Deserialize, Serialize};

/// Immutable container holding forensic evidence for an abusive incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicDossier {
    pub client_ip: String,
    pub timestamp_ms: u64,
    pub target_uri: String,
    pub http_method: String,
    pub category: AbuseCategory,
    pub trapped_field: Option<String>,
    pub user_agent: Option<String>,
    pub evidence_notes: String,
}

/// Stateless formatter generating standardized comments and X-ARF structures
pub struct DossierFormatter;

impl DossierFormatter {
    /// Renders an evidence comment strictly capped at 1024 characters (AbuseIPDB requirement)
    /// and scrubbed against ANSI CSI/OSC log poisoning and formula injection.
    pub fn render_incident_comment(dossier: &ForensicDossier) -> String {
        let safe_ip = scrub_ansi_and_control(&dossier.client_ip);
        let safe_method = scrub_ansi_and_control(&dossier.http_method);
        let safe_uri = scrub_ansi_and_control(&dossier.target_uri);
        let safe_notes = scrub_multiline_text(&dossier.evidence_notes, 1200);

        let mut comment = format!(
            "[Phylax Security Report] Type: {}\nSource IP: {}\nEndpoint: {} {}\nTimestamp: {} ms\nNotes: {}\n",
            dossier.category.name(),
            safe_ip,
            safe_method,
            safe_uri,
            dossier.timestamp_ms,
            safe_notes
        );

        if let Some(ref field) = dossier.trapped_field {
            let safe_field = scrub_ansi_and_control(field);
            comment.push_str(&format!("Honeypot Decoy Field Tripped: '{}'\n", safe_field));
        }

        if let Some(ref ua) = dossier.user_agent {
            let safe_ua = neutralize_formula_injection(ua);
            comment.push_str(&format!("User-Agent: {}\n", safe_ua));
        }

        comment.push_str(
            "Forensic validation: Automated probe detected by deterministic application defense.",
        );

        // Guard against AbuseIPDB 1024 character hard ceiling
        if comment.len() > 1024 {
            comment.truncate(1021);
            comment.push_str("...");
        }

        comment
    }

    /// Renders a sanitized CSV row with formula injection neutralization on all user-controlled fields
    pub fn render_csv_row(dossier: &ForensicDossier) -> String {
        let ip = neutralize_formula_injection(&dossier.client_ip);
        let method = neutralize_formula_injection(&dossier.http_method);
        let uri = neutralize_formula_injection(&dossier.target_uri);
        let category = neutralize_formula_injection(dossier.category.name());
        let field = dossier
            .trapped_field
            .as_deref()
            .map(neutralize_formula_injection)
            .unwrap_or_default();
        let ua = dossier
            .user_agent
            .as_deref()
            .map(neutralize_formula_injection)
            .unwrap_or_default();
        let notes = neutralize_formula_injection(&dossier.evidence_notes);

        format!(
            "\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            ip.replace('"', "\"\""),
            dossier.timestamp_ms,
            method.replace('"', "\"\""),
            uri.replace('"', "\"\""),
            category.replace('"', "\"\""),
            field.replace('"', "\"\""),
            ua.replace('"', "\"\""),
            notes.replace('"', "\"\"")
        )
    }

    /// Renders standard JSON format (compatible with X-ARF / Network Abuse Reporting 2.0)
    pub fn render_xarf_json(dossier: &ForensicDossier) -> serde_json::Value {
        serde_json::json!({
            "version": "2.0.0",
            "report_type": "web_abuse",
            "source_ip": scrub_ansi_and_control(&dossier.client_ip),
            "timestamp_ms": dossier.timestamp_ms,
            "target_uri": scrub_ansi_and_control(&dossier.target_uri),
            "http_method": scrub_ansi_and_control(&dossier.http_method),
            "category": dossier.category.name(),
            "category_ids": dossier.category.category_ids(),
            "trapped_field": dossier.trapped_field.as_deref().map(scrub_ansi_and_control),
            "user_agent": dossier.user_agent.as_deref().map(scrub_ansi_and_control),
            "evidence": scrub_multiline_text(&dossier.evidence_notes, 2048),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dossier_truncates_oversized_evidence_notes_to_1024_chars() {
        let massive_notes = "A".repeat(2000);
        let dossier = ForensicDossier {
            client_ip: "10.0.0.1".to_string(),
            timestamp_ms: 123456789,
            target_uri: "/api/test".to_string(),
            http_method: "GET".to_string(),
            category: AbuseCategory::ExploitProbe,
            trapped_field: None,
            user_agent: None,
            evidence_notes: massive_notes,
        };

        let comment = DossierFormatter::render_incident_comment(&dossier);
        assert!(comment.len() <= 1024);
        assert!(comment.ends_with("..."));
    }

    #[test]
    fn test_xarf_json_contains_proper_schema() {
        let dossier = ForensicDossier {
            client_ip: "10.0.0.1".to_string(),
            timestamp_ms: 123456789,
            target_uri: "/api/test".to_string(),
            http_method: "POST".to_string(),
            category: AbuseCategory::WebHoneypot,
            trapped_field: Some("hp_field".to_string()),
            user_agent: Some("TestAgent/1.0".to_string()),
            evidence_notes: "trip".to_string(),
        };

        let xarf = DossierFormatter::render_xarf_json(&dossier);
        assert_eq!(xarf["version"], "2.0.0");
        assert_eq!(xarf["report_type"], "web_abuse");
        assert_eq!(xarf["category_ids"][0], 10);
        assert_eq!(xarf["category_ids"][1], 21);
    }
}
