//! # Benign Workload & RFC Conformance Adversarial Test Suite
//! Asserts zero false positives on legitimate, high-entropy web workloads
//! while ensuring 100% containment of genuine adversarial climbing/injection vectors.

use phylax::payload_guard::{AdversarialPayload, PayloadGuard};

#[test]
fn test_benign_url_encoded_parameters_pass_cleanly() {
    let benign_queries = [
        // 1. QR code and deep link generator parameters with nested URLs
        "text=https%3A%2F%2Fapp.example.com%2F%3Froom%3Dlobby%26callsign%3DOperator-1",
        "redirect_uri=https%3A%2F%2Fauth.example.com%2Foauth2%2Fcallback%3Fclient_id%3D123",
        "target=https%3A%2F%2Fmedia.example.com%2Fapi%2Fv1%2Fsync",
        "url=https%3A%2F%2Fcdn.example.com%2Fimages%2Favatar.png",
        // 2. Search queries with slashes, dates, and colons
        "q=category%2Fsubcat%2Fitem",
        "search=date%3A2026%2F10%2F29%20filter%3Astatus",
        "path=user%2Fprofile%2Fsettings",
        // 3. Base64 encoded telemetry blobs & tokens
        "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        "data=aGVsbG8gd29ybGQgZnJvbSBhcHA=",
        // 4. Internationalized and localized queries
        "lang=zh-CN&msg=%E4%BD%A0%E5%A5%BD%E4%B8%96%E7%95%8C",
        "tag=%E6%88%98%E6%9C%AF%E9%80%9A%E4%BF%A1",
    ];

    for query in &benign_queries {
        let res = PayloadGuard::inspect("/api/v1/resource", query);
        assert!(
            res.is_ok(),
            "Benign query must NEVER be false-positive blocked: '{}', got: {:?}",
            query,
            res.err()
        );
    }
}

#[test]
fn test_adversarial_traversal_remains_strictly_blocked() {
    let hostile_traversals = [
        // Standard dot-dot-slash
        "path=../../etc/passwd",
        "file=..%2f..%2fetc%2fshadow",
        "target=%2e%2e%2f%2e%2e%2fetc%2fhosts",
        "name=..%5c..%5cwindows%2fwin.ini",
        "doc=%2e%2e%5c%2e%2e%5cboot.ini",
        "probe=/proc/self/environ",
        "stream=file:///etc/passwd",
        "wrapper=php://filter/read=string.rot13/resource=index.php",
    ];

    for attack in &hostile_traversals {
        let res = PayloadGuard::inspect("/download", attack);
        assert!(
            matches!(res, Err(AdversarialPayload::PathTraversal(_))),
            "Hostile traversal payload MUST be blocked: '{}', got: {:?}",
            attack,
            res
        );
    }
}
