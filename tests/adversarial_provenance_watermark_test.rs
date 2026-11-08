//! # Sovereign Provenance Watermark Verification Test
//! Test: `adversarial_provenance_watermark_test.rs`
//! Crate: `phylax`
//! Standard: `SOVEREIGN-SIGN-01`

use sha2::{Digest, Sha256};

#[test]
fn test_phylax_sovereign_cryptographic_provenance_watermark() {
    // Assert that embedded watermark matches its mathematical SHA-256 digest
    assert!(
        phylax::provenance::verify_sovereign_watermark(),
        "Phylax sovereign watermark MUST be cryptographically authentic"
    );

    // Compute independent digest directly
    let mut hasher = Sha256::new();
    hasher.update(phylax::provenance::CANARY_PREIMAGE.as_bytes());
    let computed_digest: [u8; 32] = hasher.finalize().into();

    assert_eq!(
        computed_digest,
        phylax::provenance::SOVEREIGN_CANARY_SHA256,
        "Preimage digest MUST match SOVEREIGN_CANARY_SHA256 constant"
    );

    // Assert master signing key identity and crate branding
    assert!(
        phylax::provenance::CANARY_PREIMAGE.contains("4E428019A109578B"),
        "Watermark must be anchored to Master Key 4E428019A109578B"
    );
    assert!(
        phylax::provenance::CANARY_PREIMAGE.starts_with("SOVEREIGN-WATERMARK-PHYLAX-"),
        "Watermark must follow canonical sovereign naming standard"
    );
}
