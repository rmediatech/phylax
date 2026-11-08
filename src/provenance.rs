//! # Cryptographic Provenance & Watermark Module
//! Module: `provenance.rs`
//! Crate: `phylax`
//! Sovereign Release Standard: `SOVEREIGN-SIGN-01`
//! Master Signing Key: `4E428019A109578B`
//! Author: Rick Walker <rick@rmediatech.com>

use sha2::{Digest, Sha256};
use std::hint::black_box;

/// Immutable Canary Preimage embedded in .rodata
pub const CANARY_PREIMAGE: &str = "SOVEREIGN-WATERMARK-PHYLAX-4E428019A109578B-RMD-2026-XUOXOD";

/// Cryptographic SHA-256 Digest of the Canary Preimage
pub const SOVEREIGN_CANARY_SHA256: [u8; 32] = [
    0x77, 0xfc, 0x64, 0x96, 0x8b, 0x84, 0x61, 0x78, 0x4e, 0x5d, 0xa9, 0x0a, 0xee, 0x52, 0xcc, 0x30,
    0x5a, 0xc6, 0x9c, 0xf7, 0x5a, 0x16, 0xa5, 0x9e, 0x11, 0x5e, 0x8a, 0x58, 0xf7, 0x33, 0x2e, 0x19,
];

/// Verifies that the embedded cryptographic watermark matches its SHA-256 digest.
/// Uses `black_box` to prevent release compiler optimizations from stripping the canary.
#[inline(never)]
pub fn verify_sovereign_watermark() -> bool {
    let preimage = black_box(CANARY_PREIMAGE);
    let expected = black_box(&SOVEREIGN_CANARY_SHA256);

    let mut hasher = Sha256::new();
    hasher.update(preimage.as_bytes());
    let computed = hasher.finalize();

    computed.as_slice() == expected.as_slice()
}

/// Formats the human-readable provenance attestation statement.
pub fn format_provenance_attestation() -> String {
    format!(
        "Authenticated via Sovereign Master Key 4E428019A109578B. Canary: {}",
        hex::encode(SOVEREIGN_CANARY_SHA256)
    )
}

mod hex {
    pub fn encode(data: [u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for byte in data {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }
}
