//! Time-limited vendor key generation.
//!
//! Vendors (e.g., doctors, insurers) receive derived keys that grant
//! access to specific chunks for a limited time period.

use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::ChunkKey;

/// Errors from vendor key operations.
#[derive(Debug, Error)]
pub enum VendorError {
    #[error("HKDF expansion failed")]
    HkdfError,
    #[error("vendor ID must be non-empty")]
    InvalidVendorId,
    #[error("vendor key has expired")]
    KeyExpired,
}

/// A time-limited access key for a vendor to decrypt a specific chunk.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VendorAccessKey {
    /// The derived 256-bit key for decrypting the chunk.
    pub key: [u8; 32],
    /// The vendor's identifier.
    pub vendor_id: String,
    /// Unix timestamp (seconds) when this key expires.
    pub expires_at: u64,
}

impl VendorAccessKey {
    /// Check if this vendor key has expired.
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time >= self.expires_at
    }
}

/// Generate a time-limited vendor access key for a specific chunk.
///
/// The key is deterministically derived from the chunk key, vendor ID,
/// and expiry time, ensuring that the same parameters always produce
/// the same vendor key.
///
/// # Arguments
/// * `chunk_key` - The chunk key to derive access from
/// * `vendor_id` - Unique identifier for the vendor
/// * `expires_at` - Unix timestamp when access expires
pub fn generate_vendor_key(
    chunk_key: &ChunkKey,
    vendor_id: &str,
    expires_at: u64,
) -> Result<VendorAccessKey, VendorError> {
    if vendor_id.is_empty() {
        return Err(VendorError::InvalidVendorId);
    }

    let hk = Hkdf::<Sha256>::new(Some(b"krypt-vendor-v1"), chunk_key.as_bytes());
    let info = format!("krypt:vendor:{}:{}", vendor_id, expires_at);
    let mut key = [0u8; 32];
    hk.expand(info.as_bytes(), &mut key)
        .map_err(|_| VendorError::HkdfError)?;

    Ok(VendorAccessKey {
        key,
        vendor_id: vendor_id.to_string(),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biometric::{BiometricSeed, MasterKey};
    use crate::keys::{CategoryKey, ChunkKey};

    fn test_chunk_key() -> ChunkKey {
        let seed = BiometricSeed::from_bytes([42u8; 32]).unwrap();
        let mk = MasterKey::derive(&seed).unwrap();
        let cat = CategoryKey::derive(&mk, "medical").unwrap();
        ChunkKey::derive(&cat, "blood-test-2024").unwrap()
    }

    #[test]
    fn test_generate_vendor_key() {
        let ck = test_chunk_key();
        let vk = generate_vendor_key(&ck, "dr-smith", 1700000000).unwrap();
        assert_eq!(vk.vendor_id, "dr-smith");
        assert_eq!(vk.expires_at, 1700000000);
    }

    #[test]
    fn test_vendor_key_deterministic() {
        let ck = test_chunk_key();
        let vk1 = generate_vendor_key(&ck, "dr-smith", 1700000000).unwrap();
        let vk2 = generate_vendor_key(&ck, "dr-smith", 1700000000).unwrap();
        assert_eq!(vk1.key, vk2.key);
    }

    #[test]
    fn test_different_vendors_different_keys() {
        let ck = test_chunk_key();
        let vk1 = generate_vendor_key(&ck, "dr-smith", 1700000000).unwrap();
        let vk2 = generate_vendor_key(&ck, "dr-jones", 1700000000).unwrap();
        assert_ne!(vk1.key, vk2.key);
    }

    #[test]
    fn test_different_expiry_different_keys() {
        let ck = test_chunk_key();
        let vk1 = generate_vendor_key(&ck, "dr-smith", 1700000000).unwrap();
        let vk2 = generate_vendor_key(&ck, "dr-smith", 1800000000).unwrap();
        assert_ne!(vk1.key, vk2.key);
    }

    #[test]
    fn test_empty_vendor_id_rejected() {
        let ck = test_chunk_key();
        assert!(generate_vendor_key(&ck, "", 1700000000).is_err());
    }

    #[test]
    fn test_expiry_check() {
        let ck = test_chunk_key();
        let vk = generate_vendor_key(&ck, "dr-smith", 1700000000).unwrap();
        assert!(!vk.is_expired(1699999999));
        assert!(vk.is_expired(1700000000));
        assert!(vk.is_expired(1700000001));
    }
}
