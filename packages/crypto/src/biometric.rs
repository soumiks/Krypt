//! Biometric key derivation module.
//!
//! Implements the flow:
//! 1. User provides biometric template (from device secure enclave)
//! 2. Fuzzy extractor produces a stable seed from noisy biometric input
//! 3. HKDF derives the master key from the seed
//!
//! The fuzzy extractor is simulated here — real implementations would
//! interface with device hardware (e.g., iOS Secure Enclave, Android StrongBox).

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

/// Errors that can occur during biometric key derivation.
#[derive(Debug, Error)]
pub enum BiometricError {
    #[error("biometric seed is empty or invalid")]
    InvalidSeed,
    #[error("HKDF expansion failed")]
    HkdfError,
    #[error("fuzzy extraction failed: {0}")]
    ExtractionFailed(String),
}

/// Represents the stable output of fuzzy extraction from a biometric template.
///
/// In production, this would come from a secure enclave's fuzzy extractor.
/// The seed is deterministic for the same biometric input (within tolerance).
#[derive(Clone, Debug)]
pub struct BiometricSeed {
    /// The stable 32-byte seed derived from biometric data.
    seed: [u8; 32],
}

impl BiometricSeed {
    /// Create a BiometricSeed from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, BiometricError> {
        if bytes.iter().all(|&b| b == 0) {
            return Err(BiometricError::InvalidSeed);
        }
        Ok(Self { seed: bytes })
    }

    /// Get the raw seed bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.seed
    }
}

/// The master key derived from a biometric seed via HKDF-SHA256.
///
/// This is the root of the key hierarchy. All category and chunk keys
/// are derived from this master key.
#[derive(Clone, Debug)]
pub struct MasterKey {
    key: [u8; 32],
}

impl MasterKey {
    /// Derive a master key from a biometric seed using HKDF-SHA256.
    ///
    /// # Arguments
    /// * `seed` - The biometric seed from fuzzy extraction
    ///
    /// # Returns
    /// A deterministic 256-bit master key.
    pub fn derive(seed: &BiometricSeed) -> Result<Self, BiometricError> {
        let hk = Hkdf::<Sha256>::new(Some(b"krypt-master-v1"), seed.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"krypt:master-key", &mut key)
            .map_err(|_| BiometricError::HkdfError)?;
        Ok(Self { key })
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Simulated fuzzy extractor for biometric templates.
///
/// In production, this would interface with secure hardware.
/// This implementation simulates the extraction by hashing the template
/// to produce a stable seed.
pub struct FuzzyExtractor;

impl FuzzyExtractor {
    /// Extract a stable seed from a biometric template.
    ///
    /// # Arguments
    /// * `template` - Raw biometric template bytes (e.g., from fingerprint/face scan)
    /// * `helper_data` - Public helper data for error correction (stored alongside vault)
    ///
    /// # Returns
    /// A stable `BiometricSeed` that is deterministic for the same biometric input.
    pub fn extract(
        template: &[u8],
        helper_data: &[u8],
    ) -> Result<BiometricSeed, BiometricError> {
        if template.is_empty() {
            return Err(BiometricError::ExtractionFailed(
                "empty biometric template".into(),
            ));
        }

        // Simulated fuzzy extraction: HKDF over template + helper data.
        // Real implementation would use a secure sketch + strong extractor.
        let hk = Hkdf::<Sha256>::new(Some(helper_data), template);
        let mut seed = [0u8; 32];
        hk.expand(b"krypt:fuzzy-extract-v1", &mut seed)
            .map_err(|_| BiometricError::HkdfError)?;

        BiometricSeed::from_bytes(seed)
    }

    /// Generate initial helper data for a new biometric enrollment.
    ///
    /// This helper data must be stored alongside the vault metadata.
    /// It is public and does not reveal the biometric template.
    pub fn generate_helper_data(template: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(b"krypt:helper-v1:");
        hasher.update(template);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_seed_from_bytes() {
        let bytes = [42u8; 32];
        let seed = BiometricSeed::from_bytes(bytes).unwrap();
        assert_eq!(seed.as_bytes(), &bytes);
    }

    #[test]
    fn test_biometric_seed_rejects_zero() {
        let bytes = [0u8; 32];
        assert!(BiometricSeed::from_bytes(bytes).is_err());
    }

    #[test]
    fn test_master_key_derivation_deterministic() {
        let seed = BiometricSeed::from_bytes([7u8; 32]).unwrap();
        let mk1 = MasterKey::derive(&seed).unwrap();
        let mk2 = MasterKey::derive(&seed).unwrap();
        assert_eq!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn test_different_seeds_produce_different_keys() {
        let seed1 = BiometricSeed::from_bytes([1u8; 32]).unwrap();
        let seed2 = BiometricSeed::from_bytes([2u8; 32]).unwrap();
        let mk1 = MasterKey::derive(&seed1).unwrap();
        let mk2 = MasterKey::derive(&seed2).unwrap();
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn test_fuzzy_extractor_deterministic() {
        let template = b"fingerprint-data-abc123";
        let helper = FuzzyExtractor::generate_helper_data(template);

        let seed1 = FuzzyExtractor::extract(template, &helper).unwrap();
        let seed2 = FuzzyExtractor::extract(template, &helper).unwrap();
        assert_eq!(seed1.as_bytes(), seed2.as_bytes());
    }

    #[test]
    fn test_fuzzy_extractor_empty_template() {
        assert!(FuzzyExtractor::extract(b"", b"helper").is_err());
    }

    #[test]
    fn test_full_key_hierarchy_determinism() {
        let template = b"my-biometric-template";
        let helper = FuzzyExtractor::generate_helper_data(template);
        let seed = FuzzyExtractor::extract(template, &helper).unwrap();
        let master = MasterKey::derive(&seed).unwrap();

        // Re-derive everything from scratch
        let seed2 = FuzzyExtractor::extract(template, &helper).unwrap();
        let master2 = MasterKey::derive(&seed2).unwrap();

        assert_eq!(master.as_bytes(), master2.as_bytes());
    }
}
