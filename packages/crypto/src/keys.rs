//! Key hierarchy module.
//!
//! Implements the Krypt key derivation hierarchy:
//! - **MasterKey** → derived from biometric seed (see `biometric` module)
//! - **CategoryKey** → derived from MasterKey + category name (e.g., "medical", "financial")
//! - **ChunkKey** → derived from CategoryKey + chunk ID
//!
//! All derivations use HKDF-SHA256 with unique info strings to ensure domain separation.

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

use crate::biometric::MasterKey;

/// Errors from key derivation operations.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("HKDF expansion failed")]
    HkdfError,
    #[error("invalid category name: must be non-empty")]
    InvalidCategory,
    #[error("invalid chunk ID: must be non-empty")]
    InvalidChunkId,
}

/// A category-level key derived from the master key.
///
/// Each data category (e.g., "medical", "financial", "identity")
/// gets its own derived key, providing cryptographic separation.
#[derive(Clone, Debug)]
pub struct CategoryKey {
    key: [u8; 32],
    category: String,
}

impl CategoryKey {
    /// Derive a category key from a master key and category name.
    ///
    /// # Arguments
    /// * `master` - The master key (root of hierarchy)
    /// * `category` - Category name (e.g., "medical", "financial")
    pub fn derive(master: &MasterKey, category: &str) -> Result<Self, KeyError> {
        if category.is_empty() {
            return Err(KeyError::InvalidCategory);
        }
        let hk = Hkdf::<Sha256>::new(Some(b"krypt-category-v1"), master.as_bytes());
        let info = format!("krypt:category:{}", category);
        let mut key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut key)
            .map_err(|_| KeyError::HkdfError)?;
        Ok(Self {
            key,
            category: category.to_string(),
        })
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the category name.
    pub fn category(&self) -> &str {
        &self.category
    }
}

/// A chunk-level encryption key derived from a category key.
///
/// Each data chunk within a category gets its own unique key,
/// enabling granular access control at the chunk level.
#[derive(Clone, Debug)]
pub struct ChunkKey {
    key: [u8; 32],
    chunk_id: String,
}

impl ChunkKey {
    /// Derive a chunk key from a category key and chunk identifier.
    ///
    /// # Arguments
    /// * `category_key` - The parent category key
    /// * `chunk_id` - Unique identifier for the data chunk
    pub fn derive(category_key: &CategoryKey, chunk_id: &str) -> Result<Self, KeyError> {
        if chunk_id.is_empty() {
            return Err(KeyError::InvalidChunkId);
        }
        let hk = Hkdf::<Sha256>::new(Some(b"krypt-chunk-v1"), category_key.as_bytes());
        let info = format!("krypt:chunk:{}", chunk_id);
        let mut key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut key)
            .map_err(|_| KeyError::HkdfError)?;
        Ok(Self {
            key,
            chunk_id: chunk_id.to_string(),
        })
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the chunk identifier.
    pub fn chunk_id(&self) -> &str {
        &self.chunk_id
    }
}

/// Convenience struct for deriving the full key hierarchy in one go.
pub struct KeyHierarchy;

impl KeyHierarchy {
    /// Derive the full key chain: master → category → chunk.
    ///
    /// # Arguments
    /// * `master` - The master key
    /// * `category` - Category name
    /// * `chunk_id` - Chunk identifier
    ///
    /// # Returns
    /// A tuple of (CategoryKey, ChunkKey).
    pub fn derive(
        master: &MasterKey,
        category: &str,
        chunk_id: &str,
    ) -> Result<(CategoryKey, ChunkKey), KeyError> {
        let cat_key = CategoryKey::derive(master, category)?;
        let chunk_key = ChunkKey::derive(&cat_key, chunk_id)?;
        Ok((cat_key, chunk_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biometric::{BiometricSeed, MasterKey};

    fn test_master_key() -> MasterKey {
        let seed = BiometricSeed::from_bytes([42u8; 32]).unwrap();
        MasterKey::derive(&seed).unwrap()
    }

    #[test]
    fn test_category_key_derivation() {
        let mk = test_master_key();
        let ck = CategoryKey::derive(&mk, "medical").unwrap();
        assert_eq!(ck.category(), "medical");
    }

    #[test]
    fn test_category_key_deterministic() {
        let mk = test_master_key();
        let ck1 = CategoryKey::derive(&mk, "medical").unwrap();
        let ck2 = CategoryKey::derive(&mk, "medical").unwrap();
        assert_eq!(ck1.as_bytes(), ck2.as_bytes());
    }

    #[test]
    fn test_different_categories_different_keys() {
        let mk = test_master_key();
        let ck1 = CategoryKey::derive(&mk, "medical").unwrap();
        let ck2 = CategoryKey::derive(&mk, "financial").unwrap();
        assert_ne!(ck1.as_bytes(), ck2.as_bytes());
    }

    #[test]
    fn test_empty_category_rejected() {
        let mk = test_master_key();
        assert!(CategoryKey::derive(&mk, "").is_err());
    }

    #[test]
    fn test_chunk_key_derivation() {
        let mk = test_master_key();
        let cat = CategoryKey::derive(&mk, "medical").unwrap();
        let chunk = ChunkKey::derive(&cat, "chunk-001").unwrap();
        assert_eq!(chunk.chunk_id(), "chunk-001");
    }

    #[test]
    fn test_chunk_key_deterministic() {
        let mk = test_master_key();
        let cat = CategoryKey::derive(&mk, "medical").unwrap();
        let c1 = ChunkKey::derive(&cat, "chunk-001").unwrap();
        let c2 = ChunkKey::derive(&cat, "chunk-001").unwrap();
        assert_eq!(c1.as_bytes(), c2.as_bytes());
    }

    #[test]
    fn test_different_chunks_different_keys() {
        let mk = test_master_key();
        let cat = CategoryKey::derive(&mk, "medical").unwrap();
        let c1 = ChunkKey::derive(&cat, "chunk-001").unwrap();
        let c2 = ChunkKey::derive(&cat, "chunk-002").unwrap();
        assert_ne!(c1.as_bytes(), c2.as_bytes());
    }

    #[test]
    fn test_key_hierarchy_convenience() {
        let mk = test_master_key();
        let (cat, chunk) = KeyHierarchy::derive(&mk, "medical", "chunk-001").unwrap();
        assert_eq!(cat.category(), "medical");
        assert_eq!(chunk.chunk_id(), "chunk-001");
    }

    #[test]
    fn test_full_derivation_path_deterministic() {
        let seed = BiometricSeed::from_bytes([99u8; 32]).unwrap();
        let mk1 = MasterKey::derive(&seed).unwrap();
        let (_, chunk1) = KeyHierarchy::derive(&mk1, "financial", "tx-log").unwrap();

        let mk2 = MasterKey::derive(&seed).unwrap();
        let (_, chunk2) = KeyHierarchy::derive(&mk2, "financial", "tx-log").unwrap();

        assert_eq!(chunk1.as_bytes(), chunk2.as_bytes());
    }
}
