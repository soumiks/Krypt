//! Chunk encryption and decryption module.
//!
//! Each data chunk is encrypted with AES-256-GCM using a unique chunk key.
//! A random 96-bit nonce is generated per encryption operation.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, AeadCore, Nonce,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::ChunkKey;

/// Errors from chunk encryption/decryption.
#[derive(Debug, Error)]
pub enum ChunkError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed — invalid key or corrupted data")]
    DecryptionFailed,
    #[error("invalid nonce length")]
    InvalidNonce,
}

/// An encrypted data chunk containing ciphertext and its nonce.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedChunk {
    /// The 12-byte nonce used for AES-GCM.
    pub nonce: Vec<u8>,
    /// The encrypted data (ciphertext + authentication tag).
    pub ciphertext: Vec<u8>,
}

/// Encrypt a plaintext data chunk with AES-256-GCM.
///
/// # Arguments
/// * `chunk_key` - The chunk-level encryption key
/// * `plaintext` - The data to encrypt
///
/// # Returns
/// An `EncryptedChunk` containing the nonce and ciphertext.
pub fn encrypt_chunk(chunk_key: &ChunkKey, plaintext: &[u8]) -> Result<EncryptedChunk, ChunkError> {
    let cipher = Aes256Gcm::new_from_slice(chunk_key.as_bytes())
        .map_err(|_| ChunkError::EncryptionFailed)?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| ChunkError::EncryptionFailed)?;

    Ok(EncryptedChunk {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Decrypt an encrypted data chunk with AES-256-GCM.
///
/// # Arguments
/// * `chunk_key` - The chunk-level encryption key (must match the key used for encryption)
/// * `encrypted` - The encrypted chunk data
///
/// # Returns
/// The decrypted plaintext bytes.
pub fn decrypt_chunk(
    chunk_key: &ChunkKey,
    encrypted: &EncryptedChunk,
) -> Result<Vec<u8>, ChunkError> {
    decrypt_with_key(chunk_key.as_bytes(), encrypted)
}

/// Decrypt an encrypted data chunk with a raw AES-256-GCM key.
pub fn decrypt_with_key(
    key_bytes: &[u8; 32],
    encrypted: &EncryptedChunk,
) -> Result<Vec<u8>, ChunkError> {
    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|_| ChunkError::DecryptionFailed)?;

    let nonce = Nonce::from_exact_iter(encrypted.nonce.iter().copied())
        .ok_or(ChunkError::InvalidNonce)?;

    cipher
        .decrypt(&nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| ChunkError::DecryptionFailed)
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
        ChunkKey::derive(&cat, "chunk-001").unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_chunk_key();
        let plaintext = b"sensitive medical record data here";

        let encrypted = encrypt_chunk(&key, plaintext).unwrap();
        let decrypted = decrypt_chunk(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_empty_data() {
        let key = test_chunk_key();
        let encrypted = encrypt_chunk(&key, b"").unwrap();
        let decrypted = decrypt_chunk(&key, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_large_data() {
        let key = test_chunk_key();
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB

        let encrypted = encrypt_chunk(&key, &plaintext).unwrap();
        let decrypted = decrypt_chunk(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces_per_encryption() {
        let key = test_chunk_key();
        let plaintext = b"same data twice";

        let enc1 = encrypt_chunk(&key, plaintext).unwrap();
        let enc2 = encrypt_chunk(&key, plaintext).unwrap();

        // Nonces should differ (random)
        assert_ne!(enc1.nonce, enc2.nonce);
        // Ciphertexts should also differ due to different nonces
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = test_chunk_key();

        let seed2 = BiometricSeed::from_bytes([99u8; 32]).unwrap();
        let mk2 = MasterKey::derive(&seed2).unwrap();
        let cat2 = CategoryKey::derive(&mk2, "medical").unwrap();
        let key2 = ChunkKey::derive(&cat2, "chunk-001").unwrap();

        let encrypted = encrypt_chunk(&key1, b"secret").unwrap();
        assert!(decrypt_chunk(&key2, &encrypted).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_chunk_key();
        let mut encrypted = encrypt_chunk(&key, b"secret").unwrap();
        encrypted.ciphertext[0] ^= 0xFF; // tamper
        assert!(decrypt_chunk(&key, &encrypted).is_err());
    }
}
