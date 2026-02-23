//! # Krypt Crypto
//!
//! Cryptographic core for the Krypt protocol. Provides:
//!
//! - **Biometric key derivation**: Derive deterministic keys from biometric seeds
//! - **Chunk encryption**: AES-256-GCM encryption/decryption of data chunks
//! - **Key hierarchy**: Master → Category → Chunk key derivation
//! - **Vendor access**: Time-limited vendor key generation

pub mod biometric;
pub mod chunk;
pub mod keys;
pub mod vendor;

pub use biometric::{BiometricSeed, FuzzyExtractor, MasterKey};
pub use chunk::{decrypt_chunk, encrypt_chunk, EncryptedChunk};
pub use keys::{CategoryKey, ChunkKey, KeyHierarchy};
pub use vendor::{generate_vendor_key, VendorAccessKey};
