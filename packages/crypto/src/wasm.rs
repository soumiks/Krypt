use wasm_bindgen::prelude::*;
use crate::biometric::{BiometricSeed, MasterKey};
use crate::keys::{CategoryKey, ChunkKey};
use crate::chunk::{encrypt_chunk as core_encrypt, decrypt_chunk as core_decrypt, decrypt_with_key, EncryptedChunk};
use crate::vendor::{generate_vendor_key as core_generate_vendor_key, VendorAccessKey};

// --- Biometric Seed ---

#[wasm_bindgen(js_name = BiometricSeed)]
pub struct JsBiometricSeed(BiometricSeed);

#[wasm_bindgen(js_class = BiometricSeed)]
impl JsBiometricSeed {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<JsBiometricSeed, JsValue> {
        if bytes.len() != 32 {
            return Err(JsValue::from_str("Seed must be exactly 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        
        let seed = BiometricSeed::from_bytes(arr)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        Ok(JsBiometricSeed(seed))
    }

    #[wasm_bindgen]
    pub fn from_entropy(bytes: &[u8]) -> Result<JsBiometricSeed, JsValue> {
        Self::new(bytes)
    }
}

// --- Master Key ---

#[wasm_bindgen(js_name = MasterKey)]
pub struct JsMasterKey(MasterKey);

#[wasm_bindgen(js_class = MasterKey)]
impl JsMasterKey {
    pub fn derive(seed: &JsBiometricSeed) -> Result<JsMasterKey, JsValue> {
        let key = MasterKey::derive(&seed.0)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(JsMasterKey(key))
    }
}

// --- Category Key ---

#[wasm_bindgen(js_name = CategoryKey)]
pub struct JsCategoryKey(CategoryKey);

#[wasm_bindgen(js_class = CategoryKey)]
impl JsCategoryKey {
    pub fn derive(master_key: &JsMasterKey, category: &str) -> Result<JsCategoryKey, JsValue> {
        let key = CategoryKey::derive(&master_key.0, category)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(JsCategoryKey(key))
    }
}

// --- Chunk Key ---

#[wasm_bindgen(js_name = ChunkKey)]
pub struct JsChunkKey(ChunkKey);

#[wasm_bindgen(js_class = ChunkKey)]
impl JsChunkKey {
    pub fn derive(category_key: &JsCategoryKey, chunk_id: &str) -> Result<JsChunkKey, JsValue> {
        let key = ChunkKey::derive(&category_key.0, chunk_id)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(JsChunkKey(key))
    }
}

// --- Encrypted Chunk ---

#[wasm_bindgen(js_name = EncryptedChunk)]
pub struct JsEncryptedChunk {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[wasm_bindgen(js_class = EncryptedChunk)]
impl JsEncryptedChunk {
    #[wasm_bindgen(constructor)]
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> JsEncryptedChunk {
        JsEncryptedChunk { nonce, ciphertext }
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
}

// --- Vendor Access Key ---

#[wasm_bindgen(js_name = VendorAccessKey)]
pub struct JsVendorAccessKey(VendorAccessKey);

#[wasm_bindgen(js_class = VendorAccessKey)]
impl JsVendorAccessKey {
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> Vec<u8> {
        self.0.key.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn vendor_id(&self) -> String {
        self.0.vendor_id.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn expires_at(&self) -> u64 {
        self.0.expires_at
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        self.0.is_expired(current_time)
    }

    /// Reconstruct a vendor key from its components (for the recipient).
    #[wasm_bindgen]
    pub fn from_components(key_bytes: &[u8], vendor_id: &str, expires_at: u64) -> Result<JsVendorAccessKey, JsValue> {
        if key_bytes.len() != 32 {
            return Err(JsValue::from_str("Vendor key must be exactly 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        
        Ok(JsVendorAccessKey(VendorAccessKey {
            key,
            vendor_id: vendor_id.to_string(),
            expires_at
        }))
    }
}

#[wasm_bindgen]
pub fn generate_vendor_key(
    chunk_key: &JsChunkKey,
    vendor_id: &str,
    expires_at: u64,
) -> Result<JsVendorAccessKey, JsValue> {
    let key = core_generate_vendor_key(&chunk_key.0, vendor_id, expires_at)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(JsVendorAccessKey(key))
}

// --- Core Functions ---

#[wasm_bindgen]
pub fn encrypt_chunk(
    chunk_key: &JsChunkKey,
    plaintext: &[u8]
) -> Result<JsEncryptedChunk, JsValue> {
    let encrypted = core_encrypt(&chunk_key.0, plaintext)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(JsEncryptedChunk {
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
    })
}

#[wasm_bindgen]
pub fn decrypt_chunk(
    chunk_key: &JsChunkKey,
    encrypted_chunk: &JsEncryptedChunk
) -> Result<Vec<u8>, JsValue> {
    let core_encrypted = EncryptedChunk {
        nonce: encrypted_chunk.nonce.clone(),
        ciphertext: encrypted_chunk.ciphertext.clone(),
    };

    let plaintext = core_decrypt(&chunk_key.0, &core_encrypted)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(plaintext)
}

#[wasm_bindgen]
pub fn decrypt_vendor_chunk(
    vendor_key: &JsVendorAccessKey,
    encrypted_chunk: &JsEncryptedChunk
) -> Result<Vec<u8>, JsValue> {
    let core_encrypted = EncryptedChunk {
        nonce: encrypted_chunk.nonce.clone(),
        ciphertext: encrypted_chunk.ciphertext.clone(),
    };

    let plaintext = decrypt_with_key(&vendor_key.0.key, &core_encrypted)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(plaintext)
}
