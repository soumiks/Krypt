use wasm_bindgen::prelude::*;
use crate::biometric::{BiometricSeed, MasterKey};
use crate::keys::{CategoryKey, ChunkKey};
use crate::chunk::{encrypt_chunk as core_encrypt, decrypt_chunk as core_decrypt, EncryptedChunk};

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
