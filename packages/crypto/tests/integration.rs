//! Integration tests for the full Krypt crypto pipeline.

use krypt_crypto::{
    BiometricSeed, FuzzyExtractor, KeyHierarchy, MasterKey,
    decrypt_chunk, encrypt_chunk, generate_vendor_key,
};

#[test]
fn test_end_to_end_encrypt_decrypt() {
    // 1. Simulate biometric enrollment
    let template = b"user-fingerprint-scan-data-12345";
    let helper_data = FuzzyExtractor::generate_helper_data(template);

    // 2. Extract seed and derive keys
    let seed = FuzzyExtractor::extract(template, &helper_data).unwrap();
    let master = MasterKey::derive(&seed).unwrap();
    let (_, chunk_key) = KeyHierarchy::derive(&master, "medical", "blood-test-jan-2024").unwrap();

    // 3. Encrypt data
    let medical_record = b"Patient: John Doe\nBlood Type: O+\nCholesterol: 180 mg/dL";
    let encrypted = encrypt_chunk(&chunk_key, medical_record).unwrap();

    // 4. Re-derive keys from same biometric (simulating a later session)
    let seed2 = FuzzyExtractor::extract(template, &helper_data).unwrap();
    let master2 = MasterKey::derive(&seed2).unwrap();
    let (_, chunk_key2) =
        KeyHierarchy::derive(&master2, "medical", "blood-test-jan-2024").unwrap();

    // 5. Decrypt with re-derived key
    let decrypted = decrypt_chunk(&chunk_key2, &encrypted).unwrap();
    assert_eq!(decrypted, medical_record);
}

#[test]
fn test_vendor_access_flow() {
    let seed = BiometricSeed::from_bytes([77u8; 32]).unwrap();
    let master = MasterKey::derive(&seed).unwrap();
    let (_, chunk_key) = KeyHierarchy::derive(&master, "medical", "mri-scan").unwrap();

    // Grant vendor access
    let vendor_key = generate_vendor_key(&chunk_key, "hospital-radiology", 1700000000).unwrap();
    assert!(!vendor_key.is_expired(1699000000));
    assert!(vendor_key.is_expired(1700000001));
}

#[test]
fn test_category_isolation() {
    let seed = BiometricSeed::from_bytes([55u8; 32]).unwrap();
    let master = MasterKey::derive(&seed).unwrap();

    let (_, medical_key) = KeyHierarchy::derive(&master, "medical", "record-1").unwrap();
    let (_, financial_key) = KeyHierarchy::derive(&master, "financial", "record-1").unwrap();

    // Encrypt with medical key
    let data = b"sensitive data";
    let encrypted = encrypt_chunk(&medical_key, data).unwrap();

    // Cannot decrypt with financial key
    assert!(decrypt_chunk(&financial_key, &encrypted).is_err());

    // Can decrypt with medical key
    let decrypted = decrypt_chunk(&medical_key, &encrypted).unwrap();
    assert_eq!(decrypted, data);
}
