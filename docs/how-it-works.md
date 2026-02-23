# How Krypt Works

## Overview

Krypt is a decentralized personal data vault that uses biometric-derived encryption keys and blockchain-based access control to give users full ownership of their data.

## Key Concepts

### 1. Biometric Key Derivation

```
Biometric Template → Fuzzy Extractor → Stable Seed → HKDF → Master Key
```

- The user's biometric (fingerprint, face) is captured by the device's secure enclave
- A fuzzy extractor produces a deterministic seed from the noisy biometric input
- HKDF-SHA256 derives a 256-bit master key from the seed
- No biometric data ever leaves the device

### 2. Key Hierarchy

```
Master Key
├── Category Key ("medical")
│   ├── Chunk Key ("blood-test-2024")
│   ├── Chunk Key ("mri-scan-2024")
│   └── ...
├── Category Key ("financial")
│   ├── Chunk Key ("tax-return-2023")
│   └── ...
└── ...
```

Each level uses HKDF with unique info strings for domain separation. This enables:
- **Granular access**: Share a single chunk without exposing other data
- **Category isolation**: Compromise of one category doesn't affect others
- **Deterministic re-derivation**: Keys can always be re-derived from the biometric

### 3. Chunk Encryption

Data is split into chunks, each encrypted with AES-256-GCM using its derived chunk key:
- Random 96-bit nonce per encryption
- Authenticated encryption prevents tampering
- Encrypted chunks are stored on decentralized storage (IPFS/Filecoin)

### 4. On-Chain Registry

Smart contracts on Ethereum/L2 track:
- **VaultRegistry**: Which vaults exist and their chunk pointers
- **AccessControl**: Who has access to what, with time-based expiry
- **VendorRegistry**: Approved vendors who can request access

### 5. Vendor Access Flow

```
1. Vendor requests access to a chunk (off-chain)
2. User approves and grants time-limited access (on-chain)
3. User derives a vendor-specific key and shares it (encrypted to vendor's public key)
4. Vendor decrypts the chunk using the vendor key
5. Access automatically expires at the specified time
6. All access grants/revocations are logged on-chain for audit
```

### 6. Security Properties

- **Zero-knowledge**: The platform never sees plaintext data
- **User sovereignty**: Only the user's biometric can derive the master key
- **Forward secrecy**: Each chunk has a unique key; compromising one doesn't expose others
- **Auditability**: All access is logged immutably on-chain
- **Time-bounded**: Vendor access automatically expires
