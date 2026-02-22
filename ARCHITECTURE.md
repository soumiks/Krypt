# VaultSelf — Architecture Document

> **Biometric-Secured, Blockchain-Anchored Personal Data Sovereignty**

**Version:** 0.1.0-draft
**Status:** Pre-implementation Architecture Proposal
**License:** Apache 2.0 (see §10)

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Data Model](#2-data-model)
3. [Cryptographic Architecture](#3-cryptographic-architecture)
4. [Blockchain Layer](#4-blockchain-layer)
5. [Access Control & Key Management](#5-access-control--key-management)
6. [Biometric Considerations](#6-biometric-considerations)
7. [System Components](#7-system-components)
8. [Security Analysis](#8-security-analysis)
9. [Tech Stack Recommendation](#9-tech-stack-recommendation)
10. [Open Source Strategy](#10-open-source-strategy)
11. [MVP Scope](#11-mvp-scope)
12. [Architecture Diagrams](#12-architecture-diagrams)

---

## 1. System Overview

### Project Name: **VaultSelf**

Alternatives considered: BioVault, ChunkChain, SelfShard, IdentityForge. We chose **VaultSelf** because it's memorable, domain-available-friendly, communicates the core value (a vault, controlled by the self), and works well as a CLI/library name (`vaultself`, `@vaultself/sdk`).

### Elevator Pitch

VaultSelf is an open-source personal data vault that breaks your private information into encrypted chunks, anchored to a public blockchain. Each chunk is encrypted with keys derived from your biometrics — your body is literally the key. When you need to share data (medical records with a doctor, your address with a courier), you generate a time-limited, chunk-specific decryption capability that expires automatically. No central server ever holds your data. No company can be hacked to leak it. You own it, you control it, you revoke it.

### Design Principles

| Principle | Meaning |
|---|---|
| **Privacy-first** | Raw data is never visible to anyone except the user and explicitly authorized parties. The system is designed so that even the developers cannot access user data. |
| **User sovereignty** | The user is the sole root of trust. No admin key, no backdoor, no "forgot password" flow that bypasses the user. |
| **Zero-knowledge where possible** | Prefer proving properties about data (age > 21, address in ZIP code range) over revealing the data itself. |
| **Minimal trust surface** | No backend servers in the critical path. Smart contracts and client-side crypto only. Vendors get the minimum data for the minimum time. |
| **Offline-capable** | Core operations (biometric unlock, viewing own data) work without network. Sharing requires network only to publish the grant. |
| **Auditable** | Every access grant and revocation is recorded on-chain. Users have a complete, tamper-proof log of who accessed what and when. |

### Threat Model

**We protect against:**

| Threat | Description |
|---|---|
| **Centralized breach** | There is no central database to breach. Encrypted chunks on IPFS/Arweave are useless without user-derived keys. |
| **Vendor over-collection** | Vendors get time-limited access to specific chunks only. They cannot pivot to unrelated data. |
| **Government compulsion** | No single entity holds all keys. A subpoena to the storage layer yields only ciphertext. |
| **Stolen device** | Device key alone is insufficient; biometric + device key are required. Remote wipe of device key material is supported. |
| **Biometric spoofing** | Liveness detection + on-device secure enclave processing. Biometric templates never leave the device. |
| **Insider threat** | No "admin" role exists in the protocol. Smart contracts are immutable once deployed. |

**We explicitly do NOT protect against:**

- A user voluntarily exporting and sharing their own decrypted data (you can always screenshot your own records)
- Nation-state attacks that compromise the user's physical device AND biometrics simultaneously (rubber-hose cryptanalysis)
- Bugs in the smart contracts (mitigated by audits, not by architecture)
- A vendor who screenshots data during their valid access window (mitigated by audit trail and legal agreements, not cryptography)

---

## 2. Data Model

### Chunk Categories

User data is organized into **chunk categories**, each representing a logical domain:

```
Vault (per user)
├── identity/          # Legal name, DOB, nationality, government IDs
│   ├── identity.core          # Name, DOB, photo
│   ├── identity.passport      # Passport number, expiry
│   ├── identity.drivers       # Driver's license
│   └── identity.ssn           # Social security / national ID
├── medical/           # Health records
│   ├── medical.summary        # Allergies, blood type, conditions
│   ├── medical.records[]      # Individual visit records
│   ├── medical.prescriptions[]
│   └── medical.imaging[]      # References to large files
├── financial/         # Bank accounts, tax info
│   ├── financial.banking[]
│   ├── financial.tax[]
│   └── financial.credit
├── address/           # Physical and mailing addresses
│   ├── address.primary
│   ├── address.mailing
│   └── address.history[]
├── credentials/       # Logins, certificates, diplomas
│   ├── credentials.education[]
│   ├── credentials.professional[]
│   └── credentials.certificates[]
└── custom/            # User-defined chunks
    └── custom.*
```

### Chunk Schema

Every chunk follows a uniform envelope:

```json
{
  "chunkId": "sha256(vaultId + category + index + version)",
  "vaultId": "0xabc...def",
  "category": "medical.summary",
  "version": 3,
  "createdAt": 1708632000,
  "updatedAt": 1708718400,
  "contentHash": "sha256(plaintext)",
  "encryptedPayload": "<base64 ciphertext>",
  "encryptionMeta": {
    "algorithm": "AES-256-GCM",
    "iv": "<base64>",
    "chunkKeyId": "sha256(chunk_key_public_component)"
  },
  "storagePointer": {
    "type": "arweave",
    "txId": "ar://xyz..."
  },
  "zkDisclosures": [
    {
      "property": "age",
      "circuit": "gte",
      "publicInput": 21,
      "proofType": "groth16"
    }
  ],
  "signature": "<user's vault signature over this metadata>"
}
```

**On-chain** (stored in the Vault smart contract): `chunkId`, `contentHash`, `storagePointer`, `version`, `updatedAt`, `encryptionMeta.chunkKeyId`

**Off-chain** (stored on Arweave/IPFS): The full envelope including `encryptedPayload`

### Storage Size Analysis

| Data | Typical Size | Storage |
|---|---|---|
| Chunk metadata (on-chain) | ~200 bytes | On-chain (calldata) |
| Text chunk (name, address) | 0.1–2 KB encrypted | Off-chain |
| Medical record | 1–50 KB | Off-chain |
| Medical imaging | 1–500 MB | Off-chain (Arweave) |
| Access grant record | ~150 bytes | On-chain |

**Decision:** All encrypted payloads go off-chain. On-chain stores only metadata, pointers, and access control state. This keeps gas costs manageable and avoids blockchain bloat.

---

## 3. Cryptographic Architecture

This is the heart of VaultSelf. Get this wrong, and nothing else matters.

### 3.1 Biometric Key Derivation

**The fundamental problem:** Biometrics are noisy. A fingerprint scan produces slightly different data each time. But cryptographic keys must be exact — flip one bit and decryption fails.

**Solution: Fuzzy Extractors**

We use a fuzzy extractor construction based on the work of Dodis et al. (2004), specifically a **secure sketch + strong extractor** combination:

```
┌─────────────────────────────────────────────────┐
│              ENROLLMENT (one-time)               │
│                                                  │
│  Raw Biometric ──► Feature Extraction ──► w      │
│                                            │     │
│                    ┌───────────────────────┐│     │
│                    │   Secure Sketch       ││     │
│                    │   SS(w) = s           │◄     │
│                    └───────────────────────┘│     │
│                                            │     │
│  w ──► Strong Extractor(w, seed) ──► R     │     │
│        (HKDF-SHA256)                 │     │     │
│                                      │     │     │
│  Store: (s, seed) in device secure   │     │     │
│         enclave. NEVER export.       │     │     │
│                                      │     │     │
│  R = Master Biometric Key            │     │     │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│              RECONSTRUCTION (each use)           │
│                                                  │
│  Raw Biometric ──► Feature Extraction ──► w'     │
│                                            │     │
│  Recover w from (w', s) via SS.Rec         │     │
│  (works if Hamming distance(w, w') < t)    │     │
│                                            │     │
│  w ──► Strong Extractor(w, seed) ──► R     │     │
│                                            │     │
│  R = same Master Biometric Key             │     │
└─────────────────────────────────────────────────┘
```

**Specifics:**

- **Feature extraction:** Platform-native (Apple FaceID / Touch ID via Secure Enclave, Android BiometricPrompt via StrongBox/TEE). We never access raw biometric data — we use the platform's key-release mechanism gated by biometric auth.
- **Practical reality:** On modern mobile devices, we don't implement fuzzy extractors from scratch. Instead:
  1. A 256-bit **device master key** is generated at enrollment and stored in the Secure Enclave / StrongBox
  2. This key is **gated by biometric authentication** — the OS only releases it after successful biometric match
  3. The released key is combined with a user PIN via HKDF to produce the **Master Key**

This is the pragmatic approach. Pure biometric-to-key derivation (fuzzy extractors on raw templates) is academically interesting but fragile in production. Every major secure system (Apple, Google, Signal) uses biometric-gated key release instead.

```
Master Key = HKDF-SHA256(
    ikm = device_master_key,       // released by biometric auth
    salt = user_pin_hash,          // SHA256(PIN)
    info = "vaultself-master-v1"
)
```

**ISO/IEC 24745 compliance:**
- Biometric templates are processed only within the device's secure hardware
- No biometric data is stored in application memory
- The secure sketch (if used for backup/recovery) is encrypted before storage
- Template protection is achieved by never exposing templates — only derived keys

### 3.2 Key Hierarchy

```
Master Key (MK)
│
├──► HKDF(MK, "vault-signing") ──► Vault Signing Key (Ed25519)
│    Used to sign on-chain transactions
│
├──► HKDF(MK, "chunk-root") ──► Chunk Root Key (CRK)
│    │
│    ├──► HKDF(CRK, "identity.core") ──► Chunk Key for identity.core
│    ├──► HKDF(CRK, "medical.summary") ──► Chunk Key for medical.summary
│    ├──► HKDF(CRK, "address.primary") ──► Chunk Key for address.primary
│    └──► ... (deterministic per chunk category)
│
└──► HKDF(MK, "delegation-root") ──► Delegation Root Key (DRK)
     Used to derive time-limited vendor keys
```

Each **Chunk Key** is an AES-256-GCM symmetric key. Deterministic derivation means we never need to store chunk keys — they're re-derived from the Master Key on demand.

### 3.3 Per-Chunk Encryption

```
Encrypt(chunk_plaintext, chunk_key):
    iv = random(96 bits)
    (ciphertext, tag) = AES-256-GCM(chunk_key, iv, chunk_plaintext, aad=chunkId)
    return (iv, ciphertext, tag)
```

The `chunkId` is used as Additional Authenticated Data (AAD), binding the ciphertext to its metadata and preventing chunk-swapping attacks.

### 3.4 Time-Limited Vendor Access Keys

**This is the most novel part of the architecture.** We use a combination of **proxy re-encryption** and **on-chain time enforcement**.

#### Approach: Hybrid Re-Encryption + Smart Contract Enforcement

When a user wants to share `medical.summary` with Dr. Smith for 48 hours:

**Step 1: Generate a re-encryption key**

```
// User side
vendor_pubkey = Dr. Smith's registered public key (X25519)
chunk_key = HKDF(CRK, "medical.summary")

// Create an ephemeral shared secret
ephemeral_key = X25519_keygen()
shared_secret = X25519(ephemeral_key.private, vendor_pubkey)

// Encrypt the chunk key to the vendor
encrypted_chunk_key = AES-256-GCM(
    key = shared_secret,
    plaintext = chunk_key,
    aad = grant_id
)

grant = {
    grantId: random(256 bits),
    chunkId: "sha256(...medical.summary...)",
    vendorAddress: "0xDrSmith...",
    encryptedChunkKey: encrypted_chunk_key,
    ephemeralPubkey: ephemeral_key.public,
    expiresAt: now() + 48h,
    createdAt: now()
}
```

**Step 2: Publish on-chain**

The `grant` (minus `encryptedChunkKey` which goes to the vendor via encrypted channel) is recorded on-chain. The smart contract enforces:
- The grant is only valid between `createdAt` and `expiresAt`
- The user can revoke at any time by calling `revokeGrant(grantId)`
- The vendor must prove their identity (signature) to query grant status

**Step 3: Vendor decryption**

```
// Vendor side
shared_secret = X25519(vendor_private_key, ephemeral_pubkey)
chunk_key = AES-256-GCM-Decrypt(shared_secret, encrypted_chunk_key, aad=grant_id)

// Check grant validity on-chain before decrypting
assert(VaultContract.isGrantValid(grantId) == true)

// Fetch encrypted chunk from Arweave
encrypted_chunk = fetch(storagePointer)
plaintext = AES-256-GCM-Decrypt(chunk_key, encrypted_chunk)
```

**Time enforcement is dual-layer:**

1. **Smart contract layer:** The `isGrantValid()` function returns `false` after `expiresAt`. Well-behaved vendors (using VaultSelf SDK) check this before decryption.
2. **Cryptographic layer (optional, for high-security chunks):** We can use **time-lock puzzles** (Rivest, Shamir, Wagner 1996) or **witness encryption** against a blockchain timestamp oracle, but this adds significant complexity. For MVP, smart contract enforcement is sufficient because:
   - A vendor who extracts the chunk key can technically decrypt forever
   - BUT the audit trail shows their grant expired, creating legal/reputational liability
   - AND the user can re-encrypt their chunk with a new key (key rotation), invalidating the old chunk key

**Key insight:** Perfect cryptographic time-limiting is an unsolved problem. If a vendor has the key and the ciphertext, they can decrypt at any time. Our approach bounds this through:
- Legal liability via on-chain audit trail
- Key rotation to invalidate old keys
- Vendor reputation system

### 3.5 Zero-Knowledge Selective Disclosure

For cases where the vendor doesn't need the data itself but needs to verify a property:

**Example:** "Prove the user is over 21 without revealing their birthdate."

We use **Groth16 zk-SNARKs** (via circom/snarkjs):

```
Circuit: AgeGte

Public inputs:  threshold (21), current_date, chunk_commitment
Private inputs: birthdate, chunk_key, chunk_nonce

Constraints:
  1. age = (current_date - birthdate) / 365.25
  2. age >= threshold
  3. commitment = Poseidon(birthdate, chunk_key, chunk_nonce)
  4. commitment == chunk_commitment  // proves the birthdate is from a real chunk
```

The user generates the proof on-device and sends it to the vendor. The vendor verifies the proof against the on-chain chunk commitment without ever seeing the birthdate.

**Pre-built circuits for MVP:**
- `AgeGte` — age ≥ threshold
- `AddressInRegion` — ZIP code within a set
- `CredentialValid` — has a credential of type X that hasn't expired
- `IncomeAbove` — income ≥ threshold (for financial verification)

---

## 4. Blockchain Layer

### Chain Selection: **Base (Ethereum L2)**

**Why Base:**

| Factor | Base | Polygon PoS | Solana | Arbitrum |
|---|---|---|---|---|
| Cost per tx | ~$0.001 | ~$0.01 | ~$0.0001 | ~$0.003 |
| Finality | ~2 sec | ~2 sec | ~0.4 sec | ~0.3 sec |
| EVM compatible | ✅ | ✅ | ❌ | ✅ |
| Ecosystem/tooling | Excellent | Excellent | Good | Excellent |
| Decentralization | Medium | Medium | Medium | Medium |
| Long-term viability | High (Coinbase) | High | High | High |
| Solidity support | ✅ | ✅ | ❌ (Rust) | ✅ |

**Decision:** Base is the primary target. It offers the best balance of low cost, fast finality, EVM compatibility, and growing ecosystem. Solidity tooling is mature. We design contracts to be EVM-portable so migration to Arbitrum or mainnet Ethereum is straightforward.

**Secondary consideration:** Support abstract account (ERC-4337) for gasless UX — users shouldn't need ETH to use VaultSelf.

### On-Chain vs Off-Chain

```
┌──────────────────────────────────────────────┐
│                  ON-CHAIN (Base)              │
│                                              │
│  • Vault registry (user → vault address)     │
│  • Chunk metadata (chunkId, contentHash,     │
│    storagePointer, version)                  │
│  • Access grants (grantId, vendor, chunk,    │
│    expiry, status)                           │
│  • Vendor registry (address → verification)  │
│  • Audit log (implicit from tx history)      │
│  • ZK proof verification results             │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│              OFF-CHAIN (Arweave)              │
│                                              │
│  • Encrypted chunk payloads                  │
│  • Encrypted large files (medical imaging)   │
│  • ZK circuit artifacts                      │
└──────────────────────────────────────────────┘
```

**Why Arweave over IPFS/Filecoin:**
- **Permanent storage** — pay once, stored forever. No pinning required.
- **No garbage collection** — IPFS data disappears if not pinned.
- **Simpler model** — no deals, no renewal, no retrieval markets.
- **Cost:** ~$0.50/MB at current rates, acceptable for text/small files.
- **For large files (>10MB):** Use Arweave's Bundlr network for efficient uploads.

### Smart Contract Architecture

```solidity
// Three core contracts:

VaultRegistry.sol
├── createVault(userPubkey) → vaultAddress
├── getVault(userAddress) → vaultAddress
└── vaultExists(userAddress) → bool

VaultContract.sol (one per user, deployed via factory/proxy)
├── // Chunk Management
├── registerChunk(chunkId, contentHash, storagePointer, encMeta)
├── updateChunk(chunkId, newContentHash, newStoragePointer, newVersion)
├── getChunkMeta(chunkId) → ChunkMeta
├── listChunks() → chunkId[]
├── // Access Control
├── grantAccess(grantId, vendorAddr, chunkId, expiresAt, encKeyPointer)
├── revokeGrant(grantId)
├── isGrantValid(grantId) → bool
├── getGrant(grantId) → Grant
├── listGrants(chunkId) → Grant[]
├── listGrantsByVendor(vendorAddr) → Grant[]
├── // Recovery
├── setRecoveryAddress(addr)
└── initiateRecovery() // 7-day timelock

VendorRegistry.sol
├── registerVendor(name, pubkey, category, verificationProof)
├── getVendor(address) → VendorInfo
├── isVerified(address) → bool
└── reportVendor(address, reason) // reputation system
```

**Gas Cost Estimates (Base L2):**

| Operation | Estimated Gas | Cost at 0.01 gwei |
|---|---|---|
| Create vault | ~200,000 | ~$0.005 |
| Register chunk | ~80,000 | ~$0.002 |
| Grant access | ~100,000 | ~$0.003 |
| Revoke access | ~50,000 | ~$0.001 |
| Verify ZK proof | ~300,000 | ~$0.008 |

**Optimizations:**
- Use ERC-4337 account abstraction so users pay in stablecoins or the app sponsors gas
- Use minimal proxy pattern (EIP-1167) for vault deployment — saves ~90% gas vs full deployment
- Batch chunk registrations using multicall
- Store only hashes on-chain, full metadata off-chain with on-chain content-hash verification

---

## 5. Access Control & Key Management

### 5.1 Granting Access — Step by Step

```
User (Mobile App)                Smart Contract (Base)           Vendor (SDK)
      │                                  │                          │
      │  1. User selects chunk           │                          │
      │     and vendor to share with     │                          │
      │                                  │                          │
      │  2. Biometric auth ──► unlock MK │                          │
      │     Derive chunk_key from MK     │                          │
      │                                  │                          │
      │  3. Fetch vendor's pubkey        │                          │
      │     from VendorRegistry ────────►│──── getVendor() ────────►│
      │                                  │◄─── VendorInfo ──────────│
      │◄─────────────────────────────────│                          │
      │                                  │                          │
      │  4. Generate ephemeral keypair   │                          │
      │     Compute shared secret        │                          │
      │     Encrypt chunk_key            │                          │
      │                                  │                          │
      │  5. Call grantAccess() ─────────►│                          │
      │     (grantId, vendor, chunk,     │  6. Event emitted:       │
      │      expiry)                     │     GrantCreated ────────►│
      │                                  │                          │
      │  7. Send encrypted chunk key     │                          │
      │     + ephemeral pubkey to vendor ──────── (encrypted) ─────►│
      │     via vendor's API endpoint    │                          │
      │                                  │                          │
      │                                  │  8. Vendor checks grant  │
      │                                  │◄──── isGrantValid() ─────│
      │                                  │──── true ───────────────►│
      │                                  │                          │
      │                                  │  9. Vendor fetches       │
      │                                  │     encrypted chunk      │
      │                                  │     from Arweave         │
      │                                  │                          │
      │                                  │  10. Vendor decrypts     │
      │                                  │      chunk_key, then     │
      │                                  │      chunk payload       │
```

### 5.2 Time-Limited Key Generation

The grant has a hard `expiresAt` timestamp. The VaultSelf Vendor SDK **must** call `isGrantValid(grantId)` before every decryption attempt. The SDK is designed to:
1. Cache the decrypted data only in memory, never on disk
2. Re-verify grant validity every 5 minutes
3. Wipe cached data when grant expires or is revoked
4. Log every access attempt

**Honest vendor enforcement:** The SDK is open-source and auditable. Vendors who modify the SDK to bypass checks are:
- Detectable (they won't call `isGrantValid`, missing from on-chain logs)
- Legally liable (the on-chain grant record proves expiry)
- Reputation-damaged (users can see vendor behavior on-chain)

### 5.3 Revocation Before Expiry

```solidity
function revokeGrant(bytes32 grantId) external onlyOwner {
    Grant storage g = grants[grantId];
    require(g.status == GrantStatus.Active, "not active");
    g.status = GrantStatus.Revoked;
    g.revokedAt = block.timestamp;
    emit GrantRevoked(grantId, msg.sender, block.timestamp);
}
```

After revocation, `isGrantValid()` returns `false`. The vendor SDK stops serving data.

**For extra security:** After revocation, the user can **rotate the chunk key**:
1. Derive a new chunk key: `HKDF(CRK, "medical.summary" || version+1)`
2. Re-encrypt the chunk with the new key
3. Upload new ciphertext to Arweave
4. Update on-chain metadata with new content hash and storage pointer

This invalidates any cached chunk keys the vendor might have retained.

### 5.4 Vendor Verification & Trust Levels

```
Trust Level 0: Unverified   — Any Ethereum address. User sees warning.
Trust Level 1: Self-declared — Vendor registered name/domain. Basic checks.
Trust Level 2: Domain-verified — Vendor proved domain ownership (DNS TXT record).
Trust Level 3: KYB-verified  — Vendor passed Know Your Business (third-party attestation).
```

Trust levels are stored in `VendorRegistry.sol`. Users can filter by trust level. The app shows clear warnings for low-trust vendors.

### 5.5 Audit Trail

Every `grantAccess`, `revokeGrant`, and vendor `isGrantValid` check is an on-chain transaction or event. The user's app can reconstruct a complete history:

```
📋 Access History for medical.summary
─────────────────────────────────────
2026-02-15 09:00  GRANT   Dr. Smith (verified)    expires: 2026-02-17 09:00
2026-02-15 09:05  ACCESS  Dr. Smith               ✓ valid
2026-02-15 14:30  ACCESS  Dr. Smith               ✓ valid
2026-02-16 10:00  REVOKE  by you                  reason: "visit complete"
2026-02-20 08:00  GRANT   LabCorp (verified)       expires: 2026-02-21 08:00
2026-02-21 08:00  EXPIRED LabCorp                  auto-expired
```

### 5.6 Emergency Access & Recovery

**Problem:** What if the user's biometrics change (injury, aging) or their device is lost?

**Social recovery (inspired by Vitalik's design):**
1. At setup, user designates 3-of-5 **guardians** (trusted friends/family, each identified by Ethereum address)
2. Guardian addresses are stored in the Vault contract
3. Recovery requires 3 of 5 guardians to sign a recovery transaction
4. Recovery has a **7-day timelock** — the original owner can cancel within 7 days (prevents malicious recovery)
5. After recovery, a new device + biometric enrollment produces a new Master Key
6. All chunks must be re-encrypted with new keys (automated by the app)

**Backup key (optional):**
- User can generate a 24-word BIP39 mnemonic as a cold backup
- This mnemonic derives an independent Master Key
- Stored offline (paper, steel plate) — classic crypto wallet backup
- Can be used to recover if social recovery also fails

---

## 6. Biometric Considerations

### 6.1 Supported Biometrics

| Biometric | Priority | Notes |
|---|---|---|
| **Fingerprint** | P0 (MVP) | Most widely available. Touch ID / Android fingerprint. |
| **Face** | P0 (MVP) | Face ID (iOS), face unlock (Android). |
| **Iris** | P2 (future) | Limited device support. Samsung Galaxy only. |
| **Voice** | P3 (future) | Least stable. Environmental noise issues. |

**MVP supports fingerprint and face** — whichever the device offers. Both go through the same platform API (biometric-gated key release).

### 6.2 On-Device Processing

**Absolute rule: Raw biometric data never leaves the Secure Enclave / TEE.**

```
┌─────────────────────────────────────────┐
│           Mobile Device                  │
│                                          │
│  ┌──────────────────────────────────┐   │
│  │     Secure Enclave / StrongBox    │   │
│  │                                    │   │
│  │  • Biometric template storage     │   │
│  │  • Biometric matching             │   │
│  │  • Device master key storage      │   │
│  │  • Key release on auth success    │   │
│  │                                    │   │
│  │  ══════ HARDWARE BOUNDARY ══════  │   │
│  └──────────────────────────────────┘   │
│         │                                │
│         │ key (on auth success)          │
│         ▼                                │
│  ┌──────────────────────────────────┐   │
│  │     VaultSelf App                 │   │
│  │                                    │   │
│  │  • Receives device_master_key     │   │
│  │  • Derives Master Key via HKDF    │   │
│  │  • Derives chunk keys             │   │
│  │  • Encrypts / decrypts chunks     │   │
│  │  • Signs transactions             │   │
│  │                                    │   │
│  │  Keys in memory only, wiped       │   │
│  │  after use (zeroize)              │   │
│  └──────────────────────────────────┘   │
│                                          │
└─────────────────────────────────────────┘
```

### 6.3 Biometric Stability

- **Fingerprint:** Very stable (decades). Minor cuts heal. Major injury → use backup biometric or recovery.
- **Face:** Moderately stable. Aging, weight changes, facial hair can affect matching. Platform APIs handle gradual changes via template updates.
- **Recommendation:** Enroll **at least two biometric types** when available. Either can unlock the device master key.

### 6.4 Multi-Factor Design

```
Authentication = Biometric + Device + (optional) PIN

Biometric: Proves "something you are"
Device:    Proves "something you have" (device_master_key in secure enclave)
PIN:       Proves "something you know" (mixed into HKDF)
```

All three factors contribute to the Master Key derivation. If biometric fails (temporary injury), PIN + device serves as fallback (configurable by user).

### 6.5 Liveness Detection

- Rely on platform liveness detection (Apple/Google invest billions in this)
- iOS: TrueDepth camera (infrared dot projector) — resistant to photos/masks
- Android: Require `BIOMETRIC_STRONG` classification (Class 3 biometrics)
- Additional: Challenge-response liveness (random head turn / blink sequence) for high-security operations

---

## 7. System Components

```
┌──────────────────────────────────────────────────────────────────┐
│                        USER LAYER                                │
│                                                                  │
│  ┌─────────────────┐    ┌─────────────────┐                     │
│  │   Mobile App     │    │   Web Dashboard  │                    │
│  │   (React Native) │    │   (Next.js)      │  ◄── view-only,   │
│  │                  │    │                   │      no key ops   │
│  │  • Biometric     │    │  • View audit log │                   │
│  │  • Key mgmt      │    │  • Manage grants  │                   │
│  │  • Chunk encrypt  │    │  • Browse vendors │                   │
│  │  • Grant creation │    │                   │                   │
│  └────────┬─────────┘    └────────┬──────────┘                   │
│           │                       │                              │
└───────────┼───────────────────────┼──────────────────────────────┘
            │                       │
            ▼                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                      PROTOCOL LAYER                              │
│                                                                  │
│  ┌─────────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  Smart Contracts │  │   Arweave    │  │   Relay Service    │  │
│  │  (Base L2)       │  │   (Storage)  │  │   (optional)       │  │
│  │                  │  │              │  │                    │  │
│  │  • VaultRegistry │  │  • Encrypted │  │  • Forwards enc'd  │  │
│  │  • VaultContract │  │    chunks    │  │    chunk keys to   │  │
│  │  • VendorRegistry│  │  • ZK proofs │  │    vendors         │  │
│  │  • ZK Verifier   │  │              │  │  • No access to    │  │
│  │                  │  │              │  │    plaintext        │  │
│  └──────────────────┘  └──────────────┘  └────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                       VENDOR LAYER                               │
│                                                                  │
│  ┌─────────────────────────────────────┐                         │
│  │   Vendor SDK (@vaultself/vendor-sdk) │                        │
│  │                                      │                        │
│  │  • Listen for grant events           │                        │
│  │  • Fetch + decrypt chunks            │                        │
│  │  • Verify grant validity             │                        │
│  │  • Auto-wipe on expiry               │                        │
│  │  • TypeScript + Rust implementations │                        │
│  └─────────────────────────────────────┘                         │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Component Details

**Mobile App (React Native)**
- Primary interface for all key-holding operations
- Biometric auth via `react-native-biometrics` (wraps platform APIs)
- Crypto operations via embedded Rust library (compiled to native via FFI)
- Ethers.js for blockchain interaction
- WalletConnect for dApp compatibility

**Relay Service (Optional)**
- Thin, stateless service that forwards encrypted chunk keys from user to vendor
- Has **zero access** to plaintext — only passes opaque encrypted blobs
- Can be replaced by direct P2P communication (WebRTC/libp2p) in future
- Exists only because vendors need a stable endpoint to receive grants

**Web Dashboard (Next.js)**
- View-only companion to the mobile app
- Connected via WalletConnect — mobile app signs all transactions
- Shows audit logs, active grants, chunk inventory
- No key material ever touches the browser

---

## 8. Security Analysis

### 8.1 Attack Vectors & Mitigations

| Attack | Impact | Mitigation |
|---|---|---|
| **Stolen device** | Attacker has device_master_key in enclave | Biometric required to release key. PIN adds second factor. Remote wipe capability. Enclave has brute-force lockout (10 attempts). |
| **Biometric spoofing** | Attacker bypasses biometric to release key | Platform liveness detection (TrueDepth / Class 3). Challenge-response for high-security ops. |
| **Blockchain front-running** | Attacker sees grant tx in mempool and races to use it | Grant creation doesn't contain the encrypted chunk key (sent via relay). Front-running the tx gains nothing. |
| **Vendor collusion** | Multiple vendors combine their chunks to build profile | Each chunk encrypted with different key. Vendors only get keys for their granted chunks. Combining grants from different vendors requires compromising the user's auth flow. |
| **Arweave data exposure** | All encrypted chunks are publicly visible | All payloads are AES-256-GCM encrypted. Without keys, ciphertext is indistinguishable from random. Chunk IDs are hashes, not human-readable. |
| **Quantum computing** | Shor's algorithm breaks ECC/RSA | AES-256 is quantum-resistant. Signing can migrate to post-quantum (CRYSTALS-Dilithium). X25519 key exchange can migrate to CRYSTALS-Kyber. Plan migration path but don't pre-optimize. |
| **Compromised relay** | Attacker intercepts encrypted chunk keys in transit | Chunk keys are encrypted to vendor's public key. Relay sees only ciphertext. Compromise yields nothing. |
| **Smart contract bug** | Attacker bypasses access control | Formal verification of critical functions. Multiple audits. Upgradeable proxy for fixes. Timelock on upgrades (48h). |

### 8.2 Comparison with Existing SSI Solutions

| Feature | VaultSelf | W3C DID/VC | Microsoft ION | Sovrin | Ceramic |
|---|---|---|---|---|---|
| Biometric key derivation | ✅ Core feature | ❌ | ❌ | ❌ | ❌ |
| Time-limited sharing | ✅ Native | ❌ Manual | ❌ | ❌ | ❌ |
| On-chain audit trail | ✅ | ❌ | Partial | ✅ | ❌ |
| ZK selective disclosure | ✅ | Partial (BBS+) | ❌ | Partial | ❌ |
| Arbitrary data storage | ✅ Any chunk | ❌ Credentials only | ❌ IDs only | ❌ Credentials | ✅ |
| Permanent storage | ✅ Arweave | ❌ | ❌ | ❌ | ✅ IPFS |
| No central authority | ✅ | Partial (issuers) | Partial (Microsoft) | ❌ (Sovrin Foundation) | ✅ |

**How VaultSelf differs:**
1. **Not just credentials** — stores arbitrary personal data (medical records, documents), not just attestations
2. **Biometric-native** — the body is the key, not a seed phrase or password
3. **Time-limited sharing is a first-class primitive**, not an afterthought
4. **Complete audit trail** — every access is on-chain, visible to the user
5. **DID-compatible** — VaultSelf vaults can be wrapped as DIDs (`did:vaultself:<vault-address>`) for interoperability

---

## 9. Tech Stack Recommendation

### Languages & Frameworks

| Component | Technology | Rationale |
|---|---|---|
| **Crypto core** | Rust | Memory safety, no GC, excellent crypto ecosystem (ring, aes-gcm, x25519-dalek, arkworks for ZK) |
| **Mobile app** | React Native | Cross-platform, large community, good native module support. Rust crypto via JSI bridge. |
| **Smart contracts** | Solidity | Mature tooling, wide audit talent pool, EVM-portable |
| **Web dashboard** | Next.js + TypeScript | SSR, good DX, ethers.js integration |
| **Vendor SDK** | TypeScript (primary), Rust (secondary) | TypeScript for web/Node vendors, Rust for embedded/high-security vendors |
| **ZK circuits** | Circom 2.0 + snarkjs | Most mature ZK toolchain, Groth16 for small proofs, Plonk for flexibility |

### Key Libraries

```
# Rust (crypto core)
aes-gcm = "0.10"            # AES-256-GCM encryption
x25519-dalek = "2.0"        # X25519 key exchange
ed25519-dalek = "2.0"       # Ed25519 signatures
hkdf = "0.12"               # HKDF key derivation
sha2 = "0.10"               # SHA-256
arkworks-rs                  # ZK proof generation
zeroize = "1.6"             # Secure memory wiping
uniffi = "0.25"             # Rust → mobile FFI

# JavaScript / TypeScript
ethers@6                     # Blockchain interaction
@noble/curves                # JS crypto primitives (backup)
snarkjs                      # ZK proof verification
react-native-biometrics      # Biometric API
@react-native-community/async-storage  # Local encrypted storage

# Solidity
@openzeppelin/contracts@5    # Battle-tested contract primitives
ERC-4337                     # Account abstraction
```

### Testing & Audit Strategy

1. **Unit tests:** 100% coverage on all crypto functions (Rust `#[cfg(test)]`)
2. **Fuzz testing:** `cargo-fuzz` on all serialization/deserialization paths
3. **Smart contract tests:** Foundry (Forge) test suite + Slither static analysis
4. **Formal verification:** Certora or Halmos for critical access control invariants
5. **Integration tests:** E2E flow tests (create vault → upload chunk → grant → decrypt → revoke)
6. **Security audits:** Two independent audits before mainnet:
   - Crypto audit (Trail of Bits or NCC Group) — focus on key derivation, encryption, ZK circuits
   - Smart contract audit (OpenZeppelin or Spearbit) — focus on access control, upgrade safety
7. **Bug bounty:** Immunefi program, $50K–$250K rewards based on severity

---

## 10. Open Source Strategy

### License: **Apache 2.0**

**Why:**
- Permissive enough to encourage adoption (enterprises won't touch AGPL)
- Patent grant protects contributors and users
- Compatible with most other OSS licenses
- Used by Ethereum Foundation, Hyperledger, most blockchain projects
- MIT is simpler but lacks patent protection

### Repository Structure

```
github.com/vaultself/
├── vaultself-core/          # Rust crypto library
│   ├── src/
│   │   ├── keys/            # Key derivation, hierarchy
│   │   ├── encryption/      # AES-256-GCM, chunk encryption
│   │   ├── sharing/         # Key delegation, proxy re-encryption
│   │   └── zk/              # ZK proof generation
│   ├── Cargo.toml
│   └── README.md
│
├── vaultself-contracts/     # Solidity smart contracts
│   ├── src/
│   │   ├── VaultRegistry.sol
│   │   ├── VaultContract.sol
│   │   └── VendorRegistry.sol
│   ├── test/
│   ├── script/
│   └── foundry.toml
│
├── vaultself-app/           # React Native mobile app
│   ├── src/
│   ├── ios/
│   ├── android/
│   └── package.json
│
├── vaultself-vendor-sdk/    # TypeScript vendor SDK
│   ├── src/
│   └── package.json
│
├── vaultself-circuits/      # Circom ZK circuits
│   ├── circuits/
│   ├── test/
│   └── build/
│
├── vaultself-docs/          # Documentation site
│   ├── docs/
│   └── docusaurus.config.js
│
└── .github/                 # Shared CI/CD, issue templates
```

### Community Building

1. **Documentation-first:** Comprehensive docs from day one (Docusaurus site)
2. **Good first issues:** Label easy tasks for newcomers
3. **RFC process:** Major changes go through public RFC (GitHub Discussions)
4. **Discord server:** For real-time discussion
5. **Monthly dev calls:** Recorded and published
6. **Grants program:** Fund external contributors once treasury exists
7. **Developer advocacy:** Blog posts explaining the crypto, not just the product
8. **Interop focus:** W3C DID compatibility brings the SSI community

---

## 11. MVP Scope

### MVP: "Share Your Address Securely"

The simplest useful version: **A user stores their address and can share it time-limited with a delivery vendor.**

### MVP Feature Set

| Feature | Included | Notes |
|---|---|---|
| User registration + vault creation | ✅ | Biometric enrollment, vault contract deployment |
| Store address chunk | ✅ | Encrypt, upload to Arweave, register on-chain |
| View own data | ✅ | Biometric unlock, decrypt, display |
| Grant time-limited access | ✅ | Select vendor, set expiry, publish grant |
| Revoke access | ✅ | Cancel grant before expiry |
| Vendor SDK — fetch + decrypt | ✅ | TypeScript SDK, basic demo vendor app |
| Audit log | ✅ | View who accessed what, when |
| Multiple chunk types | ❌ | Post-MVP (medical, financial, etc.) |
| ZK proofs | ❌ | Post-MVP |
| Social recovery | ❌ | Post-MVP (use mnemonic backup for MVP) |
| Web dashboard | ❌ | Post-MVP |
| Vendor trust levels | Partial | Self-registration only, no KYB |

### Timeline (2-3 Developers)

```
Month 1:  Rust crypto core (key derivation, encryption, HKDF hierarchy)
          Solidity contracts (VaultRegistry, VaultContract basics)
          Foundry test suite

Month 2:  React Native app shell (biometric auth, vault creation)
          Arweave integration (upload/fetch encrypted chunks)
          Contract deployment to Base Sepolia testnet

Month 3:  Access grant flow (user → vendor)
          Vendor SDK (TypeScript)
          Demo vendor application

Month 4:  Revocation, audit log UI
          Integration testing, security hardening
          Mnemonic backup/recovery

Month 5:  Security audit (crypto review)
          Testnet beta with selected users
          Documentation site

Month 6:  Mainnet deployment (Base)
          Bug bounty launch
          Public beta
```

**Total: ~6 months to public beta** with 2-3 full-time developers.

---

## 12. Architecture Diagrams

### 12.1 User Registration & Vault Creation

```
User                          Device Enclave          Base L2              Arweave
 │                                 │                    │                    │
 │  1. Open app, start setup       │                    │                    │
 │──────────────────────────────►  │                    │                    │
 │                                 │                    │                    │
 │  2. Biometric enrollment        │                    │                    │
 │  (fingerprint / face scan) ───► │                    │                    │
 │                                 │                    │                    │
 │  3. Generate device_master_key  │                    │                    │
 │  Store in secure enclave  ◄──── │                    │                    │
 │                                 │                    │                    │
 │  4. Prompt for PIN              │                    │                    │
 │  MK = HKDF(device_key, pin)    │                    │                    │
 │                                 │                    │                    │
 │  5. Derive vault signing key    │                    │                    │
 │  (Ed25519 from MK)             │                    │                    │
 │                                 │                    │                    │
 │  6. Deploy vault contract ─────────────────────────► │                    │
 │     via VaultRegistry.createVault()                  │                    │
 │                                                      │                    │
 │  7. Vault address returned  ◄──────────────────────  │                    │
 │                                                      │                    │
 │  8. Generate mnemonic backup    │                    │                    │
 │     Display to user for         │                    │                    │
 │     offline storage             │                    │                    │
 │                                 │                    │                    │
 │  ✅ Setup complete              │                    │                    │
```

### 12.2 Data Upload & Chunking

```
User                          App (local)              Arweave             Base L2
 │                               │                       │                   │
 │  1. Enter address data        │                       │                   │
 │───────────────────────────►   │                       │                   │
 │                               │                       │                   │
 │  2. Biometric auth            │                       │                   │
 │   → unlock MK                 │                       │                   │
 │   → derive CRK                │                       │                   │
 │   → derive chunk_key          │                       │                   │
 │     ("address.primary")       │                       │                   │
 │                               │                       │                   │
 │                               │  3. Encrypt chunk     │                   │
 │                               │  AES-256-GCM(         │                   │
 │                               │    key=chunk_key,     │                   │
 │                               │    data=address_json, │                   │
 │                               │    aad=chunkId)       │                   │
 │                               │                       │                   │
 │                               │  4. Upload ──────────►│                   │
 │                               │                       │ store             │
 │                               │  5. txId ◄────────────│                   │
 │                               │                       │                   │
 │                               │  6. Register chunk ──────────────────────►│
 │                               │     (chunkId,                             │
 │                               │      contentHash,                         │
 │                               │      ar://txId,                           │
 │                               │      version=1)                           │
 │                               │                                           │
 │                               │  7. Confirmed ◄──────────────────────────│
 │                               │                       │                   │
 │  8. ✅ "Address saved"        │                       │                   │
 │◄──────────────────────────────│                       │                   │
```

### 12.3 Vendor Access Grant Flow

```
User App                     Relay                  Base L2           Vendor SDK
 │                             │                      │                   │
 │  1. Select "Share address   │                      │                   │
 │     with DeliveryCo for     │                      │                   │
 │     24 hours"               │                      │                   │
 │                             │                      │                   │
 │  2. Biometric auth → MK    │                      │                   │
 │     → chunk_key             │                      │                   │
 │                             │                      │                   │
 │  3. Fetch vendor pubkey ────────────────────────►  │                   │
 │  ◄──────────────────────────────────────────────   │                   │
 │                             │                      │                   │
 │  4. ephemeral = X25519()    │                      │                   │
 │     shared = ECDH(eph,      │                      │                   │
 │               vendor_pub)   │                      │                   │
 │     enc_key = AES(shared,   │                      │                   │
 │               chunk_key)    │                      │                   │
 │                             │                      │                   │
 │  5. grantAccess() tx ──────────────────────────►   │                   │
 │     (grantId, vendor,       │                      │                   │
 │      chunkId, expiry=24h)   │                      │                   │
 │                             │                      │  6. GrantCreated   │
 │                             │                      │     event ────────►│
 │                             │                      │                   │
 │  7. Send enc_key + eph_pub ►│──── forward ────────────────────────────►│
 │     (encrypted to vendor)   │                      │                   │
 │                             │                      │                   │
 │  ✅ "Shared with            │                      │                   │
 │     DeliveryCo for 24h"     │                      │                   │
```

### 12.4 Vendor Decryption Flow

```
Vendor SDK                   Base L2              Arweave
 │                             │                    │
 │  1. Receive enc_key +       │                    │
 │     eph_pub from relay      │                    │
 │                             │                    │
 │  2. shared = ECDH(          │                    │
 │     vendor_priv, eph_pub)   │                    │
 │                             │                    │
 │  3. chunk_key = AES_DEC(    │                    │
 │     shared, enc_key)        │                    │
 │                             │                    │
 │  4. isGrantValid(grantId) ─►│                    │
 │  ◄── true ──────────────────│                    │
 │                             │                    │
 │  5. getChunkMeta(chunkId) ─►│                    │
 │  ◄── {storagePtr, hash} ────│                    │
 │                             │                    │
 │  6. Fetch encrypted chunk ──────────────────────►│
 │  ◄── ciphertext ────────────────────────────────│
 │                             │                    │
 │  7. Verify contentHash      │                    │
 │     SHA256(ciphertext)      │                    │
 │     == on-chain hash        │                    │
 │                             │                    │
 │  8. plaintext = AES_DEC(    │                    │
 │     chunk_key, ciphertext,  │                    │
 │     aad=chunkId)            │                    │
 │                             │                    │
 │  9. ✅ Address data ready   │                    │
 │     (held in memory only,   │                    │
 │      wiped on expiry)       │                    │
```

### 12.5 Key Revocation Flow

```
User App                     Base L2              Vendor SDK
 │                             │                    │
 │  1. "Revoke DeliveryCo      │                    │
 │     access to address"      │                    │
 │                             │                    │
 │  2. Biometric auth          │                    │
 │                             │                    │
 │  3. revokeGrant(grantId) ──►│                    │
 │                             │  4. GrantRevoked    │
 │                             │     event ─────────►│
 │                             │                    │
 │  ◄── confirmed ─────────────│                    │  5. SDK receives
 │                             │                    │     revocation event
 │                             │                    │
 │  6. (Optional) Rotate key   │                    │  7. SDK wipes cached
 │     Re-encrypt chunk        │                    │     chunk_key and
 │     Update on-chain meta ──►│                    │     plaintext from
 │                             │                    │     memory
 │  ✅ "Access revoked"        │                    │
 │                             │                    │  8. Next isGrantValid()
 │                             │◄───────────────────│     returns false
 │                             │──── false ─────────►│
 │                             │                    │  ✅ Vendor locked out
```

---

## Appendix A: Glossary

| Term | Definition |
|---|---|
| **Vault** | A user's complete collection of encrypted chunks, managed by a smart contract |
| **Chunk** | A discrete unit of personal data (e.g., "address", "medical summary") |
| **Master Key (MK)** | The root key derived from biometric + device key + PIN |
| **Chunk Key** | A per-chunk symmetric key derived from the Master Key via HKDF |
| **Grant** | A time-limited authorization for a vendor to decrypt a specific chunk |
| **Vendor** | Any entity that requests access to user data |
| **Secure Enclave** | Hardware-isolated processor for key storage and biometric matching |
| **Fuzzy Extractor** | Cryptographic primitive that derives stable keys from noisy biometric inputs |

## Appendix B: References

1. Dodis, Y., Reyzin, L., & Smith, A. (2004). "Fuzzy Extractors: How to Generate Strong Keys from Biometrics and Other Noisy Data"
2. ISO/IEC 24745:2022 — "Biometric template protection"
3. ERC-4337 — "Account Abstraction Using Alt Mempool"
4. Groth, J. (2016). "On the Size of Pairing-based Non-interactive Arguments" (Groth16)
5. Rivest, R.L., Shamir, A., & Wagner, D.A. (1996). "Time-lock Puzzles and Timed-release Crypto"
6. Buterin, V. (2021). "Why we need wide adoption of social recovery wallets"

---

*This document is a living artifact. Submit issues and PRs to improve it.*
