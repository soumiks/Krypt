import { useState, useEffect } from 'react';
import init, {
  BiometricSeed,
  MasterKey,
  CategoryKey,
  ChunkKey,
  EncryptedChunk,
  generate_vendor_key,
  decrypt_vendor_chunk,
  VendorAccessKey,
  encrypt_chunk
} from './wasm/krypt_crypto.js';
import './App.css';

function toHexString(bytes: Uint8Array) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHexString(hexString: string) {
  return new Uint8Array(
    hexString.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
  );
}

function toBase64Url(str: string): string {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function fromBase64Url(str: string): string {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return decodeURIComponent(escape(atob(b64)));
}

interface FieldConfig {
  id: string;
  chunkId: string;
  label: string;
  emoji: string;
  placeholder: string;
  vendorId: string;
  vendorName: string;
  buttonLabel: string;
}

const FIELDS: FieldConfig[] = [
  {
    id: 'home_address',
    chunkId: 'home_address',
    label: 'Home Address',
    emoji: '🏠',
    placeholder: '123 Main St, Anytown USA',
    vendorId: 'delivery-co',
    vendorName: 'Delivery Co',
    buttonLabel: 'Share Address with Delivery Co',
  },
  {
    id: 'ssn',
    chunkId: 'ssn',
    label: 'SSN',
    emoji: '🔐',
    placeholder: '123-45-6789',
    vendorId: 'bank',
    vendorName: 'Bank',
    buttonLabel: 'Share SSN with Bank',
  },
  {
    id: 'medical_record',
    chunkId: 'medical_record',
    label: 'Medical Record',
    emoji: '🏥',
    placeholder: 'Blood type: O+, Allergies: None',
    vendorId: 'doctor',
    vendorName: 'Doctor',
    buttonLabel: 'Share Medical with Doctor',
  },
];

interface EncryptedField {
  nonce: string;
  ciphertext: string;
}

function App() {
  const [isReady, setIsReady] = useState(false);

  // Vault State
  const [seedBytes, setSeedBytes] = useState<Uint8Array | null>(null);
  const [vaultId, setVaultId] = useState('');
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({
    home_address: '',
    ssn: '',
    medical_record: '',
  });
  const [encryptedFields, setEncryptedFields] = useState<Record<string, EncryptedField>>({});
  const [shareLinks, setShareLinks] = useState<Record<string, string>>({});

  // Vendor State
  const [vendorInput, setVendorInput] = useState('');
  const [decryptedValue, setDecryptedValue] = useState('');
  const [vendorMeta, setVendorMeta] = useState<{ vendorName: string; fieldName: string } | null>(null);
  const [vendorStatus, setVendorStatus] = useState('');

  useEffect(() => {
    init().then(() => setIsReady(true));
  }, []);

  const simulateScan = () => {
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);
    setSeedBytes(entropy);
    setVaultId(toHexString(entropy.slice(0, 8)).toUpperCase());
    setEncryptedFields({});
    setShareLinks({});
  };

  const encryptAll = () => {
    if (!seedBytes) return;
    const hasData = FIELDS.some((f) => fieldValues[f.id].trim());
    if (!hasData) return;

    try {
      const seed = BiometricSeed.from_entropy(seedBytes);
      const masterKey = MasterKey.derive(seed);
      const categoryKey = CategoryKey.derive(masterKey, 'personal_data');
      const encoder = new TextEncoder();
      const result: Record<string, EncryptedField> = {};

      for (const field of FIELDS) {
        const val = fieldValues[field.id].trim();
        if (!val) continue;
        const chunkKey = ChunkKey.derive(categoryKey, field.chunkId);
        const encrypted = encrypt_chunk(chunkKey, encoder.encode(val));
        result[field.id] = {
          nonce: toHexString(encrypted.nonce),
          ciphertext: toHexString(encrypted.ciphertext),
        };
        chunkKey.free();
        encrypted.free();
      }

      seed.free();
      masterKey.free();
      categoryKey.free();
      setEncryptedFields(result);
      setShareLinks({});
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(e);
      alert('Encryption failed: ' + msg);
    }
  };

  const shareWithVendor = (field: FieldConfig) => {
    if (!seedBytes || !encryptedFields[field.id]) return;

    try {
      const seed = BiometricSeed.from_entropy(seedBytes);
      const masterKey = MasterKey.derive(seed);
      const categoryKey = CategoryKey.derive(masterKey, 'personal_data');
      const chunkKey = ChunkKey.derive(categoryKey, field.chunkId);

      const expiresAt = Math.floor(Date.now() / 1000) + 3600;
      const vendorKey = generate_vendor_key(chunkKey, field.vendorId, BigInt(expiresAt));
      const chunkKeyBytes = chunkKey.as_bytes();

      const payload = {
        chunk_key: toHexString(new Uint8Array(chunkKeyBytes)),
        vendor_id: field.vendorId,
        vendor_name: field.vendorName,
        field_name: field.label,
        field_id: field.id,
        expires_at: Number(vendorKey.expires_at),
        nonce: encryptedFields[field.id].nonce,
        ciphertext: encryptedFields[field.id].ciphertext,
      };

      const json = JSON.stringify(payload);
      const b64 = toBase64Url(json);
      const link = `${window.location.origin}${window.location.pathname}#share=${b64}`;
      setShareLinks((prev) => ({ ...prev, [field.id]: link }));

      seed.free();
      masterKey.free();
      categoryKey.free();
      chunkKey.free();
      vendorKey.free();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(e);
      alert('Share generation failed: ' + msg);
    }
  };

  const handleVendorDecrypt = () => {
    try {
      let payloadStr = vendorInput.trim();
      if (payloadStr.includes('#share=')) {
        payloadStr = payloadStr.split('#share=')[1];
      }

      const json = fromBase64Url(payloadStr);
      const payload = JSON.parse(json);

      // Check expiry
      const now = Math.floor(Date.now() / 1000);
      if (now >= payload.expires_at) {
        setVendorStatus('⏰ Access denied: this share link has expired.');
        setDecryptedValue('');
        setVendorMeta(null);
        return;
      }

      const nonce = fromHexString(payload.nonce);
      const ciphertext = fromHexString(payload.ciphertext);
      const encryptedChunk = new EncryptedChunk(nonce, ciphertext);

      const chunkKeyBytes = fromHexString(payload.chunk_key);
      const vendorKey = VendorAccessKey.from_components(
        chunkKeyBytes,
        payload.vendor_id,
        BigInt(payload.expires_at)
      );

      const decryptedBytes = decrypt_vendor_chunk(vendorKey, encryptedChunk);
      const decoder = new TextDecoder();
      const value = decoder.decode(decryptedBytes);

      const expiry = new Date(payload.expires_at * 1000);
      setDecryptedValue(value);
      setVendorMeta({ vendorName: payload.vendor_name, fieldName: payload.field_name });
      setVendorStatus(
        `✅ Decrypted successfully! Access valid until: ${expiry.toLocaleTimeString()}`
      );

      vendorKey.free();
      encryptedChunk.free();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(e);
      setVendorStatus('❌ Decryption failed: ' + msg);
      setDecryptedValue('');
      setVendorMeta(null);
    }
  };

  if (!isReady) return <div className="loading">Loading Krypt WASM Core...</div>;

  const hasEncrypted = Object.keys(encryptedFields).length > 0;

  return (
    <div className="container">
      <h1>🔑 Krypt Selective Disclosure Demo</h1>
      <p className="subtitle">
        Encrypt personal data independently. Share each piece only with the vendor that needs it.
      </p>

      <div className="card vault-card">
        <h2>1. User Vault</h2>

        <div className="section">
          <button className="btn-primary" onClick={simulateScan}>
            🫁 Simulate Biometric Scan
          </button>
          {vaultId && (
            <p className="vault-id">
              <strong>Vault ID:</strong> <code>{vaultId}</code>
            </p>
          )}
        </div>

        {vaultId && (
          <>
            <div className="fields-grid">
              {FIELDS.map((field) => (
                <div key={field.id} className="field-card">
                  <label>
                    {field.emoji} <strong>{field.label}</strong>
                  </label>
                  <input
                    type="text"
                    placeholder={field.placeholder}
                    value={fieldValues[field.id]}
                    onChange={(e) =>
                      setFieldValues((prev) => ({ ...prev, [field.id]: e.target.value }))
                    }
                  />
                  {encryptedFields[field.id] && (
                    <div className="encrypted-preview">
                      <small>🔒 {encryptedFields[field.id].ciphertext.slice(0, 32)}…</small>
                    </div>
                  )}
                </div>
              ))}
            </div>

            <button className="btn-primary" onClick={encryptAll}>
              🔐 Encrypt All
            </button>

            {hasEncrypted && (
              <div className="share-section">
                <h3>Share with Vendors</h3>
                <div className="share-grid">
                  {FIELDS.map((field) =>
                    encryptedFields[field.id] ? (
                      <div key={field.id} className="share-card">
                        <button className="btn-share" onClick={() => shareWithVendor(field)}>
                          {field.emoji} {field.buttonLabel}
                        </button>
                        {shareLinks[field.id] && (
                          <div className="share-link-box">
                            <textarea readOnly value={shareLinks[field.id]} rows={2} />
                            <button
                              className="btn-small"
                              onClick={() => setVendorInput(shareLinks[field.id])}
                            >
                              Auto-fill Vendor 👇
                            </button>
                          </div>
                        )}
                      </div>
                    ) : null
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>

      <div className="card vendor-card">
        <h2>2. Vendor Portal</h2>
        <div className="section">
          <input
            type="text"
            placeholder="Paste any share link here…"
            value={vendorInput}
            onChange={(e) => setVendorInput(e.target.value)}
            style={{ width: '100%' }}
          />
          <button className="btn-primary" onClick={handleVendorDecrypt}>
            🔓 Decrypt
          </button>
        </div>

        {decryptedValue && vendorMeta && (
          <div className="section success">
            <p>
              <strong>Vendor:</strong> {vendorMeta.vendorName}
            </p>
            <p>
              <strong>Field:</strong> {vendorMeta.fieldName}
            </p>
            <p>
              <strong>Decrypted Value:</strong> {decryptedValue}
            </p>
            <p className="status">{vendorStatus}</p>
            <p className="access-note">
              ⛔ This key only grants access to: <strong>{vendorMeta.fieldName}</strong>
            </p>
          </div>
        )}
        {!decryptedValue && vendorStatus && (
          <div className="section error">
            <p>{vendorStatus}</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
