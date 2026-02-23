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

// URL-safe base64 encoding/decoding
function toBase64Url(str: string): string {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function fromBase64Url(str: string): string {
  // Restore standard base64
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding
  while (b64.length % 4) b64 += '=';
  return decodeURIComponent(escape(atob(b64)));
}

function App() {
  const [isReady, setIsReady] = useState(false);
  
  // Vault State
  const [seedBytes, setSeedBytes] = useState<Uint8Array | null>(null);
  const [vaultId, setVaultId] = useState<string>('');
  const [homeAddress, setHomeAddress] = useState('');
  const [encryptedChunkData, setEncryptedChunkData] = useState<{ nonce: string; ciphertext: string } | null>(null);
  const [shareLink, setShareLink] = useState('');
  const [_generatedVendorKey, setGeneratedVendorKey] = useState<VendorAccessKey | null>(null);
  const [chunkKeyRef, setChunkKeyRef] = useState<ChunkKey | null>(null); // Keep ref to free later if needed

  // Vendor State
  const [vendorInput, setVendorInput] = useState('');
  const [decryptedAddress, setDecryptedAddress] = useState('');
  const [vendorStatus, setVendorStatus] = useState('');

  useEffect(() => {
    init().then(() => setIsReady(true));
  }, []);

  const simulateScan = () => {
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);
    setSeedBytes(entropy);
    // Derive a "Vault ID" from the first 8 bytes of entropy for display
    setVaultId(toHexString(entropy.slice(0, 8)).toUpperCase());
    
    // Reset downstream
    setEncryptedChunkData(null);
    setShareLink('');
    setGeneratedVendorKey(null);
    if (chunkKeyRef) {
      chunkKeyRef.free();
      setChunkKeyRef(null);
    }
  };

  const encryptAndStore = () => {
    if (!seedBytes || !homeAddress) return;

    try {
      const seed = BiometricSeed.from_entropy(seedBytes);
      const masterKey = MasterKey.derive(seed);
      const categoryKey = CategoryKey.derive(masterKey, 'personal_data');
      const chunkKey = ChunkKey.derive(categoryKey, 'home_address');
      
      const encoder = new TextEncoder();
      const data = encoder.encode(homeAddress);
      
      const encrypted = encrypt_chunk(chunkKey, data);
      
      setEncryptedChunkData({
        nonce: toHexString(encrypted.nonce),
        ciphertext: toHexString(encrypted.ciphertext)
      });
      
      // Store chunkKey for sharing later (in a real app, we'd re-derive)
      // For this demo, we just keep the object alive or re-derive.
      // Better to re-derive to be safe about lifetimes, but we can keep it.
      // Wait, Rust objects in WASM must be freed. 
      // For simplicity in this demo, we rely on GC or explicit free if we were strict.
      // We'll re-derive in share function to avoid holding state too long.
      
      seed.free();
      masterKey.free();
      categoryKey.free();
      chunkKey.free(); 
      encrypted.free();
      
    } catch (e: any) {
      console.error(e);
      alert('Encryption failed: ' + e.message);
    }
  };

  const shareWithVendor = () => {
    if (!seedBytes || !encryptedChunkData) return;
    
    try {
      // Re-derive keys to decrypt, then re-encrypt with vendor key
      const seed = BiometricSeed.from_entropy(seedBytes);
      const masterKey = MasterKey.derive(seed);
      const categoryKey = CategoryKey.derive(masterKey, 'personal_data');
      const chunkKey = ChunkKey.derive(categoryKey, 'home_address');

      // Generate a vendor key
      const expiresAt = Math.floor(Date.now() / 1000) + 3600; // 1 hour
      const vendorKey = generate_vendor_key(chunkKey, 'vendor-demo', BigInt(expiresAt));

      // For the demo: share the chunk key so the vendor can decrypt directly.
      // In production, this would use proxy re-encryption — the vendor would
      // get a re-encryption key that transforms the ciphertext without exposing
      // the original chunk key.
      const chunkKeyBytes = chunkKey.as_bytes();
      
      const payload = {
        key: toHexString(new Uint8Array(chunkKeyBytes)),
        vendor_id: vendorKey.vendor_id,
        expires_at: Number(vendorKey.expires_at),
        nonce: encryptedChunkData.nonce,
        ciphertext: encryptedChunkData.ciphertext
      };
      
      const json = JSON.stringify(payload);
      const b64 = toBase64Url(json);
      const link = `${window.location.origin}${window.location.pathname}#share=${b64}`;
      setShareLink(link);
      
      seed.free();
      masterKey.free();
      categoryKey.free();
      chunkKey.free();
      vendorKey.free();
      
    } catch (e: any) {
      console.error(e);
      alert('Share generation failed: ' + e.message);
    }
  };

  const handleVendorDecrypt = () => {
    try {
      let payloadStr = vendorInput.trim();
      // Handle full URL or just the base64 part
      if (payloadStr.includes('#share=')) {
        payloadStr = payloadStr.split('#share=')[1];
      }
      
      const json = fromBase64Url(payloadStr);
      const payload = JSON.parse(json);
      
      // Check expiry
      const now = Math.floor(Date.now() / 1000);
      if (now >= payload.expires_at) {
        setVendorStatus('Access denied: this share link has expired.');
        setDecryptedAddress('');
        return;
      }
      
      const nonce = fromHexString(payload.nonce);
      const ciphertext = fromHexString(payload.ciphertext);
      const encryptedChunk = new EncryptedChunk(nonce, ciphertext);
      
      // Use the chunk key to decrypt (in production, this would be proxy re-encryption)
      const chunkKeyBytes = fromHexString(payload.chunk_key);
      const vendorKey = VendorAccessKey.from_components(chunkKeyBytes, payload.vendor_id, payload.expires_at);
      
      const decryptedBytes = decrypt_vendor_chunk(vendorKey, encryptedChunk);
      const decoder = new TextDecoder();
      setDecryptedAddress(decoder.decode(decryptedBytes));
      
      const expiry = new Date(payload.expires_at * 1000);
      setVendorStatus(`✅ Decrypted successfully! Access valid until: ${expiry.toLocaleTimeString()}`);
      
      vendorKey.free();
      encryptedChunk.free();
      
    } catch (e: any) {
      console.error(e);
      setVendorStatus('Decryption failed: ' + e.message);
      setDecryptedAddress('');
    }
  };

  if (!isReady) return <div>Loading Krypt WASM Core...</div>;

  return (
    <div className="container">
      <h1>Krypt Architecture Demo</h1>
      
      <div className="card">
        <h2>1. User Vault</h2>
        <div className="section">
          <button onClick={simulateScan}>Simulate Biometric Scan</button>
          {vaultId && <p><strong>Vault ID:</strong> {vaultId}</p>}
        </div>
        
        {vaultId && (
          <div className="section">
            <input 
              type="text" 
              placeholder="Enter Home Address" 
              value={homeAddress}
              onChange={(e) => setHomeAddress(e.target.value)}
            />
            <button onClick={encryptAndStore}>Encrypt & Store</button>
          </div>
        )}
        
        {encryptedChunkData && (
          <div className="section">
            <p><strong>Encrypted Chunk (Base64):</strong></p>
            <pre className="code-block">
              {encryptedChunkData.ciphertext.slice(0, 64)}...
            </pre>
            <button onClick={shareWithVendor}>Share with Vendor</button>
          </div>
        )}
        
        {shareLink && (
          <div className="section">
            <p><strong>Share Link:</strong></p>
            <textarea readOnly value={shareLink} style={{width: '100%', height: '60px'}} />
            <button onClick={() => { setVendorInput(shareLink); }}>
              Auto-fill Vendor Form 👇
            </button>
          </div>
        )}
      </div>

      <div className="card vendor-card">
        <h2>2. Vendor (Recipient)</h2>
        <div className="section">
          <input 
            type="text" 
            placeholder="Paste Share Link or Key Blob" 
            value={vendorInput}
            onChange={(e) => setVendorInput(e.target.value)}
            style={{width: '100%'}}
          />
          <button onClick={handleVendorDecrypt}>Decrypt Access</button>
        </div>
        
        {decryptedAddress && (
          <div className="section success">
            <p><strong>Decrypted Address:</strong> {decryptedAddress}</p>
            <p className="status">{vendorStatus}</p>
          </div>
        )}
        {!decryptedAddress && vendorStatus && (
           <div className="section error">
             <p>{vendorStatus}</p>
           </div>
        )}
      </div>
    </div>
  );
}

export default App;
