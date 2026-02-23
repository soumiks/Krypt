/**
 * @krypt/sdk — Vendor SDK for Krypt
 *
 * Provides a TypeScript interface for vendors to interact with Krypt vaults,
 * request access to data chunks, and decrypt shared data.
 */

export interface VaultInfo {
  vaultId: string;
  owner: string;
  chunkCount: number;
  createdAt: number;
}

export interface ChunkInfo {
  chunkId: string;
  storagePointer: string;
  createdAt: number;
}

export interface AccessGrant {
  vendor: string;
  chunkId: string;
  grantedAt: number;
  expiresAt: number;
  revoked: boolean;
}

export interface KryptSDKConfig {
  /** JSON-RPC endpoint URL */
  rpcUrl: string;
  /** VaultRegistry contract address */
  vaultRegistryAddress: string;
  /** AccessControl contract address */
  accessControlAddress: string;
}

/**
 * Krypt Vendor SDK
 *
 * Usage:
 * ```ts
 * const sdk = new KryptSDK({
 *   rpcUrl: "https://rpc.example.com",
 *   vaultRegistryAddress: "0x...",
 *   accessControlAddress: "0x...",
 * });
 *
 * const vault = await sdk.getVault(vaultId);
 * const hasAccess = await sdk.checkAccess(vaultId, chunkId, vendorAddress);
 * ```
 */
export class KryptSDK {
  private config: KryptSDKConfig;

  constructor(config: KryptSDKConfig) {
    this.config = config;
  }

  /**
   * Get vault information from the registry.
   */
  async getVault(vaultId: string): Promise<VaultInfo> {
    // TODO: Implement contract call via ethers
    throw new Error("Not implemented — requires contract deployment");
  }

  /**
   * Get chunk metadata.
   */
  async getChunk(vaultId: string, chunkId: string): Promise<ChunkInfo> {
    throw new Error("Not implemented — requires contract deployment");
  }

  /**
   * Check if a vendor has access to a specific chunk.
   */
  async checkAccess(
    vaultId: string,
    chunkId: string,
    vendorAddress: string
  ): Promise<boolean> {
    throw new Error("Not implemented — requires contract deployment");
  }

  /**
   * Get the access log for a vault.
   */
  async getAccessLog(vaultId: string): Promise<AccessGrant[]> {
    throw new Error("Not implemented — requires contract deployment");
  }
}

export default KryptSDK;
