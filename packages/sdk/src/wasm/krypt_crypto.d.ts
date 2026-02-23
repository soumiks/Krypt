/* tslint:disable */
/* eslint-disable */

export class BiometricSeed {
    free(): void;
    [Symbol.dispose](): void;
    static from_entropy(bytes: Uint8Array): BiometricSeed;
    constructor(bytes: Uint8Array);
}

export class CategoryKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static derive(master_key: MasterKey, category: string): CategoryKey;
}

export class ChunkKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    as_bytes(): Uint8Array;
    static derive(category_key: CategoryKey, chunk_id: string): ChunkKey;
}

export class EncryptedChunk {
    free(): void;
    [Symbol.dispose](): void;
    constructor(nonce: Uint8Array, ciphertext: Uint8Array);
    readonly ciphertext: Uint8Array;
    readonly nonce: Uint8Array;
}

export class MasterKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static derive(seed: BiometricSeed): MasterKey;
}

export class VendorAccessKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Reconstruct a vendor key from its components (for the recipient).
     */
    static from_components(key_bytes: Uint8Array, vendor_id: string, expires_at: bigint): VendorAccessKey;
    is_expired(current_time: bigint): boolean;
    readonly expires_at: bigint;
    readonly key: Uint8Array;
    readonly vendor_id: string;
}

export function decrypt_chunk(chunk_key: ChunkKey, encrypted_chunk: EncryptedChunk): Uint8Array;

export function decrypt_vendor_chunk(vendor_key: VendorAccessKey, encrypted_chunk: EncryptedChunk): Uint8Array;

export function encrypt_chunk(chunk_key: ChunkKey, plaintext: Uint8Array): EncryptedChunk;

export function generate_vendor_key(chunk_key: ChunkKey, vendor_id: string, expires_at: bigint): VendorAccessKey;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_biometricseed_free: (a: number, b: number) => void;
    readonly __wbg_categorykey_free: (a: number, b: number) => void;
    readonly __wbg_chunkkey_free: (a: number, b: number) => void;
    readonly __wbg_encryptedchunk_free: (a: number, b: number) => void;
    readonly __wbg_masterkey_free: (a: number, b: number) => void;
    readonly __wbg_vendoraccesskey_free: (a: number, b: number) => void;
    readonly biometricseed_from_entropy: (a: number, b: number) => [number, number, number];
    readonly biometricseed_new: (a: number, b: number) => [number, number, number];
    readonly categorykey_derive: (a: number, b: number, c: number) => [number, number, number];
    readonly chunkkey_as_bytes: (a: number) => [number, number];
    readonly chunkkey_derive: (a: number, b: number, c: number) => [number, number, number];
    readonly decrypt_chunk: (a: number, b: number) => [number, number, number, number];
    readonly decrypt_vendor_chunk: (a: number, b: number) => [number, number, number, number];
    readonly encrypt_chunk: (a: number, b: number, c: number) => [number, number, number];
    readonly encryptedchunk_ciphertext: (a: number) => [number, number];
    readonly encryptedchunk_new: (a: number, b: number, c: number, d: number) => number;
    readonly encryptedchunk_nonce: (a: number) => [number, number];
    readonly generate_vendor_key: (a: number, b: number, c: number, d: bigint) => [number, number, number];
    readonly masterkey_derive: (a: number) => [number, number, number];
    readonly vendoraccesskey_expires_at: (a: number) => bigint;
    readonly vendoraccesskey_from_components: (a: number, b: number, c: number, d: number, e: bigint) => [number, number, number];
    readonly vendoraccesskey_is_expired: (a: number, b: bigint) => number;
    readonly vendoraccesskey_key: (a: number) => [number, number];
    readonly vendoraccesskey_vendor_id: (a: number) => [number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
