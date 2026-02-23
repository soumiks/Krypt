/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const __wbg_biometricseed_free: (a: number, b: number) => void;
export const __wbg_categorykey_free: (a: number, b: number) => void;
export const __wbg_chunkkey_free: (a: number, b: number) => void;
export const __wbg_encryptedchunk_free: (a: number, b: number) => void;
export const __wbg_masterkey_free: (a: number, b: number) => void;
export const biometricseed_from_entropy: (a: number, b: number) => [number, number, number];
export const biometricseed_new: (a: number, b: number) => [number, number, number];
export const categorykey_derive: (a: number, b: number, c: number) => [number, number, number];
export const chunkkey_derive: (a: number, b: number, c: number) => [number, number, number];
export const decrypt_chunk: (a: number, b: number) => [number, number, number, number];
export const encrypt_chunk: (a: number, b: number, c: number) => [number, number, number];
export const encryptedchunk_ciphertext: (a: number) => [number, number];
export const encryptedchunk_new: (a: number, b: number, c: number, d: number) => number;
export const encryptedchunk_nonce: (a: number) => [number, number];
export const masterkey_derive: (a: number) => [number, number, number];
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
