/* tslint:disable */
/* eslint-disable */
/**
 * Generate a ring proof using ark-vrf (matches test vectors exactly).
 *
 * This function uses ark-vrf's RingProver which matches the exact implementation
 * used to generate the test vectors.
 *
 * # Arguments
 * * `srs_bytes` - Serialized PCS params (SRS) bytes (uncompressed arkworks format)
 * * `ring_keys_bytes` - Serialized ring public keys (compressed, 32 bytes each)
 * * `blinding_factor_bytes` - Serialized blinding factor (32 bytes, Fr scalar)
 * * `prover_index` - Index of the prover's key in the ring (0-based)
 * * `ring_size` - Number of keys in the ring
 *
 * # Returns
 * * Serialized RingProof (matches test vectors exactly)
 */
export function prove_ring_proof(srs_bytes: Uint8Array, ring_keys_bytes: Uint8Array, blinding_factor_bytes: Uint8Array, prover_index: number, ring_size: number): Uint8Array;
/**
 * Verify a ring proof using ark-vrf.
 *
 * # Arguments
 * * `srs_bytes` - Serialized PCS params (SRS) bytes (uncompressed arkworks format)
 * * `proof_bytes` - Serialized RingProof
 * * `ring_keys_bytes` - Serialized ring public keys (compressed, 32 bytes each)
 * * `key_commitment_bytes` - Serialized key commitment (Y_bar from Pedersen proof, compressed, 32 bytes)
 * * `ring_size` - Number of keys in the ring
 *
 * # Returns
 * * `true` if proof is valid, `false` otherwise
 */
export function verify_ring_proof(srs_bytes: Uint8Array, proof_bytes: Uint8Array, ring_keys_bytes: Uint8Array, key_commitment_bytes: Uint8Array, ring_size: number): boolean;
/**
 * Compute ring commitment (FixedColumnsCommitted) from ring keys.
 * This matches ark-vrf's RingProofParams::verifier_key().commitment() functionality.
 *
 * # Arguments
 * * `srs_bytes` - Serialized PCS params (SRS) bytes (uncompressed arkworks format)
 * * `ring_keys_bytes` - Serialized ring public keys (compressed, 32 bytes each)
 * * `ring_size` - Number of keys in the ring
 *
 * # Returns
 * * Serialized FixedColumnsCommitted (144 bytes: cx, cy, selector, each 48 bytes)
 */
export function compute_ring_commitment(srs_bytes: Uint8Array, ring_keys_bytes: Uint8Array, ring_size: number): Uint8Array;
export function init(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly compute_ring_commitment: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly init: () => void;
  readonly prove_ring_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
  readonly verify_ring_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number];
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
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
