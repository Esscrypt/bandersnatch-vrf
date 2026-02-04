/* tslint:disable */
/* eslint-disable */
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
export function compute_ring_commitment(
  srs_bytes: Uint8Array,
  ring_keys_bytes: Uint8Array,
  ring_size: number,
): Uint8Array
/**
 * Verify an IETF VRF proof using ark-vrf (RFC-9381).
 *
 * # Arguments
 * * `public_key_bytes` - Public key point (32 bytes, compressed)
 * * `input_point_bytes` - VRF input point alpha / H (32 bytes, compressed)
 * * `output_point_bytes` - VRF output point gamma (32 bytes, compressed)
 * * `proof_bytes` - IETF proof (64 bytes: c || s, both little-endian)
 * * `aux_data` - Additional data bound to the proof
 *
 * # Returns
 * * `true` if proof is valid, `false` otherwise
 */
export function verify_ietf_vrf(
  public_key_bytes: Uint8Array,
  input_point_bytes: Uint8Array,
  output_point_bytes: Uint8Array,
  proof_bytes: Uint8Array,
  aux_data: Uint8Array,
): boolean
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
export function prove_ring_proof(
  srs_bytes: Uint8Array,
  ring_keys_bytes: Uint8Array,
  blinding_factor_bytes: Uint8Array,
  prover_index: number,
  ring_size: number,
): Uint8Array
export function init(): void
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
export function verify_ring_proof(
  srs_bytes: Uint8Array,
  proof_bytes: Uint8Array,
  ring_keys_bytes: Uint8Array,
  key_commitment_bytes: Uint8Array,
  ring_size: number,
): boolean
