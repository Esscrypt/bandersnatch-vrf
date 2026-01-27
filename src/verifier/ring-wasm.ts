/**
 * Ring VRF Verifier using WASM bindings to Rust implementation
 *
 * This implementation uses the Rust reference implementation compiled to WASM,
 * providing full compliance with the bandersnatch-vrf-spec and VG24 Plonk zkSNARK protocol.
 */

import { readFileSync } from 'node:fs'
import { hexToBytes } from 'viem'
// Import WASM module (from ark-vrf, matches test vectors exactly)
// The Node.js build auto-initializes when imported
import { verify_ring_proof } from '../../wasm-ark-vrf/ark_vrf_wasm'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config'
import { PedersenVRFProver } from '../prover/pedersen'
import type { RingVRFInput } from '../prover/ring-kzg'
import { PedersenVRFVerifier } from './pedersen'

/**
 * Replace null (all-zero) keys with the padding point.
 * Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys.
 *
 * The WASM now uses deserialize_compressed_unchecked which skips subgroup validation,
 * matching the codec in ark-vrf. We only need to handle null keys here.
 */
function replaceNullKeyWithPadding(keyBytes: Uint8Array): Uint8Array {
  // Check for all-zero key (null key)
  if (keyBytes.every((b) => b === 0)) {
    return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
  }
  return keyBytes
}

/**
 * Ring VRF Verifier using WASM bindings
 * Provides full Plonk zkSNARK proof verification matching Rust reference implementation
 *
 * The WASM module auto-initializes when imported (Node.js build).
 */
export class RingVRFVerifierWasm {
  private srsBytes: Uint8Array

  /**
   * Create a new Ring VRF Verifier instance using WASM
   *
   * @param srsFilePath - Path to SRS file (uncompressed arkworks format)
   */
  constructor(srsFilePath: string) {
    // Load SRS file (expects uncompressed arkworks format)
    this.srsBytes = readFileSync(srsFilePath)
  }

  /**
   * Initialize the WASM module (no-op, kept for API compatibility)
   * The Node.js WASM build auto-initializes when imported.
   */
  async init(): Promise<void> {
    // No-op: WASM auto-initializes when the module is imported
  }

  /**
   * Verify Ring VRF proof using WASM
   *
   * Steps:
   * 1. Verify Pedersen VRF proof (TypeScript implementation)
   * 2. Verify ring proof using WASM (Rust Plonk verifier)
   */
  verify(
    ringKeys: Uint8Array[],
    input: RingVRFInput,
    result: {
      gamma: Uint8Array
      proof: {
        pedersenProof: Uint8Array
        ringCommitment: Uint8Array
        ringProof: Uint8Array
      }
    },
    auxData?: Uint8Array,
  ): boolean {
    const pedersenValid = PedersenVRFVerifier.verify(
      input.input,
      result.gamma,
      result.proof.pedersenProof,
      auxData,
    )
    if (!pedersenValid) {
      console.error('[RingVRFVerifierWasm] Pedersen VRF verification failed')
      return false
    }

    // Step 2: Serialize ring keys for WASM (replace null keys with padding point)
    // Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys
    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      const key = replaceNullKeyWithPadding(ringKeys[i]!)
      ringKeysBytes.set(key, i * 32)
    }

    // Step 3: Extract key commitment (Y_bar) from Pedersen proof
    // The ring proof verifies that the key commitment matches the ring
    const pedersenProof = PedersenVRFProver.deserialize(
      result.proof.pedersenProof,
    )
    const keyCommitmentBytes = pedersenProof.Y_bar // Y_bar is the key commitment

    // Step 4: Verify ring proof using WASM (ark-vrf version)
    // ark-vrf uses hardcoded seed/padding from BandersnatchSha512Ell2 suite
    // NOTE: result.proof.ringProof should ONLY contain the compressed RingBareProof bytes,
    // NOT the full 784-byte structure (which includes gamma, pedersen_proof, ring_commitment).
    // The ring proof portion is extracted from the 784-byte structure by RingVRFProver.deserialize.
    const ringProofBytes = result.proof.ringProof

    // Sanity check: ring proof should not be 784 bytes (that would be the full structure)
    if (ringProofBytes.length === 784) {
      console.error(
        '[RingVRFVerifierWasm] ERROR: ringProof is 784 bytes - this is the full structure, not just the ring proof portion!',
      )
      throw new Error(
        'Invalid ring proof: received full 784-byte structure instead of just ring proof portion',
      )
    }

    try {
      const isValid = verify_ring_proof(
        this.srsBytes,
        ringProofBytes,
        ringKeysBytes,
        keyCommitmentBytes,
        ringKeys.length, // ring_size
      )

      return isValid
    } catch (error) {
      console.error('[RingVRFVerifierWasm] Failed to verify ring proof', {
        error: error instanceof Error ? error.message : String(error),
      })
      return false
    }
  }
}
