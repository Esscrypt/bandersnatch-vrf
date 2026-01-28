/**
 * Ring VRF Prover using WASM bindings to Rust implementation
 *
 * This implementation uses the Rust reference implementation compiled to WASM,
 * providing full compliance with the bandersnatch-vrf-spec and VG24 Plonk zkSNARK protocol.
 */

import { readFileSync } from 'node:fs'
import { hexToBytes } from 'viem'
// Import WASM module (from ark-vrf, matches test vectors exactly)
// The Node.js build auto-initializes when imported
import {
  compute_ring_commitment,
  prove_ring_proof,
} from '../../wasm-ark-vrf/ark_vrf_wasm'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config'
import { PedersenVRFProver } from './pedersen'
import type { RingVRFInput, RingVRFResult } from './ring-kzg'

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
 * Ring VRF Prover using WASM bindings
 * Provides full Plonk zkSNARK proof generation matching Rust reference implementation
 *
 * The WASM module auto-initializes when imported (Node.js build).
 */
export class RingVRFProverWasm {
  private readonly srsBytes: Uint8Array

  /**
   * Create a new Ring VRF Prover instance using WASM
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
   * Generate Ring VRF proof using WASM
   *
   * Steps:
   * 1. Generate Pedersen VRF proof (TypeScript implementation)
   * 2. Compute ring commitment using WASM (Rust Ring::with_keys)
   * 3. Generate ring proof using WASM (Rust Plonk prover)
   */
  prove(secretKey: Uint8Array, input: RingVRFInput): RingVRFResult {
    // Step 1: Generate Pedersen VRF proof (TypeScript implementation)
    const pedersenInput = {
      input: input.input,
      auxData: input.auxData,
    }
    const pedersenResult = PedersenVRFProver.prove(secretKey, pedersenInput)

    // Step 2: Serialize ring keys for WASM (replace null keys with padding point)
    // Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys
    const ringKeysBytes = new Uint8Array(input.ringKeys.length * 32)
    for (let i = 0; i < input.ringKeys.length; i++) {
      const key = replaceNullKeyWithPadding(input.ringKeys[i])
      ringKeysBytes.set(key, i * 32)
    }

    // Step 3: Compute ring commitment using WASM (ark-vrf version)
    // ark-vrf uses hardcoded seed/padding from BandersnatchSha512Ell2 suite
    let ringCommitment: Uint8Array
    try {
      const commitmentBytes = compute_ring_commitment(
        this.srsBytes,
        ringKeysBytes,
        input.ringKeys.length, // ring_size
      )
      ringCommitment = new Uint8Array(commitmentBytes)
    } catch (error) {
      console.error('[RingVRFProverWasm] Failed to compute ring commitment', {
        error: error instanceof Error ? error.message : String(error),
      })
      throw error
    }

    // Step 4: Generate ring proof using WASM (w3f-ring-proof to match test vectors)
    // Use prove_ring_proof which uses w3f-ring-proof instead of w3f-ring-vrf-snark
    // This matches the proof format used in ark-vrf test vectors (592 bytes vs 1184 bytes)
    let ringProof: Uint8Array
    try {
      // Use the blinding factor from Pedersen VRF proof
      // This matches ark-vrf::ring::Prover::prove which calls ring_prover.prove(secret_blinding)
      const blindingFactor = pedersenResult.blindingFactor

      // Generate ring proof using ark-vrf (matches test vectors exactly)
      // ark-vrf uses hardcoded seed/padding/transcript from BandersnatchSha512Ell2 suite
      const proofBytes = prove_ring_proof(
        this.srsBytes,
        ringKeysBytes,
        blindingFactor,
        input.proverIndex,
        input.ringKeys.length, // ring_size
      )

      // The WASM function returns RingProof from w3f-ring-proof (592 bytes for ring size 8)
      ringProof = new Uint8Array(proofBytes)
    } catch (error) {
      console.error('[RingVRFProverWasm] Failed to generate ring proof', {
        error: error instanceof Error ? error.message : String(error),
      })
      throw error
    }

    return {
      gamma: pedersenResult.gamma,
      proof: {
        pedersenProof: pedersenResult.proof,
        ringCommitment,
        ringProof,
        proverIndex: input.proverIndex,
      },
    }
  }

  /**
   * Compute ring commitment only (without generating full proof)
   * Useful for epoch root computation
   *
   * Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys.
   * Null (all-zero) keys are replaced with the padding point before passing to WASM.
   */
  computeRingCommitment(ringKeys: Uint8Array[]): Uint8Array {
    // Serialize ring keys (replace null keys with padding point)
    // Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys
    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      const key = replaceNullKeyWithPadding(ringKeys[i])
      ringKeysBytes.set(key, i * 32)
    }

    // Compute ring commitment using WASM
    const commitmentBytes = compute_ring_commitment(
      this.srsBytes,
      ringKeysBytes,
      ringKeys.length,
    )

    return new Uint8Array(commitmentBytes)
  }
}
