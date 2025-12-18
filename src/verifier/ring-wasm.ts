/**
 * Ring VRF Verifier using WASM bindings to Rust implementation
 *
 * This implementation uses the Rust reference implementation compiled to WASM,
 * providing full compliance with the bandersnatch-vrf-spec and VG24 Plonk zkSNARK protocol.
 */

import { readFileSync } from 'node:fs'
// Import WASM module (from ark-vrf, matches test vectors exactly)
import initWasm, { verify_ring_proof } from '../../wasm-ark-vrf/ark_vrf_wasm'
import { PedersenVRFProver } from '../prover/pedersen'
import type { RingVRFInput } from '../prover/ring-kzg'
import { PedersenVRFVerifier } from './pedersen'


/**
 * Ring VRF Verifier using WASM bindings
 * Provides full Plonk zkSNARK proof verification matching Rust reference implementation
 */
export class RingVRFVerifierWasm {
  private srsBytes: Uint8Array
  private wasmInitialized = false
  /**
   * Create a new Ring VRF Verifier instance using WASM
   *
   * @param srsFilePath - Path to SRS file (compressed format)
   */
  constructor(
    srsFilePath: string,
  ) {
    // Load SRS file (expects uncompressed arkworks format)
    // Replace '-compressed.bin' with '-uncompressed.bin' if needed
    this.srsBytes = readFileSync(srsFilePath)
  }

  async init(): Promise<void> {
    // Load WASM module - pass the WASM file path directly to avoid import.meta.url issues in Bun
    const wasmPath = new URL('../../wasm-ark-vrf/ark_vrf_wasm_bg.wasm', import.meta.url)
    await initWasm(wasmPath.toString())
    this.wasmInitialized = true
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
    if (!this.wasmInitialized) {
      throw new Error('WASM module not initialized yet. Please wait for initialization to complete. ' +
        'You can await wasmInitPromise from ring-wasm if needed.')
    }

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

    // Step 2: Serialize inputs for WASM
    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      ringKeysBytes.set(ringKeys[i]!, i * 32)
    }

    // Step 3: Extract key commitment (Y_bar) from Pedersen proof
    // The ring proof verifies that the key commitment matches the ring
    const pedersenProof = PedersenVRFProver.deserialize(result.proof.pedersenProof)
    const keyCommitmentBytes = pedersenProof.Y_bar // Y_bar is the key commitment

    // Step 4: Verify ring proof using WASM (ark-vrf version)
    // ark-vrf uses hardcoded seed/padding from BandersnatchSha512Ell2 suite
    // NOTE: result.proof.ringProof should ONLY contain the compressed RingBareProof bytes,
    // NOT the full 784-byte structure (which includes gamma, pedersen_proof, ring_commitment).
    // The ring proof portion is extracted from the 784-byte structure by RingVRFProver.deserialize.
    const ringProofBytes = result.proof.ringProof
    
    // Sanity check: ring proof should not be 784 bytes (that would be the full structure)
    if (ringProofBytes.length === 784) {
      console.error('[RingVRFVerifierWasm] ERROR: ringProof is 784 bytes - this is the full structure, not just the ring proof portion!')
      throw new Error('Invalid ring proof: received full 784-byte structure instead of just ring proof portion')
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
