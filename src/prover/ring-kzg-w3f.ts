/**
 * Ring VRF Prover using Rust connector (rust-ring-proof).
 *
 * The Rust native module handles w3f ring proof (RingPiopParams::setup, index,
 * RingProver::init, prove, compute_ring_commitment). TypeScript handles
 * Pedersen step, null-key replacement, config (domain_size, seed, padding, transcript).
 * Requires the native module; build with `bun run build:native` in the package.
 */

import { readFileSync } from 'node:fs'
import { hexToBytes } from 'viem'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config'
import { PedersenVRFProver } from './pedersen'
import type { RingVRFInput, RingVRFResult } from './ring-kzg'
import {
  getRustComputeRingCommitment,
  getRustProveRingProof,
} from './rust-ring-proof-wrapper'

const RUST_REQUIRED_MSG =
  'Ring VRF prover requires the Rust native module (rust-ring-proof). Build with: cd rust-ring-proof && bun run build'

/**
 * Replace null (all-zero) keys with the padding point.
 * Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys.
 */
function replaceNullKeyWithPadding(keyBytes: Uint8Array): Uint8Array {
  // Check for all-zero key (null key)
  if (keyBytes.every((b) => b === 0)) {
    return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
  }
  return keyBytes
}

/**
 * Ring VRF Prover using Rust native module (rust-ring-proof).
 */
export class RingVRFProverW3F {
  private readonly srsBytes: Uint8Array

  /**
   * Create a new Ring VRF Prover instance.
   *
   * @param srsFilePath - Path to SRS file (uncompressed arkworks format)
   */
  constructor(srsFilePath: string) {
    this.srsBytes = readFileSync(srsFilePath)
  }

  /**
   * Initialize (no-op, kept for API compatibility).
   */
  async init(): Promise<void> {
    // No-op
  }

  /**
   * Generate Ring VRF proof using Rust native module.
   *
   * Steps:
   * 1. Generate Pedersen VRF proof (TypeScript)
   * 2. Compute ring commitment (Rust)
   * 3. Generate ring proof (Rust)
   */
  prove(secretKey: Uint8Array, input: RingVRFInput): RingVRFResult {
    // Step 1: Generate Pedersen VRF proof (TypeScript)
    const pedersenInput = {
      input: input.input,
      auxData: input.auxData,
    }
    const pedersenResult = PedersenVRFProver.prove(secretKey, pedersenInput)

    // Step 2: Serialize ring keys (replace null keys with padding point)
    // Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys
    const ringKeysBytes = new Uint8Array(input.ringKeys.length * 32)
    for (let i = 0; i < input.ringKeys.length; i++) {
      const key = replaceNullKeyWithPadding(input.ringKeys[i])
      ringKeysBytes.set(key, i * 32)
    }

    // Step 3: Compute ring commitment (Rust lines 101-111)
    const rustCompute = getRustComputeRingCommitment()
    if (!rustCompute) {
      throw new Error(RUST_REQUIRED_MSG)
    }
    let ringCommitment: Uint8Array
    try {
      ringCommitment = rustCompute(this.srsBytes, ringKeysBytes)
    } catch (error) {
      console.error('[RingVRFProverW3F] Failed to compute ring commitment', {
        error: error instanceof Error ? error.message : String(error),
      })
      throw error
    }

    // Step 4: Generate ring proof (Rust lines 299-316)
    const rustProve = getRustProveRingProof()
    if (!rustProve) {
      throw new Error(RUST_REQUIRED_MSG)
    }
    let ringProof: Uint8Array
    try {
      const blindingFactor = pedersenResult.blindingFactor
      ringProof = rustProve(
        this.srsBytes,
        ringKeysBytes,
        blindingFactor,
        input.proverIndex,
      )
    } catch (error) {
      console.error('[RingVRFProverW3F] Failed to generate ring proof', {
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
   * Null (all-zero) keys are replaced with the padding point before passing to Rust.
   */
  computeRingCommitment(ringKeys: Uint8Array[]): Uint8Array {
    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      const key = replaceNullKeyWithPadding(ringKeys[i])
      ringKeysBytes.set(key, i * 32)
    }

    const rustCompute = getRustComputeRingCommitment()
    if (!rustCompute) {
      throw new Error(RUST_REQUIRED_MSG)
    }
    return rustCompute(this.srsBytes, ringKeysBytes)
  }
}
