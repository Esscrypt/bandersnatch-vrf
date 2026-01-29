/**
 * Ring VRF Verifier using Rust connector (native) or WASM bindings
 *
 * When the Rust connector (rust-ring-proof) is built, it handles w3f verify_ring_vrf
 * (index, RingVrfVerifier::init, verify). TypeScript handles validations and mapping
 * (vrf_input = hashToCurve(input), vrf_output = gamma, seed/padding/transcript from config).
 * Falls back to ark-vrf WASM (verify_ring_proof) when the native module is not available.
 */

import { readFileSync } from 'node:fs'
import { hexToBytes } from 'viem'
import { verify_ring_proof } from '../../wasm-ark-vrf/ark_vrf_wasm'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config'
import { PedersenVRFProver } from '../prover/pedersen'
import type { RingVRFInput } from '../prover/ring-kzg'
import {
  getRustVerifyRingVrf,
  validateVerifyRingVrfInputs,
} from '../prover/rust-ring-proof-wrapper'
import { PedersenVRFVerifier } from './pedersen'

/**
 * Replace null (all-zero) keys with the padding point.
 * Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys.
 */
function replaceNullKeyWithPadding(keyBytes: Uint8Array): Uint8Array {
  if (keyBytes.every((b) => b === 0)) {
    return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
  }
  return keyBytes
}

/**
 * Ring VRF Verifier (W3F): Rust when available, else WASM.
 * Same verify API as RingVRFVerifierWasm.
 */
export class RingVRFVerifierW3F {
  private srsBytes: Uint8Array

  constructor(srsFilePath: string) {
    this.srsBytes = readFileSync(srsFilePath)
  }

  async init(): Promise<void> {
    // No-op; kept for API compatibility
  }

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
      console.error('[RingVRFVerifierW3F] Pedersen VRF verification failed')
      return false
    }

    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      const key = replaceNullKeyWithPadding(ringKeys[i]!)
      ringKeysBytes.set(key, i * 32)
    }

    const ringProofBytes = result.proof.ringProof
    if (ringProofBytes.length === 784) {
      console.error(
        '[RingVRFVerifierW3F] ERROR: ringProof is 784 bytes - full structure, not ring proof only',
      )
      throw new Error(
        'Invalid ring proof: received full 784-byte structure instead of ring proof portion',
      )
    }

    const rustVerify = getRustVerifyRingVrf()
    if (rustVerify) {
      const pedersenProof = PedersenVRFProver.deserialize(
        result.proof.pedersenProof,
      )
      const keyCommitmentBytes = pedersenProof.Y_bar
      try {
        validateVerifyRingVrfInputs({
          srsBytes: this.srsBytes,
          proofBytes: ringProofBytes,
          ringKeysBytes,
          keyCommitmentBytes,
        })
        return rustVerify(
          this.srsBytes,
          ringProofBytes,
          ringKeysBytes,
          keyCommitmentBytes,
        )
      } catch (error) {
        console.error('[RingVRFVerifierW3F] Rust verify failed', {
          error: error instanceof Error ? error.message : String(error),
        })
        return false
      }
    }

    const pedersenProof = PedersenVRFProver.deserialize(
      result.proof.pedersenProof,
    )
    const keyCommitmentBytes = pedersenProof.Y_bar
    try {
      return verify_ring_proof(
        this.srsBytes,
        ringProofBytes,
        ringKeysBytes,
        keyCommitmentBytes,
        ringKeys.length,
      )
    } catch (error) {
      console.error('[RingVRFVerifierW3F] WASM verify failed', {
        error: error instanceof Error ? error.message : String(error),
      })
      return false
    }
  }
}
