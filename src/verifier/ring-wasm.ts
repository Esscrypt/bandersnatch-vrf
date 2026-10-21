import { readFileSync } from 'node:fs'
import { hexToBytes } from 'viem'
import { verify_ring_proof } from '../../wasm-ark-vrf/ark_vrf_wasm.js'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config.ts'
import { PedersenVRFProver } from '../prover/pedersen.ts'
import type { RingVRFInput } from '../prover/ring-kzg.ts'
import { PedersenVRFVerifier } from './pedersen.ts'

function replaceNullKeyWithPadding(keyBytes: Uint8Array): Uint8Array {
  if (keyBytes.every((b) => b === 0)) {
    return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
  }
  return keyBytes
}

export class RingVRFVerifierWasm {
  private srsBytes: Uint8Array

  constructor(srsFilePath: string) {
    this.srsBytes = readFileSync(srsFilePath)
  }

  async init(): Promise<void> {}

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

    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      const key = replaceNullKeyWithPadding(ringKeys[i]!)
      ringKeysBytes.set(key, i * 32)
    }

    const pedersenProof = PedersenVRFProver.deserialize(
      result.proof.pedersenProof,
    )
    const keyCommitmentBytes = pedersenProof.Y_bar

    const ringProofBytes = result.proof.ringProof

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
        ringKeys.length,
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
