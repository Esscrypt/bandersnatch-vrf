import { readFileSync } from 'node:fs'
import { hexToBytes } from 'viem'
import {
  compute_ring_commitment,
  prove_ring_proof,
} from '../../wasm-ark-vrf/ark_vrf_wasm.js'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config.ts'
import { PedersenVRFProver } from './pedersen.ts'
import type { RingVRFInput, RingVRFResult } from './ring-kzg.ts'

function replaceNullKeyWithPadding(keyBytes: Uint8Array): Uint8Array {
  if (keyBytes.every((b) => b === 0)) {
    return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
  }
  return keyBytes
}

export class RingVRFProverWasm {
  private readonly srsBytes: Uint8Array

  constructor(srsFilePath: string) {
    this.srsBytes = readFileSync(srsFilePath)
  }

  async init(): Promise<void> {
  }

  prove(secretKey: Uint8Array, input: RingVRFInput): RingVRFResult {
    const pedersenInput = {
      input: input.input,
      auxData: input.auxData,
    }
    const pedersenResult = PedersenVRFProver.prove(secretKey, pedersenInput)

    const ringKeysBytes = new Uint8Array(input.ringKeys.length * 32)
    for (let i = 0; i < input.ringKeys.length; i++) {
      const key = replaceNullKeyWithPadding(input.ringKeys[i])
      ringKeysBytes.set(key, i * 32)
    }

    let ringCommitment: Uint8Array
    try {
      const commitmentBytes = compute_ring_commitment(
        this.srsBytes,
        ringKeysBytes,
        input.ringKeys.length,
      )
      ringCommitment = new Uint8Array(commitmentBytes)
    } catch (error) {
      console.error('[RingVRFProverWasm] Failed to compute ring commitment', {
        error: error instanceof Error ? error.message : String(error),
      })
      throw error
    }

    let ringProof: Uint8Array
    try {
      const blindingFactor = pedersenResult.blindingFactor

      const proofBytes = prove_ring_proof(
        this.srsBytes,
        ringKeysBytes,
        blindingFactor,
        input.proverIndex,
        input.ringKeys.length,
      )

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

  computeRingCommitment(ringKeys: Uint8Array[]): Uint8Array {
    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      const key = replaceNullKeyWithPadding(ringKeys[i])
      ringKeysBytes.set(key, i * 32)
    }

    const commitmentBytes = compute_ring_commitment(
      this.srsBytes,
      ringKeysBytes,
      ringKeys.length,
    )

    return new Uint8Array(commitmentBytes)
  }
}
