import { readFileSync } from 'node:fs'
import { hexToBytes } from 'viem'
import { type RingBackend, unwrapSyncBackendResult } from '../backends.ts'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config.ts'
import { PedersenVRFProver } from './pedersen.ts'
import type { RingVRFInput, RingVRFResult } from './ring-kzg.ts'
import {
  getRustComputeRingCommitment,
  getRustProveRingProof,
} from './rust-ring-proof-wrapper.ts'

const RUST_REQUIRED_MSG =
  'Ring VRF prover requires the Rust native module (rust-ring-proof). Build with: cd rust-ring-proof && bun run build'

function replaceNullKeyWithPadding(keyBytes: Uint8Array): Uint8Array {
  if (keyBytes.every((b) => b === 0)) {
    return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
  }
  return keyBytes
}

export class RingVRFProverW3F {
  private readonly srsBytes: Uint8Array | null
  private readonly backend: RingBackend | null

  constructor(srsFilePath: string)
  constructor(options: { backend: RingBackend })
  constructor(srsFilePathOrOptions: string | { backend: RingBackend }) {
    if (typeof srsFilePathOrOptions === 'object') {
      this.backend = srsFilePathOrOptions.backend
      this.srsBytes = null
      return
    }
    this.backend = null
    this.srsBytes = readFileSync(srsFilePathOrOptions)
  }

  async init(): Promise<void> {
  }

  prove(secretKey: Uint8Array, input: RingVRFInput): RingVRFResult {
    if (this.backend) {
      throw new Error('Ring VRF proving is unavailable on this runtime')
    }
    if (!this.srsBytes) {
      throw new Error('Ring VRF proving is unavailable on this runtime')
    }

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

  computeRingCommitment(ringKeys: Uint8Array[]): Uint8Array {
    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      const key = replaceNullKeyWithPadding(ringKeys[i])
      ringKeysBytes.set(key, i * 32)
    }

    if (this.backend) {
      const prepared = unwrapSyncBackendResult(
        this.backend.prepare(ringKeysBytes),
        'RingBackend.prepare',
      )
      return prepared.commitment
    }
    if (!this.srsBytes) {
      throw new Error('Ring VRF proving is unavailable on this runtime')
    }

    const rustCompute = getRustComputeRingCommitment()
    if (!rustCompute) {
      throw new Error(RUST_REQUIRED_MSG)
    }
    return rustCompute(this.srsBytes, ringKeysBytes)
  }
}
