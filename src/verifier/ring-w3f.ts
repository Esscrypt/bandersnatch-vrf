/**
 * Ring VRF Verifier using Rust connector (native) or WASM bindings
 *
 * When a RingBackend is injected (ScriptC C ABI) or the default Node-API backend
 * resolves, ring membership goes through prepare + batchVerify. TypeScript still
 * handles Pedersen composition, null-key padding, and the 784-byte proof guard.
 * Falls back to ark-vrf WASM only when neither backend nor addon resolves.
 */

import { readFileSync } from 'node:fs'
import { hexToBytes } from 'viem'
import {
  createNapiRingBackend,
  loadWasmVerifyRingProof,
  type RingBackend,
  unwrapSyncBackendResult,
} from '../backends.ts'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config.ts'
import { PedersenVRFProver } from '../prover/pedersen.ts'
import type { RingVRFInput } from '../prover/ring-kzg.ts'
import { PedersenVRFVerifier } from './pedersen.ts'

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

function flattenRingKeys(ringKeys: Uint8Array[]): Uint8Array {
  const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
  for (let i = 0; i < ringKeys.length; i++) {
    ringKeysBytes.set(replaceNullKeyWithPadding(ringKeys[i]!), i * 32)
  }
  return ringKeysBytes
}

function assertRingProofNotFullStructure(ringProofBytes: Uint8Array): void {
  if (ringProofBytes.length === 784) {
    console.error(
      '[RingVRFVerifierW3F] ERROR: ringProof is 784 bytes - full structure, not ring proof only',
    )
    throw new Error(
      'Invalid ring proof: received full 784-byte structure instead of ring proof portion',
    )
  }
}

/**
 * Ring VRF Verifier (W3F): injected/default backend when available, else WASM.
 * Same verify API as RingVRFVerifierWasm.
 */
export class RingVRFVerifierW3F {
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
    this.srsBytes = readFileSync(srsFilePathOrOptions)
    this.backend = createNapiRingBackend(this.srsBytes)
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

    const ringProofBytes = result.proof.ringProof
    assertRingProofNotFullStructure(ringProofBytes)

    const ringKeysBytes = flattenRingKeys(ringKeys)
    const keyCommitmentBytes = PedersenVRFProver.deserialize(
      result.proof.pedersenProof,
    ).Y_bar

    if (this.backend) {
      try {
        const prepared = unwrapSyncBackendResult(
          this.backend.prepare(ringKeysBytes),
          'RingBackend.prepare',
        )
        return unwrapSyncBackendResult(
          this.backend.batchVerify(prepared.ring, ringKeys.length, [
            { proof: ringProofBytes, keyCommitment: keyCommitmentBytes },
          ]),
          'RingBackend.batchVerify',
        )
      } catch (error) {
        console.error('[RingVRFVerifierW3F] backend verify failed', {
          error: error instanceof Error ? error.message : String(error),
        })
        return false
      }
    }

    if (!this.srsBytes) {
      console.error('[RingVRFVerifierW3F] WASM verify requires SRS bytes')
      return false
    }

    try {
      const verifyRingProof = loadWasmVerifyRingProof()
      return verifyRingProof(
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

  /**
   * Verify many ring VRF proofs that share one ring in a single aggregated pairing check.
   * The per-entry Pedersen check stays per-entry (it has no pairing); only the ring-membership
   * proofs are batched. Returns true only if every entry is valid. Falls back to per-entry
   * `verify` when no backend is available.
   */
  verifyBatch(
    ringKeys: Uint8Array[],
    entries: Array<{
      input: RingVRFInput
      result: {
        gamma: Uint8Array
        proof: {
          pedersenProof: Uint8Array
          ringCommitment: Uint8Array
          ringProof: Uint8Array
        }
      }
      auxData?: Uint8Array
    }>,
  ): boolean {
    if (entries.length === 0) return true

    if (!this.backend) {
      return entries.every((e) =>
        this.verify(ringKeys, e.input, e.result, e.auxData),
      )
    }

    const items: Array<{ proof: Uint8Array; keyCommitment: Uint8Array }> = []
    for (const e of entries) {
      const pedersenValid = PedersenVRFVerifier.verify(
        e.input.input,
        e.result.gamma,
        e.result.proof.pedersenProof,
        e.auxData,
      )
      if (!pedersenValid) return false

      const ringProofBytes = e.result.proof.ringProof
      assertRingProofNotFullStructure(ringProofBytes)
      items.push({
        proof: ringProofBytes,
        keyCommitment: PedersenVRFProver.deserialize(
          e.result.proof.pedersenProof,
        ).Y_bar,
      })
    }

    try {
      const prepared = unwrapSyncBackendResult(
        this.backend.prepare(flattenRingKeys(ringKeys)),
        'RingBackend.prepare',
      )
      return unwrapSyncBackendResult(
        this.backend.batchVerify(prepared.ring, ringKeys.length, items),
        'RingBackend.batchVerify',
      )
    } catch (error) {
      console.error('[RingVRFVerifierW3F] backend batch verify failed', {
        error: error instanceof Error ? error.message : String(error),
      })
      return false
    }
  }
}
