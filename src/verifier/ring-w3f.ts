/**
 * Ring VRF Verifier using Rust connector (native) or WASM bindings
 *
 * When the Rust connector (rust-ring-proof) is built, it handles w3f verify_ring_vrf
 * (index, RingVrfVerifier::init, verify). TypeScript handles validations and mapping
 * (vrf_input = hashToCurve(input), vrf_output = gamma, seed/padding/transcript from config).
 * Falls back to ark-vrf WASM (verify_ring_proof) when the native module is not available.
 */

import { readFileSync } from 'node:fs'
import { blake2b } from '@noble/hashes/blake2.js'
import { bytesToHex, hexToBytes } from 'viem'
import { verify_ring_proof } from '../../wasm-ark-vrf/ark_vrf_wasm'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config'
import { PedersenVRFProver } from '../prover/pedersen'
import type { RingVRFInput } from '../prover/ring-kzg'
import {
  getRustBatchVerifyRingVrf,
  getRustComputeRingVerifierKey,
  getRustVerifyRingVrf,
  getRustVerifyRingVrfWithKey,
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

  // Content-addressed LRU of serialized ring VerifierKeys, keyed by blake2b(ringKeys).
  // The ring is fixed per epoch, so this turns the expensive per-ticket index()+SRS work
  // into a once-per-ring computation. Self-invalidating: a changed ring hashes differently.
  private vkCache = new Map<string, Uint8Array>()
  private readonly VK_CACHE_CAP = 3

  constructor(srsFilePath: string) {
    this.srsBytes = readFileSync(srsFilePath)
  }

  async init(): Promise<void> {
    // No-op; kept for API compatibility
  }

  /** Get (or compute + cache) the serialized ring VerifierKey for these ring keys. */
  private getVerifierKey(ringKeysBytes: Uint8Array): Uint8Array | null {
    const compute = getRustComputeRingVerifierKey()
    if (!compute) return null
    const key = bytesToHex(blake2b(ringKeysBytes, { dkLen: 32 }))
    const hit = this.vkCache.get(key)
    if (hit) return hit
    const vk = compute(this.srsBytes, ringKeysBytes)
    if (this.vkCache.size >= this.VK_CACHE_CAP) {
      const oldest = this.vkCache.keys().next().value
      if (oldest !== undefined) this.vkCache.delete(oldest)
    }
    this.vkCache.set(key, vk)
    return vk
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

    const rustVerifyWithKey = getRustVerifyRingVrfWithKey()
    if (rustVerifyWithKey) {
      const pedersenProof = PedersenVRFProver.deserialize(
        result.proof.pedersenProof,
      )
      const keyCommitmentBytes = pedersenProof.Y_bar
      const vk = this.getVerifierKey(ringKeysBytes)
      if (vk) {
        try {
          return rustVerifyWithKey(
            vk,
            ringProofBytes,
            keyCommitmentBytes,
            ringKeys.length,
          )
        } catch (error) {
          console.error('[RingVRFVerifierW3F] Rust cached-VK verify failed', {
            error: error instanceof Error ? error.message : String(error),
          })
          return false
        }
      }
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

  /**
   * Verify many ring VRF proofs that share one ring in a single aggregated pairing check.
   * The per-entry Pedersen check stays per-entry (it has no pairing); only the ring-membership
   * proofs are batched. Returns true only if every entry is valid. Falls back to per-entry
   * `verify` when the native batch path is unavailable.
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

    const batchFn = getRustBatchVerifyRingVrf()
    if (!batchFn) {
      // No native batch: verify each entry individually (still uses the cached-VK fast path).
      return entries.every((e) =>
        this.verify(ringKeys, e.input, e.result, e.auxData),
      )
    }

    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      ringKeysBytes.set(replaceNullKeyWithPadding(ringKeys[i]!), i * 32)
    }

    const items: Array<{
      proofBytes: Uint8Array
      keyCommitmentBytes: Uint8Array
    }> = []
    for (const e of entries) {
      const pedersenValid = PedersenVRFVerifier.verify(
        e.input.input,
        e.result.gamma,
        e.result.proof.pedersenProof,
        e.auxData,
      )
      if (!pedersenValid) return false

      const ringProofBytes = e.result.proof.ringProof
      if (ringProofBytes.length === 784) {
        throw new Error(
          'Invalid ring proof: received full 784-byte structure instead of ring proof portion',
        )
      }
      const keyCommitmentBytes = PedersenVRFProver.deserialize(
        e.result.proof.pedersenProof,
      ).Y_bar
      items.push({ proofBytes: ringProofBytes, keyCommitmentBytes })
    }

    const vk = this.getVerifierKey(ringKeysBytes)
    if (!vk) {
      return entries.every((e) =>
        this.verify(ringKeys, e.input, e.result, e.auxData),
      )
    }
    try {
      return batchFn(vk, ringKeys.length, items)
    } catch (error) {
      console.error('[RingVRFVerifierW3F] Rust batch verify failed', {
        error: error instanceof Error ? error.message : String(error),
      })
      return false
    }
  }
}
