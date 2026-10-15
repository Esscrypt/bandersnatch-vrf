import { blake2b } from '@noble/hashes/blake2.js'
import { bytesToHex } from 'viem'
import { getRustVerifyIetfVrf } from './prover/rust-ietf-vrf-wrapper.ts'
import {
  getRustBatchVerifyRingVrf,
  getRustComputeRingVerifierKey,
  getRustVerifyRingVrf,
  getRustVerifyRingVrfWithKey,
} from './prover/rust-ring-proof-wrapper.ts'

export type RingReference = { readonly id: number }

export interface RingBackend {
  prepare(
    ringKeys: Uint8Array,
  ):
    | Promise<{ commitment: Uint8Array; ring: RingReference }>
    | { commitment: Uint8Array; ring: RingReference }
  batchVerify(
    ring: RingReference,
    ringSize: number,
    items: Array<{ proof: Uint8Array; keyCommitment: Uint8Array }>,
  ): Promise<boolean> | boolean
}

export interface IetfBackend {
  verify(
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array,
    auxData: Uint8Array,
  ): Promise<boolean> | boolean
}

const VK_CACHE_CAP = 3

export function unwrapSyncBackendResult<T>(
  value: T | Promise<T>,
  label: string,
): T {
  if (
    value != null &&
    typeof value === 'object' &&
    typeof (value as Promise<T>).then === 'function'
  ) {
    throw new Error(
      `${label} returned a Promise; expected a synchronous backend`,
    )
  }
  return value as T
}

export function createNapiRingBackend(
  srsBytes: Uint8Array,
): RingBackend | null {
  const computeVk = getRustComputeRingVerifierKey()
  const batchFn = getRustBatchVerifyRingVrf()
  const verifyWithKey = getRustVerifyRingVrfWithKey()
  const verify = getRustVerifyRingVrf()
  if (!batchFn && !verifyWithKey && !verify) return null

  type StoredRing = {
    id: number
    hash: string
    ringKeys: Uint8Array
    vk: Uint8Array | null
  }

  const byHash = new Map<string, StoredRing>()
  const byId = new Map<number, StoredRing>()
  let nextRingId = 1

  const hashRingKeys = (ringKeys: Uint8Array): string =>
    bytesToHex(blake2b(ringKeys, { dkLen: 32 }))

  const evictOldest = (): void => {
    const oldest = byHash.keys().next().value
    if (oldest === undefined) return
    const stored = byHash.get(oldest)
    byHash.delete(oldest)
    if (stored) byId.delete(stored.id)
  }

  const touch = (stored: StoredRing): void => {
    byHash.delete(stored.hash)
    byHash.set(stored.hash, stored)
  }

  const getOrInsert = (ringKeys: Uint8Array): StoredRing => {
    const hash = hashRingKeys(ringKeys)
    const hit = byHash.get(hash)
    if (hit) {
      touch(hit)
      return hit
    }
    if (byHash.size >= VK_CACHE_CAP) evictOldest()
    const vk = computeVk ? computeVk(srsBytes, ringKeys) : null
    const stored: StoredRing = {
      id: nextRingId++,
      hash,
      ringKeys,
      vk,
    }
    byHash.set(hash, stored)
    byId.set(stored.id, stored)
    return stored
  }

  return {
    prepare(ringKeys: Uint8Array) {
      const stored = getOrInsert(ringKeys)
      return {
        commitment: new Uint8Array(144),
        ring: { id: stored.id },
      }
    },
    batchVerify(ring: RingReference, ringSize: number, items) {
      const stored = byId.get(ring.id)
      if (!stored) return false
      if (stored.vk && batchFn) {
        return batchFn(
          stored.vk,
          ringSize,
          items.map((item) => ({
            proofBytes: item.proof,
            keyCommitmentBytes: item.keyCommitment,
          })),
        )
      }
      if (stored.vk && verifyWithKey) {
        return items.every((item) =>
          verifyWithKey(
            stored.vk as Uint8Array,
            item.proof,
            item.keyCommitment,
            ringSize,
          ),
        )
      }
      if (verify) {
        return items.every((item) =>
          verify(srsBytes, item.proof, stored.ringKeys, item.keyCommitment),
        )
      }
      return false
    },
  }
}

export function createNapiIetfBackend(): IetfBackend | null {
  const verify = getRustVerifyIetfVrf()
  if (!verify) return null
  return {
    verify(publicKey, input, proof, auxData) {
      return verify(publicKey, input, proof, auxData)
    },
  }
}
