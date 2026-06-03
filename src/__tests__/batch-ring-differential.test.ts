/**
 * Differential test: batched ring verification must agree (accept/reject) with per-proof
 * verification. Uses the two distinct valid test-vector proofs that share one ring.
 */

import { describe, expect, it } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
// biome-ignore lint/suspicious/noExplicitAny: native addon has no shared d.ts here
const native: any = require('../../rust-ring-proof/native')

const SRS_PATH = join(__dirname, 'test-data/srs/zcash-srs-2-16-uncompressed.bin')
const VECTORS_PATH = join(__dirname, 'vectors/bandersnatch_sha-512_ell2_ring.json')

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}

function flip(b: Uint8Array, i = 10): Uint8Array {
  const c = new Uint8Array(b)
  c[i] ^= 0xff
  return c
}

function load() {
  const srs = readFileSync(SRS_PATH)
  const vectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf-8'))
  // pick the ring shared by the most vectors
  const counts = new Map<string, number>()
  for (const v of vectors) counts.set(v.ring_pks, (counts.get(v.ring_pks) ?? 0) + 1)
  const topRing = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0]
  const shared = vectors.filter((v: { ring_pks: string }) => v.ring_pks === topRing)
  const ringKeys = hexToBytes(topRing)
  const ringSize = ringKeys.length / 32
  const vk = native.computeRingVerifierKey(srs, ringKeys)
  const items = shared.map((v: { ring_proof: string; proof_pk_com: string }) => ({
    proofBytes: Buffer.from(hexToBytes(v.ring_proof)),
    keyCommitmentBytes: Buffer.from(hexToBytes(v.proof_pk_com)),
  }))
  return { srs, ringKeys, ringSize, vk, items }
}

describe('batch ring verification differential', () => {
  it('has at least two distinct valid proofs over one ring', () => {
    const { items } = load()
    expect(items.length).toBeGreaterThanOrEqual(2)
  })

  it('each proof verifies singly (cached-VK path)', () => {
    const { vk, ringSize, items } = load()
    for (const it of items) {
      expect(native.verifyRingVrfWithKey(vk, it.proofBytes, it.keyCommitmentBytes, ringSize)).toBe(true)
    }
  })

  it('accepts the batch of all valid proofs', () => {
    const { vk, ringSize, items } = load()
    expect(native.batchVerifyRingVrf(vk, ringSize, items)).toBe(true)
  })

  it('a single-item batch equals single verify', () => {
    const { vk, ringSize, items } = load()
    expect(native.batchVerifyRingVrf(vk, ringSize, [items[0]])).toBe(true)
  })

  it('accepts a larger batch with repeats (all valid)', () => {
    const { vk, ringSize, items } = load()
    const big = [items[0], items[1], items[0], items[1]]
    expect(native.batchVerifyRingVrf(vk, ringSize, big)).toBe(true)
  })

  it('rejects the batch if any proof is tampered', () => {
    const { vk, ringSize, items } = load()
    const bad = [items[0], { ...items[1], proofBytes: Buffer.from(flip(items[1].proofBytes)) }]
    // tampering may yield non-deserializable bytes (native throws) or a deserializable-but-invalid
    // proof (returns false). Both are rejections — map throw->false, as the TS wrapper does.
    let result: boolean
    try {
      result = native.batchVerifyRingVrf(vk, ringSize, bad)
    } catch {
      result = false
    }
    expect(result).toBe(false)
  })

  it('rejects the batch if a key commitment is swapped', () => {
    const { vk, ringSize, items } = load()
    // swap commitments between the two proofs -> both openings now bind the wrong key
    const swapped = [
      { proofBytes: items[0].proofBytes, keyCommitmentBytes: items[1].keyCommitmentBytes },
      { proofBytes: items[1].proofBytes, keyCommitmentBytes: items[0].keyCommitmentBytes },
    ]
    expect(native.batchVerifyRingVrf(vk, ringSize, swapped)).toBe(false)
  })
})
