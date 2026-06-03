/**
 * Differential test: cached-VerifierKey ring verify must agree byte-for-byte (in accept/reject)
 * with the legacy single-shot `verifyRingVrf`, on valid and tampered inputs.
 */

import { describe, it, expect } from 'bun:test'
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

function loadFixture() {
  const srs = readFileSync(SRS_PATH)
  const v = JSON.parse(readFileSync(VECTORS_PATH, 'utf-8'))[0]
  const ringKeys = hexToBytes(v.ring_pks)
  const ringSize = ringKeys.length / 32
  const proof = hexToBytes(v.ring_proof)
  const kc = hexToBytes(v.proof_pk_com)
  return { srs, ringKeys, ringSize, proof, kc }
}

// The TS verifier wrappers map a native throw (e.g. malformed bytes) to a rejection (`false`).
// Apply the same mapping here so the two paths are compared on equal footing.
function asReject(fn: () => boolean): boolean {
  try {
    return fn()
  } catch {
    return false
  }
}

describe('cached VerifierKey differential', () => {
  it('verify_ring_vrf_with_key accepts what verify_ring_vrf accepts', () => {
    const { srs, ringKeys, ringSize, proof, kc } = loadFixture()
    const legacy = native.verifyRingVrf(srs, proof, ringKeys, kc)
    const vk = native.computeRingVerifierKey(srs, ringKeys)
    const fast = native.verifyRingVrfWithKey(vk, proof, kc, ringSize)
    expect(legacy).toBe(true)
    expect(fast).toBe(true)
  })

  it('rejects a tampered proof, matching legacy', () => {
    const { srs, ringKeys, ringSize, proof, kc } = loadFixture()
    const bad = new Uint8Array(proof)
    bad[10] ^= 0xff
    const vk = native.computeRingVerifierKey(srs, ringKeys)
    const legacy = asReject(() => native.verifyRingVrf(srs, bad, ringKeys, kc))
    const fast = asReject(() => native.verifyRingVrfWithKey(vk, bad, kc, ringSize))
    expect(fast).toBe(legacy)
    expect(fast).toBe(false)
  })

  it('rejects a tampered key commitment, matching legacy', () => {
    const { srs, ringKeys, ringSize, proof, kc } = loadFixture()
    const badKc = new Uint8Array(kc)
    badKc[0] ^= 0x01
    const vk = native.computeRingVerifierKey(srs, ringKeys)
    const legacy = asReject(() => native.verifyRingVrf(srs, proof, ringKeys, badKc))
    const fast = asReject(() => native.verifyRingVrfWithKey(vk, proof, badKc, ringSize))
    expect(fast).toBe(legacy)
    expect(fast).toBe(false)
  })

  it('a VerifierKey computed once is reusable across verifications', () => {
    const { srs, ringKeys, ringSize, proof, kc } = loadFixture()
    const vk = native.computeRingVerifierKey(srs, ringKeys)
    for (let i = 0; i < 3; i++) {
      expect(native.verifyRingVrfWithKey(vk, proof, kc, ringSize)).toBe(true)
    }
  })
})
