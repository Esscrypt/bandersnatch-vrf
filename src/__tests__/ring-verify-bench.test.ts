/**
 * Ring VRF verifier benchmark — before/after profiling harness.
 *
 * Runs only when BENCH=1. Writes results to BENCH_OUT (JSON).
 *
 * Measures, per ring size:
 *   - legacy_verify_ms       : full legacy `verifyRingVrf` (SRS deser + index() + pairing).
 *                              Only available at the test-vector ring size (a real valid proof).
 *   - per_ticket_index_ms    : `computeRingCommitment` = SRS-deserialize + index() MSM over the ring.
 *                              This is exactly the per-ticket overhead Component 1 caches away, so it
 *                              is the headline number for the cached-VerifierKey win and it scales with
 *                              ring size (tiny=6 → full=1023).
 *   - cachedvk_verify_ms     : 1× computeRingVerifierKey + verifyRingVrfWithKey  (present only after change)
 *   - batch_ms               : batchVerifyRingVrf over N proofs                   (present only after change)
 */

import { describe, it, expect } from 'bun:test'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
// biome-ignore lint/suspicious/noExplicitAny: native addon has no shared d.ts here
const native: any = require('../../rust-ring-proof/native')

const RUN = process.env.BENCH === '1' || process.env.BENCH === 'true'
const BENCH_OUT = process.env.BENCH_OUT || join(__dirname, '../../../../docs/superpowers/specs/ring-verify-current.json')
const ITERS = Number(process.env.BENCH_ITERS ?? '50')

const SRS_PATH = join(__dirname, 'test-data/srs/zcash-srs-2-16-uncompressed.bin')
const VECTORS_PATH = join(__dirname, 'vectors/bandersnatch_sha-512_ell2_ring.json')

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}

function concatKeys(keys: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(keys.length * 32)
  keys.forEach((k, i) => out.set(k, i * 32))
  return out
}

// Build a ring of `n` valid bandersnatch pubkeys by cycling the vector's keys.
function buildRing(baseKeys: Uint8Array[], n: number): Uint8Array {
  const keys: Uint8Array[] = []
  for (let i = 0; i < n; i++) keys.push(baseKeys[i % baseKeys.length])
  return concatKeys(keys)
}

function timeIt(fn: () => void, iters: number): { mean_ms: number; p95_ms: number } {
  const samples: number[] = []
  for (let i = 0; i < iters; i++) {
    const t0 = performance.now()
    fn()
    samples.push(performance.now() - t0)
  }
  samples.sort((a, b) => a - b)
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length
  const p95 = samples[Math.floor(samples.length * 0.95)] ?? samples[samples.length - 1]
  return { mean_ms: Number(mean.toFixed(4)), p95_ms: Number(p95.toFixed(4)) }
}

describe('ring verify benchmark', () => {
  it.skipIf(!RUN)('profiles ring verification across ring sizes', () => {
    const srs = readFileSync(SRS_PATH)
    const vectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf-8'))
    const v = vectors[0]

    // distinct valid proofs over one shared ring, for the batch measurement
    const counts = new Map<string, number>()
    for (const e of vectors) counts.set(e.ring_pks, (counts.get(e.ring_pks) ?? 0) + 1)
    const sharedRingHex = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0]
    const sharedVectors = vectors.filter(
      (e: { ring_pks: string }) => e.ring_pks === sharedRingHex,
    )

    const baseKeys: Uint8Array[] = []
    const ringPks = hexToBytes(v.ring_pks)
    for (let i = 0; i < ringPks.length; i += 32) baseKeys.push(ringPks.slice(i, i + 32))

    const vectorRing = concatKeys(baseKeys) // the real ring (size 8) with a valid proof
    const ringProof = hexToBytes(v.ring_proof) // 592-byte ring proof portion
    const keyCommitment = hexToBytes(v.proof_pk_com) // Y_bar (32 bytes)

    // sanity: the vector proof must verify under the legacy path
    const legacyOk = native.verifyRingVrf(srs, ringProof, vectorRing, keyCommitment)
    expect(legacyOk).toBe(true)

    const SIZES = [6, baseKeys.length, 256, 1023]
    const results: Record<string, unknown> = {
      iters: ITERS,
      srs: 'zcash-srs-2-16',
      vector_ring_size: baseKeys.length,
      rings: {},
    }

    for (const n of SIZES) {
      const ring = buildRing(baseKeys, n)
      const row: Record<string, unknown> = { ring_size: n }

      // headline: per-ticket index() + SRS deserialize cost (cached away by Component 1)
      row.per_ticket_index = timeIt(() => {
        native.computeRingCommitment(srs, ring)
      }, ITERS)

      // legacy full verify only available where we have a real valid proof (the vector ring size)
      if (n === baseKeys.length) {
        row.legacy_verify = timeIt(() => {
          native.verifyRingVrf(srs, ringProof, vectorRing, keyCommitment)
        }, ITERS)
      }

      // after-change paths (guarded; absent on the baseline build)
      if (typeof native.computeRingVerifierKey === 'function' && typeof native.verifyRingVrfWithKey === 'function') {
        // compute_vk is the once-per-epoch cost (amortized across all of the epoch's tickets)
        row.compute_vk = timeIt(() => {
          native.computeRingVerifierKey(srs, ring)
        }, ITERS)

        // cachedvk_verify is the real PER-TICKET cost after caching: the vk is computed ONCE
        // (outside the timed loop) and only verifyRingVrfWithKey runs per ticket.
        if (n === baseKeys.length) {
          const vk = native.computeRingVerifierKey(srs, vectorRing)
          row.cachedvk_verify = timeIt(() => {
            native.verifyRingVrfWithKey(vk, ringProof, keyCommitment, baseKeys.length)
          }, ITERS)
        }
      }

      ;(results.rings as Record<string, unknown>)[String(n)] = row
      // eslint-disable-next-line no-console
      console.log(`ring_size=${n}`, JSON.stringify(row))
    }

    // --- batch vs per-proof at the shared ring (N tickets) ---
    if (
      typeof native.batchVerifyRingVrf === 'function' &&
      typeof native.computeRingVerifierKey === 'function' &&
      typeof native.verifyRingVrfWithKey === 'function' &&
      sharedVectors.length >= 2
    ) {
      const ringKeys = hexToBytes(sharedRingHex)
      const ringSz = ringKeys.length / 32
      const vk = native.computeRingVerifierKey(srs, ringKeys)
      const base = sharedVectors.map((e: { ring_proof: string; proof_pk_com: string }) => ({
        proofBytes: Buffer.from(hexToBytes(e.ring_proof)),
        keyCommitmentBytes: Buffer.from(hexToBytes(e.proof_pk_com)),
      }))
      const batchRows: Record<string, unknown> = { ring_size: ringSz }
      for (const N of [2, 8, 16]) {
        const items = Array.from({ length: N }, (_, i) => base[i % base.length])
        const perProof = timeIt(() => {
          for (const it of items)
            native.verifyRingVrfWithKey(vk, it.proofBytes, it.keyCommitmentBytes, ringSz)
        }, ITERS)
        const batched = timeIt(() => {
          native.batchVerifyRingVrf(vk, ringSz, items)
        }, ITERS)
        batchRows[`N${N}`] = {
          per_proof_cachedvk: perProof,
          batched,
          speedup: Number((perProof.mean_ms / batched.mean_ms).toFixed(2)),
        }
        console.log(`batch N=${N}`, JSON.stringify(batchRows[`N${N}`]))
      }
      results.batch = batchRows
    }

    writeFileSync(BENCH_OUT, JSON.stringify(results, null, 2))
    // eslint-disable-next-line no-console
    console.log(`\n📊 benchmark written to ${BENCH_OUT}`)
  }, 600_000)
})
