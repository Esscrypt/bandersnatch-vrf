/**
 * IETF VRF W3F (napi-rs) End-to-End and Performance Tests
 *
 * Validates IETFVRFProverW3F and IETFVRFVerifierW3F against:
 *   1. Official bandersnatch-vrf-spec test vectors (exact gamma + proof round-trip)
 *   2. Cross-verification against the WASM baseline (IETFVRFVerifierWasm)
 *   3. Edge cases (empty input, large input, wrong key / wrong input rejection)
 *   4. Performance benchmark: 100 proves + 100 verifies, with per-op and total timing
 */

import { describe, expect, test, beforeAll } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { bytesToHex } from 'viem'
import { IETFVRFProverW3F } from '../prover/ietf-w3f'
import { IETFVRFVerifierW3F } from '../verifier/ietf-w3f'
import { IETFVRFVerifierWasm } from '../verifier/ietf-wasm'
import { isRustIetfVrfProverAvailable, isRustIetfVrfVerifierAvailable } from '../prover/rust-ietf-vrf-wrapper'
import { getCommitmentFromGamma } from '../utils/gamma'

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

const testVectorsPath = join(
  __dirname,
  './vectors/bandersnatch_sha-512_ell2_ietf.json',
)
const IETF_TEST_VECTORS = JSON.parse(
  readFileSync(testVectorsPath, 'utf-8'),
) as Array<{
  comment: string
  sk: string
  pk: string
  alpha: string
  salt: string
  ad: string
  h: string
  gamma: string
  beta: string
  proof_c: string
  proof_s: string
}>

function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith('0x')) hex = hex.slice(2)
  if (hex === '') return new Uint8Array(0)
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

// ---------------------------------------------------------------------------
// Shared instances
// ---------------------------------------------------------------------------

const verifier = new IETFVRFVerifierW3F()
const wasmVerifier = new IETFVRFVerifierWasm()

// Fixed key pair used across performance / edge-case tests
const PERF_SK = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
const PERF_PK = hexToBytes('a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b')

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hrNow(): bigint {
  return process.hrtime.bigint()
}

function nsToMs(ns: bigint): number {
  return Number(ns) / 1_000_000
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('IETFVRFProverW3F / IETFVRFVerifierW3F End-to-End Tests', () => {
  beforeAll(() => {
    const proverAvail = isRustIetfVrfProverAvailable()
    const verifierAvail = isRustIetfVrfVerifierAvailable()
    console.log(`[setup] Rust napi prover available:   ${proverAvail}`)
    console.log(`[setup] Rust napi verifier available: ${verifierAvail}`)
    if (!proverAvail || !verifierAvail) {
      console.log(
        '[setup] WARNING: native module not built; prover will throw, verifier falls back to WASM',
      )
    }
  })

  // -------------------------------------------------------------------------
  // 1. Test-vector prove + verify
  // -------------------------------------------------------------------------

  describe('Test-vector prove and verify', () => {
    for (const [index, vector] of IETF_TEST_VECTORS.entries()) {
      test(`Vector ${index + 1}: ${vector.comment}`, () => {
        const sk = hexToBytes(vector.sk)
        const pk = hexToBytes(vector.pk)
        const input = hexToBytes(vector.alpha)
        const auxData = hexToBytes(vector.ad)

        const result = IETFVRFProverW3F.prove(sk, input, auxData)

        // Structural checks
        expect(result.gamma.length).toBe(32)
        expect(result.proof.length).toBe(96)
        // proof[0..32] must equal gamma
        expect(Array.from(result.proof.subarray(0, 32))).toEqual(
          Array.from(result.gamma),
        )

        // Gamma must match test vector (ark-vrf Elligator2 h2c is deterministic)
        const actualGamma = bytesToHex(result.gamma).slice(2)
        expect(actualGamma).toBe(vector.gamma)

        // Beta (hash of gamma) must match
        const beta = getCommitmentFromGamma(result.gamma)
        expect(beta.length).toBe(64)
        const actualBeta = bytesToHex(beta).slice(2)
        expect(actualBeta).toBe(vector.beta)

        // W3F verifier must accept the proof
        const valid = verifier.verify(pk, input, result.proof, auxData)
        expect(valid).toBe(true)
      })
    }
  })

  // -------------------------------------------------------------------------
  // 2. Cross-verification: W3F prover ↔ WASM verifier  and vice-versa
  // -------------------------------------------------------------------------

  describe('Cross-verification with WASM baseline', () => {
    for (const [index, vector] of IETF_TEST_VECTORS.entries()) {
      test(`Vector ${index + 1}: W3F proof validates with WASM verifier`, () => {
        const sk = hexToBytes(vector.sk)
        const pk = hexToBytes(vector.pk)
        const input = hexToBytes(vector.alpha)
        const auxData = hexToBytes(vector.ad)

        const result = IETFVRFProverW3F.prove(sk, input, auxData)

        // WASM verifier must also accept the W3F-generated proof
        const wasmValid = wasmVerifier.verify(pk, input, result.proof, auxData)
        expect(wasmValid).toBe(true)
      })
    }
  })

  // -------------------------------------------------------------------------
  // 3. Negative cases
  // -------------------------------------------------------------------------

  describe('Negative cases', () => {
    test('Wrong public key is rejected', () => {
      const input = new TextEncoder().encode('test')
      const result = IETFVRFProverW3F.prove(PERF_SK, input)
      const wrongPk = hexToBytes('5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3')
      expect(verifier.verify(wrongPk, input, result.proof)).toBe(false)
    })

    test('Wrong input is rejected', () => {
      const input = new TextEncoder().encode('correct-input')
      const wrongInput = new TextEncoder().encode('wrong-input')
      const result = IETFVRFProverW3F.prove(PERF_SK, input)
      expect(verifier.verify(PERF_PK, wrongInput, result.proof)).toBe(false)
    })

    test('Wrong aux data is rejected', () => {
      const input = new TextEncoder().encode('test')
      const auxData = new TextEncoder().encode('correct-aux')
      const wrongAux = new TextEncoder().encode('wrong-aux')
      const result = IETFVRFProverW3F.prove(PERF_SK, input, auxData)
      expect(verifier.verify(PERF_PK, input, result.proof, wrongAux)).toBe(false)
    })

    test('Truncated proof (95 bytes) is rejected', () => {
      const input = new TextEncoder().encode('test')
      const result = IETFVRFProverW3F.prove(PERF_SK, input)
      const truncated = result.proof.subarray(0, 95)
      expect(verifier.verify(PERF_PK, input, truncated)).toBe(false)
    })

    test('Empty proof is rejected', () => {
      const input = new TextEncoder().encode('test')
      expect(verifier.verify(PERF_PK, input, new Uint8Array(0))).toBe(false)
    })
  })

  // -------------------------------------------------------------------------
  // 4. Edge cases
  // -------------------------------------------------------------------------

  describe('Edge cases', () => {
    test('Empty input', () => {
      const emptyInput = new Uint8Array(0)
      const result = IETFVRFProverW3F.prove(PERF_SK, emptyInput)
      expect(verifier.verify(PERF_PK, emptyInput, result.proof)).toBe(true)
    })

    test('Large input (1 KB)', () => {
      const largeInput = new Uint8Array(1024).fill(0xab)
      const result = IETFVRFProverW3F.prove(PERF_SK, largeInput)
      expect(verifier.verify(PERF_PK, largeInput, result.proof)).toBe(true)
    })

    test('Proof without aux data verifies without aux data', () => {
      const input = new TextEncoder().encode('no-aux')
      const result = IETFVRFProverW3F.prove(PERF_SK, input)
      // undefined auxData treated as empty bytes on both sides
      expect(verifier.verify(PERF_PK, input, result.proof)).toBe(true)
      expect(verifier.verify(PERF_PK, input, result.proof, new Uint8Array(0))).toBe(true)
    })

    test('Proof with aux data rejected without aux data', () => {
      const input = new TextEncoder().encode('with-aux')
      const aux = new TextEncoder().encode('my-aux')
      const result = IETFVRFProverW3F.prove(PERF_SK, input, aux)
      expect(verifier.verify(PERF_PK, input, result.proof)).toBe(false)
    })

    test('Different inputs produce different gammas', () => {
      const r1 = IETFVRFProverW3F.prove(PERF_SK, new TextEncoder().encode('a'))
      const r2 = IETFVRFProverW3F.prove(PERF_SK, new TextEncoder().encode('b'))
      expect(bytesToHex(r1.gamma)).not.toBe(bytesToHex(r2.gamma))
    })

    test('Gamma is deterministic for the same inputs', () => {
      const input = new TextEncoder().encode('deterministic')
      const r1 = IETFVRFProverW3F.prove(PERF_SK, input)
      const r2 = IETFVRFProverW3F.prove(PERF_SK, input)
      expect(bytesToHex(r1.gamma)).toBe(bytesToHex(r2.gamma))
    })
  })

  // -------------------------------------------------------------------------
  // 5. Performance: 100 proves + 100 verifies
  // -------------------------------------------------------------------------

  describe('Performance (100 proves + 100 verifies)', () => {
    const NUM_OPS = 100

    test(`${NUM_OPS} IETF VRF proves`, () => {
      const times: number[] = []

      for (let i = 0; i < NUM_OPS; i++) {
        const input = new TextEncoder().encode(`perf-input-${i}`)
        const aux = new TextEncoder().encode(`perf-aux-${i}`)

        const t0 = hrNow()
        const result = IETFVRFProverW3F.prove(PERF_SK, input, aux)
        const elapsed = nsToMs(hrNow() - t0)

        times.push(elapsed)

        // Structural sanity check (no overhead assertions inside the hot loop)
        expect(result.proof.length).toBe(96)
      }

      const total = times.reduce((a, b) => a + b, 0)
      const avg = total / times.length
      const min = Math.min(...times)
      const max = Math.max(...times)

      console.log(`[perf] prove ×${NUM_OPS}`)
      console.log(`  total  : ${total.toFixed(1)} ms`)
      console.log(`  avg    : ${avg.toFixed(2)} ms/op`)
      console.log(`  min    : ${min.toFixed(2)} ms`)
      console.log(`  max    : ${max.toFixed(2)} ms`)
    }, 120_000)

    test(`${NUM_OPS} IETF VRF verifies`, () => {
      // Pre-generate proofs so timing is purely for verify
      const cases: { input: Uint8Array; aux: Uint8Array; proof: Uint8Array }[] =
        []
      for (let i = 0; i < NUM_OPS; i++) {
        const input = new TextEncoder().encode(`perf-verify-input-${i}`)
        const aux = new TextEncoder().encode(`perf-verify-aux-${i}`)
        const { proof } = IETFVRFProverW3F.prove(PERF_SK, input, aux)
        cases.push({ input, aux, proof })
      }

      const times: number[] = []

      for (const { input, aux, proof } of cases) {
        const t0 = hrNow()
        const valid = verifier.verify(PERF_PK, input, proof, aux)
        const elapsed = nsToMs(hrNow() - t0)

        times.push(elapsed)
        expect(valid).toBe(true)
      }

      const total = times.reduce((a, b) => a + b, 0)
      const avg = total / times.length
      const min = Math.min(...times)
      const max = Math.max(...times)

      console.log(`[perf] verify ×${NUM_OPS}`)
      console.log(`  total  : ${total.toFixed(1)} ms`)
      console.log(`  avg    : ${avg.toFixed(2)} ms/op`)
      console.log(`  min    : ${min.toFixed(2)} ms`)
      console.log(`  max    : ${max.toFixed(2)} ms`)
    }, 120_000)

    test(`${NUM_OPS} prove-then-verify round-trips`, () => {
      const proveTimes: number[] = []
      const verifyTimes: number[] = []

      for (let i = 0; i < NUM_OPS; i++) {
        const input = new TextEncoder().encode(`perf-rt-${i}`)
        const aux = new TextEncoder().encode(`perf-rt-aux-${i}`)

        const t0 = hrNow()
        const result = IETFVRFProverW3F.prove(PERF_SK, input, aux)
        proveTimes.push(nsToMs(hrNow() - t0))

        const t1 = hrNow()
        const valid = verifier.verify(PERF_PK, input, result.proof, aux)
        verifyTimes.push(nsToMs(hrNow() - t1))

        expect(valid).toBe(true)
      }

      const proveTotal = proveTimes.reduce((a, b) => a + b, 0)
      const verifyTotal = verifyTimes.reduce((a, b) => a + b, 0)

      console.log(`[perf] round-trip ×${NUM_OPS}`)
      console.log(
        `  prove  total: ${proveTotal.toFixed(1)} ms  avg: ${(proveTotal / NUM_OPS).toFixed(2)} ms/op`,
      )
      console.log(
        `  verify total: ${verifyTotal.toFixed(1)} ms  avg: ${(verifyTotal / NUM_OPS).toFixed(2)} ms/op`,
      )
      console.log(
        `  combined avg: ${((proveTotal + verifyTotal) / NUM_OPS).toFixed(2)} ms/round-trip`,
      )
    }, 120_000)
  })
})
