/**
 * End-to-End Plonk Test
 * 
 * Based on w3f-ring-proof/src/lib.rs test_ring_proof_kzg()
 * 
 * Tests the full Plonk prover/verifier flow for ring proofs
 */

import { describe, test, expect } from 'bun:test'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BANDERSNATCH_PARAMS, BandersnatchCurve } from '@pbnjam/bandersnatch'
import { Domain } from '../domain/domain'
import { PiopParams } from '../piop/params'
import { PiopProver } from '../piop/prover'
import { PiopVerifier } from '../piop/verifier'
import { index } from '../piop/mod'
import type { ProverKey, VerifierKey } from '../piop/mod'
import { PlonkProver } from '../prover'
import { PlonkVerifier } from '../verifier'
import { SimplePlonkTranscript } from '../transcript/transcript'

/**
 * Setup PCS params and PIOP params
 * 
 * Matching Rust: setup() function
 */
function setup(domainSize: number): {
  // pcsParams: unknown // TODO: PCS params
  piopParams: PiopParams
} {
  // TODO: Setup PCS params (KZG with SRS)
  // const setupDegree = 3 * domainSize
  // const pcsParams = KZG.setup(setupDegree, rng)

  // Setup PIOP params
  const domain = new Domain(domainSize, true) // hiding = true
  const h = { x: 0n, y: 0n } // TODO: Random point
  const seed = PiopParams.getAccumulatorSeedPoint()
  const padding = PiopParams.getPaddingPoint()
  const piopParams = PiopParams.setup(domain, h, seed, padding)

  return {
    // pcsParams,
    piopParams,
  }
}

/**
 * Generate random Bandersnatch point
 */
function randomPoint(): { x: bigint; y: bigint } {
  // TODO: Generate random point on Bandersnatch curve
  // For now, return placeholder
  return { x: 0n, y: 0n }
}

/**
 * Generate random scalar
 */
function randomScalar(): bigint {
  const Fr = bls12_381.fields.Fr
  // Generate random field element
  const randomBytes = new Uint8Array(32)
  crypto.getRandomValues(randomBytes)
  const randomBigInt = BigInt(
    '0x' + Array.from(randomBytes).map((b) => b.toString(16).padStart(2, '0')).join(''),
  )
  return Fr.create(randomBigInt)
}

describe('Plonk End-to-End Tests', () => {
  test('test_ring_proof - full prover/verifier flow', () => {
    const domainSize = 2 ** 10 // 1024
    const { piopParams } = setup(domainSize)

    // Generate random ring keys
    const maxKeysetSize = piopParams.keysetPartSize
    const keysetSize = Math.floor(Math.random() * maxKeysetSize)
    const pks: Array<{ x: bigint; y: bigint }> = []
    for (let i = 0; i < keysetSize; i++) {
      pks.push(randomPoint())
    }

    const k = Math.floor(Math.random() * keysetSize) // Prover's index
    const pk = pks[k]!

    // TODO: Create prover and verifier keys
    // const [proverKey, verifierKey] = index(pcsParams, piopParams, pks)

    // Generate proof
    const secret = randomScalar() // Prover's secret scalar
    // result = h * secret + pk
    // TODO: Compute result point

    // TODO: Create PlonkProver
    // const plonkProver = PlonkProver.init(pcsCk, verifierKey, transcript)
    // const piopProver = PiopProver.build(piopParams, fixedColumns, k, secret)
    // const proof = plonkProver.prove(piopProver)

    // TODO: Create PlonkVerifier
    // const plonkVerifier = PlonkVerifier.init(pcsVk, verifierKey, transcript)
    // const res = plonkVerifier.verify(piopVerifier, proof, result)

    // expect(res).toBe(true)

    // Placeholder test - will be implemented when PlonkProver/PlonkVerifier are ready
    expect(piopParams).toBeDefined()
    expect(pks.length).toBe(keysetSize)
  })

  test('test_lagrangian_commitment - verify ring commitment matches', () => {
    const domainSize = 2 ** 9 // 512
    const { piopParams } = setup(domainSize)

    // TODO: Setup PCS params and ring builder key
    // const pcsParams = KZG.setup(...)
    // const ringBuilderKey = RingBuilderKey.from_srs(pcsParams, domainSize)

    const maxKeysetSize = piopParams.keysetPartSize
    const keysetSize = Math.floor(Math.random() * maxKeysetSize)
    const pks: Array<{ x: bigint; y: bigint }> = []
    for (let i = 0; i < keysetSize; i++) {
      pks.push(randomPoint())
    }

    // TODO: Create verifier key
    // const [_, verifierKey] = index(pcsParams, piopParams, pks)

    // TODO: Create ring and compute fixed columns committed
    // const ring = Ring.with_keys(piopParams, pks, ringBuilderKey)
    // const fixedColumnsCommitted = FixedColumnsCommitted.from_ring(ring)

    // TODO: Assert commitments match
    // expect(fixedColumnsCommitted).toEqual(verifierKey.fixedColumnsCommitted)

    // Placeholder test
    expect(piopParams).toBeDefined()
  })
})

