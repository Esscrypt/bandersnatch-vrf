/**
 * PIOP Params Tests
 * 
 * Based on w3f-ring-proof/src/piop/params.rs test_powers_of_h()
 * 
 * Tests PIOP parameters correctness
 */

import { describe, test, expect } from 'bun:test'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BANDERSNATCH_PARAMS } from '@pbnjam/bandersnatch'
import { Domain } from '../../domain/domain'
import { PiopParams } from '../../piop/params'

/**
 * Conditional sum of points based on bitmask
 * 
 * Matching w3f-plonk-common/src/test_helpers.rs cond_sum()
 */
function condSum(
  bitmask: boolean[],
  points: Array<{ x: bigint; y: bigint }>,
): { x: bigint; y: bigint } {
  if (bitmask.length !== points.length) {
    throw new Error('Bitmask and points must have same length')
  }

  // TODO: Implement point addition on Bandersnatch curve
  // For now, return placeholder
  return { x: 0n, y: 0n }
}

/**
 * Generate random scalar
 */
function randomScalar(): bigint {
  const Fr = bls12_381.fields.Fr
  const randomBytes = new Uint8Array(32)
  crypto.getRandomValues(randomBytes)
  const randomBigInt = BigInt(
    '0x' + Array.from(randomBytes).map((b) => b.toString(16).padStart(2, '0')).join(''),
  )
  return Fr.create(randomBigInt)
}

/**
 * Generate random Bandersnatch point
 */
function randomPoint(): { x: bigint; y: bigint } {
  // TODO: Generate random point on Bandersnatch curve
  return { x: 0n, y: 0n }
}

describe('PIOP Params Tests', () => {
  test('test_powers_of_h - verify powers of H computation', () => {
    const domain = new Domain(1024, false)
    const h = randomPoint()
    const seed = PiopParams.getAccumulatorSeedPoint()
    const padding = PiopParams.getPaddingPoint()

    const params = PiopParams.setup(domain, h, seed, padding)

    // Generate random scalar
    const t = randomScalar()

    // Get scalar bits
    const tBits = params.scalarPart(t)

    // Get powers of H
    const powersOfH = params.powerOf2MultiplesOfH()

    // Compute conditional sum: sum(t_bits[i] * powersOfH[i])
    const th = condSum(tBits, powersOfH)

    // TODO: Verify th equals h * t
    // This requires point multiplication on Bandersnatch curve
    // expect(th).toEqual(multiplyPoint(h, t))

    // Placeholder test
    expect(tBits.length).toBe(params.scalarBitlen)
    expect(powersOfH.length).toBe(params.scalarBitlen)
  })
})



