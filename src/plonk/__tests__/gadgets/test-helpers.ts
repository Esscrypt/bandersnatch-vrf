/**
 * Test Helpers for Gadget Tests
 * 
 * Matching w3f-plonk-common/src/test_helpers.rs
 */

import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BandersnatchCurve, BANDERSNATCH_PARAMS, mod, modInverse } from '@pbnjam/bandersnatch'

const Fr = bls12_381.fields.Fr

/**
 * Generate random boolean vector
 * 
 * Matching Rust: random_bitvec(n, density, rng)
 * 
 * @param n - Number of bits
 * @param density - Probability of true (0.0 to 1.0)
 * @returns Array of n booleans
 */
export function randomBitVec(n: number, density: number = 0.5): boolean[] {
  const result: boolean[] = []
  for (let i = 0; i < n; i++) {
    result.push(Math.random() < density)
  }
  return result
}

/**
 * Generate random field element vector
 * 
 * Matching Rust: random_vec(n, rng)
 * 
 * @param n - Number of elements
 * @returns Array of n random field elements
 */
export function randomVec(n: number): bigint[] {
  const result: bigint[] = []
  for (let i = 0; i < n; i++) {
    result.push(randomFieldElement())
  }
  return result
}

/**
 * Generate random field element
 * 
 * @returns Random field element
 */
export function randomFieldElement(): bigint {
  const randomBytes = new Uint8Array(32)
  crypto.getRandomValues(randomBytes)
  const randomBigInt = BigInt(
    '0x' + Array.from(randomBytes).map((b) => b.toString(16).padStart(2, '0')).join(''),
  )
  return Fr.create(randomBigInt)
}

/**
 * Add two points directly using Twisted Edwards formula
 * Helper for condSum
 */
function addPointsDirect(
  p1: { x: bigint; y: bigint },
  p2: { x: bigint; y: bigint },
): { x: bigint; y: bigint } {
  const { a, d } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
  const p = BANDERSNATCH_PARAMS.FIELD_MODULUS

  const x1y2 = mod(p1.x * p2.y, p)
  const y1x2 = mod(p1.y * p2.x, p)
  const y1y2 = mod(p1.y * p2.y, p)
  const x1x2 = mod(p1.x * p2.x, p)

  const dxy = mod(d * x1x2 * y1y2, p)
  const denom1 = mod(1n + dxy, p)
  const denom2 = mod(1n - dxy, p)

  const denom1Inv = modInverse(denom1, p)
  const denom2Inv = modInverse(denom2, p)

  const x3 = mod((x1y2 + y1x2) * denom1Inv, p)
  const y3 = mod((y1y2 - a * x1x2) * denom2Inv, p)

  return { x: x3, y: y3 }
}

/**
 * Conditional sum of points
 * 
 * Matching Rust: cond_sum(bitmask, points)
 * Sums points where bitmask[i] is true
 * 
 * @param bitmask - Boolean array
 * @param points - Array of curve points (as {x, y})
 * @returns Sum of points where bitmask is true
 */
export function condSum(
  bitmask: boolean[],
  points: Array<{ x: bigint; y: bigint }>,
): { x: bigint; y: bigint } {
  if (bitmask.length !== points.length) {
    throw new Error(
      `Bitmask length ${bitmask.length} must equal points length ${points.length}`,
    )
  }

  // Start with zero point (point at infinity)
  let sum: { x: bigint; y: bigint } | null = null

  for (let i = 0; i < bitmask.length; i++) {
    if (bitmask[i]) {
      const point = points[i]!
      if (sum === null) {
        sum = { x: point.x, y: point.y }
      } else {
        sum = addPointsDirect(sum, point)
      }
    }
  }

  // Return zero point if no points were selected
  if (sum === null) {
    const infinity = BandersnatchCurve.INFINITY
    const affine = infinity.toAffine()
    return { x: affine.x, y: affine.y }
  }

  return sum
}

/**
 * Generate random Bandersnatch point
 * 
 * @returns Random point on Bandersnatch curve
 */
export function randomPoint(): { x: bigint; y: bigint } {
  // Generate random scalar and multiply by generator
  const scalar = randomFieldElement()
  const generator = BandersnatchCurve.GENERATOR
  const point = BandersnatchCurve.scalarMultiply(generator, scalar)
  const affine = point.toAffine()
  return { x: affine.x, y: affine.y }
}
