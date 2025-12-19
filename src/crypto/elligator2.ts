/**
 * Elligator2 Hash-to-Curve Implementation for Bandersnatch
 *
 * This module implements Elligator2 mapping for the Bandersnatch Twisted Edwards curve,
 * which is used in VRF (Verifiable Random Function) implementations for deterministic
 * point generation from arbitrary input data.
 *
 * ## When to Use Elligator2
 *
 * Elligator2 is used in VRF implementations when you need to:
 * 1. **Hash arbitrary data to curve points**: Convert any input (like messages, nonces, or seeds)
 *    into valid points on the Bandersnatch curve
 * 2. **Ensure deterministic mapping**: Same input always produces the same curve point
 * 3. **Maintain uniform distribution**: The mapping should be approximately uniform across the curve
 * 4. **Enable VRF operations**: Required for generating VRF proofs and outputs
 *
 * ## Technical Details
 *
 * The implementation uses the birationally equivalent Weierstrass curve for Elligator2 mapping,
 * then converts back to Twisted Edwards form using the authoritative Sage script conversion functions.
 * This approach is more reliable than direct Montgomery curve mapping.
 *
 * Reference: RFC 9380 - Hashing to Elliptic Curves
 * https://datatracker.ietf.org/doc/rfc9380/
 */

import type { EdwardsPoint } from '@noble/curves/abstract/edwards.js'
import { edwards } from '@noble/curves/abstract/edwards.js'
import { pow } from '@noble/curves/abstract/modular.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { BANDERSNATCH_PARAMS, BandersnatchCurve, mod, modInverse, modSqrt, type CurvePoint } from '@pbnjam/bandersnatch'
import { bytesToHex } from 'viem'

/**
 * Convert bytes to BigInt using little-endian interpretation (arkworks-compatible)
 * This matches Rust's Fr::from_le_bytes_mod_order behavior exactly
 *
 * @param bytes - Input bytes to convert
 * @returns BigInt in little-endian interpretation
 */
export function bytesToBigIntLittleEndian(bytes: Uint8Array): bigint {
  let result = 0n
  for (let i = 0; i < bytes.length; i++) {
    result += BigInt(bytes[i]) << (8n * BigInt(i))
  }
  return result
}

/**
 * Noble Edwards curve instance for Bandersnatch
 * Used for native Noble operations with arkworks compatibility
 */
const Bandersnatch = edwards({
  p: BANDERSNATCH_PARAMS.FIELD_MODULUS,
  n: BANDERSNATCH_PARAMS.CURVE_ORDER,
  h: BANDERSNATCH_PARAMS.COFACTOR,
  a:
    BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.a +
    BANDERSNATCH_PARAMS.FIELD_MODULUS,
  d: BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.d,
  Gx: BANDERSNATCH_PARAMS.GENERATOR.x,
  Gy: BANDERSNATCH_PARAMS.GENERATOR.y,
})

/**
 * Elligator2 hash-to-curve for Bandersnatch
 *
 * Converts arbitrary input data into a valid point on the Bandersnatch curve.
 * This function is deterministic - the same input will always produce the same output.
 *
 * @param message - Input message to hash (can be any Uint8Array)
 * @returns Valid curve point on the Bandersnatch Twisted Edwards curve
 *
 * @example
 * ```typescript
 * // Hash a message to a curve point
 * const message = new TextEncoder().encode("Hello, VRF!");
 * const point = elligator2HashToCurve(message);
 * console.log(`Point: (${point.x}, ${point.y})`);
 *
 * // Hash empty input (common in test vectors)
 * const emptyPoint = elligator2HashToCurve(new Uint8Array(0));
 * ```
 */
export function elligator2HashToCurve(message: Uint8Array): CurvePoint {
  try {
    // Step 1: Hash message to two field elements (RFC 9380 hash_to_field)
    const [u1, u2] = hashToField(message)

    // Step 2: Map each field element to curve (RFC 9380 map_to_curve)
    const point1 = elligator2Map(u1)
    const point2 = elligator2Map(u2)

    // Step 3: Add the points (RFC 9380 point addition)
    const sum = addPoints(point1, point2)

    // Step 4: Clear cofactor (RFC 9380 clear_cofactor) - THIS WAS THE MISSING STEP!
    // Arkworks DOES clear cofactor as per RFC 9380 specification
    const cleared = clearCofactor(sum)

    return cleared
  } catch (error) {
    console.error('Elligator2 hash-to-curve failed', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    })
    throw new Error(
      `Elligator2 hash-to-curve failed: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
}

/**
 * Compress a point using the same format as arkworks
 * This follows the standard compressed point encoding for Edwards curves
 */
/**
 * Convert CurvePoint to Noble EdwardsPoint
 * @param point - CurvePoint to convert
 * @returns Noble EdwardsPoint
 */
export function curvePointToNoble(point: CurvePoint): EdwardsPoint {
  return Bandersnatch.fromAffine({
    x: point.x,
    y: point.y,
  })
}

export function compressPoint(point: CurvePoint): string {
  // Convert our CurvePoint to Noble EdwardsPoint
  const noblePoint = curvePointToNoble(point)

  // Compress with arkworks compatibility
  const arkworksBytes = BandersnatchCurve.pointToBytes(noblePoint)

  // Return as hex string (without 0x prefix)
  return bytesToHex(arkworksBytes).slice(2)
}

/**
 * Hash message to field element using noble package hash_to_field
 * Implements RFC 9380, Section 5.2 like arkworks DefaultFieldHasher
 *
 * @param message - Input message
 * @returns Two field elements (for uniform mapping like arkworks)
 */
// Helper functions for arkworks-compatible expand_message_xmd
function i2osp(value: number, length: number): Uint8Array {
  if (value < 0 || value >= 1 << (8 * length))
    throw new Error(`invalid I2OSP input: ${value}`)
  const res = Array.from({ length }).fill(0) as number[]
  for (let i = length - 1; i >= 0; i--) {
    res[i] = value & 0xff
    value >>>= 8
  }
  return new Uint8Array(res)
}

function strxor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const arr = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) {
    arr[i] = a[i] ^ b[i]
  }
  return arr
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const arr of arrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

function normDST(DST: string | Uint8Array): Uint8Array {
  return typeof DST === 'string' ? new TextEncoder().encode(DST) : DST
}

/**
 * Arkworks-compatible expand_message_xmd implementation
 * Key difference: Uses arkworks block_size (48 bytes) instead of SHA-512 block size (128 bytes)
 */
function arkworksExpandMessageXmd(
  msg: Uint8Array,
  DST: string | Uint8Array,
  lenInBytes: number,
): Uint8Array {
  DST = normDST(DST)

  // Handle long DST (same as Noble)
  if (DST.length > 255) {
    const longDstPrefix = new TextEncoder().encode('H2C-OVERSIZE-DST-')
    DST = sha512(concatBytes(longDstPrefix, DST))
  }

  const b_in_bytes = 64 // SHA-512 output size
  const ell = Math.ceil(lenInBytes / b_in_bytes)
  if (lenInBytes > 65535 || ell > 255)
    throw new Error('expand_message_xmd: invalid lenInBytes')

  const DST_prime = concatBytes(DST, i2osp(DST.length, 1))

  // KEY DIFFERENCE: Use arkworks block_size (48 bytes) instead of SHA-512 block size (128 bytes)
  const ARKWORKS_BLOCK_SIZE = 48 // len_per_base_elem for Bandersnatch with SEC_PARAM=128
  const Z_pad = new Uint8Array(ARKWORKS_BLOCK_SIZE) // All zeros

  const l_i_b_str = i2osp(lenInBytes, 2)

  // Calculate b_0
  const b_0 = sha512(concatBytes(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime))

  // Calculate b_1
  const b = new Array<Uint8Array>(ell)
  b[0] = sha512(concatBytes(b_0, i2osp(1, 1), DST_prime))

  // Calculate b_2, b_3, ... b_ell
  for (let i = 1; i < ell; i++) {
    const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime]
    b[i] = sha512(concatBytes(...args))
  }

  const pseudo_random_bytes = concatBytes(...b)
  return pseudo_random_bytes.slice(0, lenInBytes)
}

/**
 * Hash to field using arkworks-compatible implementation
 * This matches arkworks' DefaultFieldHasher exactly by using the correct Z_pad size
 * Implements RFC 9380, Section 5.2 like arkworks DefaultFieldHasher
 *
 * @param message - Input message
 * @returns Two field elements (for uniform mapping like arkworks)
 */
export function hashToField(message: Uint8Array): [bigint, bigint] {
  // DST construction matching arkworks exactly
  const h2cSuiteId = 'Bandersnatch_XMD:SHA-512_ELL2_RO_'
  const suiteString = 'Bandersnatch_SHA-512_ELL2'
  const DST = `ECVRF_${h2cSuiteId}${suiteString}`

  // Calculate parameters like arkworks
  const MODULUS_BIT_SIZE = 255 // Bandersnatch field modulus bit size
  const SEC_PARAM = 128
  const base_field_size_with_security_padding_in_bits =
    MODULUS_BIT_SIZE + SEC_PARAM
  const len_per_base_elem = Math.ceil(
    base_field_size_with_security_padding_in_bits / 8,
  )

  const N = 2 // Number of field elements
  const m = 1 // Extension degree
  const len_in_bytes = N * m * len_per_base_elem

  // Use our arkworks-compatible expand_message_xmd
  const uniform_bytes = arkworksExpandMessageXmd(message, DST, len_in_bytes)

  // Extract field elements like arkworks (big-endian interpretation with modular reduction)
  const u1_bytes = uniform_bytes.slice(0, len_per_base_elem)
  const u2_bytes = uniform_bytes.slice(len_per_base_elem, 2 * len_per_base_elem)

  // Convert to field elements (big-endian)
  let u1 = 0n
  for (let i = 0; i < u1_bytes.length; i++) {
    u1 = (u1 << 8n) + BigInt(u1_bytes[i])
  }
  u1 = mod(u1, BANDERSNATCH_PARAMS.FIELD_MODULUS)

  let u2 = 0n
  for (let i = 0; i < u2_bytes.length; i++) {
    u2 = (u2 << 8n) + BigInt(u2_bytes[i])
  }
  u2 = mod(u2, BANDERSNATCH_PARAMS.FIELD_MODULUS)

  return [u1, u2]
}

/**
 * Elligator2 mapping for Twisted Edwards curves
 *
 * Maps a field element to a point on the Bandersnatch curve using the Elligator2 algorithm.
 * This implementation uses the birationally equivalent Weierstrass curve for the mapping,
 * then converts back to Twisted Edwards form using the authoritative Sage script.
 *
 * @param u - Field element (typically from hashToField)
 * @returns Valid curve point on the Bandersnatch Twisted Edwards curve
 */
export function elligator2Map(u: bigint): CurvePoint {
  const p = BANDERSNATCH_PARAMS.FIELD_MODULUS

  // Use exact arkworks Montgomery curve parameters directly
  // Montgomery form: By^2 = x^3 + Ax^2 + x
  // From arkworks BandersnatchConfig MontCurveConfig
  const A = BigInt(
    '29978822694968839326280996386011761570173833766074948509196803838190355340952',
  ) // COEFF_A
  const B = BigInt(
    '25465760566081946422412445027709227188579564747101592991722834452325077642517',
  ) // COEFF_B

  // Use exact arkworks Elligator2Config Z parameter
  const Z = BANDERSNATCH_PARAMS.ELLIGATOR2_CONFIG.Z

  // Use exact arkworks Elligator2Config constants
  const k = B // COEFF_B
  const jOnK = BANDERSNATCH_PARAMS.ELLIGATOR2_CONFIG.COEFF_A_OVER_COEFF_B
  const kSqInv = BANDERSNATCH_PARAMS.ELLIGATOR2_CONFIG.ONE_OVER_COEFF_B_SQUARE

  // Step 1: x1 = -(J / K) * inv0(1 + Z * u^2)
  const uSq = mod(u * u, p)
  const den1 = mod(1n + mod(Z * uSq, p), p)

  const x1 = mod(-jOnK * (den1 === 0n ? 1n : modInverse(den1, p)), p)

  // Step 2: gx1 = x1^3 + (J / K) * x1^2 + x1 / K^2
  const x1Sq = mod(x1 * x1, p)
  const x1Cb = mod(x1Sq * x1, p)
  const gx1 = mod(x1Cb + mod(jOnK * x1Sq, p) + mod(x1 * kSqInv, p), p)

  // Step 3: x2 = -x1 - (J / K)
  const x2 = mod(-x1 - jOnK, p)

  // Step 4: gx2 = x2^3 + (J / K) * x2^2 + x2 / K^2
  const x2Sq = mod(x2 * x2, p)
  const x2Cb = mod(x2Sq * x2, p)
  const gx2 = mod(x2Cb + mod(jOnK * x2Sq, p) + mod(x2 * kSqInv, p), p)

  // Step 5: Choose x and y based on which gx is a square
  let x
  let y
  let sgn0

  const gx1IsSquare = isSquare(gx1, p)
  const gx2IsSquare = isSquare(gx2, p)

  // According to Elligator2 specification, at least one should be a square
  // If neither is a square, this indicates an implementation error
  if (!gx1IsSquare && !gx2IsSquare) {
    console.error('Elligator2 mapping error: neither gx1 nor gx2 is a square', {
      u: u.toString(16),
      x1: x1.toString(16),
      x2: x2.toString(16),
      gx1: gx1.toString(16),
      gx2: gx2.toString(16),
      gx1IsSquare,
      gx2IsSquare,
    })
    throw new Error(
      'Elligator2 mapping failed: neither gx1 nor gx2 is a square',
    )
  }

  if (gx1IsSquare) {
    x = x1
    y = modSqrt(gx1, p, Bandersnatch.Fp)
    sgn0 = true
  } else {
    x = x2
    y = modSqrt(gx2, p, Bandersnatch.Fp)
    sgn0 = false
  }

  if (y === null) {
    throw new Error('Elligator2 mapping failed: y is null')
  }

  // Step 6: Adjust y sign to match sgn0
  if (parity(y) !== sgn0) {
    y = mod(-y, p)
  }

  // Step 7: Convert to Montgomery coordinates
  const s = mod(x * k, p)
  const t = mod(y * k, p)

  // Step 8: Convert from Montgomery to Twisted Edwards
  // Rational map from RFC 9380 Appendix D
  const tv1 = mod(s + 1n, p)
  const tv2 = mod(tv1 * t, p)

  let v
  let w
  if (tv2 === 0n) {
    v = 0n
    w = 1n
  } else {
    const tv2Inv = modInverse(tv2, p)
    v = mod(mod(tv2Inv * tv1, p) * s, p)
    w = mod(mod(tv2Inv * t, p) * mod(s - 1n, p), p)
  }

  const point = { x: v, y: w, isInfinity: false }

  // Verify the point is on the curve
  if (!isOnCurve(point)) {
    const x2 = mod(v * v, p)
    const y2 = mod(w * w, p)
    const x2y2 = mod(x2 * y2, p)
    const ax2 = mod(A * x2, p)
    const leftSide = mod(ax2 + y2, p)
    const rightSide = mod(
      1n + mod(BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.d * x2y2, p),
      p,
    )

    console.error('Elligator2 mapping produced invalid point', {
      v: v.toString(16),
      w: w.toString(16),
      x2: x2.toString(16),
      y2: y2.toString(16),
      x2y2: x2y2.toString(16),
      ax2: ax2.toString(16),
      leftSide: leftSide.toString(16),
      rightSide: rightSide.toString(16),
      a: A.toString(16),
      d: BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.d.toString(16),
    })
    throw new Error('Elligator2 mapping produced invalid point')
  }

  return point
}

/**
 * Calculate parity of field element (least significant bit)
 */
export function parity(value: bigint): boolean {
  return mod(value, 2n) === 1n
}

/**
 * Check if a value is a quadratic residue (square) in the field
 *
 * @param value - Value to check
 * @param p - Prime modulus
 * @returns True if value is a quadratic residue
 */
export function isSquare(value: bigint, p: bigint): boolean {
  if (value === 0n) return true
  if (value === 1n) return true

  // Use Legendre symbol: (a/p) = a^((p-1)/2) mod p
  // If result is 1, then a is a quadratic residue
  // If result is p-1, then a is a quadratic non-residue
  const legendre = pow(value, (p - 1n) / 2n, p)
  return legendre === 1n
}

/**
 * Clear cofactor from a curve point to ensure it's in the prime-order subgroup
 *
 * For Bandersnatch, the cofactor is 4. This function multiplies the point by the
 * cofactor to clear the cofactor and ensure the result is in the correct subgroup.
 * This matches arkworks' default clear_cofactor implementation.
 * Uses efficient scalar multiplication instead of repeated addition
 *
 * @param point - Input point
 * @returns Point with cleared cofactor
 */
export function clearCofactor(point: CurvePoint): CurvePoint {
  if (point.isInfinity) return point

  // Cofactor for Bandersnatch is 4 (matches arkworks default implementation)
  const cofactor = BANDERSNATCH_PARAMS.COFACTOR

  // Multiply by cofactor to clear cofactor (arkworks default behavior)
  return scalarMultiply(point, cofactor)
}

/**
 * Check if a point is on the curve
 *
 * @param point - Point to check
 * @returns True if point is on curve
 */
export function isOnCurve(point: CurvePoint): boolean {
  if (point.isInfinity) return true

  const p = BANDERSNATCH_PARAMS.FIELD_MODULUS
  const a = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.a
  const d = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.d

  const x = point.x
  const y = point.y

  // Check twisted Edwards curve equation: a*x^2 + y^2 = 1 + d*x^2*y^2
  const x2 = mod(x * x, p)
  const y2 = mod(y * y, p)

  const leftSide = mod(a * x2 + y2, p)
  const rightSide = mod(1n + d * x2 * y2, p)

  return leftSide === rightSide
}

/**
 * Scalar multiplication using double-and-add algorithm
 *
 * @param point - Base point
 * @param scalar - Scalar multiplier
 * @returns Result point
 */
export function scalarMultiply(point: CurvePoint, scalar: bigint): CurvePoint {
  if (point.isInfinity || scalar === 0n) {
    return { x: 0n, y: 0n, isInfinity: true }
  }

  if (scalar === 1n) return point

  let result: CurvePoint = { x: 0n, y: 0n, isInfinity: true }
  let addend = point

  while (scalar > 0n) {
    if (scalar & 1n) {
      result = addPoints(result, addend)
    }
    addend = addPoints(addend, addend)
    scalar = scalar >> 1n
  }

  return result
}

/**
 * Add two points (simplified for cofactor clearing)
 *
 * @param p1 - First point
 * @param p2 - Second point
 * @returns Sum of points
 */
export function addPoints(p1: CurvePoint, p2: CurvePoint): CurvePoint {
  if (p1.isInfinity) return p2
  if (p2.isInfinity) return p1

  const p = BANDERSNATCH_PARAMS.FIELD_MODULUS
  const a = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.a
  const d = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.d

  // Check if points are the same (doubling)
  if (p1.x === p2.x && p1.y === p2.y) {
    // Point doubling formula for Twisted Edwards
    // x3 = (2*x1*y1) / (a*x1^2 + y1^2)
    // y3 = (y1^2 - a*x1^2) / (2 - a*x1^2 - y1^2)

    const x1 = p1.x
    const y1 = p1.y

    const x1Sq = mod(x1 * x1, p)
    const y1Sq = mod(y1 * y1, p)
    const ax1Sq = mod(a * x1Sq, p)

    const x3Numerator = mod(2n * x1 * y1, p)
    const x3Denominator = mod(ax1Sq + y1Sq, p)

    if (x3Denominator === 0n) {
      // This is the infinity point
      return { x: 0n, y: 1n, isInfinity: true }
    }

    const x3DenomInv = modInverse(x3Denominator, p)
    const x3 = mod(x3Numerator * x3DenomInv, p)

    const y3Numerator = mod(y1Sq - ax1Sq, p)
    const y3Denominator = mod(2n - ax1Sq - y1Sq, p)

    if (y3Denominator === 0n) {
      // This is the infinity point
      return { x: 0n, y: 1n, isInfinity: true }
    }

    const y3DenomInv = modInverse(y3Denominator, p)
    const y3 = mod(y3Numerator * y3DenomInv, p)

    return {
      x: x3,
      y: y3,
      isInfinity: false,
    }
  }

  // Twisted Edwards addition formula
  // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
  // y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)

  const x1 = p1.x
  const y1 = p1.y
  const x2 = p2.x
  const y2 = p2.y

  const x1y2 = mod(x1 * y2, p)
  const y1x2 = mod(y1 * x2, p)
  const y1y2 = mod(y1 * y2, p)
  const x1x2 = mod(x1 * x2, p)

  const dxy = mod(d * x1x2 * y1y2, p)

  const x3Numerator = mod(x1y2 + y1x2, p)
  const x3Denominator = mod(1n + dxy, p)

  if (x3Denominator === 0n) {
    // This is the infinity point
    return { x: 0n, y: 1n, isInfinity: true }
  }

  const x3DenomInv = modInverse(x3Denominator, p)
  const x3 = mod(x3Numerator * x3DenomInv, p)

  const y3Numerator = mod(y1y2 - a * x1x2, p)
  const y3Denominator = mod(1n - dxy, p)

  if (y3Denominator === 0n) {
    // This is the infinity point
    return { x: 0n, y: 1n, isInfinity: true }
  }

  const y3DenomInv = modInverse(y3Denominator, p)
  const y3 = mod(y3Numerator * y3DenomInv, p)

  return {
    x: x3,
    y: y3,
    isInfinity: false,
  }
}
