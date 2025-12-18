/**
 * Manual KZG Commitment and Proof Computation
 *
 * Implements blobToKzgCommitment and computeBlobKzgProof manually according to bandersnatch-vrf-spec.
 * Domain size |𝔻| = 2048, so blob has 2048 field elements (not 4096 like c-kzg).
 */

import { bls12_381 } from '@noble/curves/bls12-381'
import { BANDERSNATCH_PARAMS, BandersnatchCurve, Bandersnatch, mod, modInverse } from '@pbnj/bandersnatch'
import { hexToBytes } from 'viem'
import type { Safe } from '@pbnj/types'
import { safeError, safeResult } from '@pbnj/types'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config'

/**
 * Blob size according to bandersnatch-vrf-spec
 * Domain size |𝔻| = 2048, so blob = 2048 * 32 = 65536 bytes
 */
export const BYTES_PER_BLOB = 2048 * 32 // 65536 bytes
export const FIELD_ELEMENTS_PER_BLOB = 2048

/**
 * BLS12-381 scalar field order (r)
 * r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
 *
 * This is the order of the scalar field Fr (curve order), NOT the base field Fp.
 * For polynomial evaluation and KZG operations, we work in the scalar field.
 */
const BLS12_381_SCALAR_FIELD_ORDER = bls12_381.fields.Fr.ORDER

/**
 * Evaluate polynomial at point z
 *
 * This is a SCALAR FIELD operation, not a group operation.
 * We compute: p(z) = Σ(c_i * z^i) where all values are scalars in Fr.
 *
 * This is different from:
 * - Commitment (group operation): C = Σ(c_i * τ^i * G) - uses G1 point operations
 * - Proof (group operation): π = Q(τ) * G - uses G1 point operations
 *
 * For polynomial evaluation:
 * - Input: coefficients c_i (scalars) and point z (scalar)
 * - Output: y = p(z) (scalar)
 * - Operations: scalar field arithmetic (addition and multiplication mod r)
 * - Start value: 0 (additive identity in the scalar field)
 *
 * We do NOT use group operations (G1 point add/mul) here because we're
 * evaluating the polynomial itself, not committing to it.
 *
 * @param polynomial - Array of polynomial coefficients (bigint)
 * @param z - Evaluation point (bigint)
 * @returns Polynomial evaluation result y = p(z) (bigint)
 */
export function evaluatePolynomialAt(
  polynomial: bigint[],
  z: bigint,
): bigint {
  // BLS12-381 scalar field order (r) - NOT base field order!
  // For BLS12-381: scalar field Fr has order r (curve order)
  // Base field Fp has a different order
  const zReduced = mod(z, BLS12_381_SCALAR_FIELD_ORDER)

  // Start at 0 (additive identity) because we're summing scalars
  let y = 0n
  let zPower = 1n

  // Horner's method: p(z) = c_0 + z*(c_1 + z*(c_2 + ...))
  // Or equivalently: p(z) = Σ(c_i * z^i)
  for (const coeff of polynomial) {
    // term = c_i * z^i (scalar field multiplication)
    const term = mod(coeff * zPower, BLS12_381_SCALAR_FIELD_ORDER)
    // y += term (scalar field addition)
    y = mod(y + term, BLS12_381_SCALAR_FIELD_ORDER)
    // zPower *= z for next iteration
    zPower = mod(zPower * zReduced, BLS12_381_SCALAR_FIELD_ORDER)
  }
  return y
}

/**
 * Convert polynomial coefficients to blob format
 *
 * According to bandersnatch-vrf-spec:
 * - Domain size |𝔻| = 2048 (polynomial evaluation domain)
 * - Blob has 2048 BLS12-381 scalar field elements
 * - Each element is 32 bytes in big-endian
 * - Polynomial has at most domain_size - 1 = 2047 coefficients
 *
 * Each coefficient must be reduced modulo the BLS12-381 scalar field order.
 *
 * @param polynomial - Array of polynomial coefficients (bigint)
 * @returns Blob (2048 * 32 = 65536 bytes)
 */
export function polynomialToBlob(polynomial: bigint[]): Uint8Array {
  const blob = new Uint8Array(BYTES_PER_BLOB)

  for (let i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
    const coeff = polynomial[i] ?? 0n

    // Reduce coefficient to BLS12-381 scalar field (NOT Bandersnatch field!)
    const reducedCoeff = mod(coeff, BLS12_381_SCALAR_FIELD_ORDER)

    // Convert bigint to 32-byte big-endian representation
    const coeffBytes = bigintToBytes32BE(reducedCoeff)
    blob.set(coeffBytes, i * 32)
  }

  return blob
}


/**
 * Convert 32-byte big-endian bytes to bigint
 */
function bytes32BEToBigint(bytes: Uint8Array): bigint {
  let value = 0n
  for (let i = 0; i < 32; i++) {
    value = (value << 8n) | BigInt(bytes[i] ?? 0)
  }
  return value
}

/**
 * Extract polynomial coefficients from blob
 *
 * @param blob - Blob (65536 bytes)
 * @returns Array of polynomial coefficients (bigint)
 */
export function blobToPolynomial(blob: Uint8Array): bigint[] {
  if (blob.length !== BYTES_PER_BLOB) {
    throw new Error(
      `Blob must be ${BYTES_PER_BLOB} bytes, got ${blob.length}`,
    )
  }

  const polynomial: bigint[] = []

  for (let i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
    const coeffBytes = blob.slice(i * 32, (i + 1) * 32)
    const coeff = bytes32BEToBigint(coeffBytes)
    polynomial.push(coeff)
  }

  return polynomial
}

/**
 * Manual blobToKzgCommitment using MSM
 *
 * Computes: C = Σ(c_i * τ^i * G) where:
 * - c_i are polynomial coefficients from the blob
 * - τ^i * G are the SRS points (monomial basis)
 *
 * This is equivalent to committing to polynomial p(x) = Σ(c_i * x^i)
 *
 * @param blob - Blob representing polynomial coefficients
 * @param srsG1Points - SRS G1 points in monomial basis [G, τG, τ²G, ..., τ^(n-1)G]
 * @returns KZG commitment (48-byte compressed BLS12-381 G1 point)
 */
export function blobToKzgCommitment(
  blob: Uint8Array,
  srsG1Points: Uint8Array[],
): Safe<Uint8Array> {
  if (blob.length !== BYTES_PER_BLOB) {
    return safeError(
      new Error(
        `Blob must be ${BYTES_PER_BLOB} bytes, got ${blob.length}`,
      ),
    )
  }

  // Extract polynomial coefficients from blob
  const polynomial = blobToPolynomial(blob)

  // We need at least as many SRS points as polynomial coefficients
  const maxDegree = polynomial.length - 1
  if (srsG1Points.length < polynomial.length) {
    return safeError(
      new Error(
        `SRS has ${srsG1Points.length} points, but polynomial has ${polynomial.length} coefficients (degree ${maxDegree})`,
      ),
    )
  }

  // Compute commitment: C = Σ(c_i * τ^i * G)
  // This is a multi-scalar multiplication (MSM)
  let commitment = bls12_381.G1.Point.ZERO

  for (let i = 0; i < polynomial.length; i++) {
    const coeff = polynomial[i]!
    if (coeff === 0n) continue // Skip zero coefficients

    // Reduce coefficient modulo BLS12-381 scalar field
    const reducedCoeff = mod(coeff, BLS12_381_SCALAR_FIELD_ORDER)

    // Get SRS point: τ^i * G
    const srsPoint = bls12_381.G1.Point.fromBytes(srsG1Points[i]!)

    // Add: commitment += coeff * (τ^i * G)
    const scaledPoint = srsPoint.multiply(reducedCoeff)
    commitment = commitment.add(scaledPoint)
  }

  // Return compressed point (48 bytes)
  return safeResult(commitment.toBytes(true))
}

/**
 * Manual computeBlobKzgProof
 *
 * Computes a KZG proof that the polynomial p(x) evaluates to p(z) at point z.
 *
 * The proof is computed as:
 * π = Q(τ) * G where Q(x) = (p(x) - p(z)) / (x - z)
 *
 * Steps:
 * 1. Evaluate polynomial at z: y = p(z)
 * 2. Compute quotient polynomial Q(x) = (p(x) - y) / (x - z)
 * 3. Commit to Q(x) using SRS: π = Σ(q_i * τ^i * G)
 *
 * @param blob - Blob representing polynomial p(x)
 * @param commitmentBytes - KZG commitment to p(x) (for validation)
 * @param zBytes - Evaluation point z (32 bytes, big-endian)
 * @param srsG1Points - SRS G1 points in monomial basis
 * @returns KZG proof (48-byte compressed BLS12-381 G1 point)
 */
export function computeBlobKzgProof(
  blob: Uint8Array,
  zBytes: Uint8Array,
  srsG1Points: Uint8Array[],
): Safe<Uint8Array> {
  if (blob.length !== BYTES_PER_BLOB) {
    return safeError(
      new Error(
        `Blob must be ${BYTES_PER_BLOB} bytes, got ${blob.length}`,
      ),
    )
  }

  if (zBytes.length !== 32) {
    return safeError(
      new Error(`z must be 32 bytes, got ${zBytes.length}`),
    )
  }

  // Extract polynomial coefficients
  const polynomial = blobToPolynomial(blob)
  const z = bytes32BEToBigint(zBytes)

  // Reduce z modulo BLS12-381 scalar field
  const zReduced = mod(z, BLS12_381_SCALAR_FIELD_ORDER)

  // Step 1: Evaluate polynomial at z: y = p(z) = Σ(c_i * z^i)
  const y = evaluatePolynomialAt(polynomial, z)

  // Step 2: Compute quotient polynomial Q(x) = (p(x) - y) / (x - z)
  // Using synthetic division (Horner's method)
  const n = polynomial.length
  const quotient: bigint[] = new Array(n - 1).fill(0n)

  // Synthetic division: work from highest degree to lowest
  if (n > 1) {
    quotient[n - 2] = polynomial[n - 1] ?? 0n
  }

  for (let i = n - 3; i >= 0; i--) {
    const coeff = polynomial[i + 1] ?? 0n
    const nextQ = quotient[i + 1] ?? 0n
    // q_i = c_{i+1} + z * q_{i+1}
    quotient[i] = mod(
      coeff + mod(zReduced * nextQ, BLS12_381_SCALAR_FIELD_ORDER),
      BLS12_381_SCALAR_FIELD_ORDER,
    )
  }

  // Adjust constant term: q_0 = (c_0 - y) / (-z) = (y - c_0) / z
  if (zReduced === 0n) {
    // Special case: z = 0, so Q(x) = (p(x) - c_0) / x
    for (let i = 0; i < n - 1; i++) {
      quotient[i] = polynomial[i + 1] ?? 0n
    }
  } else {
    const c0 = polynomial[0] ?? 0n
    const numerator = mod(y - c0, BLS12_381_SCALAR_FIELD_ORDER)
    const zInv = modInverse(zReduced, BLS12_381_SCALAR_FIELD_ORDER)
    quotient[0] = mod(numerator * zInv, BLS12_381_SCALAR_FIELD_ORDER)
  }

  // Step 3: Commit to quotient polynomial using SRS
  // π = Σ(q_i * τ^i * G)
  let proof = bls12_381.G1.Point.ZERO

  for (let i = 0; i < quotient.length; i++) {
    const q_i = quotient[i] ?? 0n
    if (q_i === 0n) continue

    const reducedQ = mod(q_i, BLS12_381_SCALAR_FIELD_ORDER)
    const srsPoint = bls12_381.G1.Point.fromBytes(srsG1Points[i]!)
    const scaledPoint = srsPoint.multiply(reducedQ)
    proof = proof.add(scaledPoint)
  }

  return safeResult(proof.toBytes(true))
}

/**
 * Verify KZG proof
 *
 * Verifies that commitment C corresponds to polynomial p(x) and p(z) = y.
 *
 * Uses pairing check: e(C - y*G, G2) = e(π, (τ - z)*G2)
 * Which is equivalent to: e(C, G2) = e(π, (τ - z)*G2) * e(y*G, G2)
 *
 * @param commitmentBytes - KZG commitment (48 bytes)
 * @param zBytes - Evaluation point z (32 bytes)
 * @param yBytes - Evaluation result y (32 bytes)
 * @param proofBytes - KZG proof (48 bytes)
 * @param srsG1 - SRS G1 generator G (48 bytes)
 * @param srsG2 - SRS G2 generator G2 (96 bytes)
 * @param srsG2Tau - SRS G2 point τ*G2 (96 bytes)
 * @returns true if proof is valid
 */
export function verifyKzgProof(
  commitmentBytes: Uint8Array,
  zBytes: Uint8Array,
  yBytes: Uint8Array,
  proofBytes: Uint8Array,
  srsG1: Uint8Array,
  srsG2: Uint8Array,
  srsG2Tau: Uint8Array,
): Safe<boolean> {
  try {
    const commitment = bls12_381.G1.Point.fromBytes(commitmentBytes)
    const proof = bls12_381.G1.Point.fromBytes(proofBytes)
    const g1 = bls12_381.G1.Point.fromBytes(srsG1)
    const g2 = bls12_381.G2.Point.fromBytes(srsG2)
    const g2Tau = bls12_381.G2.Point.fromBytes(srsG2Tau)

    const z = bytes32BEToBigint(zBytes)
    const y = bytes32BEToBigint(yBytes)
    const zReduced = mod(z, BLS12_381_SCALAR_FIELD_ORDER)
    const yReduced = mod(y, BLS12_381_SCALAR_FIELD_ORDER)

    // Compute (τ - z)*G2 = τ*G2 - z*G2
    const g2ZTau = g2Tau.subtract(g2.multiply(zReduced))

    // Compute y*G
    const yG = g1.multiply(yReduced)

    // Compute C - y*G
    const commitmentMinusY = commitment.subtract(yG)

    // Pairing check: e(C - y*G, G2) = e(π, (τ - z)*G2)
    // This is equivalent to: e(C - y*G, G2) * e(π, (τ - z)*G2)^(-1) = 1
    const left = bls12_381.pairing(commitmentMinusY, g2)
    const right = bls12_381.pairing(proof, g2ZTau)

    // Multiply left by inverse of right, then final exponentiate
    const rightInv = bls12_381.fields.Fp12.inv(right)
    const product = bls12_381.fields.Fp12.mul(left, rightInv)
    const final = bls12_381.fields.Fp12.finalExponentiate(product)

    // Check if result equals Fp12.ONE
    return safeResult(
      bls12_381.fields.Fp12.eql(final, bls12_381.fields.Fp12.ONE),
    )
  } catch (error) {
    return safeError(
      error instanceof Error
        ? error
        : new Error(`KZG proof verification failed: ${String(error)}`),
    )
  }
  }

/**
 * Extract x and y coordinate vectors from ring keys
 *
 * This is shared logic between createRingPolynomial (x-only) and computeRingCommitment (x and y).
 * Returns both x and y coordinate vectors matching Rust Ring::with_keys() structure:
 * [keys, powers_of_h, idle_rows (4), final_padding (1)]
 *
 * @param ringKeys - Array of Bandersnatch public keys (32 bytes each)
 * @returns Object with xs and ys coordinate vectors
 */
export function extractRingCoordinateVectors(ringKeys: Uint8Array[]): {
  xs: bigint[]
  ys: bigint[]
} {
  const scalarBitlen = 253 // Bandersnatch scalar field bit length
  const idleRows = 4 // IDLE_ROWS = ZK_ROWS + 1 = 3 + 1 = 4
  const fieldModulus = BANDERSNATCH_PARAMS.FIELD_MODULUS

  // Pre-compute padding point once (optimization: avoid repeated conversions)
  const paddingPointBytes = hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
  const paddingPoint = BandersnatchCurve.bytesToPoint(paddingPointBytes)
  const paddingX = BigInt(paddingPoint.x.toString())
  const paddingY = BigInt(paddingPoint.y.toString())
  
  // Pre-compute negated padding values (used for idle rows)
  // Note: paddingX and paddingY are already in [0, fieldModulus) range, so no reduction needed
  const negPaddingX = mod(-paddingX, fieldModulus)
  const negPaddingY = mod(-paddingY, fieldModulus)

  // Pre-allocate arrays with known size (optimization: avoid reallocations)
  const vectorLength = ringKeys.length + scalarBitlen + idleRows + 1
  const xs: bigint[] = new Array(vectorLength)
  const ys: bigint[] = new Array(vectorLength)
  let idx = 0

  // Step 1: Keys portion - [(pk1_x - padding_x), (pk1_y - padding_y), ...]
  for (const key of ringKeys) {
    const isNullKey = key.every((byte) => byte === 0)
    const keyToUse = isNullKey ? paddingPointBytes : key
    const point = BandersnatchCurve.bytesToPoint(keyToUse)
    const xBigInt = BigInt(point.x.toString())
    const yBigInt = BigInt(point.y.toString())

    // Compute difference and reduce in one step (optimization: combine operations)
    let xDiff = xBigInt - paddingX
    let yDiff = yBigInt - paddingY
    if (xDiff < 0n) xDiff += fieldModulus
    if (yDiff < 0n) yDiff += fieldModulus
    xs[idx] = mod(xDiff, fieldModulus)
    ys[idx] = mod(yDiff, fieldModulus)
    idx++
  }

  // Step 2: Powers of H - [(H_x - padding_x), (H_y - padding_y), ...]
  // Pre-compute H point once (optimization: avoid repeated fromAffine calls)
  const accumulatorBase = BANDERSNATCH_PARAMS.ACCUMULATOR_BASE
  let currentH = Bandersnatch.fromAffine({
    x: accumulatorBase.x,
    y: accumulatorBase.y,
  })

  for (let i = 0; i < scalarBitlen; i++) {
    const hX = currentH.x
    const hY = currentH.y
    let xDiff = hX - paddingX
    let yDiff = hY - paddingY
    if (xDiff < 0n) xDiff += fieldModulus
    if (yDiff < 0n) yDiff += fieldModulus
    xs[idx] = mod(xDiff, fieldModulus)
    ys[idx] = mod(yDiff, fieldModulus)
    idx++

    // Double H for next iteration (only if not last)
    if (i < scalarBitlen - 1) {
      currentH = BandersnatchCurve.double(currentH)
    }
  }

  // Step 3: Idle rows - [(-padding_x), (-padding_y)] × 4
  // Reuse pre-computed negPadding values (optimization: avoid repeated mod calls)
  for (let i = 0; i < idleRows; i++) {
    xs[idx] = negPaddingX
    ys[idx] = negPaddingY
    idx++
  }

  // Step 4: Final padding - [(padding_x), (padding_y)]
  // Note: paddingX and paddingY are already in [0, fieldModulus) range, so no reduction needed
  xs[idx] = paddingX
  ys[idx] = paddingY

  return { xs, ys }
}

/**
 * Create polynomial from ring of public keys
 * Maps each public key to a coefficient in the polynomial
 *
 * Gray Paper bandersnatch.tex line 20:
 * "Note that in the case a key has no corresponding Bandersnatch point when
 * constructing the ring, then the Bandersnatch padding point as stated by
 * [hosseini2024bandersnatch] should be substituted."
 */
/**
 * Create ring polynomial matching w3f-ring-proof structure
   *
   * Rust reference: Ring::with_keys() constructs:
   * [(pk1 - padding), ..., (pkn - padding),
   *  (H - padding), ..., (2^(s-1)H - padding),
   *  -padding, -padding, -padding, -padding,
   *  padding]
   *
   * Where:
   * - keys: ringKeys (n keys)
   * - powers of H: H, 2H, 4H, ..., 2^(s-1)H (s = scalar_bitlen = 253)
   * - idle rows: 4 zeros (IDLE_ROWS = 4)
   * - final padding: 1 padding point
   *
   * Total length: keys.len() + (keyset_part_size - keys.len()) + scalar_bitlen + 4 + 1
   * = keyset_part_size + scalar_bitlen + 5
   * = domain_size - 1
   */
export function createRingPolynomial(ringKeys: Uint8Array[]): bigint[] {
  const maxRingSize = BANDERSNATCH_PARAMS.KZG_CONFIG.MAX_RING_SIZE

  if (ringKeys.length > maxRingSize) {
    throw new Error(
      `Ring size ${ringKeys.length} exceeds maximum ${maxRingSize}`,
    )
  }

  // Domain size and parameters matching Rust PiopParams
  const domainSize = BANDERSNATCH_PARAMS.KZG_CONFIG.DOMAIN_SIZE
  const scalarBitlen = 253 // Bandersnatch scalar field bit length
  const keysetPartSize = domainSize - scalarBitlen - 1 // domain.capacity - scalar_bitlen - 1

  // Rust points_column: [keys, padding, powers_of_h] with total length = domain.capacity - 1
  // The actual data is: keys (n) + padding (keysetPartSize - n) + powers_of_h (253) = keysetPartSize + 253 = domainSize - 1
  // We create a polynomial with domainSize - 1 elements, then pad to domainSize when converting to blob
  const polynomialLength = domainSize - 1 // domain.capacity - 1 = 2047
  const polynomial: bigint[] = new Array(polynomialLength).fill(0n)

  // Reuse shared coordinate extraction logic (only need x-coordinates for polynomial)
  const { xs } = extractRingCoordinateVectors(ringKeys)

  // Extract x-coordinates for polynomial (excluding idle_rows and final_padding)
  // Polynomial structure: [keys, padding (zeros), powers_of_h]
  // Note: extractRingCoordinateVectors includes idle_rows and final_padding, but polynomial doesn't
  const keysCount = ringKeys.length
  const hStartIndex = keysetPartSize

  // Copy keys portion
  for (let i = 0; i < keysCount && i < keysetPartSize; i++) {
    polynomial[i] = xs[i] ?? 0n
  }

  // Padding portion is already zeros (indices keysCount to keysetPartSize - 1)

  // Copy powers of H portion (skip idle_rows and final_padding from xs)
  // xs structure: [keys, powers_of_h, idle_rows (4), final_padding (1)]
  // polynomial structure: [keys, padding (zeros), powers_of_h]
  const powersOfHStartInXs = keysCount
  for (let i = 0; i < scalarBitlen; i++) {
    polynomial[hStartIndex + i] = xs[powersOfHStartInXs + i] ?? 0n
  }

  // Verify we filled exactly polynomialLength elements
  const lastDataIndex = keysetPartSize + scalarBitlen - 1
  if (lastDataIndex !== polynomialLength - 1) {
    throw new Error(
      `Polynomial length mismatch: expected ${polynomialLength} elements, got ${lastDataIndex + 1}`,
    )
  }

  console.debug('[createRingPolynomial] Ring polynomial structure', {
    ringKeysCount: ringKeys.length,
    keysetPartSize,
    scalarBitlen,
    totalLength: polynomial.length,
    firstKeyCoeff: polynomial[0]?.toString(),
    lastKeyCoeff: polynomial[ringKeys.length - 1]?.toString(),
    firstPowerOfH: polynomial[hStartIndex]?.toString(),
    lastPowerOfH: polynomial[hStartIndex + scalarBitlen - 1]?.toString(),
  })

  return polynomial
}


  /**
   * Convert bigint to 32-byte big-endian representation
   */
  export function bigintToBytes32BE(value: bigint): Uint8Array {
    const bytes = new Uint8Array(32)
    let val = value

    for (let i = 31; i >= 0; i--) {
      bytes[i] = Number(val & 0xffn)
      val = val >> 8n
    }

    return bytes
  }