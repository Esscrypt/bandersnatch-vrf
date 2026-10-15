import { bls12_381 } from '@noble/curves/bls12-381.js'
import {
  BANDERSNATCH_PARAMS,
  Bandersnatch,
  BandersnatchCurve,
  mod,
  modInverse,
} from '@pbnjam/bandersnatch'
import type { Safe } from '@pbnjam/types'
import { safeError, safeResult } from '@pbnjam/types'
import { hexToBytes } from 'viem'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config.ts'

export const BYTES_PER_BLOB = 2048 * 32
export const FIELD_ELEMENTS_PER_BLOB = 2048

const BLS12_381_SCALAR_FIELD_ORDER = bls12_381.fields.Fr.ORDER

export function evaluatePolynomialAt(polynomial: bigint[], z: bigint): bigint {
  const zReduced = mod(z, BLS12_381_SCALAR_FIELD_ORDER)

  let y = 0n
  let zPower = 1n

  for (const coeff of polynomial) {
    const term = mod(coeff * zPower, BLS12_381_SCALAR_FIELD_ORDER)
    y = mod(y + term, BLS12_381_SCALAR_FIELD_ORDER)
    zPower = mod(zPower * zReduced, BLS12_381_SCALAR_FIELD_ORDER)
  }
  return y
}

export function polynomialToBlob(polynomial: bigint[]): Uint8Array {
  const blob = new Uint8Array(BYTES_PER_BLOB)

  for (let i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
    const coeff = polynomial[i] ?? 0n

    const reducedCoeff = mod(coeff, BLS12_381_SCALAR_FIELD_ORDER)

    const coeffBytes = bigintToBytes32BE(reducedCoeff)
    blob.set(coeffBytes, i * 32)
  }

  return blob
}

function bytes32BEToBigint(bytes: Uint8Array): bigint {
  let value = 0n
  for (let i = 0; i < 32; i++) {
    value = (value << 8n) | BigInt(bytes[i] ?? 0)
  }
  return value
}

export function blobToPolynomial(blob: Uint8Array): bigint[] {
  if (blob.length !== BYTES_PER_BLOB) {
    throw new Error(`Blob must be ${BYTES_PER_BLOB} bytes, got ${blob.length}`)
  }

  const polynomial: bigint[] = []

  for (let i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
    const coeffBytes = blob.slice(i * 32, (i + 1) * 32)
    const coeff = bytes32BEToBigint(coeffBytes)
    polynomial.push(coeff)
  }

  return polynomial
}

export function blobToKzgCommitment(
  blob: Uint8Array,
  srsG1Points: Uint8Array[],
): Safe<Uint8Array> {
  if (blob.length !== BYTES_PER_BLOB) {
    return safeError(
      new Error(`Blob must be ${BYTES_PER_BLOB} bytes, got ${blob.length}`),
    )
  }

  const polynomial = blobToPolynomial(blob)
  return commitPolynomialCoeffs(polynomial, srsG1Points)
}

export function commitPolynomialCoeffs(
  coeffs: bigint[],
  srsG1Points: Uint8Array[],
): Safe<Uint8Array> {
  if (srsG1Points.length < coeffs.length) {
    return safeError(
      new Error(
        `SRS has ${srsG1Points.length} points, but polynomial has ${coeffs.length} coefficients (degree ${coeffs.length - 1})`,
      ),
    )
  }

  let commitment = bls12_381.G1.Point.ZERO

  for (let i = 0; i < coeffs.length; i++) {
    const coeff = coeffs[i]!
    if (coeff === 0n) continue

    const reducedCoeff = mod(coeff, BLS12_381_SCALAR_FIELD_ORDER)
    const srsPoint = bls12_381.G1.Point.fromBytes(srsG1Points[i]!)
    const scaledPoint = srsPoint.multiply(reducedCoeff)
    commitment = commitment.add(scaledPoint)
  }

  return safeResult(commitment.toBytes(true))
}

export function computeBlobKzgProof(
  blob: Uint8Array,
  zBytes: Uint8Array,
  srsG1Points: Uint8Array[],
): Safe<Uint8Array> {
  if (blob.length !== BYTES_PER_BLOB) {
    return safeError(
      new Error(`Blob must be ${BYTES_PER_BLOB} bytes, got ${blob.length}`),
    )
  }

  const polynomial = blobToPolynomial(blob)
  return computeKzgProofFromCoeffs(polynomial, zBytes, srsG1Points)
}

export function computeKzgProofFromCoeffs(
  polynomial: bigint[],
  zBytes: Uint8Array,
  srsG1Points: Uint8Array[],
): Safe<Uint8Array> {
  if (zBytes.length !== 32) {
    return safeError(new Error(`z must be 32 bytes, got ${zBytes.length}`))
  }

  const z = bytes32BEToBigint(zBytes)
  const zReduced = mod(z, BLS12_381_SCALAR_FIELD_ORDER)
  const y = evaluatePolynomialAt(polynomial, z)

  const n = polynomial.length
  const quotient: bigint[] = new Array(n - 1).fill(0n)

  if (n > 1) {
    quotient[n - 2] = polynomial[n - 1] ?? 0n
  }

  for (let i = n - 3; i >= 0; i--) {
    const coeff = polynomial[i + 1] ?? 0n
    const nextQ = quotient[i + 1] ?? 0n
    quotient[i] = mod(
      coeff + mod(zReduced * nextQ, BLS12_381_SCALAR_FIELD_ORDER),
      BLS12_381_SCALAR_FIELD_ORDER,
    )
  }

  if (zReduced === 0n) {
    for (let i = 0; i < n - 1; i++) {
      quotient[i] = polynomial[i + 1] ?? 0n
    }
  } else {
    const c0 = polynomial[0] ?? 0n
    const numerator = mod(y - c0, BLS12_381_SCALAR_FIELD_ORDER)
    const zInv = modInverse(zReduced, BLS12_381_SCALAR_FIELD_ORDER)
    quotient[0] = mod(numerator * zInv, BLS12_381_SCALAR_FIELD_ORDER)
  }

  return commitPolynomialCoeffs(quotient, srsG1Points)
}

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

    const g2ZTau = g2Tau.subtract(g2.multiply(zReduced))

    const yG = g1.multiply(yReduced)

    const commitmentMinusY = commitment.subtract(yG)

    const left = bls12_381.pairing(commitmentMinusY, g2)
    const right = bls12_381.pairing(proof, g2ZTau)

    const rightInv = bls12_381.fields.Fp12.inv(right)
    const product = bls12_381.fields.Fp12.mul(left, rightInv)
    const final = bls12_381.fields.Fp12.finalExponentiate(product)

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

export function extractRingCoordinateVectors(ringKeys: Uint8Array[]): {
  xs: bigint[]
  ys: bigint[]
} {
  const scalarBitlen = 253
  const idleRows = 4
  const fieldModulus = BANDERSNATCH_PARAMS.FIELD_MODULUS

  const paddingPointBytes = hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
  const paddingPoint = BandersnatchCurve.bytesToPoint(paddingPointBytes)
  const paddingX = BigInt(paddingPoint.x.toString())
  const paddingY = BigInt(paddingPoint.y.toString())

  const negPaddingX = mod(-paddingX, fieldModulus)
  const negPaddingY = mod(-paddingY, fieldModulus)

  const vectorLength = ringKeys.length + scalarBitlen + idleRows + 1
  const xs: bigint[] = new Array(vectorLength)
  const ys: bigint[] = new Array(vectorLength)
  let idx = 0

  for (const key of ringKeys) {
    const isNullKey = key.every((byte) => byte === 0)
    const keyToUse = isNullKey ? paddingPointBytes : key
    const point = BandersnatchCurve.bytesToPoint(keyToUse)
    const xBigInt = BigInt(point.x.toString())
    const yBigInt = BigInt(point.y.toString())

    let xDiff = xBigInt - paddingX
    let yDiff = yBigInt - paddingY
    if (xDiff < 0n) xDiff += fieldModulus
    if (yDiff < 0n) yDiff += fieldModulus
    xs[idx] = mod(xDiff, fieldModulus)
    ys[idx] = mod(yDiff, fieldModulus)
    idx++
  }

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

    if (i < scalarBitlen - 1) {
      currentH = BandersnatchCurve.double(currentH)
    }
  }

  for (let i = 0; i < idleRows; i++) {
    xs[idx] = negPaddingX
    ys[idx] = negPaddingY
    idx++
  }

  xs[idx] = paddingX
  ys[idx] = paddingY

  return { xs, ys }
}

export function createRingPolynomial(ringKeys: Uint8Array[]): bigint[] {
  const maxRingSize = BANDERSNATCH_PARAMS.KZG_CONFIG.MAX_RING_SIZE

  if (ringKeys.length > maxRingSize) {
    throw new Error(
      `Ring size ${ringKeys.length} exceeds maximum ${maxRingSize}`,
    )
  }

  const domainSize = BANDERSNATCH_PARAMS.KZG_CONFIG.DOMAIN_SIZE
  const scalarBitlen = 253
  const keysetPartSize = domainSize - scalarBitlen - 1

  const polynomialLength = domainSize - 1
  const polynomial: bigint[] = new Array(polynomialLength).fill(0n)

  const { xs } = extractRingCoordinateVectors(ringKeys)

  const keysCount = ringKeys.length
  const hStartIndex = keysetPartSize

  for (let i = 0; i < keysCount && i < keysetPartSize; i++) {
    polynomial[i] = xs[i] ?? 0n
  }

  const powersOfHStartInXs = keysCount
  for (let i = 0; i < scalarBitlen; i++) {
    polynomial[hStartIndex + i] = xs[powersOfHStartInXs + i] ?? 0n
  }

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

export function bigintToBytes32BE(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32)
  let val = value

  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn)
    val = val >> 8n
  }

  return bytes
}
