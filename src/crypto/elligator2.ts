import type { EdwardsPoint } from '@noble/curves/abstract/edwards.js'
import { edwards } from '@noble/curves/abstract/edwards.js'
import { pow } from '@noble/curves/abstract/modular.js'
import { sha512 } from '@noble/hashes/sha2.js'
import {
  BANDERSNATCH_PARAMS,
  BandersnatchCurve,
  type CurvePoint,
  mod,
  modInverse,
  modSqrt,
} from '@pbnjam/bandersnatch'
import { bytesToHex } from 'viem'

export function bytesToBigIntLittleEndian(bytes: Uint8Array): bigint {
  let result = 0n
  for (let i = 0; i < bytes.length; i++) {
    result += BigInt(bytes[i]) << (8n * BigInt(i))
  }
  return result
}

export function bytesToBigIntBigEndian(bytes: Uint8Array): bigint {
  let result = 0n
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i])
  }
  return result
}

const ECVRF_HASH_TO_FIELD_DST = new TextEncoder().encode(
  'ECVRF_Bandersnatch_XMD:SHA-512_ELL2_RO_Bandersnatch_SHA-512_ELL2',
)
const H2C_OVERSIZE_DST_PREFIX = new TextEncoder().encode('H2C-OVERSIZE-DST-')
const ARKWORKS_EXPAND_Z_PAD = new Uint8Array(48)

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

export function elligator2HashToCurve(message: Uint8Array): CurvePoint {
  try {
    const [u1, u2] = hashToField(message)

    const point1 = elligator2Map(u1)
    const point2 = elligator2Map(u2)

    const sum = addPoints(point1, point2)

    const cleared = clearCofactor(sum)

    return cleared
  } catch (error) {
    console.error('[Elligator2] hash-to-curve failed', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    })
    throw new Error(
      `Elligator2 hash-to-curve failed: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
}

export function curvePointToNoble(point: CurvePoint): EdwardsPoint {
  return Bandersnatch.fromAffine({
    x: point.x,
    y: point.y,
  })
}

export function compressPoint(point: CurvePoint): string {
  const noblePoint = curvePointToNoble(point)

  const arkworksBytes = BandersnatchCurve.pointToBytes(noblePoint)

  return bytesToHex(arkworksBytes).slice(2)
}

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

function arkworksExpandMessageXmd(
  msg: Uint8Array,
  DST: string | Uint8Array,
  lenInBytes: number,
): Uint8Array {
  DST = normDST(DST)

  if (DST.length > 255) {
    DST = sha512(concatBytes(H2C_OVERSIZE_DST_PREFIX, DST))
  }

  const b_in_bytes = 64
  const ell = Math.ceil(lenInBytes / b_in_bytes)
  if (lenInBytes > 65535 || ell > 255)
    throw new Error('expand_message_xmd: invalid lenInBytes')

  const DST_prime = concatBytes(DST, i2osp(DST.length, 1))

  const l_i_b_str = i2osp(lenInBytes, 2)

  const b_0 = sha512(
    concatBytes(ARKWORKS_EXPAND_Z_PAD, msg, l_i_b_str, i2osp(0, 1), DST_prime),
  )

  const b = new Array<Uint8Array>(ell)
  b[0] = sha512(concatBytes(b_0, i2osp(1, 1), DST_prime))

  for (let i = 1; i < ell; i++) {
    const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime]
    b[i] = sha512(concatBytes(...args))
  }

  const pseudo_random_bytes = concatBytes(...b)
  return pseudo_random_bytes.slice(0, lenInBytes)
}

export function hashToField(message: Uint8Array): [bigint, bigint] {
  const MODULUS_BIT_SIZE = 255
  const SEC_PARAM = 128
  const base_field_size_with_security_padding_in_bits =
    MODULUS_BIT_SIZE + SEC_PARAM
  const len_per_base_elem = Math.ceil(
    base_field_size_with_security_padding_in_bits / 8,
  )

  const N = 2
  const m = 1
  const len_in_bytes = N * m * len_per_base_elem

  const uniform_bytes = arkworksExpandMessageXmd(
    message,
    ECVRF_HASH_TO_FIELD_DST,
    len_in_bytes,
  )

  const u1_bytes = uniform_bytes.slice(0, len_per_base_elem)
  const u2_bytes = uniform_bytes.slice(len_per_base_elem, 2 * len_per_base_elem)

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

export function elligator2Map(u: bigint): CurvePoint {
  const p = BANDERSNATCH_PARAMS.FIELD_MODULUS

  const A = BigInt(
    '29978822694968839326280996386011761570173833766074948509196803838190355340952',
  )
  const B = BigInt(
    '25465760566081946422412445027709227188579564747101592991722834452325077642517',
  )

  const Z = BANDERSNATCH_PARAMS.ELLIGATOR2_CONFIG.Z

  const k = B
  const jOnK = BANDERSNATCH_PARAMS.ELLIGATOR2_CONFIG.COEFF_A_OVER_COEFF_B
  const kSqInv = BANDERSNATCH_PARAMS.ELLIGATOR2_CONFIG.ONE_OVER_COEFF_B_SQUARE

  const uSq = mod(u * u, p)
  const den1 = mod(1n + mod(Z * uSq, p), p)

  const x1 = mod(-jOnK * (den1 === 0n ? 1n : modInverse(den1, p)), p)

  const x1Sq = mod(x1 * x1, p)
  const x1Cb = mod(x1Sq * x1, p)
  const gx1 = mod(x1Cb + mod(jOnK * x1Sq, p) + mod(x1 * kSqInv, p), p)

  const x2 = mod(-x1 - jOnK, p)

  const x2Sq = mod(x2 * x2, p)
  const x2Cb = mod(x2Sq * x2, p)
  const gx2 = mod(x2Cb + mod(jOnK * x2Sq, p) + mod(x2 * kSqInv, p), p)

  let x
  let y
  let sgn0

  const gx1IsSquare = isSquare(gx1, p)
  const gx2IsSquare = isSquare(gx2, p)

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

  if (parity(y) !== sgn0) {
    y = mod(-y, p)
  }

  const s = mod(x * k, p)
  const t = mod(y * k, p)

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

export function parity(value: bigint): boolean {
  return mod(value, 2n) === 1n
}

export function isSquare(value: bigint, p: bigint): boolean {
  if (value === 0n) return true
  if (value === 1n) return true

  const legendre = pow(value, (p - 1n) / 2n, p)
  return legendre === 1n
}

export function clearCofactor(point: CurvePoint): CurvePoint {
  if (point.isInfinity) return point

  const cofactor = BANDERSNATCH_PARAMS.COFACTOR

  return scalarMultiply(point, cofactor)
}

export function isOnCurve(point: CurvePoint): boolean {
  if (point.isInfinity) return true

  const p = BANDERSNATCH_PARAMS.FIELD_MODULUS
  const a = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.a
  const d = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.d

  const x = point.x
  const y = point.y

  const x2 = mod(x * x, p)
  const y2 = mod(y * y, p)

  const leftSide = mod(a * x2 + y2, p)
  const rightSide = mod(1n + d * x2 * y2, p)

  return leftSide === rightSide
}

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

export function addPoints(p1: CurvePoint, p2: CurvePoint): CurvePoint {
  if (p1.isInfinity) return p2
  if (p2.isInfinity) return p1

  const p = BANDERSNATCH_PARAMS.FIELD_MODULUS
  const a = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.a
  const d = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS.d

  if (p1.x === p2.x && p1.y === p2.y) {

    const x1 = p1.x
    const y1 = p1.y

    const x1Sq = mod(x1 * x1, p)
    const y1Sq = mod(y1 * y1, p)
    const ax1Sq = mod(a * x1Sq, p)

    const x3Numerator = mod(2n * x1 * y1, p)
    const x3Denominator = mod(ax1Sq + y1Sq, p)

    if (x3Denominator === 0n) {
      return { x: 0n, y: 1n, isInfinity: true }
    }

    const x3DenomInv = modInverse(x3Denominator, p)
    const x3 = mod(x3Numerator * x3DenomInv, p)

    const y3Numerator = mod(y1Sq - ax1Sq, p)
    const y3Denominator = mod(2n - ax1Sq - y1Sq, p)

    if (y3Denominator === 0n) {
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
    return { x: 0n, y: 1n, isInfinity: true }
  }

  const x3DenomInv = modInverse(x3Denominator, p)
  const x3 = mod(x3Numerator * x3DenomInv, p)

  const y3Numerator = mod(y1y2 - a * x1x2, p)
  const y3Denominator = mod(1n - dxy, p)

  if (y3Denominator === 0n) {
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
