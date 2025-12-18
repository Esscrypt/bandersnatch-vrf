/**
 * RFC-9381 Challenge Generation Implementation
 *
 * Implements challenge generation as specified in RFC-9381 for VRF
 * Reference: https://datatracker.ietf.org/doc/rfc9381/
 */

import { sha512 } from '@noble/hashes/sha2'
import { BANDERSNATCH_PARAMS, mod } from '@pbnj/bandersnatch'
import { bytesToBigInt } from 'viem'

/**
 * Generate challenge according to RFC-9381
 *
 * This implements the challenge generation procedure from RFC-9381 Section 5.4.2.1
 * which is used in the Bandersnatch VRF specification.
 *
 * According to the spec section 1.9, the input should be points P ∈ G^n, and
 * step 2 uses point_to_string(P_{i-1}). The callers serialize points using
 * BandersnatchCurve.pointToBytes() which implements point_to_string (compressed
 * form, 32 bytes per point as per spec section 2.1).
 *
 * @param points - Array of serialized curve points (32 bytes each, compressed format)
 *                 These should be serialized using BandersnatchCurve.pointToBytes()
 *                 which implements point_to_string per spec section 2.1
 * @param additionalData - Additional data to include in challenge
 * @returns The challenge scalar
 */
export function generateChallengeRfc9381(
  points: Uint8Array[],
  additionalData: Uint8Array = new Uint8Array(0),
): bigint {
  // Step 1: str_0 = suite_string || 0x02
  const suiteString = 'Bandersnatch_SHA-512_ELL2'
  const str0 = new Uint8Array(suiteString.length + 1)
  str0.set(new TextEncoder().encode(suiteString), 0)
  str0[str0.length - 1] = 0x02

  // Step 2: str_i = str_{i-1} || point_to_string(P_{i-1}), i = 1 ... n
  // Note: points are already serialized using pointToBytes (point_to_string) by callers
  // Each point should be 32 bytes (compressed format per spec section 2.1)
  let currentStr = str0
  for (const point of points) {
    // Validate point length (should be 32 bytes for compressed format)
    if (point.length !== 32) {
      throw new Error(
        `Invalid point length: ${point.length}, expected 32 bytes (compressed format)`,
      )
    }
    const newStr = new Uint8Array(currentStr.length + point.length)
    newStr.set(currentStr, 0)
    newStr.set(point, currentStr.length)
    currentStr = newStr
  }

  // Step 3: h = hash(str_n || ad || 0x00)
  const hashInput = new Uint8Array(
    currentStr.length + additionalData.length + 1,
  )
  hashInput.set(currentStr, 0)
  hashInput.set(additionalData, currentStr.length)
  hashInput[hashInput.length - 1] = 0x00

  const h = sha512(hashInput)

  // Step 4: c = string_to_int(h_{0 ... cLen - 1})
  // For Bandersnatch, cLen is 32 bytes (256 bits)
  // Rust reference: challenge_rfc_9381 uses from_be_bytes_mod_order (line 160 in common.rs)
  // So we always interpret hash bytes as big-endian to match the Rust reference
  const cLen = 32
  const cBytes = h.slice(0, cLen)
  const c = mod(
    bytesToBigInt(cBytes), // Big-endian (matches Rust reference)
    BANDERSNATCH_PARAMS.CURVE_ORDER,
  )

  return c
}

/**
 * Point-to-hash according to RFC-9381
 *
 * This implements the point-to-hash procedure from RFC-9381 Section 5.4.2.3
 * which is used in the Bandersnatch VRF specification.
 *
 * @param point - Curve point to hash
 * @param mulByCofactor - Whether to multiply by cofactor
 * @returns The hash output
 */
export function pointToHashRfc9381(
  point: Uint8Array,
  _mulByCofactor = false,
): Uint8Array {
  // Step 1: str_0 = suite_string || 0x03
  const suiteString = 'Bandersnatch_SHA-512_ELL2'
  const str0 = new Uint8Array(suiteString.length + 1)
  str0.set(new TextEncoder().encode(suiteString), 0)
  str0[str0.length - 1] = 0x03

  // Step 2: str_1 = str_0 || point_to_string(P)
  const str1 = new Uint8Array(str0.length + point.length)
  str1.set(str0, 0)
  str1.set(point, str0.length)

  // Step 3: str_2 = str_1 || 0x00
  const str2 = new Uint8Array(str1.length + 1)
  str2.set(str1, 0)
  str2[str2.length - 1] = 0x00

  // Step 4: h = hash(str_2)
  const h = sha512(str2)

  return h
}
