import { sha512 } from '@noble/hashes/sha2.js'
import { BANDERSNATCH_PARAMS, mod } from '@pbnjam/bandersnatch'
import { bytesToBigInt } from 'viem/utils'

export const SUITE_BYTES = new TextEncoder().encode('Bandersnatch_SHA-512_ELL2')
const CHALLENGE_TAG = 0x02
const POINT_TO_HASH_TAG = 0x03
const COMPRESSED_POINT_LEN = 32
const CHALLENGE_SCALAR_LEN = 32

export function generateChallengeRfc9381(
  points: Uint8Array[],
  additionalData: Uint8Array = new Uint8Array(0),
): bigint {
  for (const point of points) {
    if (point.length !== COMPRESSED_POINT_LEN) {
      throw new Error(
        `Invalid point length: ${point.length}, expected ${COMPRESSED_POINT_LEN} bytes (compressed format)`,
      )
    }
  }

  const hashInput = new Uint8Array(
    SUITE_BYTES.length +
      1 +
      points.length * COMPRESSED_POINT_LEN +
      additionalData.length +
      1,
  )
  let offset = 0
  hashInput.set(SUITE_BYTES, offset)
  offset += SUITE_BYTES.length
  hashInput[offset++] = CHALLENGE_TAG
  for (const point of points) {
    hashInput.set(point, offset)
    offset += COMPRESSED_POINT_LEN
  }
  hashInput.set(additionalData, offset)
  offset += additionalData.length
  hashInput[offset] = 0x00

  const h = sha512(hashInput)
  return mod(
    bytesToBigInt(h.subarray(0, CHALLENGE_SCALAR_LEN)),
    BANDERSNATCH_PARAMS.CURVE_ORDER,
  )
}

export function pointToHashRfc9381(point: Uint8Array): Uint8Array {
  const hashInput = new Uint8Array(SUITE_BYTES.length + 1 + point.length + 1)
  let offset = 0
  hashInput.set(SUITE_BYTES, offset)
  offset += SUITE_BYTES.length
  hashInput[offset++] = POINT_TO_HASH_TAG
  hashInput.set(point, offset)
  offset += point.length
  hashInput[offset] = 0x00

  return sha512(hashInput)
}
