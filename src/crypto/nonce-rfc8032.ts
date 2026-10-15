import { sha512 } from '@noble/hashes/sha2.js'
import {
  BANDERSNATCH_PARAMS,
  mod,
  numberToBytesLittleEndian,
} from '@pbnjam/bandersnatch'
import { bytesToBigIntLittleEndian } from './elligator2.ts'

export function generateNonceRfc8032(
  secretKey: Uint8Array,
  inputPoint: Uint8Array,
): Uint8Array {
  const encodedScalar = secretKey

  const skHash = sha512(encodedScalar)
  const combined = new Uint8Array(32 + inputPoint.length)
  combined.set(skHash.subarray(32), 0)
  combined.set(inputPoint, 32)

  const h = sha512(combined)

  const hashValue = bytesToBigIntLittleEndian(h)
  const scalar = mod(hashValue, BANDERSNATCH_PARAMS.CURVE_ORDER)

  const nonce = numberToBytesLittleEndian(scalar)

  return nonce
}
