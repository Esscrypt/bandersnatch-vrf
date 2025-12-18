/**
 * RFC-8032 Nonce Generation Implementation
 *
 * Implements nonce generation as specified in RFC-8032 and used in the Rust implementation
 * Reference: https://www.rfc-editor.org/rfc/rfc8032.html
 */

import { sha512 } from '@noble/hashes/sha2'
import { BANDERSNATCH_PARAMS } from '@pbnj/bandersnatch'
import { mod, numberToBytesLittleEndian } from '@pbnj/bandersnatch'
import { bytesToBigIntLittleEndian } from './elligator2'

/**
 * Generate nonce according to RFC-8032 (matches Rust implementation)
 *
 * This is the nonce generation method used in the Rust bandersnatch-vrf-spec
 * and differs from the RFC-9381 method we initially implemented.
 *
 * Rust implementation (ark-vrf/src/utils/common.rs):
 * 1. Encode scalar using scalar_encode (little-endian serialization)
 * 2. Hash the encoded scalar bytes
 * 3. Take bytes [32..] (last 32 bytes of hash)
 * 4. Encode input point
 * 5. Concatenate sk_hash + input_point
 * 6. Hash the concatenation
 * 7. Decode hash as scalar using from_le_bytes_mod_order
 *
 * @param secretKey - The secret key (already in little-endian format, 32 bytes)
 * @param inputPoint - The input point (serialized, already encoded)
 * @returns The nonce scalar as bytes
 */
export function generateNonceRfc8032(
  secretKey: Uint8Array,
  inputPoint: Uint8Array,
): Uint8Array {
  // Step 1: Encode the scalar (secret key) using scalar_encode
  // For ArkworksCodec, scalar_encode uses serialize_compressed which is little-endian
  // Since secretKey is already 32 bytes in little-endian format, we can use it directly
  // as the encoded form (scalar_encode for Bandersnatch just serializes in little-endian)
  const encodedScalar = secretKey

  // Step 2: Hash the encoded scalar bytes
  const skHash = sha512(encodedScalar)
  const skHashSecondHalf = skHash.slice(32) // Take last 32 bytes (bytes [32..])

  // Step 3: Concatenate sk_hash + input_point
  // Note: inputPoint is already encoded (from point_encode in the prover)
  const combined = new Uint8Array([...skHashSecondHalf, ...inputPoint])

  // Step 4: Hash the combination
  const h = sha512(combined)

  // Step 5: Decode hash as scalar using from_le_bytes_mod_order (little-endian)
  const hashValue = bytesToBigIntLittleEndian(h)
  const scalar = mod(hashValue, BANDERSNATCH_PARAMS.CURVE_ORDER)

  const nonce = numberToBytesLittleEndian(scalar)

  return nonce
}
