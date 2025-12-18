/**
 * Entropy VRF Signature Generation and Verification
 *
 * Implements Gray Paper safrole.tex equation 158:
 * H_vrfsig ∈ bssignature{H_authorbskey}{Xentropy ∥ banderout{H_sealsig}}{[]}
 *
 * ============================================================================
 * GRAY PAPER SPECIFICATION:
 * ============================================================================
 *
 * Gray Paper safrole.tex equation 158:
 * H_vrfsig ∈ bssignature{H_authorbskey}{Xentropy ∥ banderout{H_sealsig}}{[]}
 *
 * Gray Paper safrole.tex equation 159:
 * Xentropy = "$jam_entropy"
 *
 * Gray Paper bandersnatch.tex line 5:
 * The singly-contextualized Bandersnatch Schnorr-like signatures bssignature{k}{c}{m}
 * are defined as a formulation under the IETF VRF template
 *
 * Gray Paper bandersnatch.tex line 8:
 * bssignature{k ∈ bskey}{c ∈ hash}{m ∈ blob} ⊂ blob[96]
 * banderout{s ∈ bssignature{k}{c}{m}} ∈ hash ≡ text{output}(x | x ∈ bssignature{k}{c}{m})[:32]
 *
 * ============================================================================
 * IMPLEMENTATION NOTES:
 * ============================================================================
 *
 * 1. IETF VRF provides deterministic, verifiable randomness for entropy
 * 2. Context: Xentropy ∥ banderout{H_sealsig} (concatenated)
 * 3. Message: [] (empty blob - no message data)
 * 4. Output: 96-byte IETF VRF signature
 * 5. VRF output: 32-byte hash for entropy accumulation
 *
 * @fileoverview Entropy VRF signature generation and verification using IETF VRF on Bandersnatch curve
 */

import { BandersnatchCurve } from '@pbnj/bandersnatch'
import {
  getBanderoutFromGamma,
  IETFVRFProver,
  IETFVRFVerifier,
  pointToHashRfc9381,
} from '@pbnj/bandersnatch-vrf'
import { bytesToHex } from 'viem'
import type { Safe } from '@pbnj/types'
import { safeError, safeResult } from '@pbnj/types'

/**
 * Gray Paper hardcoded context string for entropy VRF
 * Gray Paper safrole.tex equation 159: Xentropy = "$jam_entropy"
 */
const XENTROPY = new TextEncoder().encode('jam_entropy')

/**
 * Generate IETF VRF signature for entropy according to Gray Paper equation 158
 *
 * Implements Gray Paper safrole.tex equation 158:
 * H_vrfsig ∈ bssignature{H_authorbskey}{Xentropy ∥ banderout{H_sealsig}}{[]}
 *
 * This generates a deterministic, verifiable signature that provides:
 * 1. Entropy for the next block's randomness
 * 2. Proof that the block was authored by a validator with the correct secret key
 * 3. Unbiasable randomness derived from the seal signature
 *
 * @param validatorSecretKey - Validator's Bandersnatch secret key (32 bytes)
 * @param sealOutput - VRF output from seal signature (32 bytes from banderout{H_sealsig})
 * @returns IETF VRF signature (96 bytes) and VRF output hash (32 bytes)
 */
export function generateEntropyVRFSignature(
  validatorSecretKey: Uint8Array,
  sealOutput: Uint8Array,
): Safe<{
  signature: Uint8Array // 96-byte IETF VRF signature
  banderoutResult: Uint8Array // 32-byte VRF output hash
}> {
  // Validate inputs
  if (validatorSecretKey.length !== 32) {
    return safeError(new Error('Validator secret key must be 32 bytes'))
  }

  if (sealOutput.length !== 32) {
    return safeError(new Error('Seal output must be 32 bytes'))
  }

  // Build VRF context according to Gray Paper equation 158:
  // context = Xentropy ∥ banderout{H_sealsig}
  const context = new Uint8Array(XENTROPY.length + sealOutput.length)
  let offset = 0
  context.set(XENTROPY, offset)
  offset += XENTROPY.length
  context.set(sealOutput, offset)

  // Generate IETF VRF signature using IETFVRFProver
  // Gray Paper equation 158: bssignature{k}{c}{m} where:
  // k = validatorSecretKey, c = context, m = [] (empty message)
  // NOTE: When m = [] (empty), the context c becomes the input (hashed to curve point)
  // This matches the pattern used in audit signatures (bssignature{k}{c}{[]})
  // IETFVRFProver.prove parameter order is (secretKey, input, auxData)
  const vrfResult = IETFVRFProver.prove(
    validatorSecretKey,
    context, // Xentropy ∥ banderout{H_sealsig} (context) - becomes input when m = []
    new Uint8Array(0), // [] (empty auxData)
  )

  // Verify the signature is the correct length (96 bytes per Gray Paper)
  if (vrfResult.proof.length !== 96) {
    console.warn('IETF VRF signature has unexpected length', {
      expected: 96,
      actual: vrfResult.proof.length,
    })
  }

  // Verify the VRF output is the correct length (32 bytes per Gray Paper)
  // Extract banderout result: first 32 bytes of VRF output hash
  // Gray Paper: banderout{s ∈ bssignature{k}{c}{m}} ∈ hash ≡ text{output}(x | x ∈ bssignature{k}{c}{m})[:32]
  const banderoutResult = getBanderoutFromGamma(vrfResult.gamma)

  return safeResult({
    signature: vrfResult.proof,
    banderoutResult,
  })
}

/**
 * Verify IETF VRF signature for entropy according to Gray Paper equation 158
 *
 * Implements Gray Paper safrole.tex equation 158 verification:
 * H_vrfsig ∈ bssignature{H_authorbskey}{Xentropy ∥ banderout{H_sealsig}}{[]}
 *
 * This verifies that:
 * 1. The signature was generated by someone with the correct secret key
 * 2. The signature corresponds to the correct context and empty message
 * 3. The VRF output provides deterministic, verifiable randomness
 *
 * @param validatorPublicKey - Validator's Bandersnatch public key (32 bytes)
 * @param signature - IETF VRF signature to verify (96 bytes)
 * @param sealOutput - VRF output from seal signature (32 bytes from banderout{H_sealsig})
 * @returns True if signature is valid, false otherwise
 */
export function verifyEntropyVRFSignature(
  validatorPublicKey: Uint8Array,
  signature: Uint8Array,
  sealOutput: Uint8Array,
): Safe<boolean> {
  // Validate inputs
  if (validatorPublicKey.length !== 32) {
    return safeError(new Error('Validator public key must be 32 bytes'))
  }

  if (signature.length !== 96) {
    return safeError(new Error('IETF VRF signature must be 96 bytes'))
  }

  if (sealOutput.length !== 32) {
    return safeError(new Error('Seal output must be 32 bytes'))
  }

  // Build VRF context according to Gray Paper equation 158:
  // context = Xentropy ∥ banderout{H_sealsig}
  const context = new Uint8Array(XENTROPY.length + sealOutput.length)
  let offset = 0
  context.set(XENTROPY, offset)
  offset += XENTROPY.length
  context.set(sealOutput, offset)

  // Verify IETF VRF signature using IETFVRFVerifier
  // Gray Paper equation 158: bssignature{k}{c}{m} where:
  // k = validatorPublicKey, c = context, m = [] (empty message)
  // NOTE: When m = [] (empty), the context c becomes the input (hashed to curve point)
  // This matches the pattern used in audit signatures (bssignature{k}{c}{[]})
  // IETFVRFVerifier.verify parameter order is (publicKey, input, proof, auxData)
  const isValid = IETFVRFVerifier.verify(
    validatorPublicKey,
    context, // Xentropy ∥ banderout{H_sealsig} (context) - becomes input when m = []
    signature,
    new Uint8Array(0), // [] (empty auxData)
  )

  if (!isValid) {
    console.error('Entropy VRF signature verification failed', {
      publicKeyHex: bytesToHex(validatorPublicKey),
      contextHex: bytesToHex(context),
      signatureHex: bytesToHex(signature),
    })
  }

  return safeResult(isValid)
}

/**
 * Extract VRF output from seal signature using banderout function
 *
 * Gray Paper bandersnatch.tex line 8:
 * banderout{s ∈ bssignature{k}{c}{m}} ∈ hash ≡ text{output}(x | x ∈ bssignature{k}{c}{m})[:32]
 *
 * Bandersnatch VRF spec section 1.6:
 * VRF output is produced using output-to-hash procedure, which is proof-to-hash method
 * from RFC-9381 Section 5.2, but with a specific focus on the output point component
 * (referred to as Gamma in RFC-9381). This is implemented using point-to-hash from
 * RFC-9381 Section 5.4.2.3, which hashes a single point (gamma).
 *
 * @param sealSignature - IETF VRF seal signature (96 bytes)
 * @returns First 32 bytes of VRF output hash
 */
export function banderout(sealSignature: Uint8Array): Safe<Uint8Array> {
  if (sealSignature.length !== 96) {
    return safeError(new Error('Seal signature must be 96 bytes'))
  }

  // Extract gamma (VRF output point) from the proof (first 32 bytes)
  // Gray Paper: gamma is the first component of bssignature{k}{c}{m} = (gamma, c, s)
  const gammaFromProof = sealSignature.slice(0, 32)

  // Normalize gamma to ensure canonical compressed format (consistent with verifier)
  // RFC-9381: point_to_string(P) should produce canonical compressed encoding
  // We normalize by: bytes → point → bytes to ensure consistency
  const gammaPoint = BandersnatchCurve.bytesToPoint(gammaFromProof)
  const gamma = BandersnatchCurve.pointToBytes(gammaPoint) // point_to_string(P)

  // Hash gamma using point-to-hash procedure from RFC-9381 Section 5.4.2.3
  // Bandersnatch VRF spec section 1.6: o ← output_to_hash(O) where O is the VRF output point
  // This implements the "proof-to-hash with focus on output point component" as specified
  // RFC-9381 Section 5.4.2.3: str_1 = str_0 || point_to_string(P)
  const vrfOutputHash = pointToHashRfc9381(gamma, false)

  // Gray Paper: banderout returns first 32 bytes of the VRF output hash
  // Bandersnatch VRF spec: The output is a fixed-length octet string (we take first 32 bytes)
  const banderoutResult = vrfOutputHash.slice(0, 32)

  return safeResult(banderoutResult)
}
