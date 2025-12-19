/**
 * IETF VRF Prover Implementation
 *
 * Implements RFC-9381 VRF proof generation
 */

import { BandersnatchCurve, mod, numberToBytesLittleEndian } from '@pbnjam/bandersnatch'
import { bytesToHex  } from 'viem'
import {
  bytesToBigIntLittleEndian,
  curvePointToNoble,
  elligator2HashToCurve,
} from '../crypto/elligator2'
import { generateNonceRfc8032 } from '../crypto/nonce-rfc8032'
import { generateChallengeRfc9381 } from '../crypto/rfc9381'

/**
 * IETF VRF result
 */
export interface IETFVRFResult {
  /** VRF output gamma point */
  gamma: Uint8Array
  /** Serialized proof */
  proof: Uint8Array
}

/**
 * IETF VRF Prover
 * Implements RFC-9381 VRF proof generation
 */
export class IETFVRFProver {
  /**
   * Generate VRF proof and output
   */
  static prove(
    secretKey: Uint8Array,
    input: Uint8Array,
    auxData?: Uint8Array,
  ): IETFVRFResult {
    try {
      // 1. Hash input to curve point (H1)
      // According to ark-vrf implementation: h2c_data = salt || alpha
      const salt = new Uint8Array(0) // Empty salt as per test vectors
      const h2cData = new Uint8Array(salt.length + input.length)
      h2cData.set(salt, 0)
      h2cData.set(input, salt.length)

      const alpha = this.hashToCurve(h2cData)

      // 2. Scalar multiplication: gamma = alpha * secretKey
      const gamma = this.scalarMultiply(alpha, secretKey)

      // 3. Generate proof
      const proof = this.generateProof(secretKey, alpha, gamma, auxData)

      return {
        gamma,
        proof,
      }
    } catch (error) {
      console.error('IETF VRF proof generation failed', {
        error: error instanceof Error ? error.message : String(error),
      })
      throw new Error(
        `VRF proof generation failed: ${error instanceof Error ? error.message : String(error)}`,
      )
    }
  }

  /**
   * Hash input to curve point (H1 function)
   */
  static hashToCurve(message: Uint8Array): Uint8Array {
    // Use Elligator2 for hash-to-curve as specified in the Bandersnatch VRF spec
    const point = elligator2HashToCurve(message)
    // Convert CurvePoint to bytes using the compression function from elligator2
    return BandersnatchCurve.pointToBytes(curvePointToNoble(point))
  }

  /**
   * Scalar multiplication on Bandersnatch curve
   */
  private static scalarMultiply(
    pointUint8Array: Uint8Array,
    scalarUint8Array: Uint8Array,
  ): Uint8Array {
    const point = BandersnatchCurve.bytesToPoint(pointUint8Array)
    const scalar = mod(
      bytesToBigIntLittleEndian(scalarUint8Array),
      BandersnatchCurve.CURVE_ORDER,
    )
    const result = BandersnatchCurve.scalarMultiply(point, scalar)
    // Use our arkworks-compatible compression instead of Noble's native compression
    return BandersnatchCurve.pointToBytes(result)
  }

  /**
   * Generate VRF proof using RFC-9381 compliant procedures
   */
  private static generateProof(
    secretKey: Uint8Array,
    alpha: Uint8Array,
    gamma: Uint8Array,
    auxData?: Uint8Array,
  ): Uint8Array {
    // IETF VRF proof generation (RFC-9381)
    // Proof = (c, s) where:
    // c ← challenge(Y, I, O, k · G, k · I, ad)  (per spec section 2.2 step 4)
    // s = k + c * x (mod q)

    // Convert alpha and gamma to curve points
    const alphaPoint = BandersnatchCurve.bytesToPoint(alpha)
    const gammaPoint = BandersnatchCurve.bytesToPoint(gamma)

    // Generate nonce k using RFC-8032
    const kBytes = generateNonceRfc8032(secretKey, alpha)
    const k = bytesToBigIntLittleEndian(kBytes)

    // Calculate k · G (where G is the generator)
    const gToS = BandersnatchCurve.scalarMultiply(
      BandersnatchCurve.GENERATOR,
      k,
    )

    // Calculate k · I (where I is alpha, the input point)
    const hToC = BandersnatchCurve.scalarMultiply(alphaPoint, k)

    // Calculate challenge c according to bandersnatch-vrf-spec section 2.2 Prove step 4:
    // c ← challenge(Y, I, O, k · G, k · I, ad)
    // where Y = publicKey, I = alpha, O = gamma, k·G = gToS, k·I = hToC
    const publicKeyPoint = BandersnatchCurve.scalarMultiply(
      BandersnatchCurve.GENERATOR,
      mod(
        bytesToBigIntLittleEndian(secretKey),
        BandersnatchCurve.CURVE_ORDER,
      ),
    )
    const challengePoints = [
      BandersnatchCurve.pointToBytes(publicKeyPoint), // Y
      BandersnatchCurve.pointToBytes(alphaPoint), // I
      BandersnatchCurve.pointToBytes(gammaPoint), // O
      BandersnatchCurve.pointToBytes(gToS), // k · G
      BandersnatchCurve.pointToBytes(hToC), // k · I
    ]

    // Rust reference: challenge_rfc_9381 uses from_be_bytes_mod_order (line 160 in common.rs)
    // So challenge computation always uses big-endian
    const c = generateChallengeRfc9381(challengePoints, auxData)

    // Log challenge computation for debugging
    console.debug('IETF VRF prover challenge computation', {
      yHex: bytesToHex(BandersnatchCurve.pointToBytes(publicKeyPoint)),
      iHex: bytesToHex(BandersnatchCurve.pointToBytes(alphaPoint)),
      oHex: bytesToHex(BandersnatchCurve.pointToBytes(gammaPoint)),
      kGHex: bytesToHex(BandersnatchCurve.pointToBytes(gToS)),
      kIHex: bytesToHex(BandersnatchCurve.pointToBytes(hToC)),
      auxDataHex: bytesToHex(auxData || new Uint8Array(0)),
      auxDataLength: auxData?.length || 0,
      challengeC: c.toString(16),
    })

    // Calculate s = k + c * x (mod q)
    const x = mod(
      bytesToBigIntLittleEndian(secretKey),
      BandersnatchCurve.CURVE_ORDER,
    )
    const s = mod(k + c * x, BandersnatchCurve.CURVE_ORDER)

    // Serialize proof as (gamma, c, s) - each field element must be exactly 32 bytes
    // Gray Paper: bssignature{k}{c}{m} ⊂ blob[96] = 32 + 32 + 32 bytes
    // gamma is already 32 bytes (compressed point from pointToBytes)
    const gammaBytes = gamma // VRF output point (32 bytes)
    // Use little-endian encoding per bandersnatch-vrf-spec section 2.1:
    // "The int_to_string function encodes into the 32 octets little endian representation"
    const cBytes = numberToBytesLittleEndian(c) // Challenge scalar (32 bytes)
    const sBytes = numberToBytesLittleEndian(s) // Response scalar (32 bytes)

    const proofUint8Array = new Uint8Array([
      ...gammaBytes,
      ...cBytes,
      ...sBytes,
    ])

    return proofUint8Array
  }
}
