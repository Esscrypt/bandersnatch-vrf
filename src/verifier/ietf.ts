/**
 * IETF VRF Verifier Implementation
 *
 * Implements verification for IETF VRF scheme
 */

import { BANDERSNATCH_PARAMS, BandersnatchCurve, mod } from '@pbnj/bandersnatch'
import { bytesToHex } from 'viem'
import { bytesToBigIntLittleEndian } from '../crypto/elligator2'
import { generateChallengeRfc9381 } from '../crypto/rfc9381'
import { IETFVRFProver } from '../prover/ietf'

/**
 * IETF VRF Verifier
 * Implements RFC-9381 VRF proof verification
 */
export class IETFVRFVerifier {
  /**
   * Verify VRF proof
   *
   * @param publicKey - Public key point (32 bytes, compressed)
   * @param input - VRF input data
   * @param proof - VRF proof (96 bytes: gamma, c, s)
   * @param auxData - Additional data (optional)
   * @returns true if proof is valid, false otherwise
   */
  static verify(
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array,
    auxData?: Uint8Array,
  ): boolean {
    // 1. Hash input to curve point (H1)
    // According to RFC-9381: ECVRF_encode_to_curve receives salt || alpha
    // Even though encode_to_curve_salt is empty, we concatenate for consistency
    const salt = new Uint8Array(0) // Empty salt as per spec section 2.1
    const h2cData = new Uint8Array(salt.length + input.length)
    h2cData.set(salt, 0)
    h2cData.set(input, salt.length)

    // Use the same hashToCurve method as the prover for consistency
    const alphaBytes = IETFVRFProver.hashToCurve(h2cData)

    // 2. Verify proof
    const isValid = this.verifyProof(publicKey, alphaBytes, proof, auxData)

    return isValid
  }

  /**
   * Verify VRF proof
   *
   * @param publicKey - Public key point (32 bytes, compressed)
   * @param alpha - VRF input point (32 bytes, compressed)
   * @param proof - VRF proof (96 bytes: gamma, c, s)
   * @param auxData - Additional data (optional)
   * @returns true if proof is valid, false otherwise
   */
  private static verifyProof(
    publicKey: Uint8Array,
    alpha: Uint8Array,
    proof: Uint8Array,
    auxData?: Uint8Array,
  ): boolean {
    // IETF VRF proof verification (RFC-9381)
    // Verify that: g^s = u + y^c and h^s = v + gamma^c

    // Parse proof as (gamma, c, s) - Gray Paper: blob[96] = 32 + 32 + 32 bytes
    if (proof.length !== 96) {
      return false
    }

    const gammaFromProof = proof.slice(0, 32) // VRF output point
    const cUint8Array = proof.slice(32, 64) // Challenge scalar
    const sUint8Array = proof.slice(64, 96) // Response scalar

    // Parse scalars from proof
    // Rust reference: ArkworksCodec uses from_le_bytes_mod_order for scalar_decode (line 71 in codec.rs)
    // So proof bytes are always in little-endian format
    const cOriginal = bytesToBigIntLittleEndian(cUint8Array) // Always little-endian (matches ArkworksCodec)
    const sOriginal = bytesToBigIntLittleEndian(sUint8Array) // Always little-endian (matches ArkworksCodec)

    // Reduce scalars modulo curve order as per spec: string_to_int reduces modulo prime field order
    const c = mod(cOriginal, BANDERSNATCH_PARAMS.CURVE_ORDER)
    const s = mod(sOriginal, BANDERSNATCH_PARAMS.CURVE_ORDER)

    // Convert inputs to curve points
    const alphaPoint = BandersnatchCurve.bytesToPoint(alpha)
    const gammaPoint = BandersnatchCurve.bytesToPoint(gammaFromProof) // Use gamma from proof
    const publicKeyPoint = BandersnatchCurve.bytesToPoint(publicKey) // Y = public key point

    // Calculate u and v (reconstructed R points from proof)
    // Based on IETF VRF spec section 2.3 Verify:
    // U ← s · G - c · Y  (where G is generator, Y is public key)
    // V ← s · I - c · O  (where I is input point alpha, O is output point gamma)
    const gToS = BandersnatchCurve.scalarMultiply(
      BandersnatchCurve.GENERATOR,
      s,
    )
    const yToC = BandersnatchCurve.scalarMultiply(publicKeyPoint, c)
    const u = BandersnatchCurve.add(
      gToS,
      BandersnatchCurve.negate(yToC),
    )

    const hToS = BandersnatchCurve.scalarMultiply(alphaPoint, s)
    const gammaToC = BandersnatchCurve.scalarMultiply(gammaPoint, c)
    const v = BandersnatchCurve.add(
      hToS,
      BandersnatchCurve.negate(gammaToC),
    )

    // Recreate challenge c according to bandersnatch-vrf-spec section 2.3 Verify step 4:
    // c' ← challenge(Y, I, O, U, V, ad)
    // where Y = publicKey, I = alpha (input point), O = gamma (output point), U = u, V = v
    const yBytes = BandersnatchCurve.pointToBytes(publicKeyPoint) // Y -> public key point
    const iBytes = BandersnatchCurve.pointToBytes(alphaPoint) // I -> input point
    const oBytes = BandersnatchCurve.pointToBytes(gammaPoint) // O -> output point
    const uBytes = BandersnatchCurve.pointToBytes(u) // U -> calculated
    const vBytes = BandersnatchCurve.pointToBytes(v) // V -> calculated

    const challengePoints = [yBytes, iBytes, oBytes, uBytes, vBytes]
    // Rust reference: challenge_rfc_9381 uses from_be_bytes_mod_order (line 160 in common.rs)
    // So challenge computation always uses big-endian
    const expectedC = this.hashToScalar(
      challengePoints,
      auxData || new Uint8Array(0),
    )

    // Compare c with expectedC (both are already reduced modulo curve order)
    // expectedC is already reduced by hashToScalar, and c is reduced above
    const isValid = c === expectedC

    if (!isValid) {
      console.debug('IETF VRF challenge mismatch', {
        yHex: bytesToHex(yBytes),
        iHex: bytesToHex(iBytes),
        oHex: bytesToHex(oBytes),
        uHex: bytesToHex(BandersnatchCurve.pointToBytes(u)),
        vHex: bytesToHex(BandersnatchCurve.pointToBytes(v)),
        auxDataHex: bytesToHex(auxData || new Uint8Array(0)),
        auxDataLength: auxData?.length || 0,
        cFromProof: c.toString(16),
        cOriginal: cOriginal.toString(16),
        cReduced: c.toString(16),
        expectedC: expectedC.toString(16),
        cMatches: c === expectedC,
        gammaHex: bytesToHex(gammaFromProof),
      })
    }

    return isValid
  }

  /**
   * Hash to scalar for challenge verification
   * Implements the challenge generation per IETF RFC-9381
   */
  private static hashToScalar(
    points: Uint8Array[],
    auxData: Uint8Array = new Uint8Array(0),
  ): bigint {
    // Use RFC-9381 challenge generation which implements proper hash-to-scalar
    // Rust reference: challenge_rfc_9381 uses from_be_bytes_mod_order (big-endian)
    return generateChallengeRfc9381(points, auxData)
  }
}
