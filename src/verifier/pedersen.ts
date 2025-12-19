/**
 * Pedersen VRF Verifier Implementation
 *
 * Implements verification for Pedersen VRF scheme
 * Reference: Bandersnatch VRF specification section 3.3
 */

import {
  BANDERSNATCH_PARAMS,
  BandersnatchCurve,
  Bandersnatch,
} from '@pbnjam/bandersnatch'
import {
  bytesToBigIntLittleEndian,
  curvePointToNoble,
  elligator2HashToCurve,
} from '../crypto/elligator2'
import { type PedersenVRFProof, PedersenVRFProver } from '../prover/pedersen'

/**
 * Pedersen VRF Verifier
 * Implements Pedersen VRF proof verification
 */
export class PedersenVRFVerifier {
  /**
   * Verify Pedersen VRF proof according to bandersnatch-vrf-spec
   * The gamma (output) is provided as a parameter
   */
  static verify(
    input: Uint8Array,
    gamma: Uint8Array,
    proof: Uint8Array,
    auxData?: Uint8Array,
  ): boolean {
    if (proof.length !== 160) {
      throw new Error(
        'Invalid Pedersen VRF proof size, expected 160 bytes, got ' +
          proof.length +
          ' bytes',
      )
    }
    // Step 1: Deserialize proof components
    const pedersenProof = PedersenVRFProver.deserialize(proof)

    // Step 2: Hash input to curve point (H1) using Elligator2
    const I = this.hashToCurve(input)

    // Step 3: Verify proof using the provided gamma
    const isValid = this.verifyProof(I, gamma, pedersenProof, auxData)

    if (!isValid) {
      console.error('Pedersen VRF proof verification failed', {})
    } else {
      console.debug('Pedersen VRF proof verified successfully', {})
    }

    return isValid
  }

  /**
   * Hash input to curve point (H1 function)
   */
  static hashToCurve(message: Uint8Array): Uint8Array {
    // Use Elligator2 hash-to-curve for proper implementation
    const point = elligator2HashToCurve(message)
    return BandersnatchCurve.pointToBytes(curvePointToNoble(point))
  }

  /**
   * Get blinding base point B as Edwards point
   * From specification: B_x = 6150229251051246713677296363717454238956877613358614224171740096471278798312
   * B_y = 28442734166467795856797249030329035618871580593056783094884474814923353898473
   */
  private static getBlindingBase() {
    // Use the same pattern as the generator
    return Bandersnatch.fromAffine({
      x: BANDERSNATCH_PARAMS.BLINDING_BASE.x,
      y: BANDERSNATCH_PARAMS.BLINDING_BASE.y,
    })
  }

  /**
   * Verify Pedersen VRF proof with provided gamma point according to bandersnatch-vrf-spec
   * Steps:
   * 1. (Y_bar, R, O_k, s, s_b) ← π
   * 2. c ← challenge(Y_bar, I, O, R, O_k, ad)
   * 3. θ₀ ← ⊤ if O_k + c·O = I·s else ⊥
   * 4. θ₁ ← ⊤ if R + c·Y_bar = s·G + s_b·B else ⊥
   * 5. θ = θ₀ ∧ θ₁
   */
  private static verifyProof(
    I: Uint8Array,
    O: Uint8Array,
    proof: PedersenVRFProof,
    auxData?: Uint8Array,
  ): boolean {
    try {
      // Step 1: Extract proof components
      const { Y_bar, R, O_k, s, s_b } = proof

      // Convert proof components to curve points and scalars
      const IPoint = BandersnatchCurve.bytesToPoint(I)
      const OPoint = BandersnatchCurve.bytesToPoint(O)
      const Y_barPoint = BandersnatchCurve.bytesToPoint(Y_bar)
      const RPoint = BandersnatchCurve.bytesToPoint(R)
      const O_kPoint = BandersnatchCurve.bytesToPoint(O_k)

      const sScalar = bytesToBigIntLittleEndian(s)
      const s_bScalar = bytesToBigIntLittleEndian(s_b)

      // Step 2: Generate challenge
      const c = PedersenVRFProver.generateChallenge(
        Y_bar,
        I,
        O,
        R,
        O_k,
        auxData || new Uint8Array(0),
      )

      // Step 3: Verify output commitment: O_k + c·O = I·s
      const cO = BandersnatchCurve.scalarMultiply(OPoint, c)
      const leftSide = BandersnatchCurve.add(O_kPoint, cO)
      const rightSide = BandersnatchCurve.scalarMultiply(IPoint, sScalar)
      const theta0 = leftSide.equals(rightSide)

      // Step 4: Verify key commitment: R + c·Y_bar = s·G + s_b·B
      const cY_bar = BandersnatchCurve.scalarMultiply(Y_barPoint, c)
      const leftSideKey = BandersnatchCurve.add(RPoint, cY_bar)

      const G = Bandersnatch.fromAffine({
        x: BANDERSNATCH_PARAMS.GENERATOR.x,
        y: BANDERSNATCH_PARAMS.GENERATOR.y,
      })
      const B = this.getBlindingBase()
      const sG = BandersnatchCurve.scalarMultiply(G, sScalar)
      const s_bB = BandersnatchCurve.scalarMultiply(B, s_bScalar)
      const rightSideKey = BandersnatchCurve.add(sG, s_bB)
      const theta1 = leftSideKey.equals(rightSideKey)

      // Step 5: Final result
      const isValid = theta0 && theta1

      console.debug('Pedersen VRF verification details', {
        theta0,
        theta1,
        isValid,
        challenge: c.toString(16),
      })

      return isValid
    } catch (error) {
      console.error(
        'Pedersen VRF proof verification with provided gamma failed',
        {
          error: error instanceof Error ? error.message : String(error),
        },
      )
      return false
    }
  }
}
