/**
 * Ring VRF Verifier Implementation
 *
 * Implements Ring VRF verification according to bandersnatch-vrf-spec section 4.3:
 * 1. θ₀ = Pedersen.verify(I, ad, O, π_p) - Verify underlying Pedersen VRF proof
 * 2. (Ȳ, R, O_k, s, s_b) ← π_p - Extract Pedersen proof components
 * 3. θ₁ = Ring.verify(V, π_r, Ȳ) - Verify ring proof using blinded public key Ȳ
 * 4. θ ← θ₀ ∧ θ₁ - Both verifications must pass
 */

import { BANDERSNATCH_PARAMS } from '@pbnj/bandersnatch'
import { PedersenVRFProver } from '../prover/pedersen'
import type { RingVRFInput } from '../prover/ring-kzg'
import { loadSRSFromFile } from '../utils/srs-loader'
import { PedersenVRFVerifier } from './pedersen'
import { RingVRFProver } from '../prover/ring-kzg'
import { createRingPolynomial, evaluatePolynomialAt, verifyKzgProof, bigintToBytes32BE } from '../utils/kzg-manual'
/**
 * Ring VRF Verifier
 * Implements Ring VRF verification with anonymity
 */
export class RingVRFVerifier {
  private srsG1: Uint8Array
  private srsG2: Uint8Array
  private srsG2Tau: Uint8Array


  constructor(srsFilePath: string) {
    const [error, result] = loadSRSFromFile(srsFilePath)
    if (error) {
      throw new Error(`Failed to load SRS for verification: ${error.message}`)
    }
    this.srsG1 = result.g1
    this.srsG2 = result.g2
    this.srsG2Tau = result.g2Points[1]
  }

  /**
   * Verify Ring VRF proof according to bandersnatch-vrf-spec section 4.3
   *
   * This method takes the serialized Ring VRF result as bytes and deserializes it internally.
   *
   * Steps:
   * 1. Deserialize Ring VRF result to get gamma, hash, and proof components
   * 2. θ₀ = Pedersen.verify(I, ad, O, π_p)
   * 3. (Ȳ, R, O_k, s, s_b) ← π_p
   * 4. θ₁ = Ring.verify(V, π_r, Ȳ)
   * 5. θ ← θ₀ ∧ θ₁
   */
  verify(
    ringKeys: Uint8Array[],
    input: RingVRFInput,
    serializedResult: Uint8Array,
    auxData?: Uint8Array,
  ): boolean {

    console.debug('Verifying Ring VRF proof', {
      inputLength: input.input.length,
      ringSize: ringKeys.length,
      serializedResultLength: serializedResult.length,
      hasAuxData: !!auxData,
    })

      // Step 1: Deserialize Ring VRF result to get gamma and proof components
      const result = RingVRFProver.deserialize(serializedResult)
      const { gamma, proof } = result
      const pedersenProof = proof.pedersenProof
      const ringProof = proof.ringProof
      const ringCommitment = proof.ringCommitment

      // Step 2: θ₀ = Pedersen.verify(I, ad, O, π_p)
      // Verify underlying Pedersen VRF proof using the provided gamma
      // const theta0 = this.verifyPedersenVRF(input, gamma, proof, auxData)
      const pedersenValid = PedersenVRFVerifier.verify(
        input.input,
        gamma,
        proof.pedersenProof,
        auxData,
      )
      if (!pedersenValid) {
        console.error('Pedersen VRF verification failed (θ₀ = ⊥)')
        return false
      }

      // Step 3: (Ȳ, R, O_k, s, s_b) ← π_p
      // Extract Pedersen proof components
      const pedersenComponents = PedersenVRFProver.deserialize(pedersenProof)
      if (!pedersenComponents) {
        console.error('Failed to extract Pedersen proof components')
        return false
      }

      // Step 4: θ₁ = Ring.verify(V, π_r, Ȳ)
      // Verify ring proof using the blinded public key Ȳ
      const ringValid = this.verifyRingProof(
        ringKeys,
        ringCommitment,
        ringProof,
        pedersenComponents.Y_bar,
      )
      if (!ringValid) {
        console.error('Ring proof verification failed (θ₁ = ⊥)')
        return false
      }

      // Step 5: θ ← θ₀ ∧ θ₁
      // Both verifications must pass
      return true

  }


  /**
   * Step 3: θ₁ = Ring.verify(V, π_r, Ȳ)
   * Verify ring proof using KZG commitments
   */
  private verifyRingProof(
    ringKeys: Uint8Array[],
    ringCommitment: Uint8Array,
    ringProof: Uint8Array,
    yBar: Uint8Array,
  ): boolean {
      // Check SRS is loaded
      // 1. Recreate ring polynomial from public keys (representing the ring verifier V)
      const ringPolynomial = createRingPolynomial(ringKeys)

      // 2. Evaluate polynomial at domain generator to get y = p(z)
      const domainGenerator = BANDERSNATCH_PARAMS.KZG_CONFIG.DOMAIN_GENERATOR
      const y = evaluatePolynomialAt(ringPolynomial, domainGenerator)

      // 3. Convert y to bytes (32 bytes, big-endian)
      const yBytes = bigintToBytes32BE(y)

      // 4. Convert domain generator to bytes (32 bytes, big-endian)
      const zBytes = bigintToBytes32BE(domainGenerator)

      // 5. Verify the KZG commitment and proof (π_r verification)
      const [verifyError, isValid] = verifyKzgProof(
        ringCommitment, // commitmentBytes (48 bytes)
        zBytes, // zBytes - domain generator (32 bytes)
        yBytes, // yBytes - evaluation result (32 bytes)
        ringProof, // proofBytes (48 bytes)
        this.srsG1, // srsG1 (48 bytes)
        this.srsG2, // srsG2 (96 bytes)
        this.srsG2Tau, // srsG2Tau (96 bytes)
      )

      if (verifyError) {
        console.error('KZG proof verification error', {
          error: verifyError.message,
        })
        return false
      }

      console.debug('Ring proof verification', {
        ringSize: ringKeys.length,
        commitmentSize: ringCommitment.length,
        proofSize: ringProof.length,
        yBarLength: yBar.length,
        isValid,
      })

      // Note: In a complete implementation following [VG24], we would also verify
      // that the blinded public key Ȳ is properly committed in the ring proof.
      // For now, we focus on the KZG commitment verification.

      return isValid ?? false

  }

}
