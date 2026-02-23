/**
 * Ring VRF Verifier (Pure TypeScript)
 *
 * Verifies Ring VRF proofs using the Plonk-based verification from ring-kzg.ts.
 *
 * Implements Ring VRF verification according to bandersnatch-vrf-spec section 4.3:
 * 1. θ₀ = Pedersen.verify(I, ad, O, π_p) - Verify underlying Pedersen VRF proof
 * 2. (Ȳ, R, O_k, s, s_b) ← π_p - Extract Pedersen proof components
 * 3. θ₁ = Ring.verify(V, π_r, Ȳ) - Verify ring proof using Plonk verifier
 * 4. θ ← θ₀ ∧ θ₁ - Both verifications must pass
 */

import { PedersenVRFProver } from '../prover/pedersen'
import type { RingVRFInput, RingVRFProof } from '../prover/ring-kzg'
import { RingVRFProver } from '../prover/ring-kzg'
import { PedersenVRFVerifier } from './pedersen'

/**
 * Ring VRF Verifier
 *
 * Uses the Plonk-based verification logic from RingVRFProver.verifyRingProof
 * to verify ring membership proofs. Matches the API of RingVRFVerifierWasm.
 */
export class RingVRFVerifier {
  private readonly ringProver: RingVRFProver

  /**
   * @param srsFilePath - Path to SRS file (arkworks format)
   * @param ringSize    - Ring size (number of validators)
   */
  constructor(srsFilePath: string, ringSize: number) {
    this.ringProver = new RingVRFProver(srsFilePath, ringSize)
  }

  /**
   * Verify Ring VRF proof.
   *
   * Steps:
   * 1. θ₀ = Pedersen.verify(I, ad, O, π_p)
   * 2. Extract Ȳ (blinded public key) from Pedersen proof
   * 3. θ₁ = Ring.verify(π_r, ring_keys, Ȳ) via Plonk verifier
   * 4. θ ← θ₀ ∧ θ₁
   */
  verify(
    ringKeys: Uint8Array[],
    input: RingVRFInput,
    result: {
      gamma: Uint8Array
      proof: RingVRFProof
    },
    auxData?: Uint8Array,
  ): boolean {
    const pedersenValid = PedersenVRFVerifier.verify(
      input.input,
      result.gamma,
      result.proof.pedersenProof,
      auxData,
    )
    if (!pedersenValid) {
      return false
    }

    const pedersenComponents = PedersenVRFProver.deserialize(
      result.proof.pedersenProof,
    )

    return this.ringProver.verifyRingProof(
      result.proof.ringProof,
      ringKeys,
      pedersenComponents.Y_bar,
    )
  }
}
