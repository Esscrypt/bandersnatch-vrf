/**
 * Plonk Verifier
 *
 * Main Plonk verifier that verifies Plonk proofs
 * Matches w3f-plonk-common/src/verifier.rs
 */

import { bls12_381 } from '@noble/curves/bls12-381.js'
import { bigintToBytes32BE, verifyKzgProof } from '../utils/kzg-manual'
import type { RingCommitments, RingEvaluations } from './piop/mod'
import type { PiopVerifier } from './piop/verifier'
import type { Proof } from './proof'
import type { PlonkTranscript } from './transcript/transcript'

/**
 * Challenges structure
 */
export interface Challenges {
  alphas: bigint[]
  zeta: bigint
  nus: bigint[]
}

/**
 * Plonk Verifier
 *
 * Verifies Plonk proofs by:
 * - Restoring challenges from transcript
 * - Verifying constraint evaluations
 * - Batch verifying KZG proofs
 */
export class PlonkVerifier {
  private readonly pcsVk: {
    srsG1: Uint8Array
    srsG2: Uint8Array
    srsG2Tau: Uint8Array
  }
  private readonly transcriptPrelude: PlonkTranscript<Uint8Array>

  /**
   * Initialize Plonk verifier
   *
   * @param pcsVk - Polynomial commitment scheme verifier key (SRS)
   * @param verifierKey - Verifier key (for transcript)
   * @param emptyTranscript - Empty transcript instance
   */
  static init(
    pcsVk: {
      srsG1: Uint8Array
      srsG2: Uint8Array
      srsG2Tau: Uint8Array
    },
    _verifierKey: Uint8Array,
    emptyTranscript: PlonkTranscript<Uint8Array>,
  ): PlonkVerifier {
    const transcriptPrelude = emptyTranscript
    // Add verifier key to transcript
    // transcriptPrelude._add_serializable('vk', verifierKey)

    return new PlonkVerifier(pcsVk, transcriptPrelude)
  }

  private constructor(
    pcsVk: {
      srsG1: Uint8Array
      srsG2: Uint8Array
      srsG2Tau: Uint8Array
    },
    transcriptPrelude: PlonkTranscript<Uint8Array>,
  ) {
    this.pcsVk = pcsVk
    this.transcriptPrelude = transcriptPrelude
  }

  /**
   * Verify Plonk proof
   *
   * @param piop - PIOP verifier instance
   * @param proof - Plonk proof
   * @param challenges - Challenges (alphas, zeta, nus)
   * @returns true if proof is valid
   */
  verify(
    piop: PiopVerifier,
    proof: Proof<RingCommitments, RingEvaluations>,
    challenges: Challenges,
  ): boolean {
    // Evaluate quotient polynomial at zeta
    const qZeta = piop.evaluateQAtZeta(challenges.alphas, proof.linAtZetaOmega)

    // Combine all column commitments
    const precommittedCols = piop.precommittedColumns()
    const witnessCols = proof.columnCommitments.toVec()
    const columns = [
      ...precommittedCols,
      ...witnessCols,
      proof.quotientCommitment,
    ]

    // Combine all column evaluations at zeta
    const witnessEvals = proof.columnsAtZeta.toVec()
    const columnsAtZeta = [...witnessEvals, qZeta]

    // Aggregate commitments: Σ(nu_i * C_i)
    const aggComm = this.combineCommitments(columns, challenges.nus)

    // Aggregate evaluations: Σ(nu_i * y_i)
    const Fr = bls12_381.fields.Fr
    let aggAtZeta = Fr.ZERO
    for (let i = 0; i < columnsAtZeta.length; i++) {
      const nu = Fr.create(challenges.nus[i]!)
      const y = Fr.create(columnsAtZeta[i]!)
      aggAtZeta = Fr.add(aggAtZeta, Fr.mul(nu, y))
    }

    // Compute linearization polynomial commitment
    const linComm = piop.linPolyCommitment(challenges.alphas)

    // Get evaluation points
    const zeta = challenges.zeta
    const domainEval = piop.domainEvaluated()
    const omega = domainEval.omega
    const zetaOmega = Fr.mul(Fr.create(zeta), Fr.create(omega))

    // Batch verify KZG proofs
    const zetaBytes = bigintToBytes32BE(zeta)
    const zetaOmegaBytes = bigintToBytes32BE(zetaOmega)
    const aggAtZetaBytes = bigintToBytes32BE(aggAtZeta)
    const linAtZetaOmegaBytes = bigintToBytes32BE(proof.linAtZetaOmega)

    // Verify aggregated proof at zeta
    const [aggError, aggValid] = verifyKzgProof(
      aggComm,
      zetaBytes,
      aggAtZetaBytes,
      proof.aggAtZetaProof,
      this.pcsVk.srsG1,
      this.pcsVk.srsG2,
      this.pcsVk.srsG2Tau,
    )
    if (aggError || !aggValid) {
      return false
    }

    // Verify linearization proof at zeta*omega
    const [linError, linValid] = verifyKzgProof(
      linComm,
      zetaOmegaBytes,
      linAtZetaOmegaBytes,
      proof.linAtZetaOmegaProof,
      this.pcsVk.srsG1,
      this.pcsVk.srsG2,
      this.pcsVk.srsG2Tau,
    )
    if (linError || !linValid) {
      return false
    }

    return true
  }

  /**
   * Restore challenges from transcript
   *
   * @param instance - Instance (public input)
   * @param proof - Plonk proof
   * @param nPolys - Number of polynomials
   * @param nConstraints - Number of constraints
   * @returns Challenges and RNG
   */
  restoreChallenges(
    instance: Uint8Array,
    proof: Proof<RingCommitments, RingEvaluations>,
    nPolys: number,
    nConstraints: number,
  ): Challenges {
    const transcript = this.transcriptPrelude // Clone in real implementation

    transcript.addInstance(instance)
    transcript.addCommittedCols(proof.columnCommitments)

    const alphas = transcript.getConstraintsAggregationCoeffs(nConstraints)
    transcript.addQuotientCommitment(proof.quotientCommitment)

    const zeta = transcript.getEvaluationPoint()
    transcript.addEvaluations(proof.columnsAtZeta, proof.linAtZetaOmega)

    const nus = transcript.getKzgAggregationChallenges(nPolys)
    transcript.addKzgProofs(proof.aggAtZetaProof, proof.linAtZetaOmegaProof)

    return {
      alphas,
      zeta,
      nus,
    }
  }

  /**
   * Combine commitments with coefficients
   *
   * Computes: Σ(nu_i * C_i) using MSM
   */
  private combineCommitments(
    commitments: Uint8Array[],
    coeffs: bigint[],
  ): Uint8Array {
    if (coeffs.length !== commitments.length) {
      throw new Error(
        `Coefficients length ${coeffs.length} must equal commitments length ${commitments.length}`,
      )
    }

    const Fr = bls12_381.fields.Fr
    let result = bls12_381.G1.Point.ZERO

    for (let i = 0; i < commitments.length; i++) {
      const commitment = bls12_381.G1.Point.fromBytes(commitments[i]!)
      const coeff = Fr.create(coeffs[i]!)
      result = result.add(commitment.multiply(coeff))
    }

    return result.toBytes(true)
  }
}
