import { bls12_381 } from '@noble/curves/bls12-381.js'
import { bigintToBytes32BE, verifyKzgProof } from '../utils/kzg-manual.ts'
import type { RingCommitments, RingEvaluations } from './piop/mod.ts'
import type { PiopVerifier } from './piop/verifier.ts'
import type { Proof } from './proof.ts'
import type { PlonkTranscript } from './transcript/transcript.ts'

export interface Challenges {
  alphas: bigint[]
  zeta: bigint
  nus: bigint[]
}

export class PlonkVerifier {
  private readonly pcsVk: {
    srsG1: Uint8Array
    srsG2: Uint8Array
    srsG2Tau: Uint8Array
  }
  private readonly transcriptPrelude: PlonkTranscript<Uint8Array>

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

  verify(
    piop: PiopVerifier,
    proof: Proof<RingCommitments, RingEvaluations>,
    challenges: Challenges,
  ): boolean {
    const qZeta = piop.evaluateQAtZeta(challenges.alphas, proof.linAtZetaOmega)

    const precommittedCols = piop.precommittedColumns()
    const witnessCols = proof.columnCommitments.toVec()
    const columns = [
      ...precommittedCols,
      ...witnessCols,
      proof.quotientCommitment,
    ]

    const witnessEvals = proof.columnsAtZeta.toVec()
    const columnsAtZeta = [...witnessEvals, qZeta]

    const aggComm = this.combineCommitments(columns, challenges.nus)

    const Fr = bls12_381.fields.Fr
    let aggAtZeta = Fr.ZERO
    for (let i = 0; i < columnsAtZeta.length; i++) {
      const nu = Fr.create(challenges.nus[i]!)
      const y = Fr.create(columnsAtZeta[i]!)
      aggAtZeta = Fr.add(aggAtZeta, Fr.mul(nu, y))
    }

    const linComm = piop.linPolyCommitment(challenges.alphas)

    const zeta = challenges.zeta
    const domainEval = piop.domainEvaluated()
    const omega = domainEval.omega
    const zetaOmega = Fr.mul(Fr.create(zeta), Fr.create(omega))

    const zetaBytes = bigintToBytes32BE(zeta)
    const zetaOmegaBytes = bigintToBytes32BE(zetaOmega)
    const aggAtZetaBytes = bigintToBytes32BE(aggAtZeta)
    const linAtZetaOmegaBytes = bigintToBytes32BE(proof.linAtZetaOmega)

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

  restoreChallenges(
    instance: Uint8Array,
    proof: Proof<RingCommitments, RingEvaluations>,
    nPolys: number,
    nConstraints: number,
  ): Challenges {
    const transcript = this.transcriptPrelude

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
