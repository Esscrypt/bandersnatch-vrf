import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BandersnatchCurve } from '@pbnjam/bandersnatch'
import { curvePointToNoble } from '../crypto/elligator2.ts'
import {
  bigintToBytes32BE,
  commitPolynomialCoeffs,
  computeKzgProofFromCoeffs,
} from '../utils/kzg-manual.ts'
import type { DensePolynomial } from './domain/polynomial.ts'
import { DensePolynomialImpl } from './domain/polynomial.ts'
import type { RingCommitments, RingEvaluations } from './piop/mod.ts'
import type { PiopProver } from './piop/prover.ts'
import type { Proof } from './proof.ts'
import type { PlonkTranscript } from './transcript/transcript.ts'

export class PlonkProver {
  private readonly pcsCk: {
    srsG1Points: Uint8Array[]
    srsG1: Uint8Array
    srsG2: Uint8Array
    srsG2Tau: Uint8Array
  }
  private readonly transcriptPrelude: PlonkTranscript<Uint8Array>

  static init(
    pcsCk: {
      srsG1Points: Uint8Array[]
      srsG1: Uint8Array
      srsG2: Uint8Array
      srsG2Tau: Uint8Array
    },
    verifierKey: Uint8Array,
    emptyTranscript: PlonkTranscript<Uint8Array>,
  ): PlonkProver {
    const transcriptPrelude = emptyTranscript
    void verifierKey

    return new PlonkProver(pcsCk, transcriptPrelude)
  }

  private constructor(
    pcsCk: {
      srsG1Points: Uint8Array[]
      srsG1: Uint8Array
      srsG2: Uint8Array
      srsG2Tau: Uint8Array
    },
    transcriptPrelude: PlonkTranscript<Uint8Array>,
  ) {
    this.pcsCk = pcsCk
    this.transcriptPrelude = transcriptPrelude
  }

  prove(piop: PiopProver): Proof<RingCommitments, RingEvaluations> {
    const transcript = this.transcriptPrelude

    const resultPoint = piop.result()
    const curvePoint = { ...resultPoint, isInfinity: false }
    const noblePoint = curvePointToNoble(curvePoint)
    const resultBytes = BandersnatchCurve.pointToBytes(noblePoint)
    transcript.addInstance(resultBytes)

    const columnCommitments = piop.committedColumns((poly) => {
      const [error, commitment] = commitPolynomialCoeffs(
        poly.coeffs,
        this.pcsCk.srsG1Points,
      )
      if (error || !commitment) {
        throw new Error(
          `Failed to commit polynomial: ${error?.message ?? 'unknown error'}`,
        )
      }
      return commitment
    })
    transcript.addCommittedCols(columnCommitments)

    const constraintPolys = piop.constraints()
    const nConstraints = constraintPolys.length
    const alphas = transcript.getConstraintsAggregationCoeffs(nConstraints)

    const aggConstraintPoly = this.aggregateEvaluations(constraintPolys, alphas)

    const aggConstraintPolyDense = aggConstraintPoly.interpolate()

    const domain = piop.getDomain()
    const quotientPoly = domain.divideByVanishingPoly(aggConstraintPolyDense)

    const [quotientError, quotientCommitment] = commitPolynomialCoeffs(
      quotientPoly.coeffs,
      this.pcsCk.srsG1Points,
    )
    if (quotientError || !quotientCommitment) {
      throw new Error(
        `Failed to commit quotient polynomial: ${quotientError?.message ?? 'unknown error'}`,
      )
    }
    transcript.addQuotientCommitment(quotientCommitment)

    const zeta = transcript.getEvaluationPoint()
    const columnsToOpen = piop.columns()
    const columnsAtZeta = piop.columnsEvaluated(zeta)
    const constraintPolysLinearized = piop.constraintsLinearized(zeta)

    const lin = this.aggregatePolynomials(constraintPolysLinearized, alphas)

    const omega = domain.omega()
    const Fr = bls12_381.fields.Fr
    const zetaOmega = Fr.mul(Fr.create(zeta), Fr.create(omega))
    const linAtZetaOmega = lin.evaluate(zetaOmega)

    transcript.addEvaluations(columnsAtZeta, linAtZetaOmega)

    const polysAtZeta = [...columnsToOpen, quotientPoly]
    const nPolys = polysAtZeta.length
    const nus = transcript.getKzgAggregationChallenges(nPolys)

    const aggAtZeta = this.aggregatePolynomials(polysAtZeta, nus)

    const zetaBytes = bigintToBytes32BE(zeta)
    const [aggProofError, aggAtZetaProof] = computeKzgProofFromCoeffs(
      aggAtZeta.coeffs,
      zetaBytes,
      this.pcsCk.srsG1Points,
    )
    if (aggProofError || !aggAtZetaProof) {
      throw new Error(
        `Failed to generate aggregated KZG proof: ${aggProofError?.message ?? 'unknown error'}`,
      )
    }

    const zetaOmegaBytes = bigintToBytes32BE(zetaOmega)
    const [linProofError, linAtZetaOmegaProof] = computeKzgProofFromCoeffs(
      lin.coeffs,
      zetaOmegaBytes,
      this.pcsCk.srsG1Points,
    )
    if (linProofError || !linAtZetaOmegaProof) {
      throw new Error(
        `Failed to generate linearization KZG proof: ${linProofError?.message ?? 'unknown error'}`,
      )
    }

    return {
      columnCommitments,
      quotientCommitment,
      columnsAtZeta,
      linAtZetaOmega,
      aggAtZetaProof,
      linAtZetaOmegaProof,
    }
  }

  private aggregateEvaluations(
    evaluations: bigint[][],
    coeffs: bigint[],
  ): { interpolate: () => DensePolynomial } {
    if (coeffs.length !== evaluations.length) {
      throw new Error(
        `Coefficients length ${coeffs.length} must equal evaluations length ${evaluations.length}`,
      )
    }

    const Fr = bls12_381.fields.Fr
    const n = evaluations[0]?.length ?? 0

    if (n === 0) {
      return {
        interpolate: () => new DensePolynomialImpl([Fr.ZERO]),
      }
    }

    const aggregated: bigint[] = []
    for (let i = 0; i < n; i++) {
      let sum = Fr.ZERO
      for (let j = 0; j < evaluations.length; j++) {
        const coeff = Fr.create(coeffs[j]!)
        const evalValue = Fr.create(evaluations[j]![i]!)
        sum = Fr.add(sum, Fr.mul(coeff, evalValue))
      }
      aggregated.push(sum)
    }

    return {
      interpolate: () => {
        const domainSize = n
        const logNValue = Math.log2(domainSize)

        if (logNValue % 1 !== 0) {
          throw new Error(
            `Domain size ${domainSize} must be power of 2 for IFFT`,
          )
        }

        const coeffs = this.ifft(aggregated, domainSize, logNValue)
        return new DensePolynomialImpl(coeffs)
      },
    }
  }

  private ifft(values: bigint[], domainSize: number, logN: number): bigint[] {
    const Fr = bls12_381.fields.Fr

    if (logN % 1 !== 0) {
      throw new Error(`IFFT requires power of 2, got ${domainSize}`)
    }

    const exponent = (Fr.ORDER - 1n) / BigInt(domainSize)
    const omega = Fr.pow(7n, exponent)
    const omegaInv = Fr.inv(omega)

    const result = values.map((v) => Fr.create(v))

    for (let i = 0; i < domainSize; i++) {
      const j = this.bitReverse(i, logN)
      if (i < j) {
        const temp = result[i]
        result[i] = result[j]!
        result[j] = temp!
      }
    }

    let m = 1
    for (let s = 1; s <= logN; s++) {
      const wm = Fr.pow(omegaInv, BigInt(domainSize / (2 * m)))
      let k = 0
      while (k < domainSize) {
        let w = Fr.ONE
        for (let j = 0; j < m; j++) {
          const t = Fr.mul(result[k + j + m]!, w)
          const u = result[k + j]!
          result[k + j] = Fr.add(u, t)
          result[k + j + m] = Fr.sub(u, t)
          w = Fr.mul(w, wm)
        }
        k += 2 * m
      }
      m *= 2
    }

    const domainSizeInv = Fr.inv(Fr.create(BigInt(domainSize)))
    return result.map((r) => Fr.mul(r, domainSizeInv))
  }

  private bitReverse(index: number, logN: number): number {
    let reversed = 0
    for (let i = 0; i < logN; i++) {
      reversed = (reversed << 1) | (index & 1)
      index >>= 1
    }
    return reversed
  }

  private aggregatePolynomials(
    polys: DensePolynomial[],
    coeffs: bigint[],
  ): DensePolynomial {
    if (coeffs.length !== polys.length) {
      throw new Error(
        `Coefficients length ${coeffs.length} must equal polynomials length ${polys.length}`,
      )
    }

    const Fr = bls12_381.fields.Fr

    const maxDegree = Math.max(...polys.map((p) => p.degree))

    const aggregated: bigint[] = []
    for (let i = 0; i <= maxDegree; i++) {
      let sum = Fr.ZERO
      for (let j = 0; j < polys.length; j++) {
        const coeff = Fr.create(coeffs[j]!)
        const polyCoeff = polys[j]!.coeff(i)
        const polyCoeffF = Fr.create(polyCoeff)
        sum = Fr.add(sum, Fr.mul(coeff, polyCoeffF))
      }
      aggregated.push(sum)
    }

    return new DensePolynomialImpl(aggregated)
  }
}
