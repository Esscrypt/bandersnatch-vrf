/**
 * Plonk Prover
 *
 * Main Plonk prover that wraps PIOP and implements the 3-round Plonk protocol
 * Matches w3f-plonk-common/src/prover.rs
 */

import * as fft from '@noble/curves/abstract/fft.js'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BandersnatchCurve } from '@pbnjam/bandersnatch'
import { curvePointToNoble } from '../crypto/elligator2'
import {
  bigintToBytes32BE,
  blobToKzgCommitment,
  computeBlobKzgProof,
  polynomialToBlob,
} from '../utils/kzg-manual'
import type { DensePolynomial } from './domain/polynomial'
import { DensePolynomialImpl } from './domain/polynomial'
import type { RingCommitments, RingEvaluations } from './piop/mod'
import type { PiopProver } from './piop/prover'
import type { Proof } from './proof'
import type { PlonkTranscript } from './transcript/transcript'

/**
 * Plonk Prover
 *
 * Implements the 3-round Plonk protocol:
 * - Round 1: Commit to witness columns
 * - Round 2: Aggregate constraints, compute quotient polynomial
 * - Round 3: Evaluate at zeta, compute linearization, generate KZG proofs
 */
export class PlonkProver {
  private readonly pcsCk: {
    srsG1Points: Uint8Array[]
    srsG1: Uint8Array
    srsG2: Uint8Array
    srsG2Tau: Uint8Array
  }
  private readonly transcriptPrelude: PlonkTranscript<Uint8Array>

  /**
   * Initialize Plonk prover
   *
   * @param pcsCk - Polynomial commitment scheme committing key (SRS)
   * @param verifierKey - Verifier key (for transcript)
   * @param emptyTranscript - Empty transcript instance
   */
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
    // Add verifier key to transcript
    // transcriptPrelude._add_serializable('vk', verifierKey)
    void verifierKey // Will be used when transcript is fully implemented

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

  /**
   * Generate Plonk proof
   *
   * @param piop - PIOP prover instance
   * @returns Plonk proof
   */
  prove(piop: PiopProver): Proof<RingCommitments, RingEvaluations> {
    const transcript = this.transcriptPrelude // Clone in real implementation

    // Add instance (result) to transcript
    const resultPoint = piop.result()
    // Serialize result point to bytes using BandersnatchCurve.pointToBytes()
    // This produces 32 bytes (compressed format: y-coordinate + sign bit)
    // Convert {x, y} to CurvePoint format with isInfinity property
    const curvePoint = { ...resultPoint, isInfinity: false }
    const noblePoint = curvePointToNoble(curvePoint)
    const resultBytes = BandersnatchCurve.pointToBytes(noblePoint)
    transcript.addInstance(resultBytes)

    // ROUND 1: Commit to witness columns
    const columnCommitments = piop.committedColumns((poly) => {
      // Commit polynomial using KZG
      const blob = polynomialToBlob(poly.coeffs)
      const [error, commitment] = blobToKzgCommitment(
        blob,
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

    // ROUND 2: Aggregate constraints and compute quotient polynomial
    const constraintPolys = piop.constraints()
    const nConstraints = constraintPolys.length
    const alphas = transcript.getConstraintsAggregationCoeffs(nConstraints)

    // Aggregate constraint polynomials in evaluation form
    const aggConstraintPoly = this.aggregateEvaluations(constraintPolys, alphas)

    // Interpolate aggregated constraint polynomial
    const aggConstraintPolyDense = aggConstraintPoly.interpolate()

    // Divide by vanishing polynomial to get quotient
    const domain = piop.getDomain()
    const quotientPoly = domain.divideByVanishingPoly(aggConstraintPolyDense)

    // Commit to quotient polynomial
    const quotientBlob = polynomialToBlob(quotientPoly.coeffs)
    const [quotientError, quotientCommitment] = blobToKzgCommitment(
      quotientBlob,
      this.pcsCk.srsG1Points,
    )
    if (quotientError || !quotientCommitment) {
      throw new Error(
        `Failed to commit quotient polynomial: ${quotientError?.message ?? 'unknown error'}`,
      )
    }
    transcript.addQuotientCommitment(quotientCommitment)

    // ROUND 3: Evaluate columns at zeta and generate KZG proofs
    const zeta = transcript.getEvaluationPoint()
    const columnsToOpen = piop.columns()
    const columnsAtZeta = piop.columnsEvaluated(zeta)
    const constraintPolysLinearized = piop.constraintsLinearized(zeta)

    // Aggregate linearized constraint polynomials
    const lin = this.aggregatePolynomials(constraintPolysLinearized, alphas)

    // Evaluate linearization at zeta*omega
    const omega = domain.omega()
    const Fr = bls12_381.fields.Fr
    const zetaOmega = Fr.mul(Fr.create(zeta), Fr.create(omega))
    const linAtZetaOmega = lin.evaluate(zetaOmega)

    transcript.addEvaluations(columnsAtZeta, linAtZetaOmega)

    // Aggregate polynomials for batch opening
    const polysAtZeta = [...columnsToOpen, quotientPoly]
    const nPolys = polysAtZeta.length
    const nus = transcript.getKzgAggregationChallenges(nPolys)

    // Aggregate polynomials at zeta
    const aggAtZeta = this.aggregatePolynomials(polysAtZeta, nus)

    // Generate KZG proofs
    const zetaBytes = bigintToBytes32BE(zeta)
    const [aggProofError, aggAtZetaProof] = computeBlobKzgProof(
      polynomialToBlob(aggAtZeta.coeffs),
      zetaBytes,
      this.pcsCk.srsG1Points,
    )
    if (aggProofError || !aggAtZetaProof) {
      throw new Error(
        `Failed to generate aggregated KZG proof: ${aggProofError?.message ?? 'unknown error'}`,
      )
    }

    const zetaOmegaBytes = bigintToBytes32BE(zetaOmega)
    const [linProofError, linAtZetaOmegaProof] = computeBlobKzgProof(
      polynomialToBlob(lin.coeffs),
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

  /**
   * Aggregate evaluations with coefficients
   *
   * Computes: Σ(alpha_i * evaluations_i)
   * Matching Rust: aggregate_evaluations() which returns Evaluations<F> with interpolate() method
   */
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
      // Return zero polynomial if no evaluations
      return {
        interpolate: () => new DensePolynomialImpl([Fr.ZERO]),
      }
    }

    // Aggregate: result[i] = Σ(coeffs[j] * evaluations[j][i])
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

    // Return object with interpolate method
    // In Rust, Evaluations<F>.interpolate() uses IFFT to convert from evaluation form to coefficient form
    // The aggregated evaluations are over the 4x domain, so we need to use IFFT
    return {
      interpolate: () => {
        // Use IFFT to interpolate from evaluation form to coefficient form
        // The evaluations are over a domain of size n (4x domain size)
        // We need to find the domain size and apply IFFT
        const domainSize = n
        const logNValue = Math.log2(domainSize)

        if (logNValue % 1 !== 0) {
          throw new Error(
            `Domain size ${domainSize} must be power of 2 for IFFT`,
          )
        }

        // Apply IFFT to get polynomial coefficients
        const coeffs = this.ifft(aggregated, domainSize, logNValue)
        return new DensePolynomialImpl(coeffs)
      },
    }
  }

  /**
   * IFFT on field elements
   *
   * Converts from evaluation form to coefficient form
   */
  private ifft(values: bigint[], domainSize: number, logN: number): bigint[] {
    const Fr = bls12_381.fields.Fr

    if (logN % 1 !== 0) {
      throw new Error(`IFFT requires power of 2, got ${domainSize}`)
    }

    // Get roots of unity for the domain
    const roots = fft.rootsOfUnity(Fr, BigInt(domainSize))
    const omega = roots.omega(logN)
    const omegaInv = Fr.inv(omega)

    const result = values.map((v) => Fr.create(v))

    // Bit-reverse permutation
    for (let i = 0; i < domainSize; i++) {
      const j = this.bitReverse(i, logN)
      if (i < j) {
        const temp = result[i]
        result[i] = result[j]!
        result[j] = temp!
      }
    }

    // Cooley-Tukey IFFT
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

    // Normalize by dividing by domain size
    const domainSizeInv = Fr.inv(Fr.create(BigInt(domainSize)))
    return result.map((r) => Fr.mul(r, domainSizeInv))
  }

  /**
   * Bit-reverse an index for FFT/IFFT
   */
  private bitReverse(index: number, logN: number): number {
    let reversed = 0
    for (let i = 0; i < logN; i++) {
      reversed = (reversed << 1) | (index & 1)
      index >>= 1
    }
    return reversed
  }

  /**
   * Aggregate polynomials with coefficients
   *
   * Computes: Σ(nu_i * poly_i)
   */
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

    // Find maximum degree
    const maxDegree = Math.max(...polys.map((p) => p.degree))

    // Aggregate coefficients
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
