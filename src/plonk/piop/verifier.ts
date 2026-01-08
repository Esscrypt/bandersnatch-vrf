/**
 * PIOP Verifier
 * 
 * Implements the verifier side of Polynomial Interactive Oracle Proofs (PIOP)
 * Matches w3f-ring-proof/src/piop/verifier.rs
 */

import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BooleanityValues } from '../gadgets/booleanity'
import { CondAddValues } from '../gadgets/cond-add'
import { FixedCellsValues } from '../gadgets/fixed-cells'
import { InnerProdValues } from '../gadgets/inner-prod'
import type { FixedColumnsCommitted } from './mod'
import { RingCommitments, RingEvaluations } from './mod'

/**
 * Evaluated domain for verifier
 */
export interface EvaluatedDomain {
  notLastRow: bigint
  lFirst: bigint
  lLast: bigint
  omega: bigint
  vanishingPolynomialInv: bigint
}

/**
 * PIOP Verifier
 * 
 * Verifies PIOP proofs by checking constraints
 */
export class PiopVerifier {
  public static readonly N_CONSTRAINTS = 7
  public static readonly N_COLUMNS = 7

  private readonly domainEvals: EvaluatedDomain
  private readonly fixedColumnsCommitted: FixedColumnsCommitted
  private readonly witnessColumnsCommitted: RingCommitments
  private readonly booleanity: BooleanityValues
  private readonly innerProd: InnerProdValues
  private readonly innerProdAcc: FixedCellsValues
  private readonly condAdd: CondAddValues
  private readonly condAddAccX: FixedCellsValues
  private readonly condAddAccY: FixedCellsValues

  /**
   * Initialize PIOP verifier
   * 
   * @param domainEvals - Evaluated domain values
   * @param fixedColumnsCommitted - Committed fixed columns
   * @param witnessColumnsCommitted - Committed witness columns
   * @param allColumnsEvaluated - Evaluated column values
   * @param init - Initial accumulator value (seed point coordinates)
   * @param result - Result accumulator value (seed + result coordinates)
   */
  static init(
    domainEvals: EvaluatedDomain,
    fixedColumnsCommitted: FixedColumnsCommitted,
    witnessColumnsCommitted: RingCommitments,
    allColumnsEvaluated: RingEvaluations,
    init: [bigint, bigint],
    result: [bigint, bigint],
  ): PiopVerifier {
    const condAdd = new CondAddValues(
      allColumnsEvaluated.bits,
      allColumnsEvaluated.points,
      domainEvals.notLastRow,
      allColumnsEvaluated.condAddAcc,
    )

    const innerProd = new InnerProdValues(
      allColumnsEvaluated.ringSelector,
      allColumnsEvaluated.bits,
      domainEvals.notLastRow,
      allColumnsEvaluated.innProdAcc,
    )

    const booleanity = new BooleanityValues(allColumnsEvaluated.bits)

    const condAddAccX = new FixedCellsValues(
      allColumnsEvaluated.condAddAcc[0],
      init[0],
      result[0],
      domainEvals.lFirst,
      domainEvals.lLast,
    )

    const condAddAccY = new FixedCellsValues(
      allColumnsEvaluated.condAddAcc[1],
      init[1],
      result[1],
      domainEvals.lFirst,
      domainEvals.lLast,
    )

    const innerProdAcc = new FixedCellsValues(
      allColumnsEvaluated.innProdAcc,
      0n, // col_first = 0
      1n, // col_last = 1
      domainEvals.lFirst,
      domainEvals.lLast,
    )

    return new PiopVerifier(
      domainEvals,
      fixedColumnsCommitted,
      witnessColumnsCommitted,
      booleanity,
      innerProd,
      innerProdAcc,
      condAdd,
      condAddAccX,
      condAddAccY,
    )
  }

  private constructor(
    domainEvals: EvaluatedDomain,
    fixedColumnsCommitted: FixedColumnsCommitted,
    witnessColumnsCommitted: RingCommitments,
    booleanity: BooleanityValues,
    innerProd: InnerProdValues,
    innerProdAcc: FixedCellsValues,
    condAdd: CondAddValues,
    condAddAccX: FixedCellsValues,
    condAddAccY: FixedCellsValues,
  ) {
    this.domainEvals = domainEvals
    this.fixedColumnsCommitted = fixedColumnsCommitted
    this.witnessColumnsCommitted = witnessColumnsCommitted
    this.booleanity = booleanity
    this.innerProd = innerProd
    this.innerProdAcc = innerProdAcc
    this.condAdd = condAdd
    this.condAddAccX = condAddAccX
    this.condAddAccY = condAddAccY
  }

  /**
   * Get precommitted columns (fixed columns)
   */
  precommittedColumns(): Uint8Array[] {
    return [
      this.fixedColumnsCommitted.points[0],
      this.fixedColumnsCommitted.points[1],
      this.fixedColumnsCommitted.ringSelector,
    ]
  }

  /**
   * Evaluate constraints at main point
   */
  evaluateConstraintsMain(): bigint[] {
    return [
      ...this.innerProd.evaluateConstraintsMain(),
      ...this.condAdd.evaluateConstraintsMain(),
      ...this.booleanity.evaluateConstraintsMain(),
      ...this.condAddAccX.evaluateConstraintsMain(),
      ...this.condAddAccY.evaluateConstraintsMain(),
      ...this.innerProdAcc.evaluateConstraintsMain(),
    ]
  }

  /**
   * Compute linearized polynomial commitment
   * 
   * Combines witness column commitments with aggregated coefficients
   */
  linPolyCommitment(aggCoeffs: bigint[]): Uint8Array {
    if (aggCoeffs.length !== PiopVerifier.N_CONSTRAINTS) {
      throw new Error(
        `Aggregated coefficients length ${aggCoeffs.length} must equal N_CONSTRAINTS ${PiopVerifier.N_CONSTRAINTS}`,
      )
    }

    const Fr = bls12_381.fields.Fr

    // Inner product accumulator coefficient
    const innerProdAcc = this.witnessColumnsCommitted.innProdAcc
    const innerProdCoeff = Fr.mul(
      Fr.create(aggCoeffs[0]!),
      Fr.create(this.innerProd.notLast),
    )

    // CondAdd accumulator coefficients
    const condAddAccX = this.witnessColumnsCommitted.condAddAcc[0]
    const condAddAccY = this.witnessColumnsCommitted.condAddAcc[1]
    const [cAccX1, cAccY1] = this.condAdd.accCoeffs1()
    const [cAccX2, cAccY2] = this.condAdd.accCoeffs2()

    let condAddXCoeff = Fr.mul(Fr.create(aggCoeffs[1]!), Fr.create(cAccX1))
    let condAddYCoeff = Fr.mul(Fr.create(aggCoeffs[1]!), Fr.create(cAccY1))
    condAddXCoeff = Fr.add(
      condAddXCoeff,
      Fr.mul(Fr.create(aggCoeffs[2]!), Fr.create(cAccX2)),
    )
    condAddYCoeff = Fr.add(
      condAddYCoeff,
      Fr.mul(Fr.create(aggCoeffs[2]!), Fr.create(cAccY2)),
    )

    // Combine commitments: Σ(coeff_i * commitment_i)
    // Matching Rust: C::combine(&[coeffs], &[commitments])
    const commitments: Uint8Array[] = [
      innerProdAcc,
      condAddAccX,
      condAddAccY,
    ]
    const commitmentCoeffs: bigint[] = [
      innerProdCoeff,
      condAddXCoeff,
      condAddYCoeff,
    ]

    // Combine using MSM: Σ(coeff_i * C_i)
    let result = bls12_381.G1.Point.ZERO

    for (let i = 0; i < commitments.length; i++) {
      const commitment = bls12_381.G1.Point.fromBytes(commitments[i]!)
      const coeff = Fr.create(commitmentCoeffs[i]!)
      result = result.add(commitment.multiply(coeff))
    }

    return result.toBytes(true)
  }

  /**
   * Evaluate quotient polynomial at zeta
   * 
   * Computes: q(zeta) = (eval + lin_at_zeta_omega) / vanishing_poly(zeta)
   */
  evaluateQAtZeta(aggCoeffs: bigint[], linAtZetaOmega: bigint): bigint {
    const Fr = bls12_381.fields.Fr

    // Evaluate linearization polynomial constant term
    const constraintEvals = this.evaluateConstraintsMain()
    let evalResult = Fr.ZERO
    for (let i = 0; i < constraintEvals.length; i++) {
      const alpha = Fr.create(aggCoeffs[i]!)
      const constraint = Fr.create(constraintEvals[i]!)
      evalResult = Fr.add(evalResult, Fr.mul(alpha, constraint))
    }

    // Add linearization at zeta*omega
    const linAtZetaOmegaF = Fr.create(linAtZetaOmega)
    const numerator = Fr.add(evalResult, linAtZetaOmegaF)

    // Divide by vanishing polynomial
    // Matching Rust: self.domain_evaluated().divide_by_vanishing_poly_in_zeta(poly_in_zeta)
    const vanishingPolyInv = this.domainEvals.vanishingPolynomialInv
    return Fr.mul(numerator, vanishingPolyInv)
  }

  /**
   * Get evaluated domain
   */
  domainEvaluated(): EvaluatedDomain {
    return this.domainEvals
  }
}

