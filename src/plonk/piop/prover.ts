/**
 * PIOP Prover
 *
 * Implements the prover side of Polynomial Interactive Oracle Proofs (PIOP)
 * Matches w3f-ring-proof/src/piop/prover.rs
 */

import type { Domain, FieldColumn } from '../domain/domain'
import type { DensePolynomial } from '../domain/polynomial'
import { DensePolynomialImpl } from '../domain/polynomial'
import type { AffineColumn } from '../gadgets/affine-column'
import { BitColumn } from '../gadgets/bit-column'
import { Booleanity } from '../gadgets/booleanity'
import { CondAdd } from '../gadgets/cond-add'
import { FixedCells } from '../gadgets/fixed-cells'
import { InnerProd } from '../gadgets/inner-prod'
import { RingCommitments, RingEvaluations } from './mod'
import type { FixedColumns, PiopParams } from './params'

/**
 * PIOP Prover
 *
 * Builds the execution trace and constraints for ring proof
 */
export class PiopProver {
  private readonly domain: Domain
  private readonly points: AffineColumn
  private readonly ringSelector: FieldColumn
  private readonly bits: BitColumn
  private readonly booleanity: Booleanity
  private readonly innerProd: InnerProd
  private readonly innerProdAcc: FixedCells
  private readonly condAdd: CondAdd
  private readonly condAddAccX: FixedCells
  private readonly condAddAccY: FixedCells

  /**
   * Build PIOP prover
   *
   * @param params - PIOP parameters
   * @param fixedColumns - Fixed columns (points and ring selector)
   * @param proverIndexInKeys - Prover's index in the ring
   * @param secret - Prover's secret scalar (blinding factor)
   */
  static build(
    params: PiopParams,
    fixedColumns: FixedColumns,
    proverIndexInKeys: number,
    secret: bigint,
  ): PiopProver {
    const domain = params.domain
    const { points, ringSelector } = fixedColumns

    // Build bits column
    const bits = PiopProver.bitsColumn(params, proverIndexInKeys, secret)

    // Initialize gadgets
    const innerProd = InnerProd.init(ringSelector, bits.col, domain)
    const condAdd = CondAdd.init(bits, points, params.seed, domain)
    const booleanity = Booleanity.init(bits)
    const condAddAccX = FixedCells.init(condAdd.acc.xs, domain)
    const condAddAccY = FixedCells.init(condAdd.acc.ys, domain)
    const innerProdAcc = FixedCells.init(innerProd.acc, domain)

    return new PiopProver(
      domain,
      points,
      ringSelector,
      bits,
      booleanity,
      innerProd,
      innerProdAcc,
      condAdd,
      condAddAccX,
      condAddAccY,
    )
  }

  private constructor(
    domain: Domain,
    points: AffineColumn,
    ringSelector: FieldColumn,
    bits: BitColumn,
    booleanity: Booleanity,
    innerProd: InnerProd,
    innerProdAcc: FixedCells,
    condAdd: CondAdd,
    condAddAccX: FixedCells,
    condAddAccY: FixedCells,
  ) {
    this.domain = domain
    this.points = points
    this.ringSelector = ringSelector
    this.bits = bits
    this.booleanity = booleanity
    this.innerProd = innerProd
    this.innerProdAcc = innerProdAcc
    this.condAdd = condAdd
    this.condAddAccX = condAddAccX
    this.condAddAccY = condAddAccY
  }

  /**
   * Build bits column
   *
   * Structure: [keyset_part (one hot), scalar_part (secret bits)]
   * - keyset_part: all false except at prover_index
   * - scalar_part: bits of secret scalar
   */
  private static bitsColumn(
    params: PiopParams,
    indexInKeys: number,
    secret: bigint,
  ): BitColumn {
    // Keyset part: one-hot encoding of prover index
    const keysetPart = Array(params.keysetPartSize).fill(false)
    if (indexInKeys >= keysetPart.length) {
      throw new Error(
        `Prover index ${indexInKeys} out of range [0, ${keysetPart.length})`,
      )
    }
    keysetPart[indexInKeys] = true

    // Scalar part: bits of secret
    const scalarPart = params.scalarPart(secret)

    // Combine
    const bits = [...keysetPart, ...scalarPart]

    if (bits.length !== params.domain.capacity - 1) {
      throw new Error(
        `Bits length ${bits.length} must equal domain.capacity - 1 (${params.domain.capacity - 1})`,
      )
    }

    return BitColumn.init(bits, params.domain)
  }

  /**
   * Get committed columns (witness columns)
   */
  committedColumns(
    commit: (poly: DensePolynomial) => Uint8Array,
  ): RingCommitments {
    const bits = commit(this.bits.col.poly)
    const condAddAcc: [Uint8Array, Uint8Array] = [
      commit(this.condAdd.acc.xs.poly),
      commit(this.condAdd.acc.ys.poly),
    ]
    const innProdAcc = commit(this.innerProd.acc.poly)

    return new RingCommitments(bits, innProdAcc, condAddAcc)
  }

  /**
   * Get all columns as polynomials
   */
  columns(): DensePolynomial[] {
    return [
      this.points.xs.poly,
      this.points.ys.poly,
      this.ringSelector.poly,
      this.bits.col.poly,
      this.innerProd.acc.poly,
      this.condAdd.acc.xs.poly,
      this.condAdd.acc.ys.poly,
    ]
  }

  /**
   * Evaluate all columns at point zeta
   */
  columnsEvaluated(zeta: bigint): RingEvaluations {
    const points: [bigint, bigint] = [
      this.points.xs.evaluate(zeta),
      this.points.ys.evaluate(zeta),
    ]
    const ringSelector = this.ringSelector.evaluate(zeta)
    const bits = this.bits.evaluate(zeta)
    const innProdAcc = this.innerProd.acc.evaluate(zeta)
    const condAddAcc: [bigint, bigint] = [
      this.condAdd.acc.xs.evaluate(zeta),
      this.condAdd.acc.ys.evaluate(zeta),
    ]

    return new RingEvaluations(
      points,
      ringSelector,
      bits,
      innProdAcc,
      condAddAcc,
    )
  }

  /**
   * Get all constraints
   */
  constraints(): bigint[][] {
    // Combine constraints from all gadgets
    // This will be fully implemented when we have constraint evaluation
    return [
      ...this.innerProd.constraints(),
      ...this.condAdd.constraints(),
      ...this.booleanity.constraints(),
      ...this.condAddAccX.constraints(),
      ...this.condAddAccY.constraints(),
      ...this.innerProdAcc.constraints(),
    ]
  }

  /**
   * Get linearized constraints at point zeta
   */
  constraintsLinearized(zeta: bigint): DensePolynomial[] {
    const result: DensePolynomial[] = []

    // InnerProd returns array of bigint (coefficients)
    const innerProdCoeffs = this.innerProd.constraintsLinearized(zeta)
    // #region agent log
    fetch(
      'http://127.0.0.1:10000/ingest/3fca1dc3-0561-4f6b-af77-e67afc81f2d7',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          location: 'piop/prover.ts:212',
          message: 'InnerProd constraintsLinearized',
          data: {
            innerProdCoeffsLength: innerProdCoeffs.length,
            innerProdCoeffs: innerProdCoeffs.map((c) => c.toString()),
          },
          timestamp: Date.now(),
          sessionId: 'debug-session',
          runId: 'run1',
          hypothesisId: 'A',
        }),
      },
    ).catch(() => {})
    // #endregion
    for (const coeff of innerProdCoeffs) {
      result.push(new DensePolynomialImpl([coeff]))
    }

    // CondAdd returns DensePolynomial[] directly (special case)
    // Matching Rust: constraints_linearized() returns Vec<DensePolynomial<F>>
    const condAddPolys = this.condAdd.constraintsLinearizedPolynomials(zeta)
    // #region agent log
    fetch(
      'http://127.0.0.1:10000/ingest/3fca1dc3-0561-4f6b-af77-e67afc81f2d7',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          location: 'piop/prover.ts:220',
          message: 'CondAdd constraintsLinearized',
          data: {
            condAddPolysLength: condAddPolys.length,
            condAddPolysDegrees: condAddPolys.map((p) => p.degree),
          },
          timestamp: Date.now(),
          sessionId: 'debug-session',
          runId: 'run1',
          hypothesisId: 'B',
        }),
      },
    ).catch(() => {})
    // #endregion
    for (const poly of condAddPolys) {
      result.push(poly)
    }

    // Booleanity returns array of bigint (coefficients)
    const booleanityCoeffs = this.booleanity.constraintsLinearized(zeta)
    // #region agent log
    fetch(
      'http://127.0.0.1:10000/ingest/3fca1dc3-0561-4f6b-af77-e67afc81f2d7',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          location: 'piop/prover.ts:228',
          message: 'Booleanity constraintsLinearized',
          data: {
            booleanityCoeffsLength: booleanityCoeffs.length,
            booleanityCoeffs: booleanityCoeffs.map((c) => c.toString()),
          },
          timestamp: Date.now(),
          sessionId: 'debug-session',
          runId: 'run1',
          hypothesisId: 'C',
        }),
      },
    ).catch(() => {})
    // #endregion
    for (const coeff of booleanityCoeffs) {
      result.push(new DensePolynomialImpl([coeff]))
    }

    // FixedCells return arrays of bigint (coefficients)
    const condAddAccXCoeffs = this.condAddAccX.constraintsLinearized(zeta)
    // #region agent log
    fetch(
      'http://127.0.0.1:10000/ingest/3fca1dc3-0561-4f6b-af77-e67afc81f2d7',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          location: 'piop/prover.ts:236',
          message: 'CondAddAccX constraintsLinearized',
          data: {
            condAddAccXCoeffsLength: condAddAccXCoeffs.length,
            condAddAccXCoeffs: condAddAccXCoeffs.map((c) => c.toString()),
          },
          timestamp: Date.now(),
          sessionId: 'debug-session',
          runId: 'run1',
          hypothesisId: 'D',
        }),
      },
    ).catch(() => {})
    // #endregion
    for (const coeff of condAddAccXCoeffs) {
      result.push(new DensePolynomialImpl([coeff]))
    }

    const condAddAccYCoeffs = this.condAddAccY.constraintsLinearized(zeta)
    // #region agent log
    fetch(
      'http://127.0.0.1:10000/ingest/3fca1dc3-0561-4f6b-af77-e67afc81f2d7',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          location: 'piop/prover.ts:244',
          message: 'CondAddAccY constraintsLinearized',
          data: {
            condAddAccYCoeffsLength: condAddAccYCoeffs.length,
            condAddAccYCoeffs: condAddAccYCoeffs.map((c) => c.toString()),
          },
          timestamp: Date.now(),
          sessionId: 'debug-session',
          runId: 'run1',
          hypothesisId: 'E',
        }),
      },
    ).catch(() => {})
    // #endregion
    for (const coeff of condAddAccYCoeffs) {
      result.push(new DensePolynomialImpl([coeff]))
    }

    const innerProdAccCoeffs = this.innerProdAcc.constraintsLinearized(zeta)
    // #region agent log
    fetch(
      'http://127.0.0.1:10000/ingest/3fca1dc3-0561-4f6b-af77-e67afc81f2d7',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          location: 'piop/prover.ts:252',
          message: 'InnerProdAcc constraintsLinearized',
          data: {
            innerProdAccCoeffsLength: innerProdAccCoeffs.length,
            innerProdAccCoeffs: innerProdAccCoeffs.map((c) => c.toString()),
          },
          timestamp: Date.now(),
          sessionId: 'debug-session',
          runId: 'run1',
          hypothesisId: 'F',
        }),
      },
    ).catch(() => {})
    // #endregion
    for (const coeff of innerProdAccCoeffs) {
      result.push(new DensePolynomialImpl([coeff]))
    }

    // #region agent log
    fetch(
      'http://127.0.0.1:10000/ingest/3fca1dc3-0561-4f6b-af77-e67afc81f2d7',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          location: 'piop/prover.ts:260',
          message: 'Total constraintsLinearized result',
          data: { resultLength: result.length, totalExpected: 7 },
          timestamp: Date.now(),
          sessionId: 'debug-session',
          runId: 'run1',
          hypothesisId: 'G',
        }),
      },
    ).catch(() => {})
    // #endregion

    return result
  }

  /**
   * Get domain
   */
  getDomain(): Domain {
    return this.domain
  }

  /**
   * Get result (cond_add.result)
   * This is the blinded public key commitment: seed + sum(selected_points) - seed
   */
  result(): { x: bigint; y: bigint } {
    return this.condAdd.result
  }
}
