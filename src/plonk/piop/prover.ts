import type { Domain, FieldColumn } from '../domain/domain.ts'
import type { DensePolynomial } from '../domain/polynomial.ts'
import { DensePolynomialImpl } from '../domain/polynomial.ts'
import type { AffineColumn } from '../gadgets/affine-column.ts'
import { BitColumn } from '../gadgets/bit-column.ts'
import { Booleanity } from '../gadgets/booleanity.ts'
import { CondAdd } from '../gadgets/cond-add.ts'
import { FixedCells } from '../gadgets/fixed-cells.ts'
import { InnerProd } from '../gadgets/inner-prod.ts'
import { RingCommitments, RingEvaluations } from './mod.ts'
import type { FixedColumns, PiopParams } from './params.ts'

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

  static build(
    params: PiopParams,
    fixedColumns: FixedColumns,
    proverIndexInKeys: number,
    secret: bigint,
  ): PiopProver {
    const domain = params.domain
    const { points, ringSelector } = fixedColumns

    const bits = PiopProver.bitsColumn(params, proverIndexInKeys, secret)

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

  private static bitsColumn(
    params: PiopParams,
    indexInKeys: number,
    secret: bigint,
  ): BitColumn {
    const keysetPart = Array(params.keysetPartSize).fill(false)
    if (indexInKeys >= keysetPart.length) {
      throw new Error(
        `Prover index ${indexInKeys} out of range [0, ${keysetPart.length})`,
      )
    }
    keysetPart[indexInKeys] = true

    const scalarPart = params.scalarPart(secret)

    const bits = [...keysetPart, ...scalarPart]

    if (bits.length !== params.domain.capacity - 1) {
      throw new Error(
        `Bits length ${bits.length} must equal domain.capacity - 1 (${params.domain.capacity - 1})`,
      )
    }

    return BitColumn.init(bits, params.domain)
  }

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

  constraints(): bigint[][] {
    return [
      ...this.innerProd.constraints(),
      ...this.condAdd.constraints(),
      ...this.booleanity.constraints(),
      ...this.condAddAccX.constraints(),
      ...this.condAddAccY.constraints(),
      ...this.innerProdAcc.constraints(),
    ]
  }

  constraintsLinearized(zeta: bigint): DensePolynomial[] {
    const result: DensePolynomial[] = []

    const innerProdPolys = this.innerProd.constraintsLinearizedPolynomials(zeta)
    for (const poly of innerProdPolys) {
      result.push(poly)
    }

    const condAddPolys = this.condAdd.constraintsLinearizedPolynomials(zeta)
    for (const poly of condAddPolys) {
      result.push(poly)
    }

    const booleanityCoeffs = this.booleanity.constraintsLinearized(zeta)
    for (const coeff of booleanityCoeffs) {
      result.push(new DensePolynomialImpl([coeff]))
    }

    const condAddAccXCoeffs = this.condAddAccX.constraintsLinearized(zeta)
    for (const coeff of condAddAccXCoeffs) {
      result.push(new DensePolynomialImpl([coeff]))
    }

    const condAddAccYCoeffs = this.condAddAccY.constraintsLinearized(zeta)
    for (const coeff of condAddAccYCoeffs) {
      result.push(new DensePolynomialImpl([coeff]))
    }

    const innerProdAccCoeffs = this.innerProdAcc.constraintsLinearized(zeta)
    for (const coeff of innerProdAccCoeffs) {
      result.push(new DensePolynomialImpl([coeff]))
    }

    return result
  }

  getDomain(): Domain {
    return this.domain
  }

  result(): { x: bigint; y: bigint } {
    return this.condAdd.result
  }
}
