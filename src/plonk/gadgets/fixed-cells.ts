import { bls12_381 } from '@noble/curves/bls12-381.js'
import type { Domain, FieldColumn } from '../domain/domain.ts'

export class FixedCells {
  public readonly col: FieldColumn
  public readonly lFirst: FieldColumn
  public readonly lLast: FieldColumn

  static init(col: FieldColumn, domain: Domain): FixedCells {
    if (col.len !== domain.capacity) {
      throw new Error(
        `Column length ${col.len} must equal domain capacity ${domain.capacity}`,
      )
    }

    return new FixedCells(col, domain.lFirst, domain.lLast)
  }

  private constructor(
    col: FieldColumn,
    lFirst: FieldColumn,
    lLast: FieldColumn,
  ) {
    this.col = col
    this.lFirst = lFirst
    this.lLast = lLast
  }

  constraints(): bigint[][] {
    const Fr = bls12_381.fields.Fr
    const domain4xSize = this.col.evals4x.length

    const colFirst = this.col.evals[0]!
    const colLast = this.col.evals[this.col.len - 1]!

    const col = this.col.evals4x
    const lFirst = this.lFirst.evals4x
    const lLast = this.lLast.evals4x

    const colFirstConst = Array(domain4xSize).fill(colFirst)
    const colLastConst = Array(domain4xSize).fill(colLast)

    const constraint: bigint[] = []
    for (let i = 0; i < domain4xSize; i++) {
      const colF = Fr.create(col[i]!)
      const lFirstF = Fr.create(lFirst[i]!)
      const lLastF = Fr.create(lLast[i]!)
      const colFirstF = Fr.create(colFirstConst[i]!)
      const colLastF = Fr.create(colLastConst[i]!)

      const c1 = Fr.mul(lFirstF, Fr.sub(colF, colFirstF))

      const c2 = Fr.mul(lLastF, Fr.sub(colF, colLastF))

      const result = Fr.add(c1, c2)
      constraint.push(result)
    }

    return [constraint]
  }

  constraintsLinearized(_z: bigint): bigint[] {
    return [0n]
  }
}

export class FixedCellsValues {
  public readonly col: bigint
  public readonly colFirst: bigint
  public readonly colLast: bigint
  public readonly lFirst: bigint
  public readonly lLast: bigint

  constructor(
    col: bigint,
    colFirst: bigint,
    colLast: bigint,
    lFirst: bigint,
    lLast: bigint,
  ) {
    this.col = col
    this.colFirst = colFirst
    this.colLast = colLast
    this.lFirst = lFirst
    this.lLast = lLast
  }

  static evaluateForCell(
    colEval: bigint,
    liEval: bigint,
    cellVal: bigint,
  ): bigint {
    const Fr = bls12_381.fields.Fr
    const colF = Fr.create(colEval)
    const liF = Fr.create(liEval)
    const cellF = Fr.create(cellVal)
    return Fr.mul(liF, Fr.sub(colF, cellF))
  }

  evaluateConstraintsMain(): bigint[] {
    const c1 = FixedCellsValues.evaluateForCell(
      this.col,
      this.lFirst,
      this.colFirst,
    )
    const c2 = FixedCellsValues.evaluateForCell(
      this.col,
      this.lLast,
      this.colLast,
    )
    const Fr = bls12_381.fields.Fr
    return [Fr.add(c1, c2)]
  }
}
