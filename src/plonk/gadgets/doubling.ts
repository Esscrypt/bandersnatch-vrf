import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BANDERSNATCH_PARAMS, mod, modInverse } from '@pbnjam/bandersnatch'
import type { Domain, FieldColumn } from '../domain/domain.ts'
import { DensePolynomialImpl } from '../domain/polynomial.ts'
import { AffineColumn } from './affine-column.ts'

export class Doubling {
  public readonly doublings: AffineColumn
  private readonly notLast: FieldColumn
  private readonly domain: Domain

  static init(p: { x: bigint; y: bigint }, domain: Domain): Doubling {
    const doublings = Doubling.doublingsOf(p, domain)
    const doublingsCol = AffineColumn.publicColumn(doublings, domain)
    const notLast = domain.notLastRow

    return new Doubling(doublingsCol, notLast, domain)
  }

  static doublingsOf(
    p: { x: bigint; y: bigint },
    domain: Domain,
  ): Array<{ x: bigint; y: bigint }> {
    const doublings: Array<{ x: bigint; y: bigint }> = [p]
    let current = p

    for (let i = 1; i < domain.capacity; i++) {
      current = Doubling.doublePoint(current)
      doublings.push(current)
    }

    return doublings
  }

  private static doublePoint(p: { x: bigint; y: bigint }): {
    x: bigint
    y: bigint
  } {
    const { a } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
    const p_mod = BANDERSNATCH_PARAMS.FIELD_MODULUS

    const x1_sq = mod(p.x * p.x, p_mod)
    const y1_sq = mod(p.y * p.y, p_mod)
    const x1y1 = mod(p.x * p.y, p_mod)

    const a_x1_sq = mod(a * x1_sq, p_mod)
    const denom1 = mod(a_x1_sq + y1_sq, p_mod)
    const denom2 = mod(2n - a_x1_sq - y1_sq, p_mod)

    const denom1Inv = modInverse(denom1, p_mod)
    const denom2Inv = modInverse(denom2, p_mod)

    const x2 = mod(2n * x1y1 * denom1Inv, p_mod)
    const y2 = mod((y1_sq - a_x1_sq) * denom2Inv, p_mod)

    return { x: x2, y: y2 }
  }

  private constructor(
    doublings: AffineColumn,
    notLast: FieldColumn,
    domain: Domain,
  ) {
    this.doublings = doublings
    this.notLast = notLast
    this.domain = domain
  }

  witnessColumns(): Array<{ coeffs: bigint[]; degree: number }> {
    return [
      {
        coeffs: this.doublings.xs.poly.coeffs,
        degree: this.doublings.xs.poly.degree,
      },
      {
        coeffs: this.doublings.ys.poly.coeffs,
        degree: this.doublings.ys.poly.degree,
      },
    ]
  }

  constraints(): bigint[][] {
    const Fr = bls12_381.fields.Fr
    const domain4xSize = this.domain.getDomain4x().size
    const { a } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS

    const x1 = this.doublings.xs.evals4x
    const y1 = this.doublings.ys.evals4x
    const x2 = this.doublings.xs.shifted4x()
    const y2 = this.doublings.ys.shifted4x()
    const notLast = this.notLast.evals4x

    const aEvals = Array(domain4xSize).fill(BigInt(a))
    const twoEvals = Array(domain4xSize).fill(2n)

    const x1_sq: bigint[] = []
    const y1_sq: bigint[] = []
    const x1y1: bigint[] = []
    const a_x1_sq: bigint[] = []

    for (let i = 0; i < domain4xSize; i++) {
      const x1F = Fr.create(x1[i]!)
      const y1F = Fr.create(y1[i]!)
      const aF = Fr.create(aEvals[i]!)

      x1_sq.push(Fr.mul(x1F, x1F))
      y1_sq.push(Fr.mul(y1F, y1F))
      x1y1.push(Fr.mul(x1F, y1F))
      a_x1_sq.push(Fr.mul(Fr.create(x1_sq[i]!), aF))
    }

    const c1: bigint[] = []
    for (let i = 0; i < domain4xSize; i++) {
      const x2F = Fr.create(x2[i]!)
      const a_x1_sqF = Fr.create(a_x1_sq[i]!)
      const y1_sqF = Fr.create(y1_sq[i]!)
      const x1y1F = Fr.create(x1y1[i]!)
      const twoF = Fr.create(twoEvals[i]!)

      const sum = Fr.add(a_x1_sqF, y1_sqF)
      const product = Fr.mul(x2F, sum)
      const double_xy = Fr.mul(twoF, x1y1F)
      const constraint = Fr.sub(product, double_xy)

      c1.push(constraint)
    }

    const c2: bigint[] = []
    for (let i = 0; i < domain4xSize; i++) {
      const y2F = Fr.create(y2[i]!)
      const a_x1_sqF = Fr.create(a_x1_sq[i]!)
      const y1_sqF = Fr.create(y1_sq[i]!)
      const twoF = Fr.create(twoEvals[i]!)

      const diff = Fr.sub(twoF, Fr.add(a_x1_sqF, y1_sqF))
      const product = Fr.mul(y2F, diff)
      const sum = Fr.add(product, Fr.sub(a_x1_sqF, y1_sqF))

      c2.push(sum)
    }

    for (let i = 0; i < domain4xSize; i++) {
      const notLastF = Fr.create(notLast[i]!)
      c1[i] = Fr.mul(Fr.create(c1[i]!), notLastF)
      c2[i] = Fr.mul(Fr.create(c2[i]!), notLastF)
    }

    return [c1, c2]
  }

  constraintsLinearized(
    z: bigint,
  ): Array<{ coeffs: bigint[]; degree: number }> {
    const Fr = bls12_381.fields.Fr
    const { a } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS

    const [x1, y1] = this.doublings.evaluate(z)
    const notLastEval = this.notLast.evaluate(z)

    const x1F = Fr.create(x1)
    const y1F = Fr.create(y1)
    const notLastF = Fr.create(notLastEval)

    const x1_sq = Fr.mul(x1F, x1F)
    const y1_sq = Fr.mul(y1F, y1F)
    const a_x1_sq = Fr.mul(x1_sq, Fr.create(a))
    const c = Fr.add(a_x1_sq, y1_sq)

    const x2_coeff = Fr.mul(c, notLastF)
    const y2_coeff = Fr.mul(Fr.sub(Fr.create(2n), c), notLastF)

    const x2Poly = this.doublings.xs.poly
    const y2Poly = this.doublings.ys.poly

    const x2CoeffPoly = new DensePolynomialImpl([x2_coeff])
    const y2CoeffPoly = new DensePolynomialImpl([y2_coeff])

    const x2Result = this.multiplyPolynomials(x2Poly, x2CoeffPoly)
    const y2Result = this.multiplyPolynomials(y2Poly, y2CoeffPoly)

    return [
      { coeffs: x2Result.coeffs, degree: x2Result.degree },
      { coeffs: y2Result.coeffs, degree: y2Result.degree },
    ]
  }

  private multiplyPolynomials(
    p1: { coeffs: bigint[]; degree: number },
    p2: { coeffs: bigint[]; degree: number },
  ): { coeffs: bigint[]; degree: number } {
    const Fr = bls12_381.fields.Fr
    const resultDegree = p1.degree + p2.degree
    const resultCoeffs = Array(resultDegree + 1).fill(Fr.ZERO)

    for (let i = 0; i <= p1.degree; i++) {
      for (let j = 0; j <= p2.degree; j++) {
        const coeff = Fr.mul(
          Fr.create(p1.coeffs[i] ?? 0n),
          Fr.create(p2.coeffs[j] ?? 0n),
        )
        resultCoeffs[i + j] = Fr.add(
          Fr.create(resultCoeffs[i + j] ?? Fr.ZERO),
          coeff,
        )
      }
    }

    return { coeffs: resultCoeffs, degree: resultDegree }
  }

  evaluateAssignment(z: bigint): DoublingValues {
    const [x, y] = this.doublings.evaluate(z)
    const notLastEval = this.notLast.evaluate(z)

    return new DoublingValues(x, y, notLastEval)
  }
}

export class DoublingValues {
  public readonly doublings: [bigint, bigint]
  public readonly notLast: bigint

  constructor(x: bigint, y: bigint, notLast: bigint) {
    this.doublings = [x, y]
    this.notLast = notLast
  }

  getCoeffs(): [bigint, bigint] {
    const Fr = bls12_381.fields.Fr
    const { a } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
    const [x1, y1] = this.doublings

    const x1F = Fr.create(x1)
    const y1F = Fr.create(y1)
    const notLastF = Fr.create(this.notLast)

    const x1_sq = Fr.mul(x1F, x1F)
    const y1_sq = Fr.mul(y1F, y1F)
    const a_x1_sq = Fr.mul(x1_sq, Fr.create(a))
    const c = Fr.add(a_x1_sq, y1_sq)

    const x2_coeff = Fr.mul(c, notLastF)
    const y2_coeff = Fr.mul(Fr.sub(Fr.create(2n), c), notLastF)

    return [x2_coeff, y2_coeff]
  }

  evaluateConstraintsMain(): bigint[] {
    const Fr = bls12_381.fields.Fr
    const { a } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
    const [x1, y1] = this.doublings

    const x1F = Fr.create(x1)
    const y1F = Fr.create(y1)
    const notLastF = Fr.create(this.notLast)

    const c1 = Fr.mul(Fr.mul(Fr.create(-2n), Fr.mul(x1F, y1F)), notLastF)

    const x1_sq = Fr.mul(x1F, x1F)
    const y1_sq = Fr.mul(y1F, y1F)
    const a_x1_sq = Fr.mul(x1_sq, Fr.create(a))
    const c2 = Fr.mul(Fr.sub(a_x1_sq, y1_sq), notLastF)

    return [c1, c2]
  }
}
