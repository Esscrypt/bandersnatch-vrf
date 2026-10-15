import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BANDERSNATCH_PARAMS, mod, modInverse } from '@pbnjam/bandersnatch'
import type { Domain, FieldColumn } from '../domain/domain.ts'
import type { DensePolynomial } from '../domain/polynomial.ts'
import { DensePolynomialImpl } from '../domain/polynomial.ts'
import { AffineColumn } from './affine-column.ts'
import type { BitColumn } from './bit-column.ts'

export class CondAdd {
  public readonly acc: AffineColumn
  public readonly result: { x: bigint; y: bigint }
  private readonly bitmask: BitColumn
  private readonly points: AffineColumn
  private readonly notLast: FieldColumn

  static init(
    bitmask: BitColumn,
    points: AffineColumn,
    seed: { x: bigint; y: bigint },
    domain: Domain,
  ): CondAdd {
    if (bitmask.bits.length !== domain.capacity - 1) {
      throw new Error(
        `Bitmask length ${bitmask.bits.length} must equal domain capacity - 1 (${domain.capacity - 1})`,
      )
    }

    const notLast = domain.notLastRow

    const accPoints: Array<{ x: bigint; y: bigint }> = [seed]

    let currentAcc = seed
    for (let i = 0; i < bitmask.bits.length; i++) {
      const bit = bitmask.bits[i]
      const point = points.points[i]

      if (!point) {
        throw new Error(`Missing point at index ${i}`)
      }

      if (bit) {
        currentAcc = CondAdd.addPoints(currentAcc, point)
      }

      accPoints.push(currentAcc)
    }

    const acc = AffineColumn.privateColumn(accPoints, domain)

    const finalAcc = accPoints[accPoints.length - 1]!
    const result = CondAdd.subtractPoints(finalAcc, seed)

    return new CondAdd(bitmask, points, acc, notLast, domain, result)
  }

  private constructor(
    bitmask: BitColumn,
    points: AffineColumn,
    acc: AffineColumn,
    notLast: FieldColumn,
    _domain: Domain,
    result: { x: bigint; y: bigint },
  ) {
    this.bitmask = bitmask
    this.points = points
    this.acc = acc
    this.notLast = notLast
    this.result = result
  }

  private static addPoints(
    p1: { x: bigint; y: bigint },
    p2: { x: bigint; y: bigint },
  ): { x: bigint; y: bigint } {
    const { a, d } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
    const p = BANDERSNATCH_PARAMS.FIELD_MODULUS

    const x1y2 = mod(p1.x * p2.y, p)
    const y1x2 = mod(p1.y * p2.x, p)
    const y1y2 = mod(p1.y * p2.y, p)
    const x1x2 = mod(p1.x * p2.x, p)

    const dxy = mod(d * x1x2 * y1y2, p)
    const denom1 = mod(1n + dxy, p)
    const denom2 = mod(1n - dxy, p)

    const denom1Inv = modInverse(denom1, p)
    const denom2Inv = modInverse(denom2, p)

    const x3 = mod((x1y2 + y1x2) * denom1Inv, p)
    const y3 = mod((y1y2 - a * x1x2) * denom2Inv, p)

    return { x: x3, y: y3 }
  }

  private static subtractPoints(
    p1: { x: bigint; y: bigint },
    p2: { x: bigint; y: bigint },
  ): { x: bigint; y: bigint } {
    const p = BANDERSNATCH_PARAMS.FIELD_MODULUS
    const negP2 = { x: mod(-p2.x, p), y: p2.y }
    return CondAdd.addPoints(p1, negP2)
  }

  constraints(): bigint[][] {
    const Fr = bls12_381.fields.Fr
    const domain4xSize = this.bitmask.col.evals4x.length
    const { a: teA } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS

    const b = this.bitmask.col.evals4x
    const x1 = this.acc.xs.evals4x
    const y1 = this.acc.ys.evals4x
    const x2 = this.points.xs.evals4x
    const y2 = this.points.ys.evals4x
    const x3 = this.acc.xs.shifted4x()
    const y3 = this.acc.ys.shifted4x()
    const notLast = this.notLast.evals4x

    const one = Array(domain4xSize).fill(Fr.ONE)
    const teACoeff = Array(domain4xSize).fill(BigInt(teA))

    const c1: bigint[] = []
    const c2: bigint[] = []

    for (let i = 0; i < domain4xSize; i++) {
      const bF = Fr.create(b[i]!)
      const x1F = Fr.create(x1[i]!)
      const y1F = Fr.create(y1[i]!)
      const x2F = Fr.create(x2[i]!)
      const y2F = Fr.create(y2[i]!)
      const x3F = Fr.create(x3[i]!)
      const y3F = Fr.create(y3[i]!)
      const oneF = Fr.create(one[i]!)
      const teAF = Fr.create(teACoeff[i]!)
      const notLastF = Fr.create(notLast[i]!)

      const y1y2 = Fr.mul(y1F, y2F)
      const ax1x2 = Fr.mul(teAF, Fr.mul(x1F, x2F))
      const y1y2PlusAx1x2 = Fr.add(y1y2, ax1x2)
      const x3TimesY1y2PlusAx1x2 = Fr.mul(x3F, y1y2PlusAx1x2)

      const x1y1 = Fr.mul(x1F, y1F)
      const x2y2 = Fr.mul(x2F, y2F)
      const x1y1PlusX2y2 = Fr.add(x1y1, x2y2)

      const term1 = Fr.sub(x3TimesY1y2PlusAx1x2, x1y1PlusX2y2)
      const bTimesTerm1 = Fr.mul(bF, term1)

      const x3MinusX1 = Fr.sub(x3F, x1F)
      const oneMinusB = Fr.sub(oneF, bF)
      const oneMinusBTimesX3MinusX1 = Fr.mul(oneMinusB, x3MinusX1)

      const constraint1 = Fr.add(bTimesTerm1, oneMinusBTimesX3MinusX1)
      c1.push(Fr.mul(constraint1, notLastF))

      const x1y2 = Fr.mul(x1F, y2F)
      const x2y1 = Fr.mul(x2F, y1F)
      const x1y2MinusX2y1 = Fr.sub(x1y2, x2y1)
      const y3TimesX1y2MinusX2y1 = Fr.mul(y3F, x1y2MinusX2y1)

      const x1y1MinusX2y2 = Fr.sub(x1y1, x2y2)
      const term2 = Fr.sub(y3TimesX1y2MinusX2y1, x1y1MinusX2y2)
      const bTimesTerm2 = Fr.mul(bF, term2)

      const y3MinusY1 = Fr.sub(y3F, y1F)
      const oneMinusBTimesY3MinusY1 = Fr.mul(oneMinusB, y3MinusY1)

      const constraint2 = Fr.add(bTimesTerm2, oneMinusBTimesY3MinusY1)
      c2.push(Fr.mul(constraint2, notLastF))
    }

    return [c1, c2]
  }

  constraintsLinearizedPolynomials(z: bigint): DensePolynomial[] {
    const Fr = bls12_381.fields.Fr

    const bitmaskEval = this.bitmask.evaluate(z)
    const pointsEval = this.points.evaluate(z)
    const notLastEval = this.notLast.evaluate(z)
    const accEval = this.acc.evaluate(z)

    const vals = new CondAddValues(
      bitmaskEval,
      pointsEval,
      notLastEval,
      accEval,
    )

    const accXPoly = this.acc.xs.poly
    const accYPoly = this.acc.ys.poly

    const [cAccX1] = vals.accCoeffs1()
    const c1LinCoeffs = accXPoly.coeffs.map((coeff) =>
      Fr.mul(Fr.create(coeff), Fr.create(cAccX1)),
    )

    const [, cAccY2] = vals.accCoeffs2()
    const c2LinCoeffs = accYPoly.coeffs.map((coeff) =>
      Fr.mul(Fr.create(coeff), Fr.create(cAccY2)),
    )

    return [
      new DensePolynomialImpl(c1LinCoeffs),
      new DensePolynomialImpl(c2LinCoeffs),
    ]
  }

  constraintsLinearized(_z: bigint): bigint[] {
    return []
  }
}

export class CondAddValues {
  public readonly bitmask: bigint
  public readonly points: [bigint, bigint]
  public readonly notLast: bigint
  public readonly acc: [bigint, bigint]

  constructor(
    bitmask: bigint,
    points: [bigint, bigint],
    notLast: bigint,
    acc: [bigint, bigint],
  ) {
    this.bitmask = bitmask
    this.points = points
    this.notLast = notLast
    this.acc = acc
  }

  accCoeffs1(): [bigint, bigint] {
    const Fr = bls12_381.fields.Fr
    const { a } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
    const b = Fr.create(this.bitmask)
    const x1 = Fr.create(this.acc[0])
    const y1 = Fr.create(this.acc[1])
    const x2 = Fr.create(this.points[0])
    const y2 = Fr.create(this.points[1])
    const one = Fr.ONE
    const notLastF = Fr.create(this.notLast)

    const y1y2 = Fr.mul(y1, y2)
    const ax1x2 = Fr.mul(Fr.create(a), Fr.mul(x1, x2))
    const y1y2PlusAx1x2 = Fr.add(y1y2, ax1x2)
    const bTimesY1y2PlusAx1x2 = Fr.mul(b, y1y2PlusAx1x2)
    const oneMinusB = Fr.sub(one, b)
    const inner = Fr.add(bTimesY1y2PlusAx1x2, oneMinusB)

    const cAccX = Fr.mul(notLastF, inner)
    const cAccY = Fr.ZERO

    return [cAccX, cAccY]
  }

  accCoeffs2(): [bigint, bigint] {
    const Fr = bls12_381.fields.Fr
    const b = Fr.create(this.bitmask)
    const x1 = Fr.create(this.acc[0])
    const y1 = Fr.create(this.acc[1])
    const x2 = Fr.create(this.points[0])
    const y2 = Fr.create(this.points[1])
    const one = Fr.ONE
    const notLastF = Fr.create(this.notLast)

    const x1y2 = Fr.mul(x1, y2)
    const x2y1 = Fr.mul(x2, y1)
    const x1y2MinusX2y1 = Fr.sub(x1y2, x2y1)
    const bTimesX1y2MinusX2y1 = Fr.mul(b, x1y2MinusX2y1)
    const oneMinusB = Fr.sub(one, b)
    const inner = Fr.add(bTimesX1y2MinusX2y1, oneMinusB)

    const cAccX = Fr.ZERO
    const cAccY = Fr.mul(notLastF, inner)

    return [cAccX, cAccY]
  }

  evaluateConstraintsMain(): bigint[] {
    const Fr = bls12_381.fields.Fr
    const { a } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
    const b = Fr.create(this.bitmask)
    const [x1, y1] = [Fr.create(this.acc[0]), Fr.create(this.acc[1])]
    const [x2, y2] = [Fr.create(this.points[0]), Fr.create(this.points[1])]
    const [x3, y3] = [Fr.ZERO, Fr.ZERO]
    const one = Fr.ONE
    const notLastF = Fr.create(this.notLast)

    const c1 = Fr.mul(
      notLastF,
      Fr.add(
        Fr.mul(
          b,
          Fr.sub(
            Fr.mul(
              x3,
              Fr.add(Fr.mul(y1, y2), Fr.mul(Fr.create(a), Fr.mul(x1, x2))),
            ),
            Fr.add(Fr.mul(x1, y1), Fr.mul(y2, x2)),
          ),
        ),
        Fr.mul(Fr.sub(one, b), Fr.sub(x3, x1)),
      ),
    )

    const c2 = Fr.mul(
      notLastF,
      Fr.add(
        Fr.mul(
          b,
          Fr.sub(
            Fr.mul(y3, Fr.sub(Fr.mul(x1, y2), Fr.mul(x2, y1))),
            Fr.sub(Fr.mul(x1, y1), Fr.mul(x2, y2)),
          ),
        ),
        Fr.mul(Fr.sub(one, b), Fr.sub(y3, y1)),
      ),
    )

    return [c1, c2]
  }
}
