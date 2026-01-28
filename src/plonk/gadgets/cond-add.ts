/**
 * Conditional Addition Gadget (CondAdd)
 *
 * Implements conditional point addition for Twisted Edwards curves.
 * Uses the accumulator seed point as the initial accumulator value.
 *
 * This gadget accumulates points conditionally based on a bitmask:
 * - If bit is set: acc = acc + point
 * - If bit is not set: acc = acc (unchanged)
 *
 * The accumulator starts from the seed point (ACCUMULATOR_SEED_POINT).
 * The result is computed as: result = final_acc - seed
 */

import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BANDERSNATCH_PARAMS, mod, modInverse } from '@pbnjam/bandersnatch'
import type { Domain, FieldColumn } from '../domain/domain'
import type { DensePolynomial } from '../domain/polynomial'
import { DensePolynomialImpl } from '../domain/polynomial'
import { AffineColumn } from './affine-column'
import type { BitColumn } from './bit-column'

/**
 * Conditional Addition Gadget for Twisted Edwards curves
 *
 * This gadget implements the accumulator pattern used in ring proofs:
 * - Starts with accumulator seed point
 * - Conditionally adds points based on bitmask
 * - Result is the sum of selected points (final_acc - seed)
 */
export class CondAdd {
  public readonly acc: AffineColumn
  public readonly result: { x: bigint; y: bigint }
  private readonly bitmask: BitColumn
  private readonly points: AffineColumn
  private readonly notLast: FieldColumn

  /**
   * Initialize CondAdd gadget
   *
   * @param bitmask - Bit column indicating which points to add
   * @param points - Points to conditionally add
   * @param seed - Accumulator seed point (ACCUMULATOR_SEED_POINT)
   * @param domain - Plonk domain
   */
  static init(
    bitmask: BitColumn,
    points: AffineColumn,
    seed: { x: bigint; y: bigint },
    domain: Domain,
  ): CondAdd {
    // Validate inputs
    if (bitmask.bits.length !== domain.capacity - 1) {
      throw new Error(
        `Bitmask length ${bitmask.bits.length} must equal domain capacity - 1 (${domain.capacity - 1})`,
      )
    }

    const notLast = domain.notLastRow

    // Accumulate points conditionally, starting from seed
    // acc[0] = seed
    // acc[i+1] = acc[i] + (bitmask[i] ? points[i] : 0)
    const accPoints: Array<{ x: bigint; y: bigint }> = [seed]

    let currentAcc = seed
    for (let i = 0; i < bitmask.bits.length; i++) {
      const bit = bitmask.bits[i]
      const point = points.points[i]

      if (!point) {
        throw new Error(`Missing point at index ${i}`)
      }

      if (bit) {
        // Add point to accumulator
        currentAcc = CondAdd.addPoints(currentAcc, point)
      }
      // If bit is false, accumulator stays the same

      accPoints.push(currentAcc)
    }

    // Create accumulator column
    const acc = AffineColumn.privateColumn(accPoints, domain)

    // Compute result: final_acc - seed
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

  /**
   * Add two Twisted Edwards points
   */
  private static addPoints(
    p1: { x: bigint; y: bigint },
    p2: { x: bigint; y: bigint },
  ): { x: bigint; y: bigint } {
    // Twisted Edwards addition formula for Bandersnatch
    // Using complete addition formula from bandersnatch curve
    const { a, d } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
    const p = BANDERSNATCH_PARAMS.FIELD_MODULUS

    // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
    // y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)

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

  /**
   * Subtract two Twisted Edwards points (p1 - p2)
   */
  private static subtractPoints(
    p1: { x: bigint; y: bigint },
    p2: { x: bigint; y: bigint },
  ): { x: bigint; y: bigint } {
    // Negate p2 and add
    const p = BANDERSNATCH_PARAMS.FIELD_MODULUS
    const negP2 = { x: mod(-p2.x, p), y: p2.y }
    return CondAdd.addPoints(p1, negP2)
  }

  /**
   * Get constraints for conditional addition
   *
   * Constraint 1: b * (x3 * (y1*y2 + a*x1*x2) - (x1*y1 + x2*y2)) + (1-b) * (x3 - x1) = 0
   * Constraint 2: b * (y3 * (x1*y2 - x2*y1) - (x1*y1 - x2*y2)) + (1-b) * (y3 - y1) = 0
   * Matching Rust: fn constraints(&self) -> Vec<Evaluations<F>>
   */
  constraints(): bigint[][] {
    const Fr = bls12_381.fields.Fr
    const domain4xSize = this.bitmask.col.evals4x.length
    const { a: teA } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS

    // Get evaluations over 4x domain
    const b = this.bitmask.col.evals4x
    const x1 = this.acc.xs.evals4x
    const y1 = this.acc.ys.evals4x
    const x2 = this.points.xs.evals4x
    const y2 = this.points.ys.evals4x
    const x3 = this.acc.xs.shifted4x()
    const y3 = this.acc.ys.shifted4x()
    const notLast = this.notLast.evals4x

    // Create constant evaluations
    const one = Array(domain4xSize).fill(Fr.ONE)
    const teACoeff = Array(domain4xSize).fill(BigInt(teA))

    // Compute constraints
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

      // Constraint 1: b * (x3 * (y1*y2 + a*x1*x2) - (x1*y1 + x2*y2)) + (1-b) * (x3 - x1)
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

      // Constraint 2: b * (y3 * (x1*y2 - x2*y1) - (x1*y1 - x2*y2)) + (1-b) * (y3 - y1)
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

  /**
   * Get linearized constraints at point z
   * Matching Rust: constraints_linearized() returns Vec<DensePolynomial<F>>
   *
   * Computes:
   * - c1_lin = acc_x * c_acc_x + acc_y * c_acc_y (where c_acc_y = 0)
   * - c2_lin = acc_x * c_acc_x + acc_y * c_acc_y (where c_acc_x = 0)
   *
   * Returns: DensePolynomial[] directly (special case - returns polynomials, not coefficients)
   * This is stored in a special property to be handled by PiopProver
   */
  constraintsLinearizedPolynomials(z: bigint): DensePolynomial[] {
    const Fr = bls12_381.fields.Fr

    // Evaluate assignment at z to get CondAddValues
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

    // Get accumulator polynomials
    const accXPoly = this.acc.xs.poly
    const accYPoly = this.acc.ys.poly

    // Compute coefficients for constraint 1
    const [cAccX1] = vals.accCoeffs1()
    // c1_lin = acc_x * c_acc_x + acc_y * c_acc_y (c_acc_y = 0, so just acc_x * c_acc_x)
    const c1LinCoeffs = accXPoly.coeffs.map((coeff) =>
      Fr.mul(Fr.create(coeff), Fr.create(cAccX1)),
    )

    // Compute coefficients for constraint 2
    const [, cAccY2] = vals.accCoeffs2()
    // c2_lin = acc_x * c_acc_x + acc_y * c_acc_y (c_acc_x = 0, so just acc_y * c_acc_y)
    const c2LinCoeffs = accYPoly.coeffs.map((coeff) =>
      Fr.mul(Fr.create(coeff), Fr.create(cAccY2)),
    )

    // Return the two linearized polynomials
    return [
      new DensePolynomialImpl(c1LinCoeffs),
      new DensePolynomialImpl(c2LinCoeffs),
    ]
  }

  /**
   * Get linearized constraints at point z
   * Returns empty array - use constraintsLinearizedPolynomials() instead
   */
  constraintsLinearized(_z: bigint): bigint[] {
    // This method is kept for interface compatibility
    // The actual implementation is in constraintsLinearizedPolynomials()
    // PiopProver will call constraintsLinearizedPolynomials() directly for CondAdd
    return []
  }
}

// Modular arithmetic helpers imported from @pbnjam/bandersnatch

/**
 * CondAdd Values for verifier
 */
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

  /**
   * Get accumulator coefficients for constraint 1
   */
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

    // Compute: b * (y1*y2 + a*x1*x2) + (1 - b)
    const y1y2 = Fr.mul(y1, y2)
    const ax1x2 = Fr.mul(Fr.create(a), Fr.mul(x1, x2))
    const y1y2PlusAx1x2 = Fr.add(y1y2, ax1x2)
    const bTimesY1y2PlusAx1x2 = Fr.mul(b, y1y2PlusAx1x2)
    const oneMinusB = Fr.sub(one, b)
    const inner = Fr.add(bTimesY1y2PlusAx1x2, oneMinusB)

    // Multiply by notLast
    const cAccX = Fr.mul(notLastF, inner)
    const cAccY = Fr.ZERO

    return [cAccX, cAccY]
  }

  /**
   * Get accumulator coefficients for constraint 2
   */
  accCoeffs2(): [bigint, bigint] {
    const Fr = bls12_381.fields.Fr
    const b = Fr.create(this.bitmask)
    const x1 = Fr.create(this.acc[0])
    const y1 = Fr.create(this.acc[1])
    const x2 = Fr.create(this.points[0])
    const y2 = Fr.create(this.points[1])
    const one = Fr.ONE
    const notLastF = Fr.create(this.notLast)

    // Compute: b * (x1*y2 - x2*y1) + (1 - b)
    const x1y2 = Fr.mul(x1, y2)
    const x2y1 = Fr.mul(x2, y1)
    const x1y2MinusX2y1 = Fr.sub(x1y2, x2y1)
    const bTimesX1y2MinusX2y1 = Fr.mul(b, x1y2MinusX2y1)
    const oneMinusB = Fr.sub(one, b)
    const inner = Fr.add(bTimesX1y2MinusX2y1, oneMinusB)

    // Multiply by notLast
    const cAccX = Fr.ZERO
    const cAccY = Fr.mul(notLastF, inner)

    return [cAccX, cAccY]
  }

  /**
   * Evaluate constraints at main point
   */
  evaluateConstraintsMain(): bigint[] {
    const Fr = bls12_381.fields.Fr
    const { a } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
    const b = Fr.create(this.bitmask)
    const [x1, y1] = [Fr.create(this.acc[0]), Fr.create(this.acc[1])]
    const [x2, y2] = [Fr.create(this.points[0]), Fr.create(this.points[1])]
    const [x3, y3] = [Fr.ZERO, Fr.ZERO] // At main point, shifted is zero
    const one = Fr.ONE
    const notLastF = Fr.create(this.notLast)

    // Constraint 1: b * (x3 * (y1*y2 + a*x1*x2) - (x1*y1 + x2*y2)) + (1-b) * (x3 - x1)
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

    // Constraint 2: b * (y3 * (x1*y2 - x2*y1) - (x1*y1 - x2*y2)) + (1-b) * (y3 - y1)
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
