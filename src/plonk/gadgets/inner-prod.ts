/**
 * Inner Product Gadget
 *
 * Computes the inner product of two columns: acc[i] = sum(a[j] * b[j] for j <= i)
 */

import { bls12_381 } from '@noble/curves/bls12-381.js'
import type { Domain } from '../domain/domain'
import { FieldColumn } from '../domain/domain'
import type { DensePolynomial } from '../domain/polynomial'
import { DensePolynomialImpl } from '../domain/polynomial'

/**
 * Inner Product Gadget
 *
 * Computes cumulative inner product: acc[i] = sum(a[0..i] * b[0..i])
 */
export class InnerProd {
  public readonly acc: FieldColumn
  private readonly a: FieldColumn
  private readonly b: FieldColumn
  private readonly notLast: FieldColumn
  private readonly domain: Domain

  /**
   * Initialize InnerProd gadget
   *
   * @param a - First column
   * @param b - Second column
   * @param domain - Plonk domain
   */
  static init(a: FieldColumn, b: FieldColumn, domain: Domain): InnerProd {
    if (a.len !== domain.capacity - 1) {
      throw new Error(
        `Column a length ${a.len} must equal domain capacity - 1 (${domain.capacity - 1})`,
      )
    }
    if (b.len !== domain.capacity - 1) {
      throw new Error(
        `Column b length ${b.len} must equal domain capacity - 1 (${domain.capacity - 1})`,
      )
    }

    // Compute partial inner products: [a[0]b[0], a[0]b[0]+a[1]b[1], ...]
    const innerProds = InnerProd.partialInnerProds(a.evals, b.evals)

    // Accumulator: [0, a[0]b[0], a[0]b[0]+a[1]b[1], ...]
    // Matching Rust: let mut acc = vec![F::zero()]; acc.extend(inner_prods);
    // Then: domain.private_column(acc) which pads to domain.size
    const accEvals = [0n, ...innerProds]
    // FieldColumn constructor will pad to domain.size automatically
    const acc = new FieldColumn(accEvals, domain.getDomain1x(), domain.capacity)

    return new InnerProd(a, b, domain.notLastRow, domain, acc)
  }

  private constructor(
    a: FieldColumn,
    b: FieldColumn,
    notLast: FieldColumn,
    domain: Domain,
    acc: FieldColumn,
  ) {
    this.a = a
    this.b = b
    this.notLast = notLast
    this.domain = domain
    this.acc = acc
  }

  /**
   * Compute partial inner products
   * Returns: [a[0]b[0], a[0]b[0] + a[1]b[1], ..., sum(a[i]b[i] for i < n)]
   */
  private static partialInnerProds(a: bigint[], b: bigint[]): bigint[] {
    if (a.length !== b.length) {
      throw new Error(`Column lengths must match: ${a.length} vs ${b.length}`)
    }

    const Fr = bls12_381.fields.Fr
    const results: bigint[] = []
    let state = Fr.ZERO

    for (let i = 0; i < a.length; i++) {
      const product = Fr.mul(Fr.create(a[i]!), Fr.create(b[i]!))
      state = Fr.add(state, product)
      results.push(state)
    }

    return results
  }

  /**
   * Get constraints for inner product
   * Constraint: (acc_shifted - acc) - (a * b)) * not_last = 0
   * Matching Rust: fn constraints(&self) -> Vec<Evaluations<F>>
   */
  constraints(): bigint[][] {
    const Fr = bls12_381.fields.Fr
    const domain4xSize = this.domain.getDomain4x().size

    // Get evaluations over 4x domain
    const a = this.a.evals4x
    const b = this.b.evals4x
    const acc = this.acc.evals4x
    const accShifted = this.acc.shifted4x()
    const notLast = this.notLast.evals4x

    // Compute constraint: (acc_shifted - acc) - (a * b)) * not_last
    const constraint: bigint[] = []
    for (let i = 0; i < domain4xSize; i++) {
      const accShiftedF = Fr.create(accShifted[i]!)
      const accF = Fr.create(acc[i]!)
      const aF = Fr.create(a[i]!)
      const bF = Fr.create(b[i]!)
      const notLastF = Fr.create(notLast[i]!)

      // (acc_shifted - acc) - (a * b)
      const diff = Fr.sub(accShiftedF, accF)
      const product = Fr.mul(aF, bF)
      const constraintValue = Fr.sub(diff, product)

      // Multiply by not_last
      const result = Fr.mul(constraintValue, notLastF)
      constraint.push(result)
    }

    return [constraint]
  }

  /**
   * Get linearized constraints at point z
   * Returns acc(X) * notLast(z) as a polynomial
   */
  constraintsLinearizedPolynomials(z: bigint): DensePolynomial[] {
    const Fr = bls12_381.fields.Fr
    const notLastEval = Fr.create(this.notLast.evaluate(z))
    const accPoly = this.acc.poly
    const scaledCoeffs = accPoly.coeffs.map((c) =>
      Fr.mul(Fr.create(c), notLastEval),
    )
    return [new DensePolynomialImpl(scaledCoeffs)]
  }
}

/**
 * Inner Product Values for verifier
 */
export class InnerProdValues {
  public readonly a: bigint
  public readonly b: bigint
  public readonly notLast: bigint
  public readonly acc: bigint

  constructor(a: bigint, b: bigint, notLast: bigint, acc: bigint) {
    this.a = a
    this.b = b
    this.notLast = notLast
    this.acc = acc
  }

  /**
   * Evaluate constraints at main point
   * Constraint: (-acc - a*b) * notLast = 0
   */
  evaluateConstraintsMain(): bigint[] {
    const Fr = bls12_381.fields.Fr
    const aF = Fr.create(this.a)
    const bF = Fr.create(this.b)
    const accF = Fr.create(this.acc)
    const notLastF = Fr.create(this.notLast)

    const product = Fr.mul(aF, bF)
    const negAcc = Fr.sub(Fr.ZERO, accF)
    const constraint = Fr.sub(negAcc, product)
    const result = Fr.mul(constraint, notLastF)

    return [result]
  }
}
