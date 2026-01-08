/**
 * Booleanity Gadget
 * 
 * Ensures that a column contains only boolean values (0 or 1)
 * Constraint: b * (1 - b) = 0
 */

import { bls12_381 } from '@noble/curves/bls12-381.js'
import type { BitColumn } from './bit-column'

/**
 * Booleanity Gadget
 * 
 * Constrains a bit column to contain only 0 or 1 values
 */
export class Booleanity {
  public readonly bits: BitColumn

  constructor(bits: BitColumn) {
    this.bits = bits
  }

  static init(bits: BitColumn): Booleanity {
    return new Booleanity(bits)
  }

  /**
   * Get constraints for booleanity
   * Constraint: (1 - b) * b = 0
   * Matching Rust: fn constraints(&self) -> Vec<Evaluations<F>>
   */
  constraints(): bigint[][] {
    const Fr = bls12_381.fields.Fr
    const domain4xSize = this.bits.col.evals4x.length
    
    // Get evaluations over 4x domain
    const b = this.bits.col.evals4x
    const one = Fr.ONE
    
    // Compute constraint: (1 - b) * b
    const constraint: bigint[] = []
    for (let i = 0; i < domain4xSize; i++) {
      const bF = Fr.create(b[i]!)
      const oneMinusB = Fr.sub(one, bF)
      const result = Fr.mul(oneMinusB, bF)
      constraint.push(result)
    }
    
    return [constraint]
  }

  /**
   * Get linearized constraints at point z
   * Matching Rust: vec![DensePolynomial::zero()]
   */
  constraintsLinearized(_z: bigint): bigint[] {
    // Returns zero polynomial (constraint is degree 2, linearized is zero)
    // Return [0n] to create a zero polynomial (constant 0)
    return [0n]
  }
}

/**
 * Booleanity Values for verifier
 */
export class BooleanityValues {
  public readonly bits: bigint

  constructor(bits: bigint) {
    this.bits = bits
  }

  /**
   * Evaluate constraints at main point
   * Constraint: bits * (1 - bits) = 0
   */
  evaluateConstraintsMain(): bigint[] {
    const Fr = bls12_381.fields.Fr
    const bitsF = Fr.create(this.bits)
    const one = Fr.ONE
    const constraint = Fr.mul(bitsF, Fr.sub(one, bitsF))
    return [constraint]
  }
}

