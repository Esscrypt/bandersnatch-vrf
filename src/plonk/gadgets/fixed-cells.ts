/**
 * Fixed Cells Gadget
 * 
 * Constrains specific cells in a column to have fixed values
 * Uses Lagrange basis polynomials to enforce: col[i] = value
 */

import { bls12_381 } from '@noble/curves/bls12-381.js'
import type { Domain, FieldColumn } from '../domain/domain'

/**
 * Fixed Cells Gadget
 * 
 * Constrains column to have specific values at first and last positions
 */
export class FixedCells {
  public readonly col: FieldColumn
  public readonly lFirst: FieldColumn
  public readonly lLast: FieldColumn

  /**
   * Initialize FixedCells gadget
   * 
   * @param col - Column to constrain
   * @param domain - Plonk domain
   */
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

  /**
   * Get constraints for fixed cells
   * Constraint: L_first(X) * (col(X) - col[0]) + L_last(X) * (col(X) - col[n-1]) = 0
   * Matching Rust: fn constraints(&self) -> Vec<Evaluations<F>>
   */
  constraints(): bigint[][] {
    const Fr = bls12_381.fields.Fr
    const domain4xSize = this.col.evals4x.length
    
    // Get cell values
    const colFirst = this.col.evals[0]!
    const colLast = this.col.evals[this.col.len - 1]!
    
    // Get evaluations over 4x domain
    const col = this.col.evals4x
    const lFirst = this.lFirst.evals4x
    const lLast = this.lLast.evals4x
    
    // Create constant evaluations for cell values
    const colFirstConst = Array(domain4xSize).fill(colFirst)
    const colLastConst = Array(domain4xSize).fill(colLast)
    
    // Compute constraint: L_first * (col - col[0]) + L_last * (col - col[n-1])
    const constraint: bigint[] = []
    for (let i = 0; i < domain4xSize; i++) {
      const colF = Fr.create(col[i]!)
      const lFirstF = Fr.create(lFirst[i]!)
      const lLastF = Fr.create(lLast[i]!)
      const colFirstF = Fr.create(colFirstConst[i]!)
      const colLastF = Fr.create(colLastConst[i]!)
      
      // L_first * (col - col[0])
      const c1 = Fr.mul(lFirstF, Fr.sub(colF, colFirstF))
      
      // L_last * (col - col[n-1])
      const c2 = Fr.mul(lLastF, Fr.sub(colF, colLastF))
      
      // Sum
      const result = Fr.add(c1, c2)
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
 * Fixed Cells Values for verifier
 */
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

  /**
   * Evaluate constraint for a specific cell
   */
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

  /**
   * Evaluate constraints at main point
   * Constraint: L_first(X) * (col(X) - col[0]) + L_last(X) * (col(X) - col[n-1]) = 0
   */
  evaluateConstraintsMain(): bigint[] {
    const c1 = FixedCellsValues.evaluateForCell(
      this.col,
      this.lFirst,
      this.colFirst,
    )
    const c2 = FixedCellsValues.evaluateForCell(this.col, this.lLast, this.colLast)
    const Fr = bls12_381.fields.Fr
    return [Fr.add(c1, c2)]
  }
}

