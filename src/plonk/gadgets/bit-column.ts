/**
 * Bit Column for Plonk
 *
 * Represents a column of boolean values (bits) in evaluation form
 */

import type { Domain } from '../domain/domain'
import { FieldColumn } from '../domain/domain'

/**
 * Bit column representing boolean values
 */
export class BitColumn {
  public readonly bits: boolean[]
  public readonly col: FieldColumn

  private constructor(bits: boolean[], col: FieldColumn) {
    this.bits = bits
    this.col = col
  }

  /**
   * Initialize bit column from boolean array
   */
  static init(bits: boolean[], domain: Domain): BitColumn {
    // Convert bits to field elements (0 or 1)
    const evals = bits.map((b) => (b ? 1n : 0n))

    // Pad to domain size if needed
    while (evals.length < domain.size) {
      evals.push(0n)
    }

    // len should be the actual length of bits (before padding), matching Rust:
    // Rust: let len = evals.len(); in domain.column()
    const col = new FieldColumn(evals, domain.getDomain1x(), bits.length)

    return new BitColumn(bits, col)
  }

  /**
   * Evaluate at point z
   */
  evaluate(z: bigint): bigint {
    return this.col.evaluate(z)
  }
}
