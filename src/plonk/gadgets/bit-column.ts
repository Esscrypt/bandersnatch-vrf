import type { Domain } from '../domain/domain.ts'
import { FieldColumn } from '../domain/domain.ts'

export class BitColumn {
  public readonly bits: boolean[]
  public readonly col: FieldColumn

  private constructor(bits: boolean[], col: FieldColumn) {
    this.bits = bits
    this.col = col
  }

  static init(bits: boolean[], domain: Domain): BitColumn {
    const evals = bits.map((b) => (b ? 1n : 0n))

    while (evals.length < domain.size) {
      evals.push(0n)
    }

    const col = new FieldColumn(evals, domain.getDomain1x(), bits.length)

    return new BitColumn(bits, col)
  }

  evaluate(z: bigint): bigint {
    return this.col.evaluate(z)
  }
}
