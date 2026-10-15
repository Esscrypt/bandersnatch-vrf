import { bls12_381 } from '@noble/curves/bls12-381.js'
import type { BitColumn } from './bit-column.ts'

export class Booleanity {
  public readonly bits: BitColumn

  constructor(bits: BitColumn) {
    this.bits = bits
  }

  static init(bits: BitColumn): Booleanity {
    return new Booleanity(bits)
  }

  constraints(): bigint[][] {
    const Fr = bls12_381.fields.Fr
    const domain4xSize = this.bits.col.evals4x.length

    const b = this.bits.col.evals4x
    const one = Fr.ONE

    const constraint: bigint[] = []
    for (let i = 0; i < domain4xSize; i++) {
      const bF = Fr.create(b[i]!)
      const oneMinusB = Fr.sub(one, bF)
      const result = Fr.mul(oneMinusB, bF)
      constraint.push(result)
    }

    return [constraint]
  }

  constraintsLinearized(_z: bigint): bigint[] {
    return [0n]
  }
}

export class BooleanityValues {
  public readonly bits: bigint

  constructor(bits: bigint) {
    this.bits = bits
  }

  evaluateConstraintsMain(): bigint[] {
    const Fr = bls12_381.fields.Fr
    const bitsF = Fr.create(this.bits)
    const one = Fr.ONE
    const constraint = Fr.mul(bitsF, Fr.sub(one, bitsF))
    return [constraint]
  }
}
