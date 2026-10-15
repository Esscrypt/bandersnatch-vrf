import { bls12_381 } from '@noble/curves/bls12-381.js'

const Fr = bls12_381.fields.Fr

export interface DensePolynomial {
  coeffs: bigint[]
  degree: number
  evaluate(x: bigint): bigint
  coeff(i: number): bigint
}

export class DensePolynomialImpl implements DensePolynomial {
  public readonly coeffs: bigint[]
  public readonly degree: number

  constructor(coeffs: bigint[], expectedMaxDegree?: number) {
    const truncatedCoeffs = [...coeffs]

    if (
      expectedMaxDegree !== undefined &&
      truncatedCoeffs.length <= expectedMaxDegree
    ) {
      while (truncatedCoeffs.length < expectedMaxDegree + 1) {
        truncatedCoeffs.push(Fr.ZERO)
      }
    }

    const minLength =
      expectedMaxDegree !== undefined ? expectedMaxDegree + 1 : 0
    while (
      truncatedCoeffs.length > minLength &&
      Fr.eql(Fr.create(truncatedCoeffs[truncatedCoeffs.length - 1]!), Fr.ZERO)
    ) {
      truncatedCoeffs.pop()
    }

    this.coeffs = truncatedCoeffs.length > 0 ? truncatedCoeffs : [Fr.ZERO]

    this.degree = this.coeffs.length > 0 ? this.coeffs.length - 1 : -1
  }

  evaluate(x: bigint): bigint {
    const Fr = bls12_381.fields.Fr
    let result = Fr.ZERO
    const xF = Fr.create(x)

    for (let i = this.coeffs.length - 1; i >= 0; i--) {
      result = Fr.mul(result, xF)
      result = Fr.add(result, Fr.create(this.coeffs[i]!))
    }

    return result
  }

  coeff(i: number): bigint {
    return this.coeffs[i] ?? 0n
  }
}
