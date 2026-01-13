/**
 * Polynomial types and utilities
 */

import { bls12_381 } from '@noble/curves/bls12-381.js'

const Fr = bls12_381.fields.Fr

export interface DensePolynomial {
  coeffs: bigint[]
  degree: number
  evaluate(x: bigint): bigint
  coeff(i: number): bigint
}

/**
 * Dense polynomial implementation
 */
export class DensePolynomialImpl implements DensePolynomial {
  public readonly coeffs: bigint[]
  public readonly degree: number

  constructor(coeffs: bigint[], expectedMaxDegree?: number) {
    // Truncate trailing zeros (matching Rust: truncate_leading_zeros)
    // Rust: while self.coeffs.last().is_some_and(|c| c.is_zero()) { self.coeffs.pop(); }
    // However, if expectedMaxDegree is provided, we keep zeros up to that degree to match Rust's exact degree requirement
    const truncatedCoeffs = [...coeffs]

    // If expectedMaxDegree is provided, ensure we have at least expectedMaxDegree + 1 coefficients
    // This ensures the degree is exactly expectedMaxDegree even if the last coefficient is zero
    // This matches Rust's behavior where the degree is exactly the expected value
    if (
      expectedMaxDegree !== undefined &&
      truncatedCoeffs.length <= expectedMaxDegree
    ) {
      // Pad with zeros up to expectedMaxDegree + 1
      while (truncatedCoeffs.length < expectedMaxDegree + 1) {
        truncatedCoeffs.push(Fr.ZERO)
      }
    }

    // Remove trailing zeros, but keep at least expectedMaxDegree + 1 coefficients if specified
    const minLength =
      expectedMaxDegree !== undefined ? expectedMaxDegree + 1 : 0
    while (
      truncatedCoeffs.length > minLength &&
      Fr.eql(Fr.create(truncatedCoeffs[truncatedCoeffs.length - 1]!), Fr.ZERO)
    ) {
      truncatedCoeffs.pop()
    }

    this.coeffs = truncatedCoeffs.length > 0 ? truncatedCoeffs : [Fr.ZERO]

    // Find actual degree (highest non-zero coefficient)
    // Matching Rust: polynomial.degree() returns coeffs.len() - 1 after truncation
    // Since we've truncated, degree is just length - 1
    this.degree = this.coeffs.length > 0 ? this.coeffs.length - 1 : -1
  }

  evaluate(x: bigint): bigint {
    const Fr = bls12_381.fields.Fr
    let result = Fr.ZERO
    const xF = Fr.create(x)

    // Horner's method
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
