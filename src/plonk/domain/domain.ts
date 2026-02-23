/**
 * Plonk Domain Implementation
 *
 * Implements evaluation domains for Plonk proofs, including FFT support
 * and domain-specific polynomials (Lagrange basis, vanishing polynomials, etc.)
 */

import { bls12_381 } from '@noble/curves/bls12-381.js'
import { ifftFieldElements } from '../../utils/fft-utils'
import type { DensePolynomial } from './polynomial'
import { DensePolynomialImpl } from './polynomial'

export const ZK_ROWS = 3 // Zero-knowledge rows for hiding

/**
 * Plonk evaluation domain
 *
 * Provides FFT domains and domain-specific polynomials for Plonk proofs
 */
export class Domain {
  public readonly hiding: boolean
  public readonly capacity: number
  public readonly size: number
  private readonly domain1x: FFTDomain
  private readonly domain4x: FFTDomain
  public readonly notLastRow: FieldColumn
  public readonly lFirst: FieldColumn
  public readonly lLast: FieldColumn

  constructor(n: number, hiding: boolean) {
    this.hiding = hiding
    this.size = n
    this.capacity = hiding ? n - ZK_ROWS : n

    // Create 1x and 4x domains for FFT operations
    this.domain1x = new FFTDomain(n)
    this.domain4x = new FFTDomain(4 * n)

    // Compute domain-specific polynomials
    this.notLastRow = this.computeNotLastRow()
    this.lFirst = this.computeLagrangeBasis(0)
    this.lLast = this.computeLagrangeBasis(this.capacity - 1)
  }

  /**
   * Compute polynomial X - w^(n-1) that vanishes on the last row
   */
  private computeNotLastRow(): FieldColumn {
    const lastRowIndex = this.capacity - 1
    const omega = this.domain1x.omega
    const lastRowValue = this.domain1x.pow(omega, lastRowIndex)

    // Polynomial: X - w^(n-1)
    // Evaluations: [w^0 - w^(n-1), w^1 - w^(n-1), ..., w^(n-1) - w^(n-1)]
    const evals: bigint[] = []
    for (let i = 0; i < this.size; i++) {
      const x = this.domain1x.pow(omega, i)
      const evalValue = this.domain1x.sub(x, lastRowValue)
      evals.push(evalValue)
    }

    return new FieldColumn(evals, this.domain1x, this.capacity)
  }

  /**
   * Compute Lagrange basis polynomial L_i(X) that is 1 at w^i and 0 elsewhere
   */
  private computeLagrangeBasis(i: number): FieldColumn {
    const evals: bigint[] = []

    for (let j = 0; j < this.size; j++) {
      const evalValue = j === i ? 1n : 0n
      evals.push(evalValue)
    }

    return new FieldColumn(evals, this.domain1x, this.capacity)
  }

  /**
   * Get 4x domain for constraint evaluation
   */
  getDomain4x(): FFTDomain {
    return this.domain4x
  }

  /**
   * Get 1x domain for witness evaluation
   */
  getDomain1x(): FFTDomain {
    return this.domain1x
  }

  /**
   * Get primitive root of unity (omega)
   */
  omega(): bigint {
    return this.domain1x.omega
  }

  /**
   * Divide polynomial by vanishing polynomial
   *
   * The vanishing polynomial is Z_H(X) = X^n - 1 for domain H of size n
   * This computes the quotient: q(X) = p(X) / Z_H(X)
   *
   * @param poly - Polynomial to divide
   * @returns Quotient polynomial
   */
  divideByVanishingPoly(poly: DensePolynomial): DensePolynomial {
    const Fr = bls12_381.fields.Fr
    const n = this.size

    let dividend = poly
    if (this.hiding) {
      dividend = this.multiplyByZkRowsVanishingPoly(poly)
    }

    if (dividend.degree < n) {
      return new DensePolynomialImpl([Fr.ZERO])
    }

    const temp = dividend.coeffs.map((c) => Fr.create(c))
    const quotientDeg = dividend.degree - n
    const quotientCoeffs: bigint[] = new Array(quotientDeg + 1)

    for (let i = dividend.degree; i >= n; i--) {
      const q = temp[i]!
      quotientCoeffs[i - n] = q
      temp[i - n] = Fr.add(Fr.create(temp[i - n]!), Fr.create(q))
    }

    return new DensePolynomialImpl(quotientCoeffs)
  }

  /**
   * Multiply polynomial by (X - w^{n-k})(X - w^{n-k+1})...(X - w^{n-1})
   * This zeros out the last ZK_ROWS so the product is divisible by X^n - 1.
   */
  private multiplyByZkRowsVanishingPoly(
    poly: DensePolynomial,
  ): DensePolynomial {
    const Fr = bls12_381.fields.Fr
    const omega = this.domain1x.omega
    const n = this.size

    let result = poly
    for (let i = 0; i < ZK_ROWS; i++) {
      const rowIdx = n - ZK_ROWS + i
      const root = Fr.pow(Fr.create(omega), BigInt(rowIdx))
      result = this.multiplyByLinearFactor(result, root)
    }
    return result
  }

  /**
   * Multiply polynomial by (X - root)
   */
  private multiplyByLinearFactor(
    poly: DensePolynomial,
    root: bigint,
  ): DensePolynomial {
    const Fr = bls12_381.fields.Fr
    const oldCoeffs = poly.coeffs
    const newCoeffs: bigint[] = new Array(oldCoeffs.length + 1)

    newCoeffs[0] = Fr.neg(Fr.mul(Fr.create(root), Fr.create(oldCoeffs[0]!)))
    for (let i = 1; i < oldCoeffs.length; i++) {
      newCoeffs[i] = Fr.sub(
        Fr.create(oldCoeffs[i - 1]!),
        Fr.mul(Fr.create(root), Fr.create(oldCoeffs[i]!)),
      )
    }
    newCoeffs[oldCoeffs.length] = Fr.create(oldCoeffs[oldCoeffs.length - 1]!)

    return new DensePolynomialImpl(newCoeffs)
  }

  /**
   * Evaluate domain at point zeta
   *
   * Returns evaluated domain values for verifier
   * Matches w3f-plonk-common/src/domain.rs EvaluatedDomain::new()
   */
  evaluate(zeta: bigint): EvaluatedDomain {
    const Fr = bls12_381.fields.Fr
    const zetaF = Fr.create(zeta)
    const k = this.hiding ? ZK_ROWS : 0

    // Compute z^n by squaring log2(size) times
    let zN = zetaF
    const logSize = Math.log2(this.size)
    for (let i = 0; i < logSize; i++) {
      zN = Fr.sqr(zN)
    }

    // z^n - 1 (vanishing polynomial of full domain)
    const zNMinusOne = Fr.sub(zN, Fr.ONE)

    // Compute w^{n-1} (group generator inverse)
    const omega = this.domain1x.omega
    const omegaInv = this.domain1x.omegaInv
    let wi = omegaInv // w^{n-1}

    // Vanishing polynomial of zk rows: prod = (z - w^{n-1})...(z - w^{n-k})
    let prod = Fr.ONE
    for (let i = 0; i < k; i++) {
      const factor = Fr.sub(zetaF, wi)
      prod = Fr.mul(prod, factor)
      wi = Fr.mul(wi, omegaInv) // Move to next zk row
    }

    // not_last_row = z - w^{n-(k+1)}
    const notLastRow = Fr.sub(zetaF, wi)

    // w^{k+1} - matching Rust exactly
    const wj = Fr.pow(omega, BigInt(k + 1))

    // Batch inversion: [z_n_minus_one, z - 1, wj * z - 1]
    const zMinusOne = Fr.sub(zetaF, Fr.ONE)
    const wjZMinusOne = Fr.sub(Fr.mul(wj, zetaF), Fr.ONE)

    const inv0 = Fr.inv(zNMinusOne)
    const inv1 = Fr.inv(zMinusOne)
    const inv2 = Fr.inv(wjZMinusOne)

    // vanishing_polynomial_inv = prod * inv[0]
    const vanishingPolynomialInv = Fr.mul(prod, inv0)

    // l_first = (z^n - 1) / n * inv[1]
    // l_last = (z^n - 1) / n * inv[2]
    // Matching Rust exactly: l_last = z_n_minus_one_div_n * inv[2]
    // where inv[2] = 1/(wj * z - 1) and wj = w^{k+1}
    const sizeInv = Fr.inv(Fr.create(BigInt(this.size)))
    const zNMinusOneDivN = Fr.mul(zNMinusOne, sizeInv)

    // l_first = (z^n - 1) / n * inv[1] = (z^n - 1) / (n * (z - 1))
    // This correctly evaluates L_0(z)
    const lFirst = Fr.mul(zNMinusOneDivN, inv1)

    // l_last = (z^n - 1) / n * inv[2] = (z^n - 1) / (n * (wj * z - 1))
    // where wj = w^{k+1}
    // Matching Rust exactly - this is the formula Rust uses
    const lLast = Fr.mul(zNMinusOneDivN, inv2)

    return {
      notLastRow,
      lFirst,
      lLast,
      omega,
      vanishingPolynomialInv,
    }
  }
}

/**
 * Evaluated domain for verifier
 */
export interface EvaluatedDomain {
  notLastRow: bigint
  lFirst: bigint
  lLast: bigint
  omega: bigint
  vanishingPolynomialInv: bigint
}

/**
 * Multiplicative generator of BLS12-381 Fr* used to derive roots of unity.
 * 7 is the standard generator (matches arkworks).
 */
const BLS12_381_FR_MULTIPLICATIVE_GENERATOR = 7n

/**
 * FFT Domain for field operations
 */
export class FFTDomain {
  public readonly size: number
  public readonly omega: bigint
  public readonly omegaInv: bigint
  private readonly Fr: typeof bls12_381.fields.Fr

  constructor(size: number) {
    this.size = size
    this.Fr = bls12_381.fields.Fr

    const logN = Math.log2(size)
    if (logN % 1 !== 0) {
      throw new Error(`Domain size must be power of 2, got ${size}`)
    }

    // Compute primitive size-th root of unity: g^((r-1)/size) where g=7
    const exponent = (this.Fr.ORDER - 1n) / BigInt(size)
    this.omega = this.Fr.pow(BLS12_381_FR_MULTIPLICATIVE_GENERATOR, exponent)
    this.omegaInv = this.Fr.inv(this.omega)
  }

  pow(base: bigint, exp: number): bigint {
    return this.Fr.pow(base, BigInt(exp))
  }

  add(a: bigint, b: bigint): bigint {
    return this.Fr.add(a, b)
  }

  sub(a: bigint, b: bigint): bigint {
    return this.Fr.sub(a, b)
  }

  mul(a: bigint, b: bigint): bigint {
    return this.Fr.mul(a, b)
  }
}

/**
 * Field column representing a polynomial in evaluation form
 */
export class FieldColumn {
  public readonly evals: bigint[]
  public readonly evals4x: bigint[]
  public readonly poly: DensePolynomial
  public readonly len: number
  private readonly domain: FFTDomain

  constructor(evals: bigint[], domain: FFTDomain, len: number) {
    this.domain = domain
    this.len = len

    // Pad evals to domain size (matching Rust: evals.resize(domain.size(), F::zero()))
    const paddedEvals = [...evals]
    while (paddedEvals.length < domain.size) {
      paddedEvals.push(0n)
    }
    this.evals = paddedEvals

    // Interpolate to get polynomial
    this.poly = this.interpolate(this.evals)

    // Evaluate on 4x domain
    this.evals4x = this.evaluateOverDomain4x(this.poly)
  }

  /**
   * Interpolate evaluations to get polynomial coefficients
   */
  private interpolate(evals: bigint[]): DensePolynomial {
    // Use IFFT to convert from evaluation form to coefficient form
    const Fr = bls12_381.fields.Fr

    // Apply IFFT
    const coeffs = this.ifft(evals.map((e) => Fr.create(e)))

    return new DensePolynomialImpl(coeffs)
  }

  /**
   * IFFT on field elements
   *
   * Uses shared IFFT utility for consistency and maintainability.
   */
  private ifft(values: bigint[]): bigint[] {
    const Fr = bls12_381.fields.Fr

    // Use shared IFFT implementation
    return ifftFieldElements(values, this.domain.size, this.domain.omegaInv, Fr)
  }

  /**
   * Evaluate polynomial over 4x domain
   */
  private evaluateOverDomain4x(poly: DensePolynomial): bigint[] {
    const domain4x = new FFTDomain(4 * this.domain.size)
    const evals: bigint[] = []

    for (let i = 0; i < 4 * this.domain.size; i++) {
      const x = domain4x.pow(domain4x.omega, i)
      const evalValue = poly.evaluate(x)
      evals.push(evalValue)
    }

    return evals
  }

  /**
   * Get shifted evaluations (for next row)
   * Matching Rust: shifted_4x() which rotates left by 4 positions
   */
  shifted4x(): bigint[] {
    const shifted = [...this.evals4x]
    // Rotate left by 4 positions
    const first4 = shifted.slice(0, 4)
    const rest = shifted.slice(4)
    return [...rest, ...first4]
  }

  /**
   * Evaluate at point z
   */
  evaluate(z: bigint): bigint {
    return this.poly.evaluate(z)
  }
}

// DensePolynomial is defined in polynomial.ts
