import { bls12_381 } from '@noble/curves/bls12-381.js'
import { ifftFieldElements } from '../../utils/fft-utils.ts'
import type { DensePolynomial } from './polynomial.ts'
import { DensePolynomialImpl } from './polynomial.ts'

export const ZK_ROWS = 3

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

    this.domain1x = new FFTDomain(n)
    this.domain4x = new FFTDomain(4 * n)

    this.notLastRow = this.computeNotLastRow()
    this.lFirst = this.computeLagrangeBasis(0)
    this.lLast = this.computeLagrangeBasis(this.capacity - 1)
  }

  private computeNotLastRow(): FieldColumn {
    const lastRowIndex = this.capacity - 1
    const omega = this.domain1x.omega
    const lastRowValue = this.domain1x.pow(omega, lastRowIndex)

    const evals: bigint[] = []
    for (let i = 0; i < this.size; i++) {
      const x = this.domain1x.pow(omega, i)
      const evalValue = this.domain1x.sub(x, lastRowValue)
      evals.push(evalValue)
    }

    return new FieldColumn(evals, this.domain1x, this.capacity)
  }

  private computeLagrangeBasis(i: number): FieldColumn {
    const evals: bigint[] = []

    for (let j = 0; j < this.size; j++) {
      const evalValue = j === i ? 1n : 0n
      evals.push(evalValue)
    }

    return new FieldColumn(evals, this.domain1x, this.capacity)
  }

  getDomain4x(): FFTDomain {
    return this.domain4x
  }

  getDomain1x(): FFTDomain {
    return this.domain1x
  }

  omega(): bigint {
    return this.domain1x.omega
  }

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

  evaluate(zeta: bigint): EvaluatedDomain {
    const Fr = bls12_381.fields.Fr
    const zetaF = Fr.create(zeta)
    const k = this.hiding ? ZK_ROWS : 0

    let zN = zetaF
    const logSize = Math.log2(this.size)
    for (let i = 0; i < logSize; i++) {
      zN = Fr.sqr(zN)
    }

    const zNMinusOne = Fr.sub(zN, Fr.ONE)

    const omega = this.domain1x.omega
    const omegaInv = this.domain1x.omegaInv
    let wi = omegaInv

    let prod = Fr.ONE
    for (let i = 0; i < k; i++) {
      const factor = Fr.sub(zetaF, wi)
      prod = Fr.mul(prod, factor)
      wi = Fr.mul(wi, omegaInv)
    }

    const notLastRow = Fr.sub(zetaF, wi)

    const wj = Fr.pow(omega, BigInt(k + 1))

    const zMinusOne = Fr.sub(zetaF, Fr.ONE)
    const wjZMinusOne = Fr.sub(Fr.mul(wj, zetaF), Fr.ONE)

    const inv0 = Fr.inv(zNMinusOne)
    const inv1 = Fr.inv(zMinusOne)
    const inv2 = Fr.inv(wjZMinusOne)

    const vanishingPolynomialInv = Fr.mul(prod, inv0)

    const sizeInv = Fr.inv(Fr.create(BigInt(this.size)))
    const zNMinusOneDivN = Fr.mul(zNMinusOne, sizeInv)

    const lFirst = Fr.mul(zNMinusOneDivN, inv1)

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

export interface EvaluatedDomain {
  notLastRow: bigint
  lFirst: bigint
  lLast: bigint
  omega: bigint
  vanishingPolynomialInv: bigint
}

const BLS12_381_FR_MULTIPLICATIVE_GENERATOR = 7n

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

export class FieldColumn {
  public readonly evals: bigint[]
  public readonly evals4x: bigint[]
  public readonly poly: DensePolynomial
  public readonly len: number
  private readonly domain: FFTDomain

  constructor(evals: bigint[], domain: FFTDomain, len: number) {
    this.domain = domain
    this.len = len

    const paddedEvals = [...evals]
    while (paddedEvals.length < domain.size) {
      paddedEvals.push(0n)
    }
    this.evals = paddedEvals

    this.poly = this.interpolate(this.evals)

    this.evals4x = this.evaluateOverDomain4x(this.poly)
  }

  private interpolate(evals: bigint[]): DensePolynomial {
    const Fr = bls12_381.fields.Fr

    const coeffs = this.ifft(evals.map((e) => Fr.create(e)))

    return new DensePolynomialImpl(coeffs)
  }

  private ifft(values: bigint[]): bigint[] {
    const Fr = bls12_381.fields.Fr

    return ifftFieldElements(values, this.domain.size, this.domain.omegaInv, Fr)
  }

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

  shifted4x(): bigint[] {
    const shifted = [...this.evals4x]
    const first4 = shifted.slice(0, 4)
    const rest = shifted.slice(4)
    return [...rest, ...first4]
  }

  evaluate(z: bigint): bigint {
    return this.poly.evaluate(z)
  }
}
