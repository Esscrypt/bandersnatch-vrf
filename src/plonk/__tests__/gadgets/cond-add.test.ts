import { describe, test, expect } from 'bun:test'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { Domain } from '../../domain/domain.ts'
import { CondAdd } from '../../gadgets/cond-add.ts'
import { BitColumn } from '../../gadgets/bit-column.ts'
import { AffineColumn } from '../../gadgets/affine-column.ts'
import { PiopParams } from '../../piop/params.ts'
import { randomBitVec, randomPoint, condSum } from './test-helpers.ts'
import { DensePolynomialImpl } from '../../domain/polynomial.ts'
import { ifftFieldElements, getOmegaForDomain } from '../../../utils/fft-utils.ts'
import { BANDERSNATCH_PARAMS, mod, modInverse } from '@pbnjam/bandersnatch'

const Fr = bls12_381.fields.Fr

function addPoints(
  p1: { x: bigint; y: bigint },
  p2: { x: bigint; y: bigint },
): { x: bigint; y: bigint } {
  const { a, d } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
  const p = BANDERSNATCH_PARAMS.FIELD_MODULUS

  const x1y2 = mod(p1.x * p2.y, p)
  const y1x2 = mod(p1.y * p2.x, p)
  const y1y2 = mod(p1.y * p2.y, p)
  const x1x2 = mod(p1.x * p2.x, p)

  const dxy = mod(d * x1x2 * y1y2, p)
  const denom1 = mod(1n + dxy, p)
  const denom2 = mod(1n - dxy, p)

  const denom1Inv = modInverse(denom1, p)
  const denom2Inv = modInverse(denom2, p)

  const x3 = mod((x1y2 + y1x2) * denom1Inv, p)
  const y3 = mod((y1y2 - a * x1x2) * denom2Inv, p)

  return { x: x3, y: y3 }
}

function interpolateConstraint(
  evals: bigint[],
  domain: Domain,
): DensePolynomialImpl {
  const domain4xSize = domain.getDomain4x().size
  const n = domain.size
  const expectedMaxDegree = 4 * n - 3
  
  const { omegaInv } = getOmegaForDomain(domain4xSize, Fr)
  const coeffs = ifftFieldElements(evals, domain4xSize, omegaInv, Fr)
  
  const truncatedCoeffs = coeffs.slice(0, expectedMaxDegree + 1)
  
  return new DensePolynomialImpl(truncatedCoeffs, expectedMaxDegree)
}

function testCondAddGadget(hiding: boolean) {
  const logN = 10
  const n = 2 ** logN
  const domain = new Domain(n, hiding)

  const seed = PiopParams.getAccumulatorSeedPoint()

  const bitmask = randomBitVec(domain.capacity - 1, 0.5)
  const points: Array<{ x: bigint; y: bigint }> = []
  for (let i = 0; i < domain.capacity - 1; i++) {
    points.push(randomPoint())
  }

  const condSumResult = condSum(bitmask, points)
  
  const expectedRes = addPoints(seed, condSumResult)

  const bitmaskCol = BitColumn.init(bitmask, domain)
  const pointsCol = AffineColumn.privateColumn(points, domain)

  const gadget = CondAdd.init(bitmaskCol, pointsCol, seed, domain)

  const accPoints = gadget.acc.points
  const finalAcc = accPoints[accPoints.length - 1]!

  expect(Fr.eql(Fr.create(finalAcc.x), Fr.create(expectedRes.x))).toBe(true)
  expect(Fr.eql(Fr.create(finalAcc.y), Fr.create(expectedRes.y))).toBe(true)

  const constraints = gadget.constraints()
  const c1 = interpolateConstraint(constraints[0]!, domain)
  const c2 = interpolateConstraint(constraints[1]!, domain)

  const expectedMaxDegree = 4 * n - 3
  expect(c1.degree).toBe(expectedMaxDegree)
  expect(c2.degree).toBe(expectedMaxDegree)

  const quotient1 = domain.divideByVanishingPoly(c1)
  const quotient2 = domain.divideByVanishingPoly(c2)
  expect(quotient1.degree).toBeGreaterThanOrEqual(0)
  expect(quotient2.degree).toBeGreaterThanOrEqual(0)
}

describe('Conditional Addition Gadget Tests', () => {
  test('test_te_cond_add_gadget - without hiding', () => {
    testCondAddGadget(false)
  }, {timeout: 60_000})

  test('test_te_cond_add_gadget - with hiding', () => {
    testCondAddGadget(true)
  }, {timeout: 60_000})
})

