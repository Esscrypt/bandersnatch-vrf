import { describe, test, expect } from 'bun:test'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { Domain } from '../../domain/domain.ts'
import { Doubling } from '../../gadgets/doubling.ts'
import { randomPoint } from './test-helpers.ts'
import { DensePolynomialImpl } from '../../domain/polynomial.ts'
import { ifftFieldElements, getOmegaForDomain } from '../../../utils/fft-utils.ts'
import { BANDERSNATCH_PARAMS, mod, modInverse } from '@pbnjam/bandersnatch'

const Fr = bls12_381.fields.Fr

function doublePoint(p: { x: bigint; y: bigint }): { x: bigint; y: bigint } {
  const { a } = BANDERSNATCH_PARAMS.CURVE_COEFFICIENTS
  const p_mod = BANDERSNATCH_PARAMS.FIELD_MODULUS

  const x1_sq = mod(p.x * p.x, p_mod)
  const y1_sq = mod(p.y * p.y, p_mod)
  const x1y1 = mod(p.x * p.y, p_mod)

  const a_x1_sq = mod(a * x1_sq, p_mod)
  const denom1 = mod(a_x1_sq + y1_sq, p_mod)
  const denom2 = mod(2n - a_x1_sq - y1_sq, p_mod)

  const denom1Inv = modInverse(denom1, p_mod)
  const denom2Inv = modInverse(denom2, p_mod)

  const x2 = mod(2n * x1y1 * denom1Inv, p_mod)
  const y2 = mod((y1_sq - a_x1_sq) * denom2Inv, p_mod)

  return { x: x2, y: y2 }
}

function interpolateConstraint(
  evals: bigint[],
  domain: Domain,
): DensePolynomialImpl {
  const domain4xSize = domain.getDomain4x().size
  const n = domain.size
  const expectedMaxDegree = 3 * n - 2
  
  const { omegaInv } = getOmegaForDomain(domain4xSize, Fr)
  const coeffs = ifftFieldElements(evals, domain4xSize, omegaInv, Fr)
  
  const truncatedCoeffs = coeffs.slice(0, expectedMaxDegree + 1)
  
  return new DensePolynomialImpl(truncatedCoeffs, expectedMaxDegree)
}

function testDoublingGadget(hiding: boolean) {
  const logN = 4
  const n = 2 ** logN
  const domain = new Domain(n, hiding)

  const p = randomPoint()

  const gadget = Doubling.init(p, domain)

  const doublings = gadget.doublings.points
  expect(doublings.length).toBe(domain.capacity)
  expect(doublings[0]).toEqual(p)

  let current = p
  for (let i = 1; i < domain.capacity; i++) {
    current = doublePoint(current)
    expect(doublings[i]?.x).toBe(current.x)
    expect(doublings[i]?.y).toBe(current.y)
  }

  const constraints = gadget.constraints()
  expect(constraints.length).toBe(2)

  const c1 = interpolateConstraint(constraints[0]!, domain)
  const c2 = interpolateConstraint(constraints[1]!, domain)

  const expectedDegree = 3 * n - 2
  expect(c1.degree).toBe(expectedDegree)
  expect(c2.degree).toBe(expectedDegree)

  const quotient1 = domain.divideByVanishingPoly(c1)
  const quotient2 = domain.divideByVanishingPoly(c2)
  expect(quotient1.degree).toBeGreaterThanOrEqual(0)
  expect(quotient2.degree).toBeGreaterThanOrEqual(0)
}

describe('Doubling Gadget Tests', () => {
  test('doubling_gadget - without hiding', () => {
    testDoublingGadget(false)
  }, { timeout: 60_000 })

  test('doubling_gadget - with hiding', () => {
    testDoublingGadget(true)
  }, { timeout: 60_000 })
})

