import { describe, test, expect } from 'bun:test'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { Domain } from '../../domain/domain.ts'
import { Booleanity } from '../../gadgets/booleanity.ts'
import { BitColumn } from '../../gadgets/bit-column.ts'
import { randomBitVec } from './test-helpers.ts'
import { DensePolynomialImpl } from '../../domain/polynomial.ts'
import { ifftFieldElements, getOmegaForDomain } from '../../../utils/fft-utils.ts'

const Fr = bls12_381.fields.Fr

function interpolateConstraint(
  evals: bigint[],
  domain: Domain,
): DensePolynomialImpl {
  const { omegaInv } = getOmegaForDomain(domain.getDomain4x().size, Fr)
  const coeffs = ifftFieldElements(evals, domain.getDomain4x().size, omegaInv, Fr)
  return new DensePolynomialImpl(coeffs)
}

function testBooleanityGadget(hiding: boolean) {
  const logN = 10
  const n = 2 ** logN
  const domain = new Domain(n, hiding)

  const bits = randomBitVec(domain.capacity - 1, 0.5)

  const bitColumn = BitColumn.init(bits, domain)

  const gadget = Booleanity.init(bitColumn)

  const constraintEvals = gadget.constraints()[0]
  const constraintPoly = interpolateConstraint(constraintEvals, domain)

  const quotient = domain.divideByVanishingPoly(constraintPoly)
  expect(quotient.degree).toBeGreaterThanOrEqual(0)
}

describe('Booleanity Gadget Tests', () => {
  test('test_booleanity_gadget - without hiding', () => {
    testBooleanityGadget(false)
  }, {timeout: 60_000})

  test('test_booleanity_gadget - with hiding', () => {
    testBooleanityGadget(true)
  }, {timeout: 60_000})
})

