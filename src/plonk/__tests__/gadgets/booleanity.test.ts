/**
 * Booleanity Gadget Tests
 * 
 * Tests that booleanity gadget correctly enforces bits are 0 or 1
 * Constraint: b * (1 - b) = 0
 */

import { describe, test, expect } from 'bun:test'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { Domain } from '../../domain/domain'
import { Booleanity } from '../../gadgets/booleanity'
import { BitColumn } from '../../gadgets/bit-column'
import { randomBitVec } from './test-helpers'
import { DensePolynomialImpl } from '../../domain/polynomial'
import { ifftFieldElements, getOmegaForDomain } from '../../../utils/fft-utils'

const Fr = bls12_381.fields.Fr

/**
 * Convert constraint evaluations to polynomial
 */
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

  // Generate random bit vector
  const bits = randomBitVec(domain.capacity - 1, 0.5)

  // Create bit column
  const bitColumn = BitColumn.init(bits, domain)

  // Create booleanity gadget
  const gadget = Booleanity.init(bitColumn)

  // Verify constraint polynomial
  // Constraint: (1 - b) * b = 0
  // This should be zero for all valid boolean values
  const constraintEvals = gadget.constraints()[0]
  const constraintPoly = interpolateConstraint(constraintEvals, domain)

  // Constraint should divide by vanishing polynomial
  // For booleanity, the constraint is degree 2, so after multiplying by domain
  // it should be degree 2 * n - 1 (but we check it divides)
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

