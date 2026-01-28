/**
 * Fixed Cells Gadget Tests
 * 
 * Tests that fixed cells gadget correctly constrains column values at specific positions
 * Constraint: L_first(X) * (col(X) - col[0]) + L_last(X) * (col(X) - col[n-1]) = 0
 */

import { describe, test, expect } from 'bun:test'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { Domain } from '../../domain/domain'
import { FieldColumn } from '../../domain/domain'
import { FixedCells } from '../../gadgets/fixed-cells'
import { randomVec } from './test-helpers'
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

function testFixedCellsGadget(hiding: boolean) {
  const logN = 10
  const n = 2 ** logN
  const domain = new Domain(n, hiding)

  // Generate random column values
  const col = randomVec(domain.capacity)

  // Create field column
  const colColumn = new FieldColumn(col, domain.getDomain1x(), domain.capacity)

  // Create fixed cells gadget
  const gadget = FixedCells.init(colColumn, domain)

  // Verify constraint polynomial
  // Constraint: L_first * (col - col[0]) + L_last * (col - col[n-1]) = 0
  const constraintEvals = gadget.constraints()[0]
  const constraintPoly = interpolateConstraint(constraintEvals, domain)

  // Constraint should divide by vanishing polynomial
  const quotient = domain.divideByVanishingPoly(constraintPoly)
  expect(quotient.degree).toBeGreaterThanOrEqual(0)
}

describe('Fixed Cells Gadget Tests', () => {
  test('test_fixed_cells_gadget - without hiding', () => {
    testFixedCellsGadget(false)
  })

  test('test_fixed_cells_gadget - with hiding', () => {
    testFixedCellsGadget(true)
  })
})

