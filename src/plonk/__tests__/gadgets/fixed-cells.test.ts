import { describe, test, expect } from 'bun:test'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { Domain } from '../../domain/domain.ts'
import { FieldColumn } from '../../domain/domain.ts'
import { FixedCells } from '../../gadgets/fixed-cells.ts'
import { randomVec } from './test-helpers.ts'
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

function testFixedCellsGadget(hiding: boolean) {
  const logN = 10
  const n = 2 ** logN
  const domain = new Domain(n, hiding)

  const col = randomVec(domain.capacity)

  const colColumn = new FieldColumn(col, domain.getDomain1x(), domain.capacity)

  const gadget = FixedCells.init(colColumn, domain)

  const constraintEvals = gadget.constraints()[0]
  const constraintPoly = interpolateConstraint(constraintEvals, domain)

  const quotient = domain.divideByVanishingPoly(constraintPoly)
  expect(quotient.degree).toBeGreaterThanOrEqual(0)
}

describe('Fixed Cells Gadget Tests', () => {
  test('test_fixed_cells_gadget - without hiding', () => {
    testFixedCellsGadget(false)
  }, {timeout: 60_000})

  test('test_fixed_cells_gadget - with hiding', () => {
    testFixedCellsGadget(true)
  }, {timeout: 60_000})
})

