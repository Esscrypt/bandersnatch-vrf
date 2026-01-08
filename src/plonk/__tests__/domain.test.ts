/**
 * Domain Tests
 * 
 * Based on w3f-plonk-common/src/domain.rs test_evaluated_domain()
 * 
 * Tests domain evaluation correctness
 */

import { describe, test, expect } from 'bun:test'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { Domain } from '../domain/domain'

describe('Domain Tests', () => {
  function testEvaluatedDomain(hiding: boolean) {
    const n = 1024
    const domain = new Domain(n, hiding)

    // Generate random evaluation point
    const Fr = bls12_381.fields.Fr
    const randomBytes = new Uint8Array(32)
    crypto.getRandomValues(randomBytes)
    const randomBigInt = BigInt(
      '0x' + Array.from(randomBytes).map((b) => b.toString(16).padStart(2, '0')).join(''),
    )
    const z = Fr.create(randomBigInt)

    // Evaluate domain at z
    const domainEval = domain.evaluate(z)

    // Verify l_first polynomial evaluation matches
    const lFirstEval = domain.lFirst.evaluate(z)
    expect(Fr.eql(Fr.create(lFirstEval), Fr.create(domainEval.lFirst))).toBe(true)

    // Verify l_last polynomial evaluation matches
    // Matching Rust: assert_eq!(domain.l_last.poly.evaluate(&z), domain_eval.l_last);
    const lLastEval = domain.lLast.evaluate(z)
    expect(Fr.eql(Fr.create(lLastEval), Fr.create(domainEval.lLast))).toBe(true)

    // Verify not_last_row polynomial evaluation matches
    const notLastRowEval = domain.notLastRow.evaluate(z)
    expect(Fr.eql(Fr.create(notLastRowEval), Fr.create(domainEval.notLastRow))).toBe(true)
  }

  test('test_evaluated_domain - without hiding', () => {
    testEvaluatedDomain(false)
  })

  test('test_evaluated_domain - with hiding', () => {
    testEvaluatedDomain(true)
  })
})

