# Gadget Test Comparison: Rust vs TypeScript

## Overview

This document compares how gadgets are tested in the Rust reference implementation (`w3f-plonk-common`) versus our TypeScript implementation.

## Rust Test Pattern

All Rust gadget tests follow a consistent pattern:

1. **Setup**: Create domain, generate random test data
2. **Gadget Initialization**: Create gadget with test data
3. **Accumulator Verification**: 
   - Check accumulator starts at zero: `assert!(acc[0].is_zero())`
   - Check accumulator final value matches expected: `assert_eq!(acc[domain.capacity - 1], expected)`
4. **Constraint Polynomial Verification**:
   - Get constraint polynomial: `gadget.constraints()[0].interpolate_by_ref()`
   - Check degree: `assert_eq!(constraint_poly.degree(), expected_degree)`
   - Verify divides by vanishing polynomial: `domain.divide_by_vanishing_poly(&constraint_poly)`
5. **Test Both Modes**: Run tests with `hiding: false` and `hiding: true`

## Rust Test Coverage

### ✅ `inner_prod.rs`
- **Test**: `test_inner_prod_gadget()`
- **Checks**:
  - Accumulator starts at zero
  - Final accumulator equals inner product
  - Constraint polynomial degree = `2 * n - 1`
  - Constraint divides by vanishing polynomial

### ✅ `column_sum.rs`
- **Test**: `column_sum_gadget()`
- **Checks**:
  - Accumulator starts at zero
  - Final accumulator equals sum
  - Constraint polynomial degree = `n`
  - Constraint divides by vanishing polynomial

### ✅ `te_cond_add.rs` (Twisted Edwards Conditional Add)
- **Test**: `test_te_cond_add_gadget()`
- **Checks**:
  - Final accumulator point matches expected: `seed + cond_sum(&bitmask, &points)`
  - Constraint polynomial degrees: `4 * n - 3` (both constraints)
  - Both constraints divide by vanishing polynomial

### ✅ `sw_cond_add.rs` (Short Weierstrass Conditional Add)
- **Test**: `test_sw_cond_add_gadget()`
- **Checks**:
  - Final accumulator point matches expected
  - Constraint polynomial degrees: `4 * n - 3` and `3 * n - 2`
  - Both constraints divide by vanishing polynomial

### ❌ `booleanity.rs`
- **No tests found** in Rust reference (may be tested elsewhere or implicitly)

### ❌ `fixed_cells.rs`
- **No tests found** in Rust reference (may be tested elsewhere or implicitly)

## TypeScript Test Coverage

### ✅ `inner-prod.test.ts` (PARTIAL)
- **Tests**:
  - ✅ Accumulator starts at zero
  - ✅ Final accumulator equals inner product
  - ❌ **Missing**: Constraint polynomial degree check
  - ❌ **Missing**: Vanishing polynomial division check (marked as TODO)

### ❌ Missing Tests
- **No tests for**:
  - `booleanity` gadget
  - `fixed-cells` gadget
  - `cond-add` gadget (Twisted Edwards version)

## Test Helpers

### Rust Test Helpers (`test_helpers.rs`)
- `random_bitvec(n, density, rng)` - Generate random boolean vector
- `random_vec(n, rng)` - Generate random field elements or points
- `cond_sum(bitmask, points)` - Conditional sum: sum points where bitmask is true

### TypeScript Test Helpers
- `randomFieldElement()` - Generate random field element (in `inner-prod.test.ts`)
- **Missing**: `randomBitVec()`, `condSum()` helpers

## Recommendations

### 1. Complete `inner-prod.test.ts`
- [ ] Add constraint polynomial degree check
- [ ] Implement vanishing polynomial division check

### 2. Add Missing Tests
- [ ] `booleanity.test.ts` - Test booleanity constraints
- [ ] `fixed-cells.test.ts` - Test fixed cell constraints
- [ ] `cond-add.test.ts` - Test conditional addition gadget

### 3. Create Shared Test Helpers
- [ ] `test-helpers.ts` with:
  - `randomFieldElement()`
  - `randomBitVec(n, density)`
  - `condSum(bitmask, points)`
  - `randomPoint()` (for curve points)

### 4. Match Rust Test Pattern
All new tests should follow the Rust pattern:
1. Setup domain and random data
2. Initialize gadget
3. Verify accumulator values
4. Verify constraint polynomial degree
5. Verify constraint divides by vanishing polynomial
6. Test both `hiding: false` and `hiding: true`

## Example: Complete Test Template

```typescript
function testGadget(hiding: boolean) {
  const logN = 10
  const n = 2 ** logN
  const domain = new Domain(n, hiding)
  
  // Generate test data
  const testData = generateTestData(domain.capacity - 1)
  
  // Initialize gadget
  const gadget = Gadget.init(testData, domain)
  
  // Verify accumulator
  const acc = gadget.acc.evals
  expect(Fr.eql(Fr.create(acc[0]), Fr.ZERO)).toBe(true)
  expect(Fr.eql(Fr.create(acc[domain.capacity - 1]), expectedValue)).toBe(true)
  
  // Verify constraint polynomial
  const constraintPoly = gadget.constraints()[0]
  expect(constraintPoly.degree).toBe(expectedDegree)
  
  // Verify divides by vanishing polynomial
  const quotient = domain.divideByVanishingPoly(constraintPoly)
  // Quotient should be a valid polynomial (not throw error)
}

describe('Gadget Tests', () => {
  test('without hiding', () => testGadget(false))
  test('with hiding', () => testGadget(true))
})
```


