# Tests from Rust Implementation

## Overview

The Rust `w3f-plonk-common` and `w3f-ring-proof` packages have several tests we can adapt for our TypeScript implementation.

## Key Tests Found

### 1. End-to-End Ring Proof Test (`w3f-ring-proof/src/lib.rs`)

**Test**: `test_ring_proof_kzg()`
- **Purpose**: Full integration test of Plonk prover and verifier
- **Flow**:
  1. Setup PCS params and PIOP params
  2. Generate random ring keys
  3. Create prover and verifier keys using `index()`
  4. Generate proof with `RingProver.prove()`
  5. Verify proof with `RingVerifier.verify()`
  6. Assert verification succeeds

**Key Code**:
```rust
fn _test_ring_proof<CS: PCS<Fq>>(domain_size: usize) {
    let (pcs_params, piop_params) = setup(rng, domain_size);
    let (prover_key, verifier_key) = index(&pcs_params, &piop_params, &pks);
    
    let ring_prover = RingProver::init(prover_key, piop_params.clone(), k, transcript);
    let proof = ring_prover.prove(secret);
    
    let ring_verifier = RingVerifier::init(verifier_key, piop_params, transcript);
    let res = ring_verifier.verify(proof, result);
    assert!(res);
}
```

### 2. Domain Tests (`w3f-plonk-common/src/domain.rs`)

**Test**: `test_evaluated_domain()`
- **Purpose**: Verify domain evaluation correctness
- **Checks**:
  - `l_first` polynomial evaluation matches evaluated domain
  - `l_last` polynomial evaluation matches evaluated domain
  - `not_last_row` polynomial evaluation matches evaluated domain

### 3. Inner Product Gadget Test (`w3f-plonk-common/src/gadgets/inner_prod.rs`)

**Test**: `test_inner_prod_gadget()`
- **Purpose**: Verify inner product gadget correctness
- **Checks**:
  - Accumulator starts at zero
  - Final accumulator equals inner product
  - Constraint polynomial divides by vanishing polynomial

### 4. PIOP Params Test (`w3f-ring-proof/src/piop/params.rs`)

**Test**: `test_powers_of_h()`
- **Purpose**: Verify powers of H computation
- **Checks**:
  - `cond_sum(t_bits, powers_of_h)` equals `h * t`

### 5. Ring Management Test (`w3f-ring-proof/src/ring.rs`)

**Test**: `test_ring_mgmt()`
- **Purpose**: Verify ring commitment computation
- **Checks**:
  - Empty ring commitments match monomial commitments
  - Ring with keys matches monomial commitments
  - `Ring::with_keys()` produces same ring as `Ring::empty()` + `append()`

### 6. Lagrangian Commitment Test (`w3f-ring-proof/src/lib.rs`)

**Test**: `test_lagrangian_commitment()`
- **Purpose**: Verify Lagrangian SRS commitment matches ring commitment
- **Checks**:
  - `FixedColumnsCommitted::from_ring()` matches verifier key commitments

## Test Helpers (`w3f-plonk-common/src/test_helpers.rs`)

Useful helper functions:
- `random_bitvec()` - Generate random bit vectors
- `random_vec()` - Generate random field element vectors
- `cond_sum()` - Conditional sum of points based on bitmask
- `power_of_two_multiple()` - Compute 2^n * point

## TypeScript Test Structure

We should create tests for:

1. **Domain Tests** (`plonk/domain/domain.test.ts`)
   - Test evaluated domain correctness
   - Test Lagrange basis polynomials
   - Test vanishing polynomials

2. **Gadget Tests** (`plonk/gadgets/*.test.ts`)
   - Inner product gadget
   - Booleanity gadget
   - Fixed cells gadget
   - CondAdd gadget

3. **PIOP Tests** (`plonk/piop/*.test.ts`)
   - PIOP params (powers of H)
   - PIOP prover (execution trace)
   - PIOP verifier (constraints)

4. **End-to-End Test** (`plonk/plonk.test.ts`)
   - Full Plonk prover/verifier flow
   - Ring proof generation and verification
   - Multiple ring sizes

## Implementation Priority

1. **High Priority**: End-to-end test (validates entire system)
2. **Medium Priority**: Domain tests (foundation for everything)
3. **Medium Priority**: Gadget tests (validate constraint correctness)
4. **Low Priority**: Individual component tests



