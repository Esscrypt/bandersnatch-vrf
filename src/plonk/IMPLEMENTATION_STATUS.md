# Plonk Implementation Status

## Summary

We have implemented **most** of `w3f-plonk-common`, but we're **missing the core PlonkProver and PlonkVerifier** that wrap the PIOP layer. The current `ring-kzg.ts` uses a simplified KZG approach, but to match the Rust implementation, we need to use the full Plonk protocol.

## ✅ What We Have

### 1. Domain (`domain/domain.ts`)
- ✅ FFT domains (1x and 4x)
- ✅ Domain-specific polynomials (Lagrange basis, vanishing polynomials)
- ✅ Evaluated domain support

### 2. PIOP Module (`piop/`)
- ✅ `params.ts` - PIOP parameters with domain, base points, helper methods
- ✅ `prover.ts` - PIOP prover that builds execution trace
- ✅ `verifier.ts` - PIOP verifier for constraint checking
- ✅ `mod.ts` - Types, interfaces, and index function

### 3. Gadgets (`gadgets/`)
- ✅ `inner-prod.ts` - Inner product gadget
- ✅ `booleanity.ts` - Booleanity constraint
- ✅ `fixed-cells.ts` - Fixed cell constraints
- ✅ `cond-add.ts` - Conditional addition gadget (with ACCUMULATOR_SEED_POINT)
- ✅ `bit-column.ts` - Bit column
- ✅ `affine-column.ts` - Affine point column

### 4. Supporting Infrastructure
- ✅ `proof.ts` - Proof structure type
- ✅ `transcript/transcript.ts` - Fiat-Shamir transcript (basic implementation)

## ❌ What's Missing (Critical for Full Plonk)

### 1. PlonkProver (`prover.ts`) - **CRITICAL**
The main Plonk prover that:
- Wraps PIOP prover
- Implements 3-round Plonk protocol:
  - **Round 1**: Commit to witness columns
  - **Round 2**: Aggregate constraints, compute quotient polynomial, commit to quotient
  - **Round 3**: Evaluate columns at zeta, compute linearization, generate KZG proofs
- Returns `Proof` structure

**Rust Reference**: `w3f-plonk-common/src/prover.rs`

### 2. PlonkVerifier (`verifier.ts`) - **CRITICAL**
The main Plonk verifier that:
- Restores challenges from transcript
- Verifies constraint evaluations
- Batch verifies KZG proofs
- Returns boolean verification result

**Rust Reference**: `w3f-plonk-common/src/verifier.rs`

### 3. PIOP Traits (`piop.ts`)
TypeScript interfaces matching Rust traits:
- `ProverPiop<F, C>` - Trait for PIOP provers
- `VerifierPiop<F, C>` - Trait for PIOP verifiers

**Note**: Our `PiopProver` and `PiopVerifier` classes should implement these traits.

### 4. Enhanced Transcript
Current transcript is basic. Need:
- Proper serialization of domain and PCS keys
- Correct challenge generation (128-bit field elements)
- Integration with KZG proof system

## How It Should Work

### Current Flow (ring-kzg.ts)
```
RingVRFProver.prove()
  → Create ring polynomial
  → KZG commit to polynomial
  → KZG prove at domain generator
  → Return simplified proof
```

### Target Flow (Matching Rust)
```
RingVRFProver.prove()
  → Build PiopProver with ring keys and secret
  → Create PlonkProver with SRS and verifier key
  → Call PlonkProver.prove(piopProver)
    → Round 1: Commit witness columns
    → Round 2: Aggregate constraints, quotient polynomial
    → Round 3: Evaluate at zeta, linearization, KZG proofs
  → Returns RingProof (Plonk Proof)
```

### Verification Flow
```
RingVRFVerifier.verify()
  → Create PlonkVerifier with verifier key
  → Restore challenges from transcript
  → Call PlonkVerifier.verify(piopVerifier, proof, challenges)
    → Verify constraint evaluations
    → Batch verify KZG proofs
  → Return boolean
```

## Integration with ring-kzg.ts

### Option 1: Replace Current Implementation (Recommended)
Replace the simplified KZG approach in `ring-kzg.ts` with full Plonk:

```typescript
// In RingVRFProver.prove()
const piopProver = PiopProver.build(
  piopParams,
  fixedColumns,
  input.proverIndex,
  secretScalar
)

const plonkProver = PlonkProver.init(
  pcsCk,  // From SRS
  verifierKey,
  transcript
)

const proof = plonkProver.prove(piopProver)
```

### Option 2: Keep Both Implementations
- Keep `ring-kzg.ts` for simplified KZG-based proofs
- Add `ring-plonk.ts` for full Plonk-based proofs
- Use configuration to choose which to use

## Next Steps

1. **Implement PlonkProver** (`plonk/prover.ts`)
   - Match `w3f-plonk-common/src/prover.rs`
   - Integrate with KZG commitment scheme
   - Handle 3-round protocol

2. **Implement PlonkVerifier** (`plonk/verifier.ts`)
   - Match `w3f-plonk-common/src/verifier.rs`
   - Restore challenges from transcript
   - Batch verify KZG proofs

3. **Enhance Transcript**
   - Proper serialization
   - Correct challenge generation
   - Integration with existing KZG utilities

4. **Update ring-kzg.ts**
   - Replace simplified KZG with PlonkProver
   - Or create new `ring-plonk.ts` file

5. **Add PIOP Traits**
   - Ensure PiopProver implements ProverPiop
   - Ensure PiopVerifier implements VerifierPiop

## Files to Create

1. `plonk/prover.ts` - Main Plonk prover
2. `plonk/verifier.ts` - Main Plonk verifier
3. `plonk/piop.ts` - PIOP trait interfaces (optional, can use existing classes)

## Estimated Completion

- **PlonkProver**: ~200-300 lines
- **PlonkVerifier**: ~150-200 lines
- **Integration**: ~100-150 lines

**Total**: ~450-650 lines of code



