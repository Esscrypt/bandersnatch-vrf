# Plonk Implementation Status

## ✅ Implemented

1. **Domain** (`domain/domain.ts`) - FFT domains, evaluation domains
2. **PIOP Module** (`piop/`) - Polynomial Interactive Oracle Proofs
   - `params.ts` - PIOP parameters
   - `prover.ts` - PIOP prover
   - `verifier.ts` - PIOP verifier
   - `mod.ts` - Types and index function
3. **Gadgets** (`gadgets/`) - Plonk constraint gadgets
   - `inner-prod.ts` - Inner product gadget
   - `booleanity.ts` - Booleanity constraint
   - `fixed-cells.ts` - Fixed cell constraints
   - `cond-add.ts` - Conditional addition gadget
   - `bit-column.ts` - Bit column
   - `affine-column.ts` - Affine point column

## ❌ Missing (Required for Full Plonk)

1. **PlonkProver** (`prover.ts`) - Main Plonk prover that wraps PIOP
   - Handles 3-round Plonk protocol
   - Commits to columns, aggregates constraints, generates quotient polynomial
   - Produces KZG proofs

2. **PlonkVerifier** (`verifier.ts`) - Main Plonk verifier
   - Verifies Plonk proofs
   - Restores challenges from transcript
   - Batch verifies KZG proofs

3. **Transcript** (`transcript/`) - Fiat-Shamir transcript
   - Generates challenges (alphas, zeta, nus)
   - Implements PlonkTranscript trait

4. **Proof Type** - Proof structure matching Rust
   - `column_commitments` - Commitments to witness columns
   - `quotient_commitment` - Quotient polynomial commitment
   - `columns_at_zeta` - Column evaluations at zeta
   - `lin_at_zeta_omega` - Linearization at zeta*omega
   - `agg_at_zeta_proof` - Aggregated KZG proof at zeta
   - `lin_at_zeta_omega_proof` - Linearization KZG proof at zeta*omega

5. **PIOP Traits** - TypeScript interfaces matching Rust traits
   - `ProverPiop` - Trait for PIOP provers
   - `VerifierPiop` - Trait for PIOP verifiers

## Integration with ring-kzg.ts

Currently, `ring-kzg.ts` uses a simplified KZG-based approach. To match the Rust implementation:

1. **Replace direct KZG usage** with PlonkProver + PiopProver
2. **Use PlonkProver.prove()** which:
   - Takes a PiopProver instance
   - Runs the 3-round Plonk protocol
   - Returns a Plonk Proof
3. **Use PlonkVerifier.verify()** to verify proofs

The flow should be:
```
RingVRFProver.prove()
  → Build PiopProver with ring keys and secret
  → Create PlonkProver with SRS and verifier key
  → Call PlonkProver.prove(piopProver)
  → Returns RingProof (Plonk Proof)
```
