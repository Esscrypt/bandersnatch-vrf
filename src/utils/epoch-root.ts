import type { Safe } from '@pbnjam/types'
import { safeError, safeResult } from '@pbnjam/types'
import type { RingVRFProverW3F, RingVRFProverWasm } from '../prover/index.ts'

/**
 * Epoch root and ring root utilities for Gray Paper consensus.
 *
 * Gray Paper bandersnatch.tex equation 15: getRingRoot{sequence{bskey}} ∈ ringroot.
 * Gray Paper safrole.tex equation 118: z = getRingRoot({k_vk_bs | k ∈ pendingSet'}).
 *
 * @module epoch-root
 */

/**
 * getRingRoot - Create KZG polynomial commitment to ring of public keys
 *
 * ============================================================================
 * GRAY PAPER SPECIFICATION:
 * ============================================================================
 *
 * Gray Paper bandersnatch.tex equation 15:
 * getRingRoot{sequence{bskey}} ∈ ringroot ≡ commit(sequence{bskey})
 *
 * Gray Paper notation.tex line 169:
 * - ringroot ⊂ blob[144] (ring root is 144 bytes)
 *
 * Gray Paper safrole.tex equation 118:
 * z = getRingRoot({k_vk_bs | k ∈ pendingSet'})
 *
 * ============================================================================
 * BANDERSNATCH-VRF-SPEC COMPLIANCE:
 * ============================================================================
 *
 * Ring root structure (144 bytes total):
 * - KZG Polynomial Commitment (48 bytes): BLS12-381 G1 point commitment
 * - Accumulator Seed Point (32 bytes): For ring proof generation
 * - Padding Point (32 bytes): For invalid Bandersnatch keys
 * - Domain Information (32 bytes): Polynomial domain generator and size
 *
 * ============================================================================
 *
 * @param bandersnatchKeys - Sequence of Bandersnatch public keys (32 bytes each)
 * @param prover - RingVRFProver instance for computing ring commitment
 * @returns 144-byte ring root commitment with proper metadata
 */
export function getRingRoot(
  bandersnatchKeys: Uint8Array[],
  prover: RingVRFProverWasm | RingVRFProverW3F,
): Safe<Uint8Array> {
  if (bandersnatchKeys.length === 0) {
    return safeError(new Error('Cannot create ring root from empty key set'))
  }

  // Gray Paper compliant: compute ring commitment from public keys only
  // No private key needed - this is deterministic and can be computed by any node
  // computeRingCommitment now returns FixedColumnsCommitted format (144 bytes):
  // [cx (48), cy (48), selector (48)] matching Rust implementation
  let ringRoot: Uint8Array
  try {
    ringRoot = prover.computeRingCommitment(bandersnatchKeys)
  } catch (error) {
    return safeError(
      error instanceof Error
        ? error
        : new Error(`Failed to compute ring commitment: ${String(error)}`),
    )
  }

  if (!ringRoot || ringRoot.length !== 144) {
    return safeError(
      new Error(
        `Ring root must be 144 bytes (FixedColumnsCommitted), got ${ringRoot?.length ?? 0}`,
      ),
    )
  }

  return safeResult(ringRoot)
}
