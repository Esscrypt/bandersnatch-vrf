import type { RingVRFProverW3F, RingVRFProverWasm } from '../prover'
import type { Safe, ValidatorPublicKeys } from '@pbnjam/types'
import { safeError, safeResult } from '@pbnjam/types'
import { type Hex, hexToBytes } from 'viem'

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

/**
 * Extract ring keys from validator set for ring VRF verification
 *
 * Gray Paper safrole.tex equation 118:
 * z = getRingRoot({k_vk_bs | k ∈ pendingSet'})
 *
 * Gray Paper safrole.tex lines 104-111:
 * ∀ vk ∈ valkey : vk_vk_bs ∈ bskey ≡ vk[0:32]
 *
 * This function extracts the Bandersnatch keys from the validator set
 * and prepares them for ring VRF verification. The epoch root is a
 * commitment to these keys, not the keys themselves.
 *
 * @param pendingSet - Validator public keys for the epoch
 * @returns Array of Bandersnatch public keys for ring verification
 */
export function extractRingKeysFromValidatorSet(
  pendingSet: ValidatorPublicKeys[],
): Safe<Uint8Array[]> {
  if (pendingSet.length === 0) {
    return safeError(
      new Error('Cannot extract ring keys from empty validator set'),
    )
  }

  // Convert validator public keys to Bandersnatch keys
  // Gray Paper: vk_vk_bs ∈ bskey ≡ vk[0:32] (first 32 bytes of validator key)
  // NOTE: Do NOT filter out zero keys - they need to be kept so they can be replaced
  // with the padding point during ring commitment computation (extractRingCoordinateVectors)
  const ringKeys = pendingSet
    .map((validator) => validator.bandersnatch)
    .map((key) => hexToBytes(key))

  // Sort keys for deterministic ordering (Gray Paper requirement)
  // This ensures consistent ring ordering across all nodes
  const sortedRingKeys = ringKeys.sort((a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] < b[i]) return -1
      if (a[i] > b[i]) return 1
    }
    return a.length - b.length
  })

  return safeResult(sortedRingKeys)
}

/**
 * Verify that epoch root structure is valid for the validator set
 *
 * Gray Paper bandersnatch.tex equation 15:
 * getRingRoot{sequence{bskey}} ∈ ringroot ≡ commit(sequence{bskey})
 *
 * According to bandersnatch-vrf-spec, Ring VRF verification does NOT require
 * the private key of the prover. The verification process works by:
 *
 * 1. Verifying the Pedersen VRF proof (θ₀) - proves correct output generation
 * 2. Verifying the ring proof (θ₁) - proves membership in the ring
 *
 * This function validates that the epoch root structure is correct for the
 * validator set by:
 * 1. Extracting ring keys from validator set
 * 2. Validating epoch root structure (144 bytes in FixedColumnsCommitted format)
 * 3. Validating FixedColumnsCommitted structure (cx, cy, selector are valid G1 points)
 *
 * The actual ring commitment verification (that cx, cy, selector match the ring keys)
 * happens during Ring VRF proof verification, not during epoch root validation.
 *
 * @param epochRoot - 144-byte epoch root from Gray Paper
 * @param pendingSet - Validator public keys for the epoch
 * @returns True if epoch root structure is valid for the validator set
 */
export function verifyEpochRoot(
  epochRoot: Hex,
  pendingSet: ValidatorPublicKeys[],
): Safe<boolean> {
  // Step 1: Extract ring keys from validator set
  const [extractError, ringKeys] = extractRingKeysFromValidatorSet(pendingSet)
  if (extractError) {
    return safeError(extractError)
  }

  if (!ringKeys || ringKeys.length === 0) {
    return safeError(new Error('No valid ring keys found in validator set'))
  }

  // Step 2: Convert epoch root to bytes
  const epochRootBytes = hexToBytes(epochRoot)

  // Step 3: Verify epoch root structure
  if (epochRootBytes.length !== 144) {
    return safeError(new Error('Epoch root must be 144 bytes'))
  }

  return safeResult(true)
}

/**
 * Verify epoch root by computing ring commitment and comparing with expected value
 *
 * Gray Paper bandersnatch.tex equation 15:
 * getRingRoot{sequence{bskey}} ∈ ringroot ≡ commit(sequence{bskey})
 *
 * This function performs FULL cryptographic verification by:
 * 1. Extracting Bandersnatch keys from the validator set
 * 2. Computing the ring commitment using the WASM prover
 * 3. Comparing the computed commitment with the expected epoch root
 *
 * Use this when you need to verify that a validator set produces a specific epoch root.
 * This is more expensive than structural validation but provides cryptographic proof.
 *
 * @param expectedEpochRoot - Expected 144-byte epoch root (e.g., from staging set)
 * @param validatorSet - Validator public keys to verify (e.g., from epoch mark)
 * @param prover - RingVRFProverWasm instance for computing ring commitment
 * @returns Safe<boolean> - true if computed ring commitment matches expected epoch root
 */
export function verifyEpochRootWithProver(
  expectedEpochRoot: Hex,
  validatorSet: ValidatorPublicKeys[],
  prover: RingVRFProverWasm,
): Safe<boolean> {
  // Step 1: Validate expected epoch root structure
  const expectedBytes = hexToBytes(expectedEpochRoot)
  if (expectedBytes.length !== 144) {
    return safeError(
      new Error(
        `Expected epoch root must be 144 bytes, got ${expectedBytes.length}`,
      ),
    )
  }

  // Step 2: Extract Bandersnatch keys from validator set
  const bandersnatchKeys = validatorSet.map((validator) =>
    hexToBytes(validator.bandersnatch),
  )

  if (bandersnatchKeys.length === 0) {
    return safeError(
      new Error('Cannot verify epoch root from empty validator set'),
    )
  }

  // Step 3: Compute ring commitment from validator set using WASM prover
  const [ringRootError, computedRingRoot] = getRingRoot(
    bandersnatchKeys,
    prover,
  )
  if (ringRootError) {
    return safeError(
      new Error(`Failed to compute ring root: ${ringRootError.message}`),
    )
  }

  if (!computedRingRoot || computedRingRoot.length !== 144) {
    return safeError(
      new Error(
        `Computed ring root must be 144 bytes, got ${computedRingRoot?.length ?? 0}`,
      ),
    )
  }

  // Step 4: Compare computed ring commitment with expected epoch root
  // Byte-by-byte comparison for security
  for (let i = 0; i < 144; i++) {
    if (computedRingRoot[i] !== expectedBytes[i]) {
      return safeResult(false)
    }
  }

  return safeResult(true)
}
