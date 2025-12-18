/**
 * Gamma (VRF output point) utility functions
 */

import { pointToHashRfc9381 } from '../crypto/rfc9381'

/**
 * Get the commitment (hash) from a gamma point using RFC-9381 point-to-hash
 *
 * This is the standard way to derive a hash commitment from the VRF output point (gamma).
 * The hash is computed deterministically from gamma and can be used as a commitment
 * or identifier for the VRF output.
 *
 * @param gamma - The VRF output point (32 bytes)
 * @returns The hash commitment (64 bytes) derived from gamma
 */
export function getCommitmentFromGamma(gamma: Uint8Array): Uint8Array {
  if (gamma.length !== 32) {
    throw new Error(`Gamma must be 32 bytes, got ${gamma.length}`)
  }

  return pointToHashRfc9381(gamma, false)
}

/**
 * Get the banderout (first 32 bytes) from gamma according to Gray Paper
 *
 * Gray Paper definition: \banderout{p \in \bsringproof{r}{c}{m}} \in \hash \equiv \text{output}(x \mid x \in \bsringproof{r}{c}{m})\interval{}{32}
 *
 * This is the standard VRF output identifier used for ticket IDs and other identifiers
 * that need to be 32 bytes rather than the full 64-byte hash.
 *
 * @param gamma - The VRF output point (32 bytes)
 * @returns The banderout (first 32 bytes of the hash commitment)
 */
export function getBanderoutFromGamma(gamma: Uint8Array): Uint8Array {
  const fullHash = getCommitmentFromGamma(gamma)
  return fullHash.slice(0, 32)
}
