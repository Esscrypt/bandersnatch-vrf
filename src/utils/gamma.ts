import { pointToHashRfc9381 } from '../crypto/rfc9381.ts'

export function getCommitmentFromGamma(gamma: Uint8Array): Uint8Array {
  if (gamma.length !== 32) {
    throw new Error(`Gamma must be 32 bytes, got ${gamma.length}`)
  }

  return pointToHashRfc9381(gamma)
}

export function getBanderoutFromGamma(gamma: Uint8Array): Uint8Array {
  const fullHash = getCommitmentFromGamma(gamma)
  return fullHash.slice(0, 32)
}
