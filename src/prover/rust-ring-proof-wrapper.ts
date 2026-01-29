/**
 * Rust connector for ring proof (w3f ring proof lines 299-316).
 * Validations and serialization (to output format) are in TypeScript.
 */

import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)

const KEY_SIZE = 32
const BLINDING_FACTOR_SIZE = 32
/** Ring commitment: cx (48) + cy (48) + selector (48) */
export const RING_COMMITMENT_SIZE = 144

export interface ComputeRingCommitmentInputs {
  srsBytes: Uint8Array
  ringKeysBytes: Uint8Array
}

/**
 * Validate compute_ring_commitment inputs (ark-vrf algorithm: ring_size from keys).
 * Throws if any check fails.
 */
export function validateComputeRingCommitmentInputs(
  inputs: ComputeRingCommitmentInputs,
): void {
  if (!inputs.srsBytes.length) {
    throw new Error('SRS bytes cannot be empty')
  }
  if (inputs.ringKeysBytes.length % KEY_SIZE !== 0) {
    throw new Error(
      `Invalid ring keys length: expected multiple of ${KEY_SIZE}, got ${inputs.ringKeysBytes.length}`,
    )
  }
}

/**
 * Validate and construct ring commitment output (144 bytes: cx + cy + selector).
 * Throws if buffer length is not RING_COMMITMENT_SIZE.
 */
export function serializeCommitmentToOutput(
  commitmentBytes: Buffer | Uint8Array,
): Uint8Array {
  const out = new Uint8Array(commitmentBytes)
  if (out.length !== RING_COMMITMENT_SIZE) {
    throw new Error(
      `Invalid ring commitment length: expected ${RING_COMMITMENT_SIZE}, got ${out.length}`,
    )
  }
  return out
}

export interface ProveRingProofInputs {
  srsBytes: Uint8Array
  ringKeysBytes: Uint8Array
  blindingFactorBytes: Uint8Array
  proverIndex: number
}

/**
 * Validate prove_ring_proof inputs (matches Rust lib.rs: srs, ring_keys, blinding_factor, prover_index).
 * Throws if any check fails.
 */
export function validateProveRingProofInputs(
  inputs: ProveRingProofInputs,
): void {
  if (!inputs.srsBytes.length) {
    throw new Error('SRS bytes cannot be empty')
  }
  if (inputs.ringKeysBytes.length % KEY_SIZE !== 0) {
    throw new Error(
      `Invalid ring keys length: expected multiple of ${KEY_SIZE}, got ${inputs.ringKeysBytes.length}`,
    )
  }
  const numKeys = inputs.ringKeysBytes.length / KEY_SIZE
  if (inputs.proverIndex < 0 || inputs.proverIndex >= numKeys) {
    throw new Error(
      `Prover index out of bounds: proverIndex=${inputs.proverIndex}, numKeys=${numKeys}`,
    )
  }
  if (inputs.blindingFactorBytes.length !== BLINDING_FACTOR_SIZE) {
    throw new Error(
      `Blinding factor must be ${BLINDING_FACTOR_SIZE} bytes, got ${inputs.blindingFactorBytes.length}`,
    )
  }
}

/**
 * Serialize proof bytes to output format (moved from Rust lib.rs lines 110-116).
 * Takes raw proof bytes from Rust and returns the final Uint8Array for the caller.
 */
export function serializeProofToOutput(
  proofBytes: Buffer | Uint8Array,
): Uint8Array {
  return new Uint8Array(proofBytes)
}

const KEY_COMMITMENT_SIZE = 32

export interface VerifyRingVrfInputs {
  srsBytes: Uint8Array
  proofBytes: Uint8Array
  ringKeysBytes: Uint8Array
  keyCommitmentBytes: Uint8Array
}

/**
 * Validate verify_ring_vrf inputs (ring proof + key commitment Y_bar).
 * Throws if any check fails.
 */
export function validateVerifyRingVrfInputs(inputs: VerifyRingVrfInputs): void {
  if (!inputs.srsBytes.length) {
    throw new Error('SRS bytes cannot be empty')
  }
  if (!inputs.proofBytes.length) {
    throw new Error('Proof bytes cannot be empty')
  }
  if (inputs.ringKeysBytes.length % KEY_SIZE !== 0) {
    throw new Error(
      `Invalid ring keys length: expected multiple of ${KEY_SIZE}, got ${inputs.ringKeysBytes.length}`,
    )
  }
  if (inputs.keyCommitmentBytes.length !== KEY_COMMITMENT_SIZE) {
    throw new Error(
      `Key commitment must be ${KEY_COMMITMENT_SIZE} bytes, got ${inputs.keyCommitmentBytes.length}`,
    )
  }
}

export type ProveRingProofRust = (
  srsBytes: Uint8Array,
  ringKeysBytes: Uint8Array,
  blindingFactorBytes: Uint8Array,
  proverIndex: number,
) => Uint8Array

let rustProveRingProof: ProveRingProofRust | null = null

export type VerifyRingVrfRust = (
  srsBytes: Uint8Array,
  proofBytes: Uint8Array,
  ringKeysBytes: Uint8Array,
  keyCommitmentBytes: Uint8Array,
) => boolean

export type ComputeRingCommitmentRust = (
  srsBytes: Uint8Array,
  ringKeysBytes: Uint8Array,
) => Uint8Array

let rustVerifyRingVrf: VerifyRingVrfRust | null = null
let rustComputeRingCommitment: ComputeRingCommitmentRust | null = null

try {
  const native = require('../../rust-ring-proof/native') as {
    proveRingProof: (
      srsBytes: Buffer,
      ringKeysBytes: Buffer,
      blindingFactorBytes: Buffer,
      proverIndex: number,
    ) => Buffer
    computeRingCommitment: (srsBytes: Buffer, ringKeysBytes: Buffer) => Buffer
    verifyRingVrf: (
      srsBytes: Buffer,
      proofBytes: Buffer,
      ringKeysBytes: Buffer,
      keyCommitmentBytes: Buffer,
    ) => boolean
  }
  if (native?.proveRingProof) {
    rustProveRingProof = (
      srsBytes: Uint8Array,
      ringKeysBytes: Uint8Array,
      blindingFactorBytes: Uint8Array,
      proverIndex: number,
    ): Uint8Array => {
      validateProveRingProofInputs({
        srsBytes,
        ringKeysBytes,
        blindingFactorBytes,
        proverIndex,
      })
      const out = native.proveRingProof(
        Buffer.from(srsBytes),
        Buffer.from(ringKeysBytes),
        Buffer.from(blindingFactorBytes),
        proverIndex,
      )
      return serializeProofToOutput(out)
    }
  }
  if (native?.verifyRingVrf) {
    rustVerifyRingVrf = (
      srsBytes: Uint8Array,
      proofBytes: Uint8Array,
      ringKeysBytes: Uint8Array,
      keyCommitmentBytes: Uint8Array,
    ): boolean => {
      validateVerifyRingVrfInputs({
        srsBytes,
        proofBytes,
        ringKeysBytes,
        keyCommitmentBytes,
      })
      return native.verifyRingVrf(
        Buffer.from(srsBytes),
        Buffer.from(proofBytes),
        Buffer.from(ringKeysBytes),
        Buffer.from(keyCommitmentBytes),
      )
    }
  }
  if (native?.computeRingCommitment) {
    rustComputeRingCommitment = (
      srsBytes: Uint8Array,
      ringKeysBytes: Uint8Array,
    ): Uint8Array => {
      validateComputeRingCommitmentInputs({ srsBytes, ringKeysBytes })
      const out = native.computeRingCommitment(
        Buffer.from(srsBytes),
        Buffer.from(ringKeysBytes),
      )
      return serializeCommitmentToOutput(out)
    }
  }
} catch {
  // Native module not built or not available
}

export function getRustProveRingProof(): ProveRingProofRust | null {
  return rustProveRingProof
}

export function isRustRingProofAvailable(): boolean {
  return rustProveRingProof !== null
}

export function getRustVerifyRingVrf(): VerifyRingVrfRust | null {
  return rustVerifyRingVrf
}

export function isRustVerifyRingVrfAvailable(): boolean {
  return rustVerifyRingVrf !== null
}

export function getRustComputeRingCommitment(): ComputeRingCommitmentRust | null {
  return rustComputeRingCommitment
}

export function isRustComputeRingCommitmentAvailable(): boolean {
  return rustComputeRingCommitment !== null
}
