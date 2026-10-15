import { loadRingProofNative } from './native-loader.ts'

const KEY_SIZE = 32
const BLINDING_FACTOR_SIZE = 32
export const RING_COMMITMENT_SIZE = 144

export interface ComputeRingCommitmentInputs {
  srsBytes: Uint8Array
  ringKeysBytes: Uint8Array
}

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

export type ComputeRingVerifierKeyRust = (
  srsBytes: Uint8Array,
  ringKeysBytes: Uint8Array,
) => Uint8Array

export type VerifyRingVrfWithKeyRust = (
  vkBytes: Uint8Array,
  proofBytes: Uint8Array,
  keyCommitmentBytes: Uint8Array,
  ringSize: number,
) => boolean

export interface RingBatchItem {
  proofBytes: Uint8Array
  keyCommitmentBytes: Uint8Array
}

export type BatchVerifyRingVrfRust = (
  vkBytes: Uint8Array,
  ringSize: number,
  items: RingBatchItem[],
) => boolean

let rustVerifyRingVrf: VerifyRingVrfRust | null = null
let rustComputeRingCommitment: ComputeRingCommitmentRust | null = null
let rustComputeRingVerifierKey: ComputeRingVerifierKeyRust | null = null
let rustVerifyRingVrfWithKey: VerifyRingVrfWithKeyRust | null = null
let rustBatchVerifyRingVrf: BatchVerifyRingVrfRust | null = null

try {
  const native = loadRingProofNative()
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
  if (native?.computeRingVerifierKey) {
    const fn = native.computeRingVerifierKey
    rustComputeRingVerifierKey = (
      srsBytes: Uint8Array,
      ringKeysBytes: Uint8Array,
    ): Uint8Array => {
      validateComputeRingCommitmentInputs({ srsBytes, ringKeysBytes })
      return new Uint8Array(
        fn(Buffer.from(srsBytes), Buffer.from(ringKeysBytes)),
      )
    }
  }
  if (native?.verifyRingVrfWithKey) {
    const fn = native.verifyRingVrfWithKey
    rustVerifyRingVrfWithKey = (
      vkBytes: Uint8Array,
      proofBytes: Uint8Array,
      keyCommitmentBytes: Uint8Array,
      ringSize: number,
    ): boolean => {
      return fn(
        Buffer.from(vkBytes),
        Buffer.from(proofBytes),
        Buffer.from(keyCommitmentBytes),
        ringSize,
      )
    }
  }
  if (native?.batchVerifyRingVrf) {
    const fn = native.batchVerifyRingVrf
    rustBatchVerifyRingVrf = (
      vkBytes: Uint8Array,
      ringSize: number,
      items: RingBatchItem[],
    ): boolean => {
      return fn(
        Buffer.from(vkBytes),
        ringSize,
        items.map((it) => ({
          proofBytes: Buffer.from(it.proofBytes),
          keyCommitmentBytes: Buffer.from(it.keyCommitmentBytes),
        })),
      )
    }
  }
} catch {
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

export function getRustComputeRingVerifierKey(): ComputeRingVerifierKeyRust | null {
  return rustComputeRingVerifierKey
}

export function getRustVerifyRingVrfWithKey(): VerifyRingVrfWithKeyRust | null {
  return rustVerifyRingVrfWithKey
}

export function getRustBatchVerifyRingVrf(): BatchVerifyRingVrfRust | null {
  return rustBatchVerifyRingVrf
}
