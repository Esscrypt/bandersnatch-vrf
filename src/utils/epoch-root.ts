import type { Safe } from '@pbnjam/types'
import { safeError, safeResult } from '@pbnjam/types'
import type { RingVRFProverW3F, RingVRFProverWasm } from '../prover/index.ts'

export function getRingRoot(
  bandersnatchKeys: Uint8Array[],
  prover: RingVRFProverWasm | RingVRFProverW3F,
): Safe<Uint8Array> {
  if (bandersnatchKeys.length === 0) {
    return safeError(new Error('Cannot create ring root from empty key set'))
  }

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
