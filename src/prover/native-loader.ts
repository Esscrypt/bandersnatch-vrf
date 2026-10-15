import { existsSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'

export interface RingProofNativeBinding {
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
  computeRingVerifierKey?: (srsBytes: Buffer, ringKeysBytes: Buffer) => Buffer
  verifyRingVrfWithKey?: (
    vkBytes: Buffer,
    proofBytes: Buffer,
    keyCommitmentBytes: Buffer,
    ringSize: number,
  ) => boolean
  batchVerifyRingVrf?: (
    vkBytes: Buffer,
    ringSize: number,
    items: Array<{ proofBytes: Buffer; keyCommitmentBytes: Buffer }>,
  ) => boolean
  proveIetfVrf?: (
    secretKeyBytes: Buffer,
    inputBytes: Buffer,
    auxData: Buffer,
  ) => Buffer
  verifyIetfVrf?: (
    publicKeyBytes: Buffer,
    inputBytes: Buffer,
    proofBytes: Buffer,
    auxData: Buffer,
  ) => boolean
}

function getRingProofNativeFallbackPaths(): string[] {
  const execDir = dirname(process.execPath)
  const cwd = process.cwd()
  return [
    join(execDir, 'node_modules', 'pbnjam-ring-proof-native', 'native'),
    join(execDir, '..', 'node_modules', 'pbnjam-ring-proof-native', 'native'),
    join(cwd, 'node_modules', 'pbnjam-ring-proof-native', 'native'),
    join(cwd, 'packages', 'bandersnatch-vrf', 'rust-ring-proof', 'native'),
  ]
}

let cachedRingProofNative: RingProofNativeBinding | null | undefined

export function loadRingProofNative(): RingProofNativeBinding | null {
  if (cachedRingProofNative !== undefined) return cachedRingProofNative
  const require = createRequire(import.meta.url)
  try {
    cachedRingProofNative =
      require('pbnjam-ring-proof-native/native') as RingProofNativeBinding
    return cachedRingProofNative
  } catch {}
  try {
    cachedRingProofNative =
      require('../../rust-ring-proof/native') as RingProofNativeBinding
    return cachedRingProofNative
  } catch {}
  for (const nativeDir of getRingProofNativeFallbackPaths()) {
    if (existsSync(join(nativeDir, 'index.js'))) {
      try {
        cachedRingProofNative = require(nativeDir) as RingProofNativeBinding
        return cachedRingProofNative
      } catch {}
    }
  }
  cachedRingProofNative = null
  return null
}

export function loadIetfVrfNative(): RingProofNativeBinding | null {
  return loadRingProofNative()
}
