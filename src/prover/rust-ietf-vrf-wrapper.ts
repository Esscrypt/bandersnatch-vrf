/**
 * Rust napi-rs connector for IETF VRF (RFC-9381) prove and verify.
 *
 * Loads the same native module as rust-ring-proof-wrapper.
 * Falls back gracefully when the native module is not built.
 */

import { existsSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'

const require = createRequire(import.meta.url)

/** Filesystem fallback paths for compiled bun binaries (mirrors pvm-rust-executor pattern). */
function getIetfVrfNativeFallbackPaths(): string[] {
  const execDir = dirname(process.execPath)
  const cwd = process.cwd()
  return [
    join(execDir, 'node_modules', 'pbnjam-ring-proof-native', 'native'),
    join(execDir, '..', 'node_modules', 'pbnjam-ring-proof-native', 'native'),
    join(cwd, 'node_modules', 'pbnjam-ring-proof-native', 'native'),
    join(cwd, 'packages', 'bandersnatch-vrf', 'rust-ring-proof', 'native'),
  ]
}

function loadIetfVrfNative(): {
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
} | null {
  // 1. Package name (works with NODE_PATH or normal node_modules resolution)
  try {
    return require('pbnjam-ring-proof-native/native')
  } catch {}
  // 2. Relative path (works in dev when running from source)
  try {
    return require('../../rust-ring-proof/native')
  } catch {}
  // 3. Filesystem fallback (needed for compiled bun binaries in Docker)
  for (const nativeDir of getIetfVrfNativeFallbackPaths()) {
    if (existsSync(join(nativeDir, 'index.js'))) {
      try {
        return require(nativeDir)
      } catch {}
    }
  }
  return null
}

export type ProveIetfVrfRust = (
  secretKeyBytes: Uint8Array,
  inputBytes: Uint8Array,
  auxData: Uint8Array,
) => Uint8Array

export type VerifyIetfVrfRust = (
  publicKeyBytes: Uint8Array,
  inputBytes: Uint8Array,
  proofBytes: Uint8Array,
  auxData: Uint8Array,
) => boolean

let rustProveIetfVrf: ProveIetfVrfRust | null = null
let rustVerifyIetfVrf: VerifyIetfVrfRust | null = null

try {
  const native = loadIetfVrfNative()

  if (native?.proveIetfVrf) {
    rustProveIetfVrf = (
      secretKeyBytes: Uint8Array,
      inputBytes: Uint8Array,
      auxData: Uint8Array,
    ): Uint8Array => {
      const result = native.proveIetfVrf!(
        Buffer.from(secretKeyBytes),
        Buffer.from(inputBytes),
        Buffer.from(auxData),
      )
      return new Uint8Array(result)
    }
  }

  if (native?.verifyIetfVrf) {
    rustVerifyIetfVrf = (
      publicKeyBytes: Uint8Array,
      inputBytes: Uint8Array,
      proofBytes: Uint8Array,
      auxData: Uint8Array,
    ): boolean => {
      return native.verifyIetfVrf!(
        Buffer.from(publicKeyBytes),
        Buffer.from(inputBytes),
        Buffer.from(proofBytes),
        Buffer.from(auxData),
      )
    }
  }
} catch {
  // Native module not built or not available
}

export function getRustProveIetfVrf(): ProveIetfVrfRust | null {
  return rustProveIetfVrf
}

export function isRustIetfVrfProverAvailable(): boolean {
  return rustProveIetfVrf !== null
}

export function getRustVerifyIetfVrf(): VerifyIetfVrfRust | null {
  return rustVerifyIetfVrf
}

export function isRustIetfVrfVerifierAvailable(): boolean {
  return rustVerifyIetfVrf !== null
}
