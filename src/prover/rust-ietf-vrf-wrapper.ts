/**
 * Rust napi-rs connector for IETF VRF (RFC-9381) prove and verify.
 *
 * Loads the same native module as rust-ring-proof-wrapper.
 * Falls back gracefully when the native module is not built.
 */

import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)

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
  const native = require('../../rust-ring-proof/native') as {
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
