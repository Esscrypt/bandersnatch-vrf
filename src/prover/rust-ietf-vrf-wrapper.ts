import { loadIetfVrfNative } from './native-loader.ts'

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
