import { loadRingProofNative } from './native-loader.ts'

export type ProveThinVrfRust = (
  secretKeyBytes: Uint8Array,
  alphaBytes: Uint8Array,
  adBytes: Uint8Array,
) => Uint8Array

export type VerifyThinVrfRust = (
  publicKeyBytes: Uint8Array,
  alphaBytes: Uint8Array,
  proofBytes: Uint8Array,
  adBytes: Uint8Array,
) => boolean

export type VerifyThinVrfPartsRust = (
  publicKeyBytes: Uint8Array,
  alphaBytes: Uint8Array,
  outputPointBytes: Uint8Array,
  proofRBytes: Uint8Array,
  proofSBytes: Uint8Array,
  adBytes: Uint8Array,
) => boolean

export type ThinVrfOutputRust = (outputPointBytes: Uint8Array) => Uint8Array

let rustProveThinVrf: ProveThinVrfRust | null = null
let rustVerifyThinVrf: VerifyThinVrfRust | null = null
let rustThinVrfOutput: ThinVrfOutputRust | null = null
let rustVerifyThinVrfParts: VerifyThinVrfPartsRust | null = null

try {
  const native = loadRingProofNative()

  if (native?.proveThinVrf) {
    rustProveThinVrf = (
      secretKeyBytes: Uint8Array,
      alphaBytes: Uint8Array,
      adBytes: Uint8Array,
    ): Uint8Array =>
      new Uint8Array(
        native.proveThinVrf!(
          Buffer.from(secretKeyBytes),
          Buffer.from(alphaBytes),
          Buffer.from(adBytes),
        ),
      )
  }

  if (native?.verifyThinVrf) {
    rustVerifyThinVrf = (
      publicKeyBytes: Uint8Array,
      alphaBytes: Uint8Array,
      proofBytes: Uint8Array,
      adBytes: Uint8Array,
    ): boolean =>
      native.verifyThinVrf!(
        Buffer.from(publicKeyBytes),
        Buffer.from(alphaBytes),
        Buffer.from(proofBytes),
        Buffer.from(adBytes),
      )
  }

  if (native?.verifyThinVrfParts) {
    rustVerifyThinVrfParts = (
      publicKeyBytes: Uint8Array,
      alphaBytes: Uint8Array,
      outputPointBytes: Uint8Array,
      proofRBytes: Uint8Array,
      proofSBytes: Uint8Array,
      adBytes: Uint8Array,
    ): boolean =>
      native.verifyThinVrfParts!(
        Buffer.from(publicKeyBytes),
        Buffer.from(alphaBytes),
        Buffer.from(outputPointBytes),
        Buffer.from(proofRBytes),
        Buffer.from(proofSBytes),
        Buffer.from(adBytes),
      )
  }

  if (native?.thinVrfOutput) {
    rustThinVrfOutput = (outputPointBytes: Uint8Array): Uint8Array =>
      new Uint8Array(native.thinVrfOutput!(Buffer.from(outputPointBytes)))
  }
} catch {}

export function getRustProveThinVrf(): ProveThinVrfRust | null {
  return rustProveThinVrf
}

export function getRustVerifyThinVrf(): VerifyThinVrfRust | null {
  return rustVerifyThinVrf
}

export function getRustVerifyThinVrfParts(): VerifyThinVrfPartsRust | null {
  return rustVerifyThinVrfParts
}

export function getRustThinVrfOutput(): ThinVrfOutputRust | null {
  return rustThinVrfOutput
}
