import { BandersnatchCurve } from '@pbnjam/bandersnatch'
import {
  getBanderoutFromGamma,
  IETFVRFProver,
  type IETFVRFVerifier,
  type IETFVRFVerifierWasm,
} from '@pbnjam/bandersnatch-vrf'
import type { Safe } from '@pbnjam/types'
import { safeError, safeResult } from '@pbnjam/types'
import { bytesToHex } from 'viem'
import { getCommitmentFromGamma } from './gamma.ts'

const XENTROPY = new TextEncoder().encode('jam_entropy')

export function generateEntropyVRFSignature(
  validatorSecretKey: Uint8Array,
  sealOutput: Uint8Array,
): Safe<{
  signature: Uint8Array
  banderoutResult: Uint8Array
}> {
  if (validatorSecretKey.length !== 32) {
    return safeError(new Error('Validator secret key must be 32 bytes'))
  }

  if (sealOutput.length !== 32) {
    return safeError(new Error('Seal output must be 32 bytes'))
  }

  const context = new Uint8Array(XENTROPY.length + sealOutput.length)
  let offset = 0
  context.set(XENTROPY, offset)
  offset += XENTROPY.length
  context.set(sealOutput, offset)

  const vrfResult = IETFVRFProver.prove(
    validatorSecretKey,
    context,
    new Uint8Array(0),
  )

  if (vrfResult.proof.length !== 96) {
    console.warn('IETF VRF signature has unexpected length', {
      expected: 96,
      actual: vrfResult.proof.length,
    })
  }

  const banderoutResult = getBanderoutFromGamma(vrfResult.gamma)

  return safeResult({
    signature: vrfResult.proof,
    banderoutResult,
  })
}

export function verifyEntropyVRFSignature(
  validatorPublicKey: Uint8Array,
  signature: Uint8Array,
  sealOutput: Uint8Array,
  verifier: IETFVRFVerifier | IETFVRFVerifierWasm,
): Safe<boolean> {
  if (validatorPublicKey.length !== 32) {
    return safeError(new Error('Validator public key must be 32 bytes'))
  }

  if (signature.length !== 96) {
    return safeError(new Error('IETF VRF signature must be 96 bytes'))
  }

  if (sealOutput.length !== 32) {
    return safeError(new Error('Seal output must be 32 bytes'))
  }

  const context = new Uint8Array(XENTROPY.length + sealOutput.length)
  let offset = 0
  context.set(XENTROPY, offset)
  offset += XENTROPY.length
  context.set(sealOutput, offset)

  let isValid: boolean
  try {
    isValid = verifier.verify(
      validatorPublicKey,
      context,
      signature,
      new Uint8Array(0),
    )
  } catch (error) {
    console.error('Entropy VRF signature verification failed', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      publicKeyHex: bytesToHex(validatorPublicKey),
      contextHex: bytesToHex(context),
      signatureHex: bytesToHex(signature),
    })

    return safeError(new Error('verifyEntropyVRFSignature error'))
  }

  if (!isValid) {
    console.error('Entropy VRF signature verification failed', {
      publicKeyHex: bytesToHex(validatorPublicKey),
      contextHex: bytesToHex(context),
      signatureHex: bytesToHex(signature),
    })
  }

  return safeResult(isValid)
}

export function banderout(sealSignature: Uint8Array): Safe<Uint8Array> {
  if (sealSignature.length !== 96) {
    return safeError(new Error('Seal signature must be 96 bytes'))
  }

  const gammaFromProof = sealSignature.slice(0, 32)

  const gammaPoint = BandersnatchCurve.bytesToPoint(gammaFromProof)
  const gamma = BandersnatchCurve.pointToBytes(gammaPoint)

  const vrfOutputHash = getCommitmentFromGamma(gamma)

  const banderoutResult = vrfOutputHash.slice(0, 32)

  return safeResult(banderoutResult)
}
