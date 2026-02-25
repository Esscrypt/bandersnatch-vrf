import { describe, expect, test } from 'bun:test'
import {
  generateEntropyVRFSignature,
  verifyEntropyVRFSignature,
  banderout,
} from '../utils/entropy-vrf'
import { generateDevAccountValidatorKeyPair } from '../utils/core'
import { IETFVRFVerifier } from '../verifier/ietf'

const verifier = new IETFVRFVerifier()

const [keyError, aliceKeys] = generateDevAccountValidatorKeyPair(0)
if (keyError) throw new Error(`Key generation failed: ${keyError.message}`)

const secretKey = aliceKeys.bandersnatchKeyPair.privateKey
const publicKey = aliceKeys.bandersnatchKeyPair.publicKey

describe('entropy-vrf', () => {
  describe('generateEntropyVRFSignature', () => {
    test('returns error for invalid secret key length', () => {
      const [error] = generateEntropyVRFSignature(
        new Uint8Array(16),
        new Uint8Array(32),
      )
      expect(error).toBeDefined()
      expect(error!.message).toContain('32 bytes')
    })

    test('returns error for invalid seal output length', () => {
      const [error] = generateEntropyVRFSignature(
        secretKey,
        new Uint8Array(16),
      )
      expect(error).toBeDefined()
      expect(error!.message).toContain('32 bytes')
    })

    test('produces 96-byte signature and 32-byte banderout', () => {
      const sealOutput = new Uint8Array(32).fill(0x42)
      const [error, result] = generateEntropyVRFSignature(secretKey, sealOutput)

      expect(error).toBeUndefined()
      expect(result).toBeDefined()
      expect(result!.signature.length).toBe(96)
      expect(result!.banderoutResult.length).toBe(32)
    })

    test('is deterministic for the same inputs', () => {
      const sealOutput = new Uint8Array(32).fill(0x99)
      const [, r1] = generateEntropyVRFSignature(secretKey, sealOutput)
      const [, r2] = generateEntropyVRFSignature(secretKey, sealOutput)

      expect(r1!.signature).toEqual(r2!.signature)
      expect(r1!.banderoutResult).toEqual(r2!.banderoutResult)
    })

    test('produces different outputs for different seal outputs', () => {
      const [, r1] = generateEntropyVRFSignature(
        secretKey,
        new Uint8Array(32).fill(0x01),
      )
      const [, r2] = generateEntropyVRFSignature(
        secretKey,
        new Uint8Array(32).fill(0x02),
      )

      expect(r1!.banderoutResult).not.toEqual(r2!.banderoutResult)
    })
  })

  describe('verifyEntropyVRFSignature', () => {
    const sealOutput = new Uint8Array(32).fill(0xaa)

    test('returns error for invalid public key length', () => {
      const sig = new Uint8Array(96)
      const [error] = verifyEntropyVRFSignature(
        new Uint8Array(16),
        sig,
        sealOutput,
        verifier,
      )
      expect(error).toBeDefined()
      expect(error!.message).toContain('32 bytes')
    })

    test('returns error for invalid signature length', () => {
      const [error] = verifyEntropyVRFSignature(
        publicKey,
        new Uint8Array(64),
        sealOutput,
        verifier,
      )
      expect(error).toBeDefined()
      expect(error!.message).toContain('96 bytes')
    })

    test('returns error for invalid seal output length', () => {
      const [error] = verifyEntropyVRFSignature(
        publicKey,
        new Uint8Array(96),
        new Uint8Array(16),
        verifier,
      )
      expect(error).toBeDefined()
      expect(error!.message).toContain('32 bytes')
    })

    test('round-trip: generated signature verifies successfully', () => {
      const [, genResult] = generateEntropyVRFSignature(secretKey, sealOutput)
      const [error, isValid] = verifyEntropyVRFSignature(
        publicKey,
        genResult!.signature,
        sealOutput,
        verifier,
      )

      expect(error).toBeUndefined()
      expect(isValid).toBe(true)
    })

    test('rejects signature with wrong seal output', () => {
      const [, genResult] = generateEntropyVRFSignature(secretKey, sealOutput)
      const wrongSeal = new Uint8Array(32).fill(0xff)
      const [error, isValid] = verifyEntropyVRFSignature(
        publicKey,
        genResult!.signature,
        wrongSeal,
        verifier,
      )

      expect(error).toBeUndefined()
      expect(isValid).toBe(false)
    })

    test('rejects signature with wrong public key', () => {
      const [, genResult] = generateEntropyVRFSignature(secretKey, sealOutput)
      const [, bobKeys] = generateDevAccountValidatorKeyPair(1)
      const [error, isValid] = verifyEntropyVRFSignature(
        bobKeys!.bandersnatchKeyPair.publicKey,
        genResult!.signature,
        sealOutput,
        verifier,
      )

      expect(error).toBeUndefined()
      expect(isValid).toBe(false)
    })
  })

  describe('banderout', () => {
    test('returns error for invalid seal signature length', () => {
      const [error] = banderout(new Uint8Array(64))
      expect(error).toBeDefined()
      expect(error!.message).toContain('96 bytes')
    })

    test('extracts 32-byte output from valid signature', () => {
      const sealOutput = new Uint8Array(32).fill(0x55)
      const [, genResult] = generateEntropyVRFSignature(secretKey, sealOutput)

      // Build a 96-byte "seal signature" from gamma (32) + proof (64-byte challenge+scalar)
      // The banderout function expects gamma in the first 32 bytes
      const gamma = genResult!.signature.slice(0, 32)
      const fullSig = new Uint8Array(96)
      fullSig.set(gamma, 0)

      const [error, result] = banderout(fullSig)
      expect(error).toBeUndefined()
      expect(result).toBeDefined()
      expect(result!.length).toBe(32)
    })

    test('is deterministic for the same input', () => {
      const sealOutput = new Uint8Array(32).fill(0x77)
      const [, genResult] = generateEntropyVRFSignature(secretKey, sealOutput)

      const fullSig = new Uint8Array(96)
      fullSig.set(genResult!.signature.slice(0, 32), 0)

      const [, r1] = banderout(fullSig)
      const [, r2] = banderout(fullSig)
      expect(r1).toEqual(r2)
    })
  })
})
