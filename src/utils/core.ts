/**
 * Local implementations of core utilities used by audit-signature, announcement, and tests.
 *
 * Gray Paper references: utilities.tex (shuffle), crypto (blake2b, Ed25519), JIP-5 key derivation.
 * Exports: concatBytes, blake2bHash, jamShuffle, signEd25519, verifyEd25519, hex/bytes helpers,
 * generateTrivialSeed, deriveSecretSeeds, generateEd25519KeyPairFromSeed, generateValidatorKeyPairFromSeed,
 * generateDevAccountValidatorKeyPair.
 *
 * @module core
 */

import { bls12_381 } from '@noble/curves/bls12-381.js'
import * as ed from '@noble/ed25519'
import { BandersnatchCurve } from '@pbnjam/bandersnatch'
import { blake2b } from '@noble/hashes/blake2.js'
import { sha512 } from '@noble/hashes/sha2.js'
import type { ValidatorCredentials } from '@pbnjam/types'
import { type Safe, safeError, safeResult } from '@pbnjam/types'
import { bytesToHex, type Hex, hexToBytes } from 'viem'

ed.hashes.sha512 = (...m: Uint8Array[]) =>
  sha512(ed.etc.concatBytes(...m))

export type { Hex }
export { bytesToHex, hexToBytes }

/**
 * Concatenate multiple byte arrays into a single Uint8Array.
 *
 * @param bytes - Array of Uint8Array instances to concatenate
 * @returns A new Uint8Array containing all bytes in order
 */
export function concatBytes(bytes: Uint8Array[]): Uint8Array {
  const totalLength = bytes.reduce((acc, curr) => acc + curr.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const b of bytes) {
    result.set(b, offset)
    offset += b.length
  }
  return result
}

/**
 * Blake2b hash (32-byte output), returns hex string.
 *
 * @param data - Input bytes to hash
 * @returns Safe result with 64-character hex string (with or without 0x prefix from viem)
 */
export function blake2bHash(data: Uint8Array): Safe<Hex> {
  try {
    const hash = blake2b(data, { dkLen: 32 })
    return safeResult(bytesToHex(hash))
  } catch (error) {
    return safeError(error as Error)
  }
}

function fromLittleEndianBytes(bytes: Uint8Array): number {
  let result = 0
  for (let i = 0; i < bytes.length; i++) {
    result += bytes[i] * 256 ** i
  }
  return result >>> 0
}

function toLittleEndianBytes(value: number, length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    bytes[i] = (value >>> (i * 8)) & 0xff
  }
  return bytes
}

function computeQSequence(entropy: Uint8Array, length: number): number[] {
  const result: number[] = []
  for (let i = 0; i < length; i++) {
    const preimage = new Uint8Array(entropy.length + 4)
    preimage.set(entropy, 0)
    preimage.set(toLittleEndianBytes(Math.floor(i / 8), 4), entropy.length)
    const hashResult = blake2b(preimage, { dkLen: 32 })
    const offset = (4 * i) % 32
    const slice = hashResult.slice(offset, offset + 4)
    result.push(fromLittleEndianBytes(slice))
  }
  return result
}

function fisherYatesShuffle<T>(sequence: T[], randomSequence: number[]): T[] {
  if (sequence.length === 0) return []
  const length = sequence.length
  const index = randomSequence[0] % length
  const head = sequence[index]
  const sequencePost = [...sequence]
  sequencePost[index] = sequence[length - 1]
  const truncatedSequence = sequencePost.slice(0, -1)
  const remaining = fisherYatesShuffle(
    truncatedSequence,
    randomSequence.slice(1),
  )
  return [head, ...remaining]
}

/**
 * JAM Gray Paper Fisher-Yates Shuffle (Equation 331).
 * Shuffles an array using entropy from a 32-byte hash (Hex).
 *
 * @param input - Array to shuffle
 * @param entropy - 32-byte hash as Hex (64 hex chars, optional 0x prefix)
 * @returns New array with elements in shuffled order
 */
export function jamShuffle<T>(input: T[], entropy: Hex): T[] {
  if (input.length === 0) return []
  if (input.length === 1) return [...input]

  const cleanEntropy = entropy.startsWith('0x') ? entropy.slice(2) : entropy
  if (cleanEntropy.length !== 64) {
    throw new Error(
      `Invalid entropy length: expected 64 hex chars, got ${cleanEntropy.length}`,
    )
  }

  const entropyBytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    entropyBytes[i] = Number.parseInt(
      cleanEntropy.slice(i * 2, i * 2 + 2),
      16,
    )
  }

  const randomSequence = computeQSequence(entropyBytes, input.length)
  return fisherYatesShuffle([...input], randomSequence)
}

/**
 * Sign data with Ed25519 private key (32-byte seed).
 *
 * @param data - Message bytes to sign
 * @param privateKey - Ed25519 secret key (32 bytes)
 * @returns Safe result with 64-byte Ed25519 signature
 */
export function signEd25519(
  data: Uint8Array,
  privateKey: Uint8Array,
): Safe<Uint8Array> {
  if (privateKey.length !== 32) {
    return safeError(
      new Error(
        `Ed25519 private key must be 32 bytes, got ${privateKey.length}`,
      ),
    )
  }
  return safeResult(ed.sign(data, privateKey))
}

/**
 * Verify Ed25519 signature (64 bytes) against data and public key (32 bytes).
 *
 * @param data - Message bytes that were signed
 * @param signature - 64-byte Ed25519 signature
 * @param publicKey - Ed25519 public key (32 bytes)
 * @returns Safe result with true if signature is valid
 */
export function verifyEd25519(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): Safe<boolean> {
  if (signature.length !== 64) {
    return safeError(new Error('Signature must be 64 bytes'))
  }
  return safeResult(ed.verify(signature, data, publicKey))
}

function mod(a: bigint, m: bigint): bigint {
  const result = a % m
  return result < 0n ? result + m : result
}

/**
 * Generate trivial seed from 32-bit unsigned integer (JIP-5 dev account).
 *
 * @param index - Validator index (0 <= index <= 2^32 - 1)
 * @returns Safe result with 32-byte seed (little-endian repetition of index)
 */
export function generateTrivialSeed(index: number): Safe<Uint8Array> {
  if (index < 0 || index > 0xffffffff) {
    return safeError(new Error('Index must be a 32-bit unsigned integer'))
  }
  const seed = new Uint8Array(32)
  for (let i = 0; i < 8; i++) {
    seed[i * 4] = index & 0xff
    seed[i * 4 + 1] = (index >> 8) & 0xff
    seed[i * 4 + 2] = (index >> 16) & 0xff
    seed[i * 4 + 3] = (index >> 24) & 0xff
  }
  return safeResult(seed)
}

/**
 * JIP-5: derive Ed25519, Bandersnatch, and BLS secret seeds from 32-byte seed.
 *
 * @param seed - Master seed (32 bytes)
 * @returns Safe result with ed25519SecretSeed, bandersnatchSecretSeed, blsSecretSeed (each 32 bytes as Uint8Array)
 */
export function deriveSecretSeeds(seed: Uint8Array): Safe<{
  ed25519SecretSeed: Uint8Array
  bandersnatchSecretSeed: Uint8Array
  blsSecretSeed: Uint8Array
}> {
  if (seed.length !== 32) {
    return safeError(new Error('Seed must be exactly 32 bytes'))
  }
  const ed25519String = new TextEncoder().encode('jam_val_key_ed25519')
  const bandersnatchString = new TextEncoder().encode('jam_val_key_bandersnatch')
  const blsString = new TextEncoder().encode('jam_val_key_bls')

  const ed25519Input = new Uint8Array(ed25519String.length + seed.length)
  ed25519Input.set(ed25519String, 0)
  ed25519Input.set(seed, ed25519String.length)
  const bandersnatchInput = new Uint8Array(bandersnatchString.length + seed.length)
  bandersnatchInput.set(bandersnatchString, 0)
  bandersnatchInput.set(seed, bandersnatchString.length)
  const blsInput = new Uint8Array(blsString.length + seed.length)
  blsInput.set(blsString, 0)
  blsInput.set(seed, blsString.length)

  const [error, ed25519SecretSeed] = blake2bHash(ed25519Input)
  if (error) return safeError(error)
  const [error2, bandersnatchSecretSeed] = blake2bHash(bandersnatchInput)
  if (error2) return safeError(error2)
  const [error3, blsSecretSeed] = blake2bHash(blsInput)
  if (error3) return safeError(error3)

  return safeResult({
    ed25519SecretSeed: hexToBytes(ed25519SecretSeed),
    bandersnatchSecretSeed: hexToBytes(bandersnatchSecretSeed),
    blsSecretSeed: hexToBytes(blsSecretSeed),
  })
}

/**
 * Generate Ed25519 key pair from 32-byte seed.
 *
 * @param seed - 32-byte secret seed
 * @returns Safe result with publicKey and privateKey (Uint8Array)
 */
export function generateEd25519KeyPairFromSeed(
  seed: Uint8Array,
): Safe<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  const keyPair = ed.keygen(seed)
  return safeResult({
    publicKey: keyPair.publicKey,
    privateKey: keyPair.secretKey,
  })
}

/**
 * Generate BLS key pair from 32-byte seed.
 */
function generateBLSKeyPairFromSeed(
  blsSecretSeed: Uint8Array,
): Safe<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  const blss = bls12_381.shortSignatures
  const publicKey = blss.getPublicKey(blsSecretSeed).toBytes(false)
  return safeResult({ publicKey, privateKey: blsSecretSeed })
}

/**
 * Generate Bandersnatch key pair from seed (JIP-5: SHA512 + little-endian + mod curve order).
 */
function generateBandersnatchKeyPairFromSeed(
  bandersnatchSecretSeed: Uint8Array,
): Safe<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  try {
    const hashBytes = sha512(bandersnatchSecretSeed)
    let v = 0n
    for (let i = 0; i < hashBytes.length; i++) {
      v += BigInt(hashBytes[i]) << (8n * BigInt(i))
    }
    const privateKeyScalar = mod(v, BandersnatchCurve.CURVE_ORDER)
    if (privateKeyScalar === 0n) {
      return safeError(new Error('Generated scalar is zero, invalid for bandersnatch'))
    }
    const publicKeyPoint = BandersnatchCurve.scalarMultiply(
      BandersnatchCurve.GENERATOR,
      privateKeyScalar,
    )
    const publicKey = BandersnatchCurve.pointToBytes(publicKeyPoint)
    const privateKeyBytes = new Uint8Array(32)
    let temp = privateKeyScalar
    for (let i = 0; i < 32; i++) {
      privateKeyBytes[i] = Number(temp & 0xffn)
      temp >>= 8n
    }
    return safeResult({ publicKey, privateKey: privateKeyBytes })
  } catch (error) {
    return safeError(
      new Error(
        `Failed to generate Bandersnatch key pair: ${error instanceof Error ? error.message : String(error)}`,
      ),
    )
  }
}

/**
 * Generate validator key pair from 32-byte seed (Ed25519, BLS, Bandersnatch).
 */
export function generateValidatorKeyPairFromSeed(
  seed: Uint8Array,
): Safe<ValidatorCredentials> {
  const [error, secretSeeds] = deriveSecretSeeds(seed)
  if (error) return safeError(error)

  const [ed25519Error, ed25519KeyPair] = generateEd25519KeyPairFromSeed(secretSeeds.ed25519SecretSeed)
  if (ed25519Error) return safeError(ed25519Error)

  const [blsError, blsKeyPair] = generateBLSKeyPairFromSeed(secretSeeds.blsSecretSeed)
  if (blsError) return safeError(blsError)

  const [bandersnatchError, bandersnatchKeyPair] =
    generateBandersnatchKeyPairFromSeed(secretSeeds.bandersnatchSecretSeed)
  if (bandersnatchError) return safeError(bandersnatchError)

  const metadata = new Uint8Array(128)
  return safeResult({
    bandersnatchKeyPair,
    ed25519KeyPair: ed25519KeyPair!,
    blsKeyPair,
    seed,
    metadata,
  })
}

/**
 * Generate dev account validator key pair from validator index (JIP-5 trivial seed).
 *
 * @param validatorIndex - Validator index (0 <= index <= 2^32 - 1)
 * @returns Safe result with ValidatorCredentials
 */
export function generateDevAccountValidatorKeyPair(
  validatorIndex: number,
): Safe<ValidatorCredentials> {
  const [seedError, seed] = generateTrivialSeed(validatorIndex)
  if (seedError) return safeError(seedError)
  return generateValidatorKeyPairFromSeed(seed!)
}
