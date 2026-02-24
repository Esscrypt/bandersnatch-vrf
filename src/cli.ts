/**
 * CLI for Bandersnatch VRF
 *
 * Provides command-line interface for proving and verifying VRF proofs
 * using JSON file inputs
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { bytesToHex } from 'viem'
import { IETFVRFProver, type IETFVRFResult } from './prover/ietf'
import { type PedersenVRFInput, PedersenVRFProver } from './prover/pedersen'
import { type RingVRFInput, RingVRFProver } from './prover/ring-kzg'
import { RingVRFProverWasm } from './prover/ring-kzg-wasm'
import type { IETFVRFVerifier } from './verifier/ietf'
import { IETFVRFVerifierWasm } from './verifier/ietf-wasm'
import { PedersenVRFVerifier } from './verifier/pedersen'
import { RingVRFVerifier } from './verifier/ring'
import { RingVRFVerifierWasm } from './verifier/ring-wasm'

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string | undefined | null): Uint8Array {
  if (!hex) {
    return new Uint8Array(0)
  }
  if (typeof hex !== 'string') {
    throw new Error(`Expected hex string, got ${typeof hex}`)
  }
  if (hex.startsWith('0x')) {
    hex = hex.slice(2)
  }
  if (hex === '') {
    return new Uint8Array(0)
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

/**
 * Convert Uint8Array to hex string
 */
function bytesToHexString(bytes: Uint8Array): string {
  return bytesToHex(bytes)
}

/**
 * Load JSON from file
 */
function loadJson<T>(path: string): T {
  try {
    const content = readFileSync(path, 'utf-8')
    return JSON.parse(content) as T
  } catch (error) {
    throw new Error(`Failed to load JSON from ${path}: ${error}`)
  }
}

/**
 * Write JSON to file
 */
function writeJson(path: string, data: unknown): void {
  try {
    writeFileSync(path, JSON.stringify(data, null, 2), 'utf-8')
  } catch (error) {
    throw new Error(`Failed to write JSON to ${path}: ${error}`)
  }
}

/**
 * IETF VRF Prove Input
 * Supports both formats:
 * - CLI format: { secretKey, input, auxData? }
 * - Test vector format: { sk, alpha, ad? }
 */
interface IETFProveInput {
  secretKey?: string // hex string (CLI format)
  input?: string // hex string (CLI format)
  auxData?: string // hex string (optional, CLI format)
  sk?: string // hex string (test vector format)
  alpha?: string // hex string (test vector format)
  ad?: string // hex string (optional, test vector format)
}

/**
 * IETF VRF Prove Output
 */
interface IETFProveOutput {
  gamma: string // hex string
  proof: string // hex string
}

/**
 * IETF VRF Verify Input
 * Supports both formats:
 * - CLI format: { publicKey, input, proof, auxData? }
 * - Test vector format: { pk, alpha, gamma, proof_c, proof_s, ad? }
 */
interface IETFVerifyInput {
  publicKey?: string // hex string (CLI format)
  input?: string // hex string (CLI format)
  proof?: string // hex string (CLI format - 96 bytes: gamma + c + s)
  auxData?: string // hex string (optional, CLI format)
  pk?: string // hex string (test vector format)
  alpha?: string // hex string (test vector format)
  gamma?: string // hex string (test vector format - 32 bytes)
  proof_c?: string // hex string (test vector format - 32 bytes)
  proof_s?: string // hex string (test vector format - 32 bytes)
  ad?: string // hex string (optional, test vector format)
}

/**
 * Pedersen VRF Prove Input
 */
interface PedersenProveInput {
  secretKey: string // hex string
  input: string // hex string
  auxData?: string // hex string (optional)
}

/**
 * Pedersen VRF Prove Output
 */
interface PedersenProveOutput {
  gamma: string // hex string
  proof: string // hex string
}

/**
 * Pedersen VRF Verify Input
 */
interface PedersenVerifyInput {
  input: string // hex string
  gamma: string // hex string
  proof: string // hex string
  auxData?: string // hex string (optional)
}

/**
 * Ring VRF Prove Input
 */
interface RingProveInput {
  secretKey: string // hex string
  input: string // hex string
  auxData?: string // hex string (optional)
  ringKeys: string[] // array of hex strings
  proverIndex: number
  srsFilePath: string
  useWasm?: boolean // default: false
}

/**
 * Ring VRF Prove Output
 */
interface RingProveOutput {
  gamma: string // hex string
  hash: string // hex string
  proof: {
    pedersenProof: string // hex string
    ringCommitment: string // hex string
    ringProof: string // hex string
    proverIndex?: number
  }
  serialized: string // hex string
}

/**
 * Ring VRF Verify Input
 */
interface RingVerifyInput {
  ringKeys: string[] // array of hex strings
  input: string // hex string
  serializedResult: string // hex string
  auxData?: string // hex string (optional)
  srsFilePath: string
  useWasm?: boolean // default: false
}

/**
 * Prove IETF VRF
 */
export async function proveIETF(
  inputPath: string,
  outputPath?: string,
): Promise<void> {
  const input = loadJson<IETFProveInput>(inputPath)

  // Support both CLI format and test vector format
  const secretKeyHex = input.secretKey ?? input.sk
  const inputHex = input.input ?? input.alpha ?? ''
  const auxDataHex = input.auxData ?? input.ad

  if (!secretKeyHex) {
    throw new Error('Missing secretKey or sk field in input JSON')
  }

  const secretKey = hexToBytes(secretKeyHex)
  const inputData = hexToBytes(inputHex)
  const auxData = auxDataHex ? hexToBytes(auxDataHex) : undefined

  const result: IETFVRFResult = IETFVRFProver.prove(
    secretKey,
    inputData,
    auxData,
  )

  const output: IETFProveOutput = {
    gamma: bytesToHexString(result.gamma),
    proof: bytesToHexString(result.proof),
  }

  if (outputPath) {
    writeJson(outputPath, output)
    console.log(`Proof written to ${outputPath}`)
  } else {
    console.log(JSON.stringify(output, null, 2))
  }
}

/**
 * Verify IETF VRF
 */
export async function verifyIETF(
  inputPath: string,
  verifier: IETFVRFVerifier | IETFVRFVerifierWasm,
): Promise<void> {
  const input = loadJson<IETFVerifyInput>(inputPath)

  // Support both CLI format and test vector format
  const publicKeyHex = input.publicKey ?? input.pk
  const inputHex = input.input ?? input.alpha ?? ''
  const auxDataHex = input.auxData ?? input.ad

  if (!publicKeyHex) {
    throw new Error('Missing publicKey or pk field in input JSON')
  }

  // Handle proof: either direct proof (CLI format) or construct from test vector format
  let proof: Uint8Array
  if (input.proof) {
    // CLI format: proof is already combined (96 bytes: gamma + c + s)
    proof = hexToBytes(input.proof)
  } else if (input.gamma && input.proof_c && input.proof_s) {
    // Test vector format: combine gamma (32) + proof_c (32) + proof_s (32) = 96 bytes
    const gammaBytes = hexToBytes(input.gamma)
    const cBytes = hexToBytes(input.proof_c)
    const sBytes = hexToBytes(input.proof_s)
    proof = new Uint8Array(96)
    proof.set(gammaBytes, 0)
    proof.set(cBytes, 32)
    proof.set(sBytes, 64)
  } else {
    throw new Error(
      'Missing proof field or (gamma, proof_c, proof_s) fields in input JSON',
    )
  }

  const publicKey = hexToBytes(publicKeyHex)
  const inputData = hexToBytes(inputHex)
  const auxData = auxDataHex ? hexToBytes(auxDataHex) : undefined

  const isValid = verifier.verify(publicKey, inputData, proof, auxData)

  const result = {
    valid: isValid,
    message: isValid ? 'Proof is valid' : 'Proof is invalid',
  }

  console.log(JSON.stringify(result, null, 2))

  if (!isValid) {
    process.exit(1)
  }
}

/**
 * Prove Pedersen VRF
 */
export async function provePedersen(
  inputPath: string,
  outputPath?: string,
): Promise<void> {
  const input = loadJson<PedersenProveInput>(inputPath)

  const secretKey = hexToBytes(input.secretKey)
  const pedersenInput: PedersenVRFInput = {
    input: hexToBytes(input.input),
    auxData: input.auxData ? hexToBytes(input.auxData) : undefined,
  }

  const result = PedersenVRFProver.prove(secretKey, pedersenInput)

  const output: PedersenProveOutput = {
    gamma: bytesToHexString(result.gamma),
    proof: bytesToHexString(result.proof),
  }

  if (outputPath) {
    writeJson(outputPath, output)
    console.log(`Proof written to ${outputPath}`)
  } else {
    console.log(JSON.stringify(output, null, 2))
  }
}

/**
 * Verify Pedersen VRF
 */
export async function verifyPedersen(inputPath: string): Promise<void> {
  const input = loadJson<PedersenVerifyInput>(inputPath)

  const inputData = hexToBytes(input.input)
  const gamma = hexToBytes(input.gamma)
  const proof = hexToBytes(input.proof)
  const auxData = input.auxData ? hexToBytes(input.auxData) : undefined

  const isValid = PedersenVRFVerifier.verify(inputData, gamma, proof, auxData)

  const result = {
    valid: isValid,
    message: isValid ? 'Proof is valid' : 'Proof is invalid',
  }

  console.log(JSON.stringify(result, null, 2))

  if (!isValid) {
    process.exit(1)
  }
}

/**
 * Prove Ring VRF
 */
export async function proveRing(
  inputPath: string,
  outputPath?: string,
): Promise<void> {
  const input = loadJson<RingProveInput>(inputPath)

  const secretKey = hexToBytes(input.secretKey)
  const ringKeys = input.ringKeys.map(hexToBytes)

  const ringInput: RingVRFInput = {
    input: hexToBytes(input.input),
    auxData: input.auxData ? hexToBytes(input.auxData) : undefined,
    ringKeys,
    proverIndex: input.proverIndex,
  }

  const useWasm = input.useWasm ?? false

  let result
  if (useWasm) {
    const prover = new RingVRFProverWasm(input.srsFilePath)
    await prover.init()
    result = prover.prove(secretKey, ringInput)
  } else {
    const prover = new RingVRFProver(input.srsFilePath, input.ringKeys.length)
    result = prover.prove(secretKey, ringInput)
  }

  // Use RingVRFProver.serialize for both (it's a static method)
  const serialized = RingVRFProver.serialize(result)

  const output: RingProveOutput = {
    gamma: bytesToHexString(result.gamma),
    hash: '', // RingVRFResult doesn't have hash property
    proof: {
      pedersenProof: bytesToHexString(result.proof.pedersenProof),
      ringCommitment: bytesToHexString(result.proof.ringCommitment),
      ringProof: bytesToHexString(result.proof.ringProof),
      proverIndex: result.proof.proverIndex,
    },
    serialized: bytesToHexString(serialized),
  }

  if (outputPath) {
    writeJson(outputPath, output)
    console.log(`Proof written to ${outputPath}`)
  } else {
    console.log(JSON.stringify(output, null, 2))
  }
}

/**
 * Verify Ring VRF
 */
export async function verifyRing(inputPath: string): Promise<void> {
  const input = loadJson<RingVerifyInput>(inputPath)

  const ringKeys = input.ringKeys.map(hexToBytes)
  const ringInput: RingVRFInput = {
    input: hexToBytes(input.input),
    auxData: input.auxData ? hexToBytes(input.auxData) : undefined,
    ringKeys,
    proverIndex: 0, // Not used in verification
  }
  const serializedResult = hexToBytes(input.serializedResult)

  // Deserialize the result first
  const deserializedResult = RingVRFProver.deserialize(serializedResult)

  const useWasm = input.useWasm ?? false

  let isValid: boolean
  if (useWasm) {
    const verifier = new RingVRFVerifierWasm(input.srsFilePath)
    await verifier.init()
    isValid = verifier.verify(
      ringKeys,
      ringInput,
      deserializedResult,
      ringInput.auxData,
    )
  } else {
    const verifier = new RingVRFVerifier(input.srsFilePath, ringKeys.length)
    isValid = verifier.verify(
      ringKeys,
      ringInput,
      deserializedResult,
      ringInput.auxData,
    )
  }

  const verificationResult = {
    valid: isValid,
    message: isValid ? 'Proof is valid' : 'Proof is invalid',
  }

  console.log(JSON.stringify(verificationResult, null, 2))

  if (!isValid) {
    process.exit(1)
  }
}

/**
 * Main CLI entry point
 */
export async function runCLI(): Promise<void> {
  const args = process.argv.slice(2)

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log(`
Bandersnatch VRF CLI

Usage:
  bandersnatch-vrf <command> <scheme> [options]

Commands:
  prove    Generate a VRF proof
  verify    Verify a VRF proof

Schemes:
  ietf      IETF VRF (RFC-9381-style)
  pedersen  Pedersen VRF (with blinding)
  ring      Ring VRF (Pedersen VRF + KZG ring membership)

Examples:
  # Prove IETF VRF
  bandersnatch-vrf prove ietf --input input.json --output proof.json

  # Verify IETF VRF
  bandersnatch-vrf verify ietf --input verify.json

  # Prove Pedersen VRF
  bandersnatch-vrf prove pedersen --input input.json --output proof.json

  # Verify Pedersen VRF
  bandersnatch-vrf verify pedersen --input verify.json

  # Prove Ring VRF
  bandersnatch-vrf prove ring --input input.json --output proof.json

  # Verify Ring VRF
  bandersnatch-vrf verify ring --input verify.json

Options:
  --input <path>    Path to JSON input file (required)
  --output <path>   Path to JSON output file (optional, defaults to stdout)
  --help, -h        Show this help message
`)
    process.exit(0)
  }

  const command = args[0]
  const scheme = args[1]

  if (!command || !scheme) {
    console.error('Error: command and scheme are required')
    console.log('Use --help for usage information')
    process.exit(1)
  }

  // Parse options
  let inputPath: string | undefined
  let outputPath: string | undefined

  for (let i = 2; i < args.length; i++) {
    if (args[i] === '--input' && i + 1 < args.length) {
      inputPath = args[i + 1]
      i++
    } else if (args[i] === '--output' && i + 1 < args.length) {
      outputPath = args[i + 1]
      i++
    }
  }

  if (!inputPath) {
    console.error('Error: --input is required')
    process.exit(1)
  }

  const verifier: IETFVRFVerifier | IETFVRFVerifierWasm =
    new IETFVRFVerifierWasm()

  try {
    if (command === 'prove') {
      if (scheme === 'ietf') {
        await proveIETF(inputPath, outputPath)
      } else if (scheme === 'pedersen') {
        await provePedersen(inputPath, outputPath)
      } else if (scheme === 'ring') {
        await proveRing(inputPath, outputPath)
      } else {
        console.error(`Error: Unknown scheme: ${scheme}`)
        process.exit(1)
      }
    } else if (command === 'verify') {
      if (scheme === 'ietf') {
        await verifyIETF(inputPath, verifier)
      } else if (scheme === 'pedersen') {
        await verifyPedersen(inputPath)
      } else if (scheme === 'ring') {
        await verifyRing(inputPath)
      } else {
        console.error(`Error: Unknown scheme: ${scheme}`)
        process.exit(1)
      }
    } else {
      console.error(`Error: Unknown command: ${command}`)
      process.exit(1)
    }
  } catch (error) {
    console.error(
      'Error:',
      error instanceof Error ? error.message : String(error),
    )
    process.exit(1)
  }
}

// Run CLI if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runCLI().catch((error) => {
    console.error('Unhandled error:', error)
    process.exit(1)
  })
}
