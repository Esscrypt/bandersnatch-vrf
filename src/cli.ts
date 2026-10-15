import { readFileSync, writeFileSync } from 'node:fs'
import { bytesToHex } from 'viem'
import { IETFVRFProver, type IETFVRFResult } from './prover/ietf.ts'
import { type PedersenVRFInput, PedersenVRFProver } from './prover/pedersen.ts'
import { type RingVRFInput, RingVRFProver } from './prover/ring-kzg.ts'
import { RingVRFProverWasm } from './prover/ring-kzg-wasm.ts'
import type { IETFVRFVerifier } from './verifier/ietf.ts'
import { IETFVRFVerifierWasm } from './verifier/ietf-wasm.ts'
import { PedersenVRFVerifier } from './verifier/pedersen.ts'
import { RingVRFVerifier } from './verifier/ring.ts'
import { RingVRFVerifierWasm } from './verifier/ring-wasm.ts'

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

function bytesToHexString(bytes: Uint8Array): string {
  return bytesToHex(bytes)
}

function loadJson<T>(path: string): T {
  try {
    const content = readFileSync(path, 'utf-8')
    return JSON.parse(content) as T
  } catch (error) {
    throw new Error(`Failed to load JSON from ${path}: ${error}`)
  }
}

function writeJson(path: string, data: unknown): void {
  try {
    writeFileSync(path, JSON.stringify(data, null, 2), 'utf-8')
  } catch (error) {
    throw new Error(`Failed to write JSON to ${path}: ${error}`)
  }
}

interface IETFProveInput {
  secretKey?: string
  input?: string
  auxData?: string
  sk?: string
  alpha?: string
  ad?: string
}

interface IETFProveOutput {
  gamma: string
  proof: string
}

interface IETFVerifyInput {
  publicKey?: string
  input?: string
  proof?: string
  auxData?: string
  pk?: string
  alpha?: string
  gamma?: string
  proof_c?: string
  proof_s?: string
  ad?: string
}

interface PedersenProveInput {
  secretKey: string
  input: string
  auxData?: string
}

interface PedersenProveOutput {
  gamma: string
  proof: string
}

interface PedersenVerifyInput {
  input: string
  gamma: string
  proof: string
  auxData?: string
}

interface RingProveInput {
  secretKey: string
  input: string
  auxData?: string
  ringKeys: string[]
  proverIndex: number
  srsFilePath: string
  useWasm?: boolean
}

interface RingProveOutput {
  gamma: string
  hash: string
  proof: {
    pedersenProof: string
    ringCommitment: string
    ringProof: string
    proverIndex?: number
  }
  serialized: string
}

interface RingVerifyInput {
  ringKeys: string[]
  input: string
  serializedResult: string
  auxData?: string
  srsFilePath: string
  useWasm?: boolean
}

export async function proveIETF(
  inputPath: string,
  outputPath?: string,
): Promise<void> {
  const input = loadJson<IETFProveInput>(inputPath)

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

export async function verifyIETF(
  inputPath: string,
  verifier: IETFVRFVerifier | IETFVRFVerifierWasm,
): Promise<void> {
  const input = loadJson<IETFVerifyInput>(inputPath)

  const publicKeyHex = input.publicKey ?? input.pk
  const inputHex = input.input ?? input.alpha ?? ''
  const auxDataHex = input.auxData ?? input.ad

  if (!publicKeyHex) {
    throw new Error('Missing publicKey or pk field in input JSON')
  }

  let proof: Uint8Array
  if (input.proof) {
    proof = hexToBytes(input.proof)
  } else if (input.gamma && input.proof_c && input.proof_s) {
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

  const serialized = RingVRFProver.serialize(result)

  const output: RingProveOutput = {
    gamma: bytesToHexString(result.gamma),
    hash: '',
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

export async function verifyRing(inputPath: string): Promise<void> {
  const input = loadJson<RingVerifyInput>(inputPath)

  const ringKeys = input.ringKeys.map(hexToBytes)
  const ringInput: RingVRFInput = {
    input: hexToBytes(input.input),
    auxData: input.auxData ? hexToBytes(input.auxData) : undefined,
    ringKeys,
    proverIndex: 0,
  }
  const serializedResult = hexToBytes(input.serializedResult)

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

if (import.meta.url === `file://${process.argv[1]}`) {
  runCLI().catch((error) => {
    console.error('Unhandled error:', error)
    process.exit(1)
  })
}
