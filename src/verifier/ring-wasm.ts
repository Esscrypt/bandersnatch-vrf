/**
 * Ring VRF Verifier using WASM bindings to Rust implementation
 *
 * This implementation uses the Rust reference implementation compiled to WASM,
 * providing full compliance with the bandersnatch-vrf-spec and VG24 Plonk zkSNARK protocol.
 */

import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
// Import WASM module (from ark-vrf, matches test vectors exactly)
import initWasm, { verify_ring_proof } from '../../wasm-ark-vrf/ark_vrf_wasm'

/**
 * Find the WASM file by searching multiple possible locations
 * Works in both development and compiled binary contexts
 */
function findWasmFile(): string {
  const wasmFileName = 'ark_vrf_wasm_bg.wasm'

  // Strategy 1: Check environment variable
  const envPath = process.env['BANDERSNATCH_VRF_WASM_PATH']
  if (envPath && existsSync(envPath)) {
    return envPath
  }

  // Strategy 2: Try relative to current file location (development)
  const currentDir =
    typeof __dirname !== 'undefined'
      ? __dirname
      : dirname(fileURLToPath(import.meta.url))
  const relativePath = join(
    currentDir,
    '..',
    '..',
    'wasm-ark-vrf',
    wasmFileName,
  )
  if (existsSync(relativePath)) {
    return relativePath
  }

  // Strategy 3: Try to find workspace root and search from there
  // Walk up from current directory to find workspace root (has packages/ directory)
  let searchDir = currentDir
  for (let i = 0; i < 10; i++) {
    const packagesDir = join(searchDir, 'packages')
    const wasmPath = join(
      packagesDir,
      'bandersnatch-vrf',
      'wasm-ark-vrf',
      wasmFileName,
    )
    if (existsSync(wasmPath)) {
      return wasmPath
    }
    const parent = dirname(searchDir)
    if (parent === searchDir) break // Reached filesystem root
    searchDir = parent
  }

  // Strategy 4: Try from process.cwd() (current working directory)
  const cwd = process.cwd()
  const cwdPackagesPath = join(
    cwd,
    'packages',
    'bandersnatch-vrf',
    'wasm-ark-vrf',
    wasmFileName,
  )
  if (existsSync(cwdPackagesPath)) {
    return cwdPackagesPath
  }

  // Strategy 5: Try relative to process.cwd() if it's in the workspace
  if (cwd.includes('packages')) {
    const workspaceRoot = cwd.split('/packages')[0]
    const workspacePath = join(
      workspaceRoot,
      'packages',
      'bandersnatch-vrf',
      'wasm-ark-vrf',
      wasmFileName,
    )
    if (existsSync(workspacePath)) {
      return workspacePath
    }
  }

  // If none found, return the relative path (will throw a clear error)
  return relativePath
}

import { PedersenVRFProver } from '../prover/pedersen'
import type { RingVRFInput } from '../prover/ring-kzg'
import { PedersenVRFVerifier } from './pedersen'

/**
 * Ring VRF Verifier using WASM bindings
 * Provides full Plonk zkSNARK proof verification matching Rust reference implementation
 */
export class RingVRFVerifierWasm {
  private srsBytes: Uint8Array
  private wasmInitialized = false
  /**
   * Create a new Ring VRF Verifier instance using WASM
   *
   * @param srsFilePath - Path to SRS file (compressed format)
   */
  constructor(srsFilePath: string) {
    // Load SRS file (expects uncompressed arkworks format)
    // Replace '-compressed.bin' with '-uncompressed.bin' if needed
    this.srsBytes = readFileSync(srsFilePath)
  }

  async init(): Promise<void> {
    // Load WASM module - find file dynamically to work in both development and compiled binaries
    const wasmPath = findWasmFile()

    // Read WASM file as bytes and pass directly to avoid fetch() issues
    const wasmBytes = readFileSync(wasmPath)
    const wasmArrayBuffer = wasmBytes.buffer.slice(
      wasmBytes.byteOffset,
      wasmBytes.byteOffset + wasmBytes.byteLength,
    )

    await initWasm(wasmArrayBuffer)
    this.wasmInitialized = true
  }

  /**
   * Verify Ring VRF proof using WASM
   *
   * Steps:
   * 1. Verify Pedersen VRF proof (TypeScript implementation)
   * 2. Verify ring proof using WASM (Rust Plonk verifier)
   */
  verify(
    ringKeys: Uint8Array[],
    input: RingVRFInput,
    result: {
      gamma: Uint8Array
      proof: {
        pedersenProof: Uint8Array
        ringCommitment: Uint8Array
        ringProof: Uint8Array
      }
    },
    auxData?: Uint8Array,
  ): boolean {
    if (!this.wasmInitialized) {
      throw new Error(
        'WASM module not initialized yet. Please wait for initialization to complete. ' +
          'You can await wasmInitPromise from ring-wasm if needed.',
      )
    }

    const pedersenValid = PedersenVRFVerifier.verify(
      input.input,
      result.gamma,
      result.proof.pedersenProof,
      auxData,
    )
    if (!pedersenValid) {
      console.error('[RingVRFVerifierWasm] Pedersen VRF verification failed')
      return false
    }

    // Step 2: Serialize inputs for WASM
    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      ringKeysBytes.set(ringKeys[i]!, i * 32)
    }

    // Step 3: Extract key commitment (Y_bar) from Pedersen proof
    // The ring proof verifies that the key commitment matches the ring
    const pedersenProof = PedersenVRFProver.deserialize(
      result.proof.pedersenProof,
    )
    const keyCommitmentBytes = pedersenProof.Y_bar // Y_bar is the key commitment

    // Step 4: Verify ring proof using WASM (ark-vrf version)
    // ark-vrf uses hardcoded seed/padding from BandersnatchSha512Ell2 suite
    // NOTE: result.proof.ringProof should ONLY contain the compressed RingBareProof bytes,
    // NOT the full 784-byte structure (which includes gamma, pedersen_proof, ring_commitment).
    // The ring proof portion is extracted from the 784-byte structure by RingVRFProver.deserialize.
    const ringProofBytes = result.proof.ringProof

    // Sanity check: ring proof should not be 784 bytes (that would be the full structure)
    if (ringProofBytes.length === 784) {
      console.error(
        '[RingVRFVerifierWasm] ERROR: ringProof is 784 bytes - this is the full structure, not just the ring proof portion!',
      )
      throw new Error(
        'Invalid ring proof: received full 784-byte structure instead of just ring proof portion',
      )
    }

    try {
      const isValid = verify_ring_proof(
        this.srsBytes,
        ringProofBytes,
        ringKeysBytes,
        keyCommitmentBytes,
        ringKeys.length, // ring_size
      )

      return isValid
    } catch (error) {
      console.error('[RingVRFVerifierWasm] Failed to verify ring proof', {
        error: error instanceof Error ? error.message : String(error),
      })
      return false
    }
  }
}
