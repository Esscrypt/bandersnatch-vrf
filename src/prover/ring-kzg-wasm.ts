/**
 * Ring VRF Prover using WASM bindings to Rust implementation
 *
 * This implementation uses the Rust reference implementation compiled to WASM,
 * providing full compliance with the bandersnatch-vrf-spec and VG24 Plonk zkSNARK protocol.
 */

import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
// Import WASM module (from ark-vrf, matches test vectors exactly)
import initWasm, {
  compute_ring_commitment,
  prove_ring_proof,
} from '../../wasm-ark-vrf/ark_vrf_wasm'
import { PedersenVRFProver } from './pedersen'
import type { RingVRFInput, RingVRFResult } from './ring-kzg'

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
  const relativePath = join(currentDir, '..', '..', 'wasm-ark-vrf', wasmFileName)
  if (existsSync(relativePath)) {
    return relativePath
  }
  
  // Strategy 3: Try to find workspace root and search from there
  // Walk up from current directory to find workspace root (has packages/ directory)
  let searchDir = currentDir
  for (let i = 0; i < 10; i++) {
    const packagesDir = join(searchDir, 'packages')
    const wasmPath = join(packagesDir, 'bandersnatch-vrf', 'wasm-ark-vrf', wasmFileName)
    if (existsSync(wasmPath)) {
      return wasmPath
    }
    const parent = dirname(searchDir)
    if (parent === searchDir) break // Reached filesystem root
    searchDir = parent
  }
  
  // Strategy 4: Try from process.cwd() (current working directory)
  const cwd = process.cwd()
  const cwdPackagesPath = join(cwd, 'packages', 'bandersnatch-vrf', 'wasm-ark-vrf', wasmFileName)
  if (existsSync(cwdPackagesPath)) {
    return cwdPackagesPath
  }
  
  // Strategy 5: Try relative to process.cwd() if it's in the workspace
  if (cwd.includes('packages')) {
    const workspaceRoot = cwd.split('/packages')[0]
    const workspacePath = join(workspaceRoot, 'packages', 'bandersnatch-vrf', 'wasm-ark-vrf', wasmFileName)
    if (existsSync(workspacePath)) {
      return workspacePath
    }
  }
  
  // If none found, return the relative path (will throw a clear error)
  return relativePath
}

/**
 * Ring VRF Prover using WASM bindings
 * Provides full Plonk zkSNARK proof generation matching Rust reference implementation
 */
export class RingVRFProverWasm {
  private readonly srsBytes: Uint8Array
  private wasmInitialized = false
  /**
   * Create a new Ring VRF Prover instance using WASM
   *
   * @param srsFilePath - Path to SRS file (compressed format)
   */
  constructor(srsFilePath: string) {
    // Load SRS file (expects uncompressed arkworks format)
    // Replace '-compressed.bin' with '-uncompressed.bin' if needed
    this.srsBytes = readFileSync(srsFilePath)
    // Note: WASM initialization is async, but constructor can't be async
    // We'll initialize on first use in prove() or computeRingCommitment()
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
   * Generate Ring VRF proof using WASM
   *
   * Steps:
   * 1. Generate Pedersen VRF proof (TypeScript implementation)
   * 2. Compute ring commitment using WASM (Rust Ring::with_keys)
   * 3. Generate ring proof using WASM (Rust Plonk prover)
   */
  prove(secretKey: Uint8Array, input: RingVRFInput): RingVRFResult {
    if (!this.wasmInitialized) {
      throw new Error(
        'WASM module not initialized yet. Please wait for initialization to complete. ' +
          'You can await wasmInitPromise from ring-kzg-wasm if needed.',
      )
    }

    // Step 1: Generate Pedersen VRF proof (TypeScript implementation)
    const pedersenInput = {
      input: input.input,
      auxData: input.auxData,
    }
    const pedersenResult = PedersenVRFProver.prove(secretKey, pedersenInput)

    // Step 2: Serialize ring keys for WASM
    const ringKeysBytes = new Uint8Array(input.ringKeys.length * 32)
    for (let i = 0; i < input.ringKeys.length; i++) {
      ringKeysBytes.set(input.ringKeys[i], i * 32)
    }

    // Step 3: Compute ring commitment using WASM (ark-vrf version)
    // ark-vrf uses hardcoded seed/padding from BandersnatchSha512Ell2 suite
    let ringCommitment: Uint8Array
    try {
      const commitmentBytes = compute_ring_commitment(
        this.srsBytes,
        ringKeysBytes,
        input.ringKeys.length, // ring_size
      )
      ringCommitment = new Uint8Array(commitmentBytes)
    } catch (error) {
      console.error('[RingVRFProverWasm] Failed to compute ring commitment', {
        error: error instanceof Error ? error.message : String(error),
      })
      throw error
    }

    // Step 4: Generate ring proof using WASM (w3f-ring-proof to match test vectors)
    // Use prove_ring_proof which uses w3f-ring-proof instead of w3f-ring-vrf-snark
    // This matches the proof format used in ark-vrf test vectors (592 bytes vs 1184 bytes)
    let ringProof: Uint8Array
    try {
      // Use the blinding factor from Pedersen VRF proof
      // This matches ark-vrf::ring::Prover::prove which calls ring_prover.prove(secret_blinding)
      const blindingFactor = pedersenResult.blindingFactor

      // Generate ring proof using ark-vrf (matches test vectors exactly)
      // ark-vrf uses hardcoded seed/padding/transcript from BandersnatchSha512Ell2 suite
      const proofBytes = prove_ring_proof(
        this.srsBytes,
        ringKeysBytes,
        blindingFactor,
        input.proverIndex,
        input.ringKeys.length, // ring_size
      )

      // The WASM function returns RingProof from w3f-ring-proof (592 bytes for ring size 8)
      ringProof = new Uint8Array(proofBytes)
    } catch (error) {
      console.error('[RingVRFProverWasm] Failed to generate ring proof', {
        error: error instanceof Error ? error.message : String(error),
      })
      throw error
    }

    return {
      gamma: pedersenResult.gamma,
      proof: {
        pedersenProof: pedersenResult.proof,
        ringCommitment,
        ringProof,
        proverIndex: input.proverIndex,
      },
    }
  }

  /**
   * Compute ring commitment only (without generating full proof)
   * Useful for epoch root computation
   */
  computeRingCommitment(ringKeys: Uint8Array[]): Uint8Array {
    if (!this.wasmInitialized) {
      throw new Error(
        'WASM module not initialized yet. Please wait for initialization to complete. ' +
          'You can await wasmInitPromise from ring-kzg-wasm if needed.',
      )
    }

    // Serialize ring keys
    const ringKeysBytes = new Uint8Array(ringKeys.length * 32)
    for (let i = 0; i < ringKeys.length; i++) {
      ringKeysBytes.set(ringKeys[i], i * 32)
    }

    // Compute ring commitment using WASM
    const commitmentBytes = compute_ring_commitment(
      this.srsBytes,
      ringKeysBytes,
      ringKeys.length,
    )

    return new Uint8Array(commitmentBytes)
  }
}
