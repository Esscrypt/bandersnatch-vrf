/**
 * IETF VRF Verifier using Rust napi-rs bindings (rust-ring-proof native module).
 *
 * Proof wire format expected: gamma (32) || c (32) || s (32) = 96 bytes.
 * Same interface as IETFVRFVerifierWasm; falls back to WASM when neither an
 * injected backend nor the native module is available.
 *
 * Requires the native module; build with `bun run build:native` in the package.
 */

import {
  createNapiIetfBackend,
  type IetfBackend,
  loadWasmVerifyIetfVrf,
  unwrapSyncBackendResult,
} from '../backends.ts'
import { IETFVRFProver } from '../prover/ietf.ts'

const PROOF_TOTAL_LEN = 96

/**
 * IETF VRF Verifier using Rust napi-rs native module.
 *
 * When a backend is injected or the native module (rust-ring-proof) is available,
 * verification is done by that backend. Falls back to the ark-vrf WASM binding
 * when neither resolves (same as IETFVRFVerifierWasm).
 *
 * Same API as IETFVRFVerifierWasm:
 *   verify(publicKey, input, proof, auxData?) → boolean
 */
export class IETFVRFVerifierW3F {
  private readonly backend: IetfBackend | null

  constructor(options?: { backend?: IetfBackend }) {
    this.backend = options?.backend ?? createNapiIetfBackend()
  }

  /**
   * Verify an IETF VRF proof.
   *
   * @param publicKey - Public key point (32 bytes, compressed)
   * @param input - Raw VRF input data (hashed to curve internally)
   * @param proof - VRF proof (96 bytes: gamma || c || s)
   * @param auxData - Additional data bound to the proof (optional)
   * @returns true if the proof is valid
   */
  verify(
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array,
    auxData?: Uint8Array,
  ): boolean {
    if (proof.length !== PROOF_TOTAL_LEN) {
      return false
    }

    const aux = auxData ?? new Uint8Array(0)

    if (this.backend) {
      try {
        return unwrapSyncBackendResult(
          this.backend.verify(publicKey, input, proof, aux),
          'IetfBackend.verify',
        )
      } catch (error) {
        console.error('[IETFVRFVerifierW3F] backend verify failed', {
          error: error instanceof Error ? error.message : String(error),
        })
        return false
      }
    }

    const alpha = IETFVRFProver.hashToCurve(input)
    const gammaFromProof = proof.subarray(0, 32)
    const proofCS = proof.subarray(32, 96)

    try {
      const wasmVerifyIetfVrf = loadWasmVerifyIetfVrf()
      return wasmVerifyIetfVrf(publicKey, alpha, gammaFromProof, proofCS, aux)
    } catch (error) {
      console.error('[IETFVRFVerifierW3F] WASM fallback verify failed', {
        error: error instanceof Error ? error.message : String(error),
      })
      return false
    }
  }
}
