/**
 * IETF VRF Verifier using Rust napi-rs bindings (rust-ring-proof native module).
 *
 * Proof wire format expected: gamma (32) || c (32) || s (32) = 96 bytes.
 * Same interface as IETFVRFVerifierWasm; falls back to WASM when the native
 * module is not available.
 *
 * Requires the native module; build with `bun run build:native` in the package.
 */

import { verify_ietf_vrf as wasmVerifyIetfVrf } from '../../wasm-ark-vrf/ark_vrf_wasm'
import { IETFVRFProver } from '../prover/ietf'
import { getRustVerifyIetfVrf } from '../prover/rust-ietf-vrf-wrapper'

const PROOF_TOTAL_LEN = 96

/**
 * IETF VRF Verifier using Rust napi-rs native module.
 *
 * When the native module (rust-ring-proof) is available, verification is done
 * entirely in Rust. Falls back to the ark-vrf WASM binding when the native
 * module is not built (same as IETFVRFVerifierWasm).
 *
 * Same API as IETFVRFVerifierWasm:
 *   verify(publicKey, input, proof, auxData?) → boolean
 */
export class IETFVRFVerifierW3F {
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
    const rustVerify = getRustVerifyIetfVrf()

    if (rustVerify) {
      try {
        return rustVerify(publicKey, input, proof, aux)
      } catch (error) {
        console.error('[IETFVRFVerifierW3F] Rust verify failed', {
          error: error instanceof Error ? error.message : String(error),
        })
        return false
      }
    }

    // WASM fallback: hash input to curve in TypeScript (same as IETFVRFVerifierWasm)
    const salt = new Uint8Array(0)
    const h2cData = new Uint8Array(salt.length + input.length)
    h2cData.set(salt, 0)
    h2cData.set(input, salt.length)
    const alpha = IETFVRFProver.hashToCurve(h2cData)

    const gammaFromProof = proof.subarray(0, 32)
    const proofCS = proof.subarray(32, 96)

    try {
      return wasmVerifyIetfVrf(publicKey, alpha, gammaFromProof, proofCS, aux)
    } catch (error) {
      console.error('[IETFVRFVerifierW3F] WASM fallback verify failed', {
        error: error instanceof Error ? error.message : String(error),
      })
      return false
    }
  }
}
