/**
 * IETF VRF Prover using Rust napi-rs bindings (rust-ring-proof native module).
 *
 * Proof wire format: gamma (32) || c (32) || s (32) = 96 bytes.
 * Matches the format produced by IETFVRFProver and consumed by IETFVRFVerifierWasm.
 *
 * Requires the native module; build with `bun run build:native` in the package.
 */

import type { IETFVRFResult } from './ietf'
import { getRustProveIetfVrf } from './rust-ietf-vrf-wrapper'

const RUST_REQUIRED_MSG =
  'IETF VRF prover requires the Rust native module (rust-ring-proof). Build with: cd rust-ring-proof && bun run build'

const GAMMA_LEN = 32
const PROOF_TOTAL_LEN = 96

/**
 * IETF VRF Prover using Rust napi-rs native module.
 *
 * Same API as IETFVRFProver but delegates all crypto to Rust via napi-rs.
 * Hash-to-curve (Elligator2 / RFC-9380) is performed inside Rust.
 */
export class IETFVRFProverW3F {
  /**
   * Generate IETF VRF proof and output using the Rust native module.
   *
   * @param secretKey - Secret scalar (32 bytes, little-endian Fr)
   * @param input - Raw VRF input data (hashed to curve inside Rust via Elligator2)
   * @param auxData - Additional data bound to the proof (optional)
   * @returns gamma (32 bytes) and proof (96 bytes: gamma || c || s)
   */
  static prove(
    secretKey: Uint8Array,
    input: Uint8Array,
    auxData?: Uint8Array,
  ): IETFVRFResult {
    const proveNapi = getRustProveIetfVrf()
    if (!proveNapi) {
      throw new Error(RUST_REQUIRED_MSG)
    }

    const aux = auxData ?? new Uint8Array(0)

    let proofBytes: Uint8Array
    try {
      proofBytes = proveNapi(secretKey, input, aux)
    } catch (error) {
      console.error('[IETFVRFProverW3F] Failed to prove', {
        error: error instanceof Error ? error.message : String(error),
      })
      throw error
    }

    if (proofBytes.length !== PROOF_TOTAL_LEN) {
      throw new Error(
        `[IETFVRFProverW3F] Unexpected proof length: expected ${PROOF_TOTAL_LEN}, got ${proofBytes.length}`,
      )
    }

    return {
      gamma: proofBytes.subarray(0, GAMMA_LEN),
      proof: proofBytes,
    }
  }
}
