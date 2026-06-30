/**
 * IETF VRF Verifier using WASM bindings to ark-vrf
 *
 * Uses the Rust ark-vrf IETF implementation compiled to WASM for verification
 * that matches the reference implementation exactly.
 */

import { verify_ietf_vrf } from '../../wasm-ark-vrf/ark_vrf_wasm'
import { IETFVRFProver } from '../prover/ietf'

/** IETF proof layout: gamma (32) || c (32) || s (32) = 96 bytes. WASM expects gamma and c||s separately. */
const GAMMA_LEN = 32
const PROOF_CS_LEN = 64

/**
 * IETF VRF Verifier using ark-vrf WASM
 *
 * Same API as IETFVRFVerifier.verify: (publicKey, input, proof, auxData?).
 * proof is 96 bytes (gamma || c || s).
 */
export class IETFVRFVerifierWasm {
  /**
   * Verify VRF proof using ark-vrf WASM
   *
   * @param publicKey - Public key point (32 bytes, compressed)
   * @param input - VRF input data (hashed to curve inside)
   * @param proof - VRF proof (96 bytes: gamma || c || s)
   * @param auxData - Additional data (optional)
   * @returns true if proof is valid
   */
  verify(
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array,
    auxData?: Uint8Array,
  ): boolean {
    if (proof.length !== 96) {
      return false
    }
    const alpha = IETFVRFProver.hashToCurve(input)
    const gammaFromProof = proof.subarray(0, GAMMA_LEN)
    const proofCS = proof.subarray(GAMMA_LEN, GAMMA_LEN + PROOF_CS_LEN)
    const aux = auxData ?? new Uint8Array(0)
    try {
      return verify_ietf_vrf(publicKey, alpha, gammaFromProof, proofCS, aux)
    } catch {
      return false
    }
  }
}
