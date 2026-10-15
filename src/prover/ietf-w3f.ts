import type { IETFVRFResult } from './ietf.ts'
import { getRustProveIetfVrf } from './rust-ietf-vrf-wrapper.ts'

const RUST_REQUIRED_MSG =
  'IETF VRF prover requires the Rust native module (rust-ring-proof). Build with: cd rust-ring-proof && bun run build'

const GAMMA_LEN = 32
const PROOF_TOTAL_LEN = 96

export class IETFVRFProverW3F {
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
