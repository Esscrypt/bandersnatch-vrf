import { verify_ietf_vrf } from '../../wasm-ark-vrf/ark_vrf_wasm.js'
import { IETFVRFProver } from '../prover/ietf.ts'

const GAMMA_LEN = 32
const PROOF_CS_LEN = 64

export class IETFVRFVerifierWasm {
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
