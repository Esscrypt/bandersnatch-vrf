import {
  createNapiIetfBackend,
  type IetfBackend,
  unwrapSyncBackendResult,
} from '../backends.ts'

const PROOF_TOTAL_LEN = 96

export class IETFVRFVerifierW3F {
  private readonly backend: IetfBackend

  constructor(options?: { backend?: IetfBackend }) {
    const backend = options?.backend ?? createNapiIetfBackend()
    if (!backend) {
      throw new Error(
        'IETFVRFVerifierW3F requires the native IETF VRF backend; build packages/bandersnatch-vrf native bindings',
      )
    }
    this.backend = backend
  }

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
}
