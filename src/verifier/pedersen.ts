import {
  BANDERSNATCH_PARAMS,
  Bandersnatch,
  BandersnatchCurve,
} from '@pbnjam/bandersnatch'
import { hexToBytes } from 'viem'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config.ts'
import {
  bytesToBigIntLittleEndian,
  curvePointToNoble,
  elligator2HashToCurve,
} from '../crypto/elligator2.ts'
import { type PedersenVRFProof, PedersenVRFProver } from '../prover/pedersen.ts'

export class PedersenVRFVerifier {
  private static usePaddingPointIfZero(bytes: Uint8Array): Uint8Array {
    const isAllZero = bytes.every((byte) => byte === 0)
    if (isAllZero) {
      return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
    }
    return bytes
  }
  static verify(
    input: Uint8Array,
    gamma: Uint8Array,
    proof: Uint8Array,
    auxData?: Uint8Array,
  ): boolean {
    if (proof.length !== 160) {
      throw new Error(
        'Invalid Pedersen VRF proof size, expected 160 bytes, got ' +
          proof.length +
          ' bytes',
      )
    }
    const pedersenProof = PedersenVRFProver.deserialize(proof)

    const I = this.hashToCurve(input)

    const isValid = this.verifyProof(I, gamma, pedersenProof, auxData)

    if (!isValid) {
      console.error('Pedersen VRF proof verification failed', {})
    }

    return isValid
  }

  static hashToCurve(message: Uint8Array): Uint8Array {
    const point = elligator2HashToCurve(message)
    return BandersnatchCurve.pointToBytes(curvePointToNoble(point))
  }

  private static getBlindingBase() {
    return Bandersnatch.fromAffine({
      x: BANDERSNATCH_PARAMS.BLINDING_BASE.x,
      y: BANDERSNATCH_PARAMS.BLINDING_BASE.y,
    })
  }

  private static verifyProof(
    I: Uint8Array,
    O: Uint8Array,
    proof: PedersenVRFProof,
    auxData?: Uint8Array,
  ): boolean {
    try {
      const { Y_bar, R, O_k, s, s_b } = proof

      const IBytesChecked = this.usePaddingPointIfZero(I)
      const OBytesChecked = this.usePaddingPointIfZero(O)
      const Y_barBytesChecked = this.usePaddingPointIfZero(Y_bar)
      const RBytesChecked = this.usePaddingPointIfZero(R)
      const O_kBytesChecked = this.usePaddingPointIfZero(O_k)
      const IPoint = BandersnatchCurve.bytesToPoint(IBytesChecked)
      const OPoint = BandersnatchCurve.bytesToPoint(OBytesChecked)
      const Y_barPoint = BandersnatchCurve.bytesToPoint(Y_barBytesChecked)
      const RPoint = BandersnatchCurve.bytesToPoint(RBytesChecked)
      const O_kPoint = BandersnatchCurve.bytesToPoint(O_kBytesChecked)

      const sScalar = bytesToBigIntLittleEndian(s)
      const s_bScalar = bytesToBigIntLittleEndian(s_b)

      const c = PedersenVRFProver.generateChallenge(
        Y_bar,
        I,
        O,
        R,
        O_k,
        auxData || new Uint8Array(0),
      )

      const cO = BandersnatchCurve.scalarMultiply(OPoint, c)
      const leftSide = BandersnatchCurve.add(O_kPoint, cO)
      const rightSide = BandersnatchCurve.scalarMultiply(IPoint, sScalar)
      const theta0 = leftSide.equals(rightSide)

      const cY_bar = BandersnatchCurve.scalarMultiply(Y_barPoint, c)
      const leftSideKey = BandersnatchCurve.add(RPoint, cY_bar)

      const G = Bandersnatch.fromAffine({
        x: BANDERSNATCH_PARAMS.GENERATOR.x,
        y: BANDERSNATCH_PARAMS.GENERATOR.y,
      })
      const B = this.getBlindingBase()
      const sG = BandersnatchCurve.scalarMultiply(G, sScalar)
      const s_bB = BandersnatchCurve.scalarMultiply(B, s_bScalar)
      const rightSideKey = BandersnatchCurve.add(sG, s_bB)
      const theta1 = leftSideKey.equals(rightSideKey)

      const isValid = theta0 && theta1

      return isValid
    } catch (error) {
      console.error(
        'Pedersen VRF proof verification with provided gamma failed',
        {
          error: error instanceof Error ? error.message : String(error),
        },
      )
      return false
    }
  }
}
