import {
  BANDERSNATCH_PARAMS,
  BandersnatchCurve,
  mod,
} from '@pbnjam/bandersnatch'
import { bytesToHex, hexToBytes } from 'viem'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config.ts'
import { bytesToBigIntLittleEndian } from '../crypto/elligator2.ts'
import { generateChallengeRfc9381 } from '../crypto/rfc9381.ts'
import { IETFVRFProver } from '../prover/ietf.ts'

export class IETFVRFVerifier {
  private usePaddingPointIfInvalid(bytes: Uint8Array): Uint8Array {
    const isAllZero = bytes.every((byte) => byte === 0)
    if (isAllZero) {
      return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
    }
    if (bytes.length !== 32) {
      return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
    }
    try {
      BandersnatchCurve.bytesToPoint(bytes, true)
      return bytes
    } catch {
      return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
    }
  }
  verify(
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array,
    auxData?: Uint8Array,
  ): boolean {
    const alphaBytes = IETFVRFProver.hashToCurve(input)

    const isValid = this.verifyProof(publicKey, alphaBytes, proof, auxData)

    return isValid
  }

  private verifyProof(
    publicKey: Uint8Array,
    alpha: Uint8Array,
    proof: Uint8Array,
    auxData?: Uint8Array,
  ): boolean {
    if (proof.length !== 96) {
      return false
    }

    const gammaFromProof = proof.slice(0, 32)
    const cUint8Array = proof.slice(32, 64)
    const sUint8Array = proof.slice(64, 96)

    const cOriginal = bytesToBigIntLittleEndian(cUint8Array)
    const sOriginal = bytesToBigIntLittleEndian(sUint8Array)

    const c = mod(cOriginal, BANDERSNATCH_PARAMS.CURVE_ORDER)
    const s = mod(sOriginal, BANDERSNATCH_PARAMS.CURVE_ORDER)

    const alphaBytes = this.usePaddingPointIfInvalid(alpha)
    const gammaBytes = this.usePaddingPointIfInvalid(gammaFromProof)
    const publicKeyBytes = this.usePaddingPointIfInvalid(publicKey)
    const alphaPoint = BandersnatchCurve.bytesToPoint(alphaBytes)
    const gammaPoint = BandersnatchCurve.bytesToPoint(gammaBytes)
    const publicKeyPoint = BandersnatchCurve.bytesToPoint(publicKeyBytes)

    const gToS = BandersnatchCurve.scalarMultiply(
      BandersnatchCurve.GENERATOR,
      s,
    )
    const yToC = BandersnatchCurve.scalarMultiply(publicKeyPoint, c)
    const u = BandersnatchCurve.add(gToS, BandersnatchCurve.negate(yToC))

    const hToS = BandersnatchCurve.scalarMultiply(alphaPoint, s)
    const gammaToC = BandersnatchCurve.scalarMultiply(gammaPoint, c)
    const v = BandersnatchCurve.add(hToS, BandersnatchCurve.negate(gammaToC))

    const yBytes = BandersnatchCurve.pointToBytes(publicKeyPoint)
    const iBytes = BandersnatchCurve.pointToBytes(alphaPoint)
    const oBytes = BandersnatchCurve.pointToBytes(gammaPoint)
    const uBytes = BandersnatchCurve.pointToBytes(u)
    const vBytes = BandersnatchCurve.pointToBytes(v)

    const challengePoints = [yBytes, iBytes, oBytes, uBytes, vBytes]
    const expectedC = this.hashToScalar(
      challengePoints,
      auxData || new Uint8Array(0),
    )

    const isValid = c === expectedC

    if (!isValid) {
      console.debug('IETF VRF challenge mismatch', {
        yHex: bytesToHex(yBytes),
        iHex: bytesToHex(iBytes),
        oHex: bytesToHex(oBytes),
        uHex: bytesToHex(BandersnatchCurve.pointToBytes(u)),
        vHex: bytesToHex(BandersnatchCurve.pointToBytes(v)),
        auxDataHex: bytesToHex(auxData || new Uint8Array(0)),
        auxDataLength: auxData?.length || 0,
        cFromProof: c.toString(16),
        cOriginal: cOriginal.toString(16),
        cReduced: c.toString(16),
        expectedC: expectedC.toString(16),
        cMatches: c === expectedC,
        gammaHex: bytesToHex(gammaFromProof),
      })
    }

    return isValid
  }

  private hashToScalar(
    points: Uint8Array[],
    auxData: Uint8Array = new Uint8Array(0),
  ): bigint {
    return generateChallengeRfc9381(points, auxData)
  }
}
