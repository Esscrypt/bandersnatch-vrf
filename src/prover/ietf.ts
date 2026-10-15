import {
  BandersnatchCurve,
  mod,
  numberToBytesLittleEndian,
} from '@pbnjam/bandersnatch'
import { hexToBytes } from 'viem'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config.ts'
import {
  bytesToBigIntLittleEndian,
  curvePointToNoble,
  elligator2HashToCurve,
} from '../crypto/elligator2.ts'
import { generateNonceRfc8032 } from '../crypto/nonce-rfc8032.ts'
import { generateChallengeRfc9381 } from '../crypto/rfc9381.ts'

export interface IETFVRFResult {
  gamma: Uint8Array
  proof: Uint8Array
}

export class IETFVRFProver {
  private static usePaddingPointIfZero(bytes: Uint8Array): Uint8Array {
    const isAllZero = bytes.every((byte) => byte === 0)
    if (isAllZero) {
      return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
    }
    return bytes
  }
  static prove(
    secretKey: Uint8Array,
    input: Uint8Array,
    auxData?: Uint8Array,
  ): IETFVRFResult {
    try {
      const alpha = this.hashToCurve(input)

      const gamma = this.scalarMultiply(alpha, secretKey)

      const proof = this.generateProof(secretKey, alpha, gamma, auxData)

      return {
        gamma,
        proof,
      }
    } catch (error) {
      console.error('IETF VRF proof generation failed', {
        error: error instanceof Error ? error.message : String(error),
      })
      throw new Error(
        `VRF proof generation failed: ${error instanceof Error ? error.message : String(error)}`,
      )
    }
  }

  static hashToCurve(message: Uint8Array): Uint8Array {
    const point = elligator2HashToCurve(message)
    return BandersnatchCurve.pointToBytes(curvePointToNoble(point))
  }

  private static scalarMultiply(
    pointUint8Array: Uint8Array,
    scalarUint8Array: Uint8Array,
  ): Uint8Array {
    const pointBytes = this.usePaddingPointIfZero(pointUint8Array)
    const point = BandersnatchCurve.bytesToPoint(pointBytes)
    const scalar = mod(
      bytesToBigIntLittleEndian(scalarUint8Array),
      BandersnatchCurve.CURVE_ORDER,
    )
    const result = BandersnatchCurve.scalarMultiply(point, scalar)
    return BandersnatchCurve.pointToBytes(result)
  }

  private static generateProof(
    secretKey: Uint8Array,
    alpha: Uint8Array,
    gamma: Uint8Array,
    auxData?: Uint8Array,
  ): Uint8Array {

    const alphaBytesChecked = this.usePaddingPointIfZero(alpha)
    const gammaBytesChecked = this.usePaddingPointIfZero(gamma)
    const alphaPoint = BandersnatchCurve.bytesToPoint(alphaBytesChecked)
    const gammaPoint = BandersnatchCurve.bytesToPoint(gammaBytesChecked)

    const kBytes = generateNonceRfc8032(secretKey, alpha)
    const k = bytesToBigIntLittleEndian(kBytes)

    const gToS = BandersnatchCurve.scalarMultiply(
      BandersnatchCurve.GENERATOR,
      k,
    )

    const hToC = BandersnatchCurve.scalarMultiply(alphaPoint, k)

    const publicKeyPoint = BandersnatchCurve.scalarMultiply(
      BandersnatchCurve.GENERATOR,
      mod(bytesToBigIntLittleEndian(secretKey), BandersnatchCurve.CURVE_ORDER),
    )
    const challengePoints = [
      BandersnatchCurve.pointToBytes(publicKeyPoint),
      BandersnatchCurve.pointToBytes(alphaPoint),
      BandersnatchCurve.pointToBytes(gammaPoint),
      BandersnatchCurve.pointToBytes(gToS),
      BandersnatchCurve.pointToBytes(hToC),
    ]

    const c = generateChallengeRfc9381(challengePoints, auxData)

    const x = mod(
      bytesToBigIntLittleEndian(secretKey),
      BandersnatchCurve.CURVE_ORDER,
    )
    const s = mod(k + c * x, BandersnatchCurve.CURVE_ORDER)

    const gammaBytes = gamma
    const cBytes = numberToBytesLittleEndian(c)
    const sBytes = numberToBytesLittleEndian(s)

    const proofUint8Array = new Uint8Array(96)
    proofUint8Array.set(gammaBytes, 0)
    proofUint8Array.set(cBytes, 32)
    proofUint8Array.set(sBytes, 64)

    return proofUint8Array
  }
}
