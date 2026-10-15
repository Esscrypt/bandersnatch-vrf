import { sha512 } from '@noble/hashes/sha2.js'
import {
  BANDERSNATCH_PARAMS,
  Bandersnatch,
  BandersnatchCurve,
  mod,
  numberToBytesLittleEndian,
} from '@pbnjam/bandersnatch'
import { hexToBytes } from 'viem'
import { bytesToBigInt } from 'viem/utils'
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config.ts'
import {
  bytesToBigIntLittleEndian,
  curvePointToNoble,
  elligator2HashToCurve,
} from '../crypto/elligator2.ts'
import { generateNonceRfc8032 } from '../crypto/nonce-rfc8032.ts'
import { generateChallengeRfc9381, SUITE_BYTES } from '../crypto/rfc9381.ts'
import { getCommitmentFromGamma } from '../utils/gamma.ts'

const PEDERSEN_BLINDING_TAG = 0xcc

export interface PedersenVRFProof {
  Y_bar: Uint8Array
  R: Uint8Array
  O_k: Uint8Array
  s: Uint8Array
  s_b: Uint8Array
}

export interface PedersenVRFInput {
  input: Uint8Array
  auxData?: Uint8Array
}

export interface PedersenVRFResult {
  gamma: Uint8Array
  hash: Uint8Array
  proof: Uint8Array
  blindingFactor: Uint8Array
}

export class PedersenVRFProver {
  private static usePaddingPointIfZero(bytes: Uint8Array): Uint8Array {
    const isAllZero = bytes.every((byte) => byte === 0)
    if (isAllZero) {
      return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
    }
    return bytes
  }
  static generateBlindingFactor(
    secretKey: Uint8Array,
    inputPoint: Uint8Array,
    auxData?: Uint8Array,
  ): Uint8Array {
    const auxLen = auxData?.length ?? 0
    const buf = new Uint8Array(
      SUITE_BYTES.length +
        1 +
        secretKey.length +
        inputPoint.length +
        auxLen +
        1,
    )
    let offset = 0
    buf.set(SUITE_BYTES, offset)
    offset += SUITE_BYTES.length
    buf[offset++] = PEDERSEN_BLINDING_TAG
    buf.set(secretKey, offset)
    offset += secretKey.length
    buf.set(inputPoint, offset)
    offset += inputPoint.length
    if (auxData) {
      buf.set(auxData, offset)
      offset += auxData.length
    }
    buf[offset] = 0x00

    const hash = sha512(buf)
    const blindingScalar = mod(
      bytesToBigInt(hash),
      BandersnatchCurve.CURVE_ORDER,
    )
    return numberToBytesLittleEndian(blindingScalar)
  }

  static prove(
    secretKey: Uint8Array,
    input: PedersenVRFInput,
  ): PedersenVRFResult {
    try {
      const I = PedersenVRFProver.hashToCurve(input.input)

      const blindingFactor = this.generateBlindingFactor(
        secretKey,
        I,
        input.auxData,
      )

      const O = this.scalarMultiply(I, secretKey)

      const k = this.generateNonce(secretKey, I)
      const k_b = this.generateNonce(blindingFactor, I)

      const Y_bar = this.generateBlindedPublicKey(secretKey, blindingFactor)

      const R = this.generateCommitment(k, k_b)

      const O_k = this.scalarMultiply(I, k)

      const c = this.generateChallenge(Y_bar, I, O, R, O_k, input.auxData)

      const s = this.generateProofScalar(k, c, secretKey)
      const s_b = this.generateBlindingProofScalar(k_b, c, blindingFactor)

      const hash = this.hashOutput(O)

      const Y_bar_compressed = Y_bar
      const R_compressed = R
      const O_k_compressed = O_k

      return {
        gamma: O,
        hash,
        proof: this.serialize({
          Y_bar: Y_bar_compressed,
          R: R_compressed,
          O_k: O_k_compressed,
          s,
          s_b,
        }),
        blindingFactor,
      }
    } catch (error) {
      console.error('Pedersen VRF proof generation failed', {
        error: error instanceof Error ? error.message : String(error),
      })
      throw new Error(
        `Pedersen VRF proof generation failed: ${error instanceof Error ? error.message : String(error)}`,
      )
    }
  }

  static hashToCurve(message: Uint8Array): Uint8Array {
    const point = elligator2HashToCurve(message)
    const compressed = BandersnatchCurve.pointToBytes(curvePointToNoble(point))
    return compressed
  }

  private static scalarMultiply(
    pointBytes: Uint8Array,
    scalarBytes: Uint8Array,
  ): Uint8Array {
    const pointBytesChecked = this.usePaddingPointIfZero(pointBytes)
    const point = BandersnatchCurve.bytesToPoint(pointBytesChecked)
    const scalar = mod(
      bytesToBigIntLittleEndian(scalarBytes),
      BandersnatchCurve.CURVE_ORDER,
    )
    const result = BandersnatchCurve.scalarMultiply(point, scalar)
    return BandersnatchCurve.pointToBytes(result)
  }

  private static generateNonce(
    secret: Uint8Array,
    input: Uint8Array,
  ): Uint8Array {
    return generateNonceRfc8032(secret, input)
  }

  private static generateBlindedPublicKey(
    secretKey: Uint8Array,
    blindingFactor: Uint8Array,
  ): Uint8Array {
    const x = mod(
      bytesToBigIntLittleEndian(secretKey),
      BandersnatchCurve.CURVE_ORDER,
    )
    const b = mod(
      bytesToBigIntLittleEndian(blindingFactor),
      BandersnatchCurve.CURVE_ORDER,
    )

    const xG = BandersnatchCurve.scalarMultiply(BandersnatchCurve.GENERATOR, x)
    const blindingBase = this.getBlindingBase()
    const bB = BandersnatchCurve.scalarMultiply(blindingBase, b)
    const Y_bar = BandersnatchCurve.add(xG, bB)

    return BandersnatchCurve.pointToBytes(Y_bar)
  }

  private static generateCommitment(
    k: Uint8Array,
    k_b: Uint8Array,
  ): Uint8Array {
    const kScalar = mod(
      bytesToBigIntLittleEndian(k),
      BandersnatchCurve.CURVE_ORDER,
    )
    const k_bScalar = mod(
      bytesToBigIntLittleEndian(k_b),
      BandersnatchCurve.CURVE_ORDER,
    )

    const kG = BandersnatchCurve.scalarMultiply(
      BandersnatchCurve.GENERATOR,
      kScalar,
    )
    const k_bB = BandersnatchCurve.scalarMultiply(
      this.getBlindingBase(),
      k_bScalar,
    )
    const R = BandersnatchCurve.add(kG, k_bB)

    return BandersnatchCurve.pointToBytes(R)
  }

  static generateChallenge(
    Y_bar: Uint8Array,
    I: Uint8Array,
    O: Uint8Array,
    R: Uint8Array,
    O_k: Uint8Array,
    auxData?: Uint8Array,
  ): bigint {
    return generateChallengeRfc9381(
      [Y_bar, I, O, R, O_k],
      auxData ?? new Uint8Array(0),
    )
  }

  private static generateProofScalar(
    k: Uint8Array,
    c: bigint,
    secretKey: Uint8Array,
  ): Uint8Array {
    const kScalar = mod(
      bytesToBigIntLittleEndian(k),
      BandersnatchCurve.CURVE_ORDER,
    )
    const x = mod(
      bytesToBigIntLittleEndian(secretKey),
      BandersnatchCurve.CURVE_ORDER,
    )
    const s = mod(kScalar + c * x, BandersnatchCurve.CURVE_ORDER)
    return numberToBytesLittleEndian(s)
  }

  private static generateBlindingProofScalar(
    k_b: Uint8Array,
    c: bigint,
    blindingFactor: Uint8Array,
  ): Uint8Array {
    const k_bScalar = mod(
      bytesToBigIntLittleEndian(k_b),
      BandersnatchCurve.CURVE_ORDER,
    )
    const b = mod(
      bytesToBigIntLittleEndian(blindingFactor),
      BandersnatchCurve.CURVE_ORDER,
    )
    const s_b = mod(k_bScalar + c * b, BandersnatchCurve.CURVE_ORDER)
    return numberToBytesLittleEndian(s_b)
  }

  private static hashOutput(gamma: Uint8Array): Uint8Array {
    return getCommitmentFromGamma(gamma)
  }

  private static getBlindingBase() {
    return Bandersnatch.fromAffine({
      x: BANDERSNATCH_PARAMS.BLINDING_BASE.x,
      y: BANDERSNATCH_PARAMS.BLINDING_BASE.y,
    })
  }

  static serialize(proof: PedersenVRFProof): Uint8Array {
    const serialized = new Uint8Array(160)
    serialized.set(proof.Y_bar, 0)
    serialized.set(proof.R, 32)
    serialized.set(proof.O_k, 64)
    serialized.set(proof.s, 96)
    serialized.set(proof.s_b, 128)
    return serialized
  }

  static deserialize(proofBytes: Uint8Array): PedersenVRFProof {
    const pointSize = 32
    const scalarSize = 32

    let offset = 0
    const Y_bar = proofBytes.slice(offset, offset + pointSize)
    offset += pointSize

    const R = proofBytes.slice(offset, offset + pointSize)
    offset += pointSize

    const O_k = proofBytes.slice(offset, offset + pointSize)
    offset += pointSize

    const s = proofBytes.slice(offset, offset + scalarSize)
    offset += scalarSize

    const s_b = proofBytes.slice(offset, offset + scalarSize)

    return { Y_bar, R, O_k, s, s_b }
  }
}
