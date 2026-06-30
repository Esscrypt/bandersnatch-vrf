/**
 * Pedersen VRF Prover Implementation
 *
 * Implements Pedersen VRF proof generation with blinding
 * Reference: Bandersnatch VRF specification section 3
 */

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
import { BANDERSNATCH_VRF_CONFIG } from '../config/bandersnatch-vrf-config'
import {
  bytesToBigIntLittleEndian,
  curvePointToNoble,
  elligator2HashToCurve,
} from '../crypto/elligator2'
import { generateNonceRfc8032 } from '../crypto/nonce-rfc8032'
import { generateChallengeRfc9381, SUITE_BYTES } from '../crypto/rfc9381'
import { getCommitmentFromGamma } from '../utils/gamma'

const PEDERSEN_BLINDING_TAG = 0xcc

/**
 * Pedersen VRF proof structure according to bandersnatch-vrf-spec
 * π ∈ (G, G, G, F, F) = (Y_bar, R, O_k, s, s_b)
 * Note: gamma (O) is NOT part of the proof - it's reconstructed during verification
 */
export interface PedersenVRFProof {
  /** Blinded public key commitment Y_bar = x*G + b*B */
  Y_bar: Uint8Array
  /** Commitment R = k*G + k_b*B */
  R: Uint8Array
  /** Output commitment O_k = k*I */
  O_k: Uint8Array
  /** Proof scalar s = k + c*x */
  s: Uint8Array
  /** Blinding proof scalar s_b = k_b + c*b */
  s_b: Uint8Array
}

/**
 * Pedersen VRF input
 */
export interface PedersenVRFInput {
  /** VRF input data */
  input: Uint8Array
  /** Additional data */
  auxData?: Uint8Array
}

/**
 * Pedersen VRF result
 */
export interface PedersenVRFResult {
  /** VRF output gamma point */
  gamma: Uint8Array
  /** VRF output hash */
  hash: Uint8Array
  /** Serialized proof */
  proof: Uint8Array
  /** Blinding factor (b) used in Pedersen commitment - needed for ring proof */
  blindingFactor: Uint8Array
}

/**
 * Pedersen VRF Prover
 * Implements Pedersen VRF with blinding for anonymity
 */
export class PedersenVRFProver {
  /**
   * Check if bytes are all zero, and if so, return padding point bytes
   * Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys
   */
  private static usePaddingPointIfZero(bytes: Uint8Array): Uint8Array {
    // Check if all bytes are zero
    const isAllZero = bytes.every((byte) => byte === 0)
    if (isAllZero) {
      // Return padding point bytes instead
      return hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)
    }
    return bytes
  }
  /**
   * Generate blinding factor deterministically (matches arkworks implementation)
   */
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

  /**
   * Generate Pedersen VRF proof and output
   */
  static prove(
    secretKey: Uint8Array,
    input: PedersenVRFInput,
  ): PedersenVRFResult {
    try {
      // Step 1 - Hash input to curve point (H1) using Elligator2
      const I = PedersenVRFProver.hashToCurve(input.input)

      // Step 2 - Generate blinding factor deterministically
      const blindingFactor = this.generateBlindingFactor(
        secretKey,
        I,
        input.auxData,
      )

      // Step 3 - Generate VRF output O = x * I
      const O = this.scalarMultiply(I, secretKey)

      // Step 4 - Generate nonces k and k_b using RFC-8032
      const k = this.generateNonce(secretKey, I)
      const k_b = this.generateNonce(blindingFactor, I)

      // Step 5 - Generate blinded public key commitment Y_bar = x*G + b*B
      const Y_bar = this.generateBlindedPublicKey(secretKey, blindingFactor)

      // Step 6 - Generate commitment R = k*G + k_b*B
      const R = this.generateCommitment(k, k_b)

      // Step 7 - Generate output commitment O_k = k*I
      const O_k = this.scalarMultiply(I, k)

      // Step 8 - Generate challenge c = H2(Y_bar, I, O, R, O_k, ad)
      // This must be the same in both prover and verifier
      const c = this.generateChallenge(Y_bar, I, O, R, O_k, input.auxData)

      // Step 9 - Generate proof scalars s = k + c*x and s_b = k_b + c*b
      const s = this.generateProofScalar(k, c, secretKey)
      const s_b = this.generateBlindingProofScalar(k_b, c, blindingFactor)

      // Step 10 - Hash output (H2)
      const hash = this.hashOutput(O)

      // Compress points for proof (arkworks uses compressed format)
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
        blindingFactor, // Return blinding factor for ring proof generation
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

  /**
   * Hash input to curve point (H1 function)
   */
  static hashToCurve(message: Uint8Array): Uint8Array {
    // Use Elligator2 hash-to-curve for proper implementation
    const point = elligator2HashToCurve(message)
    // Convert CurvePoint to bytes using the compression function from elligator2
    const compressed = BandersnatchCurve.pointToBytes(curvePointToNoble(point))
    return compressed
  }

  /**
   * Scalar multiplication on Bandersnatch curve
   */
  private static scalarMultiply(
    pointBytes: Uint8Array,
    scalarBytes: Uint8Array,
  ): Uint8Array {
    // Check for all-zero bytes and use padding point if needed
    const pointBytesChecked = this.usePaddingPointIfZero(pointBytes)
    const point = BandersnatchCurve.bytesToPoint(pointBytesChecked)
    const scalar = mod(
      bytesToBigIntLittleEndian(scalarBytes),
      BandersnatchCurve.CURVE_ORDER,
    )
    const result = BandersnatchCurve.scalarMultiply(point, scalar)
    return BandersnatchCurve.pointToBytes(result)
  }

  /**
   * Generate nonce using RFC-8032 nonce generation (matches Rust implementation)
   */
  private static generateNonce(
    secret: Uint8Array,
    input: Uint8Array,
  ): Uint8Array {
    // Use RFC-8032 nonce generation to match Rust implementation
    return generateNonceRfc8032(secret, input)
  }

  /**
   * Generate blinded public key commitment Y_bar = x*G + b*B
   */
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

    // Y_bar = x*G + b*B
    const xG = BandersnatchCurve.scalarMultiply(BandersnatchCurve.GENERATOR, x)
    const blindingBase = this.getBlindingBase()
    const bB = BandersnatchCurve.scalarMultiply(blindingBase, b)
    const Y_bar = BandersnatchCurve.add(xG, bB)

    return BandersnatchCurve.pointToBytes(Y_bar)
  }

  /**
   * Generate commitment R = k*G + k_b*B
   */
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

    // R = k*G + k_b*B
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

  /**
   * Generate challenge c = H2(Y_bar, I, O, R, O_k, ad)
   * Made public so verifier can reuse the same implementation
   */
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

  /**
   * Generate proof scalar s = k + c*x
   */
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

  /**
   * Generate blinding proof scalar s_b = k_b + c*b
   */
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

  /**
   * Hash VRF output point (H2 function)
   */
  private static hashOutput(gamma: Uint8Array): Uint8Array {
    return getCommitmentFromGamma(gamma)
  }

  /**
   * Get blinding base point B as Edwards point
   * From specification: B_x = 6150229251051246713677296363717454238956877613358614224171740096471278798312
   * B_y = 28442734166467795856797249030329035618871580593056783094884474814923353898473
   */
  private static getBlindingBase() {
    // Use the same pattern as the generator
    return Bandersnatch.fromAffine({
      x: BANDERSNATCH_PARAMS.BLINDING_BASE.x,
      y: BANDERSNATCH_PARAMS.BLINDING_BASE.y,
    })
  }

  /**
   * Serialize Pedersen VRF proof according to bandersnatch-vrf-spec
   * π ∈ (G, G, G, F, F) = (Y_bar, R, O_k, s, s_b)
   */
  static serialize(proof: PedersenVRFProof): Uint8Array {
    const serialized = new Uint8Array(160)
    serialized.set(proof.Y_bar, 0)
    serialized.set(proof.R, 32)
    serialized.set(proof.O_k, 64)
    serialized.set(proof.s, 96)
    serialized.set(proof.s_b, 128)
    return serialized
  }

  /**
   * Deserialize Pedersen VRF proof according to bandersnatch-vrf-spec
   * π ∈ (G, G, G, F, F) = (Y_bar, R, O_k, s, s_b)
   */
  static deserialize(proofBytes: Uint8Array): PedersenVRFProof {
    const pointSize = 32 // Compressed point size (arkworks format)
    const scalarSize = 32 // Scalar size

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
