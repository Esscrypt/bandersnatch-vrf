/**
 * Pedersen VRF Prover Implementation
 *
 * Implements Pedersen VRF proof generation with blinding
 * Reference: Bandersnatch VRF specification section 3
 */

import { sha512 } from '@noble/hashes/sha2'
import {
  BANDERSNATCH_PARAMS,
  BandersnatchCurve,
  Bandersnatch,
  mod, numberToBytesLittleEndian
} from '@pbnj/bandersnatch'
import {
  bytesToBigIntLittleEndian,
  curvePointToNoble,
  elligator2HashToCurve,
} from '../crypto/elligator2'
import { generateNonceRfc8032 } from '../crypto/nonce-rfc8032'
import { pointToHashRfc9381 } from '../crypto/rfc9381'

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
   * Generate blinding factor deterministically (matches arkworks implementation)
   */
  static generateBlindingFactor(
    secretKey: Uint8Array,
    inputPoint: Uint8Array,
    auxData?: Uint8Array,
  ): Uint8Array {
    // This matches the ark-vrf PedersenSuite::blinding implementation
    const SUITE_ID = new TextEncoder().encode('Bandersnatch_SHA-512_ELL2')
    const DOM_SEP_START = 0xcc
    const DOM_SEP_END = 0x00

    let buf = new Uint8Array([...SUITE_ID, DOM_SEP_START])

    // Add scalar (secret key) in little-endian format (arkworks style)
    buf = new Uint8Array([...buf, ...secretKey])

    // Add point (input point)
    buf = new Uint8Array([...buf, ...inputPoint])

    // Add additional data
    if (auxData) {
      buf = new Uint8Array([...buf, ...auxData])
    }

    // Add domain separator end
    buf = new Uint8Array([...buf, DOM_SEP_END])

    // Hash and convert to scalar with big-endian interpretation (arkworks style)
    const hash = sha512(buf)
    let hashValue = BigInt(0)
    for (let i = 0; i < hash.length; i++) {
      hashValue = (hashValue << 8n) | BigInt(hash[i])
    }

    const blindingScalar = mod(hashValue, BandersnatchCurve.CURVE_ORDER)
    return numberToBytesLittleEndian(blindingScalar)
  }

  /**
   * Generate Pedersen VRF proof and output
   */
  static prove(
    secretKey: Uint8Array,
    input: PedersenVRFInput,
  ): PedersenVRFResult {
    const startTime = Date.now()

    console.debug('Generating Pedersen VRF proof', {
      inputLength: input.input.length,
      hasAuxData: !!input.auxData,
    })

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

      // Debug: Check if O_k is valid
      const O_kPoint = BandersnatchCurve.bytesToPoint(O_k)
      console.debug('Generated O_k point', {
        O_kX: O_kPoint.x.toString(16),
        O_kY: O_kPoint.y.toString(16),
        k: bytesToBigIntLittleEndian(k).toString(16),
        IX: BandersnatchCurve.bytesToPoint(I).x.toString(16),
        IY: BandersnatchCurve.bytesToPoint(I).y.toString(16),
      })

      // Step 8 - Generate challenge c = H2(Y_bar, I, O, R, O_k, ad)
      // This must be the same in both prover and verifier
      const c = this.generateChallenge(Y_bar, I, O, R, O_k, input.auxData)

      // Step 9 - Generate proof scalars s = k + c*x and s_b = k_b + c*b
      const s = this.generateProofScalar(k, c, secretKey)
      const s_b = this.generateBlindingProofScalar(k_b, c, blindingFactor)

      console.debug('Generated proof scalars', {
        sLength: s.length,
        s_bLength: s_b.length,
        sHex: Array.from(s.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(''),
        s_bHex: Array.from(s_b.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(''),
      })

      // Step 10 - Hash output (H2)
      const hash = this.hashOutput(O)

      const generationTime = Date.now() - startTime

      console.debug('Pedersen VRF proof generated successfully', {
        generationTime,
        proofSize: this.serialize({
          Y_bar,
          R,
          O_k,
          s,
          s_b,
        }).length,
        outputSize: hash.length,
      })

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
    const compressed = BandersnatchCurve.pointToBytes(
      curvePointToNoble(point),
    )
    return compressed
  }

  /**
   * Scalar multiplication on Bandersnatch curve
   */
  private static scalarMultiply(
    pointBytes: Uint8Array,
    scalarBytes: Uint8Array,
  ): Uint8Array {
    const point = BandersnatchCurve.bytesToPoint(pointBytes)
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
    const xG = BandersnatchCurve.scalarMultiply(
      BandersnatchCurve.GENERATOR,
      x,
    )
    const blindingBase = this.getBlindingBase()
    const bB = BandersnatchCurve.scalarMultiply(blindingBase, b)
    const Y_bar = BandersnatchCurve.add(xG, bB)

    // Debug: Check if Y_bar is valid
    console.debug('Generated Y_bar point', {
      Y_barX: Y_bar.x.toString(16),
      Y_barY: Y_bar.y.toString(16),
      x: x.toString(16),
      b: b.toString(16),
      xGX: xG.x.toString(16),
      xGY: xG.y.toString(16),
      bBX: bB.x.toString(16),
      bBY: bB.y.toString(16),
    })

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

    // Debug: Check if R is valid
    console.debug('Generated R point', {
      RX: R.x.toString(16),
      RY: R.y.toString(16),
      k: kScalar.toString(16),
      k_b: k_bScalar.toString(16),
      kGX: kG.x.toString(16),
      kGY: kG.y.toString(16),
      k_bBX: k_bB.x.toString(16),
      k_bBY: k_bB.y.toString(16),
    })

    return BandersnatchCurve.pointToBytes(R)
  }

  /**
   * Generate challenge c = H2(Y_bar, I, O, R, O_k, ad) using RFC-9381 format
   * Matches arkworks challenge_rfc_9381 implementation
   */
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
    // RFC-9381 challenge format with domain separators
    const SUITE_ID = new TextEncoder().encode('Bandersnatch_SHA-512_ELL2')
    const DOM_SEP_START = 0x02
    const DOM_SEP_END = 0x00

    // Start with suite ID and start separator
    let buf = new Uint8Array([...SUITE_ID, DOM_SEP_START])

    // Add all points in order: Y_bar, I, O, R, O_k
    buf = new Uint8Array([...buf, ...Y_bar])
    buf = new Uint8Array([...buf, ...I])
    buf = new Uint8Array([...buf, ...O])
    buf = new Uint8Array([...buf, ...R])
    buf = new Uint8Array([...buf, ...O_k])

    // Add additional data
    if (auxData && auxData.length > 0) {
      buf = new Uint8Array([...buf, ...auxData])
    }

    // Add end separator
    buf = new Uint8Array([...buf, DOM_SEP_END])

    // Hash using SHA-512
    const hashBytes = sha512(buf)

    // Take first 32 bytes (CHALLENGE_LEN) and interpret as big-endian (arkworks style)
    const challengeBytes = hashBytes.slice(0, 32)
    let hashValue = BigInt(0)
    for (let i = 0; i < challengeBytes.length; i++) {
      hashValue = (hashValue << 8n) | BigInt(challengeBytes[i])
    }

    return mod(hashValue, BandersnatchCurve.CURVE_ORDER)
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
    // Use RFC-9381 point-to-hash procedure (same as IETF VRF)
    return pointToHashRfc9381(gamma, false)
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
    // Serialize as: Y_bar || R || O_k || s || s_b
    return new Uint8Array([
      ...proof.Y_bar,
      ...proof.R,
      ...proof.O_k,
      ...proof.s,
      ...proof.s_b,
    ])
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
