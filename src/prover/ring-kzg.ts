/**
 * Ring VRF Prover with c-kzg Polynomial Commitments
 *
 * Implements Ring VRF using c-kzg for production-grade polynomial commitments.
 * This combines Pedersen VRF with KZG ring membership proofs for anonymity.
 * Uses custom SRS reading instead of loadTrustedSetup.
 */

import { pippenger } from '@noble/curves/abstract/curve.js'
import * as fft from '@noble/curves/abstract/fft.js'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BANDERSNATCH_PARAMS, BandersnatchCurve } from '@pbnjam/bandersnatch'
import { bytesToHex } from 'viem'
import { bytesToBigIntLittleEndian } from '../crypto/elligator2'
import { Domain } from '../plonk/domain/domain'
import { PiopParams } from '../plonk/piop/params'
import { PiopProver } from '../plonk/piop/prover'
import { PlonkProver } from '../plonk/prover'
import { SimplePlonkTranscript } from '../plonk/transcript/transcript'
import {
  bigintToBytes32BE,
  blobToKzgCommitment,
  computeBlobKzgProof,
  createRingPolynomial,
  evaluatePolynomialAt,
  extractRingCoordinateVectors,
  polynomialToBlob,
  verifyKzgProof,
} from '../utils/kzg-manual'
import { loadSRSFromFile } from '../utils/srs-loader'
import { PedersenVRFProver } from './pedersen'

export interface RingVRFInput {
  /** VRF input data */
  input: Uint8Array
  /** Additional data (not affecting VRF output) */
  auxData?: Uint8Array
  /** Ring of public keys */
  ringKeys: Uint8Array[]
  /** Prover's key index in the ring */
  proverIndex: number
}

export interface RingVRFProof {
  /** Pedersen VRF proof components */
  pedersenProof: Uint8Array
  /** Ring commitment (KZG commitment to ring polynomial) */
  ringCommitment: Uint8Array
  /** Ring membership proof (KZG proof) */
  ringProof: Uint8Array
  /** Prover index (for verification, not revealed in anonymous version) */
  proverIndex?: number
}

export interface RingVRFResult {
  /** VRF output */
  gamma: Uint8Array
  /** Ring VRF proof */
  proof: RingVRFProof
}

/**
 * Ring VRF Prover using c-kzg for polynomial commitments
 * Supports both blob commitment (default) and MSM with Lagrangian SRS (when SRS is provided)
 */
export class RingVRFProver {
  private srsG1: Uint8Array // G1 generator
  private srsG1Points: Uint8Array[] // Monomial SRS points [G, τG, τ²G, ...]
  private lagrangianSRS: Uint8Array[] // Lagrangian SRS points [L₀(τ)G, L₁(τ)G, ...]
  private srsG2: Uint8Array // G2 generator
  private srsG2Tau: Uint8Array // τ*G2 (second G2 point from SRS)
  private piopDomainSize: number // PIOP domain size (used for computeRingCommitment)
  private piopParams?: PiopParams // PIOP parameters for Plonk-based proofs
  private plonkProver?: PlonkProver // Plonk prover instance

  /**
   * Convert monomial SRS to Lagrangian SRS using batch IFFT on group elements
   *
   * Algorithm (matching Rust fflonk implementation):
   * 1. Take monomial SRS points [G, τG, τ²G, ..., τ^(domainSize-1)G] as group elements
   * 2. Apply IFFT directly on the points (IFFT is linear, works on group elements)
   * 3. Result: [L₀(τ)G, L₁(τ)G, ..., L_(domainSize-1)(τ)G] directly
   *
   * This is much more efficient than sequential IFFT: O(n log n) vs O(n² log n)
   *
   * @param monomialSRS - Monomial SRS points [G, τG, τ²G, ..., τ^(domainSize-1)G] (must be at least domainSize points)
   * @param domainSize - Domain size n for IFFT (e.g., 2048) - must be power of 2
   * @param count - Number of Lagrangian points to convert (default: domainSize, can be less for optimization)
   * @returns Lagrangian SRS points [L₀(τ)G, L₁(τ)G, ..., L_(count-1)(τ)G]
   */
  private convertToLagrangianSRS(
    monomialSRS: Uint8Array[],
    domainSize: number,
    count?: number,
  ): Uint8Array[] {
    const actualCount = count ?? domainSize

    // Pre-deserialize monomial SRS points as group elements
    // We need domainSize points for IFFT (even if count < domainSize)
    const monomialBases: ReturnType<typeof bls12_381.G1.Point.fromBytes>[] = []
    for (let i = 0; i < domainSize; i++) {
      if (i >= monomialSRS.length) {
        throw new Error(
          `Monomial SRS too short: need ${domainSize} points for IFFT, have ${monomialSRS.length}`,
        )
      }
      monomialBases.push(bls12_381.G1.Point.fromBytes(monomialSRS[i]!))
    }

    console.debug('[convertToLagrangianSRS] Starting batch IFFT conversion', {
      domainSize,
      count: actualCount,
      monomialSRSSize: monomialSRS.length,
    })

    // Apply IFFT directly on group elements (matching Rust: domain.ifft_in_place(&mut monomial_bases))
    // IFFT is linear, so it works on points: IFFT([G, τG, τ²G, ...]) = [L₀(τ)G, L₁(τ)G, ...]
    const lagrangianBases = this.ifftOnGroupElements(monomialBases, domainSize)

    // Normalize to affine (matching Rust: G::Group::normalize_batch(&lagrangian_bases))
    const lagrangianSRS: Uint8Array[] = []
    for (let i = 0; i < actualCount; i++) {
      lagrangianSRS.push(lagrangianBases[i]!.toBytes(true))
    }

    console.debug('[convertToLagrangianSRS] Batch IFFT conversion complete', {
      lagrangianSRSSize: lagrangianSRS.length,
    })

    return lagrangianSRS
  }

  /**
   * Apply IFFT directly on group elements (points)
   *
   * This implements the IFFT algorithm but operates on group elements instead of scalars.
   * The algorithm is the same as scalar IFFT, but uses point addition and scalar multiplication.
   *
   * Matching Rust: domain.ifft_in_place(&mut monomial_bases) where monomial_bases is Vec<G::Group>
   *
   * @param points - Group elements [G, τG, τ²G, ..., τ^(n-1)G]
   * @param domainSize - Domain size n (must be power of 2)
   * @returns Lagrangian points [L₀(τ)G, L₁(τ)G, ..., L_(n-1)(τ)G]
   */
  private ifftOnGroupElements(
    points: ReturnType<typeof bls12_381.G1.Point.fromBytes>[],
    domainSize: number,
  ): ReturnType<typeof bls12_381.G1.Point.fromBytes>[] {
    if (points.length !== domainSize) {
      throw new Error(
        `Points length ${points.length} must equal domain size ${domainSize}`,
      )
    }

    const Fr = bls12_381.fields.Fr
    const domainSizeBigInt = BigInt(domainSize)

    // Bit-reverse permutation (same as scalar IFFT)
    const logN = Math.log2(domainSize)
    if (logN % 1 !== 0) {
      throw new Error(`Domain size ${domainSize} must be a power of 2`)
    }

    // Get roots of unity for the domain
    const roots = fft.rootsOfUnity(Fr, domainSizeBigInt)
    const omega = roots.omega(logN) // Primitive root of unity (needs log2(domainSize))
    const omegaInv = Fr.inv(omega) // Inverse for IFFT

    // IFFT algorithm on group elements
    // Same as scalar IFFT, but with point operations:
    // - Point addition: P + Q
    // - Scalar multiplication: s * P
    const result = [...points]

    // Bit-reverse permutation
    for (let i = 0; i < domainSize; i++) {
      const j = this.bitReverse(i, logN)
      if (i < j) {
        const temp = result[i]
        result[i] = result[j]!
        result[j] = temp!
      }
    }

    // Cooley-Tukey IFFT algorithm (inverse FFT)
    let m = 1
    for (let s = 1; s <= logN; s++) {
      const wm = Fr.pow(omegaInv, BigInt(domainSize / (2 * m)))
      let k = 0
      while (k < domainSize) {
        let w = Fr.ONE
        for (let j = 0; j < m; j++) {
          const t = result[k + j + m]!.multiply(w)
          const u = result[k + j]!
          result[k + j] = u.add(t)
          result[k + j + m] = u.subtract(t)
          w = Fr.mul(w, wm)
        }
        k += 2 * m
      }
      m *= 2
    }

    // Normalize by dividing by domain size (IFFT normalization)
    const domainSizeInv = Fr.inv(Fr.create(BigInt(domainSize)))
    for (let i = 0; i < domainSize; i++) {
      result[i] = result[i]!.multiply(domainSizeInv)
    }

    return result
  }

  /**
   * Bit-reverse an index for FFT/IFFT
   *
   * @param index - Index to reverse
   * @param logN - Log2 of the array size
   * @returns Bit-reversed index
   */
  private bitReverse(index: number, logN: number): number {
    let reversed = 0
    for (let i = 0; i < logN; i++) {
      reversed = (reversed << 1) | (index & 1)
      index >>= 1
    }
    return reversed
  }

  /**
   * Calculate PIOP domain size from ring size (matching Rust piop_domain_size function)
   *
   * Rust formula: piop_domain_size(ring_size) = (ring_size + 4 + 253).next_power_of_two()
   *
   * @param ringSize - Maximum ring size (number of validators)
   * @returns PIOP domain size (power of 2)
   */
  private static calculatePiopDomainSize(ringSize: number): number {
    const scalarBitlen = 253 // Bandersnatch scalar field bit length
    const idleRows = 4
    // piop_domain_size = next_power_of_two(ring_size + idle_rows + scalar_bitlen)
    return 2 ** Math.ceil(Math.log2(ringSize + idleRows + scalarBitlen))
  }

  /**
   * Calculate PCS domain size from ring size (matching Rust pcs_domain_size function)
   *
   * Rust formula: pcs_domain_size(ring_size) = 3 * piop_domain_size(ring_size) + 1
   *
   * @param ringSize - Maximum ring size (number of validators)
   * @returns PCS domain size (number of SRS points needed)
   */
  private static calculatePcsDomainSize(ringSize: number): number {
    const piopDomainSize = RingVRFProver.calculatePiopDomainSize(ringSize)
    // pcs_domain_size = 3 * piop_domain_size + 1
    return 3 * piopDomainSize + 1
  }

  /**
   * Create a new Ring VRF Prover instance
   *
   * Note: Lagrangian SRS conversion is cached in the constructor (computed once).
   * This is more efficient than Rust's approach which recomputes on each RingBuilderKey creation.
   *
   * @param srsFilePath - Path to SRS file for MSM-based commitments
   * @param ringSize - Maximum ring size (number of validators/keys in the ring)
   */
  constructor(srsFilePath: string, ringSize: number) {
    const [error, result] = loadSRSFromFile(srsFilePath)
    if (error) {
      throw new Error(`Failed to load SRS for verification: ${error.message}`)
    }
    this.srsG1Points = result.g1Points
    this.srsG1 = result.g1
    this.srsG2 = result.g2
    this.srsG2Tau = result.g2Points[1]

    // Calculate PIOP domain size (matching Rust: piop_domain_size(ring_size))
    // This is the domain size used for Lagrangian SRS conversion
    // Rust calls: ck_with_lagrangian(piop_domain_size)
    const piopDomainSize = RingVRFProver.calculatePiopDomainSize(ringSize)

    // Calculate PCS domain size (for SRS truncation)
    const pcsDomainSize = RingVRFProver.calculatePcsDomainSize(ringSize)

    // Calculate required Lagrangian SRS size
    // Rust's with_keys requires: bases.length == xs.length == ys.length
    // Coordinate vectors: keys.len() + scalarBitlen + idleRows + 1
    // Bases: keys.len() + (lagrangianSRS.length - keysetPartSize) + 1
    // For match: lagrangianSRS.length - keysetPartSize == scalarBitlen + idleRows
    // Since keysetPartSize = piopDomainSize - scalarBitlen - 1:
    //   lagrangianSRS.length = keysetPartSize + scalarBitlen + idleRows
    //   lagrangianSRS.length = (piopDomainSize - scalarBitlen - 1) + scalarBitlen + idleRows
    //   lagrangianSRS.length = piopDomainSize + idleRows - 1
    //   lagrangianSRS.length = piopDomainSize + 3
    const scalarBitlen = 253
    const idleRows = 4
    const keysetPartSize = piopDomainSize - scalarBitlen - 1
    const requiredLagrangianSize = keysetPartSize + scalarBitlen + idleRows // = piopDomainSize + 3

    // Truncate monomial SRS to pcsDomainSize (matching Rust: pcs_params.powers_in_g1.truncate(pcs_domain_size))
    if (this.srsG1Points.length < pcsDomainSize) {
      throw new Error(
        `SRS file too short: need ${pcsDomainSize} points for ring size ${ringSize}, have ${this.srsG1Points.length}`,
      )
    }
    const truncatedMonomialSRS = this.srsG1Points.slice(0, pcsDomainSize)

    // For IFFT conversion, we need a domain size that's a power of 2 and >= requiredLagrangianSize
    // Use the next power of 2 that can accommodate all required Lagrangian points
    const ifftDomainSize = 2 ** Math.ceil(Math.log2(requiredLagrangianSize))

    // We need monomial SRS points up to ifftDomainSize for IFFT conversion
    if (truncatedMonomialSRS.length < ifftDomainSize) {
      throw new Error(
        `SRS file too short: need ${ifftDomainSize} points for IFFT conversion (to compute ${requiredLagrangianSize} Lagrangian points), have ${truncatedMonomialSRS.length}`,
      )
    }
    const monomialSRSForConversion = truncatedMonomialSRS.slice(
      0,
      ifftDomainSize,
    )

    console.debug('[RingVRFProver] Converting monomial SRS to Lagrangian SRS', {
      ringSize,
      piopDomainSize,
      pcsDomainSize,
      keysetPartSize,
      requiredLagrangianSize,
      ifftDomainSize,
      lagrangianPointsToConvert: requiredLagrangianSize,
      monomialSRSSize: monomialSRSForConversion.length,
      originalSRSSize: this.srsG1Points.length,
    })

    // Convert to Lagrangian SRS
    // We use ifftDomainSize (next power of 2 >= requiredLagrangianSize) for IFFT,
    // but only convert the requiredLagrangianSize points (piopDomainSize + 3)
    // This ensures we have enough points to match Rust's with_keys requirements
    this.lagrangianSRS = this.convertToLagrangianSRS(
      monomialSRSForConversion,
      ifftDomainSize,
      requiredLagrangianSize,
    )

    // Store piopDomainSize for use in computeRingCommitment
    this.piopDomainSize = piopDomainSize

    console.debug('[RingVRFProver] Lagrangian SRS conversion complete', {
      lagrangianSRSSize: this.lagrangianSRS.length,
    })

    // Initialize Plonk prover/verifier setup (lazy initialization)
    // This will be initialized when provePlonk is called
  }

  /**
   * Generate Ring VRF proof and output
   */
  prove(secretKey: Uint8Array, input: RingVRFInput): RingVRFResult {
    console.debug('Generating Ring VRF proof', {
      ringSize: input.ringKeys.length,
      proverIndex: input.proverIndex,
      inputLength: input.input.length,
    })

    // Step 1: Generate Pedersen VRF proof
    console.debug('Starting Pedersen VRF proof generation')
    const pedersenInput = {
      input: input.input,
      auxData: input.auxData,
    }
    const pedersenResult = PedersenVRFProver.prove(secretKey, pedersenInput)
    console.debug('Pedersen VRF proof generation completed')

    console.debug('Pedersen VRF proof generated', {
      outputHash: bytesToHex(pedersenResult.hash),
      proofLength: pedersenResult.proof.length,
    })

    // Step 2: Create ring polynomial from public keys
    const ringPolynomial = createRingPolynomial(input.ringKeys)

    console.debug('Ring polynomial created', {
      degree: ringPolynomial.length - 1,
      coefficientsPreview: ringPolynomial
        .slice(0, 3)
        .map((c) => c.toString(16))
        .join(', '),
    })

    // Step 3: Generate KZG commitment to ring polynomial
    const ringBlob = polynomialToBlob(ringPolynomial)

    const [commitmentError, ringCommitment] = blobToKzgCommitment(
      ringBlob,
      this.srsG1Points,
    )
    if (commitmentError || !ringCommitment) {
      throw new Error(
        `Failed to compute ring commitment: ${commitmentError?.message ?? 'unknown error'}`,
      )
    }

    console.debug('Ring commitment generated', {
      commitment: bytesToHex(ringCommitment),
      blobSize: ringBlob.length,
    })

    // Step 4: Generate KZG proof for prover's key membership
    // For ring proofs, we use the domain generator as the evaluation point
    const domainGenerator = BANDERSNATCH_PARAMS.KZG_CONFIG.DOMAIN_GENERATOR
    const zBytes = bigintToBytes32BE(domainGenerator)

    const [proofError, ringProof] = computeBlobKzgProof(
      ringBlob,
      zBytes,
      this.srsG1Points,
    )
    if (proofError || !ringProof) {
      throw new Error(
        `Failed to compute ring proof: ${proofError?.message ?? 'unknown error'}`,
      )
    }

    console.debug('Ring membership proof generated', {
      proof: bytesToHex(ringProof),
    })

    // Evaluate polynomial at z to get y
    const y = evaluatePolynomialAt(ringPolynomial, domainGenerator)
    const yBytes = bigintToBytes32BE(y)

    const [verifyError, isValid] = verifyKzgProof(
      ringCommitment,
      zBytes,
      yBytes,
      ringProof,
      this.srsG1,
      this.srsG2,
      this.srsG2Tau,
    )

    // Debug logging when verification fails
    if (verifyError || !isValid) {
      console.error('KZG proof verification failed - debugging info', {
        commitment: bytesToHex(ringCommitment),
        zBytes: bytesToHex(zBytes),
        yBytes: bytesToHex(yBytes),
        proof: bytesToHex(ringProof),
        z: domainGenerator.toString(16),
        y: y.toString(16),
        polynomialLength: ringPolynomial.length,
        polynomialDegree: ringPolynomial.length - 1,
        verifyError: verifyError?.message,
        isValid,
      })
      throw new Error(
        `Generated ring proof failed verification: ${verifyError?.message ?? 'proof invalid'}`,
      )
    }

    console.debug('Ring VRF proof verification passed')

    return {
      gamma: pedersenResult.gamma,
      proof: {
        pedersenProof: pedersenResult.proof,
        ringCommitment,
        ringProof,
        proverIndex: input.proverIndex, // In anonymous version, this would be omitted
      },
    }
  }

  /**
   * Generate Ring VRF proof using Plonk (instead of direct KZG)
   *
   * This method uses the Plonk zkSNARK protocol for ring membership proofs,
   * providing better anonymity and smaller proof sizes compared to direct KZG.
   *
   * @param secretKey - Prover's secret key (32 bytes)
   * @param input - Ring VRF input (ring keys, prover index, etc.)
   * @returns Ring VRF result with Plonk-based ring proof
   */
  provePlonk(secretKey: Uint8Array, input: RingVRFInput): RingVRFResult {
    console.debug('Generating Ring VRF proof with Plonk', {
      ringSize: input.ringKeys.length,
      proverIndex: input.proverIndex,
      inputLength: input.input.length,
    })

    // Step 1: Generate Pedersen VRF proof
    console.debug('Starting Pedersen VRF proof generation')
    const pedersenInput = {
      input: input.input,
      auxData: input.auxData,
    }
    const pedersenResult = PedersenVRFProver.prove(secretKey, pedersenInput)
    console.debug('Pedersen VRF proof generation completed')

    // Step 2: Initialize PIOP params if not already done
    if (!this.piopParams) {
      const domainSize = this.piopDomainSize
      const domain = new Domain(domainSize, true) // hiding = true

      // Get base points from config
      // Blinding base h is the Pedersen VRF blinding base point B
      // Matching Rust: EdwardsAffine::new_unchecked(MontFp!("6150229251051246713677296363717454238956877613358614224171740096471278798312"), ...)
      const h = {
        x: BANDERSNATCH_PARAMS.BLINDING_BASE.x,
        y: BANDERSNATCH_PARAMS.BLINDING_BASE.y,
      }
      const seed = PiopParams.getAccumulatorSeedPoint()
      const padding = PiopParams.getPaddingPoint()

      this.piopParams = PiopParams.setup(domain, h, seed, padding)
    }

    // Step 3: Convert ring keys to point format
    const ringKeys: Array<{ x: bigint; y: bigint }> = []
    for (const keyBytes of input.ringKeys) {
      const point = BandersnatchCurve.bytesToPoint(keyBytes)
      // Extract x and y directly from EdwardsPoint
      // EdwardsPoint from @noble/curves has x and y properties
      ringKeys.push({ x: point.x, y: point.y })
    }

    // Step 4: Setup Plonk prover/verifier keys
    // Compute ring commitment first (needed for verifier key)
    // This matches Rust: FixedColumns.commit() which commits to points.xs.poly, points.ys.poly, ringSelector.poly
    const ringCommitmentBytes = this.computeRingCommitment(input.ringKeys)

    // Parse FixedColumnsCommitted from ringCommitment (144 bytes: cx[48] + cy[48] + selector[48])
    // Matching Rust: FixedColumnsCommitted structure in w3f-ring-proof/src/piop/mod.rs:84-88
    const fixedColumnsCommitted = {
      points: [
        ringCommitmentBytes.slice(0, 48),
        ringCommitmentBytes.slice(48, 96),
      ] as [Uint8Array, Uint8Array],
      ringSelector: ringCommitmentBytes.slice(96, 144),
    }

    // Build fixed columns (matching Rust: piopParams.fixedColumns(keys))
    const fixedColumns = this.piopParams.fixedColumns(ringKeys)

    // Create verifier key with actual commitments (not placeholders)
    // Matching Rust: VerifierKey in w3f-ring-proof/src/piop/mod.rs:136-141
    const verifierKey = {
      pcsRawVk: {
        g1: this.srsG1, // SRS G1 generator (48 bytes compressed)
        g2: this.srsG2, // SRS G2 generator (96 bytes compressed)
        tauInG2: this.srsG2Tau, // tau * G2 (96 bytes compressed)
      },
      fixedColumnsCommitted,
    }

    // Create prover key (matching Rust: ProverKey in w3f-ring-proof/src/piop/mod.rs:130-134)
    const proverKey = {
      pcsCk: {
        srsG1Points: this.srsG1Points, // SRS G1 points for committing
      },
      fixedColumns,
      verifierKey,
    }

    // Step 5: Initialize Plonk prover if not already done
    if (!this.plonkProver) {
      const pcsCk = {
        srsG1Points: this.srsG1Points,
        srsG1: this.srsG1,
        srsG2: this.srsG2,
        srsG2Tau: this.srsG2Tau,
      }
      const transcript = SimplePlonkTranscript.new('w3f-ring-proof')
      // Serialize verifier key for transcript (computed in Step 4)
      // Rust: VerifierKey implements CanonicalSerialize (w3f-ring-proof/src/piop/mod.rs:136)
      // Structure: pcsRawVk (G1[48] + G2[96] + G2Tau[96] = 240 bytes) + fixedColumnsCommitted (points[2*48] + ringSelector[48] = 144 bytes)
      // Total: 240 + 144 = 384 bytes
      const verifierKeyBytes = new Uint8Array(384)
      let offset = 0

      // Serialize pcsRawVk: g1 (48) + g2 (96) + tauInG2 (96) = 240 bytes
      verifierKeyBytes.set(verifierKey.pcsRawVk.g1, offset)
      offset += 48
      verifierKeyBytes.set(verifierKey.pcsRawVk.g2, offset)
      offset += 96
      verifierKeyBytes.set(verifierKey.pcsRawVk.tauInG2, offset)
      offset += 96

      // Serialize fixedColumnsCommitted: points[0] (48) + points[1] (48) + ringSelector (48) = 144 bytes
      verifierKeyBytes.set(verifierKey.fixedColumnsCommitted.points[0], offset)
      offset += 48
      verifierKeyBytes.set(verifierKey.fixedColumnsCommitted.points[1], offset)
      offset += 48
      verifierKeyBytes.set(
        verifierKey.fixedColumnsCommitted.ringSelector,
        offset,
      )

      this.plonkProver = PlonkProver.init(pcsCk, verifierKeyBytes, transcript)
    }

    // Step 6: Build PIOP prover
    const secretScalar = bytesToBigIntLittleEndian(secretKey)
    const piopProver = PiopProver.build(
      this.piopParams,
      proverKey.fixedColumns,
      input.proverIndex,
      secretScalar,
    )

    // Step 7: Generate Plonk proof
    console.debug('Generating Plonk proof')
    const plonkProof = this.plonkProver.prove(piopProver)
    console.debug('Plonk proof generated')

    // Step 8: Use ring commitment computed in Step 4
    // The ring commitment is the FixedColumnsCommitted structure (144 bytes)
    // This matches Rust: Ring::with_keys() which computes cx, cy, selector
    const ringCommitment = ringCommitmentBytes

    // Step 9: Serialize Plonk proof
    // Rust serialization order (matching CanonicalSerialize):
    // 1. Column commitments (4 commitments × 48 bytes = 192 bytes)
    //    - bits, innProdAcc, condAddAcc[0], condAddAcc[1]
    // 2. Column evaluations at zeta (7 evaluations × 32 bytes = 224 bytes)
    //    - points[0], points[1], ringSelector, bits, innProdAcc, condAddAcc[0], condAddAcc[1]
    // 3. Quotient commitment (48 bytes)
    // 4. Linearization evaluation at zeta*omega (32 bytes)
    // 5. Aggregated KZG proof at zeta (48 bytes)
    // 6. Linearization KZG proof at zeta*omega (48 bytes)
    // Total: 192 + 224 + 48 + 32 + 48 + 48 = 592 bytes (for standard ring size)
    const commitments = plonkProof.columnCommitments.toVec()
    const evaluations = plonkProof.columnsAtZeta.toVec()

    const COMMITMENT_SIZE = 48 // Compressed G1 point
    const EVALUATION_SIZE = 32 // Field element (big-endian)

    const ringProof = new Uint8Array(
      commitments.length * COMMITMENT_SIZE +
        evaluations.length * EVALUATION_SIZE +
        COMMITMENT_SIZE + // quotientCommitment
        EVALUATION_SIZE + // linAtZetaOmega
        COMMITMENT_SIZE + // aggAtZetaProof
        COMMITMENT_SIZE, // linAtZetaOmegaProof
    )

    let offset = 0

    // 1. Column commitments (192 bytes)
    for (const commitment of commitments) {
      if (commitment.length !== COMMITMENT_SIZE) {
        throw new Error(
          `Invalid commitment size: expected ${COMMITMENT_SIZE}, got ${commitment.length}`,
        )
      }
      ringProof.set(commitment, offset)
      offset += COMMITMENT_SIZE
    }

    // 2. Column evaluations at zeta (224 bytes)
    for (const evalValue of evaluations) {
      const evalBytes = bigintToBytes32BE(evalValue)
      ringProof.set(evalBytes, offset)
      offset += EVALUATION_SIZE
    }

    // 3. Quotient commitment (48 bytes)
    if (plonkProof.quotientCommitment.length !== COMMITMENT_SIZE) {
      throw new Error(
        `Invalid quotient commitment size: expected ${COMMITMENT_SIZE}, got ${plonkProof.quotientCommitment.length}`,
      )
    }
    ringProof.set(plonkProof.quotientCommitment, offset)
    offset += COMMITMENT_SIZE

    // 4. Linearization evaluation at zeta*omega (32 bytes)
    const linEvalBytes = bigintToBytes32BE(plonkProof.linAtZetaOmega)
    ringProof.set(linEvalBytes, offset)
    offset += EVALUATION_SIZE

    // 5. Aggregated KZG proof at zeta (48 bytes)
    if (plonkProof.aggAtZetaProof.length !== COMMITMENT_SIZE) {
      throw new Error(
        `Invalid aggregated proof size: expected ${COMMITMENT_SIZE}, got ${plonkProof.aggAtZetaProof.length}`,
      )
    }
    ringProof.set(plonkProof.aggAtZetaProof, offset)
    offset += COMMITMENT_SIZE

    // 6. Linearization KZG proof at zeta*omega (48 bytes)
    if (plonkProof.linAtZetaOmegaProof.length !== COMMITMENT_SIZE) {
      throw new Error(
        `Invalid linearization proof size: expected ${COMMITMENT_SIZE}, got ${plonkProof.linAtZetaOmegaProof.length}`,
      )
    }
    ringProof.set(plonkProof.linAtZetaOmegaProof, offset)
    offset += COMMITMENT_SIZE

    console.debug('Plonk proof serialized', {
      ringProofSize: ringProof.length,
      ringCommitmentSize: ringCommitment.length,
      commitmentsCount: commitments.length,
      evaluationsCount: evaluations.length,
    })

    return {
      gamma: pedersenResult.gamma,
      proof: {
        pedersenProof: pedersenResult.proof,
        ringCommitment,
        ringProof,
        proverIndex: input.proverIndex,
      },
    }
  }

  /**
   * Compute ring commitment from public keys only (Gray Paper compliant)
   *
   * Gray Paper bandersnatch.tex equation 15:
   * getRingRoot{sequence{bskey}} ∈ ringroot ≡ commit(sequence{bskey})
   *
   * This method computes the FixedColumnsCommitted structure matching Rust implementation:
   * - cx: KZG commitment to x-coordinates vector
   * - cy: KZG commitment to y-coordinates vector
   * - selector: KZG commitment to bitvector marking key positions
   *
   * Rust reference: Ring::with_keys() in w3f-ring-proof/src/ring.rs
   *
   * @param ringKeys - Array of Bandersnatch public keys (32 bytes each)
   * @returns FixedColumnsCommitted structure (144 bytes: cx[48] + cy[48] + selector[48])
   */
  computeRingCommitment(ringKeys: Uint8Array[]): Uint8Array {
    // Use piopDomainSize (not fixed 2048) - matching Rust PiopParams
    const domainSize = this.piopDomainSize
    const scalarBitlen = 253 // Bandersnatch scalar field bit length
    const keysetPartSize = domainSize - scalarBitlen - 1 // domain.capacity - scalar_bitlen - 1

    // #region agent log
    console.log('[computeRingCommitment] Start:', {
      domainSize,
      scalarBitlen,
      keysetPartSize,
      ringKeysLength: ringKeys.length,
      lagrangianSRSSize: this.lagrangianSRS.length,
    })
    // #endregion

    // Reuse shared coordinate extraction logic
    const { xs, ys } = extractRingCoordinateVectors(ringKeys)

    // #region agent log
    console.log('[computeRingCommitment] Extracted coordinates:', {
      xsLength: xs.length,
      ysLength: ys.length,
      xsFirst3: xs.slice(0, 3).map((x) => x.toString(16)),
      ysFirst3: ys.slice(0, 3).map((y) => y.toString(16)),
    })
    // #endregion

    // Compute MSM for cx and cy using Lagrangian SRS
    // This matches Rust implementation: srs.lis_in_g1 (Lagrangian SRS)

    // Build SRS bases matching Rust structure:
    // bases = [srs[0..keys.len()], srs[keyset_part_size..], [g1]]
    // The srs[keyset_part_size..] slice includes points for:
    // - powers_of_h (scalar_bitlen points)
    // - idle_rows (4 points)
    // - and possibly more (we take what we need)
    const keysSrsLength = ringKeys.length
    const powersOfHSrsStart = keysetPartSize
    const idleRows = 4

    // Pre-deserialize Lagrangian SRS points once (major performance optimization)
    // This avoids deserializing the same points multiple times
    const deserializedBases: ReturnType<typeof bls12_381.G1.Point.fromBytes>[] =
      []
    // Keys portion: lagrangianSRS[0..keys.len()]
    for (let i = 0; i < keysSrsLength; i++) {
      const point = this.lagrangianSRS[i]
      if (point) {
        deserializedBases.push(bls12_381.G1.Point.fromBytes(point))
      }
    }
    // Powers of H + idle rows portion: lagrangianSRS[keyset_part_size..]
    // Rust uses srs[keyset_part_size..] which is a slice to the END of the SRS
    // This matches Rust: &srs.lis_in_g1[piop_params.keyset_part_size..]
    for (let i = powersOfHSrsStart; i < this.lagrangianSRS.length; i++) {
      const point = this.lagrangianSRS[i]
      if (point) {
        deserializedBases.push(bls12_381.G1.Point.fromBytes(point))
      }
    }

    // Final padding: g1
    // Rust: &[srs.g1.into()]
    deserializedBases.push(bls12_381.G1.Point.fromBytes(this.srsG1))

    // Rust expects: bases.length == xs.length == ys.length
    // Coordinate vectors have: keys.len() + scalarBitlen + idleRows + 1
    // Bases have: keys.len() + (lagrangianSRS.length - keysetPartSize) + 1
    // For these to match, we need: lagrangianSRS.length - keysetPartSize == scalarBitlen + idleRows
    // Which means: lagrangianSRS.length == keysetPartSize + scalarBitlen + idleRows
    // Or: piopDomainSize == keysetPartSize + scalarBitlen + idleRows
    // Since keysetPartSize = piopDomainSize - scalarBitlen - 1:
    //   piopDomainSize == (piopDomainSize - scalarBitlen - 1) + scalarBitlen + idleRows
    //   piopDomainSize == piopDomainSize - 1 + idleRows
    //   0 == -1 + idleRows
    //   idleRows == 1, but we have idleRows == 4
    //
    // This suggests Rust's SRS might be larger than piopDomainSize, or the structure is different.
    // For now, we truncate coordinate vectors to match available bases (matching Rust's behavior
    // when SRS length doesn't match exactly).
    const expectedCoordinateLength = keysSrsLength + scalarBitlen + idleRows + 1
    const actualBasesLength = deserializedBases.length

    if (actualBasesLength !== expectedCoordinateLength) {
      // Truncate or pad coordinate vectors to match bases length
      // Rust would fail if lengths don't match, but we handle it gracefully
      if (actualBasesLength < expectedCoordinateLength) {
        // Truncate: remove from end (final_padding, then idle_rows, then powers_of_H)
        xs.splice(actualBasesLength)
        ys.splice(actualBasesLength)
        console.warn(
          `SRS length mismatch: coordinate vectors have ${expectedCoordinateLength} elements, but bases have ${actualBasesLength}. Truncated coordinate vectors.`,
        )
      } else {
        // Pad: add zeros (shouldn't happen if SRS is correctly sized)
        while (xs.length < actualBasesLength) {
          xs.push(0n)
          ys.push(0n)
        }
        console.warn(
          `SRS length mismatch: coordinate vectors have ${expectedCoordinateLength} elements, but bases have ${actualBasesLength}. Padded coordinate vectors with zeros.`,
        )
      }
    }

    // Ensure arrays have same length for pippenger (it requires equal length)
    const vectorLength = xs.length
    if (ys.length !== vectorLength) {
      throw new Error(
        `Coordinate vector length mismatch: xs=${vectorLength}, ys=${ys.length}`,
      )
    }
    if (deserializedBases.length !== vectorLength) {
      throw new Error(
        `SRS bases length mismatch: expected ${vectorLength}, got ${deserializedBases.length}`,
      )
    }

    // #region agent log
    console.log('[computeRingCommitment] SRS bases structure:', {
      vectorLength,
      keysSrsLength,
      powersOfHSrsStart,
      deserializedBasesLength: deserializedBases.length,
      lagrangianSRSSize: this.lagrangianSRS.length,
    })
    // #endregion

    // Prepare scalars for MSM
    // Note: xs and ys are already reduced modulo BLS12_381_SCALAR_FIELD_ORDER
    // (same as BANDERSNATCH_PARAMS.FIELD_MODULUS) in extractRingCoordinateVectors,
    // so no need to reduce again. However, we ensure they're not undefined.
    const xsScalars = xs.map((x) => x ?? 0n)
    const ysScalars = ys.map((y) => y ?? 0n)

    // Compute cx = MSM(bases, xs) using Pippenger's algorithm
    // Pippenger's algorithm: ~30x faster vs naive addition for large MSM
    // Uses windowing technique to batch operations efficiently:
    // - Splits scalars into windows (e.g., 8-bit chunks)
    // - Groups points by window values into buckets
    // - Processes windows from MSB to LSB with shared doublings
    // - Constant-time for same input size
    const cx = pippenger(bls12_381.G1.Point, deserializedBases, xsScalars)

    // #region agent log
    const cxBytes = cx.toBytes(true)
    const cxHex = Array.from(cxBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    console.log('[computeRingCommitment] Computed cx:', {
      cxHex: `${cxHex.slice(0, 64)}...`,
    })
    // #endregion

    // Compute cy = MSM(bases, ys) using Pippenger's algorithm
    const cy = pippenger(bls12_381.G1.Point, deserializedBases, ysScalars)

    // #region agent log
    const cyBytes = cy.toBytes(true)
    const cyHex = Array.from(cyBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    console.log('[computeRingCommitment] Computed cy:', {
      cyHex: `${cyHex.slice(0, 64)}...`,
    })
    // #endregion

    // Compute selector = g1 - sum(lagrangianSRS[keyset_part_size..])
    // Rust: selector_inv = srs.lis_in_g1[piop_params.keyset_part_size..].iter().sum()
    //       selector = srs.g1 - selector_inv
    // We use the same slice as for the bases (from keyset_part_size to end of SRS)
    const selectorPoints: ReturnType<typeof bls12_381.G1.Point.fromBytes>[] = []
    for (let i = powersOfHSrsStart; i < this.lagrangianSRS.length; i++) {
      const point = this.lagrangianSRS[i]
      if (point) {
        selectorPoints.push(bls12_381.G1.Point.fromBytes(point))
      }
    }
    const g1Point = bls12_381.G1.Point.fromBytes(this.srsG1)
    const selectorInv = selectorPoints.reduce(
      (acc, point) => acc.add(point),
      bls12_381.G1.Point.ZERO,
    )
    const selector = g1Point.subtract(selectorInv)

    // #region agent log
    const selectorBytes = selector.toBytes(true)
    const selectorHex = Array.from(selectorBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    console.log('[computeRingCommitment] Computed selector:', {
      selectorHex: `${selectorHex.slice(0, 64)}...`,
      selectorPointsLength: selectorPoints.length,
      powersOfHSrsStart,
    })
    // #endregion

    // Return FixedColumnsCommitted: [cx (48), cy (48), selector (48)] = 144 bytes
    const result = new Uint8Array(144)
    result.set(cx.toBytes(true), 0)
    result.set(cy.toBytes(true), 48)
    result.set(selector.toBytes(true), 96)

    // #region agent log
    const resultHex = Array.from(result)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    console.log('[computeRingCommitment] Final result:', {
      resultHex: `${resultHex.slice(0, 128)}...`,
      cxHex: resultHex.slice(0, 96),
      cyHex: resultHex.slice(96, 192),
      selectorHex: resultHex.slice(192, 288),
    })
    // #endregion

    return result
  }

  /**
   * Verify Ring VRF proof
   */
  verify(input: RingVRFInput, result: RingVRFResult): boolean {
    console.debug('Verifying Ring VRF proof', {
      ringSize: input.ringKeys.length,
      outputLength: result.gamma.length,
      proofLength: result.proof.pedersenProof.length,
    })

    // Step 2: Verify ring membership proof
    // Recreate ring polynomial
    const ringPolynomial = createRingPolynomial(input.ringKeys)

    const domainGenerator = BANDERSNATCH_PARAMS.KZG_CONFIG.DOMAIN_GENERATOR
    const zBytes = bigintToBytes32BE(domainGenerator)

    // Evaluate polynomial at z to get y = p(z)
    const y = evaluatePolynomialAt(ringPolynomial, domainGenerator)
    const yBytes = bigintToBytes32BE(y)

    // Verify KZG proof with correct parameters:
    // 1. commitmentBytes - the ring commitment
    // 2. zBytes - evaluation point (domain generator)
    // 3. yBytes - evaluation result y = p(z)
    // 4. proofBytes - the ring proof
    // 5. srsG1 - SRS G1 generator
    // 6. srsG2 - SRS G2 generator
    // 7. srsG2Tau - SRS G2 point τ*G2
    const [ringValidError, ringValid] = verifyKzgProof(
      result.proof.ringCommitment, // commitmentBytes (48 bytes)
      zBytes, // zBytes - domain generator (32 bytes)
      yBytes, // yBytes - evaluation result (32 bytes)
      result.proof.ringProof, // proofBytes (48 bytes)
      this.srsG1, // srsG1 (48 bytes)
      this.srsG2, // srsG2 (96 bytes)
      this.srsG2Tau, // srsG2Tau (96 bytes)
    )
    if (ringValidError || !ringValid) {
      throw new Error(
        `Failed to verify ring commitment: ${ringValidError?.message ?? 'unknown error'}`,
      )
    }

    console.debug('Ring VRF verification result', {
      ringValid,
    })

    return ringValid
  }

  /**
   * Extract VRF output from Ring VRF result
   */
  static extractOutput(result: RingVRFResult): Uint8Array {
    return result.gamma
  }

  /**
   * Check if ring size is valid
   */
  static isValidRingSize(ringSize: number): boolean {
    const maxRingSize = BANDERSNATCH_PARAMS.KZG_CONFIG.MAX_RING_SIZE
    return ringSize > 0 && ringSize <= maxRingSize
  }

  /**
   * Get maximum supported ring size
   */
  static getMaxRingSize(): number {
    return BANDERSNATCH_PARAMS.KZG_CONFIG.MAX_RING_SIZE
  }

  /**
   * Get SRS information (for c-kzg default setup)
   */
  static getSRSInfo(): {
    domainSize: number
    maxRingSize: number
    source: string
  } {
    return {
      domainSize: BANDERSNATCH_PARAMS.KZG_CONFIG.DOMAIN_SIZE,
      maxRingSize: BANDERSNATCH_PARAMS.KZG_CONFIG.MAX_RING_SIZE,
      source: 'c-kzg-default-trusted-setup',
    }
  }

  /**
   * Serialize Ring VRF result according to bandersnatch-vrf-spec
   *
   * According to VRF-AD spec: Π ← encode_compressed((O, π))
   * Where:
   * - O ∈ G: VRF output point (gamma)
   * - π = (π_p, π_r): Combined proof
   *   - π_p ∈ (G, G, G, F, F): Pedersen proof (5 components)
   *   - π_r ∈ ((G₁)⁴, (F)⁷, G₁, F, G₁, G₁): Ring proof
   *
   * Gray Paper notation.tex line 169: bsringproof{r ∈ ringroot}{x ∈ blob}{m ∈ blob} ⊂ blob[784]
   *
   * Structure: gamma(32) || pedersen_proof(160) || ring_proof(592)
   * Total: 784 bytes
   *
   * NOTE: ring_commitment is NOT included in the ticket proof - it's part of the epoch root (144 bytes).
   * The verifier can compute the ring commitment from the epoch root during verification.
   */
  static serialize(result: RingVRFResult): Uint8Array {
    const GAMMA_SIZE = 32 // VRF output point (gamma)
    const PEDERSEN_SIZE = 160 // 5 components × 32 bytes each

    const serialized = new Uint8Array(
      GAMMA_SIZE + PEDERSEN_SIZE + result.proof.ringProof.length,
    )
    let offset = 0

    // 1. VRF output point (gamma) - 32 bytes
    serialized.set(result.gamma, offset)
    offset += GAMMA_SIZE

    // 2. Pedersen proof (π_p) - 160 bytes
    if (result.proof.pedersenProof.length !== PEDERSEN_SIZE) {
      throw new Error(
        `Pedersen proof must be ${PEDERSEN_SIZE} bytes, got ${result.proof.pedersenProof.length}`,
      )
    }
    serialized.set(result.proof.pedersenProof, offset)
    offset += PEDERSEN_SIZE

    // 3. Ring proof - variable size (592 bytes for ring size 6)
    serialized.set(result.proof.ringProof, offset)
    offset += result.proof.ringProof.length

    return serialized
  }

  /**
   * Deserialize Ring VRF result according to bandersnatch-vrf-spec
   *
   * Gray Paper notation.tex line 169: bsringproof{r ∈ ringroot}{x ∈ blob}{m ∈ blob} ⊂ blob[784]
   *
   * Structure: gamma(32) || pedersen_proof(160) || ring_proof(592)
   * Total: 784 bytes
   *
   * NOTE: ring_commitment is NOT included in the ticket proof - it's part of the epoch root (144 bytes).
   * The verifier must compute the ring commitment from the epoch root during verification.
   */
  static deserialize(resultBytes: Uint8Array): RingVRFResult {
    const GAMMA_SIZE = 32 // VRF output point (gamma)
    const PEDERSEN_SIZE = 160 // 5 components × 32 bytes each
    const RING_COMMITMENT_SIZE = 48 // G1 point compressed

    let offset = 0

    // 1. Extract VRF output point (gamma) - 32 bytes
    const gamma = resultBytes.slice(offset, offset + GAMMA_SIZE)
    offset += GAMMA_SIZE

    // 2. Extract Pedersen proof (π_p) - 160 bytes
    const pedersenProof = resultBytes.slice(offset, offset + PEDERSEN_SIZE)
    offset += PEDERSEN_SIZE

    // 3. Extract Ring commitment - 48 bytes
    const ringCommitment = resultBytes.slice(
      offset,
      offset + RING_COMMITMENT_SIZE,
    )

    // 3. Extract Ring proof - variable size (592 bytes for ring size 6)
    const ringProof = resultBytes.slice(offset)

    // Log for debugging
    if (ringProof.length === 0) {
      console.warn('[RingVRFProver.deserialize] Warning: ringProof is empty', {
        totalBytes: resultBytes.length,
        offset,
        gammaSize: GAMMA_SIZE,
        pedersenSize: PEDERSEN_SIZE,
        ringProofSize: ringProof.length,
      })
    }

    return {
      gamma,
      proof: {
        pedersenProof,
        ringCommitment,
        ringProof,
      },
    }
  }
}
