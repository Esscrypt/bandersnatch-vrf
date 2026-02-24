/**
 * Ring VRF Verifier (Pure TypeScript)
 *
 * Self-contained verifier for Ring VRF proofs. Loads its own SRS and
 * builds the PIOP/Plonk verification pipeline independently of the prover.
 *
 * Implements Ring VRF verification according to bandersnatch-vrf-spec section 4.3:
 * 1. θ₀ = Pedersen.verify(I, ad, O, π_p) - Verify underlying Pedersen VRF proof
 * 2. (Ȳ, R, O_k, s, s_b) ← π_p - Extract Pedersen proof components
 * 3. θ₁ = Ring.verify(V, π_r, Ȳ) - Verify ring proof using Plonk verifier
 * 4. θ ← θ₀ ∧ θ₁ - Both verifications must pass
 */

import {
  BANDERSNATCH_PARAMS,
  Bandersnatch,
  BandersnatchCurve,
} from '@pbnjam/bandersnatch'
import { Domain } from '../plonk/domain/domain'
import type { FixedColumnsCommitted } from '../plonk/piop/mod'
import { PiopParams } from '../plonk/piop/params'
import { PiopVerifier } from '../plonk/piop/verifier'
import { SimplePlonkTranscript } from '../plonk/transcript/transcript'
import { PlonkVerifier } from '../plonk/verifier'
import { PedersenVRFProver } from '../prover/pedersen'
import type { RingVRFInput, RingVRFProof } from '../prover/ring-kzg'
import {
  COMMITMENT_SIZE,
  deserializeProofStruct,
  maxRingSizeFromPiopDomain,
  parseRingKeysFromArrays,
  pcsDomainSizeFromRingSize,
  piopDomainSizeFromRingSize,
  SUITE_ID,
  serializeVerifierKey,
} from '../prover/ring-kzg'
import { commitPolynomialCoeffs } from '../utils/kzg-manual'
import { loadSRSFromFile } from '../utils/srs-loader'
import { PedersenVRFVerifier } from './pedersen'

/**
 * Ring VRF Verifier
 *
 * Loads its own SRS and PIOP parameters. Verifies ring membership
 * proofs using the Plonk verification protocol.
 */
export class RingVRFVerifier {
  private readonly srsG1Points: Uint8Array[]
  private readonly srsG1: Uint8Array
  private readonly srsG2: Uint8Array
  private readonly srsG2Tau: Uint8Array
  private readonly piopDomainSize: number
  private readonly piopParams: PiopParams

  /**
   * @param srsFilePath - Path to SRS file (arkworks format)
   * @param ringSize    - Ring size (number of validators)
   */
  constructor(srsFilePath: string, ringSize: number) {
    const [error, result] = loadSRSFromFile(srsFilePath)
    if (error) {
      throw new Error(`Failed to load SRS: ${error.message}`)
    }

    this.srsG1 = result.g1
    this.srsG2 = result.g2
    this.srsG2Tau = result.g2Points[1]!

    this.piopDomainSize = piopDomainSizeFromRingSize(ringSize)
    const pcsDomainSize = pcsDomainSizeFromRingSize(ringSize)

    if (result.g1Points.length < pcsDomainSize || result.g2Points.length < 2) {
      throw new Error(
        `SRS too small: need g1>=${pcsDomainSize} and g2>=2, ` +
          `got ${result.g1Points.length} and ${result.g2Points.length}`,
      )
    }
    this.srsG1Points = result.g1Points.slice(0, pcsDomainSize)

    const domain = new Domain(this.piopDomainSize, true)
    const h = {
      x: BANDERSNATCH_PARAMS.BLINDING_BASE.x,
      y: BANDERSNATCH_PARAMS.BLINDING_BASE.y,
    }
    const seed = PiopParams.getAccumulatorSeedPoint()
    const padding = PiopParams.getPaddingPoint()
    this.piopParams = PiopParams.setup(domain, h, seed, padding)
  }

  /**
   * Verify Ring VRF proof.
   *
   * Steps:
   * 1. θ₀ = Pedersen.verify(I, ad, O, π_p)
   * 2. Extract Ȳ (blinded public key) from Pedersen proof
   * 3. θ₁ = Ring.verify(π_r, ring_keys, Ȳ) via Plonk verifier
   * 4. θ ← θ₀ ∧ θ₁
   */
  verify(
    ringKeys: Uint8Array[],
    input: RingVRFInput,
    result: {
      gamma: Uint8Array
      proof: RingVRFProof
    },
    auxData?: Uint8Array,
  ): boolean {
    const pedersenValid = PedersenVRFVerifier.verify(
      input.input,
      result.gamma,
      result.proof.pedersenProof,
      auxData,
    )
    if (!pedersenValid) {
      return false
    }

    const pedersenComponents = PedersenVRFProver.deserialize(
      result.proof.pedersenProof,
    )

    return this.verifyRingProof(
      result.proof.ringProof,
      ringKeys,
      pedersenComponents.Y_bar,
    )
  }

  /**
   * Compute ring commitment from public keys.
   *
   * @returns 144 bytes: cx(48) + cy(48) + selector(48)
   */
  private computeRingCommitment(ringKeys: Uint8Array[]): Uint8Array {
    const keys = parseRingKeysFromArrays(ringKeys)
    const maxRing = maxRingSizeFromPiopDomain(this.piopDomainSize)
    const keysToUse = keys.length <= maxRing ? keys : keys.slice(0, maxRing)

    const fixedColumns = this.piopParams.fixedColumns(keysToUse)

    const [errCx, cx] = commitPolynomialCoeffs(
      fixedColumns.points.xs.poly.coeffs,
      this.srsG1Points,
    )
    if (errCx || !cx) {
      throw new Error(`Failed to commit points.xs: ${errCx?.message}`)
    }

    const [errCy, cy] = commitPolynomialCoeffs(
      fixedColumns.points.ys.poly.coeffs,
      this.srsG1Points,
    )
    if (errCy || !cy) {
      throw new Error(`Failed to commit points.ys: ${errCy?.message}`)
    }

    const [errSel, selector] = commitPolynomialCoeffs(
      fixedColumns.ringSelector.poly.coeffs,
      this.srsG1Points,
    )
    if (errSel || !selector) {
      throw new Error(`Failed to commit ringSelector: ${errSel?.message}`)
    }

    const commitment = new Uint8Array(3 * COMMITMENT_SIZE)
    commitment.set(cx, 0)
    commitment.set(cy, COMMITMENT_SIZE)
    commitment.set(selector, 2 * COMMITMENT_SIZE)
    return commitment
  }

  /**
   * Verify a Plonk-based ring proof against ring keys and a key commitment.
   *
   * @param proofBytes          Serialised w3f RingProof (592 bytes)
   * @param ringKeys            Serialised ring public keys (32 bytes each)
   * @param keyCommitmentBytes  Blinded public key Y_bar (32 bytes, compressed)
   * @returns true if the proof is valid
   */
  private verifyRingProof(
    proofBytes: Uint8Array,
    ringKeys: Uint8Array[],
    keyCommitmentBytes: Uint8Array,
  ): boolean {
    const proof = deserializeProofStruct(proofBytes)

    const ringCommitmentBytes = this.computeRingCommitment(ringKeys)
    const fixedColumnsCommitted: FixedColumnsCommitted = {
      points: [
        ringCommitmentBytes.slice(0, COMMITMENT_SIZE),
        ringCommitmentBytes.slice(COMMITMENT_SIZE, 2 * COMMITMENT_SIZE),
      ],
      ringSelector: ringCommitmentBytes.slice(
        2 * COMMITMENT_SIZE,
        3 * COMMITMENT_SIZE,
      ),
    }

    const pcsVk = {
      srsG1: this.srsG1,
      srsG2: this.srsG2,
      srsG2Tau: this.srsG2Tau,
    }

    const verifierKeyObj = {
      pcsRawVk: {
        g1: this.srsG1,
        g2: this.srsG2,
        tauInG2: this.srsG2Tau,
      },
      fixedColumnsCommitted,
    }

    const transcript = SimplePlonkTranscript.new(SUITE_ID)
    const plonkVerifier = PlonkVerifier.init(
      pcsVk,
      serializeVerifierKey(verifierKeyObj),
      transcript,
    )

    const keyCommitmentPoint =
      BandersnatchCurve.bytesToPoint(keyCommitmentBytes)

    const nConstraints = PiopVerifier.N_CONSTRAINTS
    const nPolys = PiopVerifier.N_COLUMNS + 1

    const challenges = plonkVerifier.restoreChallenges(
      keyCommitmentBytes,
      proof,
      nPolys,
      nConstraints,
    )

    const seedPoint = Bandersnatch.fromAffine({
      x: this.piopParams.seed.x,
      y: this.piopParams.seed.y,
    })
    const seedPlusResult = BandersnatchCurve.add(seedPoint, keyCommitmentPoint)

    const domainEvals = this.piopParams.domain.evaluate(challenges.zeta)
    const piopVerifier = PiopVerifier.init(
      domainEvals,
      fixedColumnsCommitted,
      proof.columnCommitments,
      proof.columnsAtZeta,
      [this.piopParams.seed.x, this.piopParams.seed.y],
      [seedPlusResult.x, seedPlusResult.y],
    )

    return plonkVerifier.verify(piopVerifier, proof, challenges)
  }
}
