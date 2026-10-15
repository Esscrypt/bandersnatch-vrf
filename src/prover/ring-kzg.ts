import {
  BANDERSNATCH_PARAMS,
  Bandersnatch,
  BandersnatchCurve,
} from '@pbnjam/bandersnatch'
import { bytesToBigIntLittleEndian } from '../crypto/elligator2.ts'
import { Domain } from '../plonk/domain/domain.ts'
import {
  type FixedColumnsCommitted,
  RingCommitments,
  RingEvaluations,
} from '../plonk/piop/mod.ts'
import { PiopParams } from '../plonk/piop/params.ts'
import { PiopProver } from '../plonk/piop/prover.ts'
import { PiopVerifier } from '../plonk/piop/verifier.ts'
import type { Proof } from '../plonk/proof.ts'
import { PlonkProver } from '../plonk/prover.ts'
import { SimplePlonkTranscript } from '../plonk/transcript/transcript.ts'
import { PlonkVerifier } from '../plonk/verifier.ts'
import {
  bigintToBytes32BE,
  commitPolynomialCoeffs,
} from '../utils/kzg-manual.ts'
import { loadSRSFromFile } from '../utils/srs-loader.ts'
import { PedersenVRFProver } from './pedersen.ts'

export const MODULUS_BIT_SIZE = 255

export const KEY_SIZE = 32
export const COMMITMENT_SIZE = 48
const EVALUATION_SIZE = 32

export const SUITE_ID = 'Bandersnatch_SHA-512_ELL2'

const PADDING_POINT_HEX =
  '0x92ca79e61dd90c1573a8693f199bf6e1e86835cc715cdcf93f5ef222560023aa'

function nextPowerOf2(n: number): number {
  return 2 ** Math.ceil(Math.log2(n))
}

export function piopDomainSizeFromRingSize(ringSize: number): number {
  return nextPowerOf2(ringSize + 4 + MODULUS_BIT_SIZE)
}

export function maxRingSizeFromPiopDomain(piopDomainSize: number): number {
  return Math.max(0, piopDomainSize - (4 + MODULUS_BIT_SIZE))
}

export function pcsDomainSizeFromRingSize(ringSize: number): number {
  return 3 * piopDomainSizeFromRingSize(ringSize) + 1
}

export function parseRingKeys(
  ringKeysBytes: Uint8Array,
): Array<{ x: bigint; y: bigint }> {
  if (ringKeysBytes.length % KEY_SIZE !== 0) {
    throw new Error(
      `Invalid ring keys length: expected multiple of ${KEY_SIZE}, got ${ringKeysBytes.length}`,
    )
  }

  const ringSize = ringKeysBytes.length / KEY_SIZE
  const paddingBytes = hexToUint8(PADDING_POINT_HEX)
  const paddingPoint = BandersnatchCurve.bytesToPoint(paddingBytes)
  const paddingXY = { x: paddingPoint.x, y: paddingPoint.y }

  const keys: Array<{ x: bigint; y: bigint }> = []
  for (let i = 0; i < ringSize; i++) {
    const keyBytes = ringKeysBytes.slice(i * KEY_SIZE, (i + 1) * KEY_SIZE)
    const isNull = keyBytes.every((b) => b === 0)
    if (isNull) {
      keys.push(paddingXY)
      continue
    }
    try {
      const point = BandersnatchCurve.bytesToPoint(keyBytes)
      keys.push({ x: point.x, y: point.y })
    } catch {
      keys.push(paddingXY)
    }
  }
  return keys
}

export function parseRingKeysFromArrays(
  ringKeys: Uint8Array[],
): Array<{ x: bigint; y: bigint }> {
  const flat = new Uint8Array(ringKeys.length * KEY_SIZE)
  for (let i = 0; i < ringKeys.length; i++) {
    flat.set(ringKeys[i]!, i * KEY_SIZE)
  }
  return parseRingKeys(flat)
}

function hexToUint8(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

export function serializeVerifierKey(vk: {
  pcsRawVk: { g1: Uint8Array; g2: Uint8Array; tauInG2: Uint8Array }
  fixedColumnsCommitted: FixedColumnsCommitted
}): Uint8Array {
  const buf = new Uint8Array(384)
  let offset = 0
  buf.set(vk.pcsRawVk.g1, offset)
  offset += 48
  buf.set(vk.pcsRawVk.g2, offset)
  offset += 96
  buf.set(vk.pcsRawVk.tauInG2, offset)
  offset += 96
  buf.set(vk.fixedColumnsCommitted.points[0], offset)
  offset += 48
  buf.set(vk.fixedColumnsCommitted.points[1], offset)
  offset += 48
  buf.set(vk.fixedColumnsCommitted.ringSelector, offset)
  return buf
}

export const N_COMMITMENTS = 4
export const N_EVALUATIONS = 7
export const PROOF_SIZE =
  N_COMMITMENTS * COMMITMENT_SIZE +
  N_EVALUATIONS * EVALUATION_SIZE +
  COMMITMENT_SIZE +
  EVALUATION_SIZE +
  COMMITMENT_SIZE +
  COMMITMENT_SIZE

function serializeProof(
  proof: Proof<RingCommitments, RingEvaluations>,
): Uint8Array {
  const buf = new Uint8Array(PROOF_SIZE)
  let offset = 0

  for (const c of proof.columnCommitments.toVec()) {
    buf.set(c, offset)
    offset += COMMITMENT_SIZE
  }

  for (const v of proof.columnsAtZeta.toVec()) {
    buf.set(bigintToBytes32BE(v), offset)
    offset += EVALUATION_SIZE
  }

  buf.set(proof.quotientCommitment, offset)
  offset += COMMITMENT_SIZE

  buf.set(bigintToBytes32BE(proof.linAtZetaOmega), offset)
  offset += EVALUATION_SIZE

  buf.set(proof.aggAtZetaProof, offset)
  offset += COMMITMENT_SIZE

  buf.set(proof.linAtZetaOmegaProof, offset)

  return buf
}

export function bytes32BEToBigint(bytes: Uint8Array): bigint {
  let result = 0n
  for (let i = 0; i < 32; i++) {
    result = (result << 8n) | BigInt(bytes[i]!)
  }
  return result
}

export function deserializeProofStruct(
  proofBytes: Uint8Array,
): Proof<RingCommitments, RingEvaluations> {
  if (proofBytes.length !== PROOF_SIZE) {
    throw new Error(
      `Invalid proof size: expected ${PROOF_SIZE}, got ${proofBytes.length}`,
    )
  }

  let offset = 0

  const commitmentVec: Uint8Array[] = []
  for (let i = 0; i < N_COMMITMENTS; i++) {
    commitmentVec.push(proofBytes.slice(offset, offset + COMMITMENT_SIZE))
    offset += COMMITMENT_SIZE
  }

  const evalVec: bigint[] = []
  for (let i = 0; i < N_EVALUATIONS; i++) {
    evalVec.push(
      bytes32BEToBigint(proofBytes.slice(offset, offset + EVALUATION_SIZE)),
    )
    offset += EVALUATION_SIZE
  }

  const quotientCommitment = proofBytes.slice(offset, offset + COMMITMENT_SIZE)
  offset += COMMITMENT_SIZE

  const linAtZetaOmega = bytes32BEToBigint(
    proofBytes.slice(offset, offset + EVALUATION_SIZE),
  )
  offset += EVALUATION_SIZE

  const aggAtZetaProof = proofBytes.slice(offset, offset + COMMITMENT_SIZE)
  offset += COMMITMENT_SIZE

  const linAtZetaOmegaProof = proofBytes.slice(offset, offset + COMMITMENT_SIZE)

  const columnCommitments = new RingCommitments(
    commitmentVec[0]!,
    commitmentVec[1]!,
    [commitmentVec[2]!, commitmentVec[3]!],
  )

  const columnsAtZeta = new RingEvaluations(
    [evalVec[0]!, evalVec[1]!],
    evalVec[2]!,
    evalVec[3]!,
    evalVec[4]!,
    [evalVec[5]!, evalVec[6]!],
  )

  return {
    columnCommitments,
    columnsAtZeta,
    quotientCommitment,
    linAtZetaOmega,
    aggAtZetaProof,
    linAtZetaOmegaProof,
  }
}

export interface RingVRFInput {
  input: Uint8Array
  auxData?: Uint8Array
  ringKeys: Uint8Array[]
  proverIndex: number
}

export interface RingVRFProof {
  pedersenProof: Uint8Array
  ringCommitment: Uint8Array
  ringProof: Uint8Array
  proverIndex?: number
}

export interface RingVRFResult {
  gamma: Uint8Array
  proof: RingVRFProof
}

export class RingVRFProver {
  private srsG1Points: Uint8Array[]
  private srsG1: Uint8Array
  private srsG2: Uint8Array
  private srsG2Tau: Uint8Array
  private piopDomainSize: number
  private piopParams: PiopParams

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

  computeRingCommitment(ringKeys: Uint8Array[]): Uint8Array {
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

    const result = new Uint8Array(144)
    result.set(cx, 0)
    result.set(cy, 48)
    result.set(selector, 96)
    return result
  }

  proveRingProof(
    ringKeys: Uint8Array[],
    blindingFactor: Uint8Array,
    proverIndex: number,
  ): Uint8Array {
    const keys = parseRingKeysFromArrays(ringKeys)
    const maxRing = maxRingSizeFromPiopDomain(this.piopDomainSize)
    const keysToUse = keys.length <= maxRing ? keys : keys.slice(0, maxRing)

    const fixedColumns = this.piopParams.fixedColumns(keysToUse)

    const ringCommitmentBytes = this.computeRingCommitment(ringKeys)
    const fixedColumnsCommitted: FixedColumnsCommitted = {
      points: [
        ringCommitmentBytes.slice(0, 48),
        ringCommitmentBytes.slice(48, 96),
      ],
      ringSelector: ringCommitmentBytes.slice(96, 144),
    }

    const verifierKeyObj = {
      pcsRawVk: {
        g1: this.srsG1,
        g2: this.srsG2,
        tauInG2: this.srsG2Tau,
      },
      fixedColumnsCommitted,
    }

    const pcsCk = {
      srsG1Points: this.srsG1Points,
      srsG1: this.srsG1,
      srsG2: this.srsG2,
      srsG2Tau: this.srsG2Tau,
    }

    const transcript = SimplePlonkTranscript.new(SUITE_ID)
    const plonkProver = PlonkProver.init(
      pcsCk,
      serializeVerifierKey(verifierKeyObj),
      transcript,
    )

    const blindingScalar = bytesToBigIntLittleEndian(blindingFactor)
    const piopProver = PiopProver.build(
      this.piopParams,
      fixedColumns,
      proverIndex,
      blindingScalar,
    )

    const proof = plonkProver.prove(piopProver)
    return serializeProof(proof)
  }

  verifyRingProof(
    proofBytes: Uint8Array,
    ringKeys: Uint8Array[],
    keyCommitmentBytes: Uint8Array,
  ): boolean {
    const proof = deserializeProofStruct(proofBytes)

    const ringCommitmentBytes = this.computeRingCommitment(ringKeys)
    const fixedColumnsCommitted: FixedColumnsCommitted = {
      points: [
        ringCommitmentBytes.slice(0, 48),
        ringCommitmentBytes.slice(48, 96),
      ],
      ringSelector: ringCommitmentBytes.slice(96, 144),
    }

    const verifierKeyObj = {
      pcsRawVk: {
        g1: this.srsG1,
        g2: this.srsG2,
        tauInG2: this.srsG2Tau,
      },
      fixedColumnsCommitted,
    }

    const pcsVk = {
      srsG1: this.srsG1,
      srsG2: this.srsG2,
      srsG2Tau: this.srsG2Tau,
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

  prove(secretKey: Uint8Array, input: RingVRFInput): RingVRFResult {
    const pedersenResult = PedersenVRFProver.prove(secretKey, {
      input: input.input,
      auxData: input.auxData,
    })

    const ringCommitment = this.computeRingCommitment(input.ringKeys)
    const ringProof = this.proveRingProof(
      input.ringKeys,
      pedersenResult.blindingFactor,
      input.proverIndex,
    )

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

  verify(
    ringKeys: Uint8Array[],
    result: RingVRFResult,
    keyCommitmentBytes: Uint8Array,
  ): boolean {
    return this.verifyRingProof(
      result.proof.ringProof,
      ringKeys,
      keyCommitmentBytes,
    )
  }

  static serialize(result: RingVRFResult): Uint8Array {
    const GAMMA_SIZE = 32
    const PEDERSEN_SIZE = 160

    const serialized = new Uint8Array(
      GAMMA_SIZE + PEDERSEN_SIZE + result.proof.ringProof.length,
    )
    let offset = 0

    serialized.set(result.gamma, offset)
    offset += GAMMA_SIZE

    if (result.proof.pedersenProof.length !== PEDERSEN_SIZE) {
      throw new Error(
        `Pedersen proof must be ${PEDERSEN_SIZE} bytes, got ${result.proof.pedersenProof.length}`,
      )
    }
    serialized.set(result.proof.pedersenProof, offset)
    offset += PEDERSEN_SIZE

    serialized.set(result.proof.ringProof, offset)
    return serialized
  }

  static deserialize(resultBytes: Uint8Array): RingVRFResult {
    const GAMMA_SIZE = 32
    const PEDERSEN_SIZE = 160

    let offset = 0
    const gamma = resultBytes.slice(offset, offset + GAMMA_SIZE)
    offset += GAMMA_SIZE

    const pedersenProof = resultBytes.slice(offset, offset + PEDERSEN_SIZE)
    offset += PEDERSEN_SIZE

    const ringCommitment = resultBytes.slice(offset, offset + COMMITMENT_SIZE)
    const ringProof = resultBytes.slice(offset)

    return {
      gamma,
      proof: {
        pedersenProof,
        ringCommitment,
        ringProof,
      },
    }
  }

  static calculatePiopDomainSize(ringSize: number): number {
    return piopDomainSizeFromRingSize(ringSize)
  }

  static calculatePcsDomainSize(ringSize: number): number {
    return pcsDomainSizeFromRingSize(ringSize)
  }

  static isValidRingSize(ringSize: number): boolean {
    return ringSize > 0 && ringSize <= RingVRFProver.getMaxRingSize()
  }

  static getMaxRingSize(): number {
    return BANDERSNATCH_PARAMS.KZG_CONFIG.MAX_RING_SIZE
  }

  static getSRSInfo(): {
    domainSize: number
    maxRingSize: number
    source: string
  } {
    return {
      domainSize: BANDERSNATCH_PARAMS.KZG_CONFIG.DOMAIN_SIZE,
      maxRingSize: BANDERSNATCH_PARAMS.KZG_CONFIG.MAX_RING_SIZE,
      source: 'zcash-powers-of-tau-ceremony',
    }
  }

  static extractOutput(result: RingVRFResult): Uint8Array {
    return result.gamma
  }
}
