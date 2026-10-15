import { createHash } from 'node:crypto'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { sha256 } from '@noble/hashes/sha2.js'
import type { ColumnsCommited, ColumnsEvaluated } from '../piop/mod.ts'

const LABEL_INSTANCE = new TextEncoder().encode('instance')
const LABEL_COMMITTED_COLS = new TextEncoder().encode('committed_cols')
const LABEL_QUOTIENT = new TextEncoder().encode('quotient')
const LABEL_KZG_PROOF_ZETA = new TextEncoder().encode('kzg_proof_zeta')
const LABEL_KZG_PROOF_ZETA_OMEGA = new TextEncoder().encode(
  'kzg_proof_zeta_omega',
)
const LABEL_REGISTER_EVALUATIONS = new TextEncoder().encode(
  'register_evaluations',
)
const LABEL_SHIFTED_LINEARIZATION_EVALUATION = new TextEncoder().encode(
  'shifted_linearization_evaluation',
)

export interface PlonkTranscript<C> {
  addProtocolParams(domain: unknown, pcsRawVk: unknown): void

  addPrecommittedCols(precommittedCols: [C, C]): void

  addInstance(instance: Uint8Array): void

  addCommittedCols(committedCols: ColumnsCommited<C>): void

  getConstraintsAggregationCoeffs(n: number): bigint[]

  addQuotientCommitment(commitment: C): void

  addKzgProofs(proofZeta: C, proofZetaOmega: C): void

  getEvaluationPoint(): bigint

  addEvaluations(evals: ColumnsEvaluated, rAtZetaOmega: bigint): void

  getKzgAggregationChallenges(n: number): bigint[]
}

export class SimplePlonkTranscript implements PlonkTranscript<Uint8Array> {
  private transcript: Uint8Array = new Uint8Array(0)

  constructor(label: Uint8Array) {
    this.transcript = label
  }

  static new(label: string): SimplePlonkTranscript {
    const encoder = new TextEncoder()
    return new SimplePlonkTranscript(encoder.encode(label))
  }

  private append(data: Uint8Array): void {
    const combined = new Uint8Array(this.transcript.length + data.length)
    combined.set(this.transcript)
    combined.set(data, this.transcript.length)
    this.transcript = combined
  }

  private challenge(label: string): bigint {
    const encoder = new TextEncoder()
    const labelBytes = encoder.encode(label)
    const combined = new Uint8Array(this.transcript.length + labelBytes.length)
    combined.set(this.transcript)
    combined.set(labelBytes, this.transcript.length)

    const hash = this.sha256Sync(combined)

    const Fr = bls12_381.fields.Fr
    const hashBigInt = this.bytesToBigInt(hash)
    return Fr.create(hashBigInt)
  }

  private sha256Sync(data: Uint8Array): Uint8Array {
    try {
      return new Uint8Array(createHash('sha256').update(data).digest())
    } catch {
      return this.fallbackHash(data)
    }
  }

  private fallbackHash(data: Uint8Array): Uint8Array {
    return sha256(data)
  }

  private bytesToBigInt(bytes: Uint8Array): bigint {
    let result = 0n
    for (let i = 0; i < bytes.length; i++) {
      result = result + (BigInt(bytes[i]!) << (8n * BigInt(i)))
    }
    return result
  }

  addProtocolParams(_domain: unknown, _pcsRawVk: unknown): void {
  }

  addPrecommittedCols(precommittedCols: [Uint8Array, Uint8Array]): void {
    this.append(precommittedCols[0]!)
    this.append(precommittedCols[1]!)
  }

  addInstance(instance: Uint8Array): void {
    this.append(LABEL_INSTANCE)
    this.append(instance)
  }

  addCommittedCols(committedCols: ColumnsCommited<Uint8Array>): void {
    this.append(LABEL_COMMITTED_COLS)
    const cols = committedCols.toVec()
    for (const col of cols) {
      this.append(col)
    }
  }

  getConstraintsAggregationCoeffs(n: number): bigint[] {
    const label = 'constraints_aggregation'
    return Array(n)
      .fill(0)
      .map(() => this.challenge(label))
  }

  addQuotientCommitment(commitment: Uint8Array): void {
    this.append(LABEL_QUOTIENT)
    this.append(commitment)
  }

  addKzgProofs(proofZeta: Uint8Array, proofZetaOmega: Uint8Array): void {
    this.append(LABEL_KZG_PROOF_ZETA)
    this.append(proofZeta)
    this.append(LABEL_KZG_PROOF_ZETA_OMEGA)
    this.append(proofZetaOmega)
  }

  getEvaluationPoint(): bigint {
    return this.challenge('evaluation_point')
  }

  addEvaluations(evals: ColumnsEvaluated, rAtZetaOmega: bigint): void {
    this.append(LABEL_REGISTER_EVALUATIONS)
    const evalsVec = evals.toVec()
    for (const evalValue of evalsVec) {
      const evalBytes = new Uint8Array(32)
      const evalBigInt = evalValue
      for (let i = 0; i < 32; i++) {
        evalBytes[i] = Number((evalBigInt >> (8n * BigInt(i))) & 0xffn)
      }
      this.append(evalBytes)
    }
    this.append(LABEL_SHIFTED_LINEARIZATION_EVALUATION)
    const rBytes = new Uint8Array(32)
    for (let i = 0; i < 32; i++) {
      rBytes[i] = Number((rAtZetaOmega >> (8n * BigInt(i))) & 0xffn)
    }
    this.append(rBytes)
  }

  getKzgAggregationChallenges(n: number): bigint[] {
    const label = 'kzg_aggregation'
    return Array(n)
      .fill(0)
      .map(() => this.challenge(label))
  }
}
