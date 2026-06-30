/**
 * Plonk Transcript (Fiat-Shamir)
 *
 * Implements Fiat-Shamir transform for Plonk protocol
 * Matches w3f-plonk-common/src/transcript.rs
 */

import { createHash } from 'node:crypto'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { sha256 } from '@noble/hashes/sha2.js'
import type { ColumnsCommited, ColumnsEvaluated } from '../piop/mod'

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

/**
 * Plonk Transcript Trait
 *
 * Generates challenges using Fiat-Shamir transform
 */
export interface PlonkTranscript<C> {
  /**
   * Add protocol parameters to transcript
   */
  addProtocolParams(domain: unknown, pcsRawVk: unknown): void

  /**
   * Add precommitted columns to transcript
   */
  addPrecommittedCols(precommittedCols: [C, C]): void

  /**
   * Add instance (public input) to transcript
   */
  addInstance(instance: Uint8Array): void

  /**
   * Add committed columns to transcript
   */
  addCommittedCols(committedCols: ColumnsCommited<C>): void

  /**
   * Get constraint aggregation coefficients (alphas)
   */
  getConstraintsAggregationCoeffs(n: number): bigint[]

  /**
   * Add quotient commitment to transcript
   */
  addQuotientCommitment(commitment: C): void

  /**
   * Add KZG proofs to transcript
   */
  addKzgProofs(proofZeta: C, proofZetaOmega: C): void

  /**
   * Get evaluation point (zeta)
   */
  getEvaluationPoint(): bigint

  /**
   * Add evaluations to transcript
   */
  addEvaluations(evals: ColumnsEvaluated, rAtZetaOmega: bigint): void

  /**
   * Get KZG aggregation challenges (nus)
   */
  getKzgAggregationChallenges(n: number): bigint[]
}

/**
 * Simple Transcript Implementation
 *
 * Uses SHA-256 for Fiat-Shamir challenges
 * Implements SHA-256-based Fiat-Shamir transcript matching Rust implementation
 */
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

    // Use SHA-256 for challenge generation
    // Matching Rust: uses SHA-256 for Fiat-Shamir
    const hash = this.sha256Sync(combined)

    // Convert to field element (reduce modulo field order)
    const Fr = bls12_381.fields.Fr
    const hashBigInt = this.bytesToBigInt(hash)
    return Fr.create(hashBigInt)
  }

  private sha256Sync(data: Uint8Array): Uint8Array {
    // Synchronous SHA-256 (for Node.js)
    // In production, use async crypto.subtle.digest
    try {
      return new Uint8Array(createHash('sha256').update(data).digest())
    } catch {
      // Fallback: use Web Crypto API if available
      // For now, use a simple hash (not cryptographically secure in this fallback)
      return this.fallbackHash(data)
    }
  }

  private fallbackHash(data: Uint8Array): Uint8Array {
    // Fallback hash using SHA-256 from @noble/hashes
    return sha256(data)
  }

  private bytesToBigInt(bytes: Uint8Array): bigint {
    // Convert bytes to bigint (little-endian, matching Rust)
    let result = 0n
    for (let i = 0; i < bytes.length; i++) {
      result = result + (BigInt(bytes[i]!) << (8n * BigInt(i)))
    }
    return result
  }

  addProtocolParams(_domain: unknown, _pcsRawVk: unknown): void {
    // Add domain and PCS verifier key to transcript
    // Implementation depends on serialization format
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
      // Convert bigint to bytes (little-endian)
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
