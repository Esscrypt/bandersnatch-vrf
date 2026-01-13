/**
 * PIOP Module
 *
 * Main module for Polynomial Interactive Oracle Proofs (PIOP)
 * Matches w3f-ring-proof/src/piop/mod.rs
 */

import type { FixedColumns, PiopParams } from './params'

/**
 * Columns Committed Trait
 *
 * Interface for converting commitments to a vector
 */
export interface ColumnsCommited<C> {
  toVec(): C[]
}

/**
 * Columns Evaluated Trait
 *
 * Interface for converting evaluations to a vector
 */
export interface ColumnsEvaluated {
  toVec(): bigint[]
}

/**
 * Ring Commitments
 *
 * Commitments to witness columns in the ring proof
 */
export class RingCommitments implements ColumnsCommited<Uint8Array> {
  /** Commitment to bits column */
  bits: Uint8Array
  /** Commitment to inner product accumulator */
  innProdAcc: Uint8Array
  /** Commitments to conditional addition accumulator (x and y coordinates) */
  condAddAcc: [Uint8Array, Uint8Array]

  constructor(
    bits: Uint8Array,
    innProdAcc: Uint8Array,
    condAddAcc: [Uint8Array, Uint8Array],
  ) {
    this.bits = bits
    this.innProdAcc = innProdAcc
    this.condAddAcc = condAddAcc
  }

  toVec(): Uint8Array[] {
    return [
      this.bits,
      this.innProdAcc,
      this.condAddAcc[0]!,
      this.condAddAcc[1]!,
    ]
  }
}

/**
 * Ring Evaluations
 *
 * Evaluations of all columns at a point zeta
 */
export class RingEvaluations implements ColumnsEvaluated {
  /** Evaluations of points column (x and y coordinates) */
  points: [bigint, bigint]
  /** Evaluation of ring selector column */
  ringSelector: bigint
  /** Evaluation of bits column */
  bits: bigint
  /** Evaluation of inner product accumulator */
  innProdAcc: bigint
  /** Evaluations of conditional addition accumulator (x and y coordinates) */
  condAddAcc: [bigint, bigint]

  constructor(
    points: [bigint, bigint],
    ringSelector: bigint,
    bits: bigint,
    innProdAcc: bigint,
    condAddAcc: [bigint, bigint],
  ) {
    this.points = points
    this.ringSelector = ringSelector
    this.bits = bits
    this.innProdAcc = innProdAcc
    this.condAddAcc = condAddAcc
  }

  toVec(): bigint[] {
    return [
      this.points[0],
      this.points[1],
      this.ringSelector,
      this.bits,
      this.innProdAcc,
      this.condAddAcc[0]!,
      this.condAddAcc[1]!,
    ]
  }
}

// FixedColumns is defined in params.ts, re-export it
export type { FixedColumns } from './params'

/**
 * Fixed Columns Committed
 *
 * Commitments to fixed columns
 */
export interface FixedColumnsCommitted {
  /** Commitments to points column (x and y coordinates) */
  points: [Uint8Array, Uint8Array]
  /** Commitment to ring selector column */
  ringSelector: Uint8Array
}

/**
 * Prover Key
 *
 * Contains all information needed by the prover
 */
export interface ProverKey {
  /** Polynomial commitment scheme committing key */
  pcsCk: unknown // Will be typed when we implement PCS
  /** Fixed columns */
  fixedColumns: FixedColumns
  /** Verifier key (used in Fiat-Shamir transform) */
  verifierKey: VerifierKey
}

/**
 * Raw KZG Verifier Key
 *
 * Matching Rust: RawKzgVerifierKey in fflonk/src/pcs/kzg/params.rs:93-100
 */
export interface RawKzgVerifierKey {
  /** G1 generator (48 bytes compressed) */
  g1: Uint8Array
  /** G2 generator (96 bytes compressed) */
  g2: Uint8Array
  /** tau * G2 (96 bytes compressed) */
  tauInG2: Uint8Array
}

/**
 * Verifier Key
 *
 * Contains all information needed by the verifier
 * Matching Rust: VerifierKey in w3f-ring-proof/src/piop/mod.rs:136-141
 */
export interface VerifierKey {
  /** Polynomial commitment scheme raw verifier key */
  pcsRawVk: RawKzgVerifierKey
  /** Committed fixed columns */
  fixedColumnsCommitted: FixedColumnsCommitted
}

/**
 * PCS Parameters structure
 *
 * Wraps SRS for polynomial commitment scheme
 * Matching Rust: PcsParams trait in fflonk/src/pcs/mod.rs:61-73
 */
export interface PcsParams {
  /** Get committing key (SRS G1 points) */
  ck(): { srsG1Points: Uint8Array[] }
  /** Get raw verifier key (SRS G1, G2, G2Tau) */
  rawVk(): RawKzgVerifierKey
}

/**
 * Index function
 *
 * Generates prover and verifier keys from PCS parameters, PIOP parameters, and ring keys
 *
 * This is the main entry point for setting up a ring proof system
 *
 * Matching Rust: w3f-ring-proof/src/piop/mod.rs:166-210
 *
 * @param pcsParams - Polynomial commitment scheme parameters (PcsParams or unknown for backward compatibility)
 * @param piopParams - PIOP parameters
 * @param keys - Ring public keys
 * @param computeRingCommitment - Function to compute FixedColumnsCommitted from ring keys
 * @returns Prover key and verifier key
 */
export function index(
  pcsParams: unknown, // Currently unused - SRS is passed directly to prover
  piopParams: PiopParams,
  keys: Array<{ x: bigint; y: bigint }>,
  computeRingCommitment?: (
    ringKeys: Array<{ x: bigint; y: bigint }>,
  ) => Uint8Array,
): [ProverKey, VerifierKey] {
  void pcsParams // SRS is passed directly to prover, not through pcsParams yet

  // Build fixed columns
  const fixedColumns = piopParams.fixedColumns(keys)

  // Commit fixed columns using computeRingCommitment if provided
  // Otherwise use placeholder (will be computed later in ring-kzg.ts)
  let fixedColumnsCommitted: FixedColumnsCommitted
  if (computeRingCommitment) {
    // Compute ring commitment directly from keys
    // Note: computeRingCommitment expects Array<{x, y}> but we have that
    // However, the actual implementation in ring-kzg.ts expects Uint8Array[]
    // So we'll compute it in ring-kzg.ts instead
    void keys // Keys are used in fixedColumns above
    const commitmentBytes = computeRingCommitment(keys)
    // Parse 144 bytes: cx[48] + cy[48] + selector[48]
    fixedColumnsCommitted = {
      points: [commitmentBytes.slice(0, 48), commitmentBytes.slice(48, 96)],
      ringSelector: commitmentBytes.slice(96, 144),
    }
  } else {
    // Placeholder - will be computed in ring-kzg.ts using computeRingCommitment()
    fixedColumnsCommitted = {
      points: [new Uint8Array(48), new Uint8Array(48)],
      ringSelector: new Uint8Array(48),
    }
  }

  // Create verifier key
  // pcsRawVk is just the SRS verifier key (G1, G2, G2Tau) - passed directly to prover
  const verifierKey: VerifierKey = {
    pcsRawVk: {
      g1: new Uint8Array(48), // Placeholder - must be provided by caller
      g2: new Uint8Array(96), // Placeholder - must be provided by caller
      tauInG2: new Uint8Array(96), // Placeholder - must be provided by caller
    },
    fixedColumnsCommitted,
  }

  // Create prover key
  // pcsCk is the SRS committing key (G1 points) - passed directly to prover
  const proverKey: ProverKey = {
    pcsCk: {} as unknown, // SRS committing key passed directly to PlonkProver
    fixedColumns,
    verifierKey,
  }

  return [proverKey, verifierKey]
}

// Re-export types and classes
export type { PiopParams } from './params'
export { PiopProver } from './prover'
export { PiopVerifier } from './verifier'
