import type { FixedColumns, PiopParams } from './params.ts'

export interface ColumnsCommited<C> {
  toVec(): C[]
}

export interface ColumnsEvaluated {
  toVec(): bigint[]
}

export class RingCommitments implements ColumnsCommited<Uint8Array> {
  bits: Uint8Array
  innProdAcc: Uint8Array
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

export class RingEvaluations implements ColumnsEvaluated {
  points: [bigint, bigint]
  ringSelector: bigint
  bits: bigint
  innProdAcc: bigint
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

export type { FixedColumns } from './params.ts'

export interface FixedColumnsCommitted {
  points: [Uint8Array, Uint8Array]
  ringSelector: Uint8Array
}

export interface ProverKey {
  pcsCk: unknown
  fixedColumns: FixedColumns
  verifierKey: VerifierKey
}

export interface RawKzgVerifierKey {
  g1: Uint8Array
  g2: Uint8Array
  tauInG2: Uint8Array
}

export interface VerifierKey {
  pcsRawVk: RawKzgVerifierKey
  fixedColumnsCommitted: FixedColumnsCommitted
}

export interface PcsParams {
  ck(): { srsG1Points: Uint8Array[] }
  rawVk(): RawKzgVerifierKey
}

export function index(
  pcsParams: unknown,
  piopParams: PiopParams,
  keys: Array<{ x: bigint; y: bigint }>,
  computeRingCommitment?: (
    ringKeys: Array<{ x: bigint; y: bigint }>,
  ) => Uint8Array,
): [ProverKey, VerifierKey] {
  void pcsParams

  const fixedColumns = piopParams.fixedColumns(keys)

  let fixedColumnsCommitted: FixedColumnsCommitted
  if (computeRingCommitment) {
    void keys
    const commitmentBytes = computeRingCommitment(keys)
    fixedColumnsCommitted = {
      points: [commitmentBytes.slice(0, 48), commitmentBytes.slice(48, 96)],
      ringSelector: commitmentBytes.slice(96, 144),
    }
  } else {
    fixedColumnsCommitted = {
      points: [new Uint8Array(48), new Uint8Array(48)],
      ringSelector: new Uint8Array(48),
    }
  }

  const verifierKey: VerifierKey = {
    pcsRawVk: {
      g1: new Uint8Array(48),
      g2: new Uint8Array(96),
      tauInG2: new Uint8Array(96),
    },
    fixedColumnsCommitted,
  }

  const proverKey: ProverKey = {
    pcsCk: {} as unknown,
    fixedColumns,
    verifierKey,
  }

  return [proverKey, verifierKey]
}

export type { PiopParams } from './params.ts'
export { PiopProver } from './prover.ts'
export { PiopVerifier } from './verifier.ts'
