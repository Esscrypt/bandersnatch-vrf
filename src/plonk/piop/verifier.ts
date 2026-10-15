import { bls12_381 } from '@noble/curves/bls12-381.js'
import { BooleanityValues } from '../gadgets/booleanity.ts'
import { CondAddValues } from '../gadgets/cond-add.ts'
import { FixedCellsValues } from '../gadgets/fixed-cells.ts'
import { InnerProdValues } from '../gadgets/inner-prod.ts'
import type {
  FixedColumnsCommitted,
  RingCommitments,
  RingEvaluations,
} from './mod.ts'

export interface EvaluatedDomain {
  notLastRow: bigint
  lFirst: bigint
  lLast: bigint
  omega: bigint
  vanishingPolynomialInv: bigint
}

export class PiopVerifier {
  public static readonly N_CONSTRAINTS = 7
  public static readonly N_COLUMNS = 7

  private readonly domainEvals: EvaluatedDomain
  private readonly fixedColumnsCommitted: FixedColumnsCommitted
  private readonly witnessColumnsCommitted: RingCommitments
  private readonly booleanity: BooleanityValues
  private readonly innerProd: InnerProdValues
  private readonly innerProdAcc: FixedCellsValues
  private readonly condAdd: CondAddValues
  private readonly condAddAccX: FixedCellsValues
  private readonly condAddAccY: FixedCellsValues

  static init(
    domainEvals: EvaluatedDomain,
    fixedColumnsCommitted: FixedColumnsCommitted,
    witnessColumnsCommitted: RingCommitments,
    allColumnsEvaluated: RingEvaluations,
    init: [bigint, bigint],
    result: [bigint, bigint],
  ): PiopVerifier {
    const condAdd = new CondAddValues(
      allColumnsEvaluated.bits,
      allColumnsEvaluated.points,
      domainEvals.notLastRow,
      allColumnsEvaluated.condAddAcc,
    )

    const innerProd = new InnerProdValues(
      allColumnsEvaluated.ringSelector,
      allColumnsEvaluated.bits,
      domainEvals.notLastRow,
      allColumnsEvaluated.innProdAcc,
    )

    const booleanity = new BooleanityValues(allColumnsEvaluated.bits)

    const condAddAccX = new FixedCellsValues(
      allColumnsEvaluated.condAddAcc[0],
      init[0],
      result[0],
      domainEvals.lFirst,
      domainEvals.lLast,
    )

    const condAddAccY = new FixedCellsValues(
      allColumnsEvaluated.condAddAcc[1],
      init[1],
      result[1],
      domainEvals.lFirst,
      domainEvals.lLast,
    )

    const innerProdAcc = new FixedCellsValues(
      allColumnsEvaluated.innProdAcc,
      0n,
      1n,
      domainEvals.lFirst,
      domainEvals.lLast,
    )

    return new PiopVerifier(
      domainEvals,
      fixedColumnsCommitted,
      witnessColumnsCommitted,
      booleanity,
      innerProd,
      innerProdAcc,
      condAdd,
      condAddAccX,
      condAddAccY,
    )
  }

  private constructor(
    domainEvals: EvaluatedDomain,
    fixedColumnsCommitted: FixedColumnsCommitted,
    witnessColumnsCommitted: RingCommitments,
    booleanity: BooleanityValues,
    innerProd: InnerProdValues,
    innerProdAcc: FixedCellsValues,
    condAdd: CondAddValues,
    condAddAccX: FixedCellsValues,
    condAddAccY: FixedCellsValues,
  ) {
    this.domainEvals = domainEvals
    this.fixedColumnsCommitted = fixedColumnsCommitted
    this.witnessColumnsCommitted = witnessColumnsCommitted
    this.booleanity = booleanity
    this.innerProd = innerProd
    this.innerProdAcc = innerProdAcc
    this.condAdd = condAdd
    this.condAddAccX = condAddAccX
    this.condAddAccY = condAddAccY
  }

  precommittedColumns(): Uint8Array[] {
    return [
      this.fixedColumnsCommitted.points[0],
      this.fixedColumnsCommitted.points[1],
      this.fixedColumnsCommitted.ringSelector,
    ]
  }

  evaluateConstraintsMain(): bigint[] {
    return [
      ...this.innerProd.evaluateConstraintsMain(),
      ...this.condAdd.evaluateConstraintsMain(),
      ...this.booleanity.evaluateConstraintsMain(),
      ...this.condAddAccX.evaluateConstraintsMain(),
      ...this.condAddAccY.evaluateConstraintsMain(),
      ...this.innerProdAcc.evaluateConstraintsMain(),
    ]
  }

  linPolyCommitment(aggCoeffs: bigint[]): Uint8Array {
    if (aggCoeffs.length !== PiopVerifier.N_CONSTRAINTS) {
      throw new Error(
        `Aggregated coefficients length ${aggCoeffs.length} must equal N_CONSTRAINTS ${PiopVerifier.N_CONSTRAINTS}`,
      )
    }

    const Fr = bls12_381.fields.Fr

    const innerProdAcc = this.witnessColumnsCommitted.innProdAcc
    const innerProdCoeff = Fr.mul(
      Fr.create(aggCoeffs[0]!),
      Fr.create(this.innerProd.notLast),
    )

    const condAddAccX = this.witnessColumnsCommitted.condAddAcc[0]
    const condAddAccY = this.witnessColumnsCommitted.condAddAcc[1]
    const [cAccX1, cAccY1] = this.condAdd.accCoeffs1()
    const [cAccX2, cAccY2] = this.condAdd.accCoeffs2()

    let condAddXCoeff = Fr.mul(Fr.create(aggCoeffs[1]!), Fr.create(cAccX1))
    let condAddYCoeff = Fr.mul(Fr.create(aggCoeffs[1]!), Fr.create(cAccY1))
    condAddXCoeff = Fr.add(
      condAddXCoeff,
      Fr.mul(Fr.create(aggCoeffs[2]!), Fr.create(cAccX2)),
    )
    condAddYCoeff = Fr.add(
      condAddYCoeff,
      Fr.mul(Fr.create(aggCoeffs[2]!), Fr.create(cAccY2)),
    )

    const commitments: Uint8Array[] = [innerProdAcc, condAddAccX, condAddAccY]
    const commitmentCoeffs: bigint[] = [
      innerProdCoeff,
      condAddXCoeff,
      condAddYCoeff,
    ]

    let result = bls12_381.G1.Point.ZERO

    for (let i = 0; i < commitments.length; i++) {
      const commitment = bls12_381.G1.Point.fromBytes(commitments[i]!)
      const coeff = Fr.create(commitmentCoeffs[i]!)
      result = result.add(commitment.multiply(coeff))
    }

    return result.toBytes(true)
  }

  evaluateQAtZeta(aggCoeffs: bigint[], linAtZetaOmega: bigint): bigint {
    const Fr = bls12_381.fields.Fr

    const constraintEvals = this.evaluateConstraintsMain()
    let evalResult = Fr.ZERO
    for (let i = 0; i < constraintEvals.length; i++) {
      const alpha = Fr.create(aggCoeffs[i]!)
      const constraint = Fr.create(constraintEvals[i]!)
      evalResult = Fr.add(evalResult, Fr.mul(alpha, constraint))
    }

    const linAtZetaOmegaF = Fr.create(linAtZetaOmega)
    const numerator = Fr.add(evalResult, linAtZetaOmegaF)

    const vanishingPolyInv = this.domainEvals.vanishingPolynomialInv
    return Fr.mul(numerator, vanishingPolyInv)
  }

  domainEvaluated(): EvaluatedDomain {
    return this.domainEvals
  }
}
