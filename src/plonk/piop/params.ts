import { BandersnatchCurve } from '@pbnjam/bandersnatch'
import { hexToBytes } from 'viem'
import { BANDERSNATCH_VRF_CONFIG } from '../../config/bandersnatch-vrf-config.ts'
import type { Domain } from '../domain/domain.ts'
import { FieldColumn } from '../domain/domain.ts'
import { AffineColumn } from '../gadgets/affine-column.ts'
import { Doubling } from '../gadgets/doubling.ts'

export class PiopParams {
  public readonly domain: Domain
  public readonly scalarBitlen: number
  public readonly keysetPartSize: number
  public readonly h: { x: bigint; y: bigint }
  public readonly seed: { x: bigint; y: bigint }
  public readonly padding: { x: bigint; y: bigint }

  static setup(
    domain: Domain,
    h: { x: bigint; y: bigint },
    seed: { x: bigint; y: bigint },
    padding: { x: bigint; y: bigint },
  ): PiopParams {
    const scalarBitlen = 253

    const keysetPartSize = domain.capacity - scalarBitlen - 1

    return new PiopParams(
      domain,
      scalarBitlen,
      keysetPartSize,
      h,
      seed,
      padding,
    )
  }

  private constructor(
    domain: Domain,
    scalarBitlen: number,
    keysetPartSize: number,
    h: { x: bigint; y: bigint },
    seed: { x: bigint; y: bigint },
    padding: { x: bigint; y: bigint },
  ) {
    this.domain = domain
    this.scalarBitlen = scalarBitlen
    this.keysetPartSize = keysetPartSize
    this.h = h
    this.seed = seed
    this.padding = padding
  }

  fixedColumns(keys: Array<{ x: bigint; y: bigint }>): FixedColumns {
    const ringSelector = this.keysetPartSelector()
    const ringSelectorCol = new FieldColumn(
      ringSelector,
      this.domain.getDomain1x(),
      this.domain.capacity - 1,
    )
    const points = this.pointsColumn(keys)
    const doublingsOfG = this.doublingsOfG()

    return {
      points,
      ringSelector: ringSelectorCol,
      doublingsOfG,
    }
  }

  pointsColumn(keys: Array<{ x: bigint; y: bigint }>): AffineColumn {
    if (keys.length > this.keysetPartSize) {
      throw new Error(
        `Too many keys: ${keys.length} > keyset_part_size ${this.keysetPartSize}`,
      )
    }

    const paddingLen = this.keysetPartSize - keys.length
    const padding = Array(paddingLen).fill(this.padding)

    const powersOfH = this.powerOf2MultiplesOfH()

    const points = [...keys, ...padding, ...powersOfH]

    if (points.length !== this.domain.capacity - 1) {
      throw new Error(
        `Points length ${points.length} must equal domain.capacity - 1 (${this.domain.capacity - 1})`,
      )
    }

    return AffineColumn.publicColumn(points, this.domain)
  }

  doublingsOfG(): AffineColumn {
    const g = {
      x: BandersnatchCurve.GENERATOR.x,
      y: BandersnatchCurve.GENERATOR.y,
    }

    const doublings = Doubling.doublingsOf(g, this.domain)

    return AffineColumn.publicColumn(doublings, this.domain)
  }

  powerOf2MultiplesOfH(): Array<{ x: bigint; y: bigint }> {
    return Doubling.doublingsOf(this.h, this.domain).slice(0, this.scalarBitlen)
  }

  scalarPart(scalar: bigint): boolean[] {
    const bits: boolean[] = []
    for (let i = 0; i < this.scalarBitlen; i++) {
      bits.push((scalar & (1n << BigInt(i))) !== 0n)
    }
    return bits
  }

  keysetPartSelector(): bigint[] {
    const ones = Array(this.keysetPartSize).fill(1n)
    const zeros = Array(this.scalarBitlen).fill(0n)
    return [...ones, ...zeros]
  }

  static getAccumulatorSeedPoint(): { x: bigint; y: bigint } {
    const seedBytes = hexToBytes(BANDERSNATCH_VRF_CONFIG.ACCUMULATOR_SEED_POINT)

    const point = BandersnatchCurve.bytesToPoint(seedBytes)

    return { x: point.x, y: point.y }
  }

  static getPaddingPoint(): { x: bigint; y: bigint } {
    const paddingBytes = hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)

    const point = BandersnatchCurve.bytesToPoint(paddingBytes)

    return { x: point.x, y: point.y }
  }
}

export interface FixedColumns {
  points: AffineColumn
  ringSelector: FieldColumn
  doublingsOfG: AffineColumn
}
