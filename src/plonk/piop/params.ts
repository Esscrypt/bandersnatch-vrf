/**
 * PIOP Parameters
 *
 * Configuration parameters for Polynomial Interactive Oracle Proofs (PIOP)
 * Matches w3f-ring-proof/src/piop/params.rs
 */

import { BandersnatchCurve } from '@pbnjam/bandersnatch'
import { hexToBytes } from 'viem'
import { BANDERSNATCH_VRF_CONFIG } from '../../config/bandersnatch-vrf-config'
import type { Domain } from '../domain/domain'
import { FieldColumn } from '../domain/domain'
import { AffineColumn } from '../gadgets/affine-column'
import { Doubling } from '../gadgets/doubling'

/**
 * PIOP Parameters
 *
 * Contains domain, curve parameters, and base points for ring proofs
 */
export class PiopParams {
  public readonly domain: Domain
  public readonly scalarBitlen: number
  public readonly keysetPartSize: number
  public readonly h: { x: bigint; y: bigint } // Blinding base point
  public readonly seed: { x: bigint; y: bigint } // Accumulator seed point (ACCUMULATOR_SEED_POINT)
  public readonly padding: { x: bigint; y: bigint } // Padding point

  /**
   * Initialize PIOP parameters
   *
   * @param domain - Polynomial evaluation domain
   * @param h - Blinding base point (Pedersen VRF base)
   * @param seed - Accumulator seed point (ACCUMULATOR_SEED_POINT)
   * @param padding - Padding point for invalid keys
   */
  static setup(
    domain: Domain,
    h: { x: bigint; y: bigint },
    seed: { x: bigint; y: bigint },
    padding: { x: bigint; y: bigint },
  ): PiopParams {
    // Scalar bit length for Bandersnatch (253 bits)
    const scalarBitlen = 253

    // Keyset part size: domain.capacity - scalar_bitlen - 1
    // The -1 accounts for the last cells that remain unconstrained
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

  /**
   * Get fixed columns for ring proof
   *
   * @param keys - Ring public keys
   * @returns Fixed columns (points, ring selector, and doublings of G)
   */
  fixedColumns(keys: Array<{ x: bigint; y: bigint }>): FixedColumns {
    const ringSelector = this.keysetPartSelector()
    // ringSelector has length keysetPartSize + scalarBitlen = domain.capacity - 1
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

  /**
   * Create points column
   *
   * Structure: [keys..., padding..., powers_of_h..., 0]
   * Total length: domain.capacity - 1
   */
  pointsColumn(keys: Array<{ x: bigint; y: bigint }>): AffineColumn {
    if (keys.length > this.keysetPartSize) {
      throw new Error(
        `Too many keys: ${keys.length} > keyset_part_size ${this.keysetPartSize}`,
      )
    }

    // Pad keys with padding point
    const paddingLen = this.keysetPartSize - keys.length
    const padding = Array(paddingLen).fill(this.padding)

    // Get powers of 2 multiples of H
    const powersOfH = this.powerOf2MultiplesOfH()

    // Combine: keys + padding + powers_of_h
    const points = [...keys, ...padding, ...powersOfH]

    if (points.length !== this.domain.capacity - 1) {
      throw new Error(
        `Points length ${points.length} must equal domain.capacity - 1 (${this.domain.capacity - 1})`,
      )
    }

    return AffineColumn.publicColumn(points, this.domain)
  }

  /**
   * Compute doublings of generator G using Doubling gadget
   *
   * Matching Rust: doublings_of_g_col() in params.rs
   * Returns AffineColumn with [G, 2G, 4G, ..., 2^(n-1)G]
   */
  doublingsOfG(): AffineColumn {
    // Generator point G
    const g = {
      x: BandersnatchCurve.GENERATOR.x,
      y: BandersnatchCurve.GENERATOR.y,
    }

    // Use Doubling gadget to compute doublings
    const doublings = Doubling.doublingsOf(g, this.domain)

    return AffineColumn.publicColumn(doublings, this.domain)
  }

  /**
   * Compute powers of 2 multiples of H: [H, 2H, 4H, ..., 2^(scalar_bitlen-1)H]
   *
   * Note: This is used for the points column, not for doublings_of_g
   * For doublings_of_g, use doublingsOfG() which uses the Doubling gadget
   */
  powerOf2MultiplesOfH(): Array<{ x: bigint; y: bigint }> {
    // Use Doubling gadget's doublingsOf method
    return Doubling.doublingsOf(this.h, this.domain).slice(0, this.scalarBitlen)
  }

  /**
   * Get scalar part as bits
   *
   * @param scalar - Scalar value to convert to bits
   * @returns Array of boolean values (little-endian)
   */
  scalarPart(scalar: bigint): boolean[] {
    const bits: boolean[] = []
    for (let i = 0; i < this.scalarBitlen; i++) {
      bits.push((scalar & (1n << BigInt(i))) !== 0n)
    }
    return bits
  }

  /**
   * Get keyset part selector
   *
   * Returns: [1, 1, ..., 1 (keyset_part_size times), 0, 0, ..., 0 (scalar_bitlen times)]
   */
  keysetPartSelector(): bigint[] {
    const ones = Array(this.keysetPartSize).fill(1n)
    const zeros = Array(this.scalarBitlen).fill(0n)
    return [...ones, ...zeros]
  }

  /**
   * Get accumulator seed point from config
   */
  static getAccumulatorSeedPoint(): { x: bigint; y: bigint } {
    // Parse ACCUMULATOR_SEED_POINT from config
    const seedBytes = hexToBytes(BANDERSNATCH_VRF_CONFIG.ACCUMULATOR_SEED_POINT)

    // Use BandersnatchCurve.bytesToPoint to decompress the point
    const point = BandersnatchCurve.bytesToPoint(seedBytes)

    return { x: point.x, y: point.y }
  }

  /**
   * Get padding point from config
   */
  static getPaddingPoint(): { x: bigint; y: bigint } {
    const paddingBytes = hexToBytes(BANDERSNATCH_VRF_CONFIG.PADDING_POINT)

    // Use BandersnatchCurve.bytesToPoint to decompress the point
    const point = BandersnatchCurve.bytesToPoint(paddingBytes)

    return { x: point.x, y: point.y }
  }
}

/**
 * Fixed columns structure
 *
 * Matching Rust: FixedColumns in piop/mod.rs
 */
export interface FixedColumns {
  points: AffineColumn
  ringSelector: FieldColumn
  doublingsOfG: AffineColumn
}
