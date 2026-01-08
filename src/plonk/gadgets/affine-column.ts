/**
 * Affine Column for Plonk
 * 
 * Represents a column of affine curve points in evaluation form
 */

import type { Domain } from '../domain/domain'
import { FieldColumn } from '../domain/domain'

/**
 * Affine column representing points on a curve
 */
export class AffineColumn {
  public readonly points: Array<{ x: bigint; y: bigint }>
  public readonly xs: FieldColumn
  public readonly ys: FieldColumn

  private constructor(
    points: Array<{ x: bigint; y: bigint }>,
    xs: FieldColumn,
    ys: FieldColumn,
  ) {
    this.points = points
    this.xs = xs
    this.ys = ys
  }

  /**
   * Create private column (witness column)
   */
  static privateColumn(
    points: Array<{ x: bigint; y: bigint }>,
    domain: Domain,
  ): AffineColumn {
    const xs = points.map(p => p.x)
    const ys = points.map(p => p.y)
    
    // Pad to domain size if needed
    while (xs.length < domain.size) {
      xs.push(0n)
      ys.push(0n)
    }

    const xsCol = new FieldColumn(xs, domain.getDomain1x(), domain.capacity)
    const ysCol = new FieldColumn(ys, domain.getDomain1x(), domain.capacity)

    return new AffineColumn(points, xsCol, ysCol)
  }

  /**
   * Create public column (fixed column)
   */
  static publicColumn(
    points: Array<{ x: bigint; y: bigint }>,
    domain: Domain,
  ): AffineColumn {
    return AffineColumn.privateColumn(points, domain)
  }

  /**
   * Evaluate at point z
   */
  evaluate(z: bigint): [bigint, bigint] {
    return [this.xs.evaluate(z), this.ys.evaluate(z)]
  }
}

