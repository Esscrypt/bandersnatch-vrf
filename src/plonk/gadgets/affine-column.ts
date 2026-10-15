import type { Domain } from '../domain/domain.ts'
import { FieldColumn } from '../domain/domain.ts'

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

  static privateColumn(
    points: Array<{ x: bigint; y: bigint }>,
    domain: Domain,
  ): AffineColumn {
    const xs = points.map((p) => p.x)
    const ys = points.map((p) => p.y)

    while (xs.length < domain.size) {
      xs.push(0n)
      ys.push(0n)
    }

    const xsCol = new FieldColumn(xs, domain.getDomain1x(), domain.capacity)
    const ysCol = new FieldColumn(ys, domain.getDomain1x(), domain.capacity)

    return new AffineColumn(points, xsCol, ysCol)
  }

  static publicColumn(
    points: Array<{ x: bigint; y: bigint }>,
    domain: Domain,
  ): AffineColumn {
    return AffineColumn.privateColumn(points, domain)
  }

  evaluate(z: bigint): [bigint, bigint] {
    return [this.xs.evaluate(z), this.ys.evaluate(z)]
  }
}
