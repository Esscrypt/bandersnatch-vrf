import type { bls12_381 } from '@noble/curves/bls12-381.js'

export function bitReverse(index: number, logN: number): number {
  let reversed = 0
  for (let i = 0; i < logN; i++) {
    reversed = (reversed << 1) | (index & 1)
    index >>= 1
  }
  return reversed
}

export function ifftFieldElements(
  values: bigint[],
  domainSize: number,
  omegaInv: bigint,
  Fr: typeof bls12_381.fields.Fr,
): bigint[] {
  const paddedValues = [...values]
  while (paddedValues.length < domainSize) {
    paddedValues.push(0n)
  }

  if (paddedValues.length > domainSize) {
    paddedValues.splice(domainSize)
  }

  const n = paddedValues.length
  const logN = Math.log2(n)

  if (logN % 1 !== 0) {
    throw new Error(
      `IFFT requires power of 2, got ${n} (domainSize=${domainSize}, values.length=${values.length})`,
    )
  }

  if (n !== domainSize) {
    throw new Error(
      `Padded values length ${n} must equal domain size ${domainSize}`,
    )
  }

  const result = paddedValues.map((v) => Fr.create(v))

  for (let i = 1; i < n - 1; i++) {
    const j = bitReverse(i, logN)
    if (i < j) {
      const temp = result[i]
      result[i] = result[j]!
      result[j] = temp!
    }
  }

  let m = 1
  for (let s = 1; s <= logN; s++) {
    const wm = Fr.pow(omegaInv, BigInt(n / (2 * m)))

    let k = 0
    while (k < n) {
      let w = Fr.ONE
      for (let j = 0; j < m; j++) {
        const hi = result[k + j + m]!
        const lo = result[k + j]!
        const hiTimesW = Fr.mul(hi, w)
        const neg = Fr.sub(lo, hiTimesW)
        result[k + j] = Fr.add(lo, hiTimesW)
        result[k + j + m] = neg
        w = Fr.mul(w, wm)
      }
      k += 2 * m
    }
    m *= 2
  }

  const domainSizeInv = Fr.inv(Fr.create(BigInt(n)))
  const normalized = result.map((r) => Fr.mul(r, domainSizeInv))

  return normalized
}

const BLS12_381_FR_MULTIPLICATIVE_GENERATOR = 7n

export function getOmegaForDomain(
  domainSize: number,
  Fr: typeof bls12_381.fields.Fr,
): { omega: bigint; omegaInv: bigint } {
  const logN = Math.log2(domainSize)
  if (logN % 1 !== 0) {
    throw new Error(`Domain size must be power of 2, got ${domainSize}`)
  }

  const exponent = (Fr.ORDER - 1n) / BigInt(domainSize)
  const omega = Fr.pow(BLS12_381_FR_MULTIPLICATIVE_GENERATOR, exponent)
  const omegaInv = Fr.inv(omega)

  return { omega, omegaInv }
}
