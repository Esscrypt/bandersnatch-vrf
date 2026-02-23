/**
 * FFT/IFFT Utilities
 *
 * Shared implementations for Fast Fourier Transform operations on field elements.
 * These utilities can be used across the codebase to avoid code duplication.
 */

import type { bls12_381 } from '@noble/curves/bls12-381.js'

/**
 * Bit-reverse an index for FFT/IFFT
 *
 * @param index - Index to reverse
 * @param logN - Log2 of the array size
 * @returns Bit-reversed index
 */
export function bitReverse(index: number, logN: number): number {
  let reversed = 0
  for (let i = 0; i < logN; i++) {
    reversed = (reversed << 1) | (index & 1)
    index >>= 1
  }
  return reversed
}

/**
 * IFFT on field elements (scalars)
 *
 * Converts from evaluation form to coefficient form using Cooley-Tukey algorithm.
 * This is a shared implementation that can be used across the codebase.
 *
 * @param values - Field element evaluations [f(w^0), f(w^1), ..., f(w^(n-1))]
 * @param domainSize - Domain size n (must be power of 2)
 * @param omegaInv - Inverse primitive root of unity (omega^-1)
 * @param Fr - Field operations (from bls12_381.fields.Fr or similar)
 * @returns Polynomial coefficients [a_0, a_1, ..., a_(n-1)]
 */
export function ifftFieldElements(
  values: bigint[],
  domainSize: number,
  omegaInv: bigint,
  Fr: typeof bls12_381.fields.Fr,
): bigint[] {
  // Pad values to domainSize if needed (domainSize must be power of 2)
  const paddedValues = [...values]
  while (paddedValues.length < domainSize) {
    paddedValues.push(0n)
  }

  // Truncate if too long (shouldn't happen, but handle gracefully)
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

  // Bit-reverse permutation
  // Match Rust derange exactly: for idx in 1..(xi.len() as u64 - 1)
  // Rust skips indices 0 and len-1, but we can do all since bitrev(0) = 0 and we check i < j
  // However, let's match Rust exactly to be safe
  for (let i = 1; i < n - 1; i++) {
    const j = bitReverse(i, logN)
    if (i < j) {
      const temp = result[i]
      result[i] = result[j]!
      result[j] = temp!
    }
  }

  // Cooley-Tukey IFFT algorithm
  // Match Rust oi_helper structure: gap starts at 1, doubles each iteration
  let m = 1
  for (let s = 1; s <= logN; s++) {
    // Compute wm = omegaInv^(n/(2*m))
    // This is the root used for this stage
    const wm = Fr.pow(omegaInv, BigInt(n / (2 * m)))

    // Match Rust oi_helper: process chunks of size 2*m
    // For gap=m, Rust uses roots[j * step] where step = num_chunks = n/(2*m)
    // roots_cache = [1, omegaInv, omegaInv^2, ..., omegaInv^{(n/2)-1}]
    // So roots[j * n/(2*m)] = omegaInv^(j * n/(2*m))
    // We compute w = wm^j = (omegaInv^(n/(2*m)))^j = omegaInv^(j*n/(2*m))
    // This should match exactly
    let k = 0
    while (k < n) {
      let w = Fr.ONE
      for (let j = 0; j < m; j++) {
        // Match Rust butterfly_fn_oi exactly:
        // *hi *= *root;  (hi = hi * root)
        // let mut neg = *lo; neg -= *hi;  (neg = lo - hi, using OLD lo)
        // *lo += *hi;  (lo = lo + hi)
        // *hi = neg;  (hi = neg = old_lo - hi)
        const hi = result[k + j + m]!
        const lo = result[k + j]!
        const hiTimesW = Fr.mul(hi, w)
        const neg = Fr.sub(lo, hiTimesW) // neg = lo - hi*w (using old lo)
        result[k + j] = Fr.add(lo, hiTimesW) // lo = lo + hi*w
        result[k + j + m] = neg // hi = neg = old_lo - hi*w
        w = Fr.mul(w, wm)
      }
      k += 2 * m
    }
    m *= 2
  }

  // Normalize by dividing by domain size
  const domainSizeInv = Fr.inv(Fr.create(BigInt(n)))
  const normalized = result.map((r) => Fr.mul(r, domainSizeInv))

  return normalized
}

/**
 * Get omega and omegaInv for a given domain size
 *
 * @param domainSize - Domain size (must be power of 2)
 * @param Fr - Field operations
 * @returns Object with omega and omegaInv
 */
/** Multiplicative generator of BLS12-381 Fr* (matches arkworks). */
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
