/**
 * SRS (Structured Reference String) Loader for Ring VRF
 *
 * Loads and parses Zcash powers of tau SRS files for use with MSM-based ring commitments.
 * The SRS file contains BLS12-381 G1 points in arkworks serialization format.
 */

import { existsSync, readFileSync } from 'node:fs'
import { bls12_381 } from '@noble/curves/bls12-381'
import type { Safe } from '@pbnj/types'
import { safeError, safeResult } from '@pbnj/types'

/**
 * Load SRS from file and extract G1 and G2 points
 *
 * The SRS file format (arkworks PcsParams):
 * - Format: [u64 G1_length][compressed G1 points...][u64 G2_length][compressed G2 points...]
 * - Compressed G1 points: 48 bytes each (BLS12-381)
 * - Compressed G2 points: 96 bytes each (BLS12-381)
 *
 * **Why many G1 points but only 2 G2 points?**
 *
 * - **G1 points (powers_in_g1)**: For KZG polynomial commitments, you need one G1 point per
 *   polynomial coefficient. For domain size n, you need n G1 points: [G, τG, τ²G, ..., τ^(n-1)G].
 *   These are used to compute commitments: commit(p) = Σ(c_i * τ^i * G) where c_i are coefficients.
 *
 * - **G2 points (powers_in_g2)**: For verification, you typically only need 2 G2 points:
 *   [G2, τ·G2]. These are used in pairing operations: e(commitment, G2) = e(proof, τ·G2).
 *   However, some protocols may require more G2 points for advanced verification.
 *
 * Reads all G1 and G2 points as specified by the length fields in the file.
 *
 * @param srsFilePath - Path to SRS file (compressed format)
 * @returns G1 and G2 points as Uint8Array arrays, plus generators (g1 = G1 generator G, g2 = G2 generator G2)
 */
export function loadSRSFromFile(srsFilePath: string): Safe<{
  g1Points: Uint8Array[]
  g1: Uint8Array
  g2Points: Uint8Array[]
  g2: Uint8Array
}> {
  if (!existsSync(srsFilePath)) {
    return safeError(new Error(`SRS file not found: ${srsFilePath}`))
  }

  // Load file
  const srsData = readFileSync(srsFilePath)
  console.debug('[loadSRSFromFile] Loaded SRS file', {
    path: srsFilePath,
    size: srsData.length,
  })

  // Read u64 (little-endian) helper
  const readU64 = (offset: number): number => {
    let value = 0n
    for (let i = 0; i < 8; i++) {
      value |= BigInt(srsData[offset + i]!) << BigInt(i * 8)
    }
    return Number(value)
  }

  let offset = 0

  // Read G1 length (u64, little-endian)
  const g1Length = readU64(offset)
  offset += 8
  console.debug('[loadSRSFromFile] G1 length', { g1Length })

  // Extract all G1 points (compressed, 48 bytes each)
  const g1Points: Uint8Array[] = []
  const g1PointSize = 48

  for (let i = 0; i < g1Length; i++) {
    const pointOffset = offset + i * g1PointSize
    if (pointOffset + g1PointSize > srsData.length) {
      return safeError(
        new Error(
          `G1 point ${i} extends beyond file: offset ${pointOffset} + ${g1PointSize} > ${srsData.length}`,
        ),
      )
    }

    const pointBytes = srsData.slice(pointOffset, pointOffset + g1PointSize)
    try {
      // Validate it's a valid compressed G1 point
      bls12_381.G1.Point.fromBytes(pointBytes)
      g1Points.push(pointBytes)
    } catch (error) {
      return safeError(
        new Error(
          `Invalid G1 point at index ${i}: ${error instanceof Error ? error.message : String(error)}`,
        ),
      )
    }
  }

  offset += g1Length * g1PointSize
  console.debug('[loadSRSFromFile] Extracted G1 points', {
    count: g1Points.length,
    offsetAfterG1: offset,
  })

  // Read G2 length (u64, little-endian)
  if (offset + 8 > srsData.length) {
    return safeError(
      new Error(
        `Cannot read G2 length: offset ${offset} + 8 > ${srsData.length}`,
      ),
    )
  }

  const g2Length = readU64(offset)
  offset += 8
  console.debug('[loadSRSFromFile] G2 length', { g2Length })

  // Extract all G2 points (compressed, 96 bytes each)
  const g2Points: Uint8Array[] = []
  const g2PointSize = 96

  for (let i = 0; i < g2Length; i++) {
    const pointOffset = offset + i * g2PointSize
    if (pointOffset + g2PointSize > srsData.length) {
      return safeError(
        new Error(
          `G2 point ${i} extends beyond file: offset ${pointOffset} + ${g2PointSize} > ${srsData.length}`,
        ),
      )
    }

    const pointBytes = srsData.slice(pointOffset, pointOffset + g2PointSize)
    try {
      // Validate it's a valid compressed G2 point
      bls12_381.G2.Point.fromBytes(pointBytes)
      g2Points.push(pointBytes)
    } catch (error) {
      return safeError(
        new Error(
          `Invalid G2 point at index ${i}: ${error instanceof Error ? error.message : String(error)}`,
        ),
      )
    }
  }

  offset += g2Length * g2PointSize
  console.debug('[loadSRSFromFile] Extracted G2 points', {
    count: g2Points.length,
    offsetAfterG2: offset,
  })

  // Verify we've read the entire file
  const expectedSize = 8 + g1Length * g1PointSize + 8 + g2Length * g2PointSize
  if (offset !== srsData.length) {
    return safeError(
      new Error(
        `File size mismatch: expected ${expectedSize} bytes (8 + ${g1Length}*${g1PointSize} + 8 + ${g2Length}*${g2PointSize}), ` +
          `but file has ${srsData.length} bytes. Read ${offset} bytes.`,
      ),
    )
  }

  console.debug('[loadSRSFromFile] File read completely', {
    totalBytesRead: offset,
    fileSize: srsData.length,
    g1PointsRead: g1Points.length,
    g2PointsRead: g2Points.length,
  })

  // Extract generators (first points: G1 generator and G2 generator)
  const g1 = g1Points[0]! // G1 generator: G
  const g2 = g2Points[0]! // G2 generator: G2

  console.info('[loadSRSFromFile] SRS loaded successfully', {
    g1Points: g1Points.length,
    g2Points: g2Points.length,
    fileSize: srsData.length,
    bytesRead: offset,
    g1Hex: Array.from(g1)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 32),
    g2Hex: Array.from(g2)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 32),
  })

  return safeResult({ g1Points, g1, g2Points, g2 })
}

/**
 * Convert monomial SRS to Lagrangian SRS
 *
 * This is a placeholder - actual conversion requires:
 * 1. Domain generator ω
 * 2. Computing Lagrange basis polynomials
 * 3. Evaluating at secret τ (which we don't have)
 *
 * For now, we return the monomial SRS as-is and note that
 * proper Lagrangian conversion requires the secret τ.
 *
 * @param monomialSRS - Monomial SRS points [G, τG, τ²G, ...]
 * @returns Lagrangian SRS points (for now, same as monomial)
 */
export function convertToLagrangianSRS(
  monomialSRS: Uint8Array[],
): Safe<Uint8Array[]> {
  // TODO: Implement proper Lagrangian conversion
  // This requires the secret τ from the ceremony, which we don't have.
  // For now, we assume the SRS file already contains Lagrangian points
  // or we use a pre-computed conversion.
  console.warn(
    '[convertToLagrangianSRS] Using monomial SRS as Lagrangian (not correct for MSM)',
  )
  return safeResult(monomialSRS)
}
