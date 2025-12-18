/**
 * Pedersen VRF Test Vectors from ark-vrf
 * 
 * These test vectors are derived from the official ark-vrf implementation
 * and are designed to validate our Pedersen VRF implementation against
 * the reference Rust implementation.
 */

import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { PedersenVRFProver } from '../prover/pedersen'
import { bytesToHex, hexToBytes } from 'viem'

// Load test vectors from bandersnatch-vrf-spec/assets/vectors/bandersnatch_sha-512_ell2_pedersen.json
const testVectorsPath = join(
  __dirname,
  './vectors/bandersnatch_sha-512_ell2_pedersen.json',
)
const PEDERSEN_TEST_VECTORS = JSON.parse(
  readFileSync(testVectorsPath, 'utf-8'),
) as Array<{
  comment: string
  sk: string
  pk: string
  alpha: string
  salt: string
  ad: string
  h: string
  gamma: string
  beta: string
  blinding: string
  proof_pk_com: string
  proof_r: string
  proof_ok: string
  proof_s: string
  proof_sb: string
}>

describe('Pedersen VRF Test Vector Validation', () => {
  for (const [index, vector] of PEDERSEN_TEST_VECTORS.entries()) {
    test(`Test Vector ${index + 1}: ${vector.comment}`, () => {
      console.log(`\n=== Testing Pedersen Vector ${index + 1}: ${vector.comment} ===`)
      
      // Convert hex strings to bytes (handle with or without 0x prefix)
      const skHex = vector.sk.startsWith('0x') ? vector.sk : `0x${vector.sk}`
      
      let alphaHex = '0x'
      if (vector.alpha) {
        alphaHex = vector.alpha.startsWith('0x') ? vector.alpha : `0x${vector.alpha}`
      }
      
      let adHex = '0x'
      if (vector.ad) {
        adHex = vector.ad.startsWith('0x') ? vector.ad : `0x${vector.ad}`
      }
      
      const privateKey = hexToBytes(skHex as `0x${string}`)
      const alpha = hexToBytes(alphaHex as `0x${string}`)
      const additionalData = hexToBytes(adHex as `0x${string}`)
      
      console.log('Input data:')
      console.log(`  Private Key: ${vector.sk}`)
      console.log(`  Public Key: ${vector.pk}`)
      console.log(`  Blinding Factor: ${vector.blinding}`)
      console.log(`  Alpha (message): ${vector.alpha || '(empty)'}`)
      console.log(`  Additional Data: ${vector.ad || '(empty)'}`)
      
      // Test our Pedersen VRF implementation
      try {
        const vrfResult = PedersenVRFProver.prove(
          privateKey,
          { input: alpha, auxData: additionalData }
        )

        // Basic validation that our implementation produces valid structure
        expect(vrfResult).toBeDefined()
        expect(vrfResult.gamma).toBeInstanceOf(Uint8Array)
        expect(vrfResult.hash).toBeInstanceOf(Uint8Array)
        expect(vrfResult.proof).toBeInstanceOf(Uint8Array)
   
        // Parse the Pedersen proof structure
        const deserializedProof = PedersenVRFProver.deserialize(vrfResult.proof)
        
        // Validate actual values against expected test vectors
        const ourGammaHex = bytesToHex(vrfResult.gamma).slice(2) // Remove 0x prefix
        const ourBetaHex = bytesToHex(vrfResult.hash).slice(2) // Remove 0x prefix
        const ourYBarHex = bytesToHex(deserializedProof.Y_bar).slice(2)
        const ourRHex = bytesToHex(deserializedProof.R).slice(2)
        const ourOkHex = bytesToHex(deserializedProof.O_k).slice(2)
        const ourSHex = bytesToHex(deserializedProof.s).slice(2)
        const ourSbHex = bytesToHex(deserializedProof.s_b).slice(2)
        

        // Assert exact value matches with ark-vrf test vectors
        expect(ourGammaHex).toBe(vector.gamma)
        expect(ourBetaHex).toBe(vector.beta)
        expect(ourYBarHex).toBe(vector.proof_pk_com)
        expect(ourRHex).toBe(vector.proof_r)
        expect(ourOkHex).toBe(vector.proof_ok)
        expect(ourSHex).toBe(vector.proof_s)
        expect(ourSbHex).toBe(vector.proof_sb)
        
      } catch (error) {
        console.error(`Pedersen VRF implementation failed for ${vector.comment}:`, error)
        throw error // Re-throw to fail the test
      }
    })
  }
})
