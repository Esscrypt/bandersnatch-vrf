/**
 * Ring VRF End-to-End Tests
 * 
 * Tests complete proof generation and verification workflow using test vectors
 * from the bandersnatch-vrf-spec
 */

import { describe, expect, test, beforeAll } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { bytesToHex, hexToBytes, type Hex } from 'viem'
import { RingVRFProverWasm } from '../prover/ring-kzg-wasm'
import { RingVRFVerifierWasm } from '../verifier/ring-wasm'
import { PedersenVRFProver } from '../prover/pedersen'
import { getBanderoutFromGamma, getCommitmentFromGamma } from '../utils/gamma'
import type { RingVRFInput } from '../prover/ring-kzg'
import path from 'node:path'

// Load test vectors from bandersnatch-vrf-spec/assets/vectors/bandersnatch_sha-512_ell2_ring.json
const testVectorsPath = join(
  __dirname,
  './vectors/bandersnatch_sha-512_ell2_ring.json',
)
const RING_TEST_VECTORS = JSON.parse(
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
  ring_pks: string
  ring_pks_com: string
  ring_proof: string
}>

// Helper function to parse ring public keys
function parseRingKeys(ringPksHex: string): Uint8Array[] {
  const keySize = 32 // Each compressed public key is 32 bytes
  // Ensure hex string has 0x prefix for viem's hexToBytes
  const normalizedHex = ringPksHex.startsWith('0x') ? ringPksHex : `0x${ringPksHex}`
  const ringPksBytes = hexToBytes(normalizedHex as Hex)
  const keys: Uint8Array[] = []
  
  for (let i = 0; i < ringPksBytes.length; i += keySize) {
    keys.push(ringPksBytes.slice(i, i + keySize))
  }
  
  return keys
}

// Utility class for Ring VRF test vector handling
class RingTestVectorUtils {
  static prepareRingInput(vector: typeof RING_TEST_VECTORS[0]): {
    secretKey: Uint8Array
    publicKey: Uint8Array
    ringInput: RingVRFInput
  } {
    // Normalize hex strings to have 0x prefix for viem's hexToBytes
    const skHex = vector.sk.startsWith('0x') ? vector.sk : `0x${vector.sk}`
    const pkHex = vector.pk.startsWith('0x') ? vector.pk : `0x${vector.pk}`
    
    let alphaHex = '0x'
    if (vector.alpha) {
      alphaHex = vector.alpha.startsWith('0x') ? vector.alpha : `0x${vector.alpha}`
    }
    
    let adHex = '0x'
    if (vector.ad) {
      adHex = vector.ad.startsWith('0x') ? vector.ad : `0x${vector.ad}`
    }
    
    const secretKey = hexToBytes(skHex as `0x${string}`)
    const publicKey = hexToBytes(pkHex as `0x${string}`)
    const inputBytes = hexToBytes(alphaHex as `0x${string}`)
    const auxData = hexToBytes(adHex as `0x${string}`)
    
    // Parse ring public keys
    const ringKeys = parseRingKeys(vector.ring_pks)
    
    console.log(`Ring size: ${ringKeys.length}`)
    console.log(`Prover public key: ${bytesToHex(publicKey)}`)
    console.log(`Ring keys:`)
    for (const [i, key] of ringKeys.entries()) {
      console.log(`  Key ${i}: ${bytesToHex(key)}`)
    }
    
    // Find prover index in ring
    let proverIndex = -1
    for (let i = 0; i < ringKeys.length; i++) {
      if (bytesToHex(ringKeys[i]) === bytesToHex(publicKey)) {
        proverIndex = i
        break
      }
    }
    
    if (proverIndex === -1) {
      throw new Error('Prover public key not found in ring')
    }
    
    console.log(`Prover index in ring: ${proverIndex}`)
    
    // Create ring input (using the prover's expected interface)
    const ringInput: RingVRFInput = {
      input: inputBytes,
      auxData: auxData,
      ringKeys: ringKeys,
      proverIndex: proverIndex
    }
    
    return { secretKey, publicKey, ringInput }
  }
}

describe('Ring VRF End-to-End Tests (WASM)', () => {
  let ringProver: RingVRFProverWasm
  let ringVerifier: RingVRFVerifierWasm
  
  beforeAll(async () => {
    const srsFilePath = path.join(__dirname, '../../../../packages/bandersnatch-vrf/test-data/srs/zcash-srs-2-11-uncompressed.bin')
    // Wait for WASM initialization to complete
    ringProver = new RingVRFProverWasm(srsFilePath)
    await ringProver.init()
    
    ringVerifier = new RingVRFVerifierWasm(srsFilePath)
    await ringVerifier.init()
  })

  describe('Exact Value Matching Against Test Vectors', () => {
    for (const [index, vector] of RING_TEST_VECTORS.slice(0, 2).entries()) {
      test(`Vector ${index + 1}: Exact value comparison with test vector`, async () => {
        console.log(`\n=== Exact Value Matching for ${vector.comment} ===`)
        
        // Parse test vector data
        const { secretKey, ringInput } = RingTestVectorUtils.prepareRingInput(vector)
        
        // Skip if prover not initialized
        // if (!ringProver || !ringVerifier) {
        //   console.log('⚠️ Skipping value matching - Ring VRF prover not initialized')
        //   return
        // }
        
        try {
          // Generate proof
          const proofResult = ringProver.prove(secretKey, ringInput)
          
          // ===== VRF Output Values (Exact Match Required) =====
          const actualGamma = bytesToHex(proofResult.gamma).slice(2) // Remove 0x
          const actualBeta = bytesToHex(getCommitmentFromGamma(proofResult.gamma)).slice(2) // Remove 0x
          const actualBanderout = bytesToHex(getBanderoutFromGamma(proofResult.gamma)).slice(2) // Remove 0x
          
          console.log(`\n--- VRF Output Values ---`)
          console.log(`Expected gamma: ${vector.gamma}`)
          console.log(`Actual gamma:   ${actualGamma}`)
          console.log(`Gamma matches:  ${actualGamma === vector.gamma}`)
          
          console.log(`Expected beta:  ${vector.beta}`)
          console.log(`Actual beta:    ${actualBeta}`)
          console.log(`Beta matches:   ${actualBeta === vector.beta}`)
          
          // ===== Blinding Factor (for debugging) =====
          // The blinding factor is used in ring proof generation
          // If it doesn't match, the ring proof will be different
          // Compute blinding factor separately to compare with test vector
          const I = PedersenVRFProver.hashToCurve(ringInput.input)
          const computedBlindingFactor = PedersenVRFProver.generateBlindingFactor(
            secretKey,
            I,
            ringInput.auxData,
          )
          const actualBlindingFactor = bytesToHex(computedBlindingFactor).slice(2)
          const expectedBlindingFactor = vector.blinding
          
          console.log(`\n--- Blinding Factor ---`)
          console.log(`Expected: ${expectedBlindingFactor}`)
          console.log(`Actual:   ${actualBlindingFactor}`)
          console.log(`Matches:  ${actualBlindingFactor === expectedBlindingFactor}`)
          
          // Assert exact value matches with test vectors
          expect(actualGamma).toBe(vector.gamma)
          expect(actualBeta).toBe(vector.beta)
          expect(actualBanderout).toBe(vector.beta.slice(0, 64)) // banderout is first 32 bytes of beta
          expect(actualBlindingFactor).toBe(expectedBlindingFactor) // Blinding factor must match for ring proof to match
          
          // ===== Pedersen Proof Components (Exact Match Required) =====
          const pedersenProofBytes = proofResult.proof.pedersenProof
          if (!pedersenProofBytes) {
            throw new Error('Pedersen proof not found in result')
          }
          
            // Deserialize the Pedersen proof to get individual components
            const pedersenProof = PedersenVRFProver.deserialize(pedersenProofBytes)

            const actualProofPkCom = bytesToHex(pedersenProof.Y_bar).slice(2)
            const actualProofR = bytesToHex(pedersenProof.R).slice(2)
            const actualProofOk = bytesToHex(pedersenProof.O_k).slice(2)
            const actualProofS = bytesToHex(pedersenProof.s).slice(2)
            const actualProofSb = bytesToHex(pedersenProof.s_b).slice(2)
          
          console.log(`\n--- Pedersen Proof Components ---`)
          console.log(`Expected proof_pk_com: ${vector.proof_pk_com}`)
          console.log(`Actual proof_pk_com:   ${actualProofPkCom}`)
          console.log(`Matches: ${actualProofPkCom === vector.proof_pk_com}`)
          
          console.log(`Expected proof_r: ${vector.proof_r}`)
          console.log(`Actual proof_r:   ${actualProofR}`)
          console.log(`Matches: ${actualProofR === vector.proof_r}`)
            
            // Assert exact value matches for proof components
            expect(actualProofPkCom).toBe(vector.proof_pk_com)
            expect(actualProofR).toBe(vector.proof_r)
            expect(actualProofOk).toBe(vector.proof_ok)
            expect(actualProofS).toBe(vector.proof_s)
            expect(actualProofSb).toBe(vector.proof_sb)
          
          // ===== Ring Commitment (FixedColumnsCommitted - Exact Match Required) =====
          // Compute ring commitment using WASM computeRingCommitment (returns 144 bytes)
          // The WASM implementation uses the Rust reference, which should match test vectors exactly
          // IMPORTANT: Use keys in the exact order from test vector (ring_pks field)
          // The test vectors were generated with keys in this specific order
          const computedRingCommitment = ringProver.computeRingCommitment(ringInput.ringKeys)
          const expectedRingCommitment = hexToBytes(`0x${vector.ring_pks_com}`)
          
          console.log(`\n--- Ring Commitment (FixedColumnsCommitted) ---`)
          console.log(`Expected length: ${expectedRingCommitment.length} bytes`)
          console.log(`Actual length:   ${computedRingCommitment.length} bytes`)
          console.log(`Expected (hex): ${bytesToHex(expectedRingCommitment).slice(2)}`)
          console.log(`Actual (hex):   ${bytesToHex(computedRingCommitment).slice(2)}`)
          console.log(`\n--- Ring Commitment Comparison (WASM) ---`)
          console.log(`Using Rust reference implementation via WASM`)
          console.log(`Should match test vectors exactly`)
          
          expect(computedRingCommitment.length).toBe(144) // FixedColumnsCommitted: cx[48] + cy[48] + selector[48]
          
          // With WASM (Rust reference), the commitment should match exactly
          const computedHex = bytesToHex(computedRingCommitment).slice(2)
          const expectedHex = bytesToHex(expectedRingCommitment).slice(2)
          
          if (computedHex === expectedHex) {
            console.log(`✅ Ring commitment matches test vector exactly!`)
          } else {
            console.log(`⚠️  Ring commitment mismatch (investigating...)`)
            console.log(`   Expected: ${expectedHex.slice(0, 64)}...`)
            console.log(`   Actual:   ${computedHex.slice(0, 64)}...`)
          }
          
          // Assert exact match (WASM should match Rust reference)
          expect(computedRingCommitment).toEqual(expectedRingCommitment)
          
          // ===== Ring Proof (Exact Match Required) =====
          // NOTE: Ring proof depends on ring commitment, so it will also fail until
          // Lagrangian SRS conversion is implemented
          if (proofResult.proof.ringProof) {
            const actualRingProof = bytesToHex(proofResult.proof.ringProof).slice(2)
            const expectedRingProof = vector.ring_proof
            
            console.log(`\n--- Ring Proof ---`)
            console.log(`Expected length: ${expectedRingProof.length / 2} bytes`)
            console.log(`Actual length:   ${proofResult.proof.ringProof.length} bytes`)
            console.log(`Expected (first 64 chars): ${expectedRingProof.slice(0, 64)}...`)
            console.log(`Actual (first 64 chars):   ${actualRingProof.slice(0, 64)}...`)
            console.log(`\n--- Ring Proof Comparison (WASM) ---`)
            console.log(`Using Rust reference implementation via WASM`)
            
            // With WASM (Rust reference), the proof should match exactly
            if (actualRingProof === expectedRingProof) {
              console.log(`✅ Ring proof matches test vector exactly!`)
            } else {
              console.log(`⚠️  Ring proof mismatch (investigating...)`)
            }
            
            // Assert exact match (WASM should match Rust reference)
            expect(actualRingProof).toBe(expectedRingProof)
          }
          
          // Verify structure
          expect(proofResult.gamma.length).toBe(32)
          
          // ===== Verification (Must Pass) =====
          console.log(`\n--- Verification ---`)
          const verificationInput: RingVRFInput = {
            input: ringInput.input,
            auxData: ringInput.auxData,
            ringKeys: ringInput.ringKeys,
            proverIndex: ringInput.proverIndex,
          }
          
          const verificationProof = {
            pedersenProof: proofResult.proof.pedersenProof,
            ringCommitment: proofResult.proof.ringCommitment,
            ringProof: proofResult.proof.ringProof,
          }
          
          const isValid = ringVerifier.verify(
            ringInput.ringKeys,
            verificationInput,
            {
              gamma: proofResult.gamma,
              proof: verificationProof,
            },
            ringInput.auxData,
          )
          
          console.log(`Verification result: ${isValid ? '✅ PASSED' : '❌ FAILED'}`)
          expect(isValid).toBe(true)
          
          console.log(`\n✅ VRF outputs and Pedersen proof components match test vector exactly!`)
          console.log(`✅ Using WASM (Rust reference) for ring commitment and proof - should match exactly!`)
          console.log(`✅ Proof verification passed!`)
          
        } catch (error) {
          console.log(`\n❌ Value matching error: ${error}`)
          throw error // Fail the test on mismatch
        }
      })
    }
  })
})
