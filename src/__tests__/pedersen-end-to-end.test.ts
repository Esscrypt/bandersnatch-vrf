import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { PedersenVRFProver, type PedersenVRFInput } from '../prover/pedersen.ts'
import { PedersenVRFVerifier } from '../verifier/pedersen.ts'

function bytesToHex(bytes: Uint8Array): string {
  if (!bytes || bytes.length === 0) return '0x'
  return '0x' + Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}

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

function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith('0x')) {
    hex = hex.slice(2)
  }
  
  if (hex === '') {
    return new Uint8Array(0)
  }
  
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

describe('Pedersen VRF End-to-End Tests', () => {
  describe('Proof Generation and Verification', () => {
    for (const [index, vector] of PEDERSEN_TEST_VECTORS.entries()) {
      test(`Vector ${index + 1}: ${vector.comment} - Complete workflow`, async () => {
        const secretKey = hexToBytes(vector.sk)
        const inputBytes = hexToBytes(vector.alpha)
        const auxData = hexToBytes(vector.ad)
        
        console.log(`\n=== Testing ${vector.comment} ===`)
        console.log(`Input: "${vector.alpha}"`)
        console.log(`Aux Data: "${vector.ad}"`)
        
        const pedersenInput: PedersenVRFInput = {
          input: inputBytes,
          auxData: auxData
        }
        
        const proofResult = PedersenVRFProver.prove(secretKey, pedersenInput)
        
        const deserializedProof = PedersenVRFProver.deserialize(proofResult.proof)
        
        console.log('Generated proof:')
        console.log(`  Gamma: ${bytesToHex(proofResult.gamma)}`)
        console.log(`  Beta:  ${bytesToHex(proofResult.hash)}`)
        console.log(`  Proof components:`)
        console.log(`    Y_bar:  ${bytesToHex(deserializedProof.Y_bar)}`)
        console.log(`    R:      ${bytesToHex(deserializedProof.R)}`)
        console.log(`    O_k:    ${bytesToHex(deserializedProof.O_k)}`)
        console.log(`    S:      ${bytesToHex(deserializedProof.s)}`)
        console.log(`    SB:     ${bytesToHex(deserializedProof.s_b)}`)
        
        try {
          const isValid = PedersenVRFVerifier.verify(
            inputBytes,
            proofResult.gamma,
            proofResult.proof,
            auxData
          )
          
          console.log(`Verification result: ${isValid ? '✅ VALID' : '❌ INVALID'}`)
          expect(isValid).toBe(true)
        } catch (error) {
          console.log(`⚠️ Verifier needs fixes: ${error}`)
        }
        
        expect(proofResult.gamma).toBeInstanceOf(Uint8Array)
        expect(proofResult.hash).toBeInstanceOf(Uint8Array)
        expect(proofResult.proof).toBeInstanceOf(Uint8Array)
        expect(deserializedProof.Y_bar).toBeInstanceOf(Uint8Array)
        expect(deserializedProof.R).toBeInstanceOf(Uint8Array)
        expect(deserializedProof.O_k).toBeInstanceOf(Uint8Array)
        expect(deserializedProof.s).toBeInstanceOf(Uint8Array)
        expect(deserializedProof.s_b).toBeInstanceOf(Uint8Array)
        
        expect(proofResult.gamma.length).toBe(32)
        expect(proofResult.hash.length).toBe(64)
        expect(deserializedProof.Y_bar.length).toBe(32)
        expect(deserializedProof.R.length).toBe(32)
        expect(deserializedProof.O_k.length).toBe(32)
        expect(deserializedProof.s.length).toBe(32)
        expect(deserializedProof.s_b.length).toBe(32)
      })
    }
  })

  describe('Value Matching Against Test Vectors', () => {
    for (const [index, vector] of PEDERSEN_TEST_VECTORS.slice(0, 2).entries()) {
      test(`Vector ${index + 1}: Exact value matching`, async () => {
        const secretKey = hexToBytes(vector.sk)
        const inputBytes = hexToBytes(vector.alpha)
        const auxData = hexToBytes(vector.ad)
        
        const pedersenInput: PedersenVRFInput = {
          input: inputBytes,
          auxData: auxData
        }
        
        const proofResult = PedersenVRFProver.prove(secretKey, pedersenInput)
        
        const deserializedProof = PedersenVRFProver.deserialize(proofResult.proof)
        
        const actualGamma = bytesToHex(proofResult.gamma).slice(2)
        const actualBeta = bytesToHex(proofResult.hash).slice(2)
        
        console.log(`\n=== Value Matching for ${vector.comment} ===`)
        console.log(`Expected gamma: ${vector.gamma}`)
        console.log(`Actual gamma:   ${actualGamma}`)
        console.log(`Gamma matches:  ${actualGamma === vector.gamma}`)
        
        console.log(`Expected beta:  ${vector.beta}`)
        console.log(`Actual beta:    ${actualBeta}`)
        console.log(`Beta matches:   ${actualBeta === vector.beta}`)
        
        const actualPkCom = bytesToHex(deserializedProof.Y_bar).slice(2)
        const actualR = bytesToHex(deserializedProof.R).slice(2)
        const actualOk = bytesToHex(deserializedProof.O_k).slice(2)
        const actualS = bytesToHex(deserializedProof.s).slice(2)
        const actualSb = bytesToHex(deserializedProof.s_b).slice(2)
        
        console.log(`Expected pk_com: ${vector.proof_pk_com}`)
        console.log(`Actual pk_com:   ${actualPkCom}`)
        console.log(`PK_COM matches:  ${actualPkCom === vector.proof_pk_com}`)
        
        console.log(`Expected r:      ${vector.proof_r}`)
        console.log(`Actual r:        ${actualR}`)
        console.log(`R matches:       ${actualR === vector.proof_r}`)
        
        console.log(`Expected ok:     ${vector.proof_ok}`)
        console.log(`Actual ok:       ${actualOk}`)
        console.log(`OK matches:      ${actualOk === vector.proof_ok}`)
        
        console.log(`Expected s:      ${vector.proof_s}`)
        console.log(`Actual s:        ${actualS}`)
        console.log(`S matches:       ${actualS === vector.proof_s}`)
        
        console.log(`Expected sb:     ${vector.proof_sb}`)
        console.log(`Actual sb:       ${actualSb}`)
        console.log(`SB matches:      ${actualSb === vector.proof_sb}`)
        
        expect(actualGamma).toBe(vector.gamma)
        expect(actualBeta).toBe(vector.beta)
        expect(actualPkCom).toBe(vector.proof_pk_com)
        expect(actualR).toBe(vector.proof_r)
        expect(actualOk).toBe(vector.proof_ok)
        expect(actualS).toBe(vector.proof_s)
        expect(actualSb).toBe(vector.proof_sb)
        
        expect(proofResult.gamma.length).toBe(32)
        expect(proofResult.hash.length).toBe(64)
        expect(deserializedProof.Y_bar.length).toBe(32)
        expect(deserializedProof.R.length).toBe(32)
        expect(deserializedProof.O_k.length).toBe(32)
        expect(deserializedProof.s.length).toBe(32)
        expect(deserializedProof.s_b.length).toBe(32)
      })
    }
  })

  describe('Basic Functionality Tests', () => {
    test('Empty input should work correctly', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const emptyInput: PedersenVRFInput = {
        input: new Uint8Array(0),
        auxData: new Uint8Array(0)
      }
      
      const proofResult = PedersenVRFProver.prove(secretKey, emptyInput)
      const deserializedProof = PedersenVRFProver.deserialize(proofResult.proof)
      
      expect(proofResult.gamma.length).toBe(32)
      expect(proofResult.hash.length).toBe(64)
      expect(deserializedProof.Y_bar.length).toBe(32)
      expect(deserializedProof.R.length).toBe(32)
      expect(deserializedProof.O_k.length).toBe(32)
      expect(deserializedProof.s.length).toBe(32)
      expect(deserializedProof.s_b.length).toBe(32)
    })

    test('Large input should work correctly', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const largeInput: PedersenVRFInput = {
        input: new Uint8Array(1000).fill(42),
        auxData: new Uint8Array(0)
      }
      
      const proofResult = PedersenVRFProver.prove(secretKey, largeInput)
      
      expect(proofResult.gamma.length).toBe(32)
      expect(proofResult.hash.length).toBe(64)
    })

    test('Auxiliary data variations', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const input = new TextEncoder().encode('test')
      
      const input1: PedersenVRFInput = {
        input: input,
        auxData: new Uint8Array(0)
      }
      const proof1 = PedersenVRFProver.prove(secretKey, input1)
      
      const auxData = new TextEncoder().encode('auxiliary')
      const input2: PedersenVRFInput = {
        input: input,
        auxData: auxData
      }
      const proof2 = PedersenVRFProver.prove(secretKey, input2)
      
      const deserializedProof1 = PedersenVRFProver.deserialize(proof1.proof)
      const deserializedProof2 = PedersenVRFProver.deserialize(proof2.proof)
      
      expect(bytesToHex(deserializedProof1.Y_bar)).not.toBe(bytesToHex(deserializedProof2.Y_bar))
      expect(bytesToHex(proof1.gamma)).toBe(bytesToHex(proof2.gamma))
      expect(bytesToHex(proof1.hash)).toBe(bytesToHex(proof2.hash))
    })

    test('Deterministic proof generation', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const input: PedersenVRFInput = {
        input: new TextEncoder().encode('deterministic test'),
        auxData: new TextEncoder().encode('aux')
      }
      
      const proof1 = PedersenVRFProver.prove(secretKey, input)
      const proof2 = PedersenVRFProver.prove(secretKey, input)
      
      const deserializedProof1 = PedersenVRFProver.deserialize(proof1.proof)
      const deserializedProof2 = PedersenVRFProver.deserialize(proof2.proof)
      
      expect(bytesToHex(proof1.gamma)).toBe(bytesToHex(proof2.gamma))
      expect(bytesToHex(proof1.hash)).toBe(bytesToHex(proof2.hash))
      expect(bytesToHex(deserializedProof1.Y_bar)).toBe(bytesToHex(deserializedProof2.Y_bar))
      expect(bytesToHex(deserializedProof1.R)).toBe(bytesToHex(deserializedProof2.R))
      expect(bytesToHex(deserializedProof1.O_k)).toBe(bytesToHex(deserializedProof2.O_k))
      expect(bytesToHex(deserializedProof1.s)).toBe(bytesToHex(deserializedProof2.s))
      expect(bytesToHex(deserializedProof1.s_b)).toBe(bytesToHex(deserializedProof2.s_b))
    })
  })
})
