import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { IETFVRFProver } from '../prover/ietf.ts'
import { IETFVRFVerifierWasm } from '../verifier/ietf-wasm.ts'
import { bytesToHex } from 'viem'
import { getCommitmentFromGamma } from '../utils/gamma.ts'
import {
  bytesToBigIntLittleEndian,
  curvePointToNoble,
  elligator2HashToCurve,
} from '../crypto/elligator2.ts'
import { BandersnatchCurve, mod } from '@pbnjam/bandersnatch'
import { generateChallengeRfc9381 } from '../crypto/rfc9381.ts'

const testVectorsPath = join(
  __dirname,
  './vectors/bandersnatch_sha-512_ell2_ietf.json',
)
const IETF_TEST_VECTORS = JSON.parse(
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
  proof_c: string
  proof_s: string
}>

const verifier = new IETFVRFVerifierWasm()

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

describe('IETF VRF End-to-End Tests', () => {
  describe('Proof Generation and Verification', () => {
    IETF_TEST_VECTORS.forEach((vector, index) => {
      test(`Vector ${index + 1}: ${vector.comment} - Complete workflow`, async () => {
        const secretKey = hexToBytes(vector.sk)
        const publicKey = hexToBytes(vector.pk)
        const input = hexToBytes(vector.alpha)
        const auxData = hexToBytes(vector.ad)
        
        console.log(`\n=== Testing ${vector.comment} ===`)
        console.log(`Input: "${vector.alpha}"`)
        console.log(`Aux Data: "${vector.ad}"`)
        
        const proofResult = IETFVRFProver.prove(secretKey, input, auxData)
        const hash = getCommitmentFromGamma(proofResult.gamma)
        console.log('Generated proof:')
        console.log(`  Gamma: ${bytesToHex(proofResult.gamma)}`)
        console.log(`  Proof: ${bytesToHex(proofResult.proof)}`)
        
        const isValid = verifier.verify(
          publicKey,
          input,
          proofResult.proof,
          auxData
        )
        
        console.log(`Verification result: ${isValid ? '✅ VALID' : '❌ INVALID'}`)
        
        expect(isValid).toBe(true)
        expect(proofResult.gamma).toBeInstanceOf(Uint8Array)
        expect(proofResult.proof).toBeInstanceOf(Uint8Array)
        
        expect(proofResult.proof.length).toBe(96)

        expect(proofResult.gamma.length).toBe(32)
        
        expect(hash.length).toBe(64)
      })
    })
  })

  describe('Value Matching Against Test Vectors', () => {
    const reliableVectors = IETF_TEST_VECTORS.slice(0, 2)
    
    reliableVectors.forEach((vector, index) => {
      test(`Vector ${index + 1}: Exact value matching`, async () => {
        const secretKey = hexToBytes(vector.sk)
        const input = hexToBytes(vector.alpha)
        const auxData = hexToBytes(vector.ad)
        
        const proofResult = IETFVRFProver.prove(secretKey, input, auxData)
        const hash = getCommitmentFromGamma(proofResult.gamma)
        
        const actualGamma = bytesToHex(proofResult.gamma).slice(2)
        const actualBeta = bytesToHex(hash).slice(2)
        
        console.log(`\n=== Value Matching for ${vector.comment} ===`)
        console.log(`Expected gamma: ${vector.gamma}`)
        console.log(`Actual gamma:   ${actualGamma}`)
        console.log(`Gamma matches:  ${actualGamma === vector.gamma}`)
        
        console.log(`Expected beta:  ${vector.beta}`)
        console.log(`Actual beta:    ${actualBeta}`)
        console.log(`Beta matches:   ${actualBeta === vector.beta}`)

        expect(proofResult.gamma.length).toBe(32)
        expect(hash.length).toBe(64)
        
        const publicKey = hexToBytes(vector.pk)
        const isValid = verifier.verify(
          publicKey,
          input,
          proofResult.proof,
          auxData
        )
        expect(isValid).toBe(true)
      })
    })
  })

  describe('Cross-Verification Tests', () => {
    test('Prover-generated proof should verify successfully', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const publicKey = hexToBytes('a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b')
      const input = new TextEncoder().encode('test message')
      const auxData = new TextEncoder().encode('aux data')
      
      const proofResult = IETFVRFProver.prove(secretKey, input, auxData)
      
      const isValid = verifier.verify(
        publicKey,
        input,
        proofResult.proof,
        auxData
      )
      
      expect(isValid).toBe(true)
    })

    test('Wrong public key should fail verification', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const wrongPublicKey = hexToBytes('5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3')
      const input = new TextEncoder().encode('test')
      
      const proofResult = IETFVRFProver.prove(secretKey, input)
      
      const isValid = verifier.verify(
        wrongPublicKey,
        input,
        proofResult.proof
      )
      
      expect(isValid).toBe(false)
    })

    test('Wrong input should fail verification', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const publicKey = hexToBytes('a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b')
      const input = new TextEncoder().encode('test')
      const wrongInput = new TextEncoder().encode('wrong')
      
      const proofResult = IETFVRFProver.prove(secretKey, input)
      
      const isValid = verifier.verify(
        publicKey,
        wrongInput,
        proofResult.proof
      )
      
      expect(isValid).toBe(false)
    })
  })

  describe('Challenge Matching', () => {
    test('Prover and verifier should compute the same challenge', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const publicKey = hexToBytes('a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b')
      const input = new TextEncoder().encode('test message')
      const auxData = new TextEncoder().encode('aux data')

      const proofResult = IETFVRFProver.prove(secretKey, input, auxData)

      const cFromProofBytes = proofResult.proof.slice(32, 64)
      const cFromProof = bytesToBigIntLittleEndian(cFromProofBytes)

      const isValid = verifier.verify(
        publicKey,
        input,
        proofResult.proof,
        auxData
      )

      expect(isValid).toBe(true)

      const gammaFromProof = proofResult.proof.slice(0, 32)
      const sFromProof = proofResult.proof.slice(64, 96)
      const s = bytesToBigIntLittleEndian(sFromProof)

      const salt = new Uint8Array(0)
      const h2cData = new Uint8Array(salt.length + input.length)
      h2cData.set(salt, 0)
      h2cData.set(input, salt.length)
      const alphaPoint = elligator2HashToCurve(h2cData)
      const alphaBytes = BandersnatchCurve.pointToBytes(curvePointToNoble(alphaPoint))

      const alphaPoint2 = BandersnatchCurve.bytesToPoint(alphaBytes)
      const gammaPoint = BandersnatchCurve.bytesToPoint(gammaFromProof)
      const publicKeyPoint = BandersnatchCurve.bytesToPoint(publicKey)

      const c = mod(cFromProof, BandersnatchCurve.CURVE_ORDER)
      const gToS = BandersnatchCurve.scalarMultiply(
        BandersnatchCurve.GENERATOR,
        s,
      )
      const yToC = BandersnatchCurve.scalarMultiply(publicKeyPoint, c)
      const u = BandersnatchCurve.add(
        gToS,
        BandersnatchCurve.negate(yToC),
      )

      const hToS = BandersnatchCurve.scalarMultiply(alphaPoint2, s)
      const gammaToC = BandersnatchCurve.scalarMultiply(gammaPoint, c)
      const v = BandersnatchCurve.add(
        hToS,
        BandersnatchCurve.negate(gammaToC),
      )

      const challengePoints = [
        BandersnatchCurve.pointToBytes(publicKeyPoint),
        BandersnatchCurve.pointToBytes(alphaPoint2),
        BandersnatchCurve.pointToBytes(gammaPoint),
        BandersnatchCurve.pointToBytes(u),
        BandersnatchCurve.pointToBytes(v),
      ]
      const expectedC = generateChallengeRfc9381(challengePoints, auxData)

      expect(c.toString(16)).toBe(expectedC.toString(16))
      expect(c).toBe(expectedC)
    })
  })

  describe('Edge Cases', () => {
    test('Empty input should work correctly', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const publicKey = hexToBytes('a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b')
      const emptyInput = new Uint8Array(0)
      
      const proofResult = IETFVRFProver.prove(secretKey, emptyInput)
      const hash = getCommitmentFromGamma(proofResult.gamma)
      const isValid = verifier.verify(
        publicKey,
        emptyInput,
        proofResult.proof
      )
      
      expect(isValid).toBe(true)
      expect(proofResult.gamma.length).toBe(32)
      expect(hash.length).toBe(64)
    })

    test('Large input should work correctly', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const publicKey = hexToBytes('a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b')
      const largeInput = new Uint8Array(1000).fill(42)
      
      const proofResult = IETFVRFProver.prove(secretKey, largeInput)
      const isValid = verifier.verify(
        publicKey,
        largeInput,
        proofResult.proof
      )
      
      expect(isValid).toBe(true)
    })

    test('Auxiliary data variations', () => {
      const secretKey = hexToBytes('3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18')
      const publicKey = hexToBytes('a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b')
      const input = new TextEncoder().encode('test')
      
      const proof1 = IETFVRFProver.prove(secretKey, input)
      const valid1 = verifier.verify(publicKey, input, proof1.proof)
      expect(valid1).toBe(true)
      
      const auxData = new TextEncoder().encode('auxiliary')
      const proof2 = IETFVRFProver.prove(secretKey, input, auxData)
      const valid2 = verifier.verify(publicKey, input, proof2.proof, auxData)
      expect(valid2).toBe(true)
      
      expect(bytesToHex(proof1.proof)).not.toBe(bytesToHex(proof2.proof))
    })
  })

  describe('Proof Serialization and Deserialization', () => {
    test('Should handle round-trip serialization for generated proof', () => {
      const vector = IETF_TEST_VECTORS[0]
      const secretKey = hexToBytes(vector.sk)
      const input = hexToBytes(vector.alpha)
      const auxData = hexToBytes(vector.ad)
      
      const proofResult = IETFVRFProver.prove(secretKey, input, auxData)
      
      const gammaFromProof = proofResult.proof.slice(0, 32)
      const cFromProof = proofResult.proof.slice(32, 64)
      const sFromProof = proofResult.proof.slice(64, 96)
      
      const reserializedProof = new Uint8Array([
        ...gammaFromProof,
        ...cFromProof,
        ...sFromProof,
      ])
      
      expect(Array.from(reserializedProof)).toEqual(
        Array.from(proofResult.proof),
      )
      expect(reserializedProof.length).toBe(96)
      
      const publicKey = hexToBytes(vector.pk)
      const isValid = verifier.verify(
        publicKey,
        input,
        reserializedProof,
        auxData,
      )
      
      expect(isValid).toBe(true)
    })

    test('Should correctly deserialize and re-serialize proof components', () => {
      const vector = IETF_TEST_VECTORS[0]
      const secretKey = hexToBytes(vector.sk)
      const input = hexToBytes(vector.alpha)
      const auxData = hexToBytes(vector.ad)
      
      const proofResult = IETFVRFProver.prove(secretKey, input, auxData)
      
      const gammaFromProof = proofResult.proof.slice(0, 32)
      const cFromProof = proofResult.proof.slice(32, 64)
      const sFromProof = proofResult.proof.slice(64, 96)
      
      expect(gammaFromProof.length).toBe(32)
      expect(cFromProof.length).toBe(32)
      expect(sFromProof.length).toBe(32)
      
      const c = bytesToBigIntLittleEndian(cFromProof)
      const s = bytesToBigIntLittleEndian(sFromProof)
      
      expect(c).toBeGreaterThan(0n)
      expect(s).toBeGreaterThan(0n)
      
      const reserializedProof = new Uint8Array([
        ...gammaFromProof,
        ...cFromProof,
        ...sFromProof,
      ])
      
      expect(reserializedProof.length).toBe(96)
      expect(Array.from(reserializedProof)).toEqual(
        Array.from(proofResult.proof),
      )

      const publicKey = hexToBytes(vector.pk)
      const isValid = verifier.verify(
        publicKey,
        input,
        reserializedProof,
        auxData,
      )
      
      expect(isValid).toBe(true)
      
      expect(bytesToHex(gammaFromProof)).toBe(bytesToHex(proofResult.gamma))
    })

    test('Should correctly round-trip pointToBytes and bytesToPoint', () => {
      const vector = IETF_TEST_VECTORS[0]
      
      const gammaBytes = hexToBytes(vector.gamma)
      expect(gammaBytes.length).toBe(32)
      
      const gammaPoint = BandersnatchCurve.bytesToPoint(gammaBytes)
      
      const gammaBytesRoundTrip = BandersnatchCurve.pointToBytes(gammaPoint)
      
      expect(gammaBytesRoundTrip).toEqual(gammaBytes)
      expect(bytesToHex(gammaBytesRoundTrip)).toBe(bytesToHex(gammaBytes))
      
      const publicKeyBytes = hexToBytes(vector.pk)
      expect(publicKeyBytes.length).toBe(32)
      
      const publicKeyPoint = BandersnatchCurve.bytesToPoint(publicKeyBytes)
      const publicKeyBytesRoundTrip = BandersnatchCurve.pointToBytes(publicKeyPoint)
      
      expect(publicKeyBytesRoundTrip).toEqual(publicKeyBytes)
      expect(bytesToHex(publicKeyBytesRoundTrip)).toBe(bytesToHex(publicKeyBytes))
      
      const hBytes = hexToBytes(vector.h)
      expect(hBytes.length).toBe(32)
      
      const hPoint = BandersnatchCurve.bytesToPoint(hBytes)
      const hBytesRoundTrip = BandersnatchCurve.pointToBytes(hPoint)
      
      expect(hBytesRoundTrip).toEqual(hBytes)
      expect(bytesToHex(hBytesRoundTrip)).toBe(bytesToHex(hBytes))
      
      const generatorPoint = BandersnatchCurve.GENERATOR
      const generatorBytes = BandersnatchCurve.pointToBytes(generatorPoint)
      expect(generatorBytes.length).toBe(32)
      
      const generatorPointRoundTrip = BandersnatchCurve.bytesToPoint(generatorBytes)
      const generatorBytesRoundTrip = BandersnatchCurve.pointToBytes(generatorPointRoundTrip)
      
      expect(generatorBytesRoundTrip).toEqual(generatorBytes)
      
      expect(generatorPointRoundTrip.x).toBe(generatorPoint.x)
      expect(generatorPointRoundTrip.y).toBe(generatorPoint.y)
      
      expect(BandersnatchCurve.isOnCurve(gammaPoint)).toBe(true)
      expect(BandersnatchCurve.isOnCurve(publicKeyPoint)).toBe(true)
      expect(BandersnatchCurve.isOnCurve(hPoint)).toBe(true)
      expect(BandersnatchCurve.isOnCurve(generatorPointRoundTrip)).toBe(true)
      
      for (const testVector of IETF_TEST_VECTORS) {
        const tvGammaBytes = hexToBytes(testVector.gamma)
        const tvGammaPoint = BandersnatchCurve.bytesToPoint(tvGammaBytes)
        const tvGammaBytesRoundTrip = BandersnatchCurve.pointToBytes(tvGammaPoint)
        expect(tvGammaBytesRoundTrip).toEqual(tvGammaBytes)
        expect(BandersnatchCurve.isOnCurve(tvGammaPoint)).toBe(true)
        
        const tvPkBytes = hexToBytes(testVector.pk)
        const tvPkPoint = BandersnatchCurve.bytesToPoint(tvPkBytes)
        const tvPkBytesRoundTrip = BandersnatchCurve.pointToBytes(tvPkPoint)
        expect(tvPkBytesRoundTrip).toEqual(tvPkBytes)
        expect(BandersnatchCurve.isOnCurve(tvPkPoint)).toBe(true)
        
        const tvHBytes = hexToBytes(testVector.h)
        const tvHPoint = BandersnatchCurve.bytesToPoint(tvHBytes)
        const tvHBytesRoundTrip = BandersnatchCurve.pointToBytes(tvHPoint)
        expect(tvHBytesRoundTrip).toEqual(tvHBytes)
        expect(BandersnatchCurve.isOnCurve(tvHPoint)).toBe(true)
      }
    })
  })
})
