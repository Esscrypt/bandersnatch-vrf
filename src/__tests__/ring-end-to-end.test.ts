/**
 * Ring VRF End-to-End Tests (Pure TypeScript)
 *
 * Tests the pure TypeScript ring VRF prover (ring-kzg.ts) and verifier (ring.ts)
 * against the standard test vectors.
 */

import { describe, expect, test, beforeAll } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import path from 'node:path'
import { bytesToHex, hexToBytes, type Hex } from 'viem'
import { RingVRFProver, type RingVRFInput } from '../prover/ring-kzg'
import { RingVRFVerifier } from '../verifier/ring'
import { PedersenVRFProver } from '../prover/pedersen'
import { getBanderoutFromGamma, getCommitmentFromGamma } from '../utils/gamma'

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

function parseRingKeys(ringPksHex: string): Uint8Array[] {
  const keySize = 32
  const normalizedHex = ringPksHex.startsWith('0x') ? ringPksHex : `0x${ringPksHex}`
  const ringPksBytes = hexToBytes(normalizedHex as Hex)
  const keys: Uint8Array[] = []
  for (let i = 0; i < ringPksBytes.length; i += keySize) {
    keys.push(ringPksBytes.slice(i, i + keySize))
  }
  return keys
}

function prepareRingInput(vector: (typeof RING_TEST_VECTORS)[0]): {
  secretKey: Uint8Array
  publicKey: Uint8Array
  ringInput: RingVRFInput
} {
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
  const ringKeys = parseRingKeys(vector.ring_pks)
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
  const ringInput: RingVRFInput = {
    input: inputBytes,
    auxData,
    ringKeys,
    proverIndex,
  }
  return { secretKey, publicKey, ringInput }
}

function timeMs(fn: () => void): number {
  const start = performance.now()
  fn()
  return performance.now() - start
}

describe('Ring VRF End-to-End Tests (Pure TypeScript)', () => {
  let prover: RingVRFProver
  let verifier: RingVRFVerifier

  beforeAll(() => {
    const srsFilePath = path.join(
      __dirname,
      'test-data/srs/zcash-srs-2-11-uncompressed.bin',
    )
    const ringSize = 8
    prover = new RingVRFProver(srsFilePath, ringSize)
    verifier = new RingVRFVerifier(srsFilePath, ringSize)
  })

  describe('Exact Value Matching Against Test Vectors', () => {
    for (const [index, vector] of RING_TEST_VECTORS.slice(0, 2).entries()) {
      test(`Vector ${index + 1}: Pure TS prove/verify + benchmark`, () => {
        const { secretKey, ringInput } = prepareRingInput(vector)

        // ----- Prove -----
        let proof: ReturnType<RingVRFProver['prove']>
        const proveMs = timeMs(() => {
          proof = prover.prove(secretKey, ringInput)
        })

        // ----- Verify -----
        const verificationInput: RingVRFInput = {
          input: ringInput.input,
          auxData: ringInput.auxData,
          ringKeys: ringInput.ringKeys,
          proverIndex: ringInput.proverIndex,
        }
        let verifyOk = false
        const verifyMs = timeMs(() => {
          verifyOk = verifier.verify(
            ringInput.ringKeys,
            verificationInput,
            { gamma: proof!.gamma, proof: proof!.proof },
            ringInput.auxData,
          )
        })

        // ----- Benchmark output -----
        console.log(`\n--- Benchmark (${vector.comment}) ---`)
        console.log(`  Pure TS: prove ${proveMs.toFixed(2)} ms, verify ${verifyMs.toFixed(2)} ms`)

        expect(verifyOk).toBe(true)

        // ----- Exact value matching (Pedersen VRF outputs are deterministic) -----
        const actualGamma = bytesToHex(proof!.gamma).slice(2)
        const actualBeta = bytesToHex(getCommitmentFromGamma(proof!.gamma)).slice(2)
        const actualBanderout = bytesToHex(getBanderoutFromGamma(proof!.gamma)).slice(2)
        const computedBlinding = PedersenVRFProver.generateBlindingFactor(
          secretKey,
          PedersenVRFProver.hashToCurve(ringInput.input),
          ringInput.auxData,
        )
        const actualBlinding = bytesToHex(computedBlinding).slice(2)

        expect(actualGamma).toBe(vector.gamma)
        expect(actualBeta).toBe(vector.beta)
        expect(actualBanderout).toBe(vector.beta.slice(0, 64))
        expect(actualBlinding).toBe(vector.blinding)

        const pedersenProof = PedersenVRFProver.deserialize(proof!.proof.pedersenProof)
        expect(bytesToHex(pedersenProof.Y_bar).slice(2)).toBe(vector.proof_pk_com)
        expect(bytesToHex(pedersenProof.R).slice(2)).toBe(vector.proof_r)
        expect(bytesToHex(pedersenProof.O_k).slice(2)).toBe(vector.proof_ok)
        expect(bytesToHex(pedersenProof.s).slice(2)).toBe(vector.proof_s)
        expect(bytesToHex(pedersenProof.s_b).slice(2)).toBe(vector.proof_sb)

        const computedRingCommitment = prover.computeRingCommitment(ringInput.ringKeys)
        const expectedRingCommitment = hexToBytes(`0x${vector.ring_pks_com}`)
        expect(computedRingCommitment.length).toBe(144)
        expect(computedRingCommitment).toEqual(expectedRingCommitment)
      }, { timeout: 1000_000 })
    }
  })
})
