import { describe, expect, it } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  getRustProveThinVrf,
  getRustThinVrfOutput,
  getRustVerifyThinVrf,
  getRustVerifyThinVrfParts,
} from '../prover/rust-thin-vrf-wrapper'

type ThinVector = {
  sk: string
  pk: string
  alpha: string
  ad: string
  gamma: string
  beta: string
  proof_r: string
  proof_s: string
}

function loadVectors(): ThinVector[] {
  const path = join(
    process.cwd(),
    'submodules',
    'bandersnatch-vrf-spec',
    'assets',
    'vectors',
    'bandersnatch_sha-512_ell2_thin.json',
  )
  return JSON.parse(readFileSync(path, 'utf8'))
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

const native = getRustProveThinVrf()
const verifier = getRustVerifyThinVrf()
const output = getRustThinVrfOutput()

describe.skipIf(!native || !verifier || !output)(
  'thin VRF against spec vectors',
  () => {
    it('reproduces gamma, r and s for every vector', () => {
      for (const vector of loadVectors()) {
        const proof = native!(hexToBytes(vector.sk), hexToBytes(vector.alpha), hexToBytes(vector.ad))
        expect(proof.length).toBe(96)
        expect(bytesToHex(proof.subarray(0, 32))).toBe(vector.gamma)
        expect(bytesToHex(proof.subarray(32, 64))).toBe(vector.proof_r)
        expect(bytesToHex(proof.subarray(64))).toBe(vector.proof_s)
      }
    })

    it('derives beta from the output point for every vector', () => {
      for (const vector of loadVectors()) {
        const beta = output!(hexToBytes(vector.gamma))
        expect(bytesToHex(beta)).toBe(vector.beta)
      }
    })

    it('verifies every vector proof', () => {
      for (const vector of loadVectors()) {
        const proof = new Uint8Array(96)
        proof.set(hexToBytes(vector.gamma), 0)
        proof.set(hexToBytes(vector.proof_r), 32)
        proof.set(hexToBytes(vector.proof_s), 64)
        expect(
          verifier!(hexToBytes(vector.pk), hexToBytes(vector.alpha), proof, hexToBytes(vector.ad)),
        ).toBe(true)
      }
    })

    it('rejects a corrupted proof', () => {
      const vector = loadVectors()[0]!
      const proof = new Uint8Array(96)
      proof.set(hexToBytes(vector.gamma), 0)
      proof.set(hexToBytes(vector.proof_r), 32)
      proof.set(hexToBytes(vector.proof_s), 64)
      proof[95] = proof[95]! ^ 0xff
      expect(
        verifier!(hexToBytes(vector.pk), hexToBytes(vector.alpha), proof, hexToBytes(vector.ad)),
      ).toBe(false)
    })
  },
)


describe.skipIf(!verifier || !getRustVerifyThinVrfParts())(
  'thin VRF envelope and parts agree',
  () => {
    const parts = getRustVerifyThinVrfParts()!

    it('the 96-byte envelope verifies wherever the parts form does', () => {
      for (const vector of loadVectors()) {
        const proof = new Uint8Array(96)
        proof.set(hexToBytes(vector.gamma), 0)
        proof.set(hexToBytes(vector.proof_r), 32)
        proof.set(hexToBytes(vector.proof_s), 64)
        const viaEnvelope = verifier!(
          hexToBytes(vector.pk),
          hexToBytes(vector.alpha),
          proof,
          hexToBytes(vector.ad),
        )
        const viaParts = parts(
          hexToBytes(vector.pk),
          hexToBytes(vector.alpha),
          hexToBytes(vector.gamma),
          hexToBytes(vector.proof_r),
          hexToBytes(vector.proof_s),
          hexToBytes(vector.ad),
        )
        expect(viaParts).toBe(viaEnvelope)
      }
    })

    it('rejects when only the output point is swapped', () => {
      const vector = loadVectors()[0]!
      const other = loadVectors()[1]!
      expect(
        parts(
          hexToBytes(vector.pk),
          hexToBytes(vector.alpha),
          hexToBytes(other.gamma),
          hexToBytes(vector.proof_r),
          hexToBytes(vector.proof_s),
          hexToBytes(vector.ad),
        ),
      ).toBe(false)
    })
  },
)
