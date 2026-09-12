/**
 * Seam tests for optional Ring/IETF backends and lazy WASM loading.
 * Production crypto stays in the W3F classes; these tests assert wiring.
 */

import { describe, expect, mock, spyOn, test } from 'bun:test'
import * as fs from 'node:fs'
import { join } from 'node:path'
import { hexToBytes } from 'viem'
import { createNapiRingBackend, type IetfBackend, type RingBackend } from '../backends.ts'
import { PedersenVRFProver } from '../prover/pedersen.ts'
import type { RingVRFInput } from '../prover/ring-kzg.ts'

const SECRET_KEY = hexToBytes(
  '0x3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18',
)
const IETF_PUBLIC_KEY = hexToBytes(
  '0xa1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b',
)

function stubRingBackend(
  overrides?: Partial<RingBackend>,
): RingBackend & {
  prepare: ReturnType<typeof mock>
  batchVerify: ReturnType<typeof mock>
} {
  const prepare = mock(() => ({
    commitment: new Uint8Array(144),
    ring: { id: 1 as const },
  }))
  const batchVerify = mock(() => true)
  return {
    prepare: overrides?.prepare ?? prepare,
    batchVerify: overrides?.batchVerify ?? batchVerify,
  } as RingBackend & {
    prepare: ReturnType<typeof mock>
    batchVerify: ReturnType<typeof mock>
  }
}

function makePedersenBundle() {
  const inputBytes = new Uint8Array([1, 2, 3, 4])
  const auxData = new Uint8Array(0)
  const pedersen = PedersenVRFProver.prove(SECRET_KEY, {
    input: inputBytes,
    auxData,
  })
  const ringKeys = [new Uint8Array(32)]
  const ringInput: RingVRFInput = {
    input: inputBytes,
    auxData,
    ringKeys,
    proverIndex: 0,
  }
  return {
    ringInput,
    ringKeys,
    result: {
      gamma: pedersen.gamma,
      proof: {
        pedersenProof: pedersen.proof,
        ringCommitment: new Uint8Array(144),
        ringProof: new Uint8Array(100),
      },
    },
  }
}

describe('WASM is not imported at module evaluation', () => {
  test('missing backend plus missing addon does not import WASM at module evaluation', async () => {
    const readSpy = spyOn(fs, 'readFileSync')
    try {
      const ringMod = await import('../verifier/ring-w3f.ts')
      const ietfMod = await import('../verifier/ietf-w3f.ts')
      expect(ringMod.RingVRFVerifierW3F).toBeDefined()
      expect(ietfMod.IETFVRFVerifierW3F).toBeDefined()
      const wasmReads = readSpy.mock.calls.filter((call) =>
        String(call[0]).includes('ark_vrf_wasm'),
      )
      expect(wasmReads).toEqual([])
    } finally {
      readSpy.mockRestore()
    }
  })
})

describe('RingVRFVerifierW3F backend seam', () => {
  test('injected backend is used for verify via one-item batchVerify', async () => {
    const { RingVRFVerifierW3F } = await import('../verifier/ring-w3f.ts')
    const backend = stubRingBackend()
    const verifier = new RingVRFVerifierW3F({ backend })
    const bundle = makePedersenBundle()

    const ok = verifier.verify(
      bundle.ringKeys,
      bundle.ringInput,
      bundle.result,
      bundle.ringInput.auxData,
    )

    expect(ok).toBe(true)
    expect(backend.prepare).toHaveBeenCalled()
    expect(backend.batchVerify).toHaveBeenCalled()
    const batchArgs = backend.batchVerify.mock.calls[0]
    expect(batchArgs[0]).toEqual({ id: 1 })
    expect(batchArgs[1]).toBe(1)
    expect(batchArgs[2]).toHaveLength(1)
  })

  test('backend constructor does not read the SRS file', async () => {
    const { RingVRFVerifierW3F } = await import('../verifier/ring-w3f.ts')
    const readSpy = spyOn(fs, 'readFileSync')
    try {
      const backend = stubRingBackend()
      new RingVRFVerifierW3F({ backend })
      expect(readSpy).not.toHaveBeenCalled()
    } finally {
      readSpy.mockRestore()
    }
  })

  test('784-byte ring proof is rejected before the backend runs', async () => {
    const { RingVRFVerifierW3F } = await import('../verifier/ring-w3f.ts')
    const backend = stubRingBackend()
    const verifier = new RingVRFVerifierW3F({ backend })
    const bundle = makePedersenBundle()
    bundle.result.proof.ringProof = new Uint8Array(784)

    expect(() =>
      verifier.verify(
        bundle.ringKeys,
        bundle.ringInput,
        bundle.result,
        bundle.ringInput.auxData,
      ),
    ).toThrow(
      'Invalid ring proof: received full 784-byte structure instead of ring proof portion',
    )
    expect(backend.batchVerify).not.toHaveBeenCalled()
  })
})

describe('RingVRFProverW3F backend seam', () => {
  test('prove throws on the backend path', async () => {
    const { RingVRFProverW3F } = await import('../prover/ring-kzg-w3f.ts')
    const backend = stubRingBackend()
    const prover = new RingVRFProverW3F({ backend })
    const bundle = makePedersenBundle()

    expect(() => prover.prove(SECRET_KEY, bundle.ringInput)).toThrow(
      'Ring VRF proving is unavailable on this runtime',
    )
  })

  test('backend constructor does not read the SRS file', async () => {
    const { RingVRFProverW3F } = await import('../prover/ring-kzg-w3f.ts')
    const readSpy = spyOn(fs, 'readFileSync')
    try {
      new RingVRFProverW3F({ backend: stubRingBackend() })
      expect(readSpy).not.toHaveBeenCalled()
    } finally {
      readSpy.mockRestore()
    }
  })

  test('computeRingCommitment uses backend.prepare and does not read SRS', async () => {
    const { RingVRFProverW3F } = await import('../prover/ring-kzg-w3f.ts')
    const commitment = new Uint8Array(144)
    commitment[0] = 0xab
    const prepare = mock(() => ({
      commitment,
      ring: { id: 9 as const },
    }))
    const backend = stubRingBackend({ prepare })
    const prover = new RingVRFProverW3F({ backend })
    const ringKeys = [new Uint8Array(32), new Uint8Array(32)]
    const readSpy = spyOn(fs, 'readFileSync')
    try {
      const result = prover.computeRingCommitment(ringKeys)
      expect(result).toBe(commitment)
      expect(prepare).toHaveBeenCalledTimes(1)
      expect(prepare.mock.calls[0][0]).toBeInstanceOf(Uint8Array)
      expect(prepare.mock.calls[0][0].length).toBe(64)
      expect(readSpy).not.toHaveBeenCalled()
    } finally {
      readSpy.mockRestore()
    }
  })
})

function unwrapPrepare(
  value: ReturnType<RingBackend['prepare']>,
): { commitment: Uint8Array; ring: { readonly id: number } } {
  if (value instanceof Promise) {
    throw new Error('expected synchronous napi prepare')
  }
  return value
}

describe('default napi ring backend cache', () => {
  const srsPath = join(
    __dirname,
    'test-data/srs/zcash-srs-2-11-uncompressed.bin',
  )

  test('prepare reuses ring id for the same keys and evicts at 3', () => {
    if (!fs.existsSync(srsPath)) return
    const backend = createNapiRingBackend(fs.readFileSync(srsPath))
    if (!backend) return

    const validKeys = [
      '0x7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313',
      '0xd3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471',
      '0x561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5',
      '0xa1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b',
      '0x4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c',
      '0x86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437',
      '0xad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b',
      '0x3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9',
    ].map((hex) => hexToBytes(hex as `0x${string}`))

    const concatPair = (a: number, b: number) => {
      const out = new Uint8Array(64)
      out.set(validKeys[a]!, 0)
      out.set(validKeys[b]!, 32)
      return out
    }
    const keysA = concatPair(0, 1)
    const keysB = concatPair(2, 3)
    const keysC = concatPair(4, 5)
    const keysD = concatPair(6, 7)

    const firstA = unwrapPrepare(backend.prepare(keysA))
    const secondA = unwrapPrepare(backend.prepare(keysA))
    expect(secondA.ring.id).toBe(firstA.ring.id)

    unwrapPrepare(backend.prepare(keysB))
    unwrapPrepare(backend.prepare(keysC))
    unwrapPrepare(backend.prepare(keysD))
    const afterEvictA = unwrapPrepare(backend.prepare(keysA))
    expect(afterEvictA.ring.id).not.toBe(firstA.ring.id)
  })
})

describe('IETFVRFVerifierW3F backend seam', () => {
  test('injected backend is used for verify', async () => {
    const { IETFVRFVerifierW3F } = await import('../verifier/ietf-w3f.ts')
    const verify = mock(() => true)
    const backend: IetfBackend = { verify }
    const verifier = new IETFVRFVerifierW3F({ backend })
    const proof = new Uint8Array(96)
    const input = new Uint8Array([9, 8, 7])
    const aux = new Uint8Array([1])

    expect(verifier.verify(IETF_PUBLIC_KEY, input, proof, aux)).toBe(true)
    expect(verify).toHaveBeenCalledTimes(1)
    expect(verify.mock.calls[0][0]).toEqual(IETF_PUBLIC_KEY)
    expect(verify.mock.calls[0][1]).toEqual(input)
    expect(verify.mock.calls[0][2]).toEqual(proof)
    expect(verify.mock.calls[0][3]).toEqual(aux)
  })

  test('96-byte proof guard rejects short proofs before the backend runs', async () => {
    const { IETFVRFVerifierW3F } = await import('../verifier/ietf-w3f.ts')
    const verify = mock(() => true)
    const verifier = new IETFVRFVerifierW3F({ backend: { verify } })

    expect(
      verifier.verify(IETF_PUBLIC_KEY, new Uint8Array(0), new Uint8Array(95)),
    ).toBe(false)
    expect(verify).not.toHaveBeenCalled()
  })
})
