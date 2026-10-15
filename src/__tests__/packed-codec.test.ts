import { describe, expect, it } from 'bun:test'
import { readFileSync } from 'node:fs'
import {
  decodeBvrfBatchVerifyItems,
  decodeBvrfIetfVerifyRequest,
  decodeBvrfLastError,
  decodeBvrfRingPrepareOutput,
  decodeBvrfRingPrepareRequest,
  decodeBvrfSrsOpenOutput,
  decodeBvrfSrsOpenRequest,
  decodeBvrfValidity,
  encodeBvrfBatchVerifyItems,
  encodeBvrfIetfVerifyRequest,
  encodeBvrfLastError,
  encodeBvrfRingPrepareOutput,
  encodeBvrfRingPrepareRequest,
  encodeBvrfSrsOpenOutput,
  encodeBvrfSrsOpenRequest,
  encodeBvrfValidity,
} from '../packed.ts'

const FIXTURES = new URL('../../test-data/packed/', import.meta.url)

function fixture(name: string): Buffer {
  return readFileSync(new URL(name, FIXTURES))
}

function fill(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value)
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(length)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

const RING_KEYS = concatBytes(fill(32, 0x11), fill(32, 0x22))
const COMMITMENT = fill(144, 0xab)
const KEY_COMMITMENT = fill(32, 0xcc)

describe('packed bandersnatch codec', () => {
  it('matches the rust SRS-open fixture', () => {
    const expected = fixture('bvrf-srs-open.bin')
    expect(Buffer.from(encodeBvrfSrsOpenRequest('srs.bin'))).toEqual(expected)
    expect(decodeBvrfSrsOpenRequest(expected)).toBe('srs.bin')
  })

  it('matches the rust ring-prepare request fixture', () => {
    const expected = fixture('bvrf-ring-keys.bin')
    expect(Buffer.from(encodeBvrfRingPrepareRequest(RING_KEYS))).toEqual(expected)
    expect(decodeBvrfRingPrepareRequest(expected)).toEqual(RING_KEYS)
  })

  it('matches the rust ring-prepare output fixture', () => {
    const expected = fixture('bvrf-ring-prepare-output.bin')
    expect(
      Buffer.from(encodeBvrfRingPrepareOutput(5, COMMITMENT)),
    ).toEqual(expected)
    expect(decodeBvrfRingPrepareOutput(expected)).toEqual({
      handle: 5,
      commitment: COMMITMENT,
    })
  })

  it('matches the rust batch-verify items fixture', () => {
    const items = [{ proof: new Uint8Array([0xde, 0xad]), keyCommitment: KEY_COMMITMENT }]
    const expected = fixture('bvrf-batch-verify-items.bin')
    expect(Buffer.from(encodeBvrfBatchVerifyItems(items))).toEqual(expected)
    expect(decodeBvrfBatchVerifyItems(expected)).toEqual(items)
  })

  it('matches the rust IETF verify request fixture', () => {
    const request = {
      publicKey: new Uint8Array([1]),
      input: new Uint8Array([2, 3]),
      proof: new Uint8Array([4]),
      aux: new Uint8Array(),
    }
    const expected = fixture('bvrf-ietf-verify.bin')
    expect(Buffer.from(encodeBvrfIetfVerifyRequest(request))).toEqual(expected)
    expect(decodeBvrfIetfVerifyRequest(expected)).toEqual(request)
  })

  it('matches the rust validity-byte fixture', () => {
    const expected = fixture('bvrf-validity.bin')
    expect(Buffer.from(encodeBvrfValidity(true))).toEqual(expected)
    expect(decodeBvrfValidity(expected)).toBe(true)
  })

  it('matches the rust last-error fixture', () => {
    const expected = fixture('bvrf-last-error.bin')
    expect(Buffer.from(encodeBvrfLastError('boom'))).toEqual(expected)
    expect(decodeBvrfLastError(expected)).toBe('boom')
  })

  it('rejects a version mismatch', () => {
    expect(() => decodeBvrfSrsOpenRequest(new Uint8Array([2]))).toThrow(
      /format version/,
    )
  })

  it('matches the rust SRS-open output fixture', () => {
    const expected = fixture('bvrf-srs-open-output.bin')
    expect(Buffer.from(encodeBvrfSrsOpenOutput(7))).toEqual(expected)
    expect(decodeBvrfSrsOpenOutput(expected)).toBe(7)
  })

  it('rejects short and long ring-prepare commitments', () => {
    expect(() => encodeBvrfRingPrepareOutput(5, fill(143, 0xab))).toThrow(
      /malformed/,
    )
    expect(() => encodeBvrfRingPrepareOutput(5, fill(145, 0xab))).toThrow(
      /malformed/,
    )
  })

  it('rejects short and long batch-verify key commitments', () => {
    const proof = new Uint8Array([0xde, 0xad])
    expect(() =>
      encodeBvrfBatchVerifyItems([{ proof, keyCommitment: fill(31, 0xcc) }]),
    ).toThrow(/malformed/)
    expect(() =>
      encodeBvrfBatchVerifyItems([{ proof, keyCommitment: fill(33, 0xcc) }]),
    ).toThrow(/malformed/)
  })

  it('rejects invalid utf-8 as a malformed packed payload', () => {
    expect(() =>
      decodeBvrfLastError(new Uint8Array([0x01, 0x01, 0x00, 0x00, 0x00, 0xff])),
    ).toThrow(/malformed packed payload: invalid utf-8/)
  })
})
