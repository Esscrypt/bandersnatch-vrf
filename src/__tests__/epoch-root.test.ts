import { describe, expect, test } from 'bun:test'
import type { ValidatorPublicKeys } from '@pbnjam/types'
import {
  extractRingKeysFromValidatorSet,
  verifyEpochRoot,
} from '../utils/epoch-root'
import { bytesToHex, hexToBytes } from 'viem'

const ZERO_KEY_HEX =
  '0x0000000000000000000000000000000000000000000000000000000000000000' as const
const KEY_A_HEX =
  '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as const
const KEY_B_HEX =
  '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as const
const KEY_C_HEX =
  '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' as const

function makeValidator(bandersnatch: `0x${string}`): ValidatorPublicKeys {
  return {
    bandersnatch,
    ed25519: ZERO_KEY_HEX,
    bls: ZERO_KEY_HEX,
    metadata: ZERO_KEY_HEX,
  }
}

describe('epoch-root', () => {
  describe('extractRingKeysFromValidatorSet', () => {
    test('returns error for empty validator set', () => {
      const [error, result] = extractRingKeysFromValidatorSet([])
      expect(error).toBeDefined()
      expect(error!.message).toContain('empty validator set')
      expect(result).toBeUndefined()
    })

    test('extracts bandersnatch keys from validators', () => {
      const validators = [makeValidator(KEY_A_HEX), makeValidator(KEY_B_HEX)]
      const [error, ringKeys] = extractRingKeysFromValidatorSet(validators)

      expect(error).toBeUndefined()
      expect(ringKeys).toBeDefined()
      expect(ringKeys!.length).toBe(2)
      for (const key of ringKeys!) {
        expect(key.length).toBe(32)
      }
    })

    test('sorts keys deterministically', () => {
      const validatorsAB = [
        makeValidator(KEY_A_HEX),
        makeValidator(KEY_B_HEX),
        makeValidator(KEY_C_HEX),
      ]
      const validatorsCBA = [
        makeValidator(KEY_C_HEX),
        makeValidator(KEY_B_HEX),
        makeValidator(KEY_A_HEX),
      ]

      const [, keysAB] = extractRingKeysFromValidatorSet(validatorsAB)
      const [, keysCBA] = extractRingKeysFromValidatorSet(validatorsCBA)

      expect(keysAB!.length).toBe(keysCBA!.length)
      for (let i = 0; i < keysAB!.length; i++) {
        expect(bytesToHex(keysAB![i])).toBe(bytesToHex(keysCBA![i]))
      }
    })

    test('preserves zero keys (for padding point replacement)', () => {
      const validators = [
        makeValidator(KEY_A_HEX),
        makeValidator(ZERO_KEY_HEX),
        makeValidator(KEY_B_HEX),
      ]
      const [error, ringKeys] = extractRingKeysFromValidatorSet(validators)

      expect(error).toBeUndefined()
      expect(ringKeys!.length).toBe(3)
    })

    test('single validator produces single key', () => {
      const validators = [makeValidator(KEY_A_HEX)]
      const [error, ringKeys] = extractRingKeysFromValidatorSet(validators)

      expect(error).toBeUndefined()
      expect(ringKeys!.length).toBe(1)
      expect(bytesToHex(ringKeys![0])).toBe(KEY_A_HEX)
    })
  })

  describe('verifyEpochRoot', () => {
    const validators = [
      makeValidator(KEY_A_HEX),
      makeValidator(KEY_B_HEX),
    ]

    test('returns error for empty validator set', () => {
      const epochRoot = ('0x' + 'ab'.repeat(144)) as `0x${string}`
      const [error] = verifyEpochRoot(epochRoot, [])
      expect(error).toBeDefined()
      expect(error!.message).toContain('empty validator set')
    })

    test('returns error for wrong epoch root length', () => {
      const shortRoot = ('0x' + 'ab'.repeat(32)) as `0x${string}`
      const [error, result] = verifyEpochRoot(shortRoot, validators)
      expect(error).toBeDefined()
      expect(error!.message).toContain('144 bytes')
    })

    test('accepts structurally valid 144-byte epoch root', () => {
      const validRoot = ('0x' + 'ab'.repeat(144)) as `0x${string}`
      const [error, result] = verifyEpochRoot(validRoot, validators)
      expect(error).toBeUndefined()
      expect(result).toBe(true)
    })
  })
})
