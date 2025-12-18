/**
 * Bandersnatch VRF Configuration Constants
 *
 * Configuration constants for Bandersnatch Ring VRF implementation
 * Based on bandersnatch-vrf-spec specification
 */

import type { Hex } from 'viem'

/**
 * Bandersnatch VRF Ring Root Configuration
 *
 * Ring root structure (144 bytes total):
 * - KZG Polynomial Commitment (48 bytes): BLS12-381 G1 point commitment
 * - Accumulator Seed Point (32 bytes): For ring proof generation
 * - Padding Point (32 bytes): For invalid Bandersnatch keys
 * - Domain Information (32 bytes): Polynomial domain generator and size
 */
export const BANDERSNATCH_VRF_CONFIG = {
  /**
   * Ring root size in bytes
   * Gray Paper notation.tex line 169: ringroot ⊂ blob[144]
   */
  RING_ROOT_SIZE: 144,

  /**
   * KZG polynomial commitment size in bytes
   * BLS12-381 G1 point in compressed form
   */
  KZG_COMMITMENT_SIZE: 48,

  /**
   * Accumulator seed point size in bytes
   */
  ACCUMULATOR_SEED_POINT_SIZE: 32,

  /**
   * Padding point size in bytes
   */
  PADDING_POINT_SIZE: 32,

  /**
   * Domain information size in bytes
   */
  DOMAIN_INFO_SIZE: 32,

  /**
   * Domain generator size in bytes (part of domain info)
   */
  DOMAIN_GENERATOR_SIZE: 28,

  /**
   * Domain size in bytes (part of domain info)
   */
  DOMAIN_SIZE_BYTES: 4,

  /**
   * Accumulator Seed Point
   * From bandersnatch-vrf-spec section 4.1
   * Compressed Twisted Edwards form
   */
  ACCUMULATOR_SEED_POINT:
    '0x6e5574f9077fb76c885c36196a832dbadd64142d305be5487724967acf9595a0' as Hex,

  /**
   * Padding Point
   * From bandersnatch-vrf-spec section 4.1
   * Compressed Twisted Edwards form
   * Derived using ECVRF_encode_to_curve with input "ring-proof-pad"
   */
  PADDING_POINT:
    '0x92ca79e61dd90c1573a8693f199bf6e1e86835cc715cdcf93f5ef222560023aa' as Hex,

  /**
   * Pedersen VRF Blinding Base Point
   * From bandersnatch-vrf-spec section 3.1
   * Compressed Twisted Edwards form
   * B_x = 6150229251051246713677296363717454238956877613358614224171740096471278798312
   * B_y = 28442734166467795856797249030329035618871580593056783094884474814923353898473
   */
  BLINDING_BASE_POINT:
    '0xe93da06b869766b158d20b843ec648cc68e0b7ba2f7083acf0f154205d04e23e' as Hex,

  /**
   * Domain Generator
   * From bandersnatch-vrf-spec section 4.1
   * ω = 49307615728544765012166121802278658070711169839041683575071795236746050763237
   * NOTE: This is a placeholder - replace with actual domain generator from spec
   */
  DOMAIN_GENERATOR:
    '0x6c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c' as Hex,

  /**
   * Domain Size
   * From bandersnatch-vrf-spec section 4.1
   * |𝔻| = 2048
   */
  DOMAIN_SIZE: 2048,

  /**
   * Secret key size in bytes
   */
  SECRET_KEY_SIZE: 32,

  /**
   * Public key size in bytes
   */
  PUBLIC_KEY_SIZE: 32,
} as const

/**
 * Ring root byte offsets
 */
export const RING_ROOT_OFFSETS = {
  KZG_COMMITMENT: 0,
  ACCUMULATOR_SEED_POINT: BANDERSNATCH_VRF_CONFIG.KZG_COMMITMENT_SIZE,
  PADDING_POINT:
    BANDERSNATCH_VRF_CONFIG.KZG_COMMITMENT_SIZE +
    BANDERSNATCH_VRF_CONFIG.ACCUMULATOR_SEED_POINT_SIZE,
  DOMAIN_GENERATOR:
    BANDERSNATCH_VRF_CONFIG.KZG_COMMITMENT_SIZE +
    BANDERSNATCH_VRF_CONFIG.ACCUMULATOR_SEED_POINT_SIZE +
    BANDERSNATCH_VRF_CONFIG.PADDING_POINT_SIZE,
  DOMAIN_SIZE:
    BANDERSNATCH_VRF_CONFIG.KZG_COMMITMENT_SIZE +
    BANDERSNATCH_VRF_CONFIG.ACCUMULATOR_SEED_POINT_SIZE +
    BANDERSNATCH_VRF_CONFIG.PADDING_POINT_SIZE +
    BANDERSNATCH_VRF_CONFIG.DOMAIN_GENERATOR_SIZE,
} as const
