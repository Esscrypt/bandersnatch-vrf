/**
 * Verifier-specific configuration for Bandersnatch VRF
 */

// Configuration constants for verifier

/**
 * Default verifier configuration
 */
export const DEFAULT_VERIFIER_CONFIG = {
  /** Use auxiliary data by default */
  useAuxData: false,
  /** Enable strict verification mode */
  strictMode: true,
  /** Enable caching for performance */
  enableCaching: true,
  /** Cache size limit */
  maxCacheSize: 1000,
  /** Timeout for operations in milliseconds */
  operationTimeout: 5000,
} as const

/**
 * Verifier performance settings
 */
export const VERIFIER_PERFORMANCE = {
  /** Batch size for batch verification */
  BATCH_SIZE: 100,
  /** Parallel processing threshold */
  PARALLEL_THRESHOLD: 10,
  /** Memory limit for caching in Uint8Array */
  CACHE_MEMORY_LIMIT: 1024 * 1024, // 1MB
} as const

/**
 * Verifier error codes
 */
export enum VerifierErrorCode {
  INVALID_PUBLIC_KEY = 'INVALID_PUBLIC_KEY',
  INVALID_INPUT = 'INVALID_INPUT',
  INVALID_OUTPUT = 'INVALID_OUTPUT',
  INVALID_PROOF = 'INVALID_PROOF',
  OPERATION_TIMEOUT = 'OPERATION_TIMEOUT',
  CACHE_FULL = 'CACHE_FULL',
  HASH_TO_CURVE_FAILED = 'HASH_TO_CURVE_FAILED',
  PROOF_VERIFICATION_FAILED = 'PROOF_VERIFICATION_FAILED',
  OUTPUT_HASH_MISMATCH = 'OUTPUT_HASH_MISMATCH',
}
