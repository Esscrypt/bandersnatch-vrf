/**
 * JAM Specialized Components Performance Benchmark
 *
 * Measures execution times for key cryptographic and consensus-critical
 * operations used across the JAM protocol. Results feed the performance
 * analysis in docs/RING_VRF_PROVER_VERIFIER_ANALYSIS.md.
 */

import { performance } from 'node:perf_hooks'
import { BandersnatchCurve, Bandersnatch } from '@pbnjam/bandersnatch'
import { IETFVRFProver } from '../prover/ietf'
import { IETFVRFVerifier } from '../verifier/ietf'
import { IETFVRFVerifierWasm } from '../verifier/ietf-wasm'
import { PedersenVRFProver } from '../prover/pedersen'
import { PedersenVRFVerifier } from '../verifier/pedersen'
import { getBanderoutFromGamma, getCommitmentFromGamma } from '../utils/gamma'
import {
  generateEntropyVRFSignature,
  verifyEntropyVRFSignature,
  banderout,
} from '../utils/entropy-vrf'
import {
  generateTranche0AuditSignature,
  verifyTranche0AuditSignature,
  generateTrancheNAuditSignature,
  verifyTrancheNAuditSignature,
} from '../utils/audit-signature'
import {
  generateAnnouncementSignature,
  verifyAnnouncementSignature,
} from '../utils/announcement'
import { encodeWorkReport } from '../utils/codec'
import { generateDevAccountValidatorKeyPair, blake2bHash } from '../utils/core'
import { pointToHashRfc9381 } from '../crypto/rfc9381'
import type { WorkReport, AuditAnnouncement } from '@pbnjam/types'
import type { Hex } from 'viem'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function avg(arr: number[]): number {
  return arr.reduce((a, b) => a + b, 0) / arr.length
}

function median(arr: number[]): number {
  const sorted = [...arr].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 !== 0
    ? sorted[mid]
    : (sorted[mid - 1] + sorted[mid]) / 2
}

function fmt(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(1)} µs`
  return `${ms.toFixed(3)} ms`
}

function bench(label: string, fn: () => void, warmup = 3, rounds = 20): { avg: number; median: number; min: number; max: number } {
  for (let i = 0; i < warmup; i++) fn()
  const times: number[] = []
  for (let i = 0; i < rounds; i++) {
    const t0 = performance.now()
    fn()
    times.push(performance.now() - t0)
  }
  const result = { avg: avg(times), median: median(times), min: Math.min(...times), max: Math.max(...times) }
  console.log(`  ${label}: avg ${fmt(result.avg)}, median ${fmt(result.median)}, min ${fmt(result.min)}, max ${fmt(result.max)}`)
  return result
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

const [keyErr, aliceKeys] = generateDevAccountValidatorKeyPair(0)
if (keyErr) throw keyErr
const [, bobKeys] = generateDevAccountValidatorKeyPair(1)

const secretKey = aliceKeys.bandersnatchKeyPair.privateKey
const publicKey = aliceKeys.bandersnatchKeyPair.publicKey

const sealOutput = new Uint8Array(32).fill(0x42)
const blockHeaderVrfOutput = new Uint8Array(32).fill(0x03)

const mockWorkReport: WorkReport = {
  package_spec: {
    hash: '0x1111111111111111111111111111111111111111111111111111111111111111',
    length: 1000n,
    erasure_root: '0x2222222222222222222222222222222222222222222222222222222222222222',
    exports_root: '0x3333333333333333333333333333333333333333333333333333333333333333',
    exports_count: 5n,
  },
  context: {
    anchor: '0x4444444444444444444444444444444444444444444444444444444444444444',
    state_root: '0x5555555555555555555555555555555555555555555555555555555555555555',
    beefy_root: '0x6666666666666666666666666666666666666666666666666666666666666666',
    lookup_anchor: '0x7777777777777777777777777777777777777777777777777777777777777777',
    lookup_anchor_slot: 1000000n,
    prerequisites: [],
  },
  core_index: 0n,
  authorizer_hash: '0x8888888888888888888888888888888888888888888888888888888888888888',
  auth_gas_used: 5000n,
  auth_output: '0x9999999999999999999999999999999999999999999999999999999999999999',
  segment_root_lookup: [],
  results: [],
}

// Pre-generate some signatures for verification benchmarks
const [, entropyGenResult] = generateEntropyVRFSignature(secretKey, sealOutput)
const [, audit0GenResult] = generateTranche0AuditSignature(secretKey, blockHeaderVrfOutput)
const [, auditNGenResult] = generateTrancheNAuditSignature(secretKey, blockHeaderVrfOutput, mockWorkReport, 1n)

const testWorkReports = [
  { coreIndex: 0n, workReportHash: '0x1111111111111111111111111111111111111111111111111111111111111111' as const },
  { coreIndex: 1n, workReportHash: '0x2222222222222222222222222222222222222222222222222222222222222222' as const },
]
const [, announceSig] = generateAnnouncementSignature(
  aliceKeys.ed25519KeyPair.privateKey,
  testWorkReports,
  2n,
  '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
)
const announcement: AuditAnnouncement = {
  headerHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  tranche: 2n,
  announcement: { workReports: testWorkReports, signature: announceSig! },
  evidence: new Uint8Array(96).fill(1),
}

const verifierTS = new IETFVRFVerifier()
let verifierWasm: IETFVRFVerifierWasm
try {
  verifierWasm = new IETFVRFVerifierWasm()
} catch {
  console.warn('WASM verifier not available, skipping WASM benchmarks')
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

console.log('='.repeat(72))
console.log('JAM Specialized Components — Performance Benchmark')
console.log('='.repeat(72))
console.log()

// 1. Bandersnatch curve operations
console.log('--- 1. Bandersnatch Curve Operations ---')
const randomScalar = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcn
const arbitraryPoint = BandersnatchCurve.scalarMultiply(BandersnatchCurve.GENERATOR, 42n)

const scalarMulGenGlv = bench('scalarMultiply(GENERATOR, k, GLV=true)', () => {
  BandersnatchCurve.scalarMultiply(BandersnatchCurve.GENERATOR, randomScalar, true)
})
const scalarMulGenNoGlv = bench('scalarMultiply(GENERATOR, k, GLV=false)', () => {
  BandersnatchCurve.scalarMultiply(BandersnatchCurve.GENERATOR, randomScalar, false)
})
const scalarMulArbGlv = bench('scalarMultiply(arbitrary, k, GLV=true)', () => {
  BandersnatchCurve.scalarMultiply(arbitraryPoint, randomScalar, true)
})
const scalarMulArbNoGlv = bench('scalarMultiply(arbitrary, k, GLV=false)', () => {
  BandersnatchCurve.scalarMultiply(arbitraryPoint, randomScalar, false)
})
const pointAdd = bench('add(P, Q)', () => {
  BandersnatchCurve.add(arbitraryPoint, BandersnatchCurve.GENERATOR)
})
const pointToBytes = bench('pointToBytes', () => {
  BandersnatchCurve.pointToBytes(arbitraryPoint)
})
const ptBytes = BandersnatchCurve.pointToBytes(arbitraryPoint)
const bytesToPoint = bench('bytesToPoint', () => {
  BandersnatchCurve.bytesToPoint(ptBytes)
})
console.log()

// 2. IETF VRF operations
console.log('--- 2. IETF VRF (Pedersen-free Schnorr VRF) ---')
const inputBytes = new Uint8Array(32).fill(0xab)
const auxData = new Uint8Array(0)

const ietfProve = bench('IETFVRFProver.prove', () => {
  IETFVRFProver.prove(secretKey, inputBytes, auxData)
})
const ietfProofResult = IETFVRFProver.prove(secretKey, inputBytes, auxData)
const ietfVerifyTS = bench('IETFVRFVerifier.verify (Pure TS)', () => {
  verifierTS.verify(publicKey, inputBytes, ietfProofResult.proof, auxData)
})
let ietfVerifyWasm: ReturnType<typeof bench> | undefined
if (verifierWasm!) {
  ietfVerifyWasm = bench('IETFVRFVerifierWasm.verify', () => {
    verifierWasm.verify(publicKey, inputBytes, ietfProofResult.proof, auxData)
  })
}
console.log()

// 3. Pedersen VRF operations
console.log('--- 3. Pedersen VRF ---')
const pedersenProve = bench('PedersenVRFProver.prove', () => {
  PedersenVRFProver.prove(secretKey, { input: inputBytes, auxData })
})
const pedersenResult = PedersenVRFProver.prove(secretKey, { input: inputBytes, auxData })
const pedersenVerify = bench('PedersenVRFVerifier.verify', () => {
  PedersenVRFVerifier.verify(publicKey, inputBytes, pedersenResult.proof, auxData)
})
console.log()

// 4. Banderout / Gamma hash
console.log('--- 4. Banderout & Gamma Hash ---')
const gammaBytes = ietfProofResult.gamma
const getBanderoutBench = bench('getBanderoutFromGamma', () => {
  getBanderoutFromGamma(gammaBytes)
})
const getCommitBench = bench('getCommitmentFromGamma (64-byte)', () => {
  getCommitmentFromGamma(gammaBytes)
})
const pointToHashBench = bench('pointToHashRfc9381', () => {
  pointToHashRfc9381(gammaBytes)
})
console.log()

// 5. Entropy VRF (Gray Paper Eq. 158)
console.log('--- 5. Entropy VRF (Gray Paper Eq. 158) ---')
const entropyGen = bench('generateEntropyVRFSignature', () => {
  generateEntropyVRFSignature(secretKey, sealOutput)
})
const entropyVerify = bench('verifyEntropyVRFSignature (Pure TS)', () => {
  verifyEntropyVRFSignature(publicKey, entropyGenResult!.signature, sealOutput, verifierTS)
})
let entropyVerifyWasm: ReturnType<typeof bench> | undefined
if (verifierWasm!) {
  entropyVerifyWasm = bench('verifyEntropyVRFSignature (WASM)', () => {
    verifyEntropyVRFSignature(publicKey, entropyGenResult!.signature, sealOutput, verifierWasm)
  })
}
const banderoutBench = bench('banderout (extract from 96-byte sig)', () => {
  banderout(entropyGenResult!.signature)
})
console.log()

// 6. Audit Signatures (Gray Paper Eq. 54-62, 105)
console.log('--- 6. Audit Signatures ---')
const auditGen0 = bench('generateTranche0AuditSignature', () => {
  generateTranche0AuditSignature(secretKey, blockHeaderVrfOutput)
})
const auditVerify0 = bench('verifyTranche0AuditSignature (Pure TS)', () => {
  verifyTranche0AuditSignature(publicKey, audit0GenResult!.signature, blockHeaderVrfOutput, verifierTS)
})
let auditVerify0Wasm: ReturnType<typeof bench> | undefined
if (verifierWasm!) {
  auditVerify0Wasm = bench('verifyTranche0AuditSignature (WASM)', () => {
    verifyTranche0AuditSignature(publicKey, audit0GenResult!.signature, blockHeaderVrfOutput, verifierWasm)
  })
}
const auditGenN = bench('generateTrancheNAuditSignature', () => {
  generateTrancheNAuditSignature(secretKey, blockHeaderVrfOutput, mockWorkReport, 1n)
})
const auditVerifyN = bench('verifyTrancheNAuditSignature (Pure TS)', () => {
  verifyTrancheNAuditSignature(publicKey, auditNGenResult!.signature, blockHeaderVrfOutput, mockWorkReport, 1n, verifierTS)
})
let auditVerifyNWasm: ReturnType<typeof bench> | undefined
if (verifierWasm!) {
  auditVerifyNWasm = bench('verifyTrancheNAuditSignature (WASM)', () => {
    verifyTrancheNAuditSignature(publicKey, auditNGenResult!.signature, blockHeaderVrfOutput, mockWorkReport, 1n, verifierWasm)
  })
}
console.log()

// 7. Announcement Signatures (Ed25519, Gray Paper Eq. 82)
console.log('--- 7. Announcement Signatures (Ed25519) ---')
const announceGen = bench('generateAnnouncementSignature', () => {
  generateAnnouncementSignature(
    aliceKeys.ed25519KeyPair.privateKey,
    testWorkReports,
    2n,
    '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  )
})
const announceVerify = bench('verifyAnnouncementSignature', () => {
  verifyAnnouncementSignature(announcement, aliceKeys.ed25519KeyPair.publicKey)
})
console.log()

// 8. Work Report Codec
console.log('--- 8. Work Report Encoding ---')
const wrEncode = bench('encodeWorkReport', () => {
  encodeWorkReport(mockWorkReport)
})
console.log()

// 9. Blake2b hash
console.log('--- 9. Blake2b Hash ---')
const data32 = new Uint8Array(32).fill(0xcc)
const data1k = new Uint8Array(1024).fill(0xdd)
const data10k = new Uint8Array(10240).fill(0xee)
const blake32 = bench('blake2bHash (32 bytes)', () => {
  blake2bHash(data32)
})
const blake1k = bench('blake2bHash (1 KB)', () => {
  blake2bHash(data1k)
})
const blake10k = bench('blake2bHash (10 KB)', () => {
  blake2bHash(data10k)
})
console.log()

// 10. Key Derivation
console.log('--- 10. Key Derivation (JIP-5) ---')
const keyDerive = bench('generateDevAccountValidatorKeyPair', () => {
  generateDevAccountValidatorKeyPair(42)
})
console.log()

// ---------------------------------------------------------------------------
// Summary Table
// ---------------------------------------------------------------------------

console.log('='.repeat(72))
console.log('Summary Table (median values)')
console.log('='.repeat(72))
console.log()
console.log('| Operation | Median | Category |')
console.log('|-----------|--------|----------|')
console.log(`| scalarMultiply (gen, GLV) | ${fmt(scalarMulGenGlv.median)} | Curve |`)
console.log(`| scalarMultiply (gen, wNAF) | ${fmt(scalarMulGenNoGlv.median)} | Curve |`)
console.log(`| scalarMultiply (arb, GLV) | ${fmt(scalarMulArbGlv.median)} | Curve |`)
console.log(`| scalarMultiply (arb, wNAF) | ${fmt(scalarMulArbNoGlv.median)} | Curve |`)
console.log(`| point add | ${fmt(pointAdd.median)} | Curve |`)
console.log(`| pointToBytes | ${fmt(pointToBytes.median)} | Curve |`)
console.log(`| bytesToPoint | ${fmt(bytesToPoint.median)} | Curve |`)
console.log(`| IETF VRF prove | ${fmt(ietfProve.median)} | VRF |`)
console.log(`| IETF VRF verify (TS) | ${fmt(ietfVerifyTS.median)} | VRF |`)
if (ietfVerifyWasm) console.log(`| IETF VRF verify (WASM) | ${fmt(ietfVerifyWasm.median)} | VRF |`)
console.log(`| Pedersen VRF prove | ${fmt(pedersenProve.median)} | VRF |`)
console.log(`| Pedersen VRF verify | ${fmt(pedersenVerify.median)} | VRF |`)
console.log(`| getBanderoutFromGamma | ${fmt(getBanderoutBench.median)} | Hash |`)
console.log(`| getCommitmentFromGamma | ${fmt(getCommitBench.median)} | Hash |`)
console.log(`| Entropy VRF sign | ${fmt(entropyGen.median)} | Safrole |`)
console.log(`| Entropy VRF verify (TS) | ${fmt(entropyVerify.median)} | Safrole |`)
if (entropyVerifyWasm) console.log(`| Entropy VRF verify (WASM) | ${fmt(entropyVerifyWasm.median)} | Safrole |`)
console.log(`| banderout (96-byte sig) | ${fmt(banderoutBench.median)} | Safrole |`)
console.log(`| Audit sig gen (tranche 0) | ${fmt(auditGen0.median)} | Auditing |`)
console.log(`| Audit sig verify T0 (TS) | ${fmt(auditVerify0.median)} | Auditing |`)
if (auditVerify0Wasm) console.log(`| Audit sig verify T0 (WASM) | ${fmt(auditVerify0Wasm.median)} | Auditing |`)
console.log(`| Audit sig gen (tranche N) | ${fmt(auditGenN.median)} | Auditing |`)
console.log(`| Audit sig verify TN (TS) | ${fmt(auditVerifyN.median)} | Auditing |`)
if (auditVerifyNWasm) console.log(`| Audit sig verify TN (WASM) | ${fmt(auditVerifyNWasm.median)} | Auditing |`)
console.log(`| Announcement sig gen | ${fmt(announceGen.median)} | Auditing |`)
console.log(`| Announcement sig verify | ${fmt(announceVerify.median)} | Auditing |`)
console.log(`| encodeWorkReport | ${fmt(wrEncode.median)} | Codec |`)
console.log(`| blake2bHash (32 B) | ${fmt(blake32.median)} | Hash |`)
console.log(`| blake2bHash (1 KB) | ${fmt(blake1k.median)} | Hash |`)
console.log(`| blake2bHash (10 KB) | ${fmt(blake10k.median)} | Hash |`)
console.log(`| Key derivation (JIP-5) | ${fmt(keyDerive.median)} | Keys |`)
