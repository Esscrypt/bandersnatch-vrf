import {
  getBanderoutFromGamma,
  IETFVRFProver,
  type IETFVRFVerifier,
  type IETFVRFVerifierWasm,
} from '@pbnjam/bandersnatch-vrf'
import type {
  AuditAnnouncement,
  IConfigService,
  Safe,
  WorkReport,
} from '@pbnjam/types'
import { safeError, safeResult } from '@pbnjam/types'
import { encodeWorkReport } from './codec.ts'
import { blake2bHash, type Hex, hexToBytes, jamShuffle } from './core.ts'

const XAUDIT = new TextEncoder().encode('jam_audit')

export interface AuditSignatureResult {
  signature: Uint8Array
  banderoutResult: Uint8Array
}

export function generateTranche0AuditSignature(
  validatorSecretKey: Uint8Array,
  blockHeaderVrfOutput: Uint8Array,
): Safe<AuditSignatureResult> {
  if (validatorSecretKey.length !== 32) {
    return safeError(new Error('Validator secret key must be 32 bytes'))
  }

  if (blockHeaderVrfOutput.length !== 32) {
    return safeError(new Error('Block header VRF output must be 32 bytes'))
  }

  const context = new Uint8Array(XAUDIT.length + blockHeaderVrfOutput.length)
  let offset = 0
  context.set(XAUDIT, offset)
  offset += XAUDIT.length
  context.set(blockHeaderVrfOutput, offset)

  const vrfResult = IETFVRFProver.prove(
    validatorSecretKey,
    context,
    new Uint8Array(0),
  )

  const banderoutResult = getBanderoutFromGamma(vrfResult.gamma)

  return safeResult({
    signature: vrfResult.proof,
    banderoutResult,
  })
}

export function generateTrancheNAuditSignature(
  validatorSecretKey: Uint8Array,
  blockHeaderVrfOutput: Uint8Array,
  workReport: WorkReport,
  trancheNumber: number,
): Safe<AuditSignatureResult> {
  if (validatorSecretKey.length !== 32) {
    return safeError(new Error('Validator secret key must be 32 bytes'))
  }

  if (blockHeaderVrfOutput.length !== 32) {
    return safeError(new Error('Block header VRF output must be 32 bytes'))
  }

  const [encodeError, encodedWorkReport] = encodeWorkReport(workReport)
  if (encodeError) {
    return safeError(encodeError)
  }

  const [hashError, workReportHash] = blake2bHash(encodedWorkReport)
  if (hashError) {
    return safeError(hashError)
  }

  const workReportHashBytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    workReportHashBytes[i] = Number.parseInt(
      workReportHash.slice(2 + i * 2, 4 + i * 2),
      16,
    )
  }

  const trancheBytes = new Uint8Array([Number(trancheNumber)])

  const context = new Uint8Array(
    XAUDIT.length +
      blockHeaderVrfOutput.length +
      workReportHashBytes.length +
      trancheBytes.length,
  )
  let offset = 0
  context.set(XAUDIT, offset)
  offset += XAUDIT.length
  context.set(blockHeaderVrfOutput, offset)
  offset += blockHeaderVrfOutput.length
  context.set(workReportHashBytes, offset)
  offset += workReportHashBytes.length
  context.set(trancheBytes, offset)

  const vrfResult = IETFVRFProver.prove(
    validatorSecretKey,
    context,
    new Uint8Array(0),
  )

  const banderoutResult = getBanderoutFromGamma(vrfResult.gamma)

  return safeResult({
    signature: vrfResult.proof,
    banderoutResult,
  })
}

export function verifyTranche0AuditSignature(
  validatorPublicKey: Uint8Array,
  signature: Uint8Array,
  blockHeaderVrfOutput: Uint8Array,
  verifier: IETFVRFVerifier | IETFVRFVerifierWasm,
): Safe<boolean> {
  if (validatorPublicKey.length !== 32) {
    return safeError(new Error('Validator public key must be 32 bytes'))
  }

  if (signature.length !== 96) {
    return safeError(new Error('IETF VRF signature must be 96 bytes'))
  }

  if (blockHeaderVrfOutput.length !== 32) {
    return safeError(new Error('Block header VRF output must be 32 bytes'))
  }

  const context = new Uint8Array(XAUDIT.length + blockHeaderVrfOutput.length)
  let offset = 0
  context.set(XAUDIT, offset)
  offset += XAUDIT.length
  context.set(blockHeaderVrfOutput, offset)

  const isValid = verifier.verify(
    validatorPublicKey,
    context,
    signature,
    new Uint8Array(0),
  )

  return safeResult(isValid)
}

export function verifyTrancheNAuditSignature(
  validatorPublicKey: Uint8Array,
  signature: Uint8Array,
  blockHeaderVrfOutput: Uint8Array,
  workReport: WorkReport,
  trancheNumber: number,
  verifier: IETFVRFVerifier | IETFVRFVerifierWasm,
): Safe<boolean> {
  if (validatorPublicKey.length !== 32) {
    return safeError(new Error('Validator public key must be 32 bytes'))
  }

  if (signature.length !== 96) {
    return safeError(new Error('IETF VRF signature must be 96 bytes'))
  }

  if (blockHeaderVrfOutput.length !== 32) {
    return safeError(new Error('Block header VRF output must be 32 bytes'))
  }

  const [encodeError, encodedWorkReport] = encodeWorkReport(workReport)
  if (encodeError) {
    return safeError(encodeError)
  }

  const [hashError, workReportHash] = blake2bHash(encodedWorkReport)
  if (hashError) {
    return safeError(hashError)
  }

  const workReportHashBytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    workReportHashBytes[i] = Number.parseInt(
      workReportHash.slice(2 + i * 2, 4 + i * 2),
      16,
    )
  }

  const trancheBytes = new Uint8Array([Number(trancheNumber)])

  const context = new Uint8Array(
    XAUDIT.length +
      blockHeaderVrfOutput.length +
      workReportHashBytes.length +
      trancheBytes.length,
  )
  let offset = 0
  context.set(XAUDIT, offset)
  offset += XAUDIT.length
  context.set(blockHeaderVrfOutput, offset)
  offset += blockHeaderVrfOutput.length
  context.set(workReportHashBytes, offset)
  offset += workReportHashBytes.length
  context.set(trancheBytes, offset)

  const isValid = verifier.verify(
    validatorPublicKey,
    context,
    signature,
    new Uint8Array(0),
  )

  return safeResult(isValid)
}

export function generateAuditSignature(
  validatorSecretKey: Uint8Array,
  blockHeaderVrfOutput: Uint8Array,
  trancheNumber: number,
  workReport?: WorkReport,
): Safe<AuditSignatureResult> {
  if (trancheNumber === 0) {
    return generateTranche0AuditSignature(
      validatorSecretKey,
      blockHeaderVrfOutput,
    )
  } else {
    if (!workReport) {
      return safeError(new Error('Work report is required for tranche N > 0'))
    }
    return generateTrancheNAuditSignature(
      validatorSecretKey,
      blockHeaderVrfOutput,
      workReport,
      trancheNumber,
    )
  }
}

export function verifyAuditSignature(
  validatorPublicKey: Uint8Array,
  signature: Uint8Array,
  blockHeaderVrfOutput: Uint8Array,
  trancheNumber: number,
  verifier: IETFVRFVerifier | IETFVRFVerifierWasm,
  workReport?: WorkReport,
): Safe<boolean> {
  if (trancheNumber === 0) {
    return verifyTranche0AuditSignature(
      validatorPublicKey,
      signature,
      blockHeaderVrfOutput,
      verifier,
    )
  } else {
    if (!workReport) {
      return safeError(new Error('Work report is required for tranche N > 0'))
    }
    return verifyTrancheNAuditSignature(
      validatorPublicKey,
      signature,
      blockHeaderVrfOutput,
      workReport,
      trancheNumber,
      verifier,
    )
  }
}

export function verifyBandersnatchVRFEvidence(
  announcement: AuditAnnouncement,
  announcerBandersnatchPublicKey: Uint8Array,
  workReport: WorkReport,
  verifier: IETFVRFVerifier | IETFVRFVerifierWasm,
): Safe<boolean> {
  const blockHeaderVrfOutput = hexToBytes(announcement.headerHash)

  if (announcement.tranche === 0) {
    return verifyTranche0AuditSignature(
      announcerBandersnatchPublicKey,
      announcement.evidence,
      blockHeaderVrfOutput,
      verifier,
    )
  } else {

    return verifyTrancheNAuditSignature(
      announcerBandersnatchPublicKey,
      announcement.evidence,
      blockHeaderVrfOutput,
      workReport,
      announcement.tranche,
      verifier,
    )
  }
}

export function verifyWorkReportSelection(
  announcement: AuditAnnouncement,
  availableCoreWorkReports: Map<number, WorkReport[]>,
  bandersnatchVrfOutput: Hex,
  configService: IConfigService,
  previousTrancheAnnouncements?: AuditAnnouncement[],
): Safe<boolean> {
  if (announcement.tranche === 0) {
    return verifyTranche0WorkReportSelection(
      announcement,
      availableCoreWorkReports,
      bandersnatchVrfOutput,
    )
  } else {
    return verifyTrancheNWorkReportSelection(
      announcement,
      bandersnatchVrfOutput,
      configService,
      previousTrancheAnnouncements || [],
    )
  }
}

function verifyTranche0WorkReportSelection(
  announcement: AuditAnnouncement,
  availableCoreWorkReports: Map<number, WorkReport[]>,
  bandersnatchVrfOutput: Hex,
): Safe<boolean> {

  const shuffledSequence = jamShuffle(
    availableCoreWorkReports.entries().toArray(),
    bandersnatchVrfOutput,
  )

  const expectedSelectedCoreIndices = new Set<number>()

  for (const [core, workReports] of shuffledSequence) {
    if (workReports.length > 0) {
      expectedSelectedCoreIndices.add(core)

      if (expectedSelectedCoreIndices.size >= 10) {
        break
      }
    }
  }

  const announcedCoreIndices = new Set(
    announcement.announcement.workReports.map((wr) => wr.coreIndex),
  )

  if (announcedCoreIndices.size !== expectedSelectedCoreIndices.size) {
    return safeResult(false)
  }

  for (const coreIndex of announcedCoreIndices) {
    if (!expectedSelectedCoreIndices.has(coreIndex)) {
      return safeResult(false)
    }
  }

  return safeResult(true)
}

function verifyTrancheNWorkReportSelection(
  announcement: AuditAnnouncement,
  bandersnatchVrfOutput: Hex,
  configService: IConfigService,
  _previousTrancheAnnouncements: AuditAnnouncement[],
): Safe<boolean> {

  const CAUDITBIASFACTOR = 2

  const biasThreshold = configService.numValidators / (256 * CAUDITBIASFACTOR)

  for (const _announcedWorkReport of announcement.announcement.workReports) {

    const previousAnnouncers = new Set<number>()

    const positiveJudgments = new Set<number>()

    const m_n = previousAnnouncers.size - positiveJudgments.size

    const vrfFirstByte = hexToBytes(bandersnatchVrfOutput)[0]

    const leftSide = (biasThreshold * vrfFirstByte) / 256

    if (leftSide >= m_n) {
      return safeResult(false)
    }
  }

  return safeResult(true)
}
