import type { AuditAnnouncement, Safe } from '@pbnjam/types'
import { safeError, safeResult } from '@pbnjam/types'
import {
  bytesToHex,
  type Hex,
  hexToBytes,
  signEd25519,
  verifyEd25519,
} from './core.ts'

const XANNOUNCE = new TextEncoder().encode('jam_announce')

const CORE_INDEX_OCTETS = 2
const SET_ELEMENT_OCTETS = CORE_INDEX_OCTETS + 32

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length && i < b.length; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i]
    }
  }
  return a.length - b.length
}

function buildAnnouncementMessage(
  workReports: Array<{ coreIndex: number; workReportHash: Hex }>,
  tranche: number,
  headerHash: Hex,
): Uint8Array {
  const elements = workReports.map(({ coreIndex, workReportHash }) => {
    const element = new Uint8Array(SET_ELEMENT_OCTETS)
    new DataView(element.buffer).setUint16(0, Number(coreIndex), true)
    element.set(hexToBytes(workReportHash), CORE_INDEX_OCTETS)
    return element
  })
  elements.sort(compareBytes)

  const headerHashBytes = hexToBytes(headerHash)
  const message = new Uint8Array(
    XANNOUNCE.length +
      1 +
      elements.length * SET_ELEMENT_OCTETS +
      headerHashBytes.length,
  )

  let offset = 0
  message.set(XANNOUNCE, offset)
  offset += XANNOUNCE.length
  message[offset] = Number(tranche)
  offset += 1
  for (const element of elements) {
    message.set(element, offset)
    offset += SET_ELEMENT_OCTETS
  }
  message.set(headerHashBytes, offset)

  return message
}

export function verifyAnnouncementSignature(
  announcement: AuditAnnouncement,
  validatorPublicKey: Uint8Array,
): Safe<boolean> {
  const message = buildAnnouncementMessage(
    announcement.announcement.workReports,
    announcement.tranche,
    announcement.headerHash,
  )
  const signatureBytes = hexToBytes(announcement.announcement.signature)

  return verifyEd25519(message, signatureBytes, validatorPublicKey)
}

export function generateAnnouncementSignature(
  validatorSecretKey: Uint8Array,
  workReports: Array<{ coreIndex: number; workReportHash: Hex }>,
  tranche: number,
  headerHash: Hex,
): Safe<Hex> {
  if (validatorSecretKey.length !== 32) {
    return safeError(new Error('Validator secret key must be 32 bytes'))
  }

  if (workReports.length === 0) {
    return safeError(new Error('Work reports array cannot be empty'))
  }

  try {
    const message = buildAnnouncementMessage(workReports, tranche, headerHash)

    const [signatureError, signature] = signEd25519(message, validatorSecretKey)
    if (signatureError) {
      return safeError(signatureError)
    }

    return safeResult(bytesToHex(signature))
  } catch (error) {
    return safeError(
      new Error(`Failed to generate announcement signature: ${error}`),
    )
  }
}
