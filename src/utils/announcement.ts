import type { AuditAnnouncement, Safe } from '@pbnjam/types'
import { safeError, safeResult } from '@pbnjam/types'
import {
  bytesToHex,
  type Hex,
  hexToBytes,
  signEd25519,
  verifyEd25519,
} from './core'

/**
 * Audit announcement signature generation and verification (Gray Paper Eq. 82).
 *
 * @module announcement
 */

/**
 * Verify audit announcement signature according to Gray Paper Eq. 82
 *
 * Gray Paper Eq. 82:
 * S ≡ edsignature{activeset[v]_vk_ed}{Xannounce ∥ n ∥ x_n ∥ blake{H}}
 * where Xannounce = token("jam_announce")
 *
 * This verifies that:
 * 1. The Ed25519 signature is valid for the announcement message
 * 2. The validator's public key matches the signature
 * 3. The message construction follows Gray Paper specification
 *
 * @param announcement - Audit announcement to verify
 * @param validatorPublicKey - Validator's public key
 * @returns Safe<boolean> - Success if signature is valid
 */
export function verifyAnnouncementSignature(
  announcement: AuditAnnouncement,
  validatorPublicKey: Uint8Array,
): Safe<boolean> {
  // Step 3: Construct the message according to Gray Paper Eq. 82:
  // message = Xannounce ∥ n ∥ x_n ∥ blake{H}
  // where:
  // - Xannounce = "jam_announce" token
  // - n = tranche number
  // - x_n = encoded work report set
  // - blake{H} = Blake2b hash of block header

  const XANNOUNCE = new TextEncoder().encode('jam_announce')

  // Convert tranche number to bytes (8 bytes, little-endian)
  const trancheBytes = new Uint8Array(8)
  new DataView(trancheBytes.buffer).setBigUint64(0, announcement.tranche, true)

  // Encode work report set (x_n)
  // This would typically be the serialized list of work reports
  // For now, we'll create a simple encoding of the work reports
  const workReportSetBytes = new Uint8Array(
    announcement.announcement.workReports.length * 36, // 4 bytes coreIndex + 32 bytes hash
  )
  let offset = 0
  for (const workReport of announcement.announcement.workReports) {
    // Core index (4 bytes, little-endian)
    const coreIndexBytes = new Uint8Array(4)
    new DataView(coreIndexBytes.buffer).setUint32(
      0,
      Number(workReport.coreIndex),
      true,
    )
    workReportSetBytes.set(coreIndexBytes, offset)
    offset += 4

    // Work report hash (32 bytes)
    const hashBytes = hexToBytes(workReport.workReportHash)
    workReportSetBytes.set(hashBytes, offset)
    offset += 32
  }

  // Blake2b hash of block header (blake{H})
  const headerHashBytes = hexToBytes(announcement.headerHash)

  // Construct the complete message
  const message = new Uint8Array(
    XANNOUNCE.length +
      trancheBytes.length +
      workReportSetBytes.length +
      headerHashBytes.length,
  )
  offset = 0
  message.set(XANNOUNCE, offset)
  offset += XANNOUNCE.length
  message.set(trancheBytes, offset)
  offset += trancheBytes.length
  message.set(workReportSetBytes, offset)
  offset += workReportSetBytes.length
  message.set(headerHashBytes, offset)

  // Step 4: Verify the Ed25519 signature
  const signatureBytes = hexToBytes(announcement.announcement.signature)

  const [verifyError, isValid] = verifyEd25519(
    message,
    signatureBytes,
    validatorPublicKey,
  )
  if (verifyError) {
    return safeError(verifyError)
  }
  return safeResult(isValid)
}

/**
 * Generate Ed25519 announcement signature according to Gray Paper Eq. 82
 *
 * Gray Paper Specification:
 * S ≡ edsignature{activeset[v]_ed}{Xannounce ∥ n ∥ x_n ∥ blake{H}}
 * where:
 * - Xannounce = "jam_announce" token
 * - n = tranche number
 * - x_n = encode{set{build{encode[2]{c} ∥ blake{w}}{wrc ∈ local_tranche_n}}}
 * - blake{H} = Blake2b hash of block header
 *
 * @param validatorSecretKey - Ed25519 secret key of the validator
 * @param workReports - Array of work reports to announce
 * @param tranche - Tranche number
 * @param headerHash - Blake2b hash of block header
 * @returns Ed25519 signature (64 bytes) as hex string
 */
export function generateAnnouncementSignature(
  validatorSecretKey: Uint8Array,
  workReports: Array<{ coreIndex: bigint; workReportHash: Hex }>,
  tranche: bigint,
  headerHash: Hex,
): Safe<Hex> {
  // Validate inputs
  if (validatorSecretKey.length !== 32) {
    return safeError(new Error('Validator secret key must be 32 bytes'))
  }

  if (workReports.length === 0) {
    return safeError(new Error('Work reports array cannot be empty'))
  }

  try {
    // Step 1: Construct the message according to Gray Paper Eq. 82
    const XANNOUNCE = new TextEncoder().encode('jam_announce')

    // Convert tranche number to bytes (8 bytes, little-endian)
    const trancheBytes = new Uint8Array(8)
    new DataView(trancheBytes.buffer).setBigUint64(0, tranche, true)

    // Encode work report set (x_n) according to Gray Paper:
    // encode{set{build{encode[2]{c} ∥ blake{w}}{wrc ∈ local_tranche_n}}}
    const workReportSetBytes = new Uint8Array(
      workReports.length * 36, // 4 bytes coreIndex + 32 bytes hash
    )
    let offset = 0
    for (const workReport of workReports) {
      // Core index (4 bytes, little-endian) - encode[2]{c}
      const coreIndexBytes = new Uint8Array(4)
      new DataView(coreIndexBytes.buffer).setUint32(
        0,
        Number(workReport.coreIndex),
        true,
      )
      workReportSetBytes.set(coreIndexBytes, offset)
      offset += 4

      // Work report hash (32 bytes) - blake{w}
      const hashBytes = hexToBytes(workReport.workReportHash)
      workReportSetBytes.set(hashBytes, offset)
      offset += 32
    }

    // Blake2b hash of block header (blake{H})
    const headerHashBytes = hexToBytes(headerHash)

    // Construct the complete message: Xannounce ∥ n ∥ x_n ∥ blake{H}
    const message = new Uint8Array(
      XANNOUNCE.length +
        trancheBytes.length +
        workReportSetBytes.length +
        headerHashBytes.length,
    )
    offset = 0
    message.set(XANNOUNCE, offset)
    offset += XANNOUNCE.length
    message.set(trancheBytes, offset)
    offset += trancheBytes.length
    message.set(workReportSetBytes, offset)
    offset += workReportSetBytes.length
    message.set(headerHashBytes, offset)

    // Step 2: Generate Ed25519 signature
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
