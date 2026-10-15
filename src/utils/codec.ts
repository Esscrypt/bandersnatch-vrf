import type {
  FixedLengthSize,
  RefineContext,
  RefineLoad,
  Safe,
  WorkError,
  WorkExecutionResult,
  WorkPackageSpec,
  WorkReport,
  WorkResult,
} from '@pbnjam/types'
import { safeError, safeResult } from '@pbnjam/types'
import { concatBytes, hexToBytes } from './core.ts'

function encodeNatural(value: number): Safe<Uint8Array>
function encodeNatural(value: bigint): Safe<Uint8Array>
function encodeNatural(value: bigint | number): Safe<Uint8Array> {
  const asBigInt = typeof value === 'bigint' ? value : BigInt(value)
  if (asBigInt < 0n)
    return safeError(new Error(`Natural number cannot be negative: ${value}`))
  if (asBigInt > 2n ** 64n - 1n)
    return safeError(new Error('Natural number exceeds maximum value'))
  if (asBigInt === 0n) return safeResult(new Uint8Array([0]))
  if (asBigInt >= 2n ** 56n) {
    const result = new Uint8Array(9)
    result[0] = 0xff
    for (let i = 0; i < 8; i++)
      result[1 + i] = Number((asBigInt >> BigInt(8 * i)) & 0xffn)
    return safeResult(result)
  }
  if (asBigInt >= 1n && asBigInt <= 127n)
    return safeResult(new Uint8Array([Number(asBigInt)]))
  let l = 1
  while (l <= 8 && asBigInt >= 1n << BigInt(7 * (l + 1))) l++
  if (l > 8)
    return safeError(
      new Error(`Unable to determine encoding length for value: ${value}`),
    )
  const prefixBase = (1n << 8n) - (1n << BigInt(8 - l))
  const highBits = asBigInt >> BigInt(8 * l)
  const prefix = prefixBase + highBits
  if (prefix > 255n)
    return safeError(new Error(`Prefix overflow for value: ${value}, l: ${l}`))
  const suffix = asBigInt & ((1n << BigInt(8 * l)) - 1n)
  const result = new Uint8Array(1 + l)
  result[0] = Number(prefix)
  for (let i = 0; i < l; i++)
    result[1 + i] = Number((suffix >> BigInt(8 * i)) & 0xffn)
  return safeResult(result)
}

function encodeFixedLength(value: number, length: 1 | 2 | 4): Safe<Uint8Array>
function encodeFixedLength(value: bigint, length: 8 | 16 | 32): Safe<Uint8Array>
function encodeFixedLength(
  value: bigint | number,
  length: FixedLengthSize,
): Safe<Uint8Array> {
  if (typeof value === 'number') {
    if (value < 0)
      return safeError(new Error(`Natural number cannot be negative: ${value}`))
    const result = new Uint8Array(length)
    if (length <= 4) {
      const view = new DataView(result.buffer)
      if (length === 1) view.setUint8(0, value)
      else if (length === 2) view.setUint16(0, value, true)
      else view.setUint32(0, value, true)
      return safeResult(result)
    }
  }
  const asBigInt = typeof value === 'bigint' ? value : BigInt(value)
  if (asBigInt < 0n)
    return safeError(new Error(`Natural number cannot be negative: ${value}`))
  const modulus = 2n ** (8n * BigInt(length))
  const wrappedValue = asBigInt % modulus
  const result = new Uint8Array(length)
  for (let i = 0; i < length; i++)
    result[i] = Number((wrappedValue >> (8n * BigInt(i))) & 0xffn)
  return safeResult(result)
}

function encodeWorkPackageSpec(spec: WorkPackageSpec): Safe<Uint8Array> {
  const parts: Uint8Array[] = []
  parts.push(hexToBytes(spec.hash))
  const [error1, bundleLenEncoded] = encodeFixedLength(spec.length, 4)
  if (error1) return safeError(error1)
  parts.push(bundleLenEncoded)
  parts.push(hexToBytes(spec.erasureRoot))
  parts.push(hexToBytes(spec.exportsRoot))
  const [error2, segCountEncoded] = encodeFixedLength(spec.exportsCount, 2)
  if (error2) return safeError(error2)
  parts.push(segCountEncoded)
  return safeResult(concatBytes(parts))
}

function encodeRefineContext(context: RefineContext): Safe<Uint8Array> {
  const parts: Uint8Array[] = []
  parts.push(hexToBytes(context.anchor))
  parts.push(hexToBytes(context.stateRoot))
  parts.push(hexToBytes(context.beefyRoot))
  parts.push(hexToBytes(context.lookupAnchor))
  const [error, encoded] = encodeFixedLength(context.lookupAnchorSlot, 4)
  if (error) return safeError(error)
  parts.push(encoded)
  const [error2, lengthEncoded] = encodeNatural(context.prerequisites.length)
  if (error2) return safeError(error2)
  parts.push(lengthEncoded)
  for (const prerequisite of context.prerequisites)
    parts.push(hexToBytes(prerequisite))
  return safeResult(concatBytes(parts))
}

function encodeRefineLoad(load: RefineLoad): Safe<Uint8Array> {
  const parts: Uint8Array[] = []
  const [e1, g] = encodeNatural(load.gas_used)
  if (e1) return safeError(e1)
  parts.push(g)
  const [e2, i] = encodeNatural(load.imports)
  if (e2) return safeError(e2)
  parts.push(i)
  const [e3, ec] = encodeNatural(load.extrinsic_count)
  if (e3) return safeError(e3)
  parts.push(ec)
  const [e4, es] = encodeNatural(load.extrinsic_size)
  if (e4) return safeError(e4)
  parts.push(es)
  const [e5, ex] = encodeNatural(load.exports)
  if (e5) return safeError(e5)
  parts.push(ex)
  return safeResult(concatBytes(parts))
}

const WORK_ERROR_DISCRIMINATOR: Record<WorkError, number> = {
  OOG: 1,
  PANIC: 2,
  BADEXPORTS: 3,
  OVERSIZE: 4,
  BAD: 5,
  BIG: 6,
}

function encodeWorkExecutionResult(
  result: WorkExecutionResult,
): Safe<Uint8Array> {
  if (result instanceof Uint8Array) {
    const [error, lengthEncoded] = encodeNatural(result.length)
    if (error) return safeError(error)
    return safeResult(concatBytes([new Uint8Array([0]), lengthEncoded, result]))
  }
  return safeResult(new Uint8Array([WORK_ERROR_DISCRIMINATOR[result]]))
}

function encodeWorkResult(result: WorkResult): Safe<Uint8Array> {
  const parts: Uint8Array[] = []
  const [e1, sid] = encodeFixedLength(result.service_id, 4)
  if (e1) return safeError(e1)
  parts.push(sid)
  parts.push(hexToBytes(result.code_hash))
  parts.push(hexToBytes(result.payload_hash))
  const [e2, ag] = encodeFixedLength(result.accumulate_gas, 8)
  if (e2) return safeError(e2)
  parts.push(ag)
  const [e3, res] = encodeWorkExecutionResult(result.result)
  if (e3) return safeError(e3)
  parts.push(res)
  const [e4, rl] = encodeRefineLoad(result.refine_load)
  if (e4) return safeError(e4)
  parts.push(rl)
  return safeResult(concatBytes(parts))
}

export function encodeWorkReport(report: WorkReport): Safe<Uint8Array> {
  const parts: Uint8Array[] = []
  const [error0, encoded0] = encodeWorkPackageSpec(report.packageSpec)
  if (error0) return safeError(error0)
  parts.push(encoded0)
  const [error1, encoded1] = encodeRefineContext(report.context)
  if (error1) return safeError(error1)
  parts.push(encoded1)
  const [error2, encoded2] = encodeNatural(report.coreIndex)
  if (error2) return safeError(error2)
  parts.push(encoded2)
  parts.push(hexToBytes(report.authorizer_hash))
  const [error3, encoded3] = encodeNatural(report.authGasUsed)
  if (error3) return safeError(error3)
  parts.push(encoded3)
  const authOutputBytes = hexToBytes(report.authOutput)
  const [error4, encoded4] = encodeNatural(authOutputBytes.length)
  if (error4) return safeError(error4)
  parts.push(encoded4)
  parts.push(authOutputBytes)
  const srLookupEntries = report.segmentRootLookup
  const [error5, encoded5] = encodeNatural(srLookupEntries.length)
  if (error5) return safeError(error5)
  parts.push(encoded5)
  for (const entry of srLookupEntries) {
    parts.push(hexToBytes(entry.workPackageHash))
    parts.push(hexToBytes(entry.segment_tree_root))
  }
  const [error6, encoded6] = encodeNatural(report.results.length)
  if (error6) return safeError(error6)
  parts.push(encoded6)
  for (const result of report.results) {
    const [error7, encoded7] = encodeWorkResult(result)
    if (error7) return safeError(error7)
    parts.push(encoded7)
  }
  return safeResult(concatBytes(parts))
}
