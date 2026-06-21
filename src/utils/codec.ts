/**
 * Local implementation of encodeWorkReport for audit-signature.
 *
 * Gray Paper Section: Appendix D.1 - Block Serialization (Equation 231-240).
 * Encoders: encodeNatural (Eq. 30-38), encodeFixedLength (Eq. 102-109),
 * encodeWorkPackageSpec (Eq. 208-214), encodeRefineContext (Eq. 199-206),
 * encodeRefineLoad, encodeWorkExecutionResult, encodeWorkResult (Eq. 216-229).
 *
 * @module codec
 */

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
import { concatBytes, hexToBytes } from './core'

/** @internal Gray Paper Equation 30-38: encode natural number. */
function encodeNatural(value: bigint): Safe<Uint8Array> {
  if (value < 0n)
    return safeError(new Error(`Natural number cannot be negative: ${value}`))
  if (value > 2n ** 64n - 1n)
    return safeError(new Error('Natural number exceeds maximum value'))
  if (value === 0n) return safeResult(new Uint8Array([0]))
  if (value >= 2n ** 56n) {
    const result = new Uint8Array(9)
    result[0] = 0xff
    for (let i = 0; i < 8; i++)
      result[1 + i] = Number((value >> BigInt(8 * i)) & 0xffn)
    return safeResult(result)
  }
  if (value >= 1n && value <= 127n)
    return safeResult(new Uint8Array([Number(value)]))
  let l = 1
  while (l <= 8 && value >= 1n << BigInt(7 * (l + 1))) l++
  if (l > 8)
    return safeError(
      new Error(`Unable to determine encoding length for value: ${value}`),
    )
  const prefixBase = (1n << 8n) - (1n << BigInt(8 - l))
  const highBits = value >> BigInt(8 * l)
  const prefix = prefixBase + highBits
  if (prefix > 255n)
    return safeError(new Error(`Prefix overflow for value: ${value}, l: ${l}`))
  const suffix = value & ((1n << BigInt(8 * l)) - 1n)
  const result = new Uint8Array(1 + l)
  result[0] = Number(prefix)
  for (let i = 0; i < l; i++)
    result[1 + i] = Number((suffix >> BigInt(8 * i)) & 0xffn)
  return safeResult(result)
}

/** @internal Gray Paper Equation 102-109: fixed-length encoding. */
function encodeFixedLength(
  value: bigint,
  length: FixedLengthSize,
): Safe<Uint8Array> {
  if (value < 0n)
    return safeError(new Error(`Natural number cannot be negative: ${value}`))
  const lengthNum = Number(length)
  const modulus = 2n ** (8n * BigInt(lengthNum))
  const wrappedValue = value % modulus
  const result = new Uint8Array(lengthNum)
  for (let i = 0; i < lengthNum; i++)
    result[i] = Number((wrappedValue >> (8n * BigInt(i))) & 0xffn)
  return safeResult(result)
}

/** @internal Gray Paper Equation 208-214: work package spec encoding. */
function encodeWorkPackageSpec(spec: WorkPackageSpec): Safe<Uint8Array> {
  const parts: Uint8Array[] = []
  parts.push(hexToBytes(spec.hash))
  const [error1, bundleLenEncoded] = encodeFixedLength(BigInt(spec.length), 4n)
  if (error1) return safeError(error1)
  parts.push(bundleLenEncoded)
  parts.push(hexToBytes(spec.erasure_root))
  parts.push(hexToBytes(spec.exports_root))
  const [error2, segCountEncoded] = encodeFixedLength(
    BigInt(spec.exports_count),
    2n,
  )
  if (error2) return safeError(error2)
  parts.push(segCountEncoded)
  return safeResult(concatBytes(parts))
}

/** @internal Gray Paper Equation 199-206: refine context encoding. */
function encodeRefineContext(context: RefineContext): Safe<Uint8Array> {
  const parts: Uint8Array[] = []
  parts.push(hexToBytes(context.anchor))
  parts.push(hexToBytes(context.state_root))
  parts.push(hexToBytes(context.beefy_root))
  parts.push(hexToBytes(context.lookup_anchor))
  const [error, encoded] = encodeFixedLength(context.lookup_anchor_slot, 4n)
  if (error) return safeError(error)
  parts.push(encoded)
  const [error2, lengthEncoded] = encodeNatural(
    BigInt(context.prerequisites.length),
  )
  if (error2) return safeError(error2)
  parts.push(lengthEncoded)
  for (const prerequisite of context.prerequisites)
    parts.push(hexToBytes(prerequisite))
  return safeResult(concatBytes(parts))
}

/** @internal Encode refine load (gas_used, imports, extrinsic_count, extrinsic_size, exports). */
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

// Work-error discriminators (0 is reserved for a successful output blob). Mirrors the canonical
// encoder in @pbnjam/codec; kept local to avoid a cross-package dependency.
const WORK_ERROR_DISCRIMINATOR: Record<WorkError, number> = {
  OOG: 1,
  PANIC: 2,
  BADEXPORTS: 3,
  OVERSIZE: 4,
  BAD: 5,
  BIG: 6,
}

/** @internal Encode a work execution result: a success output blob, or a work error. */
function encodeWorkExecutionResult(
  result: WorkExecutionResult,
): Safe<Uint8Array> {
  if (result instanceof Uint8Array) {
    const [error, lengthEncoded] = encodeNatural(BigInt(result.length))
    if (error) return safeError(error)
    return safeResult(concatBytes([new Uint8Array([0]), lengthEncoded, result]))
  }
  return safeResult(new Uint8Array([WORK_ERROR_DISCRIMINATOR[result]]))
}

/** @internal Gray Paper Equation 216-229: work result encoding. */
function encodeWorkResult(result: WorkResult): Safe<Uint8Array> {
  const parts: Uint8Array[] = []
  const [e1, sid] = encodeFixedLength(result.service_id, 4n)
  if (e1) return safeError(e1)
  parts.push(sid)
  parts.push(hexToBytes(result.code_hash))
  parts.push(hexToBytes(result.payload_hash))
  const [e2, ag] = encodeFixedLength(result.accumulate_gas, 8n)
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

/**
 * Encode work report according to Gray Paper specification (Equation 231-240).
 * encode(WR) = encode(WR_avspec, WR_context, WR_core, WR_authorizer, WR_authgasused, var{authtrace}, var{srlookup}, var{digests})
 *
 * @param report - Work report to encode (package_spec, context, core_index, authorizer_hash, auth_gas_used, auth_output, segment_root_lookup, results)
 * @returns Safe result with serialized work report bytes
 */
export function encodeWorkReport(report: WorkReport): Safe<Uint8Array> {
  const parts: Uint8Array[] = []
  const [error0, encoded0] = encodeWorkPackageSpec(report.package_spec)
  if (error0) return safeError(error0)
  parts.push(encoded0)
  const [error1, encoded1] = encodeRefineContext(report.context)
  if (error1) return safeError(error1)
  parts.push(encoded1)
  const [error2, encoded2] = encodeNatural(report.core_index)
  if (error2) return safeError(error2)
  parts.push(encoded2)
  parts.push(hexToBytes(report.authorizer_hash))
  const [error3, encoded3] = encodeNatural(report.auth_gas_used)
  if (error3) return safeError(error3)
  parts.push(encoded3)
  const authOutputBytes = hexToBytes(report.auth_output)
  const [error4, encoded4] = encodeNatural(BigInt(authOutputBytes.length))
  if (error4) return safeError(error4)
  parts.push(encoded4)
  parts.push(authOutputBytes)
  const srLookupEntries = report.segment_root_lookup
  const [error5, encoded5] = encodeNatural(BigInt(srLookupEntries.length))
  if (error5) return safeError(error5)
  parts.push(encoded5)
  for (const entry of srLookupEntries) {
    parts.push(hexToBytes(entry.work_package_hash))
    parts.push(hexToBytes(entry.segment_tree_root))
  }
  const [error6, encoded6] = encodeNatural(BigInt(report.results.length))
  if (error6) return safeError(error6)
  parts.push(encoded6)
  for (const result of report.results) {
    const [error7, encoded7] = encodeWorkResult(result)
    if (error7) return safeError(error7)
    parts.push(encoded7)
  }
  return safeResult(concatBytes(parts))
}
