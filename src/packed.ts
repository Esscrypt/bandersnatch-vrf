const FORMAT_VERSION = 0x01
const RING_COMMITMENT_LEN = 144
const RING_KEY_COMMITMENT_LEN = 32

export type PackedBvrfRingPrepareOutput = {
  handle: number
  commitment: Uint8Array
}

export type PackedBvrfBatchVerifyItem = {
  proof: Uint8Array
  keyCommitment: Uint8Array
}

export type PackedBvrfIetfVerifyRequest = {
  publicKey: Uint8Array
  input: Uint8Array
  proof: Uint8Array
  aux: Uint8Array
}

class Writer {
  private readonly bytes: number[] = [FORMAT_VERSION]

  u8(value: number): void {
    this.bytes.push(value & 0xff)
  }

  u32(value: number): void {
    this.bytes.push(
      value & 0xff,
      (value >>> 8) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 24) & 0xff,
    )
  }

  blob(value: Uint8Array): void {
    this.u32(value.length)
    for (let i = 0; i < value.length; i++) this.bytes.push(value[i] ?? 0)
  }

  utf8(value: string): void {
    this.blob(new TextEncoder().encode(value))
  }

  raw(value: Uint8Array): void {
    for (let i = 0; i < value.length; i++) this.bytes.push(value[i] ?? 0)
  }

  finish(): Uint8Array {
    return new Uint8Array(this.bytes)
  }
}

class Reader {
  private readonly view: DataView
  private pos = 0

  constructor(private readonly data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength)
    const version = this.u8()
    if (version !== FORMAT_VERSION) {
      throw new Error(`unsupported packed format version ${version}`)
    }
  }

  private need(n: number): void {
    if (this.pos + n > this.data.length) {
      throw new Error('malformed packed payload: truncated')
    }
  }

  u8(): number {
    this.need(1)
    const value = this.view.getUint8(this.pos)
    this.pos += 1
    return value
  }

  u32(): number {
    this.need(4)
    const value = this.view.getUint32(this.pos, true)
    this.pos += 4
    return value
  }

  blob(): Uint8Array {
    const length = this.u32()
    this.need(length)
    const value = this.data.slice(this.pos, this.pos + length)
    this.pos += length
    return value
  }

  utf8(): string {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(this.blob())
    } catch {
      throw new Error('malformed packed payload: invalid utf-8')
    }
  }

  raw(length: number): Uint8Array {
    this.need(length)
    const value = this.data.slice(this.pos, this.pos + length)
    this.pos += length
    return value
  }

  finish(): void {
    if (this.pos !== this.data.length) {
      throw new Error('malformed packed payload: trailing bytes')
    }
  }
}

export function encodeBvrfSrsOpenRequest(path: string): Uint8Array {
  const writer = new Writer()
  writer.utf8(path)
  return writer.finish()
}

export function decodeBvrfSrsOpenRequest(bytes: Uint8Array): string {
  const reader = new Reader(bytes)
  const path = reader.utf8()
  reader.finish()
  return path
}

export function encodeBvrfSrsOpenOutput(handle: number): Uint8Array {
  const writer = new Writer()
  writer.u32(handle)
  return writer.finish()
}

export function decodeBvrfSrsOpenOutput(bytes: Uint8Array): number {
  const reader = new Reader(bytes)
  const handle = reader.u32()
  reader.finish()
  return handle
}

export function encodeBvrfRingPrepareRequest(ringKeys: Uint8Array): Uint8Array {
  const writer = new Writer()
  writer.blob(ringKeys)
  return writer.finish()
}

export function decodeBvrfRingPrepareRequest(bytes: Uint8Array): Uint8Array {
  const reader = new Reader(bytes)
  const ringKeys = reader.blob()
  reader.finish()
  return ringKeys
}

export function encodeBvrfRingPrepareOutput(
  handle: number,
  commitment: Uint8Array,
): Uint8Array {
  if (commitment.length !== RING_COMMITMENT_LEN) {
    throw new Error(
      `malformed packed payload: ring commitment must be ${RING_COMMITMENT_LEN} bytes, got ${commitment.length}`,
    )
  }
  const writer = new Writer()
  writer.u32(handle)
  writer.raw(commitment)
  return writer.finish()
}

export function decodeBvrfRingPrepareOutput(
  bytes: Uint8Array,
): PackedBvrfRingPrepareOutput {
  const reader = new Reader(bytes)
  const output = {
    handle: reader.u32(),
    commitment: reader.raw(RING_COMMITMENT_LEN),
  }
  reader.finish()
  return output
}

export function encodeBvrfBatchVerifyItems(
  items: PackedBvrfBatchVerifyItem[],
): Uint8Array {
  const writer = new Writer()
  writer.u32(items.length)
  for (const item of items) {
    if (item.keyCommitment.length !== RING_KEY_COMMITMENT_LEN) {
      throw new Error(
        `malformed packed payload: key commitment must be ${RING_KEY_COMMITMENT_LEN} bytes, got ${item.keyCommitment.length}`,
      )
    }
    writer.blob(item.proof)
    writer.raw(item.keyCommitment)
  }
  return writer.finish()
}

export function decodeBvrfBatchVerifyItems(
  bytes: Uint8Array,
): PackedBvrfBatchVerifyItem[] {
  const reader = new Reader(bytes)
  const count = reader.u32()
  const items: PackedBvrfBatchVerifyItem[] = []
  for (let i = 0; i < count; i++) {
    items.push({
      proof: reader.blob(),
      keyCommitment: reader.raw(RING_KEY_COMMITMENT_LEN),
    })
  }
  reader.finish()
  return items
}

export function encodeBvrfIetfVerifyRequest(
  request: PackedBvrfIetfVerifyRequest,
): Uint8Array {
  const writer = new Writer()
  writer.blob(request.publicKey)
  writer.blob(request.input)
  writer.blob(request.proof)
  writer.blob(request.aux)
  return writer.finish()
}

export function decodeBvrfIetfVerifyRequest(
  bytes: Uint8Array,
): PackedBvrfIetfVerifyRequest {
  const reader = new Reader(bytes)
  const request = {
    publicKey: reader.blob(),
    input: reader.blob(),
    proof: reader.blob(),
    aux: reader.blob(),
  }
  reader.finish()
  return request
}

export function encodeBvrfValidity(valid: boolean): Uint8Array {
  const writer = new Writer()
  writer.u8(valid ? 1 : 0)
  return writer.finish()
}

export function decodeBvrfValidity(bytes: Uint8Array): boolean {
  const reader = new Reader(bytes)
  const flag = reader.u8()
  reader.finish()
  if (flag === 0) return false
  if (flag === 1) return true
  throw new Error(`malformed packed payload: invalid validity byte ${flag}`)
}

export function encodeBvrfLastError(message: string): Uint8Array {
  const writer = new Writer()
  writer.utf8(message)
  return writer.finish()
}

export function decodeBvrfLastError(bytes: Uint8Array): string {
  const reader = new Reader(bytes)
  const message = reader.utf8()
  reader.finish()
  return message
}
