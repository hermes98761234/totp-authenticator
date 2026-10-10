import { base32Decode, base32Encode, makeAccount, type Account, type Algo } from './otp'

/** Minimal protobuf reader/writer for Google Authenticator's otpauth-migration payload. */

class Reader {
  pos = 0
  b: Uint8Array
  constructor(b: Uint8Array) { this.b = b }
  get done() { return this.pos >= this.b.length }
  varint(): number {
    let r = 0
    let mul = 1
    for (;;) {
      if (this.pos >= this.b.length) throw new Error('Truncated protobuf')
      const x = this.b[this.pos++]
      r += (x & 0x7f) * mul
      if (!(x & 0x80)) return r
      mul *= 128
      if (mul > 2 ** 63) throw new Error('Varint too long')
    }
  }
  bytes(): Uint8Array {
    const n = this.varint()
    if (this.pos + n > this.b.length) throw new Error('Truncated protobuf')
    const out = this.b.subarray(this.pos, this.pos + n)
    this.pos += n
    return out
  }
  skip(wire: number) {
    if (wire === 0) this.varint()
    else if (wire === 1) this.pos += 8
    else if (wire === 2) this.bytes()
    else if (wire === 5) this.pos += 4
    else throw new Error(`Unsupported wire type ${wire}`)
  }
}

const ALGOS: Record<number, Algo> = { 0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' }

function parseParams(b: Uint8Array): Account {
  const r = new Reader(b)
  let secret = new Uint8Array()
  let name = ''
  let issuer = ''
  let algo = 1
  let digits = 1
  let type = 2
  let counter = 0
  const td = new TextDecoder()
  while (!r.done) {
    const tag = r.varint()
    const f = tag >> 3
    const w = tag & 7
    if (f === 1 && w === 2) secret = new Uint8Array(r.bytes())
    else if (f === 2 && w === 2) name = td.decode(r.bytes())
    else if (f === 3 && w === 2) issuer = td.decode(r.bytes())
    else if (f === 4 && w === 0) algo = r.varint()
    else if (f === 5 && w === 0) digits = r.varint()
    else if (f === 6 && w === 0) type = r.varint()
    else if (f === 7 && w === 0) counter = r.varint()
    else r.skip(w)
  }
  if (algo === 4) throw new Error('MD5 accounts are not supported')
  const ci = name.indexOf(':')
  if (ci >= 0 && (!issuer || name.slice(0, ci).trim() === issuer)) { issuer = name.slice(0, ci).trim(); name = name.slice(ci + 1).trim() }
  return makeAccount({ secret: base32Encode(secret), name, issuer, algorithm: ALGOS[algo] ?? 'SHA1', digits: digits === 2 ? 8 : 6, type: type === 1 ? 'hotp' : 'totp', counter })
}

export interface Migration { accounts: Account[]; batchIndex: number; batchSize: number }

export function decodeMigration(uriOrData: string): Migration {
  let data = uriOrData.trim()
  if (data.startsWith('otpauth-migration:')) {
    const u = new URL(data)
    const d = u.searchParams.get('data')
    if (!d) throw new Error('Missing data parameter')
    data = d
  }
  data = data.replace(/ /g, '+').replaceAll('-', '+').replaceAll('_', '/')
  let bin: string
  try { bin = atob(data) } catch { throw new Error('Invalid base64 data') }
  const r = new Reader(Uint8Array.from(bin, (c) => c.charCodeAt(0)))
  const accounts: Account[] = []
  let batchSize = 1
  let batchIndex = 0
  while (!r.done) {
    const tag = r.varint()
    const f = tag >> 3
    const w = tag & 7
    if (f === 1 && w === 2) accounts.push(parseParams(r.bytes()))
    else if (f === 3 && w === 0) batchSize = r.varint()
    else if (f === 4 && w === 0) batchIndex = r.varint()
    else r.skip(w)
  }
  if (accounts.length === 0) throw new Error('No accounts found in migration data')
  return { accounts, batchIndex, batchSize }
}

// ---- encoder (used for tests and for exporting back to Google Authenticator) ----
const varint = (n: number): number[] => {
  const o: number[] = []
  while (n >= 128) { o.push((n % 128) | 0x80); n = Math.floor(n / 128) }
  o.push(n)
  return o
}
const field = (f: number, payload: Uint8Array | number[]): number[] => [...varint((f << 3) | 2), ...varint(payload.length), ...payload]
const num = (f: number, n: number): number[] => [...varint(f << 3), ...varint(n)]
export function encodeMigration(accounts: Account[]): string {
  const te = new TextEncoder()
  const out: number[] = []
  for (const a of accounts) {
    const p = [
      ...field(1, base32Decode(a.secret)), ...field(2, te.encode(a.name)), ...field(3, te.encode(a.issuer)),
      ...num(4, a.algorithm === 'SHA256' ? 2 : a.algorithm === 'SHA512' ? 3 : 1), ...num(5, a.digits === 8 ? 2 : 1),
      ...num(6, a.type === 'hotp' ? 1 : 2), ...(a.type === 'hotp' ? num(7, a.counter) : []),
    ]
    out.push(...field(1, p))
  }
  out.push(...num(2, 1), ...num(3, 1), ...num(4, 0))
  return 'otpauth-migration://offline?data=' + encodeURIComponent(btoa(String.fromCharCode(...out)))
}
