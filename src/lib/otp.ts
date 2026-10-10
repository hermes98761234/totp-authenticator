export type Algo = 'SHA1' | 'SHA256' | 'SHA512'
export interface Account {
  id: string
  type: 'totp' | 'hotp'
  issuer: string
  name: string
  secret: string // base32, no padding
  algorithm: Algo
  digits: number
  period: number
  counter: number
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function base32Decode(s: string): Uint8Array {
  const clean = s.toUpperCase().replace(/[\s=-]/g, '')
  let bits = 0
  let val = 0
  const out: number[] = []
  for (const ch of clean) {
    const i = B32.indexOf(ch)
    if (i < 0) throw new Error(`Invalid base32 character "${ch}"`)
    val = (val << 5) | i
    bits += 5
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8 }
  }
  return new Uint8Array(out)
}

export function base32Encode(data: Uint8Array): string {
  let bits = 0
  let val = 0
  let out = ''
  for (const b of data) {
    val = (val << 8) | b
    bits += 8
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5 }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31]
  return out
}

const HASH: Record<Algo, string> = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }

/** RFC 4226 HOTP. `counter` may exceed 2^32 (kept as BigInt-safe via two 32-bit halves). */
export async function hotp(secret: Uint8Array, counter: number, digits = 6, algo: Algo = 'SHA1'): Promise<string> {
  const buf = new ArrayBuffer(8)
  const dv = new DataView(buf)
  dv.setUint32(0, Math.floor(counter / 2 ** 32))
  dv.setUint32(4, counter >>> 0)
  const key = await crypto.subtle.importKey('raw', secret as BufferSource, { name: 'HMAC', hash: HASH[algo] }, false, ['sign'])
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf))
  const off = mac[mac.length - 1] & 0xf
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3]
  return String(bin % 10 ** digits).padStart(digits, '0')
}

/** RFC 6238 TOTP. `timeSec` is Unix time in seconds. */
export function totp(secret: Uint8Array, timeSec: number, period = 30, digits = 6, algo: Algo = 'SHA1', t0 = 0): Promise<string> {
  return hotp(secret, Math.floor((timeSec - t0) / period), digits, algo)
}

export async function codeFor(a: Account, nowMs: number): Promise<string> {
  const key = base32Decode(a.secret)
  return a.type === 'totp' ? totp(key, nowMs / 1000, a.period, a.digits, a.algorithm) : hotp(key, a.counter, a.digits, a.algorithm)
}

export const secondsLeft = (nowMs: number, period: number) => period - (Math.floor(nowMs / 1000) % period)

let seq = 0
export const newId = () => `${Date.now().toString(36)}-${(seq++).toString(36)}-${Math.random().toString(36).slice(2, 6)}`

export function makeAccount(p: Partial<Account> & { secret: string }): Account {
  const secret = p.secret.toUpperCase().replace(/[\s=-]/g, '')
  base32Decode(secret) // validates
  if (secret.length === 0) throw new Error('Secret is empty')
  return {
    id: p.id ?? newId(), type: p.type ?? 'totp', issuer: p.issuer ?? '', name: p.name ?? '', secret,
    algorithm: p.algorithm ?? 'SHA1', digits: p.digits ?? 6, period: p.period ?? 30, counter: p.counter ?? 0,
  }
}

/** Parses an otpauth://totp|hotp/Label?secret=... URI. */
export function parseOtpauth(uri: string): Account {
  let u: URL
  try { u = new URL(uri.trim()) } catch { throw new Error('Not a valid URI') }
  if (u.protocol !== 'otpauth:') throw new Error('Not an otpauth:// URI')
  const type = u.hostname.toLowerCase()
  if (type !== 'totp' && type !== 'hotp') throw new Error(`Unsupported type "${type}"`)
  const label = decodeURIComponent(u.pathname.replace(/^\//, ''))
  let issuer = u.searchParams.get('issuer') ?? ''
  let name = label
  const ci = label.indexOf(':')
  if (ci >= 0) {
    const li = label.slice(0, ci).trim()
    name = label.slice(ci + 1).trim()
    if (!issuer) issuer = li
  }
  const secret = u.searchParams.get('secret')
  if (!secret) throw new Error('Missing secret')
  const algo = (u.searchParams.get('algorithm') ?? 'SHA1').toUpperCase().replace('SHA-', 'SHA')
  if (algo !== 'SHA1' && algo !== 'SHA256' && algo !== 'SHA512') throw new Error(`Unsupported algorithm "${algo}"`)
  const digits = Number(u.searchParams.get('digits') ?? 6)
  if (!(digits >= 6 && digits <= 10)) throw new Error('Digits must be 6 to 10')
  const period = Number(u.searchParams.get('period') ?? 30)
  if (!(period > 0)) throw new Error('Bad period')
  return makeAccount({ type, issuer, name, secret, algorithm: algo, digits, period, counter: Number(u.searchParams.get('counter') ?? 0) })
}

export function buildOtpauth(a: Account): string {
  const label = (a.issuer ? `${encodeURIComponent(a.issuer)}:` : '') + encodeURIComponent(a.name)
  const q = new URLSearchParams({ secret: a.secret })
  if (a.issuer) q.set('issuer', a.issuer)
  if (a.algorithm !== 'SHA1') q.set('algorithm', a.algorithm)
  if (a.digits !== 6) q.set('digits', String(a.digits))
  if (a.type === 'totp' && a.period !== 30) q.set('period', String(a.period))
  if (a.type === 'hotp') q.set('counter', String(a.counter))
  return `otpauth://${a.type}/${label}?${q.toString()}`
}

export const groupDigits = (code: string) => (code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code.length === 8 ? `${code.slice(0, 4)} ${code.slice(4)}` : code)
