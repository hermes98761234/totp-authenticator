import type { Account } from './otp'

export interface VaultFile { v: 1; iter: number; salt: string; iv: string; ct: string }

const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u))
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
export const DEFAULT_ITER = 600_000

async function deriveKey(password: string, salt: Uint8Array, iter: number): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations: iter }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

export async function encryptVault(accounts: Account[], password: string, iter = DEFAULT_ITER): Promise<VaultFile> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveKey(password, salt, iter)
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(accounts))))
  return { v: 1, iter, salt: b64(salt), iv: b64(iv), ct: b64(ct) }
}

export async function decryptVault(f: VaultFile, password: string): Promise<Account[]> {
  const key = await deriveKey(password, unb64(f.salt), f.iter)
  let pt: ArrayBuffer
  try {
    pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(f.iv) as BufferSource }, key, unb64(f.ct) as BufferSource)
  } catch {
    throw new Error('Wrong password or damaged vault')
  }
  return JSON.parse(new TextDecoder().decode(pt)) as Account[]
}
