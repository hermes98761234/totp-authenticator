import { describe, expect, it } from 'vitest'
import QRCode from 'qrcode'
import { base32Decode, base32Encode, buildOtpauth, codeFor, hotp, makeAccount, parseOtpauth, secondsLeft, totp } from './otp'
import { decodeMigration, encodeMigration } from './migration'
import { decryptVault, encryptVault } from './vault'
import { decodeQrPixels } from './qr'

const ascii = (s: string) => new TextEncoder().encode(s)

describe('base32', () => {
  it('matches RFC 4648 vectors', () => {
    expect(base32Encode(ascii('foobar'))).toBe('MZXW6YTBOI')
    expect(base32Encode(ascii('fo'))).toBe('MZXQ')
    expect(new TextDecoder().decode(base32Decode('MZXW6YTBOI======'))).toBe('foobar')
    expect(new TextDecoder().decode(base32Decode('mzxw 6ytb oi'))).toBe('foobar')
  })
  it('rejects invalid characters', () => {
    expect(() => base32Decode('AB1')).toThrow(/Invalid base32/)
  })
})

describe('HOTP (RFC 4226 appendix D)', () => {
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489']
  it('matches all ten reference values', async () => {
    const key = ascii('12345678901234567890')
    for (let i = 0; i < 10; i++) expect(await hotp(key, i)).toBe(expected[i])
  })
})

describe('TOTP (RFC 6238 appendix B)', () => {
  const k1 = ascii('12345678901234567890')
  const k256 = ascii('12345678901234567890123456789012')
  const k512 = ascii('1234567890123456789012345678901234567890123456789012345678901234')
  const rows: [number, string, string, string][] = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ]
  it('matches SHA1/SHA256/SHA512 vectors', async () => {
    for (const [t, a, b, c] of rows) {
      expect(await totp(k1, t, 30, 8, 'SHA1')).toBe(a)
      expect(await totp(k256, t, 30, 8, 'SHA256')).toBe(b)
      expect(await totp(k512, t, 30, 8, 'SHA512')).toBe(c)
    }
  })
  it('computes the countdown', () => {
    expect(secondsLeft(0, 30)).toBe(30)
    expect(secondsLeft(29_000, 30)).toBe(1)
    expect(secondsLeft(30_000, 30)).toBe(30)
  })
  it('codeFor uses account parameters', async () => {
    const a = makeAccount({ secret: base32Encode(k1), digits: 8 })
    expect(await codeFor(a, 59_000)).toBe('94287082')
  })
})

describe('otpauth URIs', () => {
  it('parses a full URI', () => {
    const a = parseOtpauth('otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60')
    expect(a).toMatchObject({ type: 'totp', issuer: 'ACME Co', name: 'john@example.com', algorithm: 'SHA256', digits: 8, period: 60, secret: 'HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ' })
  })
  it('takes the issuer from the label and defaults params', () => {
    const a = parseOtpauth('otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP')
    expect(a).toMatchObject({ issuer: 'GitHub', name: 'me', digits: 6, period: 30, algorithm: 'SHA1' })
  })
  it('round-trips through buildOtpauth', () => {
    const a = makeAccount({ issuer: 'A B', name: 'x@y.z', secret: 'JBSWY3DPEHPK3PXP', digits: 8, algorithm: 'SHA512', period: 45 })
    expect({ ...parseOtpauth(buildOtpauth(a)), id: '' }).toEqual({ ...a, id: '' })
    const h = makeAccount({ type: 'hotp', name: 'h', secret: 'JBSWY3DPEHPK3PXP', counter: 7 })
    expect({ ...parseOtpauth(buildOtpauth(h)), id: '' }).toEqual({ ...h, id: '' })
  })
  it('rejects bad input', () => {
    expect(() => parseOtpauth('https://example.com')).toThrow()
    expect(() => parseOtpauth('otpauth://totp/x')).toThrow(/secret/)
    expect(() => parseOtpauth('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=3')).toThrow()
    expect(() => parseOtpauth('otpauth://totp/x?secret=!!!')).toThrow()
  })
})

describe('Google Authenticator migration', () => {
  it('decodes a known export', () => {
    // Account "Example:alice@google.com", issuer Example, secret = "Hello!" + 0xDEADBEEF, SHA1, 6 digits, TOTP
    const uri = 'otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhABGAEgAA%3D%3D'
    const m = decodeMigration(uri)
    expect(m.accounts).toHaveLength(1)
    const a = m.accounts[0]
    expect(a).toMatchObject({ issuer: 'Example', name: 'alice@google.com', type: 'totp', digits: 6, algorithm: 'SHA1' })
    expect(a.secret).toBe(base32Encode(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef])))
  })
  it('round-trips several accounts', () => {
    const list = [
      makeAccount({ issuer: 'One', name: 'a', secret: 'JBSWY3DPEHPK3PXP' }),
      makeAccount({ issuer: 'Two', name: 'b', secret: 'MZXW6YTBOI', algorithm: 'SHA256', digits: 8 }),
      makeAccount({ issuer: 'Three', name: 'c', secret: 'MZXW6YTBOI', type: 'hotp', counter: 300 }),
    ]
    const back = decodeMigration(encodeMigration(list)).accounts
    expect(back.map((x) => ({ ...x, id: '' }))).toEqual(list.map((x) => ({ ...x, id: '' })))
  })
  it('rejects garbage', () => {
    expect(() => decodeMigration('otpauth-migration://offline?data=AAAA')).toThrow()
    expect(() => decodeMigration('otpauth-migration://offline')).toThrow()
  })
})

describe('vault', () => {
  it('encrypts and decrypts with the right password only', async () => {
    const list = [makeAccount({ issuer: 'X', name: 'y', secret: 'JBSWY3DPEHPK3PXP' })]
    const v = await encryptVault(list, 'hunter2', 1000)
    expect(JSON.stringify(v)).not.toContain('JBSWY3DPEHPK3PXP')
    expect(await decryptVault(v, 'hunter2')).toEqual(list)
    await expect(decryptVault(v, 'wrong')).rejects.toThrow(/Wrong password/)
  })
})

describe('QR decoding', () => {
  it('reads a rendered QR code with an otpauth URI', async () => {
    const text = 'otpauth://totp/Test:me?secret=JBSWY3DPEHPK3PXP&issuer=Test'
    const qr = QRCode.create(text, { errorCorrectionLevel: 'M' })
    const n = qr.modules.size
    const scale = 6
    const quiet = 4
    const W = (n + quiet * 2) * scale
    const px = new Uint8ClampedArray(W * W * 4).fill(255)
    for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) {
      if (!qr.modules.get(y, x)) continue
      for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) {
        const i = (((y + quiet) * scale + dy) * W + (x + quiet) * scale + dx) * 4
        px[i] = px[i + 1] = px[i + 2] = 0
      }
    }
    expect(decodeQrPixels(px, W, W)).toBe(text)
  })
})
