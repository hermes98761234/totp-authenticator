import { useCallback, useEffect, useRef, useState } from 'react'
import { CopyButton, Shell, usePrefs } from './kit'
import { UK } from './uk'
import type { T } from './i18n'
import { buildOtpauth, codeFor, groupDigits, makeAccount, parseOtpauth, secondsLeft, type Account } from './lib/otp'
import { decodeMigration, encodeMigration } from './lib/migration'
import { decodeQrFromImage } from './lib/qr'
import { decryptVault, encryptVault, type VaultFile } from './lib/vault'

const REPO = 'totp-authenticator'
const VKEY = 'totp-vault-v1'

const loadVault = (): VaultFile | null => {
  try { return JSON.parse(localStorage.getItem(VKEY) ?? 'null') as VaultFile | null } catch { return null }
}

const demo = (t: T): Account => makeAccount({ issuer: 'Example', name: t('Demo account (RFC example secret)'), secret: 'JBSWY3DPEHPK3PXP' })

function Row({ a, now, onDelete, onNext, t }: { a: Account; now: number; onDelete: () => void; onNext: () => void; t: T }) {
  const [code, setCode] = useState('')
  const step = a.type === 'totp' ? Math.floor(now / 1000 / a.period) : a.counter
  useEffect(() => {
    let live = true
    void codeFor(a, step * a.period * 1000).then((c) => { if (live) setCode(c) })
    return () => { live = false }
  }, [a, step])
  const left = secondsLeft(now, a.period)
  const frac = a.type === 'totp' ? left / a.period : 1
  return (
    <div className="acct">
      <div className="acct-info">
        <strong>{a.issuer || a.name}</strong>
        <span className="hint" style={{ margin: 0 }}>{a.issuer ? a.name : ''}</span>
      </div>
      <div className="code mono" aria-live="off">{code ? groupDigits(code) : '…'}</div>
      {a.type === 'totp' ? (
        <div className="ring" title={`${left}s`} style={{ ['--p' as string]: `${frac * 360}deg`, color: left <= 5 ? 'var(--err)' : 'var(--accent)' }}><span>{left}</span></div>
      ) : (
        <button className="small" onClick={onNext}>{t('Next code')} ({t('Counter: {0}', a.counter)})</button>
      )}
      <CopyButton text={code} t={t} />
      <button className="small danger" onClick={() => { if (confirm(t('Delete this account?'))) onDelete() }}>{t('Delete')}</button>
    </div>
  )
}

export default function App() {
  const { prefs, setPrefs, t } = usePrefs(UK)
  const [vault, setVault] = useState<VaultFile | null>(loadVault)
  const [accounts, setAccounts] = useState<Account[]>(() => (loadVault() ? [] : [demo((s) => s)]))
  const [locked, setLocked] = useState(() => loadVault() !== null)
  const [password, setPassword] = useState('')
  const [pw, setPw] = useState('') // password kept in memory while unlocked, to re-encrypt on change
  const [now, setNow] = useState(() => Date.now())
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [paste, setPaste] = useState('')
  const [man, setMan] = useState({ issuer: '', name: '', secret: '', algorithm: 'SHA1', digits: 6, period: 30, type: 'totp' })
  const [exp, setExp] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => { const i = setInterval(() => setNow(Date.now()), 500); return () => clearInterval(i) }, [])

  const persist = useCallback(async (list: Account[], p: string) => {
    if (!p) return
    const f = await encryptVault(list, p)
    localStorage.setItem(VKEY, JSON.stringify(f))
    setVault(f)
  }, [])

  const update = (list: Account[]) => { setAccounts(list); void persist(list, pw) }

  function add(list: Account[]) {
    update([...accounts, ...list])
    setMsg({ ok: true, text: t('Added {0} account(s).', list.length) })
  }
  const fail = (e: unknown) => setMsg({ ok: false, text: t('Error: {0}', t(e instanceof Error ? e.message : String(e))) })

  function importText(text: string) {
    try {
      const s = text.trim()
      if (s.startsWith('otpauth-migration:')) add(decodeMigration(s).accounts)
      else add(s.split(/\s+/).filter(Boolean).map(parseOtpauth))
      setPaste('')
    } catch (e) { fail(e) }
  }

  async function onImage(f: File | undefined) {
    if (!f) return
    try {
      const text = await decodeQrFromImage(f)
      if (!text) throw new Error('No QR code found in the image.')
      importText(text)
    } catch (e) { fail(e) }
    if (fileRef.current) fileRef.current.value = ''
  }

  async function createVault() {
    if (password.length < 8) return setMsg({ ok: false, text: t('Password must be at least 8 characters.') })
    setBusy(true)
    await new Promise((r) => setTimeout(r, 20))
    await persist(accounts, password)
    setPw(password); setPassword(''); setBusy(false); setMsg(null)
  }
  async function unlock() {
    if (!vault) return
    setBusy(true)
    await new Promise((r) => setTimeout(r, 20))
    try {
      setAccounts(await decryptVault(vault, password))
      setPw(password); setPassword(''); setLocked(false); setMsg(null)
    } catch (e) { fail(e) }
    setBusy(false)
  }
  const lock = () => { setAccounts([]); setPw(''); setLocked(true); setExp('') }

  const unlocked = !!vault && !locked

  return (
    <Shell title={t('TOTP Authenticator')} tagline={t('Two-factor codes (RFC 6238 / 4226) generated in your browser, with an encrypted local vault.')} repo={REPO} note={t('Secrets never leave this device. Without a vault they live only in this tab; the vault stores them AES-GCM encrypted.')} t={t} prefs={prefs} setPrefs={setPrefs}>
      <div className="cols">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="box">
            <h2>{t('Accounts')}</h2>
            {locked ? (
              <>
                <p className="hint">{t('Vault is locked')}</p>
                <form className="row" onSubmit={(e) => { e.preventDefault(); void unlock() }}>
                  <input type="password" autoComplete="current-password" placeholder={t('Password')} value={password} onChange={(e) => setPassword(e.target.value)} />
                  <button className="primary" disabled={busy}>{busy ? t('Working…') : t('Unlock')}</button>
                </form>
                {msg && <p className={msg.ok ? 'ok-text' : 'err-text'}>{msg.text}</p>}
                <button className="small danger" onClick={() => { if (confirm(t('Delete the encrypted vault from this browser?'))) { localStorage.removeItem(VKEY); setVault(null); setLocked(false); setAccounts([]) } }}>{t('Delete vault')}</button>
              </>
            ) : accounts.length === 0 ? (
              <p className="hint">{t('No accounts yet. Add one below.')}</p>
            ) : (
              accounts.map((a, i) => (
                <Row key={a.id} a={a} now={now} t={t}
                  onDelete={() => update(accounts.filter((_, j) => j !== i))}
                  onNext={() => update(accounts.map((x, j) => (j === i ? { ...x, counter: x.counter + 1 } : x)))} />
              ))
            )}
          </div>
          <div className="box">
            <h2>{t('Vault')}</h2>
            {unlocked ? (
              <div className="row"><span className="ok-text">{t('Unlocked. Changes are saved encrypted.')}</span><span className="spacer" /><button onClick={lock}>{t('Lock')}</button></div>
            ) : !locked ? (
              <>
                <p className="hint">{t('Not saved: accounts live only in this tab.')}</p>
                <form className="row" onSubmit={(e) => { e.preventDefault(); void createVault() }}>
                  <input type="password" autoComplete="new-password" placeholder={t('Password')} value={password} onChange={(e) => setPassword(e.target.value)} />
                  <button className="primary" disabled={busy}>{busy ? t('Working…') : t('Create vault')}</button>
                </form>
              </>
            ) : <p className="hint">{t('Unlock to see codes')}</p>}
            {unlocked && <button className="small danger" onClick={() => { if (confirm(t('Delete the encrypted vault from this browser?'))) { localStorage.removeItem(VKEY); setVault(null); setPw('') } }}>{t('Delete vault')}</button>}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {!locked && (
            <>
              <div className="box">
                <h2>{t('Add account')}</h2>
                <div className="field">
                  <label>{t('otpauth:// URI or migration link')}</label>
                  <textarea className="mono" rows={3} value={paste} placeholder={t('Paste otpauth://… or otpauth-migration://…')} onChange={(e) => setPaste(e.target.value)} />
                </div>
                <div className="row">
                  <button className="primary" disabled={!paste.trim()} onClick={() => importText(paste)}>{t('Import')}</button>
                  <button onClick={() => fileRef.current?.click()}>{t('Import from QR image')}</button>
                  <input ref={fileRef} type="file" accept="image/*" hidden onChange={(e) => void onImage(e.target.files?.[0])} />
                </div>
                {msg && <p className={msg.ok ? 'ok-text' : 'err-text'} role="status">{msg.text}</p>}
              </div>
              <div className="box">
                <h2>{t('Manual entry')}</h2>
                <div className="grid2">
                  <div className="field"><label>{t('Issuer')}</label><input type="text" value={man.issuer} onChange={(e) => setMan({ ...man, issuer: e.target.value })} /></div>
                  <div className="field"><label>{t('Account')}</label><input type="text" value={man.name} onChange={(e) => setMan({ ...man, name: e.target.value })} /></div>
                </div>
                <div className="field"><label>{t('Secret (base32)')}</label><input type="text" className="mono" value={man.secret} onChange={(e) => setMan({ ...man, secret: e.target.value })} /></div>
                <div className="grid3">
                  <div className="field"><label>{t('Algorithm')}</label><select value={man.algorithm} onChange={(e) => setMan({ ...man, algorithm: e.target.value })}><option>SHA1</option><option>SHA256</option><option>SHA512</option></select></div>
                  <div className="field"><label>{t('Digits')}</label><select value={man.digits} onChange={(e) => setMan({ ...man, digits: +e.target.value })}><option value={6}>6</option><option value={7}>7</option><option value={8}>8</option></select></div>
                  <div className="field"><label>{t('Period (s)')}</label><input type="number" min={1} value={man.period} onChange={(e) => setMan({ ...man, period: +e.target.value || 30 })} /></div>
                </div>
                <div className="row">
                  <select value={man.type} onChange={(e) => setMan({ ...man, type: e.target.value })}><option value="totp">TOTP</option><option value="hotp">HOTP</option></select>
                  <button className="primary" onClick={() => {
                    try { add([makeAccount({ ...man, algorithm: man.algorithm as Account['algorithm'], type: man.type as Account['type'] })]); setMan({ ...man, secret: '' }) } catch (e) { fail(e) }
                  }}>{t('Add')}</button>
                </div>
              </div>
              <div className="box">
                <h2>{t('Backup')}</h2>
                <div className="row">
                  <button disabled={!accounts.length} onClick={() => setExp(accounts.map(buildOtpauth).join('\n'))}>{t('Export otpauth:// URIs')}</button>
                  <button disabled={!accounts.length} onClick={() => setExp(encodeMigration(accounts))}>{t('Export Google Authenticator migration link')}</button>
                </div>
                {exp && (<><pre>{exp}</pre><div className="row"><CopyButton text={exp} t={t} /></div><p className="warn-text hint">{t('Keep exported links private: they contain your secrets.')}</p></>)}
              </div>
            </>
          )}
        </div>
      </div>
    </Shell>
  )
}
