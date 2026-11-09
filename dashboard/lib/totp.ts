// Node-only TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) for two-factor sign-in,
// plus base32 (RFC 4648) and recovery codes. Compatible with Google/Microsoft
// Authenticator, Authy, 1Password, Bitwarden, etc.
import { createHmac, randomBytes, createHash, timingSafeEqual } from 'node:crypto'

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = ''
  for (const byte of buf) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5 }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return out
}
export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/[\s=-]/g, '')
  let bits = 0, value = 0
  const out: number[] = []
  for (const ch of clean) {
    const i = B32.indexOf(ch)
    if (i < 0) throw new Error('invalid base32')
    value = (value << 5) | i
    bits += 5
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8 }
  }
  return Buffer.from(out)
}

export const PERIOD = 30
export const newSecret = () => base32Encode(randomBytes(20)) // 160-bit, as RFC 4226 recommends

export function hotp(secret: Buffer, counter: number, digits = 6): string {
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(counter))
  const h = createHmac('sha1', secret).update(msg).digest()
  const off = h[h.length - 1] & 0xf
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]
  return String(bin % 10 ** digits).padStart(digits, '0')
}

export const currentStep = (nowMs = Date.now()) => Math.floor(nowMs / 1000 / PERIOD)

// Verify a 6-digit code against steps now-1 … now+1 (allows ±30 s clock drift).
// Returns the matched step, or null. Steps <= lastStep are refused, so a code
// can never be used twice (replay protection).
export function verifyTotp(secretB32: string, code: string, lastStep = 0, nowMs = Date.now()): number | null {
  const c = code.replace(/\s/g, '')
  if (!/^\d{6}$/.test(c)) return null
  const key = base32Decode(secretB32)
  const now = currentStep(nowMs)
  for (const step of [now, now - 1, now + 1]) {
    if (step <= lastStep) continue
    const want = Buffer.from(hotp(key, step))
    if (timingSafeEqual(want, Buffer.from(c))) return step
  }
  return null
}

export function otpauthUri(secretB32: string, account: string, issuer = 'xdp-sentinel'): string {
  const label = encodeURIComponent(`${issuer}:${account}`)
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${PERIOD}`
}

// Recovery codes: 10 one-time codes like "k7m2-9xq4-p3d8" (~60 bits each). Only
// their SHA-256 hashes are stored; each works once.
const RC = 'abcdefghjkmnpqrstuvwxyz23456789'
export function newRecoveryCodes(n = 10): string[] {
  return Array.from({ length: n }, () => {
    const b = randomBytes(12)
    const s = Array.from(b, (x) => RC[x % RC.length]).join('')
    return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`
  })
}
export const normRecovery = (code: string) => code.toLowerCase().replace(/[^a-z0-9]/g, '')
export const hashRecovery = (code: string) => createHash('sha256').update(normRecovery(code)).digest('hex')
export const looksLikeRecovery = (code: string) => normRecovery(code).length === 12
