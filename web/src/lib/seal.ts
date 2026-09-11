// Seals a secret to one box: X25519 (ephemeral key against the box's seal key),
// HKDF-SHA256, AES-256-GCM. Mirrors internal/seal in Go byte for byte; the Go test
// opens a blob this code produced. The server only ever relays the result.
//
// Blob (base64): ephemeral public key (32) || nonce (12) || ciphertext with tag.

const INFO = "excubra-seal-v1"
const enc = new TextEncoder()

type Bytes = Uint8Array<ArrayBuffer>
function bytes(n: number): Bytes { return new Uint8Array(new ArrayBuffer(n)) }
export function b64(b: Uint8Array): string { let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s) }
function unb64(s: string): Bytes { const bin = atob(s); const out = bytes(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out }
function concat(...parts: Uint8Array[]): Bytes { const n = parts.reduce((a, p) => a + p.length, 0); const out = bytes(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length } return out }

// sealFor encrypts plaintext for the box whose seal key (base64) is given.
export async function sealFor(boxPublicB64: string, plaintext: string): Promise<string> {
  const recipient = unb64(boxPublicB64)
  if (recipient.length !== 32) throw new Error("Der Siegelschlüssel der Box ist ungültig.")
  if (!globalThis.crypto?.subtle) throw new Error("Dieser Browser hat kein WebCrypto; HTTPS nötig.")
  let boxKey: CryptoKey, eph: CryptoKeyPair
  try {
    boxKey = await crypto.subtle.importKey("raw", recipient, { name: "X25519" }, false, [])
    eph = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair
  } catch {
    throw new Error("Dieser Browser kann kein X25519 (Chrome 133+, Safari 17+, Firefox 130+).")
  }
  const ephPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey))
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: boxKey }, eph.privateKey, 256)
  const hk = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"])
  const aes = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: concat(ephPub, recipient), info: enc.encode(INFO) }, hk, { name: "AES-GCM", length: 256 }, false, ["encrypt"])
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(INFO) }, aes, enc.encode(plaintext)))
  return b64(concat(ephPub, nonce, ct))
}

// fingerprint is what a person compares with the box: sha256 of the key, 16 hex chars in groups of four.
export async function fingerprint(boxPublicB64: string): Promise<string> {
  let raw: Bytes
  try { raw = unb64(boxPublicB64) } catch { return "" }
  if (raw.length !== 32) return ""
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", raw))
  const hex = Array.from(h.slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("")
  return `${hex.slice(0, 4)} ${hex.slice(4, 8)} ${hex.slice(8, 12)} ${hex.slice(12, 16)}`
}
