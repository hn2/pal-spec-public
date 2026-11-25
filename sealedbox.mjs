// Sealed box for the onion/2 vectors (section 15): ephemeral X25519, HKDF-SHA-384, ChaCha20-Poly1305. No BLAKE2b (Draft 0.6.12).
// Node built-ins only. Written for the conformance vectors; production code uses the implementation in pal-core.
import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, hkdfSync } from 'node:crypto';

const P = (1n << 255n) - 19n;
const leToBig = (b) => BigInt('0x' + (Buffer.from(b).reverse().toString('hex') || '0'));
const bigToLe = (n, len) => Buffer.from(n.toString(16).padStart(len * 2, '0'), 'hex').reverse();
const modPow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };

const ED_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const X_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X_SPKI = Buffer.from('302a300506032b656e032100', 'hex');

export function ed25519PublicKey(seed) {
  const key = createPrivateKey({ key: Buffer.concat([ED_PKCS8, seed]), format: 'der', type: 'pkcs8' });
  return createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
}

// Ed25519 public key to X25519 public key: u = (1 + y) / (1 - y) mod 2^255 - 19.
export function edPublicToX25519(edPk) {
  const y = leToBig(edPk) & ((1n << 255n) - 1n);
  return bigToLe((1n + y) * modPow((P + 1n - y) % P, P - 2n, P) % P, 32);
}

// Ed25519 seed to X25519 secret key: the first 32 bytes of SHA-512(seed), clamped.
export function edSeedToX25519(seed) {
  const h = createHash('sha512').update(seed).digest().subarray(0, 32);
  h[0] &= 248; h[31] &= 127; h[31] |= 64;
  return Buffer.from(h);
}

export function x25519PublicKey(sk) {
  const key = createPrivateKey({ key: Buffer.concat([X_PKCS8, sk]), format: 'der', type: 'pkcs8' });
  return createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
}

export function x25519(sk, pk) {
  return diffieHellman({
    privateKey: createPrivateKey({ key: Buffer.concat([X_PKCS8, sk]), format: 'der', type: 'pkcs8' }),
    publicKey: createPublicKey({ key: Buffer.concat([X_SPKI, pk]), format: 'der', type: 'spki' }),
  });
}

export const SEAL_BYTES = 48;
const INFO = Buffer.from('pal-sealed-box-v1');
const NONCE = Buffer.alloc(12);

function sealKey(shared, epk, recipientXPk) {
  if (shared.every((b) => b === 0)) return null;
  return Buffer.from(hkdfSync('sha384', shared, Buffer.concat([epk, recipientXPk]), INFO, 32));
}

// sealed = ephemeral public key (32) || ciphertext || tag (16)
export function seal(plain, recipientXPk, ephemeralSk) {
  const epk = x25519PublicKey(ephemeralSk);
  const key = sealKey(x25519(ephemeralSk, recipientXPk), epk, recipientXPk);
  if (!key) throw new Error('recipient public key is not usable');
  const cipher = createCipheriv('chacha20-poly1305', key, NONCE, { authTagLength: 16 });
  return Buffer.concat([epk, cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
}

export function sealOpen(box, recipientXSk) {
  if (box.length < SEAL_BYTES) return null;
  const recipientXPk = x25519PublicKey(recipientXSk);
  const epk = box.subarray(0, 32);
  let key;
  try { key = sealKey(x25519(recipientXSk, epk), epk, recipientXPk); } catch { return null; }
  if (!key) return null;
  const decipher = createDecipheriv('chacha20-poly1305', key, NONCE, { authTagLength: 16 });
  decipher.setAuthTag(box.subarray(box.length - 16));
  try {
    return Buffer.concat([decipher.update(box.subarray(32, box.length - 16)), decipher.final()]);
  } catch {
    return null;
  }
}
