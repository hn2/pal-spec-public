// Sealed box (X25519, XSalsa20-Poly1305, nonce = BLAKE2b-24 of ephemeral key and recipient key) for the onion/2 vectors (section 15).
// Node built-ins and the repository's BLAKE2b only. Written for the conformance vectors: it is not constant-time and is not for production use.
import { createHash, createPrivateKey, createPublicKey, diffieHellman } from 'node:crypto';
import { blake2b } from './blake2b.mjs';

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

function x25519(sk, pk) {
  return diffieHellman({
    privateKey: createPrivateKey({ key: Buffer.concat([X_PKCS8, sk]), format: 'der', type: 'pkcs8' }),
    publicKey: createPublicKey({ key: Buffer.concat([X_SPKI, pk]), format: 'der', type: 'spki' }),
  });
}

const SIGMA = Buffer.from('expand 32-byte k', 'ascii');
const rotl = (v, c) => ((v << c) | (v >>> (32 - c))) >>> 0;

function salsaRounds(x) {
  const q = (a, b, c, d) => {
    x[b] ^= rotl((x[a] + x[d]) >>> 0, 7);
    x[c] ^= rotl((x[b] + x[a]) >>> 0, 9);
    x[d] ^= rotl((x[c] + x[b]) >>> 0, 13);
    x[a] ^= rotl((x[d] + x[c]) >>> 0, 18);
  };
  for (let i = 0; i < 10; i++) {
    q(0, 4, 8, 12); q(5, 9, 13, 1); q(10, 14, 2, 6); q(15, 3, 7, 11);
    q(0, 1, 2, 3); q(5, 6, 7, 4); q(10, 11, 8, 9); q(15, 12, 13, 14);
  }
}

function salsaState(key, in16) {
  const x = new Uint32Array(16);
  const w = (b, o) => b.readUInt32LE(o);
  x[0] = w(SIGMA, 0); x[5] = w(SIGMA, 4); x[10] = w(SIGMA, 8); x[15] = w(SIGMA, 12);
  for (let i = 0; i < 4; i++) { x[1 + i] = w(key, i * 4); x[11 + i] = w(key, 16 + i * 4); x[6 + i] = w(in16, i * 4); }
  return x;
}

function hsalsa20(key, in16) {
  const x = salsaState(key, in16);
  salsaRounds(x);
  const out = Buffer.alloc(32);
  [0, 5, 10, 15, 6, 7, 8, 9].forEach((idx, i) => out.writeUInt32LE(x[idx], i * 4));
  return out;
}

function salsa20Stream(key, nonce8, length) {
  const out = Buffer.alloc(Math.ceil(length / 64) * 64);
  const in16 = Buffer.alloc(16);
  nonce8.copy(in16);
  for (let block = 0; block * 64 < length; block++) {
    in16.writeBigUInt64LE(BigInt(block), 8);
    const init = salsaState(key, in16);
    const x = Uint32Array.from(init);
    salsaRounds(x);
    for (let i = 0; i < 16; i++) out.writeUInt32LE((x[i] + init[i]) >>> 0, block * 64 + i * 4);
  }
  return out.subarray(0, length);
}

function poly1305(key, msg) {
  const r = leToBig(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const s = leToBig(key.subarray(16, 32));
  const p = (1n << 130n) - 5n;
  let acc = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    const block = msg.subarray(i, i + 16);
    acc = (acc + leToBig(block) + (1n << BigInt(8 * block.length))) * r % p;
  }
  return bigToLe((acc + s) & ((1n << 128n) - 1n), 16);
}

function boxKeys(shared, nonce24) {
  const subkey = hsalsa20(hsalsa20(shared, Buffer.alloc(16)), nonce24.subarray(0, 16));
  return (length) => salsa20Stream(subkey, nonce24.subarray(16, 24), 32 + length);
}

export const SEAL_BYTES = 48;

// Output: [ephemeral X25519 public key: 32][Poly1305 tag: 16][ciphertext]. ephemeralSk is random in real use.
export function seal(plain, recipientXPk, ephemeralSk) {
  const epk = x25519PublicKey(ephemeralSk);
  const stream = boxKeys(x25519(ephemeralSk, recipientXPk), blake2b(Buffer.concat([epk, recipientXPk]), 24))(plain.length);
  const cipher = Buffer.from(plain.map((b, i) => b ^ stream[32 + i]));
  return Buffer.concat([epk, poly1305(stream.subarray(0, 32), cipher), cipher]);
}

export function sealOpen(box, recipientXSk) {
  if (box.length < SEAL_BYTES) return null;
  const recipientXPk = x25519PublicKey(recipientXSk);
  const epk = box.subarray(0, 32);
  const cipher = box.subarray(SEAL_BYTES);
  const stream = boxKeys(x25519(recipientXSk, epk), blake2b(Buffer.concat([epk, recipientXPk]), 24))(cipher.length);
  if (!poly1305(stream.subarray(0, 32), cipher).equals(box.subarray(32, 48))) return null;
  return Buffer.from(cipher.map((b, i) => b ^ stream[32 + i]));
}
