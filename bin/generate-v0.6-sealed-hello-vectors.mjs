// Generates test-vectors/v3/pal3-v0.6-sealed-hello-vectors.json (spec section 5.1, SEALED_HELLO) with the reference implementation.
// Run: node bin/generate-v0.6-sealed-hello-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// Keys, seeds and messages are fixed, so two runs give byte-identical output. The sealed records are built here from the
// construction of section 5.1 with Node primitives, and the reference implementation must open them to the same plaintext.
import { createCipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, hkdfSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-sealed-hello-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-sealed-hello-vectors.json');
const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);

const { kemKeygen, kemEncapsulate } = await lib('pqc.js');
const { openSealedHelloRecord, sealHelloRecord, HandshakeInitiator, generateHybridSigningIdentity, issueDeviceCertificate } = await lib('pal3/handshake.js');
const { packHandshakeRecord, RECORD_TYPE } = await lib('pal3/records.js');
const { encodeTlv } = await lib('pal3/tlv.js');

const hex = (b) => Buffer.from(b).toString('hex');
const sha384 = (b) => createHash('sha384').update(b).digest();
const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const privateOf = (sk) => createPrivateKey({ key: Buffer.concat([PKCS8_X25519, sk]), format: 'der', type: 'pkcs8' });
const x25519Public = (sk) => createPublicKey(privateOf(sk)).export({ format: 'der', type: 'spki' }).subarray(-32);
const x25519Shared = (sk, pk) => diffieHellman({
  privateKey: privateOf(sk),
  publicKey: createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), pk]), format: 'der', type: 'spki' }),
});

function recipient(seedByte) {
  const sk = Buffer.alloc(32, seedByte);
  const kem = kemKeygen(Buffer.alloc(64, seedByte + 1));
  return { x25519SecretKey: sk, x25519PublicKey: x25519Public(sk), kemSecretKey: kem.secretKey, kemPublicKey: kem.publicKey, kemSeed: Buffer.alloc(64, seedByte + 1) };
}

const recipientOf = (recip) => ({
  x25519SecretKeyHex: hex(recip.x25519SecretKey),
  x25519PublicKeyHex: hex(recip.x25519PublicKey),
  mlkemSeedHex: hex(recip.kemSeed),
  mlkemEncapsulationKeyHex: hex(recip.kemPublicKey),
});
function seal({ description, recip, ephByte, messageByte, plaintext, prekeyId = null }) {
  const ephSk = Buffer.alloc(32, ephByte);
  const ephPk = x25519Public(ephSk);
  const ssX = x25519Shared(ephSk, recip.x25519PublicKey);
  const enc = kemEncapsulate(recip.kemPublicKey, Buffer.alloc(32, messageByte));
  const kemContext = Buffer.concat([ephPk, recip.x25519PublicKey, sha384(recip.kemPublicKey), sha384(enc.cipherText)]);
  const ikm = Buffer.concat([ssX, enc.sharedSecret, kemContext]);
  const keyAndNonce = Buffer.from(hkdfSync('sha384', ikm, Buffer.alloc(0), Buffer.from('pal3-sealed-hello-v1', 'ascii'), 44));
  const key = keyAndNonce.subarray(0, 32);
  const nonce = keyAndNonce.subarray(32, 44);
  const aad = Buffer.concat([ephPk, sha384(enc.cipherText)]);
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const entries = [[0x0001, ephPk], [0x0002, enc.cipherText], [0x0003, ciphertext]];
  if (prekeyId) entries.push([0x0004, prekeyId]);
  const payload = encodeTlv(entries, 65536);
  const record = packHandshakeRecord(RECORD_TYPE.SEALED_HELLO, payload);
  return {
    description,
    recipient: recipientOf(recip),
    prekeyIdHex: prekeyId ? hex(prekeyId) : null,
    ephemeralX25519SecretKeyHex: hex(ephSk),
    ephemeralX25519PublicKeyHex: hex(ephPk),
    mlkemEncapsulationMessageHex: hex(Buffer.alloc(32, messageByte)),
    mlkemCiphertextHex: hex(enc.cipherText),
    mlkemSharedSecretHex: hex(enc.sharedSecret),
    x25519SharedSecretHex: hex(ssX),
    kemContextHex: hex(kemContext),
    ikmHex: hex(ikm),
    keyHex: hex(key),
    nonceHex: hex(nonce),
    aadHex: hex(aad),
    plaintextHex: hex(plaintext),
    ciphertextHex: hex(ciphertext),
    payloadHex: hex(payload),
    recordHex: hex(record),
  };
}

const openWith = (recip, recordHex, prekeyId = null) => {
  const keys = { x25519SecretKey: recip.x25519SecretKey, x25519PublicKey: recip.x25519PublicKey, kemSecretKey: recip.kemSecretKey, kemPublicKey: recip.kemPublicKey };
  const prekeys = prekeyId ? [{ prekeyId, expiresAtMs: Date.now() + 3600_000, ...keys }] : [];
  return openSealedHelloRecord(Buffer.from(recordHex, 'hex'), { ...keys, prekeys });
};
const code = (fn) => { try { fn(); return 'accepted'; } catch (err) { return /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message; } };

const pattern = (n, mul) => Buffer.from(Array.from({ length: n }, (_, i) => (i * mul + 5) % 251));
const staticKeys = recipient(0x21);
const prekeyKeys = recipient(0x41);
const prekeyId = Buffer.from('0102030405060708', 'hex');

const positive = [
  seal({ description: 'Sealed to the static signaling keys, 300-byte plaintext', recip: staticKeys, ephByte: 0x31, messageByte: 0x51, plaintext: pattern(300, 7) }),
  seal({ description: 'Sealed to a signaling prekey, named by tag 0x0004', recip: prekeyKeys, ephByte: 0x32, messageByte: 0x52, plaintext: pattern(1100, 13), prekeyId }),
  seal({ description: 'Empty plaintext: the ciphertext is the 16-byte tag', recip: staticKeys, ephByte: 0x33, messageByte: 0x53, plaintext: Buffer.alloc(0) }),
];
positive[0].recipientKind = 'static';
positive[1].recipientKind = 'prekey';
positive[2].recipientKind = 'static';
for (const c of positive) {
  const recip = c.recipientKind === 'prekey' ? prekeyKeys : staticKeys;
  const opened = openWith(recip, c.recordHex, c.prekeyIdHex ? Buffer.from(c.prekeyIdHex, 'hex') : null);
  if (hex(opened) !== c.plaintextHex) throw new Error(`the reference implementation did not open: ${c.description}`);
}

// The reference implementation seals a real HELLO; the construction of this file must open it.
const id = generateHybridSigningIdentity();
const hello = new HandshakeInitiator({ deviceCert: issueDeviceCertificate({ identity: id }), deviceKeys: id }).createHelloRecord();
const referenceSealed = sealHelloRecord(hello, { x25519PublicKey: staticKeys.x25519PublicKey, kemPublicKey: staticKeys.kemPublicKey });
if (!openWith(staticKeys, hex(referenceSealed)).equals(hello)) throw new Error('reference seal/open round trip failed');

const mutate = (record, offset) => { const b = Buffer.from(record, 'hex'); b[offset] ^= 0x01; return hex(b); };
const base = positive[0];
const payloadOffset = (base.recordHex.length - base.payloadHex.length) / 2;
const tamper = (description, recordHex, expectedError, recip = staticKeys, heldPrekeyId = null) => {
  const got = code(() => openWith(recip, recordHex, heldPrekeyId));
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${description}`);
  return { description, recordHex, openedWith: recipientOf(recip), heldPrekeyIdHex: heldPrekeyId ? hex(heldPrekeyId) : null, expectedError };
};
// Offsets inside the payload TLV: tag 0x0001 header (6) + 32 ephemeral key, tag 0x0002 header (6) + 1088 ciphertext, tag 0x0003 header (6) + body.
const ephOffset = payloadOffset + 6;
const ctOffset = payloadOffset + 6 + 32 + 6;
const aeadOffset = payloadOffset + 6 + 32 + 6 + 1088 + 6;
const negative = [
  tamper('One bit of the AEAD ciphertext is flipped', mutate(base.recordHex, aeadOffset + 3), 'E_PAL3_HANDSHAKE_AUTH_FAILED'),
  tamper('One bit of the tag is flipped', mutate(base.recordHex, base.recordHex.length / 2 - 1), 'E_PAL3_HANDSHAKE_AUTH_FAILED'),
  tamper('One bit of the ephemeral X25519 key is flipped', mutate(base.recordHex, ephOffset + 5), 'E_PAL3_HANDSHAKE_AUTH_FAILED'),
  tamper('One bit of the ML-KEM ciphertext is flipped (implicit rejection gives another key)', mutate(base.recordHex, ctOffset + 100), 'E_PAL3_HANDSHAKE_AUTH_FAILED'),
  tamper('Opened with the keys of another recipient', base.recordHex, 'E_PAL3_HANDSHAKE_AUTH_FAILED', prekeyKeys),
  tamper('The record names a prekey the responder does not hold', positive[1].recordHex, 'E_PAL3_HANDSHAKE_INVALID', prekeyKeys, Buffer.from('ffffffffffffffff', 'hex')),
];

const doc = {
  specVersion: '0.6.20',
  section: '5.1, SEALED_HELLO',
  description: 'SEALED_HELLO payload = TLV 0x0001 eph_x25519_pk (32 B), 0x0002 mlkem_ct (1088 B), 0x0003 ciphertext, optional 0x0004 prekey_id (8 B). kem_context = eph_x25519_pk || recipient_x25519_pk || SHA-384(recipient_mlkem_ek) || SHA-384(mlkem_ct); ikm = ss_x || ss_pq || kem_context; key || nonce = HKDF-SHA-384(salt = empty, ikm, info = "pal3-sealed-hello-v1", 44 bytes), 32-byte key then 12-byte nonce; ciphertext = ChaCha20-Poly1305(key, nonce, aad = eph_x25519_pk || SHA-384(mlkem_ct), plaintext) with a 16-byte tag appended. ss_x = X25519(eph_sk, recipient_pk) and ss_pq is the ML-KEM-768 shared secret of mlkem_ct under the recipient key; the ML-KEM key pair is the one generated from mlkemSeedHex. recordHex is the 20-byte handshake record header (type 0x04, epoch 0, stream 0, sequence 0) followed by the payload.',
  sealedHello: positive.map(({ recipientKind, ...c }) => c),
  sealedHelloRejected: negative,
};

writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}`);
