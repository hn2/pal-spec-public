// Generates test-vectors/v3/pal3-v0.6-sas-vectors.json (spec section 10, item 5, Quick Drop SAS) with the reference implementation.
// Run: node bin/generate-v0.6-sas-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// The exporter secret is the one of pal3-v0.6-beacon-vectors.json, the two public keys are the identities A and B of
// pal3-v0.6-pair-rendezvous-vectors.json and the root is the file identifier of pal3-v0.6-identifier-vectors.json.
// The handshake SAS (spec section 5.2, Handshake SAS) uses exporter secrets of its own and the word list of the reference implementation.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-sas-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(here, '../test-vectors/v3/pal3-v0.6-sas-vectors.json');
const { computeQuickDropSas } = await import(pathToFileURL(resolve(palCore, 'packages/protocol/lib/pal3/multipath.js')).href);
const { deriveHandshakeSas, SAS_WORDLIST } = await import(pathToFileURL(resolve(palCore, 'packages/protocol/lib/pal3/handshake.js')).href);

const existing = (name) => JSON.parse(readFileSync(resolve(here, '../test-vectors/v3', name), 'utf8'));
const exporterSecretHex = existing('pal3-v0.6-beacon-vectors.json').pairBeacon[0].exporterSecret0Hex;
const pairs = existing('pal3-v0.6-pair-rendezvous-vectors.json').identities;
const senderPkHex = pairs.A.edPublicKey;
const receiverPkHex = pairs.B.edPublicKey;
const rootHex = existing('pal3-v0.6-identifier-vectors.json').file.idHex;
const otherRootHex = existing('pal3-v0.6-identifier-vectors.json').share.idHex;

const hex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Buffer.from(h, 'hex');
const commitmentOf = (nonce) => createHash('sha384').update('pal3-sas-commit-v1').update(nonce).digest();
const nonceS = Buffer.alloc(32, 0x5a);
const baseNonceR = Buffer.alloc(32, 0xa5);
const base = {
  exporterSecretHex, senderPkHex, receiverPkHex, rootHex, offerIdHex: '0f0e0d0c0b0a09080706050403020100',
  nonceSHex: hex(nonceS), nonceRHex: hex(baseNonceR),
};

function run(c) {
  return computeQuickDropSas({
    exporterSecret: fromHex(c.exporterSecretHex),
    senderPk: fromHex(c.senderPkHex),
    receiverPk: fromHex(c.receiverPkHex),
    rootSha384: fromHex(c.rootHex),
    offerId: fromHex(c.offerIdHex),
    senderCommitment: fromHex(c.commitmentHex),
    senderNonce: fromHex(c.nonceSHex),
    receiverNonce: fromHex(c.nonceRHex),
  });
}
const full = (c) => ({ ...c, commitmentHex: hex(commitmentOf(fromHex(c.nonceSHex))) });
const positive = (description, c, extra = {}) => {
  const input = full(c);
  return { description, ...input, ...extra, expectedSas: run(input) };
};
const code = (fn) => { try { fn(); return 'accepted'; } catch (err) { return /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message; } };
const negative = (description, c, expectedError) => {
  const input = full(c);
  const result = code(() => run(input));
  if (result !== expectedError) throw new Error(`reference answered ${result}, not ${expectedError}`);
  return { description, ...input, expectedError };
};

let zeroNonceR;
for (let i = 0; ; i++) {
  const n = Buffer.alloc(32, 0xc3);
  n.writeUInt32BE(i, 28);
  if (run(full({ ...base, nonceRHex: hex(n) })).startsWith('000')) { zeroNonceR = n; break; }
}

const handshakeCase = (description, exporterSecret) => {
  const sas = deriveHandshakeSas(exporterSecret);
  return { description, exporterSecretHex: hex(exporterSecret), expectedDigits: sas.digits, expectedWords: [...sas.words], expectedPhrase: sas.phrase };
};
let zeroDigits;
for (let i = 0; ; i++) {
  const secret = Buffer.alloc(32, 0x71);
  secret.writeUInt32BE(i, 28);
  if (deriveHandshakeSas(secret).digits.startsWith('000')) { zeroDigits = secret; break; }
}
const handshakeSas = [
  handshakeCase('Baseline: the exporter secret of the beacon vector', fromHex(exporterSecretHex)),
  handshakeCase('Another exporter secret gives another code', Buffer.alloc(32, 0x44)),
  handshakeCase('Leading zeros are kept: the digits are always 8 characters', zeroDigits),
  handshakeCase('All-zero exporter secret', Buffer.alloc(32, 0)),
];
const handshakeSasRejected = [31, 33, 0].map((n) => {
  const result = code(() => deriveHandshakeSas(Buffer.alloc(n, 1)));
  if (result !== 'E_PAL3_HANDSHAKE_INVALID') throw new Error(`reference answered ${result} for a ${n}-byte secret`);
  return { description: `The exporter secret is ${n} bytes instead of 32`, exporterSecretHex: '01'.repeat(n), expectedError: 'E_PAL3_HANDSHAKE_INVALID' };
});

const baseline = positive('Baseline: sender A, receiver B, 8 digits', base);
const doc = {
  specVersion: '0.6.20',
  section: '10 item 5, Quick Drop SAS (commit-then-reveal); 5.2, Handshake SAS',
  description: 'SAS = HKDF-SHA-384(exporter_secret, salt = "pal3-sas-v1", info = lp(sender_pk) || lp(receiver_pk) || lp(root) || lp(offer_id) || nonce_S || nonce_R, 8 bytes) read as a big-endian u64, mod 10^8, printed as 8 digits with leading zeros. lp is a u32be length prefix. All inputs are byte strings given in hex (sender_pk and receiver_pk are the 32-byte Ed25519 keys, root is the 48-byte SHA-384 root, offer_id is 16 bytes). commitment = SHA-384("pal3-sas-commit-v1" || nonce_S) and the revealed nonce_S must match it before a code is computed. handshakeSas: okm = HKDF-SHA-384(exporter_secret_0, salt = "pal3-handshake-sas-v1", info = "sas", 16 bytes); digits = u64be(okm[0..8]) mod 10^8 printed as 8 digits with leading zeros; word i (0..3) = wordlist[okm[8 + i] & 0x3f]; the phrase joins the four words with "-".',
  wordlist: [...SAS_WORDLIST],
  quickDropSas: [
    baseline,
    positive('Another root and offer: the code is bound to the offer', { ...base, rootHex: otherRootHex, offerIdHex: 'f0e0d0c0b0a090807060504030201000' }, { mustDifferFromCase: 0 }),
    positive('Leading zeros are kept: the code always has 8 digits', { ...base, nonceRHex: hex(zeroNonceR) }),
    positive('Swapped roles: the receiver acting as sender (sender_pk and receiver_pk exchanged) gets a different code', { ...base, senderPkHex: receiverPkHex, receiverPkHex: senderPkHex }, { mustDifferFromCase: 0 }),
    positive('A man in the middle holds a session with another exporter secret and gets a different code', { ...base, exporterSecretHex: '44'.repeat(32) }, { mustDifferFromCase: 0 }),
  ],
  handshakeSas,
  handshakeSasRejected,
  quickDropSasRejected: [
    negative('The exporter secret is 31 bytes instead of 32', { ...base, exporterSecretHex: '33'.repeat(31) }, 'E_PAL3_SAS_INVALID'),
    negative('nonce_R is 16 bytes instead of 32', { ...base, nonceRHex: '11'.repeat(16) }, 'E_PAL3_SAS_INVALID'),
  ],
};
// The mismatch case commits to the original nonce_S and reveals a different one.
doc.quickDropSasRejected.unshift((() => {
  const input = { ...base, nonceSHex: hex(Buffer.alloc(32, 0x5b)), commitmentHex: hex(commitmentOf(nonceS)) };
  if (code(() => run(input)) !== 'E_PAL3_SAS_COMMITMENT_MISMATCH') throw new Error('reference accepted a wrong nonce_S');
  return { description: 'The revealed nonce_S does not match the commitment', ...input, expectedError: 'E_PAL3_SAS_COMMITMENT_MISMATCH' };
})());
for (const c of doc.quickDropSas) if (c.mustDifferFromCase !== undefined && c.expectedSas === baseline.expectedSas) throw new Error('a case that must differ equals the baseline');

writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}`);
