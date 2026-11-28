// Generates pal3-v0.6-transport-vectors.json: the mailbox location key and hybrid mailbox blob v2 of section 14.6.
// Uses Node built-ins for SHA-384 and Ed25519, and @noble/post-quantum (from pal-core) with extraEntropy: false for deterministic ML-DSA-65.
// Run: node test-vectors/v3/pal3-v0.6-transport-generate.mjs
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const palCore = process.env.PAL_CORE || resolve(__dirname, '../../../pal-core');
const mldsaPath = resolve(palCore, existsSync(resolve(palCore, 'node_modules/@noble/post-quantum/ml-dsa.js'))
  ? 'node_modules/@noble/post-quantum/ml-dsa.js'
  : 'packages/protocol/node_modules/@noble/post-quantum/ml-dsa.js');
const { ml_dsa65 } = await import(pathToFileURL(mldsaPath).href);

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const MAILBOX_V1_CONTEXT = 'palexplorer-mailbox-v1\n';
const MAILBOX_V2_CONTEXT = 'palexplorer-mailbox-v2\n';
const MAILBOX_V2_DSA_CONTEXT = 'palexplorer-mailbox-v2';
const MAX_V2_BYTES = 24576;

const locationKey = (recipientPublicKey, dayIndex) =>
  createHash('sha384').update(`palexplorer-mailbox-v1\n${recipientPublicKey}\n${dayIndex}`, 'utf8').digest('hex');

function identityPinHex(edPkHex, dsaPkHex) {
  return createHash('sha384')
    .update('pal3-identity-v1')
    .update(Buffer.from(edPkHex, 'hex'))
    .update(Buffer.from(dsaPkHex, 'hex'))
    .digest('hex');
}

function flipLastByte(hex) {
  const b = Buffer.from(hex, 'hex');
  b[b.length - 1] ^= 0x01;
  return b.toString('hex');
}

function keyFromSeed(edByte, dsaByte) {
  const seed = Buffer.alloc(32, edByte);
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  const dsaSeed = Buffer.alloc(32, dsaByte);
  const dsa = ml_dsa65.keygen(dsaSeed);
  const dsaPublicKey = Buffer.from(dsa.publicKey).toString('hex');
  return {
    seedHex: seed.toString('hex'),
    publicKey,
    privateKey,
    dsaSeedHex: dsaSeed.toString('hex'),
    dsaPublicKey,
    dsaSecretKey: dsa.secretKey,
    identityPinHex: identityPinHex(publicKey, dsaPublicKey),
  };
}

function signMailboxV2({ from, fromDsaPublicKey, timestamp, payload }, signer, dsaContext = MAILBOX_V2_DSA_CONTEXT) {
  const signedBytes = Buffer.from(MAILBOX_V2_CONTEXT + JSON.stringify({
    v: 2,
    from,
    fromDsaPublicKey,
    timestamp,
    payload,
  }), 'utf8');
  const signature = sign(null, signedBytes, signer.privateKey).toString('hex');
  const signatureMldsa65 = Buffer.from(
    ml_dsa65.sign(signedBytes, signer.dsaSecretKey, { context: Buffer.from(dsaContext, 'ascii'), extraEntropy: false })
  ).toString('hex');
  const object = { v: 2, from, fromDsaPublicKey, timestamp, payload, signature, signatureMldsa65 };
  return { object, signedBytes, serializedBytes: Buffer.byteLength(JSON.stringify(object), 'utf8') };
}

function signMailboxV1({ from, timestamp, payload }, signer) {
  const signedBytes = Buffer.from(MAILBOX_V1_CONTEXT + JSON.stringify({
    v: 1,
    from,
    timestamp,
    payload,
  }), 'utf8');
  const signature = sign(null, signedBytes, signer.privateKey).toString('hex');
  return { v: 1, from, timestamp, payload, signature };
}

const recipientPublicKey = 'ab'.repeat(32);
const unixSeconds = Date.parse('2026-11-15T12:00:00Z') / 1000;
const dayIndex = Math.floor(unixSeconds / 86400);

const sender = keyFromSeed(0x21, 0x31);
const impostor = keyFromSeed(0x21, 0x32); // same Ed25519 key, different ML-DSA-65 key -> different hybrid pin

const timestamp = 1794744000000;
const payload = {
  v: 1,
  nonceHex: '01'.repeat(12),
  ciphertextHex: '50414c332d6d61696c626f782d63697068657274657874',
};

const validV2 = signMailboxV2({
  from: sender.publicKey,
  fromDsaPublicKey: sender.dsaPublicKey,
  timestamp,
  payload,
}, sender);

const { signatureMldsa65: _omitted, ...missingMldsa } = validV2.object;
const wrongContextV2 = signMailboxV2({
  from: sender.publicKey,
  fromDsaPublicKey: sender.dsaPublicKey,
  timestamp,
  payload,
}, sender, 'palexplorer-mailbox-v1').object;

const pinMismatchV2 = signMailboxV2({
  from: impostor.publicKey,
  fromDsaPublicKey: impostor.dsaPublicKey,
  timestamp,
  payload,
}, impostor).object;

const legacyV1 = signMailboxV1({ from: sender.publicKey, timestamp, payload }, sender);

const oversizedPayload = { v: 1, nonceHex: '02'.repeat(12), ciphertextHex: 'aa'.repeat(7500) };
const oversizedV2 = signMailboxV2({
  from: sender.publicKey,
  fromDsaPublicKey: sender.dsaPublicKey,
  timestamp,
  payload: oversizedPayload,
}, sender);

const mailboxBlobV2Rejected = [
  {
    name: 'tamperedEd25519Signature',
    palV2Capable: true,
    expectedSenderPinHex: sender.identityPinHex,
    object: { ...validV2.object, signature: flipLastByte(validV2.object.signature) },
    expectedError: 'E_MAILBOX_BAD_SIGNATURE',
    description: 'Strict-AND: flipping one bit in the Ed25519 signature must fail even when ML-DSA-65 verifies.',
  },
  {
    name: 'tamperedMldsa65Signature',
    palV2Capable: true,
    expectedSenderPinHex: sender.identityPinHex,
    object: { ...validV2.object, signatureMldsa65: flipLastByte(validV2.object.signatureMldsa65) },
    expectedError: 'E_MAILBOX_BAD_SIGNATURE',
    description: 'Strict-AND: flipping one bit in the ML-DSA-65 signature must fail even when Ed25519 verifies.',
  },
  {
    name: 'missingMldsa65Signature',
    palV2Capable: true,
    expectedSenderPinHex: sender.identityPinHex,
    object: missingMldsa,
    expectedError: 'E_MAILBOX_BAD_SIGNATURE',
    description: 'A v2 mailbox blob missing signatureMldsa65 must be dropped.',
  },
  {
    name: 'tamperedTimestamp',
    palV2Capable: true,
    expectedSenderPinHex: sender.identityPinHex,
    object: { ...validV2.object, timestamp: timestamp + 1000 },
    expectedError: 'E_MAILBOX_BAD_SIGNATURE',
    description: 'Changing timestamp invalidates both signatures.',
  },
  {
    name: 'wrongMldsaContext',
    palV2Capable: true,
    expectedSenderPinHex: sender.identityPinHex,
    object: wrongContextV2,
    expectedError: 'E_MAILBOX_BAD_SIGNATURE',
    description: 'ML-DSA-65 signature produced under palexplorer-mailbox-v1 instead of palexplorer-mailbox-v2 must fail.',
  },
  {
    name: 'identityPinMismatch',
    palV2Capable: true,
    expectedSenderPinHex: sender.identityPinHex,
    object: pinMismatchV2,
    expectedError: 'E_MAILBOX_IDENTITY_MISMATCH',
    description: 'Valid signatures under a different ML-DSA-65 key fail the pinned hybrid identity digest check.',
  },
  {
    name: 'v1DowngradeFromV2CapablePal',
    palV2Capable: true,
    expectedSenderPinHex: sender.identityPinHex,
    object: legacyV1,
    expectedError: 'E_MAILBOX_DOWNGRADE',
    description: 'A legacy v1 blob from a v2-capable pal must be rejected with E_MAILBOX_DOWNGRADE.',
  },
  {
    name: 'exceeds24KiBLimit',
    palV2Capable: true,
    expectedSenderPinHex: sender.identityPinHex,
    object: oversizedV2.object,
    serializedBytes: oversizedV2.serializedBytes,
    expectedError: 'E_MESSAGE_TOO_LARGE',
    description: 'A v2 mailbox blob exceeding 24 KiB (24,576 bytes) must be rejected with E_MESSAGE_TOO_LARGE.',
  },
];

const out = {
  specVersion: '3.0.0-draft.6.23',
  description: 'Chat mailbox location key (48-byte SHA-384) and hybrid Ed25519+ML-DSA-65 mailbox blob v2 (section 14.6).',
  mailboxLocationKey: {
    recipientPublicKey,
    unixSeconds,
    dayIndex,
    inputUtf8: `palexplorer-mailbox-v1\n${recipientPublicKey}\n${dayIndex}`,
    locationKeyHex: locationKey(recipientPublicKey, dayIndex),
  },
  mailboxBlobV2: {
    sender: {
      seedHex: sender.seedHex,
      publicKey: sender.publicKey,
      dsaSeedHex: sender.dsaSeedHex,
      dsaPublicKey: sender.dsaPublicKey,
      identityPinHex: sender.identityPinHex,
    },
    dsaContext: MAILBOX_V2_DSA_CONTEXT,
    maxBytes: MAX_V2_BYTES,
    object: validV2.object,
    signedBytesUtf8: validV2.signedBytes.toString('utf8'),
    signedBytesHex: validV2.signedBytes.toString('hex'),
    serializedBytes: validV2.serializedBytes,
  },
  mailboxBlobV2Rejected,
};

writeFileSync(new URL('./pal3-v0.6-transport-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
